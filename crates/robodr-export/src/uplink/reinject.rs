//! Re-injection of dead-lettered records (`robodr-uplink reinject`).
//!
//! A line the server rejected for a reason an operator can fix (a robot or
//! key registered late, a site scope corrected, a finding key added) is
//! dead-lettered and acknowledged: it never comes back by itself. After the
//! fix, `robodr-uplink reinject` re-queues those records so the uplink sends
//! them again **under new batch ids** (re-sending them under their old batch
//! id would only return the server's stored response, contract §4 step 3).
//!
//! # Queue
//!
//! A re-injection writes one **generation**,
//! `<state>/reinject/<generation>/`, with
//!
//! * `records.jsonl`: the raw input records (`{topic, partition, key,
//!   headers, value}`, one per line, the same form as the diode importer's
//!   `records.jsonl`), re-read from the original input: the spool's
//!   `rejected/<seq>.json`, the diode batch's `records.jsonl` line, or an
//!   earlier generation's line; if the original is gone, the dead letter's
//!   `record` copy (it is validated again before sending, like every
//!   record);
//! * `origin.jsonl`: per line, the dead letter it came from (`source`,
//!   `position`, `code`, `batch_id`).
//!
//! The generation directory is built under a temporary name, fsynced and
//! renamed into place (the commit point), so a crash never leaves half a
//! generation. The uplink sends each generation as the line-numbered input
//! stream `reinject:<generation>` (batch ids hash the stream name, so they
//! are new) after its regular input, and marks it `done` once every line was
//! acknowledged; done generations are kept as the re-injection ledger.
//!
//! # Idempotent
//!
//! A dead letter (`source`, `position`) already named by any generation's
//! `origin.jsonl` is skipped, so running the same command twice queues
//! nothing the second time. A record rejected again after re-injection is
//! dead-lettered under `source = "reinject:<generation>"` and its line
//! number: a new entry, which a later re-injection may pick up again.
//!
//! The command takes the state directory's lock ([`super::StateLock`]): stop
//! the service first.

use super::{StateLock, UplinkError, REINJECT_DIR};
use crate::deadletter;
use crate::fsutil;
use crate::publish::{read_spool_item, LineReader, OpenRecordsError, Source};
use robodr_blackbox::crypto::{sha256, to_hex};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet, HashSet};
use std::fs;
use std::io::{self, BufRead, BufReader, Write};
use std::os::unix::fs::OpenOptionsExt;
use std::path::{Path, PathBuf};

/// `source` prefix of a re-injected stream (batches, dead letters).
pub const SOURCE_PREFIX: &str = "reinject:";
/// Records of a generation.
pub const RECORDS_FILE: &str = "records.jsonl";
/// Dead letters a generation came from.
pub const ORIGIN_FILE: &str = "origin.jsonl";
/// Marker: every line of the generation was acknowledged.
pub const DONE_FILE: &str = "done";
/// Codes re-injected when `--codes` is not given: the rejections an operator
/// fixes in the SOC's registry (robot, key, site scope, finding key).
pub const DEFAULT_CODES: [&str; 5] = [
    "unknown_robot",
    "robot_mismatch",
    "site_mismatch",
    "missing_finding_signature",
    "bad_finding_signature",
];

/// `rj-<16 digits: ms since the epoch>-<16 lower hex>`.
pub fn is_valid_generation(g: &str) -> bool {
    let Some(rest) = g.strip_prefix("rj-") else {
        return false;
    };
    let b = rest.as_bytes();
    b.len() == 33
        && b[16] == b'-'
        && b[..16].iter().all(u8::is_ascii_digit)
        && b[17..]
            .iter()
            .all(|c| c.is_ascii_digit() || (b'a'..=b'f').contains(c))
}

/// A generation directory.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Generation {
    pub name: String,
    pub done: bool,
}

/// The generations in `dir` (`<state>/reinject`), in name (= time) order.
pub fn list_generations(dir: &Path) -> io::Result<Vec<Generation>> {
    let rd = match fs::read_dir(dir) {
        Ok(rd) => rd,
        Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(Vec::new()),
        Err(e) => return Err(e),
    };
    let mut out = Vec::new();
    for e in rd {
        let e = e?;
        let Some(name) = e.file_name().to_str().map(str::to_string) else {
            continue;
        };
        if !is_valid_generation(&name) || !e.file_type()?.is_dir() {
            continue;
        }
        let done = fs::symlink_metadata(e.path().join(DONE_FILE)).is_ok();
        out.push(Generation { name, done });
    }
    out.sort_by(|a, b| a.name.cmp(&b.name));
    Ok(out)
}

/// Mark generation `g` done (every line acknowledged).
pub fn mark_done(dir: &Path, g: &str) -> io::Result<()> {
    fsutil::atomic_write(&dir.join(g).join(DONE_FILE), b"")
}

/// What to re-inject.
#[derive(Debug, Clone)]
pub struct ReinjectOptions {
    pub state_dir: PathBuf,
    /// The uplink's input (where the original records are re-read from).
    pub source: Source,
    /// Dead-letter files to read (e.g. `<state>/dead-letter.jsonl` and its
    /// rotated `.1`, `.2`, ...).
    pub dead_letters: Vec<PathBuf>,
    /// Server codes to re-inject.
    pub codes: BTreeSet<String>,
    /// Longest record accepted (as the uplink's `max_record_bytes`).
    pub max_record_bytes: usize,
    /// Report only; write nothing.
    pub dry_run: bool,
    /// Generation timestamp (ms since the epoch).
    pub now_ms: u64,
}

/// A dead letter that could not be re-injected.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Unavailable {
    pub source: String,
    pub position: u64,
    pub why: String,
}

/// What a re-injection did.
#[derive(Debug, Default, Clone, PartialEq, Eq, Serialize)]
pub struct ReinjectReport {
    /// The generation written (`None`: nothing to queue, or a dry run).
    pub generation: Option<String>,
    /// Records queued (dry run: that would be queued).
    pub queued: u64,
    /// ... of which re-read from the original input.
    pub from_input: u64,
    /// ... of which taken from the dead letter's `record` copy.
    pub from_dead_letter: u64,
    /// Dead letters already queued by an earlier generation (idempotence).
    pub already_queued: u64,
    /// Dead letters with another code (not selected).
    pub other_code: u64,
    /// Malformed dead-letter lines (counted, skipped).
    pub malformed: u64,
    /// Selected but without a usable record.
    pub unavailable: Vec<Unavailable>,
}

#[derive(Debug, Clone, Deserialize)]
struct Entry {
    source: String,
    position: u64,
    #[serde(default)]
    code: Option<String>,
    #[serde(default)]
    batch_id: Option<String>,
    #[serde(default)]
    record: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct Origin {
    source: String,
    position: u64,
    code: String,
    batch_id: Option<String>,
}

/// `(source, position)` of every dead letter some generation already holds.
fn ledger(dir: &Path) -> io::Result<HashSet<(String, u64)>> {
    let mut seen = HashSet::new();
    for g in list_generations(dir)? {
        let f = match fs::File::open(dir.join(&g.name).join(ORIGIN_FILE)) {
            Ok(f) => f,
            Err(e) if e.kind() == io::ErrorKind::NotFound => continue,
            Err(e) => return Err(e),
        };
        for line in BufReader::new(f).split(b'\n') {
            if let Ok(o) = serde_json::from_slice::<Origin>(&line?) {
                seen.insert((o.source, o.position));
            }
        }
    }
    Ok(seen)
}

/// Lines `wanted` of a line-numbered records file (`dir/<name>/records.jsonl`).
fn read_lines(
    dir: &Path,
    name: &str,
    wanted: &BTreeSet<u64>,
    max: usize,
) -> io::Result<BTreeMap<u64, Vec<u8>>> {
    let mut out = BTreeMap::new();
    let Some(last) = wanted.last().copied() else {
        return Ok(out);
    };
    let mut r = match LineReader::open(dir, name, max) {
        Ok(Some(r)) => r,
        Ok(None) | Err(OpenRecordsError::NotRegular(_)) => return Ok(out),
        Err(OpenRecordsError::Io(e)) => return Err(e),
    };
    while let Some((pos, raw)) = r.next_line()? {
        if pos > last {
            break;
        }
        if let (true, Ok(raw)) = (wanted.contains(&pos), raw) {
            out.insert(pos, raw);
        }
    }
    Ok(out)
}

/// A dead letter's `record` copy, if it can stand for the record: one JSON
/// object on one line, within the size cap.
fn record_copy(e: &Entry, max: usize) -> Option<Vec<u8>> {
    let r = e.record.as_deref()?;
    if r.is_empty() || r.len() > max || r.contains('\n') {
        return None;
    }
    serde_json::from_str::<serde_json::Value>(r)
        .ok()
        .filter(serde_json::Value::is_object)
        .map(|_| r.as_bytes().to_vec())
}

/// Re-inject (see the module docs). Takes the state directory's lock.
pub fn reinject(o: &ReinjectOptions) -> Result<ReinjectReport, UplinkError> {
    let _lock = StateLock::acquire(&o.state_dir)?;
    if o.codes.is_empty() {
        return Err(UplinkError::Config("no codes to re-inject".into()));
    }
    if o.dead_letters.is_empty() {
        return Err(UplinkError::Config("no dead-letter file given".into()));
    }
    if !(1024..=16 * 1024 * 1024).contains(&o.max_record_bytes) {
        return Err(UplinkError::Config(
            "max_record_bytes must be in 1024..=16777216".into(),
        ));
    }
    let dir = o.state_dir.join(REINJECT_DIR);
    let queued_before = ledger(&dir)?;
    let mut rep = ReinjectReport::default();

    // 1. Select.
    let mut selected: Vec<Entry> = Vec::new();
    let mut picked: HashSet<(String, u64)> = HashSet::new();
    for path in &o.dead_letters {
        let f = fs::File::open(path).map_err(|e| {
            UplinkError::Config(format!("dead-letter file {}: {e}", path.display()))
        })?;
        for line in BufReader::new(f).split(b'\n') {
            let line = line?;
            let Ok(e) = serde_json::from_slice::<Entry>(&line) else {
                rep.malformed += 1;
                continue;
            };
            let code_ok = e.code.as_deref().is_some_and(|c| o.codes.contains(c));
            if !code_ok {
                rep.other_code += 1;
                continue;
            }
            let k = (e.source.clone(), e.position);
            if queued_before.contains(&k) {
                rep.already_queued += 1;
                continue;
            }
            if picked.insert(k) {
                selected.push(e);
            }
        }
    }

    // 2. Find each record: original input first, the dead letter's copy
    //    otherwise.
    let spool_ctx = match &o.source {
        Source::Spool(root) => Some(root.display().to_string()),
        Source::DiodeOut(_) => None,
    };
    let mut by_stream: BTreeMap<(PathBuf, String), BTreeSet<u64>> = BTreeMap::new();
    for e in &selected {
        if let Some(g) = e.source.strip_prefix(SOURCE_PREFIX) {
            if is_valid_generation(g) {
                by_stream
                    .entry((dir.clone(), g.to_string()))
                    .or_default()
                    .insert(e.position);
            }
        } else if let Source::DiodeOut(out) = &o.source {
            if crate::publish::valid_batch_name(&e.source) {
                by_stream
                    .entry((out.clone(), e.source.clone()))
                    .or_default()
                    .insert(e.position);
            }
        }
    }
    let mut lines: BTreeMap<(PathBuf, String), BTreeMap<u64, Vec<u8>>> = BTreeMap::new();
    for ((d, name), wanted) in &by_stream {
        lines.insert(
            (d.clone(), name.clone()),
            read_lines(d, name, wanted, o.max_record_bytes)?,
        );
    }
    let mut records: Vec<(Origin, Vec<u8>)> = Vec::new();
    for e in selected {
        let original: Option<Vec<u8>> = if let Some(g) = e.source.strip_prefix(SOURCE_PREFIX) {
            lines
                .get(&(dir.clone(), g.to_string()))
                .and_then(|m| m.get(&e.position).cloned())
        } else {
            match &o.source {
                Source::DiodeOut(out) => lines
                    .get(&(out.clone(), e.source.clone()))
                    .and_then(|m| m.get(&e.position).cloned()),
                Source::Spool(root) if spool_ctx.as_deref() == Some(e.source.as_str()) => {
                    let p = root
                        .join("rejected")
                        .join(format!("{:020}.json", e.position));
                    read_spool_item(&p, e.position, o.max_record_bytes)?.ok()
                }
                Source::Spool(_) => None,
            }
        };
        let raw = match original {
            Some(r) => {
                rep.from_input += 1;
                r
            }
            None => match record_copy(&e, o.max_record_bytes) {
                Some(r) => {
                    rep.from_dead_letter += 1;
                    r
                }
                None => {
                    rep.unavailable.push(Unavailable {
                        source: e.source.clone(),
                        position: e.position,
                        why: "the original record is gone and the dead letter holds no \
                              usable copy"
                            .into(),
                    });
                    continue;
                }
            },
        };
        records.push((
            Origin {
                source: e.source,
                position: e.position,
                code: e.code.unwrap_or_default(),
                batch_id: e.batch_id,
            },
            raw,
        ));
    }
    rep.queued = records.len() as u64;
    if records.is_empty() || o.dry_run {
        return Ok(rep);
    }

    // 3. Write the generation (temporary name, fsync, rename, fsync).
    let mut h = Vec::new();
    for (org, _) in &records {
        h.extend_from_slice(org.source.as_bytes());
        h.push(0);
        h.extend_from_slice(&org.position.to_be_bytes());
    }
    let gen = format!(
        "rj-{:016}-{}",
        o.now_ms % 10_000_000_000_000_000,
        &to_hex(&sha256(&h))[..16]
    );
    fsutil::mkdir(&dir)?;
    // Leftovers of an interrupted run.
    for e in fs::read_dir(&dir)? {
        let e = e?;
        if e.file_name().to_string_lossy().starts_with(".tmp-") {
            fs::remove_dir_all(e.path())?;
        }
    }
    let tmp = dir.join(format!(".tmp-{gen}"));
    fsutil::mkdir(&tmp)?;
    let write = |name: &str, body: &[u8]| -> io::Result<()> {
        let mut f = fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(tmp.join(name))?;
        f.write_all(body)?;
        f.sync_all()
    };
    let mut rec_body = Vec::new();
    let mut org_body = Vec::new();
    for (org, raw) in &records {
        rec_body.extend_from_slice(raw);
        rec_body.push(b'\n');
        org_body.extend_from_slice(
            &serde_json::to_vec(org).map_err(|e| UplinkError::State(e.to_string()))?,
        );
        org_body.push(b'\n');
    }
    write(RECORDS_FILE, &rec_body)?;
    write(ORIGIN_FILE, &org_body)?;
    fsutil::fsync_dir(&tmp)?;
    fs::rename(&tmp, dir.join(&gen))?;
    fsutil::fsync_dir(&dir)?;
    rep.generation = Some(gen);
    Ok(rep)
}

/// The dead-letter files of a state directory (current and rotated), for
/// callers that want all of them.
pub fn state_dead_letter_files(state_dir: &Path) -> io::Result<Vec<PathBuf>> {
    deadletter::files(state_dir, super::DEAD_LETTER_FILE)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn generation_names() {
        assert!(is_valid_generation("rj-0001790000000000-0123456789abcdef"));
        for bad in [
            "rj-1790000000000-0123456789abcdef",
            "rj-0001790000000000-0123456789ABCDEF",
            "rj-0001790000000000_0123456789abcdef",
            "rx-0001790000000000-0123456789abcdef",
            ".tmp-rj-0001790000000000-0123456789abcdef",
            "",
        ] {
            assert!(!is_valid_generation(bad), "{bad}");
        }
    }
}
