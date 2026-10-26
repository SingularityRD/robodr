//! The findings spool: validated findings records (`robodr.findings`
//! contract; topic = the configured `findings.topic`) as files, for
//! an exporter (Kafka producer, sneakernet, ...) to pick up.
//!
//! ```text
//! <spool>/tmp/                  partial writes (cleared at start)
//! <spool>/ready/<seq:020>.json  one record per file, not yet exported
//! <spool>/acked/<seq:020>.json  moved here by the exporter after delivery
//! <spool>/status.json           daemon health snapshot (atomic replace)
//! <spool>/checkpoint.json       black-box seal at shutdown (keep off-unit)
//! ```
//!
//! # Contract with the exporter
//!
//! * Read `ready/*.json` in name order (= creation order). Each file is one
//!   complete JSON object ([`SpoolRecord`]); it appears atomically (written
//!   under `tmp/`, `fsync`ed, renamed, directory `fsync`ed), so a file seen
//!   in `ready/` is never partial.
//! * After the record is delivered, **ack** it by renaming it into `acked/`
//!   (same file system, atomic). The daemon never deletes from `ready/`.
//!
//! # Bounds
//!
//! `ready/` + `acked/` are kept within `max_bytes` and `max_files`. When a
//! new record would exceed them, the daemon deletes **acked** files, oldest
//! first. If that is not enough (the exporter is behind), the new record is
//! **not** written and counted in [`SpoolStats::dropped_full`]; the finding
//! and its evidence are still in the black box, and the daemon raises a
//! `robot.agent.spool_full` health finding (which may use a small reserve,
//! [`RESERVE_FILES`] / [`RESERVE_BYTES`], so that it is itself spooled).
//!
//! # Critical findings first (red team F1)
//!
//! A flood of lesser findings must never be the reason a **Critical** one
//! is not spooled. Records are written by [`SpoolClass`]: a non-Critical
//! finding may fill the spool only up to `max_* - max_* /`
//! [`CRITICAL_RESERVE_DIVISOR`] (7/8 of each bound: 56 MiB / 8750 files by
//! default); the last eighth is kept for Critical findings, which may use
//! the whole bound; health findings keep their own reserve beyond it.
//! Within the Critical share it is still first come, first served: a
//! flood of Critical findings can fill it, and what does not fit is in the
//! black box only (as always). The discovery-flood aggregation in agentd
//! (`crate::flood`) keeps a GUID spray from filling even the lesser share.

use std::fs::{self, File, OpenOptions};
use std::io::{self, Write};
use std::os::unix::fs::DirBuilderExt;
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use robodr_agent::FindingOutput;
use serde::Serialize;

/// Extra files allowed for health findings when the spool is full.
pub const RESERVE_FILES: u64 = 16;
/// Extra bytes allowed for health findings when the spool is full.
pub const RESERVE_BYTES: u64 = 256 * 1024;
/// `1 / CRITICAL_RESERVE_DIVISOR` of each bound is kept for Critical
/// findings (module docs).
pub const CRITICAL_RESERVE_DIVISOR: u64 = 8;

/// Which share of the spool a record may use (module docs).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SpoolClass {
    /// Below Critical: up to the bounds minus the Critical reserve.
    Normal,
    /// A Critical finding: up to the bounds.
    Critical,
    /// A self-health finding: up to the bounds plus [`RESERVE_FILES`] /
    /// [`RESERVE_BYTES`].
    Health,
}
/// Spool record schema id.
pub const SPOOL_SCHEMA: &str = "robodr.spool/v1";
/// Minimum interval between two directory scans forced by a full spool.
const RESCAN_INTERVAL: Duration = Duration::from_millis(200);

/// One spooled record: the Kafka record of a validated finding.
#[derive(Debug, Clone, Serialize, serde::Deserialize, PartialEq, Eq)]
pub struct SpoolRecord {
    pub schema: String,
    pub seq: u64,
    pub topic: String,
    /// Kafka record key (= finding id).
    pub key: String,
    pub partition: Option<u32>,
    pub headers: Vec<(String, String)>,
    /// The validated finding JSON, byte-for-byte as built (a string, so the
    /// exporter sends exactly the validated bytes).
    pub value: String,
}

/// Spool counters.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize)]
pub struct SpoolStats {
    pub written: u64,
    /// Records not written because the spool was full of unacked records.
    pub dropped_full: u64,
    /// Records not written because of an I/O error.
    pub write_errors: u64,
    /// Acked files deleted to stay within bounds.
    pub pruned: u64,
    pub ready_files: u64,
    pub ready_bytes: u64,
    pub acked_files: u64,
    pub acked_bytes: u64,
}

/// Why a record was not spooled.
#[derive(Debug)]
pub enum SpoolError {
    Full,
    Io(io::Error),
}

impl std::fmt::Display for SpoolError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            SpoolError::Full => write!(f, "spool full of unacknowledged records"),
            SpoolError::Io(e) => write!(f, "spool I/O error: {e}"),
        }
    }
}

/// See the module docs.
#[derive(Debug)]
pub struct Spool {
    root: PathBuf,
    tmp: PathBuf,
    ready: PathBuf,
    acked: PathBuf,
    max_bytes: u64,
    max_files: u64,
    next_seq: u64,
    last_scan: Option<Instant>,
    stats: SpoolStats,
}

fn is_record_name(name: &str) -> Option<u64> {
    let stem = name.strip_suffix(".json")?;
    if stem.len() != 20 || !stem.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    stem.parse().ok()
}

/// Record files of `dir` as `(seq, path, len)`, sorted by seq.
fn list(dir: &Path) -> io::Result<Vec<(u64, PathBuf, u64)>> {
    let mut out = Vec::new();
    for e in fs::read_dir(dir)? {
        let e = e?;
        let name = e.file_name();
        let Some(seq) = name.to_str().and_then(is_record_name) else {
            continue;
        };
        let Ok(meta) = e.metadata() else { continue };
        if meta.is_file() {
            out.push((seq, e.path(), meta.len()));
        }
    }
    out.sort_by_key(|x| x.0);
    Ok(out)
}

fn mkdir(p: &Path) -> io::Result<()> {
    fs::DirBuilder::new().recursive(true).mode(0o700).create(p)
}

fn sync_dir(p: &Path) -> io::Result<()> {
    File::open(p)?.sync_all()
}

/// Write `bytes` to `dir/name` atomically (tmp file in `tmp`, fsync,
/// rename, fsync of `dir`).
pub fn atomic_write(tmp: &Path, dir: &Path, name: &str, bytes: &[u8]) -> io::Result<()> {
    let t = tmp.join(format!("{name}.tmp"));
    let _ = fs::remove_file(&t);
    let mut f = OpenOptions::new().write(true).create_new(true).open(&t)?;
    let res = f
        .write_all(bytes)
        .and_then(|()| f.sync_all())
        .and_then(|()| fs::rename(&t, dir.join(name)))
        .and_then(|()| sync_dir(dir));
    if res.is_err() {
        let _ = fs::remove_file(&t);
    }
    res
}

impl Spool {
    /// Create (mode 0700) or reopen the spool. Leftover partial writes in
    /// `tmp/` are removed; numbering continues after the highest record.
    pub fn open(root: &Path, max_bytes: u64, max_files: u64) -> io::Result<Self> {
        let tmp = root.join("tmp");
        let ready = root.join("ready");
        let acked = root.join("acked");
        for d in [root, &tmp, &ready, &acked] {
            mkdir(d)?;
        }
        for e in fs::read_dir(&tmp)? {
            let _ = fs::remove_file(e?.path());
        }
        let mut s = Self {
            root: root.to_path_buf(),
            tmp,
            ready,
            acked,
            max_bytes,
            max_files,
            next_seq: 1,
            last_scan: None,
            stats: SpoolStats::default(),
        };
        let r = list(&s.ready)?;
        let a = list(&s.acked)?;
        let max = r.iter().chain(a.iter()).map(|x| x.0).max().unwrap_or(0);
        s.next_seq = max.saturating_add(1);
        s.rescan()?;
        Ok(s)
    }

    pub fn root(&self) -> &Path {
        &self.root
    }

    pub fn ready_dir(&self) -> &Path {
        &self.ready
    }

    pub fn acked_dir(&self) -> &Path {
        &self.acked
    }

    pub fn stats(&self) -> SpoolStats {
        self.stats
    }

    /// `true` if the last scan saw the spool at or over its bounds.
    pub fn is_full(&self) -> bool {
        self.used_files() >= self.max_files || self.used_bytes() >= self.max_bytes
    }

    fn used_files(&self) -> u64 {
        self.stats.ready_files + self.stats.acked_files
    }

    fn used_bytes(&self) -> u64 {
        self.stats.ready_bytes + self.stats.acked_bytes
    }

    /// Re-read the directory sizes (the exporter moves files behind our
    /// back).
    pub fn rescan(&mut self) -> io::Result<()> {
        self.last_scan = Some(Instant::now());
        let r = list(&self.ready)?;
        let a = list(&self.acked)?;
        self.stats.ready_files = r.len() as u64;
        self.stats.ready_bytes = r.iter().map(|x| x.2).sum();
        self.stats.acked_files = a.len() as u64;
        self.stats.acked_bytes = a.iter().map(|x| x.2).sum();
        Ok(())
    }

    /// Rescan and delete acked records, oldest first, until `extra_files` /
    /// `extra_bytes` more fit within the bounds (or no acked record is
    /// left). Unacked records are never deleted. Returns files deleted.
    pub fn prune(&mut self, extra_files: u64, extra_bytes: u64) -> io::Result<u64> {
        self.rescan()?;
        let mut deleted = 0;
        let fits = |s: &Self| {
            s.used_files() + extra_files <= s.max_files
                && s.used_bytes() + extra_bytes <= s.max_bytes
        };
        if fits(self) {
            return Ok(0);
        }
        for (_, path, len) in list(&self.acked)? {
            if fits(self) {
                break;
            }
            match fs::remove_file(&path) {
                Ok(()) => {
                    deleted += 1;
                    self.stats.pruned += 1;
                    self.stats.acked_files = self.stats.acked_files.saturating_sub(1);
                    self.stats.acked_bytes = self.stats.acked_bytes.saturating_sub(len);
                }
                // Already gone (exporter cleanup); rescan below fixes counts.
                Err(e) if e.kind() == io::ErrorKind::NotFound => {}
                Err(e) => return Err(e),
            }
        }
        if deleted > 0 {
            let _ = sync_dir(&self.acked);
        }
        Ok(deleted)
    }

    /// The `(files, bytes)` a record of `class` may fill the spool to.
    fn limits(&self, class: SpoolClass) -> (u64, u64) {
        match class {
            SpoolClass::Normal => (
                self.max_files - self.max_files / CRITICAL_RESERVE_DIVISOR,
                self.max_bytes - self.max_bytes / CRITICAL_RESERVE_DIVISOR,
            ),
            SpoolClass::Critical => (self.max_files, self.max_bytes),
            SpoolClass::Health => (
                self.max_files.saturating_add(RESERVE_FILES),
                self.max_bytes.saturating_add(RESERVE_BYTES),
            ),
        }
    }

    /// Spool one finding within the share of its `class` (see the module
    /// docs).
    pub fn write(&mut self, f: &FindingOutput, class: SpoolClass) -> Result<PathBuf, SpoolError> {
        let seq = self.next_seq;
        let rec = SpoolRecord {
            schema: SPOOL_SCHEMA.into(),
            seq,
            topic: f.topic.clone(),
            key: f.key.clone(),
            partition: f.partition,
            headers: f.headers.clone(),
            value: f.value.clone(),
        };
        let bytes = serde_json::to_vec(&rec).map_err(|e| SpoolError::Io(io::Error::other(e)))?;
        let len = bytes.len() as u64;
        let (max_files, max_bytes) = self.limits(class);
        let over = |s: &Self| s.used_files() + 1 > max_files || s.used_bytes() + len > max_bytes;
        if over(self) {
            // Rescanning is O(files): at most every RESCAN_INTERVAL under a
            // flood of drops.
            let stale = self
                .last_scan
                .is_none_or(|t| t.elapsed() >= RESCAN_INTERVAL);
            if stale {
                // Prune acked records until this one fits its share.
                let extra_files = 1 + self.max_files.saturating_sub(max_files);
                let extra_bytes = len + self.max_bytes.saturating_sub(max_bytes);
                if let Err(e) = self.prune(extra_files, extra_bytes) {
                    self.stats.write_errors += 1;
                    return Err(SpoolError::Io(e));
                }
            }
            if over(self) {
                self.stats.dropped_full += 1;
                return Err(SpoolError::Full);
            }
        }
        let name = format!("{seq:020}.json");
        match atomic_write(&self.tmp, &self.ready, &name, &bytes) {
            Ok(()) => {
                self.next_seq = seq.saturating_add(1);
                self.stats.written += 1;
                self.stats.ready_files += 1;
                self.stats.ready_bytes += len;
                Ok(self.ready.join(name))
            }
            Err(e) => {
                self.stats.write_errors += 1;
                Err(SpoolError::Io(e))
            }
        }
    }

    /// Atomically replace `<spool>/<name>` (status, checkpoint).
    pub fn write_side_file(&self, name: &str, bytes: &[u8]) -> io::Result<()> {
        atomic_write(&self.tmp, &self.root, name, bytes)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tmp(tag: &str) -> PathBuf {
        let d =
            std::env::temp_dir().join(format!("robodr-agentd-spool-{tag}-{}", std::process::id()));
        let _ = fs::remove_dir_all(&d);
        d
    }

    fn rec(n: usize) -> FindingOutput {
        FindingOutput {
            topic: robodr_ocsf::DEFAULT_TOPIC.into(),
            key: format!("rf1-{n}"),
            partition: None,
            value: format!("{{\"x\":\"{}\"}}", "v".repeat(n)),
            headers: vec![("h".into(), "v".into())],
        }
    }

    fn ack_all(s: &Spool) {
        for (_, p, _) in list(s.ready_dir()).unwrap() {
            fs::rename(&p, s.acked_dir().join(p.file_name().unwrap())).unwrap();
        }
    }

    #[test]
    fn writes_atomically_and_numbers_across_reopen() {
        let d = tmp("reopen");
        let mut s = Spool::open(&d, 1 << 20, 100).unwrap();
        let p = s.write(&rec(3), SpoolClass::Normal).unwrap();
        assert!(p.ends_with("ready/00000000000000000001.json"));
        let r: SpoolRecord = serde_json::from_slice(&fs::read(&p).unwrap()).unwrap();
        assert_eq!(r.seq, 1);
        assert_eq!(r.value, rec(3).value);
        assert_eq!(r.schema, SPOOL_SCHEMA);
        s.write(&rec(3), SpoolClass::Normal).unwrap();
        ack_all(&s);
        // Junk in the dirs is ignored; a leftover tmp file is removed.
        fs::write(d.join("ready/notes.txt"), b"x").unwrap();
        fs::write(d.join("tmp/00000000000000000009.json.tmp"), b"partial").unwrap();
        drop(s);
        let mut s = Spool::open(&d, 1 << 20, 100).unwrap();
        assert_eq!(fs::read_dir(d.join("tmp")).unwrap().count(), 0);
        let p = s.write(&rec(1), SpoolClass::Normal).unwrap();
        assert!(p.ends_with("ready/00000000000000000003.json"));
        assert_eq!(s.stats().acked_files, 2);
        assert_eq!(s.stats().ready_files, 1);
        let _ = fs::remove_dir_all(&d);
    }

    #[test]
    fn full_spool_prunes_acked_oldest_first_never_ready() {
        let d = tmp("full");
        let mut s = Spool::open(&d, 1 << 20, 3).unwrap();
        for i in 0..3 {
            s.write(&rec(i), SpoolClass::Normal).unwrap();
        }
        // Nothing acked: the 4th is dropped, ready/ untouched.
        assert!(matches!(
            s.write(&rec(9), SpoolClass::Normal),
            Err(SpoolError::Full)
        ));
        assert_eq!(s.stats().dropped_full, 1);
        assert_eq!(list(s.ready_dir()).unwrap().len(), 3);
        // A health finding may use the reserve.
        s.write(&rec(9), SpoolClass::Health).unwrap();
        assert_eq!(list(s.ready_dir()).unwrap().len(), 4);
        // Ack everything: the oldest acked files make room.
        ack_all(&s);
        std::thread::sleep(RESCAN_INTERVAL);
        s.write(&rec(1), SpoolClass::Normal).unwrap();
        let acked: Vec<u64> = list(s.acked_dir()).unwrap().iter().map(|x| x.0).collect();
        assert_eq!(acked, vec![3, 4], "oldest acked pruned first");
        assert_eq!(s.stats().pruned, 2);
        assert_eq!(list(s.ready_dir()).unwrap().len(), 1);
        let _ = fs::remove_dir_all(&d);
    }

    #[test]
    fn lesser_findings_leave_the_critical_share_free() {
        let d = tmp("classes");
        let mut s = Spool::open(&d, 1 << 20, 16).unwrap();
        // A flood of non-Critical records stops at 7/8 of the files...
        let mut n = 0;
        while s.write(&rec(1), SpoolClass::Normal).is_ok() {
            n += 1;
            assert!(n <= 16);
        }
        assert_eq!(n, 14, "16 - 16 / 8");
        assert_eq!(s.stats().dropped_full, 1);
        // ...so Critical findings still fit, up to the full bound.
        s.write(&rec(2), SpoolClass::Critical).unwrap();
        s.write(&rec(2), SpoolClass::Critical).unwrap();
        assert!(matches!(
            s.write(&rec(2), SpoolClass::Critical),
            Err(SpoolError::Full)
        ));
        // A health finding still has its own reserve beyond that.
        s.write(&rec(3), SpoolClass::Health).unwrap();
        assert_eq!(list(s.ready_dir()).unwrap().len(), 17);
        // Once the exporter acks, a lesser record prunes acked ones until
        // it fits its own share (the Critical share stays free).
        ack_all(&s);
        std::thread::sleep(RESCAN_INTERVAL);
        s.write(&rec(1), SpoolClass::Normal).unwrap();
        assert!(s.stats().acked_files + s.stats().ready_files <= 14);
        let _ = fs::remove_dir_all(&d);
    }

    #[test]
    fn byte_bound_is_enforced() {
        let d = tmp("bytes");
        let mut s = Spool::open(&d, 2_000, 1000).unwrap();
        let mut n = 0;
        while s.write(&rec(200), SpoolClass::Critical).is_ok() {
            n += 1;
            assert!(n < 100);
        }
        assert!(s.stats().ready_bytes <= 2_000);
        // Every record has the same size: the next one would not fit.
        let ready = s.stats().ready_bytes;
        assert!(n > 0);
        assert!(
            s.is_full() || ready + ready / n > 2_000,
            "{n} records, {ready} B"
        );
        let _ = fs::remove_dir_all(&d);
    }

    #[test]
    fn record_names() {
        assert_eq!(is_record_name("00000000000000000042.json"), Some(42));
        for bad in [
            "42.json",
            "0000000000000000004x.json",
            "00000000000000000042.json.tmp",
            "status.json",
            "",
        ] {
            assert_eq!(is_record_name(bad), None, "{bad}");
        }
    }

    #[test]
    fn side_files_replace_atomically() {
        let d = tmp("side");
        let s = Spool::open(&d, 1 << 20, 10).unwrap();
        s.write_side_file("status.json", b"{\"a\":1}").unwrap();
        s.write_side_file("status.json", b"{\"a\":2}").unwrap();
        assert_eq!(fs::read(d.join("status.json")).unwrap(), b"{\"a\":2}");
        let _ = fs::remove_dir_all(&d);
    }
}
