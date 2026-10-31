//! Bounded retention of the exporters' bookkeeping files: `done/` markers
//! (`robodr-kafka-publish`, `robodr-uplink`), rotated dead-letter files
//! (both, [`crate::deadletter`]), rejected spool records
//! (`robodr-spool-export`, and with a spool source `robodr-kafka-publish`
//! and `robodr-uplink`), the payload of finished batch directories of the
//! diode importer's `out/` ([`prune_diode_out`], opt-in, sole consumer
//! only; tombstones stay) and
//! the payload of finished re-injection generations
//! ([`prune_reinject_payloads`], opt-in; the ledger stays). What the state
//! occupies is measured by [`state_usage`] (the uplink's status file, the
//! publisher's report).
//!
//! A [`Retention`] names up to three bounds; a file is **over** them when it
//! is older than `max_age` (by modification time), or when it lies beyond
//! `max_count` files or `max_bytes` bytes counted from the newest. A file
//! over the bounds is deleted only if its owner says it is no longer
//! needed (see each caller: a marker whose batch is still in the
//! importer's `out/`, or a dead letter whose record may still be processed
//! again, is **held**, reported, and looked at again on the next run).
//!
//! Every deletion is a single `unlink` of a file that is not needed (any
//! crash leaves either the file or nothing, and both are consistent),
//! followed by an fsync of the directory. Pruning never renames, never
//! rewrites, and never touches the current dead-letter file or anything
//! not yet durably published.

use crate::fsutil;
use serde::{Deserialize, Serialize};
use std::fs;
use std::io;
use std::path::{Path, PathBuf};
use std::time::{Duration, SystemTime};

/// Retention bounds (`None`: not bounded that way).
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct Retention {
    pub max_age: Option<Duration>,
    pub max_count: Option<u64>,
    pub max_bytes: Option<u64>,
}

impl Retention {
    /// Keep everything.
    pub const UNBOUNDED: Retention = Retention {
        max_age: None,
        max_count: None,
        max_bytes: None,
    };

    /// Only an age bound.
    pub const fn max_age(d: Duration) -> Self {
        Retention {
            max_age: Some(d),
            max_count: None,
            max_bytes: None,
        }
    }

    pub fn is_unbounded(&self) -> bool {
        self.max_age.is_none() && self.max_count.is_none() && self.max_bytes.is_none()
    }

    /// `true` for each item (`(modified, bytes)`) that is over the bounds
    /// at `now`. Count and bytes accumulate from the newest item, so the
    /// newest ones are kept; of two items with the same time, the later one
    /// in `items` counts as the newer.
    pub fn over(&self, items: &[(SystemTime, u64)], now: SystemTime) -> Vec<bool> {
        let mut order: Vec<usize> = (0..items.len()).collect();
        order.sort_by(|a, b| {
            let time = |i: &usize| items.get(*i).map(|it| it.0);
            time(b).cmp(&time(a)).then(b.cmp(a))
        });
        let mut out = vec![false; items.len()];
        let (mut count, mut bytes) = (0u64, 0u64);
        for i in order {
            let (Some(&(t, n)), Some(slot)) = (items.get(i), out.get_mut(i)) else {
                continue;
            };
            count += 1;
            bytes = bytes.saturating_add(n);
            let old = self
                .max_age
                .is_some_and(|a| now.duration_since(t).is_ok_and(|age| age > a));
            *slot = old
                || self.max_count.is_some_and(|c| count > c)
                || self.max_bytes.is_some_and(|b| bytes > b);
        }
        out
    }
}

/// What one pruning pass did.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq, Serialize)]
pub struct PruneReport {
    /// Files deleted.
    pub removed: u64,
    /// Their bytes.
    pub removed_bytes: u64,
    /// Files over the bounds kept because they are still needed.
    pub held: u64,
    /// Dead-letter entries in the deleted files (rotated dead-letter files
    /// only; each such deletion is also logged).
    pub removed_entries: u64,
}

impl PruneReport {
    pub fn add(&mut self, o: PruneReport) {
        self.removed += o.removed;
        self.removed_bytes += o.removed_bytes;
        self.held += o.held;
        self.removed_entries += o.removed_entries;
    }
}

/// A file that retention may delete.
#[derive(Debug, Clone)]
pub struct Candidate {
    /// What the owner checks (e.g. a batch name).
    pub name: String,
    /// The files that make it up (deleted together, in order).
    pub paths: Vec<PathBuf>,
    pub modified: SystemTime,
    pub bytes: u64,
}

/// Delete the candidates over `r` for which `may_delete` says yes; fsync
/// `dir` once if anything was deleted. A path already gone counts as
/// deleted.
pub fn prune(
    dir: &Path,
    candidates: &[Candidate],
    r: &Retention,
    now: SystemTime,
    mut may_delete: impl FnMut(&Candidate) -> io::Result<bool>,
) -> io::Result<PruneReport> {
    let mut rep = PruneReport::default();
    if r.is_unbounded() || candidates.is_empty() {
        return Ok(rep);
    }
    let items: Vec<(SystemTime, u64)> = candidates.iter().map(|c| (c.modified, c.bytes)).collect();
    for (c, over) in candidates.iter().zip(r.over(&items, now)) {
        if !over {
            continue;
        }
        if !may_delete(c)? {
            rep.held += 1;
            continue;
        }
        for p in &c.paths {
            match fs::remove_file(p) {
                Ok(()) => {}
                Err(e) if e.kind() == io::ErrorKind::NotFound => {}
                Err(e) => return Err(e),
            }
        }
        rep.removed += 1;
        rep.removed_bytes += c.bytes;
    }
    if rep.removed > 0 {
        fsutil::fsync_dir(dir)?;
    }
    Ok(rep)
}

/// Metadata of a regular file (not following symlinks); `None` if it is
/// gone or not a regular file.
pub fn file_meta(p: &Path) -> io::Result<Option<(SystemTime, u64)>> {
    match fs::symlink_metadata(p) {
        Ok(m) if m.file_type().is_file() => Ok(Some((m.modified()?, m.len()))),
        Ok(_) => Ok(None),
        Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(None),
        Err(e) => Err(e),
    }
}

/// The `done/` markers in `dir` (regular files with a valid batch name).
pub fn done_markers(dir: &Path) -> io::Result<Vec<Candidate>> {
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
        if !crate::publish::valid_batch_name(&name) {
            continue;
        }
        let path = e.path();
        if let Some((modified, bytes)) = file_meta(&path)? {
            out.push(Candidate {
                name,
                paths: vec![path],
                modified,
                bytes,
            });
        }
    }
    Ok(out)
}

/// Prune the `done/` markers of diode batches: a marker is needed (held)
/// while its batch is still in the importer's `out/` (without it, the
/// batch would be published again). `out` is read when this is called.
pub fn prune_done_markers(
    done_dir: &Path,
    out: &Path,
    r: &Retention,
    now: SystemTime,
) -> io::Result<PruneReport> {
    if r.is_unbounded() {
        return Ok(PruneReport::default());
    }
    let markers = done_markers(done_dir)?;
    prune(done_dir, &markers, r, now, |c| {
        // Still there (any kind of entry): needed.
        match fs::symlink_metadata(out.join(&c.name)) {
            Ok(_) => Ok(false),
            Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(true),
            Err(e) => Err(e),
        }
    })
}

/// Bytes of the regular files under `dir` (not following symlinks; at
/// most `depth` directory levels below it).
pub fn tree_bytes(dir: &Path, depth: u32) -> io::Result<u64> {
    let rd = match fs::read_dir(dir) {
        Ok(rd) => rd,
        Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(0),
        Err(e) => return Err(e),
    };
    let mut n = 0u64;
    for e in rd {
        let e = e?;
        let t = e.file_type()?;
        if t.is_file() {
            n = n.saturating_add(e.metadata()?.len());
        } else if t.is_dir() && depth > 0 {
            n = n.saturating_add(tree_bytes(&e.path(), depth - 1)?);
        }
    }
    Ok(n)
}

/// The payload of an importer `out/` batch directory: every entry but the
/// manifest copy, the records file first (`(path, is_dir)`).
fn out_payload(dir: &Path) -> io::Result<Vec<(PathBuf, bool)>> {
    let mut v = Vec::new();
    for e in fs::read_dir(dir)? {
        let e = e?;
        if e.file_name() == robodr_diode::manifest::MANIFEST_FILE {
            continue;
        }
        v.push((e.path(), e.file_type()?.is_dir()));
    }
    let records = dir.join(crate::publish::RECORDS_FILE);
    v.sort_by_key(|(p, _)| *p != records);
    Ok(v)
}

/// Prune the diode importer's `out/` (opt-in, `r` unbounded by default):
/// a batch directory over `r` loses its payload (records, bundles) only
/// once this tool has finished it (its `done/` marker exists); without a
/// marker it is held. Its age is the marker's (when it was finished), its
/// size the bytes of the payload.
///
/// The directory and its `MANIFEST.json` copy stay as a **tombstone**: the
/// importer, should that unit's import state be reset and a different
/// batch arrive under the same name, then finds the name taken by another
/// manifest and emits the new batch under its hash-suffixed name (which
/// has no `done/` marker, so it is published). Were the name free, the new
/// batch would be emitted under it and skipped as done: a silent loss. A
/// tombstone holds its `done/` marker too (the batch is "still in
/// `out/`"); both are a few hundred bytes to a few KiB per batch, counted
/// in [`StateUsage::diode_out`] and [`StateUsage::done_markers`].
///
/// The records file goes first (one `unlink`), so a crash leaves a
/// finished batch with less payload, never a half-readable records file
/// under a name that is not finished; the next pass completes it.
///
/// The count and byte bounds rank every batch directory that still has
/// a payload, finished or not, from the newest: an unfinished batch
/// counts against the bounds (and so pushes older finished ones over
/// them) but is itself held. Tombstones are not ranked: `max_count`
/// bounds the batches that still have a payload, not the entries of
/// `out/`.
///
/// Only for a tool that is the **sole consumer** of `out/`: a second
/// consumer (another publisher or uplink on the same `out/`) would lose the
/// batches this one has finished.
///
/// A batch that cannot be measured (its payload or `done/` marker cannot
/// be read) is skipped, so it is neither pruned nor ranked against the
/// bounds; a batch whose payload cannot be removed (typically: this tool
/// may not write the importer's `out/<batch>/`) is left as it is. Neither
/// stops the others: the pass goes on and returns the first error, with
/// its path, beside what it did. The callers report it ([`out_prune_failure`]) and go on
/// delivering: pruning `out/` is housekeeping, never a reason to stop
/// delivering findings.
pub fn prune_diode_out(
    out: &Path,
    done_dir: &Path,
    r: &Retention,
    now: SystemTime,
) -> (PruneReport, Option<io::Error>) {
    let mut rep = PruneReport::default();
    if r.is_unbounded() {
        return (rep, None);
    }
    let (cands, mut first_err) = out_candidates(out, done_dir);
    let items: Vec<(SystemTime, u64)> = cands.iter().map(|c| (c.modified, c.bytes)).collect();
    for (c, over) in cands.iter().zip(r.over(&items, now)) {
        if !over {
            continue;
        }
        match prune_out_batch(out, done_dir, c) {
            Ok(true) => {
                rep.removed += 1;
                rep.removed_bytes += c.bytes;
            }
            Ok(false) => rep.held += 1,
            Err(e) => {
                first_err.get_or_insert(e);
            }
        }
    }
    (rep, first_err)
}

/// `e` with the path it concerns.
fn at(p: &Path, e: io::Error) -> io::Error {
    io::Error::new(e.kind(), format!("{}: {e}", p.display()))
}

/// The batch directories of `out/` that still have a payload, and the
/// first error met while listing them. A batch that cannot be measured
/// is left out (never pruned) and the others still are: leaving one out
/// only ever ranks fewer batches against the bounds, so the pass prunes
/// less, never more. A failed `read_dir` of `out/` itself, or of its
/// listing, ends the listing there.
fn out_candidates(out: &Path, done_dir: &Path) -> (Vec<Candidate>, Option<io::Error>) {
    let mut cands = Vec::new();
    let rd = match fs::read_dir(out) {
        Ok(rd) => rd,
        Err(e) if e.kind() == io::ErrorKind::NotFound => return (cands, None),
        Err(e) => return (cands, Some(at(out, e))),
    };
    let mut first_err = None;
    for e in rd {
        let e = match e {
            Ok(e) => e,
            Err(x) => {
                first_err.get_or_insert(at(out, x));
                break;
            }
        };
        match out_candidate(&e, done_dir) {
            Ok(Some(c)) => cands.push(c),
            Ok(None) => {}
            Err(x) => {
                first_err.get_or_insert(x);
            }
        }
    }
    (cands, first_err)
}

/// One entry of `out/` as a candidate (`None`: not a batch directory, or
/// a tombstone already).
fn out_candidate(e: &fs::DirEntry, done_dir: &Path) -> io::Result<Option<Candidate>> {
    let Some(name) = e.file_name().to_str().map(str::to_string) else {
        return Ok(None);
    };
    let path = e.path();
    let is_dir = e.file_type().map_err(|x| at(&path, x))?.is_dir();
    if !crate::publish::valid_batch_name(&name) || !is_dir {
        return Ok(None);
    }
    let payload = out_payload(&path).map_err(|x| at(&path, x))?;
    if payload.is_empty() {
        // A tombstone already.
        return Ok(None);
    }
    let mut bytes = 0u64;
    for (p, is_dir) in &payload {
        bytes = bytes.saturating_add(if *is_dir {
            tree_bytes(p, 3).map_err(|x| at(p, x))?
        } else {
            file_meta(p).map_err(|x| at(p, x))?.map_or(0, |m| m.1)
        });
    }
    let marker = done_dir.join(&name);
    let modified = match file_meta(&marker).map_err(|x| at(&marker, x))? {
        Some((t, _)) => t,
        None => e
            .metadata()
            .and_then(|m| m.modified())
            .map_err(|x| at(&path, x))?,
    };
    Ok(Some(Candidate {
        name,
        paths: payload.into_iter().map(|(p, _)| p).collect(),
        modified,
        bytes,
    }))
}

/// Remove one batch's payload if it is finished (`Ok(false)`: held).
fn prune_out_batch(out: &Path, done_dir: &Path, c: &Candidate) -> io::Result<bool> {
    let marker = done_dir.join(&c.name);
    if file_meta(&marker).map_err(|e| at(&marker, e))?.is_none() {
        return Ok(false);
    }
    for p in &c.paths {
        let res = match fs::symlink_metadata(p) {
            Ok(m) if m.is_dir() => fs::remove_dir_all(p),
            Ok(_) => fs::remove_file(p),
            Err(e) => Err(e),
        };
        match res {
            Ok(()) => {}
            Err(e) if e.kind() == io::ErrorKind::NotFound => {}
            Err(e) => return Err(at(p, e)),
        }
    }
    let dir = out.join(&c.name);
    fsutil::fsync_dir(&dir).map_err(|e| at(&dir, e))?;
    Ok(true)
}

/// What the publisher and the uplink report (and log, once while it
/// lasts) when pruning `out/` failed ([`prune_diode_out`]).
pub fn out_prune_failure(e: &io::Error) -> String {
    let hint = if e.kind() == io::ErrorKind::PermissionDenied {
        " (this tool needs write permission on the importer's out/<batch>/ \
         directories: run it as the importer's user or give its group write \
         access there, or drop --out-max-*)"
    } else {
        ""
    };
    format!(
        "cannot prune the importer's out/ for --out-max-*: {e}{hint}; \
         delivery goes on, that payload stays"
    )
}

/// Measures [`state_usage`] at most once per interval, across runs (and,
/// in `robodr-uplink`'s service loop, across re-opens of the uplink).
/// Measuring is monitoring: a failed measurement is reported (and the
/// last good one kept), never a reason to fail a run. A failed attempt
/// also waits for the interval before the next one.
#[derive(Debug, Clone, Default)]
pub struct UsageMeter {
    at: Option<std::time::Instant>,
    last: Option<StateUsage>,
    error: Option<String>,
}

/// What [`UsageMeter::measure_if_due`] did.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Measured {
    /// Within the interval: nothing measured.
    NotDue,
    Fresh(StateUsage),
    /// The measurement failed; `new` when the previous attempt did not
    /// fail with the same message (log it then).
    Failed {
        error: String,
        new: bool,
    },
}

impl UsageMeter {
    pub fn measure_if_due(
        &mut self,
        interval: Duration,
        measure: impl FnOnce() -> io::Result<StateUsage>,
    ) -> Measured {
        if self.at.is_some_and(|t| t.elapsed() < interval) {
            return Measured::NotDue;
        }
        self.at = Some(std::time::Instant::now());
        match measure() {
            Ok(u) => {
                self.error = None;
                self.last = Some(u.clone());
                Measured::Fresh(u)
            }
            Err(e) => {
                let error = format!("cannot measure the state usage: {e}");
                let new = self.error.as_deref() != Some(error.as_str());
                self.error = Some(error.clone());
                Measured::Failed { error, new }
            }
        }
    }

    /// The last successful measurement.
    pub fn last(&self) -> Option<&StateUsage> {
        self.last.as_ref()
    }

    /// The last attempt's error, while it lasts.
    pub fn error(&self) -> Option<&str> {
        self.error.as_deref()
    }
}

/// Prune the payload of finished re-injection generations
/// (`<state>/reinject/<generation>/records.jsonl`, `robodr-uplink`;
/// opt-in): a generation over `r`, aged by its `done` marker, loses its
/// `records.jsonl`. Its `origin.jsonl` and `done` marker stay: they are
/// the re-injection **ledger** (a dead letter already re-injected is never
/// queued twice), and they are small. A generation that is not done is
/// never touched. A record of a pruned generation that was rejected again
/// is re-injected from its dead letter's `record` copy.
pub fn prune_reinject_payloads(
    dir: &Path,
    r: &Retention,
    now: SystemTime,
) -> io::Result<PruneReport> {
    use crate::uplink::reinject;
    if r.is_unbounded() {
        return Ok(PruneReport::default());
    }
    let mut cands = Vec::new();
    for g in reinject::list_generations(dir)? {
        if !g.done {
            continue;
        }
        let gdir = dir.join(&g.name);
        let (Some((modified, _)), Some((_, bytes))) = (
            file_meta(&gdir.join(reinject::DONE_FILE))?,
            file_meta(&gdir.join(reinject::RECORDS_FILE))?,
        ) else {
            continue;
        };
        cands.push(Candidate {
            name: g.name,
            paths: vec![gdir.join(reinject::RECORDS_FILE)],
            modified,
            bytes,
        });
    }
    let mut rep = PruneReport::default();
    let items: Vec<(SystemTime, u64)> = cands.iter().map(|c| (c.modified, c.bytes)).collect();
    for (c, over) in cands.iter().zip(r.over(&items, now)) {
        if !over {
            continue;
        }
        for p in &c.paths {
            match fs::remove_file(p) {
                Ok(()) => {}
                Err(e) if e.kind() == io::ErrorKind::NotFound => {}
                Err(e) => return Err(e),
            }
            if let Some(parent) = p.parent() {
                fsutil::fsync_dir(parent)?;
            }
        }
        rep.removed += 1;
        rep.removed_bytes += c.bytes;
    }
    Ok(rep)
}

/// Entries and bytes of one kind of state.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct Usage {
    pub entries: u64,
    pub bytes: u64,
}

/// What the exporter state occupies on disk (status / report), so its
/// growth can be watched and bounded. `None`: not used with this source.
#[derive(Debug, Default, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct StateUsage {
    /// `<state>/done/` markers.
    pub done_markers: Usage,
    /// The dead-letter files (current and rotated).
    pub dead_letters: Usage,
    /// The importer's `out/` batch directories (diode source; all of them,
    /// finished or not).
    pub diode_out: Option<Usage>,
    /// `<spool>/rejected/` files (spool source).
    pub spool_rejected: Option<Usage>,
    /// Re-injection generations (`robodr-uplink`).
    pub reinject: Option<Usage>,
    /// When this was measured (ms since the epoch).
    pub measured_at_ms: u64,
}

/// Entries (not starting with `.`) directly in `dir` and the bytes under
/// it (`depth` levels).
pub fn dir_usage(dir: &Path, depth: u32) -> io::Result<Usage> {
    let rd = match fs::read_dir(dir) {
        Ok(rd) => rd,
        Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(Usage::default()),
        Err(e) => return Err(e),
    };
    let mut u = Usage::default();
    for e in rd {
        let e = e?;
        if e.file_name().as_encoded_bytes().first() == Some(&b'.') {
            continue;
        }
        u.entries += 1;
        let t = e.file_type()?;
        if t.is_file() {
            u.bytes = u.bytes.saturating_add(e.metadata()?.len());
        } else if t.is_dir() && depth > 0 {
            u.bytes = u.bytes.saturating_add(tree_bytes(&e.path(), depth - 1)?);
        }
    }
    Ok(u)
}

/// The usage of an exporter's state: `state_dir` with its `done/` and the
/// dead-letter files named `dead_letter`, the diode `out/` or the spool's
/// `rejected/`, and (`reinject`) `<state>/reinject/`.
pub fn state_usage(
    state_dir: &Path,
    dead_letter: &str,
    source: &crate::publish::Source,
    reinject: bool,
) -> io::Result<StateUsage> {
    use crate::publish::Source;
    let usage = |d: &Path, depth: u32| dir_usage(d, depth).map_err(|e| at(d, e));
    let mut dead = Usage::default();
    for p in crate::deadletter::files(state_dir, dead_letter).map_err(|e| at(state_dir, e))? {
        if let Some((_, n)) = file_meta(&p).map_err(|e| at(&p, e))? {
            dead.entries += 1;
            dead.bytes = dead.bytes.saturating_add(n);
        }
    }
    let (diode_out, spool_rejected) = match source {
        Source::DiodeOut(out) => (Some(usage(out, 4)?), None),
        Source::Spool(root) => (None, Some(usage(&root.join("rejected"), 0)?)),
    };
    Ok(StateUsage {
        done_markers: usage(&state_dir.join("done"), 0)?,
        dead_letters: dead,
        diode_out,
        spool_rejected,
        reinject: if reinject {
            Some(usage(&state_dir.join(crate::uplink::REINJECT_DIR), 1)?)
        } else {
            None
        },
        measured_at_ms: fsutil::now_ms(),
    })
}

/// The command-line flags `--<what>-max-age-s`, `--<what>-max-count` and
/// `--<what>-max-bytes` (`get` reads one numeric flag; `0`: that bound
/// off). `None` when none of them is given.
pub fn bound_flags(
    what: &str,
    mut get: impl FnMut(&str) -> Result<Option<u64>, String>,
) -> Result<Option<Retention>, String> {
    let age = get(&format!("{what}-max-age-s"))?;
    let count = get(&format!("{what}-max-count"))?;
    let bytes = get(&format!("{what}-max-bytes"))?;
    if age.is_none() && count.is_none() && bytes.is_none() {
        return Ok(None);
    }
    Ok(Some(with_flags(Retention::UNBOUNDED, age, count, bytes)))
}

/// Seconds as an optional duration (`0`: unbounded), for command lines.
pub fn secs(n: u64) -> Option<Duration> {
    (n > 0).then(|| Duration::from_secs(n))
}

/// `base` with the bounds given on a command line replaced (`Some(0)`:
/// that bound off; `None`: as in `base`). Ages are in seconds.
pub fn with_flags(
    base: Retention,
    max_age_s: Option<u64>,
    max_count: Option<u64>,
    max_bytes: Option<u64>,
) -> Retention {
    let nz = |n: u64| (n > 0).then_some(n);
    Retention {
        max_age: max_age_s.map_or(base.max_age, secs),
        max_count: max_count.map_or(base.max_count, nz),
        max_bytes: max_bytes.map_or(base.max_bytes, nz),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const DAY: Duration = Duration::from_secs(86_400);

    fn ok((rep, e): (PruneReport, Option<io::Error>)) -> PruneReport {
        assert!(e.is_none(), "{e:?}");
        rep
    }

    fn at(days_ago: u64, now: SystemTime) -> SystemTime {
        now - DAY * days_ago as u32
    }

    #[test]
    fn bounds_keep_the_newest() {
        let now = SystemTime::UNIX_EPOCH + DAY * 1000;
        // Oldest to newest, deliberately shuffled.
        let items = [
            (at(5, now), 10),
            (at(1, now), 10),
            (at(10, now), 10),
            (at(0, now), 10),
        ];
        assert_eq!(Retention::UNBOUNDED.over(&items, now), [false; 4]);
        let age = Retention::max_age(DAY * 3);
        assert_eq!(age.over(&items, now), [true, false, true, false]);
        let count = Retention {
            max_count: Some(2),
            ..Default::default()
        };
        assert_eq!(count.over(&items, now), [true, false, true, false]);
        let bytes = Retention {
            max_bytes: Some(30),
            ..Default::default()
        };
        assert_eq!(bytes.over(&items, now), [false, false, true, false]);
        // A file from the future (clock step) is not "old".
        let future = [(now + DAY, 1)];
        assert_eq!(age.over(&future, now), [false]);
        assert_eq!(secs(0), None);
        assert_eq!(secs(5), Some(Duration::from_secs(5)));
        let base = Retention::max_age(DAY);
        assert_eq!(with_flags(base, None, None, None), base);
        assert_eq!(
            with_flags(base, Some(0), Some(5), Some(0)),
            Retention {
                max_age: None,
                max_count: Some(5),
                max_bytes: None
            }
        );
    }

    fn tmp(tag: &str) -> PathBuf {
        let d = std::env::temp_dir().join(format!("robodr-ret-{tag}-{}", std::process::id()));
        let _ = fs::remove_dir_all(&d);
        fsutil::mkdir(&d).unwrap();
        d
    }

    #[test]
    fn done_markers_of_batches_still_in_out_are_held() {
        let d = tmp("done");
        let (done, out) = (d.join("done"), d.join("out"));
        fsutil::mkdir(&done).unwrap();
        fsutil::mkdir(&out).unwrap();
        for b in ["rdd_a_1", "rdd_a_2", "rdd_a_3"] {
            fs::write(done.join(b), b"").unwrap();
        }
        fsutil::mkdir(&out.join("rdd_a_2")).unwrap();
        // Not a marker: ignored.
        fs::write(done.join(".tmp-x"), b"").unwrap();
        let later = SystemTime::now() + DAY * 40;
        let r = Retention::max_age(DAY * 30);
        // Nothing old yet.
        let rep = prune_done_markers(&done, &out, &r, SystemTime::now()).unwrap();
        assert_eq!(rep, PruneReport::default());
        let rep = prune_done_markers(&done, &out, &r, later).unwrap();
        assert_eq!((rep.removed, rep.held), (2, 1));
        assert!(done.join("rdd_a_2").exists(), "batch still in out/");
        assert!(!done.join("rdd_a_1").exists() && !done.join("rdd_a_3").exists());
        assert!(done.join(".tmp-x").exists());
        // Unbounded: nothing is looked at.
        let rep = prune_done_markers(&done, &out, &Retention::UNBOUNDED, later).unwrap();
        assert_eq!(rep, PruneReport::default());
        // Count bound: the newest markers stay.
        fs::remove_dir(out.join("rdd_a_2")).unwrap();
        let r = Retention {
            max_count: Some(1),
            ..Default::default()
        };
        fs::write(done.join("rdd_a_4"), b"").unwrap();
        let rep = prune_done_markers(&done, &out, &r, SystemTime::now()).unwrap();
        assert_eq!(rep.removed + rep.held, 1, "{rep:?}");
        let _ = fs::remove_dir_all(&d);
    }

    #[test]
    fn out_batches_go_only_once_finished() {
        let d = tmp("out");
        let (done, out) = (d.join("done"), d.join("out"));
        fsutil::mkdir(&done).unwrap();
        fsutil::mkdir(&out).unwrap();
        for b in ["rdd_a_1", "rdd_a_2"] {
            fsutil::mkdir(&out.join(b)).unwrap();
            fsutil::mkdir(&out.join(b).join("bundles")).unwrap();
            fs::write(out.join(b).join("records.jsonl"), [b'x'; 100]).unwrap();
            fs::write(out.join(b).join("bundles").join("1.json"), [b'y'; 10]).unwrap();
            fs::write(out.join(b).join("MANIFEST.json"), [b'm'; 7]).unwrap();
        }
        fs::write(done.join("rdd_a_1"), b"").unwrap();
        // Not a batch directory / a staging directory: never touched.
        fs::write(out.join("rdd_a_3"), b"").unwrap();
        fsutil::mkdir(&out.join(".tmp-import")).unwrap();
        fs::write(out.join(".tmp-import").join("records.jsonl"), b"x").unwrap();
        let later = SystemTime::now() + DAY * 40;
        let r = Retention::max_age(DAY * 30);
        assert_eq!(
            ok(prune_diode_out(&out, &done, &Retention::UNBOUNDED, later)),
            PruneReport::default()
        );
        let rep = ok(prune_diode_out(&out, &done, &r, SystemTime::now()));
        assert_eq!((rep.removed, rep.held), (0, 0), "not old yet");
        let rep = ok(prune_diode_out(&out, &done, &r, later));
        assert_eq!((rep.removed, rep.held, rep.removed_bytes), (1, 1, 110));
        // Finished: only the tombstone (the manifest copy) is left.
        let left: Vec<_> = fs::read_dir(out.join("rdd_a_1"))
            .unwrap()
            .map(|e| e.unwrap().file_name())
            .collect();
        assert_eq!(left, ["MANIFEST.json"]);
        assert!(out.join("rdd_a_2").join("records.jsonl").exists(), "held");
        assert!(out.join("rdd_a_3").exists());
        assert!(out.join(".tmp-import").join("records.jsonl").exists());
        assert!(done.join("rdd_a_1").exists(), "the marker is not ours");
        // A tombstone is not pruned again.
        let rep = ok(prune_diode_out(&out, &done, &r, later));
        assert_eq!((rep.removed, rep.held), (0, 1));
        // A crash after the records went: the next pass finishes it.
        fs::write(done.join("rdd_a_2"), b"").unwrap();
        fs::remove_file(out.join("rdd_a_2").join("records.jsonl")).unwrap();
        let rep = ok(prune_diode_out(&out, &done, &r, later));
        assert_eq!((rep.removed, rep.removed_bytes), (1, 10));
        let u = dir_usage(&out, 4).unwrap();
        assert_eq!((u.entries, u.bytes), (3, 14), "two tombstones, one file");
        let _ = fs::remove_dir_all(&d);
    }

    /// One batch that cannot be measured (here: its `done/` marker path
    /// is longer than PATH_MAX, so `lstat` fails with ENAMETOOLONG; works
    /// as root too) does not stop the pass for the other batches: it is
    /// skipped, never pruned, and its error is returned.
    #[test]
    fn an_unmeasurable_batch_does_not_stop_the_others() {
        let d = tmp("unmeasurable");
        let out = d.join("out");
        fsutil::mkdir(&out).unwrap();
        // done/ deep enough that done/<128-byte name> exceeds PATH_MAX
        // (4096 with the NUL) while done/<short name> does not.
        let base = d.join("done");
        let mut done = base.clone();
        let target = 4096 - 1 - 128 + 5;
        while done.as_os_str().len() + 201 <= target {
            done.push("a".repeat(200));
        }
        let pad = target - done.as_os_str().len() - 1;
        done.push("b".repeat(pad));
        fs::create_dir_all(&done).unwrap();
        let (short, long) = ("rdd_a_1".to_string(), "r".repeat(128));
        for b in [&short, &long] {
            fsutil::mkdir(&out.join(b)).unwrap();
            fs::write(out.join(b).join("records.jsonl"), [b'x'; 10]).unwrap();
            fs::write(out.join(b).join("MANIFEST.json"), b"m").unwrap();
        }
        fs::write(done.join(&short), b"").unwrap();
        assert!(fs::symlink_metadata(done.join(&long))
            .is_err_and(|e| e.kind() != io::ErrorKind::NotFound));
        let r = Retention {
            max_count: Some(0),
            ..Default::default()
        };
        let (rep, e) = prune_diode_out(&out, &done, &r, SystemTime::now());
        let e = e.expect("the unmeasurable batch is reported");
        assert!(e.to_string().contains(&long), "{e}");
        assert_eq!((rep.removed, rep.held), (1, 0), "{rep:?}");
        assert!(!out.join(&short).join("records.jsonl").exists(), "pruned");
        assert!(out.join(&long).join("records.jsonl").exists(), "skipped");
        let _ = fs::remove_dir_all(&d);
    }

    #[test]
    fn reinject_payloads_go_the_ledger_stays() {
        use crate::uplink::reinject::{DONE_FILE, ORIGIN_FILE, RECORDS_FILE};
        let d = tmp("rj");
        let (g1, g2) = (
            "rj-0000000000000001-0123456789abcdef",
            "rj-0000000000000002-0123456789abcdef",
        );
        for g in [g1, g2] {
            fsutil::mkdir(&d.join(g)).unwrap();
            fs::write(d.join(g).join(RECORDS_FILE), [b'r'; 50]).unwrap();
            fs::write(d.join(g).join(ORIGIN_FILE), b"{}\n").unwrap();
        }
        // g1 done, g2 still being sent.
        fs::write(d.join(g1).join(DONE_FILE), b"").unwrap();
        let r = Retention {
            max_count: Some(0),
            ..Default::default()
        };
        let rep = prune_reinject_payloads(&d, &r, SystemTime::now()).unwrap();
        assert_eq!((rep.removed, rep.removed_bytes), (1, 50));
        assert!(!d.join(g1).join(RECORDS_FILE).exists());
        assert!(d.join(g1).join(ORIGIN_FILE).exists() && d.join(g1).join(DONE_FILE).exists());
        assert!(d.join(g2).join(RECORDS_FILE).exists(), "not done: kept");
        // Nothing left to prune.
        let rep = prune_reinject_payloads(&d, &r, SystemTime::now()).unwrap();
        assert_eq!(rep, PruneReport::default());
        let _ = fs::remove_dir_all(&d);
    }

    #[test]
    fn bound_flags_need_one_flag() {
        let none = bound_flags("out", |_| Ok(None)).unwrap();
        assert_eq!(none, None);
        let some = bound_flags("out", |f| Ok((f == "out-max-count").then_some(3))).unwrap();
        assert_eq!(
            some,
            Some(Retention {
                max_count: Some(3),
                ..Default::default()
            })
        );
        let off = bound_flags("out", |f| Ok((f == "out-max-age-s").then_some(0))).unwrap();
        assert!(off.is_some_and(|r| r.is_unbounded()));
        assert!(bound_flags("out", |_| Err("bad".to_string())).is_err());
    }
}
