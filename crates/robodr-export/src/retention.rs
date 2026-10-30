//! Bounded retention of the exporters' bookkeeping files: `done/` markers
//! (`robodr-kafka-publish`, `robodr-uplink`), rotated dead-letter files
//! (both, [`crate::deadletter`]) and rejected spool records
//! (`robodr-spool-export`).
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
use serde::Serialize;
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
}

impl PruneReport {
    pub fn add(&mut self, o: PruneReport) {
        self.removed += o.removed;
        self.removed_bytes += o.removed_bytes;
        self.held += o.held;
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
}
