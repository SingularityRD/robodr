//! Dead-letter files (`<state>/dead-letter.jsonl`), shared by
//! `robodr-kafka-publish` ([`crate::publish`]) and `robodr-uplink`
//! ([`crate::uplink`]).
//!
//! One JSON object per line, appended with [`fsutil::append_durable`]
//! (fsynced; a torn last line is closed before the next append, so it can
//! never swallow the next entry). Every entry carries at least `source` and
//! `position`; entries are deduplicated on that pair, so a record
//! dead-lettered again after a crash (its progress was not saved) is not
//! appended twice.
//!
//! **Malformed lines are counted, not skipped silently**: a line that is not
//! a JSON object with a string `source` and an integer `position` (a torn
//! fragment after a crash, an edited file) is reported in [`LoadStats`];
//! the callers log the count (and `robodr-uplink` puts it in its status
//! file). Its record can no longer be deduplicated, so at worst it is
//! dead-lettered once more.
//!
//! **Rotation** (optional, [`Rotation`]): when an append would take the
//! current file over `max_bytes`, it is renamed to `<name>.1` (older ones
//! shift to `.2`, ...). Deduplication reads the current file and every
//! rotated file present, so it covers the kept history.
//!
//! **Retention** ([`DeadLetters::prune`], called by the exporters after
//! every run): rotated files beyond `keep`, or over a
//! [`Retention`](crate::retention::Retention) (age, count, total bytes),
//! are deleted **only when none of their entries is still needed for
//! deduplication**: an entry is needed while its record may be processed
//! again (the caller decides: its diode batch is not done yet, its spool
//! file is still in `ready/`, its re-injected generation is not done). A
//! file holding such an entry is kept (reported as held) and looked at
//! again on the next run, so deduplication never loses an entry it still
//! needs: once a record cannot come back, its entry protects nothing, and
//! deleting it cannot cause a second dead letter. The current file is never
//! deleted. Malformed lines carry no key and protect nothing either.
//! Every deleted file that held entries is **logged on stderr** with its
//! entry count and counted in [`PruneReport::removed_entries`]: a dead
//! letter may be the only copy of its record. (`robodr-kafka-publish` does
//! not rotate by default, so nothing is deleted unless an operator opts
//! in.)

use crate::fsutil;
use crate::retention::{file_meta, Candidate, PruneReport, Retention};
use serde::{Deserialize, Serialize};
use std::collections::hash_map::DefaultHasher;
use std::collections::HashSet;
use std::fs;
use std::hash::{Hash, Hasher};
use std::io::{self, BufRead, BufReader};
use std::path::{Path, PathBuf};
use std::time::SystemTime;

/// 128-bit key of a dead-letter entry: `(source, position)`.
pub(crate) fn dead_key(source: &str, pos: u64) -> u128 {
    let h = |salt: u8| {
        let mut st = DefaultHasher::new();
        salt.hash(&mut st);
        source.hash(&mut st);
        pos.hash(&mut st);
        st.finish()
    };
    (u128::from(h(1)) << 64) | u128::from(h(2))
}

/// Size-based rotation of a dead-letter file.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Rotation {
    /// Rotate when an append would take the current file past this size.
    pub max_bytes: u64,
    /// Rotated files kept (`<name>.1` .. `<name>.<keep>`), at least 1;
    /// older ones are deleted by [`DeadLetters::prune`] once no entry of
    /// theirs is needed any more.
    pub keep: u32,
}

/// Smallest rotation size (a single larger entry is still written whole:
/// rotation happens before an append, never inside one).
pub const MIN_ROTATION_BYTES: u64 = 64 * 1024;

/// Default rotation: 64 MiB per file, 4 rotated files kept.
pub const DEFAULT_ROTATION: Rotation = Rotation {
    max_bytes: 64 * 1024 * 1024,
    keep: 4,
};

impl Rotation {
    /// `keep >= 1` and `max_bytes >=` [`MIN_ROTATION_BYTES`].
    pub fn is_valid(&self) -> bool {
        self.keep >= 1 && self.max_bytes >= MIN_ROTATION_BYTES
    }
}

/// What loading the dead-letter files found.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq, Serialize)]
pub struct LoadStats {
    /// Well-formed entries (current and rotated files).
    pub entries: u64,
    /// Lines that are not a `{source, position, ...}` object (torn
    /// fragments, edits): counted, their records cannot be deduplicated.
    pub malformed: u64,
    /// Files read.
    pub files: u64,
}

#[derive(Deserialize)]
struct KeyFields {
    source: String,
    position: u64,
}

/// One entry's dedup key, if the line is well formed.
fn line_key(line: &[u8]) -> Option<u128> {
    serde_json::from_slice::<KeyFields>(line)
        .ok()
        .map(|k| dead_key(&k.source, k.position))
}

/// Index of a rotated file name `<name>.<n>` (`n` ≥ 1, decimal).
fn rotated_index(file: &str, name: &str) -> Option<u32> {
    let n = file.strip_prefix(name)?.strip_prefix('.')?;
    if n.is_empty() || n.len() > 9 || !n.bytes().all(|b| b.is_ascii_digit()) || n.starts_with('0') {
        return None;
    }
    n.parse().ok()
}

/// The dead-letter files of `name` in `dir` that exist, oldest first: the
/// rotated ones (highest index first), then the current one.
pub fn files(dir: &Path, name: &str) -> io::Result<Vec<PathBuf>> {
    let mut rotated = Vec::new();
    let rd = match fs::read_dir(dir) {
        Ok(rd) => rd,
        Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(Vec::new()),
        Err(e) => return Err(e),
    };
    for e in rd {
        let e = e?;
        let Some(f) = e.file_name().to_str().map(str::to_string) else {
            continue;
        };
        if let Some(i) = rotated_index(&f, name) {
            if e.file_type()?.is_file() {
                rotated.push((i, e.path()));
            }
        }
    }
    rotated.sort_by_key(|x| std::cmp::Reverse(x.0));
    let mut out: Vec<PathBuf> = rotated.into_iter().map(|(_, p)| p).collect();
    let cur = dir.join(name);
    if fs::symlink_metadata(&cur).is_ok_and(|m| m.file_type().is_file()) {
        out.push(cur);
    }
    Ok(out)
}

/// Call `f` with every line (without its LF) of every dead-letter file,
/// oldest first. A last line without LF (a torn fragment) is passed too.
pub fn for_each_line(
    dir: &Path,
    name: &str,
    mut f: impl FnMut(&Path, &[u8]) -> io::Result<()>,
) -> io::Result<u64> {
    let paths = files(dir, name)?;
    for p in &paths {
        let file = match fs::File::open(p) {
            Ok(x) => x,
            // Rotated away meanwhile (another process cannot write here:
            // the state directory is locked; be lenient anyway).
            Err(e) if e.kind() == io::ErrorKind::NotFound => continue,
            Err(e) => return Err(e),
        };
        for line in BufReader::new(file).split(b'\n') {
            f(p, &line?)?;
        }
    }
    Ok(paths.len() as u64)
}

/// A dead-letter file with its dedup set (loaded on first use).
#[derive(Debug)]
pub struct DeadLetters {
    dir: PathBuf,
    name: String,
    rotation: Option<Rotation>,
    seen: Option<HashSet<u128>>,
    stats: LoadStats,
}

impl DeadLetters {
    pub fn new(dir: &Path, name: &str, rotation: Option<Rotation>) -> Self {
        Self {
            dir: dir.to_path_buf(),
            name: name.to_string(),
            rotation,
            seen: None,
            stats: LoadStats::default(),
        }
    }

    /// The current file.
    pub fn path(&self) -> PathBuf {
        self.dir.join(&self.name)
    }

    fn load(&mut self) -> io::Result<()> {
        if self.seen.is_some() {
            return Ok(());
        }
        let mut seen = HashSet::new();
        let mut st = LoadStats::default();
        st.files = for_each_line(&self.dir, &self.name, |_, line| {
            match line_key(line) {
                Some(k) => {
                    seen.insert(k);
                    st.entries += 1;
                }
                // An empty line (only possible from an edit) is malformed
                // too: the writer never produces one.
                None => st.malformed += 1,
            }
            Ok(())
        })?;
        self.seen = Some(seen);
        self.stats = st;
        Ok(())
    }

    /// Load (once) and return what the files hold.
    pub fn stats(&mut self) -> io::Result<LoadStats> {
        self.load()?;
        Ok(self.stats)
    }

    /// Whether `(source, position)` already has an entry.
    pub fn contains(&mut self, source: &str, pos: u64) -> io::Result<bool> {
        self.load()?;
        Ok(self
            .seen
            .as_ref()
            .is_some_and(|s| s.contains(&dead_key(source, pos))))
    }

    /// Append `line` (one JSON object + LF) for `(source, position)` unless
    /// an entry exists. `Ok(false)`: deduplicated, nothing written.
    pub fn append(&mut self, source: &str, pos: u64, line: &[u8]) -> io::Result<bool> {
        if self.contains(source, pos)? {
            return Ok(false);
        }
        if let Some(r) = self.rotation {
            let cur = self.path();
            let size = match fs::symlink_metadata(&cur) {
                Ok(m) => m.len(),
                Err(e) if e.kind() == io::ErrorKind::NotFound => 0,
                Err(e) => return Err(e),
            };
            if size > 0 && size.saturating_add(line.len() as u64) > r.max_bytes {
                self.rotate()?;
            }
        }
        fsutil::append_durable(&self.path(), line)?;
        if let Some(s) = self.seen.as_mut() {
            s.insert(dead_key(source, pos));
        }
        self.stats.entries += 1;
        Ok(true)
    }

    /// The rotated files present, `(index, path)`, highest index (oldest)
    /// first.
    fn rotated(&self) -> io::Result<Vec<(u32, PathBuf)>> {
        let mut v: Vec<(u32, PathBuf)> = files(&self.dir, &self.name)?
            .into_iter()
            .filter_map(|p| {
                let i = p
                    .file_name()
                    .and_then(|f| f.to_str())
                    .and_then(|f| rotated_index(f, &self.name))?;
                Some((i, p))
            })
            .collect();
        v.sort_by_key(|x| std::cmp::Reverse(x.0));
        Ok(v)
    }

    /// `<name>` → `<name>.1`, every `.i` → `.i+1` (highest first, so no
    /// rename ever replaces a file; a crash in between leaves a gap in the
    /// indices, which [`files`] tolerates). Nothing is deleted here: see
    /// [`DeadLetters::prune`].
    fn rotate(&mut self) -> io::Result<()> {
        for (i, p) in self.rotated()? {
            let to = self
                .dir
                .join(format!("{}.{}", self.name, i.saturating_add(1)));
            match fs::rename(&p, &to) {
                Ok(()) => {}
                Err(e) if e.kind() == io::ErrorKind::NotFound => {}
                Err(e) => return Err(e),
            }
        }
        fs::rename(self.path(), self.dir.join(format!("{}.1", self.name)))?;
        fsutil::fsync_dir(&self.dir)
    }

    /// Delete rotated files beyond the rotation's `keep` or over `r`
    /// (oldest first), except those holding an entry for which `needed`
    /// (`(source, position)`) says the record may still be processed again
    /// (see the module docs). Without rotation, only `r` applies.
    pub fn prune(
        &mut self,
        r: &Retention,
        now: SystemTime,
        mut needed: impl FnMut(&str, u64) -> io::Result<bool>,
    ) -> io::Result<PruneReport> {
        let mut bounds = *r;
        if let Some(rot) = self.rotation {
            let keep = u64::from(rot.keep.max(1));
            bounds.max_count = Some(bounds.max_count.map_or(keep, |c| c.min(keep)));
        }
        let mut candidates = Vec::new();
        for (_, p) in self.rotated()? {
            if let Some((modified, bytes)) = file_meta(&p)? {
                candidates.push(Candidate {
                    name: p.display().to_string(),
                    paths: vec![p],
                    modified,
                    bytes,
                });
            }
        }
        // Rotation order, not modification time, says which file is older
        // (a file rotated in the same second as another has the same
        // time): give each the oldest time of itself and the newer ones.
        let mut newest = None::<SystemTime>;
        for c in candidates.iter_mut().rev() {
            let t = newest.map_or(c.modified, |n: SystemTime| n.min(c.modified));
            c.modified = t;
            newest = Some(t);
        }
        let cur = self.path();
        // Files approved for deletion, with their entries (logged below).
        let mut doomed: Vec<(PathBuf, u64)> = Vec::new();
        let res = crate::retention::prune(&self.dir, &candidates, &bounds, now, |c| {
            let mut still = false;
            let mut entries = 0u64;
            for p in &c.paths {
                if *p == cur {
                    return Ok(false);
                }
                let file = match fs::File::open(p) {
                    Ok(f) => f,
                    Err(e) if e.kind() == io::ErrorKind::NotFound => continue,
                    Err(e) => return Err(e),
                };
                for line in BufReader::new(file).split(b'\n') {
                    let line = line?;
                    if let Ok(k) = serde_json::from_slice::<KeyFields>(&line) {
                        entries += 1;
                        if needed(&k.source, k.position)? {
                            still = true;
                            break;
                        }
                    }
                }
            }
            if !still {
                if let Some(p) = c.paths.first() {
                    doomed.push((p.clone(), entries));
                }
            }
            Ok(!still)
        });
        // Deleting dead letters destroys records (often their only copy):
        // never quietly. Logged for whatever was approved, even if a later
        // deletion failed.
        let mut removed_entries = 0u64;
        for (p, n) in &doomed {
            if *n > 0 && fs::symlink_metadata(p).is_err() {
                removed_entries += n;
                eprintln!(
                    "robodr-export: WARNING: deleted rotated dead-letter file {} holding {n} \
                     dead-lettered record(s) (retention: rotation keep / dead-letter bounds); \
                     these records may have had no other copy",
                    p.display()
                );
            }
        }
        let mut rep = res?;
        rep.removed_entries = removed_entries;
        Ok(rep)
        // The dedup set keeps the keys of deleted files until the next
        // load; that only suppresses re-appending records already
        // dead-lettered, which is the intent.
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tmp(tag: &str) -> PathBuf {
        let d = std::env::temp_dir().join(format!("robodr-dl-{tag}-{}", std::process::id()));
        let _ = fs::remove_dir_all(&d);
        fsutil::mkdir(&d).unwrap();
        d
    }

    fn entry(source: &str, pos: u64) -> Vec<u8> {
        let mut l =
            serde_json::to_vec(&serde_json::json!({"source": source, "position": pos})).unwrap();
        l.push(b'\n');
        l
    }

    #[test]
    fn dead_keys_distinguish_source_and_position() {
        assert_eq!(dead_key("a", 1), dead_key("a", 1));
        assert_ne!(dead_key("a", 1), dead_key("a", 2));
        assert_ne!(dead_key("a", 1), dead_key("b", 1));
    }

    /// Malformed lines (a torn fragment, garbage, an empty line) are
    /// counted; a torn fragment does not hide the entry appended after it.
    #[test]
    fn malformed_lines_are_counted_and_torn_lines_do_not_hide_entries() {
        let d = tmp("malformed");
        let p = d.join("dead-letter.jsonl");
        let mut body = entry("s", 1);
        body.extend_from_slice(b"garbage\n\n");
        body.extend_from_slice(b"{\"source\":\"s\",\"posi");
        fs::write(&p, &body).unwrap();
        let mut dl = DeadLetters::new(&d, "dead-letter.jsonl", None);
        assert!(dl.append("s", 2, &entry("s", 2)).unwrap());
        assert!(!dl.append("s", 1, &entry("s", 1)).unwrap(), "dedup");
        // A fresh load sees entry 2 (not merged into the fragment).
        let mut again = DeadLetters::new(&d, "dead-letter.jsonl", None);
        assert_eq!(
            again.stats().unwrap(),
            LoadStats {
                entries: 2,
                malformed: 3,
                files: 1
            }
        );
        assert!(again.contains("s", 2).unwrap());
        assert!(!again.append("s", 2, &entry("s", 2)).unwrap());
        let _ = fs::remove_dir_all(&d);
    }

    #[test]
    fn rotation_keeps_n_files_and_dedup_reads_them() {
        let d = tmp("rotate");
        let one = entry("src", 1).len() as u64;
        let rot = Rotation {
            max_bytes: one * 2,
            keep: 2,
        };
        let mut dl = DeadLetters::new(&d, "dl.jsonl", Some(rot));
        for i in 1..=7 {
            assert!(dl.append("src", i, &entry("src", i)).unwrap());
        }
        let names = |d: &Path| -> Vec<String> {
            files(d, "dl.jsonl")
                .unwrap()
                .iter()
                .map(|p| p.file_name().unwrap().to_string_lossy().into_owned())
                .collect()
        };
        // Rotation itself deletes nothing; pruning removes what is past
        // `keep` (nothing is needed here).
        assert_eq!(
            names(&d),
            ["dl.jsonl.3", "dl.jsonl.2", "dl.jsonl.1", "dl.jsonl"]
        );
        let rep = dl
            .prune(&Retention::UNBOUNDED, SystemTime::now(), |_, _| Ok(false))
            .unwrap();
        assert_eq!((rep.removed, rep.held), (1, 0));
        assert_eq!(rep.removed_entries, 2, "entries 1-2 went with .3");
        assert_eq!(names(&d), ["dl.jsonl.2", "dl.jsonl.1", "dl.jsonl"]);
        // 7 entries, 2 per file: the current file holds 7, .1 holds 5-6,
        // .2 holds 3-4; 1-2 were rotated out.
        let mut fresh = DeadLetters::new(&d, "dl.jsonl", Some(rot));
        assert_eq!(fresh.stats().unwrap().entries, 5);
        for i in 3..=7 {
            assert!(fresh.contains("src", i).unwrap(), "{i}");
        }
        assert!(!fresh.contains("src", 1).unwrap());
        // Files past `keep` (e.g. after lowering it) are removed by the
        // next prune; unrelated names are ignored.
        fs::write(d.join("dl.jsonl.9"), entry("src", 99)).unwrap();
        fs::write(d.join("dl.jsonl.01"), b"x").unwrap();
        fs::write(d.join("dl.jsonl.tmp"), b"x").unwrap();
        let mut dl = DeadLetters::new(&d, "dl.jsonl", Some(rot));
        assert!(dl.contains("src", 99).unwrap());
        for i in 8..=9 {
            dl.append("src", i, &entry("src", i)).unwrap();
        }
        dl.prune(&Retention::UNBOUNDED, SystemTime::now(), |_, _| Ok(false))
            .unwrap();
        assert!(!d.join("dl.jsonl.9").exists() && !d.join("dl.jsonl.10").exists());
        assert_eq!(names(&d), ["dl.jsonl.2", "dl.jsonl.1", "dl.jsonl"]);
        assert!(d.join("dl.jsonl.01").exists() && d.join("dl.jsonl.tmp").exists());
        let _ = fs::remove_dir_all(&d);
    }

    /// A rotated file whose entries may still be needed for deduplication
    /// (their records can be processed again) is held, whatever the
    /// bounds; once they are not, it goes. The current file never goes.
    #[test]
    fn prune_holds_files_still_needed_for_dedup() {
        let d = tmp("prune-needed");
        let one = entry("batch-a", 1).len() as u64;
        let rot = Rotation {
            max_bytes: one,
            keep: 1,
        };
        let mut dl = DeadLetters::new(&d, "dl.jsonl", Some(rot));
        // One entry per file: a1 (.3), a2 (.2), b1 (.1), b2 (current).
        for (s, p) in [
            ("batch-a", 1),
            ("batch-a", 2),
            ("batch-b", 1),
            ("batch-b", 2),
        ] {
            dl.append(s, p, &entry(s, p)).unwrap();
        }
        assert_eq!(files(&d, "dl.jsonl").unwrap().len(), 4);
        // batch-a is not done yet: its files are held; batch-b's rotated
        // file (too old, not needed) goes.
        let later = SystemTime::now() + std::time::Duration::from_secs(86_400 * 30);
        let age = Retention::max_age(std::time::Duration::from_secs(86_400));
        let rep = dl.prune(&age, later, |s, _| Ok(s == "batch-a")).unwrap();
        assert_eq!((rep.removed, rep.held), (1, 2), "{rep:?}");
        assert!(
            !d.join("dl.jsonl.1").exists(),
            "batch-b, too old, not needed"
        );
        assert!(d.join("dl.jsonl.3").exists() && d.join("dl.jsonl.2").exists());
        // A fresh load still deduplicates batch-a's entries.
        let mut fresh = DeadLetters::new(&d, "dl.jsonl", Some(rot));
        assert!(!fresh.append("batch-a", 1, &entry("batch-a", 1)).unwrap());
        // batch-a done: everything past the bounds goes, except the
        // current file.
        let rep = fresh.prune(&age, later, |_, _| Ok(false)).unwrap();
        assert_eq!((rep.removed, rep.held), (2, 0));
        assert_eq!(files(&d, "dl.jsonl").unwrap(), vec![d.join("dl.jsonl")]);
        // An error from the predicate is reported, nothing deleted.
        for (s, p) in [("batch-c", 1), ("batch-c", 2), ("batch-c", 3)] {
            fresh.append(s, p, &entry(s, p)).unwrap();
        }
        let before = files(&d, "dl.jsonl").unwrap();
        let e = fresh.prune(&age, later, |_, _| Err(io::Error::other("boom")));
        assert!(e.is_err());
        assert_eq!(files(&d, "dl.jsonl").unwrap(), before);
        let _ = fs::remove_dir_all(&d);
    }

    #[test]
    fn rotated_names() {
        assert_eq!(rotated_index("x.jsonl.1", "x.jsonl"), Some(1));
        assert_eq!(rotated_index("x.jsonl.12", "x.jsonl"), Some(12));
        for bad in [
            "x.jsonl",
            "x.jsonl.",
            "x.jsonl.0",
            "x.jsonl.01",
            "x.jsonl.1a",
            "y.1",
        ] {
            assert_eq!(rotated_index(bad, "x.jsonl"), None, "{bad}");
        }
    }
}
