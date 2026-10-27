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
//! shift to `.2`, ...; files past `keep` are deleted). Deduplication reads
//! the current file and every rotated file present, so it covers the kept
//! history; a record whose entry was rotated out may be dead-lettered once
//! more.

use crate::fsutil;
use serde::{Deserialize, Serialize};
use std::collections::hash_map::DefaultHasher;
use std::collections::HashSet;
use std::fs;
use std::hash::{Hash, Hasher};
use std::io::{self, BufRead, BufReader};
use std::path::{Path, PathBuf};

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
    /// Rotated files kept (`<name>.1` .. `<name>.<keep>`), at least 1.
    pub keep: u32,
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
                self.rotate(r.keep)?;
            }
        }
        fsutil::append_durable(&self.path(), line)?;
        if let Some(s) = self.seen.as_mut() {
            s.insert(dead_key(source, pos));
        }
        self.stats.entries += 1;
        Ok(true)
    }

    /// `<name>` → `<name>.1`, `.i` → `.i+1`; files past `keep` deleted.
    fn rotate(&mut self, keep: u32) -> io::Result<()> {
        let keep = keep.max(1);
        let rotated = |i: u32| self.dir.join(format!("{}.{i}", self.name));
        // Past `keep` (also left over from a larger earlier `keep`).
        for p in files(&self.dir, &self.name)? {
            if let Some(i) = p
                .file_name()
                .and_then(|f| f.to_str())
                .and_then(|f| rotated_index(f, &self.name))
            {
                if i >= keep {
                    fs::remove_file(&p)?;
                }
            }
        }
        for i in (1..keep).rev() {
            match fs::rename(rotated(i), rotated(i + 1)) {
                Ok(()) => {}
                Err(e) if e.kind() == io::ErrorKind::NotFound => {}
                Err(e) => return Err(e),
            }
        }
        fs::rename(self.path(), rotated(1))?;
        fsutil::fsync_dir(&self.dir)?;
        // The dedup set keeps the keys of the deleted file until the next
        // load; that only suppresses re-appending records already dead-
        // lettered, which is the intent.
        Ok(())
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
        let names: Vec<String> = files(&d, "dl.jsonl")
            .unwrap()
            .iter()
            .map(|p| p.file_name().unwrap().to_string_lossy().into_owned())
            .collect();
        assert_eq!(names, ["dl.jsonl.2", "dl.jsonl.1", "dl.jsonl"]);
        // 7 entries, 2 per file: the current file holds 7, .1 holds 5-6,
        // .2 holds 3-4; 1-2 were rotated out.
        let mut fresh = DeadLetters::new(&d, "dl.jsonl", Some(rot));
        assert_eq!(fresh.stats().unwrap().entries, 5);
        for i in 3..=7 {
            assert!(fresh.contains("src", i).unwrap(), "{i}");
        }
        assert!(!fresh.contains("src", 1).unwrap());
        // Files past `keep` (e.g. after lowering it) are removed on the
        // next rotation; unrelated names are ignored.
        fs::write(d.join("dl.jsonl.9"), entry("src", 99)).unwrap();
        fs::write(d.join("dl.jsonl.01"), b"x").unwrap();
        fs::write(d.join("dl.jsonl.tmp"), b"x").unwrap();
        let mut dl = DeadLetters::new(&d, "dl.jsonl", Some(rot));
        assert!(dl.contains("src", 99).unwrap());
        for i in 8..=9 {
            dl.append("src", i, &entry("src", i)).unwrap();
        }
        assert!(!d.join("dl.jsonl.9").exists());
        assert!(d.join("dl.jsonl.01").exists() && d.join("dl.jsonl.tmp").exists());
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
