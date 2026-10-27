//! Crash-safe append-only journals of the control plane's persistent state
//! (`control_plane.state_dir`): the request-state journal
//! (`requests.journal`, owned by the main loop) and the replay store
//! (`nonces.journal`, owned by the listener threads).
//!
//! # Format (`robodr-cp-journal/v1`)
//!
//! UTF-8 text, one entry per line:
//!
//! ```text
//! <64 lower-case hex: SHA-256 of the JSON bytes> <one JSON object>\n
//! ```
//!
//! The first line is a header entry `{"t":"header","format":
//! "robodr-cp-journal/v1","kind":"requests"|"nonces"}`. serde_json never
//! writes a raw newline inside a value, so a line is exactly one entry.
//!
//! # Durability
//!
//! * **Append:** one `write` of the whole line, then `fdatasync`; the caller
//!   acts on the entry only after that returned.
//! * **Compaction:** the live state is written to a new file
//!   `<name>.tmp-<random>` (created exclusively, mode 0600, no symlink
//!   followed), fsynced, renamed over `<name>`, and the directory is
//!   fsynced; then appends continue on the new file. A crash before the
//!   rename leaves the old journal intact (the temp file is removed at the
//!   next open); after it, the new one, which holds the same live state.
//!   After the rename, appends always go to the new file; if the directory
//!   fsync failed (the rename might not survive a power loss), the journal
//!   refuses every append until it is reopened (fail closed).
//! * **A survived append failure** (short write on a full disk, an fsync
//!   error) is rolled back by cutting the file to its previous length, so
//!   no later line follows a fragment; if that fails too, the journal
//!   refuses every append until it is reopened.
//!
//! # Loading (what a crash or damage leaves behind)
//!
//! * **One** bad line after the last good line (with or without its
//!   newline) is a torn tail (a crash during an append, whose caller never
//!   acted on it): the file is truncated to the last good line, counted in
//!   [`Loaded::torn_bytes`]. A crash can leave no more than that one line:
//!   two or more bad lines at the end are damage (next point).
//! * A bad line (checksum, JSON, over [`MAX_LINE`]) **followed by** a good
//!   one cannot come from a crash (every append is synced before the next):
//!   storage damage or an edit. The damaged lines are skipped and counted
//!   ([`Loaded::damaged`]), the original file is copied to
//!   `quarantine/<name>.<unix ms>.damaged` and the journal is rewritten
//!   from the good entries. The caller reports it and falls back to a
//!   fail-safe state (see the nonce store's fence).
//!
//! The journal is operational state, not evidence: it is checksummed
//! against crashes and media errors, not signed. Every decision it holds is
//! also a signed black-box note; the black box stays the record.

use std::fs::File;
use std::io::{self, BufRead, BufReader, Read, Write};
use std::os::unix::fs::OpenOptionsExt;
use std::path::{Path, PathBuf};

use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};
use serde_json::Value;

use robodr_blackbox::crypto::{sha256, to_hex};

use super::fsutil::{self, fault};

/// Journal format name (header line).
pub const FORMAT: &str = "robodr-cp-journal/v1";
/// Longest line accepted (a longer one is damage).
pub const MAX_LINE: usize = 256 * 1024;
/// Largest journal file loaded.
pub const MAX_FILE_BYTES: u64 = 1024 * 1024 * 1024;

#[derive(Serialize, Deserialize)]
struct Header {
    t: String,
    format: String,
    kind: String,
}

/// What [`Journal::open`] found.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct Loaded<T> {
    /// The good entries, in order (header excluded).
    pub entries: Vec<T>,
    /// Bytes of a torn tail removed (a crash during an append).
    pub torn_bytes: u64,
    /// Damaged lines skipped (storage damage or an edit; see the module).
    pub damaged: usize,
    /// Where the damaged original was copied.
    pub quarantined: Option<PathBuf>,
    /// The journal did not exist and was created.
    pub created: bool,
}

/// An open journal: appends go to `name` in `dir`.
#[derive(Debug)]
pub struct Journal {
    dir: PathBuf,
    name: String,
    kind: String,
    file: File,
    /// Entries in the file (header excluded).
    lines: usize,
    /// File length after the last good append.
    len: u64,
    /// A failed append could not be rolled back: every later append fails
    /// (fail closed) until the next open repairs the file.
    poisoned: bool,
}

fn line_of(v: &impl Serialize) -> io::Result<Vec<u8>> {
    let json = serde_json::to_vec(v).map_err(io::Error::other)?;
    if json.contains(&b'\n') || json.len() > MAX_LINE - 66 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "journal entry too large",
        ));
    }
    let mut line = Vec::with_capacity(json.len() + 66);
    line.extend_from_slice(to_hex(&sha256(&json)).as_bytes());
    line.push(b' ');
    line.extend_from_slice(&json);
    line.push(b'\n');
    Ok(line)
}

/// Parse one line (without its newline): `Some(json)` if the checksum holds.
fn parse_line(line: &[u8]) -> Option<Value> {
    if line.len() < 66 || line.len() > MAX_LINE || line[64] != b' ' {
        return None;
    }
    let (sum, json) = (&line[..64], &line[65..]);
    let want = to_hex(&sha256(json));
    if !robodr_blackbox::crypto::ct_eq(want.as_bytes(), sum) {
        return None;
    }
    let v: Value = serde_json::from_slice(json).ok()?;
    v.is_object().then_some(v)
}

fn unix_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}

impl Journal {
    /// Open (or create) `dir/name`. `kind` names the journal in its header;
    /// a journal of another kind or format is refused. Entries that do not
    /// deserialize as `T` count as damaged.
    pub fn open<T: DeserializeOwned>(
        dir: &Path,
        name: &str,
        kind: &str,
    ) -> io::Result<(Journal, Loaded<T>)> {
        let path = dir.join(name);
        remove_stale_temps(dir, name);
        let mut loaded = Loaded {
            entries: Vec::new(),
            torn_bytes: 0,
            damaged: 0,
            quarantined: None,
            created: false,
        };
        let file = match fsutil::open_read_nofollow(&path) {
            Ok(f) => f,
            Err(e) if e.kind() == io::ErrorKind::NotFound => {
                let file = create_with_header(dir, name, kind)?;
                let len = file.metadata()?.len();
                let j = Journal {
                    dir: dir.to_path_buf(),
                    name: name.to_string(),
                    kind: kind.to_string(),
                    file,
                    lines: 0,
                    len,
                    poisoned: false,
                };
                loaded.created = true;
                return Ok((j, loaded));
            }
            Err(e) => return Err(e),
        };
        let len = file.metadata()?.len();
        if len > MAX_FILE_BYTES {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!("{} is larger than {MAX_FILE_BYTES} bytes", path.display()),
            ));
        }
        // One pass: the good lines, how many bad lines precede a good one
        // (damage) and where the last good line ends (the torn tail starts).
        let mut r = BufReader::new(file);
        let mut good: Vec<Value> = Vec::new();
        let mut damaged_lines: usize = 0;
        let mut pending_bad: usize = 0;
        let mut offset: u64 = 0;
        let mut good_end: u64 = 0;
        // An unterminated last line (a fragment).
        let mut fragment = false;
        let mut buf = Vec::new();
        loop {
            buf.clear();
            let n = r
                .by_ref()
                .take(MAX_LINE as u64 + 1)
                .read_until(b'\n', &mut buf)?;
            if n == 0 {
                break;
            }
            offset += n as u64;
            if buf.last() != Some(&b'\n') {
                if n > MAX_LINE {
                    // An over-long line: skip to its end; bad either way.
                    let mut rest = Vec::new();
                    let m = r.read_until(b'\n', &mut rest)?;
                    offset += m as u64;
                    if rest.last() == Some(&b'\n') {
                        pending_bad += 1;
                        continue;
                    }
                }
                // No newline before EOF.
                fragment = true;
                break;
            }
            match parse_line(&buf[..buf.len() - 1]) {
                Some(v) => {
                    damaged_lines += pending_bad;
                    pending_bad = 0;
                    good.push(v);
                    good_end = offset;
                }
                None => pending_bad += 1,
            }
        }
        // What follows the last good line. A crash during an append leaves
        // at most that one line, whole or not (every append is a single
        // write, synced before the next): one bad line is a torn tail. Two
        // or more cannot come from a crash: damage (review finding 4), so
        // synced entries are never forgotten silently.
        let tail_lines = pending_bad + usize::from(fragment);
        if tail_lines > 1 {
            damaged_lines += tail_lines;
        } else {
            loaded.torn_bytes = len.saturating_sub(good_end);
        }
        let mut values = good.into_iter().peekable();
        // The header must be the first good line.
        let mut header_missing = false;
        match values.peek() {
            Some(v) if v.get("t").and_then(Value::as_str) == Some("header") => {
                let h: Header = serde_json::from_value(values.next().unwrap_or(Value::Null))
                    .map_err(|_| {
                        io::Error::new(
                            io::ErrorKind::InvalidData,
                            format!("{}: malformed journal header", path.display()),
                        )
                    })?;
                if h.format != FORMAT || h.kind != kind {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        format!(
                            "{}: a {:?} journal of format {:?}, expected a {kind:?} journal of \
                             {FORMAT}",
                            path.display(),
                            robodr_ros2_pipeline::sanitize(&h.kind),
                            robodr_ros2_pipeline::sanitize(&h.format)
                        ),
                    ));
                }
            }
            Some(_) => header_missing = true,
            // Nothing good at all: a crash right after the create, or
            // everything damaged (counted above only if a good line
            // followed, so: a crash).
            None => {}
        }
        let mut kept: Vec<Value> = Vec::new();
        for v in values {
            match serde_json::from_value::<T>(v.clone()) {
                Ok(e) => {
                    loaded.entries.push(e);
                    kept.push(v);
                }
                Err(_) => damaged_lines += 1,
            }
        }
        if header_missing && damaged_lines == 0 {
            // Entries without a header: not something this code writes.
            damaged_lines = 1;
        }
        loaded.damaged = damaged_lines;
        if damaged_lines > 0 {
            let qdir = dir.join("quarantine");
            fsutil::create_dir_private(&qdir)?;
            let q = qdir.join(format!("{name}.{}.damaged", unix_ms()));
            let bytes = fsutil::read_capped_nofollow(&path, MAX_FILE_BYTES)?;
            let mut f = fsutil::create_new_private(&q)?;
            f.write_all(&bytes)?;
            f.sync_all()?;
            fsutil::sync_dir(&qdir)?;
            loaded.quarantined = Some(q);
        }
        let file = if damaged_lines > 0 || good_end == 0 {
            // Rewrite from the good entries (their exact JSON values).
            let (f, synced) = rewrite(dir, name, kind, &kept)?;
            synced?;
            f
        } else {
            if loaded.torn_bytes > 0 {
                let f = std::fs::OpenOptions::new()
                    .write(true)
                    .custom_flags(fsutil::O_NOFOLLOW)
                    .open(&path)?;
                f.set_len(good_end)?;
                f.sync_all()?;
            }
            fsutil::open_append_nofollow(&path)?
        };
        let len = file.metadata()?.len();
        let j = Journal {
            dir: dir.to_path_buf(),
            name: name.to_string(),
            kind: kind.to_string(),
            file,
            lines: kept.len(),
            len,
            poisoned: false,
        };
        Ok((j, loaded))
    }

    /// Entries in the file (header excluded).
    pub fn lines(&self) -> usize {
        self.lines
    }

    pub fn path(&self) -> PathBuf {
        self.dir.join(&self.name)
    }

    /// Append one entry and make it durable (`fdatasync`) before returning.
    ///
    /// On failure (a short write on a full disk, an fsync error) the file is
    /// cut back to its length before the append, so a later good line can
    /// never follow a fragment (which the next open would have to call
    /// damage); if even that fails, the journal refuses every further
    /// append until it is reopened.
    pub fn append<T: Serialize>(&mut self, entry: &T) -> io::Result<()> {
        if self.poisoned {
            return Err(io::Error::other(
                "the journal could not be rolled back after a failed append",
            ));
        }
        let line = line_of(entry)?;
        let res = (|| -> io::Result<()> {
            #[cfg(test)]
            for point in ["journal.append.torn", "survive.journal.append.short_write"] {
                if fault::hit(point).is_err() {
                    // Half the line reaches the file, then the write fails
                    // (the process dies, or lives on: a full disk).
                    let _ = self.file.write_all(&line[..line.len() / 2]);
                    return Err(io::Error::other(format!("injected failure at {point}")));
                }
            }
            self.file.write_all(&line)?;
            fault("journal.append.before_sync")?;
            self.file.sync_data()
        })();
        match res {
            Ok(()) => {
                self.lines += 1;
                self.len += line.len() as u64;
                Ok(())
            }
            Err(e) => {
                #[cfg(test)]
                if fault::fired() {
                    // A killed process does not clean up.
                    return Err(e);
                }
                if self
                    .file
                    .set_len(self.len)
                    .and_then(|()| self.file.sync_data())
                    .is_err()
                {
                    self.poisoned = true;
                }
                Err(e)
            }
        }
    }

    /// Replace the journal by `entries` (crash-safe, see the module).
    pub fn compact<T: Serialize>(&mut self, entries: &[T]) -> io::Result<()> {
        let values: Vec<Value> = entries
            .iter()
            .map(|e| serde_json::to_value(e).map_err(io::Error::other))
            .collect::<io::Result<_>>()?;
        let (file, synced) = rewrite(&self.dir, &self.name, &self.kind, &values)?;
        // The rename happened: from now on only the new file is the
        // journal (appending to the old handle would write into the
        // replaced inode). If the rename may not be durable (the directory
        // fsync failed), refuse every append until the next open.
        self.file = file;
        self.lines = values.len();
        self.len = self.file.metadata()?.len();
        self.poisoned = synced.is_err();
        synced
    }
}

/// Write `values` under a fresh header to a temp file, fsync, rename over
/// `dir/name`, fsync the directory. `Err` if the journal was not replaced;
/// otherwise the append handle of the new file and whether the directory
/// fsync (the rename's durability) succeeded.
fn rewrite(
    dir: &Path,
    name: &str,
    kind: &str,
    values: &[Value],
) -> io::Result<(File, io::Result<()>)> {
    let tmp = dir.join(format!("{name}.tmp-{}", fsutil::random_hex16()?));
    let res = (|| {
        let mut f = fsutil::create_new_private(&tmp)?;
        let mut out = line_of(&Header {
            t: "header".into(),
            format: FORMAT.into(),
            kind: kind.into(),
        })?;
        for v in values {
            out.extend_from_slice(&line_of(v)?);
        }
        f.write_all(&out)?;
        fault("journal.compact.before_sync")?;
        f.sync_all()?;
        fault("journal.compact.before_rename")?;
        std::fs::rename(&tmp, dir.join(name))
    })();
    if let Err(e) = res {
        #[cfg(test)]
        if fault::fired() {
            // A killed process leaves the temp file behind.
            return Err(e);
        }
        let _ = std::fs::remove_file(&tmp);
        return Err(e);
    }
    let synced = fault("journal.compact.before_dir_sync")
        .and_then(|()| fault("survive.journal.compact.dir_sync"))
        .and_then(|()| fsutil::sync_dir(dir));
    let file = fsutil::open_append_nofollow(&dir.join(name))?;
    Ok((file, synced))
}

fn create_with_header(dir: &Path, name: &str, kind: &str) -> io::Result<File> {
    let path = dir.join(name);
    let mut f = fsutil::create_new_private(&path)?;
    f.write_all(&line_of(&Header {
        t: "header".into(),
        format: FORMAT.into(),
        kind: kind.into(),
    })?)?;
    f.sync_all()?;
    fsutil::sync_dir(dir)?;
    drop(f);
    fsutil::open_append_nofollow(&path)
}

fn remove_stale_temps(dir: &Path, name: &str) {
    let prefix = format!("{name}.tmp-");
    if let Ok(rd) = std::fs::read_dir(dir) {
        for e in rd.flatten() {
            if e.file_name().to_string_lossy().starts_with(&prefix) {
                let _ = std::fs::remove_file(e.path());
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::control::fsutil::fault;

    #[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
    #[serde(deny_unknown_fields)]
    struct E {
        t: String,
        n: u64,
    }

    fn e(n: u64) -> E {
        E { t: "e".into(), n }
    }

    fn tmp(tag: &str) -> PathBuf {
        let d = std::env::temp_dir().join(format!("robodr-cp-j-{tag}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&d);
        std::fs::create_dir_all(&d).unwrap();
        d
    }

    fn open(d: &Path) -> (Journal, Loaded<E>) {
        Journal::open(d, "t.journal", "test").unwrap()
    }

    fn ns(l: &Loaded<E>) -> Vec<u64> {
        l.entries.iter().map(|e| e.n).collect()
    }

    fn temps(d: &Path) -> usize {
        std::fs::read_dir(d)
            .unwrap()
            .filter(|e| {
                e.as_ref()
                    .unwrap()
                    .file_name()
                    .to_string_lossy()
                    .contains(".tmp-")
            })
            .count()
    }

    #[test]
    fn appends_survive_a_reopen() {
        let d = tmp("basic");
        let (mut j, l) = open(&d);
        assert!(l.created);
        for n in 0..5 {
            j.append(&e(n)).unwrap();
        }
        drop(j);
        let (j, l) = open(&d);
        assert_eq!(ns(&l), [0, 1, 2, 3, 4]);
        assert_eq!((l.torn_bytes, l.damaged, l.created), (0, 0, false));
        assert_eq!(j.lines(), 5);
        // The file is the documented format.
        let text = std::fs::read_to_string(d.join("t.journal")).unwrap();
        let first = text.lines().next().unwrap();
        assert!(
            first.contains(r#""format":"robodr-cp-journal/v1""#),
            "{first}"
        );
        let (sum, json) = text.lines().nth(1).unwrap().split_once(' ').unwrap();
        assert_eq!(sum, to_hex(&sha256(json.as_bytes())));
        let _ = std::fs::remove_dir_all(&d);
    }

    /// Crash point: killed half-way through an append (before its fsync):
    /// the torn line is cut at the next open, the earlier entries stay,
    /// and appending continues on a clean file.
    #[test]
    fn crash_during_append_leaves_a_torn_tail_that_is_cut() {
        let d = tmp("torn");
        let (mut j, _) = open(&d);
        j.append(&e(1)).unwrap();
        fault::arm("journal.append.torn", 1);
        assert!(j.append(&e(2)).is_err());
        assert!(fault::fired());
        drop(j);
        let (mut j, l) = open(&d);
        assert_eq!(ns(&l), [1]);
        assert!(l.torn_bytes > 0);
        assert_eq!(l.damaged, 0, "a torn tail is a crash, not damage");
        j.append(&e(3)).unwrap();
        drop(j);
        let (_, l) = open(&d);
        assert_eq!(ns(&l), [1, 3]);
        assert_eq!(l.torn_bytes, 0);
        let _ = std::fs::remove_dir_all(&d);
    }

    /// Crash point: the line was written but the process died before the
    /// fsync returned. The caller never acted on it; the entry is either
    /// there whole (process crash: the page cache survives) or torn (power
    /// loss, previous test): never half-read.
    #[test]
    fn crash_between_write_and_fsync_keeps_a_whole_entry() {
        let d = tmp("nosync");
        let (mut j, _) = open(&d);
        j.append(&e(1)).unwrap();
        fault::arm("journal.append.before_sync", 1);
        assert!(j.append(&e(2)).is_err());
        drop(j);
        let (_, l) = open(&d);
        assert_eq!(ns(&l), [1, 2]);
        assert_eq!((l.torn_bytes, l.damaged), (0, 0));
        let _ = std::fs::remove_dir_all(&d);
    }

    /// Crash points of a compaction: before the temp file is synced, before
    /// the rename (old journal intact, temp file left over and removed at
    /// the next open), and after the rename before the directory fsync
    /// (the new journal: same live state).
    #[test]
    fn crash_during_compaction_never_loses_the_live_state() {
        for (point, expect) in [
            ("journal.compact.before_sync", vec![0, 1, 2, 3]),
            ("journal.compact.before_rename", vec![0, 1, 2, 3]),
            ("journal.compact.before_dir_sync", vec![2, 3]),
        ] {
            let d = tmp(&format!("compact-{point}"));
            let (mut j, _) = open(&d);
            for n in 0..4 {
                j.append(&e(n)).unwrap();
            }
            fault::arm(point, 1);
            assert!(j.compact(&[e(2), e(3)]).is_err(), "{point}");
            drop(j);
            let leftover = temps(&d);
            let (mut j, l) = open(&d);
            assert_eq!(ns(&l), expect, "{point}");
            assert_eq!((l.torn_bytes, l.damaged), (0, 0), "{point}");
            assert_eq!(temps(&d), 0, "{point}: temp file removed at open");
            if point != "journal.compact.before_dir_sync" {
                assert_eq!(leftover, 1, "{point}: a killed compaction leaves its temp");
            }
            // And a compaction that completes.
            j.compact(&[e(9)]).unwrap();
            j.append(&e(10)).unwrap();
            drop(j);
            let (_, l) = open(&d);
            assert_eq!(ns(&l), [9, 10], "{point}");
            let _ = std::fs::remove_dir_all(&d);
        }
    }

    /// A damaged line followed by good ones is not a crash: it is counted,
    /// the original is quarantined and the journal rewritten without it.
    #[test]
    fn damage_in_the_middle_is_quarantined_and_skipped() {
        let d = tmp("damage");
        let (mut j, _) = open(&d);
        for n in 0..4 {
            j.append(&e(n)).unwrap();
        }
        drop(j);
        let p = d.join("t.journal");
        let mut text = std::fs::read(&p).unwrap();
        // Flip one byte in the third line (entry n = 1).
        let starts: Vec<usize> = std::iter::once(0)
            .chain(
                text.iter()
                    .enumerate()
                    .filter(|(_, b)| **b == b'\n')
                    .map(|(i, _)| i + 1),
            )
            .collect();
        text[starts[2] + 70] ^= 0x01;
        std::fs::write(&p, &text).unwrap();
        let (_, l) = open(&d);
        assert_eq!(ns(&l), [0, 2, 3]);
        assert_eq!(l.damaged, 1);
        let q = l.quarantined.clone().expect("quarantined copy");
        assert_eq!(std::fs::read(&q).unwrap(), text);
        // Rewritten: the next open is clean.
        let (_, l) = open(&d);
        assert_eq!(ns(&l), [0, 2, 3]);
        assert_eq!((l.damaged, l.torn_bytes), (0, 0));
        // A line of another shape (valid checksum, wrong fields) is damage
        // too.
        let mut f = fsutil::open_append_nofollow(&p).unwrap();
        f.write_all(&line_of(&serde_json::json!({"t": "x", "zzz": 1})).unwrap())
            .unwrap();
        f.write_all(&line_of(&e(4)).unwrap()).unwrap();
        drop(f);
        let (_, l) = open(&d);
        assert_eq!(ns(&l), [0, 2, 3, 4]);
        assert_eq!(l.damaged, 1);
        let _ = std::fs::remove_dir_all(&d);
    }

    /// A failed append the process survives (a short write on a full disk,
    /// an fsync error) is rolled back: no fragment is left for a later
    /// line to follow, so the next open sees no damage.
    #[test]
    fn a_survived_append_failure_leaves_no_fragment() {
        let d = tmp("rollback");
        let (mut j, _) = open(&d);
        j.append(&e(1)).unwrap();
        let before = std::fs::read(d.join("t.journal")).unwrap();
        fault::arm("survive.journal.append.short_write", 1);
        assert!(j.append(&e(2)).is_err());
        assert!(!fault::fired());
        assert_eq!(std::fs::read(d.join("t.journal")).unwrap(), before);
        fault::arm("journal.append.before_sync", 1);
        // A failed fsync of a whole line: rolled back too (it is a death
        // point, so emulate the survivor's cleanup by reopening).
        assert!(j.append(&e(3)).is_err());
        drop(j);
        let (mut j, l) = open(&d);
        assert_eq!(ns(&l), [1, 3]);
        let big = serde_json::json!({"t": "e", "n": 1, "pad": "x".repeat(MAX_LINE)});
        assert!(j.append(&big).is_err());
        j.append(&e(4)).unwrap();
        drop(j);
        let (_, l) = open(&d);
        assert_eq!(ns(&l), [1, 3, 4]);
        assert_eq!((l.damaged, l.torn_bytes), (0, 0));
        let _ = std::fs::remove_dir_all(&d);
    }

    /// A compaction whose rename happened but whose directory fsync failed
    /// (and the process lives on): appends never go to the replaced file;
    /// the journal refuses them until it is reopened, which sees the new
    /// file.
    #[test]
    fn a_failed_directory_sync_after_the_rename_fails_closed() {
        let d = tmp("dirsync");
        let (mut j, _) = open(&d);
        j.append(&e(1)).unwrap();
        fault::arm("survive.journal.compact.dir_sync", 1);
        assert!(j.compact(&[e(2)]).is_err());
        assert!(!fault::fired());
        assert!(
            j.append(&e(3)).is_err(),
            "appends are refused once the rename may not be durable"
        );
        drop(j);
        let (mut j, l) = open(&d);
        assert_eq!(ns(&l), [2]);
        j.append(&e(4)).unwrap();
        drop(j);
        assert_eq!(ns(&open(&d).1), [2, 4]);
        let _ = std::fs::remove_dir_all(&d);
    }

    /// Review finding 4: only a single trailing line can be torn (every
    /// append is one synced write). Two or more bad lines at the end are
    /// damage: counted, quarantined, rewritten, so the caller falls back to
    /// its fail-safe state instead of silently forgetting synced entries.
    #[test]
    fn tail_damage_beyond_one_line_is_damage_not_a_torn_tail() {
        let corrupt_last = |p: &Path, k: usize| {
            let mut text = std::fs::read(p).unwrap();
            let starts: Vec<usize> = std::iter::once(0)
                .chain(
                    text.iter()
                        .enumerate()
                        .filter(|(_, b)| **b == b'\n')
                        .map(|(i, _)| i + 1),
                )
                .collect();
            // starts has one entry per line plus the end of the file.
            let lines = starts.len() - 1;
            for l in lines - k..lines {
                text[starts[l] + 70] ^= 0x01;
            }
            std::fs::write(p, &text).unwrap();
            text
        };
        // One bad last line: a torn tail, as before.
        let d = tmp("tail1");
        let (mut j, _) = open(&d);
        for n in 0..4 {
            j.append(&e(n)).unwrap();
        }
        drop(j);
        corrupt_last(&d.join("t.journal"), 1);
        let (_, l) = open(&d);
        assert_eq!(ns(&l), [0, 1, 2]);
        assert!(l.torn_bytes > 0);
        assert_eq!(l.damaged, 0);
        let _ = std::fs::remove_dir_all(&d);
        // Two bad last lines: damage.
        let d = tmp("tail2");
        let (mut j, _) = open(&d);
        for n in 0..4 {
            j.append(&e(n)).unwrap();
        }
        drop(j);
        let text = corrupt_last(&d.join("t.journal"), 2);
        let (_, l) = open(&d);
        assert_eq!(ns(&l), [0, 1]);
        assert_eq!(l.damaged, 2, "two bad trailing lines cannot be one crash");
        assert_eq!(l.torn_bytes, 0);
        let q = l.quarantined.clone().expect("quarantined copy");
        assert_eq!(std::fs::read(&q).unwrap(), text);
        let (_, l) = open(&d);
        assert_eq!((l.damaged, l.torn_bytes), (0, 0), "rewritten clean");
        let _ = std::fs::remove_dir_all(&d);
        // A bad whole line followed by an unterminated fragment: damage.
        let d = tmp("tail3");
        let (mut j, _) = open(&d);
        for n in 0..3 {
            j.append(&e(n)).unwrap();
        }
        drop(j);
        corrupt_last(&d.join("t.journal"), 1);
        let mut f = fsutil::open_append_nofollow(&d.join("t.journal")).unwrap();
        f.write_all(b"0123 {\"t\":").unwrap();
        drop(f);
        let (_, l) = open(&d);
        assert_eq!(ns(&l), [0, 1]);
        assert_eq!(l.damaged, 2);
        let _ = std::fs::remove_dir_all(&d);
    }

    #[test]
    fn hostile_files_are_handled() {
        // A journal of another kind is refused, not reinterpreted.
        let d = tmp("kind");
        drop(open(&d));
        let e2 = Journal::open::<E>(&d, "t.journal", "other").unwrap_err();
        assert!(e2.to_string().contains("expected"), "{e2}");
        let _ = std::fs::remove_dir_all(&d);
        // An empty file (killed right after creating it): started over.
        let d = tmp("empty");
        std::fs::write(d.join("t.journal"), b"").unwrap();
        let (mut j, l) = open(&d);
        assert!(l.entries.is_empty());
        j.append(&e(1)).unwrap();
        drop(j);
        assert_eq!(ns(&open(&d).1), [1]);
        let _ = std::fs::remove_dir_all(&d);
        // A symlink is never followed.
        let d = tmp("link");
        std::fs::write(d.join("target"), b"x").unwrap();
        std::os::unix::fs::symlink(d.join("target"), d.join("t.journal")).unwrap();
        assert!(Journal::open::<E>(&d, "t.journal", "test").is_err());
        assert_eq!(std::fs::read(d.join("target")).unwrap(), b"x");
        let _ = std::fs::remove_dir_all(&d);
        // An over-long line in the middle is damage, garbage at the end a
        // torn tail.
        let d = tmp("long");
        let (mut j, _) = open(&d);
        j.append(&e(1)).unwrap();
        drop(j);
        let p = d.join("t.journal");
        let mut f = fsutil::open_append_nofollow(&p).unwrap();
        f.write_all(&vec![b'a'; MAX_LINE + 10]).unwrap();
        f.write_all(b"\n").unwrap();
        f.write_all(&line_of(&e(2)).unwrap()).unwrap();
        f.write_all(b"garbage without newline").unwrap();
        drop(f);
        let (_, l) = open(&d);
        assert_eq!(ns(&l), [1, 2]);
        assert_eq!(l.damaged, 1);
        let _ = std::fs::remove_dir_all(&d);
    }
}
