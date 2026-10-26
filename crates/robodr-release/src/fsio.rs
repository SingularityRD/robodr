//! File-system helpers for reading untrusted trees (removable media, an
//! inbound diode drop) and writing outputs without clobbering anything.
//!
//! * Reads refuse symlinks and anything that is not a regular file, check
//!   that the opened file is the one that was `lstat`ed (no swap between
//!   the check and the open), and stop at a hard size cap.
//! * [`walk`] lists a tree exactly: every regular file and directory, by
//!   UTF-8 relative path; a symlink, device, socket, FIFO or non-UTF-8 name
//!   anywhere is an error, never skipped.
//! * Outputs are written next to their destination and renamed into place
//!   ([`write_replace`]), or created exclusively ([`write_new`]).

use robodr_pkg::{Code, Refusal};
use std::collections::BTreeSet;
use std::fs::{self, File, OpenOptions};
use std::io::{self, Read, Write};
use std::os::unix::fs::MetadataExt;
use std::path::{Path, PathBuf};

/// Most entries (files and directories) [`walk`] lists: a bundle's file
/// cap plus room for its directories.
pub const MAX_ENTRIES: usize = robodr_pkg::bundle::MAX_FILES + robodr_pkg::bundle::MAX_RPKS * 2 + 2;

/// Buffer for streaming hashes and copies.
pub const IO_BUF: usize = 1024 * 1024;

/// Why an operation failed: a refusal of the content, or an I/O problem
/// of this host.
#[derive(Debug)]
pub enum Fail {
    Refused(Refusal),
    Io(String),
}

impl std::fmt::Display for Fail {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Fail::Refused(r) => write!(f, "{r}"),
            Fail::Io(e) => write!(f, "error: {e}"),
        }
    }
}

impl From<Refusal> for Fail {
    fn from(r: Refusal) -> Self {
        Fail::Refused(r)
    }
}

/// An I/O error on `path`.
pub fn io_err(path: &Path, e: impl std::fmt::Display) -> Fail {
    Fail::Io(format!("{}: {e}", path.display()))
}

fn refuse(code: Code, path: &Path, what: &str) -> Fail {
    Fail::Refused(Refusal::new(code, format!("{}: {what}", path.display())))
}

/// Open a regular file for reading, refusing symlinks and special files,
/// and verifying the opened file is the `lstat`ed one.
pub fn open_regular(path: &Path) -> Result<(File, u64), Fail> {
    let meta = match fs::symlink_metadata(path) {
        Ok(m) => m,
        Err(e) if e.kind() == io::ErrorKind::NotFound => {
            return Err(refuse(Code::MissingFile, path, "missing"))
        }
        Err(e) => return Err(io_err(path, e)),
    };
    if !meta.file_type().is_file() {
        return Err(refuse(
            Code::FileMismatch,
            path,
            "not a regular file (symlink, directory or special file)",
        ));
    }
    let f = File::open(path).map_err(|e| io_err(path, e))?;
    let m2 = f.metadata().map_err(|e| io_err(path, e))?;
    if m2.dev() != meta.dev() || m2.ino() != meta.ino() || !m2.is_file() {
        return Err(refuse(
            Code::FileMismatch,
            path,
            "changed while being opened",
        ));
    }
    Ok((f, m2.len()))
}

/// Read a whole regular file of at most `max` bytes.
pub fn read_capped(path: &Path, max: usize) -> Result<Vec<u8>, Fail> {
    let (f, len) = open_regular(path)?;
    if len > max as u64 {
        return Err(refuse(
            Code::TooLarge,
            path,
            &format!("{len} bytes > {max}"),
        ));
    }
    let mut v = Vec::with_capacity(len as usize);
    f.take(max as u64 + 1)
        .read_to_end(&mut v)
        .map_err(|e| io_err(path, e))?;
    if v.len() > max {
        return Err(refuse(
            Code::TooLarge,
            path,
            &format!("grew past {max} bytes"),
        ));
    }
    Ok(v)
}

/// Size and hex SHA-256 of a regular file, streaming.
pub fn hash_file(path: &Path) -> Result<(u64, String), Fail> {
    let (mut f, _) = open_regular(path)?;
    let mut h = robodr_blackbox::crypto::Sha256::new();
    let mut buf = vec![0u8; IO_BUF];
    let mut n: u64 = 0;
    loop {
        let r = f.read(&mut buf).map_err(|e| io_err(path, e))?;
        if r == 0 {
            break;
        }
        h.update(&buf[..r]);
        n += r as u64;
    }
    Ok((n, robodr_blackbox::crypto::to_hex(&h.finalize())))
}

/// Every file and directory under `root` (relative, `/`-separated paths),
/// refusing symlinks, special files and non-UTF-8 names.
#[derive(Debug, Default)]
pub struct Tree {
    pub files: BTreeSet<String>,
    pub dirs: BTreeSet<String>,
}

/// List `root` exactly (see [`Tree`]). `root` itself must be a real
/// directory.
pub fn walk(root: &Path) -> Result<Tree, Fail> {
    let meta = fs::symlink_metadata(root).map_err(|e| io_err(root, e))?;
    if !meta.file_type().is_dir() {
        return Err(refuse(Code::FileMismatch, root, "not a directory"));
    }
    let mut t = Tree::default();
    let mut stack = vec![(root.to_path_buf(), String::new())];
    while let Some((dir, rel)) = stack.pop() {
        let mut entries = Vec::new();
        for e in fs::read_dir(&dir).map_err(|e| io_err(&dir, e))? {
            entries.push(e.map_err(|e| io_err(&dir, e))?);
            // Bounded before the whole listing is held in memory.
            if t.files.len() + t.dirs.len() + entries.len() > MAX_ENTRIES {
                return Err(refuse(Code::TooLarge, root, "too many entries"));
            }
        }
        entries.sort_by_key(|e| e.file_name());
        for e in entries {
            let name = e.file_name().into_string().map_err(|n| {
                refuse(Code::UnexpectedFile, &dir, &format!("non-UTF-8 name {n:?}"))
            })?;
            let r = if rel.is_empty() {
                name
            } else {
                format!("{rel}/{name}")
            };
            let ft = e.file_type().map_err(|x| io_err(&e.path(), x))?;
            if ft.is_dir() {
                stack.push((e.path(), r.clone()));
                t.dirs.insert(r);
            } else if ft.is_file() {
                t.files.insert(r);
            } else {
                return Err(refuse(
                    Code::UnexpectedFile,
                    &e.path(),
                    "symlink or special file",
                ));
            }
        }
    }
    Ok(t)
}

/// Refuse `tree` unless its files are exactly `want` and every directory
/// is an ancestor of one of them (no empty or stray directories).
pub fn require_exact(root: &Path, tree: &Tree, want: &BTreeSet<String>) -> Result<(), Fail> {
    if let Some(p) = tree.files.difference(want).next() {
        return Err(Fail::Refused(Refusal::new(
            Code::UnexpectedFile,
            format!("{}: {p} is not listed", root.display()),
        )));
    }
    if let Some(p) = want.difference(&tree.files).next() {
        return Err(Fail::Refused(Refusal::new(
            Code::MissingFile,
            format!("{}: {p} is missing", root.display()),
        )));
    }
    let mut needed = BTreeSet::new();
    for p in want {
        let mut at = 0;
        while let Some(i) = p[at..].find('/') {
            needed.insert(p[..at + i].to_string());
            at += i + 1;
        }
    }
    if let Some(d) = tree.dirs.difference(&needed).next() {
        return Err(Fail::Refused(Refusal::new(
            Code::UnexpectedFile,
            format!(
                "{}: directory {d} is not part of the layout",
                root.display()
            ),
        )));
    }
    Ok(())
}

/// Create `path` exclusively and write `bytes` (fsync'd).
pub fn write_new(path: &Path, bytes: &[u8]) -> Result<(), Fail> {
    let mut f = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(path)
        .map_err(|e| io_err(path, e))?;
    f.write_all(bytes).map_err(|e| io_err(path, e))?;
    f.sync_all().map_err(|e| io_err(path, e))
}

/// A fresh hidden sibling name of `path`.
pub fn sibling(path: &Path, tag: &str) -> PathBuf {
    let name = path
        .file_name()
        .map(|n| n.to_string_lossy().into_owned())
        .unwrap_or_default();
    let mut n = 0u32;
    loop {
        let p = path.with_file_name(format!(".{name}.{tag}-{}-{n}", std::process::id()));
        if fs::symlink_metadata(&p).is_err() {
            return p;
        }
        n += 1;
    }
}

/// Replace `path` atomically (temp sibling, fsync, rename). Refuses to
/// replace a symlink or a non-regular file.
pub fn write_replace(path: &Path, bytes: &[u8]) -> Result<(), Fail> {
    if let Ok(m) = fs::symlink_metadata(path) {
        if !m.file_type().is_file() {
            return Err(refuse(
                Code::FileMismatch,
                path,
                "not a regular file; not replaced",
            ));
        }
    }
    let tmp = sibling(path, "new");
    write_new(&tmp, bytes)?;
    fs::rename(&tmp, path).map_err(|e| {
        let _ = fs::remove_file(&tmp);
        io_err(path, e)
    })
}

/// Make sure every directory from `root` down to `rel`'s parent exists as a
/// real directory (creating missing ones), refusing symlinks on the way.
pub fn ensure_dirs(root: &Path, rel: &str) -> Result<(), Fail> {
    let mut cur = root.to_path_buf();
    let parts: Vec<&str> = rel.split('/').collect();
    for p in &parts[..parts.len().saturating_sub(1)] {
        cur.push(p);
        match fs::symlink_metadata(&cur) {
            Ok(m) if m.file_type().is_dir() => {}
            Ok(_) => return Err(refuse(Code::FileMismatch, &cur, "not a real directory")),
            Err(e) if e.kind() == io::ErrorKind::NotFound => {
                fs::create_dir(&cur).map_err(|e| io_err(&cur, e))?
            }
            Err(e) => return Err(io_err(&cur, e)),
        }
    }
    Ok(())
}
