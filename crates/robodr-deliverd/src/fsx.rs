//! File-system helpers for the agent's own trees (state, store, install
//! roots). Untrusted media is read only through `robodr_release::fsio`.
//!
//! * Writes are crash-safe: a fresh temporary sibling (`O_CREAT|O_EXCL`,
//!   never through a symlink), `fsync`, `rename`, `fsync` of the directory.
//! * Directories on the way are required to be **real** directories: a
//!   symlink where a directory is expected is an error, never followed
//!   for a write.

use std::fs::{self, File, OpenOptions};
use std::io::{self, Write};
use std::os::unix::fs::{DirBuilderExt, OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

/// `fsync` a directory (makes renames and creations in it durable).
pub fn sync_dir(dir: &Path) -> io::Result<()> {
    File::open(dir)?.sync_all()
}

/// A fresh hidden sibling name of `path` (never an existing entry).
pub fn temp_sibling(path: &Path, tag: &str) -> PathBuf {
    static N: AtomicU64 = AtomicU64::new(0);
    let name = path
        .file_name()
        .map(|n| n.to_string_lossy().into_owned())
        .unwrap_or_default();
    loop {
        let n = N.fetch_add(1, Ordering::SeqCst);
        let p = path.with_file_name(format!(".{name}.{tag}-{}-{n}", std::process::id()));
        if fs::symlink_metadata(&p).is_err() {
            return p;
        }
    }
}

/// Create `path` exclusively with `mode`, write `bytes`, `fsync`.
pub fn write_new(path: &Path, bytes: &[u8], mode: u32) -> io::Result<()> {
    let mut f = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(mode)
        .open(path)?;
    // The umask may have cleared bits; the mode is exact.
    f.set_permissions(fs::Permissions::from_mode(mode))?;
    f.write_all(bytes)?;
    f.sync_all()
}

/// Replace `path` atomically with `bytes` (`mode`). Refuses to replace a
/// symlink or anything that is not a regular file.
pub fn write_atomic(path: &Path, bytes: &[u8], mode: u32) -> io::Result<()> {
    if let Ok(m) = fs::symlink_metadata(path) {
        if !m.file_type().is_file() {
            return Err(io::Error::other(format!(
                "{}: not a regular file; not replaced",
                path.display()
            )));
        }
    }
    let tmp = temp_sibling(path, "new");
    let res = write_new(&tmp, bytes, mode).and_then(|()| fs::rename(&tmp, path));
    if res.is_err() {
        let _ = fs::remove_file(&tmp);
    }
    res?;
    if let Some(parent) = path.parent() {
        sync_dir(parent)?;
    }
    Ok(())
}

/// `path` is a real directory (not a symlink to one).
pub fn is_real_dir(path: &Path) -> bool {
    fs::symlink_metadata(path).is_ok_and(|m| m.file_type().is_dir())
}

/// Make `path` a real directory with `mode` if it does not exist; refuse
/// a symlink or a non-directory in its place. The parent must exist.
pub fn ensure_dir(path: &Path, mode: u32) -> io::Result<()> {
    match fs::symlink_metadata(path) {
        Ok(m) if m.file_type().is_dir() => Ok(()),
        Ok(_) => Err(io::Error::other(format!(
            "{}: exists and is not a real directory (symlink or file)",
            path.display()
        ))),
        Err(e) if e.kind() == io::ErrorKind::NotFound => {
            fs::DirBuilder::new().mode(mode).create(path)?;
            fs::set_permissions(path, fs::Permissions::from_mode(mode))?;
            if let Some(parent) = path.parent() {
                sync_dir(parent)?;
            }
            Ok(())
        }
        Err(e) => Err(e),
    }
}

/// Remove `path` (a directory tree or a file) if it exists. A symlink is
/// removed itself, never followed.
pub fn remove_any(path: &Path) -> io::Result<()> {
    match fs::symlink_metadata(path) {
        Ok(m) if m.file_type().is_dir() => fs::remove_dir_all(path),
        Ok(_) => fs::remove_file(path),
        Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(()),
        Err(e) => Err(e),
    }
}

/// Atomically point the symlink `link` at `target` (a new symlink next to
/// it renamed over it). Refuses to replace anything that is not a symlink.
pub fn swap_symlink(link: &Path, target: &Path) -> io::Result<()> {
    if let Ok(m) = fs::symlink_metadata(link) {
        if !m.file_type().is_symlink() {
            return Err(io::Error::other(format!(
                "{}: exists and is not a symlink; not replaced",
                link.display()
            )));
        }
    }
    let tmp = temp_sibling(link, "link");
    std::os::unix::fs::symlink(target, &tmp)?;
    if let Err(e) = fs::rename(&tmp, link) {
        let _ = fs::remove_file(&tmp);
        return Err(e);
    }
    if let Some(parent) = link.parent() {
        sync_dir(parent)?;
    }
    Ok(())
}

/// The target of the symlink `link`, or `None` when absent. A non-symlink
/// in its place is an error.
pub fn read_link(link: &Path) -> io::Result<Option<PathBuf>> {
    match fs::symlink_metadata(link) {
        Ok(m) if m.file_type().is_symlink() => fs::read_link(link).map(Some),
        Ok(_) => Err(io::Error::other(format!(
            "{}: not a symlink",
            link.display()
        ))),
        Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(None),
        Err(e) => Err(e),
    }
}

/// Read a regular file of at most `max` bytes (no symlink), or `None` when
/// it does not exist.
pub fn read_optional(path: &Path, max: usize) -> io::Result<Option<Vec<u8>>> {
    match fs::symlink_metadata(path) {
        Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(None),
        Err(e) => return Err(e),
        Ok(_) => {}
    }
    robodr_release::fsio::read_capped(path, max)
        .map(Some)
        .map_err(|e| io::Error::other(e.to_string()))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tmp(tag: &str) -> PathBuf {
        let d = std::env::temp_dir().join(format!("deliverd-fsx-{tag}-{}", std::process::id()));
        let _ = fs::remove_dir_all(&d);
        fs::create_dir_all(&d).unwrap();
        d
    }

    #[test]
    fn atomic_write_refuses_symlink_and_keeps_mode() {
        let d = tmp("aw");
        let p = d.join("f");
        write_atomic(&p, b"one", 0o600).unwrap();
        write_atomic(&p, b"two", 0o640).unwrap();
        assert_eq!(fs::read(&p).unwrap(), b"two");
        assert_eq!(
            fs::metadata(&p).unwrap().permissions().mode() & 0o777,
            0o640
        );
        let l = d.join("l");
        std::os::unix::fs::symlink(&p, &l).unwrap();
        assert!(write_atomic(&l, b"x", 0o600).is_err());
        assert_eq!(fs::read(&p).unwrap(), b"two");
        // No temporary left behind.
        let n = fs::read_dir(&d).unwrap().count();
        assert_eq!(n, 2);
        fs::remove_dir_all(&d).unwrap();
    }

    #[test]
    fn ensure_dir_and_swap_refuse_impostors() {
        let d = tmp("ed");
        let outside = tmp("ed-out");
        std::os::unix::fs::symlink(&outside, d.join("x")).unwrap();
        assert!(ensure_dir(&d.join("x"), 0o755).is_err());
        ensure_dir(&d.join("y"), 0o755).unwrap();
        ensure_dir(&d.join("y"), 0o755).unwrap();
        fs::write(d.join("file"), b"").unwrap();
        assert!(swap_symlink(&d.join("file"), Path::new("y")).is_err());
        swap_symlink(&d.join("cur"), Path::new("y")).unwrap();
        swap_symlink(&d.join("cur"), Path::new("z")).unwrap();
        assert_eq!(read_link(&d.join("cur")).unwrap(), Some(PathBuf::from("z")));
        assert!(read_link(&d.join("file")).is_err());
        assert_eq!(read_link(&d.join("none")).unwrap(), None);
        fs::remove_dir_all(&d).unwrap();
        fs::remove_dir_all(&outside).unwrap();
    }
}
