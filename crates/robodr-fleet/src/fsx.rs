//! File helpers: capped reads that never follow a symlink, atomic writes
//! (robodr-commission's: temp file, fsync, rename, directory fsync, never
//! through a symlink), private directories, a single-instance lock and a
//! best-effort secure delete for retired key files.

use std::fs::{self, File, OpenOptions};
use std::io::{self, Read, Write};
use std::os::unix::fs::{DirBuilderExt, MetadataExt, OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};

/// Read a regular file (no symlink, no FIFO / device) of at most `max`
/// bytes.
pub fn read_capped(path: &Path, max: u64) -> io::Result<Vec<u8>> {
    let md = fs::symlink_metadata(path)?;
    if md.file_type().is_symlink() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "is a symlink (refused)",
        ));
    }
    if !md.is_file() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "not a regular file",
        ));
    }
    let f = OpenOptions::new()
        .read(true)
        .custom_flags(O_NOFOLLOW)
        .open(path)?;
    let mut v = Vec::new();
    f.take(max + 1).read_to_end(&mut v)?;
    if v.len() as u64 > max {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("larger than {max} bytes"),
        ));
    }
    Ok(v)
}

/// `O_NOFOLLOW` on Linux (RoboDR's only target OS): its value differs by
/// architecture (the same table as robodr-blackbox's `store::sys`).
const O_NOFOLLOW: i32 = if cfg!(any(
    target_arch = "aarch64",
    target_arch = "arm",
    target_arch = "powerpc",
    target_arch = "powerpc64"
)) {
    0o100000
} else {
    0o400000
};

/// Like [`read_capped`] but a missing file is `Ok(None)`.
pub fn read_optional(path: &Path, max: u64) -> io::Result<Option<Vec<u8>>> {
    match read_capped(path, max) {
        Ok(v) => Ok(Some(v)),
        Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(None),
        Err(e) => Err(e),
    }
}

/// Write `bytes` to `path` atomically, replacing it (mode 0600 for new
/// files, see `robodr_commission::write_file_atomic`).
pub fn write_atomic(path: &Path, bytes: &[u8]) -> io::Result<()> {
    robodr_commission::write_file_atomic(path, bytes, true)
}

/// Create `dir` (and parents) if missing; the last component gets mode
/// 0700. An existing directory must not be a symlink and must not be
/// writable by group or others.
pub fn ensure_private_dir(dir: &Path) -> io::Result<()> {
    match fs::symlink_metadata(dir) {
        Ok(md) => {
            if md.file_type().is_symlink() || !md.is_dir() {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    format!("{} is not a directory (or is a symlink)", dir.display()),
                ));
            }
            if md.permissions().mode() & 0o022 != 0 {
                return Err(io::Error::new(
                    io::ErrorKind::PermissionDenied,
                    format!(
                        "{} is writable by group or others (chmod go-w)",
                        dir.display()
                    ),
                ));
            }
            Ok(())
        }
        Err(e) if e.kind() == io::ErrorKind::NotFound => {
            if let Some(p) = dir.parent().filter(|p| !p.as_os_str().is_empty()) {
                fs::create_dir_all(p)?;
            }
            fs::DirBuilder::new().mode(0o700).create(dir)?;
            Ok(())
        }
        Err(e) => Err(e),
    }
}

/// The directory holding `path` must exist, not be a symlink and not be
/// writable by group or others (key directories).
pub fn check_parent_private(path: &Path) -> io::Result<()> {
    let dir = path
        .parent()
        .filter(|p| !p.as_os_str().is_empty())
        .unwrap_or(Path::new("."));
    let md = fs::symlink_metadata(dir)?;
    if md.file_type().is_symlink() || !md.is_dir() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("{} is not a directory", dir.display()),
        ));
    }
    if md.permissions().mode() & 0o022 != 0 {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            format!(
                "key directory {} is writable by group or others",
                dir.display()
            ),
        ));
    }
    Ok(())
}

/// `path` + `suffix`.
pub fn with_suffix(path: &Path, suffix: &str) -> PathBuf {
    let mut s = path.as_os_str().to_os_string();
    s.push(suffix);
    PathBuf::from(s)
}

/// fsync the directory holding `path`.
pub fn sync_parent(path: &Path) -> io::Result<()> {
    if let Some(dir) = path.parent().filter(|p| !p.as_os_str().is_empty()) {
        File::open(dir)?.sync_all()?;
    }
    Ok(())
}

/// Atomic rename + directory fsync.
pub fn rename_durable(from: &Path, to: &Path) -> io::Result<()> {
    fs::rename(from, to)?;
    sync_parent(to)
}

/// Best-effort secure delete of a (small) key file: overwrite with zeros,
/// fsync, unlink, fsync the directory. On flash storage with wear levelling
/// the old blocks may survive; the honest limit is documented (OPERATIONS
/// "Key rotation").
pub fn shred(path: &Path) -> io::Result<()> {
    let md = match fs::symlink_metadata(path) {
        Ok(m) => m,
        Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(()),
        Err(e) => return Err(e),
    };
    if md.is_file() {
        let mut f = OpenOptions::new()
            .write(true)
            .custom_flags(O_NOFOLLOW)
            .open(path)?;
        let zeros = vec![0u8; md.len().min(1 << 20) as usize];
        f.write_all(&zeros)?;
        f.sync_all()?;
    }
    fs::remove_file(path)?;
    sync_parent(path)
}

/// Whether `path` is owned by the effective user (or root) and not
/// accessible by group or others: the rule for a secret file.
pub fn check_secret_mode(path: &Path) -> io::Result<()> {
    let md = fs::symlink_metadata(path)?;
    if md.permissions().mode() & 0o077 != 0 {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            format!("{} is accessible by group or others", path.display()),
        ));
    }
    let euid = robodr_blackbox::keys::effective_uid();
    if md.uid() != euid && md.uid() != 0 {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            format!("{} is not owned by root or this user", path.display()),
        ));
    }
    Ok(())
}

// --------------------------------------------------------------- lock --

extern "C" {
    fn flock(fd: i32, operation: i32) -> i32;
}
const LOCK_EX: i32 = 2;
const LOCK_NB: i32 = 4;

/// An exclusive, non-blocking `flock` on `<dir>/fleet.lock`, held until
/// dropped: two `robodr-enroll` runs never interleave on one state
/// directory. Released by the kernel when the process dies (a crash leaves
/// no stale lock).
pub struct DirLock {
    _file: File,
}

impl DirLock {
    pub fn acquire(dir: &Path) -> io::Result<Self> {
        let path = dir.join("fleet.lock");
        let f = OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(false)
            .mode(0o600)
            .custom_flags(O_NOFOLLOW)
            .open(&path)?;
        use std::os::unix::io::AsRawFd;
        // SAFETY: `f` is an open file descriptor owned by this function;
        // flock(2) only takes the integer fd and flags and touches no
        // memory of this process.
        let rc = unsafe { flock(f.as_raw_fd(), LOCK_EX | LOCK_NB) };
        if rc != 0 {
            let e = io::Error::last_os_error();
            return Err(io::Error::new(
                io::ErrorKind::WouldBlock,
                format!(
                    "{} is locked by another robodr-enroll ({e})",
                    path.display()
                ),
            ));
        }
        Ok(Self { _file: f })
    }
}
