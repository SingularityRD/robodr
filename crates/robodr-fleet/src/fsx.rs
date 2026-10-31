//! File helpers: capped reads that never follow a symlink, atomic writes
//! (robodr-commission's: temp file, fsync, rename, directory fsync, never
//! through a symlink), private directories, a single-instance lock and a
//! best-effort secure delete for retired key files.

use std::fs::{self, File, OpenOptions};
use std::io::{self, Read, Write};
use std::os::unix::fs::{DirBuilderExt, OpenOptionsExt, PermissionsExt};
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
    check_parent_not_shared(path, "key directory")
}

/// The directory holding `path` (`what`: how to name it) must exist, not
/// be a symlink and not be writable by group or others: anyone who can
/// write there could replace the file between two checks or plant a link.
pub fn check_parent_not_shared(path: &Path, what: &str) -> io::Result<()> {
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
            format!("{what} {} is writable by group or others", dir.display()),
        ));
    }
    Ok(())
}

/// A temp file next to `path` (`<path>.robodr-enroll.tmp`, exclusive
/// create, never through a symlink) holding `bytes`, with `mode` and, if
/// given, the owner set on its **descriptor** (fchown, then fchmod) and
/// fsynced: ready for [`commit`]. A stale temp file is removed first.
pub fn stage_file(
    path: &Path,
    bytes: &[u8],
    mode: u32,
    owner: Option<(u32, u32)>,
) -> io::Result<PathBuf> {
    let tmp = with_suffix(path, ".robodr-enroll.tmp");
    match fs::symlink_metadata(&tmp) {
        Ok(_) => fs::remove_file(&tmp)?,
        Err(e) if e.kind() == io::ErrorKind::NotFound => {}
        Err(e) => return Err(e),
    }
    let res = (|| {
        let mut f = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .custom_flags(O_NOFOLLOW)
            .open(&tmp)?;
        f.write_all(bytes)?;
        if let Some((uid, gid)) = owner {
            std::os::unix::fs::fchown(&f, Some(uid), Some(gid))?;
        }
        f.set_permissions(fs::Permissions::from_mode(mode))?;
        f.sync_all()
    })();
    match res {
        Ok(()) => Ok(tmp),
        Err(e) => {
            let _ = fs::remove_file(&tmp);
            Err(e)
        }
    }
}

/// Rename a [`stage_file`] temp file over `path` and fsync the directory
/// (the temp file is removed on failure).
pub fn commit(tmp: &Path, path: &Path) -> io::Result<()> {
    let r = rename_durable(tmp, path);
    if r.is_err() {
        let _ = fs::remove_file(tmp);
    }
    r
}

/// Atomically replace `path` with `bytes`, `mode` and owner set on the
/// descriptor before the rename ([`stage_file`] + [`commit`]).
pub fn write_atomic_with(
    path: &Path,
    bytes: &[u8],
    mode: u32,
    owner: Option<(u32, u32)>,
) -> io::Result<()> {
    let tmp = stage_file(path, bytes, mode, owner)?;
    commit(&tmp, path)
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

/// Whether `path` passes the shared secret-file rule
/// (`robodr_blackbox::secret_file`): a regular file (no symlink) owned by
/// the effective user (or root) and not accessible by group or others, or
/// a systemd `LoadCredential=` file only root and this user can read.
pub fn check_secret_mode(path: &Path) -> io::Result<()> {
    robodr_blackbox::secret_file::check_secret_path(path)
        .map(|_| ())
        .map_err(|e| {
            io::Error::new(
                io::ErrorKind::PermissionDenied,
                format!("{}: {e}", path.display()),
            )
        })
}

// --------------------------------------------------------------- lock --

mod sys {
    //! `flock(2)`, declared by hand as `robodr-export`, `robodr-diode` and
    //! `robodr-blackbox` do (no libc crate offline); std links libc on every
    //! unix target.
    pub const LOCK_EX: i32 = 2;
    pub const LOCK_NB: i32 = 4;
    extern "C" {
        pub fn flock(fd: i32, operation: i32) -> i32;
    }
}

/// Attempts at `flock` before [`DirLock::acquire`] reports the lock as held.
const LOCK_RETRIES: u32 = 25;
/// Pause between two attempts (25 x 10 ms: a held lock is reported after
/// about a quarter of a second).
const LOCK_RETRY_DELAY: std::time::Duration = std::time::Duration::from_millis(10);

/// An exclusive, non-blocking `flock` on `<dir>/fleet.lock`, held until
/// dropped: two `robodr-enroll` runs never interleave on one state
/// directory. Released by the kernel when the process dies (a crash leaves
/// no stale lock).
pub struct DirLock {
    _file: File,
}

impl DirLock {
    /// Take the lock. A held lock is retried briefly (as `robodr-export`'s
    /// and `robodr-blackbox`'s locks are): a child forked by any thread of
    /// this process holds a copy of the lock file's descriptor until it
    /// execs, so a lock dropped just before such a fork can look held for a
    /// moment. A lock held by another live `robodr-enroll` stays held and is
    /// reported after about a quarter of a second.
    // FFI: `File::try_lock` (std 1.89) is newer than the MSRV (1.87).
    #[allow(unsafe_code)]
    pub fn acquire(dir: &Path) -> io::Result<Self> {
        use std::os::unix::io::AsRawFd;
        let path = dir.join("fleet.lock");
        let f = OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(false)
            .mode(0o600)
            .custom_flags(O_NOFOLLOW)
            .open(&path)?;
        let mut tries = 0u32;
        loop {
            // SAFETY: `flock` only reads its two integer arguments; the
            // descriptor is owned by `f`, which outlives the call, and no
            // memory of this process is touched.
            let rc = unsafe { sys::flock(f.as_raw_fd(), sys::LOCK_EX | sys::LOCK_NB) };
            if rc == 0 {
                return Ok(Self { _file: f });
            }
            let e = io::Error::last_os_error();
            if e.kind() != io::ErrorKind::WouldBlock {
                return Err(io::Error::new(
                    e.kind(),
                    format!("flock {}: {e}", path.display()),
                ));
            }
            tries += 1;
            if tries >= LOCK_RETRIES {
                return Err(io::Error::new(
                    io::ErrorKind::WouldBlock,
                    format!(
                        "{} is locked by another robodr-enroll ({e})",
                        path.display()
                    ),
                ));
            }
            std::thread::sleep(LOCK_RETRY_DELAY);
        }
    }
}
