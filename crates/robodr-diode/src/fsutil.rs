//! Small, symlink-averse filesystem helpers (std only).
//!
//! * Every path the importer reads from an inbox is checked with
//!   `symlink_metadata` (never followed) and opened with `O_NOFOLLOW |
//!   O_NONBLOCK`; after opening, the device/inode of the open file must equal
//!   the checked one, so a swap between check and open is detected.
//! * Every file we create is created with `create_new` (`O_CREAT|O_EXCL`,
//!   which never follows a planted symlink), written, and `fsync`ed; the
//!   containing directory is `fsync`ed after renames.

use std::fs::{self, File, OpenOptions};
use std::io::{self, Read, Write};
use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

#[cfg(all(
    target_os = "linux",
    any(
        target_arch = "x86_64",
        target_arch = "x86",
        target_arch = "riscv64",
        target_arch = "s390x",
        target_arch = "loongarch64"
    )
))]
const O_NOFOLLOW: i32 = 0o400000;
#[cfg(all(target_os = "linux", any(target_arch = "aarch64", target_arch = "arm")))]
const O_NOFOLLOW: i32 = 0o100000;
// Elsewhere we rely on the pre-open lstat and the post-open inode check.
#[cfg(not(all(
    target_os = "linux",
    any(
        target_arch = "x86_64",
        target_arch = "x86",
        target_arch = "riscv64",
        target_arch = "s390x",
        target_arch = "loongarch64",
        target_arch = "aarch64",
        target_arch = "arm"
    )
)))]
const O_NOFOLLOW: i32 = 0;
#[cfg(target_os = "linux")]
const O_NONBLOCK: i32 = 0o4000;
#[cfg(not(target_os = "linux"))]
const O_NONBLOCK: i32 = 0;

pub(crate) fn invalid(msg: impl Into<String>) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, msg.into())
}

/// `p` exists and is a directory, not a symlink to one.
pub(crate) fn require_real_dir(p: &Path) -> io::Result<()> {
    let m = fs::symlink_metadata(p)?;
    if m.file_type().is_symlink() {
        return Err(invalid(format!("{} is a symlink", p.display())));
    }
    if !m.is_dir() {
        return Err(invalid(format!("{} is not a directory", p.display())));
    }
    Ok(())
}

/// Create `p` (and parents) if missing, then [`require_real_dir`].
pub(crate) fn ensure_real_dir(p: &Path) -> io::Result<()> {
    if fs::symlink_metadata(p).is_err() {
        fs::create_dir_all(p)?;
    }
    require_real_dir(p)
}

/// Does anything (including a dangling symlink) exist at `p`?
pub(crate) fn exists_nofollow(p: &Path) -> bool {
    fs::symlink_metadata(p).is_ok()
}

/// Why a capped read failed.
#[derive(Debug)]
pub(crate) enum ReadError {
    Missing,
    NotRegular,
    TooLarge(u64),
    Io(io::Error),
}

/// Open a regular, non-symlink file of at most `max` bytes for reading.
/// Returns the file and its size at open time. Permission problems are
/// reported as [`ReadError::Io`] (kind `PermissionDenied`), not as
/// "not regular", so callers can tell an unreadable entry from a planted one.
pub(crate) fn open_capped(p: &Path, max: u64) -> Result<(File, u64), ReadError> {
    let m = match fs::symlink_metadata(p) {
        Ok(m) => m,
        Err(e) if e.kind() == io::ErrorKind::NotFound => return Err(ReadError::Missing),
        Err(e) => return Err(ReadError::Io(e)),
    };
    if !m.file_type().is_file() {
        return Err(ReadError::NotRegular);
    }
    if m.len() > max {
        return Err(ReadError::TooLarge(m.len()));
    }
    let f = OpenOptions::new()
        .read(true)
        .custom_flags(O_NOFOLLOW | O_NONBLOCK)
        .open(p)
        .map_err(|e| match e.kind() {
            io::ErrorKind::NotFound => ReadError::Missing,
            io::ErrorKind::PermissionDenied => ReadError::Io(e),
            // ELOOP from O_NOFOLLOW lands here.
            _ => ReadError::NotRegular,
        })?;
    let om = f.metadata().map_err(ReadError::Io)?;
    if !om.is_file() || om.dev() != m.dev() || om.ino() != m.ino() {
        return Err(ReadError::NotRegular);
    }
    if om.len() > max {
        return Err(ReadError::TooLarge(om.len()));
    }
    Ok((f, om.len()))
}

/// Read a regular, non-symlink file of at most `max` bytes.
pub(crate) fn read_capped(p: &Path, max: u64) -> Result<Vec<u8>, ReadError> {
    let (f, len) = open_capped(p, max)?;
    let mut buf = Vec::with_capacity(len.min(max) as usize);
    f.take(max.saturating_add(1))
        .read_to_end(&mut buf)
        .map_err(ReadError::Io)?;
    if buf.len() as u64 > max {
        return Err(ReadError::TooLarge(buf.len() as u64));
    }
    Ok(buf)
}

/// Create a new file for writing (`O_CREAT|O_EXCL|O_NOFOLLOW`: never through
/// a symlink, never an existing file).
pub(crate) fn create_new(p: &Path) -> io::Result<File> {
    OpenOptions::new()
        .write(true)
        .create_new(true)
        .custom_flags(O_NOFOLLOW)
        .open(p)
}

/// Create a new file (never through a symlink), write `bytes`, `fsync`.
pub(crate) fn write_new(p: &Path, bytes: &[u8]) -> io::Result<()> {
    let mut f = create_new(p)?;
    f.write_all(bytes)?;
    f.sync_all()
}

/// `fsync` a directory so a rename/creation in it is durable.
pub(crate) fn fsync_dir(p: &Path) -> io::Result<()> {
    File::open(p)?.sync_all()
}

static TMP_COUNTER: AtomicU64 = AtomicU64::new(0);

/// Atomically replace `p` with `bytes`: write a fresh temp file in the same
/// directory, `fsync`, rename over `p`, `fsync` the directory.
pub(crate) fn atomic_write(p: &Path, bytes: &[u8]) -> io::Result<()> {
    let dir = p
        .parent()
        .filter(|d| !d.as_os_str().is_empty())
        .unwrap_or(Path::new("."));
    let base = p
        .file_name()
        .ok_or_else(|| invalid("path has no file name"))?
        .to_string_lossy();
    if let Ok(m) = fs::symlink_metadata(p) {
        if !m.file_type().is_file() {
            return Err(invalid(format!(
                "{} exists and is not a regular file",
                p.display()
            )));
        }
    }
    let tmp: PathBuf = dir.join(format!(
        ".{base}.tmp.{}.{}",
        std::process::id(),
        TMP_COUNTER.fetch_add(1, Ordering::Relaxed)
    ));
    if let Err(e) = write_new(&tmp, bytes) {
        let _ = fs::remove_file(&tmp);
        return Err(e);
    }
    if let Err(e) = fs::rename(&tmp, p) {
        let _ = fs::remove_file(&tmp);
        return Err(e);
    }
    fsync_dir(dir)
}

static UNIQUE_COUNTER: AtomicU64 = AtomicU64::new(0);
/// Attempts per unique-name operation. Every attempt after the first uses a
/// fresh name (wall-clock ns, pid, process-wide counter), so this bound is
/// only reached if the directory changes under us on every attempt — it is
/// not a namespace that earlier runs can fill up.
const UNIQUE_ATTEMPTS: u32 = 64;

/// `<name>.<unix ns>-<pid>-<counter>`: unique across runs and within one.
fn unique_name(name: &str) -> String {
    let ns = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or(0);
    format!(
        "{name}.{ns}-{}-{}",
        std::process::id(),
        UNIQUE_COUNTER.fetch_add(1, Ordering::Relaxed)
    )
}

/// Rename `from` into `dir` under `name`, or under a timestamp/counter
/// suffixed variant of it ([`unique_name`]) if `name` is taken. Returns the
/// final path. There is no small cap on earlier occupants of `name.*`: each
/// fallback name is new.
pub(crate) fn move_unique(from: &Path, dir: &Path, name: &str) -> io::Result<PathBuf> {
    let mut candidate = dir.join(name);
    for _ in 0..UNIQUE_ATTEMPTS {
        if !exists_nofollow(&candidate) {
            fs::rename(from, &candidate)?;
            fsync_dir(dir)?;
            return Ok(candidate);
        }
        candidate = dir.join(unique_name(name));
    }
    Err(io::Error::new(
        io::ErrorKind::AlreadyExists,
        format!("no free name for {name} in {}", dir.display()),
    ))
}

/// Create a fresh directory in `dir` named `name` or a unique variant of it
/// (`create_dir` is exclusive, so the result is ours alone).
pub(crate) fn create_unique_dir(dir: &Path, name: &str) -> io::Result<PathBuf> {
    let mut candidate = dir.join(name);
    for _ in 0..UNIQUE_ATTEMPTS {
        match fs::create_dir(&candidate) {
            Ok(()) => return Ok(candidate),
            Err(e) if e.kind() == io::ErrorKind::AlreadyExists => {}
            Err(e) => return Err(e),
        }
        candidate = dir.join(unique_name(name));
    }
    Err(io::Error::new(
        io::ErrorKind::AlreadyExists,
        format!("no free name for {name} in {}", dir.display()),
    ))
}

/// Milliseconds since the epoch of `m`'s modification time (0 if unknown).
pub(crate) fn mtime_ms(m: &fs::Metadata) -> u64 {
    m.modified()
        .ok()
        .and_then(|t| t.duration_since(std::time::UNIX_EPOCH).ok())
        .map(|d| d.as_millis().min(u128::from(u64::MAX)) as u64)
        .unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tmpdir(tag: &str) -> PathBuf {
        let d = std::env::temp_dir().join(format!(
            "robodr-diode-fsutil-{tag}-{}-{}",
            std::process::id(),
            TMP_COUNTER.fetch_add(1, Ordering::Relaxed)
        ));
        let _ = fs::remove_dir_all(&d);
        fs::create_dir_all(&d).unwrap();
        d
    }

    #[test]
    fn read_capped_refuses_symlinks_and_large_files() {
        let d = tmpdir("read");
        let f = d.join("f");
        write_new(&f, b"hello").unwrap();
        assert_eq!(read_capped(&f, 5).unwrap(), b"hello");
        assert!(matches!(read_capped(&f, 4), Err(ReadError::TooLarge(5))));
        std::os::unix::fs::symlink(&f, d.join("l")).unwrap();
        assert!(matches!(
            read_capped(&d.join("l"), 10),
            Err(ReadError::NotRegular)
        ));
        assert!(matches!(
            read_capped(&d.join("missing"), 10),
            Err(ReadError::Missing)
        ));
        assert!(matches!(read_capped(&d, 10), Err(ReadError::NotRegular)));
        fs::remove_dir_all(&d).unwrap();
    }

    #[test]
    fn write_new_does_not_follow_planted_symlink() {
        let d = tmpdir("write");
        let target = d.join("target");
        write_new(&target, b"orig").unwrap();
        std::os::unix::fs::symlink(&target, d.join("link")).unwrap();
        assert!(write_new(&d.join("link"), b"evil").is_err());
        assert_eq!(fs::read(&target).unwrap(), b"orig");
        // atomic_write refuses to replace a symlink too.
        assert!(atomic_write(&d.join("link"), b"evil").is_err());
        assert_eq!(fs::read(&target).unwrap(), b"orig");
        atomic_write(&d.join("state"), b"1").unwrap();
        atomic_write(&d.join("state"), b"2").unwrap();
        assert_eq!(fs::read(d.join("state")).unwrap(), b"2");
        fs::remove_dir_all(&d).unwrap();
    }

    #[test]
    fn real_dir_checks() {
        let d = tmpdir("dir");
        require_real_dir(&d).unwrap();
        std::os::unix::fs::symlink(&d, d.join("ln")).unwrap();
        assert!(require_real_dir(&d.join("ln")).is_err());
        assert!(ensure_real_dir(&d.join("ln")).is_err());
        ensure_real_dir(&d.join("a/b")).unwrap();
        let src = d.join("src");
        fs::create_dir(&src).unwrap();
        fs::create_dir(d.join("dst")).unwrap();
        fs::create_dir(d.join("dst/x")).unwrap();
        let p = move_unique(&src, &d.join("dst"), "x").unwrap();
        assert_ne!(p, d.join("dst/x"));
        assert!(p.is_dir());
        let name = p.file_name().unwrap().to_str().unwrap();
        assert!(name.starts_with("x.") && name.len() > 2, "{name}");
        // Earlier occupants of any number of `x.N` names do not matter.
        for i in 1..=100 {
            fs::create_dir(d.join(format!("dst/x.{i}"))).unwrap();
        }
        let src2 = d.join("src2");
        fs::create_dir(&src2).unwrap();
        assert!(move_unique(&src2, &d.join("dst"), "x").unwrap().is_dir());
        let a = create_unique_dir(&d, "q").unwrap();
        let b = create_unique_dir(&d, "q").unwrap();
        assert_eq!(a, d.join("q"));
        assert_ne!(a, b);
        assert!(b.is_dir());
        fs::remove_dir_all(&d).unwrap();
    }
}
