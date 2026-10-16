//! Small durable-file helpers (std only).

use std::fs::{self, File, OpenOptions};
use std::io::{self, Read, Write};
use std::os::unix::fs::OpenOptionsExt;
use std::path::Path;

pub fn fsync_dir(p: &Path) -> io::Result<()> {
    File::open(p)?.sync_all()
}

fn parent(p: &Path) -> &Path {
    match p.parent() {
        Some(d) if !d.as_os_str().is_empty() => d,
        _ => Path::new("."),
    }
}

/// Replace `path` atomically: write `.<name>.tmp` beside it (mode 0600),
/// fsync, rename, fsync the directory.
pub fn atomic_write(path: &Path, bytes: &[u8]) -> io::Result<()> {
    let dir = parent(path);
    let name = path
        .file_name()
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "path has no file name"))?;
    let tmp = dir.join(format!(".{}.tmp", name.to_string_lossy()));
    let _ = fs::remove_file(&tmp);
    let res = (|| {
        let mut f = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(&tmp)?;
        f.write_all(bytes)?;
        f.sync_all()?;
        fs::rename(&tmp, path)?;
        fsync_dir(dir)
    })();
    if res.is_err() {
        let _ = fs::remove_file(&tmp);
    }
    res
}

/// Outcome of [`read_capped`].
#[derive(Debug)]
pub enum ReadError {
    Missing,
    NotRegular,
    TooLarge(u64),
    Io(io::Error),
}

impl std::fmt::Display for ReadError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ReadError::Missing => write!(f, "missing"),
            ReadError::NotRegular => write!(f, "not a regular file (or a symlink)"),
            ReadError::TooLarge(n) => write!(f, "larger than {n} bytes"),
            ReadError::Io(e) => write!(f, "{e}"),
        }
    }
}

/// Read a regular, non-symlink file of at most `max` bytes.
pub fn read_capped(path: &Path, max: u64) -> Result<Vec<u8>, ReadError> {
    let meta = match fs::symlink_metadata(path) {
        Ok(m) => m,
        Err(e) if e.kind() == io::ErrorKind::NotFound => return Err(ReadError::Missing),
        Err(e) => return Err(ReadError::Io(e)),
    };
    if !meta.file_type().is_file() {
        return Err(ReadError::NotRegular);
    }
    let f = OpenOptions::new()
        .read(true)
        .custom_flags(libc_o_nofollow())
        .open(path)
        .map_err(|e| {
            if e.kind() == io::ErrorKind::NotFound {
                ReadError::Missing
            } else {
                ReadError::Io(e)
            }
        })?;
    let mut buf = Vec::new();
    f.take(max + 1)
        .read_to_end(&mut buf)
        .map_err(ReadError::Io)?;
    if buf.len() as u64 > max {
        return Err(ReadError::TooLarge(max));
    }
    Ok(buf)
}

/// `O_NOFOLLOW` on Linux (all architectures Rust supports there use 0o400000
/// except a few legacy ones; fall back to 0 = no extra protection).
fn libc_o_nofollow() -> i32 {
    #[cfg(all(
        target_os = "linux",
        any(target_arch = "x86_64", target_arch = "x86", target_arch = "riscv64")
    ))]
    {
        0o400_000
    }
    #[cfg(all(target_os = "linux", any(target_arch = "aarch64", target_arch = "arm")))]
    {
        0o100_000
    }
    #[cfg(not(all(
        target_os = "linux",
        any(
            target_arch = "x86_64",
            target_arch = "x86",
            target_arch = "riscv64",
            target_arch = "aarch64",
            target_arch = "arm"
        )
    )))]
    {
        0
    }
}

/// Append `line` (which must end in `\n`) to `path` and fsync it.
pub fn append_durable(path: &Path, line: &[u8]) -> io::Result<()> {
    let mut f = OpenOptions::new()
        .append(true)
        .create(true)
        .mode(0o600)
        .open(path)?;
    f.write_all(line)?;
    f.sync_all()
}

/// Create (mode 0700) a directory and its parents.
pub fn mkdir(p: &Path) -> io::Result<()> {
    use std::os::unix::fs::DirBuilderExt;
    fs::DirBuilder::new().recursive(true).mode(0o700).create(p)
}

/// Current wall-clock time in ms since the epoch (0 if the clock is before 1970).
pub fn now_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn atomic_write_and_capped_read() {
        let d = std::env::temp_dir().join(format!("robodr-export-fsutil-{}", std::process::id()));
        let _ = fs::remove_dir_all(&d);
        mkdir(&d).unwrap();
        let p = d.join("state.json");
        atomic_write(&p, b"one").unwrap();
        atomic_write(&p, b"two").unwrap();
        assert_eq!(read_capped(&p, 3).unwrap(), b"two");
        assert!(matches!(read_capped(&p, 2), Err(ReadError::TooLarge(2))));
        assert!(matches!(
            read_capped(&d.join("nope"), 9),
            Err(ReadError::Missing)
        ));
        assert!(matches!(read_capped(&d, 9), Err(ReadError::NotRegular)));
        std::os::unix::fs::symlink(&p, d.join("link")).unwrap();
        assert!(matches!(
            read_capped(&d.join("link"), 9),
            Err(ReadError::NotRegular)
        ));
        // No temp file left behind.
        let names: Vec<_> = fs::read_dir(&d)
            .unwrap()
            .map(|e| e.unwrap().file_name())
            .collect();
        assert_eq!(names.len(), 2);
        append_durable(&d.join("log"), b"a\n").unwrap();
        append_durable(&d.join("log"), b"b\n").unwrap();
        assert_eq!(fs::read(d.join("log")).unwrap(), b"a\nb\n");
        let _ = fs::remove_dir_all(&d);
    }
}
