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

/// Attempts [`read_capped_retrying`] makes before it gives up on a file
/// that keeps failing with an I/O error.
pub const READ_ATTEMPTS: u32 = 3;
/// Pause before the second attempt (doubled before each further one).
const READ_RETRY_PAUSE: std::time::Duration = std::time::Duration::from_millis(100);

/// Reason prefix of a spool file quarantined because it could not be read
/// (see [`unreadable_reason`]); the exporters count these separately.
pub const UNREADABLE: &str = "unreadable (I/O error";

/// The quarantine reason for a file that failed [`READ_ATTEMPTS`] times.
pub fn unreadable_reason(e: &io::Error) -> String {
    format!("{UNREADABLE} after {READ_ATTEMPTS} attempts: {e}); quarantined, fix the cause and move it back to ready/ to re-drive")
}

/// [`read_capped`], retrying an I/O error (`EIO`, `EACCES`, ...; not a
/// missing, irregular or oversized file) up to [`READ_ATTEMPTS`] times in
/// all with a short pause, so one bad file is retried a bounded number of
/// times instead of failing every run forever. The caller quarantines a
/// file that still fails.
pub fn read_capped_retrying(path: &Path, max: u64) -> Result<Vec<u8>, ReadError> {
    let mut pause = READ_RETRY_PAUSE;
    let mut attempt = 1;
    loop {
        match read_capped(path, max) {
            Err(ReadError::Io(_)) if attempt < READ_ATTEMPTS => {
                std::thread::sleep(pause);
                pause = pause.saturating_mul(2);
                attempt += 1;
            }
            other => return other,
        }
    }
}

thread_local! {
    static FAIL_READS: std::cell::RefCell<std::collections::HashMap<std::ffi::OsString, u32>> =
        std::cell::RefCell::new(std::collections::HashMap::new());
}

/// Fault injection for tests: the next `times` [`read_capped`] calls on
/// this thread for a file named `file_name` fail with `EIO`.
#[doc(hidden)]
pub fn inject_read_errors(file_name: &str, times: u32) {
    FAIL_READS.with(|m| {
        m.borrow_mut().insert(file_name.into(), times);
    });
}

fn injected_read_error(path: &Path) -> bool {
    let Some(name) = path.file_name() else {
        return false;
    };
    FAIL_READS.with(|m| {
        let mut m = m.borrow_mut();
        match m.get_mut(name) {
            Some(n) if *n > 0 => {
                *n -= 1;
                true
            }
            _ => false,
        }
    })
}

/// Read a regular, non-symlink file of at most `max` bytes.
pub fn read_capped(path: &Path, max: u64) -> Result<Vec<u8>, ReadError> {
    if injected_read_error(path) {
        return Err(ReadError::Io(io::Error::from_raw_os_error(5)));
    }
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

/// `O_NOFOLLOW` of the target, from the `libc` crate (T60). The earlier
/// hand-written table fell back to 0 (no symlink protection at all) on
/// every architecture it did not list (ppc64le, s390x, mips, ...).
fn libc_o_nofollow() -> i32 {
    libc::O_NOFOLLOW
}

/// Append one line (exactly one LF, at its end) to `path` and fsync it.
///
/// Torn lines never merge with the next one: if the file does not end in
/// LF (a crash, or a write that failed half-way, left a fragment), an LF is
/// written first, so the fragment stays a malformed line of its own (loaders
/// count it, see [`crate::deadletter`]) and the new line is intact. A write
/// that fails is truncated back to the previous length (best effort; the LF
/// check covers the case where that fails too). When the call creates the
/// file, the parent directory is fsynced so the new entry survives a crash.
pub fn append_durable(path: &Path, line: &[u8]) -> io::Result<()> {
    use std::os::unix::fs::FileExt;
    let one_line = matches!(
        line.split_last(),
        Some((b'\n', text)) if !text.is_empty() && !text.contains(&b'\n')
    );
    if !one_line {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "append_durable: exactly one non-empty LF-terminated line",
        ));
    }
    let (mut f, created) = match OpenOptions::new()
        .append(true)
        .create_new(true)
        .mode(0o600)
        .custom_flags(libc_o_nofollow())
        .open(path)
    {
        Ok(f) => (f, true),
        Err(e) if e.kind() == io::ErrorKind::AlreadyExists => (
            OpenOptions::new()
                .append(true)
                .read(true)
                .custom_flags(libc_o_nofollow())
                .open(path)?,
            false,
        ),
        Err(e) => return Err(e),
    };
    let meta = f.metadata()?;
    if !meta.file_type().is_file() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("{} is not a regular file", path.display()),
        ));
    }
    let len = meta.len();
    let mut buf = Vec::with_capacity(line.len() + 1);
    if len > 0 {
        let mut last = [0u8; 1];
        f.read_exact_at(&mut last, len - 1)?;
        if last[0] != b'\n' {
            buf.push(b'\n');
        }
    }
    buf.extend_from_slice(line);
    if let Err(e) = f.write_all(&buf).and_then(|()| f.sync_all()) {
        // Do not leave a fragment for the next append to find.
        if f.set_len(len).is_ok() {
            let _ = f.sync_all();
        }
        return Err(e);
    }
    if created {
        fsync_dir(parent(path))?;
    }
    Ok(())
}

/// Attempts at `flock` before [`try_lock`] reports the lock as held.
const LOCK_RETRIES: u32 = 25;
/// Pause between two attempts (25 x 10 ms: a held lock is reported after
/// about a quarter of a second).
const LOCK_RETRY_DELAY: std::time::Duration = std::time::Duration::from_millis(10);

/// Take an exclusive, non-blocking `flock` on `p` (created mode 0600 if
/// missing, never through a symlink, never truncated or removed). `Ok(None)`
/// if another process (or another open file description in this one) holds
/// it. The lock lives as long as the returned file; the kernel drops it when
/// the process dies, so a crash never leaves a stale lock behind.
///
/// A held lock is retried briefly (like `robodr-blackbox`'s recorder lock
/// and `robodr-diode`'s state lock): a child forked by *any* thread of this
/// process holds a copy of every open descriptor, the lock file's included,
/// until it execs (std opens files close-on-exec), so a lock dropped just
/// before such a fork can look held for a moment. A lock held by another
/// live process stays held and is reported as `Ok(None)` after about a
/// quarter of a second.
// FFI: `File::try_lock` (std 1.89) is newer than the MSRV (1.87).
#[allow(unsafe_code)]
pub fn try_lock(p: &Path) -> io::Result<Option<File>> {
    use std::os::unix::io::AsRawFd;
    let f = OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .truncate(false)
        .mode(0o600)
        .custom_flags(libc_o_nofollow())
        .open(p)?;
    if !f.metadata()?.is_file() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("{} is not a regular file", p.display()),
        ));
    }
    let mut tries = 0u32;
    loop {
        // SAFETY: `flock` only reads its two integer arguments; the
        // descriptor is owned by `f`, which outlives the call.
        let rc = unsafe { libc::flock(f.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) };
        if rc == 0 {
            return Ok(Some(f));
        }
        let e = io::Error::last_os_error();
        if e.kind() != io::ErrorKind::WouldBlock {
            return Err(e);
        }
        tries += 1;
        if tries >= LOCK_RETRIES {
            return Ok(None);
        }
        std::thread::sleep(LOCK_RETRY_DELAY);
    }
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

    /// T60: the symlink guard is never compiled out (the hand-written
    /// table it replaced was 0 on unlisted architectures), and the kernel
    /// of the architecture the tests run on refuses a symlink with it
    /// (`ELOOP`). This exercises the build's own architecture only; the
    /// value for others comes from the `libc` crate.
    #[test]
    fn o_nofollow_refuses_a_symlink() {
        use std::os::unix::fs::OpenOptionsExt;
        assert_ne!(libc_o_nofollow(), 0);
        let d = std::env::temp_dir().join(format!("robodr-export-nofollow-{}", std::process::id()));
        let _ = fs::remove_dir_all(&d);
        mkdir(&d).unwrap();
        let target = d.join("target");
        fs::write(&target, b"x").unwrap();
        std::os::unix::fs::symlink(&target, d.join("link")).unwrap();
        let open = |p: &Path| {
            OpenOptions::new()
                .read(true)
                .custom_flags(libc_o_nofollow())
                .open(p)
        };
        assert!(open(&target).is_ok());
        let e = open(&d.join("link")).unwrap_err();
        assert_eq!(e.raw_os_error(), Some(libc::ELOOP), "{e}");
        let _ = fs::remove_dir_all(&d);
    }

    #[test]
    fn lock_is_exclusive_and_released_on_drop() {
        let d = std::env::temp_dir().join(format!("robodr-export-lock-{}", std::process::id()));
        let _ = fs::remove_dir_all(&d);
        mkdir(&d).unwrap();
        let lp = d.join("x.lock");
        let held = try_lock(&lp).unwrap().expect("first lock");
        // flock locks belong to the open file description: a second open in
        // this process conflicts like another process would.
        assert!(try_lock(&lp).unwrap().is_none());
        drop(held);
        assert!(try_lock(&lp).unwrap().is_some());
        std::os::unix::fs::symlink(&lp, d.join("ln.lock")).unwrap();
        assert!(try_lock(&d.join("ln.lock")).is_err());
        let _ = fs::remove_dir_all(&d);
    }

    /// A lock released while another holder still has it open for a moment
    /// (a child forked by another thread holds the descriptor until it
    /// execs) is taken once the copy goes away, within the retry window;
    /// one that stays held is reported held after the retries.
    #[test]
    fn lock_released_shortly_after_is_taken_by_the_retry() {
        let d =
            std::env::temp_dir().join(format!("robodr-export-lock-retry-{}", std::process::id()));
        let _ = fs::remove_dir_all(&d);
        mkdir(&d).unwrap();
        let lp = d.join("x.lock");
        let held = try_lock(&lp).unwrap().expect("first lock");
        // The "forked copy": released 50 ms from now, well inside the
        // 25 x 10 ms window.
        let t = std::thread::spawn(move || {
            std::thread::sleep(std::time::Duration::from_millis(50));
            drop(held);
        });
        let started = std::time::Instant::now();
        let again = try_lock(&lp).unwrap();
        t.join().unwrap();
        assert!(
            again.is_some(),
            "the retry takes a lock released in the window"
        );
        assert!(started.elapsed() >= std::time::Duration::from_millis(40));
        // Held for good: reported held, after the retries (not at once, not
        // forever).
        let started = std::time::Instant::now();
        assert!(try_lock(&lp).unwrap().is_none());
        let waited = started.elapsed();
        assert!(
            waited >= LOCK_RETRY_DELAY * (LOCK_RETRIES - 1),
            "retried: {waited:?}"
        );
        assert!(waited < std::time::Duration::from_secs(5), "{waited:?}");
        drop(again);
        let _ = fs::remove_dir_all(&d);
    }

    /// A torn last line (a crash or a failed write left bytes without their
    /// LF) is closed before the next append, so the next line stays a line
    /// of its own instead of being merged into the fragment.
    #[test]
    fn append_after_a_torn_line_starts_a_new_line() {
        let d = std::env::temp_dir().join(format!("robodr-export-torn-{}", std::process::id()));
        let _ = fs::remove_dir_all(&d);
        mkdir(&d).unwrap();
        let p = d.join("log");
        fs::write(&p, b"{\"a\":1}\n{\"torn\":").unwrap();
        append_durable(&p, b"{\"b\":2}\n").unwrap();
        assert_eq!(fs::read(&p).unwrap(), b"{\"a\":1}\n{\"torn\":\n{\"b\":2}\n");
        // Already terminated: nothing added.
        append_durable(&p, b"{\"c\":3}\n").unwrap();
        assert!(fs::read(&p).unwrap().ends_with(b"{\"b\":2}\n{\"c\":3}\n"));
        // A line must be exactly one LF-terminated line.
        for bad in [&b""[..], b"x", b"a\nb\n", b"\n"] {
            assert!(append_durable(&p, bad).is_err(), "{bad:?}");
        }
        let _ = fs::remove_dir_all(&d);
    }
}
