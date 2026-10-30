//! Small, careful filesystem helpers of the control plane's persistent
//! state (`control_plane.state_dir`): private directories, files created
//! exclusively without following symlinks, fsync of files and directories,
//! and bounded reads of files that must not be symlinks.

use std::fs::{File, OpenOptions};
use std::io::{self, Read};
use std::os::unix::fs::{DirBuilderExt, MetadataExt, OpenOptionsExt, PermissionsExt};
use std::path::Path;

/// `O_NOFOLLOW` (Linux: 0o400000, except 0o100000 on arm / aarch64 /
/// powerpc; the BSDs and macOS: 0x100).
#[cfg(any(target_os = "linux", target_os = "android"))]
pub const O_NOFOLLOW: i32 = if cfg!(any(
    target_arch = "aarch64",
    target_arch = "arm",
    target_arch = "powerpc",
    target_arch = "powerpc64"
)) {
    0o100000
} else {
    0o400000
};
#[cfg(not(any(target_os = "linux", target_os = "android")))]
pub const O_NOFOLLOW: i32 = 0x100;

/// fsync a directory (makes a create / rename / unlink in it durable).
pub fn sync_dir(dir: &Path) -> io::Result<()> {
    File::open(dir)?.sync_all()
}

/// Create a new file exclusively, mode 0600, never through a symlink.
pub fn create_new_private(path: &Path) -> io::Result<File> {
    OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .custom_flags(O_NOFOLLOW)
        .open(path)
}

/// `O_NONBLOCK` (Linux: the same value on x86_64 and aarch64; the BSDs
/// and macOS: 0x4).
#[cfg(any(target_os = "linux", target_os = "android"))]
pub const O_NONBLOCK: i32 = 0o4000;
#[cfg(not(any(target_os = "linux", target_os = "android")))]
pub const O_NONBLOCK: i32 = 0x4;

/// Open an existing regular file for reading, never through a symlink.
/// `O_NONBLOCK`: a FIFO (or a device) swapped in never blocks the open
/// (it is refused by the check on the opened descriptor); on a regular
/// file the flag changes nothing.
pub fn open_read_nofollow(path: &Path) -> io::Result<File> {
    let f = OpenOptions::new()
        .read(true)
        .custom_flags(O_NOFOLLOW | O_NONBLOCK)
        .open(path)?;
    if !f.metadata()?.is_file() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("{} is not a regular file", path.display()),
        ));
    }
    Ok(f)
}

/// Open an existing regular file for appending, never through a symlink.
pub fn open_append_nofollow(path: &Path) -> io::Result<File> {
    let f = OpenOptions::new()
        .append(true)
        .custom_flags(O_NOFOLLOW)
        .open(path)?;
    if !f.metadata()?.is_file() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("{} is not a regular file", path.display()),
        ));
    }
    Ok(f)
}

/// Create `dir` (one level) with mode 0700 if it does not exist.
pub fn create_dir_private(dir: &Path) -> io::Result<()> {
    match std::fs::DirBuilder::new().mode(0o700).create(dir) {
        Ok(()) => Ok(()),
        Err(e) if e.kind() == io::ErrorKind::AlreadyExists => Ok(()),
        Err(e) => Err(e),
    }
}

/// `dir` must be an existing directory (not a symlink), owned by `euid` (the
/// daemon's user; root may own it only when the daemon runs as root), with
/// no group or other permission bits: the control plane's state (request
/// decisions, the replay store, evidence exports) is private to the daemon.
pub fn check_private_dir(dir: &Path, euid: u32) -> Result<(), String> {
    let shown = dir.display();
    let m = std::fs::symlink_metadata(dir).map_err(|e| format!("{shown}: {e}"))?;
    if !m.file_type().is_dir() {
        return Err(format!("{shown} is not a directory (symlinks are refused)"));
    }
    if m.uid() != euid {
        return Err(format!(
            "{shown} is owned by uid {}, not by the daemon's uid {euid}",
            m.uid()
        ));
    }
    let mode = m.permissions().mode() & 0o777;
    if mode & 0o077 != 0 {
        return Err(format!(
            "{shown} has mode {mode:03o}: it must be private to the daemon (chmod 700)"
        ));
    }
    Ok(())
}

/// Read a whole file that must be a regular file (no symlink) of at most
/// `max` bytes.
pub fn read_capped_nofollow(path: &Path, max: u64) -> io::Result<Vec<u8>> {
    read_capped_file(open_read_nofollow(path)?, path, max)
}

/// Read all of an opened file of at most `max` bytes (`path`: messages).
pub fn read_capped_file(f: File, path: &Path, max: u64) -> io::Result<Vec<u8>> {
    let len = f.metadata()?.len();
    if len > max {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("{} is larger than {max} bytes", path.display()),
        ));
    }
    let mut out = Vec::with_capacity(len as usize);
    f.take(max + 1).read_to_end(&mut out)?;
    if out.len() as u64 > max {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("{} is larger than {max} bytes", path.display()),
        ));
    }
    Ok(out)
}

/// 16 random bytes, lower-case hex (temp names, decision ids).
pub fn random_hex16() -> io::Result<String> {
    let mut b = [0u8; 16];
    robodr_blackbox::crypto::fill_random(&mut b)?;
    Ok(robodr_blackbox::crypto::to_hex(&b))
}

/// A crash point (no-op outside unit tests).
#[inline]
pub fn fault(_point: &str) -> io::Result<()> {
    #[cfg(test)]
    {
        fault::hit(_point)
    }
    #[cfg(not(test))]
    {
        Ok(())
    }
}

#[cfg(test)]
pub(crate) mod fault {
    //! Fault injection for the crash-point tests: "the process dies here".
    //! Thread-local, so parallel tests do not interfere.
    use std::cell::{Cell, RefCell};
    use std::io;

    thread_local! {
        static ARMED: RefCell<Option<(String, u32)>> = const { RefCell::new(None) };
        static FIRED: Cell<bool> = const { Cell::new(false) };
    }

    /// Fail the `nth` (1-based) time `point` is reached on this thread.
    pub fn arm(point: &str, nth: u32) {
        ARMED.with(|a| *a.borrow_mut() = Some((point.to_string(), nth.max(1))));
        FIRED.with(|f| f.set(false));
    }

    pub fn fired() -> bool {
        FIRED.with(|f| f.get())
    }

    pub fn hit(point: &str) -> io::Result<()> {
        ARMED.with(|a| {
            let mut a = a.borrow_mut();
            if let Some((p, n)) = a.as_mut() {
                if p == point {
                    if *n <= 1 {
                        *a = None;
                        // `survive.*` points are errors the process lives
                        // through (it then cleans up); the others are
                        // deaths (no cleanup).
                        if !point.starts_with("survive.") {
                            FIRED.with(|f| f.set(true));
                        }
                        return Err(io::Error::other(format!("injected crash at {point}")));
                    }
                    *n -= 1;
                }
            }
            Ok(())
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Review (TLS, finding 6): a FIFO swapped in for a CRL / PEM file
    /// used to block the open (with the CRL reload lock held) until a
    /// writer appeared; it is now refused at once.
    #[test]
    fn a_fifo_never_blocks_the_open() {
        let d = std::env::temp_dir().join(format!("robodr-fsutil-fifo-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&d);
        std::fs::create_dir_all(&d).unwrap();
        let fifo = d.join("ca.crl");
        let st = std::process::Command::new("mkfifo")
            .arg(&fifo)
            .status()
            .unwrap();
        assert!(st.success());
        let (tx, rx) = std::sync::mpsc::channel();
        let f2 = fifo.clone();
        std::thread::spawn(move || {
            let _ = tx.send(read_capped_nofollow(&f2, 1024).map(|_| ()));
        });
        let r = rx.recv_timeout(std::time::Duration::from_secs(5));
        if r.is_err() {
            // Unblock the reader thread before failing.
            let _ = std::fs::OpenOptions::new().write(true).open(&fifo);
        }
        let e = r.expect("the open blocked on a FIFO").unwrap_err();
        assert_eq!(e.kind(), io::ErrorKind::InvalidInput, "{e}");
        // A symlink is still refused, a regular file still read.
        std::fs::write(d.join("real"), b"x").unwrap();
        std::os::unix::fs::symlink(d.join("real"), d.join("link")).unwrap();
        assert!(read_capped_nofollow(&d.join("link"), 16).is_err());
        assert_eq!(read_capped_nofollow(&d.join("real"), 16).unwrap(), b"x");
        let _ = std::fs::remove_dir_all(&d);
    }
}
