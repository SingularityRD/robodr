//! The depot's single-writer lock (`state_dir/depot.lock`, `flock(2)`):
//! the server opens the depot for each request and an operator's command
//! for its own run, so their database writes never interleave. The lock
//! lives as long as the [`Depot`](crate::depot::Depot); the kernel drops
//! it when the process dies (no stale lock).

use crate::{err, DepotError};
use std::fs::{File, OpenOptions};
use std::os::unix::fs::OpenOptionsExt;
use std::path::Path;
use std::time::{Duration, Instant};

mod sys {
    //! `flock(2)`, declared by hand as `robodr-diode`, `robodr-blackbox`
    //! and `robodr-export` do (no libc crate offline).
    pub const LOCK_EX: i32 = 2;
    pub const LOCK_NB: i32 = 4;
    extern "C" {
        pub fn flock(fd: i32, operation: i32) -> i32;
    }
}

/// `O_NOFOLLOW` (as `robodr-seal`).
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

/// Take the exclusive lock on `p`, waiting at most `wait`.
// FFI: `File::lock` (std 1.89) is newer than the MSRV (1.87).
#[allow(unsafe_code)]
pub fn lock(p: &Path, wait: Duration) -> Result<File, DepotError> {
    use std::os::unix::io::AsRawFd;
    let f = OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .truncate(false)
        .mode(0o600)
        .custom_flags(O_NOFOLLOW)
        .open(p)
        .map_err(|e| err(format!("{}: {e}", p.display())))?;
    if !f.metadata().map(|m| m.is_file()).unwrap_or(false) {
        return Err(err(format!("{}: not a regular file", p.display())));
    }
    let until = Instant::now() + wait;
    loop {
        // SAFETY: `flock` only reads its two integer arguments; the
        // descriptor is owned by `f`, which outlives the call.
        let rc = unsafe { sys::flock(f.as_raw_fd(), sys::LOCK_EX | sys::LOCK_NB) };
        if rc == 0 {
            return Ok(f);
        }
        let e = std::io::Error::last_os_error();
        if e.kind() != std::io::ErrorKind::WouldBlock {
            return Err(err(format!("{}: {e}", p.display())));
        }
        if Instant::now() >= until {
            return Err(err(format!(
                "{}: the depot is busy (another command or the server holds it)",
                p.display()
            )));
        }
        std::thread::sleep(Duration::from_millis(20));
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn second_holder_waits_then_fails_and_drop_releases() {
        let d = std::env::temp_dir().join(format!("robodr-depot-lock-{}", std::process::id()));
        std::fs::create_dir_all(&d).unwrap();
        let p = d.join("depot.lock");
        let a = lock(&p, Duration::ZERO).unwrap();
        // flock is per open file description: a second open in the same
        // process conflicts like another process would.
        let e = lock(&p, Duration::from_millis(60)).unwrap_err();
        assert!(e.0.contains("busy"), "{e}");
        drop(a);
        let _b = lock(&p, Duration::ZERO).unwrap();
        // A symlink in the lock's place is refused.
        let l = d.join("link.lock");
        std::os::unix::fs::symlink(&p, &l).unwrap();
        assert!(lock(&l, Duration::ZERO).is_err());
        std::fs::remove_dir_all(&d).unwrap();
    }
}
