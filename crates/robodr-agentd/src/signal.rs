//! Graceful shutdown on `SIGTERM` / `SIGINT`, std only.
//!
//! [`install`] registers a handler through libc's `signal(2)` (declared with
//! `extern "C"`; std already links libc on Linux). The handler only stores
//! into two atomics, which is async-signal-safe; the daemon's main loop polls
//! [`requested`] at least every few tens of milliseconds and then shuts down
//! in order (stop inputs, drain the bounded queue, final heartbeat, seal the
//! black box). glibc's `signal` installs the handler with BSD semantics
//! (`SA_RESTART`, not reset after delivery), so a second signal is handled
//! the same way and interrupted reads are restarted; every blocking read in
//! the daemon has a timeout (except stdin, whose thread is not joined).
//!
//! The signal numbers used are 2 (`SIGINT`) and 15 (`SIGTERM`), identical on
//! every Linux architecture.

use std::ffi::c_int;
use std::sync::atomic::{AtomicBool, AtomicI32, Ordering};

/// `SIGINT`.
pub const SIGINT: c_int = 2;
/// `SIGTERM`.
pub const SIGTERM: c_int = 15;

static REQUESTED: AtomicBool = AtomicBool::new(false);
static LAST_SIGNAL: AtomicI32 = AtomicI32::new(0);

/// `SIG_ERR` as returned by `signal(2)`.
const SIG_ERR: usize = usize::MAX;

extern "C" {
    fn signal(signum: c_int, handler: usize) -> usize;
}

extern "C" fn on_signal(sig: c_int) {
    LAST_SIGNAL.store(sig, Ordering::SeqCst);
    REQUESTED.store(true, Ordering::SeqCst);
}

/// Install the shutdown handler for `SIGTERM` and `SIGINT`.
// FFI: std has no signal-handler API.
#[allow(unsafe_code)]
pub fn install() -> std::io::Result<()> {
    for sig in [SIGINT, SIGTERM] {
        let handler: extern "C" fn(c_int) = on_signal;
        // SAFETY: `on_signal` is an `extern "C" fn(c_int)` that only touches
        // atomics (async-signal-safe); `signal` is the libc function with
        // this C signature.
        let prev = unsafe { signal(sig, handler as usize) };
        if prev == SIG_ERR {
            return Err(std::io::Error::last_os_error());
        }
    }
    Ok(())
}

/// A shutdown signal has been received.
pub fn requested() -> bool {
    REQUESTED.load(Ordering::SeqCst)
}

/// The last signal received (0 = none).
pub fn last_signal() -> c_int {
    LAST_SIGNAL.load(Ordering::SeqCst)
}

/// Request shutdown as if a signal had arrived (tests, embedders).
pub fn request() {
    REQUESTED.store(true, Ordering::SeqCst);
}
