//! Process plumbing for the binary, std only (the same patterns as
//! robodr-agentd's `signal` / `notify` modules): shutdown on `SIGTERM` /
//! `SIGINT`, `sd_notify(3)` (`READY=1`, `WATCHDOG=1` from the main loop,
//! `STOPPING=1`), and the clocks.

use std::ffi::c_int;
use std::os::unix::net::{SocketAddr, UnixDatagram};
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

static REQUESTED: AtomicBool = AtomicBool::new(false);
const SIG_ERR: usize = usize::MAX;

extern "C" {
    fn signal(signum: c_int, handler: usize) -> usize;
    fn clock_gettime(clk: i32, ts: *mut Timespec) -> i32;
}

extern "C" fn on_signal(_sig: c_int) {
    REQUESTED.store(true, Ordering::SeqCst);
}

/// Install the shutdown handler for `SIGINT` (2) and `SIGTERM` (15).
pub fn install_signals() -> std::io::Result<()> {
    for sig in [2, 15] {
        let handler: extern "C" fn(c_int) = on_signal;
        // SAFETY: `on_signal` only stores into an atomic (async-signal-safe);
        // `signal` is the libc function with this C signature.
        let prev = unsafe { signal(sig, handler as usize) };
        if prev == SIG_ERR {
            return Err(std::io::Error::last_os_error());
        }
    }
    Ok(())
}

pub fn shutdown_requested() -> bool {
    REQUESTED.load(Ordering::SeqCst)
}

#[repr(C)]
struct Timespec {
    tv_sec: i64,
    tv_nsec: i64,
}

fn clock_ns(clk: i32) -> u64 {
    let mut ts = Timespec {
        tv_sec: 0,
        tv_nsec: 0,
    };
    // SAFETY: `ts` is a valid, writable timespec.
    let rc = unsafe { clock_gettime(clk, &mut ts) };
    if rc != 0 || ts.tv_sec < 0 || ts.tv_nsec < 0 {
        return 0;
    }
    (ts.tv_sec as u64)
        .saturating_mul(1_000_000_000)
        .saturating_add(ts.tv_nsec as u64)
}

/// `CLOCK_MONOTONIC`, ns (system-wide; the firewall's clock).
pub fn monotonic_ns() -> u64 {
    clock_ns(1)
}

/// `CLOCK_REALTIME`, ns (to compare with the kernel queue timestamp).
pub fn realtime_ns() -> u64 {
    clock_ns(0)
}

/// An `sd_notify` sender (no-op without `NOTIFY_SOCKET`).
#[derive(Debug, Default)]
pub struct Notifier {
    target: Option<(UnixDatagram, SocketAddr)>,
}

impl Notifier {
    pub fn from_env() -> Self {
        let Ok(v) = std::env::var("NOTIFY_SOCKET") else {
            return Self::default();
        };
        let addr = if let Some(name) = v.strip_prefix('@') {
            use std::os::linux::net::SocketAddrExt;
            (!name.is_empty())
                .then(|| SocketAddr::from_abstract_name(name.as_bytes()).ok())
                .flatten()
        } else if v.starts_with('/') {
            SocketAddr::from_pathname(&v).ok()
        } else {
            None
        };
        let target = UnixDatagram::unbound().ok().zip(addr).inspect(|(s, _)| {
            let _ = s.set_write_timeout(Some(Duration::from_millis(100)));
        });
        Self { target }
    }

    pub fn notify(&self, msg: &str) -> bool {
        match &self.target {
            Some((s, a)) => s.send_to_addr(msg.as_bytes(), a).is_ok(),
            None => false,
        }
    }
}
