//! Liveness for supervisors: systemd `sd_notify` and a monotonic clock for
//! `status.json` staleness.
//!
//! # sd_notify
//!
//! [`Notifier`] implements the `sd_notify(3)` datagram protocol with std
//! only (`UnixDatagram`, path or Linux abstract address from
//! `NOTIFY_SOCKET`). The daemon sends `READY=1` once it is started,
//! `WATCHDOG=1` from its **main loop** (so a loop stalled in a slow fsync
//! or a hang stops the keep-alives and systemd's `WatchdogSec=` restarts
//! the unit), `STATUS=<state>` with each tick, and `STOPPING=1` at
//! shutdown. Without `NOTIFY_SOCKET` (tests, a shell) every call is a
//! no-op. Send errors are ignored: supervision is best effort and must never
//! stop the daemon.
//!
//! # Staleness of `status.json`
//!
//! `status.json` is rewritten by the main loop every tick. If the loop
//! stalls, the file keeps its last content, possibly `"state": "ok"`. Each
//! status therefore carries `updated_mono_ms` (`CLOCK_MONOTONIC`, ms; the
//! same clock any local process reads, valid within one boot), `boot_id`
//! and `stale_after_ms`. **Consumers must treat the status as `unknown`**
//! when `running` is false, the boot id differs from the current one, or
//! `now_mono_ms - updated_mono_ms > stale_after_ms`; see
//! [`crate::daemon::effective_state`].

use std::os::unix::net::{SocketAddr, UnixDatagram};
use std::time::Duration;

#[repr(C)]
struct Timespec {
    tv_sec: i64,
    tv_nsec: i64,
}

extern "C" {
    fn clock_gettime(clk: i32, ts: *mut Timespec) -> i32;
}

const CLOCK_MONOTONIC: i32 = 1;

/// `CLOCK_MONOTONIC` in milliseconds (system-wide, not process-relative).
pub fn monotonic_ms() -> u64 {
    let mut ts = Timespec {
        tv_sec: 0,
        tv_nsec: 0,
    };
    // SAFETY: `ts` is a valid, writable timespec; CLOCK_MONOTONIC exists on
    // every Linux. On the (impossible) failure, 0 makes the status stale.
    let rc = unsafe { clock_gettime(CLOCK_MONOTONIC, &mut ts) };
    if rc != 0 || ts.tv_sec < 0 || ts.tv_nsec < 0 {
        return 0;
    }
    (ts.tv_sec as u64)
        .saturating_mul(1000)
        .saturating_add(ts.tv_nsec as u64 / 1_000_000)
}

/// An `sd_notify` sender (no-op without `NOTIFY_SOCKET`).
#[derive(Debug, Default)]
pub struct Notifier {
    target: Option<(UnixDatagram, SocketAddr)>,
}

/// Parse a `NOTIFY_SOCKET` value: an absolute path, or `@name` for a Linux
/// abstract socket. Anything else is ignored (`None`).
pub fn notify_addr(value: &str) -> Option<SocketAddr> {
    if let Some(name) = value.strip_prefix('@') {
        use std::os::linux::net::SocketAddrExt;
        if name.is_empty() {
            return None;
        }
        return SocketAddr::from_abstract_name(name.as_bytes()).ok();
    }
    if value.starts_with('/') {
        return SocketAddr::from_pathname(value).ok();
    }
    None
}

impl Notifier {
    /// From `NOTIFY_SOCKET` in the environment.
    pub fn from_env() -> Self {
        match std::env::var("NOTIFY_SOCKET") {
            Ok(v) => Self::to(&v),
            Err(_) => Self::default(),
        }
    }

    /// To an explicit `NOTIFY_SOCKET`-style address.
    pub fn to(value: &str) -> Self {
        let target = UnixDatagram::unbound()
            .ok()
            .zip(notify_addr(value))
            .inspect(|(s, _)| {
                let _ = s.set_write_timeout(Some(Duration::from_millis(100)));
            });
        Self { target }
    }

    pub fn enabled(&self) -> bool {
        self.target.is_some()
    }

    /// Send one notification (newline-separated `KEY=value` lines).
    /// `true` if it was sent.
    pub fn notify(&self, msg: &str) -> bool {
        match &self.target {
            Some((s, a)) => s.send_to_addr(msg.as_bytes(), a).is_ok(),
            None => false,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn monotonic_is_monotonic_and_plausible() {
        let a = monotonic_ms();
        std::thread::sleep(Duration::from_millis(20));
        let b = monotonic_ms();
        assert!(a > 0 && b >= a + 15, "{a} {b}");
    }

    #[test]
    fn addresses() {
        assert!(notify_addr("/run/systemd/notify").is_some());
        assert!(notify_addr("@abstract-name").is_some());
        for bad in ["", "@", "relative/path", "x"] {
            assert!(notify_addr(bad).is_none(), "{bad}");
        }
        let n = Notifier::to("nope");
        assert!(!n.enabled());
        assert!(!n.notify("READY=1"));
    }

    #[test]
    fn sends_to_a_path_socket_and_an_abstract_socket() {
        let dir = std::env::temp_dir().join(format!("robodr-agentd-notify-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let p = dir.join("notify.sock");
        let rx = UnixDatagram::bind(&p).unwrap();
        let n = Notifier::to(p.to_str().unwrap());
        assert!(n.enabled());
        assert!(n.notify("READY=1\nSTATUS=ok"));
        let mut buf = [0u8; 64];
        let k = rx.recv(&mut buf).unwrap();
        assert_eq!(&buf[..k], b"READY=1\nSTATUS=ok");

        use std::os::linux::net::SocketAddrExt;
        let name = format!("robodr-agentd-test-{}", std::process::id());
        let a = SocketAddr::from_abstract_name(name.as_bytes()).unwrap();
        let rx2 = UnixDatagram::bind_addr(&a).unwrap();
        let n = Notifier::to(&format!("@{name}"));
        assert!(n.notify("WATCHDOG=1"));
        let k = rx2.recv(&mut buf).unwrap();
        assert_eq!(&buf[..k], b"WATCHDOG=1");
        // A receiver that went away: no panic, just false.
        drop(rx);
        let _ = std::fs::remove_file(&p);
        assert!(!Notifier::to(p.to_str().unwrap()).notify("WATCHDOG=1"));
        let _ = std::fs::remove_dir_all(&dir);
    }
}
