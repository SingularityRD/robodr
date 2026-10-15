//! Time for the agent.
//!
//! The agent never reads a system clock on its own. Time comes from an
//! injected [`Clock`] (the black box's clock trait, re-exported here), so a
//! replay with the same clock produces byte-identical evidence and findings.
//!
//! * `mono_ns` drives everything that measures durations: the responder's
//!   escalation windows (`mono_ns / 1e6` ms), the Motion Firewall's `now`
//!   and the motion monitor's observer time.
//! * `wall_ns` is evidence only: black-box record time and the OCSF
//!   finding times (`wall_ns / 1e6` ms since the Unix epoch).
//!
//! The black-box [`robodr_blackbox::Recorder`] owns its clock, so the agent
//! hands it an internal follow clock that it moves to each event's time before
//! appending. Record times therefore equal the agent's event times.

pub use robodr_blackbox::{Clock, SteppingClock, SystemClock, TimeSource, Timestamp};

use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex, PoisonError};

/// Deterministic clock for replays and tests: the `k`-th call (0-based)
/// returns `wall_start_ns + k * step_ns` and `mono_start_ns + k * step_ns`
/// (saturating). [`crate::Agent::new`] reads it once (the black box's
/// genesis), so with [`crate::Agent::tick`] the `k`-th event (1-based) is
/// observed at `mono_start_ns + k * step_ns`.
#[derive(Debug)]
pub struct ReplayClock {
    wall_start_ns: u64,
    mono_start_ns: u64,
    step_ns: u64,
    source: TimeSource,
    calls: AtomicU64,
}

impl ReplayClock {
    pub fn new(wall_start_ns: u64, mono_start_ns: u64, step_ns: u64, source: TimeSource) -> Self {
        Self {
            wall_start_ns,
            mono_start_ns,
            step_ns,
            source,
            calls: AtomicU64::new(0),
        }
    }
}

impl Clock for ReplayClock {
    fn now(&self) -> Timestamp {
        let k = self.calls.fetch_add(1, Ordering::Relaxed);
        let off = k.saturating_mul(self.step_ns);
        Timestamp {
            wall_ns: self.wall_start_ns.saturating_add(off),
            mono_ns: self.mono_start_ns.saturating_add(off),
            source: self.source,
        }
    }
}

/// The recorder's clock: whatever time the agent last set. `mono_ns` never
/// goes backwards (the verifier warns on monotonic regressions); `wall_ns`
/// and the source are passed through as given.
#[derive(Debug, Clone)]
pub(crate) struct FollowClock(Arc<Mutex<Timestamp>>);

impl FollowClock {
    pub(crate) fn new(start: Timestamp) -> Self {
        Self(Arc::new(Mutex::new(start)))
    }

    pub(crate) fn set(&self, t: Timestamp) {
        let mut g = self.0.lock().unwrap_or_else(PoisonError::into_inner);
        g.mono_ns = g.mono_ns.max(t.mono_ns);
        g.wall_ns = t.wall_ns;
        g.source = t.source;
    }
}

impl Clock for FollowClock {
    fn now(&self) -> Timestamp {
        *self.0.lock().unwrap_or_else(PoisonError::into_inner)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn replay_clock_steps_and_saturates() {
        let c = ReplayClock::new(10, 0, 5, TimeSource::Unknown);
        assert_eq!(c.now().mono_ns, 0);
        assert_eq!(c.now().mono_ns, 5);
        let t = c.now();
        assert_eq!((t.wall_ns, t.mono_ns), (20, 10));
        let s = ReplayClock::new(u64::MAX - 1, u64::MAX, u64::MAX, TimeSource::Rtc);
        s.now();
        let t = s.now();
        assert_eq!((t.wall_ns, t.mono_ns), (u64::MAX, u64::MAX));
    }

    #[test]
    fn follow_clock_mono_never_regresses() {
        let ts = |w, m| Timestamp {
            wall_ns: w,
            mono_ns: m,
            source: TimeSource::Gps,
        };
        let f = FollowClock::new(ts(100, 50));
        f.set(ts(90, 40));
        let n = f.now();
        assert_eq!((n.wall_ns, n.mono_ns), (90, 50));
        f.set(ts(200, 70));
        assert_eq!(f.now().mono_ns, 70);
    }
}
