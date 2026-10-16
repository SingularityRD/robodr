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
//!
//! # Time jumps
//!
//! Every observation time goes through a [`TimeGuard`] first:
//!
//! * **Monotonic regression** (`mono_ns` smaller than the last one): the time
//!   is clamped to the last value, so escalation windows, the firewall and
//!   the motion monitor never see time run backwards. A
//!   [`ClockAnomaly::MonoRegression`] is reported.
//! * **Wall/monotonic disagreement** (wall time moved by more than the
//!   tolerance away from what monotonic time says elapsed: an NTP/GNSS step,
//!   an RTC reset, or a spoofed time source): wall time is *kept as given*
//!   (evidence must show what the platform reported) and a
//!   [`ClockAnomaly::WallJump`] is reported. Nothing that measures durations
//!   uses wall time, so a wall jump cannot shorten a rate limit or an
//!   escalation window.
//!
//! The agent records each anomaly as a signed `robodr.agent_fault` note in
//! the black box and in [`crate::Agent::faults`]. Anomalies never feed the
//! responder: a clock glitch must not by itself cause a motion request.
//!
//! A forward jump of the monotonic clock alone cannot be told apart from a
//! quiet period and is not detected (it can only make windows expire early,
//! which the responder's own rate limiting bounds).

pub use robodr_blackbox::{Clock, SteppingClock, SystemClock, TimeSource, Timestamp};

use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex, PoisonError};

use serde::Serialize;

/// Default tolerance for wall vs monotonic disagreement between two
/// consecutive observations (1 s).
pub const DEFAULT_CLOCK_JUMP_TOLERANCE_NS: u64 = 1_000_000_000;

/// A time anomaly seen by [`TimeGuard::observe`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(tag = "anomaly", rename_all = "snake_case")]
pub enum ClockAnomaly {
    /// Monotonic time went backwards from `held_ns` to `observed_ns`; the
    /// agent kept `held_ns`.
    MonoRegression { observed_ns: u64, held_ns: u64 },
    /// Wall time moved by `wall_delta_ns` (signed, saturated to `i64`) while
    /// monotonic time moved by `mono_delta_ns`.
    WallJump {
        wall_delta_ns: i64,
        mono_delta_ns: u64,
    },
}

/// Sanitises observation times (see the module docs). Pure and
/// deterministic.
#[derive(Debug, Clone)]
pub struct TimeGuard {
    last: Timestamp,
    tolerance_ns: u64,
}

impl TimeGuard {
    /// `start` is the first trusted time (the agent's construction time).
    pub fn new(start: Timestamp, tolerance_ns: u64) -> Self {
        Self {
            last: start,
            tolerance_ns,
        }
    }

    /// Last time handed out.
    pub fn last(&self) -> Timestamp {
        self.last
    }

    /// Sanitise `t`: `mono_ns` never goes backwards; wall time is passed
    /// through. Returns the time to use and the anomaly, if any.
    pub fn observe(&mut self, t: Timestamp) -> (Timestamp, Option<ClockAnomaly>) {
        let prev = self.last;
        if t.mono_ns < prev.mono_ns {
            let out = Timestamp {
                mono_ns: prev.mono_ns,
                ..t
            };
            self.last = out;
            return (
                out,
                Some(ClockAnomaly::MonoRegression {
                    observed_ns: t.mono_ns,
                    held_ns: prev.mono_ns,
                }),
            );
        }
        let d_mono = t.mono_ns - prev.mono_ns;
        let d_wall = i128::from(t.wall_ns) - i128::from(prev.wall_ns);
        let skew = d_wall - i128::from(d_mono);
        self.last = t;
        if skew.unsigned_abs() > u128::from(self.tolerance_ns) {
            let wall_delta_ns =
                i64::try_from(d_wall).unwrap_or(if d_wall < 0 { i64::MIN } else { i64::MAX });
            return (
                t,
                Some(ClockAnomaly::WallJump {
                    wall_delta_ns,
                    mono_delta_ns: d_mono,
                }),
            );
        }
        (t, None)
    }
}

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

    fn ts(w: u64, m: u64) -> Timestamp {
        Timestamp {
            wall_ns: w,
            mono_ns: m,
            source: TimeSource::Ptp,
        }
    }

    #[test]
    fn time_guard_clamps_mono_regressions() {
        let mut g = TimeGuard::new(ts(1_000, 100), 50);
        let (t, a) = g.observe(ts(1_010, 110));
        assert_eq!((t.mono_ns, a), (110, None));
        let (t, a) = g.observe(ts(1_020, 90));
        assert_eq!(t.mono_ns, 110);
        assert_eq!(t.wall_ns, 1_020);
        assert_eq!(
            a,
            Some(ClockAnomaly::MonoRegression {
                observed_ns: 90,
                held_ns: 110
            })
        );
        // Equal mono is not a regression.
        assert_eq!(g.observe(ts(1_020, 110)).1, None);
        // Clamp holds against a regression to zero.
        assert_eq!(g.observe(ts(0, 0)).0.mono_ns, 110);
    }

    #[test]
    fn time_guard_reports_wall_jumps_both_ways() {
        let mut g = TimeGuard::new(ts(1_000_000, 0), 1_000);
        // Within tolerance.
        assert_eq!(g.observe(ts(1_010_500, 10_000)).1, None);
        // Wall steps forward an hour while mono moves 1 us.
        let (t, a) = g.observe(ts(1_010_500 + 3_600_000_000_000, 11_000));
        assert_eq!(
            t.wall_ns,
            1_010_500 + 3_600_000_000_000,
            "wall kept as given"
        );
        assert_eq!(
            a,
            Some(ClockAnomaly::WallJump {
                wall_delta_ns: 3_600_000_000_000,
                mono_delta_ns: 1_000
            })
        );
        // Wall steps backwards.
        let (_, a) = g.observe(ts(0, 12_000));
        assert!(matches!(
            a,
            Some(ClockAnomaly::WallJump { wall_delta_ns, .. }) if wall_delta_ns < 0
        ));
    }

    #[test]
    fn time_guard_extremes_do_not_overflow() {
        let mut g = TimeGuard::new(ts(0, 0), 0);
        let (_, a) = g.observe(ts(u64::MAX, 0));
        assert_eq!(
            a,
            Some(ClockAnomaly::WallJump {
                wall_delta_ns: i64::MAX,
                mono_delta_ns: 0
            })
        );
        let (_, a) = g.observe(ts(0, u64::MAX));
        assert!(matches!(
            a,
            Some(ClockAnomaly::WallJump {
                wall_delta_ns: i64::MIN,
                ..
            })
        ));
        let mut g = TimeGuard::new(ts(5, 5), u64::MAX);
        assert_eq!(g.observe(ts(u64::MAX, 5)).1, None, "u64::MAX disables");
        // A replay clock never trips the guard.
        let c = ReplayClock::new(1 << 60, 0, 20_000_000, TimeSource::Unknown);
        let mut g = TimeGuard::new(c.now(), DEFAULT_CLOCK_JUMP_TOLERANCE_NS);
        for _ in 0..100 {
            assert_eq!(g.observe(c.now()).1, None);
        }
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
