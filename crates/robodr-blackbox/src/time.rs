//! Timestamps for records.
//!
//! Air-gapped units have no NTP, so every record carries both a wall-clock and
//! a monotonic reading plus a [`TimeSource`] tag saying how much the wall clock
//! can be trusted. The verifier never rejects a record because of its wall
//! time (it is evidence, not an authenticator); it only warns when the
//! monotonic clock runs backwards within one recorder run.

use serde::{Deserialize, Serialize};
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Instant, SystemTime, UNIX_EPOCH};

/// Where the wall-clock reading came from.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum TimeSource {
    /// No information; wall time may be arbitrary.
    Unknown,
    /// Battery-backed real-time clock, not disciplined.
    Rtc,
    /// GPS/GNSS-disciplined.
    Gps,
    /// IEEE 1588 PTP from a local grandmaster.
    Ptp,
}

impl TimeSource {
    pub fn to_u8(self) -> u8 {
        match self {
            TimeSource::Unknown => 0,
            TimeSource::Rtc => 1,
            TimeSource::Gps => 2,
            TimeSource::Ptp => 3,
        }
    }

    pub fn from_u8(v: u8) -> Option<Self> {
        Some(match v {
            0 => TimeSource::Unknown,
            1 => TimeSource::Rtc,
            2 => TimeSource::Gps,
            3 => TimeSource::Ptp,
            _ => return None,
        })
    }
}

/// A record's time: wall clock (ns since the Unix epoch, 0 if before 1970 or
/// unavailable), a monotonic reading (ns, meaningful only within one recorder
/// run, which `Resume` records delimit) and the wall clock's source.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Timestamp {
    pub wall_ns: u64,
    pub mono_ns: u64,
    pub source: TimeSource,
}

/// Supplies timestamps to the recorder.
pub trait Clock: Send {
    fn now(&self) -> Timestamp;
}

/// Production clock: `SystemTime` for wall, `Instant` (CLOCK_MONOTONIC on
/// Linux) relative to construction for mono. The integrator states the wall
/// clock's discipline via `source`.
#[derive(Debug)]
pub struct SystemClock {
    source: TimeSource,
    origin: Instant,
}

impl SystemClock {
    pub fn new(source: TimeSource) -> Self {
        Self {
            source,
            origin: Instant::now(),
        }
    }
}

impl Clock for SystemClock {
    fn now(&self) -> Timestamp {
        let wall_ns = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| u64::try_from(d.as_nanos()).unwrap_or(u64::MAX))
            .unwrap_or(0);
        let mono_ns = u64::try_from(self.origin.elapsed().as_nanos()).unwrap_or(u64::MAX);
        Timestamp {
            wall_ns,
            mono_ns,
            source: self.source,
        }
    }
}

/// Deterministic clock for tests and simulation: each call advances by `step`.
#[derive(Debug)]
pub struct SteppingClock {
    next: AtomicU64,
    step: u64,
    source: TimeSource,
}

impl SteppingClock {
    pub fn new(start_ns: u64, step_ns: u64, source: TimeSource) -> Self {
        Self {
            next: AtomicU64::new(start_ns),
            step: step_ns,
            source,
        }
    }
}

impl Clock for SteppingClock {
    fn now(&self) -> Timestamp {
        let t = self.next.fetch_add(self.step, Ordering::Relaxed);
        Timestamp {
            wall_ns: t,
            mono_ns: t,
            source: self.source,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn time_source_codes_round_trip() {
        for s in [
            TimeSource::Unknown,
            TimeSource::Rtc,
            TimeSource::Gps,
            TimeSource::Ptp,
        ] {
            assert_eq!(TimeSource::from_u8(s.to_u8()), Some(s));
        }
        assert_eq!(TimeSource::from_u8(4), None);
        assert_eq!(TimeSource::from_u8(255), None);
    }

    #[test]
    fn system_clock_is_monotonic_and_tagged() {
        let c = SystemClock::new(TimeSource::Gps);
        let a = c.now();
        let b = c.now();
        assert!(b.mono_ns >= a.mono_ns);
        assert_eq!(a.source, TimeSource::Gps);
        assert!(a.wall_ns > 0);
    }

    #[test]
    fn stepping_clock_steps() {
        let c = SteppingClock::new(100, 5, TimeSource::Unknown);
        assert_eq!(c.now().wall_ns, 100);
        assert_eq!(c.now().mono_ns, 105);
    }
}
