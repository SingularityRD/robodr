//! Time sources. Expiry (trust file, deployments, RPKs) is judged on
//! [`effective_now`]; maintenance windows on the system clock; freshness of
//! agentd's status on `CLOCK_MONOTONIC` and the boot id.

use crate::config::ClockTrust;
use std::time::{SystemTime, UNIX_EPOCH};

/// A source of wall time (Unix seconds and milliseconds), replaceable in
/// tests.
pub trait Clock: Send {
    /// Unix seconds; a clock before 1970 is an error, never 0 (0 would make
    /// every expiry lie in the future).
    fn now_s(&self) -> Result<u64, String>;
    /// Unix milliseconds (findings' `first_seen` / `last_seen`).
    fn now_ms(&self) -> Result<u64, String> {
        Ok(self.now_s()?.saturating_mul(1000))
    }
}

/// The system clock.
#[derive(Debug, Default, Clone, Copy)]
pub struct SystemClock;

impl Clock for SystemClock {
    fn now_s(&self) -> Result<u64, String> {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_secs())
            .map_err(|_| "the system clock is before 1970".to_string())
    }
    fn now_ms(&self) -> Result<u64, String> {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| u64::try_from(d.as_millis()).unwrap_or(u64::MAX))
            .map_err(|_| "the system clock is before 1970".to_string())
    }
}

/// A fixed, settable clock (tests).
#[derive(Debug, Clone)]
pub struct FixedClock(pub std::sync::Arc<std::sync::atomic::AtomicU64>);

impl FixedClock {
    pub fn new(t: u64) -> Self {
        Self(std::sync::Arc::new(std::sync::atomic::AtomicU64::new(t)))
    }
    pub fn set(&self, t: u64) {
        self.0.store(t, std::sync::atomic::Ordering::SeqCst);
    }
}

impl Clock for FixedClock {
    fn now_s(&self) -> Result<u64, String> {
        Ok(self.0.load(std::sync::atomic::Ordering::SeqCst))
    }
}

/// The time expiry is judged on: the system clock when it is trusted,
/// otherwise the monotonic floor of depot-signed times kept in the state
/// (`time_floor`). In trusted mode a system clock behind the floor (a
/// clock set back) is overridden by the floor, so time never moves
/// backwards for the agent.
pub fn effective_now(trust: ClockTrust, system: u64, time_floor: u64) -> u64 {
    match trust {
        ClockTrust::Trusted => system.max(time_floor),
        ClockTrust::Untrusted => time_floor,
    }
}

/// Day of the week (0 = Monday) and minute of the day (UTC) of Unix
/// seconds `t`.
pub fn weekday_minute(t: u64) -> (u32, u32) {
    let days = t / 86_400;
    // 1970-01-01 was a Thursday (3 with Monday = 0).
    let wd = ((days + 3) % 7) as u32;
    let minute = ((t % 86_400) / 60) as u32;
    (wd, minute)
}

/// Whether `t` (Unix seconds, UTC) lies in the maintenance window `w`.
/// A window that runs past midnight continues into the next day.
pub fn in_window(w: &robodr_pkg::deployment::MaintenanceWindow, t: u64) -> bool {
    use robodr_pkg::deployment::Weekday::*;
    let idx = |d: &robodr_pkg::deployment::Weekday| -> u32 {
        match d {
            Mon => 0,
            Tue => 1,
            Wed => 2,
            Thu => 3,
            Fri => 4,
            Sat => 5,
            Sun => 6,
        }
    };
    let (wd, minute) = weekday_minute(t);
    let end = w.start_minute + w.duration_minutes;
    w.days.iter().any(|d| {
        let day = idx(d);
        (day == wd && minute >= w.start_minute && minute < end.min(1440))
            || (end > 1440 && (day + 1) % 7 == wd && minute < end - 1440)
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use robodr_pkg::deployment::{MaintenanceWindow, Weekday};

    #[test]
    fn weekdays() {
        assert_eq!(weekday_minute(0), (3, 0)); // Thu 1970-01-01 00:00
        assert_eq!(weekday_minute(4 * 86_400 + 61), (0, 1)); // Mon 1970-01-05 00:01
                                                             // 2026-10-26 was a Monday.
        assert_eq!(weekday_minute(1_792_972_800).0, 0);
    }

    #[test]
    fn windows_including_past_midnight() {
        let mon = 4 * 86_400; // Monday 00:00
        let w = MaintenanceWindow {
            days: vec![Weekday::Mon],
            start_minute: 23 * 60,
            duration_minutes: 120,
        };
        assert!(!in_window(&w, mon + 22 * 3600));
        assert!(in_window(&w, mon + 23 * 3600));
        assert!(in_window(&w, mon + 86_400 + 30 * 60)); // Tue 00:30
        assert!(!in_window(&w, mon + 86_400 + 60 * 60)); // Tue 01:00
        let sun = MaintenanceWindow {
            days: vec![Weekday::Sun],
            start_minute: 1439,
            duration_minutes: 2,
        };
        assert!(in_window(&sun, mon)); // Mon 00:00 follows Sun 23:59
    }

    #[test]
    fn effective_time_never_goes_back() {
        assert_eq!(effective_now(ClockTrust::Trusted, 100, 50), 100);
        assert_eq!(effective_now(ClockTrust::Trusted, 10, 50), 50);
        assert_eq!(effective_now(ClockTrust::Untrusted, 1_000_000, 50), 50);
    }
}
