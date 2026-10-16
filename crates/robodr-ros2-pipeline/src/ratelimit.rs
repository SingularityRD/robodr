//! Per-rule token buckets for the noisy protocol / capture findings.
//!
//! Dedup already collapses *identical* findings, but protocol findings are
//! keyed by source IP (and capture findings carry counts), so an attacker
//! spraying source addresses or malformed frames could still produce a
//! finding per packet. Rules under `robot.rtps.*`, `robot.capture.*` and
//! `robot.sensor.*` (the pipeline's own overflow summary) are therefore rate
//! limited per rule: a burst of `burst` findings, then one
//! more per `interval`. Suppressed findings are counted and the next finding
//! of that rule that gets through says how many were suppressed; they are
//! **not** remembered by dedup, so a suppressed finding that recurs later is
//! reported then.
//!
//! So is `robot.motion.undecodable_sample` ([`LIMITED_RULES`]). The other
//! profile rules (`robot.ros2.*`, `robot.motion.*`, ...) and the binding
//! findings are never rate limited: each is a distinct, security-relevant
//! fact and dedup keeps their memory bounded.
//!
//! Memory: one bucket per distinct rule id; the rate-limited rule ids are
//! the pipeline's own constants, so the map is bounded by that set.

use std::collections::BTreeMap;
use std::time::{Duration, Instant};

/// Default burst per rule.
pub const DEFAULT_BURST: u32 = 20;
/// Default refill interval (one finding per interval after the burst).
pub const DEFAULT_INTERVAL: Duration = Duration::from_secs(6);

/// Rule-id prefixes that are rate limited.
pub const LIMITED_PREFIXES: &[&str] = &["robot.rtps.", "robot.capture.", "robot.sensor."];

/// Individual rules outside those prefixes that are rate limited too: the
/// motion decode path's "sample not inspected" finding (one per bad sample
/// could otherwise reach the command rate, e.g. 50 Hz).
pub const LIMITED_RULES: &[&str] = &[crate::motion::rules::MOTION_UNDECODABLE_SAMPLE];

/// Is this rule rate limited?
pub fn is_limited(rule: &str) -> bool {
    LIMITED_PREFIXES.iter().any(|p| rule.starts_with(p)) || LIMITED_RULES.contains(&rule)
}

#[derive(Debug, Clone, Copy)]
struct Bucket {
    tokens: u32,
    last_refill: Instant,
    suppressed: u64,
}

/// See the module docs.
#[derive(Debug, Clone)]
pub struct RateLimiter {
    burst: u32,
    interval: Duration,
    buckets: BTreeMap<String, Bucket>,
    suppressed_total: u64,
}

impl RateLimiter {
    /// `burst` is clamped to >= 1, `interval` to >= 1 ms.
    pub fn new(burst: u32, interval: Duration) -> Self {
        Self {
            burst: burst.max(1),
            interval: interval.max(Duration::from_millis(1)),
            buckets: BTreeMap::new(),
            suppressed_total: 0,
        }
    }

    /// Take a token for `rule`. `Some(n)`: allowed, `n` findings of this
    /// rule were suppressed since the last allowed one. `None`: suppressed.
    pub fn allow(&mut self, rule: &str, now: Instant) -> Option<u64> {
        let (burst, interval) = (self.burst, self.interval);
        let b = self.buckets.entry(rule.to_string()).or_insert(Bucket {
            tokens: burst,
            last_refill: now,
            suppressed: 0,
        });
        let elapsed = now.saturating_duration_since(b.last_refill);
        let refill = elapsed.as_nanos() / interval.as_nanos();
        if refill > 0 {
            let refill = u32::try_from(refill).unwrap_or(u32::MAX);
            b.tokens = b.tokens.saturating_add(refill).min(burst);
            // Advance by whole intervals only, so partial progress is kept.
            b.last_refill += interval.saturating_mul(refill);
            if b.tokens == burst {
                b.last_refill = now;
            }
        }
        if b.tokens == 0 {
            b.suppressed += 1;
            self.suppressed_total += 1;
            return None;
        }
        b.tokens -= 1;
        Some(std::mem::take(&mut b.suppressed))
    }

    /// Findings suppressed so far, all rules.
    pub fn suppressed_total(&self) -> u64 {
        self.suppressed_total
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn burst_then_refill_and_suppressed_count() {
        let t0 = Instant::now();
        let mut r = RateLimiter::new(3, Duration::from_secs(10));
        for _ in 0..3 {
            assert_eq!(r.allow("robot.rtps.x", t0), Some(0));
        }
        for _ in 0..5 {
            assert_eq!(r.allow("robot.rtps.x", t0), None);
        }
        // Another rule has its own bucket.
        assert_eq!(r.allow("robot.capture.y", t0), Some(0));
        // Not yet refilled.
        assert_eq!(r.allow("robot.rtps.x", t0 + Duration::from_secs(9)), None);
        // One token after one interval; reports the 6 suppressed.
        assert_eq!(
            r.allow("robot.rtps.x", t0 + Duration::from_secs(10)),
            Some(6)
        );
        assert_eq!(r.allow("robot.rtps.x", t0 + Duration::from_secs(10)), None);
        // A long pause refills to the burst, not beyond.
        let later = t0 + Duration::from_secs(1000);
        for _ in 0..3 {
            assert!(r.allow("robot.rtps.x", later).is_some());
        }
        assert_eq!(r.allow("robot.rtps.x", later), None);
        assert_eq!(r.suppressed_total(), 8);
    }

    #[test]
    fn clamps_and_limited_prefixes() {
        let t0 = Instant::now();
        let mut r = RateLimiter::new(0, Duration::ZERO);
        assert_eq!(r.allow("a", t0), Some(0));
        assert_eq!(r.allow("a", t0), None);
        assert!(r.allow("a", t0 + Duration::from_millis(1)).is_some());
        assert!(is_limited("robot.rtps.malformed_discovery"));
        assert!(is_limited("robot.capture.malformed_frames"));
        assert!(!is_limited("robot.ros2.endpoint_source_mismatch"));
        assert!(!is_limited("robot.rtpsx"));
    }
}
