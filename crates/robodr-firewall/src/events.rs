//! Deviation reporting without allocating in the hot path.
//!
//! [`robodr_events::Deviation`] carries a `String` detail, so constructing one
//! allocates. `check` therefore records a compact, `Copy` [`FirewallEvent`]
//! into an [`EventBuffer`] whose storage is allocated once when the firewall is
//! built; when it is full, further events are **dropped and counted** (never
//! reallocated). The caller drains the buffer outside the control loop and
//! turns each event into a `Deviation` via `Deviation::new`
//! ([`FirewallEvent::to_deviation`]); that conversion is where formatting and
//! allocation happen.
//!
//! # Mode
//! Each deviation carries the firewall's operating [`Mode`]:
//! [`Mode::Observe`] when the policy can never enforce
//! ([`Policy::is_observe_only`]: profile not locked, or a
//! `PassThroughObserveOnly` platform), [`Mode::Enforce`] otherwise. This is
//! the same rule [`robodr_events::profile::Profile::evaluate`] uses (mode
//! follows the profile lock), so a responder never acts on a would-have
//! verdict of an observe-only firewall. A `FailOpen` internal fault on an
//! *enforcing* firewall is also [`EventAction::ObservedOnly`] (the command
//! went through unchecked) but stays [`Mode::Enforce`]: the fault is real and
//! the responder must see it.
#![deny(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects
)]

use crate::command::{ChannelId, SourceId};
use crate::config::Policy;
use crate::verdict::{RejectReason, SubstituteKind};
use robodr_events::{Deviation, Mode, Severity};

/// Stable rule ids emitted by the firewall.
pub mod rules {
    pub const REJECTED_CLOCK_REGRESSION: &str = "robot.firewall.rejected_clock_regression";
    pub const REJECTED_UNKNOWN_CHANNEL: &str = "robot.firewall.rejected_unknown_channel";
    pub const REJECTED_UNKNOWN_SOURCE: &str = "robot.firewall.rejected_unknown_source";
    pub const REJECTED_UNAUTHORIZED_SOURCE: &str = "robot.firewall.rejected_unauthorized_source";
    pub const REJECTED_RATE_LIMITED: &str = "robot.firewall.rejected_rate_limited";
    pub const REJECTED_KIND_MISMATCH: &str = "robot.firewall.rejected_kind_mismatch";
    pub const REJECTED_NON_FINITE: &str = "robot.firewall.rejected_non_finite";
    pub const REJECTED_FUTURE_TIMESTAMP: &str = "robot.firewall.rejected_future_timestamp";
    pub const REJECTED_STALE: &str = "robot.firewall.rejected_stale";
    pub const REJECTED_OUT_OF_ORDER: &str = "robot.firewall.rejected_out_of_order";
    pub const REJECTED_OVER_HARD_LIMIT: &str = "robot.firewall.rejected_over_hard_limit";
    pub const INTERNAL_FAULT: &str = "robot.firewall.internal_fault";
    pub const LIMITED_SPEED: &str = "robot.firewall.limited_speed";
    pub const LIMITED_ACCELERATION: &str = "robot.firewall.limited_acceleration";
    pub const LIMITED_JERK: &str = "robot.firewall.limited_jerk";
    /// Synthesised on drain when events were dropped because the buffer was full.
    pub const EVENTS_DROPPED: &str = "robot.firewall.events_dropped";
}

/// Rule id and severity for a rejection.
pub fn reject_rule(reason: RejectReason) -> (&'static str, Severity) {
    use RejectReason::*;
    match reason {
        ClockRegression => (rules::REJECTED_CLOCK_REGRESSION, Severity::High),
        UnknownChannel => (rules::REJECTED_UNKNOWN_CHANNEL, Severity::High),
        UnknownSource => (rules::REJECTED_UNKNOWN_SOURCE, Severity::Critical),
        UnauthorizedSource => (rules::REJECTED_UNAUTHORIZED_SOURCE, Severity::Critical),
        RateLimited => (rules::REJECTED_RATE_LIMITED, Severity::High),
        KindMismatch => (rules::REJECTED_KIND_MISMATCH, Severity::High),
        NonFinite => (rules::REJECTED_NON_FINITE, Severity::Critical),
        FutureTimestamp => (rules::REJECTED_FUTURE_TIMESTAMP, Severity::High),
        Stale => (rules::REJECTED_STALE, Severity::Medium),
        OutOfOrder => (rules::REJECTED_OUT_OF_ORDER, Severity::High),
        OverHardLimit => (rules::REJECTED_OVER_HARD_LIMIT, Severity::Critical),
        InternalFault => (rules::INTERNAL_FAULT, Severity::Critical),
    }
}

/// What the firewall actually did about the event.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EventAction {
    /// Command was forwarded with reduced motion.
    Limited,
    /// Command was not forwarded; the substitute (if any) was emitted.
    Rejected(Option<SubstituteKind>),
    /// Not enforcing (observe mode, pass-through platform or fail-open fault):
    /// the command was forwarded unchanged; this is what would have happened.
    ObservedOnly,
}

/// One compact, allocation-free deviation record.
///
/// `value` / `limit` meaning depends on the rule: speeds/accelerations in SI
/// units for limits, ages in ns for timestamp rules, `NaN` when not
/// applicable.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct FirewallEvent {
    pub rule: &'static str,
    pub severity: Severity,
    pub at_ns: u64,
    pub channel: ChannelId,
    pub source: SourceId,
    pub action: EventAction,
    pub value: f64,
    pub limit: f64,
}

impl FirewallEvent {
    /// Render as a [`Deviation`] (allocates; call outside the control loop).
    /// The mode is [`policy_mode`] of `policy` (see the module docs).
    pub fn to_deviation(&self, policy: &Policy) -> Deviation {
        let ch = policy
            .channel_name(self.channel)
            .unwrap_or("<unknown channel>");
        let src = match self.source {
            SourceId::UNKNOWN => "<unknown source>",
            id => policy.source_guid(id).unwrap_or("<unknown source>"),
        };
        let action = match self.action {
            EventAction::Limited => "limited".to_string(),
            EventAction::Rejected(None) => "rejected, nothing emitted".to_string(),
            EventAction::Rejected(Some(SubstituteKind::Zero)) => {
                "rejected, zero velocity emitted".to_string()
            }
            EventAction::Rejected(Some(SubstituteKind::HoldLast)) => {
                "rejected, last accepted command held".to_string()
            }
            EventAction::ObservedOnly => "observe only, forwarded unchanged".to_string(),
        };
        let mut detail = format!(
            "{} on {ch} from {src} at {} ns ({action})",
            self.rule, self.at_ns
        );
        if !self.value.is_nan() || !self.limit.is_nan() {
            detail.push_str(&format!(
                ": value {:.6} limit {:.6}",
                self.value, self.limit
            ));
        }
        detail.push_str(&format!(" [model {}]", policy.model()));
        Deviation::new(self.rule, self.severity, detail).with_mode(policy_mode(policy))
    }
}

/// The [`Mode`] stamped on every deviation of a firewall running `policy`.
pub fn policy_mode(policy: &Policy) -> Mode {
    if policy.is_observe_only() {
        Mode::Observe
    } else {
        Mode::Enforce
    }
}

/// Fixed-capacity event buffer. Storage is reserved once at construction;
/// `push` never reallocates.
#[derive(Debug)]
pub struct EventBuffer {
    buf: Vec<FirewallEvent>,
    cap: usize,
    dropped: u64,
}

impl EventBuffer {
    pub fn with_capacity(cap: usize) -> Self {
        Self {
            buf: Vec::with_capacity(cap),
            cap,
            dropped: 0,
        }
    }

    /// Record an event; if the buffer is full, drop it and count the drop.
    pub(crate) fn push(&mut self, ev: FirewallEvent) {
        // Compare against our own `cap`, not `Vec::capacity()` (which may be
        // larger): pushing while `len < cap <= capacity` cannot reallocate.
        if self.buf.len() < self.cap {
            self.buf.push(ev);
        } else {
            self.dropped = self.dropped.saturating_add(1);
        }
    }

    pub fn len(&self) -> usize {
        self.buf.len()
    }

    pub fn is_empty(&self) -> bool {
        self.buf.is_empty()
    }

    pub fn capacity(&self) -> usize {
        self.cap
    }

    /// Events dropped since the last drain.
    pub fn dropped(&self) -> u64 {
        self.dropped
    }

    pub fn as_slice(&self) -> &[FirewallEvent] {
        &self.buf
    }

    /// Visit every event in order, then clear (keeps the storage, no alloc).
    /// Returns the number of events dropped since the previous drain and
    /// resets that counter.
    pub fn drain_with(&mut self, mut f: impl FnMut(&FirewallEvent)) -> u64 {
        for ev in &self.buf {
            f(ev);
        }
        self.buf.clear();
        std::mem::take(&mut self.dropped)
    }
}

#[cfg(test)]
#[allow(
    clippy::unwrap_used,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects
)]
mod tests {
    use super::*;

    fn ev() -> FirewallEvent {
        FirewallEvent {
            rule: rules::LIMITED_SPEED,
            severity: Severity::High,
            at_ns: 1,
            channel: ChannelId(0),
            source: SourceId(0),
            action: EventAction::Limited,
            value: 2.0,
            limit: 1.0,
        }
    }

    #[test]
    fn buffer_drops_when_full_without_growing() {
        let mut b = EventBuffer::with_capacity(2);
        let cap_before = b.buf.capacity();
        for _ in 0..5 {
            b.push(ev());
        }
        assert_eq!(b.len(), 2);
        assert_eq!(b.dropped(), 3);
        assert_eq!(b.buf.capacity(), cap_before);
        let mut n = 0;
        assert_eq!(b.drain_with(|_| n += 1), 3);
        assert_eq!(n, 2);
        assert!(b.is_empty());
        assert_eq!(b.dropped(), 0);
        assert_eq!(b.capacity(), 2);
    }

    #[test]
    fn every_reject_reason_has_a_firewall_rule() {
        use RejectReason::*;
        for r in [
            ClockRegression,
            UnknownChannel,
            UnknownSource,
            UnauthorizedSource,
            RateLimited,
            KindMismatch,
            NonFinite,
            FutureTimestamp,
            Stale,
            OutOfOrder,
            OverHardLimit,
            InternalFault,
        ] {
            assert!(reject_rule(r).0.starts_with("robot.firewall."));
        }
    }
}
