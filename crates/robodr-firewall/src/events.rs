//! Deviation reporting without allocating in the hot path.
//!
//! [`robodr_events::Deviation`] carries a `String` detail, so constructing one
//! allocates. `check` therefore records a compact, `Copy` [`FirewallEvent`]
//! into an [`EventBuffer`] whose storage is allocated once when the firewall is
//! built and never reallocated. The caller drains the buffer outside the control loop and
//! turns each event into a `Deviation` via `Deviation::new`
//! ([`FirewallEvent::to_deviation`]); that conversion is where formatting and
//! allocation happen.
//!
//! # Retention under load (flood resistance)
//! A spoofer can trigger an event on every command it sends, so the buffer
//! must not let foreign traffic push out what an authorised source did.
//! [`EventBuffer::push`] therefore, in bounded time and without allocating:
//! 1. **Coalesces** an event into a pending one with the same
//!    (rule, channel, source, action): `count` is incremented, `last_at_ns`
//!    updated and the worst `value` (with its `limit`) kept. A flood of one
//!    kind costs one slot.
//! 2. **Reserves capacity by source class.** Events from sources that are
//!    not authorised on the channel ([`FirewallEvent::authorised`] `false`:
//!    unknown or unauthorised source, unknown channel) may occupy at most
//!    `capacity / 2` slots; the rest is reserved for authorised sources.
//! 3. **Evicts by priority** when full: priority is (severity, authorised)
//!    — severity first, an authorised source winning ties. The
//!    lowest-priority pending event (oldest among equals) is evicted only if
//!    it ranks strictly below the new one; otherwise the new one is dropped.
//!    An unauthorised event over its quota can only evict another
//!    unauthorised one. Consequence: a pending **Critical from an authorised
//!    source is never evicted**, and in particular never in favour of an
//!    unknown-source event.
//!
//! Every dropped or evicted event is counted, and the highest severity lost
//! is remembered, so the `robot.firewall.events_dropped` deviation reported
//! on drain is at least Medium and as severe as the worst event lost.
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

    // Low-level joint frames (`Firewall::check_joint`). The four
    // `joint_*_out_of_envelope` ids are used both for a clamp (action
    // `Limited`, High) and for a hard rejection (action `Rejected`,
    // Critical); the event's action tells them apart.
    /// A position target outside `[q_min, q_max]` (value: distance outside
    /// the range, rad).
    pub const JOINT_POSITION_OUT_OF_ENVELOPE: &str =
        "robot.firewall.joint_position_out_of_envelope";
    /// `|dq|` over `dq_max` (value: `|dq|`, rad/s).
    pub const JOINT_VELOCITY_OUT_OF_ENVELOPE: &str =
        "robot.firewall.joint_velocity_out_of_envelope";
    /// `|tau|` over `tau_max` (value: `|tau|`, N·m).
    pub const JOINT_TORQUE_OUT_OF_ENVELOPE: &str = "robot.firewall.joint_torque_out_of_envelope";
    /// A gain over its maximum or under its minimum (value: the gain).
    pub const JOINT_GAIN_OUT_OF_ENVELOPE: &str = "robot.firewall.joint_gain_out_of_envelope";
    /// A slot the envelope marks unused is energised.
    pub const DISABLED_MOTOR_ENERGISED: &str = "robot.firewall.disabled_motor_energised";
    /// CRC reported invalid, or not verified where required (value: 0 for
    /// "invalid", NaN for "not verified").
    pub const CRC_INVALID: &str = "robot.firewall.crc_invalid";
    /// The joint stream was slower than its `max_interval_ns` (value: the
    /// gap, ns). Recorded only; the late frame itself is evaluated normally.
    pub const JOINT_RATE_VIOLATION: &str = "robot.firewall.joint_rate_violation";
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
        CrcInvalid => (rules::CRC_INVALID, Severity::High),
        DisabledMotorEnergised => (rules::DISABLED_MOTOR_ENERGISED, Severity::Critical),
        JointPositionOutOfEnvelope => (rules::JOINT_POSITION_OUT_OF_ENVELOPE, Severity::Critical),
        JointVelocityOutOfEnvelope => (rules::JOINT_VELOCITY_OUT_OF_ENVELOPE, Severity::Critical),
        JointTorqueOutOfEnvelope => (rules::JOINT_TORQUE_OUT_OF_ENVELOPE, Severity::Critical),
        JointGainOutOfEnvelope => (rules::JOINT_GAIN_OUT_OF_ENVELOPE, Severity::Critical),
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
/// applicable. When several identical events were coalesced (see the module
/// docs) `count > 1`, `at_ns` is the first occurrence, `last_at_ns` the last,
/// and `value`/`limit` those of the worst (largest `value`) occurrence.
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
    /// Source is known and authorised on the channel (retention class).
    pub authorised: bool,
    /// Number of coalesced occurrences (>= 1, saturating).
    pub count: u32,
    /// Time of the last coalesced occurrence (`== at_ns` when `count == 1`).
    pub last_at_ns: u64,
    /// Joint frames: the motor slot the (worst) `value` belongs to; `None`
    /// for frame-level rules and for twist / joint-velocity channels.
    pub slot: Option<u8>,
}

impl FirewallEvent {
    fn same_key(&self, other: &FirewallEvent) -> bool {
        self.channel == other.channel
            && self.source == other.source
            && self.action == other.action
            && self.rule == other.rule
    }

    /// Retention priority: severity first, an authorised source wins ties.
    fn priority(&self) -> (Severity, bool) {
        (self.severity, self.authorised)
    }
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
        let joint = policy.is_joint_channel(self.channel);
        let action = match self.action {
            // A slow stream is recorded only: the late frame itself was
            // evaluated (and passed, limited or rejected) on its own merits.
            _ if self.rule == rules::JOINT_RATE_VIOLATION => "recorded only".to_string(),
            EventAction::Limited => "limited".to_string(),
            EventAction::Rejected(None) => "rejected, nothing emitted".to_string(),
            EventAction::Rejected(Some(SubstituteKind::Zero)) if joint => {
                "rejected, damping frame emitted".to_string()
            }
            EventAction::Rejected(Some(SubstituteKind::Zero)) => {
                "rejected, zero velocity emitted".to_string()
            }
            EventAction::Rejected(Some(SubstituteKind::HoldLast)) if joint => {
                "rejected, last valid frame held".to_string()
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
        if let Some(slot) = self.slot {
            detail.push_str(&format!(" motor slot {slot}"));
        }
        if self.count > 1 {
            detail.push_str(&format!(" x{} until {} ns", self.count, self.last_at_ns));
        }
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
/// `push` never reallocates. See the module docs for coalescing, per-class
/// reservation and priority eviction.
#[derive(Debug)]
pub struct EventBuffer {
    buf: Vec<FirewallEvent>,
    cap: usize,
    /// Max pending events from non-authorised sources (`cap / 2`).
    foreign_quota: usize,
    dropped: u64,
    dropped_max: Option<Severity>,
}

impl EventBuffer {
    pub fn with_capacity(cap: usize) -> Self {
        Self {
            buf: Vec::with_capacity(cap),
            cap,
            foreign_quota: cap / 2,
            dropped: 0,
            dropped_max: None,
        }
    }

    fn count_drop(&mut self, sev: Severity) {
        self.dropped = self.dropped.saturating_add(1);
        self.dropped_max = Some(self.dropped_max.map_or(sev, |m| m.max(sev)));
    }

    /// Index of the lowest-priority pending event (the oldest among equals),
    /// restricted to non-authorised events when `foreign_only`.
    fn victim(&self, foreign_only: bool) -> Option<usize> {
        let mut best: Option<(usize, (Severity, bool))> = None;
        for (i, e) in self.buf.iter().enumerate() {
            if foreign_only && e.authorised {
                continue;
            }
            let p = e.priority();
            if best.is_none_or(|(_, bp)| p < bp) {
                best = Some((i, p));
            }
        }
        best.map(|(i, _)| i)
    }

    /// Record an event: coalesce, store, or evict a lower-priority event;
    /// otherwise drop it and count the drop. Bounded: O(capacity), no
    /// allocation (`len < cap <= Vec::capacity()` on every `Vec::push`).
    pub(crate) fn push(&mut self, ev: FirewallEvent) {
        // 1. Coalesce.
        if let Some(e) = self.buf.iter_mut().rev().find(|e| e.same_key(&ev)) {
            e.count = e.count.saturating_add(ev.count.max(1));
            e.last_at_ns = e.last_at_ns.max(ev.last_at_ns);
            if ev.value > e.value || (e.value.is_nan() && !ev.value.is_nan()) {
                e.value = ev.value;
                e.limit = ev.limit;
                e.slot = ev.slot;
            }
            return;
        }
        // 2. Class quota for non-authorised sources.
        let foreign_full = !ev.authorised
            && self.buf.iter().filter(|e| !e.authorised).count() >= self.foreign_quota;
        if !foreign_full && self.buf.len() < self.cap {
            self.buf.push(ev);
            return;
        }
        // 3. Priority eviction.
        let victim = self.victim(foreign_full).and_then(|i| {
            let p = self.buf.get(i)?.priority();
            (p < ev.priority()).then_some(i)
        });
        match victim {
            Some(i) => {
                let lost = self.buf.remove(i).severity;
                self.count_drop(lost);
                self.buf.push(ev);
            }
            None => self.count_drop(ev.severity),
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

    /// Events dropped (or evicted) since the last drain.
    pub fn dropped(&self) -> u64 {
        self.dropped
    }

    /// Highest severity among events dropped or evicted since the last drain.
    pub fn dropped_max_severity(&self) -> Option<Severity> {
        self.dropped_max
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
        self.dropped_max = None;
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
            authorised: true,
            count: 1,
            last_at_ns: 1,
            slot: None,
        }
    }

    /// Distinct key per `i` (no coalescing between them).
    fn evk(i: u16, sev: Severity, authorised: bool) -> FirewallEvent {
        FirewallEvent {
            severity: sev,
            channel: ChannelId(i),
            source: if authorised {
                SourceId(0)
            } else {
                SourceId::UNKNOWN
            },
            authorised,
            at_ns: u64::from(i),
            last_at_ns: u64::from(i),
            ..ev()
        }
    }

    #[test]
    fn buffer_drops_when_full_without_growing() {
        let mut b = EventBuffer::with_capacity(2);
        let cap_before = b.buf.capacity();
        for i in 0..5 {
            b.push(evk(i, Severity::High, true));
        }
        assert_eq!(b.len(), 2);
        assert_eq!(b.dropped(), 3);
        assert_eq!(b.dropped_max_severity(), Some(Severity::High));
        assert_eq!(b.buf.capacity(), cap_before);
        let mut n = 0;
        assert_eq!(b.drain_with(|_| n += 1), 3);
        assert_eq!(n, 2);
        assert!(b.is_empty());
        assert_eq!(b.dropped(), 0);
        assert_eq!(b.dropped_max_severity(), None);
        assert_eq!(b.capacity(), 2);
    }

    #[test]
    fn identical_events_coalesce_with_count_and_worst_value() {
        let mut b = EventBuffer::with_capacity(2);
        for t in 1..=1000u64 {
            b.push(FirewallEvent {
                at_ns: t,
                last_at_ns: t,
                value: if t == 500 { 9.0 } else { 2.0 },
                limit: if t == 500 { 1.5 } else { 1.0 },
                ..ev()
            });
        }
        assert_eq!(b.len(), 1);
        assert_eq!(b.dropped(), 0);
        let e = b.as_slice()[0];
        assert_eq!((e.count, e.at_ns, e.last_at_ns), (1000, 1, 1000));
        assert_eq!((e.value, e.limit), (9.0, 1.5));
        // A NaN value never replaces a real one; a real one replaces NaN.
        let mut b = EventBuffer::with_capacity(1);
        b.push(FirewallEvent {
            value: f64::NAN,
            limit: f64::NAN,
            ..ev()
        });
        b.push(ev());
        b.push(FirewallEvent {
            value: f64::NAN,
            ..ev()
        });
        assert_eq!(b.as_slice()[0].value, 2.0);
        assert_eq!(b.as_slice()[0].count, 3);
        // Count saturates.
        let mut b = EventBuffer::with_capacity(1);
        b.push(FirewallEvent {
            count: u32::MAX,
            ..ev()
        });
        b.push(ev());
        assert_eq!(b.as_slice()[0].count, u32::MAX);
    }

    #[test]
    fn foreign_flood_is_capped_at_half_and_never_evicts_authorised_critical() {
        let mut b = EventBuffer::with_capacity(8);
        for i in 0..4 {
            b.push(evk(i, Severity::Critical, true));
        }
        for i in 100..1100 {
            b.push(evk(i, Severity::Critical, false));
        }
        let foreign = b.as_slice().iter().filter(|e| !e.authorised).count();
        assert_eq!(foreign, 4, "foreign events capped at cap/2");
        assert_eq!(
            b.as_slice()
                .iter()
                .filter(|e| e.authorised && e.severity == Severity::Critical)
                .count(),
            4
        );
        assert_eq!(b.dropped_max_severity(), Some(Severity::Critical));
        // An authorised Critical arriving into a full buffer evicts a foreign
        // one (same severity, authorised wins the tie)...
        b.push(evk(9, Severity::Critical, true));
        assert_eq!(b.as_slice().iter().filter(|e| e.authorised).count(), 5);
        // ...and authorised Criticals are never evicted by foreign events.
        for i in 2000..3000 {
            b.push(evk(i, Severity::Critical, false));
        }
        assert_eq!(b.as_slice().iter().filter(|e| e.authorised).count(), 5);
    }

    #[test]
    fn lower_priority_is_evicted_first_and_oldest_among_equals() {
        let mut b = EventBuffer::with_capacity(3);
        b.push(evk(1, Severity::Medium, true));
        b.push(evk(2, Severity::Medium, true));
        b.push(evk(3, Severity::High, true));
        b.push(evk(4, Severity::Critical, true));
        let ch: Vec<u16> = b.as_slice().iter().map(|e| e.channel.0).collect();
        assert_eq!(ch, vec![2, 3, 4]);
        assert_eq!(b.dropped_max_severity(), Some(Severity::Medium));
        // Equal priority never evicts: the newcomer is dropped.
        b.push(evk(5, Severity::Medium, true));
        let ch: Vec<u16> = b.as_slice().iter().map(|e| e.channel.0).collect();
        assert_eq!(ch, vec![2, 3, 4]);
        assert_eq!(b.dropped(), 2);
    }

    #[test]
    fn foreign_quota_zero_with_capacity_one() {
        let mut b = EventBuffer::with_capacity(1);
        b.push(evk(1, Severity::Critical, false));
        assert!(b.is_empty());
        assert_eq!(b.dropped(), 1);
        b.push(evk(2, Severity::Low, true));
        assert_eq!(b.len(), 1);
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
            CrcInvalid,
            DisabledMotorEnergised,
            JointPositionOutOfEnvelope,
            JointVelocityOutOfEnvelope,
            JointTorqueOutOfEnvelope,
            JointGainOutOfEnvelope,
        ] {
            assert!(reject_rule(r).0.starts_with("robot.firewall."));
        }
    }
}
