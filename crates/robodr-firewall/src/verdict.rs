//! The result of one [`crate::Firewall::check`].
//!
//! All types are `Copy` and unboxed (a verdict is a few hundred bytes moved
//! on the stack); boxing would put the allocator in the hot path.
#![allow(clippy::large_enum_variant)]
#![deny(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects
)]

use crate::command::Command;

/// Why a command was rejected. Ordered by the stage that decides it (see the
/// decision table in the crate docs).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum RejectReason {
    /// `now` went backwards relative to a previous `check` (gateway clock fault).
    ClockRegression,
    /// The channel id is not in the policy.
    UnknownChannel,
    /// The source id is not in the policy (or is [`crate::SourceId::UNKNOWN`]).
    UnknownSource,
    /// The source is known but not allowed on this channel.
    UnauthorizedSource,
    /// The (channel, source) pair exceeded its token-bucket rate.
    RateLimited,
    /// Twist on a joint channel, joints on a twist channel, or wrong joint count.
    KindMismatch,
    /// A component is NaN or ±inf.
    NonFinite,
    /// `stamp > now + max_future`.
    FutureTimestamp,
    /// `now − stamp > max_age`.
    Stale,
    /// `stamp <=` the last stamp seen from this source on this channel (replay
    /// or reordering).
    OutOfOrder,
    /// A speed exceeded `hard_reject_factor ×` its limit.
    OverHardLimit,
    /// The firewall's own post-condition check failed (fail-safe policy).
    InternalFault,
}

impl RejectReason {
    /// `true` for reasons caused by who sent the command rather than what it
    /// says (subject to [`crate::ForeignSourceAction`]).
    pub fn is_foreign_source(self) -> bool {
        matches!(self, Self::UnknownSource | Self::UnauthorizedSource)
    }
}

/// Bit set of the limits applied to a [`Verdict::Limited`] command.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Hash)]
pub struct LimitReasons(u8);

impl LimitReasons {
    pub const NONE: LimitReasons = LimitReasons(0);
    /// Scaled down to the speed limit.
    pub const SPEED: LimitReasons = LimitReasons(1);
    /// Rate-limited by the acceleration bound.
    pub const ACCELERATION: LimitReasons = LimitReasons(2);
    /// Rate-limited by the jerk bound.
    pub const JERK: LimitReasons = LimitReasons(4);

    pub fn contains(self, other: LimitReasons) -> bool {
        self.0 & other.0 == other.0
    }

    pub fn is_empty(self) -> bool {
        self.0 == 0
    }

    pub(crate) fn insert(&mut self, other: LimitReasons) {
        self.0 |= other.0;
    }
}

impl std::ops::BitOr for LimitReasons {
    type Output = LimitReasons;
    fn bitor(self, rhs: Self) -> Self {
        LimitReasons(self.0 | rhs.0)
    }
}

/// Which safe substitute was emitted for a rejected command.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum SubstituteKind {
    Zero,
    HoldLast,
}

/// The command to emit downstream **instead of** a rejected one. Its
/// `source` is always [`crate::SourceId::FIREWALL`] and its `stamp_ns` is the
/// `now` of the check. Its motion is either all-zero or a copy of the last
/// output the firewall accepted on that channel — never a value taken from
/// the rejected command.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct Substitute {
    pub kind: SubstituteKind,
    pub cmd: Command,
}

/// What the firewall would have done had it been enforcing.
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum WouldHave {
    Limited { cmd: Command, reasons: LimitReasons },
    Rejected { reason: RejectReason },
}

/// The decision for one command.
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum Verdict {
    /// Forward `cmd` unchanged. In observe mode (or pass-through platforms,
    /// or fail-open faults) `would_have` records what enforcement would have
    /// done; when enforcing it is always `None`.
    Passed {
        cmd: Command,
        would_have: Option<WouldHave>,
    },
    /// Forward `cmd`, which is the input with its motion reduced.
    Limited { cmd: Command, reasons: LimitReasons },
    /// Do not forward the input. Emit `substitute` if `Some`; `None` means
    /// emit nothing (unknown channel, or a foreign source with
    /// [`crate::ForeignSourceAction::Drop`]).
    Rejected {
        reason: RejectReason,
        substitute: Option<Substitute>,
    },
}

impl Verdict {
    /// The command the gateway should forward, if any.
    pub fn output(&self) -> Option<&Command> {
        match self {
            Verdict::Passed { cmd, .. } | Verdict::Limited { cmd, .. } => Some(cmd),
            Verdict::Rejected { substitute, .. } => substitute.as_ref().map(|s| &s.cmd),
        }
    }

    pub fn is_passed(&self) -> bool {
        matches!(self, Verdict::Passed { .. })
    }

    pub fn is_limited(&self) -> bool {
        matches!(self, Verdict::Limited { .. })
    }

    pub fn is_rejected(&self) -> bool {
        matches!(self, Verdict::Rejected { .. })
    }

    pub fn reject_reason(&self) -> Option<RejectReason> {
        match self {
            Verdict::Rejected { reason, .. } => Some(*reason),
            _ => None,
        }
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

    #[test]
    fn limit_reasons_bits() {
        let r = LimitReasons::SPEED | LimitReasons::JERK;
        assert!(r.contains(LimitReasons::SPEED));
        assert!(r.contains(LimitReasons::JERK));
        assert!(!r.contains(LimitReasons::ACCELERATION));
        assert!(LimitReasons::NONE.is_empty());
        assert!(!r.is_empty());
        assert!(RejectReason::UnknownSource.is_foreign_source());
        assert!(!RejectReason::Stale.is_foreign_source());
    }
}
