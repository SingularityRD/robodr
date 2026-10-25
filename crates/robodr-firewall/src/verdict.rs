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
use crate::joint::JointCommand;

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
    /// Joint frame: the decoder reported the frame's CRC invalid, or did not
    /// verify it on a channel with `require_crc`.
    CrcInvalid,
    /// Joint frame: a slot the envelope marks unused (disabled) is
    /// energised (mode enabled with a non-zero `kp`, `kd` or `tau`).
    DisabledMotorEnergised,
    /// Joint frame: a position target (with `kp > 0`) beyond the hard-reject
    /// margin of its range.
    JointPositionOutOfEnvelope,
    /// Joint frame: a velocity target (with `kd > 0`) beyond
    /// `hard_reject_factor × dq_max`.
    JointVelocityOutOfEnvelope,
    /// Joint frame: a feed-forward torque beyond
    /// `hard_reject_factor × tau_max`.
    JointTorqueOutOfEnvelope,
    /// Joint frame: a gain beyond `hard_reject_factor ×` its maximum.
    JointGainOutOfEnvelope,
    /// Joint frame: a gain below its minimum (gains are never raised; a
    /// disabled motor counts as zero gains).
    JointGainBelowMinimum,
    /// Joint frame: a position target (with `kp > 0`) further from the
    /// previous accepted target than `hard_reject_factor × max_dq_step`.
    JointStepOutOfEnvelope,
    /// Joint frame: the proportional torque demand `kp·|q − q_prev|` beyond
    /// `hard_reject_factor × tau_pd_max`.
    JointPdTorqueOutOfEnvelope,
    /// Joint frame: a slot whose mode is off (`0x00`) carries a non-zero
    /// `kp`, `kd` or `tau`.
    JointModeInconsistent,
    /// Joint frame: `mode_pr` / `mode_machine` differs from the channel's
    /// pinned value.
    JointModePinMismatch,
    /// Joint frame on a humanoid: every enabled slot is limp (no stiffness
    /// and no damping); a limp humanoid falls.
    JointLimpFrame,
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
///
/// On a low-level joint channel `Zero` is the damping frame (`kp = 0`,
/// `dq = 0`, `tau = 0`, `kd = damping_kd`; never on a humanoid) and
/// `HoldLast` the last accepted frame with its velocity targets zeroed.
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

/// Bit set of the limits applied to a [`JointVerdict::Limited`] frame.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Hash)]
pub struct JointLimitReasons(u8);

impl JointLimitReasons {
    pub const NONE: JointLimitReasons = JointLimitReasons(0);
    /// A position target clamped into `[q_min, q_max]`.
    pub const POSITION: JointLimitReasons = JointLimitReasons(1);
    /// A velocity target clamped to `±dq_max`.
    pub const VELOCITY: JointLimitReasons = JointLimitReasons(2);
    /// A feed-forward torque clamped to `±tau_max`.
    pub const TORQUE: JointLimitReasons = JointLimitReasons(4);
    /// A gain lowered to its maximum.
    pub const GAIN: JointLimitReasons = JointLimitReasons(8);
    /// A position target stepped toward the requested one by at most
    /// `max_dq_step` from the previous accepted target.
    pub const STEP: JointLimitReasons = JointLimitReasons(16);
    /// A position target moved toward the previous accepted target so that
    /// `kp·|q − q_prev| <= tau_pd_max`.
    pub const PD_TORQUE: JointLimitReasons = JointLimitReasons(32);

    pub fn contains(self, other: JointLimitReasons) -> bool {
        self.0 & other.0 == other.0
    }

    pub fn is_empty(self) -> bool {
        self.0 == 0
    }

    pub(crate) fn insert(&mut self, other: JointLimitReasons) {
        self.0 |= other.0;
    }
}

impl std::ops::BitOr for JointLimitReasons {
    type Output = JointLimitReasons;
    fn bitor(self, rhs: Self) -> Self {
        JointLimitReasons(self.0 | rhs.0)
    }
}

/// The frame to emit downstream instead of a rejected joint frame. Its
/// `source` is [`crate::SourceId::FIREWALL`], its `stamp_ns` the `now` of the
/// check, and its `crc_ok` `Some(true)` (the gateway encodes it and must
/// compute its CRC). Never a value taken from the rejected frame.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct JointSubstitute {
    pub kind: SubstituteKind,
    pub cmd: JointCommand,
}

/// What the firewall would have done to a joint frame had it been enforcing.
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum JointWouldHave {
    Limited {
        cmd: JointCommand,
        reasons: JointLimitReasons,
    },
    Rejected {
        reason: RejectReason,
    },
}

/// The decision for one low-level joint frame
/// ([`crate::Firewall::check_joint`]). Same shape and meaning as
/// [`Verdict`].
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum JointVerdict {
    /// Forward `cmd` unchanged (bit-exact when enforcing).
    Passed {
        cmd: JointCommand,
        would_have: Option<JointWouldHave>,
    },
    /// Forward `cmd`: the input with fields clamped into the envelope. The
    /// gateway must re-encode it **and recompute its CRC**.
    Limited {
        cmd: JointCommand,
        reasons: JointLimitReasons,
    },
    /// Do not forward the input. Emit `substitute` if `Some`; `None` means
    /// emit nothing (unknown channel, foreign source with `Drop`, a frame
    /// that arrived too early, or a humanoid channel with no valid frame to
    /// hold yet).
    Rejected {
        reason: RejectReason,
        substitute: Option<JointSubstitute>,
    },
}

impl JointVerdict {
    /// The frame the gateway should forward, if any.
    pub fn output(&self) -> Option<&JointCommand> {
        match self {
            JointVerdict::Passed { cmd, .. } | JointVerdict::Limited { cmd, .. } => Some(cmd),
            JointVerdict::Rejected { substitute, .. } => substitute.as_ref().map(|s| &s.cmd),
        }
    }

    pub fn is_passed(&self) -> bool {
        matches!(self, JointVerdict::Passed { .. })
    }

    pub fn is_limited(&self) -> bool {
        matches!(self, JointVerdict::Limited { .. })
    }

    pub fn is_rejected(&self) -> bool {
        matches!(self, JointVerdict::Rejected { .. })
    }

    pub fn reject_reason(&self) -> Option<RejectReason> {
        match self {
            JointVerdict::Rejected { reason, .. } => Some(*reason),
            _ => None,
        }
    }

    /// The substitute kind of a rejection, if one was emitted.
    pub fn substitute_kind(&self) -> Option<SubstituteKind> {
        match self {
            JointVerdict::Rejected {
                substitute: Some(s),
                ..
            } => Some(s.kind),
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
        let j = JointLimitReasons::POSITION | JointLimitReasons::GAIN;
        assert!(j.contains(JointLimitReasons::GAIN));
        assert!(!j.contains(JointLimitReasons::TORQUE));
        let k = JointLimitReasons::STEP | JointLimitReasons::PD_TORQUE;
        assert!(k.contains(JointLimitReasons::STEP) && k.contains(JointLimitReasons::PD_TORQUE));
        assert!(!k.contains(JointLimitReasons::POSITION));
        assert!(JointLimitReasons::NONE.is_empty());
    }
}
