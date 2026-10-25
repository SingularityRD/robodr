//! Low-level joint frames (Unitree-style `LowCmd`): one command per control
//! tick carrying, for every motor slot, a position target `q`, a velocity
//! target `dq`, a feed-forward torque `tau`, the PD gains `kp` / `kd` and an
//! enable `mode`. The motor driver computes
//! `τ = kp·(q − q_meas) + kd·(dq − dq_meas) + tau`.
//!
//! Like [`crate::Command`], everything here is `Copy`, fixed-size and
//! heap-free: a [`JointFrame`] holds up to [`MAX_MOTORS`] slots inline (the
//! largest Unitree layout, the `hg` `LowCmd` of G1 / H1-2, has 35; Go2 / B2 /
//! H1 use 20, Go1 / A1 12). The decoder (gateway) fills it from the wire and
//! says whether the frame's CRC was valid ([`JointFrame::crc_ok`]); fields of
//! the wire message that are not motor targets (`mode_pr`, `mode_machine`,
//! head / level flags, reserved words) are the gateway's business.
#![deny(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects
)]

use crate::command::{ChannelId, SourceId};

/// Largest number of motor slots a [`JointFrame`] can carry (Unitree `hg`
/// `LowCmd`: G1, H1-2). Frames for wider buses must be split over channels.
pub const MAX_MOTORS: usize = 35;

/// Per-motor enable flag as decoded from the frame (Unitree: `mode` 0x01 =
/// servo / FOC enabled, 0x00 = disabled / brake).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default)]
pub enum MotorMode {
    /// The motor is not driven: it ignores every target and gain.
    #[default]
    Disabled,
    /// The motor drives `τ = kp·(q − q_meas) + kd·(dq − dq_meas) + tau`.
    Enabled,
}

/// One motor slot of a [`JointFrame`].
///
/// Units follow the Unitree SDK: `q` rad, `dq` rad/s, `tau` N·m, `kp`
/// N·m/rad, `kd` N·m·s/rad.
#[derive(Debug, Clone, Copy, PartialEq, Default)]
pub struct MotorCmd {
    pub mode: MotorMode,
    /// Position target. Only acts while `kp > 0`.
    pub q: f64,
    /// Velocity target. Only acts while `kd > 0`.
    pub dq: f64,
    /// Feed-forward torque.
    pub tau: f64,
    /// Position gain (stiffness).
    pub kp: f64,
    /// Velocity gain (damping).
    pub kd: f64,
}

impl MotorCmd {
    /// A disabled slot with every field zero.
    pub const OFF: MotorCmd = MotorCmd {
        mode: MotorMode::Disabled,
        q: 0.0,
        dq: 0.0,
        tau: 0.0,
        kp: 0.0,
        kd: 0.0,
    };

    /// An enabled slot with the given targets and gains.
    pub const fn enabled(q: f64, dq: f64, tau: f64, kp: f64, kd: f64) -> Self {
        Self {
            mode: MotorMode::Enabled,
            q,
            dq,
            tau,
            kp,
            kd,
        }
    }

    /// `true` if every numeric field is finite.
    pub fn is_finite(&self) -> bool {
        [self.q, self.dq, self.tau, self.kp, self.kd]
            .iter()
            .all(|x| x.is_finite())
    }

    /// `true` if this slot can produce torque: the motor is enabled and at
    /// least one of `kp`, `kd`, `tau` is non-zero (NaN counts as non-zero).
    /// An enabled slot with all three at zero is inert (the Unitree SDK
    /// examples initialise unused slots that way).
    pub fn energises(&self) -> bool {
        self.mode == MotorMode::Enabled && [self.kp, self.kd, self.tau].iter().any(|x| *x != 0.0)
    }

    /// The gains and torque the motor actually applies: zero when disabled.
    pub(crate) fn effective_kp(&self) -> f64 {
        match self.mode {
            MotorMode::Enabled => self.kp,
            MotorMode::Disabled => 0.0,
        }
    }

    pub(crate) fn effective_kd(&self) -> f64 {
        match self.mode {
            MotorMode::Enabled => self.kd,
            MotorMode::Disabled => 0.0,
        }
    }
}

/// A fixed-capacity low-level joint frame.
///
/// Only the first [`slots`](Self::slots) entries are meaningful; the rest
/// are kept at [`MotorCmd::OFF`] so that `PartialEq` compares meaningful data
/// only.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct JointFrame {
    slots: u8,
    motors: [MotorCmd; MAX_MOTORS],
    /// What the decoder found when it checked the frame's CRC: `Some(true)`
    /// valid, `Some(false)` invalid, `None` not checked / not available. A
    /// channel with `require_crc` rejects anything but `Some(true)`; every
    /// channel rejects `Some(false)`.
    pub crc_ok: Option<bool>,
}

impl JointFrame {
    /// `slots` disabled motors. `None` if `slots > MAX_MOTORS`.
    pub fn new(slots: usize, crc_ok: Option<bool>) -> Option<Self> {
        if slots > MAX_MOTORS {
            return None;
        }
        Some(Self {
            slots: u8::try_from(slots).ok()?,
            motors: [MotorCmd::OFF; MAX_MOTORS],
            crc_ok,
        })
    }

    /// `slots` disabled motors, `slots` clamped to [`MAX_MOTORS`].
    pub(crate) fn off(slots: usize, crc_ok: Option<bool>) -> Self {
        let n = slots.min(MAX_MOTORS);
        Self {
            slots: u8::try_from(n).unwrap_or(0),
            motors: [MotorCmd::OFF; MAX_MOTORS],
            crc_ok,
        }
    }

    /// Build from a slice. `None` if it is longer than [`MAX_MOTORS`].
    pub fn from_slice(motors: &[MotorCmd], crc_ok: Option<bool>) -> Option<Self> {
        let mut f = Self::new(motors.len(), crc_ok)?;
        for (dst, src) in f.motors.iter_mut().zip(motors) {
            *dst = *src;
        }
        Some(f)
    }

    /// Number of motor slots in the frame.
    pub fn slots(&self) -> usize {
        usize::from(self.slots)
    }

    /// The meaningful slots.
    pub fn motors(&self) -> &[MotorCmd] {
        // `slots <= MAX_MOTORS` is a type invariant (every constructor
        // checks it); `get` keeps this panic-free regardless.
        self.motors.get(..self.slots()).unwrap_or(&[])
    }

    /// Mutable access to one slot (`None` past [`slots`](Self::slots)).
    pub fn motor_mut(&mut self, slot: usize) -> Option<&mut MotorCmd> {
        if slot >= self.slots() {
            return None;
        }
        self.motors.get_mut(slot)
    }

    /// One slot (`None` past [`slots`](Self::slots)).
    pub fn motor(&self, slot: usize) -> Option<&MotorCmd> {
        self.motors().get(slot)
    }

    /// `true` if every numeric field of every slot is finite.
    pub fn is_finite(&self) -> bool {
        self.motors().iter().all(MotorCmd::is_finite)
    }

    pub(crate) fn motors_mut(&mut self) -> &mut [MotorCmd] {
        let n = self.slots();
        self.motors.get_mut(..n).unwrap_or(&mut [])
    }
}

/// One low-level joint command as it reaches the firewall (the joint-frame
/// counterpart of [`crate::Command`]; checked by
/// [`crate::Firewall::check_joint`]).
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct JointCommand {
    /// Interned source endpoint ([`SourceId::UNKNOWN`] if unresolved).
    pub source: SourceId,
    /// Interned channel (a low-level joint channel of the policy).
    pub channel: ChannelId,
    /// Source timestamp, ns, in the gateway's monotonic clock domain.
    pub stamp_ns: u64,
    pub frame: JointFrame,
}

impl JointCommand {
    pub fn new(source: SourceId, channel: ChannelId, stamp_ns: u64, frame: JointFrame) -> Self {
        Self {
            source,
            channel,
            stamp_ns,
            frame,
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
    fn frame_bounds_and_tail() {
        assert!(JointFrame::new(MAX_MOTORS, None).is_some());
        assert!(JointFrame::new(MAX_MOTORS + 1, None).is_none());
        assert!(JointFrame::from_slice(&[MotorCmd::OFF; MAX_MOTORS + 1], None).is_none());
        let m = MotorCmd::enabled(0.1, 0.0, 1.0, 20.0, 0.5);
        let mut f = JointFrame::from_slice(&[m, m], Some(true)).unwrap();
        assert_eq!(f.slots(), 2);
        assert_eq!(f.motors(), &[m, m]);
        assert!(f.motor_mut(2).is_none());
        assert!(f.motor(2).is_none());
        f.motor_mut(1).unwrap().q = 0.2;
        assert_eq!(f.motor(1).unwrap().q, 0.2);
        // Tail stays OFF, so equality only sees meaningful slots.
        assert_eq!(
            JointFrame::from_slice(&[m], None),
            JointFrame::from_slice(&[m], None)
        );
    }

    #[test]
    fn energising_and_finite() {
        assert!(!MotorCmd::OFF.energises());
        // Enabled but inert (Unitree SDK idle slot).
        assert!(!MotorCmd::enabled(2.146e9, 16000.0, 0.0, 0.0, 0.0).energises());
        assert!(MotorCmd::enabled(0.0, 0.0, 0.1, 0.0, 0.0).energises());
        assert!(MotorCmd::enabled(0.0, 0.0, 0.0, 0.0, f64::NAN).energises());
        // Disabled never energises, whatever the gains say.
        let d = MotorCmd {
            kp: 50.0,
            ..MotorCmd::OFF
        };
        assert!(!d.energises());
        assert_eq!(d.effective_kp(), 0.0);
        assert!(!MotorCmd {
            tau: f64::INFINITY,
            ..MotorCmd::OFF
        }
        .is_finite());
    }
}
