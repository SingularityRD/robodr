//! Per-motor command / state frames: the motion content of a Unitree
//! `LowCmd` / `LowState` (and `HandCmd` / `HandState`) in a fixed-capacity,
//! heap-free form that does not depend on the IDL family.
//!
//! Unitree's motor controller applies, per joint,
//! `T = kp * (q - q_measured) + kd * (dq - dq_measured) + tau`
//! (`unitree_sdk2/example/h1/README.md`, "Parallel Mechanism Control
//! Interface"). So a commanded velocity `dq` only acts through `kd`, and a
//! position target `q` only through `kp`. The SDK examples rely on that:
//! unused motors are sent `q = PosStopF (2.146e9)`, `dq = VelStopF (16000)`
//! with `kp = kd = 0` (`example/go2/go2_low_level.cpp`), which must not be
//! read as a 16000 rad/s command. [`JointCommandFrame::max_commanded_joint_speed`]
//! follows the same rule.

use robodr_events::MotionCommand;

use crate::event::EventContext;

/// Most motors a frame holds: `unitree_hg::msg::dds_::LowCmd_` has 35
/// slots, the most of any Unitree type.
pub const MAX_FRAME_JOINTS: usize = 35;

/// One motor's command.
#[derive(Debug, Clone, Copy, PartialEq, Default)]
pub struct JointCommand {
    /// Motor mode octet as sent. `unitree_go`: `0x01` servo (FOC) /
    /// `0x00` stop (`example/go2/go2_low_level.cpp`); `unitree_hg`: `1`
    /// enable / `0` disable (`example/g1/low_level/g1_ankle_swing_example.cpp`).
    /// Anything non-zero is treated as enabled.
    pub mode: u8,
    /// Target position (rad).
    pub q: f32,
    /// Target velocity (rad/s).
    pub dq: f32,
    /// Feed-forward torque (N·m).
    pub tau: f32,
    /// Position gain.
    pub kp: f32,
    /// Velocity gain.
    pub kd: f32,
}

impl JointCommand {
    /// The motor is enabled (mode octet non-zero).
    pub fn enabled(&self) -> bool {
        self.mode != 0
    }

    /// Every numeric field is finite.
    pub fn is_finite(&self) -> bool {
        self.q.is_finite()
            && self.dq.is_finite()
            && self.tau.is_finite()
            && self.kp.is_finite()
            && self.kd.is_finite()
    }
}

/// One motor's measured state.
#[derive(Debug, Clone, Copy, PartialEq, Default)]
pub struct JointMeasurement {
    pub mode: u8,
    /// Position (rad).
    pub q: f32,
    /// Velocity (rad/s).
    pub dq: f32,
    /// Acceleration (rad/s²).
    pub ddq: f32,
    /// Estimated torque (N·m).
    pub tau_est: f32,
}

/// A fixed-capacity list of `T` (no heap): the first `len` entries of
/// `items` are meaningful.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct Bounded<T: Copy + Default, const N: usize> {
    items: [T; N],
    len: usize,
}

impl<T: Copy + Default, const N: usize> Default for Bounded<T, N> {
    fn default() -> Self {
        Bounded {
            items: [T::default(); N],
            len: 0,
        }
    }
}

impl<T: Copy + Default, const N: usize> Bounded<T, N> {
    /// Capacity.
    pub const CAPACITY: usize = N;

    /// Appends `v`; `false` (and nothing stored) when full.
    pub fn push(&mut self, v: T) -> bool {
        match self.items.get_mut(self.len) {
            Some(slot) => {
                *slot = v;
                self.len = self.len.saturating_add(1);
                true
            }
            None => false,
        }
    }

    pub fn as_slice(&self) -> &[T] {
        self.items.get(..self.len).unwrap_or(&[])
    }

    pub fn len(&self) -> usize {
        self.len
    }

    pub fn is_empty(&self) -> bool {
        self.len == 0
    }

    /// Keeps only the first `n` entries (no-op if `n >= len`).
    pub fn truncate(&mut self, n: usize) {
        self.len = self.len.min(n);
    }
}

/// The per-motor commands of one Unitree low-level command message, in
/// slot order (slot `i` = `motor_cmd[i]`).
#[derive(Debug, Clone, Copy, PartialEq, Default)]
pub struct JointCommandFrame {
    pub joints: Bounded<JointCommand, MAX_FRAME_JOINTS>,
}

impl JointCommandFrame {
    pub fn as_slice(&self) -> &[JointCommand] {
        self.joints.as_slice()
    }

    /// Restrict to the first `n` slots, e.g. the model's actuated motors
    /// ([`crate::unitree::ModelInfo::actuated_motors`]).
    pub fn truncated(mut self, n: usize) -> Self {
        self.joints.truncate(n);
        self
    }

    /// The largest commanded joint speed |dq| (rad/s) over the motors whose
    /// velocity target can act: enabled (`mode != 0`) and `kd != 0`.
    ///
    /// * `Some(0.0)` when no enabled motor has a velocity gain (pure
    ///   position / torque control, or everything disabled): the frame
    ///   commands no velocity. Position steps are not visible in a single
    ///   frame; compare consecutive frames with
    ///   [`JointCommandFrame::max_position_step`].
    /// * NaN when an enabled motor has **any** non-finite field (q, dq,
    ///   tau, kp or kd): a NaN gain or torque is as dangerous as a NaN
    ///   velocity, and `MotionCommand` only has room for the speed, so the
    ///   whole frame is poisoned (the firewall treats non-finite commands
    ///   as Critical).
    pub fn max_commanded_joint_speed(&self) -> f64 {
        let mut max = 0.0f64;
        for j in self.as_slice().iter().filter(|j| j.enabled()) {
            if !j.is_finite() {
                return f64::NAN;
            }
            if j.kd != 0.0 {
                max = max.max(f64::from(j.dq).abs());
            }
        }
        max
    }

    /// The largest |Δq| (rad) between this frame and `prev` over the slots
    /// where both frames enable the motor with `kp != 0` (a position target
    /// that acts). `None` when no slot qualifies. NaN propagates.
    pub fn max_position_step(&self, prev: &JointCommandFrame) -> Option<f64> {
        let mut out: Option<f64> = None;
        for (a, b) in self.as_slice().iter().zip(prev.as_slice()) {
            if a.enabled() && b.enabled() && a.kp != 0.0 && b.kp != 0.0 {
                let d = (f64::from(a.q) - f64::from(b.q)).abs();
                out = Some(match out {
                    None => d,
                    Some(m) if d.is_nan() || m.is_nan() => f64::NAN,
                    Some(m) => m.max(d),
                });
            }
        }
        out
    }

    /// Number of enabled motors.
    pub fn enabled_count(&self) -> usize {
        self.as_slice().iter().filter(|j| j.enabled()).count()
    }

    /// The backward-compatible pipeline event: a joint command whose
    /// `joint_speed` is [`JointCommandFrame::max_commanded_joint_speed`].
    pub fn to_motion_command(&self, ctx: &EventContext<'_>) -> MotionCommand {
        MotionCommand {
            channel: ctx.channel.to_owned(),
            source_guid: ctx.writer_guid.map(str::to_owned),
            linear_speed: None,
            joint_speed: Some(self.max_commanded_joint_speed()),
            ..MotionCommand::default()
        }
    }
}

/// The per-motor measurements of one Unitree low-level state message.
#[derive(Debug, Clone, Copy, PartialEq, Default)]
pub struct JointStateFrame {
    pub joints: Bounded<JointMeasurement, MAX_FRAME_JOINTS>,
}

impl JointStateFrame {
    pub fn as_slice(&self) -> &[JointMeasurement] {
        self.joints.as_slice()
    }

    pub fn truncated(mut self, n: usize) -> Self {
        self.joints.truncate(n);
        self
    }

    /// Largest measured |dq| over every slot (NaN propagates; `None` for
    /// an empty frame). Unused slots report 0 on a healthy robot.
    pub fn max_abs_velocity(&self) -> Option<f64> {
        let mut out: Option<f64> = None;
        for j in self.as_slice() {
            let v = f64::from(j.dq).abs();
            out = Some(match out {
                None => v,
                Some(m) if v.is_nan() || m.is_nan() => f64::NAN,
                Some(m) => m.max(v),
            });
        }
        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn frame(js: &[JointCommand]) -> JointCommandFrame {
        let mut f = JointCommandFrame::default();
        for j in js {
            assert!(f.joints.push(*j));
        }
        f
    }

    const STOP: JointCommand = JointCommand {
        mode: 1,
        q: 2.146e9,
        dq: 16000.0,
        tau: 0.0,
        kp: 0.0,
        kd: 0.0,
    };

    #[test]
    fn stop_sentinels_are_not_a_speed() {
        assert_eq!(frame(&[STOP; 20]).max_commanded_joint_speed(), 0.0);
        let mut v = STOP;
        v.kd = 2.0;
        v.dq = -3.5;
        assert_eq!(frame(&[STOP, v]).max_commanded_joint_speed(), 3.5);
        // Disabled motors are ignored entirely.
        let mut off = v;
        off.mode = 0;
        off.dq = f32::NAN;
        assert_eq!(frame(&[off]).max_commanded_joint_speed(), 0.0);
        // Any non-finite field of an enabled motor poisons the frame.
        let mut bad = STOP;
        bad.kp = f32::INFINITY;
        assert!(frame(&[v, bad]).max_commanded_joint_speed().is_nan());
    }

    #[test]
    fn position_step_and_capacity() {
        let mut a = STOP;
        a.kp = 60.0;
        a.q = 0.5;
        let mut b = a;
        b.q = -0.25;
        let fa = frame(&[a, STOP]);
        let fb = frame(&[b, STOP]);
        assert_eq!(fa.max_position_step(&fb), Some(0.75));
        assert_eq!(frame(&[STOP]).max_position_step(&frame(&[STOP])), None);
        let mut f = JointCommandFrame::default();
        for _ in 0..MAX_FRAME_JOINTS {
            assert!(f.joints.push(STOP));
        }
        assert!(!f.joints.push(STOP));
        assert_eq!(f.truncated(12).as_slice().len(), 12);
        assert_eq!(
            Bounded::<JointCommand, MAX_FRAME_JOINTS>::CAPACITY,
            MAX_FRAME_JOINTS
        );
    }

    #[test]
    fn state_max() {
        let mut s = JointStateFrame::default();
        assert_eq!(s.max_abs_velocity(), None);
        s.joints.push(JointMeasurement {
            dq: -2.0,
            ..Default::default()
        });
        s.joints.push(JointMeasurement {
            dq: 1.0,
            ..Default::default()
        });
        assert_eq!(s.max_abs_velocity(), Some(2.0));
        s.joints.push(JointMeasurement {
            dq: f32::NAN,
            ..Default::default()
        });
        assert!(s.max_abs_velocity().unwrap().is_nan());
    }
}
