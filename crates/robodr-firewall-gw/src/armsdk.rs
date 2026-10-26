//! The Unitree arm SDK channel `rt/arm_sdk`: a `LowCmd_` (`unitree_hg` on
//! G1 / H1-2 / H2 / R1, `unitree_go` on H1) that the robot's locomotion
//! service **blends** into its own arm (and waist) commands.
//!
//! Two things differ from `rt/lowcmd` (SDK evidence, `unitree_sdk2`):
//!
//! - **The mode octet does not gate a slot.** The examples set `q`, `dq`,
//!   `kp`, `kd`, `tau` of the arm joints and never `mode`
//!   (`example/g1/high_level/g1_arm7_sdk_dds_example.cpp:156-160`,
//!   `example/h1/high_level/h1_arm_sdk_dds_example.cpp:134-138`), so the
//!   blended slots arrive with mode `0`. The firewall's joint check treats a
//!   mode-0 slot as disabled and refuses one that carries gains; here
//!   **every slot that carries gains or torque (or a non-finite value) is
//!   decided as enabled**, so the channel's joint envelope (position, speed,
//!   gains, torque, step) applies to it whatever its mode octet says. The
//!   wire's mode octets are forwarded as sent.
//! - **One slot is the blend weight.** `motor_cmd[weight_slot].q` in
//!   `[0, 1]` hands the arms to the SDK (`kNotUsedJoint = 29` on G1,
//!   `g1_arm7_sdk_dds_example.cpp:54` with `msg.motor_cmd().at(JointIndex::kNotUsedJoint).q(weight)`
//!   at `:150`; `27` on H1-2, `h1_2_arm_sdk_dds_example.cpp:51`; `9` on
//!   H1, `h1_arm_sdk_dds_example.cpp:32`; `kArmSdkWeightJoint = 31` on H2,
//!   `h2/high_level/h2_arm_sdk_dds_example.cpp:32`). It is not a motor: it
//!   is left out of the joint check and must be finite, within
//!   `[0, max_weight]`, with every other field of the slot zero and mode
//!   `0`. Anything else is an **integrity failure** (the firewall's source,
//!   rate and substitute rules apply: a humanoid holds the last accepted
//!   frame).
//!
//! Rewrites keep the weight slot bit-exact from the input (a limited
//! frame) or from the last accepted frame (a hold; with none, the weight
//! is 0: the arms go back to the locomotion controller, which keeps the
//! robot balanced).

use robodr_firewall::{JointFrame, MotorCmd, MotorMode};

use crate::lowcmd::{self, Forwarded, LowCmdCodec, RewriteError, WireLowCmd, WireMotor};
use crate::round;

/// Is the weight slot a valid blend weight (module docs)?
pub fn weight_ok(msg: &WireLowCmd, slot: usize, max_weight: f64) -> bool {
    let Some(m) = msg.motor(slot) else {
        return false;
    };
    let q = f64::from(m.q);
    m.mode == 0
        && q.is_finite()
        && (0.0..=max_weight).contains(&q)
        && [m.dq, m.tau, m.kp, m.kd].iter().all(|x| *x == 0.0)
}

/// The frame the firewall decides: every slot with gains or torque (or a
/// non-finite field) as enabled, the weight slot off.
pub fn decision_frame(msg: &WireLowCmd, weight_slot: usize) -> Option<JointFrame> {
    let base = msg.joint_frame()?;
    let mut motors = [MotorCmd::OFF; robodr_firewall::MAX_MOTORS];
    for (i, m) in base.motors().iter().enumerate() {
        let slot = motors.get_mut(i)?;
        if i == weight_slot {
            continue;
        }
        let mut m = *m;
        let carries = [m.kp, m.kd, m.tau].iter().any(|x| *x != 0.0) || !m.is_finite();
        if carries {
            m.mode = MotorMode::Enabled;
        }
        *slot = m;
    }
    let mut f = JointFrame::from_slice(motors.get(..base.slots())?, base.crc_ok)?;
    f.mode_pr = base.mode_pr;
    f.mode_machine = base.mode_machine;
    Some(f)
}

/// The wire frame of a **limited** decision: the firewall's values for
/// every decided slot (rounded away from the input, as `lowcmd::limited`),
/// mode octets and the weight slot as sent.
pub fn limited(
    input: &WireLowCmd,
    out: &JointFrame,
    weight_slot: usize,
) -> Result<WireLowCmd, RewriteError> {
    let n = input.slots();
    if out.slots() != n || out.mode_pr != input.modes().0 || out.mode_machine != input.modes().1 {
        return Err(RewriteError::Value);
    }
    let mut msg = *input;
    for (i, o) in out.motors().iter().enumerate() {
        if i == weight_slot {
            continue;
        }
        let w = input.motor(i).ok_or(RewriteError::Value)?;
        let f = |o: f64, i: f32| round::away_from(o, f64::from(i)).ok_or(RewriteError::Value);
        msg.set_motor(
            i,
            WireMotor {
                mode: w.mode,
                q: f(o.q, w.q)?,
                dq: f(o.dq, w.dq)?,
                tau: f(o.tau, w.tau)?,
                kp: f(o.kp, w.kp)?,
                kd: f(o.kd, w.kd)?,
            },
        );
    }
    msg.seal();
    Ok(msg)
}

/// The wire frame of a **substitute** (hold): `lowcmd::substitute`'s motor
/// values, the mode octets and the weight slot of the last accepted frame
/// (weight 0 with none).
pub fn substitute(
    codec: LowCmdCodec,
    sub: &JointFrame,
    last: Option<&Forwarded>,
    weight_slot: usize,
) -> Result<WireLowCmd, RewriteError> {
    let mut msg = lowcmd::substitute(codec, sub, last)?;
    for i in 0..msg.slots() {
        let mut m = msg.motor(i).ok_or(RewriteError::Value)?;
        let held = last.and_then(|l| l.wire.motor(i));
        if i == weight_slot {
            m = held.unwrap_or_default();
        } else if let Some(h) = held {
            m.mode = h.mode;
        }
        msg.set_motor(i, m);
    }
    msg.seal();
    Ok(msg)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn frame(weight: f32) -> WireLowCmd {
        let mut m = lowcmd::template(LowCmdCodec::Hg);
        for i in 15..29 {
            m.set_motor(
                i,
                WireMotor {
                    mode: 0,
                    q: 0.1,
                    dq: 0.0,
                    tau: 0.0,
                    kp: 60.0,
                    kd: 1.5,
                },
            );
        }
        m.set_motor(
            29,
            WireMotor {
                q: weight,
                ..Default::default()
            },
        );
        m.seal();
        m
    }

    #[test]
    fn mode_zero_slots_with_gains_are_decided_and_the_weight_is_not_a_motor() {
        let m = frame(1.0);
        let f = decision_frame(&m, 29).unwrap();
        for i in 15..29 {
            assert_eq!(f.motor(i).unwrap().mode, MotorMode::Enabled, "{i}");
        }
        assert_eq!(*f.motor(29).unwrap(), MotorCmd::OFF);
        assert_eq!(f.motor(0).unwrap().mode, MotorMode::Disabled);
        assert!(weight_ok(&m, 29, 1.0));
        assert!(!weight_ok(&frame(1.01), 29, 1.0));
        assert!(!weight_ok(&frame(-0.01), 29, 1.0));
        assert!(!weight_ok(&frame(f32::NAN), 29, 1.0));
        assert!(!weight_ok(&frame(0.6), 29, 0.5));
        let mut bad = frame(0.5);
        let mut w = bad.motor(29).unwrap();
        w.kp = 1.0;
        bad.set_motor(29, w);
        assert!(!weight_ok(&bad, 29, 1.0));
    }

    #[test]
    fn limited_keeps_modes_and_weight() {
        let m = frame(0.7);
        let mut out = decision_frame(&m, 29).unwrap();
        out.motor_mut(20).unwrap().kp = 30.0;
        let w = limited(&m, &out, 29).unwrap();
        assert!(w.crc_ok());
        assert_eq!(w.motor(20).unwrap().kp, 30.0);
        assert_eq!(w.motor(20).unwrap().mode, 0);
        assert_eq!(w.motor(29), m.motor(29));
    }
}
