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
//! **The weight's dynamics** ([`weight_gate`], review finding F1). A
//! bounded weight is not enough: `0 → 1 → 0 → 1` on consecutive frames
//! snaps the arms between the locomotion pose and the SDK's targets at full
//! gains. Relative to the last **accepted** frame's weight `w0` (0 when
//! none):
//!
//! - `|w − w0| <= max_weight_step` (per accepted frame, default 0.02) and
//!   `|w − w0| <= max_weight_rate_per_s · Δt` (Δt since that frame, default
//!   0.5 /s; the SDK examples ramp at 0.2 /s);
//! - **engagement** (the weight rising from 0, or a first frame after a
//!   gateway start): when the robot's own joint positions are known (a
//!   `rt/lowstate` sample the gateway observed on the robot side within
//!   `lowstate_max_age_ms`), every weighted slot (a slot with `kp > 0`)
//!   must target a `q` within `engage_max_q_error` of the measured one: the
//!   hand-over then starts where the arm is (the SDK example
//!   `g1_arm7_sdk_dds_example.cpp:132-160` reads `rt/lowstate` and starts
//!   from it). A first frame after a gateway start that passes this check
//!   may carry any weight (the stream was already engaged). Without a
//!   fresh `rt/lowstate` the weight may leave 0 only up to
//!   `engage_first_step` and rise beyond it only after
//!   `engage_stable_frames` accepted frames whose weighted targets moved by
//!   at most `engage_stable_q`, i.e. once the arms had time to settle at
//!   the small blend.
//!
//! A frame outside these rules is an integrity failure like a weight out
//! of range: the humanoid holds the last accepted frame (its weight
//! included), nothing is forwarded before a first accepted frame.
//!
//! Rewrites keep the weight slot bit-exact from the input (a limited
//! frame) or from the last accepted frame (a hold; with none, the weight
//! is 0: the arms go back to the locomotion controller, which keeps the
//! robot balanced).

use robodr_firewall::{JointFrame, MotorCmd, MotorMode, MAX_MOTORS};

use crate::config::WeightDynamics;
use crate::lowcmd::{self, Forwarded, LowCmdCodec, RewriteError, WireLowCmd, WireMotor};
use crate::round;

/// Slack on weight comparisons (the weight is an `f32` on the wire).
const EPS: f64 = 1e-6;

/// The robot's measured joint positions (`rt/lowstate`, observed on the
/// robot side) and when the gateway saw them (its clock).
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct JointState {
    pub q: [f32; MAX_MOTORS],
    pub slots: usize,
    pub at_ns: u64,
}

/// The blend-weight state of an arm-SDK channel (accepted frames only).
#[derive(Debug, Clone, Copy, Default, PartialEq)]
pub struct WeightState {
    /// Weight of the last accepted frame and its gateway time.
    pub last: Option<(f64, u64)>,
    /// The current engagement was verified (against `rt/lowstate`, or by
    /// the stable-targets rule).
    pub verified: bool,
    /// Accepted frames in a row with stable weighted targets while engaged
    /// at most `engage_first_step` without verification.
    pub stable: u32,
    /// Weighted targets of the last accepted frame (`NaN`: not weighted).
    pub last_q: Option<[f32; MAX_MOTORS]>,
}

/// Why [`weight_gate`] refused a frame.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WeightRefusal {
    /// More than `max_weight_step` from the last accepted weight.
    Step,
    /// Faster than `max_weight_rate_per_s`.
    Rate,
    /// Engagement not verified (targets away from `rt/lowstate`, or above
    /// the first step without stable targets).
    Engage,
}

/// The weighted slots' targets (slots with `kp > 0`, the weight slot
/// excluded; `NaN` elsewhere).
pub fn weighted_q(msg: &WireLowCmd, weight_slot: usize) -> [f32; MAX_MOTORS] {
    let mut q = [f32::NAN; MAX_MOTORS];
    for (i, dst) in q.iter_mut().enumerate().take(msg.slots()) {
        if i == weight_slot {
            continue;
        }
        if let Some(m) = msg.motor(i) {
            if m.kp != 0.0 {
                *dst = m.q;
            }
        }
    }
    q
}

/// Is every weighted target of `q` within `tol` of `state` (a weighted slot
/// the state does not cover fails)?
fn close_to(q: &[f32; MAX_MOTORS], state: &JointState, tol: f64) -> bool {
    q.iter().enumerate().all(|(i, t)| {
        if t.is_nan() {
            return true;
        }
        i < state.slots
            && state
                .q
                .get(i)
                .is_some_and(|m| (f64::from(*t) - f64::from(*m)).abs() <= tol)
    })
}

/// Decide the blend weight's dynamics of `msg` (module docs). `Ok(verified)`
/// tells whether the engagement is verified after this frame.
pub fn weight_gate(
    msg: &WireLowCmd,
    weight_slot: usize,
    st: &WeightState,
    d: &WeightDynamics,
    now: u64,
    lowstate: Option<&JointState>,
) -> Result<bool, WeightRefusal> {
    let w = msg.motor(weight_slot).map_or(f64::NAN, |m| f64::from(m.q));
    if !w.is_finite() {
        return Err(WeightRefusal::Step);
    }
    let q = weighted_q(msg, weight_slot);
    // A state measured just after the frame arrived (it is not applied
    // yet) is as good as one just before it.
    let fresh = lowstate.filter(|l| l.at_ns.abs_diff(now) <= d.lowstate_max_age_ns);
    let matches_robot = fresh.is_some_and(|l| close_to(&q, l, d.engage_max_q_error));
    let Some((w0, t0)) = st.last else {
        // A first frame (gateway start): from rest, or a stream already
        // engaged whose targets are where the arms are.
        return if w == 0.0 {
            Ok(false)
        } else if matches_robot {
            Ok(true)
        } else if fresh.is_none() && w <= d.max_step.min(d.engage_first_step) + EPS {
            Ok(false)
        } else {
            Err(WeightRefusal::Engage)
        };
    };
    let dw = (w - w0).abs();
    if dw > d.max_step + EPS {
        return Err(WeightRefusal::Step);
    }
    let dt = now.saturating_sub(t0) as f64 * 1e-9;
    if dw > d.max_rate_per_s * dt + EPS {
        return Err(WeightRefusal::Rate);
    }
    if w <= w0 + EPS {
        return Ok(st.verified && w > 0.0);
    }
    if w0 == 0.0 {
        // Engaging from 0.
        return match fresh {
            Some(_) if matches_robot => Ok(true),
            Some(_) => Err(WeightRefusal::Engage),
            None if w <= d.engage_first_step + EPS => Ok(false),
            None => Err(WeightRefusal::Engage),
        };
    }
    if st.verified || w <= d.engage_first_step + EPS {
        return Ok(st.verified);
    }
    if st.stable >= d.engage_stable_frames {
        Ok(true)
    } else {
        Err(WeightRefusal::Engage)
    }
}

/// The state after an accepted frame (`msg` as forwarded).
pub fn accepted(
    msg: &WireLowCmd,
    weight_slot: usize,
    st: &WeightState,
    d: &WeightDynamics,
    now: u64,
    verified: bool,
) -> WeightState {
    let w = msg.motor(weight_slot).map_or(0.0, |m| f64::from(m.q));
    let q = weighted_q(msg, weight_slot);
    let stable_q = st.last_q.is_some_and(|p| {
        q.iter().zip(p.iter()).all(|(a, b)| {
            (a.is_nan() && b.is_nan()) || (f64::from(*a) - f64::from(*b)).abs() <= d.engage_stable_q
        })
    });
    let stable = if w == 0.0 || verified {
        0
    } else if stable_q {
        st.stable.saturating_add(1)
    } else {
        0
    };
    WeightState {
        last: Some((w, now)),
        verified: verified && w > 0.0,
        stable,
        last_q: Some(q),
    }
}

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
