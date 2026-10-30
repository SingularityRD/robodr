//! The low-level joint hot path: [`Firewall::check_joint`].
//!
//! Same constraints as [`crate::engine`]: no heap allocation after
//! construction, no panics (no `unwrap`, no slice indexing, saturating /
//! checked integer maths), bounded work (every loop is over at most
//! [`crate::MAX_MOTORS`] slots, plus one scan of the event buffer per event).
//!
//! ## Decision table (stages in order; the first rejection wins)
//!
//! | # | Stage | Condition | Verdict | Substitute |
//! |---|---|---|---|---|
//! | 0 | clock | `now` < previous `now` | Reject `ClockRegression` | yes |
//! | 1 | channel | unknown id / not a joint channel | Reject `UnknownChannel` / `KindMismatch` | none |
//! | 2 | source | unknown / not allowed | Reject `UnknownSource` / `UnauthorizedSource` | per [`crate::ForeignSourceAction`] |
//! | 3 | rate | `now − last accepted < min_interval` | Reject `RateLimited` | **none** (previous frame still in force) |
//! | 4 | crc | `crc_ok == Some(false)`, or `None` with `require_crc` | Reject `CrcInvalid` | yes |
//! | 5 | shape | slot count ≠ configured | Reject `KindMismatch` | yes |
//! | 5 | mode | `mode_pr` / `mode_machine` ≠ its pin (if pinned) | Reject `JointModePinMismatch` | yes |
//! | 6 | values | any NaN / ±inf in any slot | Reject `NonFinite` | yes |
//! | 7 | time | future / stale (`max_age_ns`) / out of order | Reject `FutureTimestamp` / `Stale` / `OutOfOrder` | yes |
//! | 8 | slots | mode off but `kp`, `kd` or `tau` ≠ 0 | Reject `JointModeInconsistent` | yes |
//! | 8 | slots | unused slot energised | Reject `DisabledMotorEnergised` | yes |
//! | 8 | slots | gain < min (mode off = zero gains) | Reject `JointGainBelowMinimum` | yes |
//! | 8 | slots | gain > `f`× max | Reject `JointGainOutOfEnvelope` | yes |
//! | 8 | slots | `\|tau\|` > `f·tau_max` | Reject `JointTorqueOutOfEnvelope` | yes |
//! | 8 | slots | `kd > 0` and `\|dq\|` > `f·dq_max` | Reject `JointVelocityOutOfEnvelope` | yes |
//! | 8 | slots | `kp > 0` and `q` beyond the range by > `(f−1)·width` | Reject `JointPositionOutOfEnvelope` | yes |
//! | 8 | slots | `kp > 0`, `q_prev` known, `\|q − q_prev\|` > `f·max_dq_step` | Reject `JointStepOutOfEnvelope` | yes |
//! | 8 | slots | `kp > 0`, `q_prev` known, `kp·\|q − q_prev\|` > `f·tau_pd_max` | Reject `JointPdTorqueOutOfEnvelope` | yes |
//! | 9 | clamp | gain > max, `\|tau\|` > max, `\|dq\|` > max, `q` outside range | Limit (clamp the field) | — |
//! | 9 | clamp | `\|q − q_prev\|` > `max_dq_step` or `kp·\|q − q_prev\|` > `tau_pd_max` | Limit (step `q` from `q_prev` toward it) | — |
//! | 10 | limp | humanoid, `balance_critical` channel (default): every enabled slot limp (`kp = kd = 0` or mode off) | Reject `JointLimpFrame` | yes |
//! | 11 | post | output not finite / outside the envelope (a bug) | per [`crate::FaultPolicy`] (humanoid: hold) | — |
//! | — | gap | accepted `> max_interval` after the previous one | event `joint_rate_violation` only | — |
//!
//! Slots are scanned in order; within a slot the order is the row order
//! above. A target only constrains while its gain acts: `q` is not checked
//! when `kp == 0`, `dq` not when `kd == 0` (the Unitree SDK parks idle slots
//! at `PosStopF` / `VelStopF` with zero gains).
//!
//! Clamping only ever **lowers** a magnitude (`dq`, `tau`, `kp`, `kd`) or
//! moves `q` toward its range and toward the previous target; it never
//! raises a gain (a gain below its minimum is a rejection), so the output
//! is never stiffer, faster or stronger than the input.
//!
//! `q_prev` is the slot's position target in the last **accepted** output
//! in which that slot held a position (mode on, `kp > 0`). Accepted frames
//! in which the slot holds no position (`kp = 0`) keep it: it expires by
//! **time**, `step_reference_ttl_ns` after that frame, not by frame (gateway
//! review, finding 5: alternating `kp = 0` frames used to clear it, so the
//! next position frame could jump anywhere in the range). It is unknown on
//! the first frame, after a damping substitute and once expired; then only
//! the absolute range applies.
//!
//! ## Substitutes
//! Every "yes" above is subject to the emission interval: no substitute is
//! emitted while the last emitted frame (accepted or substitute) on the
//! channel is younger than `min_interval_ns` (nothing is emitted instead;
//! the previous emission is still in force).
//! - **Humanoid** platform: the last accepted frame with `dq := 0` on every
//!   slot (`HoldLast`), whatever the reason (also under a clock regression
//!   or a fault, whatever the fault policy), or **nothing** if no frame was
//!   accepted yet. Never a zero / damping / limp frame. The hold has no
//!   release: once it is older than `max_hold_ns` the held frame's `tau` is
//!   zeroed (gains and `q` kept) and a Critical `joint_hold_exceeded` event
//!   is recorded once per hold episode.
//! - Other platforms: `HoldLast { max_hold_ns }` holds that frame while it
//!   is younger than `max_hold_ns` (not under a clock regression, not for a
//!   foreign source), else the damping frame (`Zero`); `ZeroVelocity`
//!   always damps. Faults: `FailHold` holds (damping if nothing to hold),
//!   `FailSafe` damps, `FailOpen` forwards.
#![deny(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects
)]

use crate::command::SourceId;
use crate::config::{FailBehaviour, FaultPolicy, ForeignSourceAction};
use crate::engine::{Firewall, PairState};
use crate::events::{reject_rule, rules, EventAction};
use crate::joint::{JointCommand, JointFrame, MotorCmd, MotorMode, MAX_MOTORS};
use crate::joint_config::{CompiledJointChannel, CompiledMotor};
use crate::verdict::{
    JointLimitReasons, JointSubstitute, JointVerdict, JointWouldHave, RejectReason, SubstituteKind,
};
use robodr_events::Severity;

/// No previous position target for a slot.
const NO_Q: f64 = f64::NAN;

/// Absolute part of the tolerance of the step post-condition (rad); scaled
/// by `1 + max(|q|, |q_prev|)`. Rounding of `q_prev ± step` is far below it.
const STEP_TOL: f64 = 1e-12;
/// Relative tolerance of the PD-torque post-condition.
const PD_TOL: f64 = 1e-9;

/// Per low-level joint channel state.
#[derive(Debug, Clone, Copy)]
pub(crate) struct JointChanState {
    /// Last accepted (forwarded) frame and when, on the gateway clock. The
    /// base of `HoldLast` and of the interval checks.
    accepted: Option<(JointFrame, u64)>,
    /// When the last foreign-source-triggered substitute was emitted.
    last_foreign_sub_at: Option<u64>,
    /// When the last frame (accepted or substitute) was emitted.
    last_emit_at: Option<u64>,
    /// Per slot: position target of the last accepted output in which the
    /// slot held a position, else [`NO_Q`] ...
    q_prev: [f64; MAX_MOTORS],
    /// ... and when it was accepted (it expires `step_reference_ttl_ns`
    /// later, [`JointChanState::step_reference`]).
    q_prev_at: [u64; MAX_MOTORS],
    /// A hold episode is running (hold substitutes since the last accepted
    /// frame).
    holding: bool,
    /// The running hold episode already raised `joint_hold_exceeded`.
    hold_exceeded: bool,
}

impl JointChanState {
    pub(crate) const INIT: JointChanState = JointChanState {
        accepted: None,
        last_foreign_sub_at: None,
        last_emit_at: None,
        q_prev: [NO_Q; MAX_MOTORS],
        q_prev_at: [0; MAX_MOTORS],
        holding: false,
        hold_exceeded: false,
    };

    /// The step reference in force at `now`: `q_prev` where it is younger
    /// than `ttl`, else [`NO_Q`].
    fn step_reference(&self, now: u64, ttl: u64) -> [f64; MAX_MOTORS] {
        let mut out = [NO_Q; MAX_MOTORS];
        for ((o, q), at) in out.iter_mut().zip(&self.q_prev).zip(&self.q_prev_at) {
            if now.saturating_sub(*at) <= ttl {
                *o = *q;
            }
        }
        out
    }
}

#[derive(Debug, Clone, Copy)]
struct JRejection {
    reason: RejectReason,
    value: f64,
    limit: f64,
    slot: Option<u8>,
    /// `false`: emit nothing (the frame arrived too early; the previous
    /// output is still in force).
    substitutable: bool,
}

impl JRejection {
    fn new(reason: RejectReason) -> Self {
        Self::with(reason, f64::NAN, f64::NAN, None)
    }
    fn with(reason: RejectReason, value: f64, limit: f64, slot: Option<u8>) -> Self {
        Self {
            reason,
            value,
            limit,
            slot,
            substitutable: true,
        }
    }
}

/// Worst violation of one limit kind: (value, limit, slot).
type Worst = (f64, f64, Option<u8>);
const NO_WORST: Worst = (f64::NAN, f64::NAN, None);

fn note(w: &mut Worst, value: f64, limit: f64, slot: Option<u8>) {
    if w.0.is_nan() || value > w.0 {
        *w = (value, limit, slot);
    }
}

#[derive(Debug, Clone, Copy)]
struct JAccepted {
    out: JointFrame,
    reasons: JointLimitReasons,
    position: Worst,
    velocity: Worst,
    torque: Worst,
    gain: Worst,
    step: Worst,
    pd_torque: Worst,
    /// `(gap, max_interval)` if the stream was slower than allowed.
    gap: Option<(u64, u64)>,
    pair_idx: usize,
    pair_new: PairState,
}

/// Distance of `q` outside `[lo, hi]` (0 inside).
fn outside(q: f64, lo: f64, hi: f64) -> f64 {
    if q < lo {
        lo - q
    } else if q > hi {
        q - hi
    } else {
        0.0
    }
}

/// Which motor slot index, as reported in events.
fn slot_id(i: usize) -> Option<u8> {
    u8::try_from(i).ok()
}

/// `x` clamped into `[lo, hi]` without `f64::clamp` (which panics on
/// inverted or NaN bounds). Compiled bounds are ordered; if they ever were
/// not, the result is still one of the bounds, and the post-condition
/// catches it.
fn clamp_to(x: f64, lo: f64, hi: f64) -> f64 {
    debug_assert!(lo <= hi, "inverted clamp bounds [{lo}, {hi}]");
    x.max(lo).min(hi)
}

/// `true` if the slot's position target is in force with `kp > 0`.
fn holds_position(m: &MotorCmd) -> bool {
    m.mode == MotorMode::Enabled && m.kp > 0.0
}

/// Is `m` inside the compiled envelope `lim` (post-condition; clamps produce
/// the bound itself, steps up to rounding)? `q_prev` is [`NO_Q`] when there
/// is no previous target.
fn motor_ok(m: &MotorCmd, lim: &CompiledMotor, q_prev: f64) -> bool {
    if !m.is_finite() || m.disabled_but_loaded() {
        return false;
    }
    if !lim.enabled {
        return !m.energises();
    }
    let (kp, kd) = (m.effective_kp(), m.effective_kd());
    if kp < lim.kp_min || kd < lim.kd_min {
        return false;
    }
    if m.mode == MotorMode::Disabled {
        return true;
    }
    let in_envelope = kp <= lim.kp_max
        && kd <= lim.kd_max
        && m.tau.abs() <= lim.tau_max
        && (kd == 0.0 || m.dq.abs() <= lim.dq_max)
        && (kp == 0.0 || (lim.q_min <= m.q && m.q <= lim.q_max));
    if !in_envelope {
        return false;
    }
    if kp > 0.0 && q_prev.is_finite() {
        let d = (m.q - q_prev).abs();
        let tol = STEP_TOL * (1.0 + m.q.abs().max(q_prev.abs()));
        if lim.max_dq_step.is_some_and(|s| d > s + tol) {
            return false;
        }
        if lim
            .tau_pd_max
            .is_some_and(|t| kp * d > t * (1.0 + PD_TOL) + kp * tol)
        {
            return false;
        }
    }
    true
}

/// Humanoid: is every enabled slot of `f` limp (and is there one)?
fn all_limp(ch: &CompiledJointChannel, f: &JointFrame) -> bool {
    ch.any_enabled
        && f.motors()
            .iter()
            .zip(ch.motors.iter())
            .filter(|(_, l)| l.enabled)
            .all(|(m, _)| m.is_limp())
}

fn pins_ok(ch: &CompiledJointChannel, f: &JointFrame) -> bool {
    ch.pinned_mode_pr.is_none_or(|p| f.mode_pr == Some(p))
        && ch
            .pinned_mode_machine
            .is_none_or(|p| f.mode_machine == Some(p))
}

fn frame_ok(ch: &CompiledJointChannel, f: &JointFrame, q_prev: &[f64; MAX_MOTORS]) -> bool {
    f.slots() == ch.slots
        && pins_ok(ch, f)
        && !(ch.humanoid && ch.balance_critical && all_limp(ch, f))
        && f.motors()
            .iter()
            .zip(ch.motors.iter())
            .zip(q_prev.iter())
            .all(|((m, l), q)| motor_ok(m, l, *q))
}

/// The hold substitute: `f` with every velocity target zeroed (a held
/// position target with a non-zero velocity target would keep pushing), and
/// with its feed-forward torque zeroed too when `drop_tau` (a humanoid hold
/// past `max_hold_ns`).
fn hold_frame(f: &JointFrame, drop_tau: bool) -> JointFrame {
    let mut h = *f;
    for m in h.motors_mut() {
        m.dq = 0.0;
        if drop_tau {
            m.tau = 0.0;
        }
    }
    h.crc_ok = Some(true);
    h
}

/// The damping substitute (non-humanoid platforms only): every enabled slot
/// `kp = 0, dq = 0, tau = 0, kd = min(damping_kd, kd_max)`; unused slots
/// off; the channel's pinned `mode_pr` / `mode_machine`.
fn damping_frame(ch: &CompiledJointChannel) -> JointFrame {
    let mut f = JointFrame::off(ch.slots, Some(true));
    for (m, lim) in f.motors_mut().iter_mut().zip(ch.motors.iter()) {
        *m = if lim.enabled {
            MotorCmd::enabled(0.0, 0.0, 0.0, 0.0, ch.damping_kd.min(lim.kd_max))
        } else {
            MotorCmd::OFF
        };
    }
    f.mode_pr = ch.pinned_mode_pr;
    f.mode_machine = ch.pinned_mode_machine;
    f
}

/// What [`Firewall::emit_substitute`] decided.
#[derive(Debug, Clone, Copy)]
struct Emitted {
    sub: Option<JointSubstitute>,
    /// A humanoid hold just passed `max_hold_ns` in this episode:
    /// `(hold age, max_hold_ns)` for the `joint_hold_exceeded` event.
    exceeded: Option<(u64, u64)>,
}

/// Which substitute path is asking.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum SubFor {
    /// A rejection; `allow_hold` false for clock regressions and foreign
    /// sources (non-humanoid platforms then damp).
    Reject { allow_hold: bool },
    /// An internal fault, per `FaultPolicy`.
    Fault,
}

impl Firewall {
    /// Check one low-level joint frame. Never allocates, never panics,
    /// bounded time (`O(MAX_MOTORS)` plus one event-buffer scan per event).
    /// See the module docs (and the crate README) for the decision table.
    ///
    /// `now` is the gateway's monotonic clock in ns, shared with
    /// [`Firewall::check`] (one clock for the whole firewall).
    pub fn check_joint(&mut self, cmd: &JointCommand, now: u64) -> JointVerdict {
        self.stats.checked = self.stats.checked.saturating_add(1);
        let result = self.evaluate_joint(cmd, now);

        #[cfg(test)]
        let result = match result {
            Ok(mut a) if self.inject_fault => {
                if let Some(m) = a.out.motors_mut().first_mut() {
                    m.q = f64::NAN;
                }
                Ok(a)
            }
            r => r,
        };

        match result {
            Err(rej) => self.reject_joint(cmd, now, rej),
            Ok(acc) => {
                let ok = self.policy.joint_index(cmd.channel).is_some_and(|j| {
                    match (self.policy.joint_channels.get(j), self.jchans.get(j)) {
                        (Some(ch), Some(st)) => frame_ok(
                            ch,
                            &acc.out,
                            &st.step_reference(now, ch.step_reference_ttl_ns),
                        ),
                        _ => false,
                    }
                });
                if !ok {
                    return self.fault_joint(cmd, now);
                }
                if let Some(p) = self.pairs.get_mut(acc.pair_idx) {
                    *p = acc.pair_new;
                }
                self.accept_joint(cmd, now, acc)
            }
        }
    }

    /// The verdict when the gateway **cannot evaluate** a joint frame
    /// (deadline miss, internal fault), per the platform's
    /// [`FaultPolicy`]; on a humanoid channel it always holds (or emits
    /// nothing), whatever the fault policy: never a damping frame, never the
    /// unchecked input.
    pub fn joint_fault_verdict(&mut self, cmd: &JointCommand, now: u64) -> JointVerdict {
        self.stats.checked = self.stats.checked.saturating_add(1);
        self.fault_joint(cmd, now)
    }

    fn evaluate_joint(&mut self, cmd: &JointCommand, now: u64) -> Result<JAccepted, JRejection> {
        // 0. Gateway clock.
        if let Some(last) = self.last_now {
            if now < last {
                return Err(JRejection::with(
                    RejectReason::ClockRegression,
                    now as f64,
                    last as f64,
                    None,
                ));
            }
        }
        self.last_now = Some(now);

        // 1. Channel (must be a low-level joint channel).
        let ch_idx = usize::from(cmd.channel.0);
        let joint = self.policy.joint_index(cmd.channel);
        let known_other = self.policy.channels.get(ch_idx).is_some();
        if joint.is_none() && !known_other {
            return Err(JRejection::new(RejectReason::UnknownChannel));
        }

        // 2. Source.
        let src_idx = usize::from(cmd.source.0);
        if cmd.source == SourceId::UNKNOWN || src_idx >= self.nsrc {
            return Err(JRejection::new(RejectReason::UnknownSource));
        }
        if !self.policy.allows(cmd.channel, cmd.source) {
            return Err(JRejection::new(RejectReason::UnauthorizedSource));
        }
        let Some(j) = joint else {
            // A twist / joint-velocity channel: use `check`.
            return Err(JRejection::new(RejectReason::KindMismatch));
        };
        let Some(ch) = self.policy.joint_channels.get(j) else {
            return Err(JRejection::new(RejectReason::UnknownChannel));
        };
        let st = self.jchans.get(j).unwrap_or(&JointChanState::INIT);
        let pair_idx = ch_idx
            .checked_mul(self.nsrc)
            .and_then(|x| x.checked_add(src_idx));
        let Some((pair_idx, pair)) = pair_idx.and_then(|i| self.pairs.get(i).map(|p| (i, *p)))
        else {
            return Err(JRejection::new(RejectReason::UnknownSource));
        };
        let mut pair_new = pair;

        // 3. Minimum interval since the last accepted frame (per channel:
        //    it bounds what the motor bus receives, whoever sends).
        let since = st.accepted.as_ref().map(|(_, at)| now.saturating_sub(*at));
        if let Some(gap) = since {
            if gap < ch.min_interval_ns {
                return Err(JRejection {
                    substitutable: false,
                    ..JRejection::with(
                        RejectReason::RateLimited,
                        gap as f64,
                        ch.min_interval_ns as f64,
                        None,
                    )
                });
            }
        }

        // 4. CRC as reported by the decoder.
        match cmd.frame.crc_ok {
            Some(true) => {}
            Some(false) => {
                return Err(JRejection::with(RejectReason::CrcInvalid, 0.0, 1.0, None));
            }
            None if ch.require_crc => {
                return Err(JRejection::new(RejectReason::CrcInvalid));
            }
            None => {}
        }

        // 5. Shape.
        if cmd.frame.slots() != ch.slots {
            return Err(JRejection::with(
                RejectReason::KindMismatch,
                cmd.frame.slots() as f64,
                ch.slots as f64,
                None,
            ));
        }
        // 5. Frame-level modes (G1 / H1-2 `mode_pr`, `mode_machine`): they
        //    change what the envelope's ankle `q` bounds mean.
        for (pin, got) in [
            (ch.pinned_mode_pr, cmd.frame.mode_pr),
            (ch.pinned_mode_machine, cmd.frame.mode_machine),
        ] {
            if let Some(p) = pin {
                if got != Some(p) {
                    return Err(JRejection::with(
                        RejectReason::JointModePinMismatch,
                        got.map_or(f64::NAN, f64::from),
                        f64::from(p),
                        None,
                    ));
                }
            }
        }

        // 6. Finite values (every slot, used or not).
        if !cmd.frame.is_finite() {
            return Err(JRejection::new(RejectReason::NonFinite));
        }

        // 7. Timestamps.
        if cmd.stamp_ns > now.saturating_add(ch.max_future_ns) {
            return Err(JRejection::with(
                RejectReason::FutureTimestamp,
                cmd.stamp_ns.saturating_sub(now) as f64,
                ch.max_future_ns as f64,
                None,
            ));
        }
        let age = now.saturating_sub(cmd.stamp_ns);
        if age > ch.max_age_ns {
            return Err(JRejection::with(
                RejectReason::Stale,
                age as f64,
                ch.max_age_ns as f64,
                None,
            ));
        }
        if let Some(last) = pair.last_stamp {
            if cmd.stamp_ns <= last {
                return Err(JRejection::with(
                    RejectReason::OutOfOrder,
                    cmd.stamp_ns as f64,
                    last as f64,
                    None,
                ));
            }
        }
        // The watermark never runs ahead of `now`: an accepted frame stamped
        // up to `max_future_ns` early must not lock out the on-time frames
        // that follow it.
        pair_new.last_stamp = Some(cmd.stamp_ns.min(now));

        // 8 + 9. Per slot: hard rejections, then clamps.
        let f = ch.hard_factor;
        let mut out = cmd.frame;
        let mut reasons = JointLimitReasons::NONE;
        let (mut position, mut velocity, mut torque, mut gain) =
            (NO_WORST, NO_WORST, NO_WORST, NO_WORST);
        let (mut step, mut pd_torque) = (NO_WORST, NO_WORST);
        let q_ref = st.step_reference(now, ch.step_reference_ttl_ns);
        for (i, ((m, lim), q_prev)) in out
            .motors_mut()
            .iter_mut()
            .zip(ch.motors.iter())
            .zip(q_ref.iter())
            .enumerate()
        {
            let slot = slot_id(i);
            let q_prev = *q_prev;
            let rej = |reason, value, limit| Err(JRejection::with(reason, value, limit, slot));
            // Mode off must mean inert: never forward gains / torque the
            // firewall did not check on the strength of a mode octet.
            if m.disabled_but_loaded() {
                return rej(RejectReason::JointModeInconsistent, 1.0, 0.0);
            }
            if !lim.enabled {
                if m.energises() {
                    return rej(RejectReason::DisabledMotorEnergised, 1.0, 0.0);
                }
                continue;
            }
            let (kp, kd) = (m.effective_kp(), m.effective_kd());
            if kp < lim.kp_min {
                return rej(RejectReason::JointGainBelowMinimum, kp, lim.kp_min);
            }
            if kd < lim.kd_min {
                return rej(RejectReason::JointGainBelowMinimum, kd, lim.kd_min);
            }
            if m.mode == MotorMode::Disabled {
                continue;
            }
            if kp > f * lim.kp_max {
                return rej(RejectReason::JointGainOutOfEnvelope, kp, f * lim.kp_max);
            }
            if kd > f * lim.kd_max {
                return rej(RejectReason::JointGainOutOfEnvelope, kd, f * lim.kd_max);
            }
            let tau = m.tau.abs();
            if tau > f * lim.tau_max {
                return rej(RejectReason::JointTorqueOutOfEnvelope, tau, f * lim.tau_max);
            }
            let dq = m.dq.abs();
            if kd > 0.0 && dq > f * lim.dq_max {
                return rej(RejectReason::JointVelocityOutOfEnvelope, dq, f * lim.dq_max);
            }
            let dist = outside(m.q, lim.q_min, lim.q_max);
            let margin = (f - 1.0) * (lim.q_max - lim.q_min);
            if kp > 0.0 && dist > margin {
                return rej(RejectReason::JointPositionOutOfEnvelope, dist, margin);
            }
            // Step bounds against the previous accepted target (if any).
            let tracked = kp > 0.0 && q_prev.is_finite();
            if tracked {
                let d = (m.q - q_prev).abs();
                if let Some(s) = lim.max_dq_step {
                    if d > f * s {
                        return rej(RejectReason::JointStepOutOfEnvelope, d, f * s);
                    }
                }
                if let Some(t) = lim.tau_pd_max {
                    if kp * d > f * t {
                        return rej(RejectReason::JointPdTorqueOutOfEnvelope, kp * d, f * t);
                    }
                }
            }

            // Clamps: lower magnitudes / move q; never raise anything.
            if kp > lim.kp_max {
                m.kp = lim.kp_max;
                reasons.insert(JointLimitReasons::GAIN);
                note(&mut gain, kp, lim.kp_max, slot);
            }
            if kd > lim.kd_max {
                m.kd = lim.kd_max;
                reasons.insert(JointLimitReasons::GAIN);
                note(&mut gain, kd, lim.kd_max, slot);
            }
            if tau > lim.tau_max {
                m.tau = clamp_to(m.tau, -lim.tau_max, lim.tau_max);
                reasons.insert(JointLimitReasons::TORQUE);
                note(&mut torque, tau, lim.tau_max, slot);
            }
            if kd > 0.0 && dq > lim.dq_max {
                m.dq = clamp_to(m.dq, -lim.dq_max, lim.dq_max);
                reasons.insert(JointLimitReasons::VELOCITY);
                note(&mut velocity, dq, lim.dq_max, slot);
            }
            if kp > 0.0 && dist > 0.0 {
                m.q = clamp_to(m.q, lim.q_min, lim.q_max);
                reasons.insert(JointLimitReasons::POSITION);
                note(&mut position, dist, 0.0, slot);
            }
            if tracked && m.kp > 0.0 {
                // `q_prev` and the (projected) target are both inside the
                // range, so any point between them is too.
                let target = m.q;
                let d = (target - q_prev).abs();
                let step_over = lim.max_dq_step.filter(|s| d > *s);
                let pd_over = lim.tau_pd_max.filter(|t| m.kp * d > *t);
                if step_over.is_some() || pd_over.is_some() {
                    let allowed = step_over
                        .unwrap_or(f64::INFINITY)
                        .min(pd_over.map_or(f64::INFINITY, |t| t / m.kp));
                    let moved = if target > q_prev {
                        q_prev + allowed
                    } else {
                        q_prev - allowed
                    };
                    m.q = clamp_to(moved, q_prev.min(target), q_prev.max(target));
                }
                if let Some(s) = step_over {
                    reasons.insert(JointLimitReasons::STEP);
                    note(&mut step, d, s, slot);
                }
                if let Some(t) = pd_over {
                    reasons.insert(JointLimitReasons::PD_TORQUE);
                    note(&mut pd_torque, m.kp * d, t, slot);
                }
            }
        }

        // 10. Humanoid: a frame that makes every enabled joint limp (only
        //     on a balance-critical channel: a hand may be released).
        if ch.humanoid && ch.balance_critical && all_limp(ch, &out) {
            return Err(JRejection::new(RejectReason::JointLimpFrame));
        }

        let gap = match since {
            Some(g) if g > ch.max_interval_ns => Some((g, ch.max_interval_ns)),
            _ => None,
        };
        Ok(JAccepted {
            out,
            reasons,
            position,
            velocity,
            torque,
            gain,
            step,
            pd_torque,
            gap,
            pair_idx,
            pair_new,
        })
    }

    fn accept_joint(&mut self, cmd: &JointCommand, now: u64, acc: JAccepted) -> JointVerdict {
        let action = if self.observe {
            EventAction::ObservedOnly
        } else {
            EventAction::Limited
        };
        let key = (cmd.channel, cmd.source);
        for (bit, rule, (value, limit, slot)) in [
            (
                JointLimitReasons::POSITION,
                rules::JOINT_POSITION_OUT_OF_ENVELOPE,
                acc.position,
            ),
            (
                JointLimitReasons::VELOCITY,
                rules::JOINT_VELOCITY_OUT_OF_ENVELOPE,
                acc.velocity,
            ),
            (
                JointLimitReasons::TORQUE,
                rules::JOINT_TORQUE_OUT_OF_ENVELOPE,
                acc.torque,
            ),
            (
                JointLimitReasons::GAIN,
                rules::JOINT_GAIN_OUT_OF_ENVELOPE,
                acc.gain,
            ),
            (
                JointLimitReasons::STEP,
                rules::JOINT_STEP_OUT_OF_ENVELOPE,
                acc.step,
            ),
            (
                JointLimitReasons::PD_TORQUE,
                rules::JOINT_PD_TORQUE_OUT_OF_ENVELOPE,
                acc.pd_torque,
            ),
        ] {
            if acc.reasons.contains(bit) {
                self.record(rule, Severity::High, key, now, action, (value, limit), slot);
            }
        }
        if let Some((gap, mx)) = acc.gap {
            self.record(
                rules::JOINT_RATE_VIOLATION,
                Severity::Medium,
                key,
                now,
                EventAction::ObservedOnly,
                (gap as f64, mx as f64),
                None,
            );
        }

        let limited = JointCommand {
            frame: acc.out,
            ..*cmd
        };
        let forwarded = if self.observe { cmd.frame } else { acc.out };
        if let Some(st) = self
            .policy
            .joint_index(cmd.channel)
            .and_then(|j| self.jchans.get_mut(j))
        {
            st.accepted = Some((forwarded, now));
            st.last_emit_at = Some(now);
            // The step reference is the enforced output (also in observe
            // mode, so the would-have verdicts stay those of enforcement).
            // A slot that holds no position keeps its reference (it
            // expires by time, module docs).
            for ((q, at), m) in st
                .q_prev
                .iter_mut()
                .zip(st.q_prev_at.iter_mut())
                .zip(acc.out.motors())
            {
                if holds_position(m) {
                    *q = m.q;
                    *at = now;
                }
            }
            st.holding = false;
            st.hold_exceeded = false;
            self.stats.joint_hold_age_ns = 0;
        }
        if self.observe {
            self.stats.passed = self.stats.passed.saturating_add(1);
            let would_have = if acc.reasons.is_empty() {
                None
            } else {
                self.stats.would_have = self.stats.would_have.saturating_add(1);
                Some(JointWouldHave::Limited {
                    cmd: limited,
                    reasons: acc.reasons,
                })
            };
            return JointVerdict::Passed {
                cmd: *cmd,
                would_have,
            };
        }
        if acc.reasons.is_empty() {
            self.stats.passed = self.stats.passed.saturating_add(1);
            JointVerdict::Passed {
                cmd: *cmd,
                would_have: None,
            }
        } else {
            self.stats.limited = self.stats.limited.saturating_add(1);
            JointVerdict::Limited {
                cmd: limited,
                reasons: acc.reasons,
            }
        }
    }

    /// The substitute for a rejected / faulted frame on joint channel `j`
    /// (see the module docs), and the channel state it implies. A humanoid
    /// channel only ever holds (or emits nothing): this is enforced here
    /// regardless of the configuration. Nothing is emitted while the last
    /// emission on the channel is younger than its `min_interval_ns`.
    fn emit_substitute(&mut self, cmd: &JointCommand, now: u64, j: usize, why: SubFor) -> Emitted {
        let none = Emitted {
            sub: None,
            exceeded: None,
        };
        let (Some(ch), Some(st)) = (self.policy.joint_channels.get(j), self.jchans.get(j)) else {
            return none;
        };
        // A flood of rejected frames must not become a flood of substitutes.
        // (Under a clock regression the age cannot be measured: allowed.)
        if st
            .last_emit_at
            .and_then(|at| now.checked_sub(at))
            .is_some_and(|age| age < ch.min_interval_ns)
        {
            return none;
        }
        let platform = &self.policy.platform;
        let max_hold = match platform.fail_behaviour {
            FailBehaviour::HoldLast { max_hold_ns } => Some(max_hold_ns),
            _ => None,
        };
        // `Some((frame, age))` = hold, `None` = damp.
        let held = st.accepted.map(|(f, at)| (f, now.saturating_sub(at)));
        let choice: Option<(JointFrame, u64)> = if ch.humanoid {
            match held {
                Some(h) => Some(h),
                None => return none,
            }
        } else {
            match why {
                SubFor::Fault => match (platform.fault_policy, held) {
                    (FaultPolicy::FailHold, Some(h)) => Some(h),
                    _ => None,
                },
                SubFor::Reject { allow_hold } => match (platform.fail_behaviour, st.accepted) {
                    (FailBehaviour::HoldLast { max_hold_ns }, Some((f, at)))
                        if allow_hold
                            && now.checked_sub(at).is_some_and(|age| age <= max_hold_ns) =>
                    {
                        Some((f, now.saturating_sub(at)))
                    }
                    _ => None,
                },
            }
        };
        let humanoid = ch.humanoid;
        let (kind, frame, exceeded) = match choice {
            Some((f, age)) => {
                // Humanoid past max_hold_ns: keep holding (never limp), but
                // drop the stale feed-forward torque.
                let over = if humanoid {
                    max_hold.filter(|mx| age > *mx).map(|mx| (age, mx))
                } else {
                    None
                };
                (
                    SubstituteKind::HoldLast,
                    hold_frame(&f, over.is_some()),
                    over,
                )
            }
            None => (SubstituteKind::Zero, damping_frame(ch), None),
        };
        let mut report = None;
        if let Some(st) = self.jchans.get_mut(j) {
            st.last_emit_at = Some(now);
            match kind {
                SubstituteKind::HoldLast => {
                    if !st.holding {
                        st.holding = true;
                        self.stats.joint_hold_episodes =
                            self.stats.joint_hold_episodes.saturating_add(1);
                    }
                    self.stats.joint_hold_age_ns = held.map_or(0, |(_, age)| age);
                    if exceeded.is_some() && !st.hold_exceeded {
                        st.hold_exceeded = true;
                        self.stats.joint_holds_exceeded =
                            self.stats.joint_holds_exceeded.saturating_add(1);
                        report = exceeded;
                    }
                }
                SubstituteKind::Zero => {
                    // The motors were released: no target is in force any
                    // more, and any hold episode is over.
                    st.q_prev = [NO_Q; MAX_MOTORS];
                    st.holding = false;
                    st.hold_exceeded = false;
                    self.stats.joint_hold_age_ns = 0;
                }
            }
        }
        Emitted {
            sub: Some(JointSubstitute {
                kind,
                cmd: JointCommand {
                    source: SourceId::FIREWALL,
                    channel: cmd.channel,
                    stamp_ns: now,
                    frame,
                },
            }),
            exceeded: report,
        }
    }

    /// Record the rejection / fault event, then the hold escalation (if
    /// any), for an emitted substitute.
    #[allow(clippy::too_many_arguments)]
    fn record_rejection(
        &mut self,
        cmd: &JointCommand,
        now: u64,
        rule: &'static str,
        sev: Severity,
        emitted: Emitted,
        (value, limit): (f64, f64),
        slot: Option<u8>,
    ) {
        let key = (cmd.channel, cmd.source);
        let action = EventAction::Rejected(emitted.sub.map(|s| s.kind));
        self.record(rule, sev, key, now, action, (value, limit), slot);
        if let Some((age, mx)) = emitted.exceeded {
            self.record(
                rules::JOINT_HOLD_EXCEEDED,
                Severity::Critical,
                key,
                now,
                action,
                (age as f64, mx as f64),
                None,
            );
        }
    }

    fn reject_joint(&mut self, cmd: &JointCommand, now: u64, rej: JRejection) -> JointVerdict {
        let (rule, sev) = reject_rule(rej.reason);
        let key = (cmd.channel, cmd.source);
        if self.observe {
            self.record(
                rule,
                sev,
                key,
                now,
                EventAction::ObservedOnly,
                (rej.value, rej.limit),
                rej.slot,
            );
            self.stats.passed = self.stats.passed.saturating_add(1);
            self.stats.would_have = self.stats.would_have.saturating_add(1);
            return JointVerdict::Passed {
                cmd: *cmd,
                would_have: Some(JointWouldHave::Rejected { reason: rej.reason }),
            };
        }

        let none = Emitted {
            sub: None,
            exceeded: None,
        };
        let j = self.policy.joint_index(cmd.channel);
        let foreign = rej.reason.is_foreign_source();
        let emitted = match j {
            None => none,
            Some(_) if !rej.substitutable => none,
            Some(j) if foreign => {
                let platform = &self.policy.platform;
                let window_open = match self.jchans.get(j).and_then(|s| s.last_foreign_sub_at) {
                    Some(t) => now.saturating_sub(t) >= platform.foreign_substitute_min_interval_ns,
                    None => true,
                };
                match platform.foreign_source_action {
                    ForeignSourceAction::Substitute if window_open => {
                        let e =
                            self.emit_substitute(cmd, now, j, SubFor::Reject { allow_hold: false });
                        if e.sub.is_some() {
                            if let Some(st) = self.jchans.get_mut(j) {
                                st.last_foreign_sub_at = Some(now);
                            }
                        }
                        e
                    }
                    _ => none,
                }
            }
            Some(j) => {
                // Under a clock regression the hold age cannot be measured:
                // non-humanoid platforms damp (a humanoid still holds).
                let allow_hold = rej.reason != RejectReason::ClockRegression;
                self.emit_substitute(cmd, now, j, SubFor::Reject { allow_hold })
            }
        };
        self.record_rejection(
            cmd,
            now,
            rule,
            sev,
            emitted,
            (rej.value, rej.limit),
            rej.slot,
        );
        self.stats.rejected = self.stats.rejected.saturating_add(1);
        JointVerdict::Rejected {
            reason: rej.reason,
            substitute: emitted.sub,
        }
    }

    fn fault_joint(&mut self, cmd: &JointCommand, now: u64) -> JointVerdict {
        self.stats.faults = self.stats.faults.saturating_add(1);
        let (rule, sev) = reject_rule(RejectReason::InternalFault);
        let key = (cmd.channel, cmd.source);
        let j = self.policy.joint_index(cmd.channel);
        let humanoid = j
            .and_then(|j| self.policy.joint_channels.get(j))
            .is_some_and(|ch| ch.humanoid);
        // A humanoid joint channel never forwards an unchecked frame on a
        // fault (compile refuses `FailOpen` there; this holds regardless).
        // Observe mode never enforces anything.
        let fail_open = self.observe
            || (!humanoid && self.policy.platform.fault_policy == FaultPolicy::FailOpen);
        if fail_open {
            self.record(
                rule,
                sev,
                key,
                now,
                EventAction::ObservedOnly,
                (f64::NAN, f64::NAN),
                None,
            );
            self.stats.passed = self.stats.passed.saturating_add(1);
            self.stats.would_have = self.stats.would_have.saturating_add(1);
            return JointVerdict::Passed {
                cmd: *cmd,
                would_have: Some(JointWouldHave::Rejected {
                    reason: RejectReason::InternalFault,
                }),
            };
        }
        let emitted = match j {
            Some(j) => self.emit_substitute(cmd, now, j, SubFor::Fault),
            None => Emitted {
                sub: None,
                exceeded: None,
            },
        };
        self.record_rejection(cmd, now, rule, sev, emitted, (f64::NAN, f64::NAN), None);
        self.stats.rejected = self.stats.rejected.saturating_add(1);
        JointVerdict::Rejected {
            reason: RejectReason::InternalFault,
            substitute: emitted.sub,
        }
    }
}
