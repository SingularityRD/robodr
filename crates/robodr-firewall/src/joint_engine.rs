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
//! | 6 | values | any NaN / ±inf in any slot | Reject `NonFinite` | yes |
//! | 7 | time | future / stale (`max_age_ns`) / out of order | Reject `FutureTimestamp` / `Stale` / `OutOfOrder` | yes |
//! | 8 | slots | unused slot energised | Reject `DisabledMotorEnergised` | yes |
//! | 8 | slots | gain < min (disabled motor = zero gains), or > `f`× max | Reject `JointGainOutOfEnvelope` | yes |
//! | 8 | slots | `\|tau\|` > `f·tau_max` | Reject `JointTorqueOutOfEnvelope` | yes |
//! | 8 | slots | `kd > 0` and `\|dq\|` > `f·dq_max` | Reject `JointVelocityOutOfEnvelope` | yes |
//! | 8 | slots | `kp > 0` and `q` beyond the range by > `(f−1)·width` | Reject `JointPositionOutOfEnvelope` | yes |
//! | 9 | clamp | gain > max, `\|tau\|` > max, `\|dq\|` > max, `q` outside range | Limit (clamp the field) | — |
//! | 10 | post | output not finite / outside the envelope (a bug) | per [`crate::FaultPolicy`] | — |
//! | — | gap | accepted `> max_interval` after the previous one | event `joint_rate_violation` only | — |
//!
//! Slots are scanned in order; within a slot the order is the row order
//! above. A target only constrains while its gain acts: `q` is not checked
//! when `kp == 0`, `dq` not when `kd == 0` (the Unitree SDK parks idle slots
//! at `PosStopF` / `VelStopF` with zero gains).
//!
//! Clamping only ever **lowers** a magnitude (`dq`, `tau`, `kp`, `kd`) or
//! projects `q` onto its range; it never raises a gain (a gain below its
//! minimum is a rejection), so the output is never stiffer, faster or
//! stronger than the input.
//!
//! ## Substitutes
//! - **Humanoid** platform: the last accepted frame with `dq := 0` on every
//!   slot (`HoldLast`), whatever the reason (also under a clock regression
//!   or a fault, and with no hold timeout), or **nothing** if no frame was
//!   accepted yet. Never a zero / damping frame.
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
use crate::joint::{JointCommand, JointFrame, MotorCmd, MotorMode};
use crate::joint_config::{CompiledJointChannel, CompiledMotor};
use crate::verdict::{
    JointLimitReasons, JointSubstitute, JointVerdict, JointWouldHave, RejectReason, SubstituteKind,
};
use robodr_events::Severity;

/// Per low-level joint channel state.
#[derive(Debug, Clone, Copy)]
pub(crate) struct JointChanState {
    /// Last accepted (forwarded) frame and when, on the gateway clock. The
    /// base of `HoldLast` and of the interval checks.
    accepted: Option<(JointFrame, u64)>,
    /// When the last foreign-source-triggered substitute was emitted.
    last_foreign_sub_at: Option<u64>,
}

impl JointChanState {
    pub(crate) const INIT: JointChanState = JointChanState {
        accepted: None,
        last_foreign_sub_at: None,
    };
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

/// Is `m` inside the compiled envelope `lim` (post-condition; exact, clamps
/// produce the bound itself)?
fn motor_ok(m: &MotorCmd, lim: &CompiledMotor) -> bool {
    if !m.is_finite() {
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
    kp <= lim.kp_max
        && kd <= lim.kd_max
        && m.tau.abs() <= lim.tau_max
        && (kd == 0.0 || m.dq.abs() <= lim.dq_max)
        && (kp == 0.0 || (lim.q_min <= m.q && m.q <= lim.q_max))
}

fn frame_ok(ch: &CompiledJointChannel, f: &JointFrame) -> bool {
    f.slots() == ch.slots
        && f.motors()
            .iter()
            .zip(ch.motors.iter())
            .all(|(m, l)| motor_ok(m, l))
}

/// The hold substitute: `f` with every velocity target zeroed (a held
/// position target with a non-zero velocity target would keep pushing).
fn hold_frame(f: &JointFrame) -> JointFrame {
    let mut h = *f;
    for m in h.motors_mut() {
        m.dq = 0.0;
    }
    h.crc_ok = Some(true);
    h
}

/// The damping substitute (non-humanoid platforms only): every enabled slot
/// `kp = 0, dq = 0, tau = 0, kd = min(damping_kd, kd_max)`; unused slots off.
fn damping_frame(ch: &CompiledJointChannel) -> JointFrame {
    let mut f = JointFrame::off(ch.slots, Some(true));
    for (m, lim) in f.motors_mut().iter_mut().zip(ch.motors.iter()) {
        *m = if lim.enabled {
            MotorCmd::enabled(0.0, 0.0, 0.0, 0.0, ch.damping_kd.min(lim.kd_max))
        } else {
            MotorCmd::OFF
        };
    }
    f
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
                let ok = self
                    .policy
                    .joint_index(cmd.channel)
                    .and_then(|j| self.policy.joint_channels.get(j))
                    .is_some_and(|ch| frame_ok(ch, &acc.out));
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
    /// [`FaultPolicy`]; a humanoid never gets a damping frame.
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
        let st = self.jchans.get(j).copied().unwrap_or(JointChanState::INIT);
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
        let since = st.accepted.map(|(_, at)| now.saturating_sub(at));
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
        pair_new.last_stamp = Some(cmd.stamp_ns);

        // 8 + 9. Per slot: hard rejections, then clamps.
        let f = ch.hard_factor;
        let mut out = cmd.frame;
        let mut reasons = JointLimitReasons::NONE;
        let (mut position, mut velocity, mut torque, mut gain) =
            (NO_WORST, NO_WORST, NO_WORST, NO_WORST);
        for (i, (m, lim)) in out
            .motors_mut()
            .iter_mut()
            .zip(ch.motors.iter())
            .enumerate()
        {
            let slot = slot_id(i);
            let rej = |reason, value, limit| Err(JRejection::with(reason, value, limit, slot));
            if !lim.enabled {
                if m.energises() {
                    return rej(RejectReason::DisabledMotorEnergised, 1.0, 0.0);
                }
                continue;
            }
            let (kp, kd) = (m.effective_kp(), m.effective_kd());
            if kp < lim.kp_min {
                return rej(RejectReason::JointGainOutOfEnvelope, kp, lim.kp_min);
            }
            if kd < lim.kd_min {
                return rej(RejectReason::JointGainOutOfEnvelope, kd, lim.kd_min);
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

            // Clamps: lower magnitudes / project q; never raise anything.
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
                m.tau = m.tau.clamp(-lim.tau_max, lim.tau_max);
                reasons.insert(JointLimitReasons::TORQUE);
                note(&mut torque, tau, lim.tau_max, slot);
            }
            if kd > 0.0 && dq > lim.dq_max {
                m.dq = m.dq.clamp(-lim.dq_max, lim.dq_max);
                reasons.insert(JointLimitReasons::VELOCITY);
                note(&mut velocity, dq, lim.dq_max, slot);
            }
            if kp > 0.0 && dist > 0.0 {
                m.q = m.q.clamp(lim.q_min, lim.q_max);
                reasons.insert(JointLimitReasons::POSITION);
                note(&mut position, dist, 0.0, slot);
            }
        }

        let gap = match (since, ch.max_interval_ns) {
            (Some(g), Some(mx)) if g > mx => Some((g, mx)),
            _ => None,
        };
        Ok(JAccepted {
            out,
            reasons,
            position,
            velocity,
            torque,
            gain,
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
    /// (see the module docs). A humanoid channel only ever holds (or emits
    /// nothing): this is enforced here regardless of the configuration.
    fn substitute_joint(
        &self,
        cmd: &JointCommand,
        now: u64,
        j: usize,
        why: SubFor,
    ) -> Option<JointSubstitute> {
        let ch = self.policy.joint_channels.get(j)?;
        let st = self.jchans.get(j)?;
        let held = st.accepted.map(|(f, at)| (hold_frame(&f), at));
        let platform = &self.policy.platform;
        let hold = |f: JointFrame| (SubstituteKind::HoldLast, f);
        let damp = || (SubstituteKind::Zero, damping_frame(ch));
        let (kind, frame) = if ch.humanoid {
            hold(held?.0)
        } else {
            match why {
                SubFor::Fault => match (platform.fault_policy, held) {
                    (FaultPolicy::FailHold, Some((f, _))) => hold(f),
                    _ => damp(),
                },
                SubFor::Reject { allow_hold } => match (platform.fail_behaviour, held) {
                    (FailBehaviour::HoldLast { max_hold_ns }, Some((f, at)))
                        if allow_hold
                            && now.checked_sub(at).is_some_and(|age| age <= max_hold_ns) =>
                    {
                        hold(f)
                    }
                    _ => damp(),
                },
            }
        };
        Some(JointSubstitute {
            kind,
            cmd: JointCommand {
                source: SourceId::FIREWALL,
                channel: cmd.channel,
                stamp_ns: now,
                frame,
            },
        })
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

        let j = self.policy.joint_index(cmd.channel);
        let foreign = rej.reason.is_foreign_source();
        let sub = match j {
            None => None,
            Some(_) if !rej.substitutable => None,
            Some(j) if foreign => {
                let platform = &self.policy.platform;
                let window_open = match self.jchans.get(j).and_then(|s| s.last_foreign_sub_at) {
                    Some(t) => now.saturating_sub(t) >= platform.foreign_substitute_min_interval_ns,
                    None => true,
                };
                match platform.foreign_source_action {
                    ForeignSourceAction::Substitute if window_open => {
                        let s = self.substitute_joint(
                            cmd,
                            now,
                            j,
                            SubFor::Reject { allow_hold: false },
                        );
                        if s.is_some() {
                            if let Some(st) = self.jchans.get_mut(j) {
                                st.last_foreign_sub_at = Some(now);
                            }
                        }
                        s
                    }
                    _ => None,
                }
            }
            Some(j) => {
                // Under a clock regression the hold age cannot be measured:
                // non-humanoid platforms damp (a humanoid still holds).
                let allow_hold = rej.reason != RejectReason::ClockRegression;
                self.substitute_joint(cmd, now, j, SubFor::Reject { allow_hold })
            }
        };
        self.record(
            rule,
            sev,
            key,
            now,
            EventAction::Rejected(sub.map(|s| s.kind)),
            (rej.value, rej.limit),
            rej.slot,
        );
        self.stats.rejected = self.stats.rejected.saturating_add(1);
        JointVerdict::Rejected {
            reason: rej.reason,
            substitute: sub,
        }
    }

    fn fault_joint(&mut self, cmd: &JointCommand, now: u64) -> JointVerdict {
        self.stats.faults = self.stats.faults.saturating_add(1);
        let (rule, sev) = reject_rule(RejectReason::InternalFault);
        let key = (cmd.channel, cmd.source);
        let fail_open = self.observe || self.policy.platform.fault_policy == FaultPolicy::FailOpen;
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
        let sub = self
            .policy
            .joint_index(cmd.channel)
            .and_then(|j| self.substitute_joint(cmd, now, j, SubFor::Fault));
        self.record(
            rule,
            sev,
            key,
            now,
            EventAction::Rejected(sub.map(|s| s.kind)),
            (f64::NAN, f64::NAN),
            None,
        );
        self.stats.rejected = self.stats.rejected.saturating_add(1);
        JointVerdict::Rejected {
            reason: RejectReason::InternalFault,
            substitute: sub,
        }
    }
}
