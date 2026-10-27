//! Low-level joint channel configuration ([`JointChannelSpec`]) and the JSON
//! firewall configuration file ([`FirewallConfig`]).
//!
//! A joint channel carries [`crate::JointFrame`]s (Unitree `LowCmd` style).
//! Its envelope is **per motor slot**: position range, velocity and torque
//! bounds, gain ranges and whether the slot may be energised at all. Like
//! the rest of the policy it is validated once, at compile time, and fails
//! closed: there is no "unconstrained" motor — every limit of an enabled
//! slot must be given, finite and non-negative, and every range ordered.
//! Every joint channel must declare its `rate` (with a minimum interval > 0:
//! it also bounds how often the firewall emits substitutes), and its
//! staleness / future windows are capped at [`MAX_TIME_WINDOW_NS`].
//!
//! A [`Morphology::Humanoid`] platform adds, per enabled slot: a non-zero
//! `kp_min` or `kd_min` unless the slot says `allow_limp: true`, and a
//! `max_dq_step`.
//!
//! JSON example (one slot shown; see `config/firewall.unitree-*.example.json`):
//!
//! ```json
//! {
//!   "platform": { "morphology": "humanoid",
//!                 "fail_behaviour": { "hold_last": { "max_hold_ns": 200000000 } },
//!                 "fault_policy": "fail_hold" },
//!   "joint_channels": {
//!     "/lowcmd": {
//!       "allowed_sources": ["identity:g1-locomotion"],
//!       "require_crc": true,
//!       "rate": { "expected_hz": 500.0, "min_interval_ns": 1000000, "max_interval_ns": 10000000 },
//!       "max_age_ns": 20000000,
//!       "motors": [
//!         { "name": "left_hip_pitch", "enabled": true,
//!           "q_min": -2.5307, "q_max": 2.8798, "dq_max": 32.0, "tau_max": 88.0,
//!           "kp_min": 10.0, "kp_max": 300.0, "kd_min": 0.5, "kd_max": 10.0,
//!           "max_dq_step": 0.05, "tau_pd_max": 88.0 }
//!       ]
//!     }
//!   }
//! }
//! ```

use crate::config::{
    limit, ChannelSpec, ConfigError, Morphology, PlatformConfig, Policy, MAX_SOURCES,
};
use crate::joint::MAX_MOTORS;
use robodr_events::profile::{Envelope, Profile};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

const NS_PER_S: f64 = 1e9;

/// Upper bound on a joint channel's `max_age_ns` and `max_future_ns`
/// (10 s). A low-level joint frame is meant for the next control tick
/// (milliseconds); a window of seconds is a configuration error (a typo in
/// the unit) and would let a replayed or pre-dated frame through.
pub const MAX_TIME_WINDOW_NS: u64 = 10_000_000_000;

/// Envelope of one motor slot.
///
/// `enabled: false` (the default) marks an unused / locked-out slot: a frame
/// that **energises** it (mode enabled with a non-zero `kp`, `kd` or `tau`)
/// is rejected. For an enabled slot every bound except the gain minimums is
/// **required** (`None` is a [`ConfigError::InvalidMotorLimit`], not
/// "unconstrained").
///
/// Gain minimums: a commanded gain below `kp_min` / `kd_min` (a disabled
/// motor counts as zero gains) is **rejected**, never raised. On a humanoid
/// an enabled slot must have `kp_min > 0` or `kd_min > 0` unless it sets
/// `allow_limp: true` (compile error otherwise): a limp humanoid joint (no
/// stiffness, no damping) under load folds, and a limp leg or waist makes
/// the robot fall, so a frame that would make it limp from a compromised
/// source must be refused (and the last valid frame held), not forwarded.
/// `allow_limp` is an explicit, reviewable opt-out for slots that are
/// genuinely allowed to go slack (e.g. a hand); it does not lift the
/// humanoid run-time rule that a frame in which **every** enabled slot is
/// limp is rejected.
///
/// Step bounds (relative to the previous **accepted** position target of
/// the slot, `q_prev`; the firewall has no measured joint state):
/// - `max_dq_step`: `|q − q_prev| <= max_dq_step` (rad per accepted frame).
///   **Required** on a humanoid's enabled slots, optional elsewhere.
/// - `tau_pd_max`: `kp·|q − q_prev| <= tau_pd_max` (N·m), a bound on the
///   proportional torque the new target asks for over the old one.
///
/// Beyond the bound (but within `hard_reject_factor ×` it) `q` is stepped
/// toward the requested target by the allowed amount (`Limited`); further
/// out the frame is rejected. Only checked while `kp > 0` (like `q`
/// itself). There is no `q_prev` on the first frame, after a damping
/// substitute (the target was released) or after a frame in which the slot
/// held no position (`kp = 0` or mode off): then only the absolute range
/// `[q_min, q_max]` applies.
#[derive(Debug, Clone, PartialEq, Default, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct MotorLimits {
    /// Human label (error messages only), e.g. `"left_hip_pitch"`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    pub enabled: bool,
    /// Position target range, rad (`q_min <= q_max`).
    pub q_min: Option<f64>,
    pub q_max: Option<f64>,
    /// Bound on `|dq|`, rad/s (tightened by the profile envelope's
    /// `max_joint_speed`, if set).
    pub dq_max: Option<f64>,
    /// Bound on `|tau|` (feed-forward torque), N·m.
    pub tau_max: Option<f64>,
    /// Position gain range (`0 <= kp_min <= kp_max`).
    pub kp_min: f64,
    pub kp_max: Option<f64>,
    /// Velocity gain range (`0 <= kd_min <= kd_max`).
    pub kd_min: f64,
    pub kd_max: Option<f64>,
    /// Humanoid only: allow this enabled slot to have `kp_min = kd_min = 0`
    /// (see above). Default `false`.
    pub allow_limp: bool,
    /// Bound on `|q − q_prev|`, rad per accepted frame (finite, > 0).
    pub max_dq_step: Option<f64>,
    /// Bound on `kp·|q − q_prev|`, N·m (finite, > 0).
    pub tau_pd_max: Option<f64>,
}

impl MotorLimits {
    /// An unused slot (must never be energised).
    pub fn disabled() -> Self {
        Self::default()
    }

    /// An enabled slot with the given bounds, gain minimums of zero and no
    /// step bound (a humanoid additionally needs non-zero minimums or
    /// `allow_limp`, and `max_dq_step`).
    pub fn enabled(q: (f64, f64), dq_max: f64, tau_max: f64, kp_max: f64, kd_max: f64) -> Self {
        Self {
            name: None,
            enabled: true,
            q_min: Some(q.0),
            q_max: Some(q.1),
            dq_max: Some(dq_max),
            tau_max: Some(tau_max),
            kp_min: 0.0,
            kp_max: Some(kp_max),
            kd_min: 0.0,
            kd_max: Some(kd_max),
            allow_limp: false,
            max_dq_step: None,
            tau_pd_max: None,
        }
    }
}

/// Expected frame rate of a joint channel, on the gateway clock. Required
/// on every joint channel.
///
/// - A frame arriving less than `min_interval_ns` after the last **accepted**
///   frame on the channel is rejected (`RateLimited`) and **nothing** is
///   substituted (the previous frame, sent less than an interval ago, is
///   still in force; a flood must not turn into a flood of substitutes).
/// - Any other rejection substitutes only if the last **emitted** frame
///   (accepted or substitute) is at least `min_interval_ns` old; otherwise
///   it emits nothing (the previous emission is still in force), so a flood
///   of bad frames yields at most one substitute per interval.
/// - A frame accepted more than `max_interval_ns` after the previous accepted
///   one is still evaluated normally (refusing a late frame would only make
///   the gap worse) and a `joint_rate_violation` event records the gap.
///
/// Requires `0 < min_interval_ns <= 1e9/expected_hz <= max_interval_ns`.
#[derive(Debug, Clone, Copy, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct JointRate {
    pub expected_hz: f64,
    pub min_interval_ns: u64,
    pub max_interval_ns: u64,
}

impl JointRate {
    /// `hz` with a tolerance window of `[period/2, 2·period]`.
    pub fn around(hz: f64) -> Self {
        let period = if hz.is_finite() && hz > 0.0 {
            NS_PER_S / hz
        } else {
            0.0
        };
        Self {
            expected_hz: hz,
            min_interval_ns: (period / 2.0) as u64,
            max_interval_ns: (period * 2.0).ceil() as u64,
        }
    }
}

/// A low-level joint channel (Unitree-style `LowCmd`), checked with
/// [`crate::Firewall::check_joint`]. See the crate README ("Low-level joint
/// frames") for the decision table.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct JointChannelSpec {
    /// Same format and rules as [`ChannelSpec::allowed_sources`].
    pub allowed_sources: Vec<String>,
    /// One entry per motor slot; every frame must carry exactly this many
    /// slots (`1..=MAX_MOTORS`). Unused slots: [`MotorLimits::disabled`].
    pub motors: Vec<MotorLimits>,
    /// Reject frames whose CRC the decoder did not verify as valid
    /// (`crc_ok != Some(true)`). Default `true`. A frame reported invalid
    /// (`Some(false)`) is rejected on every channel.
    pub require_crc: bool,
    /// Expected rate and interval window. **Required** (`None` is a
    /// [`ConfigError::InvalidRate`]): its `min_interval_ns` also bounds how
    /// often the firewall emits substitutes.
    pub rate: Option<JointRate>,
    /// Staleness deadline: oldest acceptable frame (now − stamp), ns. In
    /// `1..=MAX_TIME_WINDOW_NS`. Default 20 ms.
    pub max_age_ns: u64,
    /// Furthest-future acceptable frame (stamp − now), ns. At most
    /// [`MAX_TIME_WINDOW_NS`]. Default 2 ms. An accepted future-stamped
    /// frame advances the out-of-order watermark only up to `now`, so it
    /// cannot lock out the on-time frames that follow it (trade-off: within
    /// that window, a replay of the future-stamped frame is not caught as
    /// out of order; it is still bounded by the step, rate and staleness
    /// checks).
    pub max_future_ns: u64,
    /// A value further outside its bound than this factor is rejected
    /// rather than clamped: `|dq| > f·dq_max`, `|tau| > f·tau_max`,
    /// `kp > f·kp_max`, `kd > f·kd_max`, or `q` outside the range by more
    /// than `(f − 1)·(q_max − q_min)`. Finite, >= 1. Default 2.0.
    pub hard_reject_factor: f64,
    /// `kd` of the damping frame a non-humanoid platform substitutes on
    /// rejection (`FailBehaviour::ZeroVelocity`, or after a `HoldLast`
    /// expires), capped per slot at its `kd_max`. `0` (default) is a
    /// zero-torque frame. Ignored on a humanoid (it never damps).
    pub damping_kd: f64,
    /// If set, every frame must carry exactly this `mode_pr`
    /// ([`crate::JointFrame::mode_pr`]); anything else (including `None`)
    /// is rejected (`JointModePinMismatch`). On the `hg` `LowCmd` (G1 /
    /// H1-2) `mode_pr` switches the ankle joints between parallel and
    /// serial (pitch / roll) control, which changes what the envelope's
    /// ankle `q` bounds mean: pin it to the mode the envelope was written
    /// for. The gateway must pass the decoded octet through.
    pub pinned_mode_pr: Option<u8>,
    /// Same for `mode_machine` ([`crate::JointFrame::mode_machine`], the
    /// robot variant the frame is for).
    pub pinned_mode_machine: Option<u8>,
    /// Humanoid platforms: does this channel drive joints of the balance
    /// loop? Default `true` (`rt/lowcmd`, `rt/arm_sdk`). `false` lifts only
    /// the run-time rule that a frame in which **every** enabled slot is
    /// limp is rejected (stage 10, `joint_limp_frame`), for channels whose
    /// joints are not in the balance loop: a hand released with
    /// `kp = kd = 0` (the SDK's `stopMotors`) does not make the robot fall.
    /// Every other humanoid rule (non-zero gain minimums unless
    /// `allow_limp`, `max_dq_step`, hold-only substitutes) still applies.
    /// The gateway accepts `false` only on its hand codecs.
    pub balance_critical: bool,
}

impl Default for JointChannelSpec {
    fn default() -> Self {
        Self {
            allowed_sources: Vec::new(),
            motors: Vec::new(),
            require_crc: true,
            rate: None,
            max_age_ns: 20_000_000,
            max_future_ns: 2_000_000,
            hard_reject_factor: 2.0,
            damping_kd: 0.0,
            pinned_mode_pr: None,
            pinned_mode_machine: None,
            balance_critical: true,
        }
    }
}

/// One motor slot after compilation. All bounds finite; disabled slots have
/// every bound zero.
#[derive(Debug, Clone, Copy, PartialEq, Default)]
pub(crate) struct CompiledMotor {
    pub enabled: bool,
    pub q_min: f64,
    pub q_max: f64,
    pub dq_max: f64,
    pub tau_max: f64,
    pub kp_min: f64,
    pub kp_max: f64,
    pub kd_min: f64,
    pub kd_max: f64,
    /// Bound on `|q − q_prev|` (rad), if any.
    pub max_dq_step: Option<f64>,
    /// Bound on `kp·|q − q_prev|` (N·m), if any.
    pub tau_pd_max: Option<f64>,
}

/// A low-level joint channel after compilation: numbers only.
#[derive(Debug, Clone, PartialEq)]
pub(crate) struct CompiledJointChannel {
    pub name: String,
    pub allowed: [u64; MAX_SOURCES / 64],
    pub slots: usize,
    pub motors: [CompiledMotor; MAX_MOTORS],
    pub require_crc: bool,
    pub hard_factor: f64,
    pub max_age_ns: u64,
    pub max_future_ns: u64,
    /// Always > 0 (a rate is required).
    pub min_interval_ns: u64,
    pub max_interval_ns: u64,
    pub damping_kd: f64,
    /// Platform is a humanoid: never substitute zero / damping / limp.
    pub humanoid: bool,
    /// Humanoid only: the all-limp frame rule applies (see
    /// [`JointChannelSpec::balance_critical`]).
    pub balance_critical: bool,
    /// At least one slot is enabled in the envelope.
    pub any_enabled: bool,
    pub pinned_mode_pr: Option<u8>,
    pub pinned_mode_machine: Option<u8>,
}

fn motor_err(channel: &str, slot: usize, field: &'static str, why: &'static str) -> ConfigError {
    ConfigError::InvalidMotorLimit {
        channel: channel.to_string(),
        slot,
        field,
        why,
    }
}

/// A finite, non-negative motor bound (`None` → missing).
fn bound(
    channel: &str,
    slot: usize,
    field: &'static str,
    v: Option<f64>,
) -> Result<f64, ConfigError> {
    match v {
        None => Err(motor_err(
            channel,
            slot,
            field,
            "is required for an enabled slot",
        )),
        Some(x) => finite(channel, slot, field, x).and_then(|x| {
            if x < 0.0 {
                Err(motor_err(channel, slot, field, "must be >= 0"))
            } else {
                Ok(x)
            }
        }),
    }
}

fn finite(channel: &str, slot: usize, field: &'static str, x: f64) -> Result<f64, ConfigError> {
    if x.is_finite() {
        Ok(x)
    } else {
        Err(motor_err(channel, slot, field, "must be finite"))
    }
}

/// A finite, strictly positive optional bound.
fn positive(
    channel: &str,
    slot: usize,
    field: &'static str,
    v: Option<f64>,
) -> Result<Option<f64>, ConfigError> {
    match v {
        None => Ok(None),
        Some(x) if !x.is_finite() => Err(motor_err(channel, slot, field, "must be finite")),
        Some(x) if x <= 0.0 => Err(motor_err(channel, slot, field, "must be > 0")),
        Some(x) => Ok(Some(x)),
    }
}

fn compile_motor(
    channel: &str,
    slot: usize,
    m: &MotorLimits,
    env_joint: f64,
    humanoid: bool,
) -> Result<CompiledMotor, ConfigError> {
    // Whatever is given must be well-formed, even on a disabled slot (a
    // typo there is still a typo).
    for (field, v) in [
        ("q_min", m.q_min),
        ("q_max", m.q_max),
        ("dq_max", m.dq_max),
        ("tau_max", m.tau_max),
        ("kp_max", m.kp_max),
        ("kd_max", m.kd_max),
        ("kp_min", Some(m.kp_min)),
        ("kd_min", Some(m.kd_min)),
        ("max_dq_step", m.max_dq_step),
        ("tau_pd_max", m.tau_pd_max),
    ] {
        if let Some(x) = v {
            finite(channel, slot, field, x)?;
        }
    }
    if let (Some(lo), Some(hi)) = (m.q_min, m.q_max) {
        if lo > hi {
            return Err(motor_err(channel, slot, "q_min", "is greater than q_max"));
        }
    }
    let max_dq_step = positive(channel, slot, "max_dq_step", m.max_dq_step)?;
    let tau_pd_max = positive(channel, slot, "tau_pd_max", m.tau_pd_max)?;
    if !m.enabled {
        return Ok(CompiledMotor::default());
    }
    let q_min = finite(
        channel,
        slot,
        "q_min",
        m.q_min
            .ok_or_else(|| motor_err(channel, slot, "q_min", "is required for an enabled slot"))?,
    )?;
    let q_max = finite(
        channel,
        slot,
        "q_max",
        m.q_max
            .ok_or_else(|| motor_err(channel, slot, "q_max", "is required for an enabled slot"))?,
    )?;
    let dq_max = bound(channel, slot, "dq_max", m.dq_max)?.min(env_joint);
    let tau_max = bound(channel, slot, "tau_max", m.tau_max)?;
    let kp_max = bound(channel, slot, "kp_max", m.kp_max)?;
    let kd_max = bound(channel, slot, "kd_max", m.kd_max)?;
    let kp_min = bound(channel, slot, "kp_min", Some(m.kp_min))?;
    let kd_min = bound(channel, slot, "kd_min", Some(m.kd_min))?;
    if kp_min > kp_max {
        return Err(motor_err(channel, slot, "kp_min", "is greater than kp_max"));
    }
    if kd_min > kd_max {
        return Err(motor_err(channel, slot, "kd_min", "is greater than kd_max"));
    }
    if humanoid {
        if kp_min == 0.0 && kd_min == 0.0 && !m.allow_limp {
            return Err(motor_err(
                channel,
                slot,
                "kp_min",
                "and kd_min are both 0 on a humanoid: a frame could make this joint limp \
                 (no stiffness, no damping) and a limp humanoid falls; set a non-zero kp_min \
                 or kd_min, or allow_limp: true if this joint may genuinely go slack",
            ));
        }
        if max_dq_step.is_none() {
            return Err(motor_err(
                channel,
                slot,
                "max_dq_step",
                "is required for an enabled slot on a humanoid",
            ));
        }
    }
    Ok(CompiledMotor {
        enabled: true,
        q_min,
        q_max,
        dq_max,
        tau_max,
        kp_min,
        kp_max,
        kd_min,
        kd_max,
        max_dq_step,
        tau_pd_max,
    })
}

pub(crate) fn compile_joint_channel(
    name: &str,
    spec: &JointChannelSpec,
    env: &Envelope,
    allowed: [u64; MAX_SOURCES / 64],
    platform: &PlatformConfig,
) -> Result<CompiledJointChannel, ConfigError> {
    let count = spec.motors.len();
    if count == 0 || count > MAX_MOTORS {
        return Err(ConfigError::InvalidMotorCount {
            channel: name.to_string(),
            count,
        });
    }
    let env_joint = limit(name, "envelope.max_joint_speed", env.max_joint_speed)?;
    let humanoid = platform.morphology == Morphology::Humanoid;
    let mut motors = [CompiledMotor::default(); MAX_MOTORS];
    for (slot, (dst, m)) in motors.iter_mut().zip(&spec.motors).enumerate() {
        *dst = compile_motor(name, slot, m, env_joint, humanoid)?;
    }
    if !(spec.hard_reject_factor.is_finite() && spec.hard_reject_factor >= 1.0) {
        return Err(ConfigError::InvalidLimit {
            channel: name.to_string(),
            field: "hard_reject_factor",
        });
    }
    if !(spec.damping_kd.is_finite() && spec.damping_kd >= 0.0) {
        return Err(ConfigError::InvalidLimit {
            channel: name.to_string(),
            field: "damping_kd",
        });
    }
    if spec.max_age_ns == 0 {
        return Err(ConfigError::InvalidTiming {
            channel: name.to_string(),
            field: "max_age_ns",
        });
    }
    for (field, v) in [
        ("max_age_ns", spec.max_age_ns),
        ("max_future_ns", spec.max_future_ns),
    ] {
        if v > MAX_TIME_WINDOW_NS {
            return Err(ConfigError::InvalidLimit {
                channel: name.to_string(),
                field,
            });
        }
    }
    let rate_err = |why| ConfigError::InvalidRate {
        channel: name.to_string(),
        why,
    };
    let (min_interval_ns, max_interval_ns) = match spec.rate {
        None => {
            return Err(rate_err(
                "is required on a joint channel (its min_interval_ns also bounds how often \
                 the firewall emits substitutes)",
            ))
        }
        Some(r) => {
            if !(r.expected_hz.is_finite() && r.expected_hz > 0.0) {
                return Err(rate_err("expected_hz must be finite and > 0"));
            }
            let period = NS_PER_S / r.expected_hz;
            if r.min_interval_ns == 0 {
                return Err(rate_err("min_interval_ns must be > 0"));
            }
            if r.min_interval_ns > r.max_interval_ns {
                return Err(rate_err("min_interval_ns is greater than max_interval_ns"));
            }
            if (r.min_interval_ns as f64) > period {
                return Err(rate_err(
                    "min_interval_ns is longer than the expected period (every on-time frame would be refused)",
                ));
            }
            if (r.max_interval_ns as f64) < period {
                return Err(rate_err(
                    "max_interval_ns is shorter than the expected period (every on-time frame would be a violation)",
                ));
            }
            (r.min_interval_ns, r.max_interval_ns)
        }
    };
    Ok(CompiledJointChannel {
        name: name.to_string(),
        allowed,
        slots: count,
        motors,
        require_crc: spec.require_crc,
        hard_factor: spec.hard_reject_factor,
        max_age_ns: spec.max_age_ns,
        max_future_ns: spec.max_future_ns,
        min_interval_ns,
        max_interval_ns,
        damping_kd: spec.damping_kd,
        humanoid,
        balance_critical: spec.balance_critical,
        any_enabled: motors.iter().any(|m| m.enabled),
        pinned_mode_pr: spec.pinned_mode_pr,
        pinned_mode_machine: spec.pinned_mode_machine,
    })
}

/// The firewall's JSON configuration file: platform settings plus the
/// per-channel specs of both kinds. Every section is optional; unknown
/// fields anywhere are an error (typo protection).
///
/// The profile (the locked envelope and participants) is a separate
/// artifact: [`FirewallConfig::compile`] combines the two.
#[derive(Debug, Clone, PartialEq, Default, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct FirewallConfig {
    pub platform: PlatformConfig,
    /// Twist / joint-velocity channels.
    pub channels: BTreeMap<String, ChannelSpec>,
    /// Low-level joint channels.
    pub joint_channels: BTreeMap<String, JointChannelSpec>,
}

impl FirewallConfig {
    /// Parse the JSON configuration (structure only; limits are validated by
    /// [`Self::compile`]). JSON cannot spell NaN or infinity, so those can
    /// only reach the policy through the Rust API, where compile refuses
    /// them.
    pub fn from_json(text: &str) -> Result<Self, ConfigError> {
        serde_json::from_str(text).map_err(|e| ConfigError::InvalidJson(e.to_string()))
    }

    /// [`Policy::compile_with_joints`] of this configuration.
    pub fn compile(&self, profile: &Profile) -> Result<Policy, ConfigError> {
        Policy::compile_with_joints(profile, self.platform, &self.channels, &self.joint_channels)
    }
}
