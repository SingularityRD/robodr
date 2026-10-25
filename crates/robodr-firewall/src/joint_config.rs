//! Low-level joint channel configuration ([`JointChannelSpec`]) and the JSON
//! firewall configuration file ([`FirewallConfig`]).
//!
//! A joint channel carries [`crate::JointFrame`]s (Unitree `LowCmd` style).
//! Its envelope is **per motor slot**: position range, velocity and torque
//! bounds, gain ranges and whether the slot may be energised at all. Like
//! the rest of the policy it is validated once, at compile time, and fails
//! closed: there is no "unconstrained" motor — every limit of an enabled
//! slot must be given, finite and non-negative, and every range ordered.
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
//!           "kp_min": 0.0, "kp_max": 300.0, "kd_min": 0.5, "kd_max": 10.0 }
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

/// Envelope of one motor slot.
///
/// `enabled: false` (the default) marks an unused / locked-out slot: a frame
/// that **energises** it (mode enabled with a non-zero `kp`, `kd` or `tau`)
/// is rejected. For an enabled slot every bound except the gain minimums is
/// **required** (`None` is a [`ConfigError::InvalidMotorLimit`], not
/// "unconstrained").
///
/// Gain minimums: a commanded gain below `kp_min` / `kd_min` (a disabled
/// motor counts as zero gains) is **rejected**, never raised. Set them above
/// zero on a humanoid so that a limp frame (all gains zero, or motors
/// switched off) from a compromised source is refused and the last valid
/// frame held, instead of being forwarded.
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
}

impl MotorLimits {
    /// An unused slot (must never be energised).
    pub fn disabled() -> Self {
        Self::default()
    }

    /// An enabled slot with the given bounds and gain minimums of zero.
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
        }
    }
}

/// Expected frame rate of a joint channel, on the gateway clock.
///
/// - A frame arriving less than `min_interval_ns` after the last **accepted**
///   frame on the channel is rejected (`RateLimited`) and **nothing** is
///   substituted (the previous frame, sent less than an interval ago, is
///   still in force; a flood must not turn into a flood of substitutes).
/// - A frame accepted more than `max_interval_ns` after the previous accepted
///   one is still evaluated normally (refusing a late frame would only make
///   the gap worse) and a `joint_rate_violation` event records the gap.
///
/// Requires `0 <= min_interval_ns <= 1e9/expected_hz <= max_interval_ns`.
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
    /// Expected rate and interval window (`None` = not checked).
    pub rate: Option<JointRate>,
    /// Staleness deadline: oldest acceptable frame (now − stamp), ns. Must
    /// be > 0. Default 20 ms.
    pub max_age_ns: u64,
    /// Furthest-future acceptable frame (stamp − now), ns. Default 2 ms.
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
    /// 0 = no minimum interval.
    pub min_interval_ns: u64,
    pub max_interval_ns: Option<u64>,
    pub damping_kd: f64,
    /// Platform is a humanoid: never substitute zero / damping.
    pub humanoid: bool,
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

fn compile_motor(
    channel: &str,
    slot: usize,
    m: &MotorLimits,
    env_joint: f64,
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
    let mut motors = [CompiledMotor::default(); MAX_MOTORS];
    for (slot, (dst, m)) in motors.iter_mut().zip(&spec.motors).enumerate() {
        *dst = compile_motor(name, slot, m, env_joint)?;
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
    let rate_err = |why| ConfigError::InvalidRate {
        channel: name.to_string(),
        why,
    };
    let (min_interval_ns, max_interval_ns) = match spec.rate {
        None => (0, None),
        Some(r) => {
            if !(r.expected_hz.is_finite() && r.expected_hz > 0.0) {
                return Err(rate_err("expected_hz must be finite and > 0"));
            }
            let period = NS_PER_S / r.expected_hz;
            if r.max_interval_ns == 0 {
                return Err(rate_err("max_interval_ns must be > 0"));
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
            (r.min_interval_ns, Some(r.max_interval_ns))
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
        humanoid: platform.morphology == Morphology::Humanoid,
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
