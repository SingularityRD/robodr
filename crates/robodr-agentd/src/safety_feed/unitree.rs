//! Native Unitree safety-state sources (gap T17): `rt/sportmodestate` /
//! `rt/lf/sportmodestate` (`unitree_go::msg::dds_::SportModeState_`) and
//! `rt/lowstate` / `rt/lf/lowstate` (`unitree_go` or `unitree_hg`
//! `LowState_`), decoded from the captured bus by the [`crate::safety`]
//! feed with the same writer pinning as every other topic source (the
//! commissioned `writers`, the profile and the IP binding).
//!
//! # Sport mode (`unitree_sport`)
//!
//! A sample claims the most conservative of:
//!
//! * `modes[<mode>]`: the sport `mode` code mapped to a claim (`none` lets
//!   the motion level decide). A code the mapping does not list reads
//!   `unknown` (and raises `robot.safety_state.unmapped_value`);
//! * the motion level from `‖velocity‖` (m/s) and `|yaw_speed|` (rad/s)
//!   against `motion` (same thresholds and hysteresis as an Odometry
//!   source); a non-finite value reads `unknown`;
//! * `error_code_nonzero` (default `unknown`) while `error_code` is not 0.
//!
//! The same source can also report the operational context: `phase` and
//! `control` map sport mode codes to a mission phase / control mode (see
//! [`super::context`]).
//!
//! # Low state (`unitree_low`)
//!
//! A sample whose Unitree CRC does not match is **undecodable** (`unknown`,
//! `robot.safety_state.undecodable_sample`): it is corrupt or forged. Else
//! the claim is the motion level from the fastest joint, max `|dq|` over
//! every motor slot on the wire (rad/s), against `moving_above` /
//! `fast_above`; a non-finite `dq` reads `unknown`.
//!
//! # Not verified
//!
//! The layouts are those of `robodr-cdr` (Unitree's IDL, hand-built
//! vectors). The mode codes and thresholds in the shipped example
//! configurations come from Unitree's SDK documentation and must be checked
//! on the robot before they are signed off (sales-readiness B1).

use std::collections::BTreeMap;

use robodr_cdr::unitree::{decode_unitree, UnitreeKind, UnitreeMessage};
use robodr_cdr::Limits;
use robodr_responder::{ControlMode, MissionPhase, SafetyState};
use serde::Deserialize;

use super::context::{lookup, u8_keys, CtxReading, Says};
use crate::safety::{most_conservative, next_level, Claim, Level, MotionThresholds};

/// Default `unitree_low.hysteresis` (rad/s).
pub const DEFAULT_JOINT_HYSTERESIS: f64 = 0.05;

/// `unitree_sport` of a topic source.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SportSection {
    /// Sport `mode` code (decimal) -> claim (`none` or a safety state).
    pub modes: BTreeMap<String, String>,
    /// Body speed thresholds (`moving_above`, `fast_above` m/s;
    /// `angular_moving_above` rad/s of yaw).
    pub motion: MotionThresholds,
    /// The claim while `error_code` is not 0.
    #[serde(default = "default_error_claim")]
    pub error_code_nonzero: String,
    /// Sport `mode` code -> mission phase (operational context).
    #[serde(default)]
    pub phase: BTreeMap<String, MissionPhase>,
    /// Sport `mode` code -> control mode (operational context).
    #[serde(default)]
    pub control: BTreeMap<String, ControlMode>,
}

fn default_error_claim() -> String {
    "unknown".into()
}

/// A validated `unitree_sport`.
#[derive(Debug, Clone, PartialEq)]
pub struct SportSpec {
    pub modes: BTreeMap<u8, Claim>,
    pub motion: MotionThresholds,
    pub on_error: Claim,
    pub phase: BTreeMap<u8, MissionPhase>,
    pub control: BTreeMap<u8, ControlMode>,
}

impl SportSection {
    pub fn resolve(&self, what: &str) -> Result<SportSpec, String> {
        let what = format!("{what}.unitree_sport");
        let mut modes = BTreeMap::new();
        for (code, c) in crate::safety::claims(&format!("{what}.modes"), &self.modes)? {
            let v: u8 = code.parse().map_err(|_| {
                format!(
                    "{what}.modes: key {:?} is not a decimal 0..=255",
                    robodr_ros2_pipeline::sanitize(&code)
                )
            })?;
            if modes.insert(v, c).is_some() {
                return Err(format!("{what}.modes: value {v} listed twice"));
            }
        }
        crate::safety::check_motion(&what, &self.motion)?;
        let on_error = Claim::parse(&self.error_code_nonzero)
            .map_err(|e| format!("{what}.error_code_nonzero: {e}"))?;
        if on_error == Claim::None {
            return Err(format!(
                "{what}.error_code_nonzero must be a safety state (a fault never says nothing)"
            ));
        }
        Ok(SportSpec {
            modes,
            motion: self.motion,
            on_error,
            phase: u8_keys(&format!("{what}.phase"), &self.phase)?,
            control: u8_keys(&format!("{what}.control"), &self.control)?,
        })
    }
}

/// `unitree_low` of a topic source (joint speeds, rad/s).
#[derive(Debug, Clone, Copy, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LowSection {
    /// The fastest joint above this (rad/s) = moving.
    pub moving_above: f64,
    /// The fastest joint above this = moving fast. Default: never fast.
    #[serde(default)]
    pub fast_above: Option<f64>,
    #[serde(default = "default_joint_hysteresis")]
    pub hysteresis: f64,
}

fn default_joint_hysteresis() -> f64 {
    DEFAULT_JOINT_HYSTERESIS
}

impl LowSection {
    pub fn resolve(&self, what: &str) -> Result<MotionThresholds, String> {
        let t = MotionThresholds {
            moving_above: self.moving_above,
            fast_above: self.fast_above,
            // Joint speed only; the "angular" input is always 0.
            angular_moving_above: f64::MAX,
            hysteresis: self.hysteresis,
        };
        crate::safety::check_motion(&format!("{what}.unitree_low"), &t)?;
        Ok(t)
    }
}

/// A decoded Unitree sample.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct Outcome {
    /// `None`: a value the mapping does not list (read as `unknown`).
    pub claim: Option<Claim>,
    pub level: Level,
    pub ctx: CtxReading,
}

fn decode<'p>(
    kind: UnitreeKind,
    payload: &'p [u8],
    limits: &Limits,
) -> Result<UnitreeMessage<'p>, String> {
    decode_unitree(kind, payload, limits)
        .map(|d| d.message)
        .map_err(|e| e.to_string())
}

fn level_state(l: Level) -> SafetyState {
    match l {
        Level::Idle => SafetyState::Idle,
        Level::Slow => SafetyState::MovingSlow,
        Level::Fast => SafetyState::MovingFast,
    }
}

/// Decode a `SportModeState_` sample.
pub fn decode_sport(
    spec: &SportSpec,
    payload: &[u8],
    limits: &Limits,
    prev: Level,
) -> Result<Outcome, String> {
    let UnitreeMessage::GoSportModeState(s) =
        decode(UnitreeKind::GoSportModeState, payload, limits)?
    else {
        return Err("wrong message type".into());
    };
    let ctx = CtxReading {
        control: lookup(&spec.control, &s.mode),
        phase: lookup(&spec.phase, &s.mode),
        connectivity: Says::Nothing,
    };
    let [vx, vy, vz] = s.velocity.map(f64::from);
    let speed = (vx * vx + vy * vy + vz * vz).sqrt();
    let yaw = f64::from(s.yaw_speed).abs();
    if !(speed.is_finite() && yaw.is_finite()) {
        return Ok(Outcome {
            claim: Some(Claim::State(SafetyState::Unknown)),
            level: prev,
            ctx,
        });
    }
    let level = next_level(prev, speed, yaw, &spec.motion);
    let Some(mode) = spec.modes.get(&s.mode).copied() else {
        return Ok(Outcome {
            claim: None,
            level,
            ctx,
        });
    };
    let mut states = vec![level_state(level)];
    if let Claim::State(m) = mode {
        states.push(m);
    }
    if s.error_code != 0 {
        if let Claim::State(e) = spec.on_error {
            states.push(e);
        }
    }
    let claim = Some(Claim::State(
        most_conservative(states).unwrap_or(SafetyState::Unknown),
    ));
    Ok(Outcome { claim, level, ctx })
}

/// Decode a go / hg `LowState_` sample (`kind`).
pub fn decode_low(
    kind: UnitreeKind,
    t: &MotionThresholds,
    payload: &[u8],
    limits: &Limits,
    prev: Level,
) -> Result<Outcome, String> {
    let m = decode(kind, payload, limits)?;
    if m.crc_ok() != Some(true) {
        return Err(if m.crc_ok().is_none() {
            "wrong message type".into()
        } else {
            "Unitree CRC mismatch (corrupt or forged)".into()
        });
    }
    let dqs: Vec<f32> = match &m {
        UnitreeMessage::GoLowState(s) => s.motor_state.iter().map(|x| x.dq).collect(),
        UnitreeMessage::HgLowState(s) => s.motor_state.iter().map(|x| x.dq).collect(),
        _ => return Err("wrong message type".into()),
    };
    if dqs.iter().any(|v| !v.is_finite()) {
        return Ok(Outcome {
            claim: Some(Claim::State(SafetyState::Unknown)),
            level: prev,
            ctx: CtxReading::default(),
        });
    }
    let fastest = dqs.iter().map(|v| f64::from(v.abs())).fold(0.0, f64::max);
    let level = next_level(prev, fastest, 0.0, t);
    Ok(Outcome {
        claim: Some(Claim::State(level_state(level))),
        level,
        ctx: CtxReading::default(),
    })
}

/// The `LowState_` kinds a `unitree_low` source accepts.
pub fn low_kind(type_name: &str) -> Option<UnitreeKind> {
    match UnitreeKind::from_type_name(type_name)? {
        k @ (UnitreeKind::GoLowState | UnitreeKind::HgLowState) => Some(k),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sport_section_validation() {
        let ok = serde_json::json!({
            "modes": {"0": "none", "7": "safe_state_active"},
            "motion": {"moving_above": 0.05, "fast_above": 1.0},
            "phase": {"5": "parked"}
        });
        let s: SportSection = serde_json::from_value(ok.clone()).unwrap();
        let spec = s.resolve("t").unwrap();
        assert_eq!(spec.on_error, Claim::State(SafetyState::Unknown));
        assert_eq!(spec.phase.get(&5), Some(&MissionPhase::Parked));
        for (k, v) in [
            ("modes", serde_json::json!({})),
            ("modes", serde_json::json!({"x": "idle"})),
            ("modes", serde_json::json!({"256": "idle"})),
            ("modes", serde_json::json!({"1": "flying"})),
            ("error_code_nonzero", serde_json::json!("none")),
            ("phase", serde_json::json!({"a": "parked"})),
            ("motion", serde_json::json!({"moving_above": -1.0})),
        ] {
            let mut bad = ok.clone();
            bad[k] = v;
            let s: Result<SportSection, _> = serde_json::from_value(bad);
            if let Ok(s) = s {
                assert!(s.resolve("t").is_err(), "{k}");
            }
        }
        let low = LowSection {
            moving_above: 0.5,
            fast_above: Some(0.4),
            hysteresis: 0.05,
        };
        assert!(low.resolve("t").is_err(), "fast below moving");
        assert!(low_kind("unitree_go::msg::dds_::LowState_").is_some());
        assert!(low_kind("unitree_hg/msg/LowState").is_some());
        assert!(low_kind("unitree_go::msg::dds_::LowCmd_").is_none());
    }
}
