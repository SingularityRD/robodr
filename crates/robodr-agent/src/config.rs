//! Agent configuration and errors.
//!
//! [`AgentConfig::validate`] (run by [`crate::Agent::new`]) refuses a
//! configuration that would silently weaken detection: an invalid profile,
//! a platform mismatch, a non-finite or infinite firewall limit, a zero
//! Kafka partition count, or trusted labels that cannot produce a valid
//! finding (probed at start, so a bad label fails once instead of on every
//! finding).
//!
//! Files are parsed with [`strict_from_str`], which rejects unknown fields
//! at any depth. `Profile` and `MonitorConfig` default every missing field,
//! so without it a typo such as `"lockd": true` would silently leave the
//! profile in observe mode, or a misspelt threshold would silently fall
//! back to its default. JSON cannot encode NaN or infinity, and
//! `serde_json` refuses out-of-range numbers such as `1e400`.

use std::collections::BTreeMap;
use std::fmt;

use robodr_blackbox::RecorderConfig;
use robodr_events::profile::{Profile, ProfileError};
use robodr_firewall::{ChannelKind, ChannelSpec, PlatformConfig};
use robodr_motion::{FeedbackSource, MonitorConfig};
use robodr_ocsf::{AttestationStatus, RobotInfo};
use robodr_responder::{OperationalContext, PolicyError, ResponsePolicy};
use serde::de::DeserializeOwned;
use serde::Serialize;

use crate::clock::DEFAULT_CLOCK_JUMP_TOLERANCE_NS;

/// Upper bound on distinct findings whose first-seen time and occurrence
/// count the agent remembers. Beyond it, new findings are reported with
/// `count = 1` (memory stays bounded under a flood of fresh identifiers).
pub const MAX_TRACKED_FINDINGS: usize = 4096;

/// Everything the agent needs. Build with [`AgentConfig::new`] and adjust the
/// optional parts.
#[derive(Debug, Clone)]
pub struct AgentConfig {
    /// Sensor-authored robot identity for the OCSF finding (trusted config:
    /// an invalid robot id is refused at construction).
    pub robot: RobotInfo,
    /// The model profile. `locked` decides observe vs enforce for every
    /// detector (profile, Motion Firewall, motion monitor).
    pub profile: Profile,
    /// Profile version label carried in the finding (`entity_context.profile`).
    /// The profile hash is computed by the agent (see [`profile_sha256`]).
    pub profile_version: String,
    /// Response policy for the Cyber-Jidoka responder (validated on start).
    pub policy: ResponsePolicy,
    /// Operational context reported by the platform. Its `profile_locked`
    /// field is ignored: the agent derives it from `profile.locked` and from
    /// each deviation's mode.
    pub context: OperationalContext,
    /// Black-box recorder configuration (directory, device id, boot id, ...).
    pub blackbox: RecorderConfig,
    /// Optional motion/feedback consistency monitor.
    pub monitor: Option<MonitorSettings>,
    /// Optional Motion Firewall decision core (run on every `MotionCommand`).
    pub firewall: Option<FirewallSettings>,
    /// Attestation status to report in findings (control-plane supplied).
    pub attestation: AttestationStatus,
    /// Kafka partition count of `robot-edr.findings`, if known.
    pub kafka_partitions: Option<u32>,
    /// Record every event in the black box, not only events that produced a
    /// deviation or a non-pass firewall verdict. Off by default: motion
    /// topics run at 50-1000 Hz and would flood the recorder.
    pub record_all_events: bool,
    /// Largest tolerated disagreement between wall-time and monotonic-time
    /// progress between two observations before a
    /// [`crate::FaultKind::WallClockJump`] is recorded. `u64::MAX` disables.
    pub clock_jump_tolerance_ns: u64,
}

impl AgentConfig {
    pub fn new(
        robot: RobotInfo,
        profile: Profile,
        policy: ResponsePolicy,
        context: OperationalContext,
        blackbox: RecorderConfig,
    ) -> Self {
        Self {
            robot,
            profile,
            profile_version: "unversioned".into(),
            policy,
            context,
            blackbox,
            monitor: None,
            firewall: None,
            attestation: AttestationStatus::Unknown,
            kafka_partitions: None,
            record_all_events: false,
            clock_jump_tolerance_ns: DEFAULT_CLOCK_JUMP_TOLERANCE_NS,
        }
    }

    /// Checks that need no I/O (the agent additionally probes a finding and
    /// compiles the firewall and monitor). Called by [`crate::Agent::new`].
    pub fn validate(&self) -> Result<(), AgentError> {
        self.profile.validate().map_err(AgentError::Profile)?;
        if !robodr_ocsf::validate::is_valid_robot_id(&self.robot.id) {
            return Err(AgentError::Config(format!(
                "robot id {:?} must match [A-Za-z0-9._-]{{1,64}}",
                self.robot.id
            )));
        }
        if self.context.platform != self.policy.platform {
            return Err(AgentError::Config(format!(
                "context platform {:?} does not match policy platform {:?}",
                self.context.platform, self.policy.platform
            )));
        }
        if self.kafka_partitions == Some(0) {
            return Err(AgentError::Config(
                "kafka_partitions must be >= 1 (or unset)".into(),
            ));
        }
        if let Some(m) = &self.monitor {
            if let Some(bad) = m
                .feedback_sources
                .keys()
                .find(|k| k.is_empty() || k.chars().any(char::is_control))
            {
                return Err(AgentError::Config(format!(
                    "monitor feedback channel {bad:?} is empty or has control characters"
                )));
            }
        }
        if let Some(fw) = &self.firewall {
            fw.validate().map_err(AgentError::Config)?;
        }
        Ok(())
    }
}

/// Parse `text` as `T`, refusing any object key (at any depth) that `T` does
/// not keep. Works for types whose serialisation writes every field (no
/// `skip_serializing*`), which holds for `Profile` and `MonitorConfig`.
pub fn strict_from_str<T: DeserializeOwned + Serialize>(text: &str) -> Result<T, String> {
    let raw: serde_json::Value = serde_json::from_str(text).map_err(|e| e.to_string())?;
    let parsed: T = serde_json::from_str(text).map_err(|e| e.to_string())?;
    let back = serde_json::to_value(&parsed).map_err(|e| e.to_string())?;
    let mut unknown = Vec::new();
    unknown_keys(&raw, &back, String::new(), &mut unknown);
    if unknown.is_empty() {
        Ok(parsed)
    } else {
        Err(format!("unknown field(s): {}", unknown.join(", ")))
    }
}

fn unknown_keys(
    raw: &serde_json::Value,
    back: &serde_json::Value,
    path: String,
    out: &mut Vec<String>,
) {
    use serde_json::Value;
    match (raw, back) {
        (Value::Object(r), Value::Object(b)) => {
            for (k, v) in r {
                let p = format!("{path}/{k}");
                match b.get(k) {
                    None => out.push(p),
                    Some(bv) => unknown_keys(v, bv, p, out),
                }
            }
        }
        (Value::Array(r), Value::Array(b)) => {
            for (i, (rv, bv)) in r.iter().zip(b).enumerate() {
                unknown_keys(rv, bv, format!("{path}/{i}"), out);
            }
        }
        _ => {}
    }
}

/// Motion monitor settings.
#[derive(Debug, Clone)]
pub struct MonitorSettings {
    pub config: MonitorConfig,
    /// Feedback channel (e.g. `/odom`) to provenance. Channels not listed
    /// use `default_source`.
    pub feedback_sources: BTreeMap<String, FeedbackSource>,
    /// Provenance of unlisted feedback channels. Default `Other`, which the
    /// monitor's default source table does **not** compare against commands
    /// (least trusted); map real channels explicitly.
    pub default_source: FeedbackSource,
}

impl MonitorSettings {
    pub fn new(config: MonitorConfig) -> Self {
        Self {
            config,
            feedback_sources: BTreeMap::new(),
            default_source: FeedbackSource::Other,
        }
    }

    pub(crate) fn source_for(&self, channel: &str) -> FeedbackSource {
        self.feedback_sources
            .get(channel)
            .copied()
            .unwrap_or(self.default_source)
    }
}

/// Motion Firewall settings: per-platform behaviour plus one spec per
/// profiled motion channel (the firewall refuses a policy that misses one).
///
/// The platform defaults are the firewall's: a command from a source not
/// allowed on the channel is dropped (`ForeignSourceAction::Drop`, the
/// spoofer gets no effect on the output, the deviation is still recorded),
/// and `Policy::compile` runs `Profile::validate` on the profile.
#[derive(Debug, Clone)]
pub struct FirewallSettings {
    pub platform: PlatformConfig,
    pub channels: BTreeMap<String, ChannelSpec>,
}

impl FirewallSettings {
    /// One spec per envelope channel of `profile`, with default limits
    /// (the envelope itself, 2x hard-reject factor, 200 ms max age).
    ///
    /// Channel kind: `Twist` if the envelope constrains linear speed,
    /// otherwise `Joints { count: 1 }` (a `MotionCommand` carries only the
    /// max joint speed, see [`crate::agent`]). Allowed sources come from
    /// `allowed[channel]`; a channel without an entry allows **every
    /// participant in the profile** — permissive, meant for demos and
    /// replays. Production must list the real writer GUIDs.
    ///
    /// Angular limit: the profile envelope has no angular field, and the
    /// firewall treats a missing limit as unlimited, so every Twist channel
    /// needs an explicit `max_angular[channel]` (rad/s) from the agent
    /// configuration (the OEM's value; `robodr-replay
    /// --firewall-max-angular CHANNEL=RAD_S`). Fails closed with a
    /// configuration error if one is missing, or if `max_angular` names a
    /// channel that is not a profiled Twist channel (typo protection).
    pub fn from_profile(
        profile: &Profile,
        allowed: &BTreeMap<String, Vec<String>>,
        max_angular: &BTreeMap<String, f64>,
    ) -> Result<Self, AgentError> {
        let mut channels = BTreeMap::new();
        for (name, env) in &profile.motion_envelopes {
            let kind = if env.max_linear_speed.is_some() || env.max_joint_speed.is_none() {
                ChannelKind::Twist
            } else {
                ChannelKind::Joints { count: 1 }
            };
            let allowed_sources = allowed
                .get(name)
                .cloned()
                .unwrap_or_else(|| profile.participants.iter().cloned().collect());
            let max_angular_speed = match kind {
                ChannelKind::Twist => Some(
                    *max_angular
                        .get(name)
                        .ok_or_else(|| AgentError::Config(missing_angular(name)))?,
                ),
                ChannelKind::Joints { .. } => None,
            };
            channels.insert(
                name.clone(),
                ChannelSpec {
                    kind,
                    allowed_sources,
                    max_angular_speed,
                    ..ChannelSpec::default()
                },
            );
        }
        if let Some(extra) = max_angular
            .keys()
            .find(|k| !matches!(channels.get(*k), Some(c) if c.kind == ChannelKind::Twist))
        {
            return Err(AgentError::Config(format!(
                "firewall max_angular_speed given for {extra:?}, which is not a profiled Twist \
                 motion channel"
            )));
        }
        let fs = Self {
            platform: PlatformConfig::default(),
            channels,
        };
        fs.validate().map_err(AgentError::Config)?;
        Ok(fs)
    }

    /// Refuse limits the firewall would accept but that disable protection:
    /// `+inf` (the firewall only refuses NaN and negatives, and treats a
    /// missing limit as unlimited), a non-finite or < 1 hard-reject factor,
    /// and a zero deviation buffer.
    pub fn validate(&self) -> Result<(), String> {
        if self.platform.event_capacity == 0 {
            return Err("firewall event_capacity must be >= 1".into());
        }
        for (name, c) in &self.channels {
            let limits = [
                ("max_linear_speed", c.max_linear_speed),
                ("max_angular_speed", c.max_angular_speed),
                ("max_joint_speed", c.max_joint_speed),
                ("max_linear_accel", c.max_linear_accel),
                ("max_angular_accel", c.max_angular_accel),
                ("max_joint_accel", c.max_joint_accel),
                ("max_linear_jerk", c.max_linear_jerk),
                ("max_angular_jerk", c.max_angular_jerk),
                ("max_joint_jerk", c.max_joint_jerk),
            ];
            for (field, v) in limits {
                if let Some(v) = v {
                    if !v.is_finite() || v < 0.0 {
                        return Err(format!(
                            "firewall channel {name:?}: {field} must be finite and >= 0, got {v}"
                        ));
                    }
                }
            }
            if c.kind == ChannelKind::Twist && c.max_angular_speed.is_none() {
                return Err(missing_angular(name));
            }
            if !c.hard_reject_factor.is_finite() || c.hard_reject_factor < 1.0 {
                return Err(format!(
                    "firewall channel {name:?}: hard_reject_factor must be finite and >= 1, got {}",
                    c.hard_reject_factor
                ));
            }
        }
        Ok(())
    }
}

fn missing_angular(channel: &str) -> String {
    format!(
        "firewall channel {channel:?} is a Twist channel and needs an explicit max_angular_speed \
         (rad/s): the profile envelope has no angular limit and a missing one means unlimited; \
         set the OEM's value in the agent config (robodr-replay: --firewall-max-angular \
         {channel}=RAD_PER_S)"
    )
}

/// SHA-256 (hex) of the profile's canonical JSON (serde_json of the parsed
/// [`Profile`]; its sets and maps are ordered, so the bytes are stable).
/// This is the `entity_context.profile.sha256` of every finding. It is a hash
/// of the profile *as loaded*, not of the file's bytes.
pub fn profile_sha256(profile: &Profile) -> String {
    let bytes = serde_json::to_vec(profile).unwrap_or_default();
    robodr_blackbox::crypto::to_hex(&robodr_blackbox::crypto::sha256(&bytes))
}

/// Why the agent could not start or stop.
#[derive(Debug)]
pub enum AgentError {
    /// The profile failed [`Profile::validate`].
    Profile(Vec<ProfileError>),
    Policy(PolicyError),
    Monitor(robodr_motion::ConfigError),
    Firewall(robodr_firewall::ConfigError),
    BlackBox(robodr_blackbox::Error),
    Config(String),
}

impl fmt::Display for AgentError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            AgentError::Profile(errs) => {
                write!(f, "invalid profile:")?;
                for e in errs {
                    write!(f, " {e};")?;
                }
                Ok(())
            }
            AgentError::Policy(e) => write!(f, "invalid response policy: {e}"),
            AgentError::Monitor(e) => write!(f, "invalid motion monitor config: {e}"),
            AgentError::Firewall(e) => write!(f, "invalid firewall config: {e}"),
            AgentError::BlackBox(e) => write!(f, "black box: {e}"),
            AgentError::Config(m) => write!(f, "invalid agent config: {m}"),
        }
    }
}

impl std::error::Error for AgentError {}

#[cfg(test)]
mod tests {
    use super::*;
    use robodr_events::profile::Envelope;

    #[test]
    fn firewall_settings_follow_profile_envelopes() {
        let mut p = Profile {
            model: "m".into(),
            ..Profile::default()
        };
        p.participants.insert("0102030405060708090a0b0c".into());
        p.writer_topics.insert("/cmd_vel".into());
        p.writer_topics.insert("/arm".into());
        p.motion_envelopes.insert(
            "/cmd_vel".into(),
            Envelope {
                max_linear_speed: Some(0.5),
                max_joint_speed: None,
            },
        );
        p.motion_envelopes.insert(
            "/arm".into(),
            Envelope {
                max_linear_speed: None,
                max_joint_speed: Some(1.0),
            },
        );
        let mut allowed = BTreeMap::new();
        allowed.insert("/arm".to_string(), vec!["aa".to_string()]);
        let angular = BTreeMap::from([("/cmd_vel".to_string(), 0.8)]);
        let fw = FirewallSettings::from_profile(&p, &allowed, &angular).unwrap();
        assert_eq!(fw.channels["/cmd_vel"].kind, ChannelKind::Twist);
        assert_eq!(fw.channels["/cmd_vel"].max_angular_speed, Some(0.8));
        assert_eq!(fw.channels["/arm"].max_angular_speed, None);
        assert_eq!(
            fw.channels["/cmd_vel"].allowed_sources,
            vec!["0102030405060708090a0b0c".to_string()]
        );
        assert_eq!(fw.channels["/arm"].kind, ChannelKind::Joints { count: 1 });
        assert_eq!(fw.channels["/arm"].allowed_sources, vec!["aa".to_string()]);

        // Fail closed: a Twist channel without an angular bound.
        let e = FirewallSettings::from_profile(&p, &allowed, &BTreeMap::new()).unwrap_err();
        assert!(e.to_string().contains("max_angular_speed"), "{e}");
        assert!(e.to_string().contains("/cmd_vel"), "{e}");
        // A bound for a joint channel or an unknown channel is a typo.
        for bad in ["/arm", "/cmd_vell"] {
            let mut a = angular.clone();
            a.insert(bad.to_string(), 1.0);
            let e = FirewallSettings::from_profile(&p, &allowed, &a).unwrap_err();
            assert!(e.to_string().contains(bad), "{e}");
        }
        // Non-finite / negative bounds are refused.
        for v in [f64::NAN, f64::INFINITY, -1.0] {
            let a = BTreeMap::from([("/cmd_vel".to_string(), v)]);
            assert!(FirewallSettings::from_profile(&p, &allowed, &a).is_err());
        }
        // validate() also catches a hand-built Twist spec without one.
        let mut fw = fw;
        fw.channels.get_mut("/cmd_vel").unwrap().max_angular_speed = None;
        assert!(fw.validate().unwrap_err().contains("max_angular_speed"));
    }

    #[test]
    fn profile_hash_is_stable_and_sensitive() {
        let a = Profile {
            model: "m".into(),
            ..Profile::default()
        };
        let mut b = a.clone();
        assert_eq!(profile_sha256(&a), profile_sha256(&b));
        assert_eq!(profile_sha256(&a).len(), 64);
        b.locked = true;
        assert_ne!(profile_sha256(&a), profile_sha256(&b));
    }
}
