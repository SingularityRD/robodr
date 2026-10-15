//! Agent configuration and errors.

use std::collections::BTreeMap;
use std::fmt;

use robodr_blackbox::RecorderConfig;
use robodr_events::profile::{Profile, ProfileError};
use robodr_firewall::{ChannelKind, ChannelSpec, PlatformConfig};
use robodr_motion::{FeedbackSource, MonitorConfig};
use robodr_ocsf::{AttestationStatus, RobotInfo};
use robodr_responder::{OperationalContext, PolicyError, ResponsePolicy};

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
        }
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
    pub fn from_profile(profile: &Profile, allowed: &BTreeMap<String, Vec<String>>) -> Self {
        let channels = profile
            .motion_envelopes
            .iter()
            .map(|(name, env)| {
                let kind = if env.max_linear_speed.is_some() || env.max_joint_speed.is_none() {
                    ChannelKind::Twist
                } else {
                    ChannelKind::Joints { count: 1 }
                };
                let allowed_sources = allowed
                    .get(name)
                    .cloned()
                    .unwrap_or_else(|| profile.participants.iter().cloned().collect());
                (
                    name.clone(),
                    ChannelSpec {
                        kind,
                        allowed_sources,
                        ..ChannelSpec::default()
                    },
                )
            })
            .collect();
        Self {
            platform: PlatformConfig::default(),
            channels,
        }
    }
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
        let fw = FirewallSettings::from_profile(&p, &allowed);
        assert_eq!(fw.channels["/cmd_vel"].kind, ChannelKind::Twist);
        assert_eq!(
            fw.channels["/cmd_vel"].allowed_sources,
            vec!["0102030405060708090a0b0c".to_string()]
        );
        assert_eq!(fw.channels["/arm"].kind, ChannelKind::Joints { count: 1 });
        assert_eq!(fw.channels["/arm"].allowed_sources, vec!["aa".to_string()]);
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
