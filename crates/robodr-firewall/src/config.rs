//! Configuration and policy compilation.
//!
//! All string handling, validation and allocation happens here, once, when the
//! policy is compiled. [`Policy::compile`] turns a locked
//! [`robodr_events::profile::Profile`] plus per-channel [`ChannelSpec`]s and a
//! per-platform [`PlatformConfig`] into flat numeric tables the hot path reads.
//!
//! Compilation **fails closed**: any inconsistency (a profiled motion channel
//! without a spec, a spec for a channel the profile does not know, a negative
//! or NaN limit, a source GUID that does not belong to a profiled participant,
//! a channel with no allowed source) is a [`ConfigError`], and the gateway must
//! not start forwarding with a policy it could not compile.

use crate::command::{ChannelId, SourceId, MAX_JOINTS};
use robodr_events::profile::Profile;
use std::collections::{BTreeMap, BTreeSet};
use std::fmt;

/// Maximum number of distinct allowed sources across all channels.
pub const MAX_SOURCES: usize = 256;
/// Maximum number of channels in one policy.
pub const MAX_CHANNELS: usize = 64;

const NS_PER_S: u64 = 1_000_000_000;

/// What the firewall emits **instead of** a rejected command (per platform).
///
/// The firewall never originates motion: the only things it can emit on its
/// own are a zero command or a bounded repeat of the last command it accepted.
/// The platform's safety PLC / e-stop remains the final authority in all
/// cases; this is a protective layer in front of it, not a replacement.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FailBehaviour {
    /// Emit an all-zero command of the channel's kind.
    ZeroVelocity,
    /// Re-emit the last **accepted** output on that channel, but only while it
    /// is younger than `max_hold_ns` (measured from when it was accepted, so a
    /// run of consecutive rejections cannot extend it); afterwards, or if
    /// nothing was accepted yet, emit zero.
    HoldLast { max_hold_ns: u64 },
    /// Enforcement disabled on this platform even with a locked profile: every
    /// command is forwarded unchanged and the would-have verdict is recorded
    /// (identical to observe mode). Use only where the OEM has not validated
    /// any substitution behaviour. Limiting is disabled too, so that a 1.5x
    /// command is never treated more strictly than a 3x one.
    PassThroughObserveOnly,
}

/// What happens when the firewall **itself** fails (an internal invariant
/// check trips, or the gateway cannot run `check` in time).
///
/// The design document leaves this open ("Hareket Güvenlik Duvarı arızasında
/// varsayılan davranış ne olmalı?") and assigns the decision to the OEM per
/// robot model. It is therefore exposed as configuration. The **default is
/// [`FaultPolicy::FailSafe`]**: a component that cannot vouch for a command
/// does not forward it. An OEM may choose `FailOpen` where an unexpected stop
/// is the greater hazard (e.g. a vehicle at speed among people with no other
/// stopping logic) — that is a safety-case decision, not ours.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum FaultPolicy {
    /// Reject with a zero substitute (never hold: state may be corrupt).
    #[default]
    FailSafe,
    /// Forward the original command unchanged and record the fault.
    FailOpen,
}

/// What to do on a known channel when the command comes from a source that is
/// unknown or not allowed on that channel.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum ForeignSourceAction {
    /// Treat like any other rejection: emit the [`FailBehaviour`] substitute.
    /// Conservative (a foreign writer on a motion bus means compromise), but
    /// it lets a spoofer stop the robot (denial of service).
    #[default]
    Substitute,
    /// Drop the foreign command and emit nothing: the legitimate stream keeps
    /// control, the spoofer gets no effect. Still recorded as a deviation.
    Drop,
}

/// Per-platform settings (one robot model / platform type).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PlatformConfig {
    pub fail_behaviour: FailBehaviour,
    pub fault_policy: FaultPolicy,
    pub foreign_source_action: ForeignSourceAction,
    /// Capacity of the deviation output buffer (allocated once). Events beyond
    /// it are dropped and counted until the caller drains.
    pub event_capacity: usize,
}

impl Default for PlatformConfig {
    fn default() -> Self {
        Self {
            fail_behaviour: FailBehaviour::ZeroVelocity,
            fault_policy: FaultPolicy::FailSafe,
            foreign_source_action: ForeignSourceAction::Substitute,
            event_capacity: 256,
        }
    }
}

/// What a channel carries.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ChannelKind {
    Twist,
    /// Joint velocities; every command must have exactly `count` joints.
    Joints {
        count: usize,
    },
}

/// Token-bucket rate limit per (channel, source).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RateLimit {
    /// Sustained commands per second (>= 1).
    pub per_second: u32,
    /// Burst size (>= 1).
    pub burst: u32,
}

/// Per-channel limits on top of the profile's envelope. `None` = no extra
/// constraint. Speed fields here can only **tighten** the envelope (the
/// effective limit is the minimum of the two).
#[derive(Debug, Clone, PartialEq)]
pub struct ChannelSpec {
    pub kind: ChannelKind,
    /// Endpoint GUIDs (24- or 32-char hex; the first 24 chars must be a
    /// participant prefix in the profile) allowed to command this channel.
    pub allowed_sources: Vec<String>,
    /// Tighter linear speed (norm, m/s) than the envelope, if any.
    pub max_linear_speed: Option<f64>,
    /// Angular speed limit (norm, rad/s). The profile envelope has no angular
    /// field, so this is the only source of the angular limit.
    pub max_angular_speed: Option<f64>,
    /// Tighter per-joint speed than the envelope, if any.
    pub max_joint_speed: Option<f64>,
    /// Acceleration limits (norm m/s², norm rad/s², per joint).
    pub max_linear_accel: Option<f64>,
    pub max_angular_accel: Option<f64>,
    pub max_joint_accel: Option<f64>,
    /// Jerk limits: bound on the growth of the acceleration magnitude between
    /// consecutive outputs (see crate docs for the exact semantics).
    pub max_linear_jerk: Option<f64>,
    pub max_angular_jerk: Option<f64>,
    pub max_joint_jerk: Option<f64>,
    /// Speeds above `hard_reject_factor × limit` are rejected rather than
    /// scaled. Must be finite and >= 1. Default 2.0.
    pub hard_reject_factor: f64,
    /// Oldest acceptable command (now − stamp). Default 200 ms.
    pub max_age_ns: u64,
    /// Furthest-future acceptable command (stamp − now). Default 10 ms.
    pub max_future_ns: u64,
    pub rate_limit: Option<RateLimit>,
    /// Cap on the `dt` used for acceleration/jerk limiting (≈ the nominal
    /// control period). Must be > 0. Default 100 ms.
    pub dynamics_dt_cap_ns: u64,
    /// If nothing was emitted on the channel for this long, assume the robot
    /// is at rest (previous output := zero). Default 500 ms.
    pub state_reset_after_ns: u64,
    /// If `false` (default), commands that only shrink every component toward
    /// zero bypass acceleration/jerk limiting: the firewall never delays a
    /// stop. Set `true` to rate-limit deceleration too.
    pub limit_deceleration: bool,
}

impl Default for ChannelSpec {
    fn default() -> Self {
        Self {
            kind: ChannelKind::Twist,
            allowed_sources: Vec::new(),
            max_linear_speed: None,
            max_angular_speed: None,
            max_joint_speed: None,
            max_linear_accel: None,
            max_angular_accel: None,
            max_joint_accel: None,
            max_linear_jerk: None,
            max_angular_jerk: None,
            max_joint_jerk: None,
            hard_reject_factor: 2.0,
            max_age_ns: 200_000_000,
            max_future_ns: 10_000_000,
            rate_limit: None,
            dynamics_dt_cap_ns: 100_000_000,
            state_reset_after_ns: 500_000_000,
            limit_deceleration: false,
        }
    }
}

/// Why a policy could not be compiled.
#[derive(Debug, Clone, PartialEq)]
pub enum ConfigError {
    TooManyChannels(usize),
    TooManySources(usize),
    /// A spec names a channel with no envelope in the profile.
    ChannelNotInProfile(String),
    /// The profile has an envelope for a channel that has no spec.
    ChannelWithoutSpec(String),
    /// A limit is NaN or negative (or a factor is < 1 / non-finite).
    InvalidLimit {
        channel: String,
        field: &'static str,
    },
    InvalidTiming {
        channel: String,
        field: &'static str,
    },
    InvalidJointCount {
        channel: String,
        count: usize,
    },
    InvalidRateLimit(String),
    NoAllowedSources(String),
    InvalidGuid(String),
    SourceNotInProfile {
        channel: String,
        guid: String,
    },
    InvalidPlatform(&'static str),
}

impl fmt::Display for ConfigError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::TooManyChannels(n) => write!(f, "{n} channels exceed the max of {MAX_CHANNELS}"),
            Self::TooManySources(n) => write!(f, "{n} sources exceed the max of {MAX_SOURCES}"),
            Self::ChannelNotInProfile(c) => {
                write!(f, "channel {c} has a spec but no envelope in the profile")
            }
            Self::ChannelWithoutSpec(c) => {
                write!(f, "profiled motion channel {c} has no firewall spec")
            }
            Self::InvalidLimit { channel, field } => {
                write!(
                    f,
                    "channel {channel}: {field} is NaN, negative or out of range"
                )
            }
            Self::InvalidTiming { channel, field } => {
                write!(f, "channel {channel}: {field} must be > 0")
            }
            Self::InvalidJointCount { channel, count } => write!(
                f,
                "channel {channel}: joint count {count} not in 1..={MAX_JOINTS}"
            ),
            Self::InvalidRateLimit(c) => {
                write!(
                    f,
                    "channel {c}: rate limit needs per_second >= 1 and burst >= 1"
                )
            }
            Self::NoAllowedSources(c) => write!(f, "channel {c} has no allowed source"),
            Self::InvalidGuid(g) => write!(f, "source GUID {g:?} is not 24/32 hex chars"),
            Self::SourceNotInProfile { channel, guid } => write!(
                f,
                "channel {channel}: source {guid} does not belong to a profiled participant"
            ),
            Self::InvalidPlatform(why) => write!(f, "invalid platform config: {why}"),
        }
    }
}

impl std::error::Error for ConfigError {}

/// Effective numeric limits of one channel. `f64::INFINITY` = unconstrained.
#[derive(Debug, Clone, Copy, PartialEq)]
pub(crate) struct Limits {
    pub lin: f64,
    pub ang: f64,
    pub joint: f64,
    pub lin_acc: f64,
    pub ang_acc: f64,
    pub joint_acc: f64,
    pub lin_jerk: f64,
    pub ang_jerk: f64,
    pub joint_jerk: f64,
}

/// A channel after compilation: numbers only.
#[derive(Debug, Clone, PartialEq)]
pub(crate) struct CompiledChannel {
    pub name: String,
    pub kind: ChannelKind,
    pub allowed: [u64; MAX_SOURCES / 64],
    pub limits: Limits,
    pub hard_factor: f64,
    pub max_age_ns: u64,
    pub max_future_ns: u64,
    /// `(cost_ns, capacity_ns)` of the token bucket.
    pub rate: Option<(u64, u64)>,
    pub dt_cap_ns: u64,
    pub reset_after_ns: u64,
    pub limit_deceleration: bool,
}

impl CompiledChannel {
    pub(crate) fn allows(&self, src: SourceId) -> bool {
        let i = usize::from(src.0);
        let word = i / 64;
        let bit = i % 64;
        self.allowed.get(word).is_some_and(|w| (w >> bit) & 1 == 1)
    }
}

/// A compiled, validated policy. Build once, hand to [`crate::Firewall::new`].
#[derive(Debug, Clone, PartialEq)]
pub struct Policy {
    pub(crate) model: String,
    pub(crate) enforcing: bool,
    pub(crate) platform: PlatformConfig,
    pub(crate) channels: Vec<CompiledChannel>,
    pub(crate) sources: Vec<String>,
}

fn limit(channel: &str, field: &'static str, v: Option<f64>) -> Result<f64, ConfigError> {
    match v {
        None => Ok(f64::INFINITY),
        Some(x) if x.is_nan() || x < 0.0 => Err(ConfigError::InvalidLimit {
            channel: channel.to_string(),
            field,
        }),
        Some(x) => Ok(x),
    }
}

fn normalise_guid(g: &str) -> Result<String, ConfigError> {
    let lower = g.trim().to_ascii_lowercase();
    let ok_len = lower.len() == 24 || lower.len() == 32;
    if !ok_len || !lower.bytes().all(|b| b.is_ascii_hexdigit()) {
        return Err(ConfigError::InvalidGuid(g.to_string()));
    }
    Ok(lower)
}

impl Policy {
    /// Compile `profile` + per-channel `specs` + `platform` into a policy.
    ///
    /// Channel ids are assigned in lexical order of channel name; source ids
    /// in lexical order of (lower-cased) GUID. Enforcement is on iff
    /// `profile.locked`.
    pub fn compile(
        profile: &Profile,
        platform: PlatformConfig,
        specs: &BTreeMap<String, ChannelSpec>,
    ) -> Result<Policy, ConfigError> {
        if platform.event_capacity == 0 {
            return Err(ConfigError::InvalidPlatform("event_capacity must be >= 1"));
        }
        if specs.len() > MAX_CHANNELS {
            return Err(ConfigError::TooManyChannels(specs.len()));
        }
        for name in profile.motion_envelopes.keys() {
            if !specs.contains_key(name) {
                return Err(ConfigError::ChannelWithoutSpec(name.clone()));
            }
        }

        // Intern sources first so ids are stable and dense.
        let mut all_sources = BTreeSet::new();
        for (name, spec) in specs {
            if spec.allowed_sources.is_empty() {
                return Err(ConfigError::NoAllowedSources(name.clone()));
            }
            for g in &spec.allowed_sources {
                let g = normalise_guid(g)?;
                let prefix = g.get(..24).unwrap_or("");
                if !profile.participants.contains(prefix) {
                    return Err(ConfigError::SourceNotInProfile {
                        channel: name.clone(),
                        guid: g,
                    });
                }
                all_sources.insert(g);
            }
        }
        if all_sources.len() > MAX_SOURCES {
            return Err(ConfigError::TooManySources(all_sources.len()));
        }
        let sources: Vec<String> = all_sources.into_iter().collect();

        let mut channels = Vec::with_capacity(specs.len());
        for (name, spec) in specs {
            let env = profile
                .motion_envelopes
                .get(name)
                .ok_or_else(|| ConfigError::ChannelNotInProfile(name.clone()))?;
            let env_lin = limit(name, "envelope.max_linear_speed", env.max_linear_speed)?;
            let env_joint = limit(name, "envelope.max_joint_speed", env.max_joint_speed)?;
            let limits = Limits {
                lin: env_lin.min(limit(name, "max_linear_speed", spec.max_linear_speed)?),
                ang: limit(name, "max_angular_speed", spec.max_angular_speed)?,
                joint: env_joint.min(limit(name, "max_joint_speed", spec.max_joint_speed)?),
                lin_acc: limit(name, "max_linear_accel", spec.max_linear_accel)?,
                ang_acc: limit(name, "max_angular_accel", spec.max_angular_accel)?,
                joint_acc: limit(name, "max_joint_accel", spec.max_joint_accel)?,
                lin_jerk: limit(name, "max_linear_jerk", spec.max_linear_jerk)?,
                ang_jerk: limit(name, "max_angular_jerk", spec.max_angular_jerk)?,
                joint_jerk: limit(name, "max_joint_jerk", spec.max_joint_jerk)?,
            };
            if !(spec.hard_reject_factor.is_finite() && spec.hard_reject_factor >= 1.0) {
                return Err(ConfigError::InvalidLimit {
                    channel: name.clone(),
                    field: "hard_reject_factor",
                });
            }
            if let ChannelKind::Joints { count } = spec.kind {
                if count == 0 || count > MAX_JOINTS {
                    return Err(ConfigError::InvalidJointCount {
                        channel: name.clone(),
                        count,
                    });
                }
            }
            if spec.dynamics_dt_cap_ns == 0 {
                return Err(ConfigError::InvalidTiming {
                    channel: name.clone(),
                    field: "dynamics_dt_cap_ns",
                });
            }
            let rate = match spec.rate_limit {
                None => None,
                Some(r) if r.per_second == 0 || r.burst == 0 => {
                    return Err(ConfigError::InvalidRateLimit(name.clone()))
                }
                Some(r) => {
                    let cost = NS_PER_S / u64::from(r.per_second);
                    Some((cost, cost.saturating_mul(u64::from(r.burst))))
                }
            };
            let mut allowed = [0u64; MAX_SOURCES / 64];
            for g in &spec.allowed_sources {
                let g = normalise_guid(g)?;
                if let Ok(idx) = sources.binary_search(&g) {
                    if let Some(w) = allowed.get_mut(idx / 64) {
                        *w |= 1u64 << (idx % 64);
                    }
                }
            }
            channels.push(CompiledChannel {
                name: name.clone(),
                kind: spec.kind,
                allowed,
                limits,
                hard_factor: spec.hard_reject_factor,
                max_age_ns: spec.max_age_ns,
                max_future_ns: spec.max_future_ns,
                rate,
                dt_cap_ns: spec.dynamics_dt_cap_ns,
                reset_after_ns: spec.state_reset_after_ns,
                limit_deceleration: spec.limit_deceleration,
            });
        }

        Ok(Policy {
            model: profile.model.clone(),
            enforcing: profile.locked,
            platform,
            channels,
            sources,
        })
    }

    /// Resolve a channel name (configuration time, not per message).
    pub fn channel_id(&self, name: &str) -> Option<ChannelId> {
        self.channels
            .iter()
            .position(|c| c.name == name)
            .and_then(|i| u16::try_from(i).ok())
            .map(ChannelId)
    }

    /// Resolve an endpoint GUID (configuration / discovery time, not per
    /// message). Case-insensitive. `None` → the gateway passes
    /// [`SourceId::UNKNOWN`].
    pub fn source_id(&self, guid: &str) -> Option<SourceId> {
        let g = normalise_guid(guid).ok()?;
        self.sources
            .binary_search(&g)
            .ok()
            .and_then(|i| u16::try_from(i).ok())
            .map(SourceId)
    }

    pub fn channel_name(&self, id: ChannelId) -> Option<&str> {
        self.channels
            .get(usize::from(id.0))
            .map(|c| c.name.as_str())
    }

    pub fn source_guid(&self, id: SourceId) -> Option<&str> {
        self.sources.get(usize::from(id.0)).map(String::as_str)
    }

    pub fn model(&self) -> &str {
        &self.model
    }

    /// `true` iff the profile is locked (enforcement may still be disabled by
    /// [`FailBehaviour::PassThroughObserveOnly`]).
    pub fn profile_locked(&self) -> bool {
        self.enforcing
    }

    pub fn platform(&self) -> &PlatformConfig {
        &self.platform
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use robodr_events::profile::Envelope;

    const P: &str = "aaaaaaaaaaaaaaaaaaaaaaaa";

    fn profile() -> Profile {
        let mut p = Profile {
            model: "ugv".into(),
            locked: true,
            ..Default::default()
        };
        p.participants.insert(P.into());
        p.motion_envelopes.insert(
            "/cmd_vel".into(),
            Envelope {
                max_linear_speed: Some(1.0),
                max_joint_speed: None,
            },
        );
        p
    }

    fn spec() -> ChannelSpec {
        ChannelSpec {
            allowed_sources: vec![format!("{P}00000103")],
            ..Default::default()
        }
    }

    fn specs(s: ChannelSpec) -> BTreeMap<String, ChannelSpec> {
        BTreeMap::from([("/cmd_vel".to_string(), s)])
    }

    #[test]
    fn compiles_and_interns() {
        let pol = Policy::compile(&profile(), PlatformConfig::default(), &specs(spec())).unwrap();
        assert_eq!(pol.channel_id("/cmd_vel"), Some(ChannelId(0)));
        assert_eq!(pol.channel_id("/other"), None);
        let id = pol
            .source_id(&format!("{}00000103", P.to_uppercase()))
            .unwrap();
        assert_eq!(id, SourceId(0));
        assert_eq!(pol.source_guid(id), Some(format!("{P}00000103").as_str()));
        assert_eq!(pol.source_id("zz"), None);
        assert!(pol.channels[0].allows(id));
        assert!(!pol.channels[0].allows(SourceId(1)));
        assert!(!pol.channels[0].allows(SourceId::UNKNOWN));
        assert_eq!(pol.channels[0].limits.lin, 1.0);
        assert_eq!(pol.channels[0].limits.ang, f64::INFINITY);
    }

    #[test]
    fn spec_tightens_envelope_only() {
        let mut s = spec();
        s.max_linear_speed = Some(5.0);
        let pol =
            Policy::compile(&profile(), PlatformConfig::default(), &specs(s.clone())).unwrap();
        assert_eq!(pol.channels[0].limits.lin, 1.0);
        s.max_linear_speed = Some(0.3);
        let pol = Policy::compile(&profile(), PlatformConfig::default(), &specs(s)).unwrap();
        assert_eq!(pol.channels[0].limits.lin, 0.3);
    }

    #[test]
    fn rejects_bad_configs() {
        let pf = PlatformConfig::default();
        let e = |s: ChannelSpec| Policy::compile(&profile(), pf, &specs(s)).unwrap_err();

        assert!(matches!(
            Policy::compile(&profile(), pf, &BTreeMap::new()),
            Err(ConfigError::ChannelWithoutSpec(_))
        ));
        let mut extra = specs(spec());
        extra.insert("/arm".into(), spec());
        assert!(matches!(
            Policy::compile(&profile(), pf, &extra),
            Err(ConfigError::ChannelNotInProfile(_))
        ));
        assert!(matches!(
            e(ChannelSpec::default()),
            ConfigError::NoAllowedSources(_)
        ));
        let mut s = spec();
        s.max_angular_speed = Some(f64::NAN);
        assert!(matches!(e(s), ConfigError::InvalidLimit { .. }));
        let mut s = spec();
        s.max_linear_accel = Some(-1.0);
        assert!(matches!(e(s), ConfigError::InvalidLimit { .. }));
        let mut s = spec();
        s.hard_reject_factor = 0.5;
        assert!(matches!(e(s), ConfigError::InvalidLimit { .. }));
        let mut s = spec();
        s.hard_reject_factor = f64::INFINITY;
        assert!(matches!(e(s), ConfigError::InvalidLimit { .. }));
        let mut s = spec();
        s.kind = ChannelKind::Joints { count: 0 };
        assert!(matches!(e(s), ConfigError::InvalidJointCount { .. }));
        let mut s = spec();
        s.kind = ChannelKind::Joints {
            count: MAX_JOINTS + 1,
        };
        assert!(matches!(e(s), ConfigError::InvalidJointCount { .. }));
        let mut s = spec();
        s.dynamics_dt_cap_ns = 0;
        assert!(matches!(e(s), ConfigError::InvalidTiming { .. }));
        let mut s = spec();
        s.rate_limit = Some(RateLimit {
            per_second: 0,
            burst: 1,
        });
        assert!(matches!(e(s), ConfigError::InvalidRateLimit(_)));
        let mut s = spec();
        s.allowed_sources = vec!["not-hex".into()];
        assert!(matches!(e(s), ConfigError::InvalidGuid(_)));
        let mut s = spec();
        s.allowed_sources = vec!["bbbbbbbbbbbbbbbbbbbbbbbb".into()];
        assert!(matches!(e(s), ConfigError::SourceNotInProfile { .. }));

        let mut p = profile();
        p.motion_envelopes
            .get_mut("/cmd_vel")
            .unwrap()
            .max_linear_speed = Some(-0.1);
        assert!(matches!(
            Policy::compile(&p, pf, &specs(spec())),
            Err(ConfigError::InvalidLimit { .. })
        ));
        let bad_pf = PlatformConfig {
            event_capacity: 0,
            ..pf
        };
        assert!(matches!(
            Policy::compile(&profile(), bad_pf, &specs(spec())),
            Err(ConfigError::InvalidPlatform(_))
        ));
        // Display is implemented for every variant used above.
        assert!(!e(ChannelSpec::default()).to_string().is_empty());
    }

    #[test]
    fn rate_limit_compiles_to_ns() {
        let mut s = spec();
        s.rate_limit = Some(RateLimit {
            per_second: 50,
            burst: 3,
        });
        let pol = Policy::compile(&profile(), PlatformConfig::default(), &specs(s)).unwrap();
        assert_eq!(pol.channels[0].rate, Some((20_000_000, 60_000_000)));
    }

    #[test]
    fn unlocked_profile_is_not_enforcing() {
        let mut p = profile();
        p.locked = false;
        let pol = Policy::compile(&p, PlatformConfig::default(), &specs(spec())).unwrap();
        assert!(!pol.profile_locked());
    }
}
