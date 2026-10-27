//! Configuration and policy compilation.
//!
//! All string handling, validation and allocation happens here, once, when the
//! policy is compiled. [`Policy::compile`] turns a locked
//! [`robodr_events::profile::Profile`] plus per-channel [`ChannelSpec`]s and a
//! per-platform [`PlatformConfig`] into flat numeric tables the hot path reads.
//!
//! Compilation **fails closed**: any inconsistency (a profile that fails
//! [`Profile::validate`], a profiled motion channel without a spec, a spec for
//! a channel the profile does not know, a negative, NaN or infinite limit, a
//! Twist channel without an angular speed limit, a source GUID that does not
//! belong to a profiled participant, a channel with no allowed source) is a
//! [`ConfigError`], and the gateway must not start forwarding with a policy it
//! could not compile.
//!
//! "Unconstrained" is only ever expressed by **omitting** an optional limit
//! (`None`); an explicit `Some(f64::INFINITY)` is rejected, so a limit cannot
//! be disabled by a malformed number. The angular speed of a Twist channel is
//! the exception: it has no envelope field to fall back on, so it must be
//! spelled out (`max_angular_speed: Some(x)`, `x` finite and >= 0).
//!
//! Low-level joint channels ([`JointChannelSpec`]) are compiled by
//! [`Policy::compile_with_joints`]; their per-motor envelope has no
//! "unconstrained" at all (see `joint_config`). Every configuration type
//! here is also (de)serialisable as JSON ([`crate::FirewallConfig`]).

use crate::command::{ChannelId, SourceId, MAX_JOINTS};
use crate::joint::MAX_MOTORS;
use crate::joint_config::{compile_joint_channel, CompiledJointChannel, JointChannelSpec};
use robodr_events::profile::Profile;
use serde::{Deserialize, Serialize};
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
///
/// On a **low-level joint channel** ([`JointChannelSpec`]) "zero" is the
/// damping frame (every enabled slot `kp = 0`, `dq = 0`, `tau = 0`,
/// `kd = damping_kd`) and "hold" is the last accepted frame with its
/// velocity targets zeroed. A humanoid ([`Morphology::Humanoid`]) falls on a
/// damping frame, so its joint channels refuse `ZeroVelocity` at compile
/// time and always hold (see [`Morphology`]).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FailBehaviour {
    /// Emit an all-zero command of the channel's kind.
    ZeroVelocity,
    /// Re-emit the last **accepted** output on that channel, but only while it
    /// is younger than `max_hold_ns` (measured from when it was accepted, so a
    /// run of consecutive rejections cannot extend it), never more than the
    /// last **emitted** output (scaled down to a deceleration of it; zero if
    /// zero was emitted last), and never under a gateway clock regression;
    /// otherwise, or if nothing was accepted yet, emit zero.
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
/// The right behaviour is a safety-case decision that belongs to the OEM per
/// robot model, so it is exposed as configuration. The **default is
/// [`FaultPolicy::FailSafe`]**: a component that cannot vouch for a command
/// does not forward it. An OEM may choose `FailOpen` where an unexpected stop
/// is the greater hazard (e.g. a vehicle at speed among people with no other
/// stopping logic) — that is a safety-case decision, not ours.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FaultPolicy {
    /// Reject with a zero substitute (never hold: state may be corrupt).
    /// Refused for a humanoid platform with a low-level joint channel.
    #[default]
    FailSafe,
    /// Forward the original command unchanged and record the fault.
    /// Refused for a humanoid platform with a low-level joint channel (and
    /// treated as `FailHold` there by the engine regardless).
    FailOpen,
    /// Reject; on a low-level joint channel re-emit the last **accepted**
    /// frame (velocity targets zeroed), or nothing if none was accepted yet.
    /// That frame passed every check (including the post-condition) when it
    /// was accepted, so holding it cannot put the robot outside its
    /// envelope. Twist / joint-velocity channels get the zero substitute,
    /// exactly as with `FailSafe`. Required for a humanoid with a low-level
    /// joint channel.
    FailHold,
}

/// Body plan of the platform. It decides what a rejection may substitute on
/// a low-level joint channel.
///
/// - **`Humanoid`**: a zero-torque or damping frame makes a standing biped
///   fall. On its low-level joint channels a rejection (and a fault) **never**
///   substitutes zero or damping: it re-emits the last accepted frame
///   (velocity targets zeroed; no hold timeout), or nothing if no frame was
///   accepted yet (the platform keeps its own last command / timeout
///   behaviour). [`Policy::compile_with_joints`] refuses
///   [`FailBehaviour::ZeroVelocity`], [`FaultPolicy::FailSafe`] and
///   [`FaultPolicy::FailOpen`] for a humanoid with a joint channel, and the
///   engine enforces the rule again on its own (a fault always holds). A
///   frame in which every enabled slot is limp is rejected, and enabled
///   slots need non-zero gain minimums (or an explicit `allow_limp`) and a
///   `max_dq_step`. `HoldLast { max_hold_ns }` does not release the hold on
///   a humanoid: past `max_hold_ns` the firewall raises a Critical
///   `joint_hold_exceeded` event (once per hold episode) and zeroes the
///   held frame's feed-forward torque, keeping its gains and position
///   targets (stale feed-forward torque was computed for a posture and
///   phase that no longer holds; stiffness around the last valid target
///   does not depend on them). Escalation (e.g. a controlled stop by the
///   platform's own safety controller) is the responder's job.
/// - **`Quadruped`**, `Wheeled`, `Arm`, `Other`: every [`FailBehaviour`]
///   is allowed. Trade-off on a quadruped joint channel: `ZeroVelocity`
///   (damping frame) lets the robot fold down onto its belly (low height,
///   usually recoverable, but it abandons whatever it was doing, e.g. on
///   stairs); `HoldLast` keeps the last posture stiff for `max_hold_ns`,
///   then damps. An arm under damping sags under gravity: prefer
///   `HoldLast` there too.
///
/// Twist and joint-velocity channels are not affected (their zero is a
/// stop request to the platform's own controller, which keeps balance).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Morphology {
    Humanoid,
    Quadruped,
    Wheeled,
    Arm,
    #[default]
    Other,
}

/// What to do on a known channel when the command comes from a source that is
/// unknown or not allowed on that channel.
///
/// Either way the attempt is recorded as a `rejected_unknown_source` /
/// `rejected_unauthorized_source` deviation (severity Critical). The
/// *response* to a foreign writer on a motion bus — up to asking the safety
/// controller for a safe state, with human approval where the responder's
/// policy requires it — belongs to the responder (`robodr-responder`), not to
/// the in-path firewall: a spoofed packet must not be able to drive the
/// firewall's own output.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ForeignSourceAction {
    /// **Default.** Drop the foreign command and emit nothing: the legitimate
    /// stream keeps control and the spoofer gets no effect on the motion
    /// output. Still recorded as a deviation.
    #[default]
    Drop,
    /// Platform opt-in: emit the [`FailBehaviour`] substitute for a foreign
    /// command. This lets anyone who can write to the bus inject a stop
    /// (denial of service), so it is bounded: at most one foreign-triggered
    /// substitute per channel per
    /// [`PlatformConfig::foreign_substitute_min_interval_ns`] (further foreign
    /// commands in that window are dropped, still recorded). The emitted zero
    /// *is* the channel's previous output (it was sent downstream), so the
    /// legitimate stream then ramps up from it under the acceleration limits:
    /// a spoofer can force at most one stop + ramp-up per interval. Choose
    /// this only where a foreign writer must always mean "stop now".
    Substitute,
}

/// Per-platform settings (one robot model / platform type).
///
/// JSON: every field is optional (defaults below); unknown fields are an
/// error.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct PlatformConfig {
    pub fail_behaviour: FailBehaviour,
    pub fault_policy: FaultPolicy,
    pub foreign_source_action: ForeignSourceAction,
    /// With [`ForeignSourceAction::Substitute`]: minimum gap, on the gateway
    /// clock, between two foreign-triggered substitutes on one channel.
    /// `0` = no bound (every foreign command triggers one). Default 1 s.
    pub foreign_substitute_min_interval_ns: u64,
    /// Capacity of the deviation output buffer (allocated once). Identical
    /// events coalesce; at most half of it may hold events from sources not
    /// authorised on the channel; when full, lower-severity events are
    /// evicted first and the rest dropped and counted until the caller drains
    /// (see [`crate::EventBuffer`]). Each event push scans the buffer once,
    /// so keep this in the hundreds.
    pub event_capacity: usize,
    /// Body plan (default [`Morphology::Other`]). Only changes behaviour on
    /// low-level joint channels; see [`Morphology`].
    pub morphology: Morphology,
}

impl Default for PlatformConfig {
    fn default() -> Self {
        Self {
            fail_behaviour: FailBehaviour::ZeroVelocity,
            fault_policy: FaultPolicy::FailSafe,
            foreign_source_action: ForeignSourceAction::Drop,
            foreign_substitute_min_interval_ns: 1_000_000_000,
            event_capacity: 256,
            morphology: Morphology::Other,
        }
    }
}

/// What a channel carries. (Low-level joint frames have their own spec,
/// [`JointChannelSpec`], and their own entry point,
/// [`crate::Firewall::check_joint`].)
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ChannelKind {
    Twist,
    /// Joint velocities; every command must have exactly `count` joints.
    Joints {
        count: usize,
    },
}

/// Token-bucket rate limit per (channel, source).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RateLimit {
    /// Sustained commands per second (>= 1).
    pub per_second: u32,
    /// Burst size (>= 1).
    pub burst: u32,
}

/// Per-channel limits on top of the profile's envelope. `None` = no extra
/// constraint. Speed fields here can only **tighten** the envelope (the
/// effective limit is the minimum of the two).
///
/// JSON: every field is optional (defaults below); unknown fields are an
/// error.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct ChannelSpec {
    pub kind: ChannelKind,
    /// Sources allowed to command this channel: endpoint GUIDs (24- or
    /// 32-char hex; the first 24 chars must be a participant prefix in the
    /// profile), or `identity:<name>` for a participant identity of the
    /// profile (`Profile::participant_identities`), which survives the
    /// GUID change of a process restart. The gateway resolves a writer to
    /// its identity at run time (see `robodr-ros2-pipeline`'s `identity`).
    pub allowed_sources: Vec<String>,
    /// Tighter linear speed (norm, m/s) than the envelope, if any.
    pub max_linear_speed: Option<f64>,
    /// Angular speed limit (norm, rad/s). The profile envelope has no angular
    /// field, so this is the only source of the angular limit, and it is
    /// **required** for Twist channels ([`ConfigError::MissingLimit`] if
    /// `None`). Ignored for joint channels.
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
    /// A limit is NaN, infinite or negative (or a factor is < 1 / non-finite).
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
    /// A limit that has no safe default is missing (e.g. `max_angular_speed`
    /// on a Twist channel).
    MissingLimit {
        channel: String,
        field: &'static str,
    },
    /// The profile fails [`Profile::validate`] (the errors, joined).
    InvalidProfile(String),
    /// A low-level joint channel's motor table is empty or longer than
    /// [`MAX_MOTORS`].
    InvalidMotorCount {
        channel: String,
        count: usize,
    },
    /// A motor limit is missing (enabled slot), NaN / infinite / negative,
    /// or a range is inverted (`min > max`).
    InvalidMotorLimit {
        channel: String,
        slot: usize,
        field: &'static str,
        why: &'static str,
    },
    /// A joint channel's expected rate / intervals are inconsistent.
    InvalidRate {
        channel: String,
        why: &'static str,
    },
    /// The platform's fail behaviour or fault policy would substitute a
    /// zero / damping frame on a humanoid's low-level joint channel.
    UnsafeSubstitute {
        channel: String,
        why: &'static str,
    },
    /// A channel name has both a [`ChannelSpec`] and a [`JointChannelSpec`].
    DuplicateChannel(String),
    /// The JSON configuration could not be parsed.
    InvalidJson(String),
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
                    "channel {channel}: {field} is NaN, infinite, negative or out of range"
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
            Self::MissingLimit { channel, field } => {
                write!(f, "channel {channel}: {field} is required")
            }
            Self::InvalidProfile(why) => write!(f, "invalid profile: {why}"),
            Self::InvalidMotorCount { channel, count } => write!(
                f,
                "joint channel {channel}: motor slot count {count} not in 1..={MAX_MOTORS}"
            ),
            Self::InvalidMotorLimit {
                channel,
                slot,
                field,
                why,
            } => write!(
                f,
                "joint channel {channel}: motor slot {slot}: {field} {why}"
            ),
            Self::InvalidRate { channel, why } => {
                write!(f, "joint channel {channel}: rate: {why}")
            }
            Self::UnsafeSubstitute { channel, why } => {
                write!(f, "joint channel {channel}: unsafe substitute: {why}")
            }
            Self::DuplicateChannel(c) => write!(
                f,
                "channel {c} has both a channel spec and a joint channel spec"
            ),
            Self::InvalidJson(why) => write!(f, "invalid firewall JSON: {why}"),
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
        bit_allows(&self.allowed, src)
    }
}

/// Test `src` in a per-channel allow-set.
pub(crate) fn bit_allows(allowed: &[u64; MAX_SOURCES / 64], src: SourceId) -> bool {
    let i = usize::from(src.0);
    let word = i / 64;
    let bit = i % 64;
    allowed.get(word).is_some_and(|w| (w >> bit) & 1 == 1)
}

/// The allow-set of a channel from its source list (already validated and
/// interned into `sources`).
fn allowed_bits(
    list: &[String],
    sources: &[String],
) -> Result<[u64; MAX_SOURCES / 64], ConfigError> {
    let mut allowed = [0u64; MAX_SOURCES / 64];
    for g in list {
        let g = normalise_source(g)?;
        if let Ok(idx) = sources.binary_search(&g) {
            if let Some(w) = allowed.get_mut(idx / 64) {
                *w |= 1u64 << (idx % 64);
            }
        }
    }
    Ok(allowed)
}

/// A compiled, validated policy. Build once, hand to [`crate::Firewall::new`].
#[derive(Debug, Clone, PartialEq)]
pub struct Policy {
    pub(crate) model: String,
    pub(crate) enforcing: bool,
    pub(crate) platform: PlatformConfig,
    /// Twist / joint-velocity channels: ids `0..channels.len()`.
    pub(crate) channels: Vec<CompiledChannel>,
    /// Low-level joint channels: ids `channels.len()..` (after the others,
    /// so adding one never renumbers an existing channel).
    pub(crate) joint_channels: Vec<CompiledJointChannel>,
    pub(crate) sources: Vec<String>,
}

pub(crate) fn limit(
    channel: &str,
    field: &'static str,
    v: Option<f64>,
) -> Result<f64, ConfigError> {
    match v {
        None => Ok(f64::INFINITY),
        Some(x) if !x.is_finite() || x < 0.0 => Err(ConfigError::InvalidLimit {
            channel: channel.to_string(),
            field,
        }),
        Some(x) => Ok(x),
    }
}

/// Prefix of an identity source token in [`ChannelSpec::allowed_sources`].
pub const IDENTITY_SOURCE_PREFIX: &str = "identity:";

/// A GUID (lower-cased) or an `identity:<name>` token (name kept as is).
pub(crate) fn normalise_source(g: &str) -> Result<String, ConfigError> {
    let t = g.trim();
    match t.strip_prefix(IDENTITY_SOURCE_PREFIX) {
        Some(name) if robodr_events::profile::is_identity_name(name) => {
            Ok(format!("{IDENTITY_SOURCE_PREFIX}{name}"))
        }
        Some(_) => Err(ConfigError::InvalidGuid(g.to_string())),
        None => normalise_guid(t),
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
    /// `profile.locked`. Equivalent to [`Self::compile_with_joints`] with no
    /// low-level joint channel.
    pub fn compile(
        profile: &Profile,
        platform: PlatformConfig,
        specs: &BTreeMap<String, ChannelSpec>,
    ) -> Result<Policy, ConfigError> {
        Self::compile_with_joints(profile, platform, specs, &BTreeMap::new())
    }

    /// [`Self::compile`] plus low-level joint channels (`joint_specs`, see
    /// [`JointChannelSpec`]). Every profiled motion channel needs exactly one
    /// spec of either kind. Joint channel ids follow the others (lexical
    /// order among themselves), so existing ids never change. Sources are
    /// interned across both maps.
    ///
    /// Fails closed on everything [`Self::compile`] refuses, plus: an empty
    /// or > [`MAX_MOTORS`] motor table, a missing / non-finite / negative
    /// motor limit or an inverted range, an inconsistent rate, a zero
    /// staleness deadline, a missing joint `rate`, a time window over
    /// [`crate::MAX_TIME_WINDOW_NS`], and — for a
    /// [`Morphology::Humanoid`] platform with any joint channel —
    /// [`FailBehaviour::ZeroVelocity`], [`FaultPolicy::FailSafe`] or
    /// [`FaultPolicy::FailOpen`] ([`ConfigError::UnsafeSubstitute`]), an
    /// enabled slot that may go limp without `allow_limp`, or one without
    /// `max_dq_step`.
    pub fn compile_with_joints(
        profile: &Profile,
        platform: PlatformConfig,
        specs: &BTreeMap<String, ChannelSpec>,
        joint_specs: &BTreeMap<String, JointChannelSpec>,
    ) -> Result<Policy, ConfigError> {
        if let Err(errs) = profile.validate() {
            let why = errs
                .iter()
                .map(ToString::to_string)
                .collect::<Vec<_>>()
                .join("; ");
            return Err(ConfigError::InvalidProfile(why));
        }
        if platform.event_capacity == 0 {
            return Err(ConfigError::InvalidPlatform("event_capacity must be >= 1"));
        }
        let total = specs.len().saturating_add(joint_specs.len());
        if total > MAX_CHANNELS {
            return Err(ConfigError::TooManyChannels(total));
        }
        if let Some(dup) = joint_specs.keys().find(|k| specs.contains_key(*k)) {
            return Err(ConfigError::DuplicateChannel(dup.clone()));
        }
        for name in profile.motion_envelopes.keys() {
            if !specs.contains_key(name) && !joint_specs.contains_key(name) {
                return Err(ConfigError::ChannelWithoutSpec(name.clone()));
            }
        }
        if let Some(first) = joint_specs.keys().next() {
            if platform.morphology == Morphology::Humanoid {
                if platform.fail_behaviour == FailBehaviour::ZeroVelocity {
                    return Err(ConfigError::UnsafeSubstitute {
                        channel: first.clone(),
                        why: "a humanoid low-level joint channel cannot use fail_behaviour \
                              zero_velocity: a zero-torque / damping frame makes the robot \
                              fall; use hold_last (a rejection then holds the last valid frame)",
                    });
                }
                // A pass-through platform never enforces, so its faults are
                // always fail-open: no substitute to refuse.
                if platform.fault_policy == FaultPolicy::FailSafe
                    && platform.fail_behaviour != FailBehaviour::PassThroughObserveOnly
                {
                    return Err(ConfigError::UnsafeSubstitute {
                        channel: first.clone(),
                        why: "a humanoid low-level joint channel cannot use fault_policy \
                              fail_safe: its zero-torque / damping substitute makes the robot \
                              fall; use fail_hold (hold the last valid frame)",
                    });
                }
                if platform.fault_policy == FaultPolicy::FailOpen
                    && platform.fail_behaviour != FailBehaviour::PassThroughObserveOnly
                {
                    return Err(ConfigError::UnsafeSubstitute {
                        channel: first.clone(),
                        why: "a humanoid low-level joint channel cannot use fault_policy \
                              fail_open: on a fault it would forward the raw, unchecked frame \
                              (which may be limp or out of envelope) to the motors; use \
                              fail_hold (hold the last valid frame)",
                    });
                }
            }
        }

        // Intern sources first so ids are stable and dense.
        let mut all_sources = BTreeSet::new();
        let source_lists = specs
            .iter()
            .map(|(n, s)| (n, &s.allowed_sources))
            .chain(joint_specs.iter().map(|(n, s)| (n, &s.allowed_sources)));
        for (name, allowed_sources) in source_lists {
            if allowed_sources.is_empty() {
                return Err(ConfigError::NoAllowedSources(name.clone()));
            }
            for g in allowed_sources {
                let g = normalise_source(g)?;
                let known = match g.strip_prefix(IDENTITY_SOURCE_PREFIX) {
                    Some(name) => profile.participant_identities.contains_key(name),
                    None => profile.participants.contains(g.get(..24).unwrap_or("")),
                };
                if !known {
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
            if spec.kind == ChannelKind::Twist && spec.max_angular_speed.is_none() {
                return Err(ConfigError::MissingLimit {
                    channel: name.clone(),
                    field: "max_angular_speed",
                });
            }
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
            let allowed = allowed_bits(&spec.allowed_sources, &sources)?;
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

        let mut joint_channels = Vec::with_capacity(joint_specs.len());
        for (name, spec) in joint_specs {
            let env = profile
                .motion_envelopes
                .get(name)
                .ok_or_else(|| ConfigError::ChannelNotInProfile(name.clone()))?;
            let allowed = allowed_bits(&spec.allowed_sources, &sources)?;
            joint_channels.push(compile_joint_channel(name, spec, env, allowed, &platform)?);
        }

        Ok(Policy {
            model: profile.model.clone(),
            enforcing: profile.locked,
            platform,
            channels,
            joint_channels,
            sources,
        })
    }

    /// Resolve a channel name (configuration time, not per message). Covers
    /// both twist / joint-velocity and low-level joint channels.
    pub fn channel_id(&self, name: &str) -> Option<ChannelId> {
        self.channels
            .iter()
            .map(|c| c.name.as_str())
            .chain(self.joint_channels.iter().map(|c| c.name.as_str()))
            .position(|c| c == name)
            .and_then(|i| u16::try_from(i).ok())
            .map(ChannelId)
    }

    /// `true` if `id` is a low-level joint channel (checked with
    /// [`crate::Firewall::check_joint`], not `check`).
    pub fn is_joint_channel(&self, id: ChannelId) -> bool {
        self.joint_index(id).is_some()
    }

    /// Index into `joint_channels` of a low-level joint channel id.
    pub(crate) fn joint_index(&self, id: ChannelId) -> Option<usize> {
        let j = usize::from(id.0).checked_sub(self.channels.len())?;
        (j < self.joint_channels.len()).then_some(j)
    }

    /// Total number of channels (both kinds).
    pub(crate) fn channel_count(&self) -> usize {
        self.channels
            .len()
            .saturating_add(self.joint_channels.len())
    }

    /// `true` if `src` is allowed on channel `id` (either kind).
    pub(crate) fn allows(&self, id: ChannelId, src: SourceId) -> bool {
        if let Some(c) = self.channels.get(usize::from(id.0)) {
            return c.allows(src);
        }
        self.joint_index(id)
            .and_then(|j| self.joint_channels.get(j))
            .is_some_and(|c| bit_allows(&c.allowed, src))
    }

    /// Resolve an endpoint GUID (configuration / discovery time, not per
    /// message). Case-insensitive. `None` → the gateway passes
    /// [`SourceId::UNKNOWN`].
    pub fn source_id(&self, guid: &str) -> Option<SourceId> {
        let g = normalise_source(guid).ok()?;
        self.sources
            .binary_search(&g)
            .ok()
            .and_then(|i| u16::try_from(i).ok())
            .map(SourceId)
    }

    pub fn channel_name(&self, id: ChannelId) -> Option<&str> {
        match self.channels.get(usize::from(id.0)) {
            Some(c) => Some(c.name.as_str()),
            None => self
                .joint_index(id)
                .and_then(|j| self.joint_channels.get(j))
                .map(|c| c.name.as_str()),
        }
    }

    pub fn source_guid(&self, id: SourceId) -> Option<&str> {
        self.sources.get(usize::from(id.0)).map(String::as_str)
    }

    pub fn model(&self) -> &str {
        &self.model
    }

    /// `true` when this policy can never enforce: the profile is not locked,
    /// or the platform is [`FailBehaviour::PassThroughObserveOnly`]. Events
    /// of such a policy are reported as [`robodr_events::Mode::Observe`].
    pub fn is_observe_only(&self) -> bool {
        !self.enforcing || self.platform.fail_behaviour == FailBehaviour::PassThroughObserveOnly
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
        p.writer_topics.insert("/cmd_vel".into());
        p.motion_envelopes.insert(
            "/cmd_vel".into(),
            Envelope {
                max_linear_speed: Some(1.0),
                max_joint_speed: None,
                ..Default::default()
            },
        );
        p
    }

    fn spec() -> ChannelSpec {
        ChannelSpec {
            allowed_sources: vec![format!("{P}00000103")],
            max_angular_speed: Some(1.0),
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
        assert_eq!(pol.channels[0].limits.ang, 1.0);
        assert_eq!(pol.channels[0].limits.lin_acc, f64::INFINITY);
    }

    #[test]
    fn identity_sources_compile_and_resolve() {
        let mut p = profile();
        p.participant_identities.insert(
            "base".into(),
            robodr_events::profile::ParticipantIdentity {
                ips: ["10.0.0.5".to_owned()].into(),
                vendor: "010f".into(),
                ..Default::default()
            },
        );
        p.participant_identities
            .get_mut("base")
            .unwrap()
            .max_instances = 1;
        let mut s = spec();
        s.allowed_sources.push("identity:base".into());
        let pol = Policy::compile(&p, PlatformConfig::default(), &specs(s.clone())).unwrap();
        let id = pol.source_id("identity:base").unwrap();
        assert!(pol.channels[0].allows(id));
        assert_eq!(pol.source_guid(id), Some("identity:base"));
        // Names are exact (no case folding), unknown / malformed ones refused.
        assert_eq!(pol.source_id("identity:BASE"), None);
        s.allowed_sources = vec!["identity:nope".into()];
        assert!(matches!(
            Policy::compile(&p, PlatformConfig::default(), &specs(s.clone())),
            Err(ConfigError::SourceNotInProfile { .. })
        ));
        s.allowed_sources = vec!["identity:a b".into()];
        assert!(matches!(
            Policy::compile(&p, PlatformConfig::default(), &specs(s)),
            Err(ConfigError::InvalidGuid(_))
        ));
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
            Err(ConfigError::InvalidProfile(_))
        ));
        let bad_pf = PlatformConfig {
            event_capacity: 0,
            ..pf
        };
        assert!(matches!(
            Policy::compile(&profile(), bad_pf, &specs(spec())),
            Err(ConfigError::InvalidPlatform(_))
        ));
        // Infinite limits are rejected (None is the only way to say "none").
        let mut s = spec();
        s.max_linear_accel = Some(f64::INFINITY);
        assert!(matches!(e(s), ConfigError::InvalidLimit { .. }));
        let mut s = spec();
        s.max_angular_speed = Some(f64::INFINITY);
        assert!(matches!(e(s), ConfigError::InvalidLimit { .. }));
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

    #[test]
    fn twist_channel_requires_angular_limit() {
        let mut s = spec();
        s.max_angular_speed = None;
        let e = Policy::compile(&profile(), PlatformConfig::default(), &specs(s.clone()));
        assert_eq!(
            e,
            Err(ConfigError::MissingLimit {
                channel: "/cmd_vel".into(),
                field: "max_angular_speed"
            })
        );
        assert!(e.unwrap_err().to_string().contains("max_angular_speed"));
        // Joint channels have no angular group: not required there.
        let mut p = profile();
        p.writer_topics.insert("/arm".into());
        p.motion_envelopes.insert(
            "/arm".into(),
            Envelope {
                max_linear_speed: None,
                max_joint_speed: Some(1.0),
                ..Default::default()
            },
        );
        let mut all = specs(spec());
        s.kind = ChannelKind::Joints { count: 6 };
        all.insert("/arm".into(), s);
        assert!(Policy::compile(&p, PlatformConfig::default(), &all).is_ok());
    }

    #[test]
    fn invalid_profile_is_rejected() {
        for bad in [f64::INFINITY, f64::NEG_INFINITY, f64::NAN, -1.0] {
            let mut p = profile();
            p.motion_envelopes
                .get_mut("/cmd_vel")
                .unwrap()
                .max_linear_speed = Some(bad);
            assert!(matches!(
                Policy::compile(&p, PlatformConfig::default(), &specs(spec())),
                Err(ConfigError::InvalidProfile(_))
            ));
        }
        let mut p = profile();
        p.model = " ".into();
        let e = Policy::compile(&p, PlatformConfig::default(), &specs(spec())).unwrap_err();
        assert!(matches!(e, ConfigError::InvalidProfile(_)));
        assert!(e.to_string().starts_with("invalid profile"));
    }

    #[test]
    fn defaults_drop_foreign_sources() {
        let pf = PlatformConfig::default();
        assert_eq!(pf.foreign_source_action, ForeignSourceAction::Drop);
        assert_eq!(pf.foreign_substitute_min_interval_ns, 1_000_000_000);
    }

    #[test]
    fn observe_only_policy() {
        let pol = Policy::compile(&profile(), PlatformConfig::default(), &specs(spec())).unwrap();
        assert!(!pol.is_observe_only());
        let pt = PlatformConfig {
            fail_behaviour: FailBehaviour::PassThroughObserveOnly,
            ..PlatformConfig::default()
        };
        assert!(Policy::compile(&profile(), pt, &specs(spec()))
            .unwrap()
            .is_observe_only());
        let mut p = profile();
        p.locked = false;
        assert!(
            Policy::compile(&p, PlatformConfig::default(), &specs(spec()))
                .unwrap()
                .is_observe_only()
        );
    }
}
