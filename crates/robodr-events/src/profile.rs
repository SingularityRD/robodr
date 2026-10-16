//! The **model profile**: what a given robot model is allowed to do. It is
//! learned in observe mode during commissioning, then *locked* by the OEM.
//! Once locked, every event is checked against it and any deviation is a
//! signal. Robots are far more predictable than laptops, so an allowlist here
//! is tight enough to be useful rather than noisy.
//!
//! # Matching policy
//!
//! Every discovered endpoint is first de-mangled with
//! [`graph::demangle`](crate::graph::demangle) and matched by its *kind*:
//!
//! | endpoint kind                       | writer allowed if …                                   | rule if not                                   |
//! |-------------------------------------|-------------------------------------------------------|-----------------------------------------------|
//! | topic `rt/x`                        | `/x` ∈ `writer_topics` (and, for a motion topic, the participant ∈ `participants`) | `robot.ros2.unknown_writer_topic` (High) / `robot.ros2.unauthorized_motion_writer` (Critical) |
//! | service `rq/xRequest`, `rr/xReply`  | `/x` ∈ `services`                                     | `robot.ros2.unknown_service` (High)           |
//! | action part of `/a`                 | `/a` ∈ `actions`, or its full topic/service name is listed in `writer_topics`/`services` | `robot.ros2.unknown_action` (High) |
//! | raw DDS topic (no ROS prefix)       | exact name ∈ `raw_dds_topics`                         | `robot.dds.unknown_raw_writer` (High)         |
//!
//! Service **clients write the request topic** and service **servers write the
//! reply topic**, so both sides of a service are writers and both are checked
//! against `services`: an unprofiled client calling a profiled service is not
//! caught by this table (only by the participant check), but a profiled node
//! growing a new service or client is. Action clients/servers likewise write
//! the action's request/reply/feedback/status topics.
//!
//! Readers: a reader from a participant outside `participants` is
//! `robot.ros2.unknown_reader` (Medium) as before. If the optional
//! `reader_topics` allowlist is **non-empty** it is enforced too (exfiltration
//! of camera / map / pose topics by a known-but-compromised node): topics are
//! matched against `reader_topics`, services against `services`, actions
//! against `actions`, raw names against `raw_dds_topics`; a miss is
//! `robot.ros2.unknown_reader_topic` (Medium). Empty `reader_topics` = not
//! enforced (backward compatible).
//!
//! Profile names are always the **de-mangled** ROS names (`/cmd_vel`, not
//! `rt/cmd_vel`). [`Profile::validate`] requires every entry of
//! `writer_topics`, `services`, `actions`, `reader_topics` and every
//! `motion_envelopes` key to be a well-formed fully qualified ROS name
//! ([`graph::validate_full_name`](crate::graph::validate_full_name): leading
//! `/`, no trailing `/`, no `//`, only `[A-Za-z0-9_/]`, no token starting with
//! a digit). This matters for safety, not just tidiness: matching is exact, so
//! an envelope keyed `cmd_vel`, `rt/cmd_vel` or `/cmd_vel/` silently never
//! applies, and a foreign writer on the real `/cmd_vel` would not raise the
//! Critical `unauthorized_motion_writer`. `raw_dds_topics` is exempt from the
//! ROS-name rules (raw DDS names are arbitrary) with two exceptions: empty
//! entries are rejected, and so is an entry that [`demangle`] classifies as a
//! ROS name (`rt/cmd_vel`): it could never match (ROS-prefixed names are
//! checked against the ROS sets) and almost certainly means the author meant
//! the ROS name ([`ProfileError::RawTopicIsRosName`]). A *malformed* prefixed
//! name such as `rt//cmd_vel` is genuinely raw and stays allowed.
//!
//! **Defence in depth for refused profiles.** A profile that fails
//! `validate` is not enforced, but the sensor may still evaluate it in observe
//! mode for visibility. For that case only, the unauthorized-motion check also
//! treats a *malformed* envelope key as naming the ROS topic it obviously
//! means (`cmd_vel`, `rt/cmd_vel`, `/cmd_vel/`, ` /cmd_vel`, `//cmd_vel` ->
//! `/cmd_vel`): a foreign writer on `rt/cmd_vel` is still Critical instead of
//! silent. This lenient reading can only *add* detections; it never makes an
//! endpoint allowed. Well-formed keys are matched exactly as always.
//!
//! **Motion channels must be writable.** Every `motion_envelopes` key must
//! also be allowed for writers by the same rule `evaluate` uses: listed in
//! `writer_topics`, or an action feedback/status topic of an action in
//! `actions`. Otherwise a *legitimate* profiled publisher of the motion topic
//! would raise `robot.ros2.unknown_writer_topic` on every discovery (the
//! unauthorized-motion check only fires for unknown participants; a known
//! participant falls through to the ordinary topic allowlist), so the profile
//! is internally inconsistent and is rejected
//! ([`ProfileError::MotionChannelNotWritable`]).
//!
//! # Motion envelope
//!
//! See the crate docs for the NaN / negative / invalid-limit rules. Checks run
//! in this order and the first hit is returned:
//!
//! 1. non-finite value on **any** axis of the command (forward, joint, yaw,
//!    lateral, vertical, roll, pitch) → `robot.motion.non_finite_command`
//!    (Critical);
//! 2. unprofiled channel → `robot.motion.unprofiled_channel` (High);
//! 3. invalid envelope limit, or a `holonomic` envelope missing a mandatory
//!    limit → `robot.profile.invalid_envelope` (High, profile error);
//! 4. `|linear.x| > max_linear_speed`, then resultant
//!    `‖(linear.x, linear.y, linear.z)‖ > max_linear_speed`,
//!    then `|linear.y| > max_lateral_speed`, then
//!    `|linear.z| > max_vertical_speed` → `robot.motion.linear_over_envelope`
//!    (Critical; the detail names the axis);
//! 5. `‖(angular.x, angular.y)‖ > max_roll_pitch_rate` →
//!    `robot.motion.angular_over_envelope` (Critical);
//! 6. `|joint| > max_joint_speed` → `robot.motion.joint_over_envelope`
//!    (Critical).
//!
//! `None` as a limit means "not constrained"; use `None`, not `+inf`, for
//! that. A command axis that is `None` is not checked by its per-axis limit
//! (it counts as 0 in the resultant).
//!
//! **Holonomic channels.** `linear_speed` is the signed forward component
//! (`linear.x`) on every platform; a mecanum / omni base also moves along
//! `linear.y`. An envelope therefore declares `holonomic`:
//!
//! * `holonomic: false` (the default, and what every profile written before
//!   this field existed is): per-axis limits are optional, `None` = not
//!   constrained per axis. The resultant check still bounds a bogus
//!   `linear.y/z` on a differential-drive base by `max_linear_speed`, so
//!   leaving the extra axes unset cannot open a sideways bypass.
//! * `holonomic: true`: `max_linear_speed`, `max_lateral_speed`,
//!   `max_vertical_speed` and `max_roll_pitch_rate` are **mandatory**. A
//!   missing one is a validation error ([`ProfileError::MissingHolonomicLimit`])
//!   and, should such a profile be evaluated anyway, every command on the
//!   channel is denied as `robot.profile.invalid_envelope`. The asymmetry is
//!   deliberate: declaring a base holonomic is a statement that sideways /
//!   vertical / tilting motion is legitimate, so it must come with an
//!   explicit bound for each (`0.0` for an axis that must not move) instead
//!   of an implicit "unconstrained". `max_joint_speed` stays optional.
//!
//! The envelope has no yaw-rate field: a finite yaw rate is bounded by the
//! Motion Firewall's per-channel `max_angular_speed`, not here.
//!
//! # Artifact metadata ([`ProfileMetadata`])
//!
//! A locked profile is a versioned artifact. `robodr-commission lock`
//! stamps it with [`ProfileMetadata`]: the file-format `schema_version`
//! ([`PROFILE_SCHEMA_VERSION`]), a monotonic `profile_version` (u64, >= 1),
//! the `platform` (and optionally the single `unit_id`) it is for, who
//! locked it (`locked_by`, the sign-off operator) and when (`locked_at`,
//! Unix seconds, UTC), and `parent_digest`, the `sha256:<hex>` of the exact
//! locked file this version supersedes (rollback lineage; `None` for the
//! first version), and optionally `attestation` ([`ProfileAttestation`]:
//! the operator sign-off and its signatures, verified by the loaders in
//! `robodr-commission`). The metadata is optional here (drafts and legacy
//! profiles have none) and [`Profile::validate`] checks it only when
//! present ([`ProfileMetadata::validate`]); whether a locked profile *must*
//! carry it, and the signature and anti-rollback rules built on it, are
//! decided by the loaders in `robodr-commission` (this crate stays pure: no
//! crypto, no I/O). `evaluate` never looks at the metadata.
//!
//! # Limits
//!
//! `evaluate` returns at most one deviation per event and is stateless:
//! rate-of-change, command/feedback consistency and command provenance are
//! the job of `robodr-motion`. Writers from unknown participants on profiled
//! non-motion topics/services are reported only via the participant rule.

use crate::graph::{
    demangle, is_full_name, validate_full_name, ActionRole, Endpoint, Participant, RosName,
    RosNameIssue, RosNameKind,
};
use crate::{Deviation, Mode, MotionCommand, RobotEvent, Severity};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};
use std::fmt;

/// A motion envelope: the limits a command may not exceed. A limit must be
/// finite and `>= 0`; anything else is a profile error (see
/// [`Profile::validate`]).
///
/// `None` means the dimension is not constrained for this channel, **except**
/// on a channel declared `holonomic: true`: there `max_linear_speed`,
/// `max_lateral_speed`, `max_vertical_speed` and `max_roll_pitch_rate` are
/// all mandatory (use `0.0` for an axis the base cannot or must not move
/// along), validation reports a missing one as
/// [`ProfileError::MissingHolonomicLimit`] and `evaluate` reports every
/// command on the channel as `robot.profile.invalid_envelope` (fail closed).
/// See the module docs ("Motion envelope") for the full rule set.
///
/// All fields are `#[serde(default)]`: a profile written before the
/// holonomic fields existed loads unchanged as a non-holonomic envelope.
/// Construct with `..Default::default()`.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct Envelope {
    /// Max allowed linear speed, m/s: bounds `|linear.x|` and the resultant
    /// `‖(x, y, z)‖` of the commanded linear velocity.
    #[serde(default)]
    pub max_linear_speed: Option<f64>,
    /// Max allowed joint speed, rad/s.
    #[serde(default)]
    pub max_joint_speed: Option<f64>,
    /// The channel drives a holonomic (mecanum / omni / 6-DoF) base: every
    /// per-axis limit below, and `max_linear_speed`, must be set.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub holonomic: bool,
    /// Max allowed `|linear.y|` (sideways), m/s.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_lateral_speed: Option<f64>,
    /// Max allowed `|linear.z|` (vertical), m/s.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_vertical_speed: Option<f64>,
    /// Max allowed roll/pitch rate `‖(angular.x, angular.y)‖`, rad/s.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_roll_pitch_rate: Option<f64>,
}

impl Envelope {
    /// Every limit with its field id (for validation and fail-closed checks).
    pub fn limits(&self) -> [(EnvelopeField, Option<f64>); 5] {
        [
            (EnvelopeField::MaxLinearSpeed, self.max_linear_speed),
            (EnvelopeField::MaxJointSpeed, self.max_joint_speed),
            (EnvelopeField::MaxLateralSpeed, self.max_lateral_speed),
            (EnvelopeField::MaxVerticalSpeed, self.max_vertical_speed),
            (EnvelopeField::MaxRollPitchRate, self.max_roll_pitch_rate),
        ]
    }

    /// The limits a `holonomic` envelope must declare but does not (empty
    /// for a non-holonomic envelope).
    pub fn missing_holonomic_limits(&self) -> Vec<EnvelopeField> {
        if !self.holonomic {
            return Vec::new();
        }
        self.limits()
            .into_iter()
            .filter(|(f, v)| *f != EnvelopeField::MaxJointSpeed && v.is_none())
            .map(|(f, _)| f)
            .collect()
    }
}

/// The profile file-format version this crate understands
/// ([`ProfileMetadata::schema_version`]).
pub const PROFILE_SCHEMA_VERSION: u32 = 1;
/// Longest `platform` / `unit_id` label.
pub const MAX_LABEL_LEN: usize = 64;
/// Longest `locked_by` value.
pub const MAX_LOCKED_BY_LEN: usize = 128;
/// Longest text in a [`ProfileAttestation`] member.
pub const MAX_ATTESTATION_TEXT_LEN: usize = 4 << 20;

/// Operator sign-off evidence a locked profile carries
/// ([`ProfileMetadata::attestation`]): the exact text of the confirmed
/// sign-off file and of its operator signature bundle, embedded by
/// `robodr-commission lock`. This crate only carries it (pure: no crypto);
/// `robodr-commission`'s trust module verifies it at load time against the
/// operators listed in the root-signed trust file (two-person rule).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProfileAttestation {
    /// Exact text of the sign-off file the operators signed.
    pub signoff: String,
    /// Exact text of the sign-off's signature file (`<signoff>.sig`).
    pub signatures: String,
}

/// Artifact metadata of a locked profile (see the module docs). Every key
/// is always serialised (`null` for an absent optional), so a strict loader
/// can require all of them, except `attestation`, which is omitted when
/// absent so profiles locked before it existed keep their exact bytes.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProfileMetadata {
    /// File-format version; must equal [`PROFILE_SCHEMA_VERSION`].
    pub schema_version: u32,
    /// Monotonic artifact version, >= 1. A loader with anti-rollback state
    /// refuses a version lower than the last one it accepted.
    pub profile_version: u64,
    /// Platform label the profile is for, `[A-Za-z0-9._-]{1,64}`.
    pub platform: String,
    /// The single unit (robot id) this profile is for, same charset as
    /// `platform`; `None` = every unit of the platform.
    #[serde(default)]
    pub unit_id: Option<String>,
    /// Who locked it (the sign-off operator): non-empty, at most
    /// [`MAX_LOCKED_BY_LEN`] bytes, no control characters.
    pub locked_by: String,
    /// When it was locked, Unix seconds (UTC), > 0.
    pub locked_at: u64,
    /// `sha256:<64 lower-case hex>` of the exact locked file this version
    /// supersedes; `None` for the first version of a lineage.
    #[serde(default)]
    pub parent_digest: Option<String>,
    /// Operator sign-off evidence (see [`ProfileAttestation`]); `None` for
    /// an unattested profile (legacy, migrated, or hand-made), which a
    /// loader that requires attestation refuses.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub attestation: Option<ProfileAttestation>,
}

/// `sha256:` followed by exactly 64 lower-case hex digits.
pub fn is_sha256_digest(s: &str) -> bool {
    s.strip_prefix("sha256:")
        .is_some_and(|h| h.len() == 64 && h.bytes().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f')))
}

fn is_label(s: &str) -> bool {
    !s.is_empty()
        && s.len() <= MAX_LABEL_LEN
        && s.bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b'-'))
}

impl ProfileMetadata {
    /// Every problem with the metadata (empty = valid). Pure: no clock, no
    /// I/O; `locked_at` is only checked to be non-zero.
    pub fn validate(&self) -> Vec<ProfileError> {
        let mut errs = Vec::new();
        let bad = |field: &'static str, detail: &str| ProfileError::InvalidMetadata {
            field,
            detail: detail.to_owned(),
        };
        if self.schema_version != PROFILE_SCHEMA_VERSION {
            errs.push(ProfileError::UnsupportedSchemaVersion {
                found: self.schema_version,
                supported: PROFILE_SCHEMA_VERSION,
            });
        }
        if self.profile_version == 0 {
            errs.push(bad("profile_version", "must be >= 1"));
        }
        if !is_label(&self.platform) {
            errs.push(bad("platform", "must match [A-Za-z0-9._-]{1,64}"));
        }
        if let Some(u) = &self.unit_id {
            if !is_label(u) {
                errs.push(bad(
                    "unit_id",
                    "must match [A-Za-z0-9._-]{1,64} (or be null)",
                ));
            }
        }
        if self.locked_by.trim().is_empty()
            || self.locked_by.len() > MAX_LOCKED_BY_LEN
            || self.locked_by.chars().any(char::is_control)
        {
            errs.push(bad(
                "locked_by",
                "must be a non-empty name of at most 128 bytes without control characters",
            ));
        }
        if self.locked_at == 0 {
            errs.push(bad("locked_at", "must be Unix seconds > 0"));
        }
        if let Some(d) = &self.parent_digest {
            if !is_sha256_digest(d) {
                errs.push(bad(
                    "parent_digest",
                    "must be sha256:<64 lower-case hex> (or null)",
                ));
            }
        }
        if let Some(a) = &self.attestation {
            let ok = |t: &str| !t.trim().is_empty() && t.len() <= MAX_ATTESTATION_TEXT_LEN;
            if !ok(&a.signoff) || !ok(&a.signatures) {
                errs.push(bad(
                    "attestation",
                    "signoff and signatures must be non-empty texts of at most 4 MiB",
                ));
            }
        }
        errs
    }
}

/// The profile for one robot model.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct Profile {
    /// Human label, e.g. "amr-forklift-v2".
    pub model: String,
    /// `true` once the OEM has locked it; while `false` RoboDR is in observe
    /// mode: deviations are produced with [`Mode::Observe`] and must never
    /// lead to an action.
    #[serde(default)]
    pub locked: bool,
    /// Artifact metadata stamped by `lock` (see the module docs). Absent in
    /// drafts and in profiles locked before metadata existed; not
    /// serialised when `None`, so drafts are byte-identical to before.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub metadata: Option<ProfileMetadata>,
    /// GUID prefixes of participants that belong on this robot.
    #[serde(default)]
    pub participants: BTreeSet<String>,
    /// ROS topics (de-mangled, e.g. `/cmd_vel`) a writer may publish to.
    #[serde(default)]
    pub writer_topics: BTreeSet<String>,
    /// For each motion/control topic, the envelope its commands must stay in.
    #[serde(default)]
    pub motion_envelopes: BTreeMap<String, Envelope>,
    /// ROS service names (e.g. `/node/get_parameters`) that may have clients
    /// or servers on this robot. Every ROS 2 node exposes parameter services,
    /// so commissioning must learn these.
    #[serde(default)]
    pub services: BTreeSet<String>,
    /// ROS action names (e.g. `/navigate_to_pose`) that may have clients or
    /// servers. Allows all five underlying topics of the action.
    #[serde(default)]
    pub actions: BTreeSet<String>,
    /// Optional reader allowlist for ROS topics. Empty = not enforced.
    #[serde(default)]
    pub reader_topics: BTreeSet<String>,
    /// Exact raw DDS topic names (no ROS mangling) allowed on the bus.
    #[serde(default)]
    pub raw_dds_topics: BTreeSet<String>,
}

/// Which envelope limit a [`ProfileError`] refers to.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum EnvelopeField {
    MaxLinearSpeed,
    MaxJointSpeed,
    MaxLateralSpeed,
    MaxVerticalSpeed,
    MaxRollPitchRate,
}

impl EnvelopeField {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::MaxLinearSpeed => "max_linear_speed",
            Self::MaxJointSpeed => "max_joint_speed",
            Self::MaxLateralSpeed => "max_lateral_speed",
            Self::MaxVerticalSpeed => "max_vertical_speed",
            Self::MaxRollPitchRate => "max_roll_pitch_rate",
        }
    }
}

/// A problem found by [`Profile::validate`]. A profile with any error must not
/// be loaded for enforcement.
#[derive(Debug, Clone, PartialEq, Serialize)]
#[serde(tag = "error", rename_all = "snake_case")]
pub enum ProfileError {
    /// `model` is empty.
    EmptyModel,
    /// An envelope limit is NaN, infinite or negative.
    InvalidEnvelopeLimit {
        channel: String,
        field: EnvelopeField,
        /// The offending value (serialized as `null` when NaN/inf).
        value: f64,
    },
    /// A `holonomic: true` envelope leaves a mandatory limit unset (`None`).
    MissingHolonomicLimit {
        channel: String,
        field: EnvelopeField,
    },
    /// A `motion_envelopes` key is empty.
    EmptyMotionChannel,
    /// A participant entry is not 24 lower-case hex characters.
    InvalidParticipantGuid { guid: String },
    /// An entry of a ROS-name set is not a fully qualified de-mangled ROS
    /// name (must start with `/`, e.g. `/cmd_vel`, not `rt/cmd_vel`).
    NotARosName { set: &'static str, name: String },
    /// An entry of `raw_dds_topics` is empty.
    EmptyRawTopic,
    /// An entry of a ROS-name set (or a `motion_envelopes` key) starts with
    /// `/` but is otherwise malformed (`/cmd_vel/`, `//x`, `/a b`, `/1x`, …).
    /// Empty / not-`/`-prefixed names are reported as
    /// [`ProfileError::NotARosName`] instead (as before).
    MalformedRosName {
        set: &'static str,
        name: String,
        issue: RosNameIssue,
    },
    /// A `motion_envelopes` key is a valid ROS name but is not allowed for
    /// writers (not in `writer_topics`, not part of a profiled action): every
    /// legitimate publisher of it would be reported as an unknown writer.
    MotionChannelNotWritable { channel: String },
    /// A `raw_dds_topics` entry is a well-formed ROS-mangled name (`rt/x`,
    /// `rq/xRequest`, ...). Such names are always checked against the ROS
    /// sets, so the raw entry can never match: list the de-mangled name in
    /// the proper ROS set instead.
    RawTopicIsRosName { name: String },
    /// [`ProfileMetadata::schema_version`] is not one this build reads.
    UnsupportedSchemaVersion { found: u32, supported: u32 },
    /// A [`ProfileMetadata`] field is malformed.
    InvalidMetadata { field: &'static str, detail: String },
}

impl fmt::Display for ProfileError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::EmptyModel => write!(f, "profile model name is empty"),
            Self::InvalidEnvelopeLimit {
                channel,
                field,
                value,
            } => write!(
                f,
                "envelope {} on channel {channel:?} is {value} (must be finite and >= 0; use null for unconstrained)",
                field.as_str()
            ),
            Self::MissingHolonomicLimit { channel, field } => write!(
                f,
                "envelope on channel {channel:?} is holonomic but {} is not set (holonomic channels must bound every axis; use 0 for an axis that must not move)",
                field.as_str()
            ),
            Self::EmptyMotionChannel => write!(f, "motion_envelopes has an empty channel name"),
            Self::InvalidParticipantGuid { guid } => {
                write!(f, "participant {guid:?} is not a 24-char lower-case hex GUID prefix")
            }
            Self::NotARosName { set, name } => write!(
                f,
                "{set} entry {name:?} is not a fully qualified de-mangled ROS name"
            ),
            Self::EmptyRawTopic => write!(f, "raw_dds_topics has an empty entry"),
            Self::MalformedRosName { set, name, issue } => {
                write!(f, "{set} entry {name:?} is not a well-formed ROS name: {issue}")
            }
            Self::MotionChannelNotWritable { channel } => write!(
                f,
                "motion_envelopes channel {channel:?} is not in writer_topics (nor a profiled action topic); its legitimate publishers would be reported as unknown writers"
            ),
            Self::RawTopicIsRosName { name } => write!(
                f,
                "raw_dds_topics entry {name:?} is a ROS-mangled name and can never match; list the de-mangled ROS name in writer_topics/services/actions instead"
            ),
            Self::UnsupportedSchemaVersion { found, supported } => write!(
                f,
                "metadata.schema_version {found} is not supported (this build reads {supported})"
            ),
            Self::InvalidMetadata { field, detail } => {
                write!(f, "metadata.{field}: {detail}")
            }
        }
    }
}

impl std::error::Error for ProfileError {}

/// A limit is usable iff finite and non-negative.
fn valid_limit(max: f64) -> bool {
    max.is_finite() && max >= 0.0
}

fn is_guid_prefix(s: &str) -> bool {
    s.len() == 24 && s.bytes().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f'))
}

/// Map a name in ROS-name set `set` to its validation error, if any. Empty and
/// non-`/`-prefixed names keep the historic [`ProfileError::NotARosName`].
fn ros_name_error(set: &'static str, name: &str) -> Option<ProfileError> {
    match validate_full_name(name) {
        Ok(()) => None,
        Err(RosNameIssue::Empty | RosNameIssue::NotFullyQualified) => {
            Some(ProfileError::NotARosName {
                set,
                name: name.to_owned(),
            })
        }
        Err(issue) => Some(ProfileError::MalformedRosName {
            set,
            name: name.to_owned(),
            issue,
        }),
    }
}

/// Best-effort reading of a malformed profile name as the ROS topic its
/// author meant: trim whitespace, drop a `rt/` mangling prefix, drop empty
/// tokens (leading/trailing/repeated `/`), re-qualify with `/`. `None` if
/// nothing is left. Used only to *add* detections on invalid profiles.
fn lenient_ros_name(key: &str) -> Option<String> {
    let t = key.trim();
    let t = t.strip_prefix("rt/").unwrap_or(t);
    let tokens: Vec<&str> = t.split('/').filter(|s| !s.is_empty()).collect();
    if tokens.is_empty() {
        return None;
    }
    Some(format!("/{}", tokens.join("/")))
}

impl Profile {
    /// The mode deviations from this profile carry.
    pub fn mode(&self) -> Mode {
        if self.locked {
            Mode::Enforce
        } else {
            Mode::Observe
        }
    }

    /// Load-time validation for the commissioning tool and the sensor. Returns
    /// every problem found (not just the first). Callers must refuse to
    /// enforce a profile that fails validation. See the module docs for the
    /// ROS-name and motion-channel rules.
    pub fn validate(&self) -> Result<(), Vec<ProfileError>> {
        let mut errs = Vec::new();
        if self.model.trim().is_empty() {
            errs.push(ProfileError::EmptyModel);
        }
        for g in &self.participants {
            if !is_guid_prefix(g) {
                errs.push(ProfileError::InvalidParticipantGuid { guid: g.clone() });
            }
        }
        for (set, names) in [
            ("writer_topics", &self.writer_topics),
            ("services", &self.services),
            ("actions", &self.actions),
            ("reader_topics", &self.reader_topics),
        ] {
            errs.extend(names.iter().filter_map(|n| ros_name_error(set, n)));
        }
        if self.raw_dds_topics.iter().any(String::is_empty) {
            errs.push(ProfileError::EmptyRawTopic);
        }
        for raw in &self.raw_dds_topics {
            if demangle(raw).is_ros() {
                errs.push(ProfileError::RawTopicIsRosName { name: raw.clone() });
            }
        }
        for (channel, env) in &self.motion_envelopes {
            if channel.is_empty() {
                errs.push(ProfileError::EmptyMotionChannel);
            } else if let Some(e) = ros_name_error("motion_envelopes", channel) {
                errs.push(e);
            } else if !self.name_allowed(&demangle(&format!("rt{channel}")), &self.writer_topics) {
                // Same predicate check_writer applies to a known participant
                // publishing `rt<channel>`.
                errs.push(ProfileError::MotionChannelNotWritable {
                    channel: channel.clone(),
                });
            }
            for field in env.missing_holonomic_limits() {
                errs.push(ProfileError::MissingHolonomicLimit {
                    channel: channel.clone(),
                    field,
                });
            }
            for (field, lim) in env.limits() {
                if let Some(v) = lim {
                    if !valid_limit(v) {
                        errs.push(ProfileError::InvalidEnvelopeLimit {
                            channel: channel.clone(),
                            field,
                            value: v,
                        });
                    }
                }
            }
        }
        if let Some(m) = &self.metadata {
            errs.extend(m.validate());
        }
        if errs.is_empty() {
            Ok(())
        } else {
            Err(errs)
        }
    }

    /// Decide whether an event deviates from this profile. `None` = within
    /// profile. The returned deviation carries [`Profile::mode`]. The caller
    /// (Pulsar glue) decides what to do with a deviation; this function never
    /// acts and never mutates.
    pub fn evaluate(&self, event: &RobotEvent) -> Option<Deviation> {
        let dev = match event {
            RobotEvent::Ros2ParticipantDiscovered(p) => self.check_participant(p),
            RobotEvent::Ros2WriterDiscovered(e) => self.check_writer(e),
            // A new reader is lower risk than a new writer; it can exfiltrate
            // but cannot command. Report it, do not escalate.
            RobotEvent::Ros2ReaderDiscovered(e) => self.check_reader(e),
            RobotEvent::MotionCommand(c) => self.check_motion(c),
            // Stateful consistency checks live in robodr-motion.
            RobotEvent::MotionFeedback(_) => None,
        };
        dev.map(|d| d.with_mode(self.mode()))
    }

    fn check_participant(&self, p: &Participant) -> Option<Deviation> {
        if self.participants.contains(&p.guid_prefix) {
            return None;
        }
        Some(Deviation::new(
            "robot.ros2.unknown_participant",
            Severity::High,
            format!(
                "unknown DDS participant {} from {} joined the robot graph",
                p.guid_prefix, p.src_ip
            ),
        ))
    }

    /// Is this name allowed for an endpoint, given the kind-specific sets?
    /// `topics` is `writer_topics` or `reader_topics`.
    fn name_allowed(&self, rn: &RosName, topics: &BTreeSet<String>) -> bool {
        match &rn.kind {
            RosNameKind::Topic => topics.contains(&rn.name),
            RosNameKind::ServiceRequest | RosNameKind::ServiceReply => {
                self.services.contains(&rn.name)
            }
            RosNameKind::ActionPart { action, role, .. } => {
                self.actions.contains(action)
                    || match role {
                        ActionRole::Topic => topics.contains(&rn.name),
                        ActionRole::Request | ActionRole::Reply => self.services.contains(&rn.name),
                    }
            }
            RosNameKind::Raw => self.raw_dds_topics.contains(&rn.name),
        }
    }

    /// Is the de-mangled ROS topic `name` a motion channel? Exact key match,
    /// or (defence in depth for profiles that failed validation) a malformed
    /// key whose lenient reading is `name`. See the module docs.
    fn is_motion_topic(&self, name: &str) -> bool {
        self.motion_envelopes.contains_key(name)
            || self
                .motion_envelopes
                .keys()
                .filter(|k| !is_full_name(k))
                .any(|k| lenient_ros_name(k).as_deref() == Some(name))
    }

    fn check_writer(&self, e: &Endpoint) -> Option<Deviation> {
        let rn = e.ros_name();
        let known_participant = self.participants.contains(&e.guid_prefix);
        let topic_transport = matches!(
            rn.kind,
            RosNameKind::Topic
                | RosNameKind::ActionPart {
                    role: ActionRole::Topic,
                    ..
                }
        );
        let publishes_motion = topic_transport && self.is_motion_topic(&rn.name);

        // A writer to a motion topic from a participant not in the profile is
        // the RoboPAIR / spoofed-command case: highest severity.
        if publishes_motion && !known_participant {
            return Some(Deviation::new(
                "robot.ros2.unauthorized_motion_writer",
                Severity::Critical,
                format!(
                    "participant {} not in profile is publishing motion topic {}",
                    e.guid_prefix, rn.name
                ),
            ));
        }
        if self.name_allowed(&rn, &self.writer_topics) {
            return None;
        }
        let rule = match rn.kind {
            RosNameKind::Topic => "robot.ros2.unknown_writer_topic",
            RosNameKind::ServiceRequest | RosNameKind::ServiceReply => "robot.ros2.unknown_service",
            RosNameKind::ActionPart { .. } => "robot.ros2.unknown_action",
            RosNameKind::Raw => "robot.dds.unknown_raw_writer",
        };
        let detail = match rn.kind {
            // Keep the historic detail format for plain topics.
            RosNameKind::Topic => {
                format!("writer on unprofiled topic {} ({})", rn.name, e.guid_prefix)
            }
            _ => format!("writer on unprofiled {rn} ({})", e.guid_prefix),
        };
        Some(Deviation::new(rule, Severity::High, detail))
    }

    fn check_reader(&self, e: &Endpoint) -> Option<Deviation> {
        let rn = e.ros_name();
        if !self.participants.contains(&e.guid_prefix) {
            return Some(Deviation::new(
                "robot.ros2.unknown_reader",
                Severity::Medium,
                format!(
                    "reader from unprofiled participant {} on {}",
                    e.guid_prefix, rn.name
                ),
            ));
        }
        if self.reader_topics.is_empty() || self.name_allowed(&rn, &self.reader_topics) {
            return None;
        }
        Some(Deviation::new(
            "robot.ros2.unknown_reader_topic",
            Severity::Medium,
            format!("reader on unprofiled {rn} ({})", e.guid_prefix),
        ))
    }

    fn check_motion(&self, c: &MotionCommand) -> Option<Deviation> {
        // 1. Hostile floats first, on every axis: NaN compares false with
        //    everything, so it must never reach a `>` check.
        for (dim, v) in c.components() {
            if let Some(v) = v.filter(|v| !v.is_finite()) {
                return Some(Deviation::new(
                    "robot.motion.non_finite_command",
                    Severity::Critical,
                    format!("non-finite {dim} speed {v} on {}", c.channel),
                ));
            }
        }
        let Some(env) = self.motion_envelopes.get(&c.channel) else {
            // A motion command on a channel with no envelope is itself odd.
            return Some(Deviation::new(
                "robot.motion.unprofiled_channel",
                Severity::High,
                format!("motion command on channel {} with no envelope", c.channel),
            ));
        };
        // 2. Fail closed on a broken profile: an envelope we cannot enforce is
        //    reported for every command on the channel. A holonomic envelope
        //    with an unset axis limit is "cannot enforce" too.
        for (field, lim) in env.limits() {
            if let Some(max) = lim.filter(|m| !valid_limit(*m)) {
                return Some(Deviation::new(
                    "robot.profile.invalid_envelope",
                    Severity::High,
                    format!(
                        "envelope {} = {max} on {} is invalid; command cannot be checked",
                        field.as_str(),
                        c.channel
                    ),
                ));
            }
        }
        if let Some(field) = env.missing_holonomic_limits().first() {
            return Some(Deviation::new(
                "robot.profile.invalid_envelope",
                Severity::High,
                format!(
                    "holonomic envelope on {} has no {}; command cannot be checked",
                    c.channel,
                    field.as_str()
                ),
            ));
        }
        // 3. Magnitudes: compare |v| so a signed value cannot slip under.
        let over = |rule: &'static str, what: &str, unit: &str, v: f64, max: f64| {
            Deviation::new(
                rule,
                Severity::Critical,
                format!(
                    "{what} {v:.3} {unit} (|{:.3}|) over envelope {max:.3} on {}",
                    v.abs(),
                    c.channel
                ),
            )
        };
        if let Some(max) = env.max_linear_speed {
            if let Some(v) = c.linear_speed.filter(|v| v.abs() > max) {
                return Some(over(
                    "robot.motion.linear_over_envelope",
                    "linear speed",
                    "m/s",
                    v,
                    max,
                ));
            }
            // Resultant: a holonomic command can stay under the limit on
            // every axis and still exceed it diagonally; a diff-drive base
            // given a bogus linear.y is bounded the same way (as before).
            if let Some(r) = c.linear_resultant().filter(|r| *r > max) {
                return Some(over(
                    "robot.motion.linear_over_envelope",
                    "resultant linear speed ‖(x,y,z)‖",
                    "m/s",
                    r,
                    max,
                ));
            }
        }
        for (max, v, what, unit) in [
            (env.max_lateral_speed, c.linear_y, "lateral speed", "m/s"),
            (env.max_vertical_speed, c.linear_z, "vertical speed", "m/s"),
        ] {
            if let (Some(max), Some(v)) = (max, v) {
                if v.abs() > max {
                    return Some(over(
                        "robot.motion.linear_over_envelope",
                        what,
                        unit,
                        v,
                        max,
                    ));
                }
            }
        }
        if let (Some(max), Some(r)) = (env.max_roll_pitch_rate, c.roll_pitch_rate()) {
            if r > max {
                return Some(over(
                    "robot.motion.angular_over_envelope",
                    "roll/pitch rate",
                    "rad/s",
                    r,
                    max,
                ));
            }
        }
        if let (Some(max), Some(v)) = (env.max_joint_speed, c.joint_speed) {
            if v.abs() > max {
                return Some(over(
                    "robot.motion.joint_over_envelope",
                    "joint speed",
                    "rad/s",
                    v,
                    max,
                ));
            }
        }
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::graph::{Endpoint, Participant};
    use crate::MotionFeedback;

    const KNOWN: &str = "aaaaaaaaaaaaaaaaaaaaaaaa";
    const FOREIGN: &str = "ffffffffffffffffffffffff";

    fn profile() -> Profile {
        let mut p = Profile {
            model: "amr-v1".into(),
            locked: true,
            ..Default::default()
        };
        p.participants.insert(KNOWN.into());
        p.writer_topics.insert("/cmd_vel".into());
        p.writer_topics.insert("/odom".into());
        p.motion_envelopes.insert(
            "/cmd_vel".into(),
            Envelope {
                max_linear_speed: Some(0.5),
                max_joint_speed: Some(1.0),
                ..Default::default()
            },
        );
        p.services.insert("/add_two_ints".into());
        p.actions.insert("/navigate_to_pose".into());
        p.raw_dds_topics.insert("vendor_diag".into());
        p
    }

    fn endpoint(guid: &str, topic: &str) -> Endpoint {
        Endpoint {
            guid_prefix: guid.into(),
            topic: topic.into(),
            type_name: String::new(),
        }
    }
    fn writer(guid: &str, topic: &str) -> RobotEvent {
        RobotEvent::Ros2WriterDiscovered(endpoint(guid, topic))
    }
    fn reader(guid: &str, topic: &str) -> RobotEvent {
        RobotEvent::Ros2ReaderDiscovered(endpoint(guid, topic))
    }
    fn cmd(channel: &str, lin: Option<f64>, joint: Option<f64>) -> RobotEvent {
        RobotEvent::MotionCommand(MotionCommand {
            channel: channel.into(),
            source_guid: Some(KNOWN.into()),
            linear_speed: lin,
            joint_speed: joint,
            angular_speed: None,
            ..Default::default()
        })
    }
    fn with_angular(e: RobotEvent, a: f64) -> RobotEvent {
        match e {
            RobotEvent::MotionCommand(c) => RobotEvent::MotionCommand(MotionCommand {
                angular_speed: Some(a),
                ..c
            }),
            other => other,
        }
    }
    fn rule_of(p: &Profile, e: &RobotEvent) -> Option<String> {
        p.evaluate(e).map(|d| d.rule.into_owned())
    }

    // ---- participants / writers (original behaviour) ----

    #[test]
    fn known_participant_is_clean() {
        let got = profile().evaluate(&RobotEvent::Ros2ParticipantDiscovered(Participant {
            guid_prefix: KNOWN.into(),
            src_ip: "10.0.0.5".into(),
            locators: vec![],
        }));
        assert!(got.is_none());
    }

    #[test]
    fn unknown_participant_flagged_high() {
        let got = profile()
            .evaluate(&RobotEvent::Ros2ParticipantDiscovered(Participant {
                guid_prefix: FOREIGN.into(),
                src_ip: "10.0.0.9".into(),
                locators: vec![],
            }))
            .expect("should deviate");
        assert_eq!(got.rule, "robot.ros2.unknown_participant");
        assert_eq!(got.severity, Severity::High);
        assert_eq!(got.mode, Mode::Enforce);
    }

    #[test]
    fn foreign_writer_on_motion_topic_is_critical() {
        let got = profile()
            .evaluate(&writer(FOREIGN, "rt/cmd_vel"))
            .expect("should deviate");
        assert_eq!(got.rule, "robot.ros2.unauthorized_motion_writer");
        assert_eq!(got.severity, Severity::Critical);
        assert!(got.detail.contains("/cmd_vel"));
    }

    #[test]
    fn known_writer_on_known_topic_is_clean() {
        assert!(profile().evaluate(&writer(KNOWN, "rt/cmd_vel")).is_none());
        assert!(profile().evaluate(&writer(FOREIGN, "rt/odom")).is_none());
    }

    #[test]
    fn unknown_writer_topic_is_high() {
        let d = profile().evaluate(&writer(KNOWN, "rt/evil")).unwrap();
        assert_eq!(d.rule, "robot.ros2.unknown_writer_topic");
        assert_eq!(d.severity, Severity::High);
        assert_eq!(
            d.detail,
            format!("writer on unprofiled topic /evil ({KNOWN})")
        );
    }

    // ---- raw DDS names are not ROS names ----

    #[test]
    fn raw_dds_topics_never_match_ros_allowlists() {
        let p = profile();
        // Regression: "rtcmd_vel" used to be stripped to "cmd_vel"; and a raw
        // "/cmd_vel" must not count as the ROS topic /cmd_vel either.
        for raw in ["rtcmd_vel", "/cmd_vel", "cmd_vel", "rt", "rq/add_two_ints"] {
            assert_eq!(
                rule_of(&p, &writer(FOREIGN, raw)).as_deref(),
                Some("robot.dds.unknown_raw_writer"),
                "{raw}"
            );
        }
        assert!(p.evaluate(&writer(KNOWN, "vendor_diag")).is_none());
        // The raw allowlist is exact: it does not admit ROS names.
        assert_eq!(
            rule_of(&p, &writer(KNOWN, "rt/vendor_diag")).as_deref(),
            Some("robot.ros2.unknown_writer_topic")
        );
    }

    // ---- services and actions ----

    #[test]
    fn service_clients_and_servers_are_writers() {
        let p = profile();
        assert!(p
            .evaluate(&writer(KNOWN, "rq/add_two_intsRequest"))
            .is_none());
        assert!(p.evaluate(&writer(KNOWN, "rr/add_two_intsReply")).is_none());
        assert!(p
            .evaluate(&writer(KNOWN, "rq/add_two_intsRequest_"))
            .is_none());
        let d = p.evaluate(&writer(KNOWN, "rq/set_modeRequest")).unwrap();
        assert_eq!(d.rule, "robot.ros2.unknown_service");
        assert_eq!(d.severity, Severity::High);
        assert!(d.detail.contains("/set_mode"), "{}", d.detail);
        assert_eq!(
            rule_of(&p, &writer(KNOWN, "rr/set_modeReply")).as_deref(),
            Some("robot.ros2.unknown_service")
        );
        // A service named like a writer topic is not a topic.
        assert_eq!(
            rule_of(&p, &writer(KNOWN, "rq/odomRequest")).as_deref(),
            Some("robot.ros2.unknown_service")
        );
    }

    #[test]
    fn action_parts_follow_actions_set() {
        let p = profile();
        for t in [
            "rq/navigate_to_pose/_action/send_goalRequest",
            "rr/navigate_to_pose/_action/send_goalReply",
            "rq/navigate_to_pose/_action/cancel_goalRequest",
            "rr/navigate_to_pose/_action/get_resultReply",
            "rt/navigate_to_pose/_action/feedback",
            "rt/navigate_to_pose/_action/status",
        ] {
            assert!(p.evaluate(&writer(KNOWN, t)).is_none(), "{t}");
        }
        assert_eq!(
            rule_of(&p, &writer(KNOWN, "rq/dock/_action/send_goalRequest")).as_deref(),
            Some("robot.ros2.unknown_action")
        );
        // Per-part fallback: listing the full name works too.
        let mut q = p.clone();
        q.writer_topics.insert("/dock/_action/status".into());
        q.services.insert("/dock/_action/send_goal".into());
        assert!(q
            .evaluate(&writer(KNOWN, "rt/dock/_action/status"))
            .is_none());
        assert!(q
            .evaluate(&writer(KNOWN, "rq/dock/_action/send_goalRequest"))
            .is_none());
        assert_eq!(
            rule_of(&q, &writer(KNOWN, "rt/dock/_action/feedback")).as_deref(),
            Some("robot.ros2.unknown_action")
        );
    }

    // ---- readers ----

    #[test]
    fn reader_rules() {
        let mut p = profile();
        let d = p.evaluate(&reader(FOREIGN, "rt/camera/image")).unwrap();
        assert_eq!(d.rule, "robot.ros2.unknown_reader");
        assert_eq!(d.severity, Severity::Medium);
        assert!(d.detail.contains("/camera/image"));
        // reader_topics empty -> not enforced for known participants.
        assert!(p.evaluate(&reader(KNOWN, "rt/camera/image")).is_none());
        assert!(p.evaluate(&reader(KNOWN, "whatever")).is_none());

        p.reader_topics.insert("/odom".into());
        assert!(p.evaluate(&reader(KNOWN, "rt/odom")).is_none());
        let d = p.evaluate(&reader(KNOWN, "rt/camera/image")).unwrap();
        assert_eq!(d.rule, "robot.ros2.unknown_reader_topic");
        assert_eq!(d.severity, Severity::Medium);
        // Services/actions/raw readers use their own sets.
        assert!(p.evaluate(&reader(KNOWN, "rr/add_two_intsReply")).is_none());
        assert!(p
            .evaluate(&reader(KNOWN, "rt/navigate_to_pose/_action/feedback"))
            .is_none());
        assert!(p.evaluate(&reader(KNOWN, "vendor_diag")).is_none());
        assert_eq!(
            rule_of(&p, &reader(KNOWN, "rq/set_modeRequest")).as_deref(),
            Some("robot.ros2.unknown_reader_topic")
        );
        assert_eq!(
            rule_of(&p, &reader(KNOWN, "rtodom")).as_deref(),
            Some("robot.ros2.unknown_reader_topic")
        );
    }

    // ---- motion envelope ----

    #[test]
    fn speed_over_envelope_is_critical() {
        let got = profile()
            .evaluate(&cmd("/cmd_vel", Some(2.5), None))
            .expect("should deviate");
        assert_eq!(got.rule, "robot.motion.linear_over_envelope");
        assert_eq!(got.severity, Severity::Critical);
    }

    #[test]
    fn speed_within_envelope_is_clean() {
        let p = profile();
        for v in [0.0, -0.0, 0.4, 0.5, -0.5, f64::MIN_POSITIVE] {
            assert!(
                p.evaluate(&cmd("/cmd_vel", Some(v), Some(v))).is_none(),
                "{v}"
            );
        }
        assert!(p.evaluate(&cmd("/cmd_vel", None, None)).is_none());
    }

    #[test]
    fn non_finite_command_is_critical() {
        let p = profile();
        for bad in [f64::NAN, -f64::NAN, f64::INFINITY, f64::NEG_INFINITY] {
            for e in [
                cmd("/cmd_vel", Some(bad), None),
                cmd("/cmd_vel", None, Some(bad)),
                cmd("/cmd_vel", Some(0.1), Some(bad)),
                // Even on an unprofiled channel, the hostile float wins.
                cmd("/nowhere", Some(bad), None),
                // Yaw rate: no envelope limit, but never a hostile float.
                with_angular(cmd("/cmd_vel", Some(0.1), None), bad),
            ] {
                let d = p.evaluate(&e).expect("NaN/inf must deviate");
                assert_eq!(d.rule, "robot.motion.non_finite_command");
                assert_eq!(d.severity, Severity::Critical);
            }
        }
        // Unconstrained dimension does not make NaN acceptable.
        let mut q = p.clone();
        q.motion_envelopes
            .insert("/free".into(), Envelope::default());
        assert_eq!(
            rule_of(&q, &cmd("/free", Some(f64::NAN), None)).as_deref(),
            Some("robot.motion.non_finite_command")
        );
        assert!(q
            .evaluate(&cmd("/free", Some(1e300), Some(-1e300)))
            .is_none());
        // A finite signed yaw rate is not judged by the profile (no limit).
        assert!(q
            .evaluate(&with_angular(cmd("/free", Some(-0.2), None), -3.0))
            .is_none());
    }

    #[test]
    fn negative_speed_is_compared_by_magnitude() {
        let p = profile();
        let d = p.evaluate(&cmd("/cmd_vel", Some(-2.5), None)).unwrap();
        assert_eq!(d.rule, "robot.motion.linear_over_envelope");
        assert!(d.detail.contains("-2.500"), "{}", d.detail);
        let d = p.evaluate(&cmd("/cmd_vel", None, Some(-1.5))).unwrap();
        assert_eq!(d.rule, "robot.motion.joint_over_envelope");
        assert_eq!(
            rule_of(&p, &cmd("/cmd_vel", Some(-f64::MAX), None)).as_deref(),
            Some("robot.motion.linear_over_envelope")
        );
    }

    #[test]
    fn unprofiled_motion_channel_is_high() {
        let d = profile().evaluate(&cmd("/other", Some(0.1), None)).unwrap();
        assert_eq!(d.rule, "robot.motion.unprofiled_channel");
        assert_eq!(d.severity, Severity::High);
        // The channel is matched exactly, not de-mangled.
        assert_eq!(
            rule_of(&profile(), &cmd("rt/cmd_vel", Some(0.1), None)).as_deref(),
            Some("robot.motion.unprofiled_channel")
        );
    }

    #[test]
    fn invalid_envelope_fails_closed() {
        for bad in [f64::NAN, f64::INFINITY, f64::NEG_INFINITY, -0.1] {
            let mut p = profile();
            p.motion_envelopes.insert(
                "/cmd_vel".into(),
                Envelope {
                    max_linear_speed: Some(bad),
                    max_joint_speed: None,
                    ..Default::default()
                },
            );
            // Every command is reported, including ones that would have
            // slipped past `v > NaN` before.
            for e in [
                cmd("/cmd_vel", Some(100.0), None),
                cmd("/cmd_vel", Some(0.0), None),
                cmd("/cmd_vel", None, Some(0.0)),
            ] {
                let d = p.evaluate(&e).expect("must report");
                assert_eq!(d.rule, "robot.profile.invalid_envelope", "{bad}");
                assert_eq!(d.severity, Severity::High);
            }
            let errs = p.validate().unwrap_err();
            assert!(matches!(
                errs.as_slice(),
                [ProfileError::InvalidEnvelopeLimit { field: EnvelopeField::MaxLinearSpeed, channel, .. }]
                    if channel == "/cmd_vel"
            ));
        }
        // Zero is a valid (stop-only) limit.
        let mut p = profile();
        p.motion_envelopes
            .get_mut("/cmd_vel")
            .unwrap()
            .max_linear_speed = Some(0.0);
        assert!(p.validate().is_ok());
        assert!(p.evaluate(&cmd("/cmd_vel", Some(0.0), None)).is_none());
        assert!(p.evaluate(&cmd("/cmd_vel", Some(0.001), None)).is_some());
    }

    #[test]
    fn motion_feedback_is_never_a_profile_deviation() {
        let fb = RobotEvent::MotionFeedback(MotionFeedback {
            channel: "/unknown".into(),
            measured_linear_speed: Some(f64::NAN),
            measured_joint_speed: None,
            linear_velocity: None,
            angular_velocity: None,
            publisher_guid: None,
            timestamp_ns: 0,
            ..Default::default()
        });
        assert!(profile().evaluate(&fb).is_none());
    }

    // ---- observe vs enforce ----

    #[test]
    fn unlocked_profile_produces_observe_only_deviations() {
        let mut p = profile();
        p.locked = false;
        assert_eq!(p.mode(), Mode::Observe);
        for e in [
            writer(FOREIGN, "rt/cmd_vel"),
            writer(KNOWN, "rq/xRequest"),
            reader(FOREIGN, "rt/odom"),
            cmd("/cmd_vel", Some(f64::NAN), None),
            cmd("/cmd_vel", Some(9.0), None),
        ] {
            let d = p.evaluate(&e).unwrap();
            assert_eq!(d.mode, Mode::Observe);
            assert!(d.is_observe_only());
        }
        p.locked = true;
        let d = p.evaluate(&writer(FOREIGN, "rt/cmd_vel")).unwrap();
        assert_eq!(d.mode, Mode::Enforce);
        // Detection result is otherwise identical in both modes.
        let mut q = p.clone();
        q.locked = false;
        let o = q.evaluate(&writer(FOREIGN, "rt/cmd_vel")).unwrap();
        assert_eq!(
            (o.rule, o.severity, o.detail),
            (d.rule, d.severity, d.detail)
        );
    }

    // ---- validation ----

    #[test]
    fn validate_reports_all_errors() {
        let mut p = profile();
        assert_eq!(p.validate(), Ok(()));
        p.model = "  ".into();
        p.participants.insert("AAAAAAAAAAAAAAAAAAAAAAAA".into());
        p.participants.insert("abc".into());
        p.writer_topics.insert("rt/cmd_vel".into());
        p.services.insert("add".into());
        // "/" and "/a b" are now MalformedRosName (were NotARosName).
        p.actions.insert("/".into());
        p.reader_topics.insert("/a b".into());
        p.raw_dds_topics.insert(String::new());
        p.motion_envelopes.insert(
            String::new(),
            Envelope {
                max_linear_speed: Some(f64::NAN),
                max_joint_speed: Some(-1.0),
                ..Default::default()
            },
        );
        let errs = p.validate().unwrap_err();
        assert_eq!(errs.len(), 11, "{errs:#?}");
        assert_eq!(errs[0], ProfileError::EmptyModel);
        for e in &errs {
            assert!(!e.to_string().is_empty());
        }
        // Errors serialize (NaN as null) for the commissioning tool.
        let j = serde_json::to_string(&errs).unwrap();
        assert!(j.contains("\"error\":\"invalid_envelope_limit\""), "{j}");
        assert!(j.contains("\"value\":null"), "{j}");
    }

    #[test]
    fn validate_rejects_malformed_ros_names_in_every_set() {
        let bad = [
            ("cmd_vel", false),
            ("rt/cmd_vel", false),
            ("", false),
            ("/cmd_vel/", true),
            ("//cmd_vel", true),
            ("/cmd//vel", true),
            ("/", true),
            ("/cmd vel", true),
            ("/cmd-vel", true),
            ("/1cmd", true),
            ("/ns/9x", true),
            ("/x\u{0}", true),
        ];
        for (name, malformed) in bad {
            for set in ["writer_topics", "services", "actions", "reader_topics"] {
                let mut p = profile();
                match set {
                    "writer_topics" => p.writer_topics.insert(name.into()),
                    "services" => p.services.insert(name.into()),
                    "actions" => p.actions.insert(name.into()),
                    _ => p.reader_topics.insert(name.into()),
                };
                let errs = p.validate().unwrap_err();
                assert_eq!(errs.len(), 1, "{set} {name:?}: {errs:?}");
                match &errs[0] {
                    ProfileError::NotARosName { set: s, name: n } => {
                        assert!(!malformed, "{name:?}");
                        assert_eq!((*s, n.as_str()), (set, name));
                    }
                    ProfileError::MalformedRosName {
                        set: s, name: n, ..
                    } => {
                        assert!(malformed, "{name:?}");
                        assert_eq!((*s, n.as_str()), (set, name));
                    }
                    e => panic!("unexpected {e:?}"),
                }
                assert!(errs[0].to_string().contains(&format!("{name:?}")));
            }
        }
        // Raw DDS names are exempt from ROS rules (only empty is rejected).
        let mut p = profile();
        for raw in ["rt//cmd_vel", "cmd vel", "/x/", "1abc", "rtcmd_vel"] {
            p.raw_dds_topics.insert(raw.into());
        }
        assert_eq!(p.validate(), Ok(()));
        // ...but a well-formed ROS-mangled name can never match as raw.
        for ros in [
            "rt/cmd_vel",
            "rq/add_two_intsRequest",
            "rr/xReply_",
            "rt/nav/_action/status",
        ] {
            let mut q = profile();
            q.raw_dds_topics.insert(ros.into());
            assert_eq!(
                q.validate(),
                Err(vec![ProfileError::RawTopicIsRosName { name: ros.into() }]),
                "{ros}"
            );
            assert!(q.validate().unwrap_err()[0].to_string().contains(ros));
        }
        // Accepted edge forms.
        let mut p = profile();
        for ok in ["/a__b", "/_hidden", "/robot1/cmd_vel2"] {
            p.writer_topics.insert(ok.into());
        }
        assert_eq!(p.validate(), Ok(()));
    }

    #[test]
    fn validate_rejects_malformed_motion_envelope_keys() {
        for (key, malformed) in [
            ("cmd_vel", false),
            ("rt/cmd_vel", false),
            ("/cmd_vel/", true),
            ("//cmd_vel", true),
            ("/cmd_vel ", true),
            ("/2cmd_vel", true),
        ] {
            let mut p = profile();
            p.motion_envelopes.insert(key.into(), Envelope::default());
            let errs = p.validate().unwrap_err();
            assert_eq!(errs.len(), 1, "{key:?}: {errs:?}");
            let set = match &errs[0] {
                ProfileError::NotARosName { set, .. } if !malformed => *set,
                ProfileError::MalformedRosName { set, .. } if malformed => *set,
                e => panic!("{key:?}: unexpected {e:?}"),
            };
            assert_eq!(set, "motion_envelopes");
        }
        // Empty key: only the historic EmptyMotionChannel, not doubled.
        let mut p = profile();
        p.motion_envelopes
            .insert(String::new(), Envelope::default());
        assert_eq!(p.validate(), Err(vec![ProfileError::EmptyMotionChannel]));
    }

    #[test]
    fn motion_channel_must_be_writable() {
        // Inconsistent profile: /arm has an envelope but no writer entry, so
        // the legitimate (known) publisher raises unknown_writer_topic.
        let mut p = profile();
        p.motion_envelopes.insert(
            "/arm".into(),
            Envelope {
                max_linear_speed: None,
                max_joint_speed: Some(1.0),
                ..Default::default()
            },
        );
        assert_eq!(
            rule_of(&p, &writer(KNOWN, "rt/arm")).as_deref(),
            Some("robot.ros2.unknown_writer_topic")
        );
        let errs = p.validate().unwrap_err();
        assert_eq!(
            errs,
            vec![ProfileError::MotionChannelNotWritable {
                channel: "/arm".into()
            }]
        );
        assert!(errs[0].to_string().contains("/arm"));
        let j = serde_json::to_string(&errs).unwrap();
        assert!(
            j.contains("\"error\":\"motion_channel_not_writable\""),
            "{j}"
        );
        // Fixed by listing it: now consistent, known writer clean, foreign
        // writer Critical.
        p.writer_topics.insert("/arm".into());
        assert_eq!(p.validate(), Ok(()));
        assert!(p.evaluate(&writer(KNOWN, "rt/arm")).is_none());
        assert_eq!(
            rule_of(&p, &writer(FOREIGN, "rt/arm")).as_deref(),
            Some("robot.ros2.unauthorized_motion_writer")
        );
        // A motion channel that is an action topic of a profiled action is
        // writable through `actions` (same predicate as check_writer).
        let mut q = profile();
        q.motion_envelopes.insert(
            "/navigate_to_pose/_action/feedback".into(),
            Envelope::default(),
        );
        assert_eq!(q.validate(), Ok(()));
        assert!(q
            .evaluate(&writer(KNOWN, "rt/navigate_to_pose/_action/feedback"))
            .is_none());
        // ...but a service name or reader-only topic does not make it writable.
        let mut r = profile();
        r.services.insert("/drive".into());
        r.reader_topics.insert("/drive".into());
        r.motion_envelopes
            .insert("/drive".into(), Envelope::default());
        assert_eq!(
            r.validate(),
            Err(vec![ProfileError::MotionChannelNotWritable {
                channel: "/drive".into()
            }])
        );
    }

    #[test]
    fn malformed_envelope_key_still_flags_foreign_motion_writer() {
        // Validation refuses these profiles, but a refused profile may still be
        // evaluated (observe mode): it must not be silent about a foreign
        // motion writer.
        for key in [
            "cmd_vel",
            "rt/cmd_vel",
            "/cmd_vel/",
            "//cmd_vel",
            " /cmd_vel",
            "/cmd_vel\t",
            "rt//cmd_vel/",
        ] {
            let mut p = profile();
            p.motion_envelopes.clear();
            p.motion_envelopes.insert(key.into(), Envelope::default());
            assert!(p.validate().is_err(), "{key:?}");
            let d = p.evaluate(&writer(FOREIGN, "rt/cmd_vel")).unwrap();
            assert_eq!(d.rule, "robot.ros2.unauthorized_motion_writer", "{key:?}");
            assert_eq!(d.severity, Severity::Critical);
            // Lenient reading never *allows* anything: known writer still
            // clean (via writer_topics), other topics unchanged.
            assert!(p.evaluate(&writer(KNOWN, "rt/cmd_vel")).is_none());
            assert!(p.evaluate(&writer(FOREIGN, "rt/odom")).is_none());
            assert_eq!(
                rule_of(&p, &writer(FOREIGN, "rt/cmd_vel2")).as_deref(),
                Some("robot.ros2.unknown_writer_topic")
            );
        }
        // Degenerate keys read as nothing and match nothing.
        for key in ["/", "//", "rt/", "   "] {
            assert_eq!(lenient_ros_name(key), None, "{key:?}");
            let mut p = profile();
            p.motion_envelopes.insert(key.into(), Envelope::default());
            assert!(p.evaluate(&writer(FOREIGN, "rt/odom")).is_none());
        }
        assert_eq!(lenient_ros_name("a//b/").as_deref(), Some("/a/b"));
    }

    #[test]
    fn malformed_wire_names_do_not_match_profiled_names() {
        let p = profile();
        for t in ["rt//cmd_vel", "rt/cmd_vel/", "rt/cmd_vel//", "rt//odom"] {
            assert_eq!(
                rule_of(&p, &writer(KNOWN, t)).as_deref(),
                Some("robot.dds.unknown_raw_writer"),
                "{t}"
            );
            assert_eq!(
                rule_of(&p, &writer(FOREIGN, t)).as_deref(),
                Some("robot.dds.unknown_raw_writer"),
                "{t}"
            );
        }
        for t in ["rq//add_two_intsRequest", "rr/add_two_ints/Reply"] {
            assert_eq!(
                rule_of(&p, &writer(KNOWN, t)).as_deref(),
                Some("robot.dds.unknown_raw_writer"),
                "{t}"
            );
        }
    }

    // ---- serde ----

    #[test]
    fn example_profile_parses_and_validates() {
        let p: Profile =
            serde_json::from_str(include_str!("../../../config/profile.example.json")).unwrap();
        assert_eq!(p.model, "amr-forklift-v2");
        assert!(!p.locked);
        assert_eq!(p.mode(), Mode::Observe);
        assert!(p.writer_topics.contains("/cmd_vel"));
        assert!(p.services.is_empty() && p.actions.is_empty() && p.reader_topics.is_empty());
        assert_eq!(p.validate(), Ok(()));
        // The example's own participant may write /cmd_vel; a foreign one is
        // flagged, observe-only because the example is unlocked.
        let guid = p.participants.iter().next().unwrap().clone();
        assert!(p.evaluate(&writer(&guid, "rt/cmd_vel")).is_none());
        let d = p.evaluate(&writer(FOREIGN, "rt/cmd_vel")).unwrap();
        assert_eq!(d.rule, "robot.ros2.unauthorized_motion_writer");
        assert!(d.is_observe_only());
        // Round trip.
        let back: Profile = serde_json::from_str(&serde_json::to_string(&p).unwrap()).unwrap();
        assert_eq!(back, p);
    }

    #[test]
    fn profile_round_trip_with_new_fields() {
        let mut p = profile();
        p.reader_topics.insert("/odom".into());
        let j = serde_json::to_string_pretty(&p).unwrap();
        let back: Profile = serde_json::from_str(&j).unwrap();
        assert_eq!(back, p);
        // Minimal profile: only model required.
        let min: Profile = serde_json::from_str(r#"{"model":"m"}"#).unwrap();
        assert!(!min.locked && min.participants.is_empty());
        // Malformed profiles are rejected by the parser, not by a panic.
        for bad in [
            r#"{}"#,
            r#"{"model":"m","locked":"yes"}"#,
            r#"{"model":"m","motion_envelopes":{"/c":{"max_linear_speed":"fast"}}}"#,
            r#"{"model":"m","motion_envelopes":{"/c":{"max_linear_speed":1e999}}}"#,
            r#"{"model":"m","participants":"aa"}"#,
        ] {
            assert!(serde_json::from_str::<Profile>(bad).is_err(), "{bad}");
        }
        // Negative limits parse (JSON allows them) but fail validation.
        let neg: Profile = serde_json::from_str(
            r#"{"model":"m","motion_envelopes":{"/c":{"max_linear_speed":-1}}}"#,
        )
        .unwrap();
        assert!(neg.validate().is_err());
    }
}

#[cfg(test)]
mod holonomic_tests {
    use super::*;

    const MECANUM: &str = "/mecanum/cmd_vel";
    const DIFF: &str = "/cmd_vel";

    fn mecanum_env() -> Envelope {
        Envelope {
            max_linear_speed: Some(1.0),
            holonomic: true,
            max_lateral_speed: Some(0.6),
            max_vertical_speed: Some(0.0),
            max_roll_pitch_rate: Some(0.0),
            ..Default::default()
        }
    }

    fn profile() -> Profile {
        let mut p = Profile {
            model: "mecanum-ugv".into(),
            locked: true,
            ..Default::default()
        };
        p.writer_topics.insert(DIFF.into());
        p.writer_topics.insert(MECANUM.into());
        p.motion_envelopes.insert(
            DIFF.into(),
            Envelope {
                max_linear_speed: Some(0.5),
                ..Default::default()
            },
        );
        p.motion_envelopes.insert(MECANUM.into(), mecanum_env());
        p
    }

    /// A full Twist-shaped command: [x, y, z, roll, pitch, yaw].
    fn twist(channel: &str, v: [f64; 6]) -> RobotEvent {
        RobotEvent::MotionCommand(MotionCommand {
            channel: channel.into(),
            source_guid: None,
            linear_speed: Some(v[0]),
            linear_y: Some(v[1]),
            linear_z: Some(v[2]),
            angular_x: Some(v[3]),
            angular_y: Some(v[4]),
            angular_speed: Some(v[5]),
            joint_speed: None,
        })
    }

    fn rule(p: &Profile, e: &RobotEvent) -> Option<String> {
        p.evaluate(e).map(|d| d.rule.into_owned())
    }

    #[test]
    fn profile_validates() {
        assert_eq!(profile().validate(), Ok(()));
    }

    #[test]
    fn diff_drive_behaviour_is_unchanged() {
        let p = profile();
        // Planar command with explicit zero extra axes == old x/yaw command.
        for (x, yaw, want) in [
            (0.4, 1.0, None),
            (-0.5, -3.0, None),
            (0.51, 0.0, Some("robot.motion.linear_over_envelope")),
            (-2.5, 0.0, Some("robot.motion.linear_over_envelope")),
        ] {
            assert_eq!(
                rule(&p, &twist(DIFF, [x, 0.0, 0.0, 0.0, 0.0, yaw])).as_deref(),
                want,
                "{x}"
            );
            let legacy = RobotEvent::MotionCommand(MotionCommand {
                channel: DIFF.into(),
                linear_speed: Some(x),
                angular_speed: Some(yaw),
                ..Default::default()
            });
            assert_eq!(rule(&p, &legacy).as_deref(), want, "{x}");
        }
        // linear_speed is the signed x, never a folded magnitude.
        let d = p
            .evaluate(&twist(DIFF, [-0.6, 0.0, 0.0, 0.0, 0.0, 0.0]))
            .unwrap();
        assert!(d.detail.starts_with("linear speed -0.600"), "{}", d.detail);
    }

    #[test]
    fn diff_drive_bogus_lateral_is_bounded_by_the_resultant() {
        let p = profile();
        // Non-holonomic, no lateral limit: y alone or diagonal over max_linear
        // is still over envelope (no sideways bypass).
        let d = p
            .evaluate(&twist(DIFF, [0.0, 50.0, 0.0, 0.0, 0.0, 0.0]))
            .unwrap();
        assert_eq!(d.rule, "robot.motion.linear_over_envelope");
        assert_eq!(d.severity, Severity::Critical);
        assert!(d.detail.contains("resultant"), "{}", d.detail);
        let d = p
            .evaluate(&twist(DIFF, [0.4, 0.4, 0.0, 0.0, 0.0, 0.0]))
            .unwrap();
        assert!(d.detail.contains("resultant"), "{}", d.detail);
        assert_eq!(
            rule(&p, &twist(DIFF, [0.0, 0.0, -0.6, 0.0, 0.0, 0.0])).as_deref(),
            Some("robot.motion.linear_over_envelope")
        );
        // Within the resultant: clean (lateral not constrained per axis).
        assert!(p
            .evaluate(&twist(DIFF, [0.3, 0.4, 0.0, 0.0, 0.0, 0.0]))
            .is_none());
        // Roll/pitch with no limit on a non-holonomic channel: not judged.
        assert!(p
            .evaluate(&twist(DIFF, [0.0, 0.0, 0.0, 5.0, -5.0, 0.0]))
            .is_none());
    }

    #[test]
    fn mecanum_lateral_within_and_over_limits() {
        let p = profile();
        for v in [
            [0.0, 0.6, 0.0, 0.0, 0.0, 0.0],
            [0.0, -0.6, 0.0, 0.0, 0.0, 0.5],
            [0.8, 0.6, 0.0, 0.0, 0.0, 0.0], // resultant exactly 1.0
            [-0.5, 0.3, -0.0, 0.0, 0.0, -1.0],
        ] {
            assert!(p.evaluate(&twist(MECANUM, v)).is_none(), "{v:?}");
        }
        let d = p
            .evaluate(&twist(MECANUM, [0.0, -0.61, 0.0, 0.0, 0.0, 0.0]))
            .unwrap();
        assert_eq!(d.rule, "robot.motion.linear_over_envelope");
        assert_eq!(d.severity, Severity::Critical);
        assert!(d.detail.starts_with("lateral speed -0.610"), "{}", d.detail);
        // Each axis within its own limit, diagonal over max_linear.
        let d = p
            .evaluate(&twist(MECANUM, [0.9, 0.6, 0.0, 0.0, 0.0, 0.0]))
            .unwrap();
        assert!(d.detail.contains("resultant"), "{}", d.detail);
        // x alone still uses max_linear_speed.
        let d = p
            .evaluate(&twist(MECANUM, [-1.2, 0.0, 0.0, 0.0, 0.0, 0.0]))
            .unwrap();
        assert!(d.detail.starts_with("linear speed"), "{}", d.detail);
        // Vertical / roll-pitch limits of 0: any motion there is over.
        let d = p
            .evaluate(&twist(MECANUM, [0.0, 0.0, 0.01, 0.0, 0.0, 0.0]))
            .unwrap();
        assert!(d.detail.starts_with("vertical speed"), "{}", d.detail);
        let d = p
            .evaluate(&twist(MECANUM, [0.0, 0.0, 0.0, 0.0, -0.01, 0.0]))
            .unwrap();
        assert_eq!(d.rule, "robot.motion.angular_over_envelope");
        assert_eq!(d.severity, Severity::Critical);
        // An absent axis is not checked by its per-axis limit.
        let c = RobotEvent::MotionCommand(MotionCommand {
            channel: MECANUM.into(),
            linear_speed: Some(0.2),
            ..Default::default()
        });
        assert!(p.evaluate(&c).is_none());
    }

    #[test]
    fn roll_pitch_limit_uses_the_tilt_rate_magnitude() {
        let mut p = profile();
        p.motion_envelopes
            .get_mut(MECANUM)
            .unwrap()
            .max_roll_pitch_rate = Some(0.5);
        assert!(p
            .evaluate(&twist(MECANUM, [0.0, 0.0, 0.0, 0.3, -0.4, 0.0]))
            .is_none());
        assert_eq!(
            rule(&p, &twist(MECANUM, [0.0, 0.0, 0.0, 0.3, 0.41, 0.0])).as_deref(),
            Some("robot.motion.angular_over_envelope")
        );
    }

    #[test]
    fn non_finite_on_any_axis_is_critical() {
        let p = profile();
        for bad in [f64::NAN, -f64::NAN, f64::INFINITY, f64::NEG_INFINITY] {
            for i in 0..6 {
                let mut v = [0.0; 6];
                v[i] = bad;
                for ch in [MECANUM, DIFF, "/unprofiled"] {
                    let d = p.evaluate(&twist(ch, v)).expect("must deviate");
                    assert_eq!(d.rule, "robot.motion.non_finite_command", "{i} {ch}");
                    assert_eq!(d.severity, Severity::Critical);
                }
            }
            // NaN in y alone, everything else absent.
            let c = RobotEvent::MotionCommand(MotionCommand {
                channel: MECANUM.into(),
                linear_y: Some(bad),
                ..Default::default()
            });
            let d = p.evaluate(&c).unwrap();
            assert_eq!(d.rule, "robot.motion.non_finite_command");
            assert!(d.detail.contains("linear_y"), "{}", d.detail);
        }
        // NaN in y with an infinite x: hypot(inf, NaN) is inf in IEEE, but
        // the NaN is still reported (component check runs first).
        let c = MotionCommand {
            linear_speed: Some(f64::INFINITY),
            linear_y: Some(f64::NAN),
            ..Default::default()
        };
        assert!(c.linear_resultant().unwrap().is_nan());
    }

    #[test]
    fn resultant_helpers() {
        let c = MotionCommand::default();
        assert_eq!(c.linear_resultant(), None);
        assert_eq!(c.roll_pitch_rate(), None);
        assert!(!c.has_extra_axes());
        let c = MotionCommand {
            linear_speed: Some(-3.0),
            linear_y: Some(4.0),
            angular_x: Some(f64::MAX),
            angular_y: Some(f64::MAX),
            ..Default::default()
        };
        assert_eq!(c.linear_resultant(), Some(5.0));
        assert_eq!(c.roll_pitch_rate(), Some(f64::INFINITY));
        assert!(c.has_extra_axes());
        let c = MotionCommand {
            linear_z: Some(-2.0),
            ..Default::default()
        };
        assert_eq!(c.linear_resultant(), Some(2.0));
    }

    #[test]
    fn missing_limit_on_holonomic_channel_denies() {
        for (field, clear) in [
            (
                EnvelopeField::MaxLateralSpeed,
                (|e: &mut Envelope| e.max_lateral_speed = None) as fn(&mut Envelope),
            ),
            (EnvelopeField::MaxVerticalSpeed, |e: &mut Envelope| {
                e.max_vertical_speed = None
            }),
            (EnvelopeField::MaxRollPitchRate, |e: &mut Envelope| {
                e.max_roll_pitch_rate = None
            }),
            (EnvelopeField::MaxLinearSpeed, |e: &mut Envelope| {
                e.max_linear_speed = None
            }),
        ] {
            let mut p = profile();
            clear(p.motion_envelopes.get_mut(MECANUM).unwrap());
            let errs = p.validate().unwrap_err();
            assert_eq!(
                errs,
                vec![ProfileError::MissingHolonomicLimit {
                    channel: MECANUM.into(),
                    field
                }]
            );
            assert!(errs[0].to_string().contains(field.as_str()));
            // Every command on the channel is denied, even a stationary one
            // and one that says nothing about the missing axis.
            for e in [
                twist(MECANUM, [0.0; 6]),
                twist(MECANUM, [0.1, 0.0, 0.0, 0.0, 0.0, 0.0]),
                RobotEvent::MotionCommand(MotionCommand {
                    channel: MECANUM.into(),
                    linear_speed: Some(0.1),
                    ..Default::default()
                }),
            ] {
                let d = p.evaluate(&e).expect("must deny");
                assert_eq!(d.rule, "robot.profile.invalid_envelope", "{field:?}");
                assert_eq!(d.severity, Severity::High);
                assert!(d.detail.contains(field.as_str()), "{}", d.detail);
            }
            // The non-holonomic channel is unaffected.
            assert!(p
                .evaluate(&twist(DIFF, [0.1, 0.0, 0.0, 0.0, 0.0, 0.0]))
                .is_none());
            // Non-finite still wins over the profile error.
            assert_eq!(
                rule(&p, &twist(MECANUM, [f64::NAN, 0.0, 0.0, 0.0, 0.0, 0.0])).as_deref(),
                Some("robot.motion.non_finite_command")
            );
        }
        // All missing: one error per field, joint speed is never required.
        let mut p = profile();
        p.motion_envelopes.insert(
            MECANUM.into(),
            Envelope {
                holonomic: true,
                ..Default::default()
            },
        );
        assert_eq!(p.validate().unwrap_err().len(), 4);
        // The same envelope without `holonomic` is merely unconstrained.
        p.motion_envelopes
            .insert(MECANUM.into(), Envelope::default());
        assert_eq!(p.validate(), Ok(()));
        assert!(p
            .evaluate(&twist(MECANUM, [9.0, 9.0, 9.0, 9.0, 9.0, 9.0]))
            .is_none());
    }

    #[test]
    fn invalid_axis_limit_fails_closed() {
        for bad in [f64::NAN, f64::INFINITY, -0.1] {
            let mut p = profile();
            p.motion_envelopes.get_mut(DIFF).unwrap().max_lateral_speed = Some(bad);
            let errs = p.validate().unwrap_err();
            assert!(matches!(
                errs.as_slice(),
                [ProfileError::InvalidEnvelopeLimit {
                    field: EnvelopeField::MaxLateralSpeed,
                    ..
                }]
            ));
            assert_eq!(
                rule(&p, &twist(DIFF, [0.0; 6])).as_deref(),
                Some("robot.profile.invalid_envelope")
            );
        }
    }

    #[test]
    fn holonomic_example_profile_parses_and_validates() {
        let p: Profile = serde_json::from_str(include_str!(
            "../../../config/profile.holonomic.example.json"
        ))
        .unwrap();
        assert_eq!(p.validate(), Ok(()));
        let env = &p.motion_envelopes["/cmd_vel"];
        assert!(env.holonomic);
        assert!(env.missing_holonomic_limits().is_empty());
        // Sideways within limits is clean; over the lateral limit is not.
        assert!(p
            .evaluate(&twist("/cmd_vel", [0.2, -0.5, 0.0, 0.0, 0.0, 0.4]))
            .is_none());
        let d = p
            .evaluate(&twist("/cmd_vel", [0.0, 0.55, 0.0, 0.0, 0.0, 0.0]))
            .unwrap();
        assert_eq!(d.rule, "robot.motion.linear_over_envelope");
        assert!(d.is_observe_only()); // the example is unlocked
                                      // The diff-drive example stays non-holonomic.
        let old: Profile =
            serde_json::from_str(include_str!("../../../config/profile.example.json")).unwrap();
        assert!(old.motion_envelopes.values().all(|e| !e.holonomic));
    }

    #[test]
    fn serde_back_compat_profiles() {
        // A profile written before the holonomic fields existed.
        let old = r#"{"model":"m","writer_topics":["/cmd_vel"],"motion_envelopes":{"/cmd_vel":{"max_linear_speed":0.5,"max_joint_speed":null}}}"#;
        let p: Profile = serde_json::from_str(old).unwrap();
        let env = &p.motion_envelopes["/cmd_vel"];
        assert!(!env.holonomic);
        assert_eq!(
            (
                env.max_lateral_speed,
                env.max_vertical_speed,
                env.max_roll_pitch_rate
            ),
            (None, None, None)
        );
        assert_eq!(p.validate(), Ok(()));
        // ... and re-serialises without the new keys (sealed/signed bytes
        // of existing profiles stay identical).
        let j = serde_json::to_string(env).unwrap();
        assert_eq!(j, r#"{"max_linear_speed":0.5,"max_joint_speed":null}"#);
        // A holonomic envelope round-trips with its keys.
        let j = serde_json::to_string(&mecanum_env()).unwrap();
        assert!(
            j.contains(r#""holonomic":true"#) && j.contains("max_lateral_speed"),
            "{j}"
        );
        let back: Envelope = serde_json::from_str(&j).unwrap();
        assert_eq!(back, mecanum_env());
        // Wrong types are parse errors, not panics.
        for bad in [
            r#"{"holonomic":"yes"}"#,
            r#"{"max_lateral_speed":"fast"}"#,
            r#"{"max_vertical_speed":1e999}"#,
        ] {
            assert!(serde_json::from_str::<Envelope>(bad).is_err(), "{bad}");
        }
        // Holonomic declared in JSON without the limits: parses, refused by
        // validate.
        let p: Profile = serde_json::from_str(
            r#"{"model":"m","writer_topics":["/c"],"motion_envelopes":{"/c":{"max_linear_speed":1,"holonomic":true}}}"#,
        )
        .unwrap();
        assert_eq!(p.validate().unwrap_err().len(), 3);
    }
}

#[cfg(test)]
mod metadata_tests {
    use super::*;

    fn meta() -> ProfileMetadata {
        ProfileMetadata {
            schema_version: PROFILE_SCHEMA_VERSION,
            profile_version: 3,
            platform: "ugv-x1".into(),
            unit_id: Some("ugv-007".into()),
            locked_by: "A. Operator".into(),
            locked_at: 1_790_000_000,
            parent_digest: Some(format!("sha256:{}", "ab".repeat(32))),
            attestation: None,
        }
    }

    fn profile(m: Option<ProfileMetadata>) -> Profile {
        let mut p = Profile {
            model: "m".into(),
            locked: true,
            metadata: m,
            ..Default::default()
        };
        p.writer_topics.insert("/cmd_vel".into());
        p
    }

    #[test]
    fn valid_metadata_passes_and_roundtrips() {
        assert!(meta().validate().is_empty());
        let p = profile(Some(meta()));
        assert_eq!(p.validate(), Ok(()));
        let text = serde_json::to_string(&p).unwrap();
        assert_eq!(serde_json::from_str::<Profile>(&text).unwrap(), p);
        // Optional fields are written as null, never skipped.
        let mut m = meta();
        m.unit_id = None;
        m.parent_digest = None;
        let v = serde_json::to_value(&m).unwrap();
        assert!(v["unit_id"].is_null() && v["parent_digest"].is_null());
        assert!(m.validate().is_empty());
        // ... except the attestation, which is omitted when absent (older
        // locked files keep their exact bytes) and round-trips when set.
        assert!(v.get("attestation").is_none());
        m.attestation = Some(ProfileAttestation {
            signoff: "{}".into(),
            signatures: "{}".into(),
        });
        assert!(m.validate().is_empty());
        let back: ProfileMetadata =
            serde_json::from_str(&serde_json::to_string(&m).unwrap()).unwrap();
        assert_eq!(back, m);
    }

    #[test]
    fn absent_metadata_is_not_serialised() {
        let p = profile(None);
        assert!(!serde_json::to_string(&p).unwrap().contains("metadata"));
        assert_eq!(p.validate(), Ok(()));
        // Legacy JSON without the key still parses.
        let p: Profile = serde_json::from_str(r#"{"model":"m","locked":true}"#).unwrap();
        assert!(p.metadata.is_none());
    }

    #[test]
    fn every_bad_field_is_reported() {
        let m = ProfileMetadata {
            schema_version: 2,
            profile_version: 0,
            platform: "bad platform".into(),
            unit_id: Some(String::new()),
            locked_by: "x\u{1b}[31m".into(),
            locked_at: 0,
            parent_digest: Some("sha256:ABC".into()),
            attestation: Some(ProfileAttestation {
                signoff: " ".into(),
                signatures: "x".into(),
            }),
        };
        let errs = m.validate();
        assert_eq!(errs.len(), 8, "{errs:?}");
        assert!(errs.contains(&ProfileError::UnsupportedSchemaVersion {
            found: 2,
            supported: 1
        }));
        let fields: Vec<&str> = errs
            .iter()
            .filter_map(|e| match e {
                ProfileError::InvalidMetadata { field, .. } => Some(*field),
                _ => None,
            })
            .collect();
        assert_eq!(
            fields,
            [
                "profile_version",
                "platform",
                "unit_id",
                "locked_by",
                "locked_at",
                "parent_digest",
                "attestation"
            ]
        );
        // Profile::validate carries them.
        let p = profile(Some(m));
        assert_eq!(p.validate().unwrap_err().len(), 8);
        for e in errs {
            assert!(!e.to_string().is_empty());
        }
    }

    #[test]
    fn label_and_digest_edges() {
        assert!(is_sha256_digest(&format!("sha256:{}", "0".repeat(64))));
        assert!(!is_sha256_digest(&format!("sha256:{}", "0".repeat(63))));
        assert!(!is_sha256_digest(&format!("sha256:{}", "0".repeat(65))));
        assert!(!is_sha256_digest(&format!("SHA256:{}", "0".repeat(64))));
        assert!(!is_sha256_digest(&format!(
            "sha256:{}",
            "\u{e9}".repeat(32)
        )));
        assert!(is_label(&"a".repeat(MAX_LABEL_LEN)));
        assert!(!is_label(&"a".repeat(MAX_LABEL_LEN + 1)));
        assert!(!is_label("a/b"));
        let mut m = meta();
        m.locked_by = " ".into();
        assert_eq!(m.validate().len(), 1);
        m.locked_by = "x".repeat(MAX_LOCKED_BY_LEN + 1);
        assert_eq!(m.validate().len(), 1);
        m.locked_by = "x".repeat(MAX_LOCKED_BY_LEN);
        assert!(m.validate().is_empty());
        m.profile_version = u64::MAX;
        assert!(m.validate().is_empty());
    }
}
