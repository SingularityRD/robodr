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
//! Critical `unauthorized_motion_writer`. `raw_dds_topics` is exempt (raw DDS
//! names are arbitrary; only empty entries are rejected).
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
//! in this order and the first hit is returned: non-finite command (Critical),
//! unprofiled channel (High), invalid envelope limit (High, profile error),
//! linear over envelope (Critical), joint over envelope (Critical). `None` as a
//! limit means "not constrained"; use `None`, not `+inf`, for that.
//!
//! # Limits
//!
//! `evaluate` returns at most one deviation per event and is stateless:
//! rate-of-change, command/feedback consistency and command provenance are
//! the job of `robodr-motion`. Writers from unknown participants on profiled
//! non-motion topics/services are reported only via the participant rule.

use crate::graph::{
    demangle, validate_full_name, ActionRole, Endpoint, Participant, RosName, RosNameIssue,
    RosNameKind,
};
use crate::{Deviation, Mode, MotionCommand, RobotEvent, Severity};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};
use std::fmt;

/// A motion envelope: the limits a command may not exceed. `None` means the
/// dimension is not constrained for this model. A limit must be finite and
/// `>= 0`; anything else is a profile error (see [`Profile::validate`]).
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct Envelope {
    /// Max allowed linear speed, m/s.
    pub max_linear_speed: Option<f64>,
    /// Max allowed joint speed, rad/s.
    pub max_joint_speed: Option<f64>,
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
}

impl EnvelopeField {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::MaxLinearSpeed => "max_linear_speed",
            Self::MaxJointSpeed => "max_joint_speed",
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
            for (field, lim) in [
                (EnvelopeField::MaxLinearSpeed, env.max_linear_speed),
                (EnvelopeField::MaxJointSpeed, env.max_joint_speed),
            ] {
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
        let publishes_motion = topic_transport && self.motion_envelopes.contains_key(&rn.name);

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
        // 1. Hostile floats first: NaN compares false with everything, so it
        //    must never reach a `>` check.
        for (dim, v) in [("linear", c.linear_speed), ("joint", c.joint_speed)] {
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
        //    reported for every command on the channel.
        for (field, lim) in [
            (EnvelopeField::MaxLinearSpeed, env.max_linear_speed),
            (EnvelopeField::MaxJointSpeed, env.max_joint_speed),
        ] {
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
        // 3. Magnitudes: compare |v| so a signed value cannot slip under.
        if let (Some(max), Some(v)) = (env.max_linear_speed, c.linear_speed) {
            if v.abs() > max {
                return Some(Deviation::new(
                    "robot.motion.linear_over_envelope",
                    Severity::Critical,
                    format!(
                        "linear speed {v:.3} m/s (|{:.3}|) over envelope {max:.3} on {}",
                        v.abs(),
                        c.channel
                    ),
                ));
            }
        }
        if let (Some(max), Some(v)) = (env.max_joint_speed, c.joint_speed) {
            if v.abs() > max {
                return Some(Deviation::new(
                    "robot.motion.joint_over_envelope",
                    Severity::Critical,
                    format!(
                        "joint speed {v:.3} rad/s (|{:.3}|) over envelope {max:.3} on {}",
                        v.abs(),
                        c.channel
                    ),
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
        })
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
            timestamp_ns: 0,
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
        for raw in ["rt//cmd_vel", "cmd vel", "/x/", "1abc", "rt/cmd_vel"] {
            p.raw_dds_topics.insert(raw.into());
        }
        assert_eq!(p.validate(), Ok(()));
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
