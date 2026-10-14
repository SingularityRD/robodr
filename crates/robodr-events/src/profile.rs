//! The **model profile**: what a given robot model is allowed to do. It is
//! learned in observe mode during commissioning, then *locked* by the OEM.
//! Once locked, every event is checked against it and any deviation is a
//! signal. Robots are far more predictable than laptops, so an allowlist here
//! is tight enough to be useful rather than noisy.

use crate::graph::{Endpoint, Participant};
use crate::{Deviation, MotionCommand, RobotEvent, Severity};
use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;

/// A motion envelope: the limits a command may not exceed. `None` means the
/// dimension is not constrained for this model.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct Envelope {
    /// Max allowed linear speed, m/s.
    pub max_linear_speed: Option<f64>,
    /// Max allowed joint speed, rad/s.
    pub max_joint_speed: Option<f64>,
}

/// The locked profile for one robot model.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct Profile {
    /// Human label, e.g. "amr-forklift-v2".
    pub model: String,
    /// `true` once the OEM has locked it; while `false` RoboDR is in observe
    /// mode and reports deviations without ever proposing an action.
    #[serde(default)]
    pub locked: bool,
    /// GUID prefixes of participants that belong on this robot.
    #[serde(default)]
    pub participants: BTreeSet<String>,
    /// Topics a writer may publish to. A writer to any other topic is a signal.
    #[serde(default)]
    pub writer_topics: BTreeSet<String>,
    /// For each motion/control topic, the envelope its commands must stay in.
    #[serde(default)]
    pub motion_envelopes: std::collections::BTreeMap<String, Envelope>,
}

impl Profile {
    /// Decide whether an event deviates from this profile. `None` = within
    /// profile. The caller (Pulsar glue) decides what to do with a deviation;
    /// this function never acts and never mutates.
    pub fn evaluate(&self, event: &RobotEvent) -> Option<Deviation> {
        match event {
            RobotEvent::Ros2ParticipantDiscovered(p) => self.check_participant(p),
            RobotEvent::Ros2WriterDiscovered(e) => self.check_writer(e),
            // A new reader is lower risk than a new writer; it can exfiltrate
            // but cannot command. Report it, do not escalate.
            RobotEvent::Ros2ReaderDiscovered(e) => self.check_reader(e),
            RobotEvent::MotionCommand(c) => self.check_motion(c),
        }
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

    fn check_writer(&self, e: &Endpoint) -> Option<Deviation> {
        let topic = e.ros_topic();
        let known_participant = self.participants.contains(&e.guid_prefix);
        let publishes_motion = self.motion_envelopes.contains_key(topic);

        // A writer to a motion topic from a participant not in the profile is
        // the RoboPAIR / spoofed-command case: highest severity.
        if publishes_motion && !known_participant {
            return Some(Deviation::new(
                "robot.ros2.unauthorized_motion_writer",
                Severity::Critical,
                format!(
                    "participant {} not in profile is publishing motion topic {}",
                    e.guid_prefix, topic
                ),
            ));
        }
        if !self.writer_topics.contains(topic) {
            return Some(Deviation::new(
                "robot.ros2.unknown_writer_topic",
                Severity::High,
                format!("writer on unprofiled topic {} ({})", topic, e.guid_prefix),
            ));
        }
        None
    }

    fn check_reader(&self, e: &Endpoint) -> Option<Deviation> {
        if self.participants.contains(&e.guid_prefix) {
            return None;
        }
        Some(Deviation::new(
            "robot.ros2.unknown_reader",
            Severity::Medium,
            format!(
                "reader from unprofiled participant {} on {}",
                e.guid_prefix,
                e.ros_topic()
            ),
        ))
    }

    fn check_motion(&self, c: &MotionCommand) -> Option<Deviation> {
        let Some(env) = self.motion_envelopes.get(&c.channel) else {
            // A motion command on a channel with no envelope is itself odd.
            return Some(Deviation::new(
                "robot.motion.unprofiled_channel",
                Severity::High,
                format!("motion command on channel {} with no envelope", c.channel),
            ));
        };
        if let (Some(max), Some(v)) = (env.max_linear_speed, c.linear_speed) {
            if v > max {
                return Some(Deviation::new(
                    "robot.motion.linear_over_envelope",
                    Severity::Critical,
                    format!(
                        "linear speed {v:.3} m/s over envelope {max:.3} on {}",
                        c.channel
                    ),
                ));
            }
        }
        if let (Some(max), Some(v)) = (env.max_joint_speed, c.joint_speed) {
            if v > max {
                return Some(Deviation::new(
                    "robot.motion.joint_over_envelope",
                    Severity::Critical,
                    format!(
                        "joint speed {v:.3} rad/s over envelope {max:.3} on {}",
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

    fn profile() -> Profile {
        let mut p = Profile {
            model: "amr-v1".into(),
            locked: true,
            ..Default::default()
        };
        p.participants.insert("aaaaaaaaaaaaaaaaaaaaaaaa".into());
        p.writer_topics.insert("/cmd_vel".into());
        p.writer_topics.insert("/odom".into());
        p.motion_envelopes.insert(
            "/cmd_vel".into(),
            Envelope {
                max_linear_speed: Some(0.5),
                max_joint_speed: None,
            },
        );
        p
    }

    fn writer(guid: &str, topic: &str) -> RobotEvent {
        RobotEvent::Ros2WriterDiscovered(Endpoint {
            guid_prefix: guid.into(),
            topic: topic.into(),
            type_name: String::new(),
        })
    }

    #[test]
    fn known_participant_is_clean() {
        let got = profile().evaluate(&RobotEvent::Ros2ParticipantDiscovered(Participant {
            guid_prefix: "aaaaaaaaaaaaaaaaaaaaaaaa".into(),
            src_ip: "10.0.0.5".into(),
            locators: vec![],
        }));
        assert!(got.is_none());
    }

    #[test]
    fn unknown_participant_flagged_high() {
        let got = profile()
            .evaluate(&RobotEvent::Ros2ParticipantDiscovered(Participant {
                guid_prefix: "ffffffffffffffffffffffff".into(),
                src_ip: "10.0.0.9".into(),
                locators: vec![],
            }))
            .expect("should deviate");
        assert_eq!(got.rule, "robot.ros2.unknown_participant");
        assert_eq!(got.severity, Severity::High);
    }

    #[test]
    fn foreign_writer_on_motion_topic_is_critical() {
        // The spoofed-command case: not in profile, publishing rt/cmd_vel.
        let got = profile()
            .evaluate(&writer("ffffffffffffffffffffffff", "rt/cmd_vel"))
            .expect("should deviate");
        assert_eq!(got.rule, "robot.ros2.unauthorized_motion_writer");
        assert_eq!(got.severity, Severity::Critical);
    }

    #[test]
    fn known_writer_on_known_topic_is_clean() {
        assert!(profile()
            .evaluate(&writer("aaaaaaaaaaaaaaaaaaaaaaaa", "rt/cmd_vel"))
            .is_none());
    }

    #[test]
    fn speed_over_envelope_is_critical() {
        let got = profile()
            .evaluate(&RobotEvent::MotionCommand(MotionCommand {
                channel: "/cmd_vel".into(),
                source_guid: Some("aaaaaaaaaaaaaaaaaaaaaaaa".into()),
                linear_speed: Some(2.5),
                joint_speed: None,
            }))
            .expect("should deviate");
        assert_eq!(got.rule, "robot.motion.linear_over_envelope");
        assert_eq!(got.severity, Severity::Critical);
    }

    #[test]
    fn speed_within_envelope_is_clean() {
        assert!(profile()
            .evaluate(&RobotEvent::MotionCommand(MotionCommand {
                channel: "/cmd_vel".into(),
                source_guid: None,
                linear_speed: Some(0.4),
                joint_speed: None,
            }))
            .is_none());
    }
}
