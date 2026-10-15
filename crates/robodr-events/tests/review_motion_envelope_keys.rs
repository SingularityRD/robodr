//! Regression for review finding (wave 2, safety, MEDIUM): motion envelope
//! keys were not validated as de-mangled ROS names. A profile keyed `cmd_vel`,
//! `rt/cmd_vel` or `/cmd_vel/` passed `validate()`, and a FOREIGN participant
//! writing the real motion topic `rt/cmd_vel` then raised nothing (the correct
//! key `/cmd_vel` gives Critical `unauthorized_motion_writer`).
//!
//! Fixed behaviour: such profiles fail validation (and so are never loaded for
//! enforcement), and malformed wire names such as `rt//cmd_vel` are classified
//! as raw DDS instead of matching `/cmd_vel`.

use robodr_events::graph::{demangle, Endpoint, RosNameIssue, RosNameKind};
use robodr_events::profile::{Envelope, Profile, ProfileError};
use robodr_events::{RobotEvent, Severity};

const KNOWN: &str = "aaaaaaaaaaaaaaaaaaaaaaaa";
const FOREIGN: &str = "ffffffffffffffffffffffff";

fn prof(env_key: &str) -> Profile {
    let mut p = Profile {
        model: "m".into(),
        locked: true,
        ..Default::default()
    };
    p.participants.insert(KNOWN.into());
    p.writer_topics.insert("/cmd_vel".into());
    p.motion_envelopes.insert(
        env_key.into(),
        Envelope {
            max_linear_speed: Some(0.5),
            max_joint_speed: None,
        },
    );
    p
}

fn foreign_writer(topic: &str) -> RobotEvent {
    RobotEvent::Ros2WriterDiscovered(Endpoint {
        guid_prefix: FOREIGN.into(),
        topic: topic.into(),
        type_name: String::new(),
    })
}

#[test]
fn non_ros_envelope_keys_are_rejected_by_validate() {
    for (key, want) in [
        (
            "cmd_vel",
            ProfileError::NotARosName {
                set: "motion_envelopes",
                name: "cmd_vel".into(),
            },
        ),
        (
            "rt/cmd_vel",
            ProfileError::NotARosName {
                set: "motion_envelopes",
                name: "rt/cmd_vel".into(),
            },
        ),
        (
            "/cmd_vel/",
            ProfileError::MalformedRosName {
                set: "motion_envelopes",
                name: "/cmd_vel/".into(),
                issue: RosNameIssue::EndsWithSlash,
            },
        ),
    ] {
        let errs = prof(key).validate().unwrap_err();
        assert_eq!(errs, vec![want], "key {key:?}");
    }
}

#[test]
fn correct_key_validates_and_flags_foreign_motion_writer() {
    let p = prof("/cmd_vel");
    assert_eq!(p.validate(), Ok(()));
    let d = p.evaluate(&foreign_writer("rt/cmd_vel")).unwrap();
    assert_eq!(d.rule, "robot.ros2.unauthorized_motion_writer");
    assert_eq!(d.severity, Severity::Critical);
}

#[test]
fn malformed_wire_name_is_raw_not_the_ros_topic() {
    for t in ["rt//cmd_vel", "rt/cmd_vel/"] {
        assert_eq!(demangle(t).kind, RosNameKind::Raw, "{t}");
        let d = prof("/cmd_vel").evaluate(&foreign_writer(t)).unwrap();
        assert_eq!(d.rule, "robot.dds.unknown_raw_writer", "{t}");
    }
}

#[test]
fn writer_topic_entries_are_checked_too() {
    let mut p = prof("/cmd_vel");
    p.writer_topics.insert("/cmd_vel/".into());
    p.reader_topics.insert("//odom".into());
    let errs = p.validate().unwrap_err();
    assert_eq!(errs.len(), 2, "{errs:?}");
    assert!(errs.contains(&ProfileError::MalformedRosName {
        set: "writer_topics",
        name: "/cmd_vel/".into(),
        issue: RosNameIssue::EndsWithSlash,
    }));
    assert!(errs.contains(&ProfileError::MalformedRosName {
        set: "reader_topics",
        name: "//odom".into(),
        issue: RosNameIssue::RepeatedSlash,
    }));
}
