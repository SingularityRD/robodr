//! Shared fixtures for the integration tests.
#![allow(dead_code)]

use robodr_events::graph::{Endpoint, Participant};
use robodr_events::{Deviation, MotionCommand, RobotEvent, Severity};
use robodr_ocsf::*;

pub const T0: u64 = 1_790_000_000_000; // 2026-09-21T14:13:20Z

pub fn ctx() -> RobotContext {
    let mut c = RobotContext::new(
        RobotInfo {
            id: "ugv-007".into(),
            model: "ugv-tracked-v1".into(),
            platform_family: PlatformFamily::LinuxRos2,
            site: "range-north".into(),
            firmware: Some(FirmwareRef {
                version: "2.4.1".into(),
                sha256: "1f".repeat(32),
            }),
        },
        ProfileRef {
            version: "7".into(),
            sha256: "c0".repeat(32),
        },
        Mode::Enforce,
    );
    // Pin the product version so the golden example does not churn with
    // every crate version bump.
    c.product_version = "0.1.0-alpha.1".into();
    c
}

pub fn writer(topic: &str) -> Endpoint {
    Endpoint {
        guid_prefix: "0102030405060708090a0b0c".into(),
        topic: topic.into(),
        type_name: "geometry_msgs::msg::dds_::Twist_".into(),
    }
}

pub fn participant(guid: &str, ip: &str) -> Participant {
    Participant {
        guid_prefix: guid.into(),
        src_ip: ip.into(),
        locators: vec![],
    }
}

pub fn motion(channel: &str, linear: Option<f64>) -> MotionCommand {
    MotionCommand {
        channel: channel.into(),
        source_guid: Some("0102030405060708090a0b0c".into()),
        linear_speed: linear,
        joint_speed: None,
    }
}

/// The finding used for the contract example (docs/contracts).
pub fn example_finding() -> FindingEnvelope {
    let ctx = ctx();
    let e = writer("rt/cmd_vel");
    let dev = Deviation::new(
        "robot.ros2.unauthorized_motion_writer",
        Severity::Critical,
        format!(
            "participant {} not in profile publishes to motion topic {}",
            e.guid_prefix,
            e.ros_topic()
        ),
    );
    FindingBuilder::from_deviation(&dev, &ctx)
        .event(&RobotEvent::Ros2WriterDiscovered(e))
        .seen(T0, T0 + 4_250)
        .occurrences(3)
        .safety_state(SafetyState {
            motion: MotionState::Moving,
            human_proximity: HumanProximity::NotDetected,
        })
        .attestation(AttestationStatus::Verified)
        .evidence(BlackBoxRef {
            segment: 12,
            seq: 40_118,
            sha256: "9e".repeat(32),
        })
        .evidence(BlackBoxRef {
            segment: 12,
            seq: 40_117,
            sha256: "8d".repeat(32),
        })
        .build()
        .expect("example finding is valid")
}
