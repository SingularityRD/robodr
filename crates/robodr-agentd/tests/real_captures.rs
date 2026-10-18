//! The daemon on real ROS 2 Jazzy captures (`fixtures/captures/ros2-jazzy`):
//! profile learned from the baseline run (with participant identities),
//! Motion Firewall allowing `identity:teleop_twist` on `/cmd_vel`, motion
//! monitor on `/odom`.

mod common;

use common::*;
use robodr_agentd::StopReason;
use robodr_commission::{LearnConfig, Learner, PcapSource};
use std::path::PathBuf;

fn fixture(name: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../fixtures/captures/ros2-jazzy")
        .join(name)
}

fn learned(vendor: &str) -> robodr_events::profile::Profile {
    let mut l = Learner::new(LearnConfig {
        model: "lab-ugv".into(),
        ..LearnConfig::default()
    })
    .unwrap();
    l.ingest(&mut PcapSource::open(&fixture(&format!("{vendor}_baseline.pcap"))).unwrap())
        .unwrap();
    l.finish().profile
}

/// Run the daemon over one capture; the spooled rule ids.
fn run(vendor: &str, file: &str) -> Vec<String> {
    let s = setup(&format!("real-{vendor}-{file}"), &learned(vendor));
    let mut cfg = s.config(
        serde_json::json!({
            "capture": {"enabled": true, "pcap_replay": fixture(file)},
            "motion": {"feedback_topics": ["/odom"]},
        }),
        serde_json::json!([]),
        serde_json::json!({"exit_when_inputs_end": true}),
    );
    cfg["firewall"] = serde_json::json!({
        "max_angular": {"/cmd_vel": 1.0},
        "allow": {"/cmd_vel": ["identity:teleop_twist"]},
    });
    cfg["motion_monitor"] = serde_json::json!({"feedback_sources": {"/odom": "wheel_odometry"}});
    let r = s.resolve(&cfg);
    let mut log = Vec::new();
    let sum = robodr_agentd::run(&r, &|| false, &mut log).unwrap();
    let log = String::from_utf8(log).unwrap();
    assert_eq!(sum.reason, StopReason::InputsEnded, "{log}");
    assert!(
        sum.stats.motion_events > 50,
        "{vendor}/{file}: {:?}\n{log}",
        sum.stats
    );
    let found = spooled(&s.spool);
    assert_verified(&s.blackbox, Some(sum.finished.checkpoint.clone()), &found);
    rules(&found)
}

#[test]
fn the_legitimate_teleop_is_authorised_by_its_identity() {
    for v in ["fastrtps", "cyclonedds"] {
        let rules = run(v, &format!("{v}_baseline.pcap"));
        // Only the teleop leaving at the end of the capture.
        let notable: Vec<&String> = rules
            .iter()
            .filter(|r| r.as_str() != "robot.rtps.discovery_removal")
            .collect();
        assert_eq!(
            notable,
            ["robot.ros2.participant_removed"],
            "{v}: {rules:?}"
        );
    }
}

#[test]
fn the_rogue_is_rejected_and_the_restarted_teleop_is_not() {
    for v in ["fastrtps", "cyclonedds"] {
        let rules = run(v, &format!("{v}_rogue_cmd_vel.pcap"));
        let count = |r: &str| rules.iter().filter(|x| x.as_str() == r).count();
        for r in [
            "robot.ros2.unknown_participant",
            "robot.ros2.unauthorized_motion_writer",
        ] {
            assert_eq!(count(r), 1, "{v}: {r}: {rules:?}");
        }
        // The rogue sends ~75 commands at 3.0 m/s: each is over the
        // envelope and from an unknown source. The teleop (new prefix,
        // same identity) is never rejected: rejections == rogue commands.
        let over = count("robot.motion.linear_over_envelope");
        let rejected = count("robot.firewall.rejected_unknown_source");
        assert!(over > 50, "{v}: {over}");
        assert_eq!(rejected, over, "{v}: {rules:?}");
        assert!(
            !rules
                .iter()
                .any(|r| r.starts_with("robot.motion.") && r != "robot.motion.linear_over_envelope"),
            "{v}: motion monitor false positive: {rules:?}"
        );
    }
}
