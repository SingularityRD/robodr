//! The daemon on the lab captures (`fixtures/captures/ros2-jazzy/README.md`):
//! a headless Gazebo robot whose /odom crosses the wire (the motion monitor
//! sees real simulated feedback), and a robot on rmw_zenoh (no RTPS).

mod common;

use common::*;
use robodr_agentd::{State, StopReason, Summary};
use robodr_commission::{LearnConfig, Learner, PcapSource};
use robodr_events::Severity;
use robodr_ocsf::FindingEnvelope;
use std::collections::BTreeMap;
use std::path::PathBuf;

fn fixture(name: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../fixtures/captures/ros2-jazzy")
        .join(name)
}

fn learned(file: &str) -> robodr_events::profile::Profile {
    let mut l = Learner::new(LearnConfig {
        model: "lab-ugv".into(),
        ..LearnConfig::default()
    })
    .unwrap();
    l.ingest(&mut PcapSource::open(&fixture(file)).unwrap())
        .unwrap();
    l.finish().profile
}

/// Run the daemon over one capture: the summary, the spooled rule ids
/// with their counts and the spooled findings.
fn run(learn_from: &str, file: &str) -> (Summary, BTreeMap<String, usize>, Vec<FindingEnvelope>) {
    let s = setup(&format!("lab-{file}"), &learned(learn_from));
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
    assert_eq!(sum.reason, StopReason::InputsEnded);
    let found = spooled(&s.spool);
    assert_verified(&s.blackbox, Some(sum.finished.checkpoint.clone()), &found);
    let mut counts = BTreeMap::new();
    for r in rules(&found) {
        *counts.entry(r).or_insert(0) += 1;
    }
    (sum, counts, found.into_iter().map(|(_, e)| e).collect())
}

#[test]
fn gazebo_baseline_with_live_feedback_raises_nothing_but_the_teleop_leaving() {
    for v in ["fastrtps", "cyclonedds"] {
        let f = format!("{v}_gz_baseline.pcap");
        let (sum, counts, _) = run(&f, &f);
        assert!(sum.stats.motion_events > 500, "{v}: {:?}", sum.stats);
        let notable: Vec<&String> = counts
            .keys()
            .filter(|r| r.as_str() != "robot.rtps.discovery_removal")
            .collect();
        assert_eq!(
            notable,
            ["robot.ros2.participant_removed"],
            "{v}: {counts:?}"
        );
    }
}

#[test]
fn gazebo_rogue_commands_are_rejected_and_the_monitor_stays_quiet() {
    for v in ["fastrtps", "cyclonedds"] {
        let (_, counts, found) = run(
            &format!("{v}_gz_baseline.pcap"),
            &format!("{v}_gz_rogue_cmd_vel.pcap"),
        );
        let c = |r: &str| counts.get(r).copied().unwrap_or(0);
        assert_eq!(c("robot.ros2.unknown_participant"), 1, "{v}: {counts:?}");
        assert_eq!(c("robot.ros2.unauthorized_motion_writer"), 1, "{v}");
        let over = c("robot.motion.linear_over_envelope");
        assert!(over > 20, "{v}: {over}");
        assert_eq!(c("robot.firewall.rejected_unknown_source"), over, "{v}");
        // The pcap is replayed unpaced and the monitor runs on the daemon's
        // clock, so its timeline is the host's processing speed: the
        // capture's ~16 s take a few ms here, ~16 s on a slow host. Near
        // real time the monitor sees what the robot really did: the rogue's
        // 3.0 m/s (rejected by the firewall in observe mode, i.e. still
        // delivered) interleaved with the teleop's 0.3 m/s predicts more
        // speed than the simulated odometry shows, one under-motion
        // divergence (Medium), correlated with the rejection as a motion
        // hijack. That is a legitimate detection (the baseline at the same
        // pace stays quiet), allowed but not required; anything else from
        // the monitor (opposite direction, uncommanded, frozen, ...) is not.
        let allowed = [
            "robot.motion.linear_over_envelope",
            "robot.motion.feedback_divergence",
        ];
        assert!(
            !counts
                .keys()
                .any(|r| r.starts_with("robot.motion.") && !allowed.contains(&r.as_str())),
            "{v}: {counts:?}"
        );
        let div = c("robot.motion.feedback_divergence");
        assert!(div <= 1, "{v}: {counts:?}");
        for e in found
            .iter()
            .filter(|e| e.entity_context.rule_id == "robot.motion.feedback_divergence")
        {
            assert_eq!(e.severity, Severity::Medium, "{v}");
            assert!(
                e.entity_context
                    .detail
                    .value
                    .contains("robot moving less than commanded"),
                "{v}: {}",
                e.entity_context.detail.value
            );
        }
        assert_eq!(c("robot.correlate.motion_hijack"), div, "{v}: {counts:?}");
    }
}

#[test]
fn two_odometry_publishers_merged_into_one_writer_are_noticed() {
    // The upstream ros_gz_sim_demos vehicle world publishes DiffDrive (1 Hz)
    // and OdometryPublisher (50 Hz) odometry on the same Gazebo topic; the
    // bridge merges them into one ROS writer, so every second two samples
    // carry the same stamp. The monitor reports the duplicate stamp (and,
    // since the grace window, no longer an unattributed sample).
    let (_, counts, _) = run("fastrtps_gz_baseline.pcap", "fastrtps_gz_dual_odom.pcap");
    assert_eq!(
        counts.get("robot.motion.frozen_feedback"),
        Some(&1),
        "{counts:?}"
    );
    assert!(
        !counts.contains_key("robot.motion.unattributed_sample"),
        "{counts:?}"
    );
}

#[test]
fn a_zenoh_bus_is_reported_and_never_ok() {
    let (sum, counts, _) = run("fastrtps_baseline.pcap", "zenoh_rogue_cmd_vel.pcap");
    assert_eq!(
        counts.get("robot.capture.unsupported_middleware"),
        Some(&1),
        "{counts:?}"
    );
    assert_ne!(sum.last_state.state, State::Ok);
}
