//! The daemon on the lab captures (`fixtures/captures/ros2-jazzy/README.md`):
//! a headless Gazebo robot whose /odom crosses the wire (the motion monitor
//! sees real simulated feedback), and a robot on rmw_zenoh (no RTPS).
//!
//! A replay is judged on the capture's own packet timeline, not on how fast
//! the daemon reads the file (`robodr_agentd::daemon`, "Live motion data"),
//! so every count below is exact and independent of host load.

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

/// Run the daemon over one capture: the summary and the spooled rule ids
/// with their counts.
fn run(learn_from: &str, file: &str) -> (Summary, BTreeMap<String, usize>) {
    let (sum, counts, _) = run_found(learn_from, file);
    (sum, counts)
}

/// [`run`], also returning every spooled finding.
fn run_found(
    learn_from: &str,
    file: &str,
) -> (Summary, BTreeMap<String, usize>, Vec<FindingEnvelope>) {
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
        let (sum, counts) = run(&f, &f);
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

/// The rogue (3.0 m/s) and the operator (0.3 m/s) both publish `/cmd_vel`
/// at 10 Hz from about 9 s on; the simulated robot ends up between the two
/// (fixtures/captures/ros2-jazzy/README.md, second set, 8). On the
/// captures' own timelines the motion monitor's command model (both
/// writers' commands, acceleration-limited) expects more speed than the
/// robot makes: in the Fast DDS run that leaves the tolerance once, for
/// longer than the persistence window (one Medium under-motion
/// `feedback_divergence`, 0.41 m/s against a band starting at 0.43); in the
/// Cyclone DDS run it stays inside. Before replays were judged on their
/// packet timestamps this depended on how fast the host read the file.
#[test]
fn gazebo_rogue_commands_are_rejected_and_the_monitor_reports_the_fight_exactly() {
    for (v, divergences) in [("fastrtps", 1), ("cyclonedds", 0)] {
        let (_, counts, found) = run_found(
            &format!("{v}_gz_baseline.pcap"),
            &format!("{v}_gz_rogue_cmd_vel.pcap"),
        );
        let c = |r: &str| counts.get(r).copied().unwrap_or(0);
        assert_eq!(c("robot.ros2.unknown_participant"), 1, "{v}: {counts:?}");
        assert_eq!(c("robot.ros2.unauthorized_motion_writer"), 1, "{v}");
        let over = c("robot.motion.linear_over_envelope");
        assert!(over > 20, "{v}: {over}");
        assert_eq!(c("robot.firewall.rejected_unknown_source"), over, "{v}");
        assert_eq!(
            c("robot.motion.feedback_divergence"),
            divergences,
            "{v}: {counts:?}"
        );
        for f in found
            .iter()
            .filter(|f| f.entity_context.rule_id == "robot.motion.feedback_divergence")
        {
            assert_eq!(f.severity, Severity::Medium, "{v}");
            assert!(
                f.entity_context
                    .detail
                    .value
                    .contains("robot moving less than commanded"),
                "{v}: {}",
                f.entity_context.detail.value
            );
        }
        assert!(
            !counts.keys().any(|r| r.starts_with("robot.motion.")
                && r != "robot.motion.linear_over_envelope"
                && r != "robot.motion.feedback_divergence"),
            "{v}: {counts:?}"
        );
    }
}

/// The same capture replayed twice gives the same findings, rule by rule
/// and detail by detail (each run is a separate daemon with its own
/// clock; only the packet timeline is shared).
#[test]
fn a_replay_is_judged_on_its_packet_timeline_not_on_reading_speed() {
    let details = |found: &[FindingEnvelope]| -> Vec<(String, String)> {
        let mut v: Vec<(String, String)> = found
            .iter()
            .filter(|f| f.entity_context.rule_id.starts_with("robot.motion."))
            .map(|f| {
                (
                    f.entity_context.rule_id.clone(),
                    f.entity_context.detail.value.clone(),
                )
            })
            .collect();
        v.sort();
        v
    };
    let a = run_found(
        "fastrtps_gz_baseline.pcap",
        "fastrtps_gz_rogue_cmd_vel.pcap",
    );
    let b = run_found(
        "fastrtps_gz_baseline.pcap",
        "fastrtps_gz_rogue_cmd_vel.pcap",
    );
    assert_eq!(a.1, b.1);
    assert_eq!(details(&a.2), details(&b.2));
}

#[test]
fn two_odometry_publishers_merged_into_one_writer_are_noticed() {
    // The upstream ros_gz_sim_demos vehicle world publishes DiffDrive (1 Hz)
    // and OdometryPublisher (50 Hz) odometry on the same Gazebo topic; the
    // bridge merges them into one ROS writer, so every second two samples
    // carry the same stamp. The monitor reports the duplicate stamp (and,
    // since the grace window, no longer an unattributed sample).
    let (_, counts) = run("fastrtps_gz_baseline.pcap", "fastrtps_gz_dual_odom.pcap");
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
    let (sum, counts) = run("fastrtps_baseline.pcap", "zenoh_rogue_cmd_vel.pcap");
    assert_eq!(
        counts.get("robot.capture.unsupported_middleware"),
        Some(&1),
        "{counts:?}"
    );
    assert_ne!(sum.last_state.state, State::Ok);
}
