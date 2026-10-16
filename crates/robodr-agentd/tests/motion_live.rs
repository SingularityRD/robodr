//! Live motion path, end to end in process: a synthetic pcap carrying RTPS
//! user DATA (CDR `Twist` on `rt/cmd_vel`, CDR `Odometry` on `rt/odom`) ->
//! daemon -> pipeline decode -> agent (profile envelope, recording-only
//! Motion Firewall, motion monitor) -> spool + black box.
//!
//! All traffic is hand-built from the DDSI-RTPS / XCDR specs (no capture of
//! a real RMW).

mod common;

#[path = "../../robodr-cdr/tests/common/mod.rs"]
mod cdrenc;

use common::pcap::*;
use common::*;
use robodr_agentd::StopReason;
use robodr_events::Severity;

fn odom(vx: f64) -> Vec<u8> {
    cdrenc::odometry(
        robodr_cdr::Representation::CdrLe,
        &cdrenc::OdomSpec {
            frame: b"odom",
            child: b"base_link",
            position: [0.0; 3],
            orientation: [0.0, 0.0, 0.0, 1.0],
            pose_cov: [0.0; 36],
            lin: [vx, 0.0, 0.0],
            ang: [0.0; 3],
            twist_cov: [0.0; 36],
        },
    )
}

fn frames() -> Vec<Vec<u8>> {
    let unicast = |d: &[u8]| frame(ROBOT_IP, ROBOT_IP, 7411, d);
    vec![
        frame(ROBOT_IP, SPDP_GROUP, 7400, &motion_discovery()),
        // In envelope (profile: /cmd_vel max 1.0 m/s) ...
        unicast(&cmd_vel_datagram(LEGIT, CMD_WRITER, 1, 0.4)),
        unicast(&datagram(
            LEGIT,
            &[user_data(ODOM_WRITER, [0; 4], 1, &odom(0.4), true)],
        )),
        // ... then over it.
        unicast(&cmd_vel_datagram(LEGIT, CMD_WRITER, 2, 2.5)),
    ]
}

#[test]
fn over_envelope_command_on_the_wire_reaches_spool_and_black_box() {
    let s = setup("motion", &robot_profile(true));
    let pcap = s.pcap(&frames());
    let mut cfg = s.config(
        serde_json::json!({"capture": {"enabled": true, "pcap_replay": pcap}}),
        serde_json::json!([]),
        serde_json::json!({"exit_when_inputs_end": true}),
    );
    cfg["firewall"] = serde_json::json!({"max_angular": {"/cmd_vel": 1.0}});
    // `/odom` is decoded from the bus because the monitor lists it.
    cfg["motion_monitor"] = serde_json::json!({"feedback_sources": {"/odom": "wheel_odometry"}});
    let r = s.resolve(&cfg);
    assert!(r.sensor.pipeline.motion.feedback_topics.contains("/odom"));
    let mut log = Vec::new();
    let sum = robodr_agentd::run(&r, &|| false, &mut log).unwrap();
    let log = String::from_utf8(log).unwrap();
    assert_eq!(sum.reason, StopReason::InputsEnded, "{log}");
    assert_eq!(sum.stats.datagrams, 4, "{log}");
    assert_eq!(
        sum.stats.motion_events, 3,
        "two commands + one odometry\n{log}"
    );
    assert_eq!(sum.pipeline.motion.commands, 2);
    assert_eq!(sum.pipeline.motion.feedback, 1);
    assert_eq!(sum.pipeline.motion.undecodable, 0);
    assert!(sum.agent.firewall_checks >= 2, "{:?}", sum.agent);

    let found = spooled(&s.spool);
    let rules = rules(&found);
    // Exactly one envelope finding (the 2.5 m/s command; the pipeline's own
    // evaluation is off in the daemon, so it is not reported twice).
    let over: Vec<_> = found
        .iter()
        .filter(|(_, e)| e.entity_context.rule_id == "robot.motion.linear_over_envelope")
        .collect();
    assert_eq!(over.len(), 1, "{rules:?}\n{log}");
    let env = &over[0].1;
    assert_eq!(env.severity, Severity::Critical);
    assert_eq!(env.entity_context.robot.id, ROBOT);
    // Evidence: the event record is linked and verifies.
    assert!(!env.evidence_links.is_empty());
    assert_verified(&s.blackbox, Some(sum.finished.checkpoint.clone()), &found);
    // No discovery findings for the legit graph.
    assert!(
        !rules.iter().any(|r| r.starts_with("robot.ros2.")),
        "{rules:?}"
    );

    // Black box: the decoded command itself (with its writer GUID) ...
    assert!(notes_with(&s.blackbox, "\"kind\":\"motion_command\"") >= 1);
    assert!(notes_with(&s.blackbox, "\"linear_speed\":2.5") >= 1);
    assert!(notes_with(&s.blackbox, "aaaaaaaaaaaaaaaaaaaaaaaa00001003") >= 1);
    // ... and the firewall verdict, recorded as a would-have (not inline).
    assert!(notes_with(&s.blackbox, "robodr.firewall_verdict") >= 1);
    assert!(notes_with(&s.blackbox, "\"enforcing\":false") >= 1);
    assert_eq!(notes_with(&s.blackbox, "\"enforcing\":true"), 0);

    let st = status(&s.spool).unwrap();
    assert_eq!(st["daemon"]["motion_events"], 3);
    assert_eq!(st["pipeline"]["motion"]["commands"], 2);
}

#[test]
fn garbage_on_a_motion_topic_is_reported_not_fatal() {
    let s = setup("motion-garbage", &robot_profile(true));
    let unicast = |d: &[u8]| frame(ROBOT_IP, ROBOT_IP, 7411, d);
    let pcap = s.pcap(&[
        frame(ROBOT_IP, SPDP_GROUP, 7400, &motion_discovery()),
        unicast(&datagram(
            LEGIT,
            &[user_data(
                CMD_WRITER,
                CMD_READER,
                1,
                &[0x00, 0x01, 0, 0, 9],
                true,
            )],
        )),
        unicast(&cmd_vel_datagram(LEGIT, CMD_WRITER, 2, 0.2)),
    ]);
    let cfg = s.config(
        serde_json::json!({"capture": {"enabled": true, "pcap_replay": pcap}}),
        serde_json::json!([]),
        serde_json::json!({"exit_when_inputs_end": true}),
    );
    let r = s.resolve(&cfg);
    let mut log = Vec::new();
    let sum = robodr_agentd::run(&r, &|| false, &mut log).unwrap();
    let log = String::from_utf8(log).unwrap();
    let found = spooled(&s.spool);
    let rules = rules(&found);
    assert_eq!(
        rules,
        vec!["robot.motion.undecodable_sample".to_string()],
        "{log}"
    );
    assert_eq!(found[0].1.severity, Severity::Medium);
    assert_eq!(sum.stats.motion_events, 1, "the good command still flows");
    assert_verified(&s.blackbox, Some(sum.finished.checkpoint), &found);
}

#[test]
fn sensor_motion_keys_are_strict() {
    let s = setup("motion-cfg", &robot_profile(true));
    let mut cfg = s.config(
        serde_json::json!({"motion": {"feedback_topics": ["/odom"], "max_writers": 64}}),
        serde_json::json!([{"kind": "stdin"}]),
        serde_json::json!({}),
    );
    let r = robodr_agentd::load(&s.write_config(&cfg)).unwrap();
    assert_eq!(r.sensor.pipeline.motion.max_writers, 64);
    cfg["sensor"]["motion"]["feedback_topic"] = serde_json::json!(["/odom"]);
    let e = robodr_agentd::load(&s.write_config(&cfg)).unwrap_err();
    assert!(e.contains("sensor.motion: unknown key"), "{e}");
    cfg["sensor"]["motion"] = serde_json::json!({"feedback_topics": ["odom"]});
    assert!(robodr_agentd::load(&s.write_config(&cfg)).is_err());
    // A non-ROS feedback source name is only a warning (JSONL only).
    cfg["sensor"]["motion"] = serde_json::json!({});
    cfg["motion_monitor"] = serde_json::json!({"feedback_sources": {"can0": "wheel_odometry"}});
    let r = robodr_agentd::load(&s.write_config(&cfg)).unwrap();
    assert!(r.sensor.pipeline.motion.feedback_topics.is_empty());
    assert!(
        r.warnings.iter().any(|w| w.contains("can0")),
        "{:?}",
        r.warnings
    );
}

/// A command whose source the binding refuses (here: the legit prefix and
/// writer GUID, sent from another host) is never authorised by its claimed
/// GUID: the pipeline reports the mismatch and the firewall model sees an
/// unknown source.
#[test]
fn a_refused_source_never_authorises_a_command_by_its_guid() {
    let s = setup("motion-refused", &robot_profile(true));
    let pcap = s.pcap(&[
        frame(ROBOT_IP, SPDP_GROUP, 7400, &motion_discovery()),
        // Bound source: authorised, no finding.
        frame(
            ROBOT_IP,
            ROBOT_IP,
            7411,
            &cmd_vel_datagram(LEGIT, CMD_WRITER, 1, 0.2),
        ),
        // Spoofed: legit prefix + writer, rogue IP.
        frame(
            ROGUE_IP,
            ROBOT_IP,
            7411,
            &cmd_vel_datagram(LEGIT, CMD_WRITER, 2, 0.2),
        ),
    ]);
    let mut cfg = s.config(
        serde_json::json!({"capture": {"enabled": true, "pcap_replay": pcap}}),
        serde_json::json!([]),
        serde_json::json!({"exit_when_inputs_end": true}),
    );
    cfg["firewall"] = serde_json::json!({"max_angular": {"/cmd_vel": 1.0}});
    let r = s.resolve(&cfg);
    let mut log = Vec::new();
    let sum = robodr_agentd::run(&r, &|| false, &mut log).unwrap();
    let log = String::from_utf8(log).unwrap();
    assert_eq!(sum.stats.motion_events, 2, "{log}");
    let rules = rules(&spooled(&s.spool));
    assert!(
        rules.contains(&"robot.motion.sample_source_mismatch".to_string()),
        "{rules:?}\n{log}"
    );
    let unknown = rules
        .iter()
        .filter(|r| *r == "robot.firewall.rejected_unknown_source")
        .count();
    assert_eq!(unknown, 1, "only the spoofed command: {rules:?}\n{log}");
    assert!(
        !rules
            .iter()
            .any(|r| r == "robot.firewall.rejected_unauthorized_source"),
        "{rules:?}"
    );
}
