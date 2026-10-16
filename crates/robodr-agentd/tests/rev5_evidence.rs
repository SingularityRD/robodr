//! rev5 wiring: what the black box finds when it opens reaches the
//! findings stream with the recorder's severity, and the daemon never
//! claims an anchored black box without an external head anchor.

mod common;

use common::pcap::{robot_profile, scenario_frames};
use common::*;
use robodr_blackbox::store::{segment_file_name, HEAD_FILE};
use robodr_blackbox::{Recorder, RecorderConfig, SystemClock, TimeSource};
use robodr_events::Severity;
use robodr_ocsf::Mode;

fn replay_cfg(s: &Setup) -> serde_json::Value {
    let pcap = s.pcap(&scenario_frames(1));
    s.config(
        serde_json::json!({"capture": {"enabled": true, "pcap_replay": pcap}}),
        serde_json::json!([]),
        serde_json::json!({"exit_when_inputs_end": true}),
    )
}

/// Open the daemon's black box directly with its key.
fn recorder(s: &Setup, every: u64) -> Recorder {
    let mut c = RecorderConfig::new(&s.blackbox, ROBOT, "test-boot");
    c.max_segment_bytes = 4096;
    c.head_mark_every_records = every;
    let clock = SystemClock::new(TimeSource::Unknown);
    Recorder::open(c, Box::new(verifier()), Box::new(clock)).unwrap()
}

fn fill(r: &mut Recorder, n: u64) {
    for i in 0..n {
        r.append_note(&serde_json::json!({"kind": "fill", "i": i}), false)
            .unwrap();
    }
}

fn run(
    s: &Setup,
    cfg: &serde_json::Value,
) -> (
    Vec<(robodr_agentd::SpoolRecord, robodr_ocsf::FindingEnvelope)>,
    String,
) {
    let mut log = Vec::new();
    robodr_agentd::run(&s.resolve(cfg), &|| false, &mut log).unwrap();
    (spooled(&s.spool), String::from_utf8(log).unwrap())
}

#[test]
fn stray_segment_file_is_a_critical_quarantine_finding() {
    let s = setup("rev5-stray", &robot_profile(true));
    let mut r = recorder(&s, 16);
    while r.segments().len() < 3 {
        fill(&mut r, 4);
    }
    let live = *r.segments().last().unwrap();
    drop(r); // killed: the live segment is unsealed
    std::fs::write(s.blackbox.join(segment_file_name(live + 1)), b"").unwrap();

    let (found, log) = run(&s, &replay_cfg(&s));
    let q: Vec<_> = found
        .iter()
        .filter(|(_, e)| e.entity_context.rule_id == "robot.agent.evidence_quarantined")
        .collect();
    assert_eq!(q.len(), 1, "{:?}\n{log}", rules(&found));
    assert_eq!(
        q[0].1.severity,
        Severity::Critical,
        "the recorder's severity"
    );
    assert_eq!(q[0].1.entity_context.mode, Mode::Observe, "self-health");
    assert!(!s.blackbox.join(segment_file_name(live + 1)).exists());
    assert!(
        s.blackbox.join(segment_file_name(live)).exists(),
        "live segment kept"
    );
}

#[test]
fn truncation_found_at_open_is_a_critical_finding() {
    let s = setup("rev5-trunc", &robot_profile(true));
    let mut r = recorder(&s, 1);
    fill(&mut r, 2);
    let p = s.blackbox.join(segment_file_name(0));
    let before = std::fs::read(&p).unwrap();
    fill(&mut r, 3); // each one marked in head.json
    drop(r);
    std::fs::write(&p, &before).unwrap();
    assert!(s.blackbox.join(HEAD_FILE).exists());

    let (found, log) = run(&s, &replay_cfg(&s));
    let t: Vec<_> = found
        .iter()
        .filter(|(_, e)| e.entity_context.rule_id == "robot.agent.evidence_truncated")
        .collect();
    assert_eq!(t.len(), 1, "{:?}\n{log}", rules(&found));
    assert_eq!(t[0].1.severity, Severity::Critical);
    assert_eq!(t[0].1.entity_context.mode, Mode::Observe);
    assert!(log.contains("evidence_truncated"), "{log}");
}

#[test]
fn unanchored_black_box_is_never_reported_as_anchored() {
    let s = setup("rev5-unanchored", &robot_profile(true));
    let cfg = replay_cfg(&s);
    let r = s.resolve(&cfg);
    assert!(
        r.warnings.iter().any(|w| w.contains("not anchored")),
        "{:?}",
        r.warnings
    );
    let mut log = Vec::new();
    robodr_agentd::run(&r, &|| false, &mut log).unwrap();
    let log = String::from_utf8(log).unwrap();
    assert!(log.contains("not anchored"), "startup warning: {log}");
    let st = status(&s.spool).expect("status.json");
    assert_eq!(st["blackbox"]["anchored"], false, "{st}");
    assert_eq!(st["blackbox"]["anchor_kind"], "none");
    // No incident at a clean open.
    let found = spooled(&s.spool);
    assert!(!rules(&found)
        .iter()
        .any(|r| r.starts_with("robot.agent.evidence_")));
}

#[test]
fn file_head_anchor_is_configured_checked_and_used() {
    let s = setup("rev5-anchor", &robot_profile(true));
    let adir = s.dir.join("anchor");
    std::fs::create_dir_all(&adir).unwrap();
    let path = adir.join("head-anchor.json");
    let mut cfg = replay_cfg(&s);
    cfg["blackbox"]["head_anchor"] = serde_json::json!({"kind": "file", "path": path});
    let r = s.resolve(&cfg);
    assert!(
        r.warnings
            .iter()
            .any(|w| w.contains("head_anchor is a file")),
        "{:?}",
        r.warnings
    );
    robodr_agentd::run(&r, &|| false, &mut Vec::new()).unwrap();
    let st = status(&s.spool).expect("status.json");
    assert_eq!(st["blackbox"]["anchored"], true, "{st}");
    assert_eq!(st["blackbox"]["anchor_kind"], "file");
    assert_eq!(st["blackbox"]["anchor_failures"], 0);
    let held: serde_json::Value = serde_json::from_slice(&std::fs::read(&path).unwrap()).unwrap();
    assert!(held["seq"].as_u64().unwrap() > 0, "{held}");

    // Inside the black-box directory: refused (it would add nothing).
    let mut bad = cfg.clone();
    bad["blackbox"]["head_anchor"]["path"] = s.blackbox.join("anchor.json").to_str().into();
    let e = robodr_agentd::load(&s.write_config(&bad)).unwrap_err();
    assert!(e.contains("must not be inside blackbox.dir"), "{e}");
    // Relative path and unknown kind: refused.
    bad["blackbox"]["head_anchor"]["path"] = "rel/anchor.json".into();
    assert!(robodr_agentd::load(&s.write_config(&bad)).is_err());
    bad["blackbox"]["head_anchor"] = serde_json::json!({"kind": "tpm"});
    assert!(robodr_agentd::load(&s.write_config(&bad)).is_err());
}
