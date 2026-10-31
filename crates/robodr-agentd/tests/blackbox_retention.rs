//! T15: `blackbox.retention` reaches the recorder, is checked against the
//! black box's free space at start, and unexported evidence filling the
//! retention raises a finding before cyclic retention drops it.

mod common;

use common::pcap::{robot_profile, scenario_frames};
use common::*;
use robodr_blackbox::{Recorder, RecorderConfig, RetentionMode, SystemClock, TimeSource};
use robodr_events::Severity;
use robodr_ocsf::Mode;

const SEGMENT: u64 = 64 * 1024;

fn replay_cfg(s: &Setup, retention: serde_json::Value) -> serde_json::Value {
    let pcap = s.pcap(&scenario_frames(1));
    let mut c = s.config(
        serde_json::json!({"capture": {"enabled": true, "pcap_replay": pcap}}),
        serde_json::json!([]),
        serde_json::json!({"exit_when_inputs_end": true}),
    );
    c["blackbox"]["retention"] = retention;
    c
}

#[test]
fn retention_beyond_the_free_space_refuses_to_start() {
    let s = setup("t15-space", &robot_profile(true));
    // 65536 segments of 256 MiB: 16 TiB.
    let cfg = replay_cfg(
        &s,
        serde_json::json!({"segments": 65536, "segment_bytes": 268435456}),
    );
    let r = s.resolve(&cfg);
    let mut log = Vec::new();
    let e = robodr_agentd::run(&r, &|| false, &mut log).unwrap_err();
    assert!(e.to_string().contains("blackbox.retention needs"), "{e}");
    // A bad value is refused when the file is loaded.
    let cfg = replay_cfg(&s, serde_json::json!({"segments": 0}));
    let p = s.write_config(&cfg);
    let e = robodr_agentd::load(&p).unwrap_err();
    assert!(e.to_string().contains("blackbox.retention.segments"), "{e}");
}

#[test]
fn unexported_evidence_filling_the_retention_is_reported_before_it_is_dropped() {
    let s = setup("t15-pressure", &robot_profile(true));
    // What agentd will run with: 2 segments + 2 reserve of 64 KiB.
    let mut c = RecorderConfig::new(&s.blackbox, ROBOT, "test-boot");
    c.max_segment_bytes = SEGMENT;
    c.mode = RetentionMode::Cyclic { max_segments: 2 };
    c.unexported_reserve_segments = 2;
    let mut r = Recorder::open(
        c,
        Box::new(verifier()),
        Box::new(SystemClock::new(TimeSource::Unknown)),
    )
    .unwrap();
    let pad = "x".repeat(1024);
    let mut i = 0u64;
    while r.segments().len() < 4 {
        r.append_note(&serde_json::json!({"i": i, "pad": pad}), false)
            .unwrap();
        i += 1;
    }
    assert_eq!(r.segments()[0], 0, "protected: nothing dropped yet");
    drop(r);

    let cfg = replay_cfg(
        &s,
        serde_json::json!({
            "segments": 2,
            "segment_bytes": SEGMENT,
            "unexported_reserve_segments": 2,
        }),
    );
    let mut log = Vec::new();
    robodr_agentd::run(&s.resolve(&cfg), &|| false, &mut log).unwrap();
    let log = String::from_utf8(log).unwrap();
    let found = spooled(&s.spool);
    let p: Vec<_> = found
        .iter()
        .filter(|(_, e)| e.entity_context.rule_id == "robot.agent.evidence_retention_pressure")
        .filter(|(_, e)| {
            serde_json::to_string(e)
                .unwrap()
                .contains("retention pressure")
        })
        .collect();
    assert_eq!(p.len(), 1, "{:?}\n{log}", rules(&found));
    assert!(p[0].1.severity >= Severity::Medium);
    assert_eq!(p[0].1.entity_context.mode, Mode::Observe);
    assert!(log.contains("retention pressure"), "{log}");
}
