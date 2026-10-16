//! `Agent::mark_blackbox_head` / `blackbox_quarantined` /
//! `blackbox_open_incidents` / `blackbox_anchored` / `blackbox_mark_failures`:
//! the daemon's black-box upkeep hooks, and finding-key separation.

mod common;

use common::*;
use robodr_agent::Agent;
use robodr_blackbox::store::{segment_file_name, HEAD_FILE};
use robodr_blackbox::{
    Ed25519SigningKey, HmacSha256Key, MemoryHeadAnchor, OpenIncident, Recorder, RecorderConfig,
};
use robodr_events::Severity;
use std::sync::Arc;

#[test]
fn head_mark_is_written_only_when_records_are_unmarked() {
    let dir = tmpdir("upkeep-mark");
    let mut a = build(config(&dir, demo_profile(true), validated_policy()));
    // Opening wrote a mark of the opening records, or not: either way a
    // first explicit mark covers the head and a second has nothing to do.
    let first = a.mark_blackbox_head().unwrap();
    assert!(!a.mark_blackbox_head().unwrap(), "{first}");
    a.record_note(at(1_000), "note", &serde_json::json!({"kind": "t"}), false)
        .unwrap();
    assert!(a.mark_blackbox_head().unwrap(), "a new record is unmarked");
    assert!(!a.mark_blackbox_head().unwrap());
    assert_eq!(a.blackbox_mark_failures(), 0);
    assert!(a.blackbox_quarantined().is_empty());
    let head = std::fs::read_to_string(dir.join(HEAD_FILE)).unwrap();
    let seq = a.blackbox_head().unwrap().0;
    assert!(head.contains(&format!("\"seq\":{seq}")), "{head}");
    a.finish().unwrap();
}

#[test]
fn damaged_closed_segment_is_reported_by_the_agent() {
    let dir = tmpdir("upkeep-quarantine");
    // Pre-populate a multi-segment black box with the agent's key.
    let mut c = RecorderConfig::new(&dir, ROBOT, "boot-0");
    c.max_segment_bytes = 4096;
    let key = HmacSha256Key::new("test-key", &KEY).unwrap();
    let mut r = Recorder::open(c, Box::new(key), clock()).unwrap();
    let mut i = 0u64;
    while r.segments().len() < 4 {
        r.append_note(
            &serde_json::json!({"kind": "fill", "i": i, "pad": "x".repeat(200)}),
            false,
        )
        .unwrap();
        i += 1;
    }
    r.close().unwrap();
    let p = dir.join(segment_file_name(1));
    let mut b = std::fs::read(&p).unwrap();
    let mid = b.len() / 2;
    b[mid] ^= 0x20;
    std::fs::write(&p, &b).unwrap();

    let a = build(config(&dir, demo_profile(true), validated_policy()));
    assert_eq!(a.blackbox_quarantined(), &[1]);
    // Media-like damage in an older closed segment: the recorder's own
    // severity (High) is what the agent hands on.
    let inc = a.blackbox_open_incidents();
    assert_eq!(inc.len(), 1, "{inc:?}");
    assert!(matches!(
        inc[0],
        OpenIncident::SegmentQuarantined {
            segment_index: 1,
            severity: Severity::High,
            ..
        }
    ));
    assert!(!a.blackbox_anchored(), "no anchor configured");
    a.finish().unwrap();
}

#[test]
fn truncation_found_at_open_is_an_incident() {
    let dir = tmpdir("upkeep-truncation");
    let a = build(config(&dir, demo_profile(true), validated_policy()));
    a.finish().unwrap();
    // A head.json mark beyond the stored head: cut the newest records.
    let mut c = RecorderConfig::new(&dir, ROBOT, "boot-0");
    c.head_mark_every_records = 1;
    let key = HmacSha256Key::new("test-key", &KEY).unwrap();
    let mut r = Recorder::open(c, Box::new(key), clock()).unwrap();
    let before = std::fs::read(dir.join(segment_file_name(0))).unwrap();
    for i in 0..3u64 {
        r.append_note(&serde_json::json!({"kind": "fill", "i": i}), false)
            .unwrap();
    }
    drop(r);
    std::fs::write(dir.join(segment_file_name(0)), &before).unwrap();
    let a = build(config(&dir, demo_profile(true), validated_policy()));
    let inc = a.blackbox_open_incidents();
    assert!(
        inc.iter()
            .any(|i| matches!(i, OpenIncident::TruncationDetected { .. })
                && i.severity() == Severity::Critical),
        "{inc:?}"
    );
    a.finish().unwrap();
}

#[test]
fn head_anchor_is_reported_when_configured() {
    let dir = tmpdir("upkeep-anchor");
    let mut cfg = config(&dir, demo_profile(true), validated_policy());
    cfg.blackbox.head_anchor = Some(Arc::new(MemoryHeadAnchor::new()));
    let a = build(cfg);
    assert!(a.blackbox_anchored());
    assert_eq!(a.blackbox_anchor_failures(), 0);
    a.finish().unwrap();
}

#[test]
fn finding_key_must_not_be_the_blackbox_key() {
    let seed = [9u8; 32];
    let bb = || Box::new(Ed25519SigningKey::from_seed("bb-key", &seed).unwrap());
    let agent = |tag: &str| {
        Agent::new(
            config(&tmpdir(tag), demo_profile(true), validated_policy()),
            bb(),
            clock(),
        )
        .unwrap()
    };
    // The same key under another key id.
    let Err(e) = agent("keysep-bytes").with_finding_signer(Box::new(
        Ed25519SigningKey::from_seed("finding", &seed).unwrap(),
    )) else {
        panic!("black-box key accepted as finding key");
    };
    assert!(e.to_string().contains("black-box key"), "{e}");
    // Another key that claims the black-box key's id.
    let Err(e) = agent("keysep-id").with_finding_signer(Box::new(
        Ed25519SigningKey::from_seed("bb-key", &[8; 32]).unwrap(),
    )) else {
        panic!("black-box key id accepted as finding key id");
    };
    assert!(e.to_string().contains("black-box key"), "{e}");
    // A dedicated key is fine.
    let a = agent("keysep-ok")
        .with_finding_signer(Box::new(
            Ed25519SigningKey::from_seed("finding", &[8; 32]).unwrap(),
        ))
        .unwrap();
    assert!(a.signs_findings());
    a.finish().unwrap();
}
