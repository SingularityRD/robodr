//! `Agent::mark_blackbox_head` / `blackbox_quarantined` /
//! `blackbox_mark_failures`: the daemon's black-box upkeep hooks.

mod common;

use common::*;
use robodr_blackbox::store::{segment_file_name, HEAD_FILE};
use robodr_blackbox::{HmacSha256Key, Recorder, RecorderConfig};

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
    a.finish().unwrap();
}
