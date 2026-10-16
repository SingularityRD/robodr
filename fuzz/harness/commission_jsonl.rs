//! Harness: commissioning JSONL input (`robodr_commission::JsonlSource`) and
//! the learner and checker that consume it.
//!
//! Input: the bytes of a `.jsonl` recording (one `RobotEvent` per line,
//! `#` comments). Invariants beyond "no panic":
//!
//! * the source yields a bounded number of events and stops after its first
//!   error;
//! * a learned profile is always an unlocked draft;
//! * the draft as `learn` writes it (`to_json`) is accepted by the strict
//!   profile-file parser `learn`'s own output is later read back with;
//! * `check_event` of every recorded event against the draft does not panic.
#![allow(dead_code)]

use std::io::Cursor;

use robodr_commission::{
    check_event, parse_profile_text, to_json, EventSource, JsonlSource, LearnConfig, Learner,
};

pub fn run(data: &[u8]) {
    // Raw source: bounded, fused after the first error.
    let mut src = JsonlSource::new("fuzz.jsonl", Cursor::new(data));
    let mut events = Vec::new();
    let lines = data.iter().filter(|&&b| b == b'\n').count() + 1;
    while let Some(r) = src.next_event() {
        match r {
            Ok(e) => {
                events.push(e.event);
                assert!(events.len() <= lines, "more events than lines");
            }
            Err(_) => {
                assert!(src.next_event().is_none(), "source not fused after error");
                break;
            }
        }
    }

    // Learner over the same bytes (strict ingest, as the CLI does).
    let mut learner = Learner::new(LearnConfig::default()).expect("default learn config");
    let _ = learner.ingest(&mut JsonlSource::new("fuzz.jsonl", Cursor::new(data)));
    let draft = learner.profile();
    assert!(!draft.locked, "learner produced a locked profile");
    let _ = learner.report();
    let text = to_json(&draft).expect("a draft always serialises");
    if let Err(e) = parse_profile_text(&text) {
        panic!("learned draft is refused by the strict parser: {e}\n{text}");
    }
    for e in &events {
        let _ = check_event(&draft, e);
    }
}
