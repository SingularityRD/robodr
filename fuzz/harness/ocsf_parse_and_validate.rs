//! Harness: `robodr_ocsf::parse_and_validate`, the gate every finding passes
//! before it is published on `robot-edr.findings` (and the consumer-side
//! check of a received finding).
//!
//! Input: arbitrary bytes, tried as UTF-8 JSON. Invariants beyond "no
//! panic": a finding that passes the gate re-serialises (`to_json`, which
//! re-runs `validate`), the re-serialised text passes the gate again (the
//! contract is closed under its own encoder), and the Kafka record helpers
//! accept it.
#![allow(dead_code)]

use robodr_ocsf::{dedup_key, headers, parse_and_validate, partition_for, record, to_json};

pub fn run(data: &[u8]) {
    let Ok(text) = std::str::from_utf8(data) else {
        return;
    };
    let Ok(env) = parse_and_validate(text) else {
        return;
    };
    let json = to_json(&env).unwrap_or_else(|e| panic!("accepted finding fails to_json: {e:?}"));
    if let Err(e) = parse_and_validate(&json) {
        panic!("re-encoded finding is rejected: {e:?}\n{json}");
    }
    let _ = dedup_key(&env);
    let _ = headers(&env);
    let _ = partition_for(&env.entity_context.robot.id, 12);
    record(&env, Some(12)).unwrap_or_else(|e| panic!("accepted finding has no record: {e:?}"));
}
