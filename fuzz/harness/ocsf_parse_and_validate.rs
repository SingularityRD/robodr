//! Harness: `robodr_ocsf::parse_and_validate`, the gate every finding passes
//! before it is published on the findings topic (default `robodr.findings`),
//! and the consumer-side check of a received finding.
//!
//! Input: arbitrary bytes, tried as UTF-8 JSON. Invariants beyond "no
//! panic": a current-contract (2.x) finding that passes the gate
//! re-serialises (`to_json`, which re-runs `validate`), the re-serialised
//! text passes the gate again (the contract is closed under its own
//! encoder), and the Kafka record helpers accept it. A legacy 1.x finding
//! that passes the gate is parse-only: `to_json` and `record` must refuse it.
#![allow(dead_code)]

use robodr_ocsf::validate::is_emittable_contract_version;
use robodr_ocsf::{dedup_key, headers, parse_and_validate, partition_for, record, to_json};

pub fn run(data: &[u8]) {
    let Ok(text) = std::str::from_utf8(data) else {
        return;
    };
    let Ok(env) = parse_and_validate(text) else {
        return;
    };
    let _ = dedup_key(&env);
    let _ = headers(&env);
    let _ = partition_for(&env.entity_context.robot.id, 12);
    if !is_emittable_contract_version(&env.contract_version) {
        assert!(to_json(&env).is_err(), "legacy finding was emitted");
        assert!(
            record(&env, Some(12)).is_err(),
            "legacy finding got a record"
        );
        return;
    }
    let json = to_json(&env).unwrap_or_else(|e| panic!("accepted finding fails to_json: {e:?}"));
    if let Err(e) = parse_and_validate(&json) {
        panic!("re-encoded finding is rejected: {e:?}\n{json}");
    }
    let rec =
        record(&env, Some(12)).unwrap_or_else(|e| panic!("accepted finding has no record: {e:?}"));
    assert_eq!(rec.topic, env.ocsf.metadata.log_name);
}
