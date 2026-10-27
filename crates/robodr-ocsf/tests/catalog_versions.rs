//! Rule-catalog versioning (review finding M6): a catalog entry is a contract
//! minor, and the validator applies the catalog of the message's own minor.
//!
//! * 1.0 - 1.2: the base catalog;
//! * 1.3 and 2.0: base + the 1.3 entries, exactly as released in 1.3
//!   (reference: `git show c64744d:crates/robodr-ocsf/src/builder.rs`; 2.0
//!   did not change the catalog);
//! * 2.1: + the low-level joint-frame firewall ids, the robot API /
//!   control-handover motion ids, the Unitree legacy UDP sender ids, the
//!   motion command type id and the discovery-flood aggregate;
//! * 2.2: + the secure-delivery ids of `robodr-deliverd` (`robot.deliver.*`,
//!   data source `robodr_delivery`, `docs/SECURE-DELIVERY.md` §9).

mod common;

use robodr_events::{Deviation, Severity};
use robodr_ocsf::{rule_info, rule_info_for_contract, FindingBuilder, CONTRACT_VERSION};

/// Ids whose catalog entry was added after contract 2.0.0 (2.1).
const IDS_2_1: &[&str] = &[
    "robot.motion.api_id_out_of_range",
    "robot.motion.control_handover",
    "robot.unitree.legacy_unknown_sender",
    "robot.unitree.legacy_sender_flood",
    "robot.unitree.legacy_sender_mac_mismatch",
    "robot.unitree.legacy_port_rtps",
    "robot.motion.command_type_mismatch",
    "robot.ros2.discovery_flood",
    "robot.firewall.joint_position_out_of_envelope",
    "robot.firewall.joint_velocity_out_of_envelope",
    "robot.firewall.joint_torque_out_of_envelope",
    "robot.firewall.joint_gain_out_of_envelope",
    "robot.firewall.disabled_motor_energised",
    "robot.firewall.crc_invalid",
    "robot.firewall.joint_rate_violation",
    "robot.firewall.joint_gain_below_minimum",
    "robot.firewall.joint_step_out_of_envelope",
    "robot.firewall.joint_pd_torque_out_of_envelope",
    "robot.firewall.joint_mode_inconsistent",
    "robot.firewall.joint_mode_pin_mismatch",
    "robot.firewall.joint_limp_frame",
    "robot.firewall.joint_hold_exceeded",
];

/// Ids whose catalog entry was added after contract 2.1.0 (2.2).
const IDS_2_2: &[&str] = &[
    "robot.deliver.installed",
    "robot.deliver.deferred_safety",
    "robot.deliver.health_failed",
    "robot.deliver.rollback_blocked_floor",
    "robot.deliver.refused",
    "robot.deliver.stale",
    "robot.deliver.chain_gap",
];

/// A sample of 1.3 entries (wave 6 and wave 7) that must stay as they were.
const IDS_1_3: &[&str] = &[
    "robot.correlate.coordinated_intrusion",
    "robot.safety_state.writer_overflow",
    "robot.agent.evidence_truncated",
    "robot.host.pulsar_threat",
    "robot.firewall.rejected_stale",
    "robot.motion.uncommanded_motion",
];

fn generic() -> robodr_ocsf::RuleInfo {
    rule_info("robot.nope.nothing")
}

fn build(rule: &str) -> String {
    let dev = Deviation::new(rule.to_string(), Severity::High, "detail");
    let env = FindingBuilder::from_deviation(&dev, &common::ctx())
        .seen(common::T0, common::T0)
        .build()
        .unwrap();
    robodr_ocsf::to_json(&env).unwrap()
}

/// Replace the JSON array value of `"key":[...]` (no nested arrays) by `[]`.
fn empty_array(json: &str, key: &str) -> String {
    let start = json.find(&format!("\"{key}\":[")).expect(key) + key.len() + 4;
    let end = start + json[start..].find(']').unwrap();
    format!("{}{}", &json[..start], &json[end..])
}

/// What a 2.0.0 producer emitted for `id`: the generic entry (generic
/// title, description and data source, no techniques).
fn as_2_0(json: &str, id: &str) -> String {
    let new = rule_info(id);
    let old = rule_info_for_contract(id, "2.0.0");
    assert!(old.techniques.is_empty());
    let out = json
        .replace(new.title, old.title)
        .replace(new.desc, old.desc)
        .replace(
            &format!("\"{}\"", new.data_source),
            &format!("\"{}\"", old.data_source),
        )
        .replace(
            &format!("\"contract_version\":\"{CONTRACT_VERSION}\""),
            "\"contract_version\":\"2.0.0\"",
        );
    empty_array(&empty_array(&out, "mitre_predictions"), "attacks")
}

#[test]
fn current_contract_is_2_2() {
    assert_eq!(CONTRACT_VERSION, "2.2.0");
    let schema: serde_json::Value = serde_json::from_str(include_str!(
        "../../../docs/contracts/robodr-finding.schema.json"
    ))
    .unwrap();
    assert_eq!(
        schema["$id"],
        "https://schemas.singularityrd.com/robodr/findings/2.2.0"
    );
}

#[test]
fn entries_added_after_2_0_are_not_in_1_3_or_2_0() {
    let g = generic();
    for id in IDS_2_1 {
        let full = rule_info(id);
        assert_ne!(full, g, "{id} has its own entry in the current catalog");
        for v in ["1.0.0", "1.2.0", "1.3.0", "1.9.0", "2.0.0", "2.0.7"] {
            assert_eq!(rule_info_for_contract(id, v), g, "{id} @ {v}");
        }
        for v in ["2.1.0", "2.1.3", "2.2.0", "2.4.0"] {
            assert_eq!(rule_info_for_contract(id, v), full, "{id} @ {v}");
        }
        // Malformed versions get the current (strictest) catalog.
        assert_eq!(rule_info_for_contract(id, "x"), full);
    }
}

#[test]
fn entries_added_after_2_1_are_not_in_2_1_or_earlier() {
    let g = generic();
    for id in IDS_2_2 {
        let full = rule_info(id);
        assert_ne!(full, g, "{id} has its own entry in the current catalog");
        assert_eq!(full.data_source, "robodr_delivery", "{id}");
        for v in ["1.0.0", "1.3.0", "2.0.0", "2.1.0", "2.1.9"] {
            assert_eq!(rule_info_for_contract(id, v), g, "{id} @ {v}");
        }
        for v in ["2.2.0", "2.2.5", "2.9.0"] {
            assert_eq!(rule_info_for_contract(id, v), full, "{id} @ {v}");
        }
        assert_eq!(rule_info_for_contract(id, "x"), full);
    }
    // The 2.1 entries are unchanged in 2.2.
    for id in IDS_2_1 {
        assert_eq!(
            rule_info_for_contract(id, "2.2.0"),
            rule_info_for_contract(id, "2.1.0")
        );
    }
}

/// What a 2.1.0 producer emitted for `id`: the generic entry.
fn as_2_1(json: &str, id: &str) -> String {
    let new = rule_info(id);
    let old = rule_info_for_contract(id, "2.1.0");
    assert!(old.techniques.is_empty() && new.techniques.is_empty());
    json.replace(new.title, old.title)
        .replace(new.desc, old.desc)
        .replace(
            &format!("\"{}\"", new.data_source),
            &format!("\"{}\"", old.data_source),
        )
        .replace(
            &format!("\"contract_version\":\"{CONTRACT_VERSION}\""),
            "\"contract_version\":\"2.1.0\"",
        )
}

#[test]
fn a_2_1_message_validates_with_its_own_catalog() {
    for id in IDS_2_2 {
        let v22 = build(id);
        robodr_ocsf::parse_and_validate(&v22).unwrap_or_else(|e| panic!("{id}: {e:?}"));
        let v21 = as_2_1(&v22, id);
        assert_ne!(v21, v22);
        robodr_ocsf::parse_and_validate(&v21).unwrap_or_else(|e| panic!("{id} 2.1: {e:?}"));
        let up = v21.replace(
            "\"contract_version\":\"2.1.0\"",
            &format!("\"contract_version\":\"{CONTRACT_VERSION}\""),
        );
        assert!(robodr_ocsf::parse_and_validate(&up).is_err(), "{id}");
        let down = v22.replace(
            &format!("\"contract_version\":\"{CONTRACT_VERSION}\""),
            "\"contract_version\":\"2.1.0\"",
        );
        assert!(robodr_ocsf::parse_and_validate(&down).is_err(), "{id}");
    }
}

#[test]
fn the_1_3_entries_are_the_same_in_1_3_2_0_and_2_1() {
    for id in IDS_1_3 {
        let full = rule_info(id);
        assert_ne!(full, generic(), "{id}");
        for v in ["1.3.0", "2.0.0", "2.1.0", "2.2.0"] {
            assert_eq!(rule_info_for_contract(id, v), full, "{id} @ {v}");
        }
    }
}

#[test]
fn a_2_0_message_validates_with_its_own_catalog() {
    for id in [
        "robot.firewall.joint_limp_frame",
        "robot.motion.control_handover",
        "robot.firewall.joint_rate_violation",
    ] {
        let v21 = build(id);
        robodr_ocsf::parse_and_validate(&v21).unwrap_or_else(|e| panic!("{id}: {e:?}"));
        let v20 = as_2_0(&v21, id);
        assert_ne!(v20, v21);
        robodr_ocsf::parse_and_validate(&v20).unwrap_or_else(|e| panic!("{id} 2.0: {e:?}"));
        // The 2.0 form relabelled 2.1 is rejected (generic entry, new minor).
        let up = v20.replace(
            "\"contract_version\":\"2.0.0\"",
            &format!("\"contract_version\":\"{CONTRACT_VERSION}\""),
        );
        assert!(robodr_ocsf::parse_and_validate(&up).is_err(), "{id}");
        // The 2.1 form relabelled 2.0 is rejected (new entry, old minor).
        let down = v21.replace(
            &format!("\"contract_version\":\"{CONTRACT_VERSION}\""),
            "\"contract_version\":\"2.0.0\"",
        );
        assert!(robodr_ocsf::parse_and_validate(&down).is_err(), "{id}");
    }
}
