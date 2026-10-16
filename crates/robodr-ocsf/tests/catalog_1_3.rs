//! Contract 1.3 catalog entries (wave-6 detectors) and the validator's
//! per-minor catalog: a 1.2 message for a rule that only gained an entry in
//! 1.3 keeps validating with the generic entry; a 1.3 message must carry the
//! new entry; a downgraded `contract_version` cannot smuggle either way.

mod common;

use robodr_events::{Deviation, Severity};
use robodr_ocsf::{rule_info, rule_info_for_contract, FindingBuilder};
use serde_json::Value;

const NEW_IDS: &[&str] = &[
    "robot.correlate.coordinated_intrusion",
    "robot.correlate.sensor_evasion",
    "robot.correlate.credential_theft",
    "robot.correlate.trojaned_package_key_access",
    "robot.correlate.spoofed_motion_source",
    "robot.correlate.motion_hijack",
    "robot.correlate.defense_tampering",
    "robot.correlate.discovery_flood",
    "robot.correlate.host_process_persistence",
    "robot.safety_state.untrusted_source",
    "robot.safety_state.undecodable_sample",
    "robot.safety_state.unmapped_value",
    "robot.ros2.profile_state_tampered",
    "robot.agent.evidence_quarantined",
    "robot.agent.correlation_pressure",
];

fn build(rule: &str) -> String {
    let dev = Deviation::new(rule.to_string(), Severity::High, "detail");
    let env = FindingBuilder::from_deviation(&dev, &common::ctx())
        .seen(common::T0, common::T0)
        .build()
        .unwrap();
    robodr_ocsf::to_json(&env).unwrap()
}

fn load_schema() -> Value {
    let p = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../docs/contracts/robot-edr-finding.schema.json");
    serde_json::from_str(&std::fs::read_to_string(p).unwrap()).unwrap()
}

/// The `items.enum` of the first property named `key`, anywhere in `v`.
fn enum_of(v: &Value, key: &str) -> Option<Vec<String>> {
    match v {
        Value::Object(m) => {
            if let Some(e) = m
                .get(key)
                .and_then(|p| p.pointer("/items/enum"))
                .and_then(Value::as_array)
            {
                return Some(e.iter().map(|x| x.as_str().unwrap().to_string()).collect());
            }
            m.values().find_map(|x| enum_of(x, key))
        }
        Value::Array(a) => a.iter().find_map(|x| enum_of(x, key)),
        _ => None,
    }
}

#[test]
fn every_new_id_has_its_own_entry_and_validates() {
    let generic = rule_info("robot.nope.nothing");
    for id in NEW_IDS {
        let info = rule_info(id);
        assert_ne!(info.title, generic.title, "{id}");
        assert_ne!(info.data_source, "robodr", "{id}");
        let json = build(id);
        let env = robodr_ocsf::parse_and_validate(&json).unwrap_or_else(|e| panic!("{id}: {e:?}"));
        assert_eq!(env.title, info.title);
        assert_eq!(env.contract_version, "1.3.0");
    }
}

#[test]
fn custom_correlation_ids_get_the_generic_correlation_entry() {
    let info = rule_info("robot.correlate.site_specific_rule");
    assert_eq!(info.data_source, "robodr_correlation");
    assert_eq!(info.title, "Correlated RoboDR detection");
    let json = build("robot.correlate.site_specific_rule");
    robodr_ocsf::parse_and_validate(&json).unwrap();
}

#[test]
fn schema_enums_cover_every_catalog_constant() {
    let schema = load_schema();
    let types = enum_of(&schema, "types").expect("schema types enum");
    let sources = enum_of(&schema, "data_sources").expect("schema data_sources enum");
    let schema_text = schema.to_string();
    for id in NEW_IDS.iter().copied().chain([
        "robot.correlate.custom",
        "robot.motion.angular_over_envelope",
    ]) {
        let info = rule_info(id);
        assert!(types.iter().any(|t| t == info.data_source), "{id}");
        assert!(sources.iter().any(|t| t == info.data_source), "{id}");
        for (tid, name) in info.techniques {
            assert!(schema_text.contains(&format!("\"{tid}\"")), "{id} {tid}");
            assert!(schema_text.contains(&format!("\"{name}\"")), "{id} {name}");
        }
    }
}

#[test]
fn older_minor_uses_the_older_catalog() {
    for id in NEW_IDS {
        let old = rule_info_for_contract(id, "1.2.0");
        assert_eq!(old.data_source, "robodr", "{id}");
        assert_eq!(rule_info_for_contract(id, "1.3.0"), rule_info(id));
        // Malformed versions get the current (strictest) catalog.
        assert_eq!(rule_info_for_contract(id, "x"), rule_info(id));
    }
    // Entries that existed before 1.3 are the same in every minor.
    let r = "robot.ros2.unknown_participant";
    assert_eq!(rule_info_for_contract(r, "1.0.0"), rule_info(r));
}

/// Rewrite a 1.3 finding (rule without techniques) into what a 1.2
/// producer emitted: the generic catalog entry, `contract_version` 1.2.0.
fn as_1_2(json: &str, id: &str) -> String {
    let new = rule_info(id);
    let old = rule_info_for_contract(id, "1.2.0");
    assert!(new.techniques.is_empty());
    json.replace(new.title, old.title)
        .replace(new.desc, old.desc)
        .replace(
            &format!("\"{}\"", new.data_source),
            &format!("\"{}\"", old.data_source),
        )
        .replace(
            "\"contract_version\":\"1.3.0\"",
            "\"contract_version\":\"1.2.0\"",
        )
}

#[test]
fn a_1_2_message_with_the_generic_entry_stays_valid() {
    for id in [
        "robot.safety_state.unmapped_value",
        "robot.ros2.profile_state_tampered",
        "robot.correlate.defense_tampering",
    ] {
        let v13 = build(id);
        let v12 = as_1_2(&v13, id);
        assert_ne!(v12, v13);
        robodr_ocsf::parse_and_validate(&v12).unwrap_or_else(|e| panic!("{id}: {e:?}"));
        // The 1.2 form relabelled 1.3 is rejected (generic entry, new minor).
        let relabelled = v12.replace(
            "\"contract_version\":\"1.2.0\"",
            "\"contract_version\":\"1.3.0\"",
        );
        assert!(
            robodr_ocsf::parse_and_validate(&relabelled).is_err(),
            "{id}"
        );
        // The 1.3 form relabelled 1.2 is rejected (new entry, old minor).
        let downgraded = v13.replace(
            "\"contract_version\":\"1.3.0\"",
            "\"contract_version\":\"1.2.0\"",
        );
        assert!(
            robodr_ocsf::parse_and_validate(&downgraded).is_err(),
            "{id}"
        );
    }
}
