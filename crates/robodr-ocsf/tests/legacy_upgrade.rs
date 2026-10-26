//! Upgrade of unsigned contract 1.x findings to contract 2.0 (review M5).

mod common;

use robodr_events::{Deviation, Severity};
use robodr_ocsf::*;

fn build(rule: &str) -> String {
    let dev = Deviation::new(rule.to_string(), Severity::High, "detail");
    let env = FindingBuilder::from_deviation(&dev, &common::ctx())
        .seen(common::T0, common::T0)
        .build()
        .unwrap();
    to_json(&env).unwrap()
}

#[test]
fn a_1_3_finding_upgrades_to_2_0_with_its_identity() {
    let v2 = common::example_finding();
    let v13 = common::to_v1_json(&to_json(&v2).unwrap(), "1.3.0");
    let legacy = parse_and_validate(&v13).unwrap();
    assert_eq!(legacy.contract_version, "1.3.0");
    // Not emittable as is.
    assert!(to_json(&legacy).is_err());
    let up = upgrade_legacy_json(&v13, "site-a.robodr", "site-a.findings").unwrap();
    assert_eq!(up.contract_version, UPGRADE_TARGET_VERSION);
    assert_eq!(up.contract_version, "2.0.0");
    assert_eq!(up.data_source, "site-a.robodr");
    assert_eq!(up.ocsf.metadata.log_name, "site-a.findings");
    // data_source / log_name / contract_version are not identity inputs.
    assert_eq!(up.finding_id, v2.finding_id);
    assert_eq!(up.external_id, v2.external_id);
    assert_eq!(up.ocsf.metadata.uid, v2.ocsf.metadata.uid);
    // Everything else is untouched.
    let mut same = up.clone();
    same.contract_version = v2.contract_version.clone();
    same.data_source = v2.data_source.clone();
    same.ocsf.metadata.log_name = v2.ocsf.metadata.log_name.clone();
    assert_eq!(same, v2);
    let json = to_json(&up).unwrap();
    assert_eq!(parse_and_validate(&json).unwrap(), up);
    let rec = record(&up, Some(4)).unwrap();
    assert_eq!(rec.topic, "site-a.findings");
    assert!(rec
        .headers
        .contains(&("robodr-contract-version", "2.0.0".into())));
}

#[test]
fn a_1_3_finding_of_a_rule_catalogued_in_2_1_upgrades_with_the_generic_entry() {
    // Generic in 1.3 and 2.0, own entry in 2.1: the 2.0.0 label keeps it
    // valid (labelling it 2.1 would not).
    let rule = "robot.firewall.joint_limp_frame";
    let v21 = build(rule);
    let full = rule_info(rule);
    let generic = rule_info_for_contract(rule, "1.3.0");
    assert_ne!(full, generic);
    let mut v13 = common::to_v1_json(&v21, "1.3.0")
        .replace(full.title, generic.title)
        .replace(full.desc, generic.desc)
        .replace(
            &format!("\"{}\"", full.data_source),
            &format!("\"{}\"", generic.data_source),
        );
    for key in ["mitre_predictions", "attacks"] {
        let start = v13.find(&format!("\"{key}\":[")).unwrap() + key.len() + 4;
        let end = start + v13[start..].find(']').unwrap();
        v13 = format!("{}{}", &v13[..start], &v13[end..]);
    }
    parse_and_validate(&v13).expect("valid 1.3 finding");
    let up = upgrade_legacy_json(&v13, DEFAULT_DATA_SOURCE, DEFAULT_TOPIC).unwrap();
    assert_eq!(up.title, generic.title);
    assert_eq!(up.contract_version, "2.0.0");
}

#[test]
fn what_cannot_be_upgraded_is_refused() {
    let v2 = to_json(&common::example_finding()).unwrap();
    assert_eq!(
        upgrade_legacy_json(&v2, DEFAULT_DATA_SOURCE, DEFAULT_TOPIC),
        Err(UpgradeError::NotLegacy)
    );
    let v13 = common::to_v1_json(&v2, "1.3.0");
    assert_eq!(
        upgrade_legacy_json(&v13, "Bad Label", DEFAULT_TOPIC),
        Err(UpgradeError::BadLabel("data_source"))
    );
    assert_eq!(
        upgrade_legacy_json(&v13, DEFAULT_DATA_SOURCE, ".."),
        Err(UpgradeError::BadLabel("topic"))
    );
    assert!(matches!(
        upgrade_legacy_json("{}", DEFAULT_DATA_SOURCE, DEFAULT_TOPIC),
        Err(UpgradeError::Invalid(_))
    ));
    // A valid 1.2 finding whose rule only gained an entry in 1.3: valid
    // 1.x, not a valid 2.0 finding.
    let rule = "robot.safety_state.unmapped_value";
    let new = rule_info(rule);
    let old = rule_info_for_contract(rule, "1.2.0");
    let v12 = common::to_v1_json(&build(rule), "1.2.0")
        .replace(new.title, old.title)
        .replace(new.desc, old.desc)
        .replace(
            &format!("\"{}\"", new.data_source),
            &format!("\"{}\"", old.data_source),
        );
    parse_and_validate(&v12).expect("valid 1.2 finding");
    let e = upgrade_legacy_json(&v12, DEFAULT_DATA_SOURCE, DEFAULT_TOPIC).unwrap_err();
    assert!(matches!(e, UpgradeError::NotConvertible(_)), "{e:?}");
    assert!(e.to_string().contains("cannot be upgraded"));
    assert_eq!(
        LEGACY_SIGNED_REASON,
        "legacy 1.x signed record: re-sign required"
    );
}
