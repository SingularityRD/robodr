//! Contract 2.5: one OCSF rule id per shipped Pulsar host rule
//! (sales-readiness T45), with `robot.host.pulsar_threat` as the fallback.

use std::collections::BTreeSet;
use std::path::Path;

use robodr_ocsf::{host_rule_id, rule_info, HOST_RULES, HOST_THREAT_FALLBACK};

fn shipped_rule_names() -> BTreeSet<String> {
    let dir = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../rules/robodr");
    let mut names = BTreeSet::new();
    for e in std::fs::read_dir(&dir).expect("rules/robodr").flatten() {
        let p = e.path();
        if p.extension().is_none_or(|x| x != "toml") {
            continue;
        }
        for line in std::fs::read_to_string(&p).unwrap().lines() {
            if let Some(rest) = line.trim().strip_prefix("name = \"") {
                names.insert(rest.trim_end_matches('"').to_string());
            }
        }
    }
    names
}

#[test]
fn every_shipped_pulsar_rule_has_exactly_one_id_and_nothing_else_does() {
    let shipped = shipped_rule_names();
    assert!(shipped.len() > 80, "{}", shipped.len());
    let table: BTreeSet<String> = HOST_RULES.iter().map(|(n, _)| n.to_string()).collect();
    assert_eq!(table.len(), HOST_RULES.len(), "duplicate Pulsar name");
    let missing: Vec<_> = shipped.difference(&table).collect();
    let stale: Vec<_> = table.difference(&shipped).collect();
    assert!(
        missing.is_empty() && stale.is_empty(),
        "HOST_RULES out of sync with rules/robodr: missing {missing:?}, stale {stale:?}"
    );
}

#[test]
fn ids_are_unique_well_formed_and_catalogued() {
    let mut seen = BTreeSet::new();
    for (name, id) in HOST_RULES {
        assert!(seen.insert(*id), "{id} used twice");
        assert!(robodr_ocsf::validate::is_valid_rule_id(id), "{id}");
        let parts: Vec<&str> = id.split('.').collect();
        assert_eq!(parts.len(), 3, "{id}");
        assert_eq!(&parts[..2], ["robot", "host"], "{id}");
        assert_ne!(*id, HOST_THREAT_FALLBACK);
        assert_eq!(host_rule_id(name), Some(*id));
        let info = rule_info(id);
        assert_eq!(info.data_source, "host_runtime", "{id}");
        assert_eq!(Some(info.title), name.strip_prefix("RoboDR: "), "{id}");
    }
}

#[test]
fn unknown_names_fall_back() {
    assert_eq!(host_rule_id("My site: custom rule"), None);
    // Exact match only: case and whitespace matter.
    assert_eq!(
        host_rule_id("roboDR: Interactive shell started on robot controller"),
        None
    );
    assert_eq!(
        host_rule_id("RoboDR: Interactive shell started on robot controller "),
        None
    );
    assert_eq!(
        host_rule_id("RoboDR: Interactive shell started on robot controller"),
        Some("robot.host.interactive_shell")
    );
    assert_eq!(rule_info(HOST_THREAT_FALLBACK).data_source, "host_runtime");
}
