//! ATT&CK for ICS ids of the rule catalog against MITRE's own data (T61).
//!
//! The catalog's technique ids and names were written from memory
//! (`crates/robodr-ocsf/README.md`). `integrations/schemas/attack-ics-techniques.json`
//! is extracted from MITRE's official STIX bundle
//! (`integrations/schemas/extract_attack_ics.py`). Every technique the
//! catalog attaches must be a current technique with exactly that name, or
//! be listed in [`KNOWN_REVOKED`] with the replacement MITRE names; a
//! mismatch, a new revocation or a fixed entry fails the test.

#[path = "support/catalog_ids.rs"]
mod catalog_ids;

use robodr_ocsf::rule_info;
use serde_json::Value;
use std::collections::BTreeSet;
use std::path::Path;

/// Techniques the catalog still attaches that MITRE revoked in ATT&CK for
/// ICS v20 (2026-04): `(catalog id, replacement id MITRE names)`. Changing
/// the ids a finding carries is a contract change (docs/SALES-READINESS.md
/// WP2); until then consumers are told in integrations/README.md.
const KNOWN_REVOKED: &[(&str, &str)] = &[("T0855", "T1692.001"), ("T0856", "T1692.002")];

fn table() -> Value {
    let p = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../integrations/schemas/attack-ics-techniques.json");
    serde_json::from_str(&std::fs::read_to_string(p).unwrap()).unwrap()
}

fn catalog_techniques() -> BTreeSet<(String, String)> {
    catalog_ids::catalog_rule_ids()
        .iter()
        .flat_map(|id| rule_info(id).techniques.iter())
        .map(|(i, n)| (i.to_string(), n.to_string()))
        .collect()
}

#[test]
fn catalog_techniques_are_current_attack_ics_or_known_revoked() {
    let t = table();
    let used = catalog_techniques();
    assert!(!used.is_empty());
    let mut problems = Vec::new();
    for (id, name) in &used {
        if let Some(cur) = t["techniques"][id].as_str() {
            if cur != name {
                problems.push(format!("{id}: catalog says {name:?}, MITRE says {cur:?}"));
            }
            if KNOWN_REVOKED.iter().any(|(k, _)| k == id) {
                problems.push(format!("{id} is current again: drop it from KNOWN_REVOKED"));
            }
            continue;
        }
        let Some(rev) = t["revoked"].get(id) else {
            problems.push(format!("{id} ({name}) is not an ATT&CK for ICS technique"));
            continue;
        };
        if rev["name"].as_str() != Some(name.as_str()) {
            problems.push(format!("{id}: catalog name {name:?} != {}", rev["name"]));
        }
        let by: Vec<&str> = rev["revoked_by"]
            .as_array()
            .unwrap()
            .iter()
            .filter_map(|p| p[0].as_str())
            .collect();
        match KNOWN_REVOKED.iter().find(|(k, _)| k == id) {
            Some((_, repl)) if by.contains(repl) => {
                assert!(t["techniques"][*repl].is_string(), "{repl} not current");
            }
            Some((_, repl)) => problems.push(format!("{id}: revoked by {by:?}, not {repl}")),
            None => problems.push(format!("{id} ({name}) was revoked by {by:?}")),
        }
    }
    for (k, _) in KNOWN_REVOKED {
        if !used.iter().any(|(i, _)| i == k) {
            problems.push(format!("{k} is no longer used: drop it from KNOWN_REVOKED"));
        }
    }
    assert!(problems.is_empty(), "{problems:#?}");
}

#[test]
fn table_is_the_pinned_attack_release() {
    let t = table();
    assert_eq!(t["attack_version"], "20.0");
    assert!(t["techniques"].as_object().unwrap().len() >= 80);
    // The robotics set the README cites must all resolve in the table.
    for id in ["T0831", "T0836", "T0843", "T0848", "T0889", "T0801"] {
        assert!(t["techniques"][id].is_string(), "{id}");
    }
}
