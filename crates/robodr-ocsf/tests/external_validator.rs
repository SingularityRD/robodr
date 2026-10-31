//! Third-party validation of produced findings (gap T61).
//!
//! `tests/contract.rs` checks the builder's output with an in-repo subset
//! validator. This test hands the output to an independent implementation:
//! `integrations/schemas/validate_findings.py`, which runs the Python
//! `jsonschema` package (Draft 2020-12, the engine behind
//! `check-jsonschema`) against
//!
//! * the contract schema `docs/contracts/robodr-finding.schema.json`, and
//! * the strict OCSF 1.1.0 Detection Finding schema compiled from the
//!   official `ocsf/ocsf-schema` source by the OCSF project's compiler
//!   (`integrations/schemas/build_ocsf_schema.py`).
//!
//! Inputs: one finding for every rule id in the catalog, the richer
//! example finding (subjects, evidence, safety state) and the checked-in
//! golden example. Negative cases prove the validator is live and agree
//! with the in-crate validator.
//!
//! The test needs `python3` with `jsonschema` >= 4.18. Without them it is
//! skipped with a message, unless `ROBODR_REQUIRE_EXTERNAL_VALIDATOR=1`, in
//! which case a missing validator fails the test (set it in CI).

#[path = "support/catalog_ids.rs"]
mod catalog_ids;
mod common;

use robodr_events::{Deviation, Severity};
use robodr_ocsf::{parse_and_validate, to_json, FindingBuilder};
use serde_json::Value;
use std::path::{Path, PathBuf};
use std::process::Command;

/// OCSF 1.1.0 deviations of the current contract, pinned so that a new one
/// fails this test and a fixed one forces this list to shrink. Each entry is
/// `(json pointer inside ocsf, substring of the validator message)`.
///
/// * `device.model`: OCSF 1.1.0 `device` has no `model` attribute (the
///   README's OCSF-UNCERTAIN list asked exactly this). The value is also in
///   `unmapped.robodr.robot.model`; moving it out of `device` is a contract
///   change owned by the contract package (docs/SALES-READINESS.md WP2).
const KNOWN_OCSF_DEVIATIONS: &[(&str, &str)] = &[("/device", "'model' was unexpected")];

fn root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../..")
}

fn scratch(name: &str) -> PathBuf {
    let dir =
        std::env::temp_dir().join(format!("robodr-ocsf-extval-{}-{name}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

struct Report {
    messages: u64,
    /// (schema, path, message)
    errors: Vec<(String, String, String)>,
}

/// Runs the external validator; `None` when it is not installed (and not
/// required).
fn run(lines: &[String], name: &str) -> Option<Report> {
    let dir = scratch(name);
    let file = dir.join("findings.ndjson");
    std::fs::write(&file, lines.join("\n") + "\n").unwrap();
    let script = root().join("integrations/schemas/validate_findings.py");
    let out = Command::new("python3")
        .arg("-I")
        .arg(&script)
        .arg("--json")
        .arg(&file)
        .output();
    let _ = std::fs::remove_dir_all(&dir);
    let required = std::env::var_os("ROBODR_REQUIRE_EXTERNAL_VALIDATOR").is_some();
    let out = match out {
        Ok(o) if o.status.code() != Some(2) => o,
        Ok(o) => {
            let msg = String::from_utf8_lossy(&o.stderr).to_string();
            assert!(!required, "external validator unavailable: {msg}");
            eprintln!("SKIP external validator: {msg}");
            return None;
        }
        Err(e) => {
            assert!(!required, "python3 not runnable: {e}");
            eprintln!("SKIP external validator: python3 not runnable: {e}");
            return None;
        }
    };
    let v: Value = serde_json::from_slice(&out.stdout).unwrap_or_else(|e| {
        panic!(
            "validator output is not JSON ({e}): {}\n{}",
            String::from_utf8_lossy(&out.stdout),
            String::from_utf8_lossy(&out.stderr)
        )
    });
    let errors = v["errors"]
        .as_array()
        .unwrap()
        .iter()
        .map(|e| {
            (
                e["schema"].as_str().unwrap().to_string(),
                e["path"].as_str().unwrap().to_string(),
                e["message"].as_str().unwrap().to_string(),
            )
        })
        .collect();
    Some(Report {
        messages: v["messages"].as_u64().unwrap(),
        errors,
    })
}

fn is_known(e: &(String, String, String)) -> bool {
    e.0 == "ocsf"
        && KNOWN_OCSF_DEVIATIONS
            .iter()
            .any(|(p, m)| e.1 == *p && e.2.contains(m))
}

fn all_findings() -> Vec<String> {
    let ctx = common::ctx();
    let mut out = Vec::new();
    for id in catalog_ids::catalog_rule_ids() {
        for sev in [Severity::Low, Severity::Critical] {
            let dev = Deviation::new(id.clone(), sev, "detail for the external validator");
            let mut b = FindingBuilder::from_deviation(&dev, &ctx)
                .seen(common::T0, common::T0 + 5)
                .occurrences(2);
            // The health record rule requires its record (contract 2.5).
            if id == robodr_ocsf::AGENT_HEALTH_RULE {
                b = b.agent_health(common::health::sample());
            }
            let f = b.build().unwrap_or_else(|e| panic!("{id}: {e:?}"));
            out.push(to_json(&f).unwrap());
        }
    }
    out.push(to_json(&common::example_finding()).unwrap());
    let golden =
        std::fs::read_to_string(root().join("docs/contracts/robodr-finding.example.json")).unwrap();
    let golden: Value = serde_json::from_str(&golden).unwrap();
    out.push(serde_json::to_string(&golden).unwrap());
    out
}

#[test]
fn every_catalog_finding_passes_the_contract_schema_and_ocsf_1_1() {
    let lines = all_findings();
    let Some(report) = run(&lines, "all") else {
        return;
    };
    assert_eq!(report.messages, lines.len() as u64);
    let unexpected: Vec<_> = report.errors.iter().filter(|e| !is_known(e)).collect();
    assert!(
        unexpected.is_empty(),
        "external validator rejected produced findings: {:#?}",
        &unexpected[..unexpected.len().min(20)]
    );
    for (p, m) in KNOWN_OCSF_DEVIATIONS {
        assert!(
            report
                .errors
                .iter()
                .any(|e| e.0 == "ocsf" && e.1 == *p && e.2.contains(m)),
            "known OCSF deviation {p} ({m}) no longer occurs: remove it from \
             KNOWN_OCSF_DEVIATIONS and from the README's OCSF-UNCERTAIN list"
        );
    }
}

/// Tampered findings: the external validator must reject each one under the
/// named schema, and the in-crate validator must reject it too (a
/// differential check of both implementations), except where the two are
/// different by design: undeclared keys. The schemas close every object
/// (`additionalProperties: false`); `parse_and_validate` tolerates unknown
/// keys for forward compatibility within a contract major (it still applies
/// the string rules to them, `validate.rs`). [`SCHEMA_ONLY`] lists those
/// cases; the test fails if the crate starts rejecting them, so the list
/// stays exact.
#[test]
fn external_validator_rejects_tampering_like_the_crate_validator() {
    const SCHEMA_ONLY: &[&str] = &["undeclared_ocsf_attr", "undeclared_envelope_key"];
    let good: Value = serde_json::to_value(common::example_finding()).unwrap();
    type Mutation = fn(&mut Value);
    let cases: &[(&str, &str, Mutation)] = &[
        ("class_uid", "ocsf", |v| {
            v["ocsf"]["class_uid"] = 2005.into()
        }),
        ("type_uid", "ocsf", |v| {
            v["ocsf"]["type_uid"] = 200_409.into()
        }),
        ("severity_id", "ocsf", |v| {
            v["ocsf"]["severity_id"] = 7.into()
        }),
        ("status_id", "ocsf", |v| v["ocsf"]["status_id"] = 5.into()),
        ("time_type", "ocsf", |v| {
            v["ocsf"]["time"] = "2026-01-01T00:00:00Z".into()
        }),
        ("undeclared_ocsf_attr", "ocsf", |v| {
            v["ocsf"]["robot_mood"] = "fine".into()
        }),
        ("missing_finding_info_uid", "ocsf", |v| {
            v["ocsf"]["finding_info"]
                .as_object_mut()
                .unwrap()
                .remove("uid");
        }),
        ("missing_finding_id", "contract", |v| {
            v.as_object_mut().unwrap().remove("finding_id");
        }),
        ("undeclared_envelope_key", "contract", |v| {
            v["note"] = "x".into()
        }),
        ("bad_severity", "contract", |v| {
            v["severity"] = "urgent".into()
        }),
        ("markup_in_title", "contract", |v| {
            v["title"] = "<b>click</b>".into()
        }),
    ];
    let lines: Vec<String> = cases
        .iter()
        .map(|(_, _, m)| {
            let mut v = good.clone();
            m(&mut v);
            serde_json::to_string(&v).unwrap()
        })
        .collect();
    for ((name, _, _), line) in cases.iter().zip(&lines) {
        let rejected = parse_and_validate(line).is_err();
        if SCHEMA_ONLY.contains(name) {
            assert!(
                !rejected,
                "{name}: now rejected in-crate; drop it from SCHEMA_ONLY"
            );
        } else {
            assert!(
                rejected,
                "{name}: in-crate validator accepted a tampered finding"
            );
        }
    }
    let mut missed = Vec::new();
    for ((name, schema, _), line) in cases.iter().zip(&lines) {
        let Some(report) = run(std::slice::from_ref(line), name) else {
            return;
        };
        if !report.errors.iter().any(|e| e.0 == *schema && !is_known(e)) {
            missed.push(*name);
        }
    }
    assert!(
        missed.is_empty(),
        "external validator accepted tampered findings: {missed:?}"
    );
}
