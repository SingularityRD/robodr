//! Customer-facing detection catalog (gap T63): generator and drift test.
//!
//! `docs/customer/detection-rules.md` (the full rule reference; `detection-catalog.md` is the
//! customer guide around it) is generated from the trusted rule
//! catalog in `src/builder.rs` (title, description, data source, ATT&CK for
//! ICS techniques, contract version that added the entry) and from the host
//! rules shipped in `rules/robodr/*.toml`. The test regenerates it and fails
//! when the checked-in file differs, so a catalog change without a
//! regenerated document cannot merge. Regenerate with
//!
//! ```text
//! ROBODR_BLESS=1 cargo test -p robodr-ocsf --test detection_catalog
//! ```
//!
//! It also fails when `docs/contracts/robodr.findings.md` names a rule id
//! that has no catalog entry.

#[path = "support/catalog_ids.rs"]
mod catalog_ids;

use robodr_ocsf::builder::{
    CATALOG_1_3_MINOR, CATALOG_2_1_MINOR, CATALOG_2_2_MINOR, CATALOG_2_3_MINOR, CATALOG_2_4_MINOR,
};
use robodr_ocsf::{rule_info, rule_info_for_contract, RuleInfo, CONTRACT_VERSION};
use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

const DOC: &str = "docs/customer/detection-rules.md";

fn root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../..")
}

fn generic() -> RuleInfo {
    rule_info("robot.__catalog_generator__.none")
}

/// Contract versions at which the catalog grew, oldest first.
fn catalog_versions() -> Vec<String> {
    vec![
        "1.0.0".to_string(),
        format!("1.{CATALOG_1_3_MINOR}.0"),
        format!("2.{CATALOG_2_1_MINOR}.0"),
        format!("2.{CATALOG_2_2_MINOR}.0"),
        format!("2.{CATALOG_2_3_MINOR}.0"),
        format!("2.{CATALOG_2_4_MINOR}.0"),
    ]
}

/// The first contract version whose catalog has `id`'s current entry.
fn since(id: &str) -> String {
    let now = rule_info(id);
    for v in catalog_versions() {
        if rule_info_for_contract(id, &v) == now {
            return v.trim_end_matches(".0").to_string();
        }
    }
    panic!("{id}: current entry not found in any catalog version")
}

/// Markdown table cell: no pipes, no line breaks.
fn cell(s: &str) -> String {
    s.replace('|', "\\|").replace('\n', " ")
}

/// MITRE's ATT&CK for ICS table (`integrations/schemas/attack-ics-techniques.json`).
fn attack_table() -> serde_json::Value {
    let p = root().join("integrations/schemas/attack-ics-techniques.json");
    serde_json::from_str(&std::fs::read_to_string(p).unwrap()).unwrap()
}

/// Technique list; a technique MITRE revoked names its replacement.
fn attack(info: &RuleInfo, table: &serde_json::Value) -> String {
    if info.techniques.is_empty() {
        return "-".to_string();
    }
    info.techniques
        .iter()
        .map(|(id, name)| {
            let by = table["revoked"][*id]["revoked_by"]
                .as_array()
                .map(|a| {
                    a.iter()
                        .map(|p| format!("{} {}", p[0].as_str().unwrap(), p[1].as_str().unwrap()))
                        .collect::<Vec<_>>()
                        .join(", ")
                })
                .unwrap_or_default();
            if by.is_empty() {
                format!("{id} {name}")
            } else {
                format!(
                    "{id} {name} (revoked in ATT&CK for ICS {}; now {by})",
                    table["attack_version"].as_str().unwrap()
                )
            }
        })
        .collect::<Vec<_>>()
        .join("; ")
}

struct HostRule {
    name: String,
    event: String,
    category: String,
    severity: String,
}

/// The single-line `key = "value"` fields of each `[[rules]]` table. The
/// rule files are validated against Pulsar's engine by
/// `scripts/validate_rules.py`; this reads only what the catalog shows.
fn host_rules(text: &str) -> Vec<HostRule> {
    let mut out = Vec::new();
    let mut cur: Option<HostRule> = None;
    for line in text.lines() {
        let t = line.trim();
        if t == "[[rules]]" {
            out.extend(cur.take());
            cur = Some(HostRule {
                name: String::new(),
                event: String::new(),
                category: String::new(),
                severity: String::new(),
            });
            continue;
        }
        let Some(r) = cur.as_mut() else { continue };
        let Some((k, v)) = t.split_once(" = \"") else {
            continue;
        };
        let Some(v) = v.strip_suffix('"') else {
            continue;
        };
        let v = v.replace("\\\"", "\"");
        match k {
            "name" => r.name = v,
            "type" => r.event = v,
            "category" => r.category = v,
            "severity" => r.severity = v,
            _ => {}
        }
    }
    out.extend(cur);
    for r in &out {
        assert!(
            !r.name.is_empty() && !r.event.is_empty() && !r.severity.is_empty(),
            "host rule without name/type/severity: {:?}",
            r.name
        );
    }
    out
}

fn render() -> String {
    let ids = catalog_ids::catalog_rule_ids();
    let table = attack_table();
    let prefixes = catalog_ids::catalog_prefix_arms();
    let mut families: BTreeMap<String, Vec<String>> = BTreeMap::new();
    for id in &ids {
        let fam = id.split('.').nth(1).unwrap_or("other").to_string();
        families.entry(fam).or_default().push(id.clone());
    }
    let mut by_source: BTreeMap<&str, usize> = BTreeMap::new();
    for id in &ids {
        *by_source.entry(rule_info(id).data_source).or_default() += 1;
    }

    let mut o = String::new();
    o.push_str("<!-- GENERATED by crates/robodr-ocsf/tests/detection_catalog.rs; do not edit.\n");
    o.push_str(
        "     Regenerate: ROBODR_BLESS=1 cargo test -p robodr-ocsf --test detection_catalog -->\n",
    );
    o.push_str("# RoboDR detection catalog\n\n");
    o.push_str(&format!(
        "Every detection RoboDR can report, as the robot sends it in the `robodr.findings` \
         contract {CONTRACT_VERSION} (`docs/contracts/robodr.findings.md`). Generated from the \
         trusted rule catalog the sensor uses to write each finding's `title`, `description`, \
         `ocsf.finding_info.data_sources` and `mitre_predictions` / `ocsf.finding_info.attacks`, \
         so this page and the findings cannot disagree: a test fails when they do.\n\n"
    ));
    o.push_str(
        "* **Rule id** is `ocsf.finding_info.analytic.uid` and `ocsf.unmapped.robodr.rule_id`; \
         key SIEM content on it, never on the title.\n\
         * **Severity** is set by the detector per occurrence (and by the locked profile), not \
         by the catalog, so it is not listed here; the host rules below list their fixed \
         Pulsar severity.\n\
         * **ATT&CK for ICS** ids are the sensor's mapping; technique names follow the ATT&CK \
         for ICS matrix; `crates/robodr-ocsf/tests/attack_ics.rs` checks them against MITRE's \
         data (`integrations/schemas/attack-ics-techniques.json`), and a technique MITRE has \
         since revoked names its replacement. Findings keep the id they were built with until \
         a contract change moves them.\n\
         * **Since** is the contract version that added the entry. A consumer validating an \
         older message applies that message's catalog; an id without an entry is reported \
         with a generic title (\"RoboDR model-profile deviation\").\n\n",
    );
    o.push_str(&format!(
        "{} rule ids in {} families",
        ids.len(),
        families.len()
    ));
    if !prefixes.is_empty() {
        o.push_str(&format!(
            ", plus {} prefix entr{} for other ids of a family",
            prefixes.len(),
            if prefixes.len() == 1 { "y" } else { "ies" }
        ));
    }
    o.push_str(".\n\n## By data source\n\n| Data source | Rule ids |\n|---|---|\n");
    for (src, n) in &by_source {
        o.push_str(&format!("| `{src}` | {n} |\n"));
    }
    o.push_str("\n## Families\n\n");
    for fam in families.keys() {
        o.push_str(&format!(
            "* [`robot.{fam}.*`](#robot{fam}) ({})\n",
            families.get(fam).map_or(0, Vec::len)
        ));
    }
    o.push_str("* [Host rules (Pulsar)](#host-rules-pulsar)\n");
    for (fam, list) in &families {
        o.push_str(&format!("\n## robot.{fam}.*\n\n"));
        o.push_str("| Rule id | Title | Description | Data source | ATT&CK for ICS | Since |\n");
        o.push_str("|---|---|---|---|---|---|\n");
        for id in list {
            let info = rule_info(id);
            o.push_str(&format!(
                "| `{id}` | {} | {} | `{}` | {} | {} |\n",
                cell(info.title),
                cell(info.desc),
                info.data_source,
                cell(&attack(&info, &table)),
                since(id)
            ));
        }
        for p in prefixes
            .iter()
            .filter(|p| p.starts_with(&format!("robot.{fam}.")))
        {
            let probe = format!("{p}__catalog_generator_other");
            let info = rule_info(&probe);
            assert_ne!(info, generic(), "prefix arm {p} not reachable");
            o.push_str(&format!(
                "| `{p}*` (any other) | {} | {} | `{}` | {} | {} |\n",
                cell(info.title),
                cell(info.desc),
                info.data_source,
                cell(&attack(&info, &table)),
                since(&probe)
            ));
        }
    }

    o.push_str(
        "\n## Host rules (Pulsar)\n\n\
         Runtime-security rules RoboDR ships for the Pulsar engine on the robot controller \
         (`rules/robodr/*.toml`). Each match is reported as `robot.host.pulsar_threat` with \
         the rule name in the finding's detail.\n",
    );
    let dir = root().join("rules/robodr");
    let mut files: Vec<PathBuf> = std::fs::read_dir(&dir)
        .unwrap()
        .map(|e| e.unwrap().path())
        .filter(|p| p.extension().is_some_and(|x| x == "toml"))
        .collect();
    files.sort();
    let mut total = 0;
    for f in &files {
        let rules = host_rules(&std::fs::read_to_string(f).unwrap());
        total += rules.len();
        let name = f.file_name().unwrap().to_string_lossy().to_string();
        o.push_str(&format!(
            "\n### {name} ({})\n\n| Rule | Event | Category | Severity |\n|---|---|---|---|\n",
            rules.len()
        ));
        for r in rules {
            o.push_str(&format!(
                "| {} | `{}` | {} | {} |\n",
                cell(&r.name),
                r.event,
                cell(&r.category),
                r.severity
            ));
        }
    }
    o.push_str(&format!("\n{total} host rules in {} files.\n", files.len()));
    o
}

#[test]
fn detection_catalog_matches_generator() {
    let want = render();
    let path = root().join(DOC);
    if std::env::var_os("ROBODR_BLESS").is_some() {
        std::fs::write(&path, &want).unwrap();
        return;
    }
    let have = std::fs::read_to_string(&path).unwrap_or_default();
    assert!(
        have == want,
        "{DOC} is out of date with the rule catalog; regenerate with \
         ROBODR_BLESS=1 cargo test -p robodr-ocsf --test detection_catalog"
    );
}

#[test]
fn catalog_reader_finds_every_family() {
    let ids = catalog_ids::catalog_rule_ids();
    // A floor, not the exact count: the drift test pins the exact list.
    assert!(ids.len() >= 150, "only {} catalog ids found", ids.len());
    for must in [
        "robot.ros2.unknown_participant",
        "robot.motion.linear_over_envelope",
        "robot.correlate.coordinated_intrusion",
        "robot.host.pulsar_threat",
        "robot.deliver.installed",
        "robot.gateway.motion_dropped",
    ] {
        assert!(
            ids.iter().any(|i| i == must) || !robodr_ocsf::builder::rule_known(must),
            "{must} has a catalog entry but the reader missed it"
        );
    }
    assert!(ids.iter().all(|i| rule_info(i) != generic()));
}

#[test]
fn contract_doc_names_only_catalog_ids() {
    let doc = std::fs::read_to_string(root().join("docs/contracts/robodr.findings.md")).unwrap();
    let ids = catalog_ids::catalog_rule_ids();
    let mut missing = Vec::new();
    for chunk in doc.split('`').skip(1).step_by(2) {
        let looks_like_id = chunk.starts_with("robot.")
            && chunk.matches('.').count() >= 2
            && !chunk.ends_with('.')
            && !chunk.contains('*')
            && chunk
                .chars()
                .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '_' || c == '.');
        if looks_like_id && !ids.iter().any(|i| i == chunk) {
            missing.push(chunk.to_string());
        }
    }
    missing.sort();
    missing.dedup();
    assert!(
        missing.is_empty(),
        "contract doc names rule ids without a catalog entry: {missing:?}"
    );
}

#[test]
fn host_rule_reader_parses_fields() {
    let rules = host_rules(
        "[[rules]]\nname = \"A \\\"q\\\"\"\ntype = \"Exec\"\ncategory = \"execution\"\n\
         severity = \"high\"\ndescription = \"x\"\n\n[[rules]]\nname = \"B\"\ntype = \"FileOpened\"\n\
         category = \"c\"\nseverity = \"low\"\n",
    );
    assert_eq!(rules.len(), 2);
    assert_eq!(rules[0].name, "A \"q\"");
    assert_eq!(rules[1].event, "FileOpened");
    assert_eq!(rules[1].severity, "low");
}
