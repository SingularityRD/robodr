//! Keeps `robodr_correlate::catalog` in sync with the rest of the repo: the
//! Pulsar rule names in `rules/robodr/*.toml` and the `robot.*` ids used by
//! the other crates' sources.

use std::collections::BTreeSet;
use std::fs;
use std::path::{Path, PathBuf};

use robodr_correlate::catalog::{NETWORK_AND_AGENT_RULES, PULSAR_RULES};

fn repo() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../..")
}

fn rs_files(dir: &Path, out: &mut Vec<PathBuf>) {
    let Ok(rd) = fs::read_dir(dir) else { return };
    for e in rd.flatten() {
        let p = e.path();
        if p.is_dir() {
            rs_files(&p, out);
        } else if p.extension().is_some_and(|x| x == "rs") {
            out.push(p);
        }
    }
}

#[test]
fn pulsar_names_match_rule_files() {
    let dir = repo().join("rules/robodr");
    let mut names = BTreeSet::new();
    for e in fs::read_dir(&dir).expect("rules/robodr exists").flatten() {
        let p = e.path();
        if p.extension().is_none_or(|x| x != "toml") {
            continue;
        }
        let text = fs::read_to_string(&p).unwrap();
        for line in text.lines() {
            if let Some(rest) = line.trim().strip_prefix("name = \"") {
                names.insert(rest.trim_end_matches('"').to_string());
            }
        }
    }
    let catalog: BTreeSet<String> = PULSAR_RULES.iter().map(|s| s.to_string()).collect();
    let missing: Vec<_> = names.difference(&catalog).collect();
    let stale: Vec<_> = catalog.difference(&names).collect();
    assert!(
        missing.is_empty() && stale.is_empty(),
        "catalog out of sync with rules/robodr: missing {missing:?}, stale {stale:?}"
    );
}

#[test]
fn robot_ids_exist_in_other_crates() {
    let mut files = Vec::new();
    for e in fs::read_dir(repo().join("crates")).unwrap().flatten() {
        let p = e.path();
        if p.file_name().is_some_and(|n| n == "robodr-correlate") {
            continue;
        }
        rs_files(&p.join("src"), &mut files);
    }
    assert!(!files.is_empty());
    let all: String = files
        .iter()
        .filter_map(|p| fs::read_to_string(p).ok())
        .collect::<Vec<_>>()
        .join("\n");
    let missing: Vec<&str> = NETWORK_AND_AGENT_RULES
        .iter()
        .copied()
        .filter(|id| !all.contains(&format!("\"{id}\"")))
        .collect();
    assert!(
        missing.is_empty(),
        "catalog ids no longer produced anywhere: {missing:?}"
    );
}

/// `robot.*` literals in other crates' sources that are not signals the
/// correlation engine sees: ids the daemon never feeds back
/// (`robot.agent.correlation_pressure`, the periodic health record
/// `robot.agent.health`, `robot.correlate.*`), the finding ids of a
/// forwarded Pulsar threat (`robot.host.*`: agentd feeds the threat as its
/// Pulsar rule name, which is in `PULSAR_RULES`), a probe that is never
/// emitted, and unit-test fixtures.
const NOT_SIGNALS: &[&str] = &[
    "robot.agent.correlation_pressure",
    "robot.agent.health",
    "robot.host.pulsar_threat",
    "robot.agent.config_check",
    "robot.capture.y",
    "robot.rtps.x",
    "robot.motion.envelope_exceeded",
    "robot.hostile.x",
    "robot.x.y",
    "robot.x.z",
];

#[test]
fn every_robot_id_emitted_elsewhere_is_in_the_catalog() {
    let mut files = Vec::new();
    for e in fs::read_dir(repo().join("crates")).unwrap().flatten() {
        let p = e.path();
        // robodr-ocsf only holds the OCSF catalog of these ids.
        if p.file_name()
            .is_some_and(|n| n == "robodr-correlate" || n == "robodr-ocsf")
        {
            continue;
        }
        rs_files(&p.join("src"), &mut files);
    }
    let mut missing = std::collections::BTreeSet::new();
    for text in files.iter().filter_map(|p| fs::read_to_string(p).ok()) {
        for (i, _) in text.match_indices("\"robot.") {
            let rest = &text[i + 1..];
            let Some(end) = rest.find('"') else { continue };
            let id = &rest[..end];
            let shaped = id.split('.').count() == 3
                && id.split('.').all(|s| !s.is_empty())
                && id.bytes().all(|b| {
                    b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'_' || b == b'.'
                });
            if shaped
                && !id.starts_with("robot.correlate.")
                && !id.starts_with("robot.host.")
                && !NOT_SIGNALS.contains(&id)
                && !NETWORK_AND_AGENT_RULES.contains(&id)
            {
                missing.insert(id.to_string());
            }
        }
    }
    assert!(
        missing.is_empty(),
        "robot.* ids emitted but missing from NETWORK_AND_AGENT_RULES: {missing:?}"
    );
}
