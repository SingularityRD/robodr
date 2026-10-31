//! Scoring: did the daemon report what a scenario must produce, and how
//! fast?
//!
//! Input is either an agentd spool directory (`ready/` and `acked/` hold one
//! JSON spool record per finding, its `value` the finding) or an NDJSON file
//! of findings (what a SOC or SIEM received). For a spool, each record's
//! file modification time is when the finding was persisted on the robot:
//! with the injection time of a live run (`injected_unix_ms`), the report
//! gives the **time to detect** per expected rule (gap T64).
//!
//! The report is JSON; `pass` is true when every expected rule id was seen
//! at least once. Findings are matched on `entity_context.rule_id`, never on
//! titles or free text (which are attacker-influenced in places).

use crate::scenario::Scenario;
use serde_json::{json, Value};
use std::collections::BTreeMap;
use std::path::Path;
use std::time::UNIX_EPOCH;

/// One finding seen.
#[derive(Debug, Clone)]
pub struct Seen {
    pub rule_id: String,
    /// When it was spooled on the robot (spool input only).
    pub spooled_unix_ms: Option<u64>,
    /// `ocsf.time` (ms): the detection time the sensor wrote.
    pub ocsf_time_ms: Option<u64>,
}

fn from_value(v: &Value, spooled: Option<u64>) -> Option<Seen> {
    let rule = v
        .pointer("/entity_context/rule_id")
        .and_then(Value::as_str)?
        .to_string();
    Some(Seen {
        rule_id: rule,
        spooled_unix_ms: spooled,
        ocsf_time_ms: v.pointer("/ocsf/time").and_then(Value::as_u64),
    })
}

/// Findings from a spool directory or an NDJSON file (findings, or spool
/// records with a string `value`). Unparseable lines and files are skipped
/// and counted.
pub fn load(path: &Path) -> std::io::Result<(Vec<Seen>, usize)> {
    let mut out = Vec::new();
    let mut bad = 0;
    if path.is_dir() {
        for sub in ["acked", "ready"] {
            let Ok(rd) = std::fs::read_dir(path.join(sub)) else {
                continue;
            };
            for e in rd.flatten() {
                let p = e.path();
                let mtime = e
                    .metadata()
                    .and_then(|m| m.modified())
                    .ok()
                    .and_then(|t| t.duration_since(UNIX_EPOCH).ok())
                    .map(|d| d.as_millis() as u64);
                let rec: Option<Value> = std::fs::read(&p)
                    .ok()
                    .and_then(|b| serde_json::from_slice(&b).ok());
                let finding = rec
                    .as_ref()
                    .and_then(|r| r.get("value"))
                    .and_then(Value::as_str)
                    .and_then(|s| serde_json::from_str::<Value>(s).ok());
                match finding.as_ref().and_then(|f| from_value(f, mtime)) {
                    Some(s) => out.push(s),
                    None => bad += 1,
                }
            }
        }
    } else {
        let text = std::fs::read_to_string(path)?;
        for line in text.lines().filter(|l| !l.trim().is_empty()) {
            let v: Option<Value> = serde_json::from_str(line).ok();
            let v = match v {
                Some(r) if r.get("value").is_some_and(Value::is_string) => r
                    .get("value")
                    .and_then(Value::as_str)
                    .and_then(|s| serde_json::from_str(s).ok()),
                other => other,
            };
            match v.as_ref().and_then(|f| from_value(f, None)) {
                Some(s) => out.push(s),
                None => bad += 1,
            }
        }
    }
    Ok((out, bad))
}

/// The score of `scenarios` over `seen`, as JSON.
pub fn report(scenarios: &[Scenario], seen: &[Seen], injected_unix_ms: Option<u64>) -> Value {
    let mut counts: BTreeMap<&str, (u64, Option<u64>)> = BTreeMap::new();
    for s in seen {
        let e = counts.entry(s.rule_id.as_str()).or_insert((0, None));
        e.0 += 1;
        if let Some(t) = s.spooled_unix_ms {
            e.1 = Some(e.1.map_or(t, |x| x.min(t)));
        }
    }
    let mut all_pass = true;
    let per: Vec<Value> = scenarios
        .iter()
        .map(|sc| {
            let rules: Vec<Value> = sc
                .expected()
                .iter()
                .map(|r| {
                    let (n, first) = counts.get(r).copied().unwrap_or((0, None));
                    let ttd = match (first, injected_unix_ms) {
                        (Some(f), Some(i)) => Some(f.saturating_sub(i)),
                        _ => None,
                    };
                    json!({"rule_id": r, "count": n, "first_spooled_unix_ms": first,
                           "time_to_detect_ms": ttd})
                })
                .collect();
            let pass = rules.iter().all(|r| r["count"].as_u64() > Some(0));
            all_pass &= pass;
            json!({"scenario": sc.name(), "pass": pass, "expected": rules})
        })
        .collect();
    let mut other: Vec<(&str, u64)> = counts
        .iter()
        .filter(|(r, _)| !scenarios.iter().any(|s| s.expected().contains(r)))
        .map(|(r, (n, _))| (*r, *n))
        .collect();
    other.sort();
    json!({
        "pass": all_pass,
        "findings": seen.len(),
        "scenarios": per,
        "other_rule_ids": other.into_iter().map(|(r, n)| json!({"rule_id": r, "count": n})).collect::<Vec<_>>(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn seen(r: &str, t: Option<u64>) -> Seen {
        Seen {
            rule_id: r.into(),
            spooled_unix_ms: t,
            ocsf_time_ms: None,
        }
    }

    #[test]
    fn pass_needs_every_expected_rule() {
        let s = [
            seen("robot.ros2.unknown_participant", Some(1_500)),
            seen("robot.ros2.unknown_participant", Some(1_200)),
            seen("robot.rtps.discovery_removal", None),
        ];
        let r = report(&[Scenario::RogueParticipant], &s, Some(1_000));
        assert_eq!(r["pass"], true);
        assert_eq!(r["scenarios"][0]["expected"][0]["count"], 2);
        assert_eq!(r["scenarios"][0]["expected"][0]["time_to_detect_ms"], 200);
        assert_eq!(
            r["other_rule_ids"][0]["rule_id"],
            "robot.rtps.discovery_removal"
        );
        let r = report(&[Scenario::RogueParticipant, Scenario::GuidSpray], &s, None);
        assert_eq!(r["pass"], false);
        assert_eq!(r["scenarios"][1]["pass"], false);
    }

    #[test]
    fn loads_ndjson_findings_and_spool_records() {
        let dir =
            std::env::temp_dir().join(format!("robodr-attack-sim-score-{}", std::process::id()));
        std::fs::create_dir_all(dir.join("ready")).unwrap();
        let f = json!({"entity_context": {"rule_id": "robot.x.y"}, "ocsf": {"time": 5}});
        let rec = json!({"value": f.to_string()});
        std::fs::write(dir.join("ready/1.json"), rec.to_string()).unwrap();
        std::fs::write(dir.join("ready/2.json"), "junk").unwrap();
        let (s, bad) = load(&dir).unwrap();
        assert_eq!((s.len(), bad), (1, 1));
        assert!(s[0].spooled_unix_ms.is_some());
        let nd = dir.join("f.ndjson");
        std::fs::write(&nd, format!("{f}\n{rec}\nnot json\n")).unwrap();
        let (s, bad) = load(&nd).unwrap();
        assert_eq!((s.len(), bad), (2, 1));
        assert_eq!(s[0].ocsf_time_ms, Some(5));
        std::fs::remove_dir_all(&dir).unwrap();
    }
}
