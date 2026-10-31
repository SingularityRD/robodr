//! Accepted findings: append-only NDJSON on disk, the newest in memory,
//! and the metrics the viewer shows.
//!
//! An entry is stored only for a line the reference consumer accepted
//! (`created` or `updated`; duplicates are not stored again). Its
//! verification status comes from the line: `verified` when it carried a
//! `sig` (the consumer refuses a line whose signature does not verify), or
//! `unsigned` (accepted only for robots that do not require signatures).
//!
//! **Time to SOC** (T64) = arrival time at this SOC minus the finding's own
//! detection time `ocsf.time` (the sensor's clock when it reported the
//! finding, also for replayed captures), per robot and overall. Clocks must
//! be synchronised; values outside `0..=MAX_TTS_MS` (clock skew, findings
//! re-sent from an old spool) are counted as `not_comparable` instead of
//! skewing the percentiles.

use serde_json::{json, Value};
use std::collections::{BTreeMap, HashSet, VecDeque};
use std::io::Write;
use std::path::PathBuf;

/// Findings kept in memory for the viewer.
pub const MEMORY: usize = 2000;
/// Largest time to SOC counted (1 hour).
pub const MAX_TTS_MS: u64 = 3_600_000;

#[derive(Debug, Default)]
pub struct Store {
    file: Option<PathBuf>,
    recent: VecDeque<Value>,
    seen_uids: HashSet<String>,
    tts_ms: Vec<u64>,
    tts_by_robot: BTreeMap<String, Vec<u64>>,
    not_comparable: u64,
    by_rule: BTreeMap<String, u64>,
    by_severity: BTreeMap<String, u64>,
    by_verification: BTreeMap<String, u64>,
    total: u64,
}

impl Store {
    /// A store appending to `file` (created if missing), or memory only.
    pub fn new(file: Option<PathBuf>) -> Self {
        Store {
            file,
            ..Store::default()
        }
    }

    /// Record the accepted lines of a 200 ingest answer. `body` is the
    /// request body, `answer` the consumer's JSON answer (its `rejected`
    /// line numbers are skipped).
    pub fn ingest(&mut self, body: &[u8], answer: &Value, received_unix_ms: u64) -> usize {
        let rejected: HashSet<u64> = answer
            .get("rejected")
            .and_then(Value::as_array)
            .map(|a| {
                a.iter()
                    .filter_map(|r| r.get("line").and_then(Value::as_u64))
                    .collect()
            })
            .unwrap_or_default();
        let body = body.strip_suffix(b"\n").unwrap_or(body);
        let mut n = 0;
        for (i, raw) in body.split(|c| *c == b'\n').enumerate() {
            if rejected.contains(&(i as u64 + 1)) {
                continue;
            }
            let Ok(line) = serde_json::from_slice::<Value>(raw) else {
                continue;
            };
            let Some(Ok(finding)) = line
                .get("value")
                .and_then(Value::as_str)
                .map(serde_json::from_str::<Value>)
            else {
                continue;
            };
            let uid = finding
                .pointer("/ocsf/metadata/uid")
                .and_then(Value::as_str)
                .unwrap_or_default()
                .to_string();
            if uid.is_empty() || !self.seen_uids.insert(uid) {
                continue;
            }
            let (status, key_id) = match line.get("sig") {
                Some(Value::Object(s)) => ("verified", s.get("key_id").cloned()),
                _ => ("unsigned", None),
            };
            let tts = finding
                .pointer("/ocsf/time")
                .and_then(Value::as_u64)
                .and_then(|t| received_unix_ms.checked_sub(t))
                .filter(|d| *d <= MAX_TTS_MS);
            let robot = finding
                .pointer("/entity_context/robot/id")
                .and_then(Value::as_str)
                .unwrap_or("?")
                .to_string();
            match tts {
                Some(d) => {
                    self.tts_ms.push(d);
                    self.tts_by_robot.entry(robot).or_default().push(d);
                }
                None => self.not_comparable += 1,
            }
            let rule = finding
                .pointer("/entity_context/rule_id")
                .and_then(Value::as_str)
                .unwrap_or("?")
                .to_string();
            *self.by_rule.entry(rule).or_default() += 1;
            *self
                .by_severity
                .entry(
                    finding
                        .get("severity")
                        .and_then(Value::as_str)
                        .unwrap_or("?")
                        .to_string(),
                )
                .or_default() += 1;
            *self.by_verification.entry(status.to_string()).or_default() += 1;
            self.total += 1;
            let entry = json!({
                "received_unix_ms": received_unix_ms,
                "time_to_soc_ms": tts,
                "verification": {"status": status, "key_id": key_id},
                "finding": finding,
            });
            if let Some(path) = &self.file {
                if let Ok(mut f) = std::fs::OpenOptions::new()
                    .create(true)
                    .append(true)
                    .open(path)
                {
                    let _ = writeln!(f, "{entry}");
                }
            }
            if self.recent.len() >= MEMORY {
                self.recent.pop_front();
            }
            self.recent.push_back(entry);
            n += 1;
        }
        n
    }

    /// Newest first, at most `limit`.
    pub fn recent(&self, limit: usize) -> Vec<&Value> {
        self.recent.iter().rev().take(limit).collect()
    }

    pub fn metrics(&self) -> Value {
        let mut by_robot = serde_json::Map::new();
        for (robot, v) in &self.tts_by_robot {
            by_robot.insert(robot.clone(), percentiles(v));
        }
        let mut all = percentiles(&self.tts_ms);
        if let Some(o) = all.as_object_mut() {
            o.insert("not_comparable".into(), json!(self.not_comparable));
        }
        json!({
            "findings": self.total,
            "by_rule": self.by_rule,
            "by_severity": self.by_severity,
            "by_verification": self.by_verification,
            "time_to_soc_ms": all,
            "time_to_soc_ms_by_robot": by_robot,
        })
    }
}

/// Count, p50, p90, p99 and max of `v` (nearest rank).
fn percentiles(v: &[u64]) -> Value {
    let mut v = v.to_vec();
    v.sort_unstable();
    let pct = |p: f64| -> Option<u64> {
        let last = v.len().checked_sub(1)?;
        v.get(((p * last as f64).round() as usize).min(last))
            .copied()
    };
    json!({"count": v.len(), "p50": pct(0.5), "p90": pct(0.9), "p99": pct(0.99), "max": v.last()})
}

#[cfg(test)]
mod tests {
    use super::*;

    fn line(uid: &str, rule: &str, time: u64, signed: bool) -> String {
        let f = json!({"ocsf": {"metadata": {"uid": uid}, "time": time},
                       "entity_context": {"rule_id": rule}, "severity": "high"});
        let mut l = json!({"value": f.to_string()});
        l["sig"] = if signed {
            json!({"alg": "ed25519", "key_id": "k", "sig": "00"})
        } else {
            Value::Null
        };
        l.to_string()
    }

    #[test]
    fn stores_accepted_lines_once_with_time_to_soc() {
        let mut s = Store::new(None);
        let body = format!(
            "{}\n{}\n{}\n{}\n",
            line("a", "robot.x.y", 1_000, true),
            line("b", "robot.x.y", 1_500, false),
            line("c", "robot.x.z", 10, true),
            line("a", "robot.x.y", 1_000, true)
        );
        let answer = json!({"rejected": [{"line": 3}]});
        assert_eq!(s.ingest(body.as_bytes(), &answer, 2_000), 2);
        let m = s.metrics();
        assert_eq!(m["findings"], 2);
        assert_eq!(m["by_verification"]["verified"], 1);
        assert_eq!(m["by_verification"]["unsigned"], 1);
        assert_eq!(m["time_to_soc_ms"]["p50"], 1000);
        assert_eq!(m["time_to_soc_ms"]["max"], 1000);
        assert_eq!(m["time_to_soc_ms_by_robot"]["?"]["count"], 2);
        // Times outside 0..=MAX_TTS_MS (skew, old spools) are not comparable.
        let body = line("d", "robot.x.y", 1, true);
        assert_eq!(s.ingest(body.as_bytes(), &json!({}), MAX_TTS_MS + 10), 1);
        assert_eq!(s.metrics()["time_to_soc_ms"]["not_comparable"], 1);
        assert_eq!(s.recent(1)[0]["finding"]["ocsf"]["metadata"]["uid"], "d");
    }
}
