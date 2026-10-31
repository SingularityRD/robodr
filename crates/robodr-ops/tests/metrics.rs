//! robodr-metrics against a real robodr-agentd status.json (captured from
//! `tests/binary.rs` of robodr-agentd) and an uplink status: freshness,
//! format validity, no free text, and the example alert rules naming only
//! metrics the exporter writes.

mod common;

use common::*;
use robodr_ops::metrics::{render, Inputs};
use serde_json::{json, Value};
use std::collections::BTreeSet;
use std::process::Command;

fn agentd_status() -> Value {
    let t = std::fs::read_to_string(
        std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/data/agentd-status.json"),
    )
    .unwrap();
    serde_json::from_str(&t).unwrap()
}

/// A running agent written 1 s ago on this boot.
fn live() -> (Value, Inputs) {
    let mut s = agentd_status();
    s["running"] = json!(true);
    s["boot_id"] = json!("boot-a");
    s["updated_mono_ms"] = json!(100_000);
    s["stale_after_ms"] = json!(5_100);
    s["reasons"] = json!(["input stdin silent for 31 s \"quoted\"\nnewline"]);
    s["robot_id"] = json!("ugv\"007\\x");
    let inp = Inputs {
        agentd: Some(Ok(s.clone())),
        uplink: None,
        now_mono_ms: 101_000,
        boot_id: "boot-a".into(),
        now_wall_ms: 1_793_408_003_000,
    };
    (s, inp)
}

fn sample(text: &str, series: &str) -> Option<String> {
    text.lines()
        .find(|l| !l.starts_with('#') && l.rsplit_once(' ').map(|(s, _)| s) == Some(series))
        .and_then(|l| l.rsplit_once(' ').map(|(_, v)| v.to_string()))
}

/// Every line is a comment or `name{labels} value`; every family has one
/// TYPE line before its samples; no series is repeated.
fn assert_valid(text: &str) {
    let mut typed = BTreeSet::new();
    let mut series = BTreeSet::new();
    for l in text.lines() {
        if let Some(rest) = l.strip_prefix("# TYPE ") {
            let name = rest.split(' ').next().unwrap();
            assert!(typed.insert(name.to_string()), "two TYPE lines for {name}");
            continue;
        }
        if l.starts_with("# HELP ") {
            continue;
        }
        let (s, v) = l
            .rsplit_once(' ')
            .unwrap_or_else(|| panic!("bad line {l:?}"));
        v.parse::<f64>()
            .unwrap_or_else(|_| panic!("bad value {l:?}"));
        let name = s.split('{').next().unwrap();
        assert!(
            name.chars().all(|c| c.is_ascii_alphanumeric() || c == '_') && !name.is_empty(),
            "bad name {l:?}"
        );
        assert!(typed.contains(name), "sample before TYPE: {l:?}");
        assert!(series.insert(s.to_string()), "repeated series {s}");
    }
    assert!(text.ends_with('\n'));
}

#[test]
fn a_live_agent_is_fresh_and_ok() {
    let (_, inp) = live();
    let t = render(&inp);
    assert_valid(&t);
    assert_eq!(
        sample(&t, "robodr_agentd_status_readable").as_deref(),
        Some("1")
    );
    assert_eq!(sample(&t, "robodr_agentd_fresh").as_deref(), Some("1"));
    assert_eq!(
        sample(&t, "robodr_agentd_state{state=\"ok\"}").as_deref(),
        Some("1")
    );
    assert_eq!(
        sample(&t, "robodr_agentd_state{state=\"unknown\"}").as_deref(),
        Some("0")
    );
    assert_eq!(
        sample(&t, "robodr_agentd_status_age_seconds").as_deref(),
        Some("1.000")
    );
    assert_eq!(
        sample(&t, "robodr_agentd_spool_ready_files").as_deref(),
        Some("1")
    );
    assert_eq!(
        sample(&t, "robodr_agentd_daemon_findings_spooled").as_deref(),
        Some("1")
    );
    assert_eq!(
        sample(&t, "robodr_agentd_pipeline_binding_learned").as_deref(),
        Some("0")
    );
    assert_eq!(
        sample(&t, "robodr_agentd_input_received{input=\"stdin\"}").as_deref(),
        Some("1")
    );
    assert_eq!(
        sample(&t, "robodr_agentd_health_reasons").as_deref(),
        Some("1")
    );
    // Label values escaped; the free-text reason never exported.
    assert!(t.contains("robot_id=\"ugv\\\"007\\\\x\""), "{t}");
    assert!(!t.contains("silent for 31"));
}

#[test]
fn a_stale_hung_or_stopped_agent_is_unknown_never_ok() {
    // Hung: not rewritten for longer than stale_after_ms.
    let (_, mut inp) = live();
    inp.now_mono_ms = 100_000 + 5_101;
    let t = render(&inp);
    assert_eq!(sample(&t, "robodr_agentd_fresh").as_deref(), Some("0"));
    assert_eq!(
        sample(&t, "robodr_agentd_state{state=\"ok\"}").as_deref(),
        Some("0")
    );
    assert_eq!(
        sample(&t, "robodr_agentd_state{state=\"unknown\"}").as_deref(),
        Some("1")
    );
    // Another boot: no age either (monotonic clocks of two boots).
    let (_, mut inp) = live();
    inp.boot_id = "boot-b".into();
    let t = render(&inp);
    assert_eq!(sample(&t, "robodr_agentd_fresh").as_deref(), Some("0"));
    assert!(sample(&t, "robodr_agentd_status_age_seconds").is_none());
    // Stopped cleanly (the captured file itself: running false).
    let (_, mut inp) = live();
    let mut s = agentd_status();
    s["boot_id"] = json!("boot-a");
    inp.agentd = Some(Ok(s));
    let t = render(&inp);
    assert_eq!(sample(&t, "robodr_agentd_running").as_deref(), Some("0"));
    assert_eq!(
        sample(&t, "robodr_agentd_state{state=\"unknown\"}").as_deref(),
        Some("1")
    );
    // Unreadable.
    let (_, mut inp) = live();
    inp.agentd = Some(Err("No such file".into()));
    let t = render(&inp);
    assert_valid(&t);
    assert_eq!(
        sample(&t, "robodr_agentd_status_readable").as_deref(),
        Some("0")
    );
    assert_eq!(
        sample(&t, "robodr_agentd_state{state=\"unknown\"}").as_deref(),
        Some("1")
    );
    // Not an object.
    let (_, mut inp) = live();
    inp.agentd = Some(Ok(json!([1, 2])));
    assert_eq!(
        sample(&render(&inp), "robodr_agentd_status_readable").as_deref(),
        Some("0")
    );
}

fn uplink_status() -> Value {
    json!({
        "format": "robodr-uplink-status/1",
        "state": "blocked",
        "updated_at_ms": 1_793_408_000_000u64,
        "pid": 4242,
        "last_success_at_ms": 1_793_400_000_000u64,
        "last_delivery_at_ms": null,
        "last_error": { "at_ms": 1, "kind": "refused", "status": 401, "code": "unknown_key",
                        "message": "secret detail from server", "retry_after_s": null },
        "consecutive_failures": 7,
        "stuck_since_ms": 1_793_407_000_000u64,
        "pending_failed_runs": 7,
        "next_attempt_at_ms": 1_793_408_060_000u64,
        "dead_letter_malformed": 0,
        "quarantined_unreadable": 0,
        "pending_batch_id": "b-123",
        "pending_source": "spool",
        "pending_lines": 12,
        "backlog": { "spool_ready": 40, "diode_batches": null, "reinject_generations": 0 },
        "sent_lines_total": 100, "accepted_total": 88, "rejected_total": 0, "dead_lettered_total": 0
    })
}

#[test]
fn uplink_states_ages_and_counters() {
    let (_, mut inp) = live();
    inp.uplink = Some(Ok(uplink_status()));
    let t = render(&inp);
    assert_valid(&t);
    assert_eq!(
        sample(&t, "robodr_uplink_state{state=\"blocked\"}").as_deref(),
        Some("1")
    );
    assert_eq!(
        sample(&t, "robodr_uplink_state{state=\"ok\"}").as_deref(),
        Some("0")
    );
    assert_eq!(
        sample(&t, "robodr_uplink_status_age_seconds").as_deref(),
        Some("3.000")
    );
    assert_eq!(
        sample(&t, "robodr_uplink_stuck_seconds").as_deref(),
        Some("1003.000")
    );
    assert_eq!(
        sample(&t, "robodr_uplink_consecutive_failures").as_deref(),
        Some("7")
    );
    assert_eq!(
        sample(&t, "robodr_uplink_backlog_spool_ready").as_deref(),
        Some("40")
    );
    assert!(sample(&t, "robodr_uplink_last_delivery_age_seconds").is_none());
    // Times, the pid, error text and batch ids are not counters.
    for absent in [
        "robodr_uplink_pid",
        "robodr_uplink_next_attempt_at_ms",
        "secret detail",
        "b-123",
        "last_error",
    ] {
        assert!(!t.contains(absent), "{absent}: {t}");
    }
}

/// Every `robodr_*` metric named in the example alert rules is written by
/// the exporter for a live agent with an uplink (so a renamed field cannot
/// silently disable an alert).
#[test]
fn alert_rules_name_only_exported_metrics() {
    let rules = std::fs::read_to_string(repo().join("packaging/metrics/robodr-alerts.example.yml"))
        .unwrap();
    let (_, mut inp) = live();
    let mut u = uplink_status();
    u["last_delivery_at_ms"] = json!(1_793_400_000_000u64);
    inp.uplink = Some(Ok(u));
    let t = render(&inp);
    let exported: BTreeSet<&str> = t
        .lines()
        .filter(|l| !l.starts_with('#'))
        .filter_map(|l| l.split(['{', ' ']).next())
        .collect();
    let mut named = BTreeSet::new();
    for word in rules.split(|c: char| !(c.is_ascii_alphanumeric() || c == '_')) {
        if word.starts_with("robodr_") {
            named.insert(word.to_string());
        }
    }
    assert!(named.len() >= 10, "{named:?}");
    for n in &named {
        assert!(
            exported.contains(n.as_str()),
            "alert rule names {n}, which robodr-metrics does not export"
        );
    }
    // Every rule has an expr and a severity.
    assert_eq!(
        rules.matches("- alert:").count(),
        rules.matches("severity:").count()
    );
}

#[test]
fn cli_writes_atomically_and_validates_arguments() {
    let t = Tmp::new("metrics-cli");
    let bin = env!("CARGO_BIN_EXE_robodr-metrics");
    let st = t.put("/status.json", &agentd_status().to_string());
    let out = t.path("/out/robodr.prom");
    std::fs::create_dir_all(out.parent().unwrap()).unwrap();
    let o = Command::new(bin)
        .args([
            "--agentd-status",
            st.to_str().unwrap(),
            "--no-uplink",
            "--out",
            out.to_str().unwrap(),
        ])
        .output()
        .unwrap();
    assert!(o.status.success(), "{}", String::from_utf8_lossy(&o.stderr));
    let text = std::fs::read_to_string(&out).unwrap();
    assert_valid(&text);
    assert_eq!(mode(&out), 0o644);
    // Only the .prom file: no temporary left behind.
    assert_eq!(std::fs::read_dir(out.parent().unwrap()).unwrap().count(), 1);
    // Missing status: still written, readable 0.
    let o = Command::new(bin)
        .args([
            "--agentd-status",
            "/nonexistent/status.json",
            "--no-uplink",
            "--stdout",
        ])
        .output()
        .unwrap();
    assert!(o.status.success());
    assert!(String::from_utf8_lossy(&o.stdout).contains("robodr_agentd_status_readable 0"));
    for bad in [
        vec!["--out", "relative.prom"],
        vec!["--out", "/tmp/x.txt"],
        vec!["--stdout", "--out", "/tmp/x.prom"],
        vec!["--bogus"],
    ] {
        let o = Command::new(bin).args(&bad).output().unwrap();
        assert_eq!(o.status.code(), Some(2), "{bad:?}");
    }
}
