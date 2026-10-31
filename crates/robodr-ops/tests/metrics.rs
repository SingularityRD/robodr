//! robodr-metrics against a real robodr-agentd status.json (captured from
//! `tests/binary.rs` of robodr-agentd), an uplink status serialised from
//! robodr-uplink's own `Status` type and `systemctl show` output: freshness,
//! format validity, no free text, and the example alert rules naming only
//! metrics the exporter writes.

mod common;

use common::*;
use robodr_export::retention::{StateUsage, Usage};
use robodr_export::uplink::service::{Backlog, Snapshot, Status, StatusError, STATUS_FORMAT};
use robodr_ops::metrics::{render, units_show_args, Inputs, ROBODR_UNITS};
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
        units: None,
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

/// What robodr-uplink writes as `uplink-status.json`: its own `Status`
/// type serialised, so a renamed or removed field fails to compile here or
/// fails the alert-rule test below, instead of silently disabling an alert.
fn uplink_status() -> Value {
    let s = Status {
        format: STATUS_FORMAT.into(),
        state: "blocked".into(),
        updated_at_ms: 1_793_408_000_000,
        pid: 4242,
        last_success_at_ms: Some(1_793_400_000_000),
        last_delivery_at_ms: None,
        last_error: Some(StatusError {
            at_ms: 1,
            kind: "refused".into(),
            status: Some(401),
            code: Some("unknown_key".into()),
            message: "secret detail from server".into(),
            retry_after_s: None,
        }),
        consecutive_failures: 7,
        stuck_since_ms: Some(1_793_407_000_000),
        pending_failed_runs: 7,
        next_attempt_at_ms: Some(1_793_408_060_000),
        dead_letter_malformed: 0,
        quarantined_unreadable: 0,
        snapshot: Snapshot {
            pending_batch_id: Some("b-123".into()),
            pending_source: Some("spool".into()),
            pending_lines: 12,
            backlog: Backlog {
                spool_ready: Some(40),
                diode_batches: None,
                reinject_generations: 0,
            },
            sent_lines_total: 100,
            accepted_total: 88,
            rejected_total: 0,
            dead_lettered_total: 0,
            state_usage: Some(StateUsage {
                done_markers: Usage {
                    entries: 3,
                    bytes: 300,
                },
                measured_at_ms: 1_793_408_000_000,
                ..Default::default()
            }),
            state_usage_error: None,
            out_prune_error: None,
        },
        credentials: Vec::new(),
    };
    serde_json::to_value(s).unwrap()
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
    assert_eq!(
        sample(&t, "robodr_uplink_state_usage_done_markers_entries").as_deref(),
        Some("3")
    );
    // Times, the pid, error text and batch ids are not counters.
    for absent in [
        "robodr_uplink_pid",
        "robodr_uplink_next_attempt_at_ms",
        "secret detail",
        "b-123",
        "last_error",
        "measured_at",
    ] {
        assert!(!t.contains(absent), "{absent}: {t}");
    }
}

/// A state the exporter does not know is `other`: no text from the file
/// ever reaches a label value.
#[test]
fn an_unknown_uplink_state_is_other() {
    let (_, mut inp) = live();
    let mut u = uplink_status();
    u["state"] = json!("weird \"free\" text");
    inp.uplink = Some(Ok(u));
    let t = render(&inp);
    assert_valid(&t);
    assert_eq!(
        sample(&t, "robodr_uplink_state{state=\"other\"}").as_deref(),
        Some("1")
    );
    assert_eq!(
        sample(&t, "robodr_uplink_state{state=\"blocked\"}").as_deref(),
        Some("0")
    );
    assert!(!t.contains("weird"), "{t}");
    assert_eq!(t.matches("robodr_uplink_state{").count(), 5, "{t}");
}

/// `systemctl show` output as systemd 255 prints it for these properties.
fn show_output() -> String {
    let mut s = String::new();
    for u in ROBODR_UNITS {
        let (load, active, file, restarts) = match *u {
            "robodr-agentd.service" => ("loaded", "active", "enabled", 0),
            // Killed at MemoryMax= by an event storm, restarted 4 times.
            "robodr-pulsard.service" => ("loaded", "activating", "enabled", 4),
            "robodr-uplink.service" => ("loaded", "failed", "enabled-runtime", 1),
            "robodr-executor.service" => ("loaded", "inactive", "disabled", 0),
            // Enabled, but its start job failed an Assert...= (no BTF):
            // systemd leaves it inactive, not failed.
            "robodr-deliverd.service" => ("loaded", "inactive", "enabled", 0),
            _ => ("not-found", "inactive", "", 0),
        };
        s.push_str(&format!(
            "Id={u}\nLoadState={load}\nActiveState={active}\nUnitFileState={file}\nNRestarts={restarts}\n\n"
        ));
    }
    // A unit the exporter never asked for is ignored.
    s.push_str("Id=evil\"\nLoadState=loaded\nActiveState=failed\nNRestarts=9\n");
    s
}

#[test]
fn unit_states_and_restarts() {
    let (_, mut inp) = live();
    inp.units = Some(Ok(show_output()));
    let t = render(&inp);
    assert_valid(&t);
    assert_eq!(sample(&t, "robodr_units_readable").as_deref(), Some("1"));
    let s = |m: &str, u: &str| sample(&t, &format!("{m}{{unit=\"{u}\"}}"));
    assert_eq!(
        s("robodr_unit_active", "robodr-agentd.service").as_deref(),
        Some("1")
    );
    assert_eq!(
        s("robodr_unit_active", "robodr-pulsard.service").as_deref(),
        Some("0")
    );
    assert_eq!(
        s("robodr_unit_restarts", "robodr-pulsard.service").as_deref(),
        Some("4")
    );
    assert_eq!(
        s("robodr_unit_failed", "robodr-uplink.service").as_deref(),
        Some("1")
    );
    // Installed but not started (not enabled on this robot): not failed.
    assert_eq!(
        s("robodr_unit_failed", "robodr-executor.service").as_deref(),
        Some("0")
    );
    // Enabled: the site expects it to run (RoboDRUnitDown).
    for (u, want) in [
        ("robodr-agentd.service", "1"),
        ("robodr-uplink.service", "1"),
        ("robodr-executor.service", "0"),
        ("robodr-deliverd.service", "1"),
    ] {
        assert_eq!(s("robodr_unit_enabled", u).as_deref(), Some(want), "{u}");
    }
    assert_eq!(
        s("robodr_unit_failed", "robodr-deliverd.service").as_deref(),
        Some("0")
    );
    assert_eq!(
        s("robodr_unit_active", "robodr-deliverd.service").as_deref(),
        Some("0")
    );
    // Not installed: not exported. Unknown units: never exported.
    assert!(s("robodr_unit_active", "robodr-depot.service").is_none());
    assert!(!t.contains("evil"), "{t}");
    // systemd did not answer.
    inp.units = Some(Err("System has not been booted with systemd".into()));
    let t = render(&inp);
    assert_valid(&t);
    assert_eq!(sample(&t, "robodr_units_readable").as_deref(), Some("0"));
    assert!(!t.contains("robodr_unit_active"));
    assert!(!t.contains("booted"));
}

/// The exporter asks for exactly the services the packages ship.
#[test]
fn unit_list_matches_the_packaged_services() {
    let mut shipped: Vec<String> = std::fs::read_dir(repo().join("packaging/systemd"))
        .unwrap()
        .filter_map(|e| e.unwrap().file_name().into_string().ok())
        .filter(|n| n.starts_with("robodr-") && n.ends_with(".service"))
        .collect();
    shipped.sort();
    let mut ours: Vec<String> = ROBODR_UNITS.iter().map(|s| s.to_string()).collect();
    ours.sort();
    assert_eq!(ours, shipped);
    let args = units_show_args();
    assert_eq!(args[0], "show");
    assert!(args[1].contains("NRestarts") && args[1].contains("ActiveState"));
    assert!(args[1].contains("UnitFileState"));
    assert_eq!(args.len(), 2 + ROBODR_UNITS.len());
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
    inp.units = Some(Ok(show_output()));
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
            "--no-units",
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
    let text = String::from_utf8_lossy(&o.stdout);
    assert!(text.contains("robodr_agentd_status_readable 0"));
    // Without --no-units systemd is asked: answered or not, the family is
    // there (this test may run where PID 1 is not systemd).
    assert!(text.contains("robodr_units_readable "), "{text}");
    assert_valid(&text);
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
