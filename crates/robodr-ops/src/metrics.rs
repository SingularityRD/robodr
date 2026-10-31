//! Prometheus textfile exporter (`robodr-metrics`, sales-readiness T70).
//!
//! RoboDR's daemons already publish their health as status files
//! (`robodr-agentd`: `<spool>/status.json`; `robodr-uplink`:
//! `<state>/uplink-status.json`). This module renders them in the
//! Prometheus text exposition format (0.0.4), which node_exporter's
//! textfile collector serves: no RoboDR process listens on a port, and a
//! scraper can read nothing the file does not hold.
//!
//! Freshness is judged exactly as the daemon defines it
//! ([`robodr_agentd::daemon::effective_state`]: running, written on this
//! boot, younger than its `stale_after_ms` by `CLOCK_MONOTONIC`), so a
//! hung or dead agent is `robodr_agentd_fresh 0` and
//! `robodr_agentd_state{state="unknown"} 1`, never a stale "ok".
//!
//! Families (every one carries `# HELP` and `# TYPE`):
//!
//! * `robodr_metrics_last_run_timestamp_seconds` (gauge): when the file was
//!   written; alert on its age to catch a stopped exporter.
//! * `robodr_agentd_status_readable`, `robodr_agentd_running`,
//!   `robodr_agentd_fresh`, `robodr_agentd_state{state}` (one-hot of
//!   ok / degraded / unknown), `robodr_agentd_status_age_seconds`,
//!   `robodr_agentd_uptime_seconds`, `robodr_agentd_health_reasons`,
//!   `robodr_agentd_queue_bytes{,_max}`, `robodr_agentd_evidence_degraded`,
//!   `robodr_agentd_signs_findings`, `robodr_agentd_info{robot_id,
//!   profile_status, safety_state}`, `robodr_agentd_input_<field>{input}`
//!   per input, and every numeric counter of the sections `daemon`,
//!   `agent`, `spool`, `pipeline`, `blackbox`, `discovery_flood`,
//!   `correlation`, `control_plane`, `executor`, `safety_feed` as
//!   `robodr_agentd_<section>_<path>` (`untyped`: they are counters of the
//!   current process and reset on restart; `rate()` handles that).
//! * `robodr_uplink_status_readable`, `robodr_uplink_state{state}`,
//!   `robodr_uplink_status_age_seconds`,
//!   `robodr_uplink_last_success_age_seconds`,
//!   `robodr_uplink_last_delivery_age_seconds`,
//!   `robodr_uplink_stuck_seconds`, and its numeric fields as
//!   `robodr_uplink_<field>` (backlog as `robodr_uplink_backlog_<field>`).
//!   An uplink state other than ok / retrying / blocked / starting is
//!   exported as `state="other"`.
//! * `robodr_units_readable` and, for every RoboDR service in
//!   [`ROBODR_UNITS`] that systemd has loaded (`systemctl show`),
//!   `robodr_unit_active{unit}`, `robodr_unit_failed{unit}`,
//!   `robodr_unit_enabled{unit}` (0 or 1; enabled = `UnitFileState`
//!   `enabled` or `enabled-runtime`, i.e. the site expects it to run) and
//!   `robodr_unit_restarts{unit}` (systemd's `NRestarts`: automatic
//!   restarts since the unit was last started by hand). A unit that systemd
//!   gave up on, one an event storm keeps getting killed (for example
//!   `robodr-pulsard` at its `MemoryMax=`), or an enabled one that is simply
//!   not running (a failed `Assert...=` leaves it `inactive`, not `failed`)
//!   is visible here even when the daemon itself writes no status file.
//!
//! Free text (health reasons, error messages, batch ids) is never exported:
//! label values are limited to the robot id, the profile and safety states,
//! input names, the uplink state (one of five fixed values) and unit names
//! (from [`ROBODR_UNITS`]), each escaped.

use robodr_agentd::State;
use serde_json::Value;
use std::fmt::Write;

/// Where `robodr-agentd` writes its status (the packaged unit's spool).
pub const AGENTD_STATUS: &str = "/var/lib/robodr/spool/agentd/status.json";
/// Where the packaged `robodr-uplink` unit writes its status.
pub const UPLINK_STATUS: &str = "/var/lib/robodr/export/uplink/uplink-status.json";
/// Default output (robodr-metrics.service's RuntimeDirectory).
pub const DEFAULT_OUT: &str = "/run/robodr-metrics/robodr.prom";

/// RoboDR's long-running services (`packaging/systemd/*.service`, checked
/// by the test suite): the only unit names ever exported.
pub const ROBODR_UNITS: &[&str] = &[
    "robodr-agentd.service",
    "robodr-anchor-receiver.service",
    "robodr-deliverd.service",
    "robodr-depot.service",
    "robodr-executor.service",
    "robodr-firewall-gw-rules.service",
    "robodr-firewall-gw.service",
    "robodr-kafka-publish.service",
    "robodr-pulsard.service",
    "robodr-spool-export.service",
    "robodr-uplink.service",
];

/// The `systemctl show` arguments whose output [`Inputs::units`] holds.
pub fn units_show_args() -> Vec<&'static str> {
    let mut a = vec![
        "show",
        "--property=Id,LoadState,ActiveState,UnitFileState,NRestarts",
    ];
    a.extend_from_slice(ROBODR_UNITS);
    a
}

/// Uplink states exported by name; anything else is `other`.
const UPLINK_STATES: &[&str] = &["ok", "retrying", "blocked", "starting"];

/// Sections of agentd's `status.json` exported as counters.
const AGENTD_SECTIONS: &[&str] = &[
    "daemon",
    "agent",
    "spool",
    "pipeline",
    "blackbox",
    "discovery_flood",
    "correlation",
    "control_plane",
    "executor",
    "safety_feed",
];

/// Uplink fields that are times or identities, not counters.
/// (`last_error` holds a time and free text: its message is never exported.)
const UPLINK_SKIP: &[&str] = &["pid", "updated_at_ms", "format", "state", "last_error"];

#[derive(Debug)]
struct Family {
    name: String,
    help: String,
    kind: &'static str,
    samples: Vec<(String, String)>,
}

/// An exposition being built: families in insertion order, one `# TYPE`
/// each, duplicate samples refused.
#[derive(Debug, Default)]
pub struct Exposition {
    families: Vec<Family>,
}

/// `[a-zA-Z_:][a-zA-Z0-9_:]*` from any key path.
pub fn metric_name(raw: &str) -> String {
    let mut s: String = raw
        .chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() {
                c.to_ascii_lowercase()
            } else {
                '_'
            }
        })
        .collect();
    while s.contains("__") {
        s = s.replace("__", "_");
    }
    let s = s.trim_matches('_').to_string();
    if s.chars().next().is_some_and(|c| c.is_ascii_digit()) {
        format!("_{s}")
    } else {
        s
    }
}

/// A label value, escaped (`\\`, `\"`, `\n`) and bounded.
fn label_value(v: &str) -> String {
    let mut out = String::new();
    for c in v.chars().take(128) {
        match c {
            '\\' => out.push_str("\\\\"),
            '"' => out.push_str("\\\""),
            '\n' => out.push_str("\\n"),
            c if c.is_control() => out.push('?'),
            c => out.push(c),
        }
    }
    out
}

fn labels(pairs: &[(&str, &str)]) -> String {
    if pairs.is_empty() {
        return String::new();
    }
    let inner: Vec<String> = pairs
        .iter()
        .map(|(k, v)| format!("{k}=\"{}\"", label_value(v)))
        .collect();
    format!("{{{}}}", inner.join(","))
}

fn num(v: &Value) -> Option<String> {
    match v {
        Value::Bool(b) => Some(if *b { "1" } else { "0" }.into()),
        Value::Number(n) => {
            if let Some(u) = n.as_u64() {
                Some(u.to_string())
            } else if let Some(i) = n.as_i64() {
                Some(i.to_string())
            } else {
                n.as_f64().filter(|f| f.is_finite()).map(|f| f.to_string())
            }
        }
        _ => None,
    }
}

impl Exposition {
    /// Add one sample. A second sample with the same name and labels is
    /// dropped (the first wins), so the output is always valid.
    pub fn add(
        &mut self,
        name: &str,
        help: &str,
        kind: &'static str,
        lbl: &[(&str, &str)],
        value: String,
    ) {
        let l = labels(lbl);
        let idx = match self.families.iter().position(|f| f.name == name) {
            Some(i) => i,
            None => {
                self.families.push(Family {
                    name: name.to_string(),
                    help: help.to_string(),
                    kind,
                    samples: Vec::new(),
                });
                self.families.len() - 1
            }
        };
        if let Some(f) = self.families.get_mut(idx) {
            if !f.samples.iter().any(|(x, _)| *x == l) {
                f.samples.push((l, value));
            }
        }
    }

    fn gauge(&mut self, name: &str, help: &str, value: impl ToString) {
        self.add(name, help, "gauge", &[], value.to_string());
    }

    /// Every numeric or boolean leaf of `v` as `<prefix>_<path>`
    /// (`untyped`); arrays are skipped (unbounded label sets), and so are
    /// wall-clock times at any depth (`*_at_ms`, `*_since_ms`): a time is
    /// not a counter.
    fn flatten(&mut self, prefix: &str, v: &Value, help: &str, skip: &[&str]) {
        match v {
            Value::Object(o) => {
                for (k, x) in o {
                    if skip.contains(&k.as_str())
                        || k.ends_with("_at_ms")
                        || k.ends_with("_since_ms")
                    {
                        continue;
                    }
                    self.flatten(&format!("{prefix}_{}", metric_name(k)), x, help, &[]);
                }
            }
            other => {
                if let Some(n) = num(other) {
                    self.add(&metric_name(prefix), help, "untyped", &[], n);
                }
            }
        }
    }

    /// The text exposition.
    pub fn render(&self) -> String {
        let mut s = String::new();
        for f in &self.families {
            let _ = writeln!(s, "# HELP {} {}", f.name, f.help.replace('\n', " "));
            let _ = writeln!(s, "# TYPE {} {}", f.name, f.kind);
            for (l, v) in &f.samples {
                let _ = writeln!(s, "{}{l} {v}", f.name);
            }
        }
        s
    }
}

/// What the exporter looks at, read by the caller.
#[derive(Debug, Clone, Default)]
pub struct Inputs {
    /// agentd's `status.json`: `None` = not configured; `Some(Err)` =
    /// configured but unreadable or not JSON.
    pub agentd: Option<Result<Value, String>>,
    /// `uplink-status.json`, likewise.
    pub uplink: Option<Result<Value, String>>,
    /// Output of `systemctl` with [`units_show_args`]: `None` = not
    /// asked; `Some(Err)` = systemd did not answer.
    pub units: Option<Result<String, String>>,
    /// `CLOCK_MONOTONIC`, ms.
    pub now_mono_ms: u64,
    /// This boot's id (`/proc/sys/kernel/random/boot_id`).
    pub boot_id: String,
    /// Wall clock, ms since the epoch.
    pub now_wall_ms: u64,
}

fn secs(ms: u64) -> String {
    format!("{:.3}", ms as f64 / 1000.0)
}

/// Render the exposition for `inp`.
pub fn render(inp: &Inputs) -> String {
    let mut e = Exposition::default();
    e.gauge(
        "robodr_metrics_last_run_timestamp_seconds",
        "Unix time robodr-metrics wrote this file.",
        secs(inp.now_wall_ms),
    );
    if let Some(a) = &inp.agentd {
        agentd(&mut e, a, inp);
    }
    if let Some(u) = &inp.uplink {
        uplink(&mut e, u, inp);
    }
    if let Some(u) = &inp.units {
        units(&mut e, u);
    }
    e.render()
}

/// `systemctl show` output: one `Key=Value` block per unit, blocks
/// separated by an empty line.
fn show_blocks(text: &str) -> Vec<Vec<(&str, &str)>> {
    let mut out = Vec::new();
    let mut cur = Vec::new();
    for line in text.lines() {
        if line.trim().is_empty() {
            if !cur.is_empty() {
                out.push(std::mem::take(&mut cur));
            }
            continue;
        }
        if let Some(kv) = line.split_once('=') {
            cur.push(kv);
        }
    }
    if !cur.is_empty() {
        out.push(cur);
    }
    out
}

fn units(e: &mut Exposition, st: &Result<String, String>) {
    e.gauge(
        "robodr_units_readable",
        "1 if systemd answered for RoboDR's units (systemctl show).",
        u8::from(st.is_ok()),
    );
    let Ok(text) = st else { return };
    for block in show_blocks(text) {
        let get = |k: &str| block.iter().find(|(x, _)| *x == k).map(|(_, v)| *v);
        let Some(unit) = get("Id").and_then(|id| ROBODR_UNITS.iter().find(|u| **u == id)) else {
            continue;
        };
        // Not installed (not-found) or masked: nothing to watch.
        if get("LoadState") != Some("loaded") {
            continue;
        }
        let active = get("ActiveState").unwrap_or("");
        e.add(
            "robodr_unit_active",
            "1 if the RoboDR unit is active (running).",
            "gauge",
            &[("unit", unit)],
            u8::from(active == "active").to_string(),
        );
        e.add(
            "robodr_unit_failed",
            "1 if systemd put the RoboDR unit in the failed state (crashed and not restarted, or gave up restarting it).",
            "gauge",
            &[("unit", unit)],
            u8::from(active == "failed").to_string(),
        );
        let enabled = matches!(get("UnitFileState"), Some("enabled" | "enabled-runtime"));
        e.add(
            "robodr_unit_enabled",
            "1 if the RoboDR unit is enabled (systemctl enable): the site expects it to run.",
            "gauge",
            &[("unit", unit)],
            u8::from(enabled).to_string(),
        );
        if let Some(n) = get("NRestarts").and_then(|n| n.trim().parse::<u64>().ok()) {
            e.add(
                "robodr_unit_restarts",
                "Automatic restarts of the RoboDR unit by systemd since it was last started by hand (NRestarts).",
                "untyped",
                &[("unit", unit)],
                n.to_string(),
            );
        }
    }
}

fn agentd(e: &mut Exposition, st: &Result<Value, String>, inp: &Inputs) {
    let ok = matches!(st, Ok(v) if v.is_object());
    e.gauge(
        "robodr_agentd_status_readable",
        "1 if robodr-agentd's status.json could be read and parsed.",
        u8::from(ok),
    );
    let effective = match st {
        Ok(v) if ok => robodr_agentd::daemon::effective_state(v, inp.now_mono_ms, &inp.boot_id),
        _ => State::Unknown,
    };
    let fresh = match st {
        Ok(v) if ok => {
            v["running"].as_bool() == Some(true)
                && v["boot_id"].as_str() == Some(inp.boot_id.as_str())
                && matches!(
                    (v["updated_mono_ms"].as_u64(), v["stale_after_ms"].as_u64()),
                    (Some(at), Some(stale)) if inp.now_mono_ms.saturating_sub(at) <= stale
                )
        }
        _ => false,
    };
    e.gauge(
        "robodr_agentd_fresh",
        "1 if status.json is from a running robodr-agentd on this boot and younger than its stale_after_ms.",
        u8::from(fresh),
    );
    for (name, s) in [
        ("ok", State::Ok),
        ("degraded", State::Degraded),
        ("unknown", State::Unknown),
    ] {
        e.add(
            "robodr_agentd_state",
            "Monitoring state as a console shows it (stale or missing status = unknown).",
            "gauge",
            &[("state", name)],
            u8::from(effective == s).to_string(),
        );
    }
    let Ok(v) = st else { return };
    if !ok {
        return;
    }
    e.gauge(
        "robodr_agentd_running",
        "The running flag of status.json (false after a clean stop).",
        u8::from(v["running"].as_bool() == Some(true)),
    );
    if v["boot_id"].as_str() == Some(inp.boot_id.as_str()) {
        if let Some(at) = v["updated_mono_ms"].as_u64() {
            e.gauge(
                "robodr_agentd_status_age_seconds",
                "Age of status.json by CLOCK_MONOTONIC (written on this boot only).",
                secs(inp.now_mono_ms.saturating_sub(at)),
            );
        }
    }
    if let Some(up) = v["uptime_ms"].as_u64() {
        e.gauge(
            "robodr_agentd_uptime_seconds",
            "robodr-agentd uptime.",
            secs(up),
        );
    }
    e.gauge(
        "robodr_agentd_health_reasons",
        "Number of reasons behind the current health state (see status.json for the text).",
        v["reasons"].as_array().map_or(0, Vec::len),
    );
    for (k, help) in [
        ("queue_bytes", "Bytes in the input queue."),
        (
            "queue_bytes_max",
            "Input queue capacity in bytes (daemon.queue_bytes).",
        ),
        ("evidence_degraded", "1 if evidence recording is degraded."),
        (
            "signs_findings",
            "1 if findings carry a robodr-finding-sig signature.",
        ),
    ] {
        if let Some(n) = num(&v[k]) {
            e.add(&format!("robodr_agentd_{k}"), help, "gauge", &[], n);
        }
    }
    let s = |k: &str| v[k].as_str().unwrap_or("").to_string();
    e.add(
        "robodr_agentd_info",
        "Identity and modes of the robodr-agentd instance (value always 1).",
        "gauge",
        &[
            ("robot_id", &s("robot_id")),
            ("profile_status", &s("profile_status")),
            ("safety_state", &s("safety_state")),
        ],
        "1".into(),
    );
    if let Some(inputs) = v["inputs"].as_array() {
        for i in inputs {
            let Some(name) = i["name"].as_str() else {
                continue;
            };
            let Some(o) = i.as_object() else { continue };
            for (k, x) in o {
                if let Some(n) = num(x) {
                    e.add(
                        &format!("robodr_agentd_input_{}", metric_name(k)),
                        "Per-input counter of robodr-agentd (status.json inputs[]).",
                        "untyped",
                        &[("input", name)],
                        n,
                    );
                }
            }
        }
    }
    for sec in AGENTD_SECTIONS {
        if let Some(x) = v.get(*sec) {
            e.flatten(
                &format!("robodr_agentd_{sec}"),
                x,
                "Counter from robodr-agentd status.json (resets when the daemon restarts).",
                &[],
            );
        }
    }
}

fn uplink(e: &mut Exposition, st: &Result<Value, String>, inp: &Inputs) {
    let ok = matches!(st, Ok(v) if v.is_object());
    e.gauge(
        "robodr_uplink_status_readable",
        "1 if robodr-uplink's uplink-status.json could be read and parsed.",
        u8::from(ok),
    );
    let Ok(v) = st else { return };
    if !ok {
        return;
    }
    // A state this exporter does not know is `other`: the label never
    // carries text from the file.
    let raw = v["state"].as_str().unwrap_or("");
    let state = UPLINK_STATES
        .iter()
        .copied()
        .find(|s| *s == raw)
        .unwrap_or("other");
    for k in UPLINK_STATES.iter().copied().chain(["other"]) {
        e.add(
            "robodr_uplink_state",
            "robodr-uplink delivery state (blocked = refused until something is fixed; other = a state this exporter does not know).",
            "gauge",
            &[("state", k)],
            u8::from(k == state).to_string(),
        );
    }
    let age = |field: &str| {
        v[field]
            .as_u64()
            .map(|at| secs(inp.now_wall_ms.saturating_sub(at)))
    };
    for (field, name, help) in [
        (
            "updated_at_ms",
            "status_age_seconds",
            "Age of uplink-status.json (wall clock).",
        ),
        (
            "last_success_at_ms",
            "last_success_age_seconds",
            "Time since the last completed run.",
        ),
        (
            "last_delivery_at_ms",
            "last_delivery_age_seconds",
            "Time since a batch was last acknowledged by the SOC.",
        ),
        (
            "stuck_since_ms",
            "stuck_seconds",
            "Duration of the current failure streak.",
        ),
    ] {
        if let Some(a) = age(field) {
            e.add(&format!("robodr_uplink_{name}"), help, "gauge", &[], a);
        }
    }
    e.flatten(
        "robodr_uplink",
        v,
        "Counter from robodr-uplink uplink-status.json.",
        UPLINK_SKIP,
    );
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn names_and_labels() {
        assert_eq!(metric_name("a.b-C__d"), "a_b_c_d");
        assert_eq!(metric_name("9x"), "_9x");
        assert_eq!(label_value("a\"b\\c\nd"), "a\\\"b\\\\c\\nd");
    }

    #[test]
    fn show_output_is_split_per_unit() {
        let b = show_blocks("Id=a\nLoadState=loaded\n\nId=b\nX=1=2\n\n\n");
        assert_eq!(b.len(), 2);
        assert_eq!(b[1], vec![("Id", "b"), ("X", "1=2")]);
    }

    #[test]
    fn duplicate_samples_are_dropped() {
        let mut e = Exposition::default();
        e.add("x", "h", "gauge", &[], "1".into());
        e.add("x", "h", "gauge", &[], "2".into());
        assert_eq!(e.render(), "# HELP x h\n# TYPE x gauge\nx 1\n");
    }
}
