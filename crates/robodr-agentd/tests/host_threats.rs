//! The `host_threats` input: Pulsar threats from `robodr-threat-forward`
//! reach the agent (as `robot.host.<rule>` findings, `robot.host.pulsar_threat`
//! for a rule RoboDR does not ship) and the
//! correlator (as host signals named by their Pulsar rule), so the
//! host-dependent default correlation rules fire in the daemon. The
//! forwarder is played by the test (same line protocol).

mod common;

use std::io::Write;
use std::os::unix::fs::PermissionsExt;
use std::os::unix::net::UnixStream;
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;

use common::pcap::{robot_profile, scenario_frames};
use common::*;
use robodr_ocsf::Mode;

type DaemonThread = std::thread::JoinHandle<(Result<robodr_agentd::Summary, String>, String)>;

fn spawn(r: robodr_agentd::Resolved) -> (Arc<AtomicBool>, DaemonThread) {
    let stop = Arc::new(AtomicBool::new(false));
    let s2 = stop.clone();
    let h = std::thread::spawn(move || {
        let mut log = Vec::new();
        let res = robodr_agentd::run(&r, &|| s2.load(Ordering::SeqCst), &mut log)
            .map_err(|e| e.to_string());
        (res, String::from_utf8_lossy(&log).into_owned())
    });
    (stop, h)
}

/// A private (0700) directory for the socket and its path.
fn socket_in(s: &Setup) -> PathBuf {
    let run = s.dir.join("run");
    std::fs::create_dir_all(&run).unwrap();
    std::fs::set_permissions(&run, std::fs::Permissions::from_mode(0o700)).unwrap();
    run.join("host-threats.sock")
}

fn host_section(sock: &std::path::Path) -> serde_json::Value {
    // The test runs as whoever runs it; root is always allowed.
    serde_json::json!({
        "socket_path": sock,
        "allowed_uids": [robodr_agentd::config::effective_uid()],
    })
}

fn threat(rule: &str, source: &str, pid: i32, image: &str, severity: &str) -> String {
    serde_json::json!({
        "kind": "threat", "v": 1, "rule": rule, "source": source, "severity": severity,
        "category": "execution", "ts_ms": 1_790_000_000_000u64, "pid": pid, "ppid": 1,
        "uid": 0, "gid": 0, "image": image, "container": false,
    })
    .to_string()
}

fn host_input(st: &serde_json::Value) -> Option<&serde_json::Value> {
    st["inputs"]
        .as_array()?
        .iter()
        .find(|i| i["name"].as_str().is_some_and(|n| n.starts_with("host:")))
}

const SHELL: &str = "RoboDR: Interactive shell started on robot controller";
const TMP_EXEC: &str = "RoboDR: Program executed from a temporary directory";
const TRACER: &str = "RoboDR: Debugger or tracer started on robot controller";
const STOP_SERVICE: &str = "RoboDR: Attempt to stop the Pulsar or RoboDR service";

/// Rogue participant + rogue `cmd_vel` writer on the wire (synthetic pcap)
/// and a host shell from Pulsar: `coordinated_intrusion` (network + host
/// co-occurrence). Three host rules from one process:
/// `host_process_persistence`. The sensor's own threat is not counted
/// twice; junk is counted; the forwarder's losses show up as drops.
#[test]
fn pulsar_threats_fire_the_host_dependent_correlations() {
    let s = setup("host-ci", &robot_profile(true));
    let sock = socket_in(&s);
    let pcap = s.pcap(&scenario_frames(2));
    let mut cfg = s.config(
        serde_json::json!({"capture": {"enabled": true, "pcap_replay": pcap}}),
        serde_json::json!([]),
        serde_json::json!({}),
    );
    cfg["host_threats"] = host_section(&sock);
    let r = s.resolve(&cfg);
    assert!(r.host_threats.is_some());
    let (stop, h) = spawn(r);

    // Configured but no forwarder yet: never "ok".
    let st = wait_for(10, "status with the host input", || {
        let st = status(&s.spool)?;
        host_input(&st)?;
        (st["daemon"]["ticks"].as_u64()? >= 1).then_some(st)
    });
    assert_ne!(st["state"], "ok", "{st}");
    let reasons = st["reasons"].to_string();
    assert!(
        reasons.contains("host:") && reasons.contains("no data yet"),
        "{st}"
    );
    let mode = std::fs::metadata(&sock).unwrap().permissions().mode() & 0o777;
    assert_eq!(mode, 0o600);

    // The network half has been seen (replay done) before the host half.
    wait_for(10, "pcap findings", || {
        let st = status(&s.spool)?;
        (st["daemon"]["outcomes"].as_u64()? >= 2).then_some(())
    });
    let mut c = wait_for(5, "socket", || UnixStream::connect(&sock).ok());
    let lines = [
        r#"{"kind":"heartbeat","v":1,"sent":0,"dropped":3,"skipped_own":0}"#.to_string(),
        threat(SHELL, "rules-engine", 4242, "/usr/bin/bash", "medium"),
        // The sensor's own threat (agentd has it from the pipeline already).
        threat(
            "robot.ros2.unknown_participant",
            "robodr-sensor-ros2",
            1,
            "/usr/sbin/robodr-pulsard",
            "high",
        ),
        "not json".to_string(),
        r#"{"kind":"threat","v":1,"rule":"x","source":"m","pid":1,"surprise":true}"#.to_string(),
        threat(TMP_EXEC, "rules-engine", 4242, "/usr/bin/bash", "high"),
        // Same process, image not known to Pulsar's tracker yet.
        threat(TRACER, "rules-engine", 4242, "", "high"),
    ];
    for l in &lines {
        writeln!(c, "{l}").unwrap();
    }
    c.flush().unwrap();
    let st = wait_for(10, "host threats correlated", || {
        let st = status(&s.spool)?;
        let ok = st["daemon"]["host_threats"].as_u64()? == 3
            && st["daemon"]["host_threats_own_skipped"].as_u64()? == 1
            && st["daemon"]["correlated_findings"].as_u64()? >= 2
            && host_input(&st)?["malformed"].as_u64()? == 2;
        ok.then_some(st)
    });
    let hi = host_input(&st).unwrap();
    assert_eq!(hi["connections"], 1, "{st}");
    assert_eq!(hi["upstream_dropped"], 3, "{st}");
    assert_eq!(st["daemon"]["host_heartbeats"], 1, "{st}");
    stop.store(true, Ordering::SeqCst);
    let (res, log) = h.join().unwrap();
    let sum = res.unwrap_or_else(|e| panic!("{e}\n{log}"));
    assert!(
        log.contains("host threat: RoboDR: Interactive shell"),
        "{log}"
    );

    let found = spooled(&s.spool);
    let r = rules(&found);
    // One finding per forwarded host threat; the sensor's own one is not
    // there twice.
    // Contract 2.5 (T45): each shipped Pulsar rule has its own id.
    let host: Vec<_> = found
        .iter()
        .filter(|(_, e)| e.entity_context.rule_id.starts_with("robot.host."))
        .collect();
    assert_eq!(host.len(), 3, "{r:?}\n{log}");
    let mut ids: Vec<&str> = host
        .iter()
        .map(|(_, e)| e.entity_context.rule_id.as_str())
        .collect();
    ids.sort_unstable();
    assert_eq!(
        ids,
        [
            "robot.host.debugger_started",
            "robot.host.exec_from_tmp",
            "robot.host.interactive_shell"
        ],
        "{r:?}"
    );
    let env = &host
        .iter()
        .find(|(_, e)| e.entity_context.rule_id == "robot.host.interactive_shell")
        .unwrap()
        .1;
    assert_eq!(env.ocsf.finding_info.data_sources, vec!["host_runtime"]);
    assert_eq!(
        env.title, "Interactive shell started on robot controller",
        "the Pulsar rule name is the title"
    );
    // The Pulsar rule name and the process travel in the (tainted) detail.
    let detail = &env.entity_context.detail.value;
    assert!(
        detail.contains(SHELL) && detail.contains("pid 4242"),
        "{detail}"
    );
    assert_eq!(env.severity, robodr_events::Severity::Medium);
    // Network + host co-occurrence.
    let ci: Vec<_> = found
        .iter()
        .filter(|(_, e)| e.entity_context.rule_id == "robot.correlate.coordinated_intrusion")
        .collect();
    assert_eq!(ci.len(), 1, "{r:?}\n{log}");
    assert_eq!(ci[0].1.severity, robodr_events::Severity::Critical);
    assert_eq!(ci[0].1.entity_context.mode, Mode::Enforce, "locked profile");
    // Three host rules from one process, escalated one level (High -> Critical).
    let pp: Vec<_> = found
        .iter()
        .filter(|(_, e)| e.entity_context.rule_id == "robot.correlate.host_process_persistence")
        .collect();
    assert_eq!(pp.len(), 1, "{r:?}\n{log}");
    assert_eq!(pp[0].1.severity, robodr_events::Severity::Critical);
    // The forwarder's losses are reported like queue drops; the junk lines
    // as malformed input.
    assert!(r.iter().any(|x| x == "robot.agent.queue_overflow"), "{r:?}");
    assert!(
        r.iter().any(|x| x == "robot.agent.input_malformed"),
        "{r:?}"
    );
    // The correlated note cites the host signal by its Pulsar rule name and
    // groups by its process (pid), with the host finding's black-box record.
    assert!(notes_with(&s.blackbox, "robodr.correlated_finding") >= 2);
    assert!(notes_with(&s.blackbox, r#""kind":"process","value":"4242""#) >= 1);
    assert_eq!(sum.stats.host_threats, 3);
    assert_verified(&s.blackbox, Some(sum.finished.checkpoint), &found);
    assert!(!sock.exists(), "socket removed at stop");
}

/// A host input whose forwarder never connects goes silent (state
/// unknown, `robot.agent.input_silent`); a Pulsar "service stop" threat
/// together with that silence is `defense_tampering`, observe-only.
#[test]
fn a_silent_host_input_is_blind_and_service_stop_is_defense_tampering() {
    let s = setup("host-dt", &robot_profile(true));
    let sock = socket_in(&s);
    let mut cfg = s.config(
        serde_json::json!({}),
        serde_json::json!([{"kind": "unix_socket", "path": s.dir.join("run/events.sock")}]),
        serde_json::json!({"silence_ms": 300}),
    );
    cfg["host_threats"] = host_section(&sock);
    let (stop, h) = spawn(s.resolve(&cfg));
    let st = wait_for(10, "host input silent", || {
        let st = status(&s.spool)?;
        let silent = st["reasons"].as_array()?.iter().any(|r| {
            r.as_str()
                .is_some_and(|r| r.contains("host:") && r.contains("no data yet"))
        });
        // Both inputs (events socket, host socket) went silent.
        (silent && st["daemon"]["health_findings"].as_u64().unwrap_or(0) >= 2).then_some(st)
    });
    assert_eq!(st["state"], "unknown", "{st}");
    let mut c = wait_for(5, "socket", || UnixStream::connect(&sock).ok());
    writeln!(c, r#"{{"kind":"heartbeat","v":1}}"#).unwrap();
    writeln!(
        c,
        "{}",
        threat(
            STOP_SERVICE,
            "rules-engine",
            777,
            "/usr/bin/systemctl",
            "high"
        )
    )
    .unwrap();
    c.flush().unwrap();
    wait_for(10, "defense tampering", || {
        let st = status(&s.spool)?;
        (st["daemon"]["correlated_findings"].as_u64()? >= 1).then_some(())
    });
    stop.store(true, Ordering::SeqCst);
    let (res, log) = h.join().unwrap();
    res.unwrap_or_else(|e| panic!("{e}\n{log}"));
    let found = spooled(&s.spool);
    let r = rules(&found);
    // Both the events socket and the host socket went silent.
    assert_eq!(
        r.iter()
            .filter(|x| *x == "robot.agent.input_silent")
            .count(),
        2,
        "{r:?}\n{log}"
    );
    assert!(log.contains("input host:") && log.contains("delivered no valid data"));
    let dt: Vec<_> = found
        .iter()
        .filter(|(_, e)| e.entity_context.rule_id == "robot.correlate.defense_tampering")
        .collect();
    assert_eq!(dt.len(), 1, "{r:?}\n{log}");
    assert_eq!(
        dt[0].1.entity_context.mode,
        Mode::Observe,
        "agent signals are observe-only"
    );
}

/// Configuration checks: path clashes, modes, and an unsafe directory
/// refused at start.
#[test]
fn host_threats_configuration_is_strict() {
    let s = setup("host-cfg", &robot_profile(true));
    let sock = socket_in(&s);
    let base = s.config(
        serde_json::json!({}),
        serde_json::json!([{"kind": "unix_socket", "path": sock}]),
        serde_json::json!({}),
    );
    let load = |cfg: &serde_json::Value| robodr_agentd::load(&s.write_config(cfg));
    let mut cfg = base.clone();
    cfg["host_threats"] = host_section(&sock);
    let e = load(&cfg).unwrap_err();
    assert!(e.contains("also an event_inputs"), "{e}");
    let other = s.dir.join("run/other.sock");
    for (section, want) in [
        (serde_json::json!({"socket_path": "rel.sock"}), "absolute"),
        (
            serde_json::json!({"socket_path": other, "socket_mode": "0666"}),
            "socket_mode",
        ),
        (
            serde_json::json!({"socket_path": other, "max_connections": 0}),
            "max_connections",
        ),
        (
            serde_json::json!({"socket_path": other, "uids": [1]}),
            "unknown field",
        ),
        (
            serde_json::json!({"socket_path": s.spool.join("h.sock")}),
            "inside spool.dir",
        ),
    ] {
        let mut cfg = base.clone();
        cfg["host_threats"] = section;
        let e = load(&cfg).unwrap_err();
        assert!(e.contains(want), "{want}: {e}");
    }
    // A world-writable socket directory is refused when the daemon starts.
    let open = s.dir.join("open");
    std::fs::create_dir_all(&open).unwrap();
    std::fs::set_permissions(&open, std::fs::Permissions::from_mode(0o777)).unwrap();
    let mut cfg = base;
    cfg["host_threats"] = serde_json::json!({"socket_path": open.join("h.sock")});
    let r = load(&cfg).unwrap();
    let e = robodr_agentd::run(&r, &|| true, &mut Vec::new()).unwrap_err();
    assert!(e.to_string().contains("writable by group or others"), "{e}");
}
