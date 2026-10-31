//! Sales-readiness T13: `robodr-agentd selftest` against the running
//! daemon. The daemon spools a marked, Low, observe-only
//! `robot.agent.selftest` finding carrying the request's nonce; the
//! command passes only once the exporter acknowledged that record.

mod common;

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Duration;

use common::pcap::robot_profile;
use common::*;
use robodr_agentd::selftest::{self, ClientOptions, Outcome};
use serde_json::json;

type Run = std::thread::JoinHandle<(Result<robodr_agentd::Summary, String>, String)>;

fn spawn(r: robodr_agentd::Resolved) -> (Arc<AtomicBool>, Run) {
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

fn finish(stop: Arc<AtomicBool>, h: Run) -> String {
    stop.store(true, Ordering::SeqCst);
    let (res, log) = h.join().unwrap();
    res.unwrap_or_else(|e| panic!("{e}\n{log}"));
    log
}

/// A stand-in exporter: acknowledges every record in `ready/` (rename into
/// `acked/`, as `robodr-uplink` does after the SOC accepted it).
fn exporter(spool: std::path::PathBuf, stop: Arc<AtomicBool>) -> std::thread::JoinHandle<()> {
    std::thread::spawn(move || {
        while !stop.load(Ordering::SeqCst) {
            if let Ok(rd) = std::fs::read_dir(spool.join("ready")) {
                for e in rd.flatten() {
                    let _ = std::fs::rename(e.path(), spool.join("acked").join(e.file_name()));
                }
            }
            std::thread::sleep(Duration::from_millis(20));
        }
    })
}

fn opts(secs: u64) -> ClientOptions {
    ClientOptions {
        timeout: Duration::from_secs(secs),
        poll: Duration::from_millis(20),
    }
}

#[test]
fn t13_selftest_finding_travels_to_the_exporters_ack() {
    let s = setup("selftest-acked", &robot_profile(true));
    let sock = s.dir.join("ev.sock");
    let cfg = s.config(
        json!({}),
        json!([{"kind": "unix_socket", "path": sock}]),
        json!({}),
    );
    let (stop, h) = spawn(s.resolve(&cfg));
    wait_for(15, "the daemon's status", || status(&s.spool));
    let ex_stop = Arc::new(AtomicBool::new(false));
    let ex = exporter(s.spool.clone(), ex_stop.clone());

    let mut out = Vec::new();
    let o = selftest::run_client(&s.spool, opts(20), &mut out);
    // A second self-test right after the first (inside the daemon's
    // one-per-second limit) is served too, only later.
    let mut out2 = Vec::new();
    let o2 = selftest::run_client(&s.spool, opts(20), &mut out2);
    ex_stop.store(true, Ordering::SeqCst);
    ex.join().unwrap();
    let log = finish(stop, h);
    let text = String::from_utf8(out).unwrap();
    let Outcome::Acked { nonce, record } = o else {
        panic!("{o:?}\n{text}\n{log}");
    };
    assert!(matches!(o2, Outcome::Acked { .. }), "{o2:?}\n{log}");
    assert!(text.contains(&format!("ok request {nonce}")), "{text}");
    assert!(text.contains("ok acknowledged by the exporter"), "{text}");
    assert!(!s.spool.join(selftest::REQUEST_FILE).exists());

    let found = spooled(&s.spool);
    let tests: Vec<_> = found
        .iter()
        .filter(|(_, e)| e.entity_context.rule_id == selftest::RULE)
        .collect();
    assert_eq!(tests.len(), 2, "{:?}", rules(&found));
    let (rec, env) = tests
        .iter()
        .find(|(r, _)| format!("{:020}.json", r.seq) == record)
        .unwrap();
    assert!(s.spool.join("acked").join(&record).exists());
    assert!(rec.value.contains(&nonce), "the nonce is in the finding");
    assert_eq!(env.severity, robodr_events::Severity::Low);
    assert_eq!(env.entity_context.mode, robodr_ocsf::Mode::Observe);
    // Never a correlation input, never a response.
    assert!(
        !rules(&found)
            .iter()
            .any(|r| r.starts_with("robot.correlate.")),
        "{:?}",
        rules(&found)
    );
    assert!(
        log.contains(&format!("self-test {nonce} requested")),
        "{log}"
    );
}

/// Without an exporter the record stays in `ready/`: not proven.
#[test]
fn t13_selftest_without_an_exporter_is_not_proven() {
    let s = setup("selftest-noexport", &robot_profile(true));
    let sock = s.dir.join("ev.sock");
    let cfg = s.config(
        json!({}),
        json!([{"kind": "unix_socket", "path": sock}]),
        json!({}),
    );
    let (stop, h) = spawn(s.resolve(&cfg));
    wait_for(15, "the daemon's status", || status(&s.spool));
    let mut out = Vec::new();
    let o = selftest::run_client(&s.spool, opts(2), &mut out);
    let log = finish(stop, h);
    let text = String::from_utf8(out).unwrap();
    assert!(
        matches!(&o, Outcome::Failed(m) if m.contains("still waiting for the exporter")),
        "{o:?}\n{text}\n{log}"
    );
    assert!(
        text.contains("ok robot.agent.selftest finding spooled"),
        "{text}"
    );
}

fn agentd(args: &[&str]) -> std::process::Output {
    std::process::Command::new(env!("CARGO_BIN_EXE_robodr-agentd"))
        .args(args)
        .output()
        .unwrap()
}

/// The command: no daemon answers -> exit 1; usage errors -> exit 2.
#[test]
fn t13_selftest_command_exit_codes() {
    let s = setup("selftest-cli", &robot_profile(true));
    let sock = s.dir.join("ev.sock");
    let cfg = s.config(
        json!({}),
        json!([{"kind": "unix_socket", "path": sock}]),
        json!({}),
    );
    let path = s.write_config(&cfg);
    std::fs::create_dir_all(&s.spool).unwrap();
    let p = path.to_str().unwrap();
    let o = agentd(&["selftest", "--config", p, "--timeout", "1"]);
    let out = String::from_utf8_lossy(&o.stdout);
    assert_eq!(o.status.code(), Some(1), "{out}");
    assert!(
        out.contains("FAIL robodr-agentd did not take the request"),
        "{out}"
    );
    assert!(!s.spool.join(selftest::REQUEST_FILE).exists(), "withdrawn");
    for bad in [
        vec!["selftest", "--config", p, "--timeout", "0"],
        vec!["selftest", "--config", p, "--check-config"],
        vec!["selftest"],
        vec!["--config", p, "--timeout", "5"],
    ] {
        let o = agentd(&bad);
        assert_eq!(o.status.code(), Some(2), "{bad:?}");
    }
}
