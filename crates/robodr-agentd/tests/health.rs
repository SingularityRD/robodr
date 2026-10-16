//! Self-health end to end: a silent input makes the robot state "unknown"
//! (never "ok") and raises an observe-only finding; data brings it back to
//! "ok"; silence again raises a new finding.

mod common;

use std::io::Write;
use std::os::unix::net::UnixStream;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use common::pcap::{robot_profile, LEGIT_HEX};
use common::*;
use robodr_ocsf::Mode;

fn silent_findings(spool: &std::path::Path) -> Vec<robodr_ocsf::FindingEnvelope> {
    spooled(spool)
        .into_iter()
        .map(|(_, e)| e)
        .filter(|e| e.entity_context.rule_id == "robot.agent.input_silent")
        .collect()
}

#[test]
fn silent_source_is_unknown_never_ok_and_is_reported() {
    let s = setup("silent", &robot_profile(true));
    let sock = s.dir.join("ev.sock");
    let cfg = s.config(
        serde_json::json!({}),
        serde_json::json!([{"kind": "unix_socket", "path": sock}]),
        serde_json::json!({"silence_ms": 400}),
    );
    let r = s.resolve(&cfg);
    let stop = Arc::new(AtomicBool::new(false));
    let s2 = stop.clone();
    let h = std::thread::spawn(move || {
        let mut log = Vec::new();
        let res = robodr_agentd::run(&r, &|| s2.load(Ordering::SeqCst), &mut log);
        (res, String::from_utf8_lossy(&log).into_owned())
    });

    // 1. Nothing ever arrives: unknown from the start, a finding after
    //    silence_ms.
    let first = wait_for(10, "status", || status(&s.spool));
    assert_eq!(first["state"], "unknown", "{first}");
    let f = wait_for(10, "silent finding", || {
        let v = silent_findings(&s.spool);
        (!v.is_empty()).then_some(v)
    });
    assert_eq!(f.len(), 1);
    assert_eq!(f[0].entity_context.mode, Mode::Observe, "never acted upon");
    assert_eq!(f[0].severity, robodr_events::Severity::High);
    wait_for(10, "status unknown: no data", || {
        let st = status(&s.spool)?;
        (st["state"] == "unknown" && st["reasons"].to_string().contains("no data yet"))
            .then_some(())
    });

    // 2. A live, legitimate stream: state becomes ok.
    let mut c = UnixStream::connect(&sock).unwrap();
    let line = format!(
        "{{\"kind\":\"ros2_participant_discovered\",\"guid_prefix\":\"{LEGIT_HEX}\",\"src_ip\":\"192.168.50.10\",\"locators\":[]}}\n"
    );
    let deadline = Instant::now() + Duration::from_secs(10);
    let mut saw_ok = false;
    while Instant::now() < deadline {
        c.write_all(line.as_bytes()).unwrap();
        std::thread::sleep(Duration::from_millis(40));
        if status(&s.spool).is_some_and(|st| st["state"] == "ok") {
            saw_ok = true;
            break;
        }
    }
    assert!(saw_ok, "{:?}", status(&s.spool));
    // Legitimate traffic produced no finding.
    assert!(rules(&spooled(&s.spool))
        .iter()
        .all(|r| r.starts_with("robot.agent.")));

    // 3. The stream goes quiet (connection still open): unknown again, a
    //    second finding for the new episode.
    let f = wait_for(10, "second silent finding", || {
        let v = silent_findings(&s.spool);
        (v.len() >= 2).then_some(v)
    });
    // (status.json is rewritten at the end of the tick that raised it)
    wait_for(10, "status unknown: silent", || {
        let st = status(&s.spool)?;
        (st["state"] == "unknown" && st["reasons"].to_string().contains("silent for")).then_some(())
    });
    assert_eq!(
        f[1].entity_context.occurrence_count, 2,
        "same input, same finding id, counted"
    );
    assert_eq!(f[0].finding_id, f[1].finding_id);

    stop.store(true, Ordering::SeqCst);
    let (res, log) = h.join().unwrap();
    let sum = res.unwrap_or_else(|e| panic!("{e}\n{log}"));
    assert!(log.contains("robot.agent.input_silent"), "{log}");
    assert!(log.contains("InputRecovered"), "{log}");
    assert!(notes_with(&s.blackbox, "robodr.agentd_recovery") >= 1);
    let found = spooled(&s.spool);
    assert_verified(&s.blackbox, Some(sum.finished.checkpoint), &found);
    drop(c);
}
