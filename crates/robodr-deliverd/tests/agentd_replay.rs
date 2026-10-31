//! The safety-state gate end to end (`docs/SECURE-DELIVERY.md` §10, 13b):
//! a real `robodr-agentd` with a `safety_feed` socket, recorded safety
//! reports replayed into it by `robodr-safety-replay` (the binary), and
//! `robodr-deliverd` reading agentd's live state from its `status.json`.
//! The install is deferred while the replayed state is `moving_slow` and
//! proceeds once it is `idle`; both agents' black boxes record it.
//!
//! No PLC, safety system or robot is involved: the replay helper plays the
//! safety-PLC gateway.

#[path = "../../robodr-agentd/tests/common/mod.rs"]
mod agentd_common;
mod common;

use common::*;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

#[test]
fn install_waits_for_the_replayed_safety_state_to_turn_idle() {
    let s = agentd_common::setup("deliverd-replay", &agentd_common::pcap::robot_profile(true));
    let events = s.dir.join("ev.sock");
    let safety = s.dir.join("safety.sock");
    let mut cfg = s.config(
        serde_json::json!({}),
        serde_json::json!([{"kind": "unix_socket", "path": events}]),
        serde_json::json!({}),
    );
    cfg["context"] = serde_json::json!({});
    cfg["safety_feed"] = serde_json::json!({"socket": {"path": safety, "stale_after_ms": 1000}});
    let r = s.resolve(&cfg);
    let stop = Arc::new(AtomicBool::new(false));
    let s2 = stop.clone();
    let agentd = std::thread::spawn(move || {
        let mut log = Vec::new();
        let res = robodr_agentd::run(&r, &|| s2.load(Ordering::SeqCst), &mut log)
            .map_err(|e| e.to_string());
        (res, String::from_utf8_lossy(&log).into_owned())
    });

    // The recording: moving slowly for 3 s, then idle.
    let rec = s.dir.join("reports.jsonl");
    std::fs::write(
        &rec,
        "{\"at_ms\":0,\"state\":\"moving_slow\"}\n{\"at_ms\":3000,\"state\":\"idle\"}\n",
    )
    .unwrap();
    let t_replay = Instant::now();
    let mut replay = std::process::Command::new(env!("CARGO_BIN_EXE_robodr-safety-replay"))
        .arg("--socket")
        .arg(&safety)
        .arg("--file")
        .arg(&rec)
        .args([
            "--repeat-ms",
            "100",
            "--hold-ms",
            "30000",
            "--connect-timeout-ms",
            "10000",
        ])
        .spawn()
        .unwrap();

    std::fs::write(s.dir.join("boot_id"), "test-boot\n").unwrap();
    let status = s.spool.join("status.json");
    let boot = s.dir.join("boot_id");
    let u = Unit::with_status(
        "replay",
        |v| {
            // Only these two: the rest of `safety` (the test passwd that
            // names robodr-agentd as this user) stays as common set it.
            v["safety"]["agentd_status"] = serde_json::json!(status);
            v["safety"]["boot_id"] = serde_json::json!(boot);
            // agentd's own health is judged elsewhere (its event input is
            // silent here); this test is about the safety state.
            v["health"]["require_agentd_ok"] = false.into();
            // Findings go into agentd's own spool, next to its records.
            v["findings"]["spool"] = serde_json::json!(s.spool);
        },
        false,
    );
    let r = u.rpk(&files_spec(&u, "nav-stack", 1, true), &[("ok", b"v1")]);
    let b = u.bundle(1, None, std::slice::from_ref(&r));
    u.pack("p1", 1, &[r], &[b]);
    let mut e = u.open();

    let start = Instant::now();
    let mut seen_moving = false;
    let mut installed = None;
    while start.elapsed() < Duration::from_secs(30) {
        let rep = e.tick().unwrap();
        if rep.deferred.as_deref() == Some("nav-stack 1: safety_state:moving_slow") {
            seen_moving = true;
        }
        if !rep.installed.is_empty() {
            installed = Some(t_replay.elapsed());
            break;
        }
        std::thread::sleep(Duration::from_millis(100));
    }
    let _ = replay.kill();
    let _ = replay.wait();
    stop.store(true, Ordering::SeqCst);
    let (res, log) = agentd.join().unwrap();
    res.unwrap_or_else(|e| panic!("agentd: {e}\n{log}"));
    assert!(seen_moving, "the install was never deferred by moving_slow");
    let at = installed.expect("the install never proceeded after idle");
    // The recording turns idle 3 s after the replay connected.
    assert!(
        at >= Duration::from_millis(2900),
        "installed {at:?} after the replay started"
    );

    // deliverd's black box: deferred while moving_slow, switched in idle.
    let d = u.notes_of("robodr.deliver.deferred");
    assert!(
        d.iter().any(|n| n["safety_state"] == "moving_slow"),
        "{d:?}"
    );
    let act = u.notes_of("robodr.deliver.activating");
    assert_eq!(act.len(), 1);
    assert_eq!(act[0]["safety_state"], "idle");
    assert_eq!(u.notes_of("robodr.deliver.installed").len(), 1);
    assert!(u.black_box_verifies());
    // agentd's black box: the replayed transition.
    let t: Vec<(String, String)> = agentd_common::records(&s.blackbox)
        .iter()
        .filter_map(|r| serde_json::from_slice::<serde_json::Value>(&r.payload).ok())
        .filter(|v| v["kind"] == "robodr.safety_state_transition")
        .map(|v| {
            (
                v["from"].as_str().unwrap().to_string(),
                v["to"].as_str().unwrap().to_string(),
            )
        })
        .collect();
    assert!(
        t.contains(&("moving_slow".to_string(), "idle".to_string())),
        "agentd transitions: {t:?}"
    );
    // deliverd's findings are in agentd's spool, validated, numbered
    // without collision next to agentd's records.
    let found = agentd_common::spooled(&s.spool);
    let rules = agentd_common::rules(&found);
    assert!(
        rules.contains(&"robot.deliver.installed".to_string()),
        "{rules:?}"
    );
    assert!(
        rules.contains(&"robot.deliver.deferred_safety".to_string()),
        "{rules:?}"
    );
    let mut seqs: Vec<u64> = found.iter().map(|(r, _)| r.seq).collect();
    seqs.dedup();
    assert_eq!(seqs.len(), found.len());
}
