//! The `gateway_feed` input: the in-path gateway's findings
//! (`robot.gateway.*`, contract 2.3) and the Motion Firewall's deviations
//! from the gateway reach agentd over its socket, written by the gateway's
//! own feed writer (`robodr_firewall_gw::feed`), and become findings of the
//! normal pipeline; a line naming another detector's rule is malformed.

mod common;

use std::io::Write;
use std::os::unix::fs::PermissionsExt;
use std::os::unix::net::UnixStream;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Instant;

use common::pcap::robot_profile;
use common::*;
use robodr_events::{Deviation, Mode, Severity};
use robodr_firewall_gw::feed::{self, Feed};
use robodr_firewall_gw::findings::rules;

#[test]
fn gateway_findings_become_findings() {
    let s = setup("gw-feed", &robot_profile(true));
    let run = s.dir.join("run");
    std::fs::create_dir_all(&run).unwrap();
    std::fs::set_permissions(&run, std::fs::Permissions::from_mode(0o700)).unwrap();
    let sock = run.join("gateway-feed.sock");
    // agentd needs one sensor input of its own besides the gateway feed.
    let mut cfg = s.config(
        serde_json::json!({}),
        serde_json::json!([{"kind": "unix_socket", "path": run.join("events.sock")}]),
        serde_json::json!({}),
    );
    cfg["gateway_feed"] = serde_json::json!({
        "socket_path": sock,
        "allowed_uids": [robodr_agentd::config::effective_uid()],
    });
    let r = s.resolve(&cfg);
    assert!(r.gateway_feed.is_some());
    let stop = Arc::new(AtomicBool::new(false));
    let s2 = stop.clone();
    let h = std::thread::spawn(move || {
        let mut log = Vec::new();
        let res = robodr_agentd::run(&r, &|| s2.load(Ordering::SeqCst), &mut log)
            .map_err(|e| e.to_string());
        (res, String::from_utf8_lossy(&log).into_owned())
    });
    wait_for(10, "socket", || sock.exists().then_some(()));

    // The gateway's own writer.
    let mut f = Feed::new(sock.clone());
    let traj = Deviation::new(
        rules::TRAJECTORY_REJECTED,
        Severity::High,
        "channel /arm_trajectory: 4 time(s) since the last report; first: velocity",
    );
    f.push(feed::line(&traj, Some("/arm_trajectory"), 4).unwrap());
    let fw = Deviation::new(
        "robot.firewall.rejected_unknown_source",
        Severity::High,
        "x",
    )
    .with_mode(Mode::Enforce);
    f.push(feed::line(&fw, None, 1).unwrap());
    f.flush(Instant::now());
    assert_eq!(f.sent, 2, "{:?}", f.last_error);
    // A line for another detector's rule, from the same peer: refused.
    let mut c = UnixStream::connect(&sock).unwrap();
    let forged = feed::line(
        &Deviation::new("robot.safety_state.estop_engaged", Severity::Critical, "x"),
        None,
        1,
    )
    .unwrap();
    writeln!(c, "{forged}").unwrap();
    c.flush().unwrap();
    let st = wait_for(10, "gateway findings", || {
        let st = status(&s.spool)?;
        let gi = st["inputs"]
            .as_array()?
            .iter()
            .find(|i| {
                i["name"]
                    .as_str()
                    .is_some_and(|n| n.starts_with("gateway:"))
            })?
            .clone();
        (st["daemon"]["gateway_findings"].as_u64()? == 2 && gi["malformed"].as_u64()? == 1)
            .then_some(st)
    });
    stop.store(true, Ordering::SeqCst);
    let (res, log) = h.join().unwrap();
    res.unwrap_or_else(|e| panic!("{e}\n{log}"));
    let found = spooled(&s.spool);
    let g: Vec<_> = found
        .iter()
        .filter(|(_, e)| e.entity_context.rule_id == rules::TRAJECTORY_REJECTED)
        .collect();
    assert_eq!(g.len(), 1, "{st}\n{log}");
    let env = &g[0].1;
    assert_eq!(env.contract_version, robodr_ocsf::CONTRACT_VERSION);
    assert_eq!(
        env.title,
        robodr_ocsf::rule_info(rules::TRAJECTORY_REJECTED).title
    );
    assert_eq!(
        env.ocsf.finding_info.data_sources,
        vec!["ros2_motion_commands"]
    );
    assert_eq!(env.severity, Severity::High);
    assert!(env
        .entity_context
        .detail
        .value
        .contains("in-path gateway: channel /arm_trajectory"));
    assert!(found
        .iter()
        .any(|(_, e)| e.entity_context.rule_id == "robot.firewall.rejected_unknown_source"));
    assert!(!found
        .iter()
        .any(|(_, e)| e.entity_context.rule_id == "robot.safety_state.estop_engaged"));
    assert_verified(&s.blackbox, None, &found);
}

/// Soak 2026-10-30: a quiet, healthy gateway (no findings for a while)
/// made agentd report its feed silent (`robot.agent.input_silent`, High,
/// "the agent is blind on it", daemon state unknown) after every
/// `silence_ms`: eight times in 75 minutes of soak, and permanently on a
/// gateway that never has anything to report. The gateway's feed writer
/// now sends a heartbeat line while idle; a feed that stops (a dead
/// gateway) is still reported silent.
#[test]
fn gateway_heartbeats_keep_a_quiet_feed_alive() {
    let s = setup("gw-heartbeat", &robot_profile(true));
    let run = s.dir.join("run");
    std::fs::create_dir_all(&run).unwrap();
    std::fs::set_permissions(&run, std::fs::Permissions::from_mode(0o700)).unwrap();
    let sock = run.join("gateway-feed.sock");
    let mut cfg = s.config(
        serde_json::json!({}),
        serde_json::json!([{"kind": "unix_socket", "path": run.join("events.sock")}]),
        serde_json::json!({"silence_ms": 1500}),
    );
    cfg["gateway_feed"] = serde_json::json!({
        "socket_path": sock,
        "allowed_uids": [robodr_agentd::config::effective_uid()],
    });
    let r = s.resolve(&cfg);
    let stop = Arc::new(AtomicBool::new(false));
    let s2 = stop.clone();
    let h = std::thread::spawn(move || {
        let mut log = Vec::new();
        let res = robodr_agentd::run(&r, &|| s2.load(Ordering::SeqCst), &mut log)
            .map_err(|e| e.to_string());
        (res, String::from_utf8_lossy(&log).into_owned())
    });
    wait_for(10, "socket", || sock.exists().then_some(()));
    let gateway_silent = |spool: &std::path::Path| {
        spooled(spool).iter().any(|(_, e)| {
            e.entity_context.rule_id == "robot.agent.input_silent"
                && e.entity_context.detail.value.contains("gateway:")
        })
    };
    // 4 s of a quiet gateway: heartbeats only (the gateway's own writer).
    let mut f = Feed::with_heartbeat(sock.clone(), std::time::Duration::from_millis(300));
    let t0 = Instant::now();
    while t0.elapsed() < std::time::Duration::from_secs(4) {
        f.heartbeat_if_idle(Instant::now());
        f.flush(Instant::now());
        std::thread::sleep(std::time::Duration::from_millis(50));
    }
    assert!(
        f.heartbeats >= 5,
        "{} heartbeats, {:?}",
        f.heartbeats,
        f.last_error
    );
    assert_eq!(f.sent, 0, "heartbeats are not counted as findings sent");
    assert!(
        !gateway_silent(&s.spool),
        "a heartbeating gateway reported silent"
    );
    // The gateway stops: silent again after silence_ms.
    drop(f);
    let st = wait_for(10, "gateway silence", || {
        gateway_silent(&s.spool).then(|| status(&s.spool)).flatten()
    });
    stop.store(true, Ordering::SeqCst);
    let (res, log) = h.join().unwrap();
    res.unwrap_or_else(|e| panic!("{e}\n{log}"));
    assert!(
        st["daemon"]["gateway_heartbeats"].as_u64().unwrap_or(0) >= 5,
        "{st}"
    );
}

/// Sales-readiness T82 (red team W2-5, G8 / G9): a process allowed on the
/// feed socket wrote one finding per line, each a spool record. Now a
/// (rule, channel) past its budget is folded: the black box has every
/// line, the spool the first `PER_KEY` and one aggregate (at the window's
/// end, here at stop).
#[test]
fn a_feed_flood_is_folded_into_one_aggregate() {
    let s = setup("gw-flood", &robot_profile(true));
    let run = s.dir.join("run");
    std::fs::create_dir_all(&run).unwrap();
    std::fs::set_permissions(&run, std::fs::Permissions::from_mode(0o700)).unwrap();
    let sock = run.join("gateway-feed.sock");
    let mut cfg = s.config(
        serde_json::json!({}),
        serde_json::json!([{"kind": "unix_socket", "path": run.join("events.sock")}]),
        serde_json::json!({}),
    );
    cfg["gateway_feed"] = serde_json::json!({
        "socket_path": sock,
        "allowed_uids": [robodr_agentd::config::effective_uid()],
    });
    let r = s.resolve(&cfg);
    let stop = Arc::new(AtomicBool::new(false));
    let s2 = stop.clone();
    let h = std::thread::spawn(move || {
        let mut log = Vec::new();
        let res = robodr_agentd::run(&r, &|| s2.load(Ordering::SeqCst), &mut log)
            .map_err(|e| e.to_string());
        (res, String::from_utf8_lossy(&log).into_owned())
    });
    wait_for(10, "socket", || sock.exists().then_some(()));
    let mut c = UnixStream::connect(&sock).unwrap();
    const N: u64 = 50;
    for i in 0..N {
        let d = Deviation::new(
            "robot.firewall.rejected_stale",
            Severity::Critical,
            format!("flood {i}"),
        );
        writeln!(c, "{}", feed::line(&d, Some("/lowcmd"), 2).unwrap()).unwrap();
    }
    c.flush().unwrap();
    let per_key = u64::from(robodr_agentd::gateway_feed::CRITICAL_PER_KEY);
    let st = wait_for(10, "gateway lines", || {
        let st = status(&s.spool)?;
        (st["daemon"]["gateway_findings"].as_u64()? == N).then_some(st)
    });
    assert_eq!(st["daemon"]["gateway_folded"].as_u64(), Some(N - per_key));
    stop.store(true, Ordering::SeqCst);
    let (res, log) = h.join().unwrap();
    res.unwrap_or_else(|e| panic!("{e}\n{log}"));
    let found = spooled(&s.spool);
    let g: Vec<_> = found
        .iter()
        .filter(|(_, e)| e.entity_context.rule_id == "robot.firewall.rejected_stale")
        .collect();
    assert_eq!(g.len() as u64, per_key + 1, "{log}");
    let agg = g
        .iter()
        .find(|(_, e)| e.entity_context.detail.value.contains("folded"))
        .unwrap();
    assert_eq!(agg.1.severity, Severity::Critical);
    let v = &agg.1.entity_context.detail.value;
    assert!(
        v.contains(&format!(
            "{} gateway lines, gateway count {},",
            N - per_key,
            2 * (N - per_key)
        )),
        "{v}"
    );
    assert_verified(&s.blackbox, None, &found);
}

/// Sales-readiness T19 (GAP-24): the gateway's decision summaries (what it
/// enforced: mode, fail behaviour, file digests; how it decided: counters)
/// were a local file only. Now each summary the gateway's own
/// `Summarizer` writes is a black-box note, in the signed chain; editing
/// it afterwards breaks verification.
#[test]
fn gateway_summaries_are_signed_black_box_notes() {
    use robodr_firewall_gw::summary::{Event, Summarizer};
    let s = setup("gw-summary", &robot_profile(true));
    let run = s.dir.join("run");
    std::fs::create_dir_all(&run).unwrap();
    std::fs::set_permissions(&run, std::fs::Permissions::from_mode(0o700)).unwrap();
    let sock = run.join("gateway-feed.sock");
    let mut cfg = s.config(
        serde_json::json!({}),
        serde_json::json!([{"kind": "unix_socket", "path": run.join("events.sock")}]),
        serde_json::json!({}),
    );
    cfg["gateway_feed"] = serde_json::json!({
        "socket_path": sock,
        "allowed_uids": [robodr_agentd::config::effective_uid()],
    });
    let r = s.resolve(&cfg);
    let stop = Arc::new(AtomicBool::new(false));
    let s2 = stop.clone();
    let h = std::thread::spawn(move || {
        let mut log = Vec::new();
        let res = robodr_agentd::run(&r, &|| s2.load(Ordering::SeqCst), &mut log)
            .map_err(|e| e.to_string());
        (res, String::from_utf8_lossy(&log).into_owned())
    });
    wait_for(10, "socket", || sock.exists().then_some(()));

    let mut gw = robodr_firewall_gw::testkit::gateway(robodr_firewall_gw::testkit::Fixture::G1);
    gw.provenance.firewall_sha256 = Some(format!("sha256:{}", "7".repeat(64)));
    let t0 = Instant::now();
    let mut sum = Summarizer::new(robodr_firewall_gw::OnGatewayDown::FailClosed, t0);
    let mut f = Feed::new(sock.clone());
    f.push(sum.line(Event::Start, &gw, t0).unwrap());
    gw.stats.packets = 4242;
    gw.stats.limited = 77;
    f.push(sum.line(Event::Stop, &gw, t0).unwrap());
    f.flush(Instant::now());
    assert_eq!(f.sent, 2, "{:?}", f.last_error);
    wait_for(10, "summaries", || {
        let st = status(&s.spool)?;
        (st["daemon"]["gateway_summaries"].as_u64()? == 2).then_some(())
    });
    stop.store(true, Ordering::SeqCst);
    let (res, log) = h.join().unwrap();
    res.unwrap_or_else(|e| panic!("{e}\n{log}"));
    assert_eq!(
        notes_with(&s.blackbox, "robodr-gateway-summary/v1"),
        2,
        "{log}"
    );
    assert_eq!(notes_with(&s.blackbox, "\"packets\":4242"), 1);
    let found = spooled(&s.spool);
    assert_verified(&s.blackbox, None, &found);

    // Tamper: the stop summary's counters rewritten in place.
    let mut hit = 0;
    for e in std::fs::read_dir(&s.blackbox).unwrap() {
        let p = e.unwrap().path();
        let Ok(mut b) = std::fs::read(&p) else {
            continue;
        };
        let needle = b"\"limited\":77";
        if let Some(i) = b.windows(needle.len()).position(|w| w == needle) {
            b[i + needle.len() - 2] = b'0';
            std::fs::write(&p, &b).unwrap();
            hit += 1;
        }
    }
    assert_eq!(hit, 1, "the note is in one segment");
    let report = robodr_agent::verify_blackbox(&s.blackbox, &verifier(), None, Some(ROBOT));
    assert!(
        report.map_or(true, |r| !r.is_intact()),
        "an edited gateway summary must break the chain"
    );
}
