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
