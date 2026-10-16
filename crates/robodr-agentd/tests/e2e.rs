//! End to end, in process: synthetic pcap / JSONL events -> daemon ->
//! findings in the spool + a verified black box.

mod common;

use std::io::Write;
use std::os::unix::net::UnixStream;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;

use common::pcap::{robot_profile, scenario_frames};
use common::*;
use robodr_agentd::{State, StopReason};
use robodr_ocsf::Mode;

#[test]
fn pcap_replay_findings_reach_spool_with_verified_evidence() {
    let s = setup("pcap", &robot_profile(true));
    let pcap = s.pcap(&scenario_frames(5));
    let cfg = s.config(
        serde_json::json!({"capture": {"enabled": true, "pcap_replay": pcap}}),
        serde_json::json!([]),
        serde_json::json!({"exit_when_inputs_end": true}),
    );
    let r = s.resolve(&cfg);
    let mut log = Vec::new();
    let sum = robodr_agentd::run(&r, &|| false, &mut log).unwrap();
    let log = String::from_utf8(log).unwrap();
    assert_eq!(sum.reason, StopReason::InputsEnded, "{log}");
    assert_eq!(sum.stats.datagrams, 10, "{log}");

    let found = spooled(&s.spool);
    assert_eq!(
        rules(&found),
        vec![
            // Most severe first within one datagram; the rogue SPDP comes first.
            "robot.ros2.unknown_participant".to_string(),
            "robot.ros2.unauthorized_motion_writer".to_string(),
        ],
        "{log}"
    );
    for (rec, env) in &found {
        assert_eq!(rec.topic, "robot-edr.findings");
        assert_eq!(env.entity_context.robot.id, ROBOT);
        assert_eq!(
            env.entity_context.mode,
            Mode::Enforce,
            "sealed locked profile"
        );
        assert_eq!(env.evidence_links.len(), 2, "deviation + plan records");
    }
    assert_eq!(
        found[1].1.severity,
        robodr_events::Severity::Critical,
        "{:?}",
        found[1].1
    );
    assert_eq!(sum.stats.findings_spooled, 2);
    assert_eq!(sum.agent.findings, 2);

    // Black box: chain intact against the final seal, every link resolves,
    // start / heartbeat / stop notes are there.
    assert_verified(&s.blackbox, Some(sum.finished.checkpoint.clone()), &found);
    assert_eq!(notes_with(&s.blackbox, "robodr.agentd_start"), 1);
    assert!(notes_with(&s.blackbox, "robodr.agentd_heartbeat") >= 1);
    assert_eq!(notes_with(&s.blackbox, "robodr.agentd_stop"), 1);

    // The checkpoint copy for the exporter equals the final seal.
    let cp = std::fs::read_to_string(s.spool.join("checkpoint.json")).unwrap();
    assert_eq!(
        robodr_blackbox::Checkpoint::from_json(&cp).unwrap(),
        sum.finished.checkpoint
    );
    let st = status(&s.spool).unwrap();
    assert_eq!(st["running"], false);
    assert_eq!(st["profile_status"], "enforcing");
    // A replay that ended as expected is not "blind".
    assert_eq!(sum.last_state.state, State::Ok, "{:?}", sum.last_state);

    // A second run resumes the same black box and keeps numbering the spool.
    let r = s.resolve(&cfg);
    let sum2 = robodr_agentd::run(&r, &|| false, &mut Vec::new()).unwrap();
    assert_eq!(sum2.reason, StopReason::InputsEnded);
    let found2 = spooled(&s.spool);
    assert_eq!(found2.len(), 4);
    assert_eq!(found2.last().unwrap().0.seq, 4);
    assert_eq!(
        found2[2].1.entity_context.occurrence_count, 1,
        "a new process starts its occurrence counts afresh"
    );
    assert_verified(&s.blackbox, Some(sum2.finished.checkpoint), &found2);
}

#[test]
fn unlocked_and_invalid_profiles_never_enforce() {
    // Unlocked: same findings, observe-only.
    let s = setup("observe", &robot_profile(false));
    let pcap = s.pcap(&scenario_frames(2));
    let cfg = s.config(
        serde_json::json!({"capture": {"enabled": true, "pcap_replay": pcap}}),
        serde_json::json!([]),
        serde_json::json!({"exit_when_inputs_end": true}),
    );
    let sum = robodr_agentd::run(&s.resolve(&cfg), &|| false, &mut Vec::new()).unwrap();
    let found = spooled(&s.spool);
    assert_eq!(found.len(), 2);
    assert!(found
        .iter()
        .all(|(_, e)| e.entity_context.mode == Mode::Observe));
    assert_eq!(sum.last_state.state, State::Degraded);
    assert_verified(&s.blackbox, Some(sum.finished.checkpoint), &found);

    // Locked but fails validation: refused, still running observe-only,
    // the refusal is itself a finding.
    let mut bad = robot_profile(true);
    bad.motion_envelopes
        .get_mut("/cmd_vel")
        .unwrap()
        .max_linear_speed = Some(-1.0);
    let s = setup("refused", &robot_profile(true));
    std::fs::write(&s.profile, serde_json::to_string(&bad).unwrap()).unwrap();
    let pcap = s.pcap(&scenario_frames(2));
    let cfg = s.config(
        serde_json::json!({"capture": {"enabled": true, "pcap_replay": pcap}}),
        serde_json::json!([]),
        serde_json::json!({"exit_when_inputs_end": true}),
    );
    let mut log = Vec::new();
    let sum = robodr_agentd::run(&s.resolve(&cfg), &|| false, &mut log).unwrap();
    let log = String::from_utf8(log).unwrap();
    assert!(log.contains("REFUSED"), "{log}");
    let found = spooled(&s.spool);
    let r = rules(&found);
    assert_eq!(r[0], "robot.ros2.profile_refused", "{r:?}");
    assert!(r.contains(&"robot.ros2.unauthorized_motion_writer".to_string()));
    assert!(found
        .iter()
        .all(|(_, e)| e.entity_context.mode == Mode::Observe));
    assert_eq!(
        found[0].1.entity_context.robot.model,
        robodr_agentd::daemon::UNVALIDATED_MODEL
    );
    assert_verified(&s.blackbox, Some(sum.finished.checkpoint), &found);
}

#[test]
fn truncated_pcap_is_an_input_error_finding() {
    let s = setup("trunc", &robot_profile(true));
    let mut bytes = pcap_bytes(&scenario_frames(1));
    bytes.truncate(bytes.len() - 7);
    let p = s.dir.join("trunc.pcap");
    std::fs::write(&p, bytes).unwrap();
    let cfg = s.config(
        serde_json::json!({"capture": {"enabled": true, "pcap_replay": p}}),
        serde_json::json!([]),
        serde_json::json!({"exit_when_inputs_end": true}),
    );
    let sum = robodr_agentd::run(&s.resolve(&cfg), &|| false, &mut Vec::new()).unwrap();
    let found = spooled(&s.spool);
    let ended: Vec<_> = found
        .iter()
        .filter(|(_, e)| e.entity_context.rule_id == "robot.agent.input_ended")
        .collect();
    assert_eq!(ended.len(), 1, "{:?}", rules(&found));
    // Health findings are observe-only: never acted upon.
    assert_eq!(ended[0].1.entity_context.mode, Mode::Observe);
    assert_eq!(sum.last_state.state, State::Unknown);
    assert_verified(&s.blackbox, Some(sum.finished.checkpoint), &found);
}

fn pcap_bytes(frames: &[Vec<u8>]) -> Vec<u8> {
    common::pcap::pcap(frames)
}

/// The daemon's result and its log.
type DaemonThread = std::thread::JoinHandle<(Result<robodr_agentd::Summary, String>, String)>;

/// Run the daemon on a thread; returns (stop flag, join handle).
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

#[test]
fn jsonl_events_on_a_socket_run_the_full_chain_with_the_firewall() {
    // The agent's own demo profile and scenario (rogue participant, rogue
    // cmd_vel writer, over-envelope commands).
    let demo: robodr_events::profile::Profile = serde_json::from_str(
        &std::fs::read_to_string(
            std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
                .join("../robodr-agent/examples/ugv-demo.profile.json"),
        )
        .unwrap(),
    )
    .unwrap();
    let s = setup("socket", &demo);
    let sock = s.dir.join("events.sock");
    let mut cfg = s.config(
        serde_json::json!({}),
        serde_json::json!([{"kind": "unix_socket", "path": sock}]),
        serde_json::json!({}),
    );
    cfg["firewall"] = serde_json::json!({"max_angular": {"/cmd_vel": 1.0}});
    cfg["motion_monitor"] = serde_json::json!({"feedback_sources": {"/odom": "wheel_odometry"}});
    let (stop, h) = spawn(s.resolve(&cfg));
    let lines = std::fs::read_to_string(
        std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../robodr-agent/examples/rogue-ugv.jsonl"),
    )
    .unwrap();
    let mut c = wait_for(5, "socket", || UnixStream::connect(&sock).ok());
    c.write_all(lines.as_bytes()).unwrap();
    // Hostile garbage on the same stream does not end it.
    c.write_all(b"\xff\xfe garbage\n{\"kind\":\"motion_command\"}\n")
        .unwrap();
    c.flush().unwrap();
    let n_events = lines
        .lines()
        .filter(|l| !l.trim().is_empty() && !l.starts_with('#'))
        .count() as u64;
    wait_for(10, "events processed", || {
        let st = status(&s.spool)?;
        (st["daemon"]["events"].as_u64()? >= n_events
            && st["inputs"][0]["malformed"].as_u64()? >= 2)
            .then_some(())
    });
    stop.store(true, Ordering::SeqCst);
    let (res, log) = h.join().unwrap();
    let sum = res.unwrap_or_else(|e| panic!("{e}\n{log}"));
    assert_eq!(sum.reason, StopReason::Requested);
    assert_eq!(sum.stats.events, n_events);

    let found = spooled(&s.spool);
    let r = rules(&found);
    for want in [
        "robot.ros2.unknown_participant",
        "robot.ros2.unauthorized_motion_writer",
        "robot.motion.linear_over_envelope",
        "robot.agent.input_malformed",
    ] {
        assert!(
            r.iter().any(|x| x == want),
            "{want} missing from {r:?}\n{log}"
        );
    }
    // The firewall ran on the motion commands (its verdicts are evidence).
    assert!(sum.agent.firewall_checks > 0);
    assert!(
        r.iter().any(|x| x.starts_with("robot.firewall.")),
        "the rogue writer's command is refused by the firewall: {r:?}"
    );
    assert_verified(&s.blackbox, Some(sum.finished.checkpoint), &found);
    assert!(!sock.exists(), "socket removed at shutdown");
}

#[test]
fn queue_overflow_is_counted_and_reported() {
    let demo = robot_profile(true);
    let s = setup("flood", &demo);
    let sock = s.dir.join("flood.sock");
    let cfg = s.config(
        serde_json::json!({}),
        serde_json::json!([{"kind": "unix_socket", "path": sock}]),
        serde_json::json!({"queue_capacity": 1}),
    );
    let (stop, h) = spawn(s.resolve(&cfg));
    let mut c = wait_for(5, "socket", || UnixStream::connect(&sock).ok());
    // Each event deviates (unknown participant -> evidence + finding), so
    // the single-slot queue overflows.
    let mut burst = String::new();
    for i in 0..5000u32 {
        burst.push_str(&format!(
            "{{\"kind\":\"ros2_participant_discovered\",\"guid_prefix\":\"{i:024x}\",\"src_ip\":\"10.0.0.9\",\"locators\":[]}}\n"
        ));
    }
    c.write_all(burst.as_bytes()).unwrap();
    wait_for(20, "overflow finding", || {
        let found = spooled(&s.spool);
        rules(&found)
            .iter()
            .any(|r| r == "robot.agent.queue_overflow")
            .then_some(())
    });
    // Stop only once the reader has taken every line off the socket (the
    // periodic status shows it): stopping earlier makes the input thread
    // exit with lines still unread, so `received` < 5000 (flaky). After
    // this, shutdown joins the reader and drains the queue, so every line
    // is either processed or counted as dropped.
    wait_for(20, "all lines received", || {
        status(&s.spool)
            .filter(|st| st["inputs"][0]["received"].as_u64() == Some(5000))
            .map(|_| ())
    });
    stop.store(true, Ordering::SeqCst);
    let (res, log) = h.join().unwrap();
    let sum = res.unwrap_or_else(|e| panic!("{e}\n{log}"));
    assert!(sum.stats.events < 5000);
    assert!(sum.stats.events > 0);
    let st = status(&s.spool).unwrap();
    let inp = &st["inputs"][0];
    assert_eq!(
        inp["received"].as_u64().unwrap(),
        5000,
        "every line was read: queued or dropped"
    );
    assert_eq!(
        inp["dropped"].as_u64().unwrap() + sum.stats.events,
        5000,
        "{st}"
    );
    let found = spooled(&s.spool);
    assert_verified(&s.blackbox, Some(sum.finished.checkpoint), &found);
}

/// xorshift64*, deterministic.
fn rng(seed: &mut u64) -> u64 {
    *seed ^= *seed >> 12;
    *seed ^= *seed << 25;
    *seed ^= *seed >> 27;
    seed.wrapping_mul(0x2545_f491_4f6c_dd1d)
}

#[test]
fn hostile_datagrams_and_event_lines_never_stop_the_daemon() {
    use common::pcap::{frame, header, spdp_datagram, ROBOT_IP, ROGUE, ROGUE_IP, SPDP_GROUP};
    let s = setup("hostile", &robot_profile(true));
    // Mutated SPDP datagrams and random RTPS-looking junk on discovery ports.
    let mut seed = 0x5eed_1234_u64;
    let base = spdp_datagram(ROGUE, ROGUE_IP);
    let mut frames = Vec::new();
    for i in 0..400 {
        let mut d = if i % 2 == 0 {
            base.clone()
        } else {
            let mut h = header(ROGUE);
            let n = (rng(&mut seed) % 300) as usize;
            h.extend((0..n).map(|_| rng(&mut seed) as u8));
            h
        };
        for _ in 0..(rng(&mut seed) % 8) {
            let at = (rng(&mut seed) as usize) % d.len();
            d[at] = rng(&mut seed) as u8;
        }
        if rng(&mut seed).is_multiple_of(5) {
            let cut = (rng(&mut seed) as usize) % d.len();
            d.truncate(cut.max(1));
        }
        frames.push(frame(ROGUE_IP, SPDP_GROUP, 7400, &d));
    }
    frames.push(frame(
        ROBOT_IP,
        SPDP_GROUP,
        7400,
        &spdp_datagram(ROGUE, ROGUE_IP),
    ));
    let pcap = s.pcap(&frames);
    let sock = s.dir.join("hostile.sock");
    let cfg = s.config(
        serde_json::json!({"capture": {"enabled": true, "pcap_replay": pcap}}),
        serde_json::json!([{"kind": "unix_socket", "path": sock}]),
        serde_json::json!({}),
    );
    let (stop, h) = spawn(s.resolve(&cfg));
    let mut c = wait_for(5, "socket", || UnixStream::connect(&sock).ok());
    let good = r#"{"kind":"motion_command","channel":"/cmd_vel","source_guid":"eeeeeeeeeeeeeeeeeeeeeeee000001c1","linear_speed":1e308,"joint_speed":null}"#;
    let mut junk = Vec::new();
    for _ in 0..100 {
        let mut l = good.as_bytes().to_vec();
        for _ in 0..(rng(&mut seed) % 6) {
            let at = (rng(&mut seed) as usize) % l.len();
            l[at] = rng(&mut seed) as u8;
        }
        junk.extend_from_slice(&l);
        junk.push(b'\n');
    }
    junk.extend(std::iter::repeat_n(b'{', 200_000));
    junk.push(b'\n');
    junk.extend_from_slice(good.as_bytes());
    junk.push(b'\n');
    c.write_all(&junk).unwrap();
    wait_for(20, "pcap consumed and lines read", || {
        let st = status(&s.spool)?;
        let pcap_done = st["inputs"][0]["ended"].as_bool()?;
        let lines =
            st["inputs"][1]["received"].as_u64()? + st["inputs"][1]["malformed"].as_u64()?;
        (pcap_done && lines >= 102).then_some(())
    });
    stop.store(true, Ordering::SeqCst);
    let (res, log) = h.join().unwrap();
    let sum = res.unwrap_or_else(|e| panic!("{e}\n{log}"));
    assert_eq!(sum.stats.datagrams, 401);
    let found = spooled(&s.spool);
    let r = rules(&found);
    assert!(
        r.iter().any(|x| x == "robot.ros2.unknown_participant"),
        "{r:?}"
    );
    assert!(
        r.iter().any(|x| x == "robot.agent.input_malformed"),
        "{r:?}"
    );
    assert_verified(&s.blackbox, Some(sum.finished.checkpoint), &found);
}
