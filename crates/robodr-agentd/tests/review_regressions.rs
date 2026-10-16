//! Regression tests for the fourth review's findings. Each started life as
//! a proof of concept that passed while the bug existed; here they assert
//! the fixed behaviour.

mod common;

use std::io::Write;
use std::os::unix::net::{UnixDatagram, UnixListener, UnixStream};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc::sync_channel;
use std::sync::Arc;
use std::time::{Duration, Instant};

use common::pcap::{robot_profile, scenario_frames};
use common::*;
use robodr_agentd::input::{self, Feed, InputStats, Payload};
use robodr_agentd::notify::{monotonic_ms, Notifier};
use robodr_agentd::State;

#[repr(C)]
struct Timespec {
    sec: i64,
    nsec: i64,
}
extern "C" {
    fn clock_gettime(clk: i32, ts: *mut Timespec) -> i32;
}
/// CPU time of the calling thread.
fn thread_cpu() -> Duration {
    let mut ts = Timespec { sec: 0, nsec: 0 };
    // SAFETY: CLOCK_THREAD_CPUTIME_ID = 3; ts is a valid out pointer.
    assert_eq!(unsafe { clock_gettime(3, &mut ts) }, 0);
    Duration::new(ts.sec as u64, ts.nsec as u32)
}

/// Finding 1: once every input has ended in live mode
/// (`exit_when_inputs_end = false`) the main loop must sleep, not spin on
/// the disconnected queue, and the state must say the agent is blind.
#[test]
fn idle_after_all_inputs_end_and_state_is_unknown() {
    let s = setup("spin", &robot_profile(true));
    let pcap = s.pcap(&scenario_frames(1));
    let cfg = s.config(
        serde_json::json!({"capture": {"enabled": true, "pcap_replay": pcap}}),
        serde_json::json!([]),
        serde_json::json!({"exit_when_inputs_end": false, "tick_ms": 100, "heartbeat_ms": 10000}),
    );
    let r = s.resolve(&cfg);
    let mut log = Vec::new();
    let t0 = Instant::now();
    let c0 = thread_cpu();
    let stop_at = t0 + Duration::from_millis(2000);
    let sum = robodr_agentd::run(&r, &|| Instant::now() >= stop_at, &mut log).unwrap();
    let wall = t0.elapsed();
    let cpu = thread_cpu() - c0;
    // Was ~100% of the wall time; an idle loop (20 wake-ups/s) uses little.
    assert!(
        cpu < wall.mul_f64(0.25),
        "cpu {cpu:?} over {wall:?}: busy spin"
    );
    assert_eq!(sum.last_state.state, State::Unknown);
    let reasons = sum.last_state.reasons.join("; ");
    assert!(reasons.contains("every input has ended"), "{reasons}");
    assert!(reasons.contains("input pcap ended"), "{reasons}");
    // Ticks kept running while idle.
    assert!(sum.stats.ticks >= 10, "{:?}", sum.stats);
    let log = String::from_utf8_lossy(&log);
    assert!(log.contains("every input has ended"), "{log}");
    assert!(rules(&spooled(&s.spool)).contains(&"robot.agent.input_ended".to_string()));
}

/// Finding 2: an input that only ever delivers malformed lines is blind:
/// never `ok`, an `input_silent` finding (and the `input_malformed` one).
#[test]
fn malformed_only_stream_is_never_ok() {
    let s = setup("malformed-ok", &robot_profile(true));
    let sock = s.dir.join("ev.sock");
    let cfg = s.config(
        serde_json::json!({}),
        serde_json::json!([{"kind": "unix_socket", "path": sock}]),
        serde_json::json!({"silence_ms": 300, "tick_ms": 50}),
    );
    let r = s.resolve(&cfg);
    let stop = Arc::new(AtomicBool::new(false));
    let st2 = stop.clone();
    let h = std::thread::spawn(move || {
        let mut log = Vec::new();
        let sum = robodr_agentd::run(&r, &|| st2.load(Ordering::SeqCst), &mut log).unwrap();
        (sum, String::from_utf8_lossy(&log).into_owned())
    });
    wait_for(5, "socket", || UnixStream::connect(&sock).ok().map(|_| ()));
    let mut c = UnixStream::connect(&sock).unwrap();
    let deadline = Instant::now() + Duration::from_millis(2500);
    let mut last = None;
    while Instant::now() < deadline {
        // Valid JSON, wrong schema: the agent never gets a RobotEvent.
        let _ = writeln!(c, r#"{{"kind":"motion_command_v2","channel":"/cmd_vel"}}"#);
        std::thread::sleep(Duration::from_millis(50));
        if let Some(st) = status(&s.spool) {
            assert_ne!(st["state"], "ok", "ok with zero valid events: {st:#}");
            last = Some(st);
        }
    }
    stop.store(true, Ordering::SeqCst);
    let (sum, log) = h.join().unwrap();
    let st = last.expect("a status");
    assert_eq!(st["state"], "unknown", "{st:#}");
    assert_eq!(st["daemon"]["events"], 0, "{st:#}");
    assert!(
        st["inputs"][0]["malformed"].as_u64().unwrap() > 10,
        "{st:#}"
    );
    assert!(st["inputs"][0]["last_rx_age_ms"].is_null(), "{st:#}");
    assert_eq!(sum.stats.events, 0);
    assert_ne!(sum.last_state.state, State::Ok);
    let found = spooled(&s.spool);
    let rs = rules(&found);
    assert!(
        rs.contains(&"robot.agent.input_silent".to_string()),
        "{rs:?}"
    );
    assert!(
        rs.contains(&"robot.agent.input_malformed".to_string()),
        "{rs:?}"
    );
    // The silence finding counts the junk (its detail is in the log).
    assert!(log.contains("robot.agent.input_silent"), "{log}");
    assert!(log.contains("malformed item(s) skipped"), "{log}");
}

/// Finding 4: `..` in spool.dir cannot alias the black-box directory.
#[test]
fn spool_dir_cannot_alias_blackbox_dir_via_dotdot() {
    let s = setup("alias", &robot_profile(true));
    let pcap = s.pcap(&scenario_frames(1));
    let mut cfg = s.config(
        serde_json::json!({"capture": {"enabled": true, "pcap_replay": pcap}}),
        serde_json::json!([]),
        serde_json::json!({"exit_when_inputs_end": true}),
    );
    let alias = s.dir.join("x").join("..").join("blackbox");
    cfg["spool"]["dir"] = serde_json::json!(alias);
    let e = robodr_agentd::load(&s.write_config(&cfg)).unwrap_err();
    assert!(e.contains("must not contain"), "{e}");
    assert!(!s.blackbox.join("status.json").exists());
}

/// Finding 4 (race): a symlink created between the configuration check and
/// the start is caught on the canonical paths; nothing is written.
#[test]
fn symlink_alias_created_after_check_is_refused_at_start() {
    let s = setup("alias-link", &robot_profile(true));
    let pcap = s.pcap(&scenario_frames(1));
    let mut cfg = s.config(
        serde_json::json!({"capture": {"enabled": true, "pcap_replay": pcap}}),
        serde_json::json!([]),
        serde_json::json!({"exit_when_inputs_end": true}),
    );
    let link = s.dir.join("spool-link");
    cfg["spool"]["dir"] = serde_json::json!(link);
    let r = robodr_agentd::load(&s.write_config(&cfg)).unwrap();
    std::fs::create_dir_all(&s.blackbox).unwrap();
    std::os::unix::fs::symlink(&s.blackbox, &link).unwrap();
    let mut log = Vec::new();
    let e = robodr_agentd::run(&r, &|| false, &mut log).unwrap_err();
    assert!(matches!(e, robodr_agentd::DaemonError::Config(_)), "{e}");
    assert!(e.to_string().contains("must not contain"), "{e}");
    assert!(!s.blackbox.join("status.json").exists());
    assert!(!s.blackbox.join("ready").exists());
}

/// Finding 5: a live socket is never stolen, and an old instance's cleanup
/// never removes a newer instance's socket.
#[test]
fn bind_event_socket_does_not_steal_a_live_socket() {
    let d = tmpdir("steal");
    let path = d.join("ev.sock");
    let first = input::bind_event_socket(&path).unwrap();
    let e = input::bind_event_socket(&path).unwrap_err();
    assert_eq!(e.kind(), std::io::ErrorKind::AddrInUse, "{e}");
    // Still reachable, by the first listener.
    let c = UnixStream::connect(&path).unwrap();
    first.listener.set_nonblocking(true).unwrap();
    assert!(
        first.listener.accept().is_ok(),
        "connection went to the first"
    );
    drop(c);

    // The path is taken over by another instance (after the first's file
    // vanished): the first instance's shutdown leaves it alone.
    std::fs::remove_file(&path).unwrap();
    let second = UnixListener::bind(&path).unwrap();
    let (tx, _rx) = sync_channel(4);
    let feed = Feed::new(tx, 0, Arc::new(InputStats::default()), Instant::now());
    let stop = Arc::new(AtomicBool::new(true));
    input::run_unix_listener(first, 1, stop, feed);
    assert!(UnixStream::connect(&path).is_ok(), "second still reachable");
    drop(second);
}

/// Finding 3: the queue is bounded in bytes, and its item bound is capped.
#[test]
fn queue_is_bounded_in_bytes() {
    let d = robodr_agentd::config::DaemonSection::default();
    let (tx, rx) = sync_channel(d.queue_capacity);
    let stats = Arc::new(InputStats::default());
    let feed = Feed::new(tx, 0, stats.clone(), Instant::now());
    for _ in 0..d.queue_capacity {
        let dg = robodr_ros2_pipeline::Datagram::new(vec![0u8; 65_507], "10.0.0.9");
        assert!(feed.send(Payload::Datagram(dg)));
    }
    let held: usize = rx
        .try_iter()
        .map(|m| match m.payload {
            Payload::Datagram(d) => d.payload.len(),
            Payload::Event(_) | Payload::Safety(_) => 0,
        })
        .sum();
    assert!(held <= d.queue_bytes, "held {held} bytes");
    assert!(held >= d.queue_bytes / 2, "held {held} bytes");
    let dropped = stats.dropped.load(Ordering::Relaxed);
    assert!(dropped > 3000, "{dropped}");
    assert_eq!(stats.budget_drops.load(Ordering::Relaxed), dropped);
    let mut big = d;
    big.queue_capacity = 1 << 20;
    assert!(robodr_agentd::config::validate_daemon(&big).is_err());
}

/// Finding 3 end to end: the daemon reports its queue budget and the
/// configured `queue_bytes` is honoured.
#[test]
fn daemon_reports_queue_budget() {
    let s = setup("budget", &robot_profile(true));
    let pcap = s.pcap(&scenario_frames(1));
    let cfg = s.config(
        serde_json::json!({"capture": {"enabled": true, "pcap_replay": pcap}}),
        serde_json::json!([]),
        serde_json::json!({"exit_when_inputs_end": true, "queue_bytes": 2_097_152}),
    );
    let r = s.resolve(&cfg);
    let mut log = Vec::new();
    robodr_agentd::run(&r, &|| false, &mut log).unwrap();
    let st = status(&s.spool).unwrap();
    assert_eq!(st["queue_bytes_max"], 2_097_152, "{st:#}");
    assert_eq!(st["queue_bytes"], 0, "drained at stop: {st:#}");
    assert_eq!(st["inputs"][0]["budget_drops"], 0, "{st:#}");
}

/// Watchdog: READY / WATCHDOG / STATUS / STOPPING go to NOTIFY_SOCKET, and
/// a status that stops being refreshed reads as unknown.
#[test]
fn sd_notify_and_stale_status_read_as_unknown() {
    let s = setup("watchdog", &robot_profile(true));
    let sock = s.dir.join("ev.sock");
    let cfg = s.config(
        serde_json::json!({}),
        serde_json::json!([{"kind": "unix_socket", "path": sock}]),
        serde_json::json!({"tick_ms": 50, "lag_ms": 200}),
    );
    let r = s.resolve(&cfg);
    let nsock = s.dir.join("notify.sock");
    let rx = UnixDatagram::bind(&nsock).unwrap();
    rx.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
    let notifier = Notifier::to(nsock.to_str().unwrap());
    let stop = Arc::new(AtomicBool::new(false));
    let st2 = stop.clone();
    let h = std::thread::spawn(move || {
        let mut log = Vec::new();
        robodr_agentd::run_with(&r, &|| st2.load(Ordering::SeqCst), &mut log, notifier).unwrap()
    });
    let mut got: Vec<String> = Vec::new();
    let mut buf = [0u8; 256];
    let deadline = Instant::now() + Duration::from_secs(10);
    while Instant::now() < deadline
        && !(got.iter().any(|m| m.starts_with("STATUS=state"))
            && got.iter().filter(|m| m.as_str() == "WATCHDOG=1").count() >= 2)
    {
        let n = rx.recv(&mut buf).unwrap();
        got.push(String::from_utf8_lossy(&buf[..n]).into_owned());
    }
    assert!(got[0].starts_with("READY=1"), "{got:?}");
    assert!(got.iter().any(|m| m == "STATUS=state unknown"), "{got:?}");

    // A fresh status reads as its own state; the same status later (the
    // loop stalled) or from another boot reads as unknown.
    let st = wait_for(5, "status", || status(&s.spool));
    assert_eq!(st["running"], true);
    assert_eq!(st["boot_id"], "test-boot");
    assert_eq!(st["stale_after_ms"], 2 * 50 + 200);
    let at = st["updated_mono_ms"].as_u64().unwrap();
    let now = monotonic_ms();
    assert!(at <= now && now - at < 5_000, "{at} vs {now}");
    let mut ok = st.clone();
    ok["state"] = "ok".into();
    assert_eq!(
        robodr_agentd::effective_state(&ok, at + 300, "test-boot"),
        State::Ok
    );
    assert_eq!(
        robodr_agentd::effective_state(&ok, at + 301, "test-boot"),
        State::Unknown,
        "stale"
    );
    assert_eq!(
        robodr_agentd::effective_state(&ok, at, "other-boot"),
        State::Unknown
    );
    let mut broken = ok.clone();
    broken["updated_mono_ms"] = "soon".into();
    assert_eq!(
        robodr_agentd::effective_state(&broken, at, "test-boot"),
        State::Unknown
    );

    stop.store(true, Ordering::SeqCst);
    h.join().unwrap();
    let mut rest = Vec::new();
    rx.set_read_timeout(Some(Duration::from_millis(500)))
        .unwrap();
    while let Ok(n) = rx.recv(&mut buf) {
        rest.push(String::from_utf8_lossy(&buf[..n]).into_owned());
    }
    assert!(rest.iter().any(|m| m == "STOPPING=1"), "{rest:?}");
    let fin = status(&s.spool).unwrap();
    assert_eq!(fin["running"], false);
    assert_eq!(
        robodr_agentd::effective_state(&fin, monotonic_ms(), "test-boot"),
        State::Unknown
    );
}

/// Kept from the review: hostile JSON event lines (extreme floats, huge
/// strings, deep nesting, control characters) neither panic the reader nor
/// the agent.
#[test]
fn hostile_event_lines_do_not_panic() {
    let s = setup("hostile", &robot_profile(true));
    let sock = s.dir.join("ev.sock");
    let cfg = s.config(
        serde_json::json!({}),
        serde_json::json!([{"kind": "unix_socket", "path": sock}]),
        serde_json::json!({}),
    );
    let r = s.resolve(&cfg);
    let stop = Arc::new(AtomicBool::new(false));
    let st2 = stop.clone();
    let h = std::thread::spawn(move || {
        let mut log = Vec::new();
        robodr_agentd::run(&r, &|| st2.load(Ordering::SeqCst), &mut log).unwrap()
    });
    wait_for(5, "socket", || UnixStream::connect(&sock).ok().map(|_| ()));
    let mut c = UnixStream::connect(&sock).unwrap();
    let long = "A".repeat(60_000);
    let deep = format!("{}{}", "[".repeat(10_000), "]".repeat(10_000));
    let lines = [
        r#"{"kind":"motion_command","channel":"/cmd_vel","linear_speed":1e308,"angular_speed":-1e308}"#.to_string(),
        r#"{"kind":"motion_command","channel":"/cmd_vel","linear_speed":1e999}"#.to_string(),
        r#"{"kind":"motion_command","channel":"/cmd_vel","linear_speed":-0.0,"joint_speed":5e-324}"#.to_string(),
        format!(r#"{{"kind":"motion_command","channel":"{long}","linear_speed":1}}"#),
        format!(r#"{{"kind":"motion_command","channel":"/cmd_vel\u0000\u001b[2J","source_guid":"{long}"}}"#),
        deep,
        r#"{"kind":"motion_feedback","channel":"/odom","measured_linear_speed":1e308,"linear_velocity":-1e308,"angular_velocity":1e308}"#.to_string(),
    ];
    for _ in 0..50 {
        for l in &lines {
            writeln!(c, "{l}").unwrap();
        }
    }
    drop(c);
    std::thread::sleep(Duration::from_millis(500));
    stop.store(true, Ordering::SeqCst);
    let sum = h.join().expect("daemon panicked");
    assert!(sum.stats.events > 0);
}
