//! The live safety-state feed: mappings, staleness, conflicts, spoofing,
//! and its effect on plans end to end through the daemon.
//!
//! Bus traffic is hand-built RTPS + CDR (DDSI-RTPS / XCDR specs); no real
//! RMW, safety PLC or e-stop was involved.

mod common;

#[path = "../../robodr-cdr/tests/common/mod.rs"]
mod cdrenc;

use std::io::Write;
use std::net::Ipv4Addr;
use std::os::unix::net::UnixStream;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;

use common::pcap::*;
use common::*;
use robodr_agentd::safety::{rules, FeedFinding, SafetyFeed, SafetyFeedSection};
use robodr_agentd::StopReason;
use robodr_events::profile::Profile;
use robodr_events::Severity;
use robodr_responder::SafetyState as S;
use robodr_ros2_pipeline::{Datagram, Pipeline, PipelineOptions};

const ESTOP_W: [u8; 4] = [0, 0, 0x20, 0x03];
const MODE_W: [u8; 4] = [0, 0, 0x21, 0x03];
const NAME_W: [u8; 4] = [0, 0, 0x22, 0x03];
/// A legit participant's second /estop writer, announced with the wrong type.
const ESTOP_W2: [u8; 4] = [0, 0, 0x23, 0x03];
const BOOL: &str = "std_msgs::msg::dds_::Bool_";
const U8: &str = "std_msgs::msg::dds_::UInt8_";
const STR: &str = "std_msgs::msg::dds_::String_";

fn bool_cdr(v: u8) -> Vec<u8> {
    vec![0, 1, 0, 0, v, 0, 0, 0]
}

fn u8_cdr(v: u8) -> Vec<u8> {
    vec![0, 1, 0, 0, v, 0, 0, 0]
}

fn str_cdr(s: &str) -> Vec<u8> {
    let mut p = vec![0, 1, 0, 0];
    p.extend_from_slice(&(s.len() as u32 + 1).to_le_bytes());
    p.extend_from_slice(s.as_bytes());
    p.push(0);
    while !p.len().is_multiple_of(4) {
        p.push(0);
    }
    p
}

fn odom(vx: f64) -> Vec<u8> {
    cdrenc::odometry(
        robodr_cdr::Representation::CdrLe,
        &cdrenc::OdomSpec {
            frame: b"odom",
            child: b"base_link",
            position: [0.0; 3],
            orientation: [0.0, 0.0, 0.0, 1.0],
            pose_cov: [0.0; 36],
            lin: [vx, 0.0, 0.0],
            ang: [0.0; 3],
            twist_cov: [0.0; 36],
        },
    )
}

/// The lab profile plus the safety topics as writer topics.
fn profile(locked: bool) -> Profile {
    let mut p = robot_profile(locked);
    for t in ["/estop", "/robot_mode", "/mode_name"] {
        p.writer_topics.insert(t.into());
    }
    p
}

/// SPDP of the legit participant, its motion endpoints and its safety
/// writers.
fn discovery() -> Vec<u8> {
    datagram(
        LEGIT,
        &[
            spdp_sub(LEGIT, &[ROBOT_IP]),
            sedp_writer_sub(LEGIT, CMD_WRITER, "rt/cmd_vel", TWIST),
            sedp_reader_sub(LEGIT, CMD_READER, "rt/cmd_vel", TWIST),
            sedp_writer_sub(LEGIT, ODOM_WRITER, "rt/odom", ODOM),
            sedp_writer_sub(LEGIT, ESTOP_W, "rt/estop", BOOL),
            sedp_writer_sub(LEGIT, MODE_W, "rt/robot_mode", U8),
            sedp_writer_sub(LEGIT, NAME_W, "rt/mode_name", STR),
        ],
    )
}

fn sample(prefix: [u8; 12], writer: [u8; 4], sn: u32, payload: &[u8]) -> Vec<u8> {
    datagram(prefix, &[user_data(writer, [0; 4], sn, payload, true)])
}

/// `feed` with the legit participant as the commissioned writer of every
/// topic that names none (writers are mandatory).
fn with_writers(mut feed: serde_json::Value) -> serde_json::Value {
    if let Some(ts) = feed.get_mut("topics").and_then(|t| t.as_array_mut()) {
        for t in ts {
            if t.get("writers").is_none() {
                t["writers"] = serde_json::json!([LEGIT_HEX]);
            }
        }
    }
    feed
}

fn estop_values() -> serde_json::Value {
    serde_json::json!({"true": "estop_active", "false": "none"})
}

fn full_feed() -> serde_json::Value {
    serde_json::json!({
        "topics": [
            {"topic": "/estop", "type": "std_msgs/msg/Bool", "values": estop_values()},
            {"topic": "/robot_mode", "type": "std_msgs/msg/UInt8",
             "values": {"0": "idle", "1": "moving_slow", "2": "collaborative_human_nearby",
                        "7": "safe_state_active"}},
            {"topic": "/mode_name", "type": "std_msgs/msg/String",
             "values": {"AUTO": "none", "PROTECTIVE_STOP": "safe_state_active"}},
            {"topic": "/odom", "type": "nav_msgs/msg/Odometry",
             "motion": {"moving_above": 0.05, "fast_above": 1.0, "hysteresis": 0.02}}
        ]
    })
}

/// The pipeline (for its binding table) and the feed, driven datagram by
/// datagram with an explicit clock, as the daemon does.
struct Bus {
    pipeline: Pipeline,
    feed: SafetyFeed,
    sn: u32,
}

impl Bus {
    fn new(feed: serde_json::Value) -> Self {
        let p = profile(false);
        let sec: SafetyFeedSection = serde_json::from_value(with_writers(feed)).unwrap();
        let (spec, _) = sec.resolve(&p).unwrap();
        let mut b = Bus {
            pipeline: Pipeline::new(p, PipelineOptions::default()),
            feed: SafetyFeed::new(spec),
            sn: 0,
        };
        assert!(b.raw(ROBOT_IP, discovery(), 0).is_empty());
        b
    }

    fn raw(&mut self, ip: Ipv4Addr, payload: Vec<u8>, now: u64) -> Vec<FeedFinding> {
        let d = Datagram::new(payload, ip.to_string());
        self.pipeline.process_datagram_with_motion(&d, 0);
        self.feed
            .observe_datagram(&d, self.pipeline.profile(), self.pipeline.binding(), now)
    }

    /// A sample from the legit participant at the robot's IP.
    fn send(&mut self, writer: [u8; 4], payload: &[u8], now: u64) -> Vec<FeedFinding> {
        self.sn += 1;
        let d = sample(LEGIT, writer, self.sn, payload);
        self.raw(ROBOT_IP, d, now)
    }

    fn state(&mut self, now: u64) -> S {
        self.feed.evaluate(now);
        self.feed.state()
    }
}

#[test]
fn bool_and_uint8_mappings() {
    let mut b = Bus::new(full_feed());
    assert_eq!(b.state(0), S::Unknown, "nothing heard yet");
    // Every source must be fresh; e-stop released says nothing by itself.
    b.send(ESTOP_W, &bool_cdr(0), 1);
    b.send(MODE_W, &u8_cdr(0), 1);
    b.send(NAME_W, &str_cdr("AUTO"), 1);
    b.send(ODOM_WRITER, &odom(0.0), 1);
    assert_eq!(b.state(1), S::Idle);
    b.send(MODE_W, &u8_cdr(1), 2);
    assert_eq!(b.state(2), S::MovingSlow);
    b.send(MODE_W, &u8_cdr(2), 3);
    assert_eq!(b.state(3), S::CollaborativeHumanNearby);
    b.send(MODE_W, &u8_cdr(7), 4);
    assert_eq!(b.state(4), S::SafeStateActive);
    // E-stop pressed: beats everything.
    b.send(ESTOP_W, &bool_cdr(1), 5);
    assert_eq!(b.state(5), S::EStopActive);
    b.send(ESTOP_W, &bool_cdr(0), 6);
    b.send(MODE_W, &u8_cdr(0), 6);
    assert_eq!(b.state(6), S::Idle);
    assert_eq!(b.feed.stats().untrusted, 0);
    assert_eq!(b.feed.stats().applied, 10);
}

#[test]
fn string_mapping_and_unmapped_values_read_unknown() {
    let mut b = Bus::new(full_feed());
    b.send(ESTOP_W, &bool_cdr(0), 1);
    b.send(MODE_W, &u8_cdr(0), 1);
    b.send(ODOM_WRITER, &odom(0.0), 1);
    b.send(NAME_W, &str_cdr("PROTECTIVE_STOP"), 1);
    assert_eq!(b.state(1), S::SafeStateActive);
    b.send(NAME_W, &str_cdr("AUTO"), 2);
    assert_eq!(b.state(2), S::Idle);
    // Case matters; an unlisted value is unknown (and reported once).
    let f = b.send(NAME_W, &str_cdr("auto"), 3);
    assert_eq!(b.state(3), S::Unknown);
    assert_eq!(f.len(), 1);
    assert_eq!(f[0].deviation.rule_str(), rules::UNMAPPED_VALUE);
    assert_eq!(f[0].deviation.severity, Severity::Low);
    assert_eq!(f[0].topic, "/mode_name");
    assert!(b.send(NAME_W, &str_cdr("auto"), 4).is_empty(), "dedup");
    b.send(NAME_W, &str_cdr("AUTO"), 5);
    assert_eq!(b.state(5), S::Idle);
    // An unlisted mode code.
    let f = b.send(MODE_W, &u8_cdr(200), 6);
    assert_eq!(f[0].deviation.rule_str(), rules::UNMAPPED_VALUE);
    assert_eq!(b.state(6), S::Unknown);
    // A string over the decoder's bound is undecodable, not truncated.
    let f = b.send(NAME_W, &str_cdr(&"A".repeat(400)), 7);
    assert_eq!(f[0].deviation.rule_str(), rules::UNDECODABLE);
}

#[test]
fn odometry_speed_with_hysteresis() {
    let mut b = Bus::new(full_feed());
    b.send(ESTOP_W, &bool_cdr(0), 0);
    b.send(MODE_W, &u8_cdr(0), 0);
    b.send(NAME_W, &str_cdr("AUTO"), 0);
    let mut seen = Vec::new();
    for (i, v) in [0.0, 0.04, 0.06, 0.04, 0.02, 1.2, 0.99, 0.95, 0.0, -0.5]
        .into_iter()
        .enumerate()
    {
        b.send(ODOM_WRITER, &odom(v), i as u64);
        seen.push(b.state(i as u64));
    }
    assert_eq!(
        seen,
        vec![
            S::Idle,
            S::Idle,
            S::MovingSlow,
            S::MovingSlow,
            S::Idle,
            S::MovingFast,
            S::MovingFast,
            S::MovingSlow,
            S::Idle,
            S::MovingSlow, // reversing is moving
        ]
    );
    // Non-finite speed: unknown, never idle.
    b.send(ODOM_WRITER, &odom(f64::NAN), 20);
    assert_eq!(b.state(20), S::Unknown);
    b.send(ODOM_WRITER, &odom(f64::INFINITY), 21);
    assert_eq!(b.state(21), S::Unknown);
    b.send(ODOM_WRITER, &odom(0.0), 22);
    assert_eq!(b.state(22), S::Idle);
}

#[test]
fn stale_sources_read_unknown() {
    let mut b = Bus::new(serde_json::json!({
        "stale_after_ms": 1000,
        "topics": [
            {"topic": "/estop", "type": "std_msgs/msg/Bool", "values": estop_values()},
            {"topic": "/robot_mode", "type": "std_msgs/msg/UInt8", "values": {"0": "idle"},
             "stale_after_ms": 300}
        ]
    }));
    b.send(ESTOP_W, &bool_cdr(0), 0);
    b.send(MODE_W, &u8_cdr(0), 0);
    assert_eq!(b.state(0), S::Idle);
    assert_eq!(b.state(300), S::Idle, "exactly at the bound is fresh");
    assert_eq!(b.state(301), S::Unknown, "the mode source went silent");
    b.send(MODE_W, &u8_cdr(0), 900);
    assert_eq!(b.state(900), S::Idle);
    // The e-stop publisher stops: unknown, even though the mode is fresh.
    b.send(MODE_W, &u8_cdr(0), 1100);
    assert_eq!(b.state(1100), S::Unknown);
    let st = b.feed.status(1100);
    let estop = st.sources.iter().find(|s| s.name == "/estop").unwrap();
    assert!(!estop.fresh);
    assert_eq!(estop.age_ms, Some(1100));
    // Even a stale e-stop *engaged* reading reads unknown, not "released".
    b.send(ESTOP_W, &bool_cdr(1), 2000);
    b.send(MODE_W, &u8_cdr(0), 2000);
    assert_eq!(b.state(2000), S::EStopActive);
    b.send(MODE_W, &u8_cdr(0), 3100);
    assert_eq!(b.state(3100), S::Unknown);
}

#[test]
fn conflicting_sources_take_the_most_conservative() {
    let mut b = Bus::new(full_feed());
    b.send(ESTOP_W, &bool_cdr(0), 0);
    b.send(NAME_W, &str_cdr("PROTECTIVE_STOP"), 0);
    b.send(MODE_W, &u8_cdr(1), 0);
    b.send(ODOM_WRITER, &odom(1.5), 0);
    let t = b.feed.evaluate(0).unwrap();
    assert_eq!(b.feed.state(), S::SafeStateActive);
    assert!(t.conflict, "{t:?}");
    // Odometry says fast, mode says idle: moving_fast.
    b.send(NAME_W, &str_cdr("AUTO"), 1);
    b.send(MODE_W, &u8_cdr(0), 1);
    assert_eq!(b.state(1), S::MovingFast);
    // Human nearby beats moving fast.
    b.send(MODE_W, &u8_cdr(2), 2);
    assert_eq!(b.state(2), S::CollaborativeHumanNearby);
    // A stale source (unknown) beats every moving / idle claim.
    assert_eq!(b.state(5000), S::Unknown);
}

#[test]
fn unprofiled_writers_are_ignored_and_reported() {
    let mut b = Bus::new(full_feed());
    b.send(ESTOP_W, &bool_cdr(1), 0);
    b.send(MODE_W, &u8_cdr(0), 0);
    b.send(NAME_W, &str_cdr("AUTO"), 0);
    b.send(ODOM_WRITER, &odom(0.0), 0);
    assert_eq!(b.state(0), S::EStopActive);

    // A rogue participant announces an /estop writer and "releases" it, and
    // claims the robot idle on /robot_mode.
    let rogue_disc = datagram(
        ROGUE,
        &[
            spdp_sub(ROGUE, &[ROGUE_IP]),
            sedp_writer_sub(ROGUE, ROGUE_ENTITY, "rt/estop", BOOL),
        ],
    );
    assert!(b.raw(ROGUE_IP, rogue_disc, 1).is_empty());
    let f = b.raw(ROGUE_IP, sample(ROGUE, ROGUE_ENTITY, 1, &bool_cdr(0)), 1);
    assert_eq!(f.len(), 1);
    assert_eq!(f[0].deviation.rule_str(), rules::UNTRUSTED_SOURCE);
    assert_eq!(f[0].deviation.severity, Severity::High);
    assert!(
        f[0].deviation.detail.contains("not in the profile"),
        "{f:?}"
    );
    assert_eq!(f[0].src_ip, ROGUE_IP.to_string());
    assert!(f[0].writer.starts_with(ROGUE_HEX));
    assert_eq!(b.state(1), S::EStopActive, "the spoofed release is ignored");
    // Reported once per writer + reason.
    let f = b.raw(ROGUE_IP, sample(ROGUE, ROGUE_ENTITY, 2, &bool_cdr(0)), 2);
    assert!(f.is_empty());

    // The legit writer's GUID, sent from the rogue's IP (binding mismatch).
    let f = b.raw(ROGUE_IP, sample(LEGIT, ESTOP_W, 99, &bool_cdr(0)), 3);
    assert_eq!(f.len(), 1, "{f:?}");
    assert!(f[0].deviation.detail.contains("not bound"), "{f:?}");
    assert_eq!(b.state(3), S::EStopActive);

    // A profiled participant's writer announced with another type.
    let disc = datagram(LEGIT, &[sedp_writer_sub(LEGIT, ESTOP_W2, "rt/estop", U8)]);
    b.raw(ROBOT_IP, disc, 4);
    let f = b.send(ESTOP_W2, &u8_cdr(0), 4);
    assert_eq!(f.len(), 1);
    assert!(
        f[0].deviation.detail.contains("announced with type"),
        "{f:?}"
    );
    assert_eq!(b.feed.stats().untrusted, 4);
    // None of the ignored samples refreshed /estop: once the legit e-stop
    // publisher goes quiet the state is unknown, never released.
    b.send(MODE_W, &u8_cdr(0), 1500);
    b.send(NAME_W, &str_cdr("AUTO"), 1500);
    b.send(ODOM_WRITER, &odom(0.0), 1500);
    b.raw(ROGUE_IP, sample(ROGUE, ROGUE_ENTITY, 3, &bool_cdr(0)), 1500);
    assert_eq!(b.state(1500), S::Unknown);
}

#[test]
fn allowlist_and_unprofiled_topic() {
    // Only the legit e-stop writer's full GUID is allowed on /estop.
    let mut feed = full_feed();
    feed["topics"][0]["writers"] = serde_json::json!([format!("{LEGIT_HEX}00002103")]); // MODE_W, not ESTOP_W
    let mut b = Bus::new(feed);
    let f = b.send(ESTOP_W, &bool_cdr(0), 0);
    assert!(f[0].deviation.detail.contains("allowlist"), "{f:?}");

    // A topic the profile does not list: every writer is untrusted.
    let p = robot_profile(false);
    let sec: SafetyFeedSection = serde_json::from_value(with_writers(serde_json::json!({
        "topics": [{"topic": "/estop", "type": "std_msgs/msg/Bool", "values": estop_values()}]
    })))
    .unwrap();
    let (spec, warnings) = sec.resolve(&p).unwrap();
    assert!(warnings[0].contains("not a writer topic"), "{warnings:?}");
    let mut b = Bus {
        pipeline: Pipeline::new(p, PipelineOptions::default()),
        feed: SafetyFeed::new(spec),
        sn: 0,
    };
    b.raw(ROBOT_IP, discovery(), 0);
    let f = b.send(ESTOP_W, &bool_cdr(1), 0);
    assert!(
        f[0].deviation.detail.contains("does not allow writers"),
        "{f:?}"
    );
    assert_eq!(b.state(0), S::Unknown);
}

#[test]
fn undecodable_trusted_samples_read_unknown() {
    let mut b = Bus::new(full_feed());
    b.send(ESTOP_W, &bool_cdr(0), 0);
    b.send(MODE_W, &u8_cdr(0), 0);
    b.send(NAME_W, &str_cdr("AUTO"), 0);
    b.send(ODOM_WRITER, &odom(0.0), 0);
    assert_eq!(b.state(0), S::Idle);
    for (i, bad) in [
        bool_cdr(2),         // not a boolean
        vec![0, 1, 0, 0],    // truncated
        vec![0, 3, 0, 0, 1], // PL_CDR
        vec![0x7f, 0x7f, 0, 0, 1],
    ]
    .into_iter()
    .enumerate()
    {
        let f = b.send(ESTOP_W, &bad, 1 + i as u64);
        assert_eq!(b.state(1 + i as u64), S::Unknown, "{bad:?}");
        assert!(f.len() <= 1);
        if let Some(f) = f.first() {
            assert_eq!(f.deviation.rule_str(), rules::UNDECODABLE);
            assert_eq!(f.deviation.severity, Severity::Medium);
        }
        b.send(ESTOP_W, &bool_cdr(0), 1 + i as u64);
        assert_eq!(b.state(1 + i as u64), S::Idle);
    }
    assert_eq!(b.feed.stats().undecodable, 4);
    // Hostile datagrams (garbage, truncated RTPS) never panic.
    for n in 0..64 {
        let mut d = sample(LEGIT, ESTOP_W, 50, &bool_cdr(1));
        d.truncate(n);
        b.raw(ROBOT_IP, d, 10);
    }
    b.raw(ROBOT_IP, b"not rtps".to_vec(), 10);
}

// ------------------------------------------------------- through the daemon --

/// Black-box `robodr.response_plan` notes for `rule`: (safety_state,
/// max_step) of each.
fn plans_for(blackbox: &std::path::Path, rule: &str) -> Vec<(String, String)> {
    records(blackbox)
        .iter()
        .filter_map(|r| serde_json::from_slice::<serde_json::Value>(&r.payload).ok())
        .filter(|v| v["kind"] == "robodr.response_plan" && v["plan"]["rule"] == rule)
        .map(|v| {
            (
                v["plan"]["safety_state"].as_str().unwrap_or("").to_string(),
                v["plan"]["max_step"].as_str().unwrap_or("").to_string(),
            )
        })
        .collect()
}

fn transitions(blackbox: &std::path::Path) -> Vec<(String, String)> {
    records(blackbox)
        .iter()
        .filter_map(|r| serde_json::from_slice::<serde_json::Value>(&r.payload).ok())
        .filter(|v| v["kind"] == "robodr.safety_state_transition")
        .map(|v| {
            (
                v["from"].as_str().unwrap().to_string(),
                v["to"].as_str().unwrap().to_string(),
            )
        })
        .collect()
}

/// Replay `frames` through the daemon with the bus feed; the over-envelope
/// command's plan(s).
/// (from, to) or (safety_state, max_step) pairs.
type Pairs = Vec<(String, String)>;
/// The daemon's result and its log.
type DaemonThread = std::thread::JoinHandle<(Result<robodr_agentd::Summary, String>, String)>;

fn replay_with_estop(estop: u8, tag: &str) -> (Pairs, Pairs) {
    let s = setup(tag, &profile(true));
    let unicast = |d: &[u8]| frame(ROBOT_IP, ROBOT_IP, 7411, d);
    let pcap = s.pcap(&[
        frame(ROBOT_IP, SPDP_GROUP, 7400, &discovery()),
        unicast(&sample(LEGIT, ESTOP_W, 1, &bool_cdr(estop))),
        unicast(&sample(LEGIT, ODOM_WRITER, 1, &odom(0.4))),
        // A Critical over-envelope command (profile: /cmd_vel <= 1.0 m/s).
        unicast(&cmd_vel_datagram(LEGIT, CMD_WRITER, 1, 2.5)),
    ]);
    let mut cfg = s.config(
        serde_json::json!({"capture": {"enabled": true, "pcap_replay": pcap}}),
        serde_json::json!([]),
        serde_json::json!({"exit_when_inputs_end": true}),
    );
    cfg["context"] = serde_json::json!({});
    cfg["safety_feed"] = with_writers(serde_json::json!({
        "stale_after_ms": 60000,
        "topics": [
            {"topic": "/estop", "type": "std_msgs/msg/Bool", "values": estop_values()},
            {"topic": "/odom", "type": "nav_msgs/msg/Odometry",
             "motion": {"moving_above": 0.05, "fast_above": 1.0}}
        ]
    }));
    let r = s.resolve(&cfg);
    let mut log = Vec::new();
    let sum = robodr_agentd::run(&r, &|| false, &mut log).unwrap();
    let log = String::from_utf8(log).unwrap();
    assert_eq!(sum.reason, StopReason::InputsEnded, "{log}");
    let found = spooled(&s.spool);
    assert_verified(&s.blackbox, Some(sum.finished.checkpoint.clone()), &found);
    assert!(
        !rules(&found)
            .iter()
            .any(|r| r.starts_with("robot.safety_state.")),
        "{:?}",
        rules(&found)
    );
    let st = status(&s.spool).unwrap();
    assert!(st["safety_feed"]["sources"].is_array(), "{st}");
    (
        plans_for(&s.blackbox, "robot.motion.linear_over_envelope"),
        transitions(&s.blackbox),
    )
}

#[test]
fn estop_on_the_bus_forces_record_only_plans_end_to_end() {
    let (plans, trans) = replay_with_estop(1, "sf-estop");
    assert_eq!(
        plans,
        vec![("estop_active".to_string(), "record".to_string())],
        "{trans:?}"
    );
    assert_eq!(
        trans.first(),
        Some(&("unknown".to_string(), "estop_active".to_string()))
    );

    // Control: the same traffic with the e-stop released is graded as
    // moving and gets the policy's safe-state request.
    let (plans, trans) = replay_with_estop(0, "sf-released");
    assert_eq!(
        plans,
        vec![("moving_slow".to_string(), "request_safe_state".to_string())],
        "{trans:?}"
    );
    assert_eq!(
        trans.first(),
        Some(&("unknown".to_string(), "moving_slow".to_string()))
    );
}

#[test]
fn spoofed_release_on_the_bus_is_reported_and_ignored_end_to_end() {
    let s = setup("sf-spoof", &profile(true));
    let unicast = |src: Ipv4Addr, d: &[u8]| frame(src, ROBOT_IP, 7411, d);
    let pcap = s.pcap(&[
        frame(ROBOT_IP, SPDP_GROUP, 7400, &discovery()),
        unicast(ROBOT_IP, &sample(LEGIT, ESTOP_W, 1, &bool_cdr(1))),
        frame(
            ROGUE_IP,
            SPDP_GROUP,
            7400,
            &datagram(
                ROGUE,
                &[
                    spdp_sub(ROGUE, &[ROGUE_IP]),
                    sedp_writer_sub(ROGUE, ROGUE_ENTITY, "rt/estop", BOOL),
                ],
            ),
        ),
        unicast(ROGUE_IP, &sample(ROGUE, ROGUE_ENTITY, 1, &bool_cdr(0))),
        unicast(ROBOT_IP, &cmd_vel_datagram(LEGIT, CMD_WRITER, 1, 2.5)),
    ]);
    let mut cfg = s.config(
        serde_json::json!({"capture": {"enabled": true, "pcap_replay": pcap}}),
        serde_json::json!([]),
        serde_json::json!({"exit_when_inputs_end": true}),
    );
    cfg["context"] = serde_json::json!({});
    cfg["safety_feed"] = with_writers(serde_json::json!({
        "stale_after_ms": 60000,
        "topics": [{"topic": "/estop", "type": "std_msgs/msg/Bool", "values": estop_values()}]
    }));
    let r = s.resolve(&cfg);
    let mut log = Vec::new();
    let sum = robodr_agentd::run(&r, &|| false, &mut log).unwrap();
    let log = String::from_utf8(log).unwrap();
    let found = spooled(&s.spool);
    let rules = rules(&found);
    assert!(
        rules.iter().any(|r| r == rules::UNTRUSTED_SOURCE),
        "{rules:?}\n{log}"
    );
    let spoof = found
        .iter()
        .find(|(_, e)| e.entity_context.rule_id == rules::UNTRUSTED_SOURCE)
        .unwrap();
    assert_eq!(spoof.1.severity, Severity::High);
    // Graded as e-stop: the spoofed release changed nothing.
    assert_eq!(
        plans_for(&s.blackbox, "robot.motion.linear_over_envelope"),
        vec![("estop_active".to_string(), "record".to_string())]
    );
    // The spoof finding itself is planned under e-stop too: record only.
    assert_eq!(
        plans_for(&s.blackbox, rules::UNTRUSTED_SOURCE),
        vec![("estop_active".to_string(), "record".to_string())]
    );
    assert!(log.contains("safety feed: robot.safety_state.untrusted_source"));
    assert_verified(&s.blackbox, Some(sum.finished.checkpoint), &found);
}

/// Run the daemon on a thread.
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
fn plc_socket_feed_grades_plans_and_goes_stale() {
    let s = setup("sf-socket", &profile(true));
    let events = s.dir.join("ev.sock");
    let safety = s.dir.join("safety.sock");
    let mut cfg = s.config(
        serde_json::json!({}),
        serde_json::json!([{"kind": "unix_socket", "path": events}]),
        serde_json::json!({}),
    );
    cfg["context"] = serde_json::json!({});
    cfg["safety_feed"] = serde_json::json!({
        "socket": {"path": safety, "stale_after_ms": 1000}
    });
    let (stop, h) = spawn(s.resolve(&cfg));
    let mut plc = wait_for(5, "safety socket", || UnixStream::connect(&safety).ok());
    let mode = std::fs::metadata(&safety)
        .map(|m| std::os::unix::fs::PermissionsExt::mode(&m.permissions()) & 0o777);
    assert_eq!(mode.ok(), Some(0o600));
    let mut ev = wait_for(5, "event socket", || UnixStream::connect(&events).ok());
    // Garbage on the safety socket is counted, never applied.
    plc.write_all(b"{\"state\":\"released\"}\nnot json\n{\"state\":\"estop_active\"}\n")
        .unwrap();
    plc.flush().unwrap();
    wait_for(5, "estop applied", || {
        let st = status(&s.spool)?;
        (st["safety_state"] == "estop_active").then_some(())
    });
    let cmd = r#"{"kind":"motion_command","channel":"/cmd_vel","linear_speed":2.5}"#;
    writeln!(ev, "{cmd}").unwrap();
    ev.flush().unwrap();
    wait_for(5, "first command", || {
        let st = status(&s.spool)?;
        (st["daemon"]["events"].as_u64()? >= 1).then_some(())
    });
    // The gateway stops sending: unknown after 1 s.
    wait_for(5, "stale", || {
        let st = status(&s.spool)?;
        (st["safety_state"] == "unknown").then_some(())
    });
    writeln!(ev, "{cmd}").unwrap();
    ev.flush().unwrap();
    wait_for(5, "second command", || {
        let st = status(&s.spool)?;
        (st["daemon"]["events"].as_u64()? >= 2).then_some(())
    });
    // Back to moving.
    writeln!(plc, "{{\"state\":\"moving_slow\"}}").unwrap();
    plc.flush().unwrap();
    wait_for(5, "moving", || {
        let st = status(&s.spool)?;
        (st["safety_state"] == "moving_slow").then_some(())
    });
    stop.store(true, Ordering::SeqCst);
    let (res, log) = h.join().unwrap();
    let sum = res.unwrap_or_else(|e| panic!("{e}\n{log}"));
    let found = spooled(&s.spool);
    assert_verified(&s.blackbox, Some(sum.finished.checkpoint), &found);
    let plans = plans_for(&s.blackbox, "robot.motion.linear_over_envelope");
    assert_eq!(plans.len(), 2, "{plans:?}\n{log}");
    assert_eq!(plans[0], ("estop_active".to_string(), "record".to_string()));
    // Unknown: the policy's unknown row (safe-state request), which the
    // planner gates on a human's approval.
    assert_eq!(
        plans[1],
        ("unknown".to_string(), "request_safe_state".to_string())
    );
    let approvals: Vec<bool> = records(&s.blackbox)
        .iter()
        .filter_map(|r| serde_json::from_slice::<serde_json::Value>(&r.payload).ok())
        .filter(|v| v["kind"] == "robodr.response_plan")
        .filter(|v| v["plan"]["rule"] == "robot.motion.linear_over_envelope")
        .map(|v| v["plan"]["requires_human_approval"].as_bool().unwrap())
        .collect();
    assert_eq!(approvals, vec![false, true]);
    let t = transitions(&s.blackbox);
    let want = [
        ("unknown", "estop_active"),
        ("estop_active", "unknown"),
        ("unknown", "moving_slow"),
    ];
    for (a, b) in want {
        assert!(
            t.contains(&(a.to_string(), b.to_string())),
            "{a} -> {b} missing from {t:?}"
        );
    }
    let st = status(&s.spool).unwrap();
    let malformed = st["inputs"]
        .as_array()
        .unwrap()
        .iter()
        .find(|i| i["name"].as_str().unwrap().starts_with("safety:"))
        .unwrap()["malformed"]
        .as_u64()
        .unwrap();
    assert_eq!(malformed, 2);
    assert!(!safety.exists(), "socket removed at shutdown");
}

#[test]
fn feed_configuration_errors() {
    let s = setup("sf-cfg", &profile(true));
    let sock = s.dir.join("ev.sock");
    let mut cfg = s.config(
        serde_json::json!({}),
        serde_json::json!([{"kind": "unix_socket", "path": sock}]),
        serde_json::json!({}),
    );
    // The common config sets a static moving_slow: refused with a feed.
    cfg["safety_feed"] = serde_json::json!({"socket": {"path": s.dir.join("safety.sock")}});
    let e = robodr_agentd::load(&s.write_config(&cfg)).unwrap_err();
    assert!(e.contains("context.safety_state"), "{e}");
    cfg["context"] = serde_json::json!({"safety_state": "unknown"});
    let r = robodr_agentd::load(&s.write_config(&cfg)).unwrap();
    assert!(r.safety_feed.unwrap().socket.is_some());
    // The same path as an event socket.
    cfg["safety_feed"] = serde_json::json!({"socket": {"path": sock}});
    let e = robodr_agentd::load(&s.write_config(&cfg)).unwrap_err();
    assert!(e.contains("event_inputs"), "{e}");
    // Unknown keys and bad mappings are refused.
    cfg["safety_feed"] = serde_json::json!({"sockets": {}});
    assert!(robodr_agentd::load(&s.write_config(&cfg)).is_err());
    cfg["safety_feed"] = serde_json::json!({"topics": [
        {"topic": "/estop", "type": "std_msgs/msg/Bool", "values": {"true": "estop_active"}}]});
    let e = robodr_agentd::load(&s.write_config(&cfg)).unwrap_err();
    assert!(e.contains("\"true\" and \"false\""), "{e}");
    // Topics without capture: a warning (the sources stay unknown).
    cfg["safety_feed"] = serde_json::json!({"topics": [
        {"topic": "/estop", "type": "std_msgs/msg/Bool", "values": estop_values()}]});
    let e = robodr_agentd::load(&s.write_config(&cfg)).unwrap_err();
    assert!(e.contains("writers"), "{e}");
    cfg["safety_feed"] = with_writers(cfg["safety_feed"].clone());
    let r = robodr_agentd::load(&s.write_config(&cfg)).unwrap();
    assert!(
        r.warnings
            .iter()
            .any(|w| w.contains("sensor.capture is off")),
        "{:?}",
        r.warnings
    );
}
