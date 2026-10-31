//! Harness: the live safety-state feed of `robodr-agentd`
//! (`robodr_agentd::safety`): the `safety_feed` configuration section, the
//! safety-socket line parser (`input::parse_safety_line`, JSON from a
//! safety-PLC gateway) and the bus path (`SafetyFeed::observe_datagram`:
//! RTPS -> SEDP writer table -> `std_msgs` / `nav_msgs/Odometry` CDR ->
//! claims), combined by `evaluate`.
//!
//! Input: `config JSON \0 records`. When the JSON is not a `safety_feed`
//! section that resolves against the harness profile, a built-in section
//! (Bool `/estop`, UInt8 `/robot_mode`, String `/mode_name`, Odometry
//! `/odom`, Unitree `/sportmodestate`, `/lowstate` and
//! `/wirelesscontroller`, a Nav2 lifecycle `/bt_navigator/transition_event`,
//! all written by the profile's participant, plus a socket) is
//! used, so mutations of the records still reach the feed. Records are
//! `tag(1) len(u16 LE) bytes(len)`:
//!
//! * `tag % 4 == 0`: one safety-socket line from connection `tag / 4 % 4`;
//! * `tag % 4 == 1`: an RTPS datagram from the robot's IP (192.168.50.10);
//! * `tag % 4 == 2`: an RTPS datagram from another IP (192.168.50.66);
//! * `tag % 4 == 3`: the clock advances by `len` ms (no bytes follow).
//!
//! Datagrams go through the sensor pipeline first (as in the daemon), so
//! SPDP builds the binding table the feed trusts writers by.
//!
//! Invariants beyond "no panic", checked after every record:
//!
//! * never less conservative than the socket: after `evaluate(now)`, the
//!   state is at least as conservative as every connection's latest socket
//!   report that is still fresh (`now - at <= stale_after_ms`);
//! * a transition goes from the previous state to the new one, and the
//!   state is unchanged when `evaluate` reports none;
//! * `status` is total and the counters never decrease;
//! * the live operational context (`evaluate_context`) is total, reports a
//!   transition exactly when it changed, and never names `autonomous`
//!   control while a remote source is configured and has no fresh trusted
//!   reading (its `on_stale` is `manual`).
//!
//! Shared via `#[path]` with `crates/robodr-agentd/tests/fuzz_smoke.rs`.
#![allow(dead_code)]

use std::collections::BTreeMap;

use robodr_agentd::input::{parse_safety_line, Payload};
use robodr_agentd::safety::{conservativeness, Claim, FeedStats, SafetyFeed, SafetyFeedSection};
use robodr_agentd::safety_feed::context::LiveContext;
use robodr_events::profile::{Envelope, Profile};
use robodr_responder::{Connectivity, ControlMode, MissionPhase};
use robodr_ros2_pipeline::{Datagram, Pipeline, PipelineOptions};

/// The commissioned participant (GUID prefix `aa` x 12).
pub const LEGIT_HEX: &str = "aaaaaaaaaaaaaaaaaaaaaaaa";
pub const ROBOT_IP: &str = "192.168.50.10";
pub const OTHER_IP: &str = "192.168.50.66";
const MAX_RECORDS: usize = 512;

/// The profile every run uses: the legit participant, motion topics and
/// the safety topics as writer topics.
pub fn profile() -> Profile {
    let mut p = Profile {
        model: "ugv-lab".into(),
        locked: false,
        ..Default::default()
    };
    p.participants.insert(LEGIT_HEX.into());
    for t in [
        "/cmd_vel",
        "/odom",
        "/estop",
        "/robot_mode",
        "/mode_name",
        "/sportmodestate",
        "/lowstate",
        "/wirelesscontroller",
        "/bt_navigator/transition_event",
    ] {
        p.writer_topics.insert(t.into());
    }
    p.motion_envelopes.insert(
        "/cmd_vel".into(),
        Envelope {
            max_linear_speed: Some(1.0),
            max_joint_speed: None,
            ..Default::default()
        },
    );
    p
}

/// The section used when the input's JSON is not usable.
pub fn default_section() -> serde_json::Value {
    serde_json::json!({
        "stale_after_ms": 500,
        "topics": [
            {"topic": "/estop", "type": "std_msgs/msg/Bool",
             "values": {"true": "estop_active", "false": "none"}, "writers": [LEGIT_HEX]},
            {"topic": "/robot_mode", "type": "std_msgs/msg/UInt8",
             "values": {"0": "idle", "1": "moving_slow", "2": "collaborative_human_nearby",
                        "7": "safe_state_active"}, "writers": [LEGIT_HEX]},
            {"topic": "/mode_name", "type": "std_msgs/msg/String",
             "values": {"AUTO": "none", "PROTECTIVE_STOP": "safe_state_active"},
             "writers": [LEGIT_HEX]},
            {"topic": "/odom", "type": "nav_msgs/msg/Odometry",
             "motion": {"moving_above": 0.05, "fast_above": 1.0, "hysteresis": 0.02},
             "writers": [LEGIT_HEX]},
            {"topic": "/sportmodestate", "type": "unitree_go::msg::dds_::SportModeState_",
             "writers": [LEGIT_HEX],
             "unitree_sport": {"modes": {"1": "none", "3": "none", "7": "safe_state_active"},
                               "motion": {"moving_above": 0.05, "fast_above": 1.0},
                               "phase": {"1": "parked", "3": "transit"}}},
            {"topic": "/lowstate", "type": "unitree_go::msg::dds_::LowState_",
             "writers": [LEGIT_HEX], "unitree_low": {"moving_above": 0.5}},
            {"topic": "/wirelesscontroller", "type": "unitree_go::msg::dds_::WirelessController_",
             "writers": [LEGIT_HEX], "wireless_controller": {"hold_ms": 100}},
            {"topic": "/bt_navigator/transition_event",
             "type": "lifecycle_msgs/msg/TransitionEvent", "writers": [LEGIT_HEX],
             "lifecycle": {"states": {"active": {"control": "autonomous", "phase": "transit"},
                                      "inactive": {"control": "autonomous", "phase": "parked"}}}}
        ],
        "socket": {"path": "/run/robodr/safety.sock", "max_connections": 4}
    })
}

/// Build the input format (seed generation, tests).
pub fn join(config: &[u8], records: &[(u8, &[u8])]) -> Vec<u8> {
    let mut v = config.to_vec();
    v.push(0);
    for (tag, b) in records {
        v.push(*tag);
        let len = u16::try_from(b.len()).expect("record fits u16");
        v.extend_from_slice(&len.to_le_bytes());
        if tag % 4 != 3 {
            v.extend_from_slice(b);
        }
    }
    v
}

/// A clock record advancing by `ms`.
pub fn tick(ms: u16) -> (u8, Vec<u8>) {
    (3, vec![0; usize::from(ms)])
}

pub fn run(data: &[u8]) {
    let _ = run_counting(data);
}

/// [`run`], returning `(custom config accepted, final counters, findings)`
/// (seed checks).
pub fn run_counting(data: &[u8]) -> (bool, FeedStats, usize) {
    let (cfg, mut rest) = match data.iter().position(|&b| b == 0) {
        Some(i) => (&data[..i], &data[i + 1..]),
        None => (data, &[][..]),
    };
    let profile = profile();
    let custom = serde_json::from_slice::<SafetyFeedSection>(cfg)
        .ok()
        .and_then(|s| s.resolve(&profile).ok());
    let accepted = custom.is_some();
    let spec = match custom {
        Some((spec, _)) => spec,
        None => {
            let s: SafetyFeedSection =
                serde_json::from_value(default_section()).expect("default section parses");
            s.resolve(&profile).expect("default section resolves").0
        }
    };
    let socket_stale = spec.socket.as_ref().map(|s| s.stale_after_ms);
    let mut feed = SafetyFeed::new(spec);
    let mut pipeline = Pipeline::new(profile.clone(), PipelineOptions::default());
    let mut now: u64 = 0;
    // conn -> (latest reported state's conservativeness, at)
    let mut latest: BTreeMap<u64, (u8, u64)> = BTreeMap::new();
    let mut findings = 0usize;
    let mut last_stats = feed.stats();
    let mut n = 0;
    while rest.len() >= 3 && n < MAX_RECORDS {
        n += 1;
        let tag = rest[0];
        let len = usize::from(u16::from_le_bytes([rest[1], rest[2]]));
        rest = &rest[3..];
        if tag % 4 == 3 {
            now = now.saturating_add(len as u64);
        } else {
            let take = len.min(rest.len());
            let bytes = &rest[..take];
            rest = &rest[take..];
            match tag % 4 {
                0 => {
                    let conn = u64::from(tag / 4 % 4);
                    let line = String::from_utf8_lossy(bytes);
                    let t = line.trim();
                    if !t.is_empty() {
                        if let Ok(Payload::Safety(r)) = parse_safety_line(t) {
                            findings += feed.observe_report_from(conn, r, now).len();
                            latest.insert(conn, (conservativeness(r.state), now));
                        }
                    }
                }
                k => {
                    let ip = if k == 1 { ROBOT_IP } else { OTHER_IP };
                    let d = Datagram::new(bytes.to_vec(), ip);
                    let _ = pipeline.process_datagram_with_motion(&d, now);
                    findings += feed
                        .observe_datagram(&d, pipeline.profile(), pipeline.binding(), now)
                        .len();
                }
            }
        }

        let before = feed.state();
        match feed.evaluate(now) {
            Some(t) => {
                assert_eq!(t.from, Claim::State(before));
                assert_eq!(t.to, Claim::State(feed.state()));
                assert_ne!(t.from, t.to);
                assert_eq!(t.at_ms, now);
            }
            None => assert_eq!(feed.state(), before),
        }
        if let Some(stale) = socket_stale {
            let got = conservativeness(feed.state());
            for (conn, (c, at)) in &latest {
                if now.saturating_sub(*at) <= stale {
                    assert!(
                        got >= *c,
                        "state {:?} is less conservative than connection {conn}'s fresh report",
                        feed.state()
                    );
                }
            }
        }
        let fallback = LiveContext {
            control: ControlMode::Autonomous,
            phase: MissionPhase::Task,
            connectivity: Connectivity::Connected,
        };
        let prev_ctx = feed.live_context().unwrap_or(fallback);
        if let Some((ctx, t)) = feed.evaluate_context(now, now, fallback) {
            assert_eq!(feed.live_context(), Some(ctx));
            match t {
                Some(t) => {
                    assert_eq!((t.from, t.to), (prev_ctx, ctx));
                    assert_ne!(t.from, t.to);
                }
                None => assert_eq!(ctx, prev_ctx),
            }
            let st = feed.status(now);
            let view = st.context.expect("context status with context sources");
            let remote_silent = view
                .sources
                .iter()
                .any(|s| s.name == "/wirelesscontroller" && !s.fresh);
            if remote_silent {
                assert_ne!(ctx.control, ControlMode::Autonomous);
            }
        }
        let _ = feed.status(now);
        let st = feed.stats();
        assert!(st.socket_reports >= last_stats.socket_reports);
        assert!(st.applied >= last_stats.applied);
        assert!(st.transitions >= last_stats.transitions);
        last_stats = st;
    }
    (accepted, feed.stats(), findings)
}
