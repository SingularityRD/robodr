//! Native Unitree safety-state sources (T17: `SportModeState_`,
//! `LowState_`) and the live operational context (T46: Unitree remote and
//! sport mode, ROS 2 lifecycle, uplink status), through the passive feed
//! and end to end through the daemon.
//!
//! Bus traffic is hand-built RTPS + CDR from Unitree's IDL and the
//! `lifecycle_msgs` definitions; no real robot, Nav2 or uplink was involved.

mod common;

#[path = "../../robodr-cdr/tests/common/mod.rs"]
mod cdrenc;

use std::net::Ipv4Addr;

use cdrenc::Enc;
use common::pcap::*;
use common::*;
use robodr_agentd::safety::{rules, FeedFinding, SafetyFeed, SafetyFeedSection};
use robodr_agentd::safety_feed::context::LiveContext;
use robodr_agentd::StopReason;
use robodr_cdr::unitree::{decode_unitree, UnitreeKind, UnitreeMessage};
use robodr_cdr::{Limits, Representation};
use robodr_events::profile::Profile;
use robodr_events::Severity;
use robodr_responder::{Connectivity as N, ControlMode as C, MissionPhase as P, SafetyState as S};
use robodr_ros2_pipeline::{Datagram, Pipeline, PipelineOptions};

const SPORT_W: [u8; 4] = [0, 0, 0x30, 0x03];
const LOW_W: [u8; 4] = [0, 0, 0x31, 0x03];
const HG_W: [u8; 4] = [0, 0, 0x32, 0x03];
const REMOTE_W: [u8; 4] = [0, 0, 0x33, 0x03];
const LIFE_W: [u8; 4] = [0, 0, 0x34, 0x03];
const SPORT: &str = "unitree_go::msg::dds_::SportModeState_";
const GO_LOW: &str = "unitree_go::msg::dds_::LowState_";
const HG_LOW: &str = "unitree_hg::msg::dds_::LowState_";
const REMOTE: &str = "unitree_go::msg::dds_::WirelessController_";
const LIFE: &str = "lifecycle_msgs::msg::dds_::TransitionEvent_";
const REP: Representation = Representation::CdrLe;

// ---------------------------------------------------------------- payloads --

fn imu(e: &mut Enc) {
    for _ in 0..13 {
        e.f32(0.0); // quaternion[4], gyroscope[3], accelerometer[3], rpy[3]
    }
    e.byte(0); // temperature
}

/// `SportModeState_` (the `.msg` layout, without the IDL's path points).
fn sport(mode: u8, error_code: u32, vx: f32, yaw: f32) -> Vec<u8> {
    let mut e = Enc::new(REP);
    e.structure(|e| {
        e.structure(|e| {
            e.i32(1);
            e.u32(2);
        });
        e.u32(error_code);
        imu(e);
        e.byte(mode);
        e.f32(0.0); // progress
        e.byte(0); // gait_type
        e.f32(0.0); // foot_raise_height
        for _ in 0..3 {
            e.f32(0.0); // position
        }
        e.f32(0.3); // body_height
        e.f32(vx);
        e.f32(0.0);
        e.f32(0.0);
        e.f32(yaw);
        for _ in 0..4 {
            e.f32(0.0); // range_obstacle
        }
        for _ in 0..4 {
            e.i16(0); // foot_force
        }
        for _ in 0..24 {
            e.f32(0.0); // foot_position_body, foot_speed_body
        }
    });
    e.finish()
}

fn go_low_raw(dq: f32, crc: u32) -> Vec<u8> {
    let mut e = Enc::new(REP);
    e.structure(|e| {
        e.bytes(&[0xfe, 0xef, 0xff, 0]); // head, level_flag, frame_reserve
        for _ in 0..4 {
            e.u32(0); // sn, version
        }
        e.u16(0); // bandwidth
        imu(e);
        e.nonprim_seq(|e| {
            for _ in 0..20 {
                e.byte(0); // mode
                e.f32(0.0); // q
                e.f32(dq);
                for _ in 0..5 {
                    e.f32(0.0); // ddq, tau_est, q_raw, dq_raw, ddq_raw
                }
                e.byte(0); // temperature
                for _ in 0..3 {
                    e.u32(0); // lost, reserve[2]
                }
            }
        });
        e.bytes(&[0, 0, 0, 0]); // bms version / status / soc
        e.i32(0); // current
        e.u16(0); // cycle
        e.bytes(&[0; 4]); // ntc
        for _ in 0..15 {
            e.u16(0); // cell_vol
        }
        for _ in 0..8 {
            e.i16(0); // foot_force, foot_force_est
        }
        e.u32(0); // tick
        e.bytes(&[0; 40]); // wireless_remote
        e.byte(0); // bit_flag
        e.f32(0.0); // adc_reel
        e.bytes(&[0, 0]); // ntc1, ntc2
        e.f32(24.0); // power_v
        e.f32(1.0); // power_a
        for _ in 0..4 {
            e.u16(0); // fan_frequency
        }
        e.u32(0); // reserve
        e.u32(crc);
    });
    e.finish()
}

fn hg_low_raw(dq: f32, crc: u32) -> Vec<u8> {
    let mut e = Enc::new(REP);
    e.structure(|e| {
        e.u32(0);
        e.u32(0); // version
        e.byte(0); // mode_pr
        e.byte(5); // mode_machine
        e.u32(0); // tick
        for _ in 0..13 {
            e.f32(0.0);
        }
        e.i16(0); // imu temperature
        e.nonprim_seq(|e| {
            for _ in 0..35 {
                e.byte(0);
                e.f32(0.0);
                e.f32(dq);
                e.f32(0.0);
                e.f32(0.0);
                e.i16(0);
                e.i16(0);
                e.f32(0.0); // vol
                for _ in 0..7 {
                    e.u32(0); // sensor[2], motorstate, reserve[4]
                }
            }
        });
        e.bytes(&[0; 40]);
        for _ in 0..4 {
            e.u32(0);
        }
        e.u32(crc);
    });
    e.finish()
}

/// A low state with the Unitree CRC the SDK computes (`ok`) or a wrong one.
fn low(kind: UnitreeKind, dq: f32, ok: bool) -> Vec<u8> {
    let raw = |crc| match kind {
        UnitreeKind::GoLowState => go_low_raw(dq, crc),
        _ => hg_low_raw(dq, crc),
    };
    let zero = raw(0);
    let d = decode_unitree(kind, &zero, &Limits::default()).unwrap();
    let crc = match d.message {
        UnitreeMessage::GoLowState(s) => s.computed_crc(),
        UnitreeMessage::HgLowState(s) => s.computed_crc(),
        _ => unreachable!(),
    };
    raw(if ok { crc } else { crc ^ 1 })
}

fn remote(lx: f32, keys: u16) -> Vec<u8> {
    let mut e = Enc::new(REP);
    e.structure(|e| {
        e.f32(lx);
        e.f32(0.0);
        e.f32(0.0);
        e.f32(0.0);
        e.u16(keys);
    });
    e.finish()
}

/// `TransitionEvent` into `goal` (a `lifecycle_msgs/State` id).
fn transition(goal: u8) -> Vec<u8> {
    let mut e = Enc::new(REP);
    e.structure(|e| {
        e.i64(1);
        for (id, l) in [(3u8, &b"activate"[..]), (13, b"activating"), (goal, b"x")] {
            e.structure(|e| {
                e.byte(id);
                e.string(l);
            });
        }
    });
    e.finish()
}

// ------------------------------------------------------------------- bus --

fn profile(locked: bool) -> Profile {
    let mut p = robot_profile(locked);
    for t in [
        "/sportmodestate",
        "/lowstate",
        "/lf/lowstate",
        "/wirelesscontroller",
        "/bt_navigator/transition_event",
    ] {
        p.writer_topics.insert(t.into());
    }
    p
}

fn discovery_of(prefix: [u8; 12], ip: Ipv4Addr) -> Vec<u8> {
    datagram(
        prefix,
        &[
            spdp_sub(prefix, &[ip]),
            sedp_writer_sub(prefix, CMD_WRITER, "rt/cmd_vel", TWIST),
            sedp_writer_sub(prefix, SPORT_W, "rt/sportmodestate", SPORT),
            sedp_writer_sub(prefix, LOW_W, "rt/lowstate", GO_LOW),
            sedp_writer_sub(prefix, HG_W, "rt/lf/lowstate", HG_LOW),
            sedp_writer_sub(prefix, REMOTE_W, "rt/wirelesscontroller", REMOTE),
            sedp_writer_sub(prefix, LIFE_W, "rt/bt_navigator/transition_event", LIFE),
        ],
    )
}

fn sample(prefix: [u8; 12], writer: [u8; 4], sn: u32, payload: &[u8]) -> Vec<u8> {
    datagram(prefix, &[user_data(writer, [0; 4], sn, payload, true)])
}

fn sport_source() -> serde_json::Value {
    serde_json::json!({
        "topic": "/sportmodestate", "type": SPORT, "writers": [LEGIT_HEX],
        "unitree_sport": {
            "modes": {"1": "none", "3": "none", "5": "none", "7": "safe_state_active",
                      "8": "moving_slow"},
            "motion": {"moving_above": 0.05, "fast_above": 1.0, "hysteresis": 0.02}
        }
    })
}

fn low_sources() -> Vec<serde_json::Value> {
    vec![
        serde_json::json!({
            "topic": "/lowstate", "type": GO_LOW, "writers": [LEGIT_HEX],
            "unitree_low": {"moving_above": 0.5, "fast_above": 5.0}
        }),
        serde_json::json!({
            "topic": "/lf/lowstate", "type": "unitree_hg/msg/LowState", "writers": [LEGIT_HEX],
            "unitree_low": {"moving_above": 0.5}
        }),
    ]
}

/// Sport source with phase mapping, the remote and Nav2's lifecycle.
fn context_feed() -> serde_json::Value {
    let mut sport = sport_source();
    sport["unitree_sport"]["phase"] = serde_json::json!({"1": "parked", "3": "transit", "5": "parked", "7": "parked",
                           "8": "parked"});
    serde_json::json!({
        "stale_after_ms": 1000,
        "topics": [
            sport,
            {"topic": "/wirelesscontroller", "type": REMOTE, "writers": [LEGIT_HEX],
             "wireless_controller": {"deadzone": 0.1, "hold_ms": 500}},
            {"topic": "/bt_navigator/transition_event", "type": LIFE, "writers": [LEGIT_HEX],
             "lifecycle": {"states": {
                 "active": {"control": "autonomous", "phase": "transit"},
                 "inactive": {"control": "autonomous", "phase": "parked"},
                 "activating": {"control": "autonomous", "phase": "parked"},
                 "deactivating": {"control": "autonomous", "phase": "parked"}}}}
        ]
    })
}

struct Bus {
    pipeline: Pipeline,
    feed: SafetyFeed,
    sn: u32,
}

impl Bus {
    fn new(feed: serde_json::Value) -> Self {
        Self::with_options(feed, PipelineOptions::default())
    }

    fn with_options(feed: serde_json::Value, opts: PipelineOptions) -> Self {
        let p = profile(false);
        let sec: SafetyFeedSection = serde_json::from_value(feed).unwrap();
        let (spec, w) = sec.resolve(&p).unwrap();
        assert!(w.is_empty(), "{w:?}");
        let mut b = Bus {
            pipeline: Pipeline::new(p, opts),
            feed: SafetyFeed::new(spec),
            sn: 0,
        };
        assert!(b.raw(ROBOT_IP, discovery_of(LEGIT, ROBOT_IP), 0).is_empty());
        b
    }

    fn raw(&mut self, ip: Ipv4Addr, payload: Vec<u8>, now: u64) -> Vec<FeedFinding> {
        let d = Datagram::new(payload, ip.to_string());
        self.pipeline.process_datagram_with_motion(&d, 0);
        self.feed
            .observe_datagram(&d, self.pipeline.profile(), self.pipeline.binding(), now)
    }

    fn send(&mut self, writer: [u8; 4], payload: &[u8], now: u64) -> Vec<FeedFinding> {
        self.sn += 1;
        let d = sample(LEGIT, writer, self.sn, payload);
        self.raw(ROBOT_IP, d, now)
    }

    fn state(&mut self, now: u64) -> S {
        self.feed.evaluate(now);
        self.feed.state()
    }

    fn ctx(&mut self, now: u64) -> LiveContext {
        self.feed.evaluate_context(now, 0, configured()).unwrap().0
    }
}

/// The configured context the live one replaces.
fn configured() -> LiveContext {
    LiveContext {
        control: C::Autonomous,
        phase: P::Task,
        connectivity: N::Connected,
    }
}

fn rule_ids(f: &[FeedFinding]) -> Vec<&str> {
    f.iter().map(|x| x.deviation.rule_str()).collect()
}

// ---------------------------------------------------------- T17: sport --

#[test]
fn sport_mode_and_body_speed_map_to_the_safety_state() {
    let mut b = Bus::new(serde_json::json!({"topics": [sport_source()]}));
    assert_eq!(b.state(0), S::Unknown, "nothing heard yet");
    b.send(SPORT_W, &sport(1, 0, 0.0, 0.0), 1);
    assert_eq!(b.state(1), S::Idle, "balance stand, still");
    b.send(SPORT_W, &sport(3, 0, 0.5, 0.0), 2);
    assert_eq!(b.state(2), S::MovingSlow, "walking");
    b.send(SPORT_W, &sport(3, 0, 1.5, 0.0), 3);
    assert_eq!(b.state(3), S::MovingFast);
    b.send(SPORT_W, &sport(3, 0, 0.0, 0.5), 4);
    assert_eq!(b.state(4), S::MovingSlow, "turning on the spot");
    b.send(SPORT_W, &sport(1, 0, 0.0, 0.0), 5);
    assert_eq!(b.state(5), S::Idle);
    // The mapping wins over a still body: damping is the platform's safe
    // state, recovery stand is motion.
    b.send(SPORT_W, &sport(7, 0, 0.0, 0.0), 6);
    assert_eq!(b.state(6), S::SafeStateActive);
    b.send(SPORT_W, &sport(8, 0, 0.0, 0.0), 7);
    assert_eq!(b.state(7), S::MovingSlow);
    // A fault reads unknown (error_code_nonzero default), never idle.
    b.send(SPORT_W, &sport(1, 0, 0.0, 0.0), 8);
    assert_eq!(b.state(8), S::Idle);
    b.send(SPORT_W, &sport(1, 3, 0.0, 0.0), 9);
    assert_eq!(b.state(9), S::Unknown);
    // A non-finite speed says nothing trustworthy.
    b.send(SPORT_W, &sport(1, 0, 0.0, 0.0), 10);
    b.send(SPORT_W, &sport(1, 0, f32::NAN, 0.0), 11);
    assert_eq!(b.state(11), S::Unknown);
    // A mode the mapping does not list: unknown, Low finding (once).
    let f = b.send(SPORT_W, &sport(42, 0, 0.0, 0.0), 12);
    assert_eq!(rule_ids(&f), vec![rules::UNMAPPED_VALUE]);
    assert_eq!(b.state(12), S::Unknown);
    // A silent publisher: unknown.
    b.send(SPORT_W, &sport(1, 0, 0.0, 0.0), 13);
    assert_eq!(b.state(13), S::Idle);
    assert_eq!(b.state(13 + 1001), S::Unknown);
    assert_eq!(b.feed.stats().untrusted, 0);
}

#[test]
fn sport_mode_from_an_unpinned_writer_is_ignored() {
    let mut b = Bus::new(serde_json::json!({"topics": [sport_source()]}));
    // A rogue participant announces the same topic and type and claims the
    // robot is idle.
    b.raw(ROGUE_IP, discovery_of(ROGUE, ROGUE_IP), 1);
    let f = b.raw(
        ROGUE_IP,
        sample(ROGUE, SPORT_W, 1, &sport(1, 0, 0.0, 0.0)),
        2,
    );
    assert_eq!(rule_ids(&f), vec![rules::UNTRUSTED_SOURCE]);
    assert_eq!(f[0].deviation.severity, Severity::High);
    assert_eq!(b.state(2), S::Unknown);
    // The legit writer's GUID from the rogue's IP: not bound, ignored.
    let f = b.raw(
        ROGUE_IP,
        sample(LEGIT, SPORT_W, 9, &sport(1, 0, 0.0, 0.0)),
        3,
    );
    assert_eq!(rule_ids(&f), vec![rules::UNTRUSTED_SOURCE]);
    assert_eq!(b.state(3), S::Unknown);
    // The commissioned writer from its own IP is taken.
    b.send(SPORT_W, &sport(1, 0, 0.0, 0.0), 4);
    assert_eq!(b.state(4), S::Idle);
    // A spoofed "idle" never hides the legit "moving".
    b.send(SPORT_W, &sport(3, 0, 0.6, 0.0), 5);
    b.raw(
        ROGUE_IP,
        sample(ROGUE, SPORT_W, 2, &sport(1, 0, 0.0, 0.0)),
        5,
    );
    assert_eq!(b.state(5), S::MovingSlow);
}

// ------------------------------------------------------------ T17: low --

#[test]
fn low_state_joint_speed_with_crc_check() {
    let mut topics = low_sources();
    topics.push(sport_source());
    let mut b = Bus::new(serde_json::json!({"topics": topics, "stale_after_ms": 60000}));
    b.send(SPORT_W, &sport(1, 0, 0.0, 0.0), 1);
    b.send(LOW_W, &low(UnitreeKind::GoLowState, 0.0, true), 1);
    b.send(HG_W, &low(UnitreeKind::HgLowState, 0.1, true), 1);
    assert_eq!(b.state(1), S::Idle);
    // A joint moving while the body stands still (e.g. an arm or a leg).
    b.send(LOW_W, &low(UnitreeKind::GoLowState, 2.0, true), 2);
    assert_eq!(b.state(2), S::MovingSlow);
    b.send(LOW_W, &low(UnitreeKind::GoLowState, -6.0, true), 3);
    assert_eq!(b.state(3), S::MovingFast, "|dq|, not dq");
    b.send(LOW_W, &low(UnitreeKind::GoLowState, 0.0, true), 4);
    b.send(HG_W, &low(UnitreeKind::HgLowState, 9.0, true), 4);
    assert_eq!(b.state(4), S::MovingSlow, "hg: no fast threshold");
    b.send(HG_W, &low(UnitreeKind::HgLowState, 0.0, true), 5);
    assert_eq!(b.state(5), S::Idle);
    // A wrong CRC is a corrupted sample (the CRC is unkeyed: it says
    // nothing about forgery): undecodable, unknown.
    let f = b.send(LOW_W, &low(UnitreeKind::GoLowState, 0.0, false), 6);
    assert_eq!(rule_ids(&f), vec![rules::UNDECODABLE]);
    assert_eq!(f[0].deviation.severity, Severity::Medium);
    assert!(
        f[0].deviation.detail.contains("CRC"),
        "{}",
        f[0].deviation.detail
    );
    assert_eq!(b.state(6), S::Unknown);
    b.send(LOW_W, &low(UnitreeKind::GoLowState, 0.0, true), 7);
    assert_eq!(b.state(7), S::Idle);
    let f = b.send(HG_W, &low(UnitreeKind::HgLowState, 0.0, false), 8);
    assert_eq!(rule_ids(&f), vec![rules::UNDECODABLE]);
    assert_eq!(b.state(8), S::Unknown);
    b.send(HG_W, &low(UnitreeKind::HgLowState, 0.0, true), 9);
    // Non-finite joint speed: unknown.
    b.send(
        LOW_W,
        &low(UnitreeKind::GoLowState, f32::INFINITY, true),
        10,
    );
    assert_eq!(b.state(10), S::Unknown);
    // Truncated samples: undecodable, never a panic.
    let full = low(UnitreeKind::GoLowState, 0.0, true);
    for n in (0..full.len()).step_by(37) {
        b.send(LOW_W, &full[..n], 11);
    }
    assert_eq!(b.state(11), S::Unknown);
}

#[test]
fn unitree_and_context_configuration_errors() {
    let p = profile(false);
    let resolve = |v: serde_json::Value| -> Result<(), String> {
        let sec: SafetyFeedSection = serde_json::from_value(v).map_err(|e| e.to_string())?;
        sec.resolve(&p).map(|_| ())
    };
    let topic = |extra: serde_json::Value| {
        let mut t = serde_json::json!({"topic": "/sportmodestate", "writers": [LEGIT_HEX]});
        for (k, v) in extra.as_object().unwrap() {
            t[k] = v.clone();
        }
        serde_json::json!({"topics": [t]})
    };
    let sport_sec = sport_source()["unitree_sport"].clone();
    // The section must match the type.
    let e = resolve(topic(serde_json::json!({"type": SPORT}))).unwrap_err();
    assert!(e.contains("unitree_sport"), "{e}");
    let e = resolve(topic(
        serde_json::json!({"type": GO_LOW, "unitree_sport": sport_sec}),
    ))
    .unwrap_err();
    assert!(e.contains("exactly the section"), "{e}");
    let e = resolve(topic(
        serde_json::json!({"type": "std_msgs/msg/Bool", "unitree_sport": sport_sec,
                           "values": {"true": "estop_active", "false": "none"}}),
    ))
    .unwrap_err();
    assert!(e.contains("exactly the section"), "{e}");
    let e = resolve(topic(
        serde_json::json!({"type": SPORT, "unitree_sport": sport_sec,
                                              "values": {"1": "idle"}}),
    ))
    .unwrap_err();
    assert!(e.contains("values / motion"), "{e}");
    // on_stale only for a field the source reports.
    let e = resolve(topic(
        serde_json::json!({"type": SPORT, "unitree_sport": sport_sec,
                                              "on_stale": {"control": "teleop"}}),
    ))
    .unwrap_err();
    assert!(e.contains("on_stale.control"), "{e}");
    let e = resolve(topic(serde_json::json!({
        "type": "std_msgs/msg/Bool", "values": {"true": "estop_active", "false": "none"},
        "on_stale": {"phase": "unknown"}})))
    .unwrap_err();
    assert!(e.contains("on_stale"), "{e}");
    // A silent source never claims the least conservative value.
    let mut v = topic(serde_json::json!({"type": SPORT, "unitree_sport": sport_sec}));
    v["topics"].as_array_mut().unwrap().push(serde_json::json!({
        "topic": "/wirelesscontroller", "type": REMOTE,
        "writers": [LEGIT_HEX], "wireless_controller": {},
        "on_stale": {"control": "autonomous"}}));
    let e = resolve(v.clone()).unwrap_err();
    assert!(e.contains("least conservative"), "{e}");
    v["topics"][1]["on_stale"] = serde_json::json!({"control": "teleop"});
    assert!(resolve(v.clone()).is_ok());
    let mut ps = sport_sec.clone();
    ps["phase"] = serde_json::json!({"1": "parked"});
    let e = resolve(topic(
        serde_json::json!({"type": SPORT, "unitree_sport": ps,
                                              "on_stale": {"phase": "parked"}}),
    ))
    .unwrap_err();
    assert!(e.contains("least conservative"), "{e}");
    v["uplink_status"] = serde_json::json!({"path": "/x/uplink-status.json",
                                            "on_stale": "connected"});
    assert!(resolve(v).unwrap_err().contains("cannot read connected"));
    // A remote never means autonomy; a remote alone is no safety source.
    let e = resolve(topic(serde_json::json!({"type": REMOTE,
        "wireless_controller": {"control": "autonomous"}})))
    .unwrap_err();
    assert!(e.contains("manual or teleop"), "{e}");
    let e = resolve(topic(
        serde_json::json!({"type": REMOTE, "wireless_controller": {}}),
    ))
    .unwrap_err();
    assert!(e.contains("at least one safety-state source"), "{e}");
    // Writers stay mandatory.
    let mut v = topic(serde_json::json!({"type": SPORT, "unitree_sport": sport_sec}));
    v["topics"][0]["writers"] = serde_json::json!([]);
    assert!(resolve(v).unwrap_err().contains("writers"));
    // Uplink path must be absolute.
    let mut v = topic(serde_json::json!({"type": SPORT, "unitree_sport": sport_sec}));
    v["uplink_status"] = serde_json::json!({"path": "uplink-status.json"});
    assert!(resolve(v).unwrap_err().contains("absolute"));
    // Unknown keys are refused.
    let v = topic(serde_json::json!({"type": SPORT, "unitree_sport": sport_sec, "modes": {}}));
    assert!(resolve(v).is_err());
}

// --------------------------------------------------------- T46: context --

#[test]
fn live_context_from_remote_sport_mode_and_lifecycle() {
    let mut b = Bus::new(context_feed());
    // Nothing heard: every live field reads its on_stale value.
    let c = b.ctx(0);
    assert_eq!((c.control, c.phase), (C::Manual, P::Unknown));
    assert_eq!(c.connectivity, N::Connected, "no live source: configured");
    // Robot standing, remote idle, Nav2 active.
    b.send(SPORT_W, &sport(1, 0, 0.0, 0.0), 1);
    b.send(REMOTE_W, &remote(0.0, 0), 1);
    b.send(LIFE_W, &transition(3), 1);
    let c = b.ctx(1);
    assert_eq!(c.control, C::Autonomous, "lifecycle active, remote idle");
    // Sport says parked, lifecycle says transit: the more conservative.
    assert_eq!(c.phase, P::Transit);
    assert_eq!(b.state(1), S::Idle);
    // Someone picks up the remote: manual until hold_ms after the last
    // activity.
    b.send(REMOTE_W, &remote(0.6, 0), 100);
    assert_eq!(b.ctx(100).control, C::Manual);
    b.send(REMOTE_W, &remote(0.0, 0), 400);
    assert_eq!(b.ctx(400).control, C::Manual, "held");
    b.send(SPORT_W, &sport(1, 0, 0.0, 0.0), 700);
    b.send(REMOTE_W, &remote(0.0, 0), 700);
    assert_eq!(b.ctx(700).control, C::Autonomous, "released");
    // Nav2 deactivated: parked everywhere.
    b.send(LIFE_W, &transition(2), 800);
    assert_eq!(b.ctx(800).phase, P::Parked);
    // Lifecycle is latched; the remote going silent reads manual (its
    // on_stale), the sport source going silent reads phase unknown.
    let c = b.ctx(5000);
    assert_eq!((c.control, c.phase), (C::Manual, P::Unknown));
    // ... and context-only sources never touch the safety state: with the
    // sport source fresh again, the robot is idle although the remote is
    // still silent.
    b.send(SPORT_W, &sport(1, 0, 0.0, 0.0), 5000);
    assert_eq!(b.state(5000), S::Idle);
    assert_eq!(b.ctx(5000).phase, P::Parked);
    // An unlisted lifecycle state reads on_stale (and is reported once).
    let f = b.send(LIFE_W, &transition(12), 5001);
    assert_eq!(rule_ids(&f), vec![rules::UNMAPPED_VALUE]);
    // The finding says what happened: the context reads on_stale, the
    // safety state is untouched.
    let detail = &f[0].deviation.detail;
    assert!(detail.contains("operational-context topic"), "{detail}");
    assert!(detail.contains("on_stale"), "{detail}");
    assert!(!detail.contains("read as unknown"), "{detail}");
    assert_eq!(b.ctx(5001).phase, P::Unknown);
    // Transitions are recorded with the sources' views.
    let st = b.feed.status(5001);
    let ctx = st.context.unwrap();
    assert_eq!(ctx.sources.len(), 3);
    assert!(b.feed.stats().context_transitions >= 5);
}

/// SPDP of `prefix` on `ip` with an explicit lease (seconds).
fn spdp_with_lease(prefix: [u8; 12], ip: Ipv4Addr, lease_s: i32) -> Vec<u8> {
    let mut lease = lease_s.to_le_bytes().to_vec();
    lease.extend_from_slice(&0u32.to_le_bytes());
    let payload = pl_payload(&[
        param(0x0015, &[2, 3, 0, 0]),
        param(0x0016, &[0x01, 0x0f, 0, 0]),
        param(0x0050, &guid(prefix, [0, 0, 1, 0xc1])),
        param(0x0002, &lease), // PARTICIPANT_LEASE_DURATION
        param(0x0032, &locator_v4(ip, 7410)),
        param(0x0031, &locator_v4(ip, 7411)),
    ]);
    datagram(prefix, &[data(ENTITY_SPDP_WRITER, 2, &payload)])
}

/// A dispose (inline KEY_HASH + STATUS_INFO disposed|unregistered, no
/// payload) of instance `key` by builtin writer `by`, sent by `sender`.
fn dispose(sender: [u8; 12], by: [u8; 4], key: [u8; 16]) -> Vec<u8> {
    let mut body = vec![0, 0];
    body.extend_from_slice(&16u16.to_le_bytes());
    body.extend_from_slice(&[0, 0, 0, 0]);
    body.extend_from_slice(&by);
    body.extend_from_slice(&0u32.to_le_bytes());
    body.extend_from_slice(&3u32.to_le_bytes());
    body.extend_from_slice(&param(0x0070, &key));
    body.extend_from_slice(&param(0x0071, &[0, 0, 0, 3]));
    body.extend_from_slice(&[1, 0, 0, 0]); // sentinel
    let mut sub = vec![0x15, 0x03]; // DATA, E|Q
    sub.extend_from_slice(&(body.len() as u16).to_le_bytes());
    sub.extend_from_slice(&body);
    datagram(sender, &[sub])
}

/// The lifecycle source as the only context source (beside a sport-mode
/// safety source without context mappings).
fn lifecycle_only() -> serde_json::Value {
    let mut f = context_feed();
    let life = f["topics"][2].clone();
    f["topics"] = serde_json::json!([sport_source(), life]);
    f
}

#[test]
fn a_latched_lifecycle_reading_ends_with_its_participant() {
    let active = |c: LiveContext| (c.control, c.phase) == (C::Autonomous, P::Transit);
    let stale = |c: LiveContext| (c.control, c.phase) == (C::Manual, P::Unknown);
    // No lease announced (the discovery in Bus::new): the RTPS default,
    // 100 s after the event.
    let mut b = Bus::new(lifecycle_only());
    b.send(LIFE_W, &transition(3), 1_000);
    assert!(active(b.ctx(1_000)));
    assert!(active(b.ctx(101_000)), "within one lease");
    assert!(
        stale(b.ctx(101_001)),
        "Nav2 crashed (no SPDP since): its last state must not hold forever"
    );
    // A trusted SPDP keeps the participant (and the reading) alive ...
    b.send(LIFE_W, &transition(3), 200_000);
    b.raw(ROBOT_IP, spdp_with_lease(LEGIT, ROBOT_IP, 30), 250_000);
    assert!(active(b.ctx(280_000)), "lease refreshed by its SPDP");
    // ... for its announced lease (30 s), not the default.
    assert!(stale(b.ctx(280_001)));
    // A later event uses the announced lease too.
    b.send(LIFE_W, &transition(3), 300_000);
    assert!(active(b.ctx(330_000)));
    assert!(stale(b.ctx(330_001)));
    // An SPDP of the participant from a rogue IP keeps nothing alive.
    b.send(LIFE_W, &transition(3), 400_000);
    b.raw(ROGUE_IP, spdp_with_lease(LEGIT, ROBOT_IP, 600), 420_000);
    assert!(stale(b.ctx(430_001)), "a spoofed SPDP is no refresh");

    // A self-dispose of the participant: on_stale at once. A spoofed one
    // from another host changes nothing.
    let mut b = Bus::new(lifecycle_only());
    b.send(LIFE_W, &transition(3), 1_000);
    let participant = guid(LEGIT, [0, 0, 1, 0xc1]);
    b.raw(
        ROGUE_IP,
        dispose(ROGUE, ENTITY_SPDP_WRITER, participant),
        2_000,
    );
    assert!(active(b.ctx(2_000)), "a dispose from a rogue IP is ignored");
    b.raw(
        ROBOT_IP,
        dispose(LEGIT, ENTITY_SPDP_WRITER, participant),
        3_000,
    );
    assert!(stale(b.ctx(3_000)), "the participant left");
    let st = b.feed.status(3_000).context.unwrap();
    assert!(!st.sources[0].fresh);

    // The writer itself is disposed (the node shut down, its participant
    // stays): on_stale at once.
    let mut b = Bus::new(lifecycle_only());
    b.send(LIFE_W, &transition(3), 1_000);
    b.raw(
        ROBOT_IP,
        dispose(LEGIT, ENTITY_SEDP_PUB_WRITER, guid(LEGIT, LIFE_W)),
        2_000,
    );
    assert!(stale(b.ctx(2_000)), "the writer left");
}

#[test]
fn a_wrong_ip_spdp_of_a_pinned_participant_is_no_refresh() {
    // Pinned, so a second host's SPDP does not contest the prefix: only
    // the IP check stands between it and a refresh of the latched reading.
    let active = |c: LiveContext| (c.control, c.phase) == (C::Autonomous, P::Transit);
    let stale = |c: LiveContext| (c.control, c.phase) == (C::Manual, P::Unknown);
    let mut opts = PipelineOptions::default();
    opts.binding
        .participant_ips
        .insert(LEGIT, vec![ROBOT_IP.into()]);
    let mut b = Bus::with_options(lifecycle_only(), opts);
    b.send(LIFE_W, &transition(3), 1_000);
    b.raw(ROGUE_IP, spdp_with_lease(LEGIT, ROGUE_IP, 600), 90_000);
    assert!(!b.pipeline.binding().is_contested(&LEGIT));
    assert!(active(b.ctx(101_000)));
    assert!(
        stale(b.ctx(101_001)),
        "an SPDP from an IP outside the pin must not extend the latch"
    );
    // The pinned IP's SPDP does.
    b.send(LIFE_W, &transition(3), 200_000);
    b.raw(ROBOT_IP, spdp_with_lease(LEGIT, ROBOT_IP, 600), 290_000);
    assert!(active(b.ctx(890_000)));
    assert!(stale(b.ctx(890_001)));
}

#[test]
fn only_a_self_or_relayed_dispose_ends_a_latched_reading() {
    let active = |c: LiveContext| (c.control, c.phase) == (C::Autonomous, P::Transit);
    let stale = |c: LiveContext| (c.control, c.phase) == (C::Manual, P::Unknown);
    let participant = guid(LEGIT, [0, 0, 1, 0xc1]);
    // Another participant on the same (bound) IP disposes LEGIT, or its
    // lifecycle writer, under its own prefix: not a self-dispose, ignored.
    let mut b = Bus::new(lifecycle_only());
    b.send(LIFE_W, &transition(3), 1_000);
    b.raw(
        ROBOT_IP,
        dispose(ROGUE, ENTITY_SPDP_WRITER, participant),
        2_000,
    );
    assert!(
        active(b.ctx(2_000)),
        "a participant dispose by another prefix"
    );
    b.raw(
        ROBOT_IP,
        dispose(ROGUE, ENTITY_SEDP_PUB_WRITER, guid(LEGIT, LIFE_W)),
        3_000,
    );
    assert!(active(b.ctx(3_000)), "a writer dispose by another prefix");
    // The latch still ends with its lease.
    assert!(stale(b.ctx(101_001)));

    // A configured discovery server relays the participant's dispose.
    let relay = Ipv4Addr::new(10, 0, 0, 77);
    let mut opts = PipelineOptions::default();
    opts.binding.discovery_servers.push(relay.into());
    let mut b = Bus::with_options(lifecycle_only(), opts);
    b.send(LIFE_W, &transition(3), 1_000);
    b.raw(
        relay,
        dispose(ROGUE, ENTITY_SPDP_WRITER, participant),
        2_000,
    );
    assert!(
        stale(b.ctx(2_000)),
        "a relayed dispose from a discovery server"
    );
}

#[test]
fn a_spoofed_idle_remote_cannot_hand_control_back_to_autonomy() {
    let mut b = Bus::new(context_feed());
    b.send(LIFE_W, &transition(3), 1);
    b.send(REMOTE_W, &remote(0.8, 0), 1);
    assert_eq!(b.ctx(1).control, C::Manual);
    // A rogue announces the remote topic and keeps sending "idle".
    b.raw(ROGUE_IP, discovery_of(ROGUE, ROGUE_IP), 2);
    for (i, t) in (3..2000).step_by(100).enumerate() {
        let f = b.raw(
            ROGUE_IP,
            sample(ROGUE, REMOTE_W, i as u32 + 1, &remote(0.0, 0)),
            t,
        );
        if i == 0 {
            assert_eq!(rule_ids(&f), vec![rules::UNTRUSTED_SOURCE]);
        }
        // The legit remote stays in use (or goes silent): never autonomous.
        assert_ne!(b.ctx(t).control, C::Autonomous, "at {t}");
    }
    // A forged lifecycle "active" from the rogue changes nothing either.
    let f = b.raw(ROGUE_IP, sample(ROGUE, LIFE_W, 1, &transition(3)), 2001);
    assert_eq!(rule_ids(&f), vec![rules::UNTRUSTED_SOURCE]);
    assert_eq!(b.ctx(2001).control, C::Manual);
}

#[test]
fn uplink_status_drives_connectivity() {
    let dir = std::env::temp_dir().join(format!("robodr-ctx-uplink-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    let path = dir.join("uplink-status.json");
    let mut feed = serde_json::json!({"topics": [sport_source()]});
    feed["uplink_status"] =
        serde_json::json!({"path": path, "stale_after_ms": 10000, "poll_ms": 100});
    let mut b = Bus::new(feed);
    let wall = 1_800_000_000_000u64;
    let write = |state: &str, at: u64| {
        let v = serde_json::json!({"format": "robodr-uplink-status/1", "state": state,
                                   "updated_at_ms": at, "pid": 7, "consecutive_failures": 0});
        std::fs::write(&path, serde_json::to_vec(&v).unwrap()).unwrap();
    };
    let ctx = |b: &mut Bus, now: u64, w: u64| b.feed.evaluate_context(now, w, configured());
    // No file yet: disconnected (on_stale), whatever the configuration says.
    let (c, t) = ctx(&mut b, 0, wall).unwrap();
    assert_eq!(c.connectivity, N::Disconnected);
    let t = t.unwrap();
    assert_eq!(t.from.connectivity, N::Connected);
    assert_eq!(t.kind, "robodr.context_transition");
    write("ok", wall);
    assert_eq!(ctx(&mut b, 100, wall).unwrap().0.connectivity, N::Connected);
    write("retrying", wall + 1000);
    assert_eq!(
        ctx(&mut b, 200, wall + 1000).unwrap().0.connectivity,
        N::Degraded
    );
    write("blocked", wall + 2000);
    assert_eq!(
        ctx(&mut b, 300, wall + 2000).unwrap().0.connectivity,
        N::Disconnected
    );
    write("ok", wall + 3000);
    assert_eq!(
        ctx(&mut b, 400, wall + 3000).unwrap().0.connectivity,
        N::Connected
    );
    // The uplink stops writing: stale after 10 s.
    assert_eq!(
        ctx(&mut b, 500, wall + 14_000).unwrap().0.connectivity,
        N::Disconnected
    );
    let st = b.feed.status(500);
    let v = serde_json::to_value(st.context.unwrap()).unwrap();
    assert_eq!(
        v["sources"].as_array().unwrap().len(),
        1,
        "sport is no context source"
    );
    assert!(v["sources"][0]["name"]
        .as_str()
        .unwrap()
        .starts_with("uplink_status:"));
    assert!(
        v["sources"][0]["error"].as_str().unwrap().contains("stale"),
        "{v}"
    );
    let _ = std::fs::remove_dir_all(&dir);
}

// ----------------------------------------------------- through the daemon --

/// Replay sport mode (still), the remote (in use or idle) and an
/// over-envelope command; the command's plans as JSON.
fn replay(remote_lx: f32, tag: &str) -> (Vec<serde_json::Value>, Vec<serde_json::Value>) {
    let s = setup(tag, &profile(true));
    let unicast = |d: &[u8]| frame(ROBOT_IP, ROBOT_IP, 7411, d);
    let pcap = s.pcap(&[
        frame(ROBOT_IP, SPDP_GROUP, 7400, &discovery_of(LEGIT, ROBOT_IP)),
        unicast(&sample(LEGIT, SPORT_W, 1, &sport(3, 0, 0.4, 0.0))),
        unicast(&sample(LEGIT, LIFE_W, 1, &transition(3))),
        unicast(&sample(LEGIT, REMOTE_W, 1, &remote(remote_lx, 0))),
        unicast(&cmd_vel_datagram(LEGIT, CMD_WRITER, 1, 2.5)),
    ]);
    let mut cfg = s.config(
        serde_json::json!({"capture": {"enabled": true, "pcap_replay": pcap}}),
        serde_json::json!([]),
        serde_json::json!({"exit_when_inputs_end": true}),
    );
    cfg["context"] = serde_json::json!({"control": "autonomous", "phase": "task"});
    let mut feed = context_feed();
    feed["stale_after_ms"] = serde_json::json!(60000);
    feed["topics"][1]["wireless_controller"]["hold_ms"] = serde_json::json!(60000);
    cfg["safety_feed"] = feed;
    let r = s.resolve(&cfg);
    let mut log = Vec::new();
    let sum = robodr_agentd::run(&r, &|| false, &mut log).unwrap();
    let log = String::from_utf8(log).unwrap();
    assert_eq!(sum.reason, StopReason::InputsEnded, "{log}");
    let found = spooled(&s.spool);
    assert_verified(&s.blackbox, Some(sum.finished.checkpoint.clone()), &found);
    let st = status(&s.spool).unwrap();
    assert!(st["safety_feed"]["context"]["context"].is_object(), "{st}");
    let notes: Vec<serde_json::Value> = records(&s.blackbox)
        .iter()
        .filter_map(|r| serde_json::from_slice::<serde_json::Value>(&r.payload).ok())
        .collect();
    let plans = notes
        .iter()
        .filter(|v| v["kind"] == "robodr.response_plan")
        .filter(|v| v["plan"]["rule"] == "robot.motion.linear_over_envelope")
        .map(|v| v["plan"].clone())
        .collect();
    let transitions = notes
        .into_iter()
        .filter(|v| v["kind"] == "robodr.context_transition")
        .collect();
    (plans, transitions)
}

#[test]
fn remote_in_use_makes_motion_steps_proposals_end_to_end() {
    // Control: remote idle, Nav2 active -> autonomous: no human-in-command
    // gate on the plan.
    let (plans, trans) = replay(0.0, "uc-idle");
    assert_eq!(plans.len(), 1, "{trans:?}");
    assert_eq!(plans[0]["safety_state"], "moving_slow");
    let why = plans[0]["rationale"].to_string();
    assert!(
        !why.contains("human_in_command") && !why.contains("HumanInCommand"),
        "{why}"
    );
    let last = trans.last().unwrap();
    assert_eq!(last["to"]["control"], "autonomous", "{trans:?}");
    assert_eq!(last["to"]["phase"], "transit");
    // The remote in use: the same command's motion steps need a human.
    let (plans, trans) = replay(0.7, "uc-remote");
    assert_eq!(plans.len(), 1, "{trans:?}");
    assert_eq!(plans[0]["safety_state"], "moving_slow");
    assert_eq!(plans[0]["requires_human_approval"], true, "{}", plans[0]);
    let why = plans[0]["rationale"].to_string();
    assert!(
        why.contains("human_in_command") || why.contains("HumanInCommand"),
        "{why}"
    );
    let last = trans.last().unwrap();
    assert_eq!(last["to"]["control"], "manual", "{trans:?}");
    assert!(last["sources"].as_array().unwrap().len() >= 3);
}
