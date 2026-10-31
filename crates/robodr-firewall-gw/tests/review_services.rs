//! Regression tests for the gateway review's api-service finding 3: Go2's
//! `obstacles_avoid` `Move` (1003, `{"x","y","yaw","mode"}`) used to have no
//! codec; an unknown writer's request was probed as sport, where 1003 is
//! `StopMove` (always allowed), so an unbounded velocity or position
//! target passed. And a Go2 configuration without a channel for every
//! motion service now refuses to start in enforce mode.
//!
//! Finding 6: a sport channel without `allowed_api_ids` and a Go1
//! `HighCmd` channel without `allowed_high_modes` forwarded every call /
//! mode (tricks, flips, attitude, trajectory following, unknown ids, mode 1
//! poses) after a source / rate check; and a restriction did not refuse an
//! allowlisted motion call.
//!
//! Finding 4: a `TwistStamped` with a far-future `header.stamp` was
//! forwarded untouched, so `diff_drive_controller` kept executing it past
//! its `cmd_vel_timeout`; the stamp is now zeroed ("now").

use std::time::Instant;

use robodr_cdr::unitree::{ApiService, UnitreeModel};
use robodr_cdr::{ApiCall, Representation};
use robodr_firewall_gw::ip::parse_ipv4_udp;
use robodr_firewall_gw::rtps::{self, build::Datagram, Content, WalkOptions};
use robodr_firewall_gw::testkit::*;
use robodr_firewall_gw::{legacy, ros2, sport, Gateway, GatewayConfig, PacketMeta, Verdict};

const MS: u64 = 1_000_000;
const T0: u64 = 1_000_000_000;

fn meta(now: u64) -> PacketMeta {
    PacketMeta {
        now_ns: now,
        queue_delay_ns: None,
        instant: Instant::now(),
        src_mac: None,
    }
}

fn run(gw: &mut Gateway, pkt: &[u8], now: u64) -> (Verdict, Vec<u8>) {
    let mut p = pkt.to_vec();
    let v = gw.process(&mut p, meta(now));
    (v, p)
}

fn out_payload(pkt: &[u8]) -> Option<Vec<u8>> {
    let ip = parse_ipv4_udp(pkt).ok()?;
    let d = &pkt[ip.payload()];
    let mut v = Vec::new();
    rtps::walk(d, WalkOptions::default(), &mut v).ok()?;
    let s = v
        .iter()
        .find(|s| !s.builtin && s.content == Content::Data)?;
    Some(d[s.payload.clone()?].to_vec())
}

fn req(api: i64, param: &str) -> Vec<u8> {
    sport::encode_request(Representation::CdrLe, 7, api, param)
}

fn obstacles_gw() -> Gateway {
    let mut gw = gateway(Fixture::Go2);
    let sedp = sedp_datagram(
        PREFIX,
        OBSTACLES_WRITER,
        "rt/api/obstacles_avoid/request",
        "unitree_api::msg::dds_::Request_",
    );
    run(&mut gw, &packet(CONTROLLER_IP, 7410, &sedp), T0);
    gw
}

fn send(gw: &mut Gateway, prefix: [u8; 12], w: [u8; 4], sn: i64, p: &[u8], now: u64) -> Vec<u8> {
    let d = Datagram::new(prefix).data(w, sn, &[], p).finish();
    run(gw, &packet(CONTROLLER_IP, DDS_PORT, &d), now).1
}

/// The authorised obstacles_avoid writer's `Move` at 5 m/s is limited to
/// the channel's 1 m/s, as an obstacles_avoid `Move` (keys `yaw`, `mode`).
#[test]
fn f3_obstacles_avoid_move_is_limited() {
    let mut gw = obstacles_gw();
    let fast = req(1003, r#"{"x":5.0,"y":0.0,"yaw":0.0,"mode":0}"#);
    let out = send(&mut gw, PREFIX, OBSTACLES_WRITER, 1, &fast, T0 + 20 * MS);
    let p = out_payload(&out).expect("limited, not removed");
    let back =
        sport::decode_strict_for(&p, ApiService::ObstaclesAvoid, Some(UnitreeModel::Go2)).unwrap();
    match back.call {
        ApiCall::Move { vx, .. } => assert!(vx <= 1.0 + 1e-9, "vx {vx}"),
        other => panic!("{other:?}"),
    }
    assert_eq!(gw.stats.limited + gw.stats.substituted, 1);
}

/// Position targets (mode 1 / 2), `UseRemoteCommandFromApi` and the UWB
/// follow mode are refused without an allowlist; a query passes.
#[test]
fn f3_position_targets_and_handovers_are_refused() {
    let mut gw = obstacles_gw();
    let sedp = sedp_datagram(
        PREFIX,
        UWB_WRITER,
        "rt/api/uwbswitch/request",
        "unitree_api::msg::dds_::Request_",
    );
    run(&mut gw, &packet(CONTROLLER_IP, 7410, &sedp), T0);
    let mut now = T0;
    let mut sn = 0;
    for (w, api, param, pass) in [
        (
            OBSTACLES_WRITER,
            1003,
            r#"{"x":50.0,"y":0.0,"yaw":0.0,"mode":1}"#,
            false,
        ),
        (
            OBSTACLES_WRITER,
            1003,
            r#"{"x":50.0,"y":0.0,"yaw":0.0,"mode":2}"#,
            false,
        ),
        (
            OBSTACLES_WRITER,
            1004,
            r#"{"is_remote_commands_from_api":true}"#,
            false,
        ),
        (OBSTACLES_WRITER, 1002, "", true),
        (UWB_WRITER, 1001, r#"{"enable":true}"#, false),
        (UWB_WRITER, 1003, "", true),
    ] {
        sn += 1;
        now += 50 * MS;
        let out = send(&mut gw, PREFIX, w, sn, &req(api, param), now);
        assert_eq!(out_payload(&out).is_some(), pass, "{api} {param}");
    }
}

/// An unknown writer's obstacles_avoid `Move` (1003): sport reads 1003 as
/// `StopMove` (always allowed), obstacles_avoid as a velocity. Ambiguous
/// without the writer's SEDP topic: suppressed, not passed as a stop.
#[test]
fn f3_unknown_writer_request_ambiguous_between_services_fails_closed() {
    let mut gw = gateway(Fixture::Go2);
    let fast = req(1003, r#"{"x":5.0,"y":0.0,"yaw":0.0,"mode":0}"#);
    let out = send(&mut gw, PREFIX, [0, 0, 0x21, 0x03], 1, &fast, T0);
    assert!(out_payload(&out).is_none());
    assert_eq!(gw.stats.unknown_undecidable, 1);
}

/// Enforce mode on a Go2 needs every motion service's channel.
#[test]
fn f3_go2_without_every_motion_service_refuses_to_start() {
    let text =
        std::fs::read_to_string(config_dir().join("firewall-gw.unitree-go2.example.json")).unwrap();
    let mut v: serde_json::Value = serde_json::from_str(&text).unwrap();
    let chans = v["channels"].as_array_mut().unwrap();
    chans.retain(|c| c["codec"] != "unitree_uwbswitch_request");
    let e = GatewayConfig::from_json(&v.to_string()).unwrap_err();
    assert!(e.contains("unitree_uwbswitch_request"), "{e}");
    // Without robot_model, a sport channel is enough to require them.
    v.as_object_mut().unwrap().remove("robot_model");
    assert!(GatewayConfig::from_json(&v.to_string()).is_err());
    // Observe mode only observes.
    v["mode"] = serde_json::json!("observe");
    assert!(GatewayConfig::from_json(&v.to_string()).is_ok());
    // A B2 needs the sport channel only.
    v["mode"] = serde_json::json!("enforce");
    v["robot_model"] = serde_json::json!("b2");
    assert!(GatewayConfig::from_json(&v.to_string()).is_ok());
}

/// Finding 4: a far-future (and a past) stamp is zeroed in place, on a
/// passed command too; a zero stamp is forwarded byte-identical.
#[test]
fn f4_twist_stamped_stamp_is_zeroed() {
    let mut gw = g1_channels_gateway(|v| {
        v["channels"][5]["codec"] = serde_json::json!("ros2_twist_stamped");
    });
    let sedp = sedp_datagram(
        PREFIX,
        TWIST_WRITER,
        "rt/cmd_vel",
        "geometry_msgs::msg::dds_::TwistStamped_",
    );
    run(&mut gw, &packet(CONTROLLER_IP, 7410, &sedp), T0);
    let mut now = T0;
    for (sn, sec) in [(1, 0i32), (2, 2_000_000_000), (3, 1)] {
        now += 20 * MS;
        let p = ros2::encode(
            [0.1, 0.0, 0.0, 0.0, 0.0, 0.1],
            Some((sec, 5, "base_link")),
            false,
        );
        let out = send(&mut gw, PREFIX, TWIST_WRITER, sn, &p, now);
        let got = out_payload(&out).expect("forwarded");
        let w = ros2::decode_strict(&got, true).unwrap();
        assert_eq!(w.values, [0.1, 0.0, 0.0, 0.0, 0.0, 0.1]);
        assert!(ros2::stamp_is_zero(&got), "sec {sec}");
        if sec == 0 {
            assert_ne!(got, p, "nanosec 5 is zeroed too");
        }
    }
    assert_eq!(gw.stats.twist_stamp_zeroed, 3);
    // Already zero: untouched.
    now += 20 * MS;
    let p = ros2::encode(
        [0.1, 0.0, 0.0, 0.0, 0.0, 0.1],
        Some((0, 0, "base_link")),
        false,
    );
    let d = Datagram::new(PREFIX)
        .data(TWIST_WRITER, 4, &[], &p)
        .finish();
    assert_eq!(
        run(&mut gw, &packet(CONTROLLER_IP, DDS_PORT, &d), now).0,
        Verdict::Accept
    );
}

fn sport_gw(edit: impl FnOnce(&mut GatewayConfig)) -> Gateway {
    let mut cfg = gateway_config(Fixture::Go2);
    edit(&mut cfg);
    let mut gw = Gateway::new(&cfg, &profile(Fixture::Go2), &firewall(Fixture::Go2)).unwrap();
    let sedp = sedp_datagram(
        PREFIX,
        SPORT_WRITER,
        "rt/api/sport/request",
        "unitree_api::msg::dds_::Request_",
    );
    run(&mut gw, &packet(CONTROLLER_IP, 7410, &sedp), T0);
    gw
}

fn restricted() -> robodr_firewall_gw::restrict::Restriction {
    robodr_firewall_gw::restrict::parse(
        r#"{"format":"robodr-gw-restriction/v1","id":"r","factor":0.5,"expires_unix_ms":18446744073709551615}"#,
    )
    .unwrap()
}

/// A sport channel without `allowed_api_ids` is refused (it used to
/// forward every call); with the empty list only velocity, stop and query
/// calls pass: a flip (Go2 `FrontFlip` 1030), `Euler` (1007),
/// `TrajectoryFollow` (1018) and an unknown id are refused.
#[test]
fn f6_sport_without_allowlist_is_default_deny() {
    let mut cfg = gateway_config(Fixture::Go2);
    cfg.channels[1].allowed_api_ids = None;
    let e = Gateway::new(&cfg, &profile(Fixture::Go2), &firewall(Fixture::Go2)).unwrap_err();
    assert!(e.contains("allowed_api_ids"), "{e}");
    let mut gw = sport_gw(|c| c.channels[1].allowed_api_ids = Some(Vec::new()));
    let mut now = T0;
    let mut sn = 0;
    for (api, param, pass) in [
        (1030, "", false),
        (1007, r#"{"x":0.5,"y":0.5,"z":0.0}"#, false),
        (1018, "[]", false),
        (1199, "", false),
        (1003, "", true),
        (1008, r#"{"x":0.2,"y":0.0,"z":0.0}"#, true),
    ] {
        sn += 1;
        now += 100 * MS;
        let out = send(&mut gw, PREFIX, SPORT_WRITER, sn, &req(api, param), now);
        assert_eq!(out_payload(&out).is_some(), pass, "api {api}");
    }
    // A configuration file without the list is refused.
    let text =
        std::fs::read_to_string(config_dir().join("firewall-gw.unitree-go2.example.json")).unwrap();
    let mut v: serde_json::Value = serde_json::from_str(&text).unwrap();
    v["channels"][1]
        .as_object_mut()
        .unwrap()
        .remove("allowed_api_ids");
    let e = GatewayConfig::from_json(&v.to_string()).unwrap_err();
    assert!(e.contains("allowed_api_ids"), "{e}");
}

/// Under a restriction an allowlisted motion call (`StandUp` 1004) is
/// refused; `StopMove` and a capped `Move` still pass.
#[test]
fn f6_restriction_refuses_allowlisted_motion_calls() {
    let mut gw = sport_gw(|_| {});
    gw.set_restriction(Some(restricted()));
    let mut now = T0;
    for (sn, (api, param, pass)) in [
        (1004, "", false),
        (1001, "", false),
        (1003, "", true),
        (1008, r#"{"x":0.2,"y":0.0,"z":0.0}"#, true),
    ]
    .into_iter()
    .enumerate()
    {
        now += 100 * MS;
        let out = send(
            &mut gw,
            PREFIX,
            SPORT_WRITER,
            sn as i64 + 1,
            &req(api, param),
            now,
        );
        assert_eq!(out_payload(&out).is_some(), pass, "api {api}");
    }
    assert_eq!(gw.stats.restriction_refused, 2);
}

/// Go1 `HighCmd`: without `allowed_high_modes` only idle (0) and velocity
/// (2); a listed pose (mode 1) is refused under a restriction.
#[test]
fn f6_go1_high_modes_default_deny_and_restriction() {
    let high = |m: u8| packet(CONTROLLER_IP, 8082, &legacy::build_high(m, 0.0, 0.0, 0.0));
    let hi = |c: &mut GatewayConfig| {
        c.channels
            .iter_mut()
            .find(|x| x.codec == robodr_firewall_gw::config::Codec::Go1HighCmd)
            .unwrap()
            .allowed_high_modes = None;
    };
    let mut cfg = gateway_config(Fixture::Go2);
    hi(&mut cfg);
    assert!(Gateway::new(&cfg, &profile(Fixture::Go2), &firewall(Fixture::Go2)).is_err());
    let mut gw = sport_gw(|_| {});
    assert_eq!(run(&mut gw, &high(1), T0 + 100 * MS).0, Verdict::Accept);
    gw.set_restriction(Some(restricted()));
    assert_eq!(run(&mut gw, &high(1), T0 + 200 * MS).0, Verdict::Drop);
    assert_eq!(run(&mut gw, &high(0), T0 + 300 * MS).0, Verdict::Accept);
}
