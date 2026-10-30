//! Regression tests for the gateway review's api-service finding 3: Go2's
//! `obstacles_avoid` `Move` (1003, `{"x","y","yaw","mode"}`) used to have no
//! codec; an unknown writer's request was probed as sport, where 1003 is
//! `StopMove` (always allowed), so an unbounded velocity or position
//! target passed. And a Go2 configuration without a channel for every
//! motion service now refuses to start in enforce mode.

use std::time::Instant;

use robodr_cdr::unitree::{ApiService, UnitreeModel};
use robodr_cdr::{ApiCall, Representation};
use robodr_firewall_gw::ip::parse_ipv4_udp;
use robodr_firewall_gw::rtps::{self, build::Datagram, Content, WalkOptions};
use robodr_firewall_gw::testkit::*;
use robodr_firewall_gw::{sport, Gateway, GatewayConfig, PacketMeta, Verdict};

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
