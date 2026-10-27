//! The robot side, observed (review findings F1 and F7): `rt/lowstate`
//! gates the arm-SDK engagement (the weight rising from 0 hands the arms
//! to the SDK at the SDK's targets: they must be where the arms are), and
//! the robot's own SPDP / SEDP runs through the unqueued-locator check.
//! The robot's packets reach the gateway only as NFLOG copies
//! (`Gateway::observe`): nothing here is verdicted.

use std::time::Instant;

use robodr_cdr::Representation;
use robodr_firewall_gw::ip::parse_ipv4_udp;
use robodr_firewall_gw::lowcmd::{self, LowCmdCodec, WireLowCmd};
use robodr_firewall_gw::rtps::{self, Content, WalkOptions};
use robodr_firewall_gw::testkit::*;
use robodr_firewall_gw::{Gateway, PacketMeta, Verdict};

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

fn out_weight(pkt: &[u8]) -> Option<f32> {
    let ip = parse_ipv4_udp(pkt).ok()?;
    let d = &pkt[ip.payload()];
    let mut v = Vec::new();
    rtps::walk(d, WalkOptions::default(), &mut v).ok()?;
    let s = v
        .iter()
        .find(|s| !s.builtin && s.content == Content::Data)?;
    let m = lowcmd::decode_strict(&d[s.payload.clone()?], LowCmdCodec::Hg).ok()?;
    Some(m.msg.motor(29)?.q)
}

fn arm_pkt(sn: i64, m: &WireLowCmd) -> Vec<u8> {
    packet(
        CONTROLLER_IP,
        DDS_PORT,
        &data_datagram(
            ARM_WRITER,
            sn,
            &lowcmd::encode_payload(m, Representation::CdrLe),
        ),
    )
}

/// The arm channel with fast weight dynamics (the SDK example's 0 → 1 in
/// one frame, `g1_arm7_sdk_dds_example.cpp:149`), announced by SEDP.
fn gateway() -> Gateway {
    let mut gw = g1_channels_gateway(|v| {
        v["channels"][1]["max_weight_step"] = serde_json::json!(1.0);
        v["channels"][1]["max_weight_rate_per_s"] = serde_json::json!(1000.0);
    });
    let p = packet(
        CONTROLLER_IP,
        7410,
        &sedp_datagram(
            PREFIX,
            ARM_WRITER,
            "rt/arm_sdk",
            "unitree_hg::msg::dds_::LowCmd_",
        ),
    );
    assert_eq!(run(&mut gw, &p, 1).0, Verdict::Accept);
    gw
}

/// The robot's joint positions = the arm frame's targets (+ `offset`).
fn robot_q(frame: &WireLowCmd, offset: f32) -> Vec<f32> {
    (0..35)
        .map(|i| frame.motor(i).map_or(0.0, |m| m.q) + offset)
        .collect()
}

fn observe_lowstate(gw: &mut Gateway, sn: i64, q: &[f32], now: u64, frag: Option<u16>) {
    for d in lowstate_datagram(sn, q, frag) {
        gw.observe(&robot_packet(7411, &d), meta(now));
    }
}

/// F1: the weight leaves 0 at once (SDK style) only when the targets are
/// where the robot reports its arms (`rt/lowstate`, observed).
#[test]
fn f1_engagement_is_checked_against_lowstate() {
    let frame = |w| arm_frame(w, 0.0);
    // Targets where the arms are: engaged in one frame.
    let mut gw = gateway();
    assert_eq!(
        out_weight(&run(&mut gw, &arm_pkt(1, &frame(0.0)), T0).1),
        Some(0.0)
    );
    observe_lowstate(&mut gw, 1, &robot_q(&frame(1.0), 0.02), T0 + 15 * MS, None);
    assert!(gw.stats.lowstate_samples >= 1, "{:?}", gw.stats);
    let w = out_weight(&run(&mut gw, &arm_pkt(2, &frame(1.0)), T0 + 20 * MS).1);
    assert_eq!(w, Some(1.0), "engaged where the arms are");
    // Targets 0.5 rad away from the arms: refused (held at 0), also a small
    // first step (the robot's state is known: it must match).
    let mut gw = gateway();
    run(&mut gw, &arm_pkt(1, &frame(0.0)), T0);
    observe_lowstate(&mut gw, 1, &robot_q(&frame(1.0), 0.5), T0 + 15 * MS, None);
    for (k, w) in [1.0f32, 0.01].into_iter().enumerate() {
        let out = out_weight(
            &run(
                &mut gw,
                &arm_pkt(2 + k as i64, &frame(w)),
                T0 + (20 + 20 * k as u64) * MS,
            )
            .1,
        );
        assert_eq!(out, Some(0.0), "weight {w} engaged away from the arms");
    }
    assert!(gw.stats.arm_engage_rejected >= 2, "{:?}", gw.stats);
}

/// F1: a stale `rt/lowstate` (older than `lowstate_max_age_ms`) is not
/// used: the small-first-step rule applies.
#[test]
fn f1_stale_lowstate_falls_back_to_the_first_step() {
    let mut gw = gateway();
    run(&mut gw, &arm_pkt(1, &arm_frame(0.0, 0.0)), T0);
    observe_lowstate(&mut gw, 1, &robot_q(&arm_frame(1.0, 0.0), 0.0), T0, None);
    let later = T0 + 200 * MS;
    let w = out_weight(&run(&mut gw, &arm_pkt(2, &arm_frame(1.0, 0.0)), later).1);
    assert_eq!(w, Some(0.0), "stale lowstate engaged the arms");
    let w = out_weight(&run(&mut gw, &arm_pkt(3, &arm_frame(0.02, 0.0)), later + 20 * MS).1);
    assert_eq!(w, Some(0.02));
}

/// F1: a gateway that starts while the arm stream is engaged (weight 1)
/// accepts it when the targets match the robot's state (no deadlock);
/// without a state it does not.
#[test]
fn f1_restart_mid_stream_needs_matching_lowstate() {
    let mut gw = gateway();
    let w = out_weight(&run(&mut gw, &arm_pkt(1, &arm_frame(1.0, 0.0)), T0).1);
    assert_eq!(w, None, "nothing accepted: suppressed");
    observe_lowstate(
        &mut gw,
        1,
        &robot_q(&arm_frame(1.0, 0.0), 0.0),
        T0 + 10 * MS,
        None,
    );
    let w = out_weight(&run(&mut gw, &arm_pkt(2, &arm_frame(1.0, 0.0)), T0 + 20 * MS).1);
    assert_eq!(w, Some(1.0));
}

/// F1: the `hg` `LowState_` (2 KB) arrives fragmented from Cyclone DDS;
/// the observer reassembles it. A sample with a bad CRC is not a joint
/// state.
#[test]
fn f1_fragmented_lowstate_is_reassembled_and_bad_crc_ignored() {
    let mut gw = gateway();
    observe_lowstate(&mut gw, 1, &[0.0; 35], T0, Some(1024));
    assert_eq!(gw.stats.lowstate_samples, 1, "{:?}", gw.stats);
    let mut bad = hg_lowstate_payload(&[0.0; 35]);
    let n = bad.len();
    bad[n - 1] ^= 0xff;
    let d = robodr_firewall_gw::rtps::build::Datagram::new(ROBOT_PREFIX)
        .data(LOWSTATE_WRITER, 2, &[], &bad)
        .finish();
    gw.observe(&robot_packet(7411, &d), meta(T0 + MS));
    assert_eq!(gw.stats.lowstate_samples, 1);
}

/// F7: the unqueued-locator warning checked only controller-side
/// discovery; the robot's own announcements (a reader of `rt/lowcmd` at a
/// port no rule queues, a participant whose unicast discovery port is
/// outside the queued ranges) are where controller-side stacks send.
#[test]
fn f7_robot_side_discovery_is_checked() {
    let mut gw = gateway();
    let reader = sedp_with_locator(
        ROBOT_PREFIX,
        [0, 0, 0x11, 0x04],
        "rt/lowcmd",
        "unitree_hg::msg::dds_::LowCmd_",
        true,
        ROBOT_IP,
        45123,
    );
    gw.observe(&robot_packet(7410, &reader), meta(T0));
    let d = gw.discovery();
    assert_eq!(d.stats.robot_unqueued_locators, 1, "{:?}", d.stats);
    let w = d.port_bypass().expect("port_bypass_risk");
    assert!(
        w.contains("robot reader of enforced topic rt/lowcmd") && w.contains(":45123"),
        "{w}"
    );
    let mut gw = gateway();
    let spdp = spdp_with_locator(ROBOT_PREFIX, ROBOT_IP, 46000);
    gw.observe(&robot_packet(7400, &spdp), meta(T0));
    let w = gw.discovery().port_bypass().expect("port_bypass_risk");
    assert!(
        w.contains("robot participant") && w.contains(":46000"),
        "{w}"
    );
    // Inside the queued ranges: nothing.
    let mut gw = gateway();
    gw.observe(
        &robot_packet(7400, &spdp_with_locator(ROBOT_PREFIX, ROBOT_IP, 7412)),
        meta(T0),
    );
    assert!(gw.discovery().port_bypass().is_none());
    // Robot-side writers never become controller-side enforced writers.
    assert_eq!(gw.discovery().len(), 1, "only the controller's arm writer");
}
