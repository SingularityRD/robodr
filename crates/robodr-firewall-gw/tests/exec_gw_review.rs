//! Regressions for the independent review of the gateway channels
//! (`f27e02d`): findings F1 (arm-SDK blend weight rate), F2 (lenient
//! unknown-writer classification), F5 (Dex3 mode octet, hand-SDK weight),
//! F6 (hands exempt from the humanoid all-limp rule), F10 (loco twist
//! state, malformed `SetVelocity`, `Start` allowlist, the G1 arm action
//! service). Each test was written first and seen failing. The
//! robot-side observation (F1 `rt/lowstate`, F7 robot discovery) is in
//! `tests/robot_side.rs`.

use std::time::Instant;

use robodr_cdr::unitree::{ApiService, UnitreeModel};
use robodr_cdr::{ApiCall, Representation};
use robodr_events::profile::Envelope;
use robodr_firewall::{ChannelKind, ChannelSpec, FirewallConfig};
use robodr_firewall_gw::config::Codec;
use robodr_firewall_gw::ip::parse_ipv4_udp;
use robodr_firewall_gw::lowcmd::{self, LowCmdCodec, WireLowCmd};
use robodr_firewall_gw::rtps::build::Datagram;
use robodr_firewall_gw::rtps::{self, Content, WalkOptions};
use robodr_firewall_gw::testkit::*;
use robodr_firewall_gw::{hand, ros2, sport, Gateway, PacketMeta, Verdict};

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
    if v != Verdict::AcceptModified {
        assert_eq!(p, pkt, "unmodified verdict {v:?} but bytes changed");
    } else {
        assert_eq!(p.len(), pkt.len());
        parse_ipv4_udp(&p).expect("valid checksums");
    }
    (v, p)
}

/// The payload of the first user DATA of `pkt` (`None`: suppressed).
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

fn pkt(entity: [u8; 4], sn: i64, payload: &[u8]) -> Vec<u8> {
    packet(CONTROLLER_IP, DDS_PORT, &data_datagram(entity, sn, payload))
}

fn foreign_pkt(sn: i64, payload: &[u8]) -> Vec<u8> {
    packet(
        ATTACKER_IP,
        DDS_PORT,
        &Datagram::new(FOREIGN)
            .data([0, 0, 0x77, 0x03], sn, &[], payload)
            .finish(),
    )
}

fn announce(gw: &mut Gateway, w: [u8; 4], topic: &str, ty: &str) {
    let p = packet(CONTROLLER_IP, 7410, &sedp_datagram(PREFIX, w, topic, ty));
    assert_eq!(run(gw, &p, 1).0, Verdict::Accept);
}

fn announced(edit: impl FnOnce(&mut serde_json::Value)) -> Gateway {
    let mut gw = g1_channels_gateway(edit);
    for (w, topic, ty) in [
        (ARM_WRITER, "rt/arm_sdk", "unitree_hg::msg::dds_::LowCmd_"),
        (
            LOCO_WRITER,
            "rt/api/sport/request",
            "unitree_api::msg::dds_::Request_",
        ),
        (
            DEX3_WRITER,
            "rt/dex3/left/cmd",
            "unitree_hg::msg::dds_::HandCmd_",
        ),
        (
            HAND_SDK_WRITER,
            "rt/hand_sdk",
            "unitree_go::msg::dds_::MotorCmds_",
        ),
        (
            TWIST_WRITER,
            "rt/cmd_vel",
            "geometry_msgs::msg::dds_::Twist_",
        ),
    ] {
        announce(&mut gw, w, topic, ty);
    }
    gw
}

// ------------------------------------------------------------------ F1

fn arm_pkt(sn: i64, m: &WireLowCmd) -> Vec<u8> {
    pkt(
        ARM_WRITER,
        sn,
        &lowcmd::encode_payload(m, Representation::CdrLe),
    )
}

/// The weight of the forwarded arm frame (`None`: suppressed).
fn out_weight(pkt: &[u8]) -> Option<f32> {
    let p = out_payload(pkt)?;
    let d = lowcmd::decode_strict(&p, LowCmdCodec::Hg).expect("forwarded arm frame is strict");
    assert!(d.msg.crc_ok());
    Some(d.msg.motor(29).unwrap().q)
}

/// F1: the blend weight was bounded to `[0, max_weight]` but not rate
/// limited: 0 → 1 → 0 → 1 on consecutive frames was forwarded, so the arms
/// snapped between the locomotion pose and `q_sdk` at full gains.
#[test]
fn f1_arm_weight_flapping_is_never_forwarded() {
    let mut gw = announced(|_| {});
    let mut now = T0;
    let mut last: Option<f32> = None;
    for (sn, w) in [0.0f32, 1.0, 0.0, 1.0, 0.0, 1.0].into_iter().enumerate() {
        now += 20 * MS;
        let (_, out) = run(&mut gw, &arm_pkt(sn as i64 + 1, &arm_frame(w, 0.0)), now);
        if let Some(fw) = out_weight(&out) {
            if let Some(l) = last {
                assert!(
                    (fw - l).abs() <= 0.02 + 1e-6,
                    "frame {sn}: weight {l} -> {fw} forwarded"
                );
            }
            last = Some(fw);
        }
    }
    assert_eq!(last, Some(0.0), "the weight stays where it was");
    assert!(gw.stats.arm_weight_rejected >= 3, "{:?}", gw.stats);
}

/// F1: a per-frame step within `max_weight_step` but faster than
/// `max_weight_rate_per_s` is refused too (a flood of small steps).
#[test]
fn f1_arm_weight_rate_is_bounded_per_second() {
    let mut gw = announced(|v| {
        v["channels"][1]["max_weight_step"] = serde_json::json!(1.0);
        v["channels"][1]["max_weight_rate_per_s"] = serde_json::json!(0.5);
        v["channels"][1]["engage_first_step"] = serde_json::json!(1.0);
    });
    let mut now = T0;
    now += 20 * MS;
    assert_eq!(
        out_weight(&run(&mut gw, &arm_pkt(1, &arm_frame(0.0, 0.0)), now).1),
        Some(0.0)
    );
    // 0 → 0.5 in 20 ms: 25 /s.
    now += 20 * MS;
    let w = out_weight(&run(&mut gw, &arm_pkt(2, &arm_frame(0.5, 0.0)), now).1);
    assert_eq!(w, Some(0.0), "held at the last accepted weight");
    // 0 → 0.01 in 20 ms: 0.5 /s, accepted.
    now += 20 * MS;
    let w = out_weight(&run(&mut gw, &arm_pkt(3, &arm_frame(0.01, 0.0)), now).1);
    assert_eq!(w, Some(0.01));
}

/// F1, without `rt/lowstate`: the weight may leave 0 only by a small first
/// step, and rise beyond it only after `engage_stable_frames` frames of
/// unchanged arm targets.
#[test]
fn f1_arm_engagement_without_lowstate_needs_stable_targets() {
    let mut gw = announced(|v| {
        v["channels"][1]["engage_stable_frames"] = serde_json::json!(5);
    });
    let mut now = T0;
    let mut sn = 0;
    let mut send = |gw: &mut Gateway, w: f32| {
        sn += 1;
        now += 20 * MS;
        out_weight(&run(gw, &arm_pkt(sn, &arm_frame(w, 0.0)), now).1)
    };
    assert_eq!(send(&mut gw, 0.0), Some(0.0));
    assert_eq!(send(&mut gw, 0.01), Some(0.01));
    assert_eq!(send(&mut gw, 0.02), Some(0.02));
    // Beyond the first step before the targets were stable for 5 frames.
    assert_eq!(send(&mut gw, 0.03), Some(0.02), "held");
    for _ in 0..5 {
        assert_eq!(send(&mut gw, 0.02), Some(0.02));
    }
    assert_eq!(
        send(&mut gw, 0.03),
        Some(0.03),
        "engaged after stable targets"
    );
    let st = serde_json::to_value(gw.stats).unwrap();
    assert!(st["arm_engage_rejected"].as_u64() >= Some(1), "{st}");
}

#[test]
fn f1_weight_settings_are_validated() {
    let base = |k: &str, v: f64| {
        let v = if v.fract() == 0.0 && v >= 1.0 && (k.ends_with("frames") || k.ends_with("_ms")) {
            serde_json::json!(v as u64)
        } else {
            serde_json::json!(v)
        };
        let mut j = serde_json::json!({
            "mode": "enforce", "profile": "/p", "firewall": "/f",
            "queue": {"num": 0, "controller_port": "a", "robot_port": "b"},
            "channels": [{"firewall_channel": "/arm", "codec": "unitree_hg_arm_sdk",
                          "weight_slot": 29}]
        });
        j["channels"][0][k] = v;
        robodr_firewall_gw::config::GatewayConfig::from_json(&j.to_string())
    };
    for (k, v) in [
        ("max_weight_step", 0.5),
        ("max_weight_rate_per_s", 2.0),
        ("engage_first_step", 0.05),
        ("engage_max_q_error", 0.2),
        ("engage_stable_frames", 10.0),
        ("lowstate_max_age_ms", 20.0),
    ] {
        assert!(base(k, v).is_ok(), "{k} = {v} refused: {:?}", base(k, v));
    }
    for (k, v) in [
        ("max_weight_step", 0.0),
        ("max_weight_step", 1.5),
        ("max_weight_rate_per_s", -1.0),
        ("engage_first_step", 2.0),
        ("engage_max_q_error", 0.0),
    ] {
        let mut j = serde_json::json!({
            "mode": "enforce", "profile": "/p", "firewall": "/f",
            "queue": {"num": 0, "controller_port": "a", "robot_port": "b"},
            "channels": [{"firewall_channel": "/arm", "codec": "unitree_hg_arm_sdk",
                          "weight_slot": 29}]
        });
        j["channels"][0][k] = serde_json::json!(v);
        assert!(
            robodr_firewall_gw::config::GatewayConfig::from_json(&j.to_string()).is_err(),
            "{k} = {v} accepted"
        );
    }
}

// ------------------------------------------------------------------ F2

/// F2: the unknown-writer probe used the strict decoders, so a
/// non-canonical twist (XCDR2 representation id, trailing zero octets)
/// from a foreign GUID was classified as nothing and passed unchecked.
#[test]
fn f2_noncanonical_twist_from_a_foreign_writer_is_suppressed() {
    let mut gw = g1_channels_gateway(|_| {});
    let fast = [5.0, 0.0, 0.0, 0.0, 0.0, 3.0];
    let mut x2 = ros2::encode(fast, None, false);
    x2[1] = 0x07; // CDR2_LE
    let mut trailing = ros2::encode(fast, None, false);
    trailing.extend_from_slice(&[0; 8]);
    let mut be_x2 = ros2::encode(fast, None, true);
    be_x2[1] = 0x06; // CDR2_BE
    for (i, p) in [x2, trailing, be_x2].iter().enumerate() {
        assert!(
            ros2::decode_strict(p, false).is_err(),
            "PoC {i} is not canonical"
        );
        let (_, out) = run(&mut gw, &foreign_pkt(i as i64 + 1, p), T0 + i as u64 * MS);
        assert!(out_payload(&out).is_none(), "PoC {i} forwarded");
    }
    // Another foreign writer's non-motion sample still passes (the PoC
    // writer is now classified as `/cmd_vel`: its samples are decided).
    let other = packet(
        ATTACKER_IP,
        DDS_PORT,
        &Datagram::new(FOREIGN)
            .data([0, 0, 0x78, 0x03], 1, &[], &[0, 1, 0, 0, 1, 2, 3, 4])
            .finish(),
    );
    let (v, _) = run(&mut gw, &other, T0 + 10 * MS);
    assert_eq!(v, Verdict::Accept);
}

/// F2: a Dex3 `HandCmd_` with non-zero padding or trailing octets from a
/// foreign GUID was passed the same way.
#[test]
fn f2_noncanonical_dex3_from_a_foreign_writer_is_suppressed() {
    let mut gw = g1_channels_gateway(|_| {});
    let good = hand::encode(Codec::UnitreeDex3HandCmd, &dex3_fingers(0.5, dex3_mode));
    let mut pad = good.clone();
    pad[4 + 4 + 1] = 0x5a; // padding after the first mode octet
    let mut trailing = good.clone();
    trailing.extend_from_slice(&[0, 0, 0, 0, 1]);
    let mut trailing_zero = good.clone();
    trailing_zero.extend_from_slice(&[0; 8]);
    for (i, p) in [pad, trailing, trailing_zero].iter().enumerate() {
        assert!(hand::decode_strict(p, Codec::UnitreeDex3HandCmd, DEX3_MOTORS).is_err());
        let (_, out) = run(&mut gw, &foreign_pkt(i as i64 + 1, p), T0 + i as u64 * MS);
        assert!(out_payload(&out).is_none(), "PoC {i} forwarded");
    }
}

// ------------------------------------------------------------------ F5

/// The SDK's Dex3 mode octet (`g1_dex3_example.cpp:112-121`): motor id in
/// bits 0-3, status 0x01 in bits 4-6, timeout in bit 7.
fn dex3_mode(i: usize) -> u8 {
    (i as u8 & 0x0f) | (0x01 << 4)
}

fn dex3_fingers(q: f32, mode: impl Fn(usize) -> u8) -> Vec<(u8, f32, f32, f32, f32, f32)> {
    (0..DEX3_MOTORS)
        .map(|i| (mode(i), q, 0.0, 0.0, 1.5, 0.1))
        .collect()
}

/// F5: the Dex3 mode octet was not validated: a frame addressing motor
/// ids out of order or with an undocumented status passed.
#[test]
fn f5_dex3_mode_octet_is_validated() {
    let mut gw = announced(|_| {});
    let mut now = T0;
    type ModeFn = Box<dyn Fn(usize) -> u8>;
    let cases: Vec<(&str, ModeFn, bool)> = vec![
        ("sdk", Box::new(dex3_mode), true),
        (
            "id != index",
            Box::new(|i| dex3_mode((i + 1) % DEX3_MOTORS)),
            false,
        ),
        ("status 2", Box::new(|i| (i as u8) | (0x02 << 4)), false),
        ("status 0", Box::new(|i| i as u8), false),
        ("timeout bit", Box::new(|i| dex3_mode(i) | 0x80), true),
    ];
    for (sn, (what, mode, pass)) in cases.into_iter().enumerate() {
        now += 25 * MS;
        let p = hand::encode(Codec::UnitreeDex3HandCmd, &dex3_fingers(0.5, mode));
        let (_, out) = run(&mut gw, &pkt(DEX3_WRITER, sn as i64 + 1, &p), now);
        assert_eq!(out_payload(&out).is_some(), pass, "{what}");
    }
}

fn hand_sdk(weight_mode: u8, other_mode: u8) -> Vec<u8> {
    let m: Vec<_> = (0..HAND_SDK_MOTORS)
        .map(|i| {
            (
                if i == 0 { weight_mode } else { other_mode },
                0.2,
                0.0,
                0.3,
                0.0,
                0.0,
            )
        })
        .collect();
    hand::encode(Codec::UnitreeHandSdk, &m)
}

/// F5: the hand-SDK blend weight (`cmds[0].mode` = weight × 100,
/// `g1_hand_sdk_example.cpp:34-41`) is bounded to 100 and its step per
/// accepted frame to `max_weight_step`; the other elements' mode octets
/// are 0.
#[test]
fn f5_hand_sdk_weight_is_bounded_and_stepped() {
    let mut gw = announced(|_| {});
    let mut now = T0;
    for (sn, (w, other, pass)) in [
        (0u8, 0u8, true),
        (100, 0, false), // 0 → 1 in one frame
        (2, 0, true),
        (4, 0, true),
        (101, 0, false), // above 100
        (4, 1, false),   // a mode octet on another element
    ]
    .into_iter()
    .enumerate()
    {
        // 50 ms: the default rate (0.5 /s) allows 0.025 per frame.
        now += 50 * MS;
        let (_, out) = run(
            &mut gw,
            &pkt(HAND_SDK_WRITER, sn as i64 + 1, &hand_sdk(w, other)),
            now,
        );
        assert_eq!(
            out_payload(&out).is_some(),
            pass,
            "weight {w} other {other}"
        );
    }
}

// ------------------------------------------------------------------ F6

/// F6: the SDK's `stopMotors` (`kp = kd = 0`, timeout bit) is refused by
/// the humanoid all-limp rule unless the hand channel is not
/// balance-critical; the gateway refuses that flag on a non-hand channel.
#[test]
fn f6_hand_release_passes_and_the_flag_is_hands_only() {
    let mut gw = announced(|_| {});
    let stop: Vec<_> = (0..DEX3_MOTORS)
        .map(|i| (dex3_mode(i) | 0x80, 0.0, 0.0, 0.0, 0.0, 0.0))
        .collect();
    let p = hand::encode(Codec::UnitreeDex3HandCmd, &dex3_fingers(0.5, dex3_mode));
    assert!(out_payload(&run(&mut gw, &pkt(DEX3_WRITER, 1, &p), T0).1).is_some());
    let p = hand::encode(Codec::UnitreeDex3HandCmd, &stop);
    let (_, out) = run(&mut gw, &pkt(DEX3_WRITER, 2, &p), T0 + 25 * MS);
    assert!(out_payload(&out).is_some(), "hand release suppressed");
    // `balance_critical: false` on the arm SDK or `rt/lowcmd`: refused.
    for ch in ["/arm_sdk", "/lowcmd"] {
        let mut fw = g1_channels_firewall();
        let mut v = serde_json::to_value(&fw.joint_channels[ch]).unwrap();
        v["balance_critical"] = false.into();
        fw.joint_channels
            .insert(ch.into(), serde_json::from_value(v).unwrap());
        let e = Gateway::new(&g1_channels_config(|_| {}), &g1_channels_profile(), &fw)
            .expect_err("balance_critical false on a body channel");
        assert!(e.contains("balance_critical"), "{e}");
    }
}

// ----------------------------------------------------------------- F10

fn loco(id: i64, param: &str) -> Vec<u8> {
    sport::encode_request(Representation::CdrLe, 42, id, param)
}

fn set_velocity(vx: f64, d: f64) -> String {
    format!("{{\"duration\":{d:.1},\"velocity\":[{vx:.17},0.0,0.0]}}")
}

fn g1_call(p: &[u8]) -> ApiCall {
    sport::decode_strict_for(p, ApiService::Sport, Some(UnitreeModel::G1))
        .expect("strict")
        .call
}

/// The loco channel with an acceleration limit (1.05 m/s²) and a long rest
/// reset (5 s), so the twist state the firewall keeps is observable.
fn loco_gateway(edit: impl FnOnce(&mut serde_json::Value)) -> Gateway {
    let mut fw = g1_channels_firewall();
    let l = fw.channels.get_mut("/loco").unwrap();
    l.max_linear_accel = Some(1.05);
    l.state_reset_after_ns = 5_000_000_000;
    let mut gw = Gateway::new(&g1_channels_config(edit), &g1_channels_profile(), &fw).unwrap();
    announce(
        &mut gw,
        LOCO_WRITER,
        "rt/api/sport/request",
        "unitree_api::msg::dds_::Request_",
    );
    gw
}

/// Ramp to 0.5 m/s at 1 m/s² (0.1 m/s per 100 ms); returns (sn, now).
fn ramp(gw: &mut Gateway) -> (i64, u64) {
    let mut now = T0;
    for k in 1..=5 {
        now += 100 * MS;
        let (v, _) = run(
            gw,
            &pkt(
                LOCO_WRITER,
                k,
                &loco(7105, &set_velocity(k as f64 / 10.0, 1.0)),
            ),
            now,
        );
        assert_eq!(v, Verdict::Accept, "ramp step {k}");
    }
    (5, now)
}

/// F10 (a): `SetVelocity` lasts `duration` (the robot stops after it); the
/// firewall's twist state did not, so 2 s later the same 0.5 m/s was judged
/// as no acceleration although the robot stands.
#[test]
fn f10a_twist_state_expires_with_the_set_velocity_duration() {
    let mut gw = loco_gateway(|_| {});
    let (sn, now) = ramp(&mut gw);
    let later = now + 2_000 * MS;
    let (v, out) = run(
        &mut gw,
        &pkt(LOCO_WRITER, sn + 1, &loco(7105, &set_velocity(0.5, 1.0))),
        later,
    );
    assert_eq!(
        v,
        Verdict::AcceptModified,
        "a jump from rest must be ramped"
    );
    match g1_call(&out_payload(&out).unwrap()) {
        ApiCall::SetVelocity { vx, .. } => assert!(vx <= 0.105 + 1e-6, "{vx}"),
        c => panic!("{c:?}"),
    }
}

/// F10 (b): a query (or an allowlisted call) was checked as a zero twist,
/// which reset the firewall's twist state: the next unchanged velocity was
/// then judged as a jump from zero.
#[test]
fn f10b_queries_do_not_feed_a_zero_twist() {
    let mut gw = loco_gateway(|_| {});
    let (sn, now) = ramp(&mut gw);
    let (v, _) = run(
        &mut gw,
        &pkt(LOCO_WRITER, sn + 1, &loco(7001, "")),
        now + 30 * MS,
    );
    assert_eq!(v, Verdict::Accept, "GetFsmId passes");
    let (v, _) = run(
        &mut gw,
        &pkt(LOCO_WRITER, sn + 2, &loco(7105, &set_velocity(0.5, 1.0))),
        now + 100 * MS,
    );
    assert_eq!(v, Verdict::Accept, "the same velocity is not a jump");
}

/// F10 (c): a malformed `SetVelocity` (negative duration) was turned into
/// a well-formed substitute and forwarded; it is suppressed.
#[test]
fn f10c_malformed_set_velocity_is_suppressed() {
    let mut gw = loco_gateway(|_| {});
    let (sn, now) = ramp(&mut gw);
    for (k, bad) in [
        set_velocity(0.5, -1.0),
        "{\"duration\":1.0,\"velocity\":[0.3,0.0]}".to_string(),
        "{\"velocity\":[0.3,0.0,0.0]}".to_string(),
    ]
    .iter()
    .enumerate()
    {
        let (_, out) = run(
            &mut gw,
            &pkt(LOCO_WRITER, sn + 1 + k as i64, &loco(7105, bad)),
            now + (k as u64 + 1) * 20 * MS,
        );
        assert!(out_payload(&out).is_none(), "malformed {bad} forwarded");
    }
}

/// F10 (e): `Start` (G1 500, H1 204, H2 601, R1 811) hands the robot to
/// the walking controller from any state (also from a damped, lying robot):
/// refused unless the site lists it in `allowed_fsm_ids`.
#[test]
fn f10e_start_needs_the_allowlist() {
    let mut gw = loco_gateway(|_| {});
    let (_, out) = run(
        &mut gw,
        &pkt(LOCO_WRITER, 1, &loco(7101, "{\"data\":500}")),
        T0,
    );
    assert!(out_payload(&out).is_none(), "Start forwarded by default");
    let mut gw = loco_gateway(|v| v["channels"][2]["allowed_fsm_ids"] = serde_json::json!([500]));
    let (v, _) = run(
        &mut gw,
        &pkt(LOCO_WRITER, 1, &loco(7101, "{\"data\":500}")),
        T0,
    );
    assert_eq!(v, Verdict::Accept);
}

/// F10 (f): the G1 arm action service (`rt/api/arm/request`,
/// `g1_arm_action_api.hpp`: `ExecuteAction` 7106, `ExecuteCustomAction`
/// 7108, `StopCustomAction` 7113) had no codec: a channel for it refuses
/// every call but queries unless allowlisted.
#[test]
fn f10f_arm_action_requests_need_the_allowlist() {
    const ARM_ACTION_WRITER: [u8; 4] = [0, 0, 0x08, 0x03];
    let build = |allow: Option<Vec<i64>>| {
        let mut fw: FirewallConfig = g1_channels_firewall();
        fw.channels.insert(
            "/arm_action".into(),
            ChannelSpec {
                kind: ChannelKind::Twist,
                allowed_sources: vec![guid_hex(&PREFIX, ARM_ACTION_WRITER)],
                max_linear_speed: Some(0.1),
                max_angular_speed: Some(0.1),
                ..Default::default()
            },
        );
        let mut profile = g1_channels_profile();
        profile.writer_topics.insert("/arm_action".into());
        profile.motion_envelopes.insert(
            "/arm_action".into(),
            Envelope {
                max_linear_speed: Some(1.5),
                ..Default::default()
            },
        );
        let cfg = g1_channels_config(|v| {
            let mut c = serde_json::json!({"firewall_channel": "/arm_action",
                "codec": "unitree_arm_request", "robot_model": "g1"});
            if let Some(a) = &allow {
                c["allowed_api_ids"] = serde_json::json!(a);
            }
            v["channels"].as_array_mut().unwrap().push(c);
        });
        let mut gw = Gateway::new(&cfg, &profile, &fw).expect("arm request channel");
        announce(
            &mut gw,
            ARM_ACTION_WRITER,
            "rt/api/arm/request",
            "unitree_api::msg::dds_::Request_",
        );
        gw
    };
    let mut gw = build(None);
    let mut now = T0;
    for (sn, (id, param, pass)) in [
        (7106, "{\"action_id\":26}", false),      // ExecuteAction
        (7108, "{\"action_name\":\"x\"}", false), // ExecuteCustomAction
        (7113, "", false),                        // StopCustomAction
        (7107, "", true),                         // GetActionList
        (7999, "", false),
    ]
    .into_iter()
    .enumerate()
    {
        now += 50 * MS;
        let (_, out) = run(
            &mut gw,
            &pkt(ARM_ACTION_WRITER, sn as i64 + 1, &loco(id, param)),
            now,
        );
        assert_eq!(out_payload(&out).is_some(), pass, "api {id}");
    }
    let mut gw = build(Some(vec![7106]));
    let (v, _) = run(
        &mut gw,
        &pkt(ARM_ACTION_WRITER, 1, &loco(7106, "{\"action_id\":26}")),
        T0,
    );
    assert_eq!(v, Verdict::Accept);
}

/// F10 (d): a limited `SetVelocity` is written as decimal text the robot
/// parses into `float`; no written number may read back (as `f32`) above
/// the firewall's limit.
#[test]
fn f10d_rewritten_numbers_never_round_up_as_f32() {
    let mut gw = loco_gateway(|_| {});
    let (mut sn, mut now) = ramp(&mut gw);
    let mut rewritten = 0;
    // Speeds just above the 0.8 limit: the rewrite writes the limit.
    for k in 0..20 {
        sn += 1;
        now += 100 * MS;
        let vx = 0.79 + 0.003 * f64::from(k);
        let (v, out) = run(
            &mut gw,
            &pkt(LOCO_WRITER, sn, &loco(7105, &set_velocity(vx, 1.0))),
            now,
        );
        let Some(p) = out_payload(&out) else { continue };
        if v != Verdict::AcceptModified {
            continue;
        }
        let text = String::from_utf8_lossy(&p).to_string();
        // The decimal text parsed as f32 (what the SDK's `float` holds:
        // nlohmann::json reads a double, the client casts it).
        let start = text.find("velocity\":[").unwrap() + 11;
        let num: String = text[start..]
            .chars()
            .take_while(|c| c.is_ascii_digit() || *c == '.' || *c == '-' || *c == 'e')
            .collect();
        let f = num.parse::<f64>().unwrap() as f32;
        assert!(
            f64::from(f) <= TWIST_MAX_LIN,
            "{num} reads as f32 {f} above the limit {TWIST_MAX_LIN}"
        );
        rewritten += 1;
    }
    assert!(rewritten > 0);
}
