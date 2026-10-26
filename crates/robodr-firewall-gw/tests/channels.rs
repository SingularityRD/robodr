//! The channels added after S8 (README "Channels"): humanoid loco requests
//! (`SetVelocity` limited and duration-capped, `Damp` / `ZeroTorque` /
//! posture FSM states refused unless allowlisted), the arm SDK (`mode 0`
//! slots decided, the blend weight bounded, holds never damp), the Dex3 /
//! hand-SDK hands (pass or suppress), ROS 2 `Twist` / `TwistStamped`, extra
//! queued port ranges with the unqueued-locator warning, and fuzz
//! invariants over all of them.

use std::time::Instant;

use robodr_cdr::unitree::{ApiService, UnitreeModel};
use robodr_cdr::{ApiCall, Representation};
use robodr_firewall_gw::config::Codec;
use robodr_firewall_gw::ip::parse_ipv4_udp;
use robodr_firewall_gw::lowcmd::{self, LowCmdCodec, WireLowCmd};
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
        assert_eq!(p.len(), pkt.len(), "rewrite changed the length");
        parse_ipv4_udp(&p).expect("rewritten packet has valid IP / UDP checksums");
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

/// The fixture gateway with every writer announced by SEDP (as on a robot:
/// the controller's announcements cross the bridge), so no sample depends
/// on the content probe.
fn gw_announced(edit: impl FnOnce(&mut serde_json::Value)) -> Gateway {
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
        let p = packet(CONTROLLER_IP, 7410, &sedp_datagram(PREFIX, w, topic, ty));
        assert_eq!(run(&mut gw, &p, 1).0, Verdict::Accept);
    }
    gw
}

fn pkt(entity: [u8; 4], sn: i64, payload: &[u8]) -> Vec<u8> {
    packet(CONTROLLER_IP, DDS_PORT, &data_datagram(entity, sn, payload))
}

fn loco(id: i64, param: &str) -> Vec<u8> {
    sport::encode_request(Representation::CdrLe, 42, id, param)
}

fn g1_loco_call(p: &[u8]) -> ApiCall {
    sport::decode_strict_for(p, ApiService::Sport, Some(UnitreeModel::G1))
        .expect("forwarded loco request decodes strictly")
        .call
}

// ------------------------------------------------------------------ loco

/// SDK `SetVelocity` text (`nlohmann::json` of `JsonizeVelocityCommand`).
fn set_velocity(vx: f64, vy: f64, w: f64, d: f64) -> String {
    format!("{{\"duration\":{d:.1},\"velocity\":[{vx:.17},{vy:.17},{w:.17}]}}")
}

#[test]
fn loco_set_velocity_is_limited_and_its_duration_capped() {
    let mut gw = g1_channels_gateway(|_| {});
    let mut now = T0;
    let mut sn = 0;
    let mut send = |gw: &mut Gateway, param: &str| {
        sn += 1;
        now += 20 * MS;
        let p = pkt(LOCO_WRITER, sn, &loco(7105, param));
        run(gw, &p, now)
    };
    // Within the envelope, SDK default duration: byte-identical.
    let (v, _) = send(&mut gw, &set_velocity(0.3, 0.0, 0.2, 1.0));
    assert_eq!(v, Verdict::Accept);
    // Too fast: rewritten in place, never above the limit.
    let (v, out) = send(&mut gw, &set_velocity(2.5, 0.0, 0.0, 1.0));
    assert_eq!(v, Verdict::AcceptModified);
    match g1_loco_call(&out_payload(&out).unwrap()) {
        ApiCall::SetVelocity {
            vx,
            vy,
            vyaw,
            duration,
        } => {
            assert!(
                vx.abs() <= TWIST_MAX_LIN && vy.abs() <= TWIST_MAX_LIN,
                "{vx} {vy}"
            );
            assert!(vyaw.abs() <= TWIST_MAX_ANG);
            assert!(duration <= 1.0);
        }
        c => panic!("{c:?}"),
    }
    // `Move(..., continous_move = true)`: 864000 s → capped to 1 s.
    let (v, out) = send(&mut gw, &set_velocity(0.3, 0.0, 0.0, 864000.0));
    assert_eq!(v, Verdict::AcceptModified);
    match g1_loco_call(&out_payload(&out).unwrap()) {
        ApiCall::SetVelocity { vx, duration, .. } => {
            assert_eq!(duration, 1.0);
            assert!(vx > 0.29 && vx <= 0.3000001);
        }
        c => panic!("{c:?}"),
    }
    assert!(gw.stats.duration_capped >= 1);
    // A negative or missing duration is not a velocity command.
    for bad in [
        set_velocity(0.3, 0.0, 0.0, -1.0),
        "{\"velocity\":[0.3,0.0,0.0]}".to_string(),
        "{\"duration\":1.0,\"velocity\":[0.3,0.0]}".to_string(),
    ] {
        let (_, out) = send(&mut gw, &bad);
        if let Some(p) = out_payload(&out) {
            // Only a substitute (a zero / held velocity) may ride on it.
            match g1_loco_call(&p) {
                ApiCall::SetVelocity {
                    vx,
                    vy,
                    vyaw,
                    duration,
                } => {
                    assert!(vx.abs() <= TWIST_MAX_LIN && vy.abs() <= TWIST_MAX_LIN);
                    assert!(vyaw.abs() <= TWIST_MAX_ANG && duration <= 1.0);
                }
                c => panic!("malformed SetVelocity forwarded as {c:?}"),
            }
        }
    }
}

/// Every `SetFsmId` of the G1 client helpers (`unitree_sdk2`
/// `include/unitree/robot/g1/loco/g1_loco_client.hpp`): `ZeroTorque` (0,
/// `:224`), `Damp` (1, `:214`), `Squat` (2, `:218`), `Sit` (3, `:220`),
/// `StandUp` (4, `:222`), any other value and, since review finding F10
/// (e), `Start` (500, `:216`) too are suppressed unless `allowed_fsm_ids`
/// lists them.
#[test]
fn humanoid_never_goes_limp_through_loco() {
    let refused = [0i64, 1, 2, 3, 4, 702, 706, 999];
    let mut gw = g1_channels_gateway(|_| {});
    let mut now = T0;
    for (i, fsm) in refused.iter().enumerate() {
        now += 20 * MS;
        let p = pkt(
            LOCO_WRITER,
            i as i64 + 1,
            &loco(7101, &format!("{{\"data\":{fsm}}}")),
        );
        let (v, out) = run(&mut gw, &p, now);
        assert_eq!(v, Verdict::AcceptModified, "fsm {fsm}");
        assert!(out_payload(&out).is_none(), "fsm {fsm} forwarded");
    }
    assert_eq!(gw.stats.loco_refused, refused.len() as u64);
    now += 20 * MS;
    let p = pkt(LOCO_WRITER, 100, &loco(7101, "{\"data\":500}"));
    assert!(
        out_payload(&run(&mut gw, &p, now).1).is_none(),
        "Start needs the allowlist"
    );
    // Hand-over / tricks / unknown ids / sport ids: refused; queries pass.
    for (j, (id, param, pass)) in [
        (7110, "{}", false),           // SwitchToUserCtrl: hands the motors to rt/lowcmd
        (7106, "{\"data\":1}", false), // SetArmTask
        (7100, "{}", false),           // FsmApi
        (7104, "{\"data\":0.1}", false), // SetStandHeight
        (7999, "{}", false),           // unknown
        (1008, "{\"x\":0.1,\"y\":0,\"z\":0}", false), // a sport Move: not G1 loco
        (7001, "", true),              // GetFsmId
    ]
    .into_iter()
    .enumerate()
    {
        now += 20 * MS;
        let p = pkt(LOCO_WRITER, 200 + j as i64, &loco(id, param));
        let (v, out) = run(&mut gw, &p, now);
        assert_eq!(out_payload(&out).is_some(), pass, "api {id}: {v:?}");
    }
    // The site may allow a posture call explicitly.
    let mut gw = g1_channels_gateway(|v| {
        v["channels"][2]["allowed_fsm_ids"] = serde_json::json!([4]);
        v["channels"][2]["allowed_api_ids"] = serde_json::json!([7104]);
    });
    let p = pkt(LOCO_WRITER, 1, &loco(7101, "{\"data\":4}"));
    assert_eq!(run(&mut gw, &p, T0).0, Verdict::Accept);
    let p = pkt(LOCO_WRITER, 2, &loco(7101, "{\"data\":1}"));
    assert!(out_payload(&run(&mut gw, &p, T0 + 20 * MS).1).is_none());
    let p = pkt(LOCO_WRITER, 3, &loco(7104, "{\"data\":0.1}"));
    assert_eq!(run(&mut gw, &p, T0 + 40 * MS).0, Verdict::Accept);
}

/// H1's client is service `loco` (`h1_loco_api.hpp:11`) with ids 8xxx:
/// `Damp` 8101 `{"data":1}` (`h1_loco_client.hpp:224`) refused, `Start`
/// 204 (`:226`) passes, `SetVelocity` 8105 limited.
#[test]
fn h1_loco_on_its_own_topic() {
    let mut gw = g1_channels_gateway(|v| {
        v["channels"][2]["robot_model"] = serde_json::json!("h1");
        v["channels"][2]["allowed_fsm_ids"] = serde_json::json!([204]);
    });
    let h1 = |p: &[u8]| {
        sport::decode_strict_for(p, ApiService::Loco, Some(UnitreeModel::H1))
            .unwrap()
            .call
    };
    let p = pkt(LOCO_WRITER, 1, &loco(8101, "{\"data\":1}"));
    assert!(out_payload(&run(&mut gw, &p, T0).1).is_none());
    let p = pkt(LOCO_WRITER, 2, &loco(8101, "{\"data\":204}"));
    assert_eq!(run(&mut gw, &p, T0 + 20 * MS).0, Verdict::Accept);
    let p = pkt(
        LOCO_WRITER,
        3,
        &loco(8105, &set_velocity(3.0, 0.0, 0.0, 1.0)),
    );
    let (v, out) = run(&mut gw, &p, T0 + 40 * MS);
    assert_eq!(v, Verdict::AcceptModified);
    match h1(&out_payload(&out).unwrap()) {
        ApiCall::SetVelocity { vx, .. } => assert!(vx <= TWIST_MAX_LIN),
        c => panic!("{c:?}"),
    }
    // The G1 ids mean nothing on H1's service.
    let p = pkt(
        LOCO_WRITER,
        4,
        &loco(7105, &set_velocity(0.1, 0.0, 0.0, 1.0)),
    );
    assert!(out_payload(&run(&mut gw, &p, T0 + 60 * MS).1).is_none());
}

#[test]
fn sport_codec_is_refused_for_a_humanoid() {
    let cfg = g1_channels_config(|v| {
        v["channels"][2] = serde_json::json!(
            {"firewall_channel": "/loco", "codec": "unitree_sport_request"});
    });
    let e = Gateway::new(&cfg, &g1_channels_profile(), &g1_channels_firewall()).unwrap_err();
    assert!(e.contains("unitree_loco_request"), "{e}");
}

#[test]
fn foreign_loco_writer_is_suppressed() {
    let mut gw = g1_channels_gateway(|_| {});
    let p = packet(
        CONTROLLER_IP,
        DDS_PORT,
        &robodr_firewall_gw::rtps::build::Datagram::new(FOREIGN)
            .data(
                LOCO_WRITER,
                1,
                &[],
                &loco(7105, &set_velocity(0.1, 0.0, 0.0, 1.0)),
            )
            .finish(),
    );
    assert!(out_payload(&run(&mut gw, &p, T0).1).is_none());
}

// --------------------------------------------------------------- arm SDK

fn arm_pkt(sn: i64, m: &WireLowCmd) -> Vec<u8> {
    pkt(
        ARM_WRITER,
        sn,
        &lowcmd::encode_payload(m, Representation::CdrLe),
    )
}

fn out_arm(pkt: &[u8]) -> Option<WireLowCmd> {
    let p = out_payload(pkt)?;
    let d = lowcmd::decode_strict(&p, LowCmdCodec::Hg).expect("forwarded arm frame is strict");
    assert!(d.msg.crc_ok());
    Some(d.msg)
}

/// The arm channel with the blend weight's dynamics opened up (a full
/// weight on the first frame), so the joint checks are what is tested
/// here; the dynamics are in `tests/exec_gw_review.rs`.
fn open_weight(v: &mut serde_json::Value) {
    v["channels"][1]["max_weight_step"] = serde_json::json!(1.0);
    v["channels"][1]["max_weight_rate_per_s"] = serde_json::json!(1000.0);
    v["channels"][1]["engage_first_step"] = serde_json::json!(1.0);
}

#[test]
fn arm_sdk_mode_zero_slots_are_enforced_and_the_weight_bounded() {
    let mut gw = gw_announced(open_weight);
    let good = arm_frame(1.0, 0.0);
    let (v, _) = run(&mut gw, &arm_pkt(1, &good), T0);
    assert_eq!(
        v,
        Verdict::Accept,
        "an SDK-style frame (mode 0 + gains) passes"
    );
    // Out of the joint range on a mode-0 arm slot: limited in place, mode
    // octets and the weight kept.
    let mut far = arm_frame(1.0, 0.0);
    let mut m = far.motor(18).unwrap();
    m.q += 0.12; // within one step, above nothing yet
    far.set_motor(18, m);
    let mut m = far.motor(15).unwrap();
    m.q = 2.9; // above left_shoulder_pitch q_max 2.6704
    far.set_motor(15, m);
    far.seal();
    let (v, out) = run(&mut gw, &arm_pkt(2, &far), T0 + 2 * MS);
    assert_eq!(v, Verdict::AcceptModified);
    let o = out_arm(&out).expect("limited, not suppressed");
    assert!(f64::from(o.motor(15).unwrap().q) <= 2.6704 + 1e-6);
    for i in 0..35 {
        assert_eq!(
            o.motor(i).unwrap().mode,
            far.motor(i).unwrap().mode,
            "mode {i}"
        );
    }
    assert_eq!(o.motor(29), far.motor(29), "weight slot kept");
    let accepted = o;
    // The weight out of [0, max_weight], or carrying gains: integrity
    // failure → hold of the last accepted frame (never damping).
    for (k, w) in [1.5f32, -0.1, f32::NAN].into_iter().enumerate() {
        let bad = arm_frame(w, 0.0);
        let (_, out) = run(
            &mut gw,
            &arm_pkt(3 + k as i64, &bad),
            T0 + (4 + 2 * k as u64) * MS,
        );
        if let Some(o) = out_arm(&out) {
            for i in 0..35 {
                assert_eq!(o.motor(i), accepted.motor(i), "hold slot {i} (weight {w})");
            }
        }
    }
    assert!(gw.stats.arm_weight_rejected >= 3);
    // Gains on a leg slot (disabled on this channel): rejected → hold.
    let mut leg = arm_frame(1.0, 0.0);
    let mut m = leg.motor(3).unwrap();
    m.kp = 50.0;
    m.q = 0.5;
    leg.set_motor(3, m);
    leg.seal();
    let (_, out) = run(&mut gw, &arm_pkt(10, &leg), T0 + 20 * MS);
    if let Some(o) = out_arm(&out) {
        assert_eq!(o.motor(3).unwrap().kp, 0.0, "leg gains never forwarded");
        assert_eq!(o.motor(29), accepted.motor(29));
    }
}

#[test]
fn arm_sdk_with_nothing_accepted_is_suppressed() {
    let mut gw = gw_announced(|_| {});
    let (_, out) = run(&mut gw, &arm_pkt(1, &arm_frame(2.0, 0.0)), T0);
    assert!(out_arm(&out).is_none(), "no hold without an accepted frame");
}

// ------------------------------------------------------------------ hands

/// Hand elements with the SDK's mode octets: Dex3 `id | status 1 << 4`
/// (`g1_dex3_example.cpp:112-121`), hand SDK 0 (a weight of 0 in
/// `cmds[0]`).
fn fingers_for(codec: Codec, n: usize, q: f32) -> Vec<(u8, f32, f32, f32, f32, f32)> {
    (0..n)
        .map(|i| {
            let mode = if codec == Codec::UnitreeDex3HandCmd {
                (i as u8 & 0x0f) | 0x10
            } else {
                0
            };
            (mode, q, 0.0, 0.0, 2.0, 0.1)
        })
        .collect()
}

#[test]
fn hands_pass_or_are_suppressed() {
    let mut gw = g1_channels_gateway(|_| {});
    let mut now = T0;
    for (entity, codec, n) in [
        (DEX3_WRITER, Codec::UnitreeDex3HandCmd, DEX3_MOTORS),
        (HAND_SDK_WRITER, Codec::UnitreeHandSdk, HAND_SDK_MOTORS),
    ] {
        for (sn, (payload, pass)) in [
            (hand::encode(codec, &fingers_for(codec, n, 0.5)), true),
            (hand::encode(codec, &fingers_for(codec, n, 3.0)), false), // q out of range
            (hand::encode(codec, &fingers_for(codec, n + 1, 0.5)), false), // wrong count
            (hand::encode(codec, &fingers_for(codec, n, f32::NAN)), false),
            (hand::encode(codec, &fingers_for(codec, n, 0.4)), true),
        ]
        .into_iter()
        .enumerate()
        {
            now += 5 * MS;
            let p = pkt(entity, sn as i64 + 1, &payload);
            let (v, out) = run(&mut gw, &p, now);
            assert_eq!(out_payload(&out).is_some(), pass, "{codec:?} {sn}");
            if pass {
                assert_eq!(v, Verdict::Accept, "forwarded unchanged");
            }
        }
    }
    assert_eq!(gw.stats.hand_passed, 4);
    assert_eq!(gw.stats.hand_suppressed, 6);
}

// ------------------------------------------------------------ ROS 2 twist

#[test]
fn ros2_twist_uses_the_twist_firewall() {
    for stamped in [false, true] {
        let mut gw = g1_channels_gateway(|v| {
            if stamped {
                v["channels"][5]["codec"] = serde_json::json!("ros2_twist_stamped");
            }
        });
        let st = stamped.then_some((1, 2, "base_link"));
        let mut now = T0;
        let mut sn = 0;
        let mut send = |gw: &mut Gateway, v: [f64; 6]| {
            sn += 1;
            now += 20 * MS;
            run(gw, &pkt(TWIST_WRITER, sn, &ros2::encode(v, st, false)), now)
        };
        assert_eq!(
            send(&mut gw, [0.2, 0.0, 0.0, 0.0, 0.0, 0.3]).0,
            Verdict::Accept
        );
        let (v, out) = send(&mut gw, [3.0, 0.0, 0.0, 0.0, 0.0, -2.0]);
        assert_eq!(v, Verdict::AcceptModified);
        let w = ros2::decode_strict(&out_payload(&out).unwrap(), stamped).unwrap();
        let lin = (w.values[0].powi(2) + w.values[1].powi(2) + w.values[2].powi(2)).sqrt();
        assert!(lin <= TWIST_MAX_LIN + 1e-9 && w.values[5].abs() <= TWIST_MAX_ANG + 1e-9);
        // Non-finite: never forwarded as sent.
        let (_, out) = send(&mut gw, [f64::NAN, 0.0, 0.0, 0.0, 0.0, 0.0]);
        if let Some(p) = out_payload(&out) {
            let w = ros2::decode_strict(&p, stamped).unwrap();
            assert!(w.values.iter().all(|x| x.is_finite()));
        }
        // A Twist on a TwistStamped channel (and vice versa) is undecidable.
        let other = ros2::encode(
            [0.1; 6],
            if stamped { None } else { Some((0, 0, "x")) },
            false,
        );
        sn += 1;
        let (_, out) = run(&mut gw, &pkt(TWIST_WRITER, sn, &other), now + 20 * MS);
        if let Some(p) = out_payload(&out) {
            assert!(
                ros2::decode_strict(&p, stamped).is_ok(),
                "forwarded undecidable"
            );
        }
    }
}

// ------------------------------------------ extra ports, locator warning

#[test]
fn extra_port_ranges_are_decided_and_unqueued_locators_flagged() {
    let mut gw = g1_channels_gateway(|v| {
        v["rtps"] = serde_json::json!({"extra_port_ranges": [[30000, 30100]]});
    });
    // A Damp to a non-default DDS port inside an extra range: decided.
    let damp = data_datagram(LOCO_WRITER, 1, &loco(7101, "{\"data\":1}"));
    let (_, out) = run(&mut gw, &packet(CONTROLLER_IP, 30050, &damp), T0);
    assert!(out_payload(&out).is_none(), "decided on an extra port");
    // Outside every range: not the gateway's (the ruleset does not queue it).
    let (v, _) = run(&mut gw, &packet(CONTROLLER_IP, 31000, &damp), T0 + MS);
    assert_eq!(v, Verdict::Accept);
    assert_eq!(gw.stats.unmatched_port, 1);
    // Discovery: a locator inside the queued ranges is fine ...
    let ok = sedp_with_locator(
        PREFIX,
        LOCO_WRITER,
        "rt/api/sport/request",
        "unitree_api::msg::dds_::Request_",
        false,
        CONTROLLER_IP,
        30010,
    );
    run(&mut gw, &packet(CONTROLLER_IP, 7410, &ok), T0 + 2 * MS);
    assert!(gw.discovery().port_bypass().is_none());
    assert_eq!(gw.discovery().stats.unqueued_locators, 0);
    // ... a reader of an enforced topic at an unqueued port is flagged.
    let bad = sedp_with_locator(
        [9; 12],
        [0, 0, 1, 4],
        "rt/lowcmd",
        "unitree_hg::msg::dds_::LowCmd_",
        true,
        ROBOT_IP,
        45123,
    );
    run(&mut gw, &packet(CONTROLLER_IP, 7410, &bad), T0 + 3 * MS);
    assert_eq!(gw.discovery().stats.unqueued_locators, 1);
    let w = gw.discovery().port_bypass().unwrap();
    assert!(
        w.contains("reader of enforced topic rt/lowcmd") && w.contains(":45123"),
        "{w}"
    );
    // Not an enforced topic: not this check's business.
    let other = sedp_with_locator(
        [8; 12],
        [0, 0, 1, 4],
        "rt/lowstate",
        "x",
        true,
        ROBOT_IP,
        45124,
    );
    run(&mut gw, &packet(CONTROLLER_IP, 7410, &other), T0 + 4 * MS);
    assert_eq!(gw.discovery().stats.unqueued_locators, 1);
}

// ------------------------------------------------------------------- fuzz

struct Rng(u64);
impl Rng {
    fn next(&mut self) -> u64 {
        self.0 ^= self.0 << 13;
        self.0 ^= self.0 >> 7;
        self.0 ^= self.0 << 17;
        self.0
    }
    fn below(&mut self, n: usize) -> usize {
        (self.next() % n as u64) as usize
    }
}

/// Mutated packets of every new channel: no panic, accept = unchanged,
/// rewrite = same length + valid checksums (`run`), and what is forwarded
/// on an enforced channel stays inside the invariants: no loco `SetFsmId`
/// (none is allowlisted), no `SetVelocity` above the limits or the 1 s
/// duration, no arm frame with a weight outside `[0, 1]`, a weight step
/// above `max_weight_step` from the last forwarded one or gains on a
/// disabled slot, no hand frame or ROS 2 twist outside its envelope, no
/// Dex3 element addressing another motor.
#[test]
fn fuzz_invariants_of_the_new_channels() {
    let mut rng = Rng(0x9e37_79b9_7f4a_7c15);
    let seeds: Vec<([u8; 4], Vec<u8>)> = vec![
        (LOCO_WRITER, loco(7105, &set_velocity(0.3, 0.1, 0.2, 1.0))),
        (LOCO_WRITER, loco(7101, "{\"data\":500}")),
        (
            ARM_WRITER,
            lowcmd::encode_payload(&arm_frame(0.0, 0.0), Representation::CdrLe),
        ),
        (
            ARM_WRITER,
            lowcmd::encode_payload(&arm_frame(0.01, 0.0), Representation::CdrLe),
        ),
        (
            DEX3_WRITER,
            hand::encode(
                Codec::UnitreeDex3HandCmd,
                &fingers_for(Codec::UnitreeDex3HandCmd, DEX3_MOTORS, 0.3),
            ),
        ),
        (
            HAND_SDK_WRITER,
            hand::encode(
                Codec::UnitreeHandSdk,
                &fingers_for(Codec::UnitreeHandSdk, HAND_SDK_MOTORS, 0.3),
            ),
        ),
        (
            TWIST_WRITER,
            ros2::encode([0.2, 0.0, 0.0, 0.0, 0.0, 0.1], None, false),
        ),
    ];
    let mut gw = gw_announced(|_| {});
    let mut now = T0;
    let mut last_weight: Option<f32> = None;
    for round in 0..6000u64 {
        let (entity, seed) = &seeds[rng.below(seeds.len())];
        let mut payload = seed.clone();
        for _ in 0..1 + rng.below(4) {
            let i = rng.below(payload.len());
            match rng.below(4) {
                0 => payload[i] ^= 1 << rng.below(8),
                1 => payload[i] = rng.next() as u8,
                2 => payload[i] = b"0123456789.-e{}[],\" "[rng.below(20)],
                _ => payload[i] = 0,
            }
        }
        now += MS + rng.below(20) as u64 * MS;
        let p = pkt(*entity, round as i64 + 1, &payload);
        let (_, out) = run(&mut gw, &p, now);
        let Some(fwd) = out_payload(&out) else {
            continue;
        };
        match *entity {
            LOCO_WRITER => match g1_loco_call(&fwd) {
                ApiCall::SetVelocity {
                    vx,
                    vy,
                    vyaw,
                    duration,
                } => {
                    assert!(
                        vx.abs() <= TWIST_MAX_LIN + 1e-6
                            && vy.abs() <= TWIST_MAX_LIN + 1e-6
                            && vyaw.abs() <= TWIST_MAX_ANG + 1e-6
                            && duration.is_finite()
                            && (0.0..=1.0).contains(&duration),
                        "round {round}: {vx} {vy} {vyaw} {duration}"
                    );
                }
                ApiCall::SetFsmId { fsm_id, .. } => {
                    panic!("round {round}: SetFsmId {fsm_id} forwarded (none allowlisted)")
                }
                ApiCall::Other { class, .. } => {
                    assert_eq!(class, robodr_cdr::unitree::ApiClass::Query, "round {round}")
                }
                c => panic!("round {round}: forwarded {c:?}"),
            },
            ARM_WRITER => {
                let d = lowcmd::decode_strict(&fwd, LowCmdCodec::Hg).expect("strict");
                assert!(d.msg.crc_ok());
                let w = d.msg.motor(29).unwrap();
                assert!((0.0..=1.0).contains(&w.q) && w.kp == 0.0 && w.kd == 0.0 && w.tau == 0.0);
                if let Some(l) = last_weight {
                    assert!(
                        (w.q - l).abs() <= 0.02 + 1e-6,
                        "round {round}: weight {l} -> {}",
                        w.q
                    );
                }
                last_weight = Some(w.q);
                for i in 0..15 {
                    let m = d.msg.motor(i).unwrap();
                    assert!(
                        m.kp == 0.0 && m.kd == 0.0 && m.tau == 0.0,
                        "round {round} slot {i}"
                    );
                }
            }
            DEX3_WRITER | HAND_SDK_WRITER => {
                assert_eq!(fwd, payload, "hands are only passed unchanged");
                let codec = if *entity == DEX3_WRITER {
                    Codec::UnitreeDex3HandCmd
                } else {
                    Codec::UnitreeHandSdk
                };
                let n = if *entity == DEX3_WRITER {
                    DEX3_MOTORS
                } else {
                    HAND_SDK_MOTORS
                };
                let f = hand::decode_hand(&fwd, codec, n).expect("strict").frame;
                assert!(f
                    .motors()
                    .iter()
                    .all(|m| m.q.abs() <= HAND_Q && m.kp <= 5.0 && m.tau.abs() <= 2.0));
            }
            _ => {
                let w = ros2::decode_strict(&fwd, false).expect("strict");
                let lin = (w.values[0].powi(2) + w.values[1].powi(2) + w.values[2].powi(2)).sqrt();
                assert!(lin <= TWIST_MAX_LIN + 1e-9, "round {round}: {:?}", w.values);
            }
        }
    }
    // The run exercised every outcome.
    let st = gw.stats;
    assert!(st.passed > 100 && st.suppressed > 100, "{st:?}");
    assert!(
        st.limited + st.substituted + st.duration_capped > 0,
        "{st:?}"
    );
    assert!(st.hand_passed > 0 && st.hand_suppressed > 0, "{st:?}");
}
