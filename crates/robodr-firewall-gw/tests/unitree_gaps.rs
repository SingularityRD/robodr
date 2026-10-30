//! The Unitree coverage gaps closed on the gateway: the Go1 compressed
//! `LowCmd` channel (`go1_low_cmd_compressed`), the A2 / AS2 low-level
//! channel (`unitree_a2_lowcmd`), `bms.off` on the legacy channels, and the
//! Go2 WebRTC flow block (`webrtc` section of the ruleset).

use std::time::Instant;

use robodr_cdr::unitree_legacy::{LegacyLowCmdCompressed, LEGACY_LOW_CMD_COMPRESSED_LEN};
use robodr_cdr::Representation;
use robodr_firewall_gw::config::{Codec, GatewayConfig, OnGatewayDown};
use robodr_firewall_gw::ip::parse_ipv4_udp;
use robodr_firewall_gw::lowcmd::{self, LowCmdCodec, WireLowCmd};
use robodr_firewall_gw::rtps::{self, Content, WalkOptions};
use robodr_firewall_gw::testkit::*;
use robodr_firewall_gw::{legacy, Gateway, PacketMeta, Verdict};

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

fn payload(pkt: &[u8]) -> Vec<u8> {
    let ip = parse_ipv4_udp(pkt).unwrap();
    pkt[ip.payload()].to_vec()
}

// ------------------------------------------------------------ Go1 compressed

fn compressed_config() -> GatewayConfig {
    let mut c = gateway_config(Fixture::Go2);
    let ch = c
        .channels
        .iter_mut()
        .find(|c| c.firewall_channel == "/legacy/low_cmd")
        .unwrap();
    ch.codec = Codec::Go1LowCmdCompressed;
    c
}

fn compressed_gateway() -> Gateway {
    Gateway::new(
        &compressed_config(),
        &profile(Fixture::Go2),
        &firewall(Fixture::Go2),
    )
    .unwrap()
}

/// Every enabled slot of the Go2 example at mid range, `tau` 0, `kp` 20,
/// `kd` 1 (all exactly representable in the compressed fixed point).
fn mid_motors() -> Vec<(u8, [f32; 5])> {
    let spec = lowcmd_spec(Fixture::Go2);
    let mut motors = vec![(0u8, [0f32; 5]); 20];
    for (i, m) in spec.motors.iter().enumerate() {
        if m.enabled {
            let q = ((m.q_min.unwrap() + m.q_max.unwrap()) / 2.0) as f32;
            motors[i] = (0x0A, [q, 0.0, 0.0, 20.0, 1.0]);
        }
    }
    motors
}

fn low_pkt(frame: &[u8]) -> Vec<u8> {
    packet(CONTROLLER_IP, 8007, frame)
}

#[test]
fn compressed_low_cmd_is_decided_limited_and_held() {
    let mut gw = compressed_gateway();
    let motors = mid_motors();
    let ok = legacy::build_low_compressed(&motors);
    assert_eq!(ok.len(), LEGACY_LOW_CMD_COMPRESSED_LEN);
    // A valid frame passes byte-identical.
    assert_eq!(run(&mut gw, &low_pkt(&ok), T0).0, Verdict::Accept);

    // Torque over the envelope (23.7) but inside 2x: limited in place, the
    // fixed-point value on the safe side of the bound.
    let mut over = motors.clone();
    over[0].1[2] = 30.0;
    let (v, out) = run(
        &mut gw,
        &low_pkt(&legacy::build_low_compressed(&over)),
        T0 + 2 * MS,
    );
    assert_eq!(v, Verdict::AcceptModified);
    let f = payload(&out);
    assert!(legacy::crc_ok(&f));
    let d = LegacyLowCmdCompressed::decode(&f).unwrap();
    let tau = f64::from(d.motor_cmd[0].tau());
    assert!(tau <= 23.7 && tau > 23.7 - 1.0 / 256.0, "{tau}");
    // Every other field untouched.
    let input = LegacyLowCmdCompressed::decode(&legacy::build_low_compressed(&over)).unwrap();
    for i in 1..20 {
        assert_eq!(d.motor_cmd[i], input.motor_cmd[i], "{i}");
    }

    // Hard violation (4x): the hold of the last accepted frame, written
    // into the same datagram (no datagram of the gateway's own).
    over[0].1[2] = 100.0;
    let (v, out) = run(
        &mut gw,
        &low_pkt(&legacy::build_low_compressed(&over)),
        T0 + 4 * MS,
    );
    assert_eq!(v, Verdict::AcceptModified);
    let held = LegacyLowCmdCompressed::decode(&payload(&out)).unwrap();
    assert!(f64::from(held.motor_cmd[0].tau()) <= 23.7);
    assert!(legacy::crc_ok(&payload(&out)));

    // CRC mismatch: integrity failure, held (never forwarded as sent).
    let mut bad = legacy::build_low_compressed(&motors);
    bad[30] ^= 0x01;
    let (v, out) = run(&mut gw, &low_pkt(&bad), T0 + 6 * MS);
    assert_ne!(v, Verdict::Accept);
    if v == Verdict::AcceptModified {
        assert!(legacy::crc_ok(&payload(&out)));
        assert_ne!(payload(&out), bad);
    }

    // NaN position: rejected, never forwarded as sent.
    let mut nan = motors.clone();
    nan[1].1[0] = f32::NAN;
    let (v, out) = run(
        &mut gw,
        &low_pkt(&legacy::build_low_compressed(&nan)),
        T0 + 8 * MS,
    );
    assert_ne!(v, Verdict::Accept);
    if v == Verdict::AcceptModified {
        let d = LegacyLowCmdCompressed::decode(&payload(&out)).unwrap();
        assert!(d.motor_cmd.iter().all(|m| m.q().is_finite()));
    }

    // A negative gain (what an out-of-range Kp wraps to on the sender)
    // is out of the envelope: never forwarded as sent.
    let mut neg = motors.clone();
    neg[0].1[3] = -20.0;
    let (v, _) = run(
        &mut gw,
        &low_pkt(&legacy::build_low_compressed(&neg)),
        T0 + 10 * MS,
    );
    assert_ne!(v, Verdict::Accept);

    // Battery off: refused like an integrity failure; whatever is
    // forwarded carries bms.off = 0.
    let mut off = legacy::build_low_compressed(&motors);
    off[legacy::LOWC_BMS_AT] = 0xA5;
    legacy::seal(&mut off);
    let (v, out) = run(&mut gw, &low_pkt(&off), T0 + 12 * MS);
    assert_ne!(v, Verdict::Accept);
    if v == Verdict::AcceptModified {
        assert_eq!(payload(&out)[legacy::LOWC_BMS_AT], 0);
    }

    // The declared 734-octet form on the compressed channel, truncation
    // and extension: undecidable, and a substitute of another length is
    // never written: dropped.
    for len in [
        LEGACY_LOW_CMD_COMPRESSED_LEN - 1,
        LEGACY_LOW_CMD_COMPRESSED_LEN + 1,
    ] {
        let mut b = legacy::build_low_compressed(&motors);
        b.resize(len, 0);
        assert_eq!(
            run(&mut gw, &low_pkt(&b), T0 + 14 * MS).0,
            Verdict::Drop,
            "{len}"
        );
    }
    assert_eq!(
        run(&mut gw, &low_pkt(&legacy::build_low(&motors)), T0 + 16 * MS).0,
        Verdict::Drop
    );

    // A foreign sender (unlisted IP): dropped.
    let spoof = packet(ATTACKER_IP, 8007, &legacy::build_low_compressed(&motors));
    assert_eq!(run(&mut gw, &spoof, T0 + 18 * MS).0, Verdict::Drop);
    assert!(gw.stats.undecidable >= 4);
}

#[test]
fn compressed_low_cmd_before_any_accepted_frame_never_invents_motion() {
    let mut gw = compressed_gateway();
    let mut over = mid_motors();
    over[0].1[2] = 100.0;
    let (v, out) = run(&mut gw, &low_pkt(&legacy::build_low_compressed(&over)), T0);
    // Nothing was accepted yet: the substitute rides on the SDK template
    // (every motor off) or the datagram is dropped.
    if v == Verdict::AcceptModified {
        let d = LegacyLowCmdCompressed::decode(&payload(&out)).unwrap();
        for m in &d.motor_cmd {
            assert!(m.tau_q.unsigned_abs() as f64 / 256.0 <= 23.7);
            assert!(m.kp() <= 100.0);
        }
    } else {
        assert_eq!(v, Verdict::Drop);
    }
}

#[test]
fn compressed_and_declared_channels_cannot_share_the_port() {
    let mut c = compressed_config();
    let mut extra = c
        .channels
        .iter()
        .find(|c| c.firewall_channel == "/legacy/low_cmd")
        .unwrap()
        .clone();
    extra.firewall_channel = "/legacy/low_cmd_declared".into();
    extra.codec = Codec::Go1LowCmd;
    c.channels.push(extra);
    let e = c.validate().unwrap_err();
    assert!(e.contains("8007"), "{e}");
    assert_eq!(
        Codec::Go1LowCmdCompressed.as_str(),
        "go1_low_cmd_compressed"
    );
    assert_eq!(Codec::Go1LowCmdCompressed.default_ports(), &[8007]);
    assert!(!Codec::Go1LowCmdCompressed.is_rtps());
    assert_eq!(Codec::Go1LowCmdCompressed.slots(), Some(20));
    let j: GatewayConfig = GatewayConfig::from_json(
        &serde_json::json!({
            "mode": "observe", "profile": "/p", "firewall": "/f",
            "queue": {"num": 0, "controller_port": "a", "robot_port": "b"},
            "channels": [{"firewall_channel": "/l", "codec": "go1_low_cmd_compressed"}]
        })
        .to_string(),
    )
    .unwrap();
    assert_eq!(j.legacy_ports(), vec![8007]);
}

#[test]
fn legacy_high_cmd_battery_off_is_never_forwarded() {
    let mut gw = gateway(Fixture::Go2);
    let good = legacy::build_high(2, 0.5, 0.0, 0.0);
    assert_eq!(
        run(&mut gw, &packet(CONTROLLER_IP, 8082, &good), T0).0,
        Verdict::Accept
    );
    let mut off = legacy::build_high(2, 0.5, 0.0, 0.0);
    off[legacy::HIGH_BMS_AT] = 0xA5;
    legacy::seal(&mut off);
    let (v, out) = run(&mut gw, &packet(CONTROLLER_IP, 8082, &off), T0 + 20 * MS);
    assert_ne!(v, Verdict::Accept);
    if v == Verdict::AcceptModified {
        assert_eq!(payload(&out)[legacy::HIGH_BMS_AT], 0);
    }
    // And on the declared LowCmd channel.
    let mut low = legacy::build_low(&mid_motors());
    assert_eq!(
        run(&mut gw, &packet(CONTROLLER_IP, 8007, &low), T0 + 40 * MS).0,
        Verdict::Accept
    );
    low[legacy::LOW_BMS_AT] = 0xA5;
    legacy::seal(&mut low);
    let (v, out) = run(&mut gw, &packet(CONTROLLER_IP, 8007, &low), T0 + 42 * MS);
    assert_ne!(v, Verdict::Accept);
    if v == Verdict::AcceptModified {
        assert_eq!(payload(&out)[legacy::LOW_BMS_AT], 0);
    }
}

// ------------------------------------------------------------------ A2 / AS2

const GO_TYPE: &str = "unitree_go::msg::dds_::LowCmd_";
const HG_TYPE: &str = "unitree_hg::msg::dds_::LowCmd_";

fn a2_config() -> GatewayConfig {
    let v = serde_json::json!({
        "mode": "enforce",
        "profile": "/nonexistent/profile.json",
        "firewall": "/nonexistent/firewall.json",
        "queue": { "num": 0, "controller_port": "ctrl0", "robot_port": "robot0" },
        "channels": [{ "firewall_channel": "/lowcmd", "codec": "unitree_a2_lowcmd" }],
    });
    GatewayConfig::from_json(&v.to_string()).unwrap()
}

fn a2_profile(t: Option<&str>) -> robodr_events::profile::Profile {
    let mut p = profile(Fixture::Go2);
    if let Some(t) = t {
        p.motion_types.insert("/lowcmd".into(), t.into());
    }
    p
}

fn a2_gateway() -> Gateway {
    Gateway::new(
        &a2_config(),
        &a2_profile(Some(GO_TYPE)),
        &firewall(Fixture::Go2),
    )
    .unwrap()
}

fn go_frame(phase: f64) -> WireLowCmd {
    let spec = lowcmd_spec(Fixture::Go2);
    mid_frame(LowCmdCodec::Go, &spec.motors, phase, (None, None))
}

fn go_pkt(sn: i64, msg: &WireLowCmd) -> Vec<u8> {
    packet(
        CONTROLLER_IP,
        DDS_PORT,
        &lowcmd_datagram(PREFIX, WRITER, sn, msg, Representation::CdrLe),
    )
}

fn out_go(pkt: &[u8]) -> Option<WireLowCmd> {
    let ip = parse_ipv4_udp(pkt).unwrap();
    let d = &pkt[ip.payload()];
    let mut v = Vec::new();
    rtps::walk(d, WalkOptions::default(), &mut v).unwrap();
    let s = v
        .iter()
        .find(|s| !s.builtin && s.content == Content::Data)?;
    let slot = &d[s.payload.clone().unwrap()];
    let dec = lowcmd::decode_strict(slot, LowCmdCodec::Go).ok()?;
    Some(dec.msg)
}

#[test]
fn a2_channel_refuses_unverified_shortcuts() {
    let fw = firewall(Fixture::Go2);
    // The type must be recorded in the profile (learned on the robot).
    let e = Gateway::new(&a2_config(), &a2_profile(None), &fw)
        .err()
        .unwrap();
    assert!(e.contains("inferred"), "{e}");
    // ... and be the go LowCmd_: an hg type (another model's layout) is
    // refused at start.
    let e = Gateway::new(&a2_config(), &a2_profile(Some(HG_TYPE)), &fw)
        .err()
        .unwrap();
    assert!(e.contains(HG_TYPE), "{e}");
    // require_crc is mandatory.
    let mut nocrc = fw.clone();
    nocrc.joint_channels.get_mut("/lowcmd").unwrap().require_crc = false;
    let e = Gateway::new(&a2_config(), &a2_profile(Some(GO_TYPE)), &nocrc)
        .err()
        .unwrap();
    assert!(e.contains("require_crc"), "{e}");
    // bypass on gateway down is refused.
    let mut by = a2_config();
    by.queue.on_gateway_down = OnGatewayDown::Bypass;
    let e = Gateway::new(&by, &a2_profile(Some(GO_TYPE)), &fw)
        .err()
        .unwrap();
    assert!(e.contains("bypass"), "{e}");
    // allow_battery_off is a configuration error.
    let mut bat = a2_config();
    bat.channels[0].allow_battery_off = true;
    assert!(bat.validate().is_err());
    assert_eq!(Codec::UnitreeA2Lowcmd.dds_type_name(), GO_TYPE);
    assert_eq!(Codec::UnitreeA2Lowcmd.default_topic(), Some("rt/lowcmd"));
    assert_eq!(Codec::UnitreeA2Lowcmd.as_str(), "unitree_a2_lowcmd");
}

#[test]
fn a2_channel_enforces_like_unitree_go_lowcmd_and_rejects_aliases() {
    let mut gw = a2_gateway();
    let sedp = packet(
        CONTROLLER_IP,
        DDS_PORT,
        &sedp_datagram(PREFIX, WRITER, "rt/lowcmd", GO_TYPE),
    );
    assert_eq!(run(&mut gw, &sedp, T0).0, Verdict::Accept);
    let good = go_frame(0.0);
    assert_eq!(
        run(&mut gw, &go_pkt(1, &good), T0 + 2 * MS).0,
        Verdict::Accept
    );
    // Over-torque: limited in place, CRC recomputed.
    let mut over = go_frame(0.1);
    let mut w = over.motor(0).unwrap();
    w.tau = 30.0;
    over.set_motor(0, w);
    over.seal();
    let (v, out) = run(&mut gw, &go_pkt(2, &over), T0 + 4 * MS);
    assert_eq!(v, Verdict::AcceptModified);
    let m = out_go(&out).unwrap();
    assert!(m.crc_ok());
    assert!(f64::from(m.motor(0).unwrap().tau) <= 23.7);
    // CRC mismatch: never forwarded as sent.
    let mut bad = go_frame(0.2);
    bad.seal();
    let mut w = bad.motor(1).unwrap();
    w.kp += 1.0;
    bad.set_motor(1, w); // not resealed
    let (v, out) = run(&mut gw, &go_pkt(3, &bad), T0 + 6 * MS);
    assert_ne!(v, Verdict::Accept);
    if let Some(m) = out_go(&out) {
        assert!(m.crc_ok());
    }
    // Model aliasing: a 35-slot hg frame (a humanoid's layout) on the A2
    // writer cannot be decoded as the go type: never forwarded as sent.
    let g1 = lowcmd_spec(Fixture::G1);
    let hg = mid_frame(
        LowCmdCodec::Hg,
        &g1.motors,
        0.0,
        (g1.pinned_mode_pr, g1.pinned_mode_machine),
    );
    let (v, out) = run(&mut gw, &go_pkt(4, &hg), T0 + 8 * MS);
    assert_ne!(v, Verdict::Accept);
    if let Some(m) = out_go(&out) {
        assert!(m.crc_ok());
    }
    // Truncated payload: never forwarded as sent.
    let full = lowcmd_datagram(PREFIX, WRITER, 5, &good, Representation::CdrLe);
    let mut cut = full.clone();
    cut.truncate(full.len() - 40);
    let (v, _) = run(
        &mut gw,
        &packet(CONTROLLER_IP, DDS_PORT, &cut),
        T0 + 10 * MS,
    );
    assert_ne!(v, Verdict::Accept);
    assert!(gw.stats.undecidable >= 1, "the hg frame is undecidable");
}
