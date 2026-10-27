//! Harness: the in-path gateway's packet path (`robodr-firewall-gw`):
//! IPv4 / UDP framing, the strict RTPS walker, SEDP learning, the strict
//! `LowCmd_` / sport `Request_` / Go1 legacy decoders, the firewall
//! decision and the in-place rewrites; plus the NFQUEUE netlink parser.
//!
//! Input: byte 0 = flags (bit 0: Go2 fixture with sport + legacy channels,
//! else G1; bit 1: observe mode; bit 2: the G1 fixture with the arm-SDK,
//! loco, Dex3, hand-SDK and ROS 2 twist channels, overriding bit 0). Then
//! records `len (u16 LE) | kind (u8) | len bytes`: `kind & 3` = 0 RTPS
//! from the controller IP to a DDS port, 1 RTPS from another IP, 2 Go1
//! `HighCmd` port, 3 Go1 `LowCmd` port; `kind & 0x80`: instead a
//! robot-side packet (RTPS from the robot to the controller) handed to the
//! observer (`Gateway::observe`, the NFLOG copy path: `rt/lowstate`, robot
//! discovery). Each record is wrapped in a valid IPv4 / UDP packet (so the
//! payload, not the checksum, is what gets explored) and processed at 2 ms
//! steps; `(kind >> 2) & 0x1f` adds 0..31 ms. The whole input is also fed
//! to the NFQUEUE and NFLOG parsers.
//!
//! Invariants beyond "no panic":
//! - `Accept` leaves the packet byte-identical; `AcceptModified` keeps its
//!   length and yields valid IP / UDP checksums; observe mode always
//!   accepts unchanged;
//! - in enforce mode, every user DATA left in a forwarded datagram whose
//!   writer the gateway classified to an enforced channel decodes
//!   **strictly** (canonical CDR) and, for `LowCmd_`, carries a valid
//!   Unitree CRC: the gateway never forwards an enforced sample it could
//!   not read;
//! - every forwarded Go1 frame on an enforced port has a valid CRC;
//! - in enforce mode, no DATA_FRAG / key-only / non-standard sample of a
//!   writer the gateway has no classification for is forwarded (it could
//!   not be probed);
//! - no forwarded enforced go `LowCmd_` carries `bms_cmd.off != 0`;
//! - channels fixture: no forwarded arm-SDK frame with a weight outside
//!   `[0, 1]` or a weight step above `max_weight_step` (0.02) from the
//!   previous forwarded one; no forwarded loco `SetFsmId` (none is
//!   allowlisted), malformed request or `SetVelocity` longer than 1 s; no
//!   forwarded hand frame whose mode octets / weight are not the SDK's
//!   (strict `decode_hand`); no forwarded twist that is not canonical
//!   XCDR1.
#![allow(dead_code)]

use std::time::Instant;

use robodr_firewall_gw::config::{Codec, GatewayMode};
use robodr_firewall_gw::ip::parse_ipv4_udp;
use robodr_firewall_gw::lowcmd::{self, LowCmdCodec};
use robodr_firewall_gw::rtps::{self, Content, WalkOptions};
use robodr_firewall_gw::testkit::{self, Fixture};
use robodr_firewall_gw::{hand, legacy, nflog, nfq, ros2, sport, Gateway, PacketMeta, Verdict};

pub fn run(data: &[u8]) {
    nfq::parse_packets(data, |_| {});
    nflog::parse_packets(data, |_| {});
    let Some((&flags, mut rest)) = data.split_first() else {
        return;
    };
    let fx = if flags & 1 == 0 {
        Fixture::G1
    } else {
        Fixture::Go2
    };
    let channels = flags & 4 != 0;
    let mut cfg = if channels {
        testkit::g1_channels_config(|_| {})
    } else {
        testkit::gateway_config(fx)
    };
    let observe = flags & 2 != 0;
    if observe {
        cfg.mode = GatewayMode::Observe;
    }
    let codecs: Vec<Codec> = cfg.channels.iter().map(|c| c.codec).collect();
    let built = if channels {
        Gateway::new(
            &cfg,
            &testkit::g1_channels_profile(),
            &testkit::g1_channels_firewall(),
        )
    } else {
        Gateway::new(&cfg, &testkit::profile(fx), &testkit::firewall(fx))
    };
    let Ok(mut gw) = built else {
        panic!("fixture gateway must build");
    };
    let mut last_weight: Option<f32> = None;
    let mut now = 1_000_000_000u64;
    let mut records = 0;
    while rest.len() >= 3 && records < 64 {
        records += 1;
        let len = usize::from(u16::from_le_bytes([rest[0], rest[1]]));
        let kind = rest[2];
        let body = &rest[3..3 + len.min(rest.len() - 3)];
        rest = &rest[3 + body.len()..];
        let (src, port) = match kind & 3 {
            0 => (testkit::CONTROLLER_IP, testkit::DDS_PORT),
            1 => (testkit::ATTACKER_IP, testkit::DDS_PORT),
            2 => (testkit::CONTROLLER_IP, 8082),
            _ => (testkit::CONTROLLER_IP, 8007),
        };
        if body.len() > 60_000 {
            continue;
        }
        now += 2_000_000 + u64::from((kind >> 2) & 0x1f) * 1_000_000;
        if kind & 0x80 != 0 {
            // The robot side: observed only, never verdicted.
            gw.observe(
                &testkit::robot_packet(testkit::DDS_PORT, body),
                PacketMeta {
                    now_ns: now,
                    queue_delay_ns: None,
                    instant: Instant::now(),
                    src_mac: None,
                },
            );
            continue;
        }
        let pkt = testkit::packet(src, port, body);
        let mut out = pkt.clone();
        let v = gw.process(
            &mut out,
            PacketMeta {
                now_ns: now,
                queue_delay_ns: None,
                instant: Instant::now(),
                src_mac: None,
            },
        );
        match v {
            Verdict::Accept | Verdict::Drop => assert_eq!(out, pkt, "{v:?} changed the packet"),
            Verdict::AcceptModified => {
                assert_eq!(out.len(), pkt.len());
                assert!(parse_ipv4_udp(&out).is_ok(), "rewritten packet checksums");
            }
        }
        if observe {
            assert_eq!(v, Verdict::Accept, "observe mode always accepts");
            continue;
        }
        if v == Verdict::Drop {
            continue;
        }
        let Ok(ip) = parse_ipv4_udp(&out) else {
            continue;
        };
        let d = &out[ip.payload()];
        if port == 8082 || port == 8007 {
            if fx == Fixture::Go2 {
                assert!(legacy::crc_ok(d), "forwarded Go1 frame has a valid CRC");
            }
            continue;
        }
        let mut samples = Vec::new();
        if rtps::walk(d, WalkOptions::default(), &mut samples).is_err() {
            continue;
        }
        for s in samples.iter().filter(|s| !s.builtin) {
            if gw.discovery().writer(&s.writer).is_none() {
                assert!(
                    s.kind == rtps::SampleKind::Data
                        && !s.non_standard
                        && s.content != Content::Key,
                    "an unknown writer's unprobeable sample was forwarded"
                );
            }
        }
        for s in samples
            .iter()
            .filter(|s| !s.builtin && s.content == Content::Data)
        {
            let Some(ch) = gw.discovery().writer(&s.writer).and_then(|w| w.channel) else {
                continue;
            };
            let Some(r) = s.payload.clone() else { continue };
            let slot = &d[r];
            match codecs.get(ch) {
                Some(Codec::UnitreeGoLowcmd) | Some(Codec::UnitreeHgLowcmd) => {
                    let c = if codecs.get(ch) == Some(&Codec::UnitreeGoLowcmd) {
                        LowCmdCodec::Go
                    } else {
                        LowCmdCodec::Hg
                    };
                    let m = lowcmd::decode_strict(slot, c)
                        .expect("forwarded enforced LowCmd decodes strictly");
                    assert!(m.msg.crc_ok(), "forwarded enforced LowCmd has a valid CRC");
                    assert!(
                        lowcmd::non_motor_ok(&m.msg, false),
                        "forwarded enforced LowCmd turns the battery off"
                    );
                }
                Some(Codec::UnitreeSportRequest) => {
                    sport::decode_strict(slot, None)
                        .expect("forwarded sport request decodes strictly");
                }
                Some(Codec::UnitreeHgArmSdk) => {
                    let m = lowcmd::decode_strict(slot, LowCmdCodec::Hg)
                        .expect("forwarded arm frame decodes strictly");
                    assert!(m.msg.crc_ok(), "forwarded arm frame has a valid CRC");
                    let w = m.msg.motor(29).map_or(f32::NAN, |x| x.q);
                    assert!((0.0..=1.0).contains(&w), "forwarded arm weight {w}");
                    if let Some(l) = last_weight {
                        assert!(
                            (w - l).abs() <= 0.02 + 1e-6,
                            "forwarded arm weight step {l} -> {w}"
                        );
                    }
                    last_weight = Some(w);
                }
                Some(Codec::UnitreeLocoRequest) => {
                    let r = sport::decode_strict_for(
                        slot,
                        robodr_cdr::unitree::ApiService::Sport,
                        Some(robodr_cdr::unitree::UnitreeModel::G1),
                    )
                    .expect("forwarded loco request decodes strictly");
                    match r.call {
                        robodr_cdr::ApiCall::SetVelocity { duration, .. } => {
                            assert!((0.0..=1.0).contains(&duration), "duration {duration}")
                        }
                        robodr_cdr::ApiCall::SetFsmId { .. }
                        | robodr_cdr::ApiCall::Malformed { .. }
                        | robodr_cdr::ApiCall::Unknown { .. } => {
                            panic!("forwarded loco call {:?}", r.call)
                        }
                        _ => {}
                    }
                }
                Some(c @ (Codec::UnitreeDex3HandCmd | Codec::UnitreeHandSdk)) => {
                    let n = if *c == Codec::UnitreeDex3HandCmd {
                        testkit::DEX3_MOTORS
                    } else {
                        testkit::HAND_SDK_MOTORS
                    };
                    hand::decode_hand(slot, *c, n).expect("forwarded hand frame is the SDK's");
                }
                Some(Codec::Ros2Twist) => {
                    ros2::decode_strict(slot, false).expect("forwarded twist is canonical");
                }
                _ => {}
            }
        }
    }
}

/// Encode one record (seed generation).
pub fn record(kind: u8, body: &[u8]) -> Vec<u8> {
    let mut v = (body.len() as u16).to_le_bytes().to_vec();
    v.push(kind);
    v.extend_from_slice(body);
    v
}
