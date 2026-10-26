//! Harness: the in-path gateway's packet path (`robodr-firewall-gw`):
//! IPv4 / UDP framing, the strict RTPS walker, SEDP learning, the strict
//! `LowCmd_` / sport `Request_` / Go1 legacy decoders, the firewall
//! decision and the in-place rewrites; plus the NFQUEUE netlink parser.
//!
//! Input: byte 0 = flags (bit 0: Go2 fixture with sport + legacy channels,
//! else G1; bit 1: observe mode). Then records `len (u16 LE) | kind (u8) |
//! len bytes`: `kind & 3` = 0 RTPS from the controller IP to a DDS port,
//! 1 RTPS from another IP, 2 Go1 `HighCmd` port, 3 Go1 `LowCmd` port. Each
//! record is wrapped in a valid IPv4 / UDP packet (so the payload, not the
//! checksum, is what gets explored) and processed at 2 ms steps; `kind >> 2`
//! adds 0..63 ms. The whole input is also fed to the NFQUEUE parser.
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
//! - no forwarded enforced go `LowCmd_` carries `bms_cmd.off != 0`.
#![allow(dead_code)]

use std::time::Instant;

use robodr_firewall_gw::config::{Codec, GatewayMode};
use robodr_firewall_gw::ip::parse_ipv4_udp;
use robodr_firewall_gw::lowcmd::{self, LowCmdCodec};
use robodr_firewall_gw::rtps::{self, Content, WalkOptions};
use robodr_firewall_gw::testkit::{self, Fixture};
use robodr_firewall_gw::{legacy, nfq, sport, Gateway, PacketMeta, Verdict};

pub fn run(data: &[u8]) {
    nfq::parse_packets(data, |_| {});
    let Some((&flags, mut rest)) = data.split_first() else {
        return;
    };
    let fx = if flags & 1 == 0 {
        Fixture::G1
    } else {
        Fixture::Go2
    };
    let mut cfg = testkit::gateway_config(fx);
    let observe = flags & 2 != 0;
    if observe {
        cfg.mode = GatewayMode::Observe;
    }
    let codecs: Vec<Codec> = cfg.channels.iter().map(|c| c.codec).collect();
    let Ok(mut gw) = Gateway::new(&cfg, &testkit::profile(fx), &testkit::firewall(fx)) else {
        panic!("fixture gateway must build");
    };
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
        now += 2_000_000 + u64::from(kind >> 2) * 1_000_000;
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
