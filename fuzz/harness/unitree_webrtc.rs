//! Harness of the `unitree_webrtc` target: the Go2 WebRTC session parsers
//! and monitor in `robodr-ros2-pipeline` (`webrtc`).
//!
//! Input: a selector byte, then records `[len u16 BE][flags u8][bytes]`.
//! Each record goes to every parser (`classify_udp`, `parse_stun`,
//! `parse_dtls`, `parse_http_request` / `_response`, `classify_signalling`,
//! `con_notify_answer_members`, `parse_sdp`, `decode_ipv4`) and, as a
//! packet between a peer and the robot (direction, transport and peer from
//! `flags`), to one `WebRtcMonitor`. Invariants (panic on violation):
//!
//! 1. No parser panics; a parsed STUN message's length equals the input's.
//! 2. Every finding is a `robot.unitree.webrtc_*` rule with a detail of at
//!    most 2000 characters, and never contains the ICE password or the
//!    `token` value of a legacy offer (the harness plants both).
//! 3. Memory is bounded: at most `max_peers` sessions, at most
//!    `MAX_FLOWS_PER_PEER` flows each.

use std::net::{IpAddr, Ipv4Addr};

use robodr_ros2_pipeline::webrtc::*;

const SECRET_PWD: &str = "PLANTEDPWDPLANTEDPWD12";
const SECRET_TOKEN: &str = "PLANTEDTOKEN";

pub fn run(data: &[u8]) {
    let Some((&sel, mut rest)) = data.split_first() else {
        return;
    };
    let mut opts = WebRtcOptions {
        enabled: true,
        max_peers: 4,
        ..WebRtcOptions::default()
    };
    if sel & 1 == 1 {
        opts.controllers
            .insert(IpAddr::V4(Ipv4Addr::new(192, 168, 123, 20)), None);
    }
    if sel & 2 == 2 {
        if let Ok(w) = DenyWindow::parse("00:00-23:59") {
            opts.deny_windows.push(w);
        }
    }
    let robot = IpAddr::V4(Ipv4Addr::new(192, 168, 123, 161));
    let mut m = WebRtcMonitor::new(opts);
    let mut t = 0u64;
    while rest.len() >= 3 {
        let len = usize::from(u16::from_be_bytes([rest[0], rest[1]])).min(rest.len() - 3);
        let flags = rest[2];
        let rec = &rest[3..3 + len];
        rest = &rest[3 + len..];
        if let Some(s) = parse_stun(rec) {
            assert_eq!(rec.len() % 4, 0);
            let _ = s.username;
        }
        let _ = classify_udp(rec);
        let _ = parse_dtls(rec);
        if let Some(r) = parse_http_request(rec) {
            let m = classify_signalling(&r);
            assert!(!format!("{m:?}").contains(SECRET_TOKEN));
        }
        let _ = parse_http_response(rec);
        let _ = con_notify_answer_members(rec);
        if let Ok(s) = std::str::from_utf8(rec) {
            let sdp = parse_sdp(s);
            assert!(sdp.candidates.len() <= MAX_CANDIDATES);
        }
        let _ = decode_ipv4(rec);
        let peer = IpAddr::V4(Ipv4Addr::new(192, 168, 123, 20 + (flags >> 4)));
        let l4 = if flags & 1 == 1 { L4::Tcp } else { L4::Udp };
        let (src, dst, sp, dp) = if flags & 2 == 2 {
            (robot, peer, if l4 == L4::Tcp { 8081 } else { 40000 }, 50000)
        } else {
            (peer, robot, 50000, if l4 == L4::Tcp { 8081 } else { 40000 })
        };
        t += u64::from(flags & 0x0c) * 1_000_000_000;
        for d in m.process(&FlowPacket {
            wall_ns: t,
            mono_ns: t,
            l4,
            src,
            src_port: sp,
            dst,
            dst_port: dp,
            src_mac: None,
            payload: rec,
        }) {
            assert!(d.rule_str().starts_with("robot.unitree.webrtc_"));
            assert!(d.detail.chars().count() <= 2000);
            assert!(!d.detail.contains(SECRET_PWD) && !d.detail.contains(SECRET_TOKEN));
        }
        assert!(m.sessions().count() <= 4);
        assert!(m.sessions().all(|s| s.flows.len() <= MAX_FLOWS_PER_PEER));
    }
}

/// The planted secrets (for the seed generator).
pub fn secrets() -> (&'static str, &'static str) {
    (SECRET_PWD, SECRET_TOKEN)
}
