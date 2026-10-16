//! Harness: link-layer decode (`decode_frame`) and IPv4/IPv6 fragment
//! reassembly (`Reassembler`), directly and through the `rtps_datagrams`
//! pipeline, with small resource limits so eviction paths run.
//!
//! Input format (so a fuzzer can build multi-frame fragment trains):
//!
//! ```text
//! [link selector u8] { [dt u8] [len u16 BE] [frame: len bytes] }*
//! ```
//!
//! `link selector % LINKTYPES.len()` picks the link type of every frame;
//! `dt` advances the capture clock by `dt * 50 ms` (so reassembly timeouts
//! fire); a short last frame takes what is left. Invariants beyond "no
//! panic": a decoded UDP payload is a sub-slice of its frame, reassembly
//! never holds more than its limits allow, a reassembled payload is at most
//! 65 535 bytes, and the pipeline counts every frame exactly once.
#![allow(dead_code)]

use std::time::Duration;

use robodr_capture::{
    decode_frame, rtps_datagrams, Decoded, LinkType, Reassembler, ReassemblyLimits, VecSource,
};

pub const LINKTYPES: [LinkType; 9] = [
    LinkType::ETHERNET,
    LinkType::RAW,
    LinkType::LINUX_SLL,
    LinkType::LINUX_SLL2,
    LinkType::NULL,
    LinkType::LOOP,
    LinkType::IPV4,
    LinkType::IPV6,
    LinkType(12345),
];

pub fn limits() -> ReassemblyLimits {
    ReassemblyLimits {
        max_datagrams: 8,
        max_bytes: 32 * 1024,
        max_bytes_per_dst: 16 * 1024,
        timeout: Duration::from_millis(500),
        timeout_v6: Duration::from_millis(700),
        ..Default::default()
    }
}

/// Split the input into `(ts, linktype, frame)` triples.
pub fn frames(data: &[u8]) -> Vec<(Duration, LinkType, Vec<u8>)> {
    let Some((&sel, mut rest)) = data.split_first() else {
        return Vec::new();
    };
    let lt = LINKTYPES[sel as usize % LINKTYPES.len()];
    let mut ts = Duration::ZERO;
    let mut out = Vec::new();
    while rest.len() >= 3 {
        ts += Duration::from_millis(u64::from(rest[0]) * 50);
        let len = usize::from(u16::from_be_bytes([rest[1], rest[2]]));
        rest = &rest[3..];
        let take = len.min(rest.len());
        out.push((ts, lt, rest[..take].to_vec()));
        rest = &rest[take..];
    }
    out
}

/// Encode frames in the harness input format (seed generation).
pub fn encode(link_selector: u8, frames: &[(u8, Vec<u8>)]) -> Vec<u8> {
    let mut v = vec![link_selector];
    for (dt, f) in frames {
        v.push(*dt);
        v.extend_from_slice(&(f.len() as u16).to_be_bytes());
        v.extend_from_slice(f);
    }
    v
}

pub fn run(data: &[u8]) {
    let frames = frames(data);
    let lim = limits();
    let mut reasm = Reassembler::new(lim);
    for (ts, lt, frame) in &frames {
        match decode_frame(*lt, frame) {
            Ok(Decoded::Udp(u)) => {
                let fr = frame.as_ptr_range();
                let pr = u.payload.as_ptr_range();
                assert!(
                    fr.start <= pr.start && pr.end <= fr.end,
                    "payload outside frame"
                );
                let _ = robodr_rtps::parse_datagram(u.payload, &u.src.to_string());
            }
            Ok(Decoded::Fragment(f)) => {
                if let Some(r) = reasm.push(*ts, &f) {
                    assert!(r.payload.len() <= 65_535, "reassembled {}", r.payload.len());
                }
                // Limits apply per IP version.
                assert!(reasm.in_flight() <= 2 * lim.max_datagrams, "in flight");
                assert!(
                    reasm.buffered_bytes() <= 2 * (lim.max_bytes + 65_535 + 1024),
                    "buffered {}",
                    reasm.buffered_bytes()
                );
            }
            Err(_) => {}
        }
    }
    let n = frames.len() as u64;
    let mut it = rtps_datagrams(VecSource::new(frames)).with_reassembly_limits(lim);
    while let Some(pkt) = it.next_packet() {
        assert!(pkt.payload.len() <= 65_535);
        let _ = robodr_rtps::parse_datagram(&pkt.payload, &pkt.src.to_string());
    }
    assert_eq!(it.stats().frames, n, "frame count");
}
