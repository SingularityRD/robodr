//! Passive packet capture for RoboDR: turns captured frames into RTPS
//! datagrams for the discovery parser.
//!
//! # Why
//! DDS participants announce themselves with SPDP on a multicast group, but
//! announce their *endpoints* (which topics they write and read — e.g. a
//! foreign writer on `rt/cmd_vel`) with SEDP, which most vendors send
//! **unicast** to each peer's metatraffic port. A sensor that only joins the
//! SPDP multicast group never sees it. This crate observes the traffic
//! passively instead, from a live `AF_PACKET` socket or from capture files,
//! and hands each RTPS payload to `robodr_rtps::parse_datagram`:
//!
//! ```no_run
//! # fn main() -> Result<(), Box<dyn std::error::Error>> {
//! use robodr_capture::{rtps_datagrams, CaptureFile};
//! let file = CaptureFile::open("discovery.pcapng")?;
//! for (src_ip, payload) in rtps_datagrams(file) {
//!     for event in robodr_rtps::parse_datagram(&payload, &src_ip) {
//!         // feed the graph / profile
//!         let _ = event;
//!     }
//! }
//! # Ok(())
//! # }
//! ```
//!
//! Live (Linux, `CAP_NET_RAW`), looping across read timeouts so the caller
//! can stop cleanly:
//!
//! ```no_run
//! # #[cfg(target_os = "linux")]
//! # fn main() -> Result<(), Box<dyn std::error::Error>> {
//! use robodr_capture::afpacket::{AfPacketConfig, AfPacketSource};
//! use robodr_capture::rtps_datagrams;
//! let src = AfPacketSource::open(&AfPacketConfig::default())?;
//! let mut datagrams = rtps_datagrams(src).with_frame_budget(1024);
//! let shutdown = || false;
//! while !shutdown() && !datagrams.is_finished() {
//!     for (src_ip, payload) in datagrams.by_ref() {
//!         let _events = robodr_rtps::parse_datagram(&payload, &src_ip);
//!     }
//! }
//! # Ok(())
//! # }
//! # #[cfg(not(target_os = "linux"))]
//! # fn main() {}
//! ```
//!
//! # Pipeline
//! 1. [`PacketSource`]: [`CaptureFile`] (classic pcap or pcapng, see
//!    [`pcap`]), [`afpacket::AfPacketSource`] (Linux live), or [`VecSource`].
//! 2. [`decode`]: Ethernet II (+ up to two VLAN tags), Linux cooked SLL/SLL2,
//!    raw IP, BSD NULL/LOOP -> IPv4 / IPv6 (extension headers walked) -> UDP.
//!    Pure functions, no `unsafe`, bounds-checked, fuzzed.
//! 3. [`reassembly`]: bounded IPv4/IPv6 fragment reassembly, so a large or
//!    deliberately fragmented SEDP announcement is not missed. Conflicting
//!    overlaps drop the datagram (and are counted).
//! 4. [`ports`]: [`RtpsFilter`] = DDSI-RTPS well-known ports and/or the
//!    `"RTPS"` magic (see the module docs for the trade-off).
//! 5. [`RtpsDatagrams`]: the glue iterator yielding `(src_ip, payload)`.
//!    [`bpf`] compiles the same filter to a kernel socket filter.
//!
//! # Read-only guarantee
//! Nothing in this crate can transmit. The live reader declares no send or
//! write function at all, does not enable promiscuous mode, and never sets up
//! a TX ring; the only writer ([`pcap::PcapWriter`]) writes capture files.
//!
//! # Privileges
//! File replay needs none. Live capture needs `CAP_NET_RAW`; see
//! [`afpacket`]. All `unsafe` code lives in that one module
//! (`#![deny(unsafe_code)]` elsewhere).
//!
//! # Limits — what packet capture cannot see
//! - **Shared-memory transports are invisible.** Fast DDS enables its SHM
//!   transport by default for participants on the same host, Cyclone DDS can
//!   use Iceoryx shared memory, and Connext has its own SHMEM transport. Such
//!   traffic never touches a network interface, not even loopback. For
//!   same-host discovery this depends on the vendor and version (Fast DDS
//!   still sends SPDP/SEDP over UDP while data goes over SHM; with
//!   data-sharing / Iceoryx, user data is invisible here). Per-vendor
//!   validation and an SHM observation path are Sprint 2 follow-ups.
//! - RTPS over TCP (Fast DDS TCP transport, Connext TCP/TLS) is not decoded.
//! - DDS Security with RTPS-level protection (SRTPS) or encrypted discovery
//!   hides topic names; the RTPS header (participant GUID) is still visible.
//! - Jumbograms, IPsec ESP and tunnels other than VLAN are not decoded.
//! - Snap-length-limited captures (`tcpdump -s 96`) yield truncated frames,
//!   which are counted and dropped, not parsed.
//! - IP/UDP checksums are not verified (offload makes them unreliable on the
//!   capturing host).

#![deny(unsafe_code)]

#[cfg(all(
    target_os = "linux",
    any(
        target_arch = "x86_64",
        target_arch = "x86",
        target_arch = "aarch64",
        target_arch = "arm",
        target_arch = "riscv64"
    )
))]
#[allow(unsafe_code)]
pub mod afpacket;
pub mod bpf;
pub mod decode;
pub mod pcap;
pub mod ports;
pub mod reassembly;
pub mod source;
pub mod synth;

use std::net::IpAddr;
use std::time::Duration;

pub use decode::{decode_frame, decode_udp, DecodeError, Decoded, LinkType, UdpDatagram};
pub use pcap::{CaptureFile, PcapNgReader, PcapReader, PcapWriter};
pub use ports::{MatchMode, PortClass, PortKind, RtpsFilter, RtpsPortMap};
pub use reassembly::{Reassembler, ReassemblyLimits};
pub use source::{CaptureError, Packet, PacketSource, VecSource};

/// One RTPS datagram with its context.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RtpsPacket {
    pub ts: Duration,
    pub src: IpAddr,
    pub dst: IpAddr,
    pub src_port: u16,
    pub dst_port: u16,
    /// Well-known-port meaning of `dst_port`, `None` if the datagram was
    /// accepted by the magic on a non-standard port (worth reporting).
    pub port_class: Option<PortClass>,
    /// Recovered from IP fragments.
    pub reassembled: bool,
    pub payload: Vec<u8>,
}

/// Counters kept by [`RtpsDatagrams`].
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct CaptureStats {
    pub frames: u64,
    pub udp: u64,
    pub rtps: u64,
    /// UDP datagrams the [`RtpsFilter`] rejected.
    pub filtered_out: u64,
    pub not_ip: u64,
    pub not_udp: u64,
    pub truncated: u64,
    pub malformed: u64,
    pub unsupported_linktype: u64,
    pub fragments: u64,
    pub reassembled: u64,
    /// Transient source errors (live read timeouts).
    pub timeouts: u64,
    /// Calls that returned early because the frame budget ran out.
    pub budget_yields: u64,
}

/// Iterator glue: packet source -> decoders -> reassembly -> RTPS filter.
///
/// As an [`Iterator`] it yields `(src_ip, payload)`; use
/// [`next_packet`](Self::next_packet) for the full [`RtpsPacket`].
///
/// End of iteration: for files, at end of file or on a fatal error (see
/// [`last_error`](Self::last_error)); for live sources, `None` is also
/// returned on each read timeout so the caller can check for shutdown and
/// simply iterate again ([`is_finished`](Self::is_finished) stays false).
/// On a busy link the source may never time out while every frame is
/// filtered; set [`with_frame_budget`](Self::with_frame_budget) for live
/// sources so a call also returns `None` after that many non-RTPS frames.
#[derive(Debug)]
pub struct RtpsDatagrams<S> {
    source: S,
    filter: RtpsFilter,
    reassembler: Reassembler,
    stats: CaptureStats,
    last_error: Option<CaptureError>,
    finished: bool,
    frame_budget: Option<usize>,
}

/// [`RtpsDatagrams`] with the default filter (ROS 2 domain 0 ports or the
/// RTPS magic) and default reassembly limits.
pub fn rtps_datagrams<S: PacketSource>(source: S) -> RtpsDatagrams<S> {
    RtpsDatagrams::new(source, RtpsFilter::default())
}

impl<S: PacketSource> RtpsDatagrams<S> {
    pub fn new(source: S, filter: RtpsFilter) -> Self {
        Self {
            source,
            filter,
            reassembler: Reassembler::default(),
            stats: CaptureStats::default(),
            last_error: None,
            finished: false,
            frame_budget: None,
        }
    }

    /// Return `None` (without finishing) after `frames` consecutive frames
    /// that yielded nothing, so a live capture loop gets control back even
    /// under a flood of non-RTPS traffic. Leave unset (the default) for
    /// files, where `None` should mean end of file.
    pub fn with_frame_budget(mut self, frames: usize) -> Self {
        self.frame_budget = Some(frames.max(1));
        self
    }

    pub fn with_reassembly_limits(mut self, limits: ReassemblyLimits) -> Self {
        self.reassembler = Reassembler::new(limits);
        self
    }

    pub fn stats(&self) -> &CaptureStats {
        &self.stats
    }

    pub fn reassembly_stats(&self) -> &reassembly::ReassemblyStats {
        self.reassembler.stats()
    }

    /// The fatal error that ended iteration, if any.
    pub fn last_error(&self) -> Option<&CaptureError> {
        self.last_error.as_ref()
    }

    /// The source is exhausted (EOF or fatal error).
    pub fn is_finished(&self) -> bool {
        self.finished
    }

    pub fn source(&self) -> &S {
        &self.source
    }

    pub fn into_source(self) -> S {
        self.source
    }

    /// Next RTPS datagram, or `None` (see the type docs for when).
    pub fn next_packet(&mut self) -> Option<RtpsPacket> {
        if self.finished {
            return None;
        }
        let mut spent = 0usize;
        loop {
            if self.frame_budget.is_some_and(|b| spent >= b) {
                self.stats.budget_yields += 1;
                return None;
            }
            spent += 1;
            let pkt = match self.source.next_packet() {
                Ok(Some(p)) => p,
                Ok(None) => {
                    self.finished = true;
                    return None;
                }
                Err(e) if e.is_transient() => {
                    self.stats.timeouts += 1;
                    return None;
                }
                Err(e) => {
                    self.last_error = Some(e);
                    self.finished = true;
                    return None;
                }
            };
            let out = process(
                &self.filter,
                &mut self.reassembler,
                &mut self.stats,
                pkt.ts,
                pkt.linktype,
                pkt.data,
            );
            if out.is_some() {
                return out;
            }
        }
    }
}

impl<S: PacketSource> Iterator for RtpsDatagrams<S> {
    type Item = (String, Vec<u8>);

    fn next(&mut self) -> Option<Self::Item> {
        self.next_packet().map(|p| (p.src.to_string(), p.payload))
    }
}

fn process(
    filter: &RtpsFilter,
    reassembler: &mut Reassembler,
    stats: &mut CaptureStats,
    ts: Duration,
    link: LinkType,
    data: &[u8],
) -> Option<RtpsPacket> {
    stats.frames += 1;
    let accept = |stats: &mut CaptureStats, u: &UdpDatagram<'_>, reassembled: bool| {
        stats.udp += 1;
        if !filter.matches(u) {
            stats.filtered_out += 1;
            return None;
        }
        stats.rtps += 1;
        Some(RtpsPacket {
            ts,
            src: u.src,
            dst: u.dst,
            src_port: u.src_port,
            dst_port: u.dst_port,
            port_class: filter.ports.classify(u.dst_port),
            reassembled,
            payload: u.payload.to_vec(),
        })
    };
    match decode_frame(link, data) {
        Ok(Decoded::Udp(u)) => accept(stats, &u, false),
        Ok(Decoded::Fragment(f)) => {
            stats.fragments += 1;
            let r = reassembler.push(ts, &f)?;
            stats.reassembled += 1;
            let udp = match r.src {
                IpAddr::V4(_) => decode::decode_udp_segment(r.src, r.dst, &r.payload),
                IpAddr::V6(_) => decode::decode_ipv6_upper(r.src, r.dst, r.protocol, &r.payload),
            };
            match udp {
                Ok(u) => accept(stats, &u, true),
                Err(e) => {
                    count_error(stats, e);
                    None
                }
            }
        }
        Err(e) => {
            count_error(stats, e);
            None
        }
    }
}

fn count_error(stats: &mut CaptureStats, e: DecodeError) {
    match e {
        DecodeError::UnsupportedLinkType(_) => stats.unsupported_linktype += 1,
        DecodeError::Truncated(_) => stats.truncated += 1,
        DecodeError::Malformed(..) | DecodeError::Fragment => stats.malformed += 1,
        DecodeError::NotIp => stats.not_ip += 1,
        DecodeError::NotUdp => stats.not_udp += 1,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{Ipv4Addr, Ipv6Addr};

    fn rtps_payload(tag: u8) -> Vec<u8> {
        let mut p = b"RTPS\x02\x03\x01\x0f".to_vec();
        p.extend_from_slice(&[tag; 12]);
        p
    }

    #[test]
    fn glue_filters_decodes_and_counts() {
        let a = Ipv4Addr::new(192, 168, 1, 10);
        let b = Ipv4Addr::new(192, 168, 1, 20);
        let ts = Duration::from_secs(1);
        let frames = vec![
            // SEDP-like unicast to metatraffic port of participant 3.
            (
                ts,
                LinkType::ETHERNET,
                synth::ethernet(
                    0x0800,
                    &synth::ipv4_udp(a, b, 51000, 7416, &rtps_payload(1)),
                ),
            ),
            // RTPS on a non-standard port: accepted by the magic.
            (
                ts,
                LinkType::ETHERNET,
                synth::ethernet(
                    0x0800,
                    &synth::ipv4_udp(a, b, 51000, 20000, &rtps_payload(2)),
                ),
            ),
            // Non-RTPS UDP: filtered.
            (
                ts,
                LinkType::ETHERNET,
                synth::ethernet(0x0800, &synth::ipv4_udp(a, b, 5353, 5353, b"mdns")),
            ),
            // ARP: not IP.
            (ts, LinkType::ETHERNET, synth::ethernet(0x0806, &[0; 28])),
            // Garbage link type.
            (ts, LinkType(9999), vec![0; 10]),
            // Truncated.
            (ts, LinkType::RAW, vec![0x45, 0, 0]),
        ];
        let mut it = rtps_datagrams(VecSource::new(frames));
        let p1 = it.next_packet().unwrap();
        assert_eq!(p1.src, IpAddr::V4(a));
        assert_eq!(
            p1.port_class,
            Some(PortClass {
                domain: 0,
                participant: Some(3),
                kind: PortKind::MetatrafficUnicast
            })
        );
        let p2 = it.next_packet().unwrap();
        assert_eq!(p2.port_class, None);
        assert!(it.next_packet().is_none());
        assert!(it.is_finished());
        assert!(it.last_error().is_none());
        let s = *it.stats();
        assert_eq!((s.frames, s.udp, s.rtps, s.filtered_out), (6, 3, 2, 1));
        assert_eq!((s.not_ip, s.unsupported_linktype, s.truncated), (1, 1, 1));
    }

    #[test]
    fn glue_reassembles_v4_and_v6() {
        let a = Ipv4Addr::new(10, 0, 0, 1);
        let mut payload = rtps_payload(7);
        payload.extend(std::iter::repeat_n(0xab, 3000));
        let ip = synth::ipv4_udp(a, a, 1, 7410, &payload);
        let mut frames: Vec<_> = synth::ipv4_fragment(&ip, 1480)
            .into_iter()
            .map(|f| (Duration::ZERO, LinkType::RAW, f))
            .collect();
        frames.reverse(); // out of order
        let s6: Ipv6Addr = "fe80::1".parse().unwrap();
        let ip6 = synth::ipv6_udp(s6, s6, 1, 7410, &[], &payload);
        frames.extend(
            synth::ipv6_fragment(&ip6, 1232, 42)
                .into_iter()
                .map(|f| (Duration::ZERO, LinkType::RAW, f)),
        );
        let got: Vec<RtpsPacket> = std::iter::from_fn({
            let mut it = rtps_datagrams(VecSource::new(frames));
            move || it.next_packet()
        })
        .collect();
        assert_eq!(got.len(), 2);
        for p in &got {
            assert!(p.reassembled);
            assert_eq!(p.payload, payload);
        }
        assert_eq!(got[1].src.to_string(), "fe80::1");
    }

    #[test]
    fn frame_budget_yields_without_finishing() {
        let a = Ipv4Addr::new(10, 0, 0, 1);
        let noise = synth::ipv4_udp(a, a, 1, 53, b"dns");
        let mut frames = vec![(Duration::ZERO, LinkType::RAW, noise); 10];
        frames.push((
            Duration::ZERO,
            LinkType::RAW,
            synth::ipv4_udp(a, a, 1, 7410, &rtps_payload(3)),
        ));
        let mut it = rtps_datagrams(VecSource::new(frames)).with_frame_budget(4);
        assert!(it.next_packet().is_none());
        assert!(it.next_packet().is_none());
        assert!(!it.is_finished());
        assert_eq!(it.stats().budget_yields, 2);
        assert!(it.next_packet().is_some()); // frames 9..11
        assert!(it.next_packet().is_none());
        assert!(it.is_finished());
    }

    struct Flaky(u32);
    impl PacketSource for Flaky {
        fn next_packet(&mut self) -> Result<Option<Packet<'_>>, CaptureError> {
            self.0 += 1;
            match self.0 {
                1 => Err(CaptureError::Timeout),
                2 => Ok(Some(Packet {
                    ts: Duration::ZERO,
                    linktype: LinkType::RAW,
                    data: &[],
                    orig_len: 0,
                })),
                _ => Err(CaptureError::Format("boom".into())),
            }
        }
    }

    #[test]
    fn glue_timeouts_resume_and_fatal_errors_end() {
        let mut it = rtps_datagrams(Flaky(0));
        assert!(it.next().is_none());
        assert!(!it.is_finished());
        assert_eq!(it.stats().timeouts, 1);
        assert!(it.next().is_none());
        assert!(it.is_finished());
        assert!(matches!(it.last_error(), Some(CaptureError::Format(_))));
        assert!(it.next().is_none());
        assert_eq!(it.stats().frames, 1);
    }
}
