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
//! 3. [`checksum`]: IPv4 header checksums are verified *before* reassembly
//!    and UDP checksums after it, so the sensor drops what the robot's IP
//!    stack drops (forged packets or fragments only the detector would see).
//! 4. [`reassembly`]: bounded IPv4/IPv6 fragment reassembly mirroring the
//!    Linux rules (first copy wins on exact duplicates, partial overlaps
//!    drop the datagram, per-destination memory budgets that refuse rather
//!    than evict), so a large or deliberately fragmented SEDP announcement is
//!    neither missed nor hideable by a flood.
//! 5. [`ports`]: [`RtpsFilter`] = DDSI-RTPS well-known ports and/or the
//!    `"RTPS"` magic (see the module docs for the trade-off).
//! 6. [`RtpsDatagrams`]: the glue iterator yielding `(src_ip, payload)`
//!    ([`RtpsPacket`] via `next_packet`). [`bpf`] compiles the same filter
//!    to a kernel socket filter.
//!
//! Every [`RtpsPacket`] carries its [`ingress`]: interface index, name,
//! loopback flag and packet type, from the live socket's `sockaddr_ll`, the
//! pcapng Interface Description Block / `epb_flags`, or the Linux cooked
//! (SLL/SLL2) header, merged over the fragments of a reassembled datagram.
//! This lets the consumer tell a loopback source address on `lo` (same
//! host) from one on a physical interface (forged), also for captures bound
//! to every interface and `tcpdump -i any` files. Outgoing copies on a
//! loopback interface are skipped ([`CaptureStats::loopback_outgoing`]) so
//! each datagram is delivered once, as the live reader does.
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
//! - UDP checksums holding the offload pseudo-header sum are accepted in the
//!   default [`UdpChecksumMode::Auto`] (same-host traffic carries them); see
//!   [`checksum`] for the residual risk and [`UdpChecksumMode::Always`] for
//!   SPAN/TAP captures.

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
pub mod checksum;
pub mod decode;
pub mod ingress;
pub mod middleware;
pub mod pcap;
pub mod ports;
pub mod reassembly;
pub mod source;
pub mod synth;

use std::net::IpAddr;
use std::time::Duration;

pub use checksum::{UdpChecksumMode, UdpChecksumStatus};
pub use decode::{decode_frame, decode_udp, DecodeError, Decoded, LinkType, UdpDatagram};
pub use ingress::{IngressInfo, PacketIngress, PacketType};
pub use pcap::{CaptureFile, PcapNgReader, PcapReader, PcapWriter};
pub use ports::{MatchMode, PortClass, PortKind, RtpsFilter, RtpsPortMap, MAX_LEGACY_UDP_PORTS};
pub use reassembly::{Reassembler, ReassemblyLimits};
pub use source::{CaptureError, Packet, PacketSource, VecSource};

/// What kind of datagram an [`RtpsPacket`] carries.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Default)]
pub enum PacketKind {
    /// RTPS (well-known port or `RTPS` magic).
    #[default]
    Rtps,
    /// UDP on a configured Unitree legacy port
    /// ([`RtpsFilter::legacy_udp_ports`], `unitree_legged_sdk`, Go1
    /// generation), whatever its payload; [`RtpsPacket::also_rtps`] when it
    /// is RTPS as well.
    UnitreeLegacy,
}

/// One RTPS datagram with its context.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RtpsPacket {
    /// RTPS, or a Unitree legacy UDP datagram (only when the filter has
    /// legacy ports).
    pub kind: PacketKind,
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
    /// The interface the datagram arrived on, as far as the source and the
    /// frame's link-layer header tell (see [`ingress`]); for reassembled
    /// datagrams, merged over every fragment (any non-loopback fragment
    /// makes the datagram non-loopback).
    pub ingress: IngressInfo,
    /// Link-layer (MAC) source of the frame when its header carries one
    /// (Ethernet, Linux cooked capture, the `AF_PACKET` source); `None` for
    /// raw-IP captures and for reassembled datagrams (fragments may come
    /// from different frames).
    pub src_mac: Option<[u8; 6]>,
    /// A [`PacketKind::UnitreeLegacy`] datagram that the [`RtpsFilter`]
    /// also accepts as RTPS (well-known port or `RTPS` magic): a datagram
    /// on a legacy port is always delivered as legacy, and this flag tells
    /// the consumer to inspect it as RTPS as well.
    pub also_rtps: bool,
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
    /// Frames skipped because they are the *outgoing* copy of a packet on a
    /// loopback interface (Linux cooked capture of `any`/`lo`, pcapng
    /// `epb_flags`): the incoming copy follows, so each datagram is
    /// delivered once, as with the live reader.
    pub loopback_outgoing: u64,
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
    /// IPv4 packets (or fragments, checked before reassembly) dropped for a
    /// wrong header checksum. The robot's kernel drops these too: non-zero
    /// means injection attempts aimed at the sensor, or a broken NIC.
    pub bad_ip_checksum: u64,
    /// UDP datagrams dropped for a wrong UDP checksum (or zero over IPv6).
    pub bad_udp_checksum: u64,
    /// UDP datagrams accepted with the offload pseudo-header sum in the
    /// checksum field ([`UdpChecksumMode::Auto`]). Expected on loopback,
    /// veth and the capturing host's outgoing traffic; suspicious otherwise.
    pub udp_checksum_partial: u64,
    /// IPv4 UDP datagrams without a checksum (field 0, legal).
    pub udp_checksum_none: u64,
    /// UDP datagrams not verified because of [`UdpChecksumMode::Never`].
    pub udp_checksum_unverified: u64,
    /// IPv6 packets with more than
    /// [`decode::SUSPICIOUS_IPV6_EXT_HEADERS`] extension headers (decoded,
    /// since Linux delivers them, but a typical evasion trait).
    pub ipv6_long_ext_chains: u64,
    /// Packets of a middleware the sensor does not decode (Zenoh, see
    /// [`middleware`]): counted, never inspected, not in `not_udp` /
    /// `filtered_out` / `truncated`.
    pub zenoh: u64,
    /// Source address of the latest such packet (evidence for the finding).
    pub zenoh_last_src: Option<IpAddr>,
    /// UDP datagrams accepted as Unitree legacy frames
    /// ([`RtpsFilter::legacy_udp_ports`]); not in `rtps`.
    pub legacy_udp: u64,
    /// Of those, datagrams that also matched the RTPS filter
    /// ([`RtpsPacket::also_rtps`]).
    pub rtps_on_legacy_port: u64,
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
    udp_checksum: UdpChecksumMode,
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
            udp_checksum: UdpChecksumMode::default(),
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

    /// Which UDP checksums to verify (default [`UdpChecksumMode::Auto`]).
    /// IPv4 header checksums are always verified.
    pub fn with_udp_checksum_mode(mut self, mode: UdpChecksumMode) -> Self {
        self.udp_checksum = mode;
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
                self.udp_checksum,
                &mut self.reassembler,
                &mut self.stats,
                &pkt,
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

/// Apply the UDP checksum policy; false = drop (counted).
fn udp_checksum_ok(
    mode: UdpChecksumMode,
    stats: &mut CaptureStats,
    u: &UdpDatagram<'_>,
    segment: &[u8],
) -> bool {
    if mode == UdpChecksumMode::Never {
        stats.udp_checksum_unverified += 1;
        return true;
    }
    match checksum::udp_checksum_status(u.src, u.dst, segment) {
        UdpChecksumStatus::Valid => true,
        UdpChecksumStatus::NotComputed => {
            stats.udp_checksum_none += 1;
            true
        }
        UdpChecksumStatus::Partial if mode == UdpChecksumMode::Auto => {
            stats.udp_checksum_partial += 1;
            true
        }
        UdpChecksumStatus::Partial | UdpChecksumStatus::Bad => {
            stats.bad_udp_checksum += 1;
            false
        }
    }
}

fn process(
    filter: &RtpsFilter,
    udp_mode: UdpChecksumMode,
    reassembler: &mut Reassembler,
    stats: &mut CaptureStats,
    pkt: &Packet<'_>,
) -> Option<RtpsPacket> {
    let (ts, link, data) = (pkt.ts, pkt.linktype, pkt.data);
    stats.frames += 1;
    let ingress = ingress::resolve(&pkt.ingress, ingress::link_ingress(link, data));
    if ingress.loopback == Some(true) && ingress.pkttype.is_some_and(PacketType::is_outgoing) {
        stats.loopback_outgoing += 1;
        return None;
    }
    let accept = |stats: &mut CaptureStats,
                  u: &UdpDatagram<'_>,
                  segment: &[u8],
                  reassembled,
                  ingress: IngressInfo,
                  src_mac: Option<[u8; 6]>| {
        if !udp_checksum_ok(udp_mode, stats, u, segment) {
            return None;
        }
        stats.udp += 1;
        if middleware::classify_udp(u).is_some() {
            stats.zenoh += 1;
            stats.zenoh_last_src = Some(u.src);
            return None;
        }
        // A datagram on a configured legacy port is always a legacy
        // datagram (an attacker must not be able to skip the legacy sender
        // check by starting the payload with "RTPS"); if it is RTPS as well,
        // the consumer inspects it on both paths.
        let rtps = filter.matches(u);
        let (kind, also_rtps) = if filter.is_legacy(u) {
            stats.legacy_udp += 1;
            if rtps {
                stats.rtps_on_legacy_port += 1;
            }
            (PacketKind::UnitreeLegacy, rtps)
        } else if rtps {
            stats.rtps += 1;
            (PacketKind::Rtps, false)
        } else {
            stats.filtered_out += 1;
            return None;
        };
        Some(RtpsPacket {
            kind,
            ts,
            src: u.src,
            dst: u.dst,
            src_port: u.src_port,
            dst_port: u.dst_port,
            port_class: filter.ports.classify(u.dst_port),
            reassembled,
            ingress,
            src_mac,
            also_rtps,
            payload: u.payload.to_vec(),
        })
    };
    let d = match decode::decode_frame_detail(link, data) {
        Ok(d) => d,
        Err(e @ (DecodeError::NotUdp | DecodeError::Truncated(_))) => {
            // TCP to / from the Zenoh port (also when the kernel filter cut
            // it to its headers): counted as a foreign middleware.
            match middleware::classify_tcp_frame(link, data) {
                Some((src, _)) => {
                    stats.zenoh += 1;
                    stats.zenoh_last_src = Some(src);
                }
                None => count_error(stats, e),
            }
            return None;
        }
        Err(e) => {
            count_error(stats, e);
            return None;
        }
    };
    // The kernel verifies the IPv4 header checksum before anything else,
    // fragments included (ip_rcv_core runs before ip_defrag).
    if let Some(h) = d.ipv4_header {
        if !checksum::ipv4_header_valid(h) {
            stats.bad_ip_checksum += 1;
            return None;
        }
    }
    if d.ext_headers > decode::SUSPICIOUS_IPV6_EXT_HEADERS {
        stats.ipv6_long_ext_chains += 1;
    }
    match d.decoded {
        Decoded::Udp(u) => {
            let segment = d.udp_segment.unwrap_or_default();
            accept(
                stats,
                &u,
                segment,
                false,
                ingress,
                decode::link_src_mac(link, data),
            )
        }
        Decoded::Fragment(f) => {
            stats.fragments += 1;
            let (r, ingress) = reassembler.push_with_ingress(ts, &f, &ingress)?;
            stats.reassembled += 1;
            let udp = match r.src {
                IpAddr::V4(_) => decode::udp_segment_inner(r.src, r.dst, &r.payload),
                IpAddr::V6(_) => decode::decode_ipv6_upper_detail(
                    r.src, r.dst, r.protocol, &r.payload,
                )
                .map(|(u, seg, n)| {
                    if d.ext_headers + n > decode::SUSPICIOUS_IPV6_EXT_HEADERS
                        && d.ext_headers <= decode::SUSPICIOUS_IPV6_EXT_HEADERS
                    {
                        stats.ipv6_long_ext_chains += 1;
                    }
                    (u, seg)
                }),
            };
            match udp {
                Ok((u, seg)) => accept(stats, &u, seg, true, ingress, None),
                Err(e) => {
                    count_error(stats, e);
                    None
                }
            }
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

    /// Unitree legacy UDP: off by default; with legacy ports, delivered as
    /// `PacketKind::UnitreeLegacy` in both directions, other UDP is still
    /// filtered, and a datagram on a legacy port is **always** delivered as
    /// legacy (review H2: one that starts with `RTPS` is flagged
    /// `also_rtps` so both paths inspect it, never only the RTPS one).
    #[test]
    fn glue_classifies_unitree_legacy_udp() {
        let pc = Ipv4Addr::new(192, 168, 123, 15);
        let robot = Ipv4Addr::new(192, 168, 123, 161);
        let ts = Duration::from_secs(1);
        let udp = |s, d, sp, dp, p: &[u8]| {
            (
                ts,
                LinkType::ETHERNET,
                synth::ethernet(0x0800, &synth::ipv4_udp(s, d, sp, dp, p)),
            )
        };
        let frames = || {
            vec![
                udp(pc, robot, 8090, 8082, &[0xfe; 129]),     // HighCmd
                udp(robot, pc, 8082, 8090, &[0xfe; 1087]),    // HighState
                udp(pc, robot, 8090, 8082, &rtps_payload(3)), // RTPS on a legacy port
                udp(pc, robot, 5353, 5353, b"mdns"),
            ]
        };
        let mut off = rtps_datagrams(VecSource::new(frames()));
        assert_eq!(off.next_packet().unwrap().kind, PacketKind::Rtps);
        assert!(off.next_packet().is_none());
        assert_eq!((off.stats().legacy_udp, off.stats().filtered_out), (0, 3));

        let filter = RtpsFilter::default().with_legacy_udp_ports([8082, 8090, 8007]);
        let mut on = RtpsDatagrams::new(VecSource::new(frames()), filter);
        let a = on.next_packet().unwrap();
        assert_eq!(
            (a.kind, a.src_port, a.dst_port, a.also_rtps),
            (PacketKind::UnitreeLegacy, 8090, 8082, false)
        );
        assert_eq!(a.payload.len(), 129);
        assert_eq!(a.src_mac, Some([0x02, 0, 0, 0, 0, 2]), "Ethernet source");
        let b = on.next_packet().unwrap();
        assert_eq!(
            (b.kind, b.src, b.payload.len()),
            (PacketKind::UnitreeLegacy, IpAddr::V4(robot), 1087)
        );
        let c = on.next_packet().unwrap();
        assert_eq!(
            (c.kind, c.also_rtps),
            (PacketKind::UnitreeLegacy, true),
            "RTPS on a legacy port goes to the legacy path too"
        );
        assert!(on.next_packet().is_none());
        let s = *on.stats();
        assert_eq!(
            (s.legacy_udp, s.rtps, s.filtered_out, s.rtps_on_legacy_port),
            (3, 0, 1, 1)
        );
    }

    /// 802.1Q / 802.1ad tagged frames (one or two tags) reach the legacy
    /// and RTPS classifiers from a pcap replay (Ethernet and Linux cooked
    /// capture) and keep their link-layer source.
    #[test]
    fn glue_decodes_vlan_tagged_frames() {
        let pc = Ipv4Addr::new(192, 168, 123, 15);
        let robot = Ipv4Addr::new(192, 168, 123, 10);
        let ip = synth::ipv4_udp(pc, robot, 8080, 8007, &[0x5a; 614]);
        let ts = Duration::from_secs(1);
        let mut inner = vec![0x20, 7];
        inner.extend_from_slice(&0x0800u16.to_be_bytes());
        inner.extend_from_slice(&ip);
        let frames = vec![
            (
                ts,
                LinkType::ETHERNET,
                synth::ethernet_vlan(&[(0x8100, 123)], 0x0800, &ip),
            ),
            (
                ts,
                LinkType::ETHERNET,
                synth::ethernet_vlan(&[(0x88a8, 10), (0x8100, 20)], 0x0800, &ip),
            ),
            (ts, LinkType::LINUX_SLL, synth::linux_sll(0x8100, &inner)),
        ];
        let filter = RtpsFilter::default().with_legacy_udp_ports([8007, 8080]);
        let mut it = RtpsDatagrams::new(VecSource::new(frames), filter);
        for n in 0..3 {
            let p = it.next_packet().unwrap_or_else(|| panic!("frame {n}"));
            assert_eq!(p.kind, PacketKind::UnitreeLegacy, "frame {n}");
            assert_eq!(p.payload.len(), 614);
            assert_eq!(
                p.src_mac,
                Some([0x02, 0, 0, 0, 0, if n == 2 { 1 } else { 2 }])
            );
        }
        assert!(it.next_packet().is_none());
        assert_eq!(it.stats().not_ip, 0);
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

    fn info(ifindex: u32, name: &str, lo: bool) -> IngressInfo {
        IngressInfo {
            ifindex: Some(ifindex),
            name: Some(name.into()),
            loopback: Some(lo),
            pkttype: Some(PacketType::Host),
        }
    }

    #[test]
    fn glue_reports_per_packet_ingress_from_source_and_cooked_headers() {
        use ingress::ARPHRD_LOOPBACK;
        let lo = Ipv4Addr::LOCALHOST;
        let a = Ipv4Addr::new(10, 0, 0, 1);
        let ip_lo = synth::ipv4_udp(lo, lo, 1, 7410, &rtps_payload(1));
        let ip_a = synth::ipv4_udp(a, a, 1, 7410, &rtps_payload(2));
        let t = Duration::ZERO;
        let any = IngressInfo {
            name: Some("any".into()),
            ..Default::default()
        };
        let frames = vec![
            // Source-provided (live AF_PACKET style).
            (t, LinkType::RAW, ip_lo.clone(), info(1, "lo", true)),
            (t, LinkType::RAW, ip_lo.clone(), info(2, "eth0", false)),
            // SLL2 from an "any" capture: ifindex/hatype/pkttype from the frame.
            (
                t,
                LinkType::LINUX_SLL2,
                synth::linux_sll2_on(1, ARPHRD_LOOPBACK, 4, 0x0800, &ip_lo),
                any.clone(),
            ),
            (
                t,
                LinkType::LINUX_SLL2,
                synth::linux_sll2_on(1, ARPHRD_LOOPBACK, 0, 0x0800, &ip_lo),
                any.clone(),
            ),
            (
                t,
                LinkType::LINUX_SLL2,
                synth::linux_sll2_on(3, 1, 0, 0x0800, &ip_lo),
                any.clone(),
            ),
            // SLL v1: no ifindex, hatype still tells.
            (
                t,
                LinkType::LINUX_SLL,
                synth::linux_sll_on(4, ARPHRD_LOOPBACK, 0x0800, &ip_a),
                any.clone(),
            ),
            (
                t,
                LinkType::LINUX_SLL,
                synth::linux_sll_on(0, ARPHRD_LOOPBACK, 0x0800, &ip_a),
                any.clone(),
            ),
            (
                t,
                LinkType::LINUX_SLL,
                synth::linux_sll_on(4, 1, 0x0800, &ip_a),
                IngressInfo::default(),
            ),
            // Nothing known.
            (t, LinkType::RAW, ip_a.clone(), IngressInfo::default()),
        ];
        let got: Vec<RtpsPacket> = std::iter::from_fn({
            let mut it = rtps_datagrams(VecSource::with_ingress(frames));
            move || it.next_packet()
        })
        .collect();
        let ing: Vec<_> = got.iter().map(|p| p.ingress.clone()).collect();
        assert_eq!(ing.len(), 7, "{ing:?}");
        assert_eq!(ing[0], info(1, "lo", true));
        assert_eq!(ing[1], info(2, "eth0", false));
        // ing[2]: the SLL2 *outgoing* loopback copy was skipped.
        assert_eq!(
            ing[2],
            IngressInfo {
                ifindex: Some(1),
                name: None,
                loopback: Some(true),
                pkttype: Some(PacketType::Host),
            }
        );
        assert_eq!((ing[3].ifindex, ing[3].loopback), (Some(3), Some(false)));
        assert_eq!((ing[4].ifindex, ing[4].loopback), (None, Some(true)));
        assert_eq!(ing[5].loopback, Some(false));
        assert_eq!(ing[5].pkttype, Some(PacketType::Outgoing), "kept off lo");
        assert!(ing[6].is_unknown());
        assert_eq!(got[3].src, IpAddr::V4(lo));
    }

    #[test]
    fn glue_counts_skipped_loopback_outgoing_copies() {
        let lo = Ipv4Addr::LOCALHOST;
        let ip = synth::ipv4_udp(lo, lo, 1, 7410, &rtps_payload(1));
        let frames = [4u16, 0].map(|pt| {
            (
                Duration::ZERO,
                LinkType::LINUX_SLL,
                synth::linux_sll_on(pt, ingress::ARPHRD_LOOPBACK, 0x0800, &ip),
            )
        });
        let mut it = rtps_datagrams(VecSource::new(frames));
        assert!(it.next_packet().is_some());
        assert!(it.next_packet().is_none());
        assert_eq!(it.stats().loopback_outgoing, 1);
        assert_eq!(it.stats().rtps, 1);
    }

    #[test]
    fn fragments_seen_off_loopback_make_the_datagram_non_loopback() {
        let lo = Ipv4Addr::LOCALHOST;
        let mut payload = rtps_payload(5);
        payload.extend(std::iter::repeat_n(0xcd, 3000));
        let ip = synth::ipv4_udp(lo, lo, 1, 7410, &payload);
        let frags = synth::ipv4_fragment(&ip, 1480);
        assert!(frags.len() >= 3);
        let run = |tags: &[IngressInfo]| {
            let frames: Vec<_> = frags
                .iter()
                .zip(tags.iter().cycle())
                .map(|(f, t)| (Duration::ZERO, LinkType::RAW, f.clone(), t.clone()))
                .collect();
            let mut it = rtps_datagrams(VecSource::with_ingress(frames));
            let p = it.next_packet().expect("reassembled");
            assert!(p.reassembled);
            assert_eq!(p.payload, payload);
            p.ingress
        };
        let l = info(1, "lo", true);
        let e = info(2, "eth0", false);
        assert_eq!(run(std::slice::from_ref(&l)), l);
        // A forged first fragment on eth0 completed by a fragment on lo.
        let mixed = run(&[e.clone(), l.clone()]);
        assert_eq!(mixed.loopback, Some(false));
        assert_eq!((mixed.ifindex, mixed.name), (None, None));
        let mixed = run(&[l.clone(), l.clone(), e.clone()]);
        assert_eq!(mixed.loopback, Some(false));
        let unknown = run(&[l.clone(), IngressInfo::default()]);
        assert_eq!(unknown.loopback, None);
    }

    #[test]
    fn pcapng_multi_interface_replay_reports_each_interface() {
        let lo = Ipv4Addr::LOCALHOST;
        let ip = synth::ipv4_udp(lo, lo, 1, 7410, &rtps_payload(9));
        let mut b = pcap::tests::NgBuilder::new(true);
        b.idb_named(1, b"lo");
        b.idb_named(101, b"eth0");
        b.epb(0, 1, &synth::ethernet(0x0800, &ip), 0);
        b.epb(1, 1, &ip, 0);
        let mut it = rtps_datagrams(CaptureFile::new(&b.out[..]).unwrap());
        let a = it.next_packet().unwrap();
        let c = it.next_packet().unwrap();
        assert!(it.next_packet().is_none() && it.last_error().is_none());
        assert_eq!(
            (a.ingress.name.as_deref(), a.ingress.loopback),
            (Some("lo"), Some(true))
        );
        assert_eq!(
            (c.ingress.name.as_deref(), c.ingress.loopback),
            (Some("eth0"), Some(false))
        );
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
                    ingress: PacketIngress::default(),
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
