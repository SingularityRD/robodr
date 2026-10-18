//! Robot middleware the sensor **cannot** inspect: recognise it so a blind
//! spot is reported instead of looking like a clean, quiet bus.
//!
//! ROS 2 Jazzy ships `rmw_zenoh_cpp` as a supported middleware. Zenoh does
//! not speak DDSI-RTPS: nodes talk to a Zenoh router (`rmw_zenohd`) and to
//! each other over TCP (default port [`ZENOH_PORT`] 7447) and may scout for
//! peers over UDP multicast ([`ZENOH_SCOUT_GROUP_V4`]:[`ZENOH_SCOUT_PORT`]).
//! None of it reaches the RTPS parser, so without this module a robot running
//! rmw_zenoh would produce no participants, no writers and no findings: the
//! sensor would be blind and nothing would say so.
//!
//! This is a **detector, not a decoder**: it classifies packets by transport
//! and port only and counts them ([`crate::CaptureStats::zenoh`]); their
//! content is never parsed. The consumer turns a growing count into a
//! finding (`robot.capture.unsupported_middleware` in
//! `robodr-ros2-pipeline`) and refuses an "ok" health state when nothing but
//! Zenoh is seen.
//!
//! # What counts as Zenoh
//!
//! - TCP with source or destination port [`ZENOH_PORT`] (the router's and
//!   rmw_zenoh's default listen port);
//! - UDP with source or destination port [`ZENOH_PORT`] or
//!   [`ZENOH_SCOUT_PORT`] whose payload does **not** start with the `RTPS`
//!   magic. Both ports also are DDSI-RTPS well-known ports of domain 0
//!   (participant id 18: metatraffic / user unicast), so real RTPS on them
//!   (always magic-prefixed) is still delivered as RTPS.
//!
//! A Zenoh deployment on non-default ports is not recognised (configure the
//! ports on the Zenoh side, or extend this list); neither is any other
//! non-RTPS middleware.
//!
//! # Kernel filter
//!
//! The live socket's BPF program ([`crate::bpf`]) passes UDP on these ports
//! already (they are inside the RTPS port map) and, for TCP, only segments
//! to or from [`ZENOH_PORT`] with SYN, FIN or RST set, cut to
//! [`crate::bpf::ZENOH_SNAP_LEN`] bytes: connection set-up and tear-down,
//! never the session's data stream. A long-lived Zenoh session that started
//! before the sensor and never reconnects is therefore only seen through
//! scouting; file replays (`tcpdump` captures) see every segment.

use std::net::{IpAddr, Ipv4Addr};

use crate::decode::{ethertype_dispatch, LinkType, UdpDatagram};
use crate::ports::has_rtps_magic;

/// Zenoh's default TCP/UDP port (router and peers).
pub const ZENOH_PORT: u16 = 7447;
/// Zenoh's default scouting port (UDP multicast).
pub const ZENOH_SCOUT_PORT: u16 = 7446;
/// Zenoh's default IPv4 scouting multicast group.
pub const ZENOH_SCOUT_GROUP_V4: Ipv4Addr = Ipv4Addr::new(224, 0, 0, 224);

/// IANA protocol number for TCP.
const IPPROTO_TCP: u8 = 6;

/// A middleware recognised (by transport and port) but not decoded.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum ForeignMiddleware {
    /// Zenoh over TCP (session traffic, port 7447).
    ZenohTcp,
    /// Zenoh over UDP (scouting on 7446, or a UDP link on 7447).
    ZenohUdp,
}

impl ForeignMiddleware {
    /// Short name for findings and reports.
    pub fn name(self) -> &'static str {
        match self {
            Self::ZenohTcp => "zenoh/tcp",
            Self::ZenohUdp => "zenoh/udp",
        }
    }
}

/// A UDP datagram on a Zenoh port that is not RTPS.
pub fn classify_udp(u: &UdpDatagram<'_>) -> Option<ForeignMiddleware> {
    let zenoh_port = |p: u16| p == ZENOH_PORT || p == ZENOH_SCOUT_PORT;
    if (zenoh_port(u.dst_port) || zenoh_port(u.src_port)) && !has_rtps_magic(u.payload) {
        Some(ForeignMiddleware::ZenohUdp)
    } else {
        None
    }
}

/// The source address and transport of a frame that is a TCP segment to or
/// from [`ZENOH_PORT`]. Reads only the link header, the fixed IP header and
/// the TCP ports, so a snap-length-cut frame (the kernel filter keeps
/// [`crate::bpf::ZENOH_SNAP_LEN`] bytes) is still recognised. IPv6 only
/// without extension headers; IPv4 non-first fragments never match.
pub fn classify_tcp_frame(link: LinkType, frame: &[u8]) -> Option<(IpAddr, ForeignMiddleware)> {
    let ip = link_ip(link, frame)?;
    let (src, l4) = match ip.first()? >> 4 {
        4 => {
            let ihl = usize::from(ip[0] & 0x0f) * 4;
            let frag = u16::from_be_bytes([*ip.get(6)?, *ip.get(7)?]);
            if ihl < 20 || *ip.get(9)? != IPPROTO_TCP || frag & 0x1fff != 0 {
                return None;
            }
            let s = ip.get(12..16)?;
            (
                IpAddr::V4(Ipv4Addr::new(s[0], s[1], s[2], s[3])),
                ip.get(ihl..)?,
            )
        }
        6 => {
            if *ip.get(6)? != IPPROTO_TCP {
                return None;
            }
            let s: [u8; 16] = ip.get(8..24)?.try_into().ok()?;
            (IpAddr::from(s), ip.get(40..)?)
        }
        _ => return None,
    };
    let sport = u16::from_be_bytes([*l4.first()?, *l4.get(1)?]);
    let dport = u16::from_be_bytes([*l4.get(2)?, *l4.get(3)?]);
    (sport == ZENOH_PORT || dport == ZENOH_PORT).then_some((src, ForeignMiddleware::ZenohTcp))
}

/// The network-layer bytes of a frame (same link types as
/// [`crate::decode`]), without checking the IP header.
fn link_ip(link: LinkType, frame: &[u8]) -> Option<&[u8]> {
    match link {
        LinkType::ETHERNET => {
            let et = u16::from_be_bytes([*frame.get(12)?, *frame.get(13)?]);
            ethertype_dispatch(et, frame.get(14..)?)
                .ok()
                .map(|(_, p)| p)
        }
        LinkType::LINUX_SLL => {
            let et = u16::from_be_bytes([*frame.get(14)?, *frame.get(15)?]);
            ethertype_dispatch(et, frame.get(16..)?)
                .ok()
                .map(|(_, p)| p)
        }
        LinkType::LINUX_SLL2 => {
            let et = u16::from_be_bytes([*frame.first()?, *frame.get(1)?]);
            ethertype_dispatch(et, frame.get(20..)?)
                .ok()
                .map(|(_, p)| p)
        }
        LinkType::RAW | LinkType::IPV4 | LinkType::IPV6 => Some(frame),
        LinkType::NULL | LinkType::LOOP => frame.get(4..),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::synth;
    use std::net::Ipv6Addr;

    /// A TCP segment (no options, no payload) with the given flags.
    pub(crate) fn ipv4_tcp(src: Ipv4Addr, dst: Ipv4Addr, sport: u16, dport: u16) -> Vec<u8> {
        let mut p = synth::ipv4_udp(src, dst, sport, dport, &[0u8; 12]);
        p[9] = IPPROTO_TCP;
        p
    }

    #[test]
    fn tcp_on_the_zenoh_port_either_side() {
        let a = Ipv4Addr::new(10, 0, 0, 1);
        let b = Ipv4Addr::new(10, 0, 0, 2);
        for (s, d) in [(50000, ZENOH_PORT), (ZENOH_PORT, 50000)] {
            let f = synth::ethernet(0x0800, &ipv4_tcp(a, b, s, d));
            assert_eq!(
                classify_tcp_frame(LinkType::ETHERNET, &f),
                Some((IpAddr::V4(a), ForeignMiddleware::ZenohTcp))
            );
            // Cut after the ports (snap length): still recognised.
            assert!(classify_tcp_frame(LinkType::ETHERNET, &f[..14 + 24]).is_some());
        }
        let other = synth::ethernet(0x0800, &ipv4_tcp(a, b, 50000, 22));
        assert_eq!(classify_tcp_frame(LinkType::ETHERNET, &other), None);
        // UDP on 7447 is not TCP.
        let udp = synth::ipv4_udp(a, b, 1, ZENOH_PORT, b"x");
        assert_eq!(classify_tcp_frame(LinkType::RAW, &udp), None);
        // A non-first fragment carries no ports.
        let mut frag = ipv4_tcp(a, b, 50000, ZENOH_PORT);
        frag[7] = 1;
        assert_eq!(classify_tcp_frame(LinkType::RAW, &frag), None);
        assert_eq!(classify_tcp_frame(LinkType::RAW, &[]), None);
        assert_eq!(classify_tcp_frame(LinkType::RAW, &[0x45, 0, 0]), None);
    }

    #[test]
    fn tcp_over_ipv6_and_cooked_links() {
        let s6: Ipv6Addr = "fd00::1".parse().unwrap();
        let mut p = synth::ipv6_udp(s6, s6, 40000, ZENOH_PORT, &[], &[0u8; 12]);
        p[6] = IPPROTO_TCP;
        assert_eq!(
            classify_tcp_frame(LinkType::RAW, &p),
            Some((IpAddr::V6(s6), ForeignMiddleware::ZenohTcp))
        );
        let a = Ipv4Addr::LOCALHOST;
        let ip = ipv4_tcp(a, a, 40000, ZENOH_PORT);
        let sll = synth::linux_sll_on(0, 772, 0x0800, &ip);
        assert!(classify_tcp_frame(LinkType::LINUX_SLL, &sll).is_some());
        let sll2 = synth::linux_sll2_on(1, 772, 0, 0x0800, &ip);
        assert!(classify_tcp_frame(LinkType::LINUX_SLL2, &sll2).is_some());
        assert_eq!(classify_tcp_frame(LinkType(9999), &ip), None);
    }

    #[test]
    fn udp_on_zenoh_ports_unless_rtps() {
        let a = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1));
        let g = IpAddr::V4(ZENOH_SCOUT_GROUP_V4);
        let u = |sp, dp, payload: &'static [u8]| UdpDatagram {
            src: a,
            dst: g,
            src_port: sp,
            dst_port: dp,
            payload,
        };
        assert_eq!(
            classify_udp(&u(40000, ZENOH_SCOUT_PORT, b"\x01\x09")),
            Some(ForeignMiddleware::ZenohUdp)
        );
        assert_eq!(
            classify_udp(&u(ZENOH_PORT, 40000, b"\x02")),
            Some(ForeignMiddleware::ZenohUdp)
        );
        // Real RTPS on participant 18's ports stays RTPS.
        assert_eq!(classify_udp(&u(40000, 7446, b"RTPS\x02\x03")), None);
        assert_eq!(classify_udp(&u(40000, 7400, b"\x01\x09")), None);
        assert_eq!(ForeignMiddleware::ZenohTcp.name(), "zenoh/tcp");
        assert_eq!(ForeignMiddleware::ZenohUdp.name(), "zenoh/udp");
    }
}
