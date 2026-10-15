//! Pure frame decoders: link layer -> IPv4 / IPv6 -> UDP.
//!
//! No I/O, no allocation, no `unsafe`. Every field access is bounds-checked
//! against the bytes actually present, so a truncated, padded or crafted frame
//! produces a [`DecodeError`], never a panic or an out-of-bounds read. The
//! returned [`UdpDatagram`] borrows its payload from the input frame.
//!
//! Supported link types (pcap `LINKTYPE_*` numbering, see [`LinkType`]):
//!
//! | Link type | Header | Notes |
//! |---|---|---|
//! | `ETHERNET` (1) | 14 bytes | Ethernet II; up to [`MAX_VLAN_TAGS`] 802.1Q / 802.1ad tags. 802.3/LLC frames are "not IP". |
//! | `LINUX_SLL` (113) | 16 bytes | Linux "cooked" capture v1 (`tcpdump -i any`, older libpcap). |
//! | `LINUX_SLL2` (276) | 20 bytes | Linux "cooked" capture v2 (`-i any`, libpcap >= 1.10). |
//! | `RAW` (101), `IPV4` (228), `IPV6` (229) | none | Raw IP; version taken from the first nibble. Also what [`crate::afpacket`] yields. |
//! | `NULL` (0) | 4 bytes | BSD loopback, address family in the *capturing host's* byte order (both accepted). |
//! | `LOOP` (108) | 4 bytes | OpenBSD loopback, address family in network byte order. |
//!
//! Network layer:
//! - **IPv4**: version, IHL (>= 5, options skipped), total length (must
//!   be >= IHL and fit the captured bytes; link padding and Ethernet FCS past the
//!   total length are trimmed). Header checksums are **not** verified:
//!   loopback and checksum-offloaded NICs routinely capture packets whose
//!   checksum is not filled in yet.
//! - **IPv6**: payload length checked; the extension-header chain
//!   (hop-by-hop, routing, destination options, AH, mobility, HIP, shim6,
//!   fragment) is walked with per-header bounds checks and a hard limit of
//!   [`MAX_IPV6_EXT_HEADERS`]. ESP (encrypted) and "no next header" are
//!   reported as [`DecodeError::NotUdp`]. Jumbograms are not supported.
//! - **Fragments** (IPv4 MF/offset, IPv6 fragment header) are returned as
//!   [`Decoded::Fragment`] for the bounded reassembler in
//!   [`crate::reassembly`]; [`decode_udp`] reports them as
//!   [`DecodeError::Fragment`]. An IPv6 *atomic* fragment (offset 0, M=0,
//!   RFC 6946) is decoded as an ordinary packet.
//!
//! Transport: only UDP. The UDP length must be >= 8 and fit the IP payload;
//! bytes after the UDP length are trimmed. The UDP checksum is not verified
//! (same offload reason as above).

use std::fmt;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

/// Maximum number of stacked VLAN tags accepted (single 802.1Q or 802.1ad
/// "QinQ" double tagging). A frame with more tags is [`DecodeError::Malformed`].
pub const MAX_VLAN_TAGS: usize = 2;

/// Maximum number of IPv6 extension headers walked before giving up.
pub const MAX_IPV6_EXT_HEADERS: usize = 8;

/// IANA protocol number for UDP.
pub const IPPROTO_UDP: u8 = 17;

const ETHERTYPE_IPV4: u16 = 0x0800;
const ETHERTYPE_IPV6: u16 = 0x86dd;
const ETHERTYPE_VLAN: u16 = 0x8100;
const ETHERTYPE_QINQ: u16 = 0x88a8;
const ETHERTYPE_QINQ_LEGACY: u16 = 0x9100;
const ARPHRD_NETLINK: u16 = 824;

const IP6_HOP_BY_HOP: u8 = 0;
const IP6_ROUTING: u8 = 43;
const IP6_FRAGMENT: u8 = 44;
const IP6_AH: u8 = 51;
const IP6_DEST_OPTS: u8 = 60;
const IP6_MOBILITY: u8 = 135;
const IP6_HIP: u8 = 139;
const IP6_SHIM6: u8 = 140;

/// A pcap / pcapng link-layer header type (`LINKTYPE_*` value).
#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug)]
pub struct LinkType(pub u32);

impl LinkType {
    /// BSD loopback; 4-byte address family in host byte order.
    pub const NULL: Self = Self(0);
    /// Ethernet II (with optional VLAN tags).
    pub const ETHERNET: Self = Self(1);
    /// Raw IPv4 or IPv6, version from the first nibble.
    pub const RAW: Self = Self(101);
    /// OpenBSD loopback; 4-byte address family in network byte order.
    pub const LOOP: Self = Self(108);
    /// Linux cooked capture v1.
    pub const LINUX_SLL: Self = Self(113);
    /// Raw IPv4 only.
    pub const IPV4: Self = Self(228);
    /// Raw IPv6 only.
    pub const IPV6: Self = Self(229);
    /// Linux cooked capture v2.
    pub const LINUX_SLL2: Self = Self(276);

    /// Whether [`decode_frame`] understands this link type.
    pub fn is_supported(self) -> bool {
        matches!(
            self,
            Self::NULL
                | Self::ETHERNET
                | Self::RAW
                | Self::LOOP
                | Self::LINUX_SLL
                | Self::IPV4
                | Self::IPV6
                | Self::LINUX_SLL2
        )
    }
}

impl fmt::Display for LinkType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let name = match *self {
            Self::NULL => "NULL",
            Self::ETHERNET => "ETHERNET",
            Self::RAW => "RAW",
            Self::LOOP => "LOOP",
            Self::LINUX_SLL => "LINUX_SLL",
            Self::IPV4 => "IPV4",
            Self::IPV6 => "IPV6",
            Self::LINUX_SLL2 => "LINUX_SLL2",
            _ => return write!(f, "LINKTYPE({})", self.0),
        };
        f.write_str(name)
    }
}

/// The protocol layer at which decoding stopped.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Layer {
    Link,
    Ipv4,
    Ipv6,
    Udp,
}

/// Why a frame did not decode to a UDP datagram.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum DecodeError {
    /// The link type is not one we decode.
    UnsupportedLinkType(LinkType),
    /// A header, or a length a header declares, runs past the captured bytes
    /// (short frame, or a snap-length-limited capture).
    Truncated(Layer),
    /// A header field is inconsistent (bad version, length below minimum,
    /// too many VLAN tags / extension headers, ...).
    Malformed(Layer, &'static str),
    /// Valid frame that does not carry IPv4/IPv6 (ARP, LLC, netlink, ...).
    NotIp,
    /// Valid IP packet that is not (reachably) UDP: TCP, ICMP, ESP, ...
    NotUdp,
    /// Part of a fragmented IP datagram; only returned by [`decode_udp`]. Use
    /// [`decode_frame`] plus [`crate::reassembly::Reassembler`] to recover it.
    Fragment,
}

impl fmt::Display for DecodeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::UnsupportedLinkType(l) => write!(f, "unsupported link type {l}"),
            Self::Truncated(l) => write!(f, "truncated at {l:?} layer"),
            Self::Malformed(l, why) => write!(f, "malformed {l:?}: {why}"),
            Self::NotIp => f.write_str("not an IP packet"),
            Self::NotUdp => f.write_str("not UDP"),
            Self::Fragment => f.write_str("IP fragment"),
        }
    }
}

impl std::error::Error for DecodeError {}

/// A decoded UDP datagram, borrowing its payload from the captured frame.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct UdpDatagram<'a> {
    pub src: IpAddr,
    pub dst: IpAddr,
    pub src_port: u16,
    pub dst_port: u16,
    pub payload: &'a [u8],
}

/// One fragment of a fragmented IPv4/IPv6 datagram.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct IpFragment<'a> {
    pub src: IpAddr,
    pub dst: IpAddr,
    /// IPv4 identification (16 bits) or IPv6 fragment identification.
    pub id: u32,
    /// IPv4 protocol, or for IPv6 the next-header value of the fragmentable
    /// part (UDP or an extension header that precedes it).
    pub protocol: u8,
    /// Byte offset of `data` in the reassembled payload.
    pub offset: usize,
    /// More fragments follow (MF / M flag).
    pub more: bool,
    /// The fragment's bytes.
    pub data: &'a [u8],
}

/// Result of decoding a frame down to the transport layer.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Decoded<'a> {
    /// A complete UDP datagram.
    Udp(UdpDatagram<'a>),
    /// A fragment of a (possibly UDP) datagram that must be reassembled.
    Fragment(IpFragment<'a>),
}

fn be16(b: &[u8], at: usize) -> Option<u16> {
    let s = b.get(at..at.checked_add(2)?)?;
    Some(u16::from_be_bytes([s[0], s[1]]))
}

fn be32(b: &[u8], at: usize) -> Option<u32> {
    let s = b.get(at..at.checked_add(4)?)?;
    Some(u32::from_be_bytes([s[0], s[1], s[2], s[3]]))
}

fn le32(b: &[u8], at: usize) -> Option<u32> {
    let s = b.get(at..at.checked_add(4)?)?;
    Some(u32::from_le_bytes([s[0], s[1], s[2], s[3]]))
}

/// Decode a captured frame of the given link type down to UDP, returning
/// fragments as [`Decoded::Fragment`].
pub fn decode_frame(link: LinkType, frame: &[u8]) -> Result<Decoded<'_>, DecodeError> {
    let (expected, ip) = link_payload(link, frame)?;
    decode_ip_expect(expected, ip)
}

/// Decode a captured frame to a complete UDP datagram. Fragments yield
/// [`DecodeError::Fragment`] (non-first fragments carry no UDP header; first
/// fragments carry only part of the payload).
pub fn decode_udp(link: LinkType, frame: &[u8]) -> Result<UdpDatagram<'_>, DecodeError> {
    match decode_frame(link, frame)? {
        Decoded::Udp(u) => Ok(u),
        Decoded::Fragment(_) => Err(DecodeError::Fragment),
    }
}

/// Decode a bare IPv4 or IPv6 packet (version from the first nibble).
pub fn decode_ip(packet: &[u8]) -> Result<Decoded<'_>, DecodeError> {
    decode_ip_expect(None, packet)
}

/// Strip the link-layer header. Returns the IP version the link layer
/// announces (`None` = infer from the first nibble) and the network packet.
fn link_payload(link: LinkType, frame: &[u8]) -> Result<(Option<u8>, &[u8]), DecodeError> {
    match link {
        LinkType::ETHERNET => {
            let et = be16(frame, 12).ok_or(DecodeError::Truncated(Layer::Link))?;
            ethertype_dispatch(et, &frame[14..])
        }
        LinkType::LINUX_SLL => {
            // pkttype(2) hatype(2) halen(2) addr(8) protocol(2)
            if frame.len() < 16 {
                return Err(DecodeError::Truncated(Layer::Link));
            }
            if be16(frame, 2) == Some(ARPHRD_NETLINK) {
                return Err(DecodeError::NotIp);
            }
            let proto = be16(frame, 14).ok_or(DecodeError::Truncated(Layer::Link))?;
            ethertype_dispatch(proto, &frame[16..])
        }
        LinkType::LINUX_SLL2 => {
            // protocol(2) reserved(2) ifindex(4) hatype(2) pkttype(1) halen(1) addr(8)
            if frame.len() < 20 {
                return Err(DecodeError::Truncated(Layer::Link));
            }
            if be16(frame, 8) == Some(ARPHRD_NETLINK) {
                return Err(DecodeError::NotIp);
            }
            let proto = be16(frame, 0).ok_or(DecodeError::Truncated(Layer::Link))?;
            ethertype_dispatch(proto, &frame[20..])
        }
        LinkType::RAW => Ok((None, frame)),
        LinkType::IPV4 => Ok((Some(4), frame)),
        LinkType::IPV6 => Ok((Some(6), frame)),
        LinkType::NULL => {
            let le = le32(frame, 0).ok_or(DecodeError::Truncated(Layer::Link))?;
            let be = be32(frame, 0).ok_or(DecodeError::Truncated(Layer::Link))?;
            // Host byte order of the *capturing* machine, which we do not
            // know. Every AF_ value fits in 16 bits, so whichever reading
            // keeps the high half zero is the right one.
            let family = if le & 0xffff_0000 == 0 { le } else { be };
            Ok((Some(family_to_version(family)?), &frame[4..]))
        }
        LinkType::LOOP => {
            let family = be32(frame, 0).ok_or(DecodeError::Truncated(Layer::Link))?;
            Ok((Some(family_to_version(family)?), &frame[4..]))
        }
        other => Err(DecodeError::UnsupportedLinkType(other)),
    }
}

/// BSD address family -> IP version. AF_INET6 differs per OS: 10 (Linux),
/// 24 (NetBSD/OpenBSD), 28 (FreeBSD/DragonFly), 30 (macOS).
fn family_to_version(family: u32) -> Result<u8, DecodeError> {
    match family {
        2 => Ok(4),
        10 | 24 | 28 | 30 => Ok(6),
        _ => Err(DecodeError::NotIp),
    }
}

/// Follow VLAN tags to the IP ethertype.
fn ethertype_dispatch(
    mut ethertype: u16,
    mut rest: &[u8],
) -> Result<(Option<u8>, &[u8]), DecodeError> {
    let mut tags = 0;
    loop {
        match ethertype {
            ETHERTYPE_IPV4 => return Ok((Some(4), rest)),
            ETHERTYPE_IPV6 => return Ok((Some(6), rest)),
            ETHERTYPE_VLAN | ETHERTYPE_QINQ | ETHERTYPE_QINQ_LEGACY => {
                if tags == MAX_VLAN_TAGS {
                    return Err(DecodeError::Malformed(Layer::Link, "too many VLAN tags"));
                }
                // TCI(2) + inner ethertype(2)
                ethertype = be16(rest, 2).ok_or(DecodeError::Truncated(Layer::Link))?;
                rest = &rest[4..];
                tags += 1;
            }
            _ => return Err(DecodeError::NotIp),
        }
    }
}

fn decode_ip_expect(expected: Option<u8>, p: &[u8]) -> Result<Decoded<'_>, DecodeError> {
    let layer_of = |v: Option<u8>| match v {
        Some(6) => Layer::Ipv6,
        Some(4) => Layer::Ipv4,
        _ => Layer::Link,
    };
    let Some(&first) = p.first() else {
        return Err(DecodeError::Truncated(layer_of(expected)));
    };
    let version = first >> 4;
    if let Some(exp) = expected {
        if exp != version {
            return Err(DecodeError::Malformed(
                layer_of(expected),
                "IP version does not match link-layer protocol",
            ));
        }
    }
    match version {
        4 => decode_ipv4(p),
        6 => decode_ipv6(p),
        _ => Err(DecodeError::NotIp),
    }
}

fn decode_ipv4(p: &[u8]) -> Result<Decoded<'_>, DecodeError> {
    const L: Layer = Layer::Ipv4;
    if p.len() < 20 {
        return Err(DecodeError::Truncated(L));
    }
    if p[0] >> 4 != 4 {
        return Err(DecodeError::Malformed(L, "version is not 4"));
    }
    let ihl = usize::from(p[0] & 0x0f) * 4;
    if ihl < 20 {
        return Err(DecodeError::Malformed(L, "header length below 20 bytes"));
    }
    if ihl > p.len() {
        return Err(DecodeError::Truncated(L));
    }
    let total = usize::from(be16(p, 2).ok_or(DecodeError::Truncated(L))?);
    if total < ihl {
        return Err(DecodeError::Malformed(
            L,
            "total length below header length",
        ));
    }
    if total > p.len() {
        return Err(DecodeError::Truncated(L));
    }
    let p = &p[..total]; // drop link padding / FCS
    let frag = be16(p, 6).ok_or(DecodeError::Truncated(L))?;
    let more = frag & 0x2000 != 0;
    let offset = usize::from(frag & 0x1fff) * 8;
    let protocol = p[9];
    let src = IpAddr::V4(Ipv4Addr::new(p[12], p[13], p[14], p[15]));
    let dst = IpAddr::V4(Ipv4Addr::new(p[16], p[17], p[18], p[19]));
    let data = &p[ihl..];
    if protocol != IPPROTO_UDP {
        return Err(DecodeError::NotUdp);
    }
    if more || offset != 0 {
        let id = u32::from(be16(p, 4).ok_or(DecodeError::Truncated(L))?);
        return Ok(Decoded::Fragment(IpFragment {
            src,
            dst,
            id,
            protocol,
            offset,
            more,
            data,
        }));
    }
    decode_udp_segment(src, dst, data).map(Decoded::Udp)
}

fn ipv6_addr(b: &[u8]) -> Ipv6Addr {
    let mut a = [0u8; 16];
    a.copy_from_slice(&b[..16]);
    Ipv6Addr::from(a)
}

fn decode_ipv6(p: &[u8]) -> Result<Decoded<'_>, DecodeError> {
    const L: Layer = Layer::Ipv6;
    if p.len() < 40 {
        return Err(DecodeError::Truncated(L));
    }
    if p[0] >> 4 != 6 {
        return Err(DecodeError::Malformed(L, "version is not 6"));
    }
    let plen = usize::from(be16(p, 4).ok_or(DecodeError::Truncated(L))?);
    if plen == 0 {
        return Err(DecodeError::Malformed(
            L,
            "zero payload length (jumbogram) unsupported",
        ));
    }
    if 40 + plen > p.len() {
        return Err(DecodeError::Truncated(L));
    }
    let src = IpAddr::V6(ipv6_addr(&p[8..24]));
    let dst = IpAddr::V6(ipv6_addr(&p[24..40]));
    walk_ipv6(src, dst, p[6], &p[40..40 + plen], true)
}

/// Decode the upper layers of a *reassembled* IPv6 payload, starting from the
/// fragment header's next-header value. A second fragment header is malformed.
pub fn decode_ipv6_upper(
    src: IpAddr,
    dst: IpAddr,
    next_header: u8,
    payload: &[u8],
) -> Result<UdpDatagram<'_>, DecodeError> {
    match walk_ipv6(src, dst, next_header, payload, false)? {
        Decoded::Udp(u) => Ok(u),
        Decoded::Fragment(_) => Err(DecodeError::Fragment), // unreachable by construction
    }
}

fn is_ipv6_ext_header(nh: u8) -> bool {
    matches!(
        nh,
        IP6_HOP_BY_HOP
            | IP6_ROUTING
            | IP6_FRAGMENT
            | IP6_AH
            | IP6_DEST_OPTS
            | IP6_MOBILITY
            | IP6_HIP
            | IP6_SHIM6
    )
}

fn walk_ipv6(
    src: IpAddr,
    dst: IpAddr,
    mut nh: u8,
    buf: &[u8],
    allow_fragment: bool,
) -> Result<Decoded<'_>, DecodeError> {
    const L: Layer = Layer::Ipv6;
    let mut off = 0usize;
    for _ in 0..=MAX_IPV6_EXT_HEADERS {
        let rest = &buf[off..];
        match nh {
            IPPROTO_UDP => return decode_udp_segment(src, dst, rest).map(Decoded::Udp),
            IP6_FRAGMENT => {
                if !allow_fragment {
                    return Err(DecodeError::Malformed(L, "nested fragment header"));
                }
                if rest.len() < 8 {
                    return Err(DecodeError::Truncated(L));
                }
                let frag_nh = rest[0];
                let fo = be16(rest, 2).ok_or(DecodeError::Truncated(L))?;
                let offset = usize::from(fo & 0xfff8);
                let more = fo & 1 != 0;
                let id = be32(rest, 4).ok_or(DecodeError::Truncated(L))?;
                off += 8;
                if offset == 0 && !more {
                    // Atomic fragment (RFC 6946): just a header to skip.
                    nh = frag_nh;
                    continue;
                }
                if frag_nh != IPPROTO_UDP && !is_ipv6_ext_header(frag_nh) {
                    return Err(DecodeError::NotUdp);
                }
                return Ok(Decoded::Fragment(IpFragment {
                    src,
                    dst,
                    id,
                    protocol: frag_nh,
                    offset,
                    more,
                    data: &buf[off..],
                }));
            }
            IP6_AH => {
                if rest.len() < 2 {
                    return Err(DecodeError::Truncated(L));
                }
                let len = (usize::from(rest[1]) + 2) * 4;
                if len > rest.len() {
                    return Err(DecodeError::Truncated(L));
                }
                nh = rest[0];
                off += len;
            }
            h if is_ipv6_ext_header(h) => {
                if rest.len() < 2 {
                    return Err(DecodeError::Truncated(L));
                }
                let len = (usize::from(rest[1]) + 1) * 8;
                if len > rest.len() {
                    return Err(DecodeError::Truncated(L));
                }
                nh = rest[0];
                off += len;
            }
            _ => return Err(DecodeError::NotUdp), // TCP, ICMPv6, ESP, no-next-header, ...
        }
    }
    Err(DecodeError::Malformed(L, "too many extension headers"))
}

/// Decode a UDP header + payload carried between `src` and `dst`.
pub fn decode_udp_segment(
    src: IpAddr,
    dst: IpAddr,
    seg: &[u8],
) -> Result<UdpDatagram<'_>, DecodeError> {
    const L: Layer = Layer::Udp;
    if seg.len() < 8 {
        return Err(DecodeError::Truncated(L));
    }
    let src_port = be16(seg, 0).ok_or(DecodeError::Truncated(L))?;
    let dst_port = be16(seg, 2).ok_or(DecodeError::Truncated(L))?;
    let len = usize::from(be16(seg, 4).ok_or(DecodeError::Truncated(L))?);
    if len < 8 {
        return Err(DecodeError::Malformed(L, "length below 8"));
    }
    if len > seg.len() {
        return Err(DecodeError::Truncated(L));
    }
    Ok(UdpDatagram {
        src,
        dst,
        src_port,
        dst_port,
        payload: &seg[8..len],
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::synth;

    const SRC4: Ipv4Addr = Ipv4Addr::new(10, 0, 0, 5);
    const DST4: Ipv4Addr = Ipv4Addr::new(10, 0, 0, 6);

    fn src6() -> Ipv6Addr {
        "fd00::5".parse().unwrap()
    }
    fn dst6() -> Ipv6Addr {
        "fd00::6".parse().unwrap()
    }

    fn v4_packet(payload: &[u8]) -> Vec<u8> {
        synth::ipv4_udp(SRC4, DST4, 40000, 7410, payload)
    }

    fn check_udp(d: &UdpDatagram<'_>, payload: &[u8]) {
        assert_eq!(d.src_port, 40000);
        assert_eq!(d.dst_port, 7410);
        assert_eq!(d.payload, payload);
    }

    #[test]
    fn ethernet_ipv4_udp() {
        let f = synth::ethernet(ETHERTYPE_IPV4, &v4_packet(b"RTPShello"));
        let d = decode_udp(LinkType::ETHERNET, &f).unwrap();
        check_udp(&d, b"RTPShello");
        assert_eq!(d.src, IpAddr::V4(SRC4));
        assert_eq!(d.dst, IpAddr::V4(DST4));
    }

    #[test]
    fn ethernet_padding_and_fcs_are_trimmed() {
        let mut f = synth::ethernet(ETHERTYPE_IPV4, &v4_packet(b"x"));
        f.extend_from_slice(&[0xee; 20]); // padding to 60 + 4-byte FCS
        check_udp(&decode_udp(LinkType::ETHERNET, &f).unwrap(), b"x");
    }

    #[test]
    fn ethernet_single_and_double_vlan() {
        let ip = v4_packet(b"vlan");
        let single = synth::ethernet_vlan(&[(ETHERTYPE_VLAN, 100)], ETHERTYPE_IPV4, &ip);
        check_udp(&decode_udp(LinkType::ETHERNET, &single).unwrap(), b"vlan");
        let double = synth::ethernet_vlan(
            &[(ETHERTYPE_QINQ, 10), (ETHERTYPE_VLAN, 20)],
            ETHERTYPE_IPV4,
            &ip,
        );
        check_udp(&decode_udp(LinkType::ETHERNET, &double).unwrap(), b"vlan");
        let legacy = synth::ethernet_vlan(
            &[(ETHERTYPE_QINQ_LEGACY, 10), (ETHERTYPE_VLAN, 20)],
            ETHERTYPE_IPV4,
            &ip,
        );
        check_udp(&decode_udp(LinkType::ETHERNET, &legacy).unwrap(), b"vlan");
        let triple = synth::ethernet_vlan(
            &[
                (ETHERTYPE_QINQ, 1),
                (ETHERTYPE_VLAN, 2),
                (ETHERTYPE_VLAN, 3),
            ],
            ETHERTYPE_IPV4,
            &ip,
        );
        assert_eq!(
            decode_udp(LinkType::ETHERNET, &triple),
            Err(DecodeError::Malformed(Layer::Link, "too many VLAN tags"))
        );
        // Tag present but cut short.
        let mut cut = synth::ethernet(ETHERTYPE_VLAN, &[]);
        cut.extend_from_slice(&[0, 100]);
        assert_eq!(
            decode_udp(LinkType::ETHERNET, &cut),
            Err(DecodeError::Truncated(Layer::Link))
        );
    }

    #[test]
    fn ethernet_non_ip_and_llc() {
        let arp = synth::ethernet(0x0806, &[0; 28]);
        assert_eq!(
            decode_udp(LinkType::ETHERNET, &arp),
            Err(DecodeError::NotIp)
        );
        let llc = synth::ethernet(0x0040, &[0; 64]); // 802.3 length field
        assert_eq!(
            decode_udp(LinkType::ETHERNET, &llc),
            Err(DecodeError::NotIp)
        );
        assert_eq!(
            decode_udp(LinkType::ETHERNET, &[0; 13]),
            Err(DecodeError::Truncated(Layer::Link))
        );
    }

    #[test]
    fn ethertype_version_mismatch() {
        let f = synth::ethernet(ETHERTYPE_IPV6, &v4_packet(b"x"));
        assert!(matches!(
            decode_udp(LinkType::ETHERNET, &f),
            Err(DecodeError::Malformed(Layer::Ipv6, _))
        ));
    }

    #[test]
    fn linux_sll_v1_and_v2() {
        let ip = v4_packet(b"sll");
        let f1 = synth::linux_sll(ETHERTYPE_IPV4, &ip);
        check_udp(&decode_udp(LinkType::LINUX_SLL, &f1).unwrap(), b"sll");
        let f2 = synth::linux_sll2(ETHERTYPE_IPV4, &ip);
        check_udp(&decode_udp(LinkType::LINUX_SLL2, &f2).unwrap(), b"sll");
        // VLAN inside cooked capture (tag not offloaded).
        let mut inner = vec![0, 7];
        inner.extend_from_slice(&ETHERTYPE_IPV4.to_be_bytes());
        inner.extend_from_slice(&ip);
        let f3 = synth::linux_sll(ETHERTYPE_VLAN, &inner);
        check_udp(&decode_udp(LinkType::LINUX_SLL, &f3).unwrap(), b"sll");
        // Short headers.
        assert_eq!(
            decode_udp(LinkType::LINUX_SLL, &f1[..15]),
            Err(DecodeError::Truncated(Layer::Link))
        );
        assert_eq!(
            decode_udp(LinkType::LINUX_SLL2, &f2[..19]),
            Err(DecodeError::Truncated(Layer::Link))
        );
        // Netlink captures on "any" are not IP even if the protocol says so.
        let mut nl = f1.clone();
        nl[2..4].copy_from_slice(&ARPHRD_NETLINK.to_be_bytes());
        assert_eq!(
            decode_udp(LinkType::LINUX_SLL, &nl),
            Err(DecodeError::NotIp)
        );
        let mut nl2 = f2.clone();
        nl2[8..10].copy_from_slice(&ARPHRD_NETLINK.to_be_bytes());
        assert_eq!(
            decode_udp(LinkType::LINUX_SLL2, &nl2),
            Err(DecodeError::NotIp)
        );
    }

    #[test]
    fn raw_ip_variants() {
        let ip4 = v4_packet(b"raw");
        check_udp(&decode_udp(LinkType::RAW, &ip4).unwrap(), b"raw");
        check_udp(&decode_udp(LinkType::IPV4, &ip4).unwrap(), b"raw");
        assert!(matches!(
            decode_udp(LinkType::IPV6, &ip4),
            Err(DecodeError::Malformed(Layer::Ipv6, _))
        ));
        let ip6 = synth::ipv6_udp(src6(), dst6(), 40000, 7410, &[], b"raw6");
        check_udp(&decode_udp(LinkType::RAW, &ip6).unwrap(), b"raw6");
        check_udp(&decode_udp(LinkType::IPV6, &ip6).unwrap(), b"raw6");
        assert_eq!(
            decode_udp(LinkType::RAW, &[0x50; 40]),
            Err(DecodeError::NotIp)
        );
        assert_eq!(
            decode_udp(LinkType::RAW, &[]),
            Err(DecodeError::Truncated(Layer::Link))
        );
    }

    #[test]
    fn null_and_loop_in_both_byte_orders() {
        let ip4 = v4_packet(b"lo");
        let ip6 = synth::ipv6_udp(src6(), dst6(), 40000, 7410, &[], b"lo");
        for fam6 in [10u32, 24, 28, 30] {
            for le in [true, false] {
                let f = synth::null_loopback(fam6, le, &ip6);
                check_udp(&decode_udp(LinkType::NULL, &f).unwrap(), b"lo");
            }
        }
        for le in [true, false] {
            let f = synth::null_loopback(2, le, &ip4);
            check_udp(&decode_udp(LinkType::NULL, &f).unwrap(), b"lo");
        }
        let lp = synth::null_loopback(2, false, &ip4);
        check_udp(&decode_udp(LinkType::LOOP, &lp).unwrap(), b"lo");
        let unknown = synth::null_loopback(7, true, &ip4);
        assert_eq!(
            decode_udp(LinkType::NULL, &unknown),
            Err(DecodeError::NotIp)
        );
        assert_eq!(
            decode_udp(LinkType::NULL, &[2, 0, 0]),
            Err(DecodeError::Truncated(Layer::Link))
        );
    }

    #[test]
    fn unsupported_link_type() {
        assert_eq!(
            decode_udp(LinkType(147), &[0; 64]),
            Err(DecodeError::UnsupportedLinkType(LinkType(147)))
        );
        assert!(!LinkType(147).is_supported());
        assert!(LinkType::LINUX_SLL2.is_supported());
        assert_eq!(LinkType(147).to_string(), "LINKTYPE(147)");
        assert_eq!(LinkType::ETHERNET.to_string(), "ETHERNET");
    }

    #[test]
    fn ipv4_options_are_skipped() {
        let mut ip = v4_packet(b"opts");
        // Insert 8 bytes of options (NOPs + EOL) after the 20-byte header.
        let opts = [1u8, 1, 1, 1, 1, 1, 1, 0];
        ip.splice(20..20, opts);
        ip[0] = 0x47; // IHL = 7
        let total = ip.len() as u16;
        ip[2..4].copy_from_slice(&total.to_be_bytes());
        check_udp(&decode_udp(LinkType::RAW, &ip).unwrap(), b"opts");
    }

    #[test]
    fn ipv4_bogus_lengths() {
        let ip = v4_packet(b"abc");
        let mut bad_ihl = ip.clone();
        bad_ihl[0] = 0x44; // IHL 4 -> 16 bytes
        assert!(matches!(
            decode_udp(LinkType::RAW, &bad_ihl),
            Err(DecodeError::Malformed(Layer::Ipv4, _))
        ));
        let mut huge_ihl = ip.clone();
        huge_ihl[0] = 0x4f; // 60 bytes, longer than packet
        assert_eq!(
            decode_udp(LinkType::RAW, &huge_ihl),
            Err(DecodeError::Truncated(Layer::Ipv4))
        );
        let mut short_total = ip.clone();
        short_total[2..4].copy_from_slice(&10u16.to_be_bytes());
        assert!(matches!(
            decode_udp(LinkType::RAW, &short_total),
            Err(DecodeError::Malformed(Layer::Ipv4, _))
        ));
        let mut long_total = ip.clone();
        long_total[2..4].copy_from_slice(&0xffffu16.to_be_bytes());
        assert_eq!(
            decode_udp(LinkType::RAW, &long_total),
            Err(DecodeError::Truncated(Layer::Ipv4))
        );
        // Total length cutting into the UDP header.
        let mut cut_udp = ip.clone();
        cut_udp[2..4].copy_from_slice(&24u16.to_be_bytes());
        assert_eq!(
            decode_udp(LinkType::RAW, &cut_udp),
            Err(DecodeError::Truncated(Layer::Udp))
        );
        let mut tcp = ip;
        tcp[9] = 6;
        assert_eq!(decode_udp(LinkType::RAW, &tcp), Err(DecodeError::NotUdp));
    }

    #[test]
    fn udp_bogus_lengths() {
        let ip = v4_packet(b"abcdef");
        let mut small = ip.clone();
        small[24..26].copy_from_slice(&7u16.to_be_bytes());
        assert!(matches!(
            decode_udp(LinkType::RAW, &small),
            Err(DecodeError::Malformed(Layer::Udp, _))
        ));
        let mut big = ip.clone();
        big[24..26].copy_from_slice(&100u16.to_be_bytes());
        assert_eq!(
            decode_udp(LinkType::RAW, &big),
            Err(DecodeError::Truncated(Layer::Udp))
        );
        // UDP length shorter than IP payload: trailing bytes are trimmed.
        let mut shorter = ip;
        shorter[24..26].copy_from_slice(&11u16.to_be_bytes());
        assert_eq!(decode_udp(LinkType::RAW, &shorter).unwrap().payload, b"abc");
    }

    #[test]
    fn every_truncation_is_an_error_not_a_panic() {
        let frames: Vec<(LinkType, Vec<u8>)> = vec![
            (
                LinkType::ETHERNET,
                synth::ethernet(ETHERTYPE_IPV4, &v4_packet(b"RTPS0123")),
            ),
            (
                LinkType::ETHERNET,
                synth::ethernet(
                    ETHERTYPE_IPV6,
                    &synth::ipv6_udp(
                        src6(),
                        dst6(),
                        40000,
                        7410,
                        &[(0, 8), (60, 16)],
                        b"RTPS0123",
                    ),
                ),
            ),
            (
                LinkType::LINUX_SLL,
                synth::linux_sll(ETHERTYPE_IPV4, &v4_packet(b"RTPS0123")),
            ),
            (
                LinkType::LINUX_SLL2,
                synth::linux_sll2(ETHERTYPE_IPV4, &v4_packet(b"RTPS0123")),
            ),
            (
                LinkType::NULL,
                synth::null_loopback(2, true, &v4_packet(b"RTPS0123")),
            ),
        ];
        for (lt, f) in frames {
            assert!(decode_udp(lt, &f).is_ok(), "{lt} full frame must decode");
            for cut in 0..f.len() {
                assert!(
                    decode_frame(lt, &f[..cut]).is_err(),
                    "{lt} cut at {cut} decoded"
                );
            }
        }
    }

    #[test]
    fn ipv6_extension_headers_are_walked() {
        // hop-by-hop (8), routing (24), destination options (16), then UDP.
        let p = synth::ipv6_udp(
            src6(),
            dst6(),
            40000,
            7410,
            &[(0, 8), (43, 24), (60, 16)],
            b"ext",
        );
        let d = decode_udp(LinkType::RAW, &p).unwrap();
        check_udp(&d, b"ext");
        assert_eq!(d.src, IpAddr::V6(src6()));
        // AH uses 4-byte units: (len+2)*4.
        let mut ah = synth::ipv6_udp(src6(), dst6(), 40000, 7410, &[(51, 16)], b"ah");
        ah[40 + 1] = 2; // (2+2)*4 = 16
        check_udp(&decode_udp(LinkType::RAW, &ah).unwrap(), b"ah");
    }

    #[test]
    fn ipv6_ext_header_bounds() {
        // Extension header claiming more bytes than present.
        let mut p = synth::ipv6_udp(src6(), dst6(), 40000, 7410, &[(60, 8)], b"x");
        p[41] = 200;
        assert_eq!(
            decode_udp(LinkType::RAW, &p),
            Err(DecodeError::Truncated(Layer::Ipv6))
        );
        // Too many extension headers.
        let many: Vec<(u8, usize)> = (0..=MAX_IPV6_EXT_HEADERS).map(|_| (60u8, 8)).collect();
        let p = synth::ipv6_udp(src6(), dst6(), 40000, 7410, &many, b"x");
        assert!(matches!(
            decode_udp(LinkType::RAW, &p),
            Err(DecodeError::Malformed(Layer::Ipv6, _))
        ));
        // Exactly the limit is fine.
        let ok: Vec<(u8, usize)> = (0..MAX_IPV6_EXT_HEADERS).map(|_| (60u8, 8)).collect();
        let p = synth::ipv6_udp(src6(), dst6(), 40000, 7410, &ok, b"x");
        assert!(decode_udp(LinkType::RAW, &p).is_ok());
        // ESP and no-next-header are not UDP.
        let mut esp = synth::ipv6_udp(src6(), dst6(), 40000, 7410, &[], b"x");
        esp[6] = 50;
        assert_eq!(decode_udp(LinkType::RAW, &esp), Err(DecodeError::NotUdp));
        esp[6] = 59;
        assert_eq!(decode_udp(LinkType::RAW, &esp), Err(DecodeError::NotUdp));
        // Payload length past the buffer; zero payload length.
        let mut long = synth::ipv6_udp(src6(), dst6(), 40000, 7410, &[], b"x");
        long[4..6].copy_from_slice(&500u16.to_be_bytes());
        assert_eq!(
            decode_udp(LinkType::RAW, &long),
            Err(DecodeError::Truncated(Layer::Ipv6))
        );
        long[4..6].copy_from_slice(&0u16.to_be_bytes());
        assert!(matches!(
            decode_udp(LinkType::RAW, &long),
            Err(DecodeError::Malformed(Layer::Ipv6, _))
        ));
    }

    #[test]
    fn ipv4_fragments_are_flagged() {
        let ip = v4_packet(b"0123456789abcdef");
        let frags = synth::ipv4_fragment(&ip, 8);
        assert_eq!(frags.len(), 3); // 24 bytes of UDP -> 8 + 8 + 8
        assert_eq!(
            decode_udp(LinkType::RAW, &frags[0]),
            Err(DecodeError::Fragment)
        );
        assert_eq!(
            decode_udp(LinkType::RAW, &frags[1]),
            Err(DecodeError::Fragment)
        );
        match decode_frame(LinkType::RAW, &frags[1]).unwrap() {
            Decoded::Fragment(f) => {
                assert_eq!(f.offset, 8);
                assert!(f.more);
                assert_eq!(f.protocol, IPPROTO_UDP);
                assert_eq!(f.data.len(), 8);
            }
            other => panic!("{other:?}"),
        }
        match decode_frame(LinkType::RAW, &frags[2]).unwrap() {
            Decoded::Fragment(f) => {
                assert_eq!(f.offset, 16);
                assert!(!f.more);
            }
            other => panic!("{other:?}"),
        }
    }

    #[test]
    fn ipv6_fragments_and_atomic_fragment() {
        let p = synth::ipv6_udp(src6(), dst6(), 40000, 7410, &[], b"0123456789abcdef");
        let frags = synth::ipv6_fragment(&p, 16, 0xdead_beef);
        assert_eq!(frags.len(), 2);
        match decode_frame(LinkType::RAW, &frags[0]).unwrap() {
            Decoded::Fragment(f) => {
                assert_eq!(f.id, 0xdead_beef);
                assert_eq!(f.offset, 0);
                assert!(f.more);
                assert_eq!(f.protocol, IPPROTO_UDP);
            }
            other => panic!("{other:?}"),
        }
        // Atomic fragment: offset 0, M = 0 -> plain datagram.
        let atomic = synth::ipv6_fragment(&p, 4096, 1);
        assert_eq!(atomic.len(), 1);
        check_udp(
            &decode_udp(LinkType::RAW, &atomic[0]).unwrap(),
            b"0123456789abcdef",
        );
        // Fragment of a TCP datagram is not ours.
        let mut tcp = frags[0].clone();
        tcp[40] = 6;
        assert_eq!(decode_frame(LinkType::RAW, &tcp), Err(DecodeError::NotUdp));
        // A nested fragment header after reassembly is malformed.
        assert!(matches!(
            decode_ipv6_upper(
                IpAddr::V6(src6()),
                IpAddr::V6(dst6()),
                44,
                &[17, 0, 0, 0, 0, 0, 0, 0]
            ),
            Err(DecodeError::Malformed(Layer::Ipv6, _))
        ));
    }

    #[test]
    fn errors_display() {
        assert_eq!(DecodeError::NotUdp.to_string(), "not UDP");
        assert_eq!(
            DecodeError::Truncated(Layer::Udp).to_string(),
            "truncated at Udp layer"
        );
    }
}
