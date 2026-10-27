//! IPv4 / UDP framing of a queued packet.
//!
//! NFQUEUE hands the gateway the network-layer packet (for bridged IPv4 with
//! `br_netfilter`: the IPv4 header onwards). [`parse_ipv4_udp`] locates the
//! UDP payload and refuses everything the gateway must not decide on:
//!
//! - not IPv4, a header shorter than 20 octets or longer than the packet, a
//!   bad IPv4 header checksum (the kernel's bridge input already drops those;
//!   checked again because a rewrite must never resurrect a packet the
//!   receiver would drop);
//! - an IP **fragment** (MF set or a non-zero offset): the gateway only
//!   decides on complete datagrams. Deployment enables defragmentation in
//!   front of the queue (see the README); a fragment that still reaches the
//!   queue is dropped;
//! - not UDP, a UDP length that disagrees with the IP total length, or a
//!   packet longer than its IP total length (trailing octets);
//! - a **wrong UDP checksum** ([`UdpChecksumStatus::Bad`], and the bare
//!   offload pseudo-sum, which on a forwarded packet is also wrong): the
//!   receiving host would drop such a datagram, and after a rewrite the
//!   gateway writes a correct checksum, so deciding on it would turn a frame
//!   the robot ignores into one it executes.
//!
//! [`refresh_udp_checksum`] recomputes the checksum after the payload was
//! rewritten (same length, so the IPv4 header and its checksum are
//! unchanged). A datagram sent without a checksum (field 0, legal over IPv4)
//! keeps 0.

use std::net::{IpAddr, Ipv4Addr};

use robodr_capture::checksum::{ipv4_header_valid, udp_checksum, udp_checksum_status};
use robodr_capture::UdpChecksumStatus;

/// Where the parts of a queued IPv4 / UDP packet are.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Ipv4Udp {
    pub src: Ipv4Addr,
    pub dst: Ipv4Addr,
    pub src_port: u16,
    pub dst_port: u16,
    /// Offset of the UDP header.
    pub udp_start: usize,
    /// Offset of the UDP payload (`udp_start + 8`).
    pub payload_start: usize,
    /// End of the UDP datagram (= packet length).
    pub end: usize,
    /// The UDP checksum field was 0 (not computed).
    pub checksum_zero: bool,
}

impl Ipv4Udp {
    /// The UDP payload range.
    pub fn payload(&self) -> std::ops::Range<usize> {
        self.payload_start..self.end
    }
}

/// Why a packet is not a decidable IPv4 / UDP datagram.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum IpError {
    NotIpv4,
    Truncated,
    BadHeaderChecksum,
    Fragment,
    NotUdp,
    BadLength,
    BadUdpChecksum,
}

impl IpError {
    pub fn as_str(self) -> &'static str {
        match self {
            IpError::NotIpv4 => "not_ipv4",
            IpError::Truncated => "truncated",
            IpError::BadHeaderChecksum => "bad_ip_header_checksum",
            IpError::Fragment => "ip_fragment",
            IpError::NotUdp => "not_udp",
            IpError::BadLength => "bad_length",
            IpError::BadUdpChecksum => "bad_udp_checksum",
        }
    }
}

fn be16(b: &[u8], at: usize) -> Option<u16> {
    Some(u16::from_be_bytes([
        *b.get(at)?,
        *b.get(at.checked_add(1)?)?,
    ]))
}

/// Parse one queued packet (see the module docs).
pub fn parse_ipv4_udp(pkt: &[u8]) -> Result<Ipv4Udp, IpError> {
    let first = *pkt.first().ok_or(IpError::Truncated)?;
    if first >> 4 != 4 {
        return Err(IpError::NotIpv4);
    }
    let ihl = usize::from(first & 0x0f) * 4;
    if ihl < 20 {
        return Err(IpError::NotIpv4);
    }
    let header = pkt.get(..ihl).ok_or(IpError::Truncated)?;
    if !ipv4_header_valid(header) {
        return Err(IpError::BadHeaderChecksum);
    }
    let total = usize::from(be16(pkt, 2).ok_or(IpError::Truncated)?);
    if total < ihl || total > pkt.len() {
        return Err(IpError::Truncated);
    }
    if total != pkt.len() {
        return Err(IpError::BadLength);
    }
    let frag = be16(pkt, 6).ok_or(IpError::Truncated)?;
    // MF flag or a non-zero fragment offset.
    if frag & 0x3fff != 0 {
        return Err(IpError::Fragment);
    }
    if *pkt.get(9).ok_or(IpError::Truncated)? != 17 {
        return Err(IpError::NotUdp);
    }
    let src = Ipv4Addr::new(
        *pkt.get(12).ok_or(IpError::Truncated)?,
        *pkt.get(13).ok_or(IpError::Truncated)?,
        *pkt.get(14).ok_or(IpError::Truncated)?,
        *pkt.get(15).ok_or(IpError::Truncated)?,
    );
    let dst = Ipv4Addr::new(
        *pkt.get(16).ok_or(IpError::Truncated)?,
        *pkt.get(17).ok_or(IpError::Truncated)?,
        *pkt.get(18).ok_or(IpError::Truncated)?,
        *pkt.get(19).ok_or(IpError::Truncated)?,
    );
    let udp_start = ihl;
    let src_port = be16(pkt, udp_start).ok_or(IpError::Truncated)?;
    let dst_port = be16(pkt, udp_start + 2).ok_or(IpError::Truncated)?;
    let udp_len = usize::from(be16(pkt, udp_start + 4).ok_or(IpError::Truncated)?);
    if udp_len < 8 || udp_start.checked_add(udp_len) != Some(total) {
        return Err(IpError::BadLength);
    }
    let segment = pkt.get(udp_start..total).ok_or(IpError::Truncated)?;
    let checksum_zero = match udp_checksum_status(IpAddr::V4(src), IpAddr::V4(dst), segment) {
        UdpChecksumStatus::Valid => false,
        UdpChecksumStatus::NotComputed => true,
        // On a forwarded packet the kernel has already resolved any
        // checksum offload before queueing, so a bare pseudo-sum here is a
        // wrong checksum on the wire: the receiver drops it.
        UdpChecksumStatus::Partial | UdpChecksumStatus::Bad => return Err(IpError::BadUdpChecksum),
    };
    Ok(Ipv4Udp {
        src,
        dst,
        src_port,
        dst_port,
        udp_start,
        payload_start: udp_start + 8,
        end: total,
        checksum_zero,
    })
}

/// Recompute the UDP checksum of `pkt` after its payload was rewritten in
/// place (a datagram sent without a checksum keeps 0).
pub fn refresh_udp_checksum(pkt: &mut [u8], at: &Ipv4Udp) {
    if at.checksum_zero {
        return;
    }
    let Some(segment) = pkt.get(at.udp_start..at.end) else {
        return;
    };
    let c = udp_checksum(IpAddr::V4(at.src), IpAddr::V4(at.dst), segment);
    if let Some(field) = pkt.get_mut(at.udp_start + 6..at.udp_start + 8) {
        field.copy_from_slice(&c.to_be_bytes());
    }
}

/// Build an IPv4 / UDP packet (tests, the latency harness, the fuzz seeds):
/// no options, DF set, TTL 64, both checksums computed.
pub fn build_ipv4_udp(
    src: Ipv4Addr,
    dst: Ipv4Addr,
    src_port: u16,
    dst_port: u16,
    payload: &[u8],
) -> Vec<u8> {
    let total = 28 + payload.len();
    let mut p = Vec::with_capacity(total);
    p.extend_from_slice(&[0x45, 0]);
    p.extend_from_slice(&(total as u16).to_be_bytes());
    p.extend_from_slice(&[0x12, 0x34, 0x40, 0x00, 64, 17, 0, 0]);
    p.extend_from_slice(&src.octets());
    p.extend_from_slice(&dst.octets());
    let hc = robodr_capture::checksum::ipv4_header_checksum(&p[..20]);
    p[10..12].copy_from_slice(&hc.to_be_bytes());
    p.extend_from_slice(&src_port.to_be_bytes());
    p.extend_from_slice(&dst_port.to_be_bytes());
    p.extend_from_slice(&((8 + payload.len()) as u16).to_be_bytes());
    p.extend_from_slice(&[0, 0]);
    p.extend_from_slice(payload);
    let c = udp_checksum(IpAddr::V4(src), IpAddr::V4(dst), &p[20..]);
    p[26..28].copy_from_slice(&c.to_be_bytes());
    p
}

#[cfg(test)]
mod tests {
    use super::*;

    const A: Ipv4Addr = Ipv4Addr::new(10, 0, 0, 1);
    const B: Ipv4Addr = Ipv4Addr::new(10, 0, 0, 2);

    #[test]
    fn roundtrip_and_refusals() {
        let p = build_ipv4_udp(A, B, 1000, 7411, b"hello world!");
        let u = parse_ipv4_udp(&p).unwrap();
        assert_eq!((u.src, u.dst, u.src_port, u.dst_port), (A, B, 1000, 7411));
        assert_eq!(&p[u.payload()], b"hello world!");
        assert!(!u.checksum_zero);

        // Rewrite + refresh keeps it valid; without refresh it is refused.
        let mut q = p.clone();
        q[u.payload_start] = b'J';
        assert_eq!(parse_ipv4_udp(&q), Err(IpError::BadUdpChecksum));
        refresh_udp_checksum(&mut q, &u);
        assert!(parse_ipv4_udp(&q).is_ok());

        // Zero checksum: accepted and kept zero.
        let mut z = p.clone();
        z[26] = 0;
        z[27] = 0;
        let uz = parse_ipv4_udp(&z).unwrap();
        assert!(uz.checksum_zero);
        z[uz.payload_start] = b'X';
        refresh_udp_checksum(&mut z, &uz);
        assert_eq!(&z[26..28], &[0, 0]);

        // Fragment (MF), fragment offset, not UDP, trailing bytes, IPv6.
        let mut f = p.clone();
        f[6] = 0x20;
        let hc = {
            f[10] = 0;
            f[11] = 0;
            robodr_capture::checksum::ipv4_header_checksum(&f[..20])
        };
        f[10..12].copy_from_slice(&hc.to_be_bytes());
        assert_eq!(parse_ipv4_udp(&f), Err(IpError::Fragment));
        let mut t = p.clone();
        t.push(0);
        assert!(parse_ipv4_udp(&t).is_err());
        assert_eq!(parse_ipv4_udp(&[0x60; 40]), Err(IpError::NotIpv4));
        assert_eq!(parse_ipv4_udp(&[]), Err(IpError::Truncated));
        let mut bad_hdr = p.clone();
        bad_hdr[8] = 1; // TTL changed, checksum stale
        assert_eq!(parse_ipv4_udp(&bad_hdr), Err(IpError::BadHeaderChecksum));
    }
}
