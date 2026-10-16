//! Frame builders for tests, fixtures and commissioning self-checks.
//!
//! These construct well-formed link/IP/UDP frames in memory so tests (and a
//! commissioning tool's self-test) can exercise the decoders and file readers
//! without real traffic. Nothing here touches the network.
//!
//! Checksums: the IPv4 header checksum is always computed. The UDP checksum
//! is computed for IPv6 (where it is mandatory) and left at zero ("not
//! computed", legal per RFC 768) by [`ipv4_udp`], so tests may patch IPv4
//! payload bytes freely; [`ipv4_udp_checksummed`] fills it in.

use std::net::{Ipv4Addr, Ipv6Addr};

fn ipv4_checksum(header: &[u8]) -> u16 {
    let mut sum: u32 = 0;
    for pair in header.chunks(2) {
        let hi = u32::from(pair[0]) << 8;
        let lo = u32::from(*pair.get(1).unwrap_or(&0));
        sum += hi | lo;
    }
    while sum >> 16 != 0 {
        sum = (sum & 0xffff) + (sum >> 16);
    }
    !(sum as u16)
}

fn udp(src_port: u16, dst_port: u16, payload: &[u8]) -> Vec<u8> {
    let mut u = Vec::with_capacity(8 + payload.len());
    u.extend_from_slice(&src_port.to_be_bytes());
    u.extend_from_slice(&dst_port.to_be_bytes());
    u.extend_from_slice(&((8 + payload.len()) as u16).to_be_bytes());
    u.extend_from_slice(&[0, 0]);
    u.extend_from_slice(payload);
    u
}

fn ipv4_header(src: Ipv4Addr, dst: Ipv4Addr, id: u16, frag: u16, body_len: usize) -> Vec<u8> {
    let mut h = vec![0x45, 0];
    h.extend_from_slice(&((20 + body_len) as u16).to_be_bytes());
    h.extend_from_slice(&id.to_be_bytes());
    h.extend_from_slice(&frag.to_be_bytes());
    h.extend_from_slice(&[64, 17, 0, 0]);
    h.extend_from_slice(&src.octets());
    h.extend_from_slice(&dst.octets());
    let c = ipv4_checksum(&h);
    h[10..12].copy_from_slice(&c.to_be_bytes());
    h
}

/// An IPv4 packet carrying one UDP datagram (IP identification 0x1234).
pub fn ipv4_udp(
    src: Ipv4Addr,
    dst: Ipv4Addr,
    src_port: u16,
    dst_port: u16,
    payload: &[u8],
) -> Vec<u8> {
    let u = udp(src_port, dst_port, payload);
    let mut p = ipv4_header(src, dst, 0x1234, 0, u.len());
    p.extend_from_slice(&u);
    p
}

/// [`ipv4_udp`] with the UDP checksum filled in.
pub fn ipv4_udp_checksummed(
    src: Ipv4Addr,
    dst: Ipv4Addr,
    src_port: u16,
    dst_port: u16,
    payload: &[u8],
) -> Vec<u8> {
    let mut p = ipv4_udp(src, dst, src_port, dst_port, payload);
    let c = crate::checksum::udp_checksum(src.into(), dst.into(), &p[20..]);
    p[26..28].copy_from_slice(&c.to_be_bytes());
    p
}

/// Split an (option-less) IPv4 packet into fragments carrying at most
/// `chunk` payload bytes each (`chunk` is rounded down to a multiple of 8,
/// minimum 8).
pub fn ipv4_fragment(packet: &[u8], chunk: usize) -> Vec<Vec<u8>> {
    let chunk = (chunk / 8).max(1) * 8;
    let src = Ipv4Addr::new(packet[12], packet[13], packet[14], packet[15]);
    let dst = Ipv4Addr::new(packet[16], packet[17], packet[18], packet[19]);
    let id = u16::from_be_bytes([packet[4], packet[5]]);
    let body = &packet[20..];
    let mut out = Vec::new();
    let mut off = 0;
    while off < body.len() {
        let end = (off + chunk).min(body.len());
        let more = end < body.len();
        let frag = ((off / 8) as u16) | if more { 0x2000 } else { 0 };
        let mut p = ipv4_header(src, dst, id, frag, end - off);
        p.extend_from_slice(&body[off..end]);
        out.push(p);
        off = end;
    }
    out
}

/// An IPv6 packet carrying one UDP datagram behind the given extension headers,
/// each `(next-header code of this header, total length in bytes)`. Lengths
/// must be multiples of 8 (AH: multiples of 4, >= 8). Header bodies are
/// zero-filled (PadN-free zero padding is fine for our decoder).
pub fn ipv6_udp(
    src: Ipv6Addr,
    dst: Ipv6Addr,
    src_port: u16,
    dst_port: u16,
    ext: &[(u8, usize)],
    payload: &[u8],
) -> Vec<u8> {
    let mut u = udp(src_port, dst_port, payload);
    let c = crate::checksum::udp_checksum(src.into(), dst.into(), &u);
    u[6..8].copy_from_slice(&c.to_be_bytes());
    let mut chain = Vec::new();
    for (i, &(_, len)) in ext.iter().enumerate() {
        let next = ext.get(i + 1).map_or(17, |e| e.0);
        let mut h = vec![0u8; len];
        h[0] = next;
        h[1] = if ext[i].0 == 51 {
            (len / 4 - 2) as u8
        } else {
            (len / 8 - 1) as u8
        };
        chain.extend_from_slice(&h);
    }
    chain.extend_from_slice(&u);
    let first = ext.first().map_or(17, |e| e.0);
    ipv6_raw(src, dst, first, &chain)
}

fn ipv6_raw(src: Ipv6Addr, dst: Ipv6Addr, next: u8, body: &[u8]) -> Vec<u8> {
    let mut p = vec![0x60, 0, 0, 0];
    p.extend_from_slice(&(body.len() as u16).to_be_bytes());
    p.extend_from_slice(&[next, 64]);
    p.extend_from_slice(&src.octets());
    p.extend_from_slice(&dst.octets());
    p.extend_from_slice(body);
    p
}

/// Fragment an IPv6 packet *without* extension headers (next header taken from
/// the fixed header) into fragments of at most `chunk` bytes (rounded down to
/// a multiple of 8). If the payload fits in one chunk, the result is a single
/// atomic fragment (offset 0, M = 0).
pub fn ipv6_fragment(packet: &[u8], chunk: usize, id: u32) -> Vec<Vec<u8>> {
    let chunk = (chunk / 8).max(1) * 8;
    let mut src = [0u8; 16];
    src.copy_from_slice(&packet[8..24]);
    let mut dst = [0u8; 16];
    dst.copy_from_slice(&packet[24..40]);
    let next = packet[6];
    let body = &packet[40..];
    let mut out = Vec::new();
    let mut off = 0;
    loop {
        let end = (off + chunk).min(body.len());
        let more = end < body.len();
        let mut fh = vec![next, 0];
        fh.extend_from_slice(&((off as u16) | u16::from(more)).to_be_bytes());
        fh.extend_from_slice(&id.to_be_bytes());
        fh.extend_from_slice(&body[off..end]);
        out.push(ipv6_raw(src.into(), dst.into(), 44, &fh));
        off = end;
        if !more {
            break;
        }
    }
    out
}

/// Ethernet II frame (zero MACs) carrying `payload` with `ethertype`.
pub fn ethernet(ethertype: u16, payload: &[u8]) -> Vec<u8> {
    ethernet_vlan(&[], ethertype, payload)
}

/// Ethernet II frame with VLAN tags, each `(tag protocol id, VLAN id)`.
pub fn ethernet_vlan(tags: &[(u16, u16)], ethertype: u16, payload: &[u8]) -> Vec<u8> {
    let mut f = vec![0x02, 0, 0, 0, 0, 1, 0x02, 0, 0, 0, 0, 2];
    for &(tpid, vid) in tags {
        f.extend_from_slice(&tpid.to_be_bytes());
        f.extend_from_slice(&(vid & 0x0fff).to_be_bytes());
    }
    f.extend_from_slice(&ethertype.to_be_bytes());
    f.extend_from_slice(payload);
    f
}

/// Linux cooked capture v1 header (packet type "host", ARPHRD_ETHER).
pub fn linux_sll(protocol: u16, payload: &[u8]) -> Vec<u8> {
    let mut f = vec![0, 0, 0, 1, 0, 6, 2, 0, 0, 0, 0, 1, 0, 0];
    f.extend_from_slice(&protocol.to_be_bytes());
    f.extend_from_slice(payload);
    f
}

/// Linux cooked capture v2 header (ifindex 1, ARPHRD_ETHER).
pub fn linux_sll2(protocol: u16, payload: &[u8]) -> Vec<u8> {
    let mut f = protocol.to_be_bytes().to_vec();
    f.extend_from_slice(&[0, 0, 0, 0, 0, 1, 0, 1, 0, 6, 2, 0, 0, 0, 0, 1, 0, 0]);
    f.extend_from_slice(payload);
    f
}

/// BSD NULL / OpenBSD LOOP header: 4-byte address family.
pub fn null_loopback(family: u32, little_endian: bool, payload: &[u8]) -> Vec<u8> {
    let mut f = if little_endian {
        family.to_le_bytes().to_vec()
    } else {
        family.to_be_bytes().to_vec()
    };
    f.extend_from_slice(payload);
    f
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ipv4_checksum_matches_rfc1071_example() {
        // Header from a well-known capture; checksum field zeroed -> 0xb861.
        let h = [
            0x45, 0x00, 0x00, 0x73, 0x00, 0x00, 0x40, 0x00, 0x40, 0x11, 0x00, 0x00, 0xc0, 0xa8,
            0x00, 0x01, 0xc0, 0xa8, 0x00, 0xc7,
        ];
        assert_eq!(ipv4_checksum(&h), 0xb861);
        let p = ipv4_udp(Ipv4Addr::LOCALHOST, Ipv4Addr::LOCALHOST, 1, 2, b"x");
        assert_eq!(
            ipv4_checksum(&p[..20]),
            0,
            "checksum over valid header is 0"
        );
    }
}
