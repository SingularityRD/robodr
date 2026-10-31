//! Ethernet II / IPv4 / UDP frames: split a carrier frame, rebuild one with
//! correct lengths and IPv4 checksum (UDP checksum 0, legal for IPv4), and
//! fragment an oversized datagram. Mirrors `tools/e2e/rtlib.py`.

use robodr_capture::synth;
use std::net::Ipv4Addr;

const ETH_LEN: usize = 14;
const ETHERTYPE_IPV4: u16 = 0x0800;

/// One unfragmented IPv4/UDP datagram in an Ethernet II frame.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Udp4 {
    pub dst_mac: [u8; 6],
    pub src_mac: [u8; 6],
    pub src: Ipv4Addr,
    pub dst: Ipv4Addr,
    pub src_port: u16,
    pub dst_port: u16,
    pub payload: Vec<u8>,
}

fn arr<const N: usize>(b: &[u8], at: usize) -> Option<[u8; N]> {
    b.get(at..)?.first_chunk::<N>().copied()
}

/// Split an Ethernet II frame carrying one unfragmented IPv4/UDP datagram;
/// `None` for anything else (VLAN tags, IPv6, fragments, other protocols),
/// which scenarios pass through unchanged.
pub fn parse(frame: &[u8]) -> Option<Udp4> {
    let dst_mac = arr::<6>(frame, 0)?;
    let src_mac = arr::<6>(frame, 6)?;
    if u16::from_be_bytes(arr::<2>(frame, 12)?) != ETHERTYPE_IPV4 {
        return None;
    }
    let ip = frame.get(ETH_LEN..)?;
    let vihl = *ip.first()?;
    if vihl >> 4 != 4 {
        return None;
    }
    let ihl = usize::from(vihl & 0x0f) * 4;
    let total = usize::from(u16::from_be_bytes(arr::<2>(ip, 2)?));
    let frag = u16::from_be_bytes(arr::<2>(ip, 6)?);
    if ihl < 20 || frag & 0x3fff != 0 || *ip.get(9)? != 17 || total < ihl + 8 {
        return None;
    }
    let src = Ipv4Addr::from(arr::<4>(ip, 12)?);
    let dst = Ipv4Addr::from(arr::<4>(ip, 16)?);
    let udp = ip.get(ihl..total)?;
    let src_port = u16::from_be_bytes(arr::<2>(udp, 0)?);
    let dst_port = u16::from_be_bytes(arr::<2>(udp, 2)?);
    let ulen = usize::from(u16::from_be_bytes(arr::<2>(udp, 4)?));
    let payload = udp.get(8..ulen.min(udp.len()).max(8))?.to_vec();
    Some(Udp4 {
        dst_mac,
        src_mac,
        src,
        dst,
        src_port,
        dst_port,
        payload,
    })
}

fn ethernet(dst: [u8; 6], src: [u8; 6], ip: &[u8]) -> Vec<u8> {
    let mut f = Vec::with_capacity(ETH_LEN + ip.len());
    f.extend_from_slice(&dst);
    f.extend_from_slice(&src);
    f.extend_from_slice(&ETHERTYPE_IPV4.to_be_bytes());
    f.extend_from_slice(ip);
    f
}

impl Udp4 {
    /// The IPv4 packet (header checksum computed, UDP checksum 0).
    pub fn ip_packet(&self) -> Vec<u8> {
        synth::ipv4_udp(
            self.src,
            self.dst,
            self.src_port,
            self.dst_port,
            &self.payload,
        )
    }

    /// The Ethernet frame. A payload over 65 507 bytes cannot be one UDP
    /// datagram and is truncated to that size.
    pub fn frame(&self) -> Vec<u8> {
        ethernet(self.dst_mac, self.src_mac, &self.ip_packet())
    }

    /// The datagram as IPv4 fragments of at most `chunk` payload bytes
    /// (a multiple of 8) with IP identification `ident`, each in its own
    /// Ethernet frame.
    pub fn fragments(&self, chunk: usize, ident: u16) -> Vec<Vec<u8>> {
        let mut packet = self.ip_packet();
        if let Some(id) = packet.get_mut(4..6) {
            id.copy_from_slice(&ident.to_be_bytes());
        }
        synth::ipv4_fragment(&packet, chunk)
            .iter()
            .map(|p| ethernet(self.dst_mac, self.src_mac, p))
            .collect()
    }
}

/// The RTPS GUID prefix of an RTPS message (`RTPS`, version, vendor id,
/// prefix), or `None` when `payload` is not RTPS.
pub fn rtps_prefix(payload: &[u8]) -> Option<[u8; 12]> {
    if payload.get(..4)? != b"RTPS" {
        return None;
    }
    arr::<12>(payload, 8)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trip_and_fragments() {
        let d = Udp4 {
            dst_mac: [1; 6],
            src_mac: [2; 6],
            src: Ipv4Addr::new(10, 0, 0, 1),
            dst: Ipv4Addr::new(239, 255, 0, 1),
            src_port: 1234,
            dst_port: 7400,
            payload: b"RTPS\x02\x03\x01\x0f0123456789ab".to_vec(),
        };
        let f = d.frame();
        assert_eq!(parse(&f).unwrap(), d);
        assert_eq!(rtps_prefix(&d.payload).unwrap(), *b"0123456789ab");
        let big = Udp4 {
            payload: vec![7; 4000],
            ..d.clone()
        };
        let frags = big.fragments(1480, 0x5000);
        assert_eq!(frags.len(), 3);
        // Fragments are not single datagrams: scenarios pass them through.
        assert!(frags.iter().all(|f| parse(f).is_none()));
        assert!(parse(&f[..20]).is_none());
        assert!(rtps_prefix(b"RTPX").is_none());
    }
}
