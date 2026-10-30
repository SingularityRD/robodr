//! Internet checksums (RFC 1071) for IPv4 headers and UDP over IPv4 / IPv6.
//!
//! # Why the sensor verifies checksums
//! A host's IP stack silently drops a packet whose IPv4 header checksum or
//! UDP checksum is wrong. A sensor that does *not* check would therefore see
//! packets the robot's DDS stack never receives: an attacker can inject
//! frames (or IP fragments that poison reassembly) that only the detector
//! sees, to frame a peer or to hide a real announcement. So
//! [`crate::RtpsDatagrams`] drops such packets from the RTPS path and counts
//! them in [`crate::CaptureStats`] (a non-zero count is evidence of injection
//! attempts, or of a broken NIC).
//!
//! # What is verified, and the offload problem
//! - **IPv4 header checksum: always.** Linux computes it in software on
//!   transmit and always verifies it on receive (`ip_rcv_core`), loopback
//!   included, so a capture taken on Linux never has a legitimately wrong one.
//!   (Captures taken on hosts that offload the IPv4 header checksum, e.g.
//!   some Windows NIC drivers, show zero checksums on that host's *outgoing*
//!   packets; those are dropped and counted.)
//! - **UDP checksum**, see [`UdpChecksumMode`]. On transmit, Linux usually
//!   leaves the UDP checksum to the NIC (`CHECKSUM_PARTIAL`): a capture taken
//!   on the sending host (outgoing packets, loopback, veth/container traffic)
//!   holds only the *pseudo-header sum* in the checksum field, not the final
//!   value. [`udp_checksum_status`] recognises that exact value as
//!   [`UdpChecksumStatus::Partial`]. The receiving kernel trusts such packets
//!   on loopback/veth (`CHECKSUM_UNNECESSARY`), so `Auto` accepts them (and
//!   counts them); a packet that arrived from a real wire with that value
//!   would be dropped by the host — the residual risk is documented on
//!   [`UdpChecksumMode::Auto`].
//! - IPv4 UDP checksum 0 means "not computed" (RFC 768) and is accepted, as
//!   the kernel does. For IPv6 a zero UDP checksum is invalid (RFC 8200
//!   section 8.1); Linux drops it unless the socket opted in
//!   (`UDP_NO_CHECK6_RX`, used by tunnels, never by DDS).

use std::net::IpAddr;

/// Ones'-complement 16-bit sum of `data` (odd length padded with a zero
/// byte), added to `initial`, not folded and not complemented.
fn sum16(initial: u64, data: &[u8]) -> u64 {
    let mut sum = initial;
    let mut chunks = data.chunks_exact(2);
    for c in &mut chunks {
        if let &[hi, lo] = c {
            sum += u64::from(u16::from_be_bytes([hi, lo]));
        }
    }
    if let [last] = chunks.remainder() {
        sum += u64::from(*last) << 8;
    }
    sum
}

fn fold(mut sum: u64) -> u16 {
    while sum >> 16 != 0 {
        sum = (sum & 0xffff) + (sum >> 16);
    }
    sum as u16
}

/// RFC 1071 Internet checksum of `data`: the value to store in a checksum
/// field that is zero inside `data`. Over data that already contains a
/// correct checksum, the result is 0.
pub fn internet_checksum(data: &[u8]) -> u16 {
    !fold(sum16(0, data))
}

/// Checksum of an IPv4 header (`header` = the IHL * 4 header bytes, with the
/// checksum field at bytes 10..12 zeroed when *computing*). Over a header
/// whose checksum field is filled in correctly the result is 0, so this is
/// also the verification primitive (see [`ipv4_header_valid`]).
pub fn ipv4_header_checksum(header: &[u8]) -> u16 {
    internet_checksum(header)
}

/// The IPv4 header (IHL * 4 bytes) carries a correct checksum.
pub fn ipv4_header_valid(header: &[u8]) -> bool {
    header.len() >= 20 && ipv4_header_checksum(header) == 0
}

/// Unfolded sum of the UDP pseudo-header for `len` bytes of UDP.
fn pseudo_sum(src: IpAddr, dst: IpAddr, len: usize) -> u64 {
    let len = len as u64; // <= 65535 for IPv4; IPv6 uses a 32-bit field
    match (src, dst) {
        (IpAddr::V4(s), IpAddr::V4(d)) => {
            sum16(sum16(0, &s.octets()), &d.octets()) + u64::from(crate::decode::IPPROTO_UDP) + len
        }
        _ => {
            let s = match src {
                IpAddr::V6(a) => a.octets(),
                IpAddr::V4(a) => a.to_ipv6_mapped().octets(),
            };
            let d = match dst {
                IpAddr::V6(a) => a.octets(),
                IpAddr::V4(a) => a.to_ipv6_mapped().octets(),
            };
            sum16(sum16(0, &s), &d)
                + (len >> 16)
                + (len & 0xffff)
                + u64::from(crate::decode::IPPROTO_UDP)
        }
    }
}

/// The checksum field (bytes 6..8) of a UDP header; `None` if `segment` is
/// shorter than a UDP header.
fn stored_checksum(segment: &[u8]) -> Option<u16> {
    let (header, _) = segment.split_first_chunk::<8>()?;
    Some(u16::from_be_bytes([header[6], header[7]]))
}

/// The UDP checksum for `segment` (UDP header + payload, exactly UDP-length
/// bytes) between `src` and `dst`, computed as if the checksum field were
/// zero. A computed 0 is returned as 0xffff (RFC 768: 0 means "none").
pub fn udp_checksum(src: IpAddr, dst: IpAddr, segment: &[u8]) -> u16 {
    let mut sum = pseudo_sum(src, dst, segment.len()) + sum16(0, segment);
    if let Some(stored) = stored_checksum(segment) {
        // Remove the stored checksum field from the sum.
        sum += u64::from(!stored); // x + ~x == 0xffff == -0 in ones' complement
    }
    match !fold(sum) {
        0 => 0xffff,
        c => c,
    }
}

/// Outcome of checking a UDP checksum, see the module docs.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum UdpChecksumStatus {
    /// The checksum is correct.
    Valid,
    /// IPv4 checksum field 0: sender did not compute one (legal, RFC 768).
    NotComputed,
    /// The field holds the bare pseudo-header sum a sender with checksum
    /// offload leaves for the NIC: a locally originated packet captured
    /// before the NIC (outgoing, loopback, veth).
    Partial,
    /// Wrong checksum (or zero over IPv6): a receiving host drops it.
    Bad,
}

/// Classify the UDP checksum of `segment` (UDP header + payload, exactly
/// UDP-length bytes). Segments shorter than a UDP header are [`Bad`](UdpChecksumStatus::Bad).
pub fn udp_checksum_status(src: IpAddr, dst: IpAddr, segment: &[u8]) -> UdpChecksumStatus {
    let Some(stored) = stored_checksum(segment) else {
        return UdpChecksumStatus::Bad;
    };
    if stored == 0 {
        return if src.is_ipv4() && dst.is_ipv4() {
            UdpChecksumStatus::NotComputed
        } else {
            UdpChecksumStatus::Bad
        };
    }
    let total = pseudo_sum(src, dst, segment.len()) + sum16(0, segment);
    if fold(total) == 0xffff {
        return UdpChecksumStatus::Valid;
    }
    if stored == fold(pseudo_sum(src, dst, segment.len())) {
        return UdpChecksumStatus::Partial;
    }
    UdpChecksumStatus::Bad
}

/// Which UDP checksums [`crate::RtpsDatagrams`] verifies. The IPv4 header
/// checksum is verified in every mode.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum UdpChecksumMode {
    /// Verify, but accept (and count in
    /// [`crate::CaptureStats::udp_checksum_partial`]) a checksum field that
    /// holds exactly the offload pseudo-header sum
    /// ([`UdpChecksumStatus::Partial`]): loopback, veth/container traffic and
    /// the capturing host's own outgoing packets carry it legitimately, and
    /// the receiving kernel trusts those without verifying. Rejecting them
    /// would hide same-host DDS traffic from the sensor. Residual risk: an
    /// attacker on a real wire can forge that one value; the host drops such
    /// a packet while the sensor accepts it (a false positive, never an
    /// evasion; a non-zero `udp_checksum_partial` on a physical interface is
    /// suspicious). Zero over IPv4 is accepted (RFC 768).
    #[default]
    Auto,
    /// Verify every UDP checksum; offload pseudo-sums count as failures.
    /// Use on a capture of traffic received from the wire (SPAN/TAP).
    Always,
    /// Never verify UDP checksums (e.g. captures from hosts whose offload
    /// leaves arbitrary values). Still counted as unverified.
    Never,
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{Ipv4Addr, Ipv6Addr};

    #[test]
    fn rfc1071_ipv4_header_vector() {
        // Well-known header, checksum field zeroed -> 0xb861.
        let mut h = [
            0x45, 0x00, 0x00, 0x73, 0x00, 0x00, 0x40, 0x00, 0x40, 0x11, 0x00, 0x00, 0xc0, 0xa8,
            0x00, 0x01, 0xc0, 0xa8, 0x00, 0xc7,
        ];
        assert_eq!(ipv4_header_checksum(&h), 0xb861);
        assert!(!ipv4_header_valid(&h));
        h[10..12].copy_from_slice(&0xb861u16.to_be_bytes());
        assert!(ipv4_header_valid(&h));
        assert!(!ipv4_header_valid(&h[..19]));
        // RFC 1071 section 3 example bytes: sum 0xddf2 -> checksum 0x220d.
        assert_eq!(
            internet_checksum(&[0x00, 0x01, 0xf2, 0x03, 0xf4, 0xf5, 0xf6, 0xf7]),
            0x220d
        );
        // Odd length pads with zero.
        assert_eq!(internet_checksum(&[0xff]), !0xff00u16);
    }

    /// 192.168.0.1:1024 -> 192.168.0.199:53 (the addresses of the header
    /// above), checked against a hand-expanded RFC 768 sum.
    #[test]
    fn udp_v4_known_vector() {
        let s: IpAddr = Ipv4Addr::new(192, 168, 0, 1).into();
        let d: IpAddr = Ipv4Addr::new(192, 168, 0, 199).into();
        let mut seg = vec![
            0x04, 0x00, 0x00, 0x35, 0x00, 0x0c, 0x00, 0x00, b'a', b'b', b'c', b'd',
        ];
        let c = udp_checksum(s, d, &seg);
        // sum: c0a8+0001+c0a8+00c7+0011+000c + 0400+0035+000c+6162+6364
        let manual = !fold(
            0xc0a8
                + 0x0001
                + 0xc0a8
                + 0x00c7
                + 0x0011
                + 0x000c
                + 0x0400
                + 0x0035
                + 0x000c
                + 0x6162
                + 0x6364,
        );
        assert_eq!(c, manual);
        assert_eq!(
            udp_checksum_status(s, d, &seg),
            UdpChecksumStatus::NotComputed
        );
        seg[6..8].copy_from_slice(&c.to_be_bytes());
        assert_eq!(udp_checksum_status(s, d, &seg), UdpChecksumStatus::Valid);
        // Recomputing over a filled-in segment gives the same value.
        assert_eq!(udp_checksum(s, d, &seg), c);
        seg[9] ^= 1;
        assert_eq!(udp_checksum_status(s, d, &seg), UdpChecksumStatus::Bad);
        // Wrong pseudo-header (different destination) is also bad.
        seg[9] ^= 1;
        let other: IpAddr = Ipv4Addr::new(192, 168, 0, 198).into();
        assert_eq!(udp_checksum_status(s, other, &seg), UdpChecksumStatus::Bad);
        assert_eq!(udp_checksum_status(s, d, &seg[..7]), UdpChecksumStatus::Bad);
    }

    /// Vectors computed with an independent implementation (Python
    /// `struct`-based RFC 1071 sum over the RFC 768 / RFC 8200 pseudo-header):
    /// 10.0.0.66:40000 -> 10.0.0.5:7410 = 0x48bf, the same segment
    /// fd00::66 -> ff02::1 = 0x609b.
    #[test]
    fn udp_independent_vectors() {
        let mut seg = vec![
            0x9c, 0x40, 0x1c, 0xf2, 0x00, 0x15, 0x00, 0x00, b'R', b'T', b'P', b'S', 2, 3, 1, 0x0f,
        ];
        seg.extend_from_slice(b"hello");
        let s4: IpAddr = Ipv4Addr::new(10, 0, 0, 66).into();
        let d4: IpAddr = Ipv4Addr::new(10, 0, 0, 5).into();
        assert_eq!(udp_checksum(s4, d4, &seg), 0x48bf);
        let s6: IpAddr = "fd00::66".parse::<Ipv6Addr>().unwrap().into();
        let d6: IpAddr = "ff02::1".parse::<Ipv6Addr>().unwrap().into();
        assert_eq!(udp_checksum(s6, d6, &seg), 0x609b);
        seg[6..8].copy_from_slice(&0x609bu16.to_be_bytes());
        assert_eq!(udp_checksum_status(s6, d6, &seg), UdpChecksumStatus::Valid);
        assert_eq!(udp_checksum_status(s4, d4, &seg), UdpChecksumStatus::Bad);
        // Odd payload length exercises the zero-pad path (21 bytes).
        assert_eq!(seg.len() % 2, 1);
    }

    #[test]
    fn udp_v6_zero_is_bad_and_valid_roundtrips() {
        let s: IpAddr = "fd00::1".parse::<Ipv6Addr>().unwrap().into();
        let d: IpAddr = "fd00::2".parse::<Ipv6Addr>().unwrap().into();
        let mut seg = vec![
            0x1c, 0xf2, 0x1c, 0xf2, 0x00, 0x0d, 0, 0, b'R', b'T', b'P', b'S', b'!',
        ];
        assert_eq!(udp_checksum_status(s, d, &seg), UdpChecksumStatus::Bad);
        let c = udp_checksum(s, d, &seg);
        seg[6..8].copy_from_slice(&c.to_be_bytes());
        assert_eq!(udp_checksum_status(s, d, &seg), UdpChecksumStatus::Valid);
    }

    #[test]
    fn offload_partial_value_is_recognised() {
        for (s, d) in [
            (
                IpAddr::from(Ipv4Addr::LOCALHOST),
                IpAddr::from(Ipv4Addr::new(10, 0, 0, 9)),
            ),
            (
                IpAddr::from(Ipv6Addr::LOCALHOST),
                IpAddr::from("fd00::9".parse::<Ipv6Addr>().unwrap()),
            ),
        ] {
            let mut seg = vec![0x9c, 0x40, 0x1c, 0xf2, 0x00, 0x0c, 0, 0, 1, 2, 3, 4];
            // What Linux writes for CHECKSUM_PARTIAL: ~csum_*_magic(.., 0),
            // i.e. the folded, uncomplemented pseudo-header sum.
            let partial = fold(pseudo_sum(s, d, seg.len()));
            seg[6..8].copy_from_slice(&partial.to_be_bytes());
            assert_eq!(udp_checksum_status(s, d, &seg), UdpChecksumStatus::Partial);
        }
    }

    #[test]
    fn computed_zero_is_sent_as_ffff() {
        // Choose payload so the checksum computes to 0 -> 0xffff, which must verify.
        let s: IpAddr = Ipv4Addr::new(0, 0, 0, 0).into();
        let d: IpAddr = Ipv4Addr::new(0, 0, 0, 0).into();
        let mut seg = vec![0, 0, 0, 0, 0, 10, 0, 0, 0, 0];
        // pseudo: 0x11 + 10; header: 10. Payload word w makes the sum 0xffff.
        let w = 0xffffu16 - (0x11 + 10 + 10);
        seg[8..10].copy_from_slice(&w.to_be_bytes());
        let c = udp_checksum(s, d, &seg);
        assert_eq!(c, 0xffff);
        seg[6..8].copy_from_slice(&c.to_be_bytes());
        assert_eq!(udp_checksum_status(s, d, &seg), UdpChecksumStatus::Valid);
    }
}
