//! Regression tests for the passive-capture security review (findings F7a,
//! F7b, F7c, F8). Each test starts from the reviewer's proof of concept and
//! asserts the FIXED behaviour: the sensor now accepts exactly what the
//! robot's Linux IP stack would deliver.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::time::Duration;

use robodr_capture::{
    decode_frame, rtps_datagrams, synth, DecodeError, Decoded, LinkType, RtpsDatagrams,
    UdpChecksumMode, VecSource,
};

const A: Ipv4Addr = Ipv4Addr::new(10, 0, 0, 66);
const R: Ipv4Addr = Ipv4Addr::new(10, 0, 0, 5);

fn rtps(n: usize) -> Vec<u8> {
    let mut p = b"RTPS\x02\x03\x01\x0f".to_vec();
    p.extend_from_slice(&[0xaa; 12]);
    p.resize(n, 0x5a);
    p
}

fn set_id(pkt: &mut [u8], id: u16) {
    pkt[4..6].copy_from_slice(&id.to_be_bytes());
}

/// Recompute the IPv4 header checksum after editing header fields.
fn fix_ip_checksum(pkt: &mut [u8]) {
    let ihl = usize::from(pkt[0] & 0x0f) * 4;
    pkt[10..12].copy_from_slice(&[0, 0]);
    let c = robodr_capture::checksum::internet_checksum(&pkt[..ihl]);
    pkt[10..12].copy_from_slice(&c.to_be_bytes());
}

fn frames(pkts: Vec<Vec<u8>>) -> VecSource {
    VecSource::new(
        pkts.into_iter()
            .enumerate()
            .map(|(i, p)| (Duration::from_millis(i as u64), LinkType::RAW, p)),
    )
}

fn run(pkts: Vec<Vec<u8>>) -> (Vec<Vec<u8>>, RtpsDatagrams<VecSource>) {
    let mut it = rtps_datagrams(frames(pkts));
    let got = it.by_ref().map(|(_, p)| p).collect();
    (got, it)
}

/// A junk 8-byte first fragment from `src` to `dst` with IP id `id`.
fn junk_v4(src: Ipv4Addr, dst: Ipv4Addr, id: u16) -> Vec<u8> {
    let mut j = synth::ipv4_fragment(&synth::ipv4_udp(src, dst, 1, 7410, &[0; 16]), 8)[0].clone();
    set_id(&mut j, id);
    fix_ip_checksum(&mut j);
    j
}

// ---------------------------------------------------------------- F7a ----

/// The reviewer's exact sequence: 64 junk first-fragments from the *same*
/// source between the real datagram's fragments. Nothing is evicted any
/// more. The datagram is still not delivered, because 64 fragments from one
/// source exceed Linux's `ipfrag_max_dist` (default 64): the kernel restarts
/// that queue too (`ip_frag_too_far`), so the sensor matches it.
#[test]
fn f7a_poc_sequence_no_eviction_and_kernel_max_dist() {
    let payload = rtps(3000);
    let real = synth::ipv4_udp(A, R, 40000, 7410, &payload);
    let fr = synth::ipv4_fragment(&real, 1480);
    assert!(fr.len() >= 3);
    // Literally as in the PoC, `set_id` left the junk's IP header checksum
    // stale: the kernel drops all 64 before reassembly, and so do we.
    let mut seq = vec![fr[0].clone()];
    for id in 0..64u16 {
        let mut j = synth::ipv4_fragment(&synth::ipv4_udp(A, R, 1, 7410, &[0; 16]), 8)[0].clone();
        set_id(&mut j, 0x8000 + id);
        seq.push(j);
    }
    seq.extend_from_slice(&fr[1..]);
    let (got, it) = run(seq);
    assert_eq!(got, vec![payload.clone()]);
    assert_eq!(it.stats().bad_ip_checksum, 64);
    assert_eq!(it.reassembly_stats().dropped_capacity, 0);
    // With valid checksums on the junk:
    for (junk, delivered) in [(64u16, false), (63, true)] {
        let mut seq = vec![fr[0].clone()];
        for id in 0..junk {
            seq.push(junk_v4(A, R, 0x8000 + id));
        }
        seq.extend_from_slice(&fr[1..]);
        let (got, it) = run(seq);
        assert_eq!(it.reassembly_stats().dropped_capacity, 0, "junk {junk}");
        assert_eq!(it.reassembly_stats().refused_capacity, 0, "junk {junk}");
        assert_eq!(got.len(), usize::from(delivered), "junk {junk}");
        if delivered {
            assert_eq!(got[0], payload);
        } else {
            assert_eq!(it.reassembly_stats().dropped_too_far, 1);
        }
    }
}

/// The eviction flood itself: thousands of junk first-fragments, from
/// spoofed sources (IPv4: `max_dist` is per source, so the kernel keeps the
/// datagram) or from the attacker's own source (IPv6: no `max_dist`), never
/// evict the real datagram.
#[test]
fn f7a_junk_flood_never_evicts_real_datagram() {
    let payload = rtps(3000);
    // IPv4, 5000 spoofed sources.
    let fr = synth::ipv4_fragment(&synth::ipv4_udp(A, R, 40000, 7410, &payload), 1480);
    let mut seq = vec![fr[0].clone()];
    for i in 0..5000u32 {
        let src = Ipv4Addr::from(0x0a80_0000 + i);
        seq.push(junk_v4(src, R, (i % 65_536) as u16));
    }
    seq.extend_from_slice(&fr[1..]);
    let (got, it) = run(seq);
    assert_eq!(got, vec![payload.clone()]);
    assert_eq!(it.reassembly_stats().dropped_capacity, 0);

    // IPv4, the attacker's own source flooding *other* destinations: the
    // robot's kernel never sees those, so they must not count either.
    let mut seq = vec![fr[0].clone()];
    for i in 0..500u16 {
        seq.push(junk_v4(A, Ipv4Addr::new(10, 0, 1, (i % 250) as u8), i));
    }
    seq.extend_from_slice(&fr[1..]);
    let (got, it) = run(seq);
    assert_eq!(got, vec![payload.clone()]);
    assert_eq!(it.reassembly_stats().dropped_too_far, 0);

    // IPv6, same source and destination, 20 000 junk datagrams.
    let s: Ipv6Addr = "fd00::66".parse().unwrap();
    let d: Ipv6Addr = "fd00::5".parse().unwrap();
    let fr6 = synth::ipv6_fragment(&synth::ipv6_udp(s, d, 40000, 7410, &[], &payload), 1232, 7);
    let junk6 = synth::ipv6_udp(s, d, 1, 7410, &[], &[0; 16]);
    let mut seq = vec![fr6[0].clone()];
    for id in 0..20_000u32 {
        seq.push(synth::ipv6_fragment(&junk6, 8, 1000 + id)[0].clone());
    }
    seq.extend_from_slice(&fr6[1..]);
    let (got, it) = run(seq);
    assert_eq!(got, vec![payload]);
    assert_eq!(it.reassembly_stats().dropped_capacity, 0);
    assert_eq!(it.reassembly_stats().refused_capacity, 0);
}

// ---------------------------------------------------------------- F7b ----

/// The reviewer's exact sequence: a forged conflicting first fragment with a
/// bad IPv4 header checksum. The kernel drops it before reassembly, and now
/// so does the sensor: the real datagram is delivered.
#[test]
fn f7b_bad_checksum_fragment_cannot_poison_reassembly() {
    let payload = rtps(3000);
    let real = synth::ipv4_udp(A, R, 40000, 7410, &payload);
    let fr = synth::ipv4_fragment(&real, 1480);
    let mut forged = fr[0].clone();
    let last = forged.len() - 1;
    forged[last] ^= 0xff; // conflicting byte
    forged[10] ^= 0xff; // break IP header checksum -> kernel drops it
    let mut seq = vec![forged];
    seq.extend(fr.iter().cloned());
    let (got, it) = run(seq);
    assert_eq!(got, vec![payload]);
    assert_eq!(it.stats().bad_ip_checksum, 1);
    assert_eq!(it.reassembly_stats().dropped_overlap, 0);
    assert_eq!(it.reassembly_stats().duplicates, 0);
}

/// With a *valid* IP checksum the forged copy is queued first by the kernel
/// too (first wins); with a UDP checksum on the real datagram, both the
/// kernel and the sensor then reject the reassembled datagram.
#[test]
fn f7b_forged_first_copy_with_valid_ip_checksum_matches_kernel() {
    let payload = rtps(3000);
    let real = synth::ipv4_udp_checksummed(A, R, 40000, 7410, &payload);
    let fr = synth::ipv4_fragment(&real, 1480);
    let mut forged = fr[1].clone();
    let last = forged.len() - 1;
    forged[last] ^= 0xff;
    let mut seq = vec![fr[0].clone(), forged];
    seq.extend(fr[1..].iter().cloned());
    let (got, it) = run(seq);
    assert!(got.is_empty());
    assert_eq!(it.reassembly_stats().duplicate_conflicts, 1);
    assert_eq!(it.stats().bad_udp_checksum, 1);
    // A late forged copy is ignored and the real datagram delivered.
    let mut forged = fr[1].clone();
    let last = forged.len() - 1;
    forged[last] ^= 0xff;
    let mut seq: Vec<_> = fr.clone();
    seq.insert(2, forged);
    let (got, _) = run(seq);
    assert_eq!(got, vec![payload]);
}

// ---------------------------------------------------------------- F7c ----

/// The reviewer's exact packet: a bad IPv4 header checksum is now dropped.
#[test]
fn f7c_bad_ip_checksum_packet_rejected() {
    let mut p = synth::ipv4_udp(A, R, 40000, 7410, &rtps(64));
    p[10] ^= 0xff;
    let (got, it) = run(vec![p]);
    assert!(got.is_empty());
    assert_eq!(it.stats().bad_ip_checksum, 1);
    assert_eq!(it.stats().udp, 0);
}

#[test]
fn f7c_udp_checksums_verified() {
    let payload = rtps(64);
    // IPv4: valid and zero ("not computed") checksums are accepted.
    let good = synth::ipv4_udp_checksummed(A, R, 40000, 7410, &payload);
    let zero = synth::ipv4_udp(A, R, 40000, 7410, &payload);
    assert_ne!(good[26..28], [0, 0]);
    let mut bad = good.clone();
    let n = bad.len();
    bad[n - 1] ^= 1;
    let (got, it) = run(vec![good.clone(), zero, bad.clone()]);
    assert_eq!(got.len(), 2);
    assert_eq!(it.stats().bad_udp_checksum, 1);
    assert_eq!(it.stats().udp_checksum_none, 1);

    // IPv6: valid accepted, zero and wrong rejected.
    let s: Ipv6Addr = "fd00::66".parse().unwrap();
    let d: Ipv6Addr = "fd00::5".parse().unwrap();
    let good6 = synth::ipv6_udp(s, d, 40000, 7410, &[], &payload);
    let mut zero6 = good6.clone();
    zero6[46..48].copy_from_slice(&[0, 0]);
    let mut bad6 = good6.clone();
    let n = bad6.len();
    bad6[n - 1] ^= 1;
    let (got, it) = run(vec![good6, zero6, bad6]);
    assert_eq!(got.len(), 1);
    assert_eq!(it.stats().bad_udp_checksum, 2);

    // Reassembled datagrams are verified too.
    let big = synth::ipv4_udp_checksummed(A, R, 40000, 7410, &rtps(3000));
    let mut fr = synth::ipv4_fragment(&big, 1480);
    let last = fr.len() - 1;
    let n = fr[last].len();
    fr[last][n - 1] ^= 1; // payload only: IP header checksum still valid
    let (got, it) = run(fr);
    assert!(got.is_empty());
    assert_eq!(it.stats().bad_udp_checksum, 1);
    assert_eq!(it.stats().reassembled, 1);

    // Modes: Never accepts the bad one, Always and Auto reject it.
    let mut never =
        rtps_datagrams(frames(vec![bad.clone()])).with_udp_checksum_mode(UdpChecksumMode::Never);
    assert!(never.next().is_some());
    assert_eq!(never.stats().udp_checksum_unverified, 1);
    let mut always =
        rtps_datagrams(frames(vec![bad])).with_udp_checksum_mode(UdpChecksumMode::Always);
    assert!(always.next().is_none());
}

/// Offload pseudo-header sums (loopback / own outgoing traffic) are accepted
/// and counted in `Auto`, rejected in `Always`.
#[test]
fn f7c_offload_partial_checksum_policy() {
    let mut p = synth::ipv4_udp(A, R, 40000, 7410, &rtps(64));
    let seg_len = (p.len() - 20) as u32;
    // Folded, uncomplemented pseudo-header sum (what CHECKSUM_PARTIAL leaves).
    let mut sum: u32 = 0;
    for w in [&A.octets()[..], &R.octets()[..]] {
        sum += u32::from(u16::from_be_bytes([w[0], w[1]]));
        sum += u32::from(u16::from_be_bytes([w[2], w[3]]));
    }
    sum += 17 + seg_len;
    while sum >> 16 != 0 {
        sum = (sum & 0xffff) + (sum >> 16);
    }
    p[26..28].copy_from_slice(&(sum as u16).to_be_bytes());
    let mut auto = rtps_datagrams(frames(vec![p.clone()]));
    assert!(auto.next().is_some());
    assert_eq!(auto.stats().udp_checksum_partial, 1);
    let mut always =
        rtps_datagrams(frames(vec![p])).with_udp_checksum_mode(UdpChecksumMode::Always);
    assert!(always.next().is_none());
    assert_eq!(always.stats().bad_udp_checksum, 1);
}

// ----------------------------------------------------------------- F8 ----

/// The reviewer's exact packet (nine destination-options headers) now
/// decodes, as do much longer chains; the pipeline delivers them and flags
/// the long chain.
#[test]
fn f8_long_ipv6_extension_chains_parsed() {
    let s: Ipv6Addr = "fd00::66".parse().unwrap();
    let d: Ipv6Addr = "fd00::5".parse().unwrap();
    for n in [9usize, 64, 4000] {
        let ext: Vec<(u8, usize)> = (0..n).map(|_| (60u8, 8usize)).collect();
        let p = synth::ipv6_udp(s, d, 40000, 7410, &ext, &rtps(64));
        match decode_frame(LinkType::RAW, &p) {
            Ok(Decoded::Udp(u)) => {
                assert_eq!(u.src, IpAddr::V6(s));
                assert_eq!(u.payload, &rtps(64)[..]);
            }
            other => panic!("{n} headers: {other:?}"),
        }
        let (got, it) = run(vec![p]);
        assert_eq!(got.len(), 1, "{n} headers");
        assert_eq!(it.stats().ipv6_long_ext_chains, 1);
    }
    // Hostile chains are still bounded: one claiming to run past the packet.
    let ext: Vec<(u8, usize)> = (0..9).map(|_| (60u8, 8usize)).collect();
    let mut p = synth::ipv6_udp(s, d, 40000, 7410, &ext, &rtps(64));
    p[40 + 8 * 8 + 1] = 0xff; // last header claims 2 KiB
    assert!(matches!(
        decode_frame(LinkType::RAW, &p),
        Err(DecodeError::Truncated(_) | DecodeError::Malformed(..))
    ));
}
