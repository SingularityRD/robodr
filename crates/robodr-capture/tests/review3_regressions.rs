//! Regression tests for the third independent review (R3-C1..C3). The
//! reviewer's PoCs asserted the buggy behaviour; these assert the fix.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::time::Duration;

use robodr_capture::reassembly::ReassemblyLimits;
use robodr_capture::{rtps_datagrams, synth, LinkType, Reassembler, RtpsDatagrams, VecSource};

fn rtps(n: usize) -> Vec<u8> {
    let mut p = b"RTPS\x02\x03\x01\x0f".to_vec();
    p.extend_from_slice(&[0xaa; 12]);
    p.resize(n, 0x5a);
    p
}

fn run(pkts: Vec<Vec<u8>>) -> (Vec<Vec<u8>>, RtpsDatagrams<VecSource>) {
    let src = VecSource::new(
        pkts.into_iter()
            .enumerate()
            .map(|(i, p)| (Duration::from_millis(i as u64), LinkType::RAW, p)),
    );
    let mut it = rtps_datagrams(src);
    let got = it.by_ref().map(|(_, p)| p).collect();
    (got, it)
}

fn v6(s: &str) -> Ipv6Addr {
    s.parse().unwrap()
}

/// R3-C1: the Fragment header's Next Header of non-first fragments is
/// ignored, as Linux does; the datagram the kernel delivers is seen.
#[test]
fn r3_c1_ipv6_nonfirst_fragment_next_header_is_ignored() {
    let (s, d) = (v6("fd00::66"), v6("fd00::5"));
    let payload = rtps(3000);
    let pkt = synth::ipv6_udp(s, d, 40000, 7410, &[], &payload);
    let frags = synth::ipv6_fragment(&pkt, 1232, 77);
    assert!(frags.len() >= 3);

    for nh in [59u8, 6, 58, 50] {
        let mut evil = frags.clone();
        for f in evil.iter_mut().skip(1) {
            f[40] = nh;
        }
        let (got, it) = run(evil);
        assert_eq!(got, vec![payload.clone()], "next header {nh}");
        assert_eq!(it.stats().not_udp, 0);
        assert_eq!(it.reassembly_stats().completed, 1);
    }

    // The first fragment's value decides: a non-UDP first fragment rules the
    // datagram out (counted as not UDP), whatever the others say.
    let mut tcp = frags.clone();
    tcp[0][40] = 6;
    let (got, it) = run(tcp);
    assert!(got.is_empty());
    assert!(it.stats().not_udp >= 1);
    // Even when the non-UDP first fragment arrives last.
    let mut tcp_last = frags[1..].to_vec();
    let mut first = frags[0].clone();
    first[40] = 6;
    tcp_last.push(first);
    let (got, it) = run(tcp_last);
    assert!(got.is_empty());
    assert!(it.stats().not_udp >= 1);
}

/// R3-C2: UDP length 0 over IPv6 means "the IPv6 payload length" (Linux
/// __udp6_lib_rcv); with a correct checksum the datagram is delivered.
#[test]
fn r3_c2_ipv6_udp_length_zero_is_delivered_like_linux() {
    let (s, d) = (v6("fd00::66"), v6("fd00::5"));
    let payload = rtps(200);
    let mut pkt = synth::ipv6_udp(s, d, 40000, 7410, &[], &payload);
    pkt[44..46].copy_from_slice(&[0, 0]); // length 0
    pkt[46..48].copy_from_slice(&[0, 0]);
    let c = robodr_capture::checksum::udp_checksum(IpAddr::V6(s), IpAddr::V6(d), &pkt[40..]);
    pkt[46..48].copy_from_slice(&c.to_be_bytes());
    let (got, it) = run(vec![pkt.clone()]);
    assert_eq!(got, vec![payload.clone()]);
    assert_eq!(it.stats().malformed, 0);
    assert_eq!(it.stats().bad_udp_checksum, 0);

    // The checksum is still verified (with the real length): a wrong one
    // is dropped, as the kernel drops it.
    let mut bad = pkt.clone();
    bad[60] ^= 0xff;
    let (got, it) = run(vec![bad]);
    assert!(got.is_empty());
    assert_eq!(it.stats().bad_udp_checksum, 1);

    // Also for a fragmented datagram (length 0 in the reassembled header).
    let mut big = synth::ipv6_udp(s, d, 40000, 7410, &[], &rtps(3000));
    big[44..46].copy_from_slice(&[0, 0]);
    big[46..48].copy_from_slice(&[0, 0]);
    let c = robodr_capture::checksum::udp_checksum(IpAddr::V6(s), IpAddr::V6(d), &big[40..]);
    big[46..48].copy_from_slice(&c.to_be_bytes());
    let (got, _) = run(synth::ipv6_fragment(&big, 1232, 5));
    assert_eq!(got, vec![rtps(3000)]);

    // IPv4 keeps rejecting length 0 (Linux __udp4_lib_rcv does).
    let mut v4 = synth::ipv4_udp(
        Ipv4Addr::new(10, 0, 0, 66),
        Ipv4Addr::new(10, 0, 0, 5),
        40000,
        7410,
        &payload,
    );
    v4[24..26].copy_from_slice(&[0, 0]);
    v4[26..28].copy_from_slice(&[0, 0]);
    let (got, it) = run(vec![v4]);
    assert!(got.is_empty());
    assert_eq!(it.stats().malformed, 1);
}

/// R3-C3: the robot's fragment, its destination below its own budget, is
/// never refused because of junk to other destinations, even when the
/// robot's bucket is the heaviest. The global limit evicts the least
/// recently progressed junk instead (reported in `dropped_capacity`).
#[test]
fn r3_c3_global_cap_never_refuses_robot_fragment_below_its_budget() {
    let lim = ReassemblyLimits::default();
    let mut r = Reassembler::new(lim);
    let robot = Ipv4Addr::new(10, 0, 0, 5);
    let legit = Ipv4Addr::new(10, 0, 0, 7);
    let att = Ipv4Addr::new(10, 0, 0, 66);
    let ts = Duration::from_secs(1);

    let real = synth::ipv4_udp(legit, robot, 1, 7410, &rtps(2900));
    let real_frags = synth::ipv4_fragment(&real, 1480);
    assert_eq!(real_frags.len(), 2);
    let push = |r: &mut Reassembler, p: &[u8]| match robodr_capture::decode::decode_ip(p).unwrap() {
        robodr_capture::Decoded::Fragment(f) => r.push(ts, &f),
        _ => panic!("not a fragment"),
    };

    // One 1480-byte first fragment of a fresh datagram from att to `dst`.
    let junk = |dst: Ipv4Addr, id: u16| {
        let mut f =
            synth::ipv4_fragment(&synth::ipv4_udp(att, dst, 1, 7410, &[0; 3000]), 1480)[0].clone();
        f[4..6].copy_from_slice(&id.to_be_bytes());
        f[10..12].copy_from_slice(&[0, 0]);
        let c = robodr_capture::checksum::internet_checksum(&f[..20]);
        f[10..12].copy_from_slice(&c.to_be_bytes());
        f
    };
    let fakes: Vec<Ipv4Addr> = (0..40).map(|i| Ipv4Addr::new(10, 9, 0, i)).collect();

    // Order 1 (the reviewer's): the real first fragment, then ~1.1 MiB of
    // junk to the robot and ~31 MiB to 40 lighter fake destinations, then
    // the real last fragment.
    // Order 2 (no race needed): the same junk queued *before* the real
    // datagram starts; the junk keeps flowing between its two fragments.
    for junk_first in [false, true] {
        let mut r2 = Reassembler::new(lim);
        let r = if junk_first { &mut r2 } else { &mut r };
        if !junk_first {
            assert!(push(r, &real_frags[0]).is_none());
        }
        let mut id = 0u16;
        while r.buffered_bytes_for(IpAddr::V4(robot)) < 1_100_000 {
            id = id.wrapping_add(1);
            push(r, &junk(robot, id));
        }
        let robot_bytes = r.buffered_bytes_for(IpAddr::V4(robot));
        let mut k = 0usize;
        while r.buffered_bytes() <= lim.max_bytes {
            id = id.wrapping_add(1);
            push(r, &junk(fakes[k % fakes.len()], id));
            k += 1;
        }
        for f in &fakes {
            assert!(r.buffered_bytes_for(IpAddr::V4(*f)) < robot_bytes);
        }
        assert!(robot_bytes < lim.max_bytes_per_dst / 3);
        if junk_first {
            assert!(push(r, &real_frags[0]).is_none());
            // Some more junk between the real fragments (fewer than the
            // ~500 datagrams the full table holds).
            for _ in 0..100 {
                id = id.wrapping_add(1);
                push(r, &junk(fakes[k % fakes.len()], id));
                k += 1;
            }
        }
        let refused = r.stats().refused_capacity;
        let out = push(r, &real_frags[1]).expect("the robot's datagram is delivered");
        assert_eq!(&out.payload[8..], &rtps(2900)[..]);
        assert_eq!(r.stats().refused_capacity, refused, "nothing refused");
        if junk_first {
            assert!(r.stats().dropped_capacity > 0, "evictions are reported");
        }
        assert!(r.buffered_bytes() <= lim.max_bytes + 2 * 1600);
    }
}
