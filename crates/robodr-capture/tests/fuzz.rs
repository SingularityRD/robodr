//! Deterministic mutation fuzz (std only): decoders, reassembler, file
//! readers and the full pipeline must never panic, loop forever or read out of
//! bounds on hostile input. Debug test builds also trap integer overflow.
//!
//! `ROBODR_FUZZ_ITERS` overrides the iteration count (default 50 000).

use std::net::{Ipv4Addr, Ipv6Addr};
use std::time::Duration;

use robodr_capture::{
    bpf::rtps_filter_program, decode::IpFragment, decode_frame, pcap::PcapWriter, rtps_datagrams,
    synth, CaptureFile, Decoded, LinkType, PacketSource, Reassembler, ReassemblyLimits, RtpsFilter,
    VecSource,
};

/// xorshift64* — deterministic, std-only.
struct Rng(u64);

impl Rng {
    fn next(&mut self) -> u64 {
        self.0 ^= self.0 >> 12;
        self.0 ^= self.0 << 25;
        self.0 ^= self.0 >> 27;
        self.0.wrapping_mul(0x2545_f491_4f6c_dd1d)
    }
    fn below(&mut self, n: usize) -> usize {
        if n == 0 {
            0
        } else {
            (self.next() % n as u64) as usize
        }
    }
    fn byte(&mut self) -> u8 {
        self.next() as u8
    }
}

fn iters() -> usize {
    std::env::var("ROBODR_FUZZ_ITERS")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(50_000)
}

fn mutate(rng: &mut Rng, input: &[u8]) -> Vec<u8> {
    let mut v = input.to_vec();
    for _ in 0..1 + rng.below(4) {
        match rng.below(7) {
            0 if !v.is_empty() => {
                let i = rng.below(v.len());
                v[i] ^= 1 << rng.below(8);
            }
            1 if !v.is_empty() => {
                let i = rng.below(v.len());
                v[i] = rng.byte();
            }
            2 => {
                let n = rng.below(v.len() + 1);
                v.truncate(n);
            }
            3 => {
                for _ in 0..rng.below(16) {
                    v.push(rng.byte());
                }
            }
            4 if !v.is_empty() => {
                let i = rng.below(v.len());
                v.remove(i);
            }
            5 => {
                let i = rng.below(v.len() + 1);
                v.insert(i, rng.byte());
            }
            6 if v.len() >= 2 => {
                // Interesting values in a 16-bit field (lengths!).
                let i = rng.below(v.len() - 1);
                let val: u16 = [0, 1, 7, 8, 0x7fff, 0xffff, 20, 40][rng.below(8)];
                v[i..i + 2].copy_from_slice(&val.to_be_bytes());
            }
            _ => {}
        }
    }
    v
}

fn seeds() -> Vec<(LinkType, Vec<u8>)> {
    let a = Ipv4Addr::new(10, 1, 2, 3);
    let b = Ipv4Addr::new(10, 1, 2, 4);
    let a6: Ipv6Addr = "fd00::3".parse().unwrap();
    let b6: Ipv6Addr = "fd00::4".parse().unwrap();
    let rtps = b"RTPS\x02\x03\x01\x0f\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa".to_vec();
    let v4 = synth::ipv4_udp(a, b, 7410, 7412, &rtps);
    let v6 = synth::ipv6_udp(
        a6,
        b6,
        7410,
        7412,
        &[(0, 8), (43, 16), (51, 12), (60, 8)],
        &rtps,
    );
    let mut seeds = vec![
        (LinkType::ETHERNET, synth::ethernet(0x0800, &v4)),
        (
            LinkType::ETHERNET,
            synth::ethernet_vlan(&[(0x88a8, 1), (0x8100, 2)], 0x86dd, &v6),
        ),
        (LinkType::LINUX_SLL, synth::linux_sll(0x86dd, &v6)),
        (LinkType::LINUX_SLL2, synth::linux_sll2(0x0800, &v4)),
        (LinkType::RAW, v4.clone()),
        (LinkType::IPV6, v6.clone()),
        (LinkType::NULL, synth::null_loopback(30, true, &v6)),
        (LinkType::LOOP, synth::null_loopback(2, false, &v4)),
    ];
    for f in synth::ipv4_fragment(&v4, 8) {
        seeds.push((LinkType::RAW, f));
    }
    let plain6 = synth::ipv6_udp(a6, b6, 1, 7410, &[], &rtps);
    for f in synth::ipv6_fragment(&plain6, 16, 9) {
        seeds.push((LinkType::RAW, f));
    }
    seeds
}

const LINKTYPES: [LinkType; 9] = [
    LinkType::NULL,
    LinkType::ETHERNET,
    LinkType::RAW,
    LinkType::LOOP,
    LinkType::LINUX_SLL,
    LinkType::IPV4,
    LinkType::IPV6,
    LinkType::LINUX_SLL2,
    LinkType(12345),
];

#[test]
fn decoders_and_reassembler_never_panic() {
    let seeds = seeds();
    let mut rng = Rng(0x005e_ed0f_d0d5);
    let prog = rtps_filter_program(&RtpsFilter::default()).unwrap();
    let mut reasm = Reassembler::new(ReassemblyLimits {
        max_datagrams: 16,
        max_bytes: 64 * 1024,
        max_bytes_per_dst: 32 * 1024,
        timeout: Duration::from_secs(2),
        timeout_v6: Duration::from_secs(3),
        ..Default::default()
    });
    let mut decoded = 0usize;
    for i in 0..iters() {
        let (lt, seed) = &seeds[rng.below(seeds.len())];
        let frame = mutate(&mut rng, seed);
        // Usually the right link type, sometimes a wrong one.
        let lt = if rng.below(8) == 0 {
            LINKTYPES[rng.below(LINKTYPES.len())]
        } else {
            *lt
        };
        let ts = Duration::from_millis(i as u64 * 10);
        match decode_frame(lt, &frame) {
            Ok(Decoded::Udp(u)) => {
                decoded += 1;
                // The payload must be a sub-slice of the frame.
                let fr = frame.as_ptr_range();
                let pr = u.payload.as_ptr_range();
                assert!(fr.start <= pr.start && pr.end <= fr.end);
            }
            Ok(Decoded::Fragment(f)) => {
                let _ = reasm.push(ts, &f);
            }
            Err(_) => {}
        }
        // Kernel-filter interpreter on the same bytes (as raw IP).
        let _ = prog.run(&frame);
        // Hostile fragments straight into the reassembler.
        if rng.below(4) == 0 {
            let data = mutate(&mut rng, &frame);
            let frag = IpFragment {
                src: Ipv4Addr::new(1, 1, 1, rng.byte()).into(),
                dst: Ipv4Addr::new(2, 2, 2, 2).into(),
                id: rng.below(4) as u32,
                protocol: 17,
                offset: rng.below(70_000) & !7,
                more: rng.below(2) == 0,
                data: &data,
                header_len: 20,
            };
            let _ = reasm.push(ts, &frag);
            // max_datagrams applies per IP version.
            assert!(reasm.in_flight() <= 32);
            assert!(reasm.buffered_bytes() <= 2 * (64 * 1024 + 70_000 + 256));
        }
    }
    assert!(
        decoded > 0,
        "fuzz never produced a valid datagram; mutations too aggressive"
    );
}

#[test]
fn file_readers_and_pipeline_never_panic() {
    let seeds = seeds();
    // A pcap and a pcapng built from all seeds.
    let mut w = PcapWriter::new(Vec::new(), LinkType::ETHERNET, 65535, false).unwrap();
    for (_, f) in seeds.iter().take(2) {
        w.write_packet(Duration::from_secs(1), f, f.len() as u32)
            .unwrap();
    }
    let pcap = w.into_inner();
    let mut pcapng = Vec::new();
    let mut blk = |t: u32, body: &[u8]| {
        let mut body = body.to_vec();
        while !body.len().is_multiple_of(4) {
            body.push(0);
        }
        let len = (12 + body.len()) as u32;
        pcapng.extend_from_slice(&t.to_le_bytes());
        pcapng.extend_from_slice(&len.to_le_bytes());
        pcapng.extend_from_slice(&body);
        pcapng.extend_from_slice(&len.to_le_bytes());
    };
    blk(
        0x0a0d_0d0a,
        &[
            0x4d, 0x3c, 0x2b, 0x1a, 1, 0, 0, 0, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
        ],
    );
    blk(
        1,
        &[101, 0, 0, 0, 0, 0, 0, 0, 9, 0, 1, 0, 9, 0, 0, 0, 0, 0, 0, 0],
    );
    for (lt, f) in &seeds {
        if *lt == LinkType::RAW {
            let mut epb = vec![0u8; 12];
            epb.extend_from_slice(&(f.len() as u32).to_le_bytes());
            epb.extend_from_slice(&(f.len() as u32).to_le_bytes());
            epb.extend_from_slice(f);
            blk(6, &epb);
        }
    }
    blk(3, &[4, 0, 0, 0, 1, 2, 3, 4]);

    // Sanity: unmutated files are fully readable.
    for file in [&pcap, &pcapng] {
        let mut it = rtps_datagrams(CaptureFile::new(&file[..]).unwrap());
        assert!(it.by_ref().count() > 0);
        assert!(it.last_error().is_none(), "{:?}", it.last_error());
    }

    let mut rng = Rng(0xf11e_5eed);
    let n = iters() / 10;
    for i in 0..n {
        let base = if i % 2 == 0 { &pcap } else { &pcapng };
        let file = mutate(&mut rng, base);
        if let Ok(mut src) = CaptureFile::new(&file[..]) {
            // Raw reader: bounded number of packets (no infinite loop).
            let mut count = 0;
            while let Ok(Some(_)) = src.next_packet() {
                count += 1;
                assert!(count < 10_000);
            }
        }
        if let Ok(src) = CaptureFile::new(&file[..]) {
            let it = rtps_datagrams(src);
            for (ip, payload) in it.take(10_000) {
                let _ = robodr_rtps::parse_datagram(&payload, &ip);
            }
        }
    }

    // Random frames through the pipeline with random link types.
    let frames: Vec<_> = (0..2_000)
        .map(|_| {
            let (lt, s) = &seeds[rng.below(seeds.len())];
            (
                Duration::from_millis(rng.below(100_000) as u64),
                *lt,
                mutate(&mut rng, s),
            )
        })
        .collect();
    let mut it = rtps_datagrams(VecSource::new(frames));
    for (ip, payload) in it.by_ref() {
        let _ = robodr_rtps::parse_datagram(&payload, &ip);
    }
    assert_eq!(it.stats().frames, 2_000);
}
