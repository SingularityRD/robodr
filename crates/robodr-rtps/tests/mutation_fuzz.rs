//! Deterministic mutation fuzzing of `parse_datagram`, ported from the
//! standalone `4-dogrulama/fuzz-rtps.rs` program (500k xorshift mutations of
//! one SEDP seed) and widened to every synthetic fixture as a seed.
//!
//! No external crates: a xorshift64* PRNG with fixed seeds makes every run
//! reproduce exactly. Each iteration picks a seed datagram and applies one of
//! several mutation strategies (byte flips, length-field corruption,
//! truncation, extension, insertion/deletion, splicing two seeds, a random
//! tail after a valid header). The parser output is then checked against
//! `common::check_invariants`:
//!
//! * no panic (a panic is caught and re-raised with the offending datagram
//!   in hex, the iteration and the PRNG seed, so it can be pasted into a test);
//! * bounded output: at most `1 + (len - 20) / 24` events per datagram;
//! * every guid_prefix is 24 lower-case hex characters;
//! * topic/type names are valid UTF-8 and shorter than the datagram;
//! * non-RTPS input yields no events; the parse is deterministic.
//!
//! `fast_mutation_fuzz` runs 20k iterations by default (override with
//! `ROBODR_FUZZ_ITERS`). `long_mutation_fuzz` runs 500k and is `#[ignore]`d:
//! `cargo test -p robodr-rtps --release --test mutation_fuzz -- --ignored`.
//! Coverage-guided fuzzing lives in the top-level `fuzz/` cargo-fuzz crate.

mod common;

use common::{all, check_invariants, hex, max_events};
use robodr_rtps::parse_datagram;
use std::panic::{catch_unwind, AssertUnwindSafe};

/// xorshift64* (Vigna). Never seeded with 0.
struct Rng(u64);

impl Rng {
    fn new(seed: u64) -> Self {
        Self(seed | 1)
    }
    fn next(&mut self) -> u64 {
        self.0 ^= self.0 >> 12;
        self.0 ^= self.0 << 25;
        self.0 ^= self.0 >> 27;
        self.0.wrapping_mul(0x2545_f491_4f6c_dd1d)
    }
    /// Uniform-ish in `0..n` (n > 0).
    fn below(&mut self, n: usize) -> usize {
        (self.next() % n as u64) as usize
    }
    fn byte(&mut self) -> u8 {
        self.next() as u8
    }
}

/// Values that tend to break length arithmetic.
const INTERESTING_U16: [u16; 8] = [0, 1, 3, 4, 0x7fff, 0x8000, 0xfffe, 0xffff];

fn mutate(rng: &mut Rng, seeds: &[Vec<u8>], d: &mut Vec<u8>) {
    let body_pos = |rng: &mut Rng, d: &Vec<u8>| {
        if d.len() > 20 {
            20 + rng.below(d.len() - 20)
        } else {
            rng.below(d.len().max(1))
        }
    };
    match rng.below(9) {
        // 1-8 random byte overwrites after the header (the original program).
        0 | 1 => {
            for _ in 0..1 + rng.below(8) {
                if d.is_empty() {
                    break;
                }
                let p = body_pos(rng, d);
                d[p] = rng.byte();
            }
        }
        // Single bit flips.
        2 => {
            for _ in 0..1 + rng.below(4) {
                if d.is_empty() {
                    break;
                }
                let p = rng.below(d.len());
                d[p] ^= 1 << rng.below(8);
            }
        }
        // Overwrite an aligned u16 (submessage / parameter lengths sit on
        // 2-byte boundaries) with an interesting value, either endianness.
        3 => {
            if d.len() >= 22 {
                let p = (body_pos(rng, d) & !1).min(d.len() - 2);
                let v = INTERESTING_U16[rng.below(INTERESTING_U16.len())];
                let b = if rng.below(2) == 0 {
                    v.to_le_bytes()
                } else {
                    v.to_be_bytes()
                };
                d[p..p + 2].copy_from_slice(&b);
            }
        }
        // Truncate anywhere, including inside the header.
        4 => {
            let l = rng.below(d.len() + 1);
            d.truncate(l);
        }
        // Extend with random bytes.
        5 => {
            for _ in 0..rng.below(64) {
                d.push(rng.byte());
            }
        }
        // Insert or delete a run of bytes (misaligns everything after it).
        6 => {
            if d.len() > 20 {
                let p = body_pos(rng, d);
                if rng.below(2) == 0 {
                    let n = 1 + rng.below(8);
                    let end = (p + n).min(d.len());
                    d.drain(p..end);
                } else {
                    for _ in 0..1 + rng.below(8) {
                        d.insert(p, rng.byte());
                    }
                }
            }
        }
        // Splice: our header+prefix of submessages, another seed's tail.
        7 => {
            let other = &seeds[rng.below(seeds.len())];
            if d.len() > 20 && other.len() > 20 {
                let cut = body_pos(rng, d);
                let from = 20 + rng.below(other.len() - 20);
                d.truncate(cut);
                d.extend_from_slice(&other[from..]);
            }
        }
        // Valid header, fully random tail (1 in 7 iterations in the original).
        _ => {
            d.truncate(20);
            for _ in 0..rng.below(512) {
                d.push(rng.byte());
            }
        }
    }
}

fn run(iterations: usize, rng_seed: u64) -> usize {
    let seeds: Vec<Vec<u8>> = all().into_iter().map(|f| f.bytes).collect();
    for s in &seeds {
        assert!(!parse_datagram(s, "x").is_empty(), "seed must parse");
    }
    let mut rng = Rng::new(rng_seed);
    let mut endpoint_events = 0usize;
    for i in 0..iterations {
        let mut d = seeds[rng.below(seeds.len())].clone();
        // Stack 1-3 mutations.
        for _ in 0..1 + rng.below(3) {
            mutate(&mut rng, &seeds, &mut d);
        }
        let src = "198.51.100.7";
        let events = match catch_unwind(AssertUnwindSafe(|| parse_datagram(&d, src))) {
            Ok(ev) => ev,
            Err(_) => panic!(
                "parse_datagram panicked (iteration {i}, rng seed {rng_seed:#x}) on {} bytes: {}",
                d.len(),
                hex(&d)
            ),
        };
        if let Err(why) = check_invariants(&d, src, &events) {
            panic!(
                "invariant violated (iteration {i}): {why}\ninput: {}",
                hex(&d)
            );
        }
        if i % 16 == 0 {
            assert_eq!(events, parse_datagram(&d, src), "non-deterministic parse");
        }
        endpoint_events += events.len().saturating_sub(1);
    }
    endpoint_events
}

#[test]
fn fast_mutation_fuzz() {
    let iters = std::env::var("ROBODR_FUZZ_ITERS")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(20_000);
    let endpoints = run(iters, 0x9e37_79b9_7f4a_7c15);
    println!(
        "fuzzed {iters} mutated datagrams: no panics; {endpoints} endpoint events still parsed"
    );
    // The mutations must not be so destructive that nothing parses any more:
    // otherwise the fuzz would only exercise the early-exit paths.
    assert!(
        endpoints > iters / 50,
        "only {endpoints} endpoint events survived"
    );
}

#[test]
#[ignore = "long run: cargo test -p robodr-rtps --release --test mutation_fuzz -- --ignored"]
fn long_mutation_fuzz() {
    let a = run(500_000, 0xd1b5_4a32_d192_ed03);
    let b = run(100_000, 0x0123_4567_89ab_cdef);
    println!(
        "fuzzed 600000 mutated datagrams: no panics; {} endpoint events",
        a + b
    );
}

/// Pure random noise, with and without the RTPS magic.
#[test]
fn random_noise_never_panics() {
    let mut rng = Rng::new(0x5eed);
    for i in 0..5_000 {
        let len = rng.below(600);
        let mut d: Vec<u8> = (0..len).map(|_| rng.byte()).collect();
        if i % 2 == 0 && d.len() >= 4 {
            d[..4].copy_from_slice(b"RTPS");
        }
        let events = parse_datagram(&d, "x");
        check_invariants(&d, "x", &events).unwrap_or_else(|e| panic!("{e}: {}", hex(&d)));
    }
}

/// Every prefix of every seed: truncation at each possible byte.
#[test]
fn every_truncation_of_every_seed() {
    for f in all() {
        for cut in 0..=f.bytes.len() {
            let d = &f.bytes[..cut];
            let events = parse_datagram(d, "x");
            check_invariants(d, "x", &events)
                .unwrap_or_else(|e| panic!("{} cut {cut}: {e}", f.name));
            assert_eq!(events.is_empty(), cut < 20, "{} cut {cut}", f.name);
        }
    }
}

#[test]
fn event_bound_is_sane() {
    assert_eq!(max_events(0), 0);
    assert_eq!(max_events(19), 0);
    assert_eq!(max_events(20), 1);
    assert_eq!(max_events(20 + 24), 2);
}
