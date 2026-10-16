//! Std-only deterministic mutation driver for the `fuzz_smoke` tests.
//!
//! libFuzzer / cargo-fuzz cannot run in every environment (it needs nightly
//! and `libfuzzer-sys` from crates.io), so every libFuzzer target in
//! `fuzz/fuzz_targets/` has a harness file in `fuzz/harness/` that both the
//! target and a `tests/fuzz_smoke.rs` integration test in the owning crate
//! include via `#[path]`. This file is the smoke tests' stand-in for the
//! fuzzer engine: it loads the target's seed corpus (`fuzz/corpus/<target>/`)
//! plus any in-memory seeds, mutates them with a xorshift64* PRNG and feeds
//! each input to the harness.
//!
//! Mutations: bit flips, random byte overwrites, truncation, random
//! extension, insertion/deletion of byte runs, splicing two seeds, chunk
//! duplication, "length-field inflation" (an aligned u16/u32 overwritten
//! with boundary values, either endianness) and a few text-aware ones
//! (digit runs replaced by extreme numbers, structural characters inserted)
//! because most targets parse JSON.
//!
//! Every iteration is deterministic for a given `rng_seed`. The run stops
//! after `ROBODR_FUZZ_ITERS` iterations (default 20 000) or after
//! `ROBODR_FUZZ_SECS` seconds of wall time (default 8), whichever comes
//! first (`ROBODR_FUZZ_SEED` is XOR-ed into each test's PRNG seed to
//! explore other sequences), so a slow debug build cannot make CI time out; at least
//! [`MIN_ITERS`] iterations must complete. Each single input must finish in
//! [`MAX_INPUT_TIME`] ("bounded time": no hang, no quadratic blow-up).
//!
//! On a panic the input is minimised (greedy chunk removal while it still
//! panics) and the test fails with the minimised input as a Rust byte-string
//! literal, ready to paste into a regression test.
#![allow(dead_code)]

use std::panic::{catch_unwind, AssertUnwindSafe};
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

/// Iterations that must complete inside the time budget.
pub const MIN_ITERS: usize = 1_000;
/// Hard bound for one input (debug build).
pub const MAX_INPUT_TIME: Duration = Duration::from_secs(3);
/// Inputs are capped at this size after mutation (libFuzzer's `-max_len`).
pub const MAX_LEN: usize = 256 * 1024;

/// xorshift64* (Vigna). Never seeded with 0.
pub struct Rng(u64);

impl Rng {
    pub fn new(seed: u64) -> Self {
        Self(seed | 1)
    }
    pub fn next(&mut self) -> u64 {
        self.0 ^= self.0 >> 12;
        self.0 ^= self.0 << 25;
        self.0 ^= self.0 >> 27;
        self.0.wrapping_mul(0x2545_f491_4f6c_dd1d)
    }
    /// `0..n`, 0 for `n == 0`.
    pub fn below(&mut self, n: usize) -> usize {
        if n == 0 {
            0
        } else {
            (self.next() % n as u64) as usize
        }
    }
    pub fn byte(&mut self) -> u8 {
        self.next() as u8
    }
}

const INTERESTING_U16: [u16; 9] = [0, 1, 2, 7, 8, 0x7fff, 0x8000, 0xfffe, 0xffff];
const INTERESTING_U32: [u32; 9] = [
    0,
    1,
    8,
    0x7fff_ffff,
    0x8000_0000,
    0xffff_fffe,
    0xffff_ffff,
    0x0100_0000,
    0x0001_0000,
];
const TEXT_NUMBERS: [&str; 12] = [
    "-1",
    "0",
    "-0",
    "1e308",
    "-1e308",
    "1e400",
    "18446744073709551616",
    "-9223372036854775809",
    "4294967296",
    "65536",
    "0.0000000000000000000001",
    "NaN",
];
const TEXT_TOKENS: [&str; 14] = [
    "[", "]", "{", "}", "\"", ",", ":", "null", "true", "\\u0000", "\\ud800", "\u{202e}", "\n",
    "\"\":",
];

/// One mutation of `d` (`seeds` are splice donors).
pub fn mutate(rng: &mut Rng, seeds: &[Vec<u8>], d: &mut Vec<u8>) {
    for _ in 0..1 + rng.below(3) {
        mutate_once(rng, seeds, d);
    }
    d.truncate(MAX_LEN);
}

fn mutate_once(rng: &mut Rng, seeds: &[Vec<u8>], d: &mut Vec<u8>) {
    match rng.below(13) {
        // Bit flips.
        0 => {
            for _ in 0..1 + rng.below(4) {
                if d.is_empty() {
                    break;
                }
                let p = rng.below(d.len());
                d[p] ^= 1 << rng.below(8);
            }
        }
        // Random byte overwrites.
        1 => {
            for _ in 0..1 + rng.below(8) {
                if d.is_empty() {
                    break;
                }
                let p = rng.below(d.len());
                d[p] = rng.byte();
            }
        }
        // Truncate anywhere.
        2 => {
            let l = rng.below(d.len() + 1);
            d.truncate(l);
        }
        // Extend with random bytes.
        3 => {
            for _ in 0..rng.below(64) {
                d.push(rng.byte());
            }
        }
        // Delete a run.
        4 if !d.is_empty() => {
            let p = rng.below(d.len());
            let end = (p + 1 + rng.below(16)).min(d.len());
            d.drain(p..end);
        }
        // Insert a random run.
        5 => {
            let p = rng.below(d.len() + 1);
            for _ in 0..1 + rng.below(8) {
                d.insert(p, rng.byte());
            }
        }
        // Splice: our prefix, another seed's suffix.
        6 if !seeds.is_empty() => {
            let other = &seeds[rng.below(seeds.len())];
            let cut = rng.below(d.len() + 1);
            let from = rng.below(other.len() + 1);
            d.truncate(cut);
            d.extend_from_slice(&other[from..]);
        }
        // Length-field inflation: aligned u16 / u32, either endianness.
        7 if d.len() >= 2 => {
            let p = rng.below(d.len() - 1) & !1;
            let v = INTERESTING_U16[rng.below(INTERESTING_U16.len())];
            let b = if rng.below(2) == 0 {
                v.to_le_bytes()
            } else {
                v.to_be_bytes()
            };
            d[p..p + 2].copy_from_slice(&b);
        }
        8 if d.len() >= 4 => {
            let p = rng.below(d.len() - 3) & !3;
            let v = INTERESTING_U32[rng.below(INTERESTING_U32.len())];
            let b = if rng.below(2) == 0 {
                v.to_le_bytes()
            } else {
                v.to_be_bytes()
            };
            d[p..p + 4].copy_from_slice(&b);
        }
        // Duplicate a chunk in place (repeated records, deeper nesting).
        9 if !d.is_empty() => {
            let p = rng.below(d.len());
            let end = (p + 1 + rng.below(64)).min(d.len());
            let chunk = d[p..end].to_vec();
            let at = rng.below(d.len() + 1);
            for _ in 0..1 + rng.below(4) {
                d.splice(at..at, chunk.iter().copied());
            }
        }
        // Text: replace a digit run with an extreme number.
        10 => {
            let digits: Vec<usize> = (0..d.len()).filter(|&i| d[i].is_ascii_digit()).collect();
            if !digits.is_empty() {
                let s = digits[rng.below(digits.len())];
                let mut e = s;
                while e < d.len() && (d[e].is_ascii_digit() || d[e] == b'.') {
                    e += 1;
                }
                let n = TEXT_NUMBERS[rng.below(TEXT_NUMBERS.len())];
                d.splice(s..e, n.bytes());
            }
        }
        // Text: insert a structural token.
        11 => {
            let p = rng.below(d.len() + 1);
            let t = TEXT_TOKENS[rng.below(TEXT_TOKENS.len())];
            d.splice(p..p, t.bytes());
        }
        // Text: copy one quoted string over another (duplicate keys,
        // swapped values).
        _ => {
            let quotes: Vec<usize> = (0..d.len()).filter(|&i| d[i] == b'"').collect();
            if quotes.len() >= 4 {
                let a = rng.below(quotes.len() - 1);
                let b = rng.below(quotes.len() - 1);
                let src = d[quotes[a]..=quotes[a + 1]].to_vec();
                let (s, e) = (quotes[b], quotes[b + 1]);
                if s < e {
                    d.splice(s..=e, src);
                }
            }
        }
    }
}

/// Seed files of `target` in `fuzz/corpus/<target>/`, sorted by name.
/// `manifest_dir` is the including crate's `CARGO_MANIFEST_DIR`
/// (`crates/<name>`).
pub fn corpus(manifest_dir: &str, target: &str) -> Vec<Vec<u8>> {
    let dir = corpus_dir(manifest_dir, target);
    let mut files: Vec<PathBuf> = std::fs::read_dir(&dir)
        .unwrap_or_else(|e| panic!("seed corpus {} unreadable: {e}", dir.display()))
        .filter_map(|e| e.ok().map(|e| e.path()))
        .filter(|p| p.is_file())
        .collect();
    files.sort();
    assert!(!files.is_empty(), "seed corpus {} is empty", dir.display());
    files
        .iter()
        .map(|p| std::fs::read(p).unwrap_or_else(|e| panic!("{}: {e}", p.display())))
        .collect()
}

pub fn corpus_dir(manifest_dir: &str, target: &str) -> PathBuf {
    Path::new(manifest_dir)
        .join("../../fuzz/corpus")
        .join(target)
}

fn env_or(name: &str, default: u64) -> u64 {
    std::env::var(name)
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(default)
}

/// Rust byte-string literal for `b` (printable ASCII kept, rest escaped).
pub fn literal(b: &[u8]) -> String {
    let mut s = String::from("b\"");
    for &c in b {
        match c {
            b'"' => s.push_str("\\\""),
            b'\\' => s.push_str("\\\\"),
            b'\n' => s.push_str("\\n"),
            0x20..=0x7e => s.push(c as char),
            _ => s.push_str(&format!("\\x{c:02x}")),
        }
    }
    s.push('"');
    s
}

fn panics(f: &dyn Fn(&[u8]), d: &[u8]) -> Option<String> {
    catch_unwind(AssertUnwindSafe(|| f(d))).err().map(|e| {
        e.downcast_ref::<String>()
            .cloned()
            .or_else(|| e.downcast_ref::<&str>().map(|s| s.to_string()))
            .unwrap_or_else(|| "<non-string panic>".into())
    })
}

/// Greedy delta minimisation: drop chunks (halving sizes) while the input
/// still panics. Bounded number of attempts.
pub fn minimise(f: &dyn Fn(&[u8]), input: &[u8]) -> Vec<u8> {
    let mut cur = input.to_vec();
    let mut attempts = 0usize;
    let mut chunk = (cur.len() / 2).max(1);
    loop {
        let mut i = 0;
        let mut progress = false;
        while i < cur.len() && attempts < 20_000 {
            let end = (i + chunk).min(cur.len());
            let mut cand = cur.clone();
            cand.drain(i..end);
            attempts += 1;
            if panics(f, &cand).is_some() {
                cur = cand;
                progress = true;
            } else {
                i += chunk;
            }
        }
        if attempts >= 20_000 || (chunk == 1 && !progress) {
            break;
        }
        if !progress {
            chunk = (chunk / 2).max(1);
        }
    }
    cur
}

/// Statistics of one smoke run.
#[derive(Debug, Default, Clone, Copy)]
pub struct Outcome {
    pub iterations: usize,
    pub slowest: Duration,
}

/// Run `harness` over every seed, then over mutated inputs. Panics (test
/// failure) on a harness panic or an input that exceeds [`MAX_INPUT_TIME`].
pub fn run(target: &str, seeds: &[Vec<u8>], rng_seed: u64, harness: &dyn Fn(&[u8])) -> Outcome {
    assert!(!seeds.is_empty());
    let iters = env_or("ROBODR_FUZZ_ITERS", 20_000) as usize;
    let budget = Duration::from_secs(env_or("ROBODR_FUZZ_SECS", 8));
    let mut out = Outcome::default();
    // Explore other sequences without editing the test.
    let rng_seed = rng_seed ^ env_or("ROBODR_FUZZ_SEED", 0);
    let mut rng = Rng::new(rng_seed);
    let started = Instant::now();
    let total = seeds.len() + iters;
    for i in 0..total {
        if i >= seeds.len() + MIN_ITERS.min(iters) && started.elapsed() > budget {
            break;
        }
        let input = if i < seeds.len() {
            seeds[i].clone()
        } else {
            let mut d = seeds[rng.below(seeds.len())].clone();
            mutate(&mut rng, seeds, &mut d);
            d
        };
        let t = Instant::now();
        if let Some(msg) = panics(harness, &input) {
            fail(target, harness, &input, &msg, i, rng_seed);
        }
        let took = t.elapsed();
        out.slowest = out.slowest.max(took);
        assert!(
            took <= MAX_INPUT_TIME,
            "{target}: input took {took:?} (> {MAX_INPUT_TIME:?}), iteration {i}, rng seed \
             {rng_seed:#x}, {} bytes: {}",
            input.len(),
            literal(&input[..input.len().min(4096)])
        );
        out.iterations = i + 1;
    }
    eprintln!(
        "{target}: {} inputs ({} seeds) in {:?}, slowest {:?}",
        out.iterations,
        seeds.len(),
        started.elapsed(),
        out.slowest
    );
    out
}

fn fail(target: &str, harness: &dyn Fn(&[u8]), input: &[u8], msg: &str, i: usize, seed: u64) -> ! {
    let prev = std::panic::take_hook();
    std::panic::set_hook(Box::new(|_| {}));
    let min = minimise(harness, input);
    std::panic::set_hook(prev);
    let min_msg = panics(harness, &min).unwrap_or_default();
    panic!(
        "{target}: harness panicked at iteration {i} (rng seed {seed:#x}): {msg}\n\
         minimised ({} -> {} bytes), panics with: {min_msg}\n{}",
        input.len(),
        min.len(),
        literal(&min)
    );
}

#[cfg(test)]
mod self_tests {
    use super::*;

    #[test]
    fn mutator_is_deterministic_and_bounded() {
        let seeds = vec![b"{\"a\": [1, 2.5, \"x\"]}".to_vec(), vec![0u8; 40]];
        let gen = |s| {
            let mut r = Rng::new(s);
            (0..500)
                .map(|_| {
                    let mut d = seeds[r.below(2)].clone();
                    mutate(&mut r, &seeds, &mut d);
                    d
                })
                .collect::<Vec<_>>()
        };
        assert_eq!(gen(7), gen(7));
        assert!(gen(7).iter().all(|d| d.len() <= MAX_LEN));
    }

    #[test]
    fn minimiser_finds_the_trigger() {
        let f = |d: &[u8]| assert!(!d.windows(3).any(|w| w == b"BUG"), "bug");
        let prev = std::panic::take_hook();
        std::panic::set_hook(Box::new(|_| {}));
        let m = minimise(&f, b"xxxxxxxxBUGyyyyyyyyyyyyy");
        std::panic::set_hook(prev);
        assert_eq!(m, b"BUG");
        assert_eq!(literal(b"a\"\\\n\x01"), "b\"a\\\"\\\\\\n\\x01\"");
    }
}
