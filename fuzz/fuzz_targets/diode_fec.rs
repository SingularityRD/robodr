//! libFuzzer target: diode Reed-Solomon encode/erase/rebuild against the `reed-solomon` oracle.
//!
//! The harness (input format, invariants) is `fuzz/harness/diode_fec.rs`, shared
//! via `#[path]` with the std-only smoke test
//! `crates/robodr-diode/tests/fuzz_smoke.rs`, so the two cannot drift.
//!
//! Run: `cargo +nightly fuzz run diode_fec` (seeds: `fuzz/corpus/diode_fec/`).
#![no_main]

use libfuzzer_sys::fuzz_target;

#[path = "../harness/diode_fec.rs"]
mod harness;

fuzz_target!(|data: &[u8]| {
    harness::run(data);
});
