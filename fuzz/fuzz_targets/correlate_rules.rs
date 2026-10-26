//! libFuzzer target: correlation rule JSON + the engine driven by it.
//!
//! The harness (input format, invariants) is `fuzz/harness/correlate_rules.rs`, shared
//! via `#[path]` with the std-only smoke test
//! `crates/robodr-correlate/tests/fuzz_smoke.rs`, so the two cannot drift.
//!
//! Run: `cargo +nightly fuzz run correlate_rules` (seeds: `fuzz/corpus/correlate_rules/`).
#![no_main]

use libfuzzer_sys::fuzz_target;

#[path = "../harness/correlate_rules.rs"]
mod harness;

fuzz_target!(|data: &[u8]| {
    harness::run(data);
});
