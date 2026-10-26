//! libFuzzer target: diode batch manifest + signature file parse and checks.
//!
//! The harness (input format, invariants) is `fuzz/harness/diode_manifest.rs`, shared
//! via `#[path]` with the std-only smoke test
//! `crates/robodr-diode/tests/fuzz_smoke.rs`, so the two cannot drift.
//!
//! Run: `cargo +nightly fuzz run diode_manifest` (seeds: `fuzz/corpus/diode_manifest/`).
#![no_main]

use libfuzzer_sys::fuzz_target;

#[path = "../harness/diode_manifest.rs"]
mod harness;

fuzz_target!(|data: &[u8]| {
    harness::run(data);
});
