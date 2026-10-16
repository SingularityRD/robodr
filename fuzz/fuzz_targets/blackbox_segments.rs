//! libFuzzer target: black-box segment scan/decode, `verify_segments` / `verify_dir`, export bundle.
//!
//! The harness (input format, invariants) is `fuzz/harness/blackbox_segments.rs`, shared
//! via `#[path]` with the std-only smoke test
//! `crates/robodr-blackbox/tests/fuzz_smoke.rs`, so the two cannot drift.
//!
//! Run: `cargo +nightly fuzz run blackbox_segments` (seeds: `fuzz/corpus/blackbox_segments/`).
#![no_main]

use libfuzzer_sys::fuzz_target;

#[path = "../harness/blackbox_segments.rs"]
mod harness;

fuzz_target!(|data: &[u8]| {
    harness::run(data);
});
