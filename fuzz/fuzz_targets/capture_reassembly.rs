//! libFuzzer target: link-layer decode + IPv4/IPv6 reassembly (`decode_frame`, `Reassembler`).
//!
//! The harness (input format, invariants) is `fuzz/harness/capture_reassembly.rs`, shared
//! via `#[path]` with the std-only smoke test
//! `crates/robodr-capture/tests/fuzz_smoke.rs`, so the two cannot drift.
//!
//! Run: `cargo +nightly fuzz run capture_reassembly` (seeds: `fuzz/corpus/capture_reassembly/`).
#![no_main]

use libfuzzer_sys::fuzz_target;

#[path = "../harness/capture_reassembly.rs"]
mod harness;

fuzz_target!(|data: &[u8]| {
    harness::run(data);
});
