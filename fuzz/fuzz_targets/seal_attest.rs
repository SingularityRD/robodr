//! libFuzzer target: see the harness `fuzz/harness/seal_attest.rs` (input format,
//! invariants), shared via `#[path]` with the std-only smoke test of its
//! crate, so the two cannot drift.
//!
//! Run: `cargo +nightly fuzz run seal_attest` (seeds: `fuzz/corpus/seal_attest/`).
#![no_main]

use libfuzzer_sys::fuzz_target;

#[path = "../harness/seal_attest.rs"]
mod harness;

fuzz_target!(|data: &[u8]| {
    harness::run(data);
});
