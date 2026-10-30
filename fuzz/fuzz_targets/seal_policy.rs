//! libFuzzer target: see the harness `fuzz/harness/seal_policy.rs` (input format,
//! invariants), shared via `#[path]` with the std-only smoke test
//! `crates/robodr-seal/tests/fuzz_smoke.rs`, so the two cannot drift.
//!
//! Run: `cargo +nightly fuzz run seal_policy` (seeds: `fuzz/corpus/seal_policy/`).
#![no_main]

use libfuzzer_sys::fuzz_target;

#[path = "../harness/seal_policy.rs"]
mod harness;

fuzz_target!(|data: &[u8]| {
    harness::run(data);
});
