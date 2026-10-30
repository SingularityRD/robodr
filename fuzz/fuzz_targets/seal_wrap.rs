//! libFuzzer target: see the harness `fuzz/harness/seal_wrap.rs` (input format,
//! invariants), shared via `#[path]` with the std-only smoke test
//! `crates/robodr-seal/tests/fuzz_smoke.rs`, so the two cannot drift.
//!
//! Run: `cargo +nightly fuzz run seal_wrap` (seeds: `fuzz/corpus/seal_wrap/`).
#![no_main]

use libfuzzer_sys::fuzz_target;

#[path = "../harness/seal_wrap.rs"]
mod harness;

fuzz_target!(|data: &[u8]| {
    harness::run(data);
});
