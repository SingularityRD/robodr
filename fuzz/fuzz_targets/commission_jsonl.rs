//! libFuzzer target: JSONL event input + learner + checker.
//!
//! The harness (input format, invariants) is `fuzz/harness/commission_jsonl.rs`, shared
//! via `#[path]` with the std-only smoke test
//! `crates/robodr-commission/tests/fuzz_smoke.rs`, so the two cannot drift.
//!
//! Run: `cargo +nightly fuzz run commission_jsonl` (seeds: `fuzz/corpus/commission_jsonl/`).
#![no_main]

use libfuzzer_sys::fuzz_target;

#[path = "../harness/commission_jsonl.rs"]
mod harness;

fuzz_target!(|data: &[u8]| {
    harness::run(data);
});
