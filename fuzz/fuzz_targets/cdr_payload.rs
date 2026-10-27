//! libFuzzer target: every robodr-cdr decoder (all message kinds, std_msgs, registry) on one payload.
//!
//! The harness (input format, invariants) is `fuzz/harness/cdr_payload.rs`, shared
//! via `#[path]` with the std-only smoke test
//! `crates/robodr-cdr/tests/fuzz_smoke.rs`, so the two cannot drift.
//!
//! Run: `cargo +nightly fuzz run cdr_payload` (seeds: `fuzz/corpus/cdr_payload/`).
#![no_main]

use libfuzzer_sys::fuzz_target;

#[path = "../harness/cdr_payload.rs"]
mod harness;

fuzz_target!(|data: &[u8]| {
    harness::run(data);
});
