//! libFuzzer target: robodr-deliverd's agentd status, passwd, safety-recording and rules parsers.
//!
//! The harness (input format, invariants) is `fuzz/harness/deliverd_inputs.rs`, shared
//! via `#[path]` with the std-only smoke test
//! `crates/robodr-deliverd/tests/fuzz_smoke.rs`, so the two cannot drift.
//!
//! Run: `cargo +nightly fuzz run deliverd_inputs` (seeds: `fuzz/corpus/deliverd_inputs/`).
#![no_main]

use libfuzzer_sys::fuzz_target;

#[path = "../harness/deliverd_inputs.rs"]
mod harness;

fuzz_target!(|data: &[u8]| {
    harness::run(data);
});
