//! libFuzzer target: robodr-deliverd's configuration and state file parsers.
//!
//! The harness (input format, invariants) is `fuzz/harness/deliverd_state.rs`, shared
//! via `#[path]` with the std-only smoke test
//! `crates/robodr-deliverd/tests/fuzz_smoke.rs`, so the two cannot drift.
//!
//! Run: `cargo +nightly fuzz run deliverd_state` (seeds: `fuzz/corpus/deliverd_state/`).
#![no_main]

use libfuzzer_sys::fuzz_target;

#[path = "../harness/deliverd_state.rs"]
mod harness;

fuzz_target!(|data: &[u8]| {
    harness::run(data);
});
