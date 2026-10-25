//! libFuzzer target: the Unitree decoders in `robodr-cdr`.
//!
//! The harness (input format, invariants) is `fuzz/harness/cdr_unitree.rs`,
//! shared via `#[path]` with the std-only smoke test
//! `crates/robodr-cdr/tests/fuzz_smoke.rs`, so the two cannot drift.
//!
//! Run: `cargo +nightly fuzz run cdr_unitree` (seeds:
//! `fuzz/corpus/cdr_unitree/`).
#![no_main]

use libfuzzer_sys::fuzz_target;

#[path = "../harness/cdr_unitree.rs"]
mod harness;

fuzz_target!(|data: &[u8]| {
    harness::run(data);
});
