//! libFuzzer target: a whole diode batch through the high-side importer.
//!
//! The harness (input format, invariants) is `fuzz/harness/diode_import.rs`, shared
//! via `#[path]` with the std-only smoke test
//! `crates/robodr-diode/tests/fuzz_smoke.rs`, so the two cannot drift.
//!
//! Run: `cargo +nightly fuzz run diode_import` (seeds: `fuzz/corpus/diode_import/`).
#![no_main]

use libfuzzer_sys::fuzz_target;

#[path = "../harness/diode_import.rs"]
mod harness;

fuzz_target!(|data: &[u8]| {
    harness::run(data);
});
