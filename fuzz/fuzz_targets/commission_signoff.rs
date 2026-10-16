//! libFuzzer target: operator sign-off JSON + `ops::lock`.
//!
//! The harness (input format, invariants) is `fuzz/harness/commission_signoff.rs`, shared
//! via `#[path]` with the std-only smoke test
//! `crates/robodr-commission/tests/fuzz_smoke.rs`, so the two cannot drift.
//!
//! Run: `cargo +nightly fuzz run commission_signoff` (seeds: `fuzz/corpus/commission_signoff/`).
#![no_main]

use libfuzzer_sys::fuzz_target;

#[path = "../harness/commission_signoff.rs"]
mod harness;

fuzz_target!(|data: &[u8]| {
    harness::run(data);
});
