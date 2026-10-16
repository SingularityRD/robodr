//! libFuzzer target: strict profile file `parse_profile_text` + seal/lock round trip.
//!
//! The harness (input format, invariants) is `fuzz/harness/commission_profile_file.rs`, shared
//! via `#[path]` with the std-only smoke test
//! `crates/robodr-commission/tests/fuzz_smoke.rs`, so the two cannot drift.
//!
//! Run: `cargo +nightly fuzz run commission_profile_file` (seeds: `fuzz/corpus/commission_profile_file/`).
#![no_main]

use libfuzzer_sys::fuzz_target;

#[path = "../harness/commission_profile_file.rs"]
mod harness;

fuzz_target!(|data: &[u8]| {
    harness::run(data);
});
