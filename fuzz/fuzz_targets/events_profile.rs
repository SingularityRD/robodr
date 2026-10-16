//! libFuzzer target: model-profile JSON parse + `validate` + `evaluate`.
//!
//! The harness (input format, invariants) is `fuzz/harness/events_profile.rs`, shared
//! via `#[path]` with the std-only smoke test
//! `crates/robodr-events/tests/fuzz_smoke.rs`, so the two cannot drift.
//!
//! Run: `cargo +nightly fuzz run events_profile` (seeds: `fuzz/corpus/events_profile/`).
#![no_main]

use libfuzzer_sys::fuzz_target;

#[path = "../harness/events_profile.rs"]
mod harness;

fuzz_target!(|data: &[u8]| {
    harness::run(data);
});
