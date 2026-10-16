//! libFuzzer target: `robodr_ocsf::parse_and_validate`.
//!
//! The harness (input format, invariants) is `fuzz/harness/ocsf_parse_and_validate.rs`, shared
//! via `#[path]` with the std-only smoke test
//! `crates/robodr-ocsf/tests/fuzz_smoke.rs`, so the two cannot drift.
//!
//! Run: `cargo +nightly fuzz run ocsf_parse_and_validate` (seeds: `fuzz/corpus/ocsf_parse_and_validate/`).
#![no_main]

use libfuzzer_sys::fuzz_target;

#[path = "../harness/ocsf_parse_and_validate.rs"]
mod harness;

fuzz_target!(|data: &[u8]| {
    harness::run(data);
});
