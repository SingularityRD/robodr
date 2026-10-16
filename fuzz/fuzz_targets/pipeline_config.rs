//! libFuzzer target: sensor `Config` deserialise + `validate_with` + pipeline.
//!
//! The harness (input format, invariants) is `fuzz/harness/pipeline_config.rs`, shared
//! via `#[path]` with the std-only smoke test
//! `crates/robodr-ros2-pipeline/tests/fuzz_smoke.rs`, so the two cannot drift.
//!
//! Run: `cargo +nightly fuzz run pipeline_config` (seeds: `fuzz/corpus/pipeline_config/`).
#![no_main]

use libfuzzer_sys::fuzz_target;

#[path = "../harness/pipeline_config.rs"]
mod harness;

fuzz_target!(|data: &[u8]| {
    harness::run(data);
});
