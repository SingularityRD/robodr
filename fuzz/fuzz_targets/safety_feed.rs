//! libFuzzer target: safety_feed config, safety-socket lines and bus datagrams through the safety feed.
//!
//! The harness (input format, invariants) is `fuzz/harness/safety_feed.rs`, shared
//! via `#[path]` with the std-only smoke test
//! `crates/robodr-agentd/tests/fuzz_smoke.rs`, so the two cannot drift.
//!
//! Run: `cargo +nightly fuzz run safety_feed` (seeds: `fuzz/corpus/safety_feed/`).
#![no_main]

use libfuzzer_sys::fuzz_target;

#[path = "../harness/safety_feed.rs"]
mod harness;

fuzz_target!(|data: &[u8]| {
    harness::run(data);
});
