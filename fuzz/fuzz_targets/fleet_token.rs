//! libFuzzer target: see `fuzz/harness/fleet_token.rs` (input format, invariants),
//! shared via `#[path]` with the std-only smoke test
//! `crates/robodr-fleet/tests/fuzz_smoke.rs`, so the two cannot drift.
//!
//! Run: `cargo +nightly fuzz run fleet_token` (seeds: `fuzz/corpus/fleet_token/`).
#![no_main]

use libfuzzer_sys::fuzz_target;

#[path = "../harness/fleet_token.rs"]
mod harness;

fuzz_target!(|data: &[u8]| {
    harness::run(data);
});
