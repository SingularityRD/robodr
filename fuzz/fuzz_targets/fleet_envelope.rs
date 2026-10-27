//! libFuzzer target: see `fuzz/harness/fleet_envelope.rs` (input format, invariants),
//! shared via `#[path]` with the std-only smoke test
//! `crates/robodr-fleet/tests/fuzz_smoke.rs`, so the two cannot drift.
//!
//! Run: `cargo +nightly fuzz run fleet_envelope` (seeds: `fuzz/corpus/fleet_envelope/`).
#![no_main]

use libfuzzer_sys::fuzz_target;

#[path = "../harness/fleet_envelope.rs"]
mod harness;

fuzz_target!(|data: &[u8]| {
    harness::run(data);
});
