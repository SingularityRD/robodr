//! libFuzzer target: Motion Firewall policy from profile JSON + `Firewall::check`.
//!
//! The harness (input format, invariants) is `fuzz/harness/firewall_policy.rs`, shared
//! via `#[path]` with the std-only smoke test
//! `crates/robodr-agent/tests/fuzz_smoke.rs`, so the two cannot drift.
//!
//! Run: `cargo +nightly fuzz run firewall_policy` (seeds: `fuzz/corpus/firewall_policy/`).
#![no_main]

use libfuzzer_sys::fuzz_target;

#[path = "../harness/firewall_policy.rs"]
mod harness;

fuzz_target!(|data: &[u8]| {
    harness::run(data);
});
