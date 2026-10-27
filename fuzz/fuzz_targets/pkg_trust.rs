//! libFuzzer target: see the harness `fuzz/harness/pkg_trust.rs` (input format,
//! invariants), shared via `#[path]` with the std-only smoke test
//! `crates/robodr-pkg/tests/fuzz_smoke.rs`, so the two cannot drift.
//!
//! Run: `cargo +nightly fuzz run pkg_trust` (seeds: `fuzz/corpus/pkg_trust/`).
#![no_main]

use libfuzzer_sys::fuzz_target;

#[path = "../harness/pkg_trust.rs"]
mod harness;

fuzz_target!(|data: &[u8]| {
    harness::run(data);
});
