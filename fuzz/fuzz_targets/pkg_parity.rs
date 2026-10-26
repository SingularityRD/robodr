//! libFuzzer target: see the harness `fuzz/harness/pkg_parity.rs` (input format,
//! invariants), shared via `#[path]` with the std-only smoke test
//! `crates/robodr-pkg/tests/fuzz_smoke.rs`, so the two cannot drift.
//!
//! Run: `cargo +nightly fuzz run pkg_parity` (seeds: `fuzz/corpus/pkg_parity/`).
#![no_main]

use libfuzzer_sys::fuzz_target;

#[path = "../harness/pkg_parity.rs"]
mod harness;

fuzz_target!(|data: &[u8]| {
    harness::run(data);
});
