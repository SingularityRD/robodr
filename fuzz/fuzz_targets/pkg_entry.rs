//! libFuzzer target: see the harness `fuzz/harness/pkg_entry.rs` (input format,
//! invariants), shared via `#[path]` with the std-only smoke test of its
//! crate, so the two cannot drift.
//!
//! Run: `cargo +nightly fuzz run pkg_entry` (seeds: `fuzz/corpus/pkg_entry/`).
#![no_main]

use libfuzzer_sys::fuzz_target;

#[path = "../harness/pkg_entry.rs"]
mod harness;

fuzz_target!(|data: &[u8]| {
    harness::run(data);
});
