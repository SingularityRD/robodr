//! libFuzzer target: `robodr_rtps::secured_prefix::prefix_matches_subject`
//! (the certificate subject parser and DER rebuild behind the SPDP
//! identity check).
//!
//! The harness (invariants) is `fuzz/harness/rtps_secured_prefix.rs`,
//! shared via `#[path]` with the std-only smoke test
//! `crates/robodr-rtps/tests/fuzz_smoke_secured_prefix.rs`.
//!
//! Run: `cargo +nightly fuzz run rtps_secured_prefix` (seeds:
//! `fuzz/corpus/rtps_secured_prefix/`).
#![no_main]

use libfuzzer_sys::fuzz_target;

#[path = "../harness/rtps_secured_prefix.rs"]
mod harness;

fuzz_target!(|data: &[u8]| {
    harness::run(data);
});
