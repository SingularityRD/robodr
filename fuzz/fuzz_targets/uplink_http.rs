//! libFuzzer target: the uplink HTTP response parser, URL, pin and Retry-After
//! (robodr-uplink).
//!
//! The harness (input format, invariants) is `fuzz/harness/uplink_http.rs`; its std-only
//! smoke test is `crates/robodr-export/tests/fuzz_smoke_uplink.rs`.
//!
//! Run: `cargo +nightly fuzz run uplink_http` (seeds: `fuzz/corpus/uplink_http/`).
#![no_main]

use libfuzzer_sys::fuzz_target;

#[path = "../harness/uplink_http.rs"]
mod harness;

fuzz_target!(|data: &[u8]| {
    harness::run(data);
});
