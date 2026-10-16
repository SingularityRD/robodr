//! libFuzzer target: pcap / pcapng reader + capture pipeline (`robodr_capture::CaptureFile`, `rtps_datagrams`).
//!
//! The harness (input format, invariants) is `fuzz/harness/pcap_reader.rs`, shared
//! via `#[path]` with the std-only smoke test
//! `crates/robodr-capture/tests/fuzz_smoke.rs`, so the two cannot drift.
//!
//! Run: `cargo +nightly fuzz run pcap_reader` (seeds: `fuzz/corpus/pcap_reader/`).
#![no_main]

use libfuzzer_sys::fuzz_target;

#[path = "../harness/pcap_reader.rs"]
mod harness;

fuzz_target!(|data: &[u8]| {
    harness::run(data);
});
