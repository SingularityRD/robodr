//! libFuzzer target: the Go2 WebRTC session parsers and monitor
//! (`robodr-ros2-pipeline`, `webrtc`).
//!
//! The harness (input format, invariants) is
//! `fuzz/harness/unitree_webrtc.rs`, shared via `#[path]` with the
//! std-only smoke test `crates/robodr-ros2-pipeline/tests/fuzz_smoke_webrtc.rs`.
//!
//! Run: `cargo +nightly fuzz run unitree_webrtc` (seeds:
//! `fuzz/corpus/unitree_webrtc/`).
#![no_main]

use libfuzzer_sys::fuzz_target;

#[path = "../harness/unitree_webrtc.rs"]
mod harness;

fuzz_target!(|data: &[u8]| {
    harness::run(data);
});
