//! libFuzzer target: the agentd-executor protocol (envelopes, messages, line reader,
//! key file).
//!
//! The harness (input format, invariants) is `fuzz/harness/executor_proto.rs`; its std-only
//! smoke test is `crates/robodr-executor/tests/fuzz_smoke.rs`.
//!
//! Run: `cargo +nightly fuzz run executor_proto` (seeds: `fuzz/corpus/executor_proto/`).
#![no_main]

use libfuzzer_sys::fuzz_target;

#[path = "../harness/executor_proto.rs"]
mod harness;

fuzz_target!(|data: &[u8]| {
    harness::run(data);
});
