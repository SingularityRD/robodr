//! libFuzzer target: the executor's own check of the SOC approval (orders and reverts,
//! signed requests, replay store).
//!
//! The harness (input format, invariants) is `fuzz/harness/executor_soc.rs`; its std-only
//! smoke test is `crates/robodr-executor/tests/fuzz_smoke.rs`.
//!
//! Run: `cargo +nightly fuzz run executor_soc` (seeds: `fuzz/corpus/executor_soc/`).
#![no_main]

use libfuzzer_sys::fuzz_target;

#[path = "../harness/executor_soc.rs"]
mod harness;

fuzz_target!(|data: &[u8]| {
    harness::run(data);
});
