//! libFuzzer target: Kafka SASL/SCRAM (server-first, server-final, base64,
//! SaslHandshake / SaslAuthenticate responses).
//!
//! The harness (input format, invariants) is `fuzz/harness/kafka_sasl.rs`; its std-only
//! smoke test is `crates/robodr-export/tests/fuzz_smoke_sasl.rs`.
//!
//! Run: `cargo +nightly fuzz run kafka_sasl` (seeds: `fuzz/corpus/kafka_sasl/`).
#![no_main]

use libfuzzer_sys::fuzz_target;

#[path = "../harness/kafka_sasl.rs"]
mod harness;

fuzz_target!(|data: &[u8]| {
    harness::run(data);
});
