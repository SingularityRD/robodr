//! libFuzzer target: Kafka wire decoders (ApiVersions / Metadata / Produce, RecordBatch v2).
//!
//! The harness (input format, invariants) is `fuzz/harness/kafka_wire.rs`. It has no
//! std-only smoke test (see the harness docs): it runs under libFuzzer only.
//!
//! Run: `cargo +nightly fuzz run kafka_wire` (seeds: `fuzz/corpus/kafka_wire/`).
#![no_main]

use libfuzzer_sys::fuzz_target;

#[path = "../harness/kafka_wire.rs"]
mod harness;

fuzz_target!(|data: &[u8]| {
    harness::run(data);
});
