//! A minimal std-only Kafka producer: just enough of the protocol to
//! publish findings records with `acks=all`, idempotent by default.
//!
//! * [`wire`]: primitive types and zig-zag varints.
//! * [`batch`]: RecordBatch v2 encoding (CRC-32C, headers, no compression;
//!   producer id, epoch and base sequence for idempotence).
//! * [`proto`]: ApiVersions v0, Metadata v1–8, Produce v3–8, InitProducerId
//!   v0–1.
//! * [`sasl`]: SASL/SCRAM-SHA-256 / -512 (SaslHandshake v1, SaslAuthenticate
//!   v0–v1), over TLS only.
//! * [`errors`]: error-code classification (retriable / record / sequence /
//!   fatal).
//! * [`client`]: [`Producer`]: connections, version negotiation, metadata,
//!   leader routing, retries with backoff, timeouts and size bounds, and the
//!   idempotent producer (sequence numbers, resets, a restart journal).
//!
//! CI tests it against the in-process fake broker in `tests/`, which
//! implements these APIs from the protocol documentation (and enforces the
//! idempotent producer's sequence numbers);
//! `tests/kafka_real_broker.rs` (`#[ignore]`d, run by `scripts/kafka-it.sh`)
//! runs it against a real single-node Apache Kafka broker (verified with
//! 3.9.1 and 4.1.0). See the crate README for the full list of limits.

pub mod batch;
pub mod client;
pub mod errors;
pub mod proto;
pub mod sasl;
pub mod wire;

pub use batch::{decode_batches, encode_batch, encode_batch_idempotent, ProduceRecord};
pub use client::{
    IdempotentState, JournalBatch, Outcome, PersistFn, ProduceError, Producer, ProducerConfig,
    ProducerStats, SendJournal,
};
