//! A minimal std-only Kafka producer: just enough of the protocol to
//! publish findings records with `acks=all`.
//!
//! * [`wire`]: primitive types and zig-zag varints.
//! * [`batch`]: RecordBatch v2 encoding (CRC-32C, headers, no compression).
//! * [`proto`]: ApiVersions v0, Metadata v1–8, Produce v3–8.
//! * [`errors`]: error-code classification (retriable / record / fatal).
//! * [`client`]: [`Producer`]: connections, version negotiation, metadata,
//!   leader routing, retries with backoff, timeouts and size bounds.
//!
//! CI tests it against the in-process fake broker in `tests/`, which
//! implements these three APIs from the protocol documentation;
//! `tests/kafka_real_broker.rs` (`#[ignore]`d, run by `scripts/kafka-it.sh`)
//! runs it against a real single-node Apache Kafka broker (verified with
//! 3.9.1 and 4.1.0). See the crate README for the full list of limits.

pub mod batch;
pub mod client;
pub mod errors;
pub mod proto;
pub mod wire;

pub use batch::{decode_batches, encode_batch, ProduceRecord};
pub use client::{Outcome, ProduceError, Producer, ProducerConfig, ProducerStats};
