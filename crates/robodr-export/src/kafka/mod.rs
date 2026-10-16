//! A minimal std-only Kafka producer: just enough of the protocol to
//! publish `robot-edr.findings` records with `acks=all`.
//!
//! * [`wire`]: primitive types and zig-zag varints.
//! * [`batch`]: RecordBatch v2 encoding (CRC-32C, headers, no compression).
//! * [`proto`]: ApiVersions v0, Metadata v1–8, Produce v3–8.
//! * [`errors`]: error-code classification (retriable / record / fatal).
//! * [`client`]: [`Producer`]: connections, version negotiation, metadata,
//!   leader routing, retries with backoff, timeouts and size bounds.
//!
//! **Not tested against a real Kafka broker** (none is reachable from the
//! build environment): it is tested against the in-process fake broker in
//! `tests/`, which implements these three APIs from the protocol
//! documentation. See the crate README for the full list of limits.

pub mod batch;
pub mod client;
pub mod errors;
pub mod proto;
pub mod wire;

pub use batch::{decode_batches, encode_batch, ProduceRecord};
pub use client::{Outcome, ProduceError, Producer, ProducerConfig, ProducerStats};
