//! # robodr-export
//!
//! The two missing hops of the findings path (`robodr.findings` contract,
//! `docs/contracts/robodr.findings.md`):
//!
//! ```text
//!  robot (air-gapped)                                     SOC
//!  agentd spool ──► spool_export ──► diode outbox ══ diode ══► importer out/ ──► publish ──► Kafka
//!  ready/ → acked/   (robodr-spool-export)                         (robodr-kafka-publish)
//!                                                connected site: agentd spool ──► publish ──┘
//! ```
//!
//! * [`spool_export`] (robot side): agentd's spool `ready/` files, in order,
//!   into `robodr_diode::Packer` batches; records are renamed into `acked/`
//!   only after their batch is durably published. Crash-safe and idempotent
//!   on restart via an intent journal (see the module docs).
//! * [`publish`] (SOC side): the importer's `out/<batch>/records.jsonl` (or
//!   a connected site's spool) to Kafka, with the contract's key, partition
//!   rule and headers; per-batch committed offsets persisted atomically,
//!   together with the idempotent producer's id, sequences and in-flight
//!   journal, so a chunk re-sent after a crash is deduplicated by the
//!   broker.
//! * [`uplink`] (robot / sensor box, or SOC side): the same inputs to the
//!   AutoSecOps ingest API (`docs/contracts/robodr.ingest-api.md`): signed
//!   NDJSON batches over TLS (rustls, ring), batch ids derived from the
//!   input position and the body, the batch in flight persisted, records
//!   acknowledged only after a `200` names them.
//! * [`kafka`]: a minimal in-crate Kafka producer (ApiVersions, Metadata,
//!   Produce v3+ with RecordBatch v2 and CRC-32C ([`crc32c`]), `acks=all`,
//!   no compression, idempotent by default: InitProducerId and sequence
//!   numbers) over **TLS** (rustls, ring; plain TCP only when explicitly
//!   allowed), optional mutual TLS and SASL/SCRAM.
//! * [`retention`]: bounded retention of `done/` markers, rotated
//!   dead-letter files and rejected spool records, never deleting what is
//!   still needed.
//!
//! Honest limits (details in README): the Kafka client is tested against
//! an in-process fake broker and single-node real brokers only; with
//! idempotence off (brokers without the ACL) delivery is at-least-once, and
//! consumers dedupe on `event-uid` in any case.

// S10: `unsafe` is denied crate-wide; each item that needs it (FFI to libc
// symbols std already links) carries a local `#[allow(unsafe_code)]` and a
// `// SAFETY:` comment on every block.
#![deny(unsafe_code)]
#![deny(unsafe_op_in_unsafe_fn)]
#![warn(clippy::undocumented_unsafe_blocks)]
// Review L3 (S10, R9): the robodr-uplink daemon and robodr-enroll (through
// robodr-fleet) link this library and release builds use
// `panic = "abort"`, so a panic here kills the process. Non-test code has
// no unwrap / expect / panic!-family call and no unchecked indexing;
// arithmetic is left to review and fuzzing.
#![cfg_attr(
    not(test),
    deny(
        clippy::indexing_slicing,
        clippy::unwrap_used,
        clippy::expect_used,
        clippy::panic,
        clippy::unreachable,
        clippy::todo,
        clippy::unimplemented
    )
)]

pub mod crc32c;
pub mod deadletter;
mod fsutil;
pub mod kafka;
pub mod publish;
pub mod retention;
pub mod spool_export;
pub mod uplink;

pub use fsutil::now_ms;
pub use publish::{PublishConfig, PublishError, PublishReport, Publisher, Sink, Source};
pub use spool_export::{ExportConfig, ExportError, ExportReport, Exporter};
pub use uplink::{Uplink, UplinkConfig, UplinkError, UplinkReport};
