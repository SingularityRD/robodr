//! # robodr-ocsf
//!
//! Maps RoboDR [`Deviation`](robodr_events::Deviation)s to **OCSF Detection
//! Findings** wrapped in the AutoSecOps ingestion envelope, for the
//! `robot-edr.findings` Kafka topic (design doc, *AI SOC entegrasyonu*).
//!
//! * [`model`] — typed, serde-derived wire structs ([`FindingEnvelope`]).
//! * [`builder`] — [`FindingBuilder::from_deviation`], deterministic ids,
//!   trusted rule catalog, severity mapping.
//! * [`taint`] — SR-TAINT: neutralising attacker-controlled ROS/DDS strings
//!   before they reach an LLM-based SOC.
//! * [`validate`](mod@validate) — strict validator for outgoing and replayed findings.
//! * [`kafka`] — record key, headers, partitioning by robot id.
//! * [`hash`] — std-only SHA-256 and Kafka murmur2 (vector-tested).
//!
//! The crate is pure: no I/O, no clock, no network. Given the same inputs it
//! produces byte-identical JSON. The JSON Schema in
//! `docs/contracts/robot-edr-finding.schema.json` and the example in
//! `docs/contracts/robot-edr-finding.example.json` are checked against the
//! builder's output by the integration tests.
//!
//! Protective scope: a finding *describes* a deviation. Nothing here commands
//! the robot; AutoSecOps actions go to the control plane and the on-robot agent
//! has the final say (design doc: "AI SOC robota hiçbir zaman doğrudan hareket
//! komutu göndermez").

pub mod builder;
pub mod hash;
pub mod kafka;
pub mod model;
pub mod taint;
pub mod validate;

pub use builder::{
    effective_mode, finding_uid, ocsf_severity_id, ocsf_severity_name, rule_info, FindingBuilder,
    RobotContext, RuleInfo, Subject,
};
pub use kafka::{dedup_key, headers, partition_for, record, record_key, to_json, Record};
pub use model::*;
pub use taint::{Charset, Provenance, Tainted, TAINT_LABEL};
pub use validate::{parse_and_validate, validate, validate_for_emit, ValidationError};
