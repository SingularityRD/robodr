//! # robodr-ocsf
//!
//! Maps RoboDR [`Deviation`](robodr_events::Deviation)s to **OCSF Detection
//! Findings** wrapped in the vendor-neutral `robodr.findings` envelope
//! (contract 2.x, `docs/contracts/robodr.findings.md`): what the robot sends
//! a SOC or SIEM is correlated findings with links to black-box evidence,
//! not raw telemetry. Contract 1.x (`robot-edr.findings`) messages are still
//! parsed and validated, never emitted.
//!
//! * [`model`] — typed, serde-derived wire structs ([`FindingEnvelope`]).
//! * [`builder`] — [`FindingBuilder::from_deviation`], deterministic ids,
//!   trusted rule catalog, severity mapping.
//! * [`taint`] — SR-TAINT: neutralising attacker-controlled ROS/DDS strings
//!   before they reach an LLM-based SOC.
//! * [`validate`](mod@validate) — strict validator for outgoing and replayed findings.
//! * [`kafka`] — record key, headers, partitioning by robot id.
//! * [`hash`] — std-only SHA-256 and Kafka murmur2 (vector-tested).
//! * [`sig`] — detached per-finding Ed25519 signatures (contract 1.2):
//!   signed bytes = the exact record value; carried in the
//!   `robodr-finding-sig` header; [`parse_and_validate_signed`] binds the
//!   key to the unit the finding names.
//!
//! The crate is pure: no I/O, no clock, no network (signing goes through the
//! `robodr-blackbox` [`Signer`](robodr_blackbox::Signer) /
//! [`Verifier`](robodr_blackbox::Verifier) traits). Given the same inputs it
//! produces byte-identical JSON. The JSON Schema in
//! `docs/contracts/robodr-finding.schema.json` and the example in
//! `docs/contracts/robodr-finding.example.json` are checked against the
//! builder's output by the integration tests.
//!
//! Protective scope: a finding *describes* a deviation. Nothing here commands
//! the robot. A SOC never sends a motion command to a robot: approved actions
//! go to the control plane and the on-robot agent has the final say.

pub mod builder;
pub mod hash;
pub mod kafka;
pub mod model;
pub mod sig;
pub mod taint;
pub mod upgrade;
pub mod validate;

pub use builder::{
    effective_mode, finding_uid, ocsf_severity_id, ocsf_severity_name, rule_info,
    rule_info_for_contract, FindingBuilder, RobotContext, RuleInfo, Subject,
};
pub use kafka::{dedup_key, headers, partition_for, record, record_key, to_json, Record};
pub use model::*;
pub use sig::{
    parse_and_validate_signed, record_signed, sign_record, sign_value, signature_header,
    verify_record, FindingSignature, ReplayKey, SignatureError, SignaturePolicy, SignatureStatus,
    VerifiedFinding, VerifierByUnit, SIG_HEADER,
};
pub use taint::{Charset, Provenance, Tainted, TAINT_LABEL};
pub use upgrade::{
    upgrade_legacy, upgrade_legacy_json, UpgradeError, LEGACY_SIGNED_REASON, UPGRADE_TARGET_VERSION,
};
pub use validate::{parse_and_validate, validate, validate_for_emit, ValidationError};
