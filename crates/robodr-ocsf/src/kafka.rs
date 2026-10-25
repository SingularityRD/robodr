//! Kafka record helpers for `robodr.findings` (see the contract,
//! `docs/contracts/robodr.findings.md`).
//!
//! This module does not talk to Kafka (no client crate is available, and the
//! robot side is air-gapped); it fixes the *record shape* so every producer —
//! the agent spool, the diode importer, the publisher, test tooling — agrees.
//! Everything is derived from the validated value: the record topic is the
//! value's `ocsf.metadata.log_name` (the deployment's configured topic,
//! default [`crate::DEFAULT_TOPIC`]) and the `data-source` header is its
//! `data_source`.

use crate::hash::kafka_murmur2;
use crate::model::{FindingEnvelope, CONTRACT_VERSION, OCSF_VERSION};
use crate::validate::{validate_for_emit, ValidationError};

/// Header names, all lower-case ASCII.
pub mod header {
    pub const CONTENT_TYPE: &str = "content-type";
    pub const CONTRACT_VERSION: &str = "robodr-contract-version";
    pub const OCSF_VERSION: &str = "ocsf-version";
    pub const DATA_SOURCE: &str = "data-source";
    pub const ROBOT_ID: &str = "robot-id";
    pub const SEVERITY: &str = "severity";
    pub const EVENT_UID: &str = "event-uid";
    /// Detached finding signature (contract 1.2, optional; see [`crate::sig`]).
    /// Not emitted by [`super::headers`]; added by [`crate::sig::sign_record`].
    pub const FINDING_SIG: &str = crate::sig::SIG_HEADER;
}

/// One ready-to-send record.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Record {
    /// The value's `ocsf.metadata.log_name`.
    pub topic: String,
    /// Explicit partition (by robot id), when the partition count is known.
    pub partition: Option<u32>,
    /// Record key: the finding id.
    pub key: String,
    /// Compact JSON of the validated envelope.
    pub value: String,
    pub headers: Vec<(&'static str, String)>,
}

/// Validate ([`validate_for_emit`]: contract 1.x is never emitted) and
/// serialise to compact, deterministic JSON.
pub fn to_json(env: &FindingEnvelope) -> Result<String, Vec<ValidationError>> {
    validate_for_emit(env)?;
    serde_json::to_string(env).map_err(|e| vec![ValidationError::Parse(e.to_string())])
}

/// Kafka record key: the finding id (stable across repeats of a finding).
pub fn record_key(env: &FindingEnvelope) -> &str {
    &env.finding_id
}

/// Consumer dedup key `(data_source, external_id)`.
pub fn dedup_key(env: &FindingEnvelope) -> (&str, &str) {
    (&env.data_source, &env.external_id)
}

/// Record headers, in a fixed order.
pub fn headers(env: &FindingEnvelope) -> Vec<(&'static str, String)> {
    vec![
        (header::CONTENT_TYPE, "application/json".into()),
        (header::CONTRACT_VERSION, CONTRACT_VERSION.into()),
        (header::OCSF_VERSION, OCSF_VERSION.into()),
        (header::DATA_SOURCE, env.data_source.clone()),
        (header::ROBOT_ID, env.entity_context.robot.id.clone()),
        (
            header::SEVERITY,
            crate::builder::ocsf_severity_name(env.severity).to_ascii_lowercase(),
        ),
        (header::EVENT_UID, env.ocsf.metadata.uid.clone()),
    ]
}

/// Partition for a robot id: Kafka's default `toPositive(murmur2(key)) % n`,
/// applied to the **robot id** (not the record key), so all findings of one
/// robot are totally ordered on one partition. `None` if `partitions == 0`.
pub fn partition_for(robot_id: &str, partitions: u32) -> Option<u32> {
    if partitions == 0 {
        return None;
    }
    let h = (kafka_murmur2(robot_id.as_bytes()) as u32) & 0x7fff_ffff;
    Some(h % partitions)
}

/// Build a complete record. `partitions` = topic partition count, if known.
pub fn record(
    env: &FindingEnvelope,
    partitions: Option<u32>,
) -> Result<Record, Vec<ValidationError>> {
    let value = to_json(env)?;
    Ok(Record {
        topic: env.ocsf.metadata.log_name.clone(),
        partition: partitions.and_then(|n| partition_for(&env.entity_context.robot.id, n)),
        key: record_key(env).to_string(),
        value,
        headers: headers(env),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn partition_is_stable_and_in_range() {
        assert_eq!(partition_for("ugv-007", 0), None);
        for n in [1, 3, 12, 64] {
            let p = partition_for("ugv-007", n).unwrap();
            assert!(p < n);
            assert_eq!(Some(p), partition_for("ugv-007", n));
        }
        // Kafka: toPositive(murmur2("foobar")) % 10, murmur2 = -790332482.
        assert_eq!(
            partition_for("foobar", 10),
            Some(((-790332482i32 as u32) & 0x7fff_ffff) % 10)
        );
    }
}
