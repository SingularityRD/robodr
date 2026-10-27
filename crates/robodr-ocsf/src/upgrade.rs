//! Upgrade of legacy contract 1.x findings (`robot-edr.findings`) to the
//! current contract major, for findings still in flight (agentd spool,
//! exporter outbox, diode batches, importer output) when a site upgrades.
//!
//! # What changes, and why it is safe
//!
//! Contract 2.0 changed only the envelope labels (see
//! `docs/contracts/robodr.findings.md` §5): `data_source` (1.x constant
//! `robot_edr`) and the topic in `ocsf.metadata.log_name` (1.x constant
//! `robot-edr.findings`) became deployment labels, and `contract_version`
//! moved to 2.x. None of the three is an input of a finding's identity:
//! `finding_id` (`rf1-`) is derived from `(robot id, rule id, subject)` and
//! `ocsf.metadata.uid` (`re1-`) from `(finding id, last_seen_time, count)`
//! ([`crate::finding_uid`], [`crate::builder::event_uid`]). So an upgraded
//! finding keeps its identity and dedups with any copy of itself.
//!
//! The upgraded finding is labelled contract **2.0.0** — not the current
//! minor — because the 2.0 rule catalog is exactly the 1.3 catalog: a 1.3
//! finding carries the 1.3 catalog constants, which are the 2.0 ones. Every
//! upgraded finding is validated in full under the 2.0 rules before it is
//! returned; a 1.x finding that is not also a valid 2.0 finding (e.g. a 1.2
//! finding with the generic entry for a rule that gained an entry in 1.3)
//! is refused ([`UpgradeError::NotConvertible`]), never patched.
//!
//! # Signed findings are never upgraded
//!
//! A per-finding signature (contract §2a) covers the exact value bytes; an
//! upgraded value no longer matches it, and re-signing needs the robot's
//! finding key, which the SOC side does not hold. Callers must therefore
//! not upgrade a record that carries a `robodr-finding-sig` header: they
//! keep it with the reason [`LEGACY_SIGNED_REASON`] (re-sign it on the
//! robot, or drain it before the upgrade). Diode batches carry no
//! per-finding signature (the batch is signed and verified by the
//! importer), so their findings may be upgraded at import.

use std::fmt;

use crate::model::{legacy_v1, FindingEnvelope, LEGACY_CONTRACT_MAJOR};
use crate::validate::{contract_major, is_valid_data_source, is_valid_topic, validate};

/// The contract version an upgraded 1.x finding carries.
pub const UPGRADE_TARGET_VERSION: &str = "2.0.0";

/// The reason a signed 1.x record is kept instead of upgraded.
pub const LEGACY_SIGNED_REASON: &str = "legacy 1.x signed record: re-sign required";

/// Why a finding was not upgraded.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum UpgradeError {
    /// Not a contract 1.x finding (nothing to upgrade).
    NotLegacy,
    /// The 1.x finding itself is invalid.
    Invalid(Vec<String>),
    /// Valid 1.x, but its 2.0 form does not validate.
    NotConvertible(Vec<String>),
    /// The target `data_source` or topic is not a valid label.
    BadLabel(&'static str),
}

impl fmt::Display for UpgradeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            UpgradeError::NotLegacy => write!(f, "not a contract 1.x finding"),
            UpgradeError::Invalid(e) => write!(f, "invalid 1.x finding: {}", e.join("; ")),
            UpgradeError::NotConvertible(e) => write!(
                f,
                "legacy 1.x finding cannot be upgraded to contract {UPGRADE_TARGET_VERSION}: {}",
                e.join("; ")
            ),
            UpgradeError::BadLabel(what) => write!(f, "invalid upgrade target {what}"),
        }
    }
}

impl std::error::Error for UpgradeError {}

/// `true` for a well-formed contract 1.x version.
pub fn is_legacy_version(v: &str) -> bool {
    contract_major(v) == Some(LEGACY_CONTRACT_MAJOR)
}

fn first(errs: Vec<crate::ValidationError>) -> Vec<String> {
    errs.iter().take(3).map(ToString::to_string).collect()
}

/// Upgrade an **unsigned** contract 1.x finding to contract
/// [`UPGRADE_TARGET_VERSION`], relabelled with the deployment's
/// `data_source` and `topic` (`ocsf.metadata.log_name`). The input is
/// validated as 1.x and the output as 2.0; identity fields are untouched.
pub fn upgrade_legacy(
    env: &FindingEnvelope,
    data_source: &str,
    topic: &str,
) -> Result<FindingEnvelope, UpgradeError> {
    if !is_legacy_version(&env.contract_version) {
        return Err(UpgradeError::NotLegacy);
    }
    if !is_valid_data_source(data_source) {
        return Err(UpgradeError::BadLabel("data_source"));
    }
    if !is_valid_topic(topic) {
        return Err(UpgradeError::BadLabel("topic"));
    }
    validate(env).map_err(|e| UpgradeError::Invalid(first(e)))?;
    // A valid 1.x finding carries the 1.x constants (the validator checks
    // them); refuse anything else rather than relabel it.
    if env.data_source != legacy_v1::DATA_SOURCE || env.ocsf.metadata.log_name != legacy_v1::TOPIC {
        return Err(UpgradeError::Invalid(vec![
            "1.x finding without the 1.x labels".into(),
        ]));
    }
    let mut up = env.clone();
    up.contract_version = UPGRADE_TARGET_VERSION.to_string();
    up.data_source = data_source.to_string();
    up.ocsf.metadata.log_name = topic.to_string();
    validate(&up).map_err(|e| UpgradeError::NotConvertible(first(e)))?;
    Ok(up)
}

/// [`upgrade_legacy`] for a raw JSON value (parsed and validated with
/// [`crate::parse_and_validate`] first).
pub fn upgrade_legacy_json(
    json: &str,
    data_source: &str,
    topic: &str,
) -> Result<FindingEnvelope, UpgradeError> {
    let env = crate::parse_and_validate(json).map_err(|e| UpgradeError::Invalid(first(e)))?;
    upgrade_legacy(&env, data_source, topic)
}
