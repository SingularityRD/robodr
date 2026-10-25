//! Typed wire model of one `robodr.findings` message (contract 2.x).
//!
//! A message is a [`FindingEnvelope`]: a vendor-neutral envelope with the
//! fields any SOC or SIEM needs to ingest, deduplicate and triage a finding
//! (`finding_id`, `external_id`, `data_source`, `title`, `description`,
//! `severity`, `timestamp`, `entity_context`, `mitre_predictions`,
//! `evidence_links`, `anomaly_score`, `adversary_controlled_fields`), plus
//! the full **OCSF Detection Finding** (class_uid 2004, category_uid 2
//! "Findings") under `ocsf`, so the same object can be forwarded verbatim to
//! any OCSF-capable SIEM/SOAR or syslog path.
//!
//! `data_source` (default [`DEFAULT_DATA_SOURCE`]) and the topic named in
//! `ocsf.metadata.log_name` (default [`DEFAULT_TOPIC`]) are deployment
//! configuration. Contract 1.x messages (fixed `data_source` and topic, see
//! [`legacy_v1`]) are still parsed and validated, never emitted.
//!
//! Every struct derives `Serialize`/`Deserialize`. Field order is declaration
//! order, there are no hash maps, and the builder sorts every list whose
//! order is not semantically fixed, so serialisation is byte-for-byte
//! deterministic for the same input (`serde_json` prints `f64` with the
//! shortest round-trip representation, which is also deterministic).
//!
//! OCSF fields this crate is *not certain* exist with exactly this name/shape
//! in the targeted OCSF version are marked `OCSF-UNCERTAIN` in their docs and
//! listed in the crate README.

use crate::taint::Tainted;
use robodr_events::Severity;
use serde::{Deserialize, Serialize};

/// Contract name: the schema `$id` is
/// `https://schemas.singularityrd.com/robodr/findings/<version>`.
pub const CONTRACT_NAME: &str = "robodr.findings";
/// Contract (envelope) schema version emitted, semver. See
/// `docs/contracts/robodr.findings.md`.
pub const CONTRACT_VERSION: &str = "2.0.0";
/// Contract major emitted and validated in full.
pub const CONTRACT_MAJOR: u64 = 2;
/// Older contract major still accepted on parse (replay, migration), never
/// emitted.
pub const LEGACY_CONTRACT_MAJOR: u64 = 1;
/// OCSF schema version written to `metadata.version`. Detection Finding
/// (2004) was introduced in OCSF 1.1.0.
pub const OCSF_VERSION: &str = "1.1.0";
/// Default topic (Kafka topic, and `ocsf.metadata.log_name`). Configurable
/// per deployment ([`crate::RobotContext::topic`]); any name matching
/// [`crate::validate::is_valid_topic`] is accepted.
pub const DEFAULT_TOPIC: &str = "robodr.findings";
/// Default `data_source` (with `external_id` the consumer's dedup key).
/// Configurable per deployment ([`crate::RobotContext::data_source`]); any
/// name matching [`crate::validate::is_valid_data_source`] is accepted.
pub const DEFAULT_DATA_SOURCE: &str = "robodr";

/// Constants of contract 1.x (`robot-edr.findings`), which fixed both
/// values. Used only to validate 1.x messages on parse.
pub mod legacy_v1 {
    /// The 1.x topic and `ocsf.metadata.log_name`.
    pub const TOPIC: &str = "robot-edr.findings";
    /// The 1.x `data_source`.
    pub const DATA_SOURCE: &str = "robot_edr";
}
/// `metadata.product.name`.
pub const PRODUCT_NAME: &str = "RoboDR";
/// `metadata.product.vendor_name`.
pub const VENDOR_NAME: &str = "Singularity RD";

/// OCSF class/category constants for Detection Finding.
pub mod ocsf_ids {
    pub const CATEGORY_UID: u32 = 2;
    pub const CATEGORY_NAME: &str = "Findings";
    pub const CLASS_UID: u32 = 2004;
    pub const CLASS_NAME: &str = "Detection Finding";
}

/// One findings message (contract [`CONTRACT_NAME`]).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct FindingEnvelope {
    /// [`CONTRACT_VERSION`] of the producer.
    pub contract_version: String,
    /// Finding id; equals `ocsf.finding_info.uid` and the Kafka record key.
    pub finding_id: String,
    /// `<robot_id>:<finding_id>`; with `data_source` the consumer's dedup
    /// key.
    pub external_id: String,
    /// Producer label, default [`DEFAULT_DATA_SOURCE`] (configurable;
    /// [`legacy_v1::DATA_SOURCE`] in contract 1.x).
    pub data_source: String,
    /// Rule title from the trusted rule catalog. Never contains tainted text.
    pub title: String,
    /// Built from trusted templates + sensor-authored facts only.
    pub description: String,
    /// RoboDR severity, lower-case (`low|medium|high|critical`).
    pub severity: Severity,
    /// RFC 3339 UTC with millisecond precision, = `ocsf.time`.
    pub timestamp: String,
    /// Robot context for triage. Sensor-authored except [`Tainted`] values.
    pub entity_context: EntityContext,
    /// ATT&CK for ICS techniques, authored by the sensor's rule catalog.
    pub mitre_predictions: Vec<MitrePrediction>,
    /// Links to black-box evidence records (see [`BlackBoxRef::uri`]).
    pub evidence_links: Vec<String>,
    /// Anomaly-model score in `[0, 1]`, when a model produced the finding.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub anomaly_score: Option<f64>,
    /// JSON Pointers (RFC 6901) of every attacker-controlled value in this
    /// message. Recomputed and checked by the validator.
    pub adversary_controlled_fields: Vec<String>,
    /// The OCSF Detection Finding.
    pub ocsf: DetectionFinding,
}

/// ATT&CK for ICS technique attached by the rule catalog.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MitrePrediction {
    /// e.g. `T0855`.
    pub technique_id: String,
    /// e.g. `Unauthorized Command Message`.
    pub technique_name: String,
    /// Always `attack_ics`.
    pub framework: String,
    /// Always `sensor`: written by RoboDR's rule catalog, not a third party.
    pub provenance: crate::taint::Provenance,
}

/// Observe (profile not locked: report only) vs enforce (locked profile,
/// response allowed per Cyber-Jidoka).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Mode {
    Observe,
    Enforce,
}

/// Robot motion state at detection time.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum MotionState {
    Moving,
    Stationary,
    Unknown,
}

/// Whether a human was detected near the robot at detection time.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum HumanProximity {
    Detected,
    NotDetected,
    Unknown,
}

/// Safety state at detection: is the robot moving or stopped, is a human
/// nearby. Sensor-authored.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct SafetyState {
    pub motion: MotionState,
    pub human_proximity: HumanProximity,
}

impl SafetyState {
    pub const UNKNOWN: Self = Self {
        motion: MotionState::Unknown,
        human_proximity: HumanProximity::Unknown,
    };
}

/// Attestation status as the control plane reports it (verified /
/// deviation / unknown).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AttestationStatus {
    Verified,
    Deviation,
    Unknown,
}

/// Robot computing-platform family: how RoboDR is deployed on the robot
/// (agent, SDK, appliance, bus tap), not the robot's form factor.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PlatformFamily {
    /// Linux + ROS 2 (Full Agent).
    LinuxRos2,
    /// RTOS / microcontroller (Lite SDK).
    Rtos,
    /// Closed industrial controller (Sentinel Box).
    ClosedController,
    /// Field bus only (Bus Tap).
    Fieldbus,
    Other,
}

/// Static identity of the robot.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RobotInfo {
    /// Fleet-unique robot id, `[A-Za-z0-9._-]{1,64}`.
    pub id: String,
    /// Robot model label, e.g. `ugv-tracked-v1`.
    pub model: String,
    pub platform_family: PlatformFamily,
    /// Site / deployment label.
    pub site: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub firmware: Option<FirmwareRef>,
}

/// Firmware version and measured hash.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FirmwareRef {
    pub version: String,
    /// SHA-256, lower-case hex.
    pub sha256: String,
}

/// The locked model profile the deviation was evaluated against.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProfileRef {
    pub version: String,
    /// SHA-256 of the canonical profile artifact, lower-case hex.
    pub sha256: String,
}

/// ROS 2 / DDS identifiers involved. **All attacker-controlled.**
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct RosContext {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub participant_guid: Option<Tainted>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub node: Option<Tainted>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub topic: Option<Tainted>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub type_name: Option<Tainted>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub src_ip: Option<Tainted>,
}

/// Commanded value and the permitted envelope (motion deviations).
/// Numeric values are sensor-measured; the channel name is tainted.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct CommandContext {
    pub channel: Tainted,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub linear_speed: Option<f64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub joint_speed: Option<f64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub envelope_max_linear_speed: Option<f64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub envelope_max_joint_speed: Option<f64>,
}

/// Robot context for triage, also embedded as `ocsf.unmapped.robodr`.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct EntityContext {
    pub robot: RobotInfo,
    pub profile: ProfileRef,
    /// Stable rule id, e.g. `robot.ros2.unknown_participant`.
    pub rule_id: String,
    pub mode: Mode,
    pub safety_state: SafetyState,
    pub attestation: AttestationStatus,
    pub ros: RosContext,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub command: Option<CommandContext>,
    /// Field-bus message id (CAN id etc.), sensor-observed.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub bus_message_id: Option<u32>,
    /// How many times this (robot, rule, subject) was seen up to `last_seen`.
    pub occurrence_count: u64,
    /// The deviation's raw detail line. It interpolates attacker-chosen names,
    /// so it is carried only as tainted data.
    pub detail: Tainted,
}

/// A reference to one record in the signed, hash-chained black box.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct BlackBoxRef {
    /// Black-box segment number.
    pub segment: u64,
    /// Record sequence number within the chain.
    pub seq: u64,
    /// SHA-256 of the record (chain hash), lower-case hex.
    pub sha256: String,
}

impl BlackBoxRef {
    /// `robodr-blackbox://<robot_id>/<segment>/<seq>?sha256=<hex>`.
    pub fn uri(&self, robot_id: &str) -> String {
        format!(
            "robodr-blackbox://{}/{}/{}?sha256={}",
            robot_id, self.segment, self.seq, self.sha256
        )
    }
}

// ---------------------------------------------------------------- OCSF -----

/// OCSF 1.x Detection Finding (class_uid 2004).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct DetectionFinding {
    /// 1 Create (first occurrence), 2 Update (repeat), 3 Close.
    pub activity_id: u8,
    pub activity_name: String,
    pub category_uid: u32,
    pub category_name: String,
    pub class_uid: u32,
    pub class_name: String,
    /// `class_uid * 100 + activity_id`.
    pub type_uid: u32,
    pub type_name: String,
    /// OCSF: 0 Unknown, 1 Informational, 2 Low, 3 Medium, 4 High, 5 Critical,
    /// 6 Fatal, 99 Other. RoboDR emits 2..=5 only.
    pub severity_id: u8,
    pub severity: String,
    /// Finding status: 1 New (others are for the SOC to set).
    /// OCSF-UNCERTAIN: enum values per Detection Finding 1.1 (0 Unknown, 1 New,
    /// 2 In Progress, 3 Suppressed, 4 Resolved, 99 Other).
    pub status_id: u8,
    pub status: String,
    /// Event time, ms since the Unix epoch (= `finding_info.last_seen_time`).
    pub time: u64,
    /// Same as `title`; trusted text only.
    pub message: String,
    /// Number of occurrences aggregated into this event (base attribute `count`).
    pub count: u64,
    pub metadata: Metadata,
    pub finding_info: FindingInfo,
    pub device: Device,
    /// Black-box evidence. OCSF-UNCERTAIN: the `evidences[]` object ("Evidence
    /// Artifacts") is used only through its free-form `data` attribute.
    pub evidences: Vec<Evidence>,
    /// ROS/DDS resources involved; `uid`/`name` are tainted (see `labels`).
    pub resources: Vec<Resource>,
    /// Robot-specific data that has no OCSF attribute.
    pub unmapped: Unmapped,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Metadata {
    /// OCSF schema version, [`OCSF_VERSION`].
    pub version: String,
    pub product: Product,
    /// Per-emission event uid (finding uid + last_seen + count), deterministic.
    pub uid: String,
    /// The topic the producer published on (default [`DEFAULT_TOPIC`];
    /// [`legacy_v1::TOPIC`] in 1.x). OCSF-UNCERTAIN only in semantics.
    pub log_name: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Product {
    pub name: String,
    pub vendor_name: String,
    pub version: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FindingInfo {
    /// Deterministic: hash(robot id, rule id, subject). See `builder`.
    pub uid: String,
    pub title: String,
    pub desc: String,
    pub types: Vec<String>,
    /// ms since epoch.
    pub first_seen_time: u64,
    /// ms since epoch.
    pub last_seen_time: u64,
    pub analytic: Analytic,
    /// ATT&CK for ICS. OCSF-UNCERTAIN: `attacks[]` is modelled on ATT&CK
    /// Enterprise; we fill only `technique.{uid,name}`.
    pub attacks: Vec<Attack>,
    pub data_sources: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Analytic {
    /// The rule id.
    pub uid: String,
    pub name: String,
    /// 1 Rule.
    pub type_id: u8,
    #[serde(rename = "type")]
    pub type_: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Attack {
    pub technique: Technique,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Technique {
    pub uid: String,
    pub name: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Device {
    /// Robot id.
    pub uid: String,
    pub name: String,
    /// 99 Other (OCSF has no robot device type).
    pub type_id: u8,
    #[serde(rename = "type")]
    pub type_: String,
    /// Robot model. OCSF-UNCERTAIN: `device.model` attribute name/version.
    pub model: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Evidence {
    pub data: EvidenceData,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EvidenceData {
    /// Always `robodr.blackbox`.
    pub kind: String,
    pub segment: u64,
    pub seq: u64,
    pub sha256: String,
    pub uri: String,
}

/// OCSF `resource_details`. OCSF-UNCERTAIN: `labels` on resource_details.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Resource {
    /// `ros2.participant` | `ros2.node` | `ros2.topic` | `ip_address`.
    #[serde(rename = "type")]
    pub type_: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub uid: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    /// Contains [`crate::taint::TAINT_LABEL`] for attacker-controlled values.
    pub labels: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Unmapped {
    pub robodr: EntityContext,
}
