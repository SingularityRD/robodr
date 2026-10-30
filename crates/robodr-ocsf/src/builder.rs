//! Building a [`FindingEnvelope`] from a [`Deviation`].
//!
//! ```
//! use robodr_events::{Deviation, Severity, graph::Participant, RobotEvent};
//! use robodr_ocsf::*;
//!
//! let ctx = RobotContext::new(
//!     RobotInfo {
//!         id: "ugv-007".into(),
//!         model: "ugv-tracked-v1".into(),
//!         platform_family: PlatformFamily::LinuxRos2,
//!         site: "site-a".into(),
//!         firmware: None,
//!     },
//!     ProfileRef { version: "3".into(), sha256: "ab".repeat(32) },
//!     Mode::Enforce,
//! );
//! let p = Participant { guid_prefix: "0102030405060708090a0b0c".into(),
//!                       src_ip: "10.0.0.66".into(), locators: vec![] };
//! let dev = Deviation::new("robot.ros2.unknown_participant", Severity::High, "unknown participant");
//! let finding = FindingBuilder::from_deviation(&dev, &ctx)
//!     .event(&RobotEvent::Ros2ParticipantDiscovered(p))
//!     .seen(1_790_000_000_000, 1_790_000_000_000)
//!     .build()
//!     .expect("valid finding");
//! assert_eq!(finding.ocsf.severity_id, 4);
//! let json = to_json(&finding).unwrap();
//! assert!(json.contains("\"data_source\":\"robodr\""));
//! ```
//!
//! ## Identity and deduplication
//!
//! * `finding_info.uid` / `finding_id` = `rf1-` + first 128 bits (hex) of
//!   SHA-256 over a length-framed tuple `(robot id, rule id, subject)`, where
//!   the subject is the *raw* (pre-neutralisation) participant GUID, node,
//!   topic, type name and source IP, each marked present/absent. The same
//!   deviation on the same robot about the same subject therefore always maps
//!   to the same finding, across restarts and across producers.
//! * Repeats of the same finding are sent as OCSF activity *Update* (2) with
//!   the same `finding_id`, a larger `count` and a later `last_seen_time`.
//! * `metadata.uid` = `re1-` + hash(finding uid, last_seen, count) identifies
//!   one emission, so a replayed message (e.g. after a diode re-send) is
//!   recognisably the same event.
//! * The consumer's dedup key is `(data_source, external_id)` =
//!   `("robodr", "<robot_id>:<finding_id>")` with the default data source
//!   ([`RobotContext::data_source`]).
//!
//! ## Deployment labels
//!
//! [`RobotContext::data_source`] (default [`DEFAULT_DATA_SOURCE`]) and
//! [`RobotContext::topic`] (default [`DEFAULT_TOPIC`], written to
//! `ocsf.metadata.log_name` and used by [`crate::record`]) are trusted
//! configuration; the builder refuses values the validator would.
//!
//! ## Trusted vs tainted text
//!
//! `title`, `description` and `message` are built **only** from the trusted
//! rule catalog in this module and from sensor-authored context (robot id,
//! model, site, profile version, mode, safety state). `Deviation::detail` is
//! *not* used for narrative text, because the detection core interpolates
//! attacker-chosen names into it; it is carried as a [`Tainted`] value
//! (free-text charset); ROS/DDS identifiers use the stricter ROS-name charset
//! (see [`crate::taint`]).
//!
//! ## Mode
//!
//! `entity_context.mode` (and the `mode` in `description`) is
//! [`effective_mode`]: *observe* if either the robot context or the
//! [`Deviation::mode`] says observe. A consumer must never see `enforce` for a
//! deviation the detection core marked observe-only.

use crate::hash::{framed_sha256, hex};
use crate::model::*;
use crate::taint::{caps, Provenance, Tainted, TAINT_LABEL};
use crate::validate::{self, ValidationError};
use robodr_events::graph::{Endpoint, Participant};
use robodr_events::profile::Envelope;
use robodr_events::{Deviation, MotionCommand, RobotEvent, Severity};

/// Static, sensor-authored context of the robot that produced the deviation.
#[derive(Debug, Clone, PartialEq)]
pub struct RobotContext {
    pub robot: RobotInfo,
    pub profile: ProfileRef,
    pub mode: Mode,
    /// `metadata.product.version`; defaults to this crate's version.
    pub product_version: String,
    /// Envelope `data_source`; defaults to [`DEFAULT_DATA_SOURCE`].
    pub data_source: String,
    /// Topic the finding is published on (`ocsf.metadata.log_name`, the
    /// Kafka record topic); defaults to [`DEFAULT_TOPIC`].
    pub topic: String,
}

impl RobotContext {
    pub fn new(robot: RobotInfo, profile: ProfileRef, mode: Mode) -> Self {
        Self {
            robot,
            profile,
            mode,
            product_version: env!("CARGO_PKG_VERSION").to_string(),
            data_source: DEFAULT_DATA_SOURCE.to_string(),
            topic: DEFAULT_TOPIC.to_string(),
        }
    }
}

/// What the deviation is *about*: raw, attacker-controlled identifiers.
/// Raw values feed the deterministic uid; neutralised copies go on the wire.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Subject {
    pub participant_guid: Option<String>,
    pub node: Option<String>,
    pub topic: Option<String>,
    pub type_name: Option<String>,
    pub src_ip: Option<String>,
}

impl Subject {
    pub fn from_participant(p: &Participant) -> Self {
        Self {
            participant_guid: Some(p.guid_prefix.clone()),
            src_ip: Some(p.src_ip.clone()),
            ..Self::default()
        }
    }

    pub fn from_endpoint(e: &Endpoint) -> Self {
        Self {
            participant_guid: Some(e.guid_prefix.clone()),
            topic: Some(e.topic.clone()),
            type_name: (!e.type_name.is_empty()).then(|| e.type_name.clone()),
            ..Self::default()
        }
    }

    pub fn from_command(c: &MotionCommand) -> Self {
        Self {
            participant_guid: c.source_guid.clone(),
            topic: Some(c.channel.clone()),
            ..Self::default()
        }
    }

    fn framed_fields(&self) -> Vec<Vec<u8>> {
        [
            &self.participant_guid,
            &self.node,
            &self.topic,
            &self.type_name,
            &self.src_ip,
        ]
        .iter()
        .map(|f| match f {
            Some(v) => {
                let mut b = Vec::with_capacity(v.len() + 1);
                b.push(1);
                b.extend_from_slice(v.as_bytes());
                b
            }
            None => vec![0],
        })
        .collect()
    }
}

/// Trusted catalog entry for a rule id.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RuleInfo {
    pub title: &'static str,
    pub desc: &'static str,
    pub data_source: &'static str,
    /// ATT&CK for ICS `(id, name)`.
    pub techniques: &'static [(&'static str, &'static str)],
}

const T0855: (&str, &str) = ("T0855", "Unauthorized Command Message");
const T0831: (&str, &str) = ("T0831", "Manipulation of Control");
const T0848: (&str, &str) = ("T0848", "Rogue Master");
const T0801: (&str, &str) = ("T0801", "Monitor Process State");
const T0856: (&str, &str) = ("T0856", "Spoof Reporting Message");

/// The generic entry for a rule id without a catalog entry.
const GENERIC: RuleInfo = RuleInfo {
    title: "RoboDR model-profile deviation",
    desc: "The detection core reported a deviation from the locked model profile for a rule without a catalog entry.",
    data_source: "robodr",
    techniques: &[],
};

/// Contract 1.x minor that added [`catalog_1_3`]'s entries.
pub const CATALOG_1_3_MINOR: u64 = 3;
/// Contract 2.x minor that added [`catalog_2_1`]'s entries.
pub const CATALOG_2_1_MINOR: u64 = 1;
/// Contract 2.x minor that added [`catalog_2_2`]'s entries.
pub const CATALOG_2_2_MINOR: u64 = 2;
/// Contract 2.x minor that added [`catalog_2_3`]'s entries.
pub const CATALOG_2_3_MINOR: u64 = 3;

/// The trusted rule catalog of the current contract
/// ([`crate::CONTRACT_VERSION`]). Unknown rule ids get a generic entry (the
/// rule id itself is a `&'static str` from the detection core and is
/// charset-checked by the validator).
pub fn rule_info(rule: &str) -> RuleInfo {
    catalog_1_0(rule)
        .or_else(|| catalog_1_3(rule))
        .or_else(|| catalog_2_1(rule))
        .or_else(|| catalog_2_2(rule))
        .or_else(|| catalog_2_3(rule))
        .unwrap_or(GENERIC)
}

/// The catalog as a validator for a message of `contract_version` must
/// apply it: entries added in a later contract minor than the message's are
/// not used (its producer built such a finding with the generic entry, and
/// it stays valid). Adding an entry is a contract minor bump:
///
/// | contract | catalog |
/// |---|---|
/// | 1.0 - 1.2 | base ([`catalog_1_0`]) |
/// | 1.3+ (1.x), 2.0 | base + 1.3 ([`catalog_1_3`], exactly as released in 1.3) |
/// | 2.1 | base + 1.3 + 2.1 ([`catalog_2_1`]) |
/// | 2.2 | base + 1.3 + 2.1 + 2.2 ([`catalog_2_2`]) |
/// | 2.3+ | base + 1.3 + 2.1 + 2.2 + 2.3 ([`catalog_2_3`]) |
///
/// A malformed version gets the current catalog (and is rejected anyway).
pub fn rule_info_for_contract(rule: &str, contract_version: &str) -> RuleInfo {
    let mut parts = contract_version.split('.').map(|p| p.parse::<u64>().ok());
    let (major, minor) = (parts.next().flatten(), parts.next().flatten());
    let (Some(major), Some(minor)) = (major, minor) else {
        return rule_info(rule);
    };
    let with_1_3 = major > LEGACY_CONTRACT_MAJOR || minor >= CATALOG_1_3_MINOR;
    let with_2_1 =
        major > CONTRACT_MAJOR || (major == CONTRACT_MAJOR && minor >= CATALOG_2_1_MINOR);
    let with_2_2 =
        major > CONTRACT_MAJOR || (major == CONTRACT_MAJOR && minor >= CATALOG_2_2_MINOR);
    let with_2_3 =
        major > CONTRACT_MAJOR || (major == CONTRACT_MAJOR && minor >= CATALOG_2_3_MINOR);
    catalog_1_0(rule)
        .or_else(|| with_1_3.then(|| catalog_1_3(rule)).flatten())
        .or_else(|| with_2_1.then(|| catalog_2_1(rule)).flatten())
        .or_else(|| with_2_2.then(|| catalog_2_2(rule)).flatten())
        .or_else(|| with_2_3.then(|| catalog_2_3(rule)).flatten())
        .unwrap_or(GENERIC)
}

/// Entries added in contract 1.3: wave-6 detectors (correlation engine,
/// live safety-state feed, profile anti-rollback witness, agentd evidence
/// and correlation health).
fn catalog_1_3(rule: &str) -> Option<RuleInfo> {
    const CORRELATE: &str = "robodr_correlation";
    const SAFETY: &str = "robot_safety_state";
    const AGENT: &str = "robodr_agent";
    // Checked first: it holds a `robot.correlate.*` id that must not fall
    // into the generic correlation arm below.
    if let Some(info) = catalog_1_3_wave7(rule) {
        return Some(info);
    }
    Some(match rule {
        "robot.correlate.coordinated_intrusion" => RuleInfo {
            title: "Correlated intrusion: unknown participant, foreign motion writer and host anomaly",
            desc: "Within one minute an unknown DDS participant, an unauthorized motion writer and a host process anomaly were each detected; the correlation cites every contributing detection.",
            data_source: CORRELATE,
            techniques: &[T0848, T0855],
        },
        "robot.correlate.sensor_evasion" => RuleInfo {
            title: "Correlated sensor evasion: capture refusals with uninspected discovery",
            desc: "Repeated capture or fragment refusals coincided with discovery traffic the sensor could not inspect, a pattern consistent with an attempt to blind the sensor.",
            data_source: CORRELATE,
            techniques: &[],
        },
        "robot.correlate.credential_theft" => RuleInfo {
            title: "Correlated credential theft: SROS 2 key read, then a foreign participant",
            desc: "An SROS 2 private key was read outside the ROS stack and an unknown or source-mismatched participant appeared afterwards within the correlation window.",
            data_source: CORRELATE,
            techniques: &[T0848],
        },
        "robot.correlate.trojaned_package_key_access" => RuleInfo {
            title: "Correlated supply-chain compromise: package install, then key access",
            desc: "A package install or maintainer script was followed by an SROS 2 private key read within the correlation window.",
            data_source: CORRELATE,
            techniques: &[],
        },
        "robot.correlate.spoofed_motion_source" => RuleInfo {
            title: "Correlated spoofed motion source from one address",
            desc: "A participant or endpoint source mismatch was followed by an unauthorized motion writer from the same source address within the correlation window.",
            data_source: CORRELATE,
            techniques: &[T0855],
        },
        "robot.correlate.motion_hijack" => RuleInfo {
            title: "Correlated motion hijack: foreign motion source, then unexpected motion",
            desc: "A foreign motion writer or a firewall source rejection was followed by uncommanded motion, feedback divergence or a second feedback publisher within the correlation window.",
            data_source: CORRELATE,
            techniques: &[T0855, T0831],
        },
        "robot.correlate.defense_tampering" => RuleInfo {
            title: "Correlated defense tampering: protected file or service change with a silent input",
            desc: "A host rule saw a RoboDR or Pulsar protected file change or a service stop while the agent reported an input silent or ended; observe-only by construction.",
            data_source: CORRELATE,
            techniques: &[],
        },
        "robot.correlate.discovery_flood" => RuleInfo {
            title: "Correlated discovery flood: unknown participants from many addresses",
            desc: "Unknown DDS participants were announced from many distinct source addresses within the correlation window: a discovery flood or scan.",
            data_source: CORRELATE,
            techniques: &[T0848],
        },
        "robot.correlate.host_process_persistence" => RuleInfo {
            title: "Correlated host activity: one process tripped several host rules",
            desc: "The same host process raised several host-side detections within the correlation window.",
            data_source: CORRELATE,
            techniques: &[],
        },
        r if r.starts_with("robot.correlate.") => RuleInfo {
            title: "Correlated RoboDR detection",
            desc: "A deployment-specific correlation rule combined several detections that were each reported on their own; the correlation cites every contributing detection.",
            data_source: CORRELATE,
            techniques: &[],
        },
        "robot.safety_state.untrusted_source" => RuleInfo {
            title: "Safety-state sample from an untrusted writer",
            desc: "A safety-state sample came from a writer the locked model profile does not vouch for; it was ignored and the safety state was not taken from it.",
            data_source: SAFETY,
            techniques: &[T0856],
        },
        "robot.safety_state.undecodable_sample" => RuleInfo {
            title: "Undecodable safety-state sample",
            desc: "A safety-state sample from a trusted writer could not be decoded; that source reads unknown until a valid sample arrives.",
            data_source: SAFETY,
            techniques: &[],
        },
        "robot.safety_state.unmapped_value" => RuleInfo {
            title: "Safety-state value outside the configured mapping",
            desc: "A trusted safety-state source carried a value the configured mapping does not cover; that source reads unknown.",
            data_source: SAFETY,
            techniques: &[],
        },
        "robot.ros2.profile_state_tampered" => RuleInfo {
            title: "Profile anti-rollback state missing or behind the black box",
            desc: "The profile anti-rollback state file is missing or older than the newest accepted-profile record in the black box; the black-box record was used as the baseline.",
            data_source: AGENT,
            techniques: &[],
        },
        "robot.agent.evidence_quarantined" => RuleInfo {
            title: "Damaged black-box segment quarantined",
            desc: "Opening the black box found closed segments that failed verification; they were copied to quarantine and recording continued without reusing sequence numbers.",
            data_source: AGENT,
            techniques: &[],
        },
        "robot.agent.correlation_pressure" => RuleInfo {
            title: "Correlation engine state under pressure",
            desc: "The correlation engine evicted or refused pending correlation state, which happens when many fresh entities arrive within a window (possibly a flood aimed at hiding a correlation).",
            data_source: AGENT,
            techniques: &[],
        },
        _ => return None,
    })
}

/// Entries added later in the (unreleased) 1.3 cycle: wave-7 detectors
/// (safety-feed writer overflow, correlation eviction notice, black-box
/// truncation) and every other `robot.*` id the in-repo detectors emitted
/// then that used to fall back to the generic entry. Same contract minor as
/// [`catalog_1_3`]: 1.3.0 had not been released when these were added. This
/// list is frozen at what 1.3.0 shipped; later entries go to a 2.x catalog
/// ([`catalog_2_1`]).
fn catalog_1_3_wave7(rule: &str) -> Option<RuleInfo> {
    const GRAPH: &str = "ros2_dds_discovery";
    const MOTION: &str = "ros2_motion_commands";
    const CORRELATE: &str = "robodr_correlation";
    const SAFETY: &str = "robot_safety_state";
    const AGENT: &str = "robodr_agent";
    const HOST: &str = "host_runtime";
    // Small helper so the table below stays one entry per line group.
    const fn e(
        title: &'static str,
        desc: &'static str,
        data_source: &'static str,
        techniques: &'static [(&'static str, &'static str)],
    ) -> RuleInfo {
        RuleInfo {
            title,
            desc,
            data_source,
            techniques,
        }
    }
    Some(match rule {
        // --- wave 7 -------------------------------------------------------
        "robot.safety_state.writer_overflow" => e(
            "Safety-state writer table overflowed",
            "A safety-state source saw more fresh writers or socket connections than it keeps; that source reads at least unknown until the extra writers go stale.",
            SAFETY,
            &[],
        ),
        "robot.correlate.correlation_state_evicted" => e(
            "Correlation evidence evicted under pressure",
            "The correlation engine evicted a pending group that already held evidence to stay within its bounds; the named correlation rule may have missed a detection. Observe-only.",
            CORRELATE,
            &[],
        ),
        "robot.agent.evidence_truncated" => e(
            "Black-box records cut after the newest mark",
            "Opening the black box found authentic proof that records after its newest integrity mark were removed; treat the evidence store as tampered with.",
            AGENT,
            &[],
        ),
        "robot.agent.control_plane_unauthenticated" => e(
            "Control-plane request failed authentication",
            "The robot's control-plane API refused requests that did not carry a valid SOC signature (missing or bad signature, unknown key, stale timestamp or replayed nonce); nothing was judged or executed.",
            AGENT,
            &[],
        ),
        "robot.agent.control_plane_invalid" => e(
            "Invalid control-plane action request refused",
            "The robot's control-plane API refused authenticated requests for an action, parameter, time limit or authority it never allows; each was recorded in the black box and nothing was executed.",
            AGENT,
            &[],
        ),
        "robot.host.pulsar_threat" => e(
            "Host runtime-security detection (Pulsar rule)",
            "A Pulsar runtime-security rule fired on the robot controller (process, file or network activity of the host operating system); the detail names the Pulsar rule and the process.",
            HOST,
            &[],
        ),
        // --- robodr-agentd self-health -------------------------------------
        "robot.agent.input_silent" => e(
            "Agent input silent",
            "An agent input delivered no valid data within the silence window; the robot state reads unknown while the agent is blind.",
            AGENT,
            &[],
        ),
        "robot.agent.input_ended" => e(
            "Agent input ended",
            "An agent input reached end of stream or failed while the daemon was running; detections from that input stopped.",
            AGENT,
            &[],
        ),
        "robot.agent.queue_overflow" => e(
            "Agent input queue overflowed",
            "The agent's input queue was full and items were dropped without inspection.",
            AGENT,
            &[],
        ),
        "robot.agent.input_malformed" => e(
            "Malformed agent input",
            "An agent input delivered items that could not be parsed; they were skipped.",
            AGENT,
            &[],
        ),
        "robot.agent.pipeline_lag" => e(
            "Agent pipeline lagging",
            "Queue latency or tick delay in the agent exceeded the configured lag bound; detections are late.",
            AGENT,
            &[],
        ),
        "robot.agent.spool_full" => e(
            "Finding spool full or failing",
            "The agent could not write findings to its outbound spool (full or write errors); findings may be lost before export.",
            AGENT,
            &[],
        ),
        "robot.agent.evidence_degraded" => e(
            "Black-box recording failing",
            "The black-box recorder failed to store evidence; records from this outage are missing.",
            AGENT,
            &[],
        ),
        // --- robodr-events profile (rules without a 1.0 entry) -------------
        "robot.ros2.unknown_service" => e(
            "Writer on a service outside the model profile",
            "A writer was announced on a ROS 2 service request or reply the locked model profile does not allow.",
            GRAPH,
            &[T0855],
        ),
        "robot.ros2.unknown_action" => e(
            "Writer on an action outside the model profile",
            "A writer was announced on a ROS 2 action topic or service the locked model profile does not allow.",
            GRAPH,
            &[T0855],
        ),
        "robot.dds.unknown_raw_writer" => e(
            "Writer on a raw DDS topic outside the model profile",
            "A writer was announced on a non-ROS DDS topic the locked model profile does not allow.",
            GRAPH,
            &[T0855],
        ),
        "robot.ros2.unknown_reader_topic" => e(
            "Subscriber on a topic outside the reader allowlist",
            "A reader was announced on a topic, service or action outside the profile's reader allowlist; it cannot command but may collect data.",
            GRAPH,
            &[T0801],
        ),
        "robot.motion.non_finite_command" => e(
            "Motion command with a non-finite value",
            "A motion command carried NaN or infinity on at least one axis; no envelope can bound it.",
            MOTION,
            &[T0831],
        ),
        "robot.profile.invalid_envelope" => e(
            "Motion envelope in the profile cannot be enforced",
            "The profile's envelope for this channel has an invalid or missing mandatory limit; every command on the channel is reported (fail closed).",
            MOTION,
            &[],
        ),
        // --- robodr-ros2-pipeline: profile, discovery, capture -------------
        "robot.ros2.profile_refused" => e(
            "Model profile refused",
            "The model profile failed validation and is not enforced; the sensor reports in observe-only mode.",
            AGENT,
            &[],
        ),
        "robot.ros2.participant_removed" => e(
            "Profiled DDS participant removed",
            "A participant in the locked model profile was announced as disposed or unregistered.",
            GRAPH,
            &[],
        ),
        "robot.rtps.malformed_discovery" => e(
            "Malformed RTPS discovery traffic",
            "The RTPS parser saw discovery content a well-behaved DDS stack would not send.",
            GRAPH,
            &[],
        ),
        "robot.rtps.fragmented_discovery" => e(
            "Fragmented RTPS discovery data",
            "Discovery data arrived fragmented (DATA_FRAG) and was reassembled before inspection.",
            GRAPH,
            &[],
        ),
        "robot.rtps.discovery_fragment_rejected" => e(
            "Discovery fragments refused",
            "Discovery fragments were refused (over a cap, bad geometry or no capacity); that announcement was not inspected.",
            GRAPH,
            &[],
        ),
        "robot.rtps.discovery_fragment_conflict" => e(
            "Conflicting discovery fragments",
            "Discovery fragments overlapped already received bytes with different content; a DDS stack may act on a different announcement than the one inspected.",
            GRAPH,
            &[],
        ),
        "robot.rtps.discovery_fragment_evicted" => e(
            "Partial discovery samples evicted",
            "Partially reassembled discovery samples were evicted to stay within the reassembler's bounds; those announcements were not inspected.",
            GRAPH,
            &[],
        ),
        "robot.rtps.discovery_removal" => e(
            "Discovery dispose or unregister",
            "A discovery dispose or unregister arrived for an entity other than a profiled participant.",
            GRAPH,
            &[],
        ),
        "robot.rtps.discovery_not_inspected" => e(
            "Discovery traffic not inspected",
            "The parser had to drop all or part of a discovery datagram (unsupported version, malformed parameter list, undecodable name); that content was not inspected.",
            GRAPH,
            &[],
        ),
        "robot.ros2.ambiguous_discovery" => e(
            "Ambiguous discovery announcement",
            "A discovery announcement repeats an identity parameter with conflicting values; DDS stacks differ on which one wins, so what was inspected may not be what a stack acts on.",
            GRAPH,
            &[],
        ),
        "robot.capture.malformed_frames" => e(
            "Malformed or truncated captured frames",
            "The capture saw malformed or truncated frames; they were not inspected.",
            GRAPH,
            &[],
        ),
        "robot.capture.ip_fragment_conflict" => e(
            "Conflicting overlapping IP fragments",
            "IP fragments overlapped with conflicting bytes, an evasion pattern; the host may reassemble different content than the sensor inspected.",
            GRAPH,
            &[],
        ),
        "robot.capture.ip_reassembly_dropped" => e(
            "IP datagrams dropped in reassembly",
            "IP datagrams were dropped for bad fragment geometry or reassembly timeout; they were not inspected.",
            GRAPH,
            &[],
        ),
        "robot.capture.ip_reassembly_evicted" => e(
            "IP datagrams evicted from reassembly",
            "Partially reassembled IP datagrams were evicted to bound memory; they were not inspected.",
            GRAPH,
            &[],
        ),
        "robot.capture.unsupported_middleware" => e(
            "Robot middleware not inspected (Zenoh)",
            "The capture sees Zenoh (rmw_zenoh) traffic, which RoboDR does not decode: participants, publishers and motion commands on it are not inspected; with no RTPS at all the sensor is blind to the robot's bus.",
            GRAPH,
            &[],
        ),
        "robot.capture.ip_fragment_refused" => e(
            "IP fragments refused, reassembly budget full",
            "IP fragments were refused because the reassembly budget was full; those datagrams were not inspected (possibly a flood aimed at blinding the sensor).",
            GRAPH,
            &[],
        ),
        "robot.capture.ip_fragment_duplicate_conflict" => e(
            "Duplicate IP fragment with different content",
            "A duplicate IP fragment differed from the queued copy (first copy kept); what was inspected may differ from what the host accepts.",
            GRAPH,
            &[],
        ),
        "robot.capture.bad_checksum" => e(
            "IP or UDP checksum failures",
            "Captured packets failed the IPv4 header or UDP checksum; the robot's kernel drops these too (injection attempt aimed at the sensor, or a faulty interface).",
            GRAPH,
            &[],
        ),
        "robot.capture.not_udp" => e(
            "Non-UDP packets reached the sensor",
            "IP packets that were not UDP passed the kernel capture filter; they were not inspected.",
            GRAPH,
            &[],
        ),
        "robot.sensor.findings_capped" => e(
            "Sensor findings capped for one input",
            "One input produced more findings than the per-datagram cap; the least severe were suppressed.",
            GRAPH,
            &[],
        ),
        // --- robodr-ros2-pipeline: source binding --------------------------
        "robot.ros2.participant_source_mismatch" => e(
            "DDS participant announced from an unbound address",
            "A participant announcement for a bound participant came from an address outside its binding, or was relayed by an untrusted address; it was not learned.",
            GRAPH,
            &[T0848],
        ),
        "robot.ros2.identity_instances_exceeded" => e(
            "Extra DDS participant claims a robot identity",
            "A participant matched a stable identity of the profile (source IP, DDS vendor, enclave) whose allowed instances are all held by live participants; it is not trusted.",
            GRAPH,
            &[T0848],
        ),
        "robot.ros2.endpoint_source_mismatch" => e(
            "DDS endpoint announced from an unbound address",
            "An endpoint announcement for a participant came from an address not bound to it, or was relayed or GUID-conflicting from an untrusted address.",
            GRAPH,
            &[T0848],
        ),
        "robot.ros2.endpoint_unannounced_participant" => e(
            "DDS endpoint for a participant that never announced itself",
            "An endpoint announcement referred to a participant with no participant announcement within the hold window, or the hold queue overflowed.",
            GRAPH,
            &[],
        ),
        // --- robodr-ros2-pipeline: motion sample decode --------------------
        "robot.motion.undecodable_sample" => e(
            "Undecodable motion or feedback sample",
            "A sample on a motion or feedback topic could not be decoded; it was not inspected.",
            MOTION,
            &[],
        ),
        "robot.motion.unattributed_sample" => e(
            "Motion sample from an unattributed writer",
            "A motion or feedback sample came from a writer that was never announced, or whose binding is unbound or contested; it was not treated as authorised.",
            MOTION,
            &[T0855],
        ),
        "robot.motion.sample_source_mismatch" => e(
            "Motion sample from an address not bound to its writer",
            "A decoded motion or feedback sample came from a source address not bound to its writer's participant.",
            MOTION,
            &[T0855],
        ),
        "robot.motion.unverifiable_command" => e(
            "Motion command that cannot be bounded",
            "A decoded command's speed cannot be bounded from the message, so no envelope can check it.",
            MOTION,
            &[],
        ),
        "robot.motion.decode_anomaly" => e(
            "Motion sample decode anomaly",
            "A decoded motion or feedback sample carried an oddity that did not stop decoding, such as trailing bytes.",
            MOTION,
            &[],
        ),
        // --- robodr-motion consistency monitor -----------------------------
        "robot.motion.feedback_divergence" => e(
            "Motion feedback diverges from commands",
            "Measured feedback stayed apart from what the observed commands predict for longer than the configured tolerance.",
            MOTION,
            &[T0831],
        ),
        "robot.motion.uncommanded_motion" => e(
            "Uncommanded motion",
            "Feedback measured motion while the observed command was rest or absent.",
            MOTION,
            &[T0831],
        ),
        "robot.motion.frozen_feedback" => e(
            "Motion feedback frozen or silent",
            "Motion feedback was frozen, silent or carried anomalous timestamps; the platform's motion cannot be verified.",
            MOTION,
            &[],
        ),
        "robot.motion.cross_sensor_disagreement" => e(
            "Independent motion sensors disagree",
            "Two independent feedback sources persistently disagreed about the platform's motion.",
            MOTION,
            &[T0856],
        ),
        "robot.motion.invalid_feedback" => e(
            "Motion feedback with a non-finite value",
            "Motion feedback carried NaN or infinity.",
            MOTION,
            &[],
        ),
        "robot.motion.multiple_feedback_publishers" => e(
            "Several publishers for one feedback source",
            "More than one publisher interleaved samples for the same feedback source type.",
            MOTION,
            &[T0856],
        ),
        "robot.motion.inconsistent_feedback_stream" => e(
            "Inconsistent motion feedback stream",
            "One feedback stream repeatedly jumped between values faster than the platform can accelerate: interleaved publishers under one identity, or a faulty driver.",
            MOTION,
            &[T0856],
        ),
        // --- robodr-firewall ------------------------------------------------
        "robot.firewall.rejected_clock_regression" => e(
            "Motion command rejected: clock regression",
            "The motion firewall rejected a command because the gateway clock went backwards (in observe mode: would have rejected).",
            MOTION,
            &[],
        ),
        "robot.firewall.rejected_unknown_channel" => e(
            "Motion command rejected: unknown channel",
            "The motion firewall rejected a command on a channel its policy does not know (in observe mode: would have rejected).",
            MOTION,
            &[T0855],
        ),
        "robot.firewall.rejected_unknown_source" => e(
            "Motion command rejected: unknown source",
            "The motion firewall rejected a command from a source its policy does not know (in observe mode: would have rejected).",
            MOTION,
            &[T0855],
        ),
        "robot.firewall.rejected_unauthorized_source" => e(
            "Motion command rejected: unauthorised source",
            "The motion firewall rejected a command from a source not authorised on the channel (in observe mode: would have rejected).",
            MOTION,
            &[T0855],
        ),
        "robot.firewall.rejected_rate_limited" => e(
            "Motion command rejected: rate limit",
            "The motion firewall rejected a command over the channel's rate limit (in observe mode: would have rejected).",
            MOTION,
            &[],
        ),
        "robot.firewall.rejected_kind_mismatch" => e(
            "Motion command rejected: kind mismatch",
            "The motion firewall rejected a command whose kind (twist or joints, joint count) does not match the channel (in observe mode: would have rejected).",
            MOTION,
            &[],
        ),
        "robot.firewall.rejected_non_finite" => e(
            "Motion command rejected: non-finite value",
            "The motion firewall rejected a command carrying NaN or infinity (in observe mode: would have rejected).",
            MOTION,
            &[T0831],
        ),
        "robot.firewall.rejected_future_timestamp" => e(
            "Motion command rejected: future timestamp",
            "The motion firewall rejected a command stamped in the future (in observe mode: would have rejected).",
            MOTION,
            &[],
        ),
        "robot.firewall.rejected_stale" => e(
            "Motion command rejected: stale",
            "The motion firewall rejected a command older than its freshness bound (in observe mode: would have rejected).",
            MOTION,
            &[],
        ),
        "robot.firewall.rejected_out_of_order" => e(
            "Motion command rejected: out of order",
            "The motion firewall rejected a command stamped no later than the previous one from the same source on the channel, a replay or reordering (in observe mode: would have rejected).",
            MOTION,
            &[],
        ),
        "robot.firewall.rejected_over_hard_limit" => e(
            "Motion command rejected: over hard limit",
            "The motion firewall rejected a command whose speed exceeded the channel's hard-reject bound (in observe mode: would have rejected).",
            MOTION,
            &[T0831],
        ),
        "robot.firewall.internal_fault" => e(
            "Motion firewall internal fault",
            "The motion firewall failed its own post-condition check and applied its configured fault policy to the command.",
            MOTION,
            &[],
        ),
        "robot.firewall.limited_speed" => e(
            "Motion command speed limited",
            "The motion firewall limited a command's speed to the channel's bound (in observe mode: would have limited).",
            MOTION,
            &[],
        ),
        "robot.firewall.limited_acceleration" => e(
            "Motion command acceleration limited",
            "The motion firewall limited a command's acceleration to the channel's bound (in observe mode: would have limited).",
            MOTION,
            &[],
        ),
        "robot.firewall.limited_jerk" => e(
            "Motion command jerk limited",
            "The motion firewall limited a command's jerk to the channel's bound (in observe mode: would have limited).",
            MOTION,
            &[],
        ),
        "robot.firewall.events_dropped" => e(
            "Motion firewall events dropped",
            "The motion firewall's event buffer was full and events were dropped or evicted; this finding is as severe as the worst event lost.",
            MOTION,
            &[],
        ),
        _ => return None,
    })
}

/// Entries added in contract **2.1**: the low-level joint-frame firewall ids
/// (Unitree `LowCmd` envelope, humanoid no-zero rule), the robot-API /
/// control-handover motion ids, the Unitree legacy UDP sender ids and the
/// discovery-flood aggregate. Not in 1.3 or 2.0: a 2.0 producer built
/// such a finding with the generic entry, and the validator keeps applying
/// that to a 2.0 message ([`rule_info_for_contract`]).
fn catalog_2_1(rule: &str) -> Option<RuleInfo> {
    const MOTION: &str = "ros2_motion_commands";
    const fn e(
        title: &'static str,
        desc: &'static str,
        data_source: &'static str,
        techniques: &'static [(&'static str, &'static str)],
    ) -> RuleInfo {
        RuleInfo {
            title,
            desc,
            data_source,
            techniques,
        }
    }
    Some(match rule {
        "robot.motion.api_id_out_of_range" => e(
            "Robot API request with an aliased call id",
            "A robot API request carried a call id outside the 32-bit range the robot dispatches on, so the robot executes a different call than the one written.",
            MOTION,
            &[T0855],
        ),
        "robot.unitree.legacy_unknown_sender" => e(
            "Unitree legacy UDP frame from an unknown host",
            "A Unitree legacy (unitree_legged_sdk, Go1 generation) UDP command or state frame came from a source address the sensor configuration does not list; the protocol is unauthenticated, so an unlisted command sender can drive the robot.",
            MOTION,
            &[T0855],
        ),
        "robot.unitree.legacy_sender_flood" => e(
            "Unitree legacy UDP frames from many unknown hosts",
            "Unitree legacy (unitree_legged_sdk) UDP frames arrived from more unlisted source addresses than are reported one by one, or listed command senders appeared with many different wrong link-layer addresses; the frames are counted in aggregate. A spoofed-source flood or a scan of the robot's command ports.",
            MOTION,
            &[T0855],
        ),
        "robot.unitree.legacy_sender_mac_mismatch" => e(
            "Unitree legacy command from a listed IP with the wrong MAC",
            "A Unitree legacy UDP command came from a configured command sender IP, but its link-layer source address is not the MAC bound to that IP (or could not be verified because the datagram was reassembled from fragments): another host on the LAN may be using the sender's address.",
            MOTION,
            &[T0855],
        ),
        "robot.unitree.legacy_port_rtps" => e(
            "RTPS traffic on a Unitree legacy UDP port",
            "A datagram on a configured Unitree legacy UDP port also parses as RTPS; it was inspected on both paths. DDS traffic on the legacy command ports is not normal and can be an attempt to evade the legacy sender check.",
            MOTION,
            &[T0855],
        ),
        "robot.ros2.discovery_flood" => e(
            "Discovery flood: unknown participants aggregated",
            "One source address (or many) announced more new DDS participants than are reported one by one; their per-participant findings are folded into this one, with the count per rule, first and last seen and sample GUID prefixes, and each is still recorded in the black box. A GUID spray or a discovery scan, possibly aimed at flooding the findings path.",
            "ros2_dds_discovery",
            &[T0848],
        ),
        "robot.motion.command_type_mismatch" => e(
            "Motion command writer with an unexpected type",
            "A writer on a profiled motion command channel announced a type name other than the one the locked profile records for the channel, a type no decoder knows, or a feedback type: its commands cannot be checked as the profile intends.",
            MOTION,
            &[T0855],
        ),
        "robot.motion.control_handover" => e(
            "Motor control handed to another channel",
            "A command hands motor control to, or takes it from, another channel or controller (motion switcher release, user or arm SDK control).",
            MOTION,
            &[T0855],
        ),
        "robot.firewall.joint_position_out_of_envelope" => e(
            "Joint command position out of envelope",
            "The motion firewall found a low-level joint command whose position target lies outside the joint's envelope and clamped or rejected it (in observe mode: would have).",
            MOTION,
            &[T0831],
        ),
        "robot.firewall.joint_velocity_out_of_envelope" => e(
            "Joint command velocity out of envelope",
            "The motion firewall found a low-level joint command whose velocity target exceeds the joint's bound and clamped or rejected it (in observe mode: would have).",
            MOTION,
            &[T0831],
        ),
        "robot.firewall.joint_torque_out_of_envelope" => e(
            "Joint command torque out of envelope",
            "The motion firewall found a low-level joint command whose feed-forward torque exceeds the joint's bound and clamped or rejected it (in observe mode: would have).",
            MOTION,
            &[T0831],
        ),
        "robot.firewall.joint_gain_out_of_envelope" => e(
            "Joint command gain out of envelope",
            "The motion firewall found a low-level joint command whose stiffness or damping gain lies outside the joint's range; gains are only ever lowered, a gain below its minimum is rejected (in observe mode: would have).",
            MOTION,
            &[T0831],
        ),
        "robot.firewall.disabled_motor_energised" => e(
            "Disabled motor energised",
            "A low-level joint command energises a motor slot the profile marks as unused (non-zero torque or gain); the motion firewall rejected it (in observe mode: would have).",
            MOTION,
            &[T0831, T0855],
        ),
        "robot.firewall.crc_invalid" => e(
            "Joint command integrity check failed",
            "A low-level joint command arrived with an invalid frame checksum, or unchecked where the channel requires one; the motion firewall rejected it (in observe mode: would have).",
            MOTION,
            &[T0855],
        ),
        "robot.firewall.joint_rate_violation" => e(
            "Joint command stream gap",
            "The gap between two low-level joint commands on a channel exceeded its configured maximum interval; recorded only, the late frame is still decided normally.",
            MOTION,
            &[],
        ),
        "robot.firewall.joint_gain_below_minimum" => e(
            "Joint command gain below minimum",
            "The motion firewall rejected a low-level joint command whose stiffness or damping gain is below the joint's minimum (a disabled motor counts as zero gains); gains are never raised (in observe mode: would have rejected).",
            MOTION,
            &[T0831],
        ),
        "robot.firewall.joint_step_out_of_envelope" => e(
            "Joint command position step out of envelope",
            "The motion firewall found a low-level joint command whose position target moved further from the previous accepted target than the joint's per-frame step bound and stepped or rejected it (in observe mode: would have).",
            MOTION,
            &[T0831],
        ),
        "robot.firewall.joint_pd_torque_out_of_envelope" => e(
            "Joint command proportional torque out of envelope",
            "The motion firewall found a low-level joint command whose stiffness times position step exceeds the joint's proportional torque bound and stepped or rejected it (in observe mode: would have).",
            MOTION,
            &[T0831],
        ),
        "robot.firewall.joint_mode_inconsistent" => e(
            "Joint command mode inconsistent",
            "A low-level joint command switches a motor off while carrying non-zero gains or torque for it; the motion firewall rejected it rather than forward unchecked values (in observe mode: would have).",
            MOTION,
            &[T0831, T0855],
        ),
        "robot.firewall.joint_mode_pin_mismatch" => e(
            "Joint command operating mode changed",
            "A low-level joint command carries a frame-level mode (ankle control mode or robot variant) other than the one the channel is pinned to, which changes what the joint envelope means; the motion firewall rejected it (in observe mode: would have).",
            MOTION,
            &[T0831, T0855],
        ),
        "robot.firewall.joint_limp_frame" => e(
            "Humanoid joint command would go limp",
            "A low-level joint command for a humanoid leaves every enabled joint without stiffness or damping, which makes the robot fall; the motion firewall rejected it and held the last valid frame (in observe mode: would have).",
            MOTION,
            &[T0831, T0855],
        ),
        "robot.firewall.joint_hold_exceeded" => e(
            "Humanoid joint hold exceeded its time limit",
            "The motion firewall has been holding a humanoid's last valid joint frame for longer than the configured hold time because newer frames keep being rejected; it keeps holding with the feed-forward torque removed and needs escalation.",
            MOTION,
            &[],
        ),
        _ => return None,
    })
}

/// Entries added in contract **2.2**: the secure-delivery findings of the
/// on-unit agent `robodr-deliverd` (`docs/SECURE-DELIVERY.md` §9, Sprint
/// 13b), data source `robodr_delivery`. Not in 2.1 or earlier: a 2.1
/// validator applies the generic entry to these ids, and so does a 2.2
/// validator to a 2.1 message ([`rule_info_for_contract`]).
fn catalog_2_2(rule: &str) -> Option<RuleInfo> {
    const DELIVERY: &str = "robodr_delivery";
    const fn e(
        title: &'static str,
        desc: &'static str,
        data_source: &'static str,
        techniques: &'static [(&'static str, &'static str)],
    ) -> RuleInfo {
        RuleInfo {
            title,
            desc,
            data_source,
            techniques,
        }
    }
    Some(match rule {
        "robot.deliver.installed" => e(
            "Delivered package installed",
            "The unit's delivery agent installed a release-signed package that a depot and operator quorum assigned to it, and the package passed its health gate. Informational: the evidence trail of what runs on the unit.",
            DELIVERY,
            &[],
        ),
        "robot.deliver.deferred_safety" => e(
            "Delivery deferred by the robot's safety state",
            "The unit's delivery agent deferred an install or rollback because the robot's live safety state was not idle or safe-state (moving, human nearby, e-stop or unknown); downloading and staging continue and the install waits for a safe window. Repeated deferrals mean the unit never reaches one.",
            DELIVERY,
            &[],
        ),
        "robot.deliver.health_failed" => e(
            "Delivered package failed its health gate; rolled back",
            "A package installed by the unit's delivery agent failed its health checks; the agent rolled back automatically to the previous version at or above the anti-rollback floor.",
            DELIVERY,
            &[],
        ),
        "robot.deliver.rollback_blocked_floor" => e(
            "Failed package cannot be rolled back",
            "A package installed by the unit's delivery agent failed its health checks and there is no earlier version at or above the anti-rollback floor (or the rollback itself failed); the unit stays on the failing version until an operator acts.",
            DELIVERY,
            &[],
        ),
        "robot.deliver.refused" => e(
            "Delivery refused",
            "The unit's delivery agent refused a media pack, deployment or package: a signature, quorum, revocation, floor, scope (unit, ring, site), platform or hash check failed, or its state had to be restored. Nothing was installed from it.",
            DELIVERY,
            &[],
        ),
        "robot.deliver.stale" => e(
            "No fresh deployment or trust file",
            "The unit's newest deployment or its site trust file expired without a fresh one arriving: updates or revocations may be withheld from the unit.",
            DELIVERY,
            &[],
        ),
        "robot.deliver.chain_gap" => e(
            "Release bundle chain gap or equivocation",
            "The unit's delivery agent saw a release bundle that skips bundles it never received, or two different bundles with the same sequence number, or one that does not follow the accepted bundle.",
            DELIVERY,
            &[],
        ),
        _ => return None,
    })
}

/// Entries added in contract **2.3**. Each feature that adds entries in
/// this minor keeps its own block below (one function per block), so
/// additions merge without touching each other.
fn catalog_2_3(rule: &str) -> Option<RuleInfo> {
    catalog_2_3_seal(rule)
        .or_else(|| catalog_2_3_gateway(rule))
        .or_else(|| catalog_2_3_depot(rule))
}

// ---------------------------------------------------------------------------
// Contract 2.3 block: the site depot and executed erase (secure delivery,
// `docs/SECURE-DELIVERY.md` §5, §7.6, §8, §9, Sprints 14a / 14b;
// robodr-depot and robodr-deliverd), data source `robodr_delivery`.
// ---------------------------------------------------------------------------

/// The `robot.depot.*` ids of the site depot and `robot.seal.erase_deferred`
/// of the executed erase (Sprints 14a / 14b). Not in 2.2 or earlier: a 2.2
/// validator applies the generic entry to these ids, and so does a 2.3
/// validator to a 2.2 message ([`rule_info_for_contract`]).
fn catalog_2_3_depot(rule: &str) -> Option<RuleInfo> {
    const DELIVERY: &str = "robodr_delivery";
    const fn e(title: &'static str, desc: &'static str) -> RuleInfo {
        RuleInfo {
            title,
            desc,
            data_source: DELIVERY,
            techniques: &[],
        }
    }
    Some(match rule {
        "robot.depot.import_refused" => e(
            "Depot refused a release bundle",
            "The site depot refused to import a release bundle: no passing entry-station report for exactly that bundle, a signature, quorum, chain, revocation, floor or hash check failed. Nothing of the bundle can be deployed.",
        ),
        "robot.depot.enrolment_refused" => e(
            "Depot refused a unit enrolment",
            "The site depot refused to enrol a unit: its EK certificate does not chain to a TPM vendor CA the site trusts, the attestation key or a certified key is not resident in that TPM, the unit's keys are not bound to the site's policy, its boot measurements do not match the signed policy, or the credential challenge was not answered by the unit's TPM. No key is wrapped for it.",
        ),
        "robot.depot.unit_enrolled" => e(
            "Unit enrolled at the depot",
            "A unit was enrolled at the site depot after TPM credential activation and the operator quorum; the depot may now deliver and wrap keys for it.",
        ),
        "robot.depot.rollout_halted" => e(
            "Staged rollout halted",
            "A unit of the current ring reported a failed health gate or a refusal beyond the rollout's failure threshold; the site depot halted the rollout and serves nothing more of it until operators resume it.",
        ),
        "robot.depot.locked" => e(
            "Depot database failed its anti-rollback check",
            "The site depot's database is older than its TPM anti-rollback counter says, or the counter was recreated: the database was restored or replaced. The depot signs, serves and imports nothing until operators re-anchor it.",
        ),
        "robot.seal.erase_deferred" => e(
            "Crypto-erase deferred by the safety state",
            "A crypto-erase trigger fired, and the responder deferred the erase because the robot is moving (or its safety state is unknown); it runs as soon as the robot is idle or its safety system holds it.",
        ),
        _ => return None,
    })
}

// ---------------------------------------------------------------------------
// Contract 2.3 block: sealing (captured-unit software protection,
// `docs/SECURE-DELIVERY.md` §7 and §9, Sprint 13c; robodr-seal through
// robodr-deliverd), data source `robodr_delivery`.
// ---------------------------------------------------------------------------

/// The `robot.seal.*` ids of `docs/SECURE-DELIVERY.md` §9. Not in 2.2 or
/// earlier: a 2.2 validator applies the generic entry to these ids, and so
/// does a 2.3 validator to a 2.2 message ([`rule_info_for_contract`]).
fn catalog_2_3_seal(rule: &str) -> Option<RuleInfo> {
    const DELIVERY: &str = "robodr_delivery";
    const fn e(title: &'static str, desc: &'static str) -> RuleInfo {
        RuleInfo {
            title,
            desc,
            data_source: DELIVERY,
            techniques: &[],
        }
    }
    Some(match rule {
        "robot.seal.unseal_failed" => e(
            "Unit could not unseal delivered software",
            "The unit's TPM refused to release the key of a sealed (encrypted) delivered package: the boot measurements do not match the signed PCR policy, the policy was revoked, or the unit's sealing keys were crypto-erased. The package stays unreadable on the unit; RoboDR detection keeps running.",
        ),
        "robot.seal.lease_expired" => e(
            "Site lease expired",
            "The unit's site lease for unsealing delivered software expired: sealed packages become unavailable after its next reboot until a fresh lease is issued.",
        ),
        "robot.seal.erased" => e(
            "Crypto-erase of delivered software executed",
            "The unit's sealing keys were cryptographically erased (the TPM erase epoch moved on, or the fallback key and volume keyslots were destroyed), with the trigger named in the finding. Every sealed package on the unit is permanently unreadable; recovery is re-enrolment and re-delivery.",
        ),
        "robot.seal.tamper" => e(
            "Enclosure tamper or erase trigger fired",
            "An enclosure tamper input or another crypto-erase trigger fired on the unit; a crypto-erase of its sealing keys follows.",
        ),
        _ => return None,
    })
}

// --- Contract 2.3: in-path gateway (robot.gateway.*) -------------------------
// Kept in its own function and block: other 2.3 additions (e.g. sealing)
// live in their own `catalog_2_3_*` function, chained the same way.

/// Entries added in contract **2.3** for the in-path Motion Firewall
/// gateway `robodr-firewall-gw` (its own decisions, fed to agentd through
/// the `gateway_feed` socket; Sprint 8), data source
/// `ros2_motion_commands` (like the firewall's own entries). Not in 2.2 or
/// earlier: a 2.2 validator applies the generic entry to these ids, and so
/// does a 2.3 validator to a 2.2 message ([`rule_info_for_contract`]).
fn catalog_2_3_gateway(rule: &str) -> Option<RuleInfo> {
    const MOTION: &str = "ros2_motion_commands";
    const fn e(title: &'static str, desc: &'static str) -> RuleInfo {
        RuleInfo {
            title,
            desc,
            data_source: MOTION,
            techniques: &[],
        }
    }
    Some(match rule {
        "robot.gateway.trajectory_rejected" => e(
            "Joint trajectory blocked by the in-path gateway",
            "The in-path motion gateway suppressed a ROS 2 joint trajectory or FollowJointTrajectory goal that was outside the channel's bounds: an unknown or repeated joint name, a non-finite value, time not increasing, too many points or too long, or a position, velocity, acceleration or effort beyond its joint limit. It never reached the robot.",
        ),
        "robot.gateway.trajectory_time_scaled" => e(
            "Joint trajectory slowed down by the in-path gateway",
            "The in-path motion gateway forwarded a ROS 2 joint trajectory slowed down in place, because its velocities or accelerations exceeded the channel's limits; the path is unchanged.",
        ),
        "robot.gateway.undecodable_command" => e(
            "Undecodable motion command blocked by the in-path gateway",
            "The in-path motion gateway could not decode a sample of an enforced motion channel strictly (truncated, non-canonical or unsupported encoding) and decided it as an integrity failure: it was suppressed or replaced by the firewall's substitute.",
        ),
        "robot.gateway.fragmented_command" => e(
            "Fragmented motion command blocked by the in-path gateway",
            "The in-path motion gateway suppressed a fragmented, key-only or non-standard RTPS sample of an enforced motion channel, or of a writer it could not classify; such a sample cannot be decided in place.",
        ),
        "robot.gateway.writer_binding_conflict" => e(
            "Authorised motion writer seen from another address",
            "The in-path motion gateway received samples under an authorised writer's GUID from another source address or MAC than the one the writer's stream is bound to, while the bound side was live: a spoofing attempt, suppressed.",
        ),
        "robot.gateway.sequence_jump" => e(
            "Motion command sequence jump held back",
            "The in-path motion gateway held back a sample whose RTPS sequence number jumped far past the writer's stream until the writer confirmed it: a forged high sequence number could otherwise make the robot drop the genuine commands.",
        ),
        "robot.gateway.port_bypass_risk" => e(
            "Motion traffic may bypass the in-path gateway",
            "DDS discovery announced a locator on a UDP port the in-path motion gateway does not inspect: commands sent there would reach the robot unchecked until the gateway's port ranges are fixed.",
        ),
        "robot.gateway.restriction_changed" => e(
            "Motion restriction changed on the in-path gateway",
            "A restrict_motion restriction was applied, changed, lifted or expired on the in-path motion gateway. Informational: the evidence trail of the robot's effective motion limits.",
        ),
        "robot.gateway.findings_dropped" => e(
            "In-path gateway findings lost",
            "The in-path motion gateway had more distinct findings in one reporting period than it can hold; some were counted but not reported individually.",
        ),
        _ => return None,
    })
}

// ---------------------------------------------------------------------------
// End of the contract 2.3 sealing block.
// ---------------------------------------------------------------------------

/// The contract 1.0 - 1.2 catalog.
fn catalog_1_0(rule: &str) -> Option<RuleInfo> {
    const GRAPH: &str = "ros2_dds_discovery";
    const MOTION: &str = "ros2_motion_commands";
    Some(match rule {
        "robot.ros2.unknown_participant" => RuleInfo {
            title: "Unknown DDS participant joined the robot graph",
            desc: "A DDS participant that is not in the locked model profile announced itself on the robot's RTPS discovery bus.",
            data_source: GRAPH,
            techniques: &[T0848],
        },
        "robot.ros2.unauthorized_motion_writer" => RuleInfo {
            title: "Unauthorized publisher on a motion topic",
            desc: "A participant that is not in the locked model profile announced a writer on a motion/control topic.",
            data_source: GRAPH,
            techniques: &[T0855],
        },
        "robot.ros2.unknown_writer_topic" => RuleInfo {
            title: "Writer on a topic outside the model profile",
            desc: "A writer was announced on a topic the locked model profile does not allow anyone to publish to.",
            data_source: GRAPH,
            techniques: &[T0855],
        },
        "robot.ros2.unknown_reader" => RuleInfo {
            title: "Unknown subscriber in the robot graph",
            desc: "A participant that is not in the locked model profile announced a reader; it cannot command but may collect data.",
            data_source: GRAPH,
            techniques: &[T0801],
        },
        "robot.motion.unprofiled_channel" => RuleInfo {
            title: "Motion command on an unprofiled channel",
            desc: "A motion command was observed on a channel that has no envelope in the locked model profile.",
            data_source: MOTION,
            techniques: &[T0855],
        },
        "robot.motion.linear_over_envelope" => RuleInfo {
            title: "Linear speed command exceeds the motion envelope",
            desc: "A commanded linear speed (forward, lateral, vertical or their resultant) exceeded the maximum allowed by the locked model profile for this channel.",
            data_source: MOTION,
            techniques: &[T0831],
        },
        "robot.motion.angular_over_envelope" => RuleInfo {
            title: "Roll/pitch rate command exceeds the motion envelope",
            desc: "A commanded roll/pitch rate exceeded the maximum allowed by the locked model profile for this channel.",
            data_source: MOTION,
            techniques: &[T0831],
        },
        "robot.motion.joint_over_envelope" => RuleInfo {
            title: "Joint speed command exceeds the motion envelope",
            desc: "A commanded joint speed exceeded the maximum allowed by the locked model profile for this channel.",
            data_source: MOTION,
            techniques: &[T0831],
        },
        _ => return None,
    })
}

/// OCSF `severity_id` for a RoboDR severity.
pub fn ocsf_severity_id(s: Severity) -> u8 {
    match s {
        Severity::Low => 2,
        Severity::Medium => 3,
        Severity::High => 4,
        Severity::Critical => 5,
    }
}

/// OCSF `severity` caption for a RoboDR severity.
pub fn ocsf_severity_name(s: Severity) -> &'static str {
    match s {
        Severity::Low => "Low",
        Severity::Medium => "Medium",
        Severity::High => "High",
        Severity::Critical => "Critical",
    }
}

/// Deterministic finding uid for `(robot id, rule id, subject)`.
pub fn finding_uid(robot_id: &str, rule: &str, subject: &Subject) -> String {
    let sub = subject.framed_fields();
    let mut fields: Vec<&[u8]> = vec![robot_id.as_bytes(), rule.as_bytes()];
    fields.extend(sub.iter().map(|v| v.as_slice()));
    let h = framed_sha256("robodr.finding-uid.v1", &fields);
    format!("rf1-{}", hex(&h[..16]))
}

/// Deterministic per-emission uid (`metadata.uid`).
pub fn event_uid(finding_uid: &str, last_seen_ms: u64, count: u64) -> String {
    let h = framed_sha256(
        "robodr.event-uid.v1",
        &[
            finding_uid.as_bytes(),
            &last_seen_ms.to_be_bytes(),
            &count.to_be_bytes(),
        ],
    );
    format!("re1-{}", hex(&h[..16]))
}

/// RFC 3339 UTC timestamp with millisecond precision for `ms` since the epoch.
pub fn rfc3339_ms(ms: u64) -> String {
    let secs = ms / 1000;
    let millis = ms % 1000;
    let days = (secs / 86_400) as i64;
    let sod = secs % 86_400;
    // Howard Hinnant's civil_from_days.
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z.rem_euclid(146_097);
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = if m <= 2 { y + 1 } else { y };
    format!(
        "{:04}-{:02}-{:02}T{:02}:{:02}:{:02}.{:03}Z",
        y,
        m,
        d,
        sod / 3600,
        (sod % 3600) / 60,
        sod % 60,
        millis
    )
}

/// The mode published for `dev` raised under `ctx_mode`: the stricter of the
/// two, where *observe* (report only, never act) is stricter than enforce.
pub fn effective_mode(ctx_mode: Mode, dev: &Deviation) -> Mode {
    if ctx_mode == Mode::Observe || dev.is_observe_only() {
        Mode::Observe
    } else {
        Mode::Enforce
    }
}

fn mode_name(m: Mode) -> &'static str {
    match m {
        Mode::Observe => "observe",
        Mode::Enforce => "enforce",
    }
}

fn motion_name(m: MotionState) -> &'static str {
    match m {
        MotionState::Moving => "moving",
        MotionState::Stationary => "stationary",
        MotionState::Unknown => "unknown",
    }
}

fn proximity_name(h: HumanProximity) -> &'static str {
    match h {
        HumanProximity::Detected => "detected",
        HumanProximity::NotDetected => "not detected",
        HumanProximity::Unknown => "unknown",
    }
}

fn attestation_name(a: AttestationStatus) -> &'static str {
    match a {
        AttestationStatus::Verified => "verified",
        AttestationStatus::Deviation => "deviation",
        AttestationStatus::Unknown => "unknown",
    }
}

#[derive(Debug, Clone, PartialEq)]
struct CommandObservation {
    channel: String,
    linear_speed: Option<f64>,
    joint_speed: Option<f64>,
    envelope: Option<Envelope>,
}

/// Builder for one [`FindingEnvelope`]. All inputs are explicit (no clock is
/// read), so the output is a pure function of the inputs.
#[derive(Debug, Clone)]
pub struct FindingBuilder<'a> {
    dev: &'a Deviation,
    ctx: &'a RobotContext,
    subject: Subject,
    command: Option<CommandObservation>,
    first_seen: Option<u64>,
    last_seen: Option<u64>,
    count: u64,
    safety: SafetyState,
    attestation: AttestationStatus,
    evidence: Vec<BlackBoxRef>,
    bus_message_id: Option<u32>,
    anomaly_score: Option<f64>,
}

impl<'a> FindingBuilder<'a> {
    /// Start a finding for `dev` raised on the robot described by `ctx`.
    pub fn from_deviation(dev: &'a Deviation, ctx: &'a RobotContext) -> Self {
        Self {
            dev,
            ctx,
            subject: Subject::default(),
            command: None,
            first_seen: None,
            last_seen: None,
            count: 1,
            safety: SafetyState::UNKNOWN,
            attestation: AttestationStatus::Unknown,
            evidence: Vec::new(),
            bus_message_id: None,
            anomaly_score: None,
        }
    }

    /// Set subject (and command, for motion events) from the triggering event.
    pub fn event(mut self, ev: &RobotEvent) -> Self {
        match ev {
            RobotEvent::Ros2ParticipantDiscovered(p) => self.subject = Subject::from_participant(p),
            RobotEvent::Ros2WriterDiscovered(e) | RobotEvent::Ros2ReaderDiscovered(e) => {
                self.subject = Subject::from_endpoint(e)
            }
            RobotEvent::MotionCommand(c) => {
                self.subject = Subject::from_command(c);
                self = self.command(c, None);
            }
            // Feedback has no source endpoint; the channel is the subject.
            RobotEvent::MotionFeedback(f) => {
                self.subject = Subject {
                    topic: Some(f.channel.clone()),
                    ..Subject::default()
                };
            }
        }
        self
    }

    /// Set the subject explicitly.
    pub fn subject(mut self, s: Subject) -> Self {
        self.subject = s;
        self
    }

    /// Attach the commanded values and, if known, the permitted envelope.
    pub fn command(mut self, c: &MotionCommand, envelope: Option<&Envelope>) -> Self {
        self.command = Some(CommandObservation {
            channel: c.channel.clone(),
            linear_speed: c.linear_speed,
            joint_speed: c.joint_speed,
            envelope: envelope.cloned(),
        });
        self
    }

    /// First and last time (ms since epoch) this finding was observed.
    pub fn seen(mut self, first_ms: u64, last_ms: u64) -> Self {
        self.first_seen = Some(first_ms);
        self.last_seen = Some(last_ms);
        self
    }

    /// Number of occurrences aggregated (>= 1). 1 => OCSF Create, else Update.
    pub fn occurrences(mut self, n: u64) -> Self {
        self.count = n;
        self
    }

    pub fn safety_state(mut self, s: SafetyState) -> Self {
        self.safety = s;
        self
    }

    pub fn attestation(mut self, a: AttestationStatus) -> Self {
        self.attestation = a;
        self
    }

    /// Add a black-box evidence reference. Order of calls does not matter.
    pub fn evidence(mut self, r: BlackBoxRef) -> Self {
        self.evidence.push(r);
        self
    }

    pub fn bus_message_id(mut self, id: u32) -> Self {
        self.bus_message_id = Some(id);
        self
    }

    pub fn anomaly_score(mut self, s: f64) -> Self {
        self.anomaly_score = Some(s);
        self
    }

    /// The deterministic finding uid this builder will produce.
    pub fn finding_uid(&self) -> String {
        finding_uid(&self.ctx.robot.id, self.dev.rule_str(), &self.subject)
    }

    /// Assemble and validate. Never panics on hostile input; returns every
    /// validation problem found.
    pub fn build(self) -> Result<FindingEnvelope, Vec<ValidationError>> {
        let (first, last) = match (self.first_seen, self.last_seen) {
            (Some(f), Some(l)) => (f, l),
            _ => return Err(vec![ValidationError::Missing("seen (first/last time)")]),
        };
        let ctx = self.ctx;
        let dev = self.dev;
        let info = rule_info(dev.rule_str());
        let uid = self.finding_uid();
        let robot_id = ctx.robot.id.clone();

        // Observe wins: a deviation the detection core marked observe-only must
        // never be published as enforce, whatever the robot context says (and
        // an observe-mode context downgrades every deviation).
        let mode = effective_mode(ctx.mode, dev);

        let t = |v: &Option<String>, cap| v.as_deref().map(|s| Tainted::ros_name(s, cap));
        let ros = RosContext {
            participant_guid: t(&self.subject.participant_guid, caps::GUID),
            node: t(&self.subject.node, caps::NODE),
            topic: t(&self.subject.topic, caps::TOPIC),
            type_name: t(&self.subject.type_name, caps::TYPE_NAME),
            src_ip: t(&self.subject.src_ip, caps::IP),
        };
        let command = self.command.as_ref().map(|c| CommandContext {
            channel: Tainted::ros_name(&c.channel, caps::TOPIC),
            linear_speed: c.linear_speed,
            joint_speed: c.joint_speed,
            envelope_max_linear_speed: c.envelope.as_ref().and_then(|e| e.max_linear_speed),
            envelope_max_joint_speed: c.envelope.as_ref().and_then(|e| e.max_joint_speed),
        });

        let entity_context = EntityContext {
            robot: ctx.robot.clone(),
            profile: ctx.profile.clone(),
            rule_id: dev.rule.to_string(),
            mode,
            safety_state: self.safety,
            attestation: self.attestation,
            ros: ros.clone(),
            command,
            bus_message_id: self.bus_message_id,
            occurrence_count: self.count,
            detail: Tainted::new(&dev.detail, caps::DETAIL),
        };

        let mut evidence = self.evidence;
        evidence.sort();
        evidence.dedup();
        let evidence_links: Vec<String> = evidence.iter().map(|e| e.uri(&robot_id)).collect();
        let evidences: Vec<Evidence> = evidence
            .iter()
            .map(|e| Evidence {
                data: EvidenceData {
                    kind: "robodr.blackbox".into(),
                    segment: e.segment,
                    seq: e.seq,
                    sha256: e.sha256.clone(),
                    uri: e.uri(&robot_id),
                },
            })
            .collect();

        let mut resources = Vec::new();
        let mut push = |type_: &str, uid: Option<&Tainted>, name: Option<&Tainted>| {
            if uid.is_none() && name.is_none() {
                return;
            }
            resources.push(Resource {
                type_: type_.into(),
                uid: uid.map(|t| t.value.clone()),
                name: name.map(|t| t.value.clone()),
                labels: vec![TAINT_LABEL.into()],
            });
        };
        push("ros2.participant", ros.participant_guid.as_ref(), None);
        push("ros2.node", None, ros.node.as_ref());
        push("ros2.topic", None, ros.topic.as_ref());
        push("ip_address", None, ros.src_ip.as_ref());

        let title = info.title.to_string();
        let firmware = match &ctx.robot.firmware {
            Some(f) => format!("firmware {}", f.version),
            None => "firmware unknown".to_string(),
        };
        let description = format!(
            "{} Robot {} (model {}, site {}, {}); profile version {}; mode {}; \
             safety state: motion {}, human proximity {}; attestation {}; occurrences {}.",
            info.desc,
            ctx.robot.id,
            ctx.robot.model,
            ctx.robot.site,
            firmware,
            ctx.profile.version,
            mode_name(mode),
            motion_name(self.safety.motion),
            proximity_name(self.safety.human_proximity),
            attestation_name(self.attestation),
            self.count,
        );

        let (activity_id, activity_name) = if self.count <= 1 {
            (1u8, "Create")
        } else {
            (2u8, "Update")
        };
        let mitre_predictions = info
            .techniques
            .iter()
            .map(|(id, name)| MitrePrediction {
                technique_id: (*id).into(),
                technique_name: (*name).into(),
                framework: "attack_ics".into(),
                provenance: Provenance::Sensor,
            })
            .collect();
        let attacks = info
            .techniques
            .iter()
            .map(|(id, name)| Attack {
                technique: Technique {
                    uid: (*id).into(),
                    name: (*name).into(),
                },
            })
            .collect();

        let ocsf = DetectionFinding {
            activity_id,
            activity_name: activity_name.into(),
            category_uid: ocsf_ids::CATEGORY_UID,
            category_name: ocsf_ids::CATEGORY_NAME.into(),
            class_uid: ocsf_ids::CLASS_UID,
            class_name: ocsf_ids::CLASS_NAME.into(),
            type_uid: ocsf_ids::CLASS_UID * 100 + activity_id as u32,
            type_name: format!("{}: {}", ocsf_ids::CLASS_NAME, activity_name),
            severity_id: ocsf_severity_id(dev.severity),
            severity: ocsf_severity_name(dev.severity).into(),
            status_id: 1,
            status: "New".into(),
            time: last,
            message: title.clone(),
            count: self.count,
            metadata: Metadata {
                version: OCSF_VERSION.into(),
                product: Product {
                    name: PRODUCT_NAME.into(),
                    vendor_name: VENDOR_NAME.into(),
                    version: ctx.product_version.clone(),
                },
                uid: event_uid(&uid, last, self.count),
                log_name: ctx.topic.clone(),
            },
            finding_info: FindingInfo {
                uid: uid.clone(),
                title: title.clone(),
                desc: description.clone(),
                types: vec!["robot_deviation".into(), info.data_source.into()],
                first_seen_time: first,
                last_seen_time: last,
                analytic: Analytic {
                    uid: dev.rule_str().into(),
                    name: dev.rule_str().into(),
                    type_id: 1,
                    type_: "Rule".into(),
                },
                attacks,
                data_sources: vec![info.data_source.into()],
            },
            device: Device {
                uid: robot_id.clone(),
                name: robot_id.clone(),
                type_id: 99,
                type_: "Robot".into(),
                model: ctx.robot.model.clone(),
            },
            evidences,
            resources,
            unmapped: Unmapped {
                robodr: entity_context.clone(),
            },
        };

        let mut env = FindingEnvelope {
            contract_version: CONTRACT_VERSION.into(),
            finding_id: uid.clone(),
            external_id: format!("{robot_id}:{uid}"),
            data_source: ctx.data_source.clone(),
            title,
            description,
            severity: dev.severity,
            timestamp: rfc3339_ms(last),
            entity_context,
            mitre_predictions,
            evidence_links,
            anomaly_score: self.anomaly_score,
            adversary_controlled_fields: Vec::new(),
            ocsf,
        };
        // Pointers are computed from the serialised form, so they can never
        // drift from the actual layout. Non-finite floats would serialise as
        // null; validation below rejects them on the typed struct.
        env.adversary_controlled_fields = validate::tainted_pointers(&env);
        validate::validate(&env)?;
        Ok(env)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rfc3339_known_values() {
        assert_eq!(rfc3339_ms(0), "1970-01-01T00:00:00.000Z");
        assert_eq!(rfc3339_ms(951_782_400_000), "2000-02-29T00:00:00.000Z");
        assert_eq!(rfc3339_ms(1_790_000_000_123), "2026-09-21T14:13:20.123Z");
        assert_eq!(rfc3339_ms(4_102_444_799_999), "2099-12-31T23:59:59.999Z");
    }

    #[test]
    fn severity_mapping_matches_ocsf() {
        assert_eq!(ocsf_severity_id(Severity::Low), 2);
        assert_eq!(ocsf_severity_id(Severity::Medium), 3);
        assert_eq!(ocsf_severity_id(Severity::High), 4);
        assert_eq!(ocsf_severity_id(Severity::Critical), 5);
        assert_eq!(ocsf_severity_name(Severity::Critical), "Critical");
    }

    #[test]
    fn uid_depends_on_every_identity_component() {
        let s = Subject {
            participant_guid: Some("aa".into()),
            ..Subject::default()
        };
        let base = finding_uid("r1", "rule.a", &s);
        assert_eq!(base, finding_uid("r1", "rule.a", &s));
        assert!(base.starts_with("rf1-") && base.len() == 36);
        assert_ne!(base, finding_uid("r2", "rule.a", &s));
        assert_ne!(base, finding_uid("r1", "rule.b", &s));
        let mut s2 = s.clone();
        s2.topic = Some(String::new());
        assert_ne!(
            base,
            finding_uid("r1", "rule.a", &s2),
            "present-but-empty != absent"
        );
        let s3 = Subject {
            node: Some("aa".into()),
            ..Subject::default()
        };
        assert_ne!(
            base,
            finding_uid("r1", "rule.a", &s3),
            "field position matters"
        );
    }

    #[test]
    fn event_uid_changes_per_emission() {
        let a = event_uid("rf1-x", 1, 1);
        assert_ne!(a, event_uid("rf1-x", 2, 1));
        assert_ne!(a, event_uid("rf1-x", 1, 2));
        assert_eq!(a, event_uid("rf1-x", 1, 1));
    }
}
