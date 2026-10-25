//! Datagram -> RTPS report -> profile deviations (+ protocol findings) ->
//! bounded dedup -> sanitised [`Finding`]s.
//!
//! One [`Pipeline`] holds everything stateful about the sensor's view of the
//! bus: the profile and its validation result, the dedup set and **one
//! long-lived [`FragmentReassembler`]**, so a discovery announcement split
//! over several RTPS `DATA_FRAG` submessages (and several UDP datagrams) is
//! reassembled within strict memory caps and evaluated like any other.
//!
//! # What becomes a finding
//!
//! | Source | Rule | Severity |
//! |---|---|---|
//! | every `RobotEvent` from the report, through `Profile::evaluate` | the profile's rules (`robot.ros2.unknown_participant`, `robot.ros2.unauthorized_motion_writer`, ...) | as the profile says |
//! | an SEDP endpoint announced from an IP not bound to its participant, or relayed / GUID-conflicting from a non-discovery-server IP ([`crate::binding`]) | [`rules::ENDPOINT_SOURCE_MISMATCH`] | Critical (writer on a motion topic, or any endpoint with a loopback source seen on a non-loopback interface) / High |
//! | an SEDP endpoint whose participant never sent SPDP within the hold window | [`rules::ENDPOINT_UNANNOUNCED_PARTICIPANT`] | Medium |
//! | an SPDP for a bound participant from outside its binding, or relayed by a non-discovery-server IP | [`rules::PARTICIPANT_SOURCE_MISMATCH`] | High (profiled) / Medium |
//! | a *profiled* participant announced as disposed / unregistered | [`rules::PARTICIPANT_REMOVED`] | Medium |
//! | any other dispose / unregister (unprofiled participant, endpoint) | [`rules::DISCOVERY_REMOVAL`] | Low; Medium when sent from an IP outside the owner's binding |
//! | conflicting duplicate identity parameters (topic, type, GUIDs, key hash, status), or a non-canonical topic / type string (embedded / missing NUL; parsed up to the first NUL) | [`rules::AMBIGUOUS_DISCOVERY`] | High (writers in it are then judged as motion writers by the binding check) |
//! | an anomaly after which the parser dropped content (version, truncation, malformed PL, bad value, no topic, anomaly overflow) | [`rules::DISCOVERY_NOT_INSPECTED`] | Medium, always |
//! | any other parse [`Anomaly`] (if `report_anomalies`) | [`rules::MALFORMED_DISCOVERY`] | Low |
//! | discovery `DATA_FRAG` seen (if `report_fragmentation`) | [`rules::FRAGMENTED_DISCOVERY`] | Low |
//! | discovery fragments refused by the reassembler (always) | [`rules::DISCOVERY_FRAGMENT_REJECTED`] | Medium |
//! | discovery fragments overlapping received bytes with conflicting content (first copy inspected; writers in that datagram judged as motion writers) (always, even with `report_anomalies = false`) | [`rules::DISCOVERY_FRAGMENT_CONFLICT`] | Medium |
//! | partially reassembled discovery samples evicted by the reassembler (always) | [`rules::DISCOVERY_FRAGMENT_EVICTED`] | Medium |
//! | capture-layer counters grew ([`Pipeline::capture_findings`]) | `robot.capture.*`: [`rules::CAPTURE_IP_FRAGMENT_CONFLICT`], [`rules::CAPTURE_IP_FRAGMENT_DUPLICATE_CONFLICT`], [`rules::CAPTURE_IP_FRAGMENT_REFUSED`], [`rules::CAPTURE_IP_REASSEMBLY_EVICTED`] | Medium |
//! | | [`rules::CAPTURE_MALFORMED_FRAMES`], [`rules::CAPTURE_IP_REASSEMBLY_DROPPED`] (geometry, timeout, distance rule), [`rules::CAPTURE_NOT_UDP`] | Low |
//! | | [`rules::CAPTURE_BAD_CHECKSUM`] | Low; Medium when bursty |
//! | | [`rules::CAPTURE_UNSUPPORTED_MIDDLEWARE`]: Zenoh (`rmw_zenoh_cpp`) packets on the bus, which the sensor cannot decode | **High** while the capture has accepted no RTPS at all (the sensor is blind to this robot), Medium when RTPS is seen too (part of the bus is not inspected) |
//! | the profile failed `Profile::validate`, or a locked profile file failed the commissioning file check (seal: edited after `lock`) or the trust check (signature, trust anchors, platform/unit, anti-rollback; see [`crate::profile_trust`]) (once, [`Pipeline::status_findings`]) | [`rules::PROFILE_REFUSED`] | High |
//! | one input produced more than `max_findings_per_datagram` new findings | [`rules::FINDINGS_CAPPED`] | most severe suppressed, >= Medium |
//! | user DATA on a motion / feedback topic ([`crate::motion`]): undecodable, unattributed (writer never announced), from an IP outside the writer's binding; decoded commands through `Profile::evaluate` | [`rules::MOTION_UNDECODABLE_SAMPLE`], [`rules::MOTION_UNATTRIBUTED_SAMPLE`], [`rules::MOTION_SAMPLE_SOURCE_MISMATCH`], the profile's `robot.motion.*` rules | Medium (rate limited) / High / Critical (command) or High (feedback) / as the profile says |
//!
//! # Motion samples
//!
//! Besides findings, a datagram can carry motion commands and feedback
//! (`rt/cmd_vel`, `rt/odom`). [`Pipeline::process_with_motion_at`] returns
//! them, decoded, as [`MotionSample`]s ([`ProcessOutput::motion`]) so a
//! caller can feed them to the agent chain (Motion Firewall, motion
//! monitor). The plain `process*` methods run the same decode (and report
//! its findings) but drop the samples. See [`crate::motion`].
//!
//! Every finding is de-duplicated on (rule, detail). In addition, the noisy
//! `robot.rtps.*`, `robot.capture.*` and `robot.sensor.*` rules are **rate
//! limited** per rule ([`crate::ratelimit`]); the profile and binding rules
//! never are. Finally each input (datagram, tick, finish, capture-health
//! update) reports at most `max_findings_per_datagram` new findings, most
//! severe first; the overflow is summarised and not remembered, so it is
//! reported when it recurs (see `Pipeline::emit`).
//!
//! # Time
//!
//! The binding hold window and the rate limiter need a clock.
//! [`Pipeline::process`] uses `Instant::now()`; [`Pipeline::process_at`]
//! takes the time explicitly (tests, replays). Call [`Pipeline::tick`]
//! periodically on an idle bus so held announcements still expire, and
//! [`Pipeline::finish`] at the end of a finite input (pcap replay) to report
//! what is still held.
//!
//! # Observe vs enforce, and the invalid-profile decision (fail closed)
//!
//! The effective [`Mode`] of every finding is decided once, when the
//! pipeline is built ([`ProfileStatus`]):
//!
//! - profile valid and `locked = true` -> [`ProfileStatus::Enforcing`],
//!   findings carry [`Mode::Enforce`];
//! - profile valid and `locked = false` -> [`ProfileStatus::Observing`]
//!   (commissioning), [`Mode::Observe`];
//! - profile **fails `Profile::validate`** (locked or not) ->
//!   [`ProfileStatus::Refused`]: the errors are reported (one
//!   `robot.ros2.profile_refused` finding plus the error list), the profile is
//!   **not** enforced, and the sensor keeps running in observe-only mode
//!   against it.
//!
//! Why observe-only rather than refusing to start: a broken profile is a
//! configuration error, not an attack, and RoboDR must never escalate one into
//! a safe-state request (that would let anyone who can corrupt the profile
//! file stop the robot). Refusing to start would blind the sensor entirely.
//! Observe-only keeps visibility, never drives a response from a profile we
//! cannot trust, and makes the problem loud. Enforcement resumes only after a
//! valid profile is loaded (module restart).
//!
//! # Known limits
//!
//! - No rate limit on *distinct* profile / binding findings: an attacker
//!   announcing new GUIDs produces up to `max_findings_per_datagram` findings
//!   per datagram (each a true positive, the dedup set stays bounded).
//!   Downstream consumers should aggregate. Protocol and capture findings are
//!   rate limited.
//! - Duplicate identity parameters: the RTPS parser keeps the first value
//!   and records the conflict as an anomaly without the other value. The
//!   pipeline cannot judge the other topic itself; it raises
//!   [`rules::AMBIGUOUS_DISCOVERY`] and judges every writer of that datagram
//!   as a motion writer (worst case) in the binding check.
//! - Dedup is forever-until-evicted: a participant that leaves and comes back
//!   is not re-reported unless its entry was evicted.
//! - Text copied into findings is attacker controlled and passed through
//!   [`sanitize`].

use std::collections::{BTreeMap, HashSet};
use std::fmt;
use std::io::Read;
use std::net::IpAddr;
use std::path::Path;
use std::time::{Duration, Instant};

use robodr_commission::ProfileFileError;
use robodr_events::profile::{Profile, ProfileError};
use robodr_events::{Deviation, Mode, Severity};
use robodr_rtps::{
    hex12, hex_guid, Anomaly, DatagramReport, EndpointKind, FragmentEventKind, FragmentReassembler,
    ReassemblyLimits,
};
use serde::Serialize;

use crate::binding::{
    parse_src_ip, BindingFinding, BindingOptions, BindingStats, BindingTable, Ingress,
};
use crate::dedup::DedupSet;
use crate::identity::{IdentityResolver, IdentityStats, Resolution};
use crate::motion::{DatagramCtx, MotionOptions, MotionSample, MotionStats, MotionTracker};
use crate::ratelimit::{self, RateLimiter};
use crate::sanitize::sanitize;
use crate::source::{CaptureHealth, Datagram};

/// Prefix added to the threat description of every observe-only finding.
pub const OBSERVE_ONLY_TAG: &str = "[observe-only] ";

/// Default dedup capacity.
pub const DEFAULT_DEDUP_CAPACITY: usize = 4096;

/// Largest profile file accepted by [`load_profile`].
pub const MAX_PROFILE_BYTES: u64 = 16 << 20;

/// `src_ip` of findings that do not come from the network.
pub const LOCAL_SOURCE: &str = "local";

/// `src_ip` of capture-layer findings (no single peer).
pub const CAPTURE_SOURCE: &str = "capture";

/// Default [`PipelineOptions::max_findings_per_datagram`].
pub const DEFAULT_MAX_FINDINGS_PER_DATAGRAM: usize = 64;
/// Largest [`PipelineOptions::max_findings_per_datagram`].
pub const MAX_FINDINGS_PER_DATAGRAM: usize = 4096;
/// Checksum failures within [`CHECKSUM_BURST_WINDOW`] from which
/// [`rules::CAPTURE_BAD_CHECKSUM`] is Medium instead of Low.
pub const CHECKSUM_BURST_THRESHOLD: u64 = 32;
/// Window of the checksum burst detection.
pub const CHECKSUM_BURST_WINDOW: Duration = Duration::from_secs(10);

/// Distinct rule ids listed in a [`rules::FINDINGS_CAPPED`] summary.
const MAX_CAPPED_RULES_LISTED: usize = 16;

/// A raw deviation and the source IP it is attributed to, before dedup,
/// ordering, the per-datagram cap and the rate limit ([`Pipeline::emit`]).
type Candidate = (Deviation, String);

/// DDSI-RTPS parameter ids whose value decides *what* an announcement is
/// (topic, type, endpoint / participant identity, instance, liveliness).
/// A conflicting duplicate of one of them makes the announcement ambiguous.
const IDENTITY_PIDS: &[(u16, &str)] = &[
    (0x0005, "PID_TOPIC_NAME"),
    (0x0007, "PID_TYPE_NAME"),
    (0x0050, "PID_PARTICIPANT_GUID"),
    (0x005a, "PID_ENDPOINT_GUID"),
    (0x0070, "PID_KEY_HASH"),
    (0x0071, "PID_STATUS_INFO"),
];

fn pid_name(pid: u16) -> String {
    IDENTITY_PIDS
        .iter()
        .find(|(p, _)| *p == pid)
        .map_or_else(|| format!("PID 0x{pid:04x}"), |(_, n)| (*n).to_string())
}

/// An identity parameter that DDS stacks may read differently: repeated with
/// conflicting values, or a topic / type name whose CDR string is not
/// canonical (embedded or missing NUL, wrong length; the parser reads it up
/// to the first NUL like a C-string based stack, a length-based stack reads
/// something else).
fn is_identity_conflict(a: &Anomaly) -> bool {
    identity_conflict_pid(a).is_some()
}

fn identity_conflict_pid(a: &Anomaly) -> Option<u16> {
    match a {
        Anomaly::ConflictingDuplicateParameter(pid) | Anomaly::NonCanonicalString(pid)
            if IDENTITY_PIDS.iter().any(|(p, _)| p == pid) =>
        {
            Some(*pid)
        }
        _ => None,
    }
}

/// Anomalies after which the parser dropped (part of) the content: a
/// submessage, a sample, an announcement or a value that a DDS stack might
/// still accept. Those are reported as [`rules::DISCOVERY_NOT_INSPECTED`].
fn drops_content(a: &Anomaly) -> bool {
    matches!(
        a,
        Anomaly::UnsupportedProtocolVersion(..)
            | Anomaly::TruncatedSubmessage
            | Anomaly::MalformedInfoSource
            | Anomaly::MalformedData
            | Anomaly::MalformedDataFrag
            | Anomaly::BadOctetsToInlineQos
            | Anomaly::MalformedParameterList
            | Anomaly::UnsupportedParameter
            | Anomaly::UnsupportedEncapsulation(_)
            | Anomaly::BadParameterValue(_)
            | Anomaly::AnnouncementWithoutTopic
    )
}

/// Is the datagram's discovery content ambiguous (see [`IDENTITY_PIDS`])?
#[derive(Debug, Default)]
struct Ambiguity {
    /// Identity PIDs repeated with conflicting values or carried as a
    /// non-canonical string, and inline-QoS PIDs that conflict between the
    /// fragments of one sample (`FragmentEventKind::ConflictingInlineQos`)
    /// (sorted, distinct).
    conflicting_pids: Vec<u16>,
    /// More anomalies than the parser records: an identity conflict cannot
    /// be ruled out (an attacker could pad the list with junk first).
    anomalies_truncated: bool,
    /// Discovery fragments overlapped with conflicting bytes: the sample
    /// was reassembled from the first copy, a last-copy-wins stack may see
    /// a different announcement.
    fragment_conflict: bool,
}

impl Ambiguity {
    fn of(report: &DatagramReport) -> Self {
        let mut pids: Vec<u16> = report
            .anomalies
            .iter()
            .filter_map(identity_conflict_pid)
            .collect();
        // Fragments of one sample whose inline QoS (PID_STATUS_INFO /
        // PID_KEY_HASH) disagree: status smuggling through a duplicate or
        // later fragment (R3-R1). robodr-rtps also records the anomaly, but
        // the anomaly list is bounded and the fragment events are not
        // crowded out by it, so both are read.
        pids.extend(report.fragment_events.iter().filter_map(|e| match e.kind {
            FragmentEventKind::ConflictingInlineQos(pid) => Some(pid),
            _ => None,
        }));
        pids.sort_unstable();
        pids.dedup();
        Self {
            conflicting_pids: pids,
            anomalies_truncated: report.stats.anomalies as usize > report.anomalies.len(),
            fragment_conflict: report.stats.frag_conflicts > 0
                || report
                    .anomalies
                    .iter()
                    .any(|a| matches!(a, Anomaly::ConflictingDiscoveryFragment)),
        }
    }

    fn any(&self) -> bool {
        !self.conflicting_pids.is_empty() || self.anomalies_truncated || self.fragment_conflict
    }
}

/// Rule ids raised by the pipeline itself (the profile's own rules live in
/// `robodr-events`).
pub mod rules {
    /// The profile failed `Profile::validate`; it is not enforced.
    pub const PROFILE_REFUSED: &str = "robot.ros2.profile_refused";
    /// A profiled participant was announced as disposed / unregistered.
    pub const PARTICIPANT_REMOVED: &str = "robot.ros2.participant_removed";
    /// The RTPS parser flagged something a well-behaved stack would not send.
    pub const MALFORMED_DISCOVERY: &str = "robot.rtps.malformed_discovery";
    /// Discovery data arrives fragmented (DATA_FRAG); reassembled here.
    pub const FRAGMENTED_DISCOVERY: &str = "robot.rtps.fragmented_discovery";
    /// Discovery fragments were refused (over a cap, bad geometry, no
    /// capacity): that announcement was **not** inspected.
    pub const DISCOVERY_FRAGMENT_REJECTED: &str = "robot.rtps.discovery_fragment_rejected";
    /// Discovery fragments overlapped already received bytes with
    /// **different** content (robodr-rtps `frag_conflicts`): the first copy
    /// was inspected, a DDS stack that keeps the last copy reassembles a
    /// different announcement. Medium, always (not gated by
    /// `report_anomalies`), rate limited in its own bucket.
    pub const DISCOVERY_FRAGMENT_CONFLICT: &str = "robot.rtps.discovery_fragment_conflict";
    /// Partially reassembled discovery samples were evicted to stay within
    /// the reassembler's caps: those announcements were **not** inspected.
    pub const DISCOVERY_FRAGMENT_EVICTED: &str = "robot.rtps.discovery_fragment_evicted";
    /// A dispose / unregister other than a profiled participant's.
    pub const DISCOVERY_REMOVAL: &str = "robot.rtps.discovery_removal";
    /// Capture saw malformed or truncated frames.
    pub const CAPTURE_MALFORMED_FRAMES: &str = "robot.capture.malformed_frames";
    /// IP fragments overlapped with conflicting bytes (evasion pattern).
    pub const CAPTURE_IP_FRAGMENT_CONFLICT: &str = "robot.capture.ip_fragment_conflict";
    /// IP datagrams dropped (bad fragment geometry or reassembly timeout).
    pub const CAPTURE_IP_REASSEMBLY_DROPPED: &str = "robot.capture.ip_reassembly_dropped";
    /// IP datagrams evicted from reassembly to bound memory.
    pub const CAPTURE_IP_REASSEMBLY_EVICTED: &str = "robot.capture.ip_reassembly_evicted";
    /// IP fragments refused because the reassembly budget was full: those
    /// datagrams were not inspected (a flood aimed at blinding the sensor).
    pub const CAPTURE_IP_FRAGMENT_REFUSED: &str = "robot.capture.ip_fragment_refused";
    /// Duplicate IP fragments whose bytes differ from the queued copy (first
    /// copy kept): what was inspected may differ from what a host accepts.
    pub const CAPTURE_IP_FRAGMENT_DUPLICATE_CONFLICT: &str =
        "robot.capture.ip_fragment_duplicate_conflict";
    /// IPv4 header or UDP checksum failures (the robot's kernel drops these
    /// too): injection attempts aimed at the sensor, or a broken NIC. Low;
    /// Medium when bursty ([`super::CHECKSUM_BURST_THRESHOLD`] within
    /// [`super::CHECKSUM_BURST_WINDOW`]).
    pub const CAPTURE_BAD_CHECKSUM: &str = "robot.capture.bad_checksum";
    /// IP packets that were not UDP reached the user-space filter (the
    /// kernel filter should only pass UDP): not inspected.
    pub const CAPTURE_NOT_UDP: &str = "robot.capture.not_udp";
    /// The capture sees a robot middleware RoboDR does not decode (Zenoh,
    /// `rmw_zenoh_cpp`: TCP/UDP 7447, scouting UDP 7446; see
    /// `robodr_capture::middleware`): participants, publishers and motion
    /// commands carried by it are not inspected. High while no RTPS was seen
    /// at all (blind), Medium otherwise. Rate limited like every
    /// `robot.capture.*` rule.
    pub const CAPTURE_UNSUPPORTED_MIDDLEWARE: &str = "robot.capture.unsupported_middleware";
    /// A discovery announcement repeats an identity parameter (topic, type,
    /// GUID, key hash, status) with conflicting values: DDS stacks differ on
    /// which value wins, so what was inspected may not be what a stack acts
    /// on. High, never rate limited.
    pub const AMBIGUOUS_DISCOVERY: &str = "robot.ros2.ambiguous_discovery";
    /// The parser had to drop (part of) a discovery datagram (unsupported
    /// version, malformed parameter list, undecodable topic, ...): that
    /// content was not inspected. Medium, rate limited (own bucket).
    pub const DISCOVERY_NOT_INSPECTED: &str = "robot.rtps.discovery_not_inspected";
    /// More findings from one input than `max_findings_per_datagram`; the
    /// least severe were suppressed (and are reported if they recur).
    pub const FINDINGS_CAPPED: &str = "robot.sensor.findings_capped";
    pub use crate::binding::rules::{
        ENDPOINT_SOURCE_MISMATCH, ENDPOINT_UNANNOUNCED_PARTICIPANT, PARTICIPANT_SOURCE_MISMATCH,
    };
    pub use crate::identity::rules::IDENTITY_INSTANCES_EXCEEDED;
    pub use crate::motion::rules::{
        MOTION_API_ID_OUT_OF_RANGE, MOTION_DECODE_ANOMALY, MOTION_SAMPLE_SOURCE_MISMATCH,
        MOTION_UNATTRIBUTED_SAMPLE, MOTION_UNDECODABLE_SAMPLE, MOTION_UNVERIFIABLE_COMMAND,
    };
}

/// Knobs of the pipeline.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PipelineOptions {
    /// Max distinct findings remembered for dedup (clamped to 1..=2^20).
    pub dedup_capacity: usize,
    /// Caps of the RTPS DATA_FRAG reassembler.
    pub reassembly: ReassemblyLimits,
    /// Raise a Low finding per parse anomaly kind and source IP.
    pub report_anomalies: bool,
    /// Raise a Low finding per source IP that sends fragmented discovery.
    pub report_fragmentation: bool,
    /// Participant ↔ source-IP binding check ([`crate::binding`]).
    pub binding: BindingOptions,
    /// Rate limit of `robot.rtps.*` / `robot.capture.*`: burst per rule.
    pub rate_limit_burst: u32,
    /// Rate limit: one more finding per rule per this interval.
    pub rate_limit_interval: Duration,
    /// Max findings reported per input (datagram, tick, finish, capture
    /// health update), most severe first; the rest are summarised in one
    /// [`rules::FINDINGS_CAPPED`] finding. Clamped to
    /// 1..=[`MAX_FINDINGS_PER_DATAGRAM`].
    pub max_findings_per_datagram: usize,
    /// The user-DATA motion decode path ([`crate::motion`]).
    pub motion: MotionOptions,
}

impl Default for PipelineOptions {
    fn default() -> Self {
        Self {
            dedup_capacity: DEFAULT_DEDUP_CAPACITY,
            reassembly: ReassemblyLimits::default(),
            report_anomalies: true,
            report_fragmentation: true,
            binding: BindingOptions::default(),
            rate_limit_burst: ratelimit::DEFAULT_BURST,
            rate_limit_interval: ratelimit::DEFAULT_INTERVAL,
            max_findings_per_datagram: DEFAULT_MAX_FINDINGS_PER_DATAGRAM,
            motion: MotionOptions::default(),
        }
    }
}

/// Outcome of the load-time profile check. See the module docs.
#[derive(Debug, Clone, PartialEq)]
pub enum ProfileStatus {
    /// Valid and locked: findings are [`Mode::Enforce`].
    Enforcing,
    /// Valid, not locked (commissioning): findings are [`Mode::Observe`].
    Observing,
    /// Failed validation: not enforced, findings are [`Mode::Observe`].
    Refused(Vec<ProfileError>),
    /// A locked profile file that fails the commissioning file check
    /// (`robodr_commission::parse_profile_text`: seal missing or not
    /// matching, i.e. edited after `lock`; unknown / missing keys) or the
    /// trust check (no valid signature from a trusted key, legacy profile
    /// without metadata, wrong platform/unit, rollback), or a draft refused
    /// by anti-rollback: not enforced, findings are [`Mode::Observe`].
    /// Carries the reason.
    FileRejected(String),
}

impl ProfileStatus {
    /// Validate `profile` and classify it.
    pub fn of(profile: &Profile) -> Self {
        match profile.validate() {
            Err(errors) => Self::Refused(errors),
            Ok(()) if profile.locked => Self::Enforcing,
            Ok(()) => Self::Observing,
        }
    }

    /// The mode every finding carries.
    pub fn mode(&self) -> Mode {
        match self {
            Self::Enforcing => Mode::Enforce,
            Self::Observing | Self::Refused(_) | Self::FileRejected(_) => Mode::Observe,
        }
    }

    /// `"enforcing"`, `"observing"` or `"refused"` (validation or file
    /// check failed).
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Enforcing => "enforcing",
            Self::Observing => "observing",
            Self::Refused(_) | Self::FileRejected(_) => "refused",
        }
    }

    /// The validation errors, empty unless refused.
    pub fn errors(&self) -> &[ProfileError] {
        match self {
            Self::Refused(e) => e,
            _ => &[],
        }
    }
}

/// A profile file as loaded by [`load_profile`]: the parsed profile and
/// the result of the commissioning file check.
#[derive(Debug, Clone, PartialEq)]
pub struct LoadedProfile {
    pub profile: Profile,
    /// `robodr_commission::parse_profile_text` on the file's exact text:
    /// strict keys, and for a locked profile a valid lock seal (an edited
    /// locked file fails here) plus `Profile::validate`.
    pub file_check: Result<(), ProfileFileError>,
}

impl LoadedProfile {
    /// An in-memory profile with no file behind it (tests, tools); its
    /// status is decided by `Profile::validate` alone.
    pub fn unchecked(profile: Profile) -> Self {
        Self {
            profile,
            file_check: Ok(()),
        }
    }
}

/// [`crate::profile_trust::load_profile_with_trust`] with **no trust
/// anchors configured**: drafts load as before, but every locked profile
/// fails the trust check (fail closed: it cannot be authenticated) and runs
/// observe-only. Kept for callers not yet wired to a trust configuration
/// (e.g. the Pulsar sensor glue); production callers pass the sensor's
/// `profile_trust` settings to `load_profile_with_trust`.
pub fn load_profile(path: &Path) -> Result<LoadedProfile, String> {
    crate::profile_trust::load_profile_with_trust(
        path,
        &crate::profile_trust::ProfileTrustConfig::default(),
    )
}

/// Read a profile file's text (size-capped) and parse it leniently
/// (robodr-events tolerates unknown keys and the `seal` member, so an old
/// or hand-written draft can still be observed against).
pub(crate) fn read_profile_lenient(path: &Path) -> Result<(String, Profile), String> {
    let file = std::fs::File::open(path)
        .map_err(|e| format!("reading profile {}: {e}", path.display()))?;
    let mut raw = String::new();
    file.take(MAX_PROFILE_BYTES + 1)
        .read_to_string(&mut raw)
        .map_err(|e| format!("reading profile {}: {e}", path.display()))?;
    if raw.len() as u64 > MAX_PROFILE_BYTES {
        return Err(format!(
            "profile {} is larger than {MAX_PROFILE_BYTES} bytes",
            path.display()
        ));
    }
    let profile: Profile = serde_json::from_str(&raw)
        .map_err(|e| format!("parsing profile {}: {e}", path.display()))?;
    Ok((raw, profile))
}

/// A new (not previously reported) finding, ready to become one threat.
#[derive(Debug, Clone, PartialEq)]
pub struct Finding {
    /// The deviation, with its `mode` set to the pipeline's effective mode.
    pub deviation: Deviation,
    /// Source IP of the datagram that revealed it ([`LOCAL_SOURCE`] for
    /// profile findings).
    pub src_ip: String,
    /// `profile.model` the finding was evaluated against.
    pub profile_model: String,
    /// [`ProfileStatus::as_str`] at the time.
    pub profile_status: &'static str,
}

/// Structured data attached to a threat (`Threat::extra` in Pulsar) and the
/// JSON line printed by `robodr-ros2-watch`. Every field is a scalar on
/// purpose: Pulsar stores `extra` as a TOML table (see
/// docs/PULSAR-INTEGRATION.md). All text is sanitised.
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct ThreatExtra {
    pub rule: String,
    pub severity: Severity,
    pub detail: String,
    /// `"enforce"` or `"observe"`.
    pub mode: Mode,
    pub observe_only: bool,
    pub src_ip: String,
    pub profile_model: String,
    /// `"enforcing"`, `"observing"` or `"refused"`.
    pub profile_status: &'static str,
}

impl Finding {
    pub fn mode(&self) -> Mode {
        self.deviation.mode
    }

    pub fn is_observe_only(&self) -> bool {
        self.deviation.is_observe_only()
    }

    /// Human-readable threat description: the sanitised detail, prefixed with
    /// [`OBSERVE_ONLY_TAG`] when observe-only.
    pub fn description(&self) -> String {
        let detail = sanitize(&self.deviation.detail);
        if self.is_observe_only() {
            format!("{OBSERVE_ONLY_TAG}{detail}")
        } else {
            detail
        }
    }

    pub fn extra(&self) -> ThreatExtra {
        ThreatExtra {
            rule: sanitize(self.deviation.rule_str()),
            severity: self.deviation.severity,
            detail: sanitize(&self.deviation.detail),
            mode: self.deviation.mode,
            observe_only: self.is_observe_only(),
            src_ip: sanitize(&self.src_ip),
            profile_model: sanitize(&self.profile_model),
            profile_status: self.profile_status,
        }
    }
}

/// Counters, for status pages and the watch tool.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize)]
pub struct PipelineStats {
    pub datagrams: u64,
    /// Datagrams that were not RTPS (no valid header).
    pub not_rtps: u64,
    pub events: u64,
    /// Deviations / protocol findings before dedup.
    pub raw_findings: u64,
    /// Suppressed by dedup.
    pub duplicates: u64,
    /// Reported.
    pub findings: u64,
    pub anomalies: u64,
    pub participant_removals: u64,
    pub endpoint_removals: u64,
    /// Discovery DATA_FRAG submessages seen.
    pub discovery_fragments: u64,
    pub fragment_samples_completed: u64,
    pub fragments_rejected: u64,
    /// Discovery fragments that overlapped with conflicting content.
    pub fragment_conflicts: u64,
    /// Partial discovery samples evicted by the reassembler.
    pub fragment_evictions: u64,
    /// `robot.rtps.*` / `robot.capture.*` findings suppressed by the rate
    /// limit (not counted in `duplicates`).
    pub rate_limited: u64,
    /// Capture-layer findings raised.
    pub capture_findings: u64,
    /// Findings suppressed by the per-datagram cap (not remembered).
    pub capped: u64,
    /// Datagrams with conflicting duplicate identity parameters.
    pub ambiguous_announcements: u64,
    /// The participant binding table.
    pub binding: BindingStats,
    /// The motion decode path.
    pub motion: MotionStats,
    /// Run-time participant identity resolution ([`crate::identity`]).
    pub identity: IdentityStats,
}

/// What one datagram produced: new findings and decoded motion samples.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct ProcessOutput {
    pub findings: Vec<Finding>,
    /// Decoded `MotionCommand` / `MotionFeedback` samples, in datagram
    /// order (see [`crate::motion`]).
    pub motion: Vec<MotionSample>,
}

/// Datagram -> findings, against one profile. See the module docs.
pub struct Pipeline {
    profile: Profile,
    status: ProfileStatus,
    /// File-check problem of an unlocked profile (observe mode anyway),
    /// shown in [`Pipeline::status_message`].
    file_note: Option<String>,
    seen: DedupSet,
    reassembler: FragmentReassembler,
    binding: BindingTable,
    limiter: RateLimiter,
    /// `reassembler.evicted()` already reported.
    frag_evicted_seen: u64,
    /// Last capture health snapshot already turned into findings.
    last_health: Option<CaptureHealth>,
    /// Checksum failures seen in the current burst window (start, count).
    checksum_window: Option<(Instant, u64)>,
    /// User-DATA motion decode path.
    motion: MotionTracker,
    /// Fresh GUID prefixes -> the profile's stable identities. Resolved
    /// prefixes are added to `profile.participants` (the working copy) and
    /// removed again when they release the identity.
    identities: IdentityResolver,
    /// The profile's own `participants` (never removed by a release).
    static_participants: std::collections::BTreeSet<String>,
    /// Prefixes that disposed themselves and released their identity: they
    /// stay in the working `participants` until this deadline, so the
    /// stragglers of the dispose (repeated dispose samples, final
    /// heartbeats, whose RTPS header still names the prefix) are not
    /// reported as an unknown participant. The identity slot is free at
    /// once (a restart may take it).
    released: BTreeMap<robodr_rtps::GuidPrefix, Instant>,
    /// Origin of the default capture timestamps ([`Pipeline::process_at`]).
    epoch: Instant,
    opts: PipelineOptions,
    stats: PipelineStats,
}

impl fmt::Debug for Pipeline {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Pipeline")
            .field("profile_model", &self.profile.model)
            .field("status", &self.status)
            .field("remembered", &self.seen.len())
            .field("pending_fragments", &self.reassembler.pending_samples())
            .field("bound_participants", &self.binding.len())
            .field("held_endpoints", &self.binding.held_len())
            .field("opts", &self.opts)
            .field("stats", &self.stats)
            .finish()
    }
}

impl Pipeline {
    /// Validate the profile ([`ProfileStatus::of`]) and build the pipeline.
    /// For a profile read from a file use [`Pipeline::from_loaded`], which
    /// also enforces the commissioning file check (lock seal).
    pub fn new(profile: Profile, opts: PipelineOptions) -> Self {
        Self::from_loaded(LoadedProfile::unchecked(profile), opts)
    }

    /// Build from a [`load_profile`] result. Status: `Refused` if
    /// `Profile::validate` fails; otherwise, for a locked profile whose file
    /// check failed (edited after `lock`, missing seal, strict-key errors,
    /// no valid trusted signature, rollback), `FileRejected` (observe-only:
    /// never enforce a profile that is not the one the OEM locked and
    /// signed, never go blind); a trust refusal of an unlocked draft
    /// (anti-rollback: a draft replacing a locked profile) is
    /// `FileRejected` too; otherwise as [`ProfileStatus::of`]. Any other
    /// file-check problem of an unlocked profile is only a note in
    /// [`Pipeline::status_message`].
    pub fn from_loaded(loaded: LoadedProfile, opts: PipelineOptions) -> Self {
        let LoadedProfile {
            profile,
            file_check,
        } = loaded;
        let mut status = ProfileStatus::of(&profile);
        let mut file_note = None;
        if let Err(e) = file_check {
            let untrusted = matches!(e, ProfileFileError::Untrusted { .. });
            let msg = e.to_string();
            match status {
                ProfileStatus::Enforcing => status = ProfileStatus::FileRejected(msg),
                ProfileStatus::Observing if untrusted => status = ProfileStatus::FileRejected(msg),
                ProfileStatus::Observing => file_note = Some(msg),
                _ => {}
            }
        }
        Self {
            status,
            file_note,
            seen: DedupSet::new(opts.dedup_capacity),
            reassembler: FragmentReassembler::new(opts.reassembly),
            binding: BindingTable::new(opts.binding.clone(), &profile),
            limiter: RateLimiter::new(opts.rate_limit_burst, opts.rate_limit_interval),
            frag_evicted_seen: 0,
            last_health: None,
            checksum_window: None,
            motion: MotionTracker::new(opts.motion.clone()),
            epoch: Instant::now(),
            identities: IdentityResolver::new(&profile),
            static_participants: profile.participants.clone(),
            released: BTreeMap::new(),
            profile,
            opts,
            stats: PipelineStats::default(),
        }
    }

    pub fn status(&self) -> &ProfileStatus {
        &self.status
    }

    /// Effective mode of every finding.
    pub fn mode(&self) -> Mode {
        self.status.mode()
    }

    pub fn profile(&self) -> &Profile {
        &self.profile
    }

    pub fn options(&self) -> &PipelineOptions {
        &self.opts
    }

    /// Counters (a snapshot, including the binding table's).
    pub fn stats(&self) -> &PipelineStats {
        &self.stats
    }

    /// The participant binding table.
    pub fn binding(&self) -> &BindingTable {
        &self.binding
    }

    /// Number of distinct findings currently remembered.
    pub fn remembered(&self) -> usize {
        self.seen.len()
    }

    /// The DATA_FRAG reassembler (for its counters).
    pub fn reassembler(&self) -> &FragmentReassembler {
        &self.reassembler
    }

    /// The motion decode path (options, counters).
    pub fn motion(&self) -> &MotionTracker {
        &self.motion
    }

    /// The motion decode path, e.g. to register a vendor type name with
    /// `motion_mut().registry_mut().register(..)`.
    pub fn motion_mut(&mut self) -> &mut MotionTracker {
        &mut self.motion
    }

    /// A one-line, sanitised operator warning when the profile is not
    /// enforced (`None` when enforcing). For `raise_warning` / stderr.
    pub fn status_message(&self) -> Option<String> {
        let model = sanitize(&self.profile.model);
        match &self.status {
            ProfileStatus::Enforcing => None,
            ProfileStatus::Observing => Some(match &self.file_note {
                None => format!(
                    "profile '{model}' is NOT locked: observe mode, findings are tagged \
                     observe-only"
                ),
                Some(n) => format!(
                    "profile '{model}' is NOT locked: observe mode, findings are tagged \
                     observe-only (profile file check: {})",
                    sanitize(n)
                ),
            }),
            ProfileStatus::FileRejected(why) => Some(format!(
                "profile '{model}' REFUSED for enforcement (profile file check failed: {}); \
                 running observe-only until a sealed profile from `robodr-commission lock`, \
                 signed by a trusted key, is loaded",
                sanitize(why)
            )),
            ProfileStatus::Refused(errors) => Some(format!(
                "profile '{model}' REFUSED for enforcement ({} validation error(s): {}); \
                 running observe-only until a valid profile is loaded",
                errors.len(),
                sanitize(
                    &errors
                        .iter()
                        .map(ToString::to_string)
                        .collect::<Vec<_>>()
                        .join("; ")
                )
            )),
        }
    }

    /// Findings about the profile itself: one [`rules::PROFILE_REFUSED`]
    /// finding when it failed validation or (locked) the file check,
    /// otherwise none. Report these once at start-up.
    pub fn status_findings(&self) -> Vec<Finding> {
        match &self.status {
            ProfileStatus::Refused(errors) => {
                let detail = format!(
                    "model profile '{}' failed validation and is not enforced ({} error(s): {})",
                    self.profile.model,
                    errors.len(),
                    errors
                        .iter()
                        .map(ToString::to_string)
                        .collect::<Vec<_>>()
                        .join("; ")
                );
                vec![self.finding(
                    Deviation::new(rules::PROFILE_REFUSED, Severity::High, detail),
                    LOCAL_SOURCE,
                )]
            }
            ProfileStatus::FileRejected(why) => {
                let detail = format!(
                    "model profile '{}' failed the profile file check and is not enforced: \
                     {why}",
                    self.profile.model
                );
                vec![self.finding(
                    Deviation::new(rules::PROFILE_REFUSED, Severity::High, detail),
                    LOCAL_SOURCE,
                )]
            }
            _ => Vec::new(),
        }
    }

    fn finding(&self, deviation: Deviation, src_ip: &str) -> Finding {
        Finding {
            deviation: deviation.with_mode(self.mode()),
            src_ip: src_ip.to_string(),
            profile_model: self.profile.model.clone(),
            profile_status: self.status.as_str(),
        }
    }

    /// Queue one raw deviation; [`Pipeline::emit`] decides what is reported.
    fn push(&mut self, out: &mut Vec<Candidate>, deviation: Deviation, src_ip: &str) {
        self.stats.raw_findings += 1;
        out.push((deviation, src_ip.to_string()));
    }

    fn push_binding(&mut self, out: &mut Vec<Candidate>, found: Vec<BindingFinding>) {
        for (dev, ip) in found {
            self.push(out, dev, &ip);
        }
        self.stats.binding = *self.binding.stats();
    }

    /// Turn the candidates of one call (one datagram, tick, finish or
    /// capture-health update) into findings:
    ///
    /// 1. drop those already reported (dedup, also within the batch);
    /// 2. order the rest by severity, most severe first (stable);
    /// 3. report at most `max_findings_per_datagram` of them, rate limiting
    ///    `robot.rtps.*` / `robot.capture.*` / `robot.sensor.*`;
    /// 4. summarise the overflow in one [`rules::FINDINGS_CAPPED`] finding.
    ///
    /// Overflowed and rate-limited candidates are **not** remembered, so they
    /// are reported when they recur (DDS re-sends discovery periodically).
    /// The cap bounds the output a single hostile datagram can cause (a
    /// 64 KiB datagram can name thousands of fake participants), while the
    /// ordering guarantees that the most severe findings (e.g. a Critical
    /// rogue motion writer) are never the ones crowded out.
    fn emit(&mut self, cands: Vec<Candidate>, now: Instant) -> Vec<Finding> {
        let mut fresh: Vec<(String, Deviation, String)> = Vec::with_capacity(cands.len());
        let mut batch_keys = HashSet::new();
        for (dev, ip) in cands {
            let key = format!("{}|{}", dev.rule, dev.detail);
            if self.seen.contains(&key) || !batch_keys.insert(key.clone()) {
                self.stats.duplicates += 1;
                continue;
            }
            fresh.push((key, dev, ip));
        }
        fresh.sort_by_key(|c| std::cmp::Reverse(c.1.severity));
        let cap = self
            .opts
            .max_findings_per_datagram
            .clamp(1, MAX_FINDINGS_PER_DATAGRAM);
        let mut out = Vec::new();
        let mut capped: BTreeMap<String, u64> = BTreeMap::new();
        let mut capped_max = Severity::Low;
        let mut capped_n = 0u64;
        for (key, mut dev, ip) in fresh {
            if out.len() >= cap {
                capped_n += 1;
                capped_max = capped_max.max(dev.severity);
                // Bounded: at most MAX_CAPPED_RULES_LISTED rule ids listed.
                if capped.len() < MAX_CAPPED_RULES_LISTED || capped.contains_key(dev.rule_str()) {
                    *capped.entry(dev.rule_str().to_string()).or_insert(0) += 1;
                }
                continue;
            }
            if !self.rate_allow(&mut dev, now) {
                continue;
            }
            self.seen.insert(&key);
            self.stats.findings += 1;
            out.push(self.finding(dev, &ip));
        }
        if capped_n > 0 {
            self.stats.capped += capped_n;
            let listed = capped
                .iter()
                .map(|(r, n)| format!("{r} x{n}"))
                .collect::<Vec<_>>()
                .join(", ");
            let detail = format!(
                "{capped_n} more finding(s) from one input suppressed by the per-datagram cap of \
                 {cap} (most severe suppressed: {capped_max:?}; {listed}); they are reported if \
                 they recur"
            );
            let mut dev = Deviation::new(
                rules::FINDINGS_CAPPED,
                capped_max.max(Severity::Medium),
                detail,
            );
            if self.rate_allow(&mut dev, now) {
                self.stats.findings += 1;
                out.push(self.finding(dev, LOCAL_SOURCE));
            }
        }
        out
    }

    /// Rate limit (`robot.rtps.*` / `robot.capture.*` / `robot.sensor.*`
    /// only). `false` = suppressed (counted, not remembered).
    fn rate_allow(&mut self, dev: &mut Deviation, now: Instant) -> bool {
        if !ratelimit::is_limited(dev.rule_str()) {
            return true;
        }
        match self.limiter.allow(dev.rule_str(), now) {
            None => {
                self.stats.rate_limited += 1;
                false
            }
            Some(0) => true,
            Some(n) => {
                dev.detail.push_str(&format!(
                    " [{n} more finding(s) of this rule suppressed by the rate limit]"
                ));
                true
            }
        }
    }

    /// Parse one datagram and return the findings not reported before.
    /// Never panics: malformed or non-RTPS input yields at most protocol
    /// findings. Uses `Instant::now()`; see [`Pipeline::process_at`].
    pub fn process(&mut self, payload: &[u8], src_ip: &str) -> Vec<Finding> {
        self.process_at(payload, src_ip, Instant::now())
    }

    /// [`Pipeline::process`] at an explicit time (monotonic across calls).
    /// The ingress interface is unknown ([`Ingress::Unknown`]); see
    /// [`Pipeline::process_from_at`].
    pub fn process_at(&mut self, payload: &[u8], src_ip: &str, now: Instant) -> Vec<Finding> {
        self.process_from_at(payload, src_ip, Ingress::Unknown, now)
    }

    /// [`Pipeline::process_at`] for a datagram whose source knows which kind
    /// of interface it arrived on: a loopback source address is then judged
    /// as same-host traffic ([`Ingress::Loopback`]) or as forged
    /// ([`Ingress::External`]); see [`crate::binding`].
    pub fn process_from_at(
        &mut self,
        payload: &[u8],
        src_ip: &str,
        ingress: Ingress,
        now: Instant,
    ) -> Vec<Finding> {
        let capture_ns = self.default_capture_ns(now);
        self.process_with_motion_at(payload, src_ip, ingress, now, capture_ns)
            .findings
    }

    /// Nanoseconds since the pipeline was built: the capture timestamp of
    /// the plain `process*` methods.
    fn default_capture_ns(&self, now: Instant) -> u64 {
        u64::try_from(now.saturating_duration_since(self.epoch).as_nanos()).unwrap_or(u64::MAX)
    }

    /// [`Pipeline::process_from_at`], also returning the decoded motion
    /// samples. `capture_ns` is the observation time stamped into every
    /// `MotionCommand` / `MotionFeedback` (the caller's clock, e.g. the
    /// agent's monotonic nanoseconds; never a value from the wire).
    pub fn process_with_motion_at(
        &mut self,
        payload: &[u8],
        src_ip: &str,
        ingress: Ingress,
        now: Instant,
        capture_ns: u64,
    ) -> ProcessOutput {
        self.stats.datagrams += 1;
        let mut out = Vec::new();
        self.expire_into(now, &mut out);
        let Some(report) = self.reassembler.parse_datagram_detailed(payload) else {
            self.stats.not_rtps += 1;
            return ProcessOutput {
                findings: self.emit(out, now),
                motion: Vec::new(),
            };
        };
        let ip = parse_src_ip(src_ip);
        let ambiguity = Ambiguity::of(&report);
        self.resolve_identities(&report, ip, ingress, src_ip, now, &mut out);
        self.profile_findings(&report, src_ip, &mut out);
        self.binding_findings(&report, ip, ingress, ambiguity.any(), &mut out, now);
        self.removal_findings(&report, src_ip, ip, ingress, now, &mut out);
        self.node_evidence(&report, now);
        self.protocol_findings(&report, src_ip, &ambiguity, &mut out);
        // Motion: learn this datagram's SEDP first, then its user DATA.
        self.motion.learn(&self.profile, &report);
        let ctx = DatagramCtx {
            src_ip,
            ip,
            ingress,
            capture_ns,
            now,
        };
        let m = self
            .motion
            .process(payload, &ctx, &self.profile, &self.binding);
        self.stats.motion = self.motion.stats();
        for dev in m.deviations {
            self.push(&mut out, dev, src_ip);
        }
        ProcessOutput {
            findings: self.emit(out, now),
            motion: m.samples,
        }
    }

    /// [`Pipeline::process_datagram`], also returning the decoded motion
    /// samples, stamped with `capture_ns` (see
    /// [`Pipeline::process_with_motion_at`]).
    pub fn process_datagram_with_motion(
        &mut self,
        datagram: &Datagram,
        capture_ns: u64,
    ) -> ProcessOutput {
        self.process_with_motion_at(
            &datagram.payload,
            &datagram.src_ip,
            datagram.ingress,
            Instant::now(),
            capture_ns,
        )
    }

    fn expire_into(&mut self, now: Instant, out: &mut Vec<Candidate>) {
        for (p, _) in self.identities.expire(now) {
            self.unresolve(p);
        }
        let done: Vec<robodr_rtps::GuidPrefix> = self
            .released
            .iter()
            .filter(|(_, at)| now >= **at)
            .map(|(p, _)| *p)
            .collect();
        for p in done {
            self.released.remove(&p);
            if !self.identities.holds(&p) {
                self.unresolve(p);
            }
        }
        self.stats.identity = *self.identities.stats();
        let mut found = Vec::new();
        self.binding.expire(&self.profile, now, &mut found);
        self.push_binding(out, found);
        for (dev, src) in self.motion.expire_unattributed(Some(now)) {
            self.push(out, dev, &src);
        }
    }

    /// Node evidence for resolved prefixes: a writer of
    /// `rr/<node>/get_parametersReply` announced by the participant itself
    /// names one of its nodes ([`crate::identity`], "Which identity").
    fn node_evidence(&mut self, report: &DatagramReport, now: Instant) {
        if self.identities.is_empty() {
            return;
        }
        for ep in &report.endpoints {
            if ep.kind != EndpointKind::Writer
                || ep.source != ep.participant
                || ep.guid_conflict
                || !self.identities.holds(&ep.participant)
            {
                continue;
            }
            let rn = robodr_events::graph::demangle(&ep.topic);
            if rn.kind != robodr_events::graph::RosNameKind::ServiceReply {
                continue;
            }
            if let Some(node) = rn.name.strip_suffix("/get_parameters") {
                if !node.is_empty() {
                    self.identities.observe_node(&ep.participant, node, now);
                }
            }
        }
        self.stats.identity = *self.identities.stats();
    }

    /// The identity a run-time resolved prefix holds ([`crate::identity`]),
    /// once confirmed by node evidence.
    pub fn identity_of(&self, prefix: &robodr_rtps::GuidPrefix) -> Option<&str> {
        self.identities.identity_of(prefix)
    }

    /// The live run-time resolved prefixes and their identities.
    pub fn identity_holders(&self) -> Vec<(robodr_rtps::GuidPrefix, String)> {
        self.identities
            .holders()
            .map(|(p, n)| (*p, n.to_owned()))
            .collect()
    }

    /// A prefix released its identity: it is no longer profiled (unless the
    /// profile lists it itself).
    fn unresolve(&mut self, p: robodr_rtps::GuidPrefix) {
        let g = hex12(&p);
        if !self.static_participants.contains(&g) {
            self.profile.participants.remove(&g);
            self.binding.set_profiled(p, false);
        }
    }

    /// Resolve this datagram's SPDP announcements of not statically profiled
    /// prefixes to the profile's identities, before the profile judges them
    /// (see [`crate::identity`]).
    fn resolve_identities(
        &mut self,
        report: &DatagramReport,
        ip: Option<IpAddr>,
        ingress: Ingress,
        src_ip: &str,
        now: Instant,
        out: &mut Vec<Candidate>,
    ) {
        if self.identities.is_empty() {
            return;
        }
        let Some(ip) = ip else { return };
        for spdp in &report.participants {
            let p = spdp.guid_prefix;
            let g = hex12(&p);
            // A statically profiled prefix (the learned run's own process)
            // resolves too, so it holds its identity for `identity:<name>`
            // rights; it stays profiled whatever the resolver says.
            let is_static = self.static_participants.contains(&g);
            if spdp.source != p
                || !spdp.alternate_guid_prefixes.is_empty()
                || (ip.is_loopback() && ingress == Ingress::External)
                || self.binding.is_contested(&p)
                || self.binding.allows_from(&p, ip, ingress) == Some(false)
            {
                continue;
            }
            match self.identities.observe_spdp(spdp, ip, now) {
                Resolution::Resolved { .. } => {
                    self.released.remove(&p);
                    self.profile.participants.insert(g);
                    self.binding.set_profiled(p, true);
                }
                Resolution::PoolFull { .. } if is_static => {}
                Resolution::PoolFull {
                    identity,
                    max,
                    holders,
                } => {
                    let held: Vec<String> = holders.iter().map(hex12).collect();
                    let detail = format!(
                        "participant {g} from {src_ip} matches identity '{}' but its {max} \
                         instance(s) are held by live participant(s) {}",
                        sanitize(&identity),
                        held.join(", ")
                    );
                    self.push(
                        out,
                        Deviation::new(rules::IDENTITY_INSTANCES_EXCEEDED, Severity::High, detail),
                        src_ip,
                    );
                }
                Resolution::Refreshed | Resolution::NoMatch => {}
            }
        }
        self.stats.identity = *self.identities.stats();
    }

    /// Report SEDP announcements whose hold window (waiting for their
    /// participant's SPDP) has expired. [`Pipeline::process`] does this on
    /// every datagram; call it periodically (e.g. every second) so an idle
    /// bus still reports them.
    pub fn tick(&mut self) -> Vec<Finding> {
        self.tick_at(Instant::now())
    }

    /// [`Pipeline::tick`] at an explicit time.
    pub fn tick_at(&mut self, now: Instant) -> Vec<Finding> {
        let mut out = Vec::new();
        self.expire_into(now, &mut out);
        self.emit(out, now)
    }

    /// End of a finite input (capture replay): report every SEDP
    /// announcement still held for a never-announced participant.
    /// The per-call cap of [`PipelineOptions::max_findings_per_datagram`]
    /// applies; what it suppresses is summarised in one finding.
    pub fn finish(&mut self) -> Vec<Finding> {
        let mut found = Vec::new();
        self.binding.flush(&self.profile, &mut found);
        let mut out = Vec::new();
        self.push_binding(&mut out, found);
        for (dev, src) in self.motion.expire_unattributed(None) {
            self.push(&mut out, dev, &src);
        }
        self.emit(out, Instant::now())
    }

    /// Process a [`Datagram`] from a [`crate::DatagramSource`], including
    /// its [`Ingress`].
    pub fn process_datagram(&mut self, datagram: &Datagram) -> Vec<Finding> {
        self.process_from_at(
            &datagram.payload,
            &datagram.src_ip,
            datagram.ingress,
            Instant::now(),
        )
    }

    fn profile_findings(
        &mut self,
        report: &DatagramReport,
        src_ip: &str,
        out: &mut Vec<Candidate>,
    ) {
        for event in report.to_events(src_ip) {
            self.stats.events += 1;
            if let Some(dev) = self.profile.evaluate(&event) {
                self.push(out, dev, src_ip);
            }
        }
    }

    /// SPDP first (learn / refresh / reject), then judge the endpoints, so a
    /// participant announcing itself and its endpoints in one datagram is
    /// bound before its endpoints are judged.
    fn binding_findings(
        &mut self,
        report: &DatagramReport,
        ip: Option<IpAddr>,
        ingress: Ingress,
        ambiguous: bool,
        out: &mut Vec<Candidate>,
        now: Instant,
    ) {
        let mut found = Vec::new();
        for spdp in &report.participants {
            self.binding
                .observe_spdp(&self.profile, spdp, ip, ingress, now, &mut found);
        }
        for ep in &report.endpoints {
            self.binding.observe_endpoint(
                &self.profile,
                ep,
                ip,
                ingress,
                ambiguous,
                now,
                &mut found,
            );
        }
        self.push_binding(out, found);
    }

    fn removal_findings(
        &mut self,
        report: &DatagramReport,
        src_ip: &str,
        ip: Option<IpAddr>,
        ingress: Ingress,
        now: Instant,
        out: &mut Vec<Candidate>,
    ) {
        for r in &report.removed_participants {
            self.stats.participant_removals += 1;
            let guid = hex12(&r.guid_prefix);
            let what = match (r.status.disposed(), r.status.unregistered()) {
                (true, true) => "disposed and unregistered",
                (true, false) => "disposed",
                _ => "unregistered",
            };
            let by = if r.source == r.guid_prefix {
                String::new()
            } else {
                format!(" (relayed by {})", hex12(&r.source))
            };
            // Judged before the binding may be dropped by this removal.
            let consistent = self.binding.observe_participant_removal(r, ip, ingress);
            self.stats.binding = *self.binding.stats();
            let unbound = if consistent == Some(false) {
                ", an IP outside its binding"
            } else {
                ""
            };
            // A self-dispose from a consistent source frees a run-time
            // identity (the finding below still says "profiled", which it
            // was until now).
            let resolved = self.identities.holds(&r.guid_prefix);
            if resolved && r.source == r.guid_prefix && consistent != Some(false) {
                self.identities.release(&r.guid_prefix);
                self.stats.identity = *self.identities.stats();
                self.released
                    .insert(r.guid_prefix, now + crate::binding::MIN_LEASE);
            }
            if self.profile.participants.contains(&guid) {
                let detail = format!(
                    "profiled participant {guid} announced as {what}{by} from {src_ip}{unbound}"
                );
                self.push(
                    out,
                    Deviation::new(rules::PARTICIPANT_REMOVED, Severity::Medium, detail),
                    src_ip,
                );
            } else {
                let sev = if consistent == Some(false) {
                    Severity::Medium
                } else {
                    Severity::Low
                };
                let detail = format!(
                    "unprofiled participant {guid} announced as {what}{by} from {src_ip}{unbound}"
                );
                self.push(
                    out,
                    Deviation::new(rules::DISCOVERY_REMOVAL, sev, detail),
                    src_ip,
                );
            }
        }
        for r in &report.removed_endpoints {
            self.stats.endpoint_removals += 1;
            let what = match (r.status.disposed(), r.status.unregistered()) {
                (true, true) => "disposed and unregistered",
                (true, false) => "disposed",
                _ => "unregistered",
            };
            let kind = match r.kind {
                EndpointKind::Writer => "writer",
                EndpointKind::Reader => "reader",
            };
            let id = r.guid.map(|g| hex_guid(&g)).unwrap_or_else(|| "?".into());
            let spoofed = ip
                .and_then(|ip| self.binding.allows_from(&r.participant, ip, ingress))
                .is_some_and(|ok| !ok)
                || (r.source != r.participant
                    && !ip.is_some_and(|ip| self.opts.binding.discovery_servers.contains(&ip))
                    && self.opts.binding.enabled);
            let (sev, note) = if spoofed {
                (
                    Severity::Medium,
                    ", not from an IP bound to its participant (spoofed removal?)",
                )
            } else {
                (Severity::Low, "")
            };
            let detail = format!(
                "{kind} {id} of participant {} announced as {what} from {src_ip}{note}",
                hex12(&r.participant)
            );
            self.push(
                out,
                Deviation::new(rules::DISCOVERY_REMOVAL, sev, detail),
                src_ip,
            );
        }
    }

    /// Increases of the capture layer's cumulative counters become
    /// rate-limited `robot.capture.*` findings (that traffic was not
    /// inspected, or was tampered with below RTPS). Call it with the
    /// source's latest [`CaptureHealth`] (e.g. after each datagram, or
    /// periodically); unchanged counters cost nothing. A counter that went
    /// down (the source restarted) re-bases silently.
    pub fn capture_findings(&mut self, health: &CaptureHealth) -> Vec<Finding> {
        self.capture_findings_at(health, Instant::now())
    }

    /// [`Pipeline::capture_findings`] at an explicit time.
    pub fn capture_findings_at(&mut self, health: &CaptureHealth, now: Instant) -> Vec<Finding> {
        let prev = self.last_health.unwrap_or_default();
        self.last_health = Some(*health);
        if prev == *health {
            return Vec::new();
        }
        let d = |new: u64, old: u64| new.saturating_sub(old);
        let h = health;
        let checksum_delta = d(h.bad_ip_checksum, prev.bad_ip_checksum)
            .saturating_add(d(h.bad_udp_checksum, prev.bad_udp_checksum));
        let checksum_sev = self.checksum_severity(checksum_delta, now);
        let checks = [
            (
                d(h.truncated, prev.truncated).saturating_add(d(h.malformed, prev.malformed)),
                h.truncated.saturating_add(h.malformed),
                rules::CAPTURE_MALFORMED_FRAMES,
                Severity::Low,
                "malformed or truncated frame(s); their content was not inspected",
            ),
            (
                d(h.ip_fragment_conflicts, prev.ip_fragment_conflicts),
                h.ip_fragment_conflicts,
                rules::CAPTURE_IP_FRAGMENT_CONFLICT,
                Severity::Medium,
                "IP datagram(s) dropped because fragments overlapped with conflicting bytes \
                 (evasion pattern); not inspected",
            ),
            (
                d(h.ip_fragment_invalid, prev.ip_fragment_invalid)
                    .saturating_add(d(h.ip_fragment_timeouts, prev.ip_fragment_timeouts)),
                h.ip_fragment_invalid.saturating_add(h.ip_fragment_timeouts),
                rules::CAPTURE_IP_REASSEMBLY_DROPPED,
                Severity::Low,
                "IP datagram(s) dropped (bad fragment geometry or reassembly timeout); \
                 not inspected",
            ),
            (
                d(h.ip_fragment_evicted, prev.ip_fragment_evicted),
                h.ip_fragment_evicted,
                rules::CAPTURE_IP_REASSEMBLY_EVICTED,
                Severity::Medium,
                "partially reassembled IP datagram(s) evicted to bound memory; not inspected",
            ),
            (
                d(h.ip_fragment_refused, prev.ip_fragment_refused),
                h.ip_fragment_refused,
                rules::CAPTURE_IP_FRAGMENT_REFUSED,
                Severity::Medium,
                "IP fragment(s) refused because the reassembly budget was full; those \
                 datagrams were not inspected",
            ),
            (
                d(
                    h.ip_fragment_duplicate_conflicts,
                    prev.ip_fragment_duplicate_conflicts,
                ),
                h.ip_fragment_duplicate_conflicts,
                rules::CAPTURE_IP_FRAGMENT_DUPLICATE_CONFLICT,
                Severity::Medium,
                "duplicate IP fragment(s) with bytes differing from the queued copy (first \
                 copy inspected; a host may have accepted the other)",
            ),
            (
                d(h.ip_fragment_too_far, prev.ip_fragment_too_far),
                h.ip_fragment_too_far,
                rules::CAPTURE_IP_REASSEMBLY_DROPPED,
                Severity::Low,
                "IPv4 datagram(s) restarted by the reassembly distance rule (fragments too far \
                 apart, as Linux ipfrag_max_dist); partly not inspected",
            ),
            (
                checksum_delta,
                h.bad_ip_checksum.saturating_add(h.bad_udp_checksum),
                rules::CAPTURE_BAD_CHECKSUM,
                checksum_sev,
                "packet(s) with a bad IPv4 header or UDP checksum (dropped by the robot's \
                 kernel too: injection attempts aimed at the sensor, or a faulty NIC)",
            ),
            (
                d(h.not_udp, prev.not_udp),
                h.not_udp,
                rules::CAPTURE_NOT_UDP,
                Severity::Low,
                "IP packet(s) that are not UDP reached the RTPS filter (the kernel filter \
                 should only pass UDP); not inspected",
            ),
        ];
        let mut out = Vec::new();
        for (delta, total, rule, sev, what) in checks {
            if delta == 0 {
                continue;
            }
            self.stats.capture_findings += 1;
            let detail = format!("capture: {delta} new {what} ({total} since capture start)");
            self.push(&mut out, Deviation::new(rule, sev, detail), CAPTURE_SOURCE);
        }
        let zenoh = d(h.zenoh, prev.zenoh);
        if zenoh > 0 {
            self.stats.capture_findings += 1;
            let blind = h.rtps == 0;
            let (sev, tail) = if blind {
                (
                    Severity::High,
                    "; no RTPS was seen at all: the sensor is blind to this robot's bus (its \
                     clean state means nothing)",
                )
            } else {
                (
                    Severity::Medium,
                    "; only the RTPS part of the bus is inspected",
                )
            };
            let src = h
                .zenoh_last_src
                .map_or_else(|| CAPTURE_SOURCE.to_string(), |ip| ip.to_string());
            let detail = format!(
                "capture: {zenoh} new Zenoh packet(s) (rmw_zenoh_cpp: TCP/UDP 7447, scouting UDP \
                 7446; latest from {src}) ({} since capture start): RoboDR does not decode Zenoh, \
                 so participants, publishers and motion commands carried by it are not \
                 inspected{tail}",
                h.zenoh
            );
            self.push(
                &mut out,
                Deviation::new(rules::CAPTURE_UNSUPPORTED_MIDDLEWARE, sev, detail),
                &src,
            );
        }
        self.emit(out, now)
    }

    /// Low, or Medium when at least [`CHECKSUM_BURST_THRESHOLD`] checksum
    /// failures arrived within [`CHECKSUM_BURST_WINDOW`] (a fixed window that
    /// restarts at the first failure after it ended).
    fn checksum_severity(&mut self, delta: u64, now: Instant) -> Severity {
        if delta == 0 {
            return Severity::Low;
        }
        let (start, count) = match self.checksum_window {
            Some((start, count))
                if now.saturating_duration_since(start) <= CHECKSUM_BURST_WINDOW =>
            {
                (start, count.saturating_add(delta))
            }
            _ => (now, delta),
        };
        self.checksum_window = Some((start, count));
        if count >= CHECKSUM_BURST_THRESHOLD {
            Severity::Medium
        } else {
            Severity::Low
        }
    }

    fn protocol_findings(
        &mut self,
        report: &DatagramReport,
        src_ip: &str,
        ambiguity: &Ambiguity,
        out: &mut Vec<Candidate>,
    ) {
        let s = &report.stats;
        self.stats.anomalies += u64::from(s.anomalies);
        self.stats.discovery_fragments += u64::from(s.discovery_data_frag);
        self.stats.fragment_samples_completed += u64::from(s.frag_completed);
        self.stats.fragments_rejected += u64::from(s.frag_rejected);
        self.stats.fragment_conflicts += u64::from(s.frag_conflicts);

        // Conflicting duplicate identity parameters: always reported, never
        // rate limited (robot.ros2.*): DDS stacks differ on first- vs
        // last-wins, so the endpoint may be on a topic other than the one
        // parsed (and judged by the profile).
        if !ambiguity.conflicting_pids.is_empty() {
            self.stats.ambiguous_announcements += 1;
            let pids = ambiguity
                .conflicting_pids
                .iter()
                .map(|p| pid_name(*p))
                .collect::<Vec<_>>()
                .join(", ");
            let topics = report
                .endpoints
                .iter()
                .take(4)
                .map(|e| e.topic.chars().take(64).collect::<String>())
                .collect::<Vec<_>>()
                .join(", ");
            let detail = format!(
                "discovery from {src_ip} carries {pids} with conflicting (repeated) or \
                 non-canonical values; other DDS stacks may act on a different value than the one \
                 inspected (parsed topic(s): [{topics}]); writers in it are judged as motion writers"
            );
            self.push(
                out,
                Deviation::new(rules::AMBIGUOUS_DISCOVERY, Severity::High, detail),
                src_ip,
            );
        }
        // Content the parser had to drop: a DDS stack may still accept it.
        // Always reported (Medium, own rate-limit bucket so a flood of Low
        // anomalies cannot use up its budget).
        let mut dropped: Vec<String> = Vec::new();
        for a in report.anomalies.iter().filter(|a| drops_content(a)) {
            let k = format!("{a:?}");
            if !dropped.contains(&k) {
                dropped.push(k);
            }
        }
        if ambiguity.anomalies_truncated {
            dropped.push(format!(
                "{} anomalies, only {} recorded",
                s.anomalies,
                report.anomalies.len()
            ));
        }
        if !dropped.is_empty() {
            let detail = format!(
                "discovery from {src_ip} was (partly) not inspected: {}",
                dropped.join(", ")
            );
            self.push(
                out,
                Deviation::new(rules::DISCOVERY_NOT_INSPECTED, Severity::Medium, detail),
                src_ip,
            );
        }
        if self.opts.report_anomalies {
            let mut kinds: Vec<String> = Vec::new();
            for a in report
                .anomalies
                .iter()
                .filter(|a| !drops_content(a) && !is_identity_conflict(a))
            {
                let k = format!("{a:?}");
                if !kinds.contains(&k) {
                    kinds.push(k);
                }
            }
            for k in kinds {
                let detail = format!("malformed RTPS discovery from {src_ip}: {k}");
                self.push(
                    out,
                    Deviation::new(rules::MALFORMED_DISCOVERY, Severity::Low, detail),
                    src_ip,
                );
            }
        }
        // The reassembler keeps the first copy of conflicting overlapping
        // fragments (robodr-rtps `frag_conflicts`, also recorded as an
        // anomaly, but the anomaly list is bounded and the counter is not);
        // a stack that keeps the last copy would see a different
        // announcement than the one inspected. Always reported.
        if ambiguity.fragment_conflict {
            let samples = report
                .fragment_events
                .iter()
                .filter(|e| e.kind == FragmentEventKind::ConflictingOverlap)
                .take(4)
                .map(|e| format!("{:?} sample sn {} of {}", e.topic, e.sn, hex12(&e.source)))
                .collect::<Vec<_>>()
                .join(", ");
            let n = s.frag_conflicts.max(1);
            let detail = format!(
                "{n} discovery fragment(s) from {src_ip} overlap received bytes with conflicting \
                 content [{samples}]; the first copy was inspected, a DDS stack may reassemble \
                 the other (writers in it are judged as motion writers)"
            );
            self.push(
                out,
                Deviation::new(rules::DISCOVERY_FRAGMENT_CONFLICT, Severity::Medium, detail),
                src_ip,
            );
        }
        if s.frag_rejected > 0 {
            let detail = format!(
                "discovery fragments from {src_ip} refused by the reassembler (over a size cap, \
                 inconsistent geometry or no capacity); that announcement was not inspected"
            );
            self.push(
                out,
                Deviation::new(rules::DISCOVERY_FRAGMENT_REJECTED, Severity::Medium, detail),
                src_ip,
            );
        }
        // TODO(rtps-hardening): the parallel robodr-rtps work adds per-datagram
        // eviction / conflict info to the detailed report. Until then the
        // reassembler's cumulative `evicted()` counter is diffed here; the
        // evicted sample may belong to another sender than `src_ip` (the one
        // whose datagram caused the eviction).
        let evicted = self.reassembler.evicted();
        if evicted > self.frag_evicted_seen {
            let delta = evicted - self.frag_evicted_seen;
            self.frag_evicted_seen = evicted;
            self.stats.fragment_evictions += delta;
            let detail = format!(
                "{delta} partially reassembled discovery sample(s) evicted to stay within the \
                 reassembler's memory caps while processing discovery from {src_ip}; those \
                 announcements were not inspected"
            );
            self.push(
                out,
                Deviation::new(rules::DISCOVERY_FRAGMENT_EVICTED, Severity::Medium, detail),
                src_ip,
            );
        }
        if self.opts.report_fragmentation && report.fragmented_discovery_seen() {
            let detail = format!(
                "discovery data from {src_ip} arrives fragmented (DATA_FRAG); reassembled by the \
                 sensor within its memory caps"
            );
            self.push(
                out,
                Deviation::new(rules::FRAGMENTED_DISCOVERY, Severity::Low, detail),
                src_ip,
            );
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use robodr_events::profile::Envelope;

    const KNOWN: [u8; 12] = [0xaa; 12];
    const KNOWN_HEX: &str = "aaaaaaaaaaaaaaaaaaaaaaaa";

    /// A 20-byte RTPS header (no submessages) with the given GUID prefix.
    fn header(prefix: [u8; 12]) -> Vec<u8> {
        let mut d = b"RTPS".to_vec();
        d.extend_from_slice(&[2, 2, 0x01, 0x0f]);
        d.extend_from_slice(&prefix);
        d
    }

    fn profile(locked: bool) -> Profile {
        let mut p = Profile {
            model: "amr-v1".into(),
            locked,
            ..Default::default()
        };
        p.participants.insert(KNOWN_HEX.into());
        p
    }

    fn pl(locked: bool, cap: usize) -> Pipeline {
        Pipeline::new(
            profile(locked),
            PipelineOptions {
                dedup_capacity: cap,
                ..Default::default()
            },
        )
    }

    fn prefix(n: u32) -> [u8; 12] {
        let mut p = [0x11u8; 12];
        p[8..].copy_from_slice(&n.to_be_bytes());
        p
    }

    /// SPDP dispose: DATA from the SPDP writer with inline QoS KEY_HASH +
    /// STATUS_INFO and no payload.
    fn spdp_dispose(sender: [u8; 12], victim: [u8; 12], status: u8) -> Vec<u8> {
        let mut body = vec![0, 0];
        body.extend_from_slice(&16u16.to_le_bytes());
        body.extend_from_slice(&[0, 0, 0, 0]);
        body.extend_from_slice(&[0x00, 0x01, 0x00, 0xc2]);
        body.extend_from_slice(&0u32.to_le_bytes());
        body.extend_from_slice(&9u32.to_le_bytes());
        body.extend_from_slice(&0x0070u16.to_le_bytes());
        body.extend_from_slice(&16u16.to_le_bytes());
        body.extend_from_slice(&victim);
        body.extend_from_slice(&[0, 0, 1, 0xc1]);
        body.extend_from_slice(&0x0071u16.to_le_bytes());
        body.extend_from_slice(&4u16.to_le_bytes());
        body.extend_from_slice(&[0, 0, 0, status]);
        body.extend_from_slice(&[1, 0, 0, 0]); // sentinel
        let mut d = header(sender);
        d.extend_from_slice(&[0x15, 0x03]); // DATA, E|Q
        d.extend_from_slice(&(body.len() as u16).to_le_bytes());
        d.extend_from_slice(&body);
        d
    }

    /// R3-P1 (pipeline side): a conflicting PID_STATUS_INFO reported by
    /// robodr-rtps (duplicate-fragment / inline-QoS status smuggling) as
    /// an identity-parameter conflict is High `ambiguous_discovery` and
    /// makes writers in the datagram motion writers for the binding check.
    #[test]
    fn status_info_conflict_is_an_identity_conflict() {
        let a = Anomaly::ConflictingDuplicateParameter(0x0071);
        assert!(is_identity_conflict(&a));
        assert_eq!(pid_name(0x0071), "PID_STATUS_INFO");
        assert!(is_identity_conflict(&Anomaly::NonCanonicalString(0x0005)));
        assert!(!is_identity_conflict(
            &Anomaly::ConflictingDuplicateParameter(0x0002)
        ));
        assert_eq!(pid_name(0x0002), "PID 0x0002");
        assert!(!drops_content(&a));
    }

    #[test]
    fn known_participant_yields_nothing() {
        let mut p = pl(true, 16);
        assert_eq!(p.status(), &ProfileStatus::Enforcing);
        assert!(p.process(&header(KNOWN), "10.0.0.5").is_empty());
        assert_eq!(p.remembered(), 0);
        assert_eq!(p.stats().events, 1);
    }

    #[test]
    fn unknown_participant_yields_one_enforce_finding() {
        let mut p = pl(true, 16);
        let f = p.process(&header([0xff; 12]), "10.0.0.9");
        assert_eq!(f.len(), 1);
        assert_eq!(f[0].deviation.rule, "robot.ros2.unknown_participant");
        assert_eq!(f[0].mode(), Mode::Enforce);
        assert!(!f[0].is_observe_only());
        assert_eq!(f[0].src_ip, "10.0.0.9");
        assert_eq!(f[0].profile_model, "amr-v1");
        assert_eq!(f[0].profile_status, "enforcing");
    }

    #[test]
    fn repeated_beacons_are_reported_once() {
        let mut p = pl(true, 16);
        let d = header([0xff; 12]);
        assert_eq!(p.process(&d, "10.0.0.9").len(), 1);
        for _ in 0..100 {
            assert!(p.process(&d, "10.0.0.9").is_empty());
        }
        assert_eq!(p.remembered(), 1);
        assert_eq!(p.stats().duplicates, 100);
        assert_eq!(p.stats().findings, 1);
    }

    #[test]
    fn same_guid_from_another_ip_is_a_new_finding() {
        let mut p = pl(true, 16);
        let d = header([0xff; 12]);
        assert_eq!(p.process(&d, "10.0.0.9").len(), 1);
        assert_eq!(p.process(&d, "10.0.0.10").len(), 1);
    }

    #[test]
    fn guid_spray_stays_bounded() {
        let cap = 64;
        let mut p = pl(true, cap);
        for n in 0..10_000u32 {
            assert_eq!(p.process(&header(prefix(n)), "10.0.0.66").len(), 1);
            assert!(p.remembered() <= cap);
        }
        assert_eq!(p.remembered(), cap);
    }

    #[test]
    fn hostile_input_never_panics() {
        let mut p = pl(true, 16);
        let mut inputs: Vec<Vec<u8>> = vec![
            vec![],
            b"RTPS".to_vec(),
            b"RTPX0000000000000000".to_vec(),
            vec![0xff; 65_535],
        ];
        let mut long = header([0xff; 12]);
        long.extend_from_slice(&[0x15, 0x05, 0xff, 0xff, 1, 2, 3]);
        let mut frag = header([0xfe; 12]);
        frag.extend_from_slice(&[0x16, 0x01, 0x40, 0x00]);
        frag.extend_from_slice(&[0, 0, 28, 0, 0, 0, 0, 0, 0, 0, 3, 0xc2]);
        frag.extend(std::iter::repeat_n(0xff, 52));
        for base in [long, frag] {
            for n in 0..=base.len() {
                inputs.push(base[..n].to_vec());
            }
        }
        for i in &inputs {
            let f = p.process(i, "10.0.0.1");
            if i.len() < 20 || &i[..4] != b"RTPS" {
                assert!(f.is_empty());
            }
            for x in f {
                assert!(!x.description().chars().any(char::is_control));
            }
        }
        assert!(p.stats().not_rtps >= 4);
    }

    #[test]
    fn unlocked_profile_is_observe_only() {
        let mut p = pl(false, 16);
        assert_eq!(p.status(), &ProfileStatus::Observing);
        assert_eq!(p.mode(), Mode::Observe);
        assert!(p.status_message().unwrap().contains("NOT locked"));
        assert!(p.status_findings().is_empty());
        let f = p.process(&header([0xff; 12]), "10.0.0.9").remove(0);
        assert!(f.is_observe_only());
        assert!(f.description().starts_with(OBSERVE_ONLY_TAG));
        let x = f.extra();
        assert!(x.observe_only);
        assert_eq!(x.profile_status, "observing");
    }

    #[test]
    fn invalid_locked_profile_is_refused_and_observe_only() {
        let mut prof = profile(true);
        prof.participants.insert("NOT-A-GUID\n".into());
        prof.writer_topics.insert("/cmd_vel".into());
        prof.motion_envelopes.insert(
            "/cmd_vel".into(),
            Envelope {
                max_linear_speed: Some(f64::NAN),
                max_joint_speed: None,
                ..Default::default()
            },
        );
        let mut p = Pipeline::new(prof, PipelineOptions::default());
        match p.status() {
            ProfileStatus::Refused(e) => assert_eq!(e.len(), 2),
            other => panic!("expected refused, got {other:?}"),
        }
        assert_eq!(p.mode(), Mode::Observe);
        let msg = p.status_message().unwrap();
        assert!(msg.contains("REFUSED") && msg.contains("2 validation error"));
        assert!(!msg.contains('\n'), "status message is sanitised");
        let sf = p.status_findings();
        assert_eq!(sf.len(), 1);
        assert_eq!(sf[0].deviation.rule, rules::PROFILE_REFUSED);
        assert_eq!(sf[0].deviation.severity, Severity::High);
        assert!(sf[0].is_observe_only());
        assert_eq!(sf[0].src_ip, LOCAL_SOURCE);
        assert!(!sf[0].description().contains('\n'));
        // The profile is still used, observe-only.
        let f = p.process(&header([0xff; 12]), "10.0.0.9");
        assert_eq!(f.len(), 1);
        assert!(f[0].is_observe_only());
        assert_eq!(f[0].profile_status, "refused");
    }

    #[test]
    fn profiled_participant_dispose_is_reported_unknown_is_counted() {
        let mut p = pl(true, 16);
        // Self-dispose of the known participant.
        let f = p.process(&spdp_dispose(KNOWN, KNOWN, 1), "10.0.0.5");
        assert_eq!(f.len(), 1, "{f:?}");
        assert_eq!(f[0].deviation.rule, rules::PARTICIPANT_REMOVED);
        assert_eq!(f[0].deviation.severity, Severity::Medium);
        assert!(f[0].deviation.detail.contains("disposed"));
        assert!(!f[0].deviation.detail.contains("relayed"));
        // Someone else unregistering the known participant: relayed.
        let f = p.process(&spdp_dispose([0xee; 12], KNOWN, 2), "10.0.0.66");
        let removal: Vec<_> = f
            .iter()
            .filter(|x| x.deviation.rule == rules::PARTICIPANT_REMOVED)
            .collect();
        assert_eq!(removal.len(), 1);
        assert!(removal[0].deviation.detail.contains("relayed by eeee"));
        assert!(removal[0].deviation.detail.contains("unregistered"));
        // Unknown participant removing itself: counted, no removal finding.
        let f = p.process(&spdp_dispose([0xdd; 12], [0xdd; 12], 3), "10.0.0.67");
        assert!(f
            .iter()
            .all(|x| x.deviation.rule != rules::PARTICIPANT_REMOVED));
        assert_eq!(p.stats().participant_removals, 3);
    }

    #[test]
    fn anomalies_are_reported_once_per_kind_and_source() {
        let mut d = header(KNOWN);
        d.extend_from_slice(&[0x15, 0x01, 0xff, 0x00]); // DATA claims 255 bytes
        let mut p = pl(true, 16);
        let f = p.process(&d, "10.0.0.5");
        // A truncated submessage drops content: Medium "not inspected".
        assert_eq!(f.len(), 1, "{f:?}");
        assert_eq!(f[0].deviation.rule, rules::DISCOVERY_NOT_INSPECTED);
        assert_eq!(f[0].deviation.severity, Severity::Medium);
        assert!(p.process(&d, "10.0.0.5").is_empty());
        assert!(p.stats().anomalies >= 2);
        // `report_anomalies = false` silences only the Low anomalies; content
        // that was not inspected is always reported.
        let mut q = Pipeline::new(
            profile(true),
            PipelineOptions {
                report_anomalies: false,
                ..Default::default()
            },
        );
        let f = q.process(&d, "10.0.0.5");
        assert_eq!(f.len(), 1);
        assert_eq!(f[0].deviation.rule, rules::DISCOVERY_NOT_INSPECTED);
        assert!(q.stats().anomalies >= 1);
    }

    #[test]
    fn extra_serialises_to_flat_scalars() {
        let mut p = pl(false, 16);
        let f = p.process(&header([0xff; 12]), "10.0.0.9").remove(0);
        let v = serde_json::to_value(f.extra()).unwrap();
        let obj = v.as_object().unwrap();
        assert_eq!(obj.len(), 8);
        assert!(obj.values().all(|v| !v.is_object() && !v.is_array()));
        assert_eq!(obj["severity"], "high");
        assert_eq!(obj["mode"], "observe");
        assert_eq!(obj["observe_only"], true);
        assert_eq!(obj["profile_status"], "observing");
    }

    #[test]
    fn attacker_text_is_sanitised_in_description_and_extra() {
        let mut p = pl(true, 16);
        let dev = Deviation::new("r", Severity::Low, "evil\n\u{1b}[2Jtopic");
        let mut out = Vec::new();
        p.push(&mut out, dev, "1.2.3.4\n");
        let f = p.emit(out, Instant::now()).remove(0);
        assert!(!f.description().contains('\n'));
        let x = f.extra();
        assert!(!x.detail.contains('\u{1b}'));
        assert_eq!(x.src_ip, "1.2.3.4\\n");
    }

    #[test]
    fn load_profile_errors_and_success() {
        let dir = std::env::temp_dir().join(format!("robodr-pl-prof-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let ok = dir.join("ok.json");
        std::fs::write(&ok, r#"{"model":"m","locked":true}"#).unwrap();
        let l = load_profile(&ok).unwrap();
        assert!(l.profile.locked);
        // Locked but unsealed (and keys missing): fails the file check.
        assert!(l.file_check.is_err());
        let bad = dir.join("bad.json");
        std::fs::write(&bad, "{not json").unwrap();
        assert!(load_profile(&bad).unwrap_err().contains("parsing profile"));
        assert!(load_profile(&dir.join("missing.json"))
            .unwrap_err()
            .contains("reading profile"));
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn edited_locked_profile_file_is_refused_observe_only() {
        let dir = std::env::temp_dir().join(format!("robodr-pl-seal-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let mut prof = profile(true);
        prof.writer_topics.insert("/cmd_vel".into());
        let sealed = robodr_commission::sealed_text(&prof).unwrap();

        // A sealed but unsigned, unversioned file through the default
        // loader (no trust anchors): not enforced. The signed path is
        // tested in `profile_trust`.
        let good = dir.join("sealed.json");
        std::fs::write(&good, &sealed).unwrap();
        let p = Pipeline::from_loaded(load_profile(&good).unwrap(), PipelineOptions::default());
        assert!(matches!(p.status(), ProfileStatus::FileRejected(_)));
        assert_eq!(p.status_findings().len(), 1);

        // A participant added by hand after locking: seal mismatch.
        let edited = dir.join("edited.json");
        let text = sealed.replace(KNOWN_HEX, "eeeeeeeeeeeeeeeeeeeeeeee");
        assert_ne!(text, sealed);
        std::fs::write(&edited, &text).unwrap();
        let loaded = load_profile(&edited).unwrap();
        assert!(loaded.profile.locked);
        let mut p = Pipeline::from_loaded(loaded, PipelineOptions::default());
        let ProfileStatus::FileRejected(why) = p.status().clone() else {
            panic!("expected file rejection, got {:?}", p.status());
        };
        assert!(why.contains("seal"), "{why}");
        assert_eq!(p.mode(), Mode::Observe);
        assert!(p.status_message().unwrap().contains("REFUSED"));
        let sf = p.status_findings();
        assert_eq!(sf.len(), 1);
        assert_eq!(sf[0].deviation.rule, rules::PROFILE_REFUSED);
        assert_eq!(sf[0].profile_status, "refused");
        // Still watching, observe-only.
        let f = p.process(&header([0xff; 12]), "10.0.0.9");
        assert_eq!(f.len(), 1);
        assert!(f[0].is_observe_only());

        // Locked flipped on by hand (no seal): refused too.
        let flipped = dir.join("flipped.json");
        let mut draft = prof.clone();
        draft.locked = false;
        let text = serde_json::to_string_pretty(&draft)
            .unwrap()
            .replace("\"locked\": false", "\"locked\": true");
        std::fs::write(&flipped, text).unwrap();
        let p = Pipeline::from_loaded(load_profile(&flipped).unwrap(), PipelineOptions::default());
        assert!(matches!(p.status(), ProfileStatus::FileRejected(_)));

        // An unlocked draft with a file problem is observed, with a note.
        let draft_file = dir.join("draft.json");
        std::fs::write(&draft_file, r#"{"model":"m","locked":false}"#).unwrap();
        let p = Pipeline::from_loaded(
            load_profile(&draft_file).unwrap(),
            PipelineOptions::default(),
        );
        assert_eq!(p.status(), &ProfileStatus::Observing);
        assert!(p.status_message().unwrap().contains("profile file check"));
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn datagram_entry_point_matches_slice_entry_point() {
        let mut p = pl(true, 16);
        let d = Datagram::new(header([0xff; 12]), "10.0.0.9");
        assert_eq!(p.process_datagram(&d).len(), 1);
        assert!(p.process(&d.payload, &d.src_ip).is_empty());
        assert!(format!("{p:?}").contains("amr-v1"));
    }
}
