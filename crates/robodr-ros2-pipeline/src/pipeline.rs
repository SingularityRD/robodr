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
//! | a *profiled* participant announced as disposed / unregistered | [`rules::PARTICIPANT_REMOVED`] | Medium |
//! | a parse [`Anomaly`](robodr_rtps::Anomaly) (if `report_anomalies`) | [`rules::MALFORMED_DISCOVERY`] | Low |
//! | discovery `DATA_FRAG` seen (if `report_fragmentation`) | [`rules::FRAGMENTED_DISCOVERY`] | Low |
//! | discovery fragments refused by the reassembler (always) | [`rules::DISCOVERY_FRAGMENT_REJECTED`] | Medium |
//! | the profile failed `Profile::validate` (once, [`Pipeline::status_findings`]) | [`rules::PROFILE_REFUSED`] | High |
//!
//! Removals of unknown participants and endpoint removals are only counted
//! ([`PipelineStats`]): the unknown participant was already reported when it
//! appeared, and an endpoint removal carries no topic to judge it by.
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
//! - No rate limit on *distinct* findings: an attacker announcing a new GUID
//!   per packet produces one finding per packet (each a true positive, the
//!   dedup set stays bounded). Downstream consumers should aggregate.
//! - Dedup is forever-until-evicted: a participant that leaves and comes back
//!   is not re-reported unless its entry was evicted.
//! - Text copied into findings is attacker controlled and passed through
//!   [`sanitize`].

use std::fmt;
use std::io::Read;
use std::path::Path;

use robodr_events::profile::{Profile, ProfileError};
use robodr_events::{Deviation, Mode, Severity};
use robodr_rtps::{hex12, DatagramReport, FragmentReassembler, ReassemblyLimits};
use serde::Serialize;

use crate::dedup::DedupSet;
use crate::sanitize::sanitize;
use crate::source::Datagram;

/// Prefix added to the threat description of every observe-only finding.
pub const OBSERVE_ONLY_TAG: &str = "[observe-only] ";

/// Default dedup capacity.
pub const DEFAULT_DEDUP_CAPACITY: usize = 4096;

/// Largest profile file accepted by [`load_profile`].
pub const MAX_PROFILE_BYTES: u64 = 16 << 20;

/// `src_ip` of findings that do not come from the network.
pub const LOCAL_SOURCE: &str = "local";

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
    /// Discovery fragments were refused (over a cap, bad geometry or a
    /// conflicting overlap): that announcement was **not** inspected.
    pub const DISCOVERY_FRAGMENT_REJECTED: &str = "robot.rtps.discovery_fragment_rejected";
}

/// Knobs of the pipeline.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PipelineOptions {
    /// Max distinct findings remembered for dedup (clamped to 1..=2^20).
    pub dedup_capacity: usize,
    /// Caps of the RTPS DATA_FRAG reassembler.
    pub reassembly: ReassemblyLimits,
    /// Raise a Low finding per parse anomaly kind and source IP.
    pub report_anomalies: bool,
    /// Raise a Low finding per source IP that sends fragmented discovery.
    pub report_fragmentation: bool,
}

impl Default for PipelineOptions {
    fn default() -> Self {
        Self {
            dedup_capacity: DEFAULT_DEDUP_CAPACITY,
            reassembly: ReassemblyLimits::default(),
            report_anomalies: true,
            report_fragmentation: true,
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
            Self::Observing | Self::Refused(_) => Mode::Observe,
        }
    }

    /// `"enforcing"`, `"observing"` or `"refused"`.
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Enforcing => "enforcing",
            Self::Observing => "observing",
            Self::Refused(_) => "refused",
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

/// Read and parse a profile (JSON). Validation is **not** done here; it is
/// done by [`Pipeline::new`] so that an invalid profile still yields an
/// observe-only pipeline instead of a blind sensor. An unreadable or
/// unparseable file is an error (there is nothing to observe against).
pub fn load_profile(path: &Path) -> Result<Profile, String> {
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
    serde_json::from_str(&raw).map_err(|e| format!("parsing profile {}: {e}", path.display()))
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
}

/// Datagram -> findings, against one profile. See the module docs.
pub struct Pipeline {
    profile: Profile,
    status: ProfileStatus,
    seen: DedupSet,
    reassembler: FragmentReassembler,
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
            .field("opts", &self.opts)
            .field("stats", &self.stats)
            .finish()
    }
}

impl Pipeline {
    /// Validate the profile ([`ProfileStatus::of`]) and build the pipeline.
    pub fn new(profile: Profile, opts: PipelineOptions) -> Self {
        Self {
            status: ProfileStatus::of(&profile),
            profile,
            seen: DedupSet::new(opts.dedup_capacity),
            reassembler: FragmentReassembler::new(opts.reassembly),
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

    pub fn stats(&self) -> &PipelineStats {
        &self.stats
    }

    /// Number of distinct findings currently remembered.
    pub fn remembered(&self) -> usize {
        self.seen.len()
    }

    /// The DATA_FRAG reassembler (for its counters).
    pub fn reassembler(&self) -> &FragmentReassembler {
        &self.reassembler
    }

    /// A one-line, sanitised operator warning when the profile is not
    /// enforced (`None` when enforcing). For `raise_warning` / stderr.
    pub fn status_message(&self) -> Option<String> {
        let model = sanitize(&self.profile.model);
        match &self.status {
            ProfileStatus::Enforcing => None,
            ProfileStatus::Observing => Some(format!(
                "profile '{model}' is NOT locked: observe mode, findings are tagged observe-only"
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
    /// finding when it failed validation, otherwise none. Report these once
    /// at start-up.
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

    /// Dedup and stamp one raw deviation.
    fn push(&mut self, out: &mut Vec<Finding>, deviation: Deviation, src_ip: &str) {
        self.stats.raw_findings += 1;
        let key = format!("{}|{}", deviation.rule, deviation.detail);
        if !self.seen.insert(&key) {
            self.stats.duplicates += 1;
            return;
        }
        self.stats.findings += 1;
        out.push(self.finding(deviation, src_ip));
    }

    /// Parse one datagram and return the findings not reported before.
    /// Never panics: malformed or non-RTPS input yields at most protocol
    /// findings.
    pub fn process(&mut self, payload: &[u8], src_ip: &str) -> Vec<Finding> {
        self.stats.datagrams += 1;
        let Some(report) = self.reassembler.parse_datagram_detailed(payload) else {
            self.stats.not_rtps += 1;
            return Vec::new();
        };
        let mut out = Vec::new();
        self.profile_findings(&report, src_ip, &mut out);
        self.removal_findings(&report, src_ip, &mut out);
        self.protocol_findings(&report, src_ip, &mut out);
        out
    }

    pub fn process_datagram(&mut self, datagram: &Datagram) -> Vec<Finding> {
        self.process(&datagram.payload, &datagram.src_ip)
    }

    fn profile_findings(&mut self, report: &DatagramReport, src_ip: &str, out: &mut Vec<Finding>) {
        for event in report.to_events(src_ip) {
            self.stats.events += 1;
            if let Some(dev) = self.profile.evaluate(&event) {
                self.push(out, dev, src_ip);
            }
        }
    }

    fn removal_findings(&mut self, report: &DatagramReport, src_ip: &str, out: &mut Vec<Finding>) {
        self.stats.endpoint_removals += report.removed_endpoints.len() as u64;
        for r in &report.removed_participants {
            self.stats.participant_removals += 1;
            let guid = hex12(&r.guid_prefix);
            if !self.profile.participants.contains(&guid) {
                continue;
            }
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
            let detail =
                format!("profiled participant {guid} announced as {what}{by} from {src_ip}");
            self.push(
                out,
                Deviation::new(rules::PARTICIPANT_REMOVED, Severity::Medium, detail),
                src_ip,
            );
        }
    }

    fn protocol_findings(&mut self, report: &DatagramReport, src_ip: &str, out: &mut Vec<Finding>) {
        let s = &report.stats;
        self.stats.anomalies += u64::from(s.anomalies);
        self.stats.discovery_fragments += u64::from(s.discovery_data_frag);
        self.stats.fragment_samples_completed += u64::from(s.frag_completed);
        self.stats.fragments_rejected += u64::from(s.frag_rejected);

        if self.opts.report_anomalies {
            let mut kinds: Vec<String> = Vec::new();
            for a in &report.anomalies {
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
        if s.frag_rejected > 0 {
            let detail = format!(
                "discovery fragments from {src_ip} refused by the reassembler (over a size cap, \
                 inconsistent geometry or conflicting overlap); that announcement was not inspected"
            );
            self.push(
                out,
                Deviation::new(rules::DISCOVERY_FRAGMENT_REJECTED, Severity::Medium, detail),
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
        prof.motion_envelopes.insert(
            "/cmd_vel".into(),
            Envelope {
                max_linear_speed: Some(f64::NAN),
                max_joint_speed: None,
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
        assert_eq!(f.len(), 1, "{f:?}");
        assert_eq!(f[0].deviation.rule, rules::MALFORMED_DISCOVERY);
        assert_eq!(f[0].deviation.severity, Severity::Low);
        assert!(p.process(&d, "10.0.0.5").is_empty());
        assert!(p.stats().anomalies >= 2);
        // Disabled: counted only.
        let mut q = Pipeline::new(
            profile(true),
            PipelineOptions {
                report_anomalies: false,
                ..Default::default()
            },
        );
        assert!(q.process(&d, "10.0.0.5").is_empty());
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
        let f = out.remove(0);
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
        assert!(load_profile(&ok).unwrap().locked);
        let bad = dir.join("bad.json");
        std::fs::write(&bad, "{not json").unwrap();
        assert!(load_profile(&bad).unwrap_err().contains("parsing profile"));
        assert!(load_profile(&dir.join("missing.json"))
            .unwrap_err()
            .contains("reading profile"));
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
