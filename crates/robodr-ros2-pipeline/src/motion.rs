//! Live motion decode path: RTPS user DATA on motion topics →
//! `MotionCommand` / `MotionFeedback`.
//!
//! Discovery tells the pipeline *who* may write `/cmd_vel`; this module looks
//! at *what* they write. For every datagram it:
//!
//! 1. **learns** writer GUID → (topic, type name) and reader GUID → topic
//!    from the SEDP announcements the discovery parser already decoded
//!    (bounded tables, see [`MotionOptions::max_writers`]);
//! 2. walks the datagram's **user DATA** with `robodr-rtps`'s
//!    [`UserDataWalker`] (INFO_SRC / INFO_DST / INFO_TS, both endiannesses,
//!    DATA and DATA_FRAG with a per-writer reassembly quota), keeping only
//!    samples whose writer is announced on a **profiled motion channel**
//!    (`profile.motion_envelopes`) or a **configured feedback topic**
//!    ([`MotionOptions::feedback_topics`]); nothing else is copied or
//!    buffered;
//! 3. **decodes** each kept sample with `robodr-cdr`'s [`Registry`], by the
//!    type name SEDP announced for that writer (never by guessing from the
//!    bytes), and maps it with `to_event` and an [`EventContext`] built from
//!    the transport only: channel = de-mangled topic, writer GUID = the
//!    DATA's writer, timestamp = the caller's **capture** time (the INFO_TS
//!    source timestamp is a sender claim; it is exposed, never used as time);
//! 4. evaluates each `MotionCommand` with `Profile::evaluate` (the envelope,
//!    non-finite and unprofiled-channel rules of `robodr-events`) unless
//!    [`MotionOptions::evaluate_commands`] is off (a consumer that runs the
//!    same evaluation itself, e.g. `robodr-agentd`'s agent chain);
//! 5. returns the decoded events as [`MotionSample`]s
//!    ([`crate::Pipeline::process_with_motion_at`]).
//!
//! # Findings
//!
//! | When | Rule | Severity |
//! |---|---|---|
//! | a sample on a motion / feedback topic that cannot be inspected: undecodable payload (truncated, unknown encapsulation id (anything outside XTypes 1.3 Table 60), `PL_CDR`, over a cap, malformed string), unknown type name, a type of the wrong role for the topic (feedback type on a command channel or the reverse), non-standard payload, malformed DATA / inline QoS, fragments refused / evicted / conflicting, per-datagram sample cap | [`rules::MOTION_UNDECODABLE_SAMPLE`] | Medium, rate limited (`robot.motion.undecodable_sample` bucket), dedup by channel + writer + reason |
//! | DATA addressed to a reader entity announced on a motion / feedback topic, from a writer **never announced via SEDP** (cannot be attributed, so cannot be checked against the profile) | [`rules::MOTION_UNATTRIBUTED_SAMPLE`] | High, dedup by writer + topic |
//! | a decoded sample whose writer prefix is bound to other source IPs than the one it came from (binding table, [`crate::binding`]): somebody speaks for a profiled writer | [`rules::MOTION_SAMPLE_SOURCE_MISMATCH`] | Critical on a command channel, High on a feedback topic |
//! | a decoded sample whose writer prefix is **contested** (claimed by SPDP from two hosts, unpinned): no source is trusted for it | [`rules::MOTION_SAMPLE_SOURCE_MISMATCH`] | Critical on a command channel, High on a feedback topic |
//! | a decoded sample whose writer was announced via SEDP but whose participant has **no binding** (no SPDP seen, not pinned, binding expired) or whose datagram source IP does not parse, while the binding check is on | [`rules::MOTION_UNATTRIBUTED_SAMPLE`] | High |
//! | a decoded command whose speed cannot be bounded from the message (`JointTrajectory` with no velocities and fewer than two points with positions; `robodr_cdr::DecodeAnomaly::UnverifiableCommand`): no envelope can check it | [`rules::MOTION_UNVERIFIABLE_COMMAND`] | Medium, dedup by channel + writer |
//! | a decoded sample with more bytes after the message than XCDR end padding explains (> 3, `robodr_cdr::DecodeAnomaly::ExcessTrailingBytes`): DDS readers ignore them, nothing standard sends them | [`rules::MOTION_DECODE_ANOMALY`] | Low, dedup by channel + writer + kind (byte count not in the dedup key) |
//! | every decoded `MotionCommand` (if `evaluate_commands`) | the profile's motion rules (`robot.motion.linear_over_envelope`, `angular_over_envelope`, `joint_over_envelope`, `non_finite_command`, `unprofiled_channel`, `robot.profile.invalid_envelope`) | as `robodr-events` decides (Critical for over-envelope / non-finite) |
//!
//! A writer on a motion topic that is not in the profile is already the
//! discovery rule `robot.ros2.unauthorized_motion_writer` (Critical); its
//! commands are still decoded and evaluated, so the firewall / monitor see
//! what it actually sent.
//!
//! # Trust and limits
//!
//! * Every GUID and timestamp on the wire is a claim (no DDS-Security). The
//!   writer → topic mapping is only as good as the SEDP it came from, which
//!   the binding check judges; DATA itself is judged against the binding
//!   with the safety feed's rule: only `allows_from == Some(true)` is
//!   trusted. Each [`MotionSample`] carries the verdict
//!   ([`MotionSample::attribution`]); a sample that is unbound, contested or
//!   source-mismatched is still decoded and handed on (so the firewall /
//!   monitor see what was sent) with a finding, and consumers must not let
//!   its writer GUID authorise anything (`robodr-agentd` drops the GUID of
//!   such a command, so the firewall model sees an unknown source). With the
//!   binding check disabled the verdict is
//!   [`SampleAttribution::NotChecked`] (no finding, not trusted).
//! * Removals (SEDP dispose) do **not** forget a writer: a spoofed dispose
//!   must not blind the decoder. Entries are evicted only by the table bound
//!   (least recently announced, non-motion entries first).
//! * A writer announced before the sensor started is unknown until its
//!   participant re-announces it (SEDP is not periodic): its samples are not
//!   decoded meanwhile, and samples to a known motion reader raise the
//!   unattributed finding. `MotionStats::unattributed` counts them.
//! * Shared-memory transports, RTPS over TCP and DDS-Security payload /
//!   submessage protection are invisible or opaque. Protected payloads on a
//!   motion topic fail to decode and are reported as undecodable.
//! * Only synthetic datagrams (hand-built RTPS + CDR from the spec) have been
//!   run through this path; no capture of a real RMW (Fast DDS, Cyclone DDS)
//!   was available.

use std::collections::{BTreeSet, HashMap};
use std::net::IpAddr;

use robodr_cdr::{DecodeAnomaly, DecodeError, EventContext, Limits, MotionRole, Registry};
use robodr_events::graph::{demangle, RosNameKind};
use robodr_events::profile::Profile;
use robodr_events::{Deviation, RobotEvent, Severity};
use robodr_rtps::{
    hex_guid, DatagramReport, EndpointKind, EntityId, FragmentEventKind, Guid, PayloadKind,
    RtpsTime, SampleAddress, UserDataLimits, UserDataWalker, GUIDPREFIX_UNKNOWN,
};
use serde::Serialize;

use crate::binding::{BindingTable, Ingress};

/// Rule ids raised by the motion decode path.
pub mod rules {
    /// A sample on a motion / feedback topic that could not be inspected.
    /// Medium, rate limited.
    pub const MOTION_UNDECODABLE_SAMPLE: &str = "robot.motion.undecodable_sample";
    /// DATA to a motion / feedback reader from a writer never announced via
    /// SEDP. High.
    pub const MOTION_UNATTRIBUTED_SAMPLE: &str = "robot.motion.unattributed_sample";
    /// A decoded motion sample from a source IP not bound to its writer's
    /// participant. Critical (command) / High (feedback).
    pub const MOTION_SAMPLE_SOURCE_MISMATCH: &str = "robot.motion.sample_source_mismatch";
    /// A decoded command whose speed cannot be bounded from the message, so
    /// no envelope can check it. Medium.
    pub const MOTION_UNVERIFIABLE_COMMAND: &str = "robot.motion.unverifiable_command";
    /// A decoded sample with an oddity that does not stop decoding (e.g.
    /// trailing bytes beyond XCDR end padding). Low.
    pub const MOTION_DECODE_ANOMALY: &str = "robot.motion.decode_anomaly";
}

/// Default [`MotionOptions::max_writers`] / `max_readers`.
pub const DEFAULT_MAX_ENDPOINTS: usize = 4096;
/// Largest [`MotionOptions::max_writers`] / `max_readers`.
pub const MAX_MAX_ENDPOINTS: usize = 65_536;
/// Distinct (topic, type) readings kept per endpoint GUID.
pub const MAX_READINGS_PER_ENDPOINT: usize = 4;
/// Unattributed addresses examined per datagram (the rest are counted).
const MAX_UNATTRIBUTED_PER_DATAGRAM: usize = 64;

/// Knobs of the motion decode path.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MotionOptions {
    /// Decode user DATA at all (default on).
    pub enabled: bool,
    /// ROS topic names (`/odom`, `/joint_states`) whose samples are decoded
    /// as feedback, in addition to the profile's motion channels (commands).
    pub feedback_topics: BTreeSet<String>,
    /// Evaluate decoded commands with `Profile::evaluate` and report the
    /// deviations (default on). `robodr-agentd` turns it off: its agent
    /// evaluates the same events itself, with evidence.
    pub evaluate_commands: bool,
    /// Bound of the writer GUID → topic table (1..=[`MAX_MAX_ENDPOINTS`]).
    pub max_writers: usize,
    /// Bound of the reader GUID → topic table (1..=[`MAX_MAX_ENDPOINTS`]).
    pub max_readers: usize,
    /// Caps of the CDR decoder.
    pub cdr_limits: Limits,
    /// Caps of the user-data walker (reassembly, samples per datagram).
    pub user_data: UserDataLimits,
}

impl Default for MotionOptions {
    fn default() -> Self {
        Self {
            enabled: true,
            feedback_topics: BTreeSet::new(),
            evaluate_commands: true,
            max_writers: DEFAULT_MAX_ENDPOINTS,
            max_readers: DEFAULT_MAX_ENDPOINTS,
            cdr_limits: Limits::default(),
            user_data: UserDataLimits::default(),
        }
    }
}

/// One decoded motion sample, ready for the agent chain.
#[derive(Debug, Clone, PartialEq)]
pub struct MotionSample {
    /// `RobotEvent::MotionCommand` or `RobotEvent::MotionFeedback`
    /// (channel = de-mangled topic, writer GUID, capture timestamp).
    pub event: RobotEvent,
    /// Source IP of the datagram.
    pub src_ip: String,
    /// Writer GUID, 32 lower-case hex digits.
    pub writer_guid: String,
    /// RTPS topic as announced (`rt/cmd_vel`).
    pub topic: String,
    /// DDS type name as announced.
    pub type_name: String,
    pub sequence_number: i64,
    /// INFO_TS of the sample: a **sender claim**, informational only.
    pub source_timestamp: Option<RtpsTime>,
    /// The capture timestamp passed by the caller (also in the event).
    pub capture_ns: u64,
    /// Reassembled from DATA_FRAG.
    pub from_fragments: bool,
    /// Bytes after the decoded message (XCDR padding or appended members;
    /// more than 3 is also a [`rules::MOTION_DECODE_ANOMALY`] finding).
    pub trailing_bytes: usize,
    /// What the binding table says about the sample's source. Only
    /// [`SampleAttribution::Bound`] means the writer GUID may be taken at
    /// its word; see [`SampleAttribution::is_trusted`].
    pub attribution: SampleAttribution,
}

/// How a decoded sample's source was judged against the participant
/// binding ([`crate::binding`]). The writer GUID in the sample is a claim;
/// only `Bound` vouches for it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum SampleAttribution {
    /// The binding accepts the source IP for the writer's prefix
    /// (`allows_from == Some(true)`).
    Bound,
    /// The binding check is disabled and nothing pins the prefix: the
    /// operator chose not to attribute sources. Not a finding, but not
    /// trusted either.
    NotChecked,
    /// The binding check is on but the writer's participant has no binding
    /// (no SPDP seen, not pinned, or the binding expired), or the datagram's
    /// source IP could not be parsed. [`rules::MOTION_UNATTRIBUTED_SAMPLE`].
    Unbound,
    /// The writer's prefix is contested (claimed by SPDP from two hosts):
    /// no source is trusted for it. [`rules::MOTION_SAMPLE_SOURCE_MISMATCH`].
    Contested,
    /// The source IP is outside the writer's binding.
    /// [`rules::MOTION_SAMPLE_SOURCE_MISMATCH`].
    SourceMismatch,
}

impl SampleAttribution {
    /// Only a bound source is trusted; every other verdict (including "no
    /// binding yet") means the writer GUID must not authorise anything.
    pub fn is_trusted(self) -> bool {
        self == SampleAttribution::Bound
    }

    /// Unbound, contested or mismatched: the binding check ran and did not
    /// vouch for the source (a finding was raised).
    pub fn is_refused(self) -> bool {
        matches!(
            self,
            SampleAttribution::Unbound
                | SampleAttribution::Contested
                | SampleAttribution::SourceMismatch
        )
    }
}

/// Counters of the motion decode path.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize)]
pub struct MotionStats {
    /// User samples on motion / feedback topics handed to the decoder.
    pub samples: u64,
    pub commands: u64,
    pub feedback: u64,
    /// Samples that were not inspected (undecodable, unknown type, ...).
    pub undecodable: u64,
    /// DATA to a motion reader from a writer never announced via SEDP, and
    /// decoded samples whose writer's participant has no binding.
    pub unattributed: u64,
    /// Decoded samples from a source IP outside the writer's binding, or
    /// from a writer whose prefix is contested.
    pub source_mismatch: u64,
    /// Decoded commands whose speed could not be bounded.
    pub unverifiable: u64,
    /// Decoded samples with a decode anomaly (excess trailing bytes).
    pub anomalies: u64,
    /// Key-only / no-payload samples on motion topics (dispose etc.).
    pub not_data: u64,
    /// Writers / readers currently known.
    pub writers_known: u64,
    pub readers_known: u64,
    /// Table evictions (bounded tables).
    pub writers_evicted: u64,
    pub readers_evicted: u64,
    /// User fragments refused / evicted on motion topics.
    pub fragments_refused: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Role {
    Command,
    Feedback,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct Reading {
    topic: String,
    type_name: String,
    /// The de-mangled channel and its role, when it is a motion / feedback
    /// topic.
    motion: Option<(String, Role)>,
}

#[derive(Debug, Clone)]
struct Entry {
    readings: Vec<Reading>,
    last_seen: u64,
}

impl Entry {
    fn is_motion(&self) -> bool {
        self.readings.iter().any(|r| r.motion.is_some())
    }
}

/// Bounded GUID → readings table. Eviction: least recently announced
/// non-motion entry first, then least recently announced overall.
#[derive(Debug, Default)]
struct Table {
    map: HashMap<Guid, Entry>,
    cap: usize,
    clock: u64,
    evicted: u64,
}

impl Table {
    fn new(cap: usize) -> Self {
        Self {
            cap: cap.clamp(1, MAX_MAX_ENDPOINTS),
            ..Self::default()
        }
    }

    /// Record a reading; returns the GUID of an evicted entry, if any.
    fn learn(&mut self, guid: Guid, reading: Reading) -> Option<(Guid, Entry)> {
        self.clock += 1;
        let clock = self.clock;
        if let Some(e) = self.map.get_mut(&guid) {
            e.last_seen = clock;
            if e.readings.contains(&reading) {
                return None;
            }
            if e.readings.len() < MAX_READINGS_PER_ENDPOINT {
                e.readings.push(reading);
            } else if reading.motion.is_some() {
                // Never let junk readings displace a motion reading; a
                // motion reading may displace the newest non-motion one.
                if let Some(i) = e.readings.iter().rposition(|r| r.motion.is_none()) {
                    e.readings[i] = reading;
                }
            }
            return None;
        }
        let mut evicted = None;
        if self.map.len() >= self.cap {
            let victim = self
                .map
                .iter()
                .min_by_key(|(_, e)| (e.is_motion(), e.last_seen))
                .map(|(g, _)| *g);
            if let Some(g) = victim {
                evicted = self.map.remove(&g).map(|e| (g, e));
                self.evicted += 1;
            }
        }
        self.map.insert(
            guid,
            Entry {
                readings: vec![reading],
                last_seen: clock,
            },
        );
        evicted
    }
}

/// State of the motion decode path. Owned by [`crate::Pipeline`].
pub struct MotionTracker {
    opts: MotionOptions,
    registry: Registry,
    walker: UserDataWalker,
    writers: Table,
    readers: Table,
    /// Reader entity ids of motion / feedback readers → number of such
    /// readers (for DATA addressed without INFO_DST).
    motion_reader_entities: HashMap<EntityId, u32>,
    stats: MotionStats,
}

impl std::fmt::Debug for MotionTracker {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("MotionTracker")
            .field("opts", &self.opts)
            .field("stats", &self.stats)
            .finish()
    }
}

/// Stable name of a decode error (dedup key; the values are in the stats).
fn decode_error_kind(e: &DecodeError) -> String {
    match e {
        DecodeError::MissingEncapsulation => "missing encapsulation header".into(),
        DecodeError::UnknownRepresentation(id) => format!("unknown encapsulation 0x{id:04x}"),
        DecodeError::UnsupportedRepresentation(r) => format!("unsupported encapsulation {r:?}"),
        DecodeError::PayloadTooLarge { max, .. } => format!("payload over the {max}-byte cap"),
        DecodeError::Truncated { .. } => "truncated payload".into(),
        DecodeError::StringTooLong { .. } => "string over the cap".into(),
        DecodeError::StringNotTerminated { .. } => "string not NUL-terminated".into(),
        DecodeError::StringLengthZero { .. } => "string with length 0".into(),
        DecodeError::SequenceTooLong { .. } => "sequence over the cap".into(),
        DecodeError::DelimiterOutOfBounds { .. } | DecodeError::DelimiterOverrun { .. } => {
            "bad XCDR2 DHEADER".into()
        }
        DecodeError::UnknownType => "no decoder for the announced type".into(),
    }
}

fn short(s: &str) -> String {
    s.chars().take(96).collect()
}

/// What one datagram produced: deviations (attributed to the datagram's
/// source IP) and decoded samples.
#[derive(Debug, Default)]
pub(crate) struct MotionOutput {
    pub deviations: Vec<Deviation>,
    pub samples: Vec<MotionSample>,
}

/// Per-datagram context.
pub(crate) struct DatagramCtx<'a> {
    pub src_ip: &'a str,
    pub ip: Option<IpAddr>,
    pub ingress: Ingress,
    pub capture_ns: u64,
}

impl MotionTracker {
    pub fn new(opts: MotionOptions) -> Self {
        Self {
            registry: Registry::with_builtin(),
            walker: UserDataWalker::new(opts.user_data),
            writers: Table::new(opts.max_writers),
            readers: Table::new(opts.max_readers),
            motion_reader_entities: HashMap::new(),
            stats: MotionStats::default(),
            opts,
        }
    }

    pub fn options(&self) -> &MotionOptions {
        &self.opts
    }

    pub fn stats(&self) -> MotionStats {
        let mut s = self.stats;
        s.writers_known = self.writers.map.len() as u64;
        s.readers_known = self.readers.map.len() as u64;
        s.writers_evicted = self.writers.evicted;
        s.readers_evicted = self.readers.evicted;
        s
    }

    /// The registry used to decode (add vendor type names with
    /// [`Registry::register`]).
    pub fn registry_mut(&mut self) -> &mut Registry {
        &mut self.registry
    }

    /// The topic's channel and role, if it is a motion command channel of
    /// the profile or a configured feedback topic.
    fn classify(&self, profile: &Profile, topic: &str) -> Option<(String, Role)> {
        let rn = demangle(topic);
        if !matches!(
            rn.kind,
            RosNameKind::Topic
                | RosNameKind::ActionPart {
                    role: robodr_events::graph::ActionRole::Topic,
                    ..
                }
        ) {
            return None;
        }
        if profile.motion_envelopes.contains_key(&rn.name) {
            Some((rn.name, Role::Command))
        } else if rn.kind == RosNameKind::Topic && self.opts.feedback_topics.contains(&rn.name) {
            Some((rn.name, Role::Feedback))
        } else {
            None
        }
    }

    /// Learn writer / reader GUIDs from the SEDP announcements of `report`
    /// (every reading, alternates included).
    pub(crate) fn learn(&mut self, profile: &Profile, report: &DatagramReport) {
        for ep in &report.endpoints {
            let mut readings: Vec<(Guid, String, String)> = Vec::new();
            if let Some(g) = ep.guid {
                readings.push((g, ep.topic.clone(), ep.type_name.clone()));
            }
            for a in &ep.alternates {
                if let Some(g) = a.guid.or(ep.guid) {
                    readings.push((g, a.topic.clone(), a.type_name.clone()));
                }
            }
            for (guid, topic, type_name) in readings {
                let motion = self.classify(profile, &topic);
                let reading = Reading {
                    topic,
                    type_name,
                    motion,
                };
                match ep.kind {
                    EndpointKind::Writer => {
                        self.writers.learn(guid, reading);
                    }
                    EndpointKind::Reader => {
                        let entity: EntityId = guid[12..].try_into().unwrap_or_default();
                        let was_motion = self.readers.map.get(&guid).is_some_and(Entry::is_motion);
                        let evicted = self.readers.learn(guid, reading);
                        let is_motion = self.readers.map.get(&guid).is_some_and(Entry::is_motion);
                        if is_motion && !was_motion {
                            *self.motion_reader_entities.entry(entity).or_insert(0) += 1;
                        }
                        if let Some((g, e)) = evicted {
                            if e.is_motion() {
                                let ent: EntityId = g[12..].try_into().unwrap_or_default();
                                if let Some(n) = self.motion_reader_entities.get_mut(&ent) {
                                    *n = n.saturating_sub(1);
                                    if *n == 0 {
                                        self.motion_reader_entities.remove(&ent);
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }
    }

    fn undecodable(&mut self, out: &mut MotionOutput, channel: &str, writer: &str, why: &str) {
        self.stats.undecodable += 1;
        out.deviations.push(Deviation::new(
            rules::MOTION_UNDECODABLE_SAMPLE,
            Severity::Medium,
            format!(
                "motion sample on {} from writer {writer} was not inspected: {why}",
                short(channel)
            ),
        ));
    }

    /// The first motion channel of a known writer (for findings).
    fn writer_channel(&self, writer: &Guid) -> Option<String> {
        self.writers
            .map
            .get(writer)
            .and_then(|e| e.readings.iter().find_map(|r| r.motion.clone()))
            .map(|(c, _)| c)
    }

    /// Walk the user DATA of one datagram. See the module docs.
    pub(crate) fn process(
        &mut self,
        payload: &[u8],
        ctx: &DatagramCtx<'_>,
        profile: &Profile,
        binding: &BindingTable,
    ) -> MotionOutput {
        let mut out = MotionOutput::default();
        if !self.opts.enabled {
            return out;
        }
        // Wanted: writers announced on a motion / feedback topic. Unknown
        // writers addressing a motion reader are noted, never buffered.
        let mut unattributed: Vec<(SampleAddress, String)> = Vec::new();
        let mut unattributed_more = 0u64;
        let report = {
            let Self {
                walker,
                writers,
                readers,
                motion_reader_entities,
                ..
            } = self;
            walker.walk_with(payload, |a| match writers.map.get(&a.writer) {
                Some(e) => e.is_motion(),
                None => {
                    if let Some(t) = motion_reader_topic(readers, motion_reader_entities, a) {
                        if unattributed.len() < MAX_UNATTRIBUTED_PER_DATAGRAM {
                            unattributed.push((*a, t));
                        } else {
                            unattributed_more += 1;
                        }
                    }
                    false
                }
            })
        };
        let Some(report) = report else {
            return out;
        };

        self.stats.unattributed += unattributed.len() as u64 + unattributed_more;
        for (a, topic) in unattributed {
            out.deviations.push(Deviation::new(
                rules::MOTION_UNATTRIBUTED_SAMPLE,
                Severity::High,
                format!(
                    "DATA for the {} reader {} from writer {}, which was never announced via \
                     SEDP: the sample cannot be attributed or checked against the profile",
                    short(&topic),
                    hex_guid(&a.reader),
                    hex_guid(&a.writer)
                ),
            ));
        }
        for an in &report.anomalies {
            let Some(a) = an.address else { continue };
            if let Some(ch) = self.writer_channel(&a.writer) {
                let why = format!("malformed submessage ({:?})", an.kind);
                self.undecodable(&mut out, &ch, &hex_guid(&a.writer), &why);
            }
        }
        for e in &report.fragment_events {
            let Some(ch) = self.writer_channel(&e.writer) else {
                continue;
            };
            let why = match e.kind {
                FragmentEventKind::Rejected(r) => {
                    self.stats.fragments_refused += 1;
                    format!("fragments refused by the reassembler ({r:?})")
                }
                FragmentEventKind::Evicted(r) => {
                    self.stats.fragments_refused += 1;
                    format!("partial sample evicted by the reassembler ({r:?})")
                }
                FragmentEventKind::ConflictingOverlap => {
                    "fragments overlap with conflicting bytes (the first copy was inspected, a \
                     DDS stack may keep the other)"
                        .to_string()
                }
                FragmentEventKind::ConflictingInlineQos(pid) => {
                    format!("fragments carry conflicting inline QoS (PID 0x{pid:04x})")
                }
            };
            self.undecodable(&mut out, &ch, &hex_guid(&e.writer), &why);
        }
        if report.stats.samples_capped > 0 {
            let why = format!(
                "{} sample(s) beyond the per-datagram cap of {}",
                report.stats.samples_capped,
                self.walker.max_samples_per_datagram()
            );
            self.undecodable(&mut out, "motion topics", "(several)", &why);
        }

        for s in &report.samples {
            let Some(entry) = self.writers.map.get(&s.address.writer) else {
                continue;
            };
            let readings: Vec<(String, Role, String, String)> = entry
                .readings
                .iter()
                .filter_map(|r| {
                    r.motion
                        .clone()
                        .map(|(c, role)| (c, role, r.topic.clone(), r.type_name.clone()))
                })
                .collect();
            let writer = hex_guid(&s.address.writer);
            if s.payload_kind != PayloadKind::Data {
                self.stats.not_data += 1;
                continue;
            }
            for (channel, role, topic, type_name) in readings {
                self.stats.samples += 1;
                if s.non_standard_payload {
                    self.undecodable(&mut out, &channel, &writer, "non-standard payload (N flag)");
                    continue;
                }
                let decoded =
                    match self
                        .registry
                        .decode(&type_name, &s.payload, &self.opts.cdr_limits)
                    {
                        Ok(d) => d,
                        Err(e) => {
                            let why =
                                format!("{} (type {})", decode_error_kind(&e), short(&type_name));
                            self.undecodable(&mut out, &channel, &writer, &why);
                            continue;
                        }
                    };
                let (want, role_name) = match role {
                    Role::Command => (MotionRole::Command, "command"),
                    Role::Feedback => (MotionRole::Feedback, "feedback"),
                };
                if decoded.message.role() != want {
                    let why = format!(
                        "type {} is not a {role_name} type, but the topic is a {role_name} topic",
                        short(&type_name)
                    );
                    self.undecodable(&mut out, &channel, &writer, &why);
                    continue;
                }
                for an in decoded.anomalies() {
                    match an {
                        DecodeAnomaly::UnverifiableCommand { reason } => {
                            self.stats.unverifiable += 1;
                            out.deviations.push(Deviation::new(
                                rules::MOTION_UNVERIFIABLE_COMMAND,
                                Severity::Medium,
                                format!(
                                    "command on {} from writer {writer} cannot be checked against \
                                     the envelope: {reason}",
                                    short(&channel)
                                ),
                            ));
                        }
                        DecodeAnomaly::ExcessTrailingBytes { allowed, .. } => {
                            // Value-free detail: the dedup key is rule + detail.
                            self.stats.anomalies += 1;
                            out.deviations.push(Deviation::new(
                                rules::MOTION_DECODE_ANOMALY,
                                Severity::Low,
                                format!(
                                    "{role_name} sample on {} from writer {writer} carries more \
                                     than {allowed} bytes after the message (type {}); DDS \
                                     readers ignore them",
                                    short(&channel),
                                    short(&type_name)
                                ),
                            ));
                        }
                    }
                }
                let event = decoded.message.to_event(&EventContext {
                    channel: &channel,
                    writer_guid: Some(&writer),
                    timestamp_ns: ctx.capture_ns,
                });
                let attribution =
                    self.attribute(&mut out, binding, ctx, &s.address, role, &channel);
                match role {
                    Role::Command => self.stats.commands += 1,
                    Role::Feedback => self.stats.feedback += 1,
                }
                if role == Role::Command && self.opts.evaluate_commands {
                    if let Some(d) = profile.evaluate(&event) {
                        out.deviations.push(d);
                    }
                }
                out.samples.push(MotionSample {
                    event,
                    src_ip: ctx.src_ip.to_string(),
                    writer_guid: writer.clone(),
                    topic,
                    type_name,
                    sequence_number: s.address.sequence_number,
                    source_timestamp: s.source_timestamp,
                    capture_ns: ctx.capture_ns,
                    from_fragments: s.from_fragments,
                    trailing_bytes: decoded.trailing_bytes,
                    attribution,
                });
            }
        }
        out
    }
}

impl MotionTracker {
    /// Judge a decoded sample's source against the binding and raise the
    /// finding for anything but a bound source (same rule as the safety
    /// feed: only `allows_from == Some(true)` is trusted; unbound and
    /// contested are never silently accepted).
    fn attribute(
        &mut self,
        out: &mut MotionOutput,
        binding: &BindingTable,
        ctx: &DatagramCtx<'_>,
        address: &SampleAddress,
        role: Role,
        channel: &str,
    ) -> SampleAttribution {
        let prefix = address.writer_prefix();
        let writer = hex_guid(&address.writer);
        let role_name = match role {
            Role::Command => "command",
            Role::Feedback => "feedback",
        };
        let verdict = ctx
            .ip
            .map(|ip| binding.allows_from(&prefix, ip, ctx.ingress));
        let attribution = match verdict {
            Some(Some(true)) => SampleAttribution::Bound,
            Some(Some(false)) if binding.is_contested(&prefix) => SampleAttribution::Contested,
            Some(Some(false)) => SampleAttribution::SourceMismatch,
            _ if !binding.options().enabled => SampleAttribution::NotChecked,
            _ => SampleAttribution::Unbound,
        };
        let mismatch_sev = match role {
            Role::Command => Severity::Critical,
            Role::Feedback => Severity::High,
        };
        match attribution {
            SampleAttribution::Bound | SampleAttribution::NotChecked => {}
            SampleAttribution::SourceMismatch => {
                self.stats.source_mismatch += 1;
                out.deviations.push(Deviation::new(
                    rules::MOTION_SAMPLE_SOURCE_MISMATCH,
                    mismatch_sev,
                    format!(
                        "{role_name} sample on {} from writer {writer} arrived from {}, an IP \
                         not bound to its participant (spoofed writer?)",
                        short(channel),
                        ctx.src_ip
                    ),
                ));
            }
            SampleAttribution::Contested => {
                self.stats.source_mismatch += 1;
                out.deviations.push(Deviation::new(
                    rules::MOTION_SAMPLE_SOURCE_MISMATCH,
                    mismatch_sev,
                    format!(
                        "{role_name} sample on {} from writer {writer} (from {}): its \
                         participant's GUID prefix is contested (announced from more than one \
                         host), so no source is trusted for it; pin it in participant_ips",
                        short(channel),
                        ctx.src_ip
                    ),
                ));
            }
            SampleAttribution::Unbound => {
                self.stats.unattributed += 1;
                let why = if ctx.ip.is_none() {
                    "its datagram's source IP could not be parsed"
                } else {
                    "its participant has no binding (no SPDP seen from it, not pinned, or the \
                     binding expired)"
                };
                out.deviations.push(Deviation::new(
                    rules::MOTION_UNATTRIBUTED_SAMPLE,
                    Severity::High,
                    format!(
                        "{role_name} sample on {} from writer {writer} (from {}) cannot be \
                         attributed: {why}; it is not treated as authorised",
                        short(channel),
                        ctx.src_ip
                    ),
                ));
            }
        }
        attribution
    }
}

/// The motion / feedback topic a DATA to `address.reader` targets, if the
/// reader is known: by full GUID when INFO_DST named a participant, else by
/// entity id among the known motion readers.
fn motion_reader_topic(
    readers: &Table,
    motion_entities: &HashMap<EntityId, u32>,
    address: &SampleAddress,
) -> Option<String> {
    let motion_topic = |e: &Entry| {
        e.readings
            .iter()
            .find(|r| r.motion.is_some())
            .map(|r| r.topic.clone())
    };
    if address.reader_prefix() != GUIDPREFIX_UNKNOWN {
        return readers.map.get(&address.reader).and_then(motion_topic);
    }
    let entity = address.reader_entity();
    if !motion_entities.contains_key(&entity) {
        return None;
    }
    readers
        .map
        .iter()
        .filter(|(g, _)| g[12..] == entity)
        .find_map(|(_, e)| motion_topic(e))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn reading(topic: &str, motion: bool) -> Reading {
        Reading {
            topic: topic.into(),
            type_name: "T".into(),
            motion: motion.then(|| (format!("/{topic}"), Role::Command)),
        }
    }

    fn g(n: u8) -> Guid {
        [n; 16]
    }

    #[test]
    fn table_evicts_non_motion_entries_first_and_stays_bounded() {
        let mut t = Table::new(3);
        t.learn(g(1), reading("cmd", true));
        t.learn(g(2), reading("a", false));
        t.learn(g(3), reading("b", false));
        // Re-announcing refreshes; the oldest non-motion entry goes.
        t.learn(g(2), reading("a", false));
        let ev = t.learn(g(4), reading("c", false)).map(|(g, _)| g);
        assert_eq!(ev, Some(g(3)));
        for n in 5..50 {
            t.learn(g(n), reading("x", false));
            assert!(t.map.len() <= 3);
        }
        assert!(t.map.contains_key(&g(1)), "the motion writer survives");
        assert_eq!(t.evicted, 46);
        assert_eq!(Table::new(0).cap, 1);
        assert_eq!(Table::new(usize::MAX).cap, MAX_MAX_ENDPOINTS);
    }

    #[test]
    fn junk_readings_never_displace_a_motion_reading() {
        let mut t = Table::new(4);
        t.learn(g(1), reading("cmd", true));
        for i in 0..20 {
            t.learn(g(1), reading(&format!("junk{i}"), false));
        }
        let e = &t.map[&g(1)];
        assert_eq!(e.readings.len(), MAX_READINGS_PER_ENDPOINT);
        assert!(e.is_motion());
        // A motion reading displaces a junk one when full.
        t.learn(g(1), reading("cmd2", true));
        assert_eq!(
            t.map[&g(1)]
                .readings
                .iter()
                .filter(|r| r.motion.is_some())
                .count(),
            2
        );
    }

    #[test]
    fn decode_error_kinds_are_value_free() {
        let a = decode_error_kind(&DecodeError::Truncated { at: 1, need: 8 });
        let b = decode_error_kind(&DecodeError::Truncated { at: 9, need: 2 });
        assert_eq!(a, b);
        assert!(decode_error_kind(&DecodeError::UnknownType).contains("no decoder"));
    }
}
