//! The observe-mode [`Learner`]: turns a clean run's events into a draft
//! [`Profile`] (`locked: false`) plus a [`CommissioningReport`] the OEM reads
//! before locking.
//!
//! # What is learned
//!
//! * `participants`: every GUID prefix seen in an SPDP participant
//!   announcement. GUIDs seen *only* on endpoints or motion commands are not
//!   added; they are reported as a warning instead (an endpoint whose
//!   participant never announced itself is something a human should look at).
//! * Endpoint names, routed by kind exactly as `Profile::evaluate` matches
//!   them (see [`ProfileSlot`] and the table below), so that learn -> lock ->
//!   check over the same clean run gives zero deviations (property-tested in
//!   `tests/roundtrip.rs`).
//! * `motion_envelopes`: for each motion channel, per dimension (linear m/s,
//!   joint rad/s), `min(max_observed * margin, ceiling)` where the ceiling is
//!   the OEM's optional hard limit. See [`envelope_bound`] for the exact math.
//!   A channel with no valid sample in any dimension gets an empty envelope,
//!   which [`crate::ops::lock`] refuses: the OEM must decide, not the tool.
//!
//! | endpoint name ([`demangle`](robodr_events::graph::demangle))  | learned into      |
//! |---------------------------------------------------------------|-------------------|
//! | topic `rt/x` (incl. `rt/rosout`, `rt/parameter_events`)        | `writer_topics` (writers), `reader_topics` (readers, opt-in) |
//! | service `rq/xRequest`, `rr/xReply`                             | `services` (`/x`) |
//! | action part (`rq/a/_action/send_goalRequest`, `rt/a/_action/status`, ...) | `actions` (`/a`) |
//! | raw DDS name (e.g. `ros_discovery_info`, vendor tools)          | `raw_dds_topics` (exact) |
//!
//! Every ROS 2 node serves six parameter services
//! (`/node/get_parameters`, ...), so a real profile always has `services`;
//! the report warns when a ROS node (a participant writing `/rosout`) serves
//! none, or a node's set is incomplete: both mean the capture missed part of
//! discovery and the locked profile would flag healthy nodes.
//!
//! Services, actions and raw topics are learned from **writer** endpoints by
//! default. Both sides of a service or action write something (clients write
//! requests, servers write replies / feedback / status), so a complete
//! capture covers every one; a name seen only on readers points at an
//! incomplete capture and is reported (`reader_only_name`), not learned.
//!
//! ## Readers (`learn_readers`, CLI `--learn-readers`, default off)
//!
//! `Profile::reader_topics` is enforced only when non-empty. It is **not**
//! learned by default, because turning it on is a policy decision for the
//! OEM, not something a recording should decide silently: reader sets are
//! the noisiest part of a ROS 2 graph (rosbag, rqt and `ros2 topic echo`
//! subscribe to anything; launch-time-only subscribers are easily missed by
//! a capture) and a missed subscriber becomes a deviation on every boot. The
//! report always lists reader topics, and says how many were not learned, so
//! the OEM can opt in knowingly. With `learn_readers`, reader topics go to
//! `reader_topics` and reader-side services / actions / raw names are added
//! to their sets as well, since reader enforcement checks those sets too.
//!
//! # Anomalies
//!
//! Non-finite or negative speeds, empty topics/channels, ROS names that
//! `Profile::validate` would reject (whitespace or control characters) and
//! GUID prefixes that are not 24 lower-case hex chars are counted as
//! anomalies and never feed the profile. A clean run should have none; the report says so loudly.
//!
//! # Determinism
//!
//! All state lives in `BTreeMap`/`BTreeSet`; samples are sorted with
//! `f64::total_cmp`; no clocks, no hashing, no randomness. The profile depends
//! only on sets and maxima, so it is also independent of event order and of
//! the order in which learners are [`merge`](Learner::merge)d.
//!
//! # Positions
//!
//! `RobotEvent` carries no timestamp, so "first/last seen" are [`SeenAt`]
//! positions: (run index, position in that run), where position is the JSONL
//! line number, the frame ordinal for pcap input, or the event ordinal for
//! in-memory sources.

use crate::input::{CaptureDiagnostics, EventSource, InputError};
use crate::stats::SpeedStats;
use robodr_events::graph::{ActionRole, RosName, RosNameKind};
use robodr_events::profile::{Envelope, Profile};
use robodr_events::RobotEvent;
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};
use std::fmt;

/// Default safety margin applied to observed maxima.
pub const DEFAULT_MARGIN: f64 = 1.10;
/// Upper bound on the margin: beyond 10x the envelope stops meaning anything.
pub const MAX_MARGIN: f64 = 10.0;
/// Below this many valid samples per dimension, an envelope is flagged.
pub const DEFAULT_MIN_SAMPLES: u64 = 30;
/// Model name used when none is given (flagged in the report).
pub const DEFAULT_MODEL: &str = "unnamed-model";
/// At most this many anomalies are kept verbatim; all are counted.
pub const MAX_STORED_ANOMALIES: usize = 1000;
/// The parameter services every ROS 2 node serves (unless started with
/// `start_parameter_services:=false`), as the last name segment.
pub const PARAMETER_SERVICES: [&str; 6] = [
    "describe_parameters",
    "get_parameter_types",
    "get_parameters",
    "list_parameters",
    "set_parameters",
    "set_parameters_atomically",
];
/// Raw (non-ROS-mangled) DDS topics that ROS 2 itself creates. They are
/// learned like any raw topic but not flagged as unusual in the report.
/// `ros_discovery_info` carries the node-to-participant map (rmw_dds_common).
pub const ROS_INTERNAL_RAW_TOPICS: [&str; 1] = ["ros_discovery_info"];

/// Which profile set admits an endpoint, mirroring the kind-aware matching
/// of `Profile::evaluate` in robodr-events (writers: topic -> `writer_topics`;
/// service request/reply -> `services`; any action part -> `actions` by
/// action name; raw DDS -> `raw_dds_topics`, exact; readers likewise with
/// `reader_topics` in place of `writer_topics`).
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub enum ProfileSlot {
    Topic(String),
    Service(String),
    Action(String),
    Raw(String),
}

impl ProfileSlot {
    pub fn of(rn: &RosName) -> Self {
        match &rn.kind {
            RosNameKind::Topic => Self::Topic(rn.name.clone()),
            RosNameKind::ServiceRequest | RosNameKind::ServiceReply => {
                Self::Service(rn.name.clone())
            }
            RosNameKind::ActionPart { action, .. } => Self::Action(action.clone()),
            RosNameKind::Raw => Self::Raw(rn.name.clone()),
        }
    }

    pub fn name(&self) -> &str {
        match self {
            Self::Topic(n) | Self::Service(n) | Self::Action(n) | Self::Raw(n) => n,
        }
    }

    /// Would `Profile::validate` accept this name in its set? (Same rule:
    /// ROS names start with `/`, are longer than 1 and carry no whitespace or
    /// control characters; raw names must be non-empty.)
    pub fn is_valid(&self) -> bool {
        match self {
            Self::Raw(n) => !n.is_empty(),
            _ => {
                let n = self.name();
                n.len() > 1
                    && n.starts_with('/')
                    && !n.chars().any(|c| c.is_whitespace() || c.is_control())
            }
        }
    }
}

/// For a service/action endpoint: is its participant the client side?
/// Clients write requests and read replies, feedback and status; servers do
/// the opposite. `None` for plain topics and raw names.
fn is_client_side(kind: &RosNameKind, is_writer: bool) -> Option<bool> {
    match kind {
        RosNameKind::ServiceRequest
        | RosNameKind::ActionPart {
            role: ActionRole::Request,
            ..
        } => Some(is_writer),
        RosNameKind::ServiceReply
        | RosNameKind::ActionPart {
            role: ActionRole::Reply | ActionRole::Topic,
            ..
        } => Some(!is_writer),
        RosNameKind::Topic | RosNameKind::Raw => None,
    }
}

/// Learner configuration.
#[derive(Debug, Clone, PartialEq)]
pub struct LearnConfig {
    pub model: String,
    /// Multiplier on observed max speed, in `[1.0, MAX_MARGIN]`.
    pub margin: f64,
    /// OEM hard ceiling for linear speed (m/s); envelopes never exceed it.
    pub ceiling_linear: Option<f64>,
    /// OEM hard ceiling for joint speed (rad/s); envelopes never exceed it.
    pub ceiling_joint: Option<f64>,
    /// Minimum valid samples per dimension for an envelope to be trusted.
    pub min_samples: u64,
    /// Learn `reader_topics` (which turns reader-topic enforcement on) and
    /// reader-side services / actions / raw names. Off by default; see the
    /// module docs for why.
    pub learn_readers: bool,
}

impl Default for LearnConfig {
    fn default() -> Self {
        Self {
            model: DEFAULT_MODEL.into(),
            margin: DEFAULT_MARGIN,
            ceiling_linear: None,
            ceiling_joint: None,
            min_samples: DEFAULT_MIN_SAMPLES,
            learn_readers: false,
        }
    }
}

/// Invalid learner configuration.
#[derive(Debug, Clone, PartialEq)]
pub enum ConfigError {
    EmptyModel,
    InvalidMargin(f64),
    InvalidCeiling { dimension: &'static str, value: f64 },
}

impl fmt::Display for ConfigError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ConfigError::EmptyModel => write!(f, "model name must not be empty"),
            ConfigError::InvalidMargin(m) => write!(
                f,
                "margin {m} invalid: must be finite and in [1.0, {MAX_MARGIN}] \
                 (a margin below 1 would make the clean run itself deviate)"
            ),
            ConfigError::InvalidCeiling { dimension, value } => write!(
                f,
                "{dimension} ceiling {value} invalid: must be finite and > 0"
            ),
        }
    }
}

impl std::error::Error for ConfigError {}

impl LearnConfig {
    pub fn validate(&self) -> Result<(), ConfigError> {
        if self.model.trim().is_empty() {
            return Err(ConfigError::EmptyModel);
        }
        if !self.margin.is_finite() || !(1.0..=MAX_MARGIN).contains(&self.margin) {
            return Err(ConfigError::InvalidMargin(self.margin));
        }
        for (dimension, c) in [
            ("linear", self.ceiling_linear),
            ("joint", self.ceiling_joint),
        ] {
            if let Some(value) = c {
                if !value.is_finite() || value <= 0.0 {
                    return Err(ConfigError::InvalidCeiling { dimension, value });
                }
            }
        }
        Ok(())
    }
}

/// Envelope bound for one dimension: `observed_max * margin`, rounded *up*
/// to 1e-6 (so profile.json shows `0.55`, not `0.5500000000000001`, and the
/// bound is never below the observed max), then capped at `ceiling`.
/// Returns `(bound, capped_by_ceiling)`. If the product overflows, the
/// observed max itself is used (still finite, still >= every sample).
pub fn envelope_bound(observed_max: f64, margin: f64, ceiling: Option<f64>) -> (f64, bool) {
    let product = observed_max * margin;
    let scaled = if product.is_finite() {
        quantise_up(product).max(observed_max)
    } else {
        observed_max
    };
    match ceiling {
        Some(c) if scaled > c => (c, true),
        _ => (scaled, false),
    }
}

/// Round up to a multiple of 1e-6, treating values within float noise of a
/// multiple as that multiple. Values too large to scale are returned as is.
fn quantise_up(x: f64) -> f64 {
    if !x.is_finite() || x.abs() >= 1e9 {
        return x;
    }
    let q = x * 1e6;
    let r = q.round();
    let units = if (q - r).abs() <= 1e-6 { r } else { q.ceil() };
    units / 1e6
}

/// Position of an observation: run index (order runs were fed) and position
/// inside that run (JSONL line number or event ordinal).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub struct SeenAt {
    pub run: usize,
    pub position: u64,
}

impl fmt::Display for SeenAt {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "run{}:{}", self.run, self.position)
    }
}

#[derive(Debug, Clone, PartialEq)]
struct Span {
    count: u64,
    first: SeenAt,
    last: SeenAt,
}

impl Span {
    fn new(at: SeenAt) -> Self {
        Self {
            count: 1,
            first: at,
            last: at,
        }
    }
    fn hit(&mut self, at: SeenAt) {
        self.count = self.count.saturating_add(1);
        self.first = self.first.min(at);
        self.last = self.last.max(at);
    }
    fn absorb(&mut self, o: &Span) {
        self.count = self.count.saturating_add(o.count);
        self.first = self.first.min(o.first);
        self.last = self.last.max(o.last);
    }
    fn shifted(&self, runs: usize) -> Span {
        Span {
            count: self.count,
            first: shift(self.first, runs),
            last: shift(self.last, runs),
        }
    }
}

fn shift(at: SeenAt, runs: usize) -> SeenAt {
    SeenAt {
        run: at.run + runs,
        position: at.position,
    }
}

fn touch(span: &mut Option<Span>, at: SeenAt) {
    match span {
        Some(s) => s.hit(at),
        None => *span = Some(Span::new(at)),
    }
}

#[derive(Debug, Clone, Default, PartialEq)]
struct ParticipantAcc {
    span: Option<Span>,
    src_ips: BTreeSet<String>,
}

#[derive(Debug, Clone, Default, PartialEq)]
struct EndpointAcc {
    span: Option<Span>,
    participants: BTreeSet<String>,
    type_names: BTreeSet<String>,
}

/// Services, actions and raw topics: who is on which side.
#[derive(Debug, Clone, Default, PartialEq)]
struct RoleAcc {
    span: Option<Span>,
    /// Services/actions: client participants. Raw topics: writers.
    side_a: BTreeSet<String>,
    /// Services/actions: server participants. Raw topics: readers.
    side_b: BTreeSet<String>,
    /// Seen on at least one writer endpoint.
    written: bool,
    /// Actions: components seen (`send_goal`, ..., `status`).
    components: BTreeSet<String>,
    type_names: BTreeSet<String>,
}

impl RoleAcc {
    fn absorb(&mut self, o: &RoleAcc, off: usize) {
        if let Some(s) = &o.span {
            let s = s.shifted(off);
            match &mut self.span {
                Some(d) => d.absorb(&s),
                None => self.span = Some(s),
            }
        }
        self.side_a.extend(o.side_a.iter().cloned());
        self.side_b.extend(o.side_b.iter().cloned());
        self.written |= o.written;
        self.components.extend(o.components.iter().cloned());
        self.type_names.extend(o.type_names.iter().cloned());
    }
}

#[derive(Debug, Clone, Default, PartialEq)]
struct MotionAcc {
    span: Option<Span>,
    sources: BTreeSet<String>,
    linear: Vec<f64>,
    joint: Vec<f64>,
}

/// Something in the input that a clean run should not contain.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Anomaly {
    pub at: SeenAt,
    /// Stable kind, e.g. `non_finite_linear_speed`.
    pub kind: String,
    /// What it concerns (channel, topic or GUID).
    pub subject: String,
    pub detail: String,
}

/// One input run that was learned.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct RunSummary {
    pub label: String,
    pub events: u64,
    /// Present for packet-capture inputs.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub capture: Option<CaptureDiagnostics>,
}

/// Learns a draft profile from observed events. See the module docs.
#[derive(Debug, Clone, PartialEq)]
pub struct Learner {
    config: LearnConfig,
    runs: Vec<RunSummary>,
    events_by_kind: BTreeMap<String, u64>,
    participants: BTreeMap<String, ParticipantAcc>,
    writers: BTreeMap<String, EndpointAcc>,
    readers: BTreeMap<String, EndpointAcc>,
    services: BTreeMap<String, RoleAcc>,
    actions: BTreeMap<String, RoleAcc>,
    raw: BTreeMap<String, RoleAcc>,
    motion: BTreeMap<String, MotionAcc>,
    /// GUIDs referenced by endpoints/motion commands (to spot unannounced ones).
    referenced_guids: BTreeMap<String, SeenAt>,
    anomalies_total: u64,
    anomalies: Vec<Anomaly>,
}

/// The two artefacts of commissioning.
#[derive(Debug, Clone, PartialEq)]
pub struct Commissioning {
    pub profile: Profile,
    pub report: CommissioningReport,
}

impl Learner {
    /// New learner; fails on an invalid configuration.
    pub fn new(config: LearnConfig) -> Result<Self, ConfigError> {
        config.validate()?;
        Ok(Self {
            config,
            runs: Vec::new(),
            events_by_kind: BTreeMap::new(),
            participants: BTreeMap::new(),
            writers: BTreeMap::new(),
            readers: BTreeMap::new(),
            services: BTreeMap::new(),
            actions: BTreeMap::new(),
            raw: BTreeMap::new(),
            motion: BTreeMap::new(),
            referenced_guids: BTreeMap::new(),
            anomalies_total: 0,
            anomalies: Vec::new(),
        })
    }

    pub fn config(&self) -> &LearnConfig {
        &self.config
    }

    /// Start a new run (one mission / one capture). Events observed before
    /// any `start_run` go into an implicit run labelled `run0`.
    pub fn start_run(&mut self, label: impl Into<String>) {
        self.runs.push(RunSummary {
            label: label.into(),
            events: 0,
            capture: None,
        });
    }

    fn current_run(&mut self) -> usize {
        if self.runs.is_empty() {
            self.start_run("run0");
        }
        self.runs.len() - 1
    }

    /// Observe one event at the next ordinal position of the current run.
    pub fn observe(&mut self, event: &RobotEvent) {
        let run = self.current_run();
        let pos = self.runs[run].events + 1;
        self.observe_at(event, pos);
    }

    /// Observe one event at an explicit position (e.g. JSONL line number).
    pub fn observe_at(&mut self, event: &RobotEvent, position: u64) {
        let run = self.current_run();
        self.runs[run].events += 1;
        let at = SeenAt { run, position };
        let kind = match event {
            RobotEvent::Ros2ParticipantDiscovered(_) => "ros2_participant_discovered",
            RobotEvent::Ros2WriterDiscovered(_) => "ros2_writer_discovered",
            RobotEvent::Ros2ReaderDiscovered(_) => "ros2_reader_discovered",
            RobotEvent::MotionCommand(_) => "motion_command",
            RobotEvent::MotionFeedback(_) => "motion_feedback",
        };
        *self.events_by_kind.entry(kind.into()).or_insert(0) += 1;

        match event {
            RobotEvent::Ros2ParticipantDiscovered(p) => {
                self.check_guid(&p.guid_prefix, at);
                let acc = self.participants.entry(p.guid_prefix.clone()).or_default();
                touch(&mut acc.span, at);
                acc.src_ips.insert(p.src_ip.clone());
            }
            RobotEvent::Ros2WriterDiscovered(e) | RobotEvent::Ros2ReaderDiscovered(e) => {
                let is_writer = matches!(event, RobotEvent::Ros2WriterDiscovered(_));
                if e.topic.is_empty() {
                    self.anomaly(
                        at,
                        "empty_topic",
                        &e.guid_prefix,
                        "endpoint with empty topic",
                    );
                    return;
                }
                let rn = e.ros_name();
                let slot = ProfileSlot::of(&rn);
                if !slot.is_valid() {
                    let shown: String = e.topic.chars().take(128).collect();
                    self.anomaly(
                        at,
                        "invalid_ros_name",
                        &e.guid_prefix,
                        format!(
                            "endpoint name {shown:?} is not a valid ROS name (whitespace or \
                             control characters); not learned"
                        ),
                    );
                    return;
                }
                self.check_guid(&e.guid_prefix, at);
                self.reference(&e.guid_prefix, at);
                let guid = e.guid_prefix.clone();
                let client = is_client_side(&rn.kind, is_writer);
                let (map, side_a) = match &slot {
                    ProfileSlot::Topic(topic) => {
                        let map = if is_writer {
                            &mut self.writers
                        } else {
                            &mut self.readers
                        };
                        let acc = map.entry(topic.clone()).or_default();
                        touch(&mut acc.span, at);
                        acc.participants.insert(guid);
                        if !e.type_name.is_empty() {
                            acc.type_names.insert(e.type_name.clone());
                        }
                        return;
                    }
                    ProfileSlot::Service(_) => (&mut self.services, client == Some(true)),
                    ProfileSlot::Action(_) => (&mut self.actions, client == Some(true)),
                    ProfileSlot::Raw(_) => (&mut self.raw, is_writer),
                };
                let acc = map.entry(slot.name().to_string()).or_default();
                touch(&mut acc.span, at);
                if side_a {
                    acc.side_a.insert(guid);
                } else {
                    acc.side_b.insert(guid);
                }
                acc.written |= is_writer;
                if let RosNameKind::ActionPart { component, .. } = &rn.kind {
                    acc.components.insert(component.as_str().to_string());
                }
                if !e.type_name.is_empty() {
                    acc.type_names.insert(e.type_name.clone());
                }
            }
            RobotEvent::MotionCommand(c) => {
                if c.channel.is_empty() {
                    self.anomaly(at, "empty_channel", "", "motion command with empty channel");
                    return;
                }
                if let Some(g) = &c.source_guid {
                    self.check_guid(g, at);
                    self.reference(g, at);
                }
                let linear = self.speed_sample(at, &c.channel, "linear", c.linear_speed);
                let joint = self.speed_sample(at, &c.channel, "joint", c.joint_speed);
                let acc = self.motion.entry(c.channel.clone()).or_default();
                touch(&mut acc.span, at);
                if let Some(g) = &c.source_guid {
                    acc.sources.insert(g.clone());
                }
                acc.linear.extend(linear);
                acc.joint.extend(joint);
            }
            // Feedback is consumed by robodr-motion's consistency monitor; it
            // carries nothing the allowlist profile learns.
            RobotEvent::MotionFeedback(_) => {}
        }
    }

    /// Learn everything from a source as one new run. Strict: stops at and
    /// returns the first input error (events before it remain learned).
    pub fn ingest(&mut self, src: &mut dyn EventSource) -> Result<u64, InputError> {
        self.start_run(src.label().to_string());
        let mut n = 0;
        while let Some(r) = src.next_event() {
            let se = r?;
            self.observe_at(&se.event, se.position);
            n += 1;
        }
        let run = self.runs.len() - 1;
        self.runs[run].capture = src.capture_diagnostics();
        Ok(n)
    }

    /// Union another learner's observations into this one (multi-mission
    /// commissioning). `other`'s runs are appended after ours; this learner's
    /// configuration (margin, ceilings, model) is kept. Because the profile
    /// depends only on sets and maxima, `a.merge(b)` and `b.merge(a)` yield
    /// the same profile.
    pub fn merge(&mut self, other: &Learner) {
        let off = self.runs.len();
        self.runs.extend(other.runs.iter().cloned());
        for (k, v) in &other.events_by_kind {
            *self.events_by_kind.entry(k.clone()).or_insert(0) += v;
        }
        let merge_span = |dst: &mut Option<Span>, src: &Option<Span>| {
            if let Some(s) = src {
                let s = s.shifted(off);
                match dst {
                    Some(d) => d.absorb(&s),
                    None => *dst = Some(s),
                }
            }
        };
        for (g, p) in &other.participants {
            let acc = self.participants.entry(g.clone()).or_default();
            merge_span(&mut acc.span, &p.span);
            acc.src_ips.extend(p.src_ips.iter().cloned());
        }
        for (mine, theirs) in [
            (&mut self.writers, &other.writers),
            (&mut self.readers, &other.readers),
        ] {
            for (t, e) in theirs {
                let acc = mine.entry(t.clone()).or_default();
                merge_span(&mut acc.span, &e.span);
                acc.participants.extend(e.participants.iter().cloned());
                acc.type_names.extend(e.type_names.iter().cloned());
            }
        }
        for (mine, theirs) in [
            (&mut self.services, &other.services),
            (&mut self.actions, &other.actions),
            (&mut self.raw, &other.raw),
        ] {
            for (n, a) in theirs {
                mine.entry(n.clone()).or_default().absorb(a, off);
            }
        }
        for (c, m) in &other.motion {
            let acc = self.motion.entry(c.clone()).or_default();
            merge_span(&mut acc.span, &m.span);
            acc.sources.extend(m.sources.iter().cloned());
            acc.linear.extend_from_slice(&m.linear);
            acc.joint.extend_from_slice(&m.joint);
        }
        for (g, at) in &other.referenced_guids {
            let at = shift(*at, off);
            self.referenced_guids
                .entry(g.clone())
                .and_modify(|a| *a = (*a).min(at))
                .or_insert(at);
        }
        self.anomalies_total = self.anomalies_total.saturating_add(other.anomalies_total);
        for a in &other.anomalies {
            if self.anomalies.len() >= MAX_STORED_ANOMALIES {
                break;
            }
            let mut a = a.clone();
            a.at = shift(a.at, off);
            self.anomalies.push(a);
        }
    }

    fn reference(&mut self, guid: &str, at: SeenAt) {
        self.referenced_guids
            .entry(guid.to_string())
            .and_modify(|a| *a = (*a).min(at))
            .or_insert(at);
    }

    fn anomaly(&mut self, at: SeenAt, kind: &str, subject: &str, detail: impl Into<String>) {
        self.anomalies_total = self.anomalies_total.saturating_add(1);
        if self.anomalies.len() < MAX_STORED_ANOMALIES {
            self.anomalies.push(Anomaly {
                at,
                kind: kind.into(),
                subject: subject.into(),
                detail: detail.into(),
            });
        }
    }

    fn check_guid(&mut self, guid: &str, at: SeenAt) {
        let ok = guid.len() == 24
            && guid
                .bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b));
        if !ok {
            let shown: String = guid.chars().take(64).collect();
            self.anomaly(
                at,
                "malformed_guid_prefix",
                &shown,
                "GUID prefix is not 24 lower-case hex chars; profile matching is exact",
            );
        }
    }

    /// Validate one speed; returns it if usable, records an anomaly if not.
    fn speed_sample(
        &mut self,
        at: SeenAt,
        channel: &str,
        dim: &str,
        v: Option<f64>,
    ) -> Option<f64> {
        let v = v?;
        if !v.is_finite() {
            self.anomaly(
                at,
                &format!("non_finite_{dim}_speed"),
                channel,
                format!("{dim} speed {v} ignored"),
            );
            return None;
        }
        if v < 0.0 {
            self.anomaly(
                at,
                &format!("negative_{dim}_speed"),
                channel,
                format!("{dim} speed {v} ignored (speeds are absolute values)"),
            );
            return None;
        }
        // -0.0 normalised so it serialises as 0.
        Some(if v == 0.0 { 0.0 } else { v })
    }

    fn dim_bound(&self, samples: &[f64], ceiling: Option<f64>) -> Option<(f64, f64, bool)> {
        let max = samples
            .iter()
            .copied()
            .fold(None, |m: Option<f64>, v| Some(m.map_or(v, |m| m.max(v))))?;
        let (bound, capped) = envelope_bound(max, self.config.margin, ceiling);
        Some((max, bound, capped))
    }

    /// The draft profile (`locked: false`).
    pub fn profile(&self) -> Profile {
        let mut p = Profile {
            model: self.config.model.clone(),
            locked: false,
            ..Default::default()
        };
        p.participants = self.participants.keys().cloned().collect();
        p.writer_topics = self.writers.keys().cloned().collect();
        let all = self.config.learn_readers;
        if all {
            p.reader_topics = self.readers.keys().cloned().collect();
        }
        let learned = |m: &BTreeMap<String, RoleAcc>| -> BTreeSet<String> {
            m.iter()
                .filter(|(_, a)| a.written || all)
                .map(|(n, _)| n.clone())
                .collect()
        };
        p.services = learned(&self.services);
        p.actions = learned(&self.actions);
        p.raw_dds_topics = learned(&self.raw);
        for (ch, m) in &self.motion {
            let env = Envelope {
                max_linear_speed: self
                    .dim_bound(&m.linear, self.config.ceiling_linear)
                    .map(|t| t.1),
                max_joint_speed: self
                    .dim_bound(&m.joint, self.config.ceiling_joint)
                    .map(|t| t.1),
            };
            p.motion_envelopes.insert(ch.clone(), env);
        }
        p
    }

    /// The commissioning report.
    pub fn report(&self) -> CommissioningReport {
        let profile = self.profile();
        let mut warnings = Vec::new();
        let mut warn = |level: WarningLevel, code: &str, subject: &str, message: String| {
            warnings.push(Warning {
                level,
                code: code.into(),
                subject: subject.into(),
                message,
            })
        };
        use WarningLevel::{Info, Warn};

        let total: u64 = self.runs.iter().map(|r| r.events).sum();
        if total == 0 {
            warn(
                Warn,
                "no_events",
                "",
                "no events observed: the profile is empty".into(),
            );
        }
        if self.config.model == DEFAULT_MODEL {
            warn(
                Warn,
                "default_model_name",
                &self.config.model,
                "no --model given; name the profile after the robot model before locking".into(),
            );
        }
        if self.anomalies_total > 0 {
            warn(
                Warn,
                "anomalies_present",
                "",
                format!(
                    "{} anomalies in what should be a clean run; investigate before locking",
                    self.anomalies_total
                ),
            );
        }

        // Participants.
        let mut participants = BTreeMap::new();
        for (g, acc) in &self.participants {
            let Some(span) = &acc.span else { continue };
            if span.count == 1 {
                warn(
                    Warn,
                    "participant_seen_once",
                    g,
                    format!(
                        "participant {g} announced only once at {} (transient? a tool or laptop?)",
                        span.first
                    ),
                );
            }
            let topics_of = |m: &BTreeMap<String, EndpointAcc>| -> BTreeSet<String> {
                m.iter()
                    .filter(|(_, e)| e.participants.contains(g))
                    .map(|(t, _)| t.clone())
                    .collect()
            };
            participants.insert(
                g.clone(),
                ParticipantReport {
                    announcements: span.count,
                    first_seen: span.first,
                    last_seen: span.last,
                    src_ips: acc.src_ips.clone(),
                    writer_topics: topics_of(&self.writers),
                    reader_topics: topics_of(&self.readers),
                },
            );
        }
        for (g, at) in &self.referenced_guids {
            if !self.participants.contains_key(g) {
                warn(
                    Warn,
                    "unannounced_participant",
                    g,
                    format!(
                        "GUID {g} used by an endpoint or motion command (first at {at}) but never \
                         announced as a participant; it is NOT in the profile"
                    ),
                );
            }
        }

        // Endpoints.
        let endpoint_reports = |m: &BTreeMap<String, EndpointAcc>| {
            m.iter()
                .filter_map(|(t, e)| {
                    let s = e.span.as_ref()?;
                    Some((
                        t.clone(),
                        EndpointReport {
                            announcements: s.count,
                            first_seen: s.first,
                            last_seen: s.last,
                            participants: e.participants.clone(),
                            type_names: e.type_names.clone(),
                        },
                    ))
                })
                .collect::<BTreeMap<_, _>>()
        };
        let writer_topics = endpoint_reports(&self.writers);
        let reader_topics = endpoint_reports(&self.readers);
        for t in writer_topics.keys() {
            // Nothing subscribes to /rosout on a robot without a log tool.
            if !reader_topics.contains_key(t) && t != "/rosout" {
                warn(
                    Info,
                    "writer_without_reader",
                    t,
                    format!("writer on {t} but no reader seen anywhere (dead topic? exfil path?)"),
                );
            }
            if self.writers[t].type_names.len() > 1 {
                warn(
                    Warn,
                    "topic_type_conflict",
                    t,
                    format!(
                        "writers on {t} announce several types: {:?}",
                        self.writers[t].type_names
                    ),
                );
            }
        }

        // Services, actions, raw DDS topics.
        let all = self.config.learn_readers;
        let role_reports = |m: &BTreeMap<String, RoleAcc>| {
            m.iter()
                .filter_map(|(n, a)| {
                    let s = a.span.as_ref()?;
                    Some((
                        n.clone(),
                        ServiceReport {
                            announcements: s.count,
                            first_seen: s.first,
                            last_seen: s.last,
                            clients: a.side_a.clone(),
                            servers: a.side_b.clone(),
                            components: a.components.clone(),
                            in_profile: a.written || all,
                        },
                    ))
                })
                .collect::<BTreeMap<_, _>>()
        };
        let services = role_reports(&self.services);
        let actions = role_reports(&self.actions);
        let mut raw_dds_topics = BTreeMap::new();
        for (n, a) in &self.raw {
            let Some(s) = &a.span else { continue };
            let ros_internal = ROS_INTERNAL_RAW_TOPICS.contains(&n.as_str());
            raw_dds_topics.insert(
                n.clone(),
                RawTopicReport {
                    announcements: s.count,
                    first_seen: s.first,
                    last_seen: s.last,
                    writers: a.side_a.clone(),
                    readers: a.side_b.clone(),
                    type_names: a.type_names.clone(),
                    ros_internal,
                    in_profile: a.written || all,
                },
            );
            if !ros_internal {
                warn(
                    Info,
                    "raw_dds_topic",
                    n,
                    format!(
                        "non-ROS DDS topic {n:?} (vendor tool? bridge? legacy DDS app?); \
                         confirm it belongs on this robot"
                    ),
                );
            }
        }
        for (what, m) in [
            ("service", &self.services),
            ("action", &self.actions),
            ("raw DDS topic", &self.raw),
        ] {
            for (n, a) in m {
                // Raw topics may legitimately have only subscribers.
                if !a.written && !all && what != "raw DDS topic" {
                    warn(
                        Warn,
                        "reader_only_name",
                        n,
                        format!(
                            "{what} {n} seen only on reader endpoints, so it is NOT in the \
                             profile; its other side always writes, so the capture is \
                             probably incomplete"
                        ),
                    );
                }
            }
        }
        // Parameter services: per node (service name prefix) and per ROS
        // participant (one that writes /rosout).
        let mut nodes: BTreeMap<&str, BTreeSet<&str>> = BTreeMap::new();
        let mut param_servers: BTreeSet<&str> = BTreeSet::new();
        for (n, a) in &self.services {
            if let Some((node, last)) = n.rsplit_once('/') {
                if PARAMETER_SERVICES.contains(&last) && !node.is_empty() {
                    nodes.entry(node).or_default().insert(last);
                    param_servers.extend(a.side_b.iter().map(String::as_str));
                }
            }
        }
        for (node, have) in &nodes {
            if have.len() < PARAMETER_SERVICES.len() {
                let missing: Vec<&str> = PARAMETER_SERVICES
                    .iter()
                    .copied()
                    .filter(|p| !have.contains(p))
                    .collect();
                warn(
                    Warn,
                    "incomplete_parameter_services",
                    node,
                    format!(
                        "node {node} serves only {} of {} parameter services (missing {missing:?}); \
                         likely an incomplete capture",
                        have.len(),
                        PARAMETER_SERVICES.len()
                    ),
                );
            }
        }
        if let Some(rosout) = self.writers.get("/rosout") {
            for g in &rosout.participants {
                if !param_servers.contains(g.as_str()) {
                    warn(
                        Warn,
                        "missing_parameter_services",
                        g,
                        format!(
                            "participant {g} hosts ROS 2 node(s) (writes /rosout) but serves no \
                             parameter services: capture probably started after discovery or \
                             missed SEDP (or the node disables parameter services); the locked \
                             profile would flag its /<node>/get_parameters etc."
                        ),
                    );
                }
            }
        }
        let reader_enforcement = all && !self.readers.is_empty();
        if !all && !self.readers.is_empty() {
            warn(
                Info,
                "reader_topics_not_learned",
                "",
                format!(
                    "{} reader topics observed but not learned: reader-topic enforcement stays \
                     off (use --learn-readers to opt in)",
                    self.readers.len()
                ),
            );
        }
        // Capture-level problems.
        for (i, r) in self.runs.iter().enumerate() {
            let Some(c) = &r.capture else { continue };
            let subject = format!("run{i}");
            if c.discovery_reassembly_failed() {
                warn(
                    Warn,
                    "fragmented_discovery_unreassembled",
                    &subject,
                    format!(
                        "{}: fragmented discovery (DATA_FRAG) was seen but not all of it was \
                         rebuilt ({} rejected, {} evicted, {} incomplete at end): some \
                         endpoint announcements are missing from the profile",
                        r.label,
                        c.discovery_frag_rejected,
                        c.discovery_frag_evicted,
                        c.discovery_frag_incomplete
                    ),
                );
            } else if c.discovery_frag_completed > 0 {
                warn(
                    Info,
                    "fragmented_discovery_reassembled",
                    &subject,
                    format!(
                        "{}: {} fragmented discovery sample(s) reassembled",
                        r.label, c.discovery_frag_completed
                    ),
                );
            }
            if c.ip_reassembly_dropped > 0 {
                warn(
                    Warn,
                    "ip_reassembly_failed",
                    &subject,
                    format!(
                        "{}: {} IP-fragmented datagram(s) could not be reassembled",
                        r.label, c.ip_reassembly_dropped
                    ),
                );
            }
            if c.truncated_frames > 0 {
                warn(
                    Warn,
                    "truncated_frames",
                    &subject,
                    format!(
                        "{}: {} frame(s) cut by the snap length were skipped; capture with \
                         a full snap length (tcpdump -s 0)",
                        r.label, c.truncated_frames
                    ),
                );
            }
            if c.secure_submessages > 0 {
                warn(
                    Warn,
                    "protected_discovery",
                    &subject,
                    format!(
                        "{}: {} DDS-Security protected submessage(s): their endpoints are \
                         invisible to commissioning",
                        r.label, c.secure_submessages
                    ),
                );
            }
        }

        // Motion channels.
        let mut motion_channels = BTreeMap::new();
        for (ch, m) in &self.motion {
            let Some(span) = &m.span else { continue };
            if ch.starts_with("rt/") {
                warn(
                    Warn,
                    "mangled_motion_channel",
                    ch,
                    format!("motion channel {ch} looks DDS-mangled; profile checks expect /topic"),
                );
            }
            if !self.writers.contains_key(ch) {
                warn(
                    Info,
                    "motion_channel_without_writer",
                    ch,
                    format!("no writer announced on motion channel {ch}"),
                );
            }
            let env = profile
                .motion_envelopes
                .get(ch)
                .cloned()
                .unwrap_or_default();
            let mut dims = [
                (
                    "linear",
                    &m.linear,
                    self.config.ceiling_linear,
                    "m/s",
                    false,
                ),
                ("joint", &m.joint, self.config.ceiling_joint, "rad/s", false),
            ];
            for d in dims.iter_mut() {
                let (dim, samples, ceiling, unit, _) = *d;
                let n = samples.len() as u64;
                if n > 0 && n < self.config.min_samples {
                    warn(
                        Warn,
                        "few_motion_samples",
                        ch,
                        format!(
                            "motion channel {ch} has {n} {dim} samples (< {}): envelope not trustworthy",
                            self.config.min_samples
                        ),
                    );
                }
                if let Some((max, bound, capped)) = self.dim_bound(samples, ceiling) {
                    d.4 = capped;
                    if max == 0.0 {
                        warn(
                            Warn,
                            "zero_envelope",
                            ch,
                            format!(
                                "{ch}: every {dim} sample was 0; envelope 0 forbids any motion"
                            ),
                        );
                    }
                    if let Some(c) = ceiling {
                        if max > c {
                            warn(
                                Warn,
                                "observed_exceeds_ceiling",
                                ch,
                                format!(
                                    "{ch}: observed {dim} max {max} {unit} exceeds OEM ceiling {c}; \
                                     the clean run itself would deviate"
                                ),
                            );
                        } else if capped {
                            warn(
                                Info,
                                "margin_capped_by_ceiling",
                                ch,
                                format!("{ch}: {dim} envelope capped at OEM ceiling {c} {unit} (margin wanted {bound})"),
                            );
                        }
                    }
                }
            }
            if m.linear.is_empty() && m.joint.is_empty() {
                warn(
                    Warn,
                    "motion_channel_without_envelope",
                    ch,
                    format!("{ch}: no valid speed sample; envelope empty, lock will refuse"),
                );
            }
            motion_channels.insert(
                ch.clone(),
                MotionReport {
                    commands: span.count,
                    first_seen: span.first,
                    last_seen: span.last,
                    sources: m.sources.clone(),
                    linear: SpeedStats::from_samples(&m.linear),
                    joint: SpeedStats::from_samples(&m.joint),
                    envelope: env,
                    linear_capped_by_ceiling: dims[0].4,
                    joint_capped_by_ceiling: dims[1].4,
                },
            );
        }

        CommissioningReport {
            model: self.config.model.clone(),
            config: ReportConfig {
                margin: self.config.margin,
                ceiling_linear: self.config.ceiling_linear,
                ceiling_joint: self.config.ceiling_joint,
                min_samples: self.config.min_samples,
                learn_readers: self.config.learn_readers,
            },
            runs: self.runs.clone(),
            events_total: total,
            events_by_kind: self.events_by_kind.clone(),
            participants,
            writer_topics,
            reader_topics,
            reader_enforcement,
            services,
            actions,
            raw_dds_topics,
            motion_channels,
            anomalies_total: self.anomalies_total,
            anomalies: self.anomalies.clone(),
            warnings,
        }
    }

    /// Profile and report together.
    pub fn finish(&self) -> Commissioning {
        Commissioning {
            profile: self.profile(),
            report: self.report(),
        }
    }
}

/// How loud a warning is. `Warn` items should be resolved (or consciously
/// accepted) before locking; `Info` items are context.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum WarningLevel {
    Info,
    Warn,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Warning {
    pub level: WarningLevel,
    /// Stable code, e.g. `few_motion_samples`.
    pub code: String,
    pub subject: String,
    pub message: String,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ReportConfig {
    pub margin: f64,
    pub ceiling_linear: Option<f64>,
    pub ceiling_joint: Option<f64>,
    pub min_samples: u64,
    pub learn_readers: bool,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ParticipantReport {
    pub announcements: u64,
    pub first_seen: SeenAt,
    pub last_seen: SeenAt,
    pub src_ips: BTreeSet<String>,
    pub writer_topics: BTreeSet<String>,
    pub reader_topics: BTreeSet<String>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct EndpointReport {
    pub announcements: u64,
    pub first_seen: SeenAt,
    pub last_seen: SeenAt,
    pub participants: BTreeSet<String>,
    pub type_names: BTreeSet<String>,
}

/// A ROS 2 service or action as observed.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ServiceReport {
    pub announcements: u64,
    pub first_seen: SeenAt,
    pub last_seen: SeenAt,
    /// Participants on the client side (write requests, read replies /
    /// feedback / status).
    pub clients: BTreeSet<String>,
    /// Participants on the server side.
    pub servers: BTreeSet<String>,
    /// Actions only: components seen (`send_goal`, ..., `status`).
    #[serde(default, skip_serializing_if = "BTreeSet::is_empty")]
    pub components: BTreeSet<String>,
    /// Learned into the profile.
    pub in_profile: bool,
}

/// A raw (non-ROS) DDS topic as observed.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct RawTopicReport {
    pub announcements: u64,
    pub first_seen: SeenAt,
    pub last_seen: SeenAt,
    pub writers: BTreeSet<String>,
    pub readers: BTreeSet<String>,
    pub type_names: BTreeSet<String>,
    /// Created by ROS 2 itself (see [`ROS_INTERNAL_RAW_TOPICS`]).
    pub ros_internal: bool,
    pub in_profile: bool,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct MotionReport {
    pub commands: u64,
    pub first_seen: SeenAt,
    pub last_seen: SeenAt,
    pub sources: BTreeSet<String>,
    pub linear: Option<SpeedStats>,
    pub joint: Option<SpeedStats>,
    pub envelope: Envelope,
    pub linear_capped_by_ceiling: bool,
    pub joint_capped_by_ceiling: bool,
}

/// Everything the OEM needs to review a draft profile before locking it.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct CommissioningReport {
    pub model: String,
    pub config: ReportConfig,
    pub runs: Vec<RunSummary>,
    pub events_total: u64,
    pub events_by_kind: BTreeMap<String, u64>,
    pub participants: BTreeMap<String, ParticipantReport>,
    pub writer_topics: BTreeMap<String, EndpointReport>,
    pub reader_topics: BTreeMap<String, EndpointReport>,
    /// The profile's `reader_topics` is non-empty, so reader topics will be
    /// enforced.
    pub reader_enforcement: bool,
    pub services: BTreeMap<String, ServiceReport>,
    pub actions: BTreeMap<String, ServiceReport>,
    pub raw_dds_topics: BTreeMap<String, RawTopicReport>,
    pub motion_channels: BTreeMap<String, MotionReport>,
    pub anomalies_total: u64,
    /// First [`MAX_STORED_ANOMALIES`] anomalies, in observation order.
    pub anomalies: Vec<Anomaly>,
    pub warnings: Vec<Warning>,
}

impl CommissioningReport {
    pub fn warn_count(&self) -> usize {
        self.warnings
            .iter()
            .filter(|w| w.level == WarningLevel::Warn)
            .count()
    }
}

fn opt(v: Option<f64>) -> String {
    v.map_or_else(|| "-".to_string(), |v| v.to_string())
}

impl fmt::Display for CommissioningReport {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        writeln!(f, "RoboDR commissioning report: model {}", self.model)?;
        writeln!(
            f,
            "  margin x{}  ceiling linear {} m/s  ceiling joint {} rad/s  min samples {}  learn readers {}",
            self.config.margin,
            opt(self.config.ceiling_linear),
            opt(self.config.ceiling_joint),
            self.config.min_samples,
            self.config.learn_readers
        )?;
        for (i, r) in self.runs.iter().enumerate() {
            writeln!(f, "  run{i}: {} ({} events)", r.label, r.events)?;
            if let Some(c) = &r.capture {
                writeln!(
                    f,
                    "    capture: {} frames, {} RTPS datagrams, {} IP-reassembled, \
                     discovery DATA_FRAG {} (rebuilt {}, rejected {}, evicted {}, incomplete {})",
                    c.frames,
                    c.rtps_datagrams,
                    c.ip_reassembled,
                    c.discovery_data_frag,
                    c.discovery_frag_completed,
                    c.discovery_frag_rejected,
                    c.discovery_frag_evicted,
                    c.discovery_frag_incomplete
                )?;
            }
        }
        writeln!(f, "  events: {} total", self.events_total)?;
        for (k, v) in &self.events_by_kind {
            writeln!(f, "    {k}: {v}")?;
        }
        writeln!(f, "\nParticipants ({}):", self.participants.len())?;
        for (g, p) in &self.participants {
            writeln!(
                f,
                "  {g}  seen {}x [{} .. {}]  ip {:?}  writes {:?}  reads {:?}",
                p.announcements,
                p.first_seen,
                p.last_seen,
                p.src_ips,
                p.writer_topics,
                p.reader_topics
            )?;
        }
        for (title, m) in [
            ("Writer topics", &self.writer_topics),
            ("Reader topics", &self.reader_topics),
        ] {
            writeln!(f, "\n{title} ({}):", m.len())?;
            for (t, e) in m {
                writeln!(
                    f,
                    "  {t}  seen {}x [{} .. {}]  by {:?}",
                    e.announcements, e.first_seen, e.last_seen, e.participants
                )?;
            }
        }
        writeln!(
            f,
            "Reader-topic enforcement: {}",
            if self.reader_enforcement {
                "on (reader_topics learned)"
            } else {
                "off (reader_topics empty)"
            }
        )?;
        let learned = |b: bool| if b { "" } else { "  [NOT in profile]" };
        for (title, m) in [("Services", &self.services), ("Actions", &self.actions)] {
            writeln!(f, "\n{title} ({}):", m.len())?;
            for (n, r) in m {
                let comps = if r.components.is_empty() {
                    String::new()
                } else {
                    format!("  parts {:?}", r.components)
                };
                writeln!(
                    f,
                    "  {n}  clients {:?}  servers {:?}{comps}{}",
                    r.clients,
                    r.servers,
                    learned(r.in_profile)
                )?;
            }
        }
        writeln!(f, "\nRaw DDS topics ({}):", self.raw_dds_topics.len())?;
        for (n, r) in &self.raw_dds_topics {
            writeln!(
                f,
                "  {n:?}{}  writers {:?}  readers {:?}{}",
                if r.ros_internal {
                    " (ROS 2 internal)"
                } else {
                    ""
                },
                r.writers,
                r.readers,
                learned(r.in_profile)
            )?;
        }
        writeln!(f, "\nMotion channels ({}):", self.motion_channels.len())?;
        for (c, m) in &self.motion_channels {
            writeln!(
                f,
                "  {c}  {} commands [{} .. {}]",
                m.commands, m.first_seen, m.last_seen
            )?;
            for (dim, s, env, capped, unit) in [
                (
                    "linear",
                    &m.linear,
                    m.envelope.max_linear_speed,
                    m.linear_capped_by_ceiling,
                    "m/s",
                ),
                (
                    "joint",
                    &m.joint,
                    m.envelope.max_joint_speed,
                    m.joint_capped_by_ceiling,
                    "rad/s",
                ),
            ] {
                if let Some(s) = s {
                    writeln!(
                        f,
                        "    {dim}: n={} min={} p50={} p99={} max={} -> envelope {} {unit}{}",
                        s.samples,
                        s.min,
                        s.p50,
                        s.p99,
                        s.max,
                        opt(env),
                        if capped {
                            " (capped by OEM ceiling)"
                        } else {
                            ""
                        }
                    )?;
                }
            }
        }
        writeln!(f, "\nAnomalies: {}", self.anomalies_total)?;
        for a in &self.anomalies {
            writeln!(f, "  {} {} {}: {}", a.at, a.kind, a.subject, a.detail)?;
        }
        if (self.anomalies.len() as u64) < self.anomalies_total {
            writeln!(
                f,
                "  ... {} more not shown",
                self.anomalies_total - self.anomalies.len() as u64
            )?;
        }
        writeln!(
            f,
            "\nWarnings: {} ({} need attention)",
            self.warnings.len(),
            self.warn_count()
        )?;
        for w in &self.warnings {
            let lvl = match w.level {
                WarningLevel::Info => "info",
                WarningLevel::Warn => "WARN",
            };
            writeln!(f, "  [{lvl}] {}: {}", w.code, w.message)?;
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use robodr_events::graph::{Endpoint, Participant};
    use robodr_events::MotionCommand;

    const A: &str = "aaaaaaaaaaaaaaaaaaaaaaaa";
    const B: &str = "bbbbbbbbbbbbbbbbbbbbbbbb";

    fn part(g: &str) -> RobotEvent {
        RobotEvent::Ros2ParticipantDiscovered(Participant {
            guid_prefix: g.into(),
            src_ip: "10.0.0.1".into(),
            locators: vec![],
        })
    }
    fn writer(g: &str, t: &str) -> RobotEvent {
        RobotEvent::Ros2WriterDiscovered(Endpoint {
            guid_prefix: g.into(),
            topic: t.into(),
            type_name: "geometry_msgs::msg::dds_::Twist_".into(),
        })
    }
    fn reader(g: &str, t: &str) -> RobotEvent {
        RobotEvent::Ros2ReaderDiscovered(Endpoint {
            guid_prefix: g.into(),
            topic: t.into(),
            type_name: String::new(),
        })
    }
    fn mv(ch: &str, lin: Option<f64>, joint: Option<f64>) -> RobotEvent {
        RobotEvent::MotionCommand(MotionCommand {
            channel: ch.into(),
            source_guid: Some(A.into()),
            linear_speed: lin,
            joint_speed: joint,
        })
    }

    fn cfg() -> LearnConfig {
        LearnConfig {
            model: "ugv-test".into(),
            ..Default::default()
        }
    }

    fn learn(cfg: LearnConfig, evs: &[RobotEvent]) -> Learner {
        let mut l = Learner::new(cfg).unwrap();
        for e in evs {
            l.observe(e);
        }
        l
    }

    fn clean() -> Vec<RobotEvent> {
        let mut v = vec![part(A), part(B), part(A), part(B)];
        v.push(writer(A, "rt/cmd_vel"));
        v.push(reader(B, "rt/cmd_vel"));
        v.push(writer(B, "rt/odom"));
        v.push(reader(A, "rt/odom"));
        for i in 0..40 {
            v.push(mv("/cmd_vel", Some(0.01 * f64::from(i)), None));
        }
        v
    }

    #[test]
    fn learns_participants_topics_and_envelope() {
        let l = learn(cfg(), &clean());
        let p = l.profile();
        assert!(!p.locked);
        assert_eq!(p.model, "ugv-test");
        assert_eq!(p.participants.iter().collect::<Vec<_>>(), vec![A, B]);
        assert_eq!(
            p.writer_topics.iter().collect::<Vec<_>>(),
            vec!["/cmd_vel", "/odom"]
        );
        let env = &p.motion_envelopes["/cmd_vel"];
        // max 0.39 * 1.1 = 0.429
        assert_eq!(env.max_linear_speed, Some(0.429));
        assert_eq!(env.max_joint_speed, None);
        let r = l.report();
        assert_eq!(r.anomalies_total, 0);
        assert_eq!(r.warn_count(), 0, "{r}");
        // The clean run evaluates clean against its own (unlocked) profile.
        for e in clean() {
            assert!(p.evaluate(&e).is_none(), "{e:?}");
        }
    }

    #[test]
    fn margin_math_and_quantisation() {
        assert_eq!(envelope_bound(0.5, 1.1, None), (0.55, false));
        assert_eq!(envelope_bound(0.5, 1.0, None), (0.5, false));
        assert_eq!(envelope_bound(0.1, 1.0, None), (0.1, false));
        // Rounds UP, never below observed * margin.
        let (b, _) = envelope_bound(0.123_456_789, 1.0, None);
        assert_eq!(b, 0.123_457);
        assert!(b >= 0.123_456_789);
        assert_eq!(envelope_bound(0.0, 1.1, None), (0.0, false));
        // Huge values: no overflow to inf.
        let (b, _) = envelope_bound(f64::MAX, 1.1, None);
        assert!(b.is_finite());
        assert_eq!(b, f64::MAX);
        assert_eq!(envelope_bound(1e12, 1.5, None).0, 1.5e12);
    }

    #[test]
    fn ceiling_caps_envelope() {
        assert_eq!(envelope_bound(0.5, 1.1, Some(0.52)), (0.52, true));
        assert_eq!(envelope_bound(0.5, 1.1, Some(0.6)), (0.55, false));
        assert_eq!(envelope_bound(0.7, 1.1, Some(0.6)), (0.6, true));
        // Exactly at ceiling is not capped.
        assert_eq!(envelope_bound(0.5, 1.1, Some(0.55)), (0.55, false));
    }

    #[test]
    fn ceiling_applied_in_profile_and_warned() {
        let mut c = cfg();
        c.ceiling_linear = Some(0.3);
        c.ceiling_joint = Some(10.0);
        let mut evs = clean();
        evs.extend((0..40).map(|_| mv("/arm", None, Some(1.0))));
        let l = learn(c, &evs);
        let p = l.profile();
        assert_eq!(p.motion_envelopes["/cmd_vel"].max_linear_speed, Some(0.3));
        assert_eq!(p.motion_envelopes["/arm"].max_joint_speed, Some(1.1));
        let r = l.report();
        assert!(r.motion_channels["/cmd_vel"].linear_capped_by_ceiling);
        assert!(!r.motion_channels["/arm"].joint_capped_by_ceiling);
        assert!(r
            .warnings
            .iter()
            .any(|w| w.code == "observed_exceeds_ceiling" && w.subject == "/cmd_vel"));

        // Margin-only capping is info, not warn.
        let mut c = cfg();
        c.ceiling_linear = Some(0.40);
        let r = learn(c, &clean()).report();
        let w = r
            .warnings
            .iter()
            .find(|w| w.code == "margin_capped_by_ceiling")
            .unwrap();
        assert_eq!(w.level, WarningLevel::Info);
    }

    #[test]
    fn config_validation() {
        let bad = |f: fn(&mut LearnConfig)| {
            let mut c = cfg();
            f(&mut c);
            Learner::new(c).unwrap_err()
        };
        assert_eq!(bad(|c| c.model = " ".into()), ConfigError::EmptyModel);
        assert!(matches!(
            bad(|c| c.margin = 0.9),
            ConfigError::InvalidMargin(_)
        ));
        assert!(matches!(
            bad(|c| c.margin = f64::NAN),
            ConfigError::InvalidMargin(_)
        ));
        assert!(matches!(
            bad(|c| c.margin = f64::INFINITY),
            ConfigError::InvalidMargin(_)
        ));
        assert!(matches!(
            bad(|c| c.margin = 11.0),
            ConfigError::InvalidMargin(_)
        ));
        assert!(matches!(
            bad(|c| c.ceiling_linear = Some(0.0)),
            ConfigError::InvalidCeiling {
                dimension: "linear",
                ..
            }
        ));
        assert!(matches!(
            bad(|c| c.ceiling_joint = Some(f64::NAN)),
            ConfigError::InvalidCeiling {
                dimension: "joint",
                ..
            }
        ));
        assert!(matches!(
            bad(|c| c.ceiling_joint = Some(-1.0)),
            ConfigError::InvalidCeiling { .. }
        ));
    }

    #[test]
    fn non_finite_and_negative_speeds_are_anomalies_not_envelope() {
        let mut evs = clean();
        evs.push(mv("/cmd_vel", Some(f64::NAN), None));
        evs.push(mv("/cmd_vel", Some(f64::INFINITY), None));
        evs.push(mv("/cmd_vel", Some(-5.0), Some(f64::NEG_INFINITY)));
        evs.push(mv("/cmd_vel", Some(-0.0), None));
        let l = learn(cfg(), &evs);
        let p = l.profile();
        assert_eq!(p.motion_envelopes["/cmd_vel"].max_linear_speed, Some(0.429));
        assert_eq!(p.motion_envelopes["/cmd_vel"].max_joint_speed, None);
        let r = l.report();
        assert_eq!(r.anomalies_total, 4);
        let kinds: Vec<_> = r.anomalies.iter().map(|a| a.kind.as_str()).collect();
        assert_eq!(
            kinds,
            vec![
                "non_finite_linear_speed",
                "non_finite_linear_speed",
                "negative_linear_speed",
                "non_finite_joint_speed"
            ]
        );
        assert!(r.warnings.iter().any(|w| w.code == "anomalies_present"));
        // The report must still serialise (no NaN leaks into JSON).
        serde_json::to_string(&r).unwrap();
    }

    #[test]
    fn channel_without_valid_samples_has_empty_envelope() {
        let mut evs = clean();
        evs.push(mv("/arm", Some(f64::NAN), None));
        evs.push(mv("/arm", None, None));
        let l = learn(cfg(), &evs);
        assert_eq!(l.profile().motion_envelopes["/arm"], Envelope::default());
        let r = l.report();
        assert!(r
            .warnings
            .iter()
            .any(|w| w.code == "motion_channel_without_envelope" && w.subject == "/arm"));
        assert!(r.motion_channels["/arm"].linear.is_none());
    }

    #[test]
    fn warnings_for_suspicious_commissioning_runs() {
        let evs = vec![
            part(A),
            part(B),
            part(B),
            writer(A, "rt/cmd_vel"),
            writer(B, "rt/diag"),
            reader(B, "rt/cmd_vel"),
            writer("cccccccccccccccccccccccc", "rt/x"),
            mv("/cmd_vel", Some(0.2), None),
            mv("rt/mangled", Some(0.0), None),
        ];
        let r = learn(LearnConfig::default(), &evs).report();
        let has = |code: &str, subj: &str| {
            r.warnings
                .iter()
                .any(|w| w.code == code && w.subject == subj)
        };
        assert!(has("participant_seen_once", A), "{r}");
        assert!(!has("participant_seen_once", B));
        assert!(has("few_motion_samples", "/cmd_vel"));
        assert!(has("writer_without_reader", "/diag"));
        assert!(!has("writer_without_reader", "/cmd_vel"));
        assert!(has("unannounced_participant", "cccccccccccccccccccccccc"));
        assert!(has("mangled_motion_channel", "rt/mangled"));
        assert!(has("zero_envelope", "rt/mangled"));
        assert!(has("motion_channel_without_writer", "rt/mangled"));
        assert!(has("default_model_name", DEFAULT_MODEL));
        // Unannounced GUID is not in the profile.
        assert!(!learn(cfg(), &evs)
            .profile()
            .participants
            .contains("cccccccccccccccccccccccc"));
    }

    #[test]
    fn malformed_guid_and_empty_names_are_anomalies() {
        let evs = vec![
            part("AAAAAAAAAAAAAAAAAAAAAAAA"),
            part("short"),
            writer(A, ""),
            mv("", Some(1.0), None),
        ];
        let l = learn(cfg(), &evs);
        let r = l.report();
        let kinds: Vec<_> = r.anomalies.iter().map(|a| a.kind.as_str()).collect();
        assert_eq!(
            kinds,
            vec![
                "malformed_guid_prefix",
                "malformed_guid_prefix",
                "empty_topic",
                "empty_channel"
            ]
        );
        assert!(l.profile().writer_topics.is_empty());
        assert!(l.profile().motion_envelopes.is_empty());
    }

    #[test]
    fn anomaly_storage_is_capped_but_counted() {
        let evs: Vec<_> = (0..(MAX_STORED_ANOMALIES + 50))
            .map(|_| mv("/cmd_vel", Some(-1.0), None))
            .collect();
        let r = learn(cfg(), &evs).report();
        assert_eq!(r.anomalies_total, (MAX_STORED_ANOMALIES + 50) as u64);
        assert_eq!(r.anomalies.len(), MAX_STORED_ANOMALIES);
        assert!(r.to_string().contains("50 more not shown"));
    }

    #[test]
    fn deterministic_byte_identical_output() {
        let a = learn(cfg(), &clean()).finish();
        let b = learn(cfg(), &clean()).finish();
        assert_eq!(
            serde_json::to_string_pretty(&a.profile).unwrap(),
            serde_json::to_string_pretty(&b.profile).unwrap()
        );
        assert_eq!(
            serde_json::to_string_pretty(&a.report).unwrap(),
            serde_json::to_string_pretty(&b.report).unwrap()
        );
        // Profile is independent of event order.
        let mut rev = clean();
        rev.reverse();
        assert_eq!(
            serde_json::to_string(&learn(cfg(), &rev).profile()).unwrap(),
            serde_json::to_string(&a.profile).unwrap()
        );
    }

    #[test]
    fn merge_unions_runs_and_is_order_independent_for_profile() {
        let mut r1 = clean();
        r1.truncate(8); // graph only
        r1.extend((0..40).map(|i| mv("/cmd_vel", Some(0.005 * f64::from(i)), None)));
        let mut r2 = vec![part(A), part(A), writer(A, "rt/arm_cmd")];
        r2.extend((0..40).map(|_| mv("/cmd_vel", Some(0.8), Some(0.2))));

        let mut a = Learner::new(cfg()).unwrap();
        a.start_run("m1");
        r1.iter().for_each(|e| a.observe(e));
        let mut b = Learner::new(cfg()).unwrap();
        b.start_run("m2");
        r2.iter().for_each(|e| b.observe(e));

        let mut ab = a.clone();
        ab.merge(&b);
        let mut ba = b.clone();
        ba.merge(&a);
        let p = ab.profile();
        assert_eq!(p, ba.profile());
        assert!(p.writer_topics.contains("/arm_cmd"));
        assert!(p.writer_topics.contains("/odom"));
        assert_eq!(p.motion_envelopes["/cmd_vel"].max_linear_speed, Some(0.88));
        assert_eq!(p.motion_envelopes["/cmd_vel"].max_joint_speed, Some(0.22));

        let r = ab.report();
        assert_eq!(r.runs.len(), 2);
        assert_eq!(r.runs[1].label, "m2");
        assert_eq!(r.motion_channels["/cmd_vel"].commands, 80);
        // A's first sighting in run0, last in run1 (shifted).
        assert_eq!(r.participants[A].first_seen.run, 0);
        assert_eq!(r.participants[A].last_seen.run, 1);
        assert_eq!(r.participants[A].announcements, 4);

        // Merging learners equals learning both runs in one learner.
        let mut one = Learner::new(cfg()).unwrap();
        one.start_run("m1");
        r1.iter().for_each(|e| one.observe(e));
        one.start_run("m2");
        r2.iter().for_each(|e| one.observe(e));
        assert_eq!(one.report(), r);
    }

    #[test]
    fn ingest_uses_source_positions() {
        let text = "# synthetic\n{\"kind\":\"ros2_participant_discovered\",\"guid_prefix\":\"aaaaaaaaaaaaaaaaaaaaaaaa\",\"src_ip\":\"10.0.0.1\"}\n";
        let mut src = crate::input::JsonlSource::new("mem.jsonl", text.as_bytes());
        let mut l = Learner::new(cfg()).unwrap();
        assert_eq!(l.ingest(&mut src).unwrap(), 1);
        let r = l.report();
        assert_eq!(
            r.participants[A].first_seen,
            SeenAt {
                run: 0,
                position: 2
            }
        );
        assert_eq!(r.runs[0].label, "mem.jsonl");
    }

    #[test]
    fn empty_learner_reports_no_events() {
        let l = Learner::new(cfg()).unwrap();
        let r = l.report();
        assert!(r.warnings.iter().any(|w| w.code == "no_events"));
        assert_eq!(l.profile().participants.len(), 0);
        assert!(!r.to_string().is_empty());
    }

    fn param_writers(g: &str, node: &str) -> Vec<RobotEvent> {
        PARAMETER_SERVICES
            .iter()
            .flat_map(|svc| {
                [
                    writer(g, &format!("rr{node}/{svc}Reply")),
                    reader(g, &format!("rq{node}/{svc}Request")),
                ]
            })
            .collect()
    }

    #[test]
    fn endpoints_are_routed_by_kind_into_profile_sets() {
        let mut evs = vec![part(A), part(A), part(B), part(B)];
        evs.extend([
            writer(A, "rt/rosout"),
            writer(A, "rt/parameter_events"),
            reader(A, "rt/parameter_events"),
            writer(A, "ros_discovery_info"),
            reader(A, "ros_discovery_info"),
            writer(B, "vendor_diag"),
            // Service /set_mode: A client, B server.
            writer(A, "rq/set_modeRequest"),
            reader(B, "rq/set_modeRequest"),
            writer(B, "rr/set_modeReply_"),
            reader(A, "rr/set_modeReply"),
            // Action /dock: B server, A client.
            writer(B, "rr/dock/_action/send_goalReply"),
            writer(B, "rt/dock/_action/feedback"),
            writer(A, "rq/dock/_action/send_goalRequest"),
            reader(A, "rt/dock/_action/status"),
            // Wrong transport: a plain topic, not an action part.
            writer(A, "rt/dock/_action/send_goal"),
            // Reader-only names.
            reader(A, "rq/ghostRequest"),
            reader(B, "raw_sub_only"),
            reader(B, "rt/camera/image"),
        ]);
        evs.extend(param_writers(A, "/nav"));
        let l = learn(cfg(), &evs);
        let p = l.profile();
        let v = |s: &BTreeSet<String>| s.iter().cloned().collect::<Vec<_>>();
        assert_eq!(
            v(&p.writer_topics),
            vec!["/dock/_action/send_goal", "/parameter_events", "/rosout"]
        );
        assert!(p.services.contains("/set_mode"));
        assert!(p.services.contains("/nav/get_parameters"));
        assert_eq!(p.services.len(), 7, "{:?}", p.services);
        assert!(!p.services.contains("/ghost"), "reader-only not learned");
        assert_eq!(v(&p.actions), vec!["/dock"]);
        assert_eq!(
            v(&p.raw_dds_topics),
            vec!["ros_discovery_info", "vendor_diag"]
        );
        assert!(p.reader_topics.is_empty(), "readers are opt-in");
        assert_eq!(p.validate(), Ok(()));

        let r = l.report();
        let svc = &r.services["/set_mode"];
        assert_eq!(svc.clients.iter().collect::<Vec<_>>(), vec![A]);
        assert_eq!(svc.servers.iter().collect::<Vec<_>>(), vec![B]);
        assert!(svc.in_profile);
        assert!(!r.services["/ghost"].in_profile);
        let act = &r.actions["/dock"];
        assert_eq!(act.servers.iter().collect::<Vec<_>>(), vec![B]);
        assert_eq!(act.clients.iter().collect::<Vec<_>>(), vec![A]);
        assert_eq!(
            act.components.iter().collect::<Vec<_>>(),
            vec!["feedback", "send_goal", "status"]
        );
        assert!(r.raw_dds_topics["ros_discovery_info"].ros_internal);
        assert!(!r.raw_dds_topics["raw_sub_only"].in_profile);
        assert!(!r.reader_enforcement);
        let has = |code: &str, subj: &str| {
            r.warnings
                .iter()
                .any(|w| w.code == code && w.subject == subj)
        };
        assert!(has("reader_only_name", "/ghost"));
        assert!(!has("reader_only_name", "raw_sub_only"));
        assert!(has("raw_dds_topic", "vendor_diag"));
        assert!(!has("raw_dds_topic", "ros_discovery_info"));
        assert!(has("reader_topics_not_learned", ""));
        assert!(!has("missing_parameter_services", A));
        assert!(!has("incomplete_parameter_services", "/nav"));
        let text = r.to_string();
        assert!(text.contains("Services (8):"), "{text}");
        assert!(text.contains("/ghost  clients"), "{text}");
        assert!(text.contains("[NOT in profile]"));
        assert!(text.contains("(ROS 2 internal)"));
        assert!(text.contains("parts {\"feedback\""), "{text}");
        assert!(text.contains("Reader-topic enforcement: off"));

        // The clean run evaluates clean against its own profile.
        for e in &evs {
            assert!(p.evaluate(e).is_none(), "{e:?}");
        }
    }

    #[test]
    fn learn_readers_fills_reader_sets_and_stays_clean() {
        let mut evs = vec![part(A), part(B)];
        evs.extend([
            writer(A, "rt/odom"),
            reader(B, "rt/odom"),
            reader(B, "rt/camera/image"),
            reader(A, "rq/ghostRequest"),
            reader(B, "rt/nav/_action/status"),
            reader(B, "raw_sub_only"),
        ]);
        let mut c = cfg();
        c.learn_readers = true;
        let l = learn(c, &evs);
        let p = l.profile();
        assert_eq!(
            p.reader_topics.iter().collect::<Vec<_>>(),
            vec!["/camera/image", "/odom"]
        );
        assert!(p.services.contains("/ghost"));
        assert!(p.actions.contains("/nav"));
        assert!(p.raw_dds_topics.contains("raw_sub_only"));
        for e in &evs {
            assert!(p.evaluate(e).is_none(), "{e:?}");
        }
        // Enforcement is live: an unseen reader topic deviates.
        let d = p.evaluate(&reader(B, "rt/map")).unwrap();
        assert_eq!(d.rule, "robot.ros2.unknown_reader_topic");
        let r = l.report();
        assert!(r.reader_enforcement);
        assert!(r.config.learn_readers);
        assert!(!r.warnings.iter().any(|w| w.code == "reader_only_name"));
        assert!(r.services["/ghost"].in_profile);
    }

    #[test]
    fn parameter_service_warnings() {
        const C: &str = "cccccccccccccccccccccccc";
        let mut evs = vec![part(A), part(A), part(B), part(B), part(C), part(C)];
        // A: complete node. B: ROS node without any parameter service.
        // C: node with an incomplete set.
        evs.extend([
            writer(A, "rt/rosout"),
            writer(B, "rt/rosout"),
            writer(C, "rt/rosout"),
        ]);
        evs.extend(param_writers(A, "/nav"));
        evs.extend(param_writers(C, "/ns/driver").into_iter().take(6));
        let r = learn(cfg(), &evs).report();
        let has = |code: &str, subj: &str| {
            r.warnings
                .iter()
                .any(|w| w.code == code && w.subject == subj && w.level == WarningLevel::Warn)
        };
        assert!(!has("missing_parameter_services", A), "{r}");
        assert!(has("missing_parameter_services", B), "{r}");
        assert!(!has("missing_parameter_services", C));
        assert!(has("incomplete_parameter_services", "/ns/driver"), "{r}");
        assert!(!has("incomplete_parameter_services", "/nav"));
        let w = r
            .warnings
            .iter()
            .find(|w| w.code == "incomplete_parameter_services")
            .unwrap();
        assert!(w.message.contains("3 of 6"), "{}", w.message);
    }

    #[test]
    fn invalid_ros_names_are_anomalies_not_learned() {
        let evs = vec![
            part(A),
            writer(A, "rt/bad name"),
            writer(A, "rq/ctl\u{7}Request"),
            writer(A, "rt/ok"),
            // Raw names are exact and may contain anything but must be non-empty.
            writer(A, "raw with space"),
        ];
        let l = learn(cfg(), &evs);
        let r = l.report();
        assert_eq!(
            r.anomalies
                .iter()
                .filter(|a| a.kind == "invalid_ros_name")
                .count(),
            2
        );
        let p = l.profile();
        assert_eq!(p.writer_topics.iter().collect::<Vec<_>>(), vec!["/ok"]);
        assert!(p.services.is_empty());
        assert!(p.raw_dds_topics.contains("raw with space"));
        assert_eq!(p.validate(), Ok(()));
    }

    #[test]
    fn profile_slot_matches_validate_rules() {
        use robodr_events::graph::demangle;
        assert_eq!(
            ProfileSlot::of(&demangle("rq/nav/_action/get_resultRequest")),
            ProfileSlot::Action("/nav".into())
        );
        assert_eq!(
            ProfileSlot::of(&demangle("rr/addReply_")),
            ProfileSlot::Service("/add".into())
        );
        assert_eq!(
            ProfileSlot::of(&demangle("rtfoo")),
            ProfileSlot::Raw("rtfoo".into())
        );
        assert!(!ProfileSlot::Raw(String::new()).is_valid());
        assert!(ProfileSlot::Raw(" x ".into()).is_valid());
        assert!(!ProfileSlot::Topic("/".into()).is_valid());
        assert!(!ProfileSlot::Topic("/a\tb".into()).is_valid());
        assert!(ProfileSlot::Topic("//".into()).is_valid());
        assert_eq!(ProfileSlot::Service("/s".into()).name(), "/s");
    }

    #[test]
    fn merge_unions_services_actions_raw() {
        let mut a = Learner::new(cfg()).unwrap();
        a.observe(&part(A));
        a.observe(&writer(A, "rq/xRequest"));
        a.observe(&writer(A, "vendor"));
        let mut b = Learner::new(cfg()).unwrap();
        b.observe(&part(B));
        b.observe(&writer(B, "rr/xReply"));
        b.observe(&writer(B, "rt/nav/_action/status"));
        b.observe(&reader(B, "rq/yRequest"));
        let mut ab = a.clone();
        ab.merge(&b);
        let mut ba = b.clone();
        ba.merge(&a);
        assert_eq!(ab.profile(), ba.profile());
        let p = ab.profile();
        assert_eq!(p.services.iter().collect::<Vec<_>>(), vec!["/x"]);
        assert!(p.actions.contains("/nav") && p.raw_dds_topics.contains("vendor"));
        let r = ab.report();
        assert_eq!(r.services["/x"].clients.len(), 1);
        assert_eq!(r.services["/x"].servers.len(), 1);
        assert_eq!(r.services["/x"].first_seen.run, 0);
        assert_eq!(r.services["/x"].last_seen.run, 1);
        assert!(!r.services["/y"].in_profile);
    }

    struct FakeCapture(Option<CaptureDiagnostics>, Vec<RobotEvent>);
    impl EventSource for FakeCapture {
        fn label(&self) -> &str {
            "fake.pcap"
        }
        fn next_event(&mut self) -> Option<Result<crate::input::SourcedEvent, InputError>> {
            if self.1.is_empty() {
                return None;
            }
            Some(Ok(crate::input::SourcedEvent {
                position: 7,
                event: self.1.remove(0),
            }))
        }
        fn capture_diagnostics(&self) -> Option<CaptureDiagnostics> {
            self.0.clone()
        }
    }

    #[test]
    fn capture_diagnostics_become_warnings() {
        let bad = CaptureDiagnostics {
            frames: 10,
            rtps_datagrams: 9,
            discovery_data_frag: 4,
            discovery_frag_incomplete: 1,
            ip_reassembly_dropped: 2,
            truncated_frames: 1,
            secure_submessages: 3,
            ..Default::default()
        };
        let good = CaptureDiagnostics {
            discovery_data_frag: 2,
            discovery_frag_completed: 1,
            ..Default::default()
        };
        let mut l = Learner::new(cfg()).unwrap();
        l.ingest(&mut FakeCapture(Some(bad.clone()), vec![part(A)]))
            .unwrap();
        l.ingest(&mut FakeCapture(Some(good), vec![part(A)]))
            .unwrap();
        l.ingest(&mut VecSourceAlias::new("x", vec![part(A)]))
            .unwrap();
        let r = l.report();
        assert_eq!(r.runs[0].capture, Some(bad));
        assert!(r.runs[2].capture.is_none());
        let has = |code: &str, subj: &str, lvl: WarningLevel| {
            r.warnings
                .iter()
                .any(|w| w.code == code && w.subject == subj && w.level == lvl)
        };
        use WarningLevel::{Info, Warn};
        assert!(
            has("fragmented_discovery_unreassembled", "run0", Warn),
            "{r}"
        );
        assert!(has("ip_reassembly_failed", "run0", Warn));
        assert!(has("truncated_frames", "run0", Warn));
        assert!(has("protected_discovery", "run0", Warn));
        assert!(has("fragmented_discovery_reassembled", "run1", Info));
        assert!(!has("fragmented_discovery_unreassembled", "run1", Warn));
        assert_eq!(r.participants[A].first_seen.position, 7);
        let text = r.to_string();
        assert!(
            text.contains("capture: 10 frames, 9 RTPS datagrams"),
            "{text}"
        );
        // JSON: absent capture is omitted, present one round-trips.
        let j = serde_json::to_value(&r).unwrap();
        assert!(j["runs"][2].get("capture").is_none());
        let back: CommissioningReport = serde_json::from_value(j).unwrap();
        assert_eq!(back, r);
    }

    use crate::input::VecSource as VecSourceAlias;

    #[test]
    fn human_report_mentions_stats() {
        let s = learn(cfg(), &clean()).report().to_string();
        assert!(s.contains("p99="), "{s}");
        assert!(s.contains("/cmd_vel"));
        assert!(s.contains("envelope 0.429"));
    }
}
