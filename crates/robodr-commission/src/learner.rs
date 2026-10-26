//! The observe-mode [`Learner`]: turns a clean run's events into a draft
//! [`Profile`] (`locked: false`), a [`CommissioningReport`] the OEM reads
//! before locking, and a [`Signoff`] list a named operator must confirm
//! before `lock` accepts the draft.
//!
//! # What is learned
//!
//! * `participants`: every GUID prefix seen in a participant announcement
//!   that passes the **anti-poisoning gate** below. GUIDs seen *only* on
//!   endpoints or motion commands are never added (warning
//!   `unannounced_participant`).
//! * Endpoint names, routed by kind exactly as `Profile::evaluate` matches
//!   them (see [`ProfileSlot`] and the table below), **only when at least one
//!   accepted participant announced them**. learn -> lock -> check over the
//!   same clean run gives zero deviations (property-tested in
//!   `tests/roundtrip.rs` with a permissive gate).
//! * `motion_envelopes`: for each motion channel, per dimension (linear m/s,
//!   joint rad/s), `min(max_observed * margin, effective_cap)` over samples
//!   from accepted sources, where `effective_cap` is the OEM ceiling if set
//!   and never more than the configured **hard cap** (see
//!   [`envelope_bound`]). A channel with no valid sample in any dimension
//!   gets an empty envelope, which `lock` refuses: the OEM must decide. A
//!   dimension never exercised on a channel that has samples in the other
//!   one is **never left `None` (= unlimited)**: it is bounded at the OEM
//!   ceiling if one is configured, else at 0 (deny), and listed for sign-off
//!   (`envelope_dimension_unobserved`).
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
//! # Learning-time poisoning (threat model and mitigations)
//!
//! Whatever is on the bus during commissioning becomes "normal". An attacker
//! present during the clean run (a rogue node, a laptop, a compromised
//! component) would otherwise be baked into the locked allowlist, and a
//! fast motion command injected during the run would widen the envelope.
//! Mitigations, all on by default:
//!
//! 1. **Quarantine** (not learned, reported): a participant announced fewer
//!    than `min_participant_announcements` times, or, when the input has
//!    capture timestamps, observed for less than
//!    `min_participant_duration` in every run it appears in. Its endpoints
//!    and its motion samples are not learned either, so a quarantined
//!    attacker leaves no trace in the profile. An operator who knows a
//!    quarantined participant is legitimate re-runs `learn` with
//!    `--accept-participant <guid>`; that acceptance is itself a sign-off
//!    item.
//! 2. **Flags for sign-off** (learned, but `lock` needs a named operator to
//!    confirm each): participants that first appeared late in the run
//!    (`late_fraction`), were present only briefly (`brief_fraction` of the
//!    run), announced from several source IPs (spoofing or multi-homing),
//!    or were missing from some runs; **every participant that writes a
//!    motion topic or sends motion commands**; motion commands without a
//!    source; motion channels with fewer than `min_samples` samples;
//!    envelope-relevant samples above the hard cap; envelopes whose maximum
//!    is more than `outlier_ratio` (default 3) times their 99th percentile
//!    (`envelope_outlier`: one stray or injected command set the bound);
//!    capacity overflow; anomalies.
//! 3. **Envelope hard cap**: no envelope is ever wider than
//!    `hard_cap_linear` / `hard_cap_joint` (or the tighter OEM ceiling),
//!    whatever was observed; NaN, infinite and negative speeds are never
//!    learned; samples from quarantined, unannounced or malformed sources
//!    never widen an envelope.
//! 4. **Endpoint provenance** (packet captures): an endpoint announcement
//!    is learned for the GUID it claims only if (a) that GUID prefix is the
//!    prefix the RTPS message was sent under (header, as changed by
//!    INFO_SRC; see [`Origin`]) and (b) its source IP is one of the owner's
//!    *commissioned IPs*: the IPs from which the owner itself passes the
//!    gate of 1. (announcement count, duration). Otherwise it is not learned
//!    and becomes an `endpoint_sender_mismatch` sign-off item naming the
//!    claimed owner, the sender, the IP and the endpoint names. So an
//!    intruder cannot get a topic learned by naming a legitimate
//!    participant's GUID in `PID_ENDPOINT_GUID`, nor by spoofing that
//!    participant's header prefix from its own host a few times. An
//!    operator-accepted participant has all its IPs commissioned. Event
//!    recordings (JSONL) carry no sender, so this check does not apply to
//!    them (the sensor that produced them is trusted for attribution).
//!
//!    **Discovery servers** ([`LearnConfig::discovery_servers`], CLI
//!    `--discovery-server` / `--trusted-discovery-server`, mirroring the
//!    sensor pipeline's `discovery_servers` binding option). A discovery
//!    server re-sends other participants' announcements under its own
//!    prefix. A relayed announcement (sender prefix != claimed owner) whose
//!    sender matches a configured server ([`DiscoveryServer`]: GUID prefix
//!    and/or source IP) is attributed to its owner, never to the server,
//!    and never binds the server's IP to the owner:
//!    * from a **known** server, a relayed endpoint is accepted only as a
//!      copy: no item if the owner is accepted and announced the same
//!      endpoint *directly* (from a commissioned IP); otherwise it is not
//!      learned and is an `endpoint_sender_mismatch` item naming the
//!      server. Relayed participant announcements are ignored (they neither
//!      count for nor against the gate).
//!    * from a **trusted** server, a relayed endpoint is learned for its
//!      owner if the owner is accepted, even if the owner never announced
//!      it directly (the server vouches); relayed participant announcements
//!      count for the owner's gate under the pseudo-address
//!      `relay:<server>` (shown in the report's source IPs, not counted as
//!      a second IP). An endpoint relayed for an owner that is not accepted
//!      is still an `endpoint_sender_mismatch` item.
//!    * a relay from a sender that matches no configured server is
//!      `endpoint_sender_mismatch`, as before.
//!
//!    Trusting a server means trusting whatever it relays (as the sensor
//!    does); prefer the known-server mode with a capture point that also
//!    sees the participants' own announcements (on the server host or a
//!    mirror port). A **trusted** server must be pinned by source IP
//!    (`PREFIX@IP` or `IP`): the RTPS header prefix is written by the
//!    sender, so any host could claim a prefix-only server's prefix and have
//!    its own participants and endpoints (or endpoints it attributes to a
//!    legitimate participant) learned as relays. A prefix-only server is
//!    accepted as **known** only, where a relay never gets anything learned
//!    on its own (it is at most a copy of the owner's direct announcement).
//! 5. **Bounded memory**: every map and set has a cap (see [`Limits`]);
//!    entries past a cap are dropped (fail-closed: they later deviate),
//!    counted, and turned into a `capacity_exceeded` sign-off item. Motion
//!    samples live in decimating [`SampleBuffer`]s; envelopes use exact
//!    per-source maxima, so they do not depend on decimation.
//!
//! Limits of these heuristics (honest list): an attacker present for the
//! *whole* commissioning run, from the start, announcing at the normal rate
//! from a single IP and not touching motion topics is indistinguishable
//! from a legitimate node by traffic alone; only the operator's review of
//! the participant list (which the report gives with IPs and topics) can
//! catch it. "Late" and "brief" are measured in **capture time** when the
//! input has timestamps (packet captures), so flooding the bus with frames
//! cannot dilute them; for timestamp-less input (JSONL lines) they fall back
//! to input positions, which a flood of input can skew, and the report says
//! so (`presence_measured_by_position`, info). Capture timestamps come from
//! the capture file (written by the commissioning host, not by bus
//! participants). With caps hit, which entries got in depends on arrival
//! order.
//!
//! # Anomalies
//!
//! Non-finite or negative speeds, empty topics/channels, ROS names that
//! `Profile::validate` would reject (whitespace or control characters),
//! GUID prefixes that are not 24 lower-case hex chars and capacity overflow
//! are counted as anomalies and never feed the profile. A clean run should
//! have none; the report says so loudly.
//!
//! # Determinism
//!
//! All state lives in `BTreeMap`/`BTreeSet`; no clocks, no hashing, no
//! randomness. Below the caps the profile depends only on sets, maxima and
//! per-run presence, so it is independent of event order within a run and
//! of the order in which learners are [`merge`](Learner::merge)d.
//!
//! # Positions
//!
//! `RobotEvent` carries no timestamp, so "first/last seen" in the report are
//! [`SeenAt`] positions: (run index, position in that run), where position is the JSONL
//! line number, the frame ordinal for pcap input, or the event ordinal for
//! in-memory sources.

use crate::input::{CaptureDiagnostics, EventSource, InputError, Origin, SourcedEvent};
use crate::signoff::{Signoff, SignoffItem};
use crate::stats::{SampleBuffer, SpeedStats};
use robodr_events::graph::{ActionRole, RosName, RosNameKind};
use robodr_events::profile::{Envelope, ParticipantIdentity, Profile, ProfileError};
use robodr_events::RobotEvent;
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};
use std::fmt;
use std::time::Duration;

/// Default safety margin applied to observed maxima.
pub const DEFAULT_MARGIN: f64 = 1.10;
/// Upper bound on the margin: beyond 10x the envelope stops meaning anything.
pub const MAX_MARGIN: f64 = 10.0;
/// Below this many valid samples per dimension, an envelope needs sign-off.
pub const DEFAULT_MIN_SAMPLES: u64 = 30;
/// Model name used when none is given (flagged in the report).
pub const DEFAULT_MODEL: &str = "unnamed-model";
/// At most this many anomalies are kept verbatim; all are counted.
pub const MAX_STORED_ANOMALIES: usize = 1000;
/// Default hard cap on any learned linear envelope, m/s. Generous for a
/// ground UGV; set `--hard-cap-linear` to the platform's physical limit.
pub const DEFAULT_HARD_CAP_LINEAR: f64 = 10.0;
/// Default hard cap on any learned joint envelope, rad/s.
pub const DEFAULT_HARD_CAP_JOINT: f64 = 10.0;
/// Default hard cap on a learned `max_joint_torque`, N·m (above the
/// largest joint torque in Unitree's published specifications; set
/// `--hard-cap-torque` to the platform's motors).
pub const DEFAULT_HARD_CAP_TORQUE: f64 = 400.0;
/// Default hard cap on a learned `max_joint_kp` (the SDK examples use up to
/// 500, `example/g1/g1d/g1d_waist_example.cpp`).
pub const DEFAULT_HARD_CAP_KP: f64 = 1000.0;
/// Default hard cap on a learned `max_joint_position_step`, rad per
/// command (a 500 Hz controller moves far less).
pub const DEFAULT_HARD_CAP_POSITION_STEP: f64 = 0.5;

/// The low-level joint-command terms learned besides linear / joint speed
/// (`MotionCommand::joint_torque`, `joint_kp`, `joint_position_step`):
/// `(dimension, unit)`. Learned like a speed (`max * margin`, capped by
/// the term's hard cap) but only on channels whose commands carry the term:
/// a term never observed stays `None`, which `Profile::evaluate` reports as
/// `robot.motion.unverifiable_command` for a command that uses it (never as
/// "unlimited").
pub const JOINT_TERMS: [(&str, &str); 3] = [
    ("joint_torque", "N·m"),
    ("joint_kp", ""),
    ("joint_position_step", "rad"),
];
/// A participant announced fewer times than this is quarantined.
pub const DEFAULT_MIN_PARTICIPANT_ANNOUNCEMENTS: u64 = 2;
/// With capture timestamps, a participant observed for less than this (in
/// every run it appears in) is quarantined.
pub const DEFAULT_MIN_PARTICIPANT_DURATION: Duration = Duration::from_secs(5);
/// First seen after this fraction of the run: flagged "late".
pub const DEFAULT_LATE_FRACTION: f64 = 0.25;
/// Present for less than this fraction of the run: flagged "brief".
pub const DEFAULT_BRIEF_FRACTION: f64 = 0.5;
/// An envelope dimension whose observed maximum exceeds this many times its
/// 99th percentile needs sign-off (`envelope_outlier`): one stray (or
/// injected) sample is setting the bound.
pub const DEFAULT_OUTLIER_RATIO: f64 = 3.0;
/// Topics always treated as motion topics (writers need sign-off), in
/// addition to learned motion channels and the name heuristic in
/// [`is_motion_like`].
pub const DEFAULT_MOTION_TOPICS: [&str; 1] = ["/cmd_vel"];
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
/// How many example names a summary warning lists.
const EXAMPLES_SHOWN: usize = 20;

/// Name heuristic for "this topic probably commands motion": the last
/// segment contains `cmd`, `command`, `twist` or `trajectory`. Over-broad
/// on purpose: a false hit only costs one sign-off line.
pub fn is_motion_like(topic: &str) -> bool {
    let last = topic
        .rsplit('/')
        .next()
        .unwrap_or(topic)
        .to_ascii_lowercase();
    ["cmd", "command", "twist", "trajectory"]
        .iter()
        .any(|k| last.contains(k))
}

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

/// Prefix of the pseudo-address under which announcements relayed by a
/// *trusted* discovery server are recorded (see [`DiscoveryServer`]).
pub const RELAY_MARK: &str = "relay:";
/// Max configured discovery servers (as the sensor pipeline).
pub const MAX_DISCOVERY_SERVERS: usize = 32;

/// A configured discovery server (or other relay): announcements it sends
/// on behalf of other participants are attributed to their owners. See the
/// module docs, "Endpoint provenance".
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct DiscoveryServer {
    /// The server's GUID prefix (the RTPS sender prefix of what it relays).
    pub prefix: Option<String>,
    /// The server's source IP.
    pub ip: Option<std::net::IpAddr>,
    /// Trusted: relayed endpoints are learned for accepted owners without a
    /// direct announcement, and relayed participant announcements count
    /// for the gate. A trusted server must have an `ip` (see
    /// [`DiscoveryServer::parse`]).
    pub trusted: bool,
}

fn canonical_ip(ip: std::net::IpAddr) -> std::net::IpAddr {
    ip.to_canonical()
}

impl DiscoveryServer {
    /// Parse `PREFIX`, `PREFIX@IP`, `@IP` or a bare `IP`. A trusted server
    /// must include the IP: `PREFIX` alone is refused for `trusted` (the
    /// header prefix is sender-controlled and would let any host launder
    /// spoofed relays); it is fine for a known server.
    pub fn parse(spec: &str, trusted: bool) -> Result<Self, ConfigError> {
        let bad = || ConfigError::InvalidDiscoveryServer(spec.chars().take(128).collect());
        let (prefix, ip) = match spec.split_once('@') {
            Some((p, i)) => (Some(p).filter(|p| !p.is_empty()), Some(i)),
            None if is_guid_prefix(spec) => (Some(spec), None),
            None => (None, Some(spec)),
        };
        let ip = ip
            .map(|i| i.parse::<std::net::IpAddr>().map_err(|_| bad()))
            .transpose()?
            .map(canonical_ip);
        let s = Self {
            prefix: prefix.map(str::to_string),
            ip,
            trusted,
        };
        if trusted && s.ip.is_none() && s.prefix.is_some() {
            return Err(ConfigError::InvalidDiscoveryServer(format!(
                "{} (a trusted discovery server must be pinned by IP: PREFIX@IP or IP)",
                spec.chars().take(128).collect::<String>()
            )));
        }
        s.validate().map_err(|_| bad())?;
        Ok(s)
    }

    fn validate(&self) -> Result<(), ConfigError> {
        let bad = || ConfigError::InvalidDiscoveryServer(self.label());
        if self.prefix.is_none() && self.ip.is_none() {
            return Err(bad());
        }
        if self.prefix.as_deref().is_some_and(|p| !is_guid_prefix(p)) {
            return Err(bad());
        }
        if self.ip.is_some_and(|i| i.is_unspecified()) {
            return Err(bad());
        }
        if self.trusted && self.ip.is_none() {
            return Err(ConfigError::InvalidDiscoveryServer(format!(
                "{} (a trusted discovery server must be pinned by IP: PREFIX@IP or IP)",
                self.label()
            )));
        }
        Ok(())
    }

    /// Did this server send a message with origin `o`? Every configured
    /// part (prefix, IP) must match.
    pub fn matches(&self, o: &Origin) -> bool {
        self.prefix.as_deref().is_none_or(|p| p == o.sender_prefix)
            && self.ip.is_none_or(|ip| {
                o.src_ip
                    .parse::<std::net::IpAddr>()
                    .is_ok_and(|x| canonical_ip(x) == ip)
            })
    }

    /// `prefix@ip`, `prefix` or `@ip`.
    pub fn label(&self) -> String {
        format!(
            "{}{}",
            self.prefix.as_deref().unwrap_or(""),
            self.ip.map(|i| format!("@{i}")).unwrap_or_default()
        )
    }
}

fn is_guid_prefix(g: &str) -> bool {
    g.len() == 24 && g.bytes().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f'))
}

/// Memory caps. Entries beyond a cap are dropped (never learned), counted
/// and reported; see the module docs.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Limits {
    /// Distinct participants (and distinct referenced GUIDs).
    pub max_participants: usize,
    /// Distinct names per kind (writer topics, reader topics, services,
    /// actions, raw topics).
    pub max_names: usize,
    /// Distinct motion channels.
    pub max_motion_channels: usize,
    /// Entries per inner set (participants per topic, IPs per participant,
    /// type names, sources per motion channel).
    pub max_set_entries: usize,
    /// Retained samples per motion channel and dimension (decimated
    /// beyond; count/min/max stay exact).
    pub max_samples: usize,
}

impl Default for Limits {
    fn default() -> Self {
        Self {
            max_participants: 4096,
            max_names: 16384,
            max_motion_channels: 256,
            max_set_entries: 256,
            max_samples: 16384,
        }
    }
}

/// Learner configuration.
#[derive(Debug, Clone, PartialEq)]
pub struct LearnConfig {
    pub model: String,
    /// Multiplier on observed max speed, in `[1.0, MAX_MARGIN]`.
    pub margin: f64,
    /// OEM ceiling for linear speed (m/s); envelopes never exceed it.
    pub ceiling_linear: Option<f64>,
    /// OEM ceiling for joint speed (rad/s); envelopes never exceed it.
    pub ceiling_joint: Option<f64>,
    /// Absolute cap on any learned linear envelope (m/s), always applied.
    pub hard_cap_linear: f64,
    /// Absolute cap on any learned joint envelope (rad/s), always applied.
    pub hard_cap_joint: f64,
    /// Absolute cap on a learned `max_joint_torque` (N·m).
    pub hard_cap_torque: f64,
    /// Absolute cap on a learned `max_joint_kp`.
    pub hard_cap_kp: f64,
    /// Absolute cap on a learned `max_joint_position_step` (rad).
    pub hard_cap_position_step: f64,
    /// Minimum valid samples per dimension for an envelope to be trusted
    /// without sign-off.
    pub min_samples: u64,
    /// Learn `reader_topics` (which turns reader-topic enforcement on) and
    /// reader-side services / actions / raw names. Off by default; see the
    /// module docs for why.
    pub learn_readers: bool,
    /// Participants announced fewer times are quarantined (>= 1).
    pub min_participant_announcements: u64,
    /// With capture timestamps: participants observed for less are
    /// quarantined. `Duration::ZERO` disables the check.
    pub min_participant_duration: Duration,
    /// First seen after this fraction of a run: flagged late. In `[0, 1]`.
    pub late_fraction: f64,
    /// Present for less than this fraction of a run: flagged brief.
    pub brief_fraction: f64,
    /// `max > p99 * outlier_ratio` on an envelope dimension raises the
    /// `envelope_outlier` sign-off item. Finite, `>= 1`.
    pub outlier_ratio: f64,
    /// Operator override: learn these participants even if quarantined
    /// (each becomes a sign-off item).
    pub accept_participants: BTreeSet<String>,
    /// Extra topics whose writers need sign-off (de-mangled ROS names).
    pub motion_topics: BTreeSet<String>,
    /// Discovery servers whose relayed announcements are attributed to
    /// their owners (see the module docs). At most
    /// [`MAX_DISCOVERY_SERVERS`].
    pub discovery_servers: Vec<DiscoveryServer>,
    pub limits: Limits,
    /// Do not write `participant_identities` (GUID matching only: the
    /// profile then matches only the processes of the learned run).
    pub no_identities: bool,
}

impl Default for LearnConfig {
    fn default() -> Self {
        Self {
            model: DEFAULT_MODEL.into(),
            margin: DEFAULT_MARGIN,
            ceiling_linear: None,
            ceiling_joint: None,
            hard_cap_linear: DEFAULT_HARD_CAP_LINEAR,
            hard_cap_joint: DEFAULT_HARD_CAP_JOINT,
            hard_cap_torque: DEFAULT_HARD_CAP_TORQUE,
            hard_cap_kp: DEFAULT_HARD_CAP_KP,
            hard_cap_position_step: DEFAULT_HARD_CAP_POSITION_STEP,
            min_samples: DEFAULT_MIN_SAMPLES,
            learn_readers: false,
            min_participant_announcements: DEFAULT_MIN_PARTICIPANT_ANNOUNCEMENTS,
            min_participant_duration: DEFAULT_MIN_PARTICIPANT_DURATION,
            late_fraction: DEFAULT_LATE_FRACTION,
            brief_fraction: DEFAULT_BRIEF_FRACTION,
            outlier_ratio: DEFAULT_OUTLIER_RATIO,
            accept_participants: BTreeSet::new(),
            motion_topics: DEFAULT_MOTION_TOPICS
                .iter()
                .map(|s| s.to_string())
                .collect(),
            discovery_servers: Vec::new(),
            limits: Limits::default(),
            no_identities: false,
        }
    }
}

/// Invalid learner configuration.
#[derive(Debug, Clone, PartialEq)]
pub enum ConfigError {
    EmptyModel,
    InvalidMargin(f64),
    InvalidCeiling {
        dimension: &'static str,
        value: f64,
    },
    InvalidHardCap {
        dimension: &'static str,
        value: f64,
    },
    InvalidFraction {
        name: &'static str,
        value: f64,
    },
    InvalidOutlierRatio(f64),
    InvalidMinAnnouncements,
    InvalidLimit {
        name: &'static str,
    },
    InvalidAcceptedParticipant(String),
    InvalidMotionTopic(String),
    /// A discovery server spec that names neither a valid GUID prefix nor a
    /// valid IP, or too many servers.
    InvalidDiscoveryServer(String),
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
            ConfigError::InvalidHardCap { dimension, value } => write!(
                f,
                "{dimension} hard cap {value} invalid: must be finite and > 0"
            ),
            ConfigError::InvalidFraction { name, value } => {
                write!(f, "{name} {value} invalid: must be in [0, 1]")
            }
            ConfigError::InvalidOutlierRatio(v) => {
                write!(f, "outlier ratio {v} invalid: must be finite and >= 1")
            }
            ConfigError::InvalidMinAnnouncements => {
                write!(f, "minimum participant announcements must be at least 1")
            }
            ConfigError::InvalidLimit { name } => write!(f, "limit {name} must be at least 2"),
            ConfigError::InvalidAcceptedParticipant(g) => write!(
                f,
                "accepted participant {g:?} is not a 24-char lower-case hex GUID prefix"
            ),
            ConfigError::InvalidMotionTopic(t) => write!(
                f,
                "motion topic {t:?} is not a fully qualified ROS name (e.g. /cmd_vel)"
            ),
            ConfigError::InvalidDiscoveryServer(d) => write!(
                f,
                "discovery server {d:?} invalid: give PREFIX (24 lower-case hex chars), \
                 PREFIX@IP or IP, at most {MAX_DISCOVERY_SERVERS} servers"
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
        for (dimension, value) in [
            ("linear", self.hard_cap_linear),
            ("joint", self.hard_cap_joint),
            ("torque", self.hard_cap_torque),
            ("kp", self.hard_cap_kp),
            ("position step", self.hard_cap_position_step),
        ] {
            if !value.is_finite() || value <= 0.0 {
                return Err(ConfigError::InvalidHardCap { dimension, value });
            }
        }
        for (name, value) in [
            ("late fraction", self.late_fraction),
            ("brief fraction", self.brief_fraction),
        ] {
            if !(0.0..=1.0).contains(&value) {
                return Err(ConfigError::InvalidFraction { name, value });
            }
        }
        if !self.outlier_ratio.is_finite() || self.outlier_ratio < 1.0 {
            return Err(ConfigError::InvalidOutlierRatio(self.outlier_ratio));
        }
        if self.min_participant_announcements == 0 {
            return Err(ConfigError::InvalidMinAnnouncements);
        }
        let l = &self.limits;
        for (name, v) in [
            ("max_participants", l.max_participants),
            ("max_names", l.max_names),
            ("max_motion_channels", l.max_motion_channels),
            ("max_set_entries", l.max_set_entries),
            ("max_samples", l.max_samples),
        ] {
            if v < 2 {
                return Err(ConfigError::InvalidLimit { name });
            }
        }
        if let Some(g) = self.accept_participants.iter().find(|g| !is_guid_prefix(g)) {
            return Err(ConfigError::InvalidAcceptedParticipant(g.clone()));
        }
        if let Some(t) = self
            .motion_topics
            .iter()
            .find(|t| !ProfileSlot::Topic((*t).clone()).is_valid())
        {
            return Err(ConfigError::InvalidMotionTopic(t.clone()));
        }
        if self.discovery_servers.len() > MAX_DISCOVERY_SERVERS {
            return Err(ConfigError::InvalidDiscoveryServer(format!(
                "{} servers",
                self.discovery_servers.len()
            )));
        }
        for d in &self.discovery_servers {
            d.validate()?;
        }
        Ok(())
    }

    /// The configured discovery server that sent `o`, if any (a trusted
    /// match wins over a known one).
    pub fn discovery_server_for(&self, o: &Origin) -> Option<&DiscoveryServer> {
        let mut found: Option<&DiscoveryServer> = None;
        for d in self.discovery_servers.iter().filter(|d| d.matches(o)) {
            if found.is_none_or(|f| !f.trusted && d.trusted) {
                found = Some(d);
            }
        }
        found
    }

    /// The cap actually applied to one dimension: the OEM ceiling if it is
    /// tighter, else the hard cap.
    pub fn effective_cap(&self, joint: bool) -> f64 {
        let (ceiling, hard) = if joint {
            (self.ceiling_joint, self.hard_cap_joint)
        } else {
            (self.ceiling_linear, self.hard_cap_linear)
        };
        ceiling.map_or(hard, |c| c.min(hard))
    }

    /// The hard caps of the [`JOINT_TERMS`], in that order.
    pub fn joint_term_caps(&self) -> [f64; 3] {
        [
            self.hard_cap_torque,
            self.hard_cap_kp,
            self.hard_cap_position_step,
        ]
    }
}

/// Envelope bound for one dimension: `observed_max * margin`, rounded *up*
/// to 1e-6 (so profile.json shows `0.55`, not `0.5500000000000001`, and the
/// bound is never below the observed max), then capped at `ceiling`.
/// Returns `(bound, capped_by_ceiling)`. If the product overflows, the
/// observed max itself is used (still finite, still >= every sample).
/// A non-finite or negative `observed_max` yields the ceiling (or 0 without
/// one) so garbage can never produce a NaN/inf bound.
pub fn envelope_bound(observed_max: f64, margin: f64, ceiling: Option<f64>) -> (f64, bool) {
    if !observed_max.is_finite() || observed_max < 0.0 {
        return match ceiling {
            Some(c) if c.is_finite() && c >= 0.0 => (c, true),
            _ => (0.0, false),
        };
    }
    let margin = if margin.is_finite() && margin >= 1.0 {
        margin
    } else {
        1.0
    };
    let product = observed_max * margin;
    let scaled = if product.is_finite() {
        quantise_up(product).max(observed_max)
    } else {
        observed_max
    };
    match ceiling {
        Some(c) if c.is_finite() && scaled > c => (c.max(0.0), true),
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
        run: at.run.saturating_add(runs),
        position: at.position,
    }
}

fn touch(span: &mut Option<Span>, at: SeenAt) {
    match span {
        Some(s) => s.hit(at),
        None => *span = Some(Span::new(at)),
    }
}

fn merge_span(dst: &mut Option<Span>, src: &Option<Span>, off: usize) {
    if let Some(s) = src {
        let s = s.shifted(off);
        match dst {
            Some(d) => d.absorb(&s),
            None => *dst = Some(s),
        }
    }
}

/// Extent of positions and timestamps within one run.
#[derive(Debug, Clone, Copy, Default, PartialEq)]
struct Extent {
    min_pos: Option<u64>,
    max_pos: Option<u64>,
    min_ts: Option<Duration>,
    max_ts: Option<Duration>,
}

impl Extent {
    fn update(&mut self, pos: u64, ts: Option<Duration>) {
        self.min_pos = Some(self.min_pos.map_or(pos, |m| m.min(pos)));
        self.max_pos = Some(self.max_pos.map_or(pos, |m| m.max(pos)));
        if let Some(t) = ts {
            self.min_ts = Some(self.min_ts.map_or(t, |m| m.min(t)));
            self.max_ts = Some(self.max_ts.map_or(t, |m| m.max(t)));
        }
    }
    fn absorb(&mut self, o: &Extent) {
        if let (Some(a), Some(b)) = (o.min_pos, o.max_pos) {
            self.update(a, o.min_ts);
            self.update(b, o.max_ts);
        }
    }
    fn pos_span(&self) -> u64 {
        match (self.min_pos, self.max_pos) {
            (Some(a), Some(b)) => b.saturating_sub(a),
            _ => 0,
        }
    }
    fn duration(&self) -> Option<Duration> {
        Some(self.max_ts?.saturating_sub(self.min_ts?))
    }
}

#[derive(Debug, Clone, Default, PartialEq)]
struct ParticipantAcc {
    span: Option<Span>,
    src_ips: BTreeSet<String>,
    /// Presence per run index.
    runs: BTreeMap<usize, Extent>,
    /// Presence per source IP (same keys as `src_ips`): the anti-poisoning
    /// gate is applied to every (participant, IP) pair to decide which IPs
    /// are the participant's *commissioned* IPs.
    ip_presence: BTreeMap<String, IpAcc>,
}

#[derive(Debug, Clone, Default, PartialEq)]
struct IpAcc {
    count: u64,
    runs: BTreeMap<usize, Extent>,
}

impl IpAcc {
    fn absorb(&mut self, o: &IpAcc, off: usize) {
        self.count = self.count.saturating_add(o.count);
        for (r, e) in &o.runs {
            self.runs.entry(r + off).or_default().absorb(e);
        }
    }
}

/// Endpoint provenance: claimed owner GUID -> source IPs the announcement
/// came from (`""` = the input carries no sender, e.g. a JSONL recording of
/// the sensor's events). See [`Learner`] docs, "endpoint provenance".
type Origins = BTreeMap<String, BTreeSet<String>>;

/// Record that `guid` was announced from `ip`; `false` if a cap was hit.
fn note_origin(map: &mut Origins, guid: &str, ip: &str, cap: usize) -> bool {
    if !map.contains_key(guid) && map.len() >= cap {
        return false;
    }
    insert_capped(map.entry(guid.to_string()).or_default(), ip, cap)
}

fn merge_origins(dst: &mut Origins, src: &Origins, cap: usize) -> u64 {
    let mut dropped = 0;
    for (g, ips) in src {
        for ip in ips {
            if !note_origin(dst, g, ip, cap) {
                dropped += 1;
            }
        }
    }
    dropped
}

#[derive(Debug, Clone, Default, PartialEq)]
struct EndpointAcc {
    span: Option<Span>,
    participants: BTreeSet<String>,
    type_names: BTreeSet<String>,
    origins: Origins,
}

/// Endpoint announcements whose claimed owner is not their sender.
#[derive(Debug, Clone, PartialEq)]
struct MismatchAcc {
    owner: String,
    sender: String,
    src_ip: String,
    span: Span,
    /// Endpoint names (capped).
    names: BTreeSet<String>,
}

/// Announcements relayed for `owner` by a configured discovery server.
#[derive(Debug, Clone, PartialEq)]
struct RelayAcc {
    owner: String,
    sender: String,
    src_ip: String,
    server: String,
    trusted: bool,
    span: Span,
    /// `(slot, is_writer)` of every relayed endpoint (capped).
    endpoints: BTreeSet<(ProfileSlot, bool)>,
}

/// Services, actions and raw topics: who is on which side.
#[derive(Debug, Clone, Default, PartialEq)]
struct RoleAcc {
    span: Option<Span>,
    /// Services/actions: client participants. Raw topics: writers.
    side_a: BTreeSet<String>,
    /// Services/actions: server participants. Raw topics: readers.
    side_b: BTreeSet<String>,
    /// Participants seen on a writer endpoint of this name.
    writer_guids: BTreeSet<String>,
    /// Actions: components seen (`send_goal`, ..., `status`).
    components: BTreeSet<String>,
    type_names: BTreeSet<String>,
    /// Provenance of writer-side and reader-side announcements.
    writer_origins: Origins,
    reader_origins: Origins,
}

#[derive(Debug, Clone, Copy, Default, PartialEq)]
struct DimStat {
    n: u64,
    min: f64,
    max: f64,
}

impl DimStat {
    fn record(&mut self, v: f64) {
        if self.n == 0 {
            self.min = v;
            self.max = v;
        } else {
            self.min = self.min.min(v);
            self.max = self.max.max(v);
        }
        self.n = self.n.saturating_add(1);
    }
    fn absorb(&mut self, o: &DimStat) {
        if o.n == 0 {
            return;
        }
        if self.n == 0 {
            *self = *o;
        } else {
            self.min = self.min.min(o.min);
            self.max = self.max.max(o.max);
            self.n = self.n.saturating_add(o.n);
        }
    }
}

#[derive(Debug, Clone, Copy, Default, PartialEq)]
struct SourceStat {
    commands: u64,
    linear: DimStat,
    joint: DimStat,
    /// [`JOINT_TERMS`], in order.
    terms: [DimStat; 3],
}

#[derive(Debug, Clone, Default, PartialEq)]
struct MotionAcc {
    span: Option<Span>,
    /// Source table: `None` = command without `source_guid`.
    sources: Vec<Option<String>>,
    stats: Vec<SourceStat>,
    /// `(speed, source index)`.
    linear: SampleBuffer<(f64, u32)>,
    joint: SampleBuffer<(f64, u32)>,
    /// [`JOINT_TERMS`], in order.
    terms: [SampleBuffer<(f64, u32)>; 3],
}

impl MotionAcc {
    fn source_index(&mut self, src: &Option<String>, cap: usize) -> Option<usize> {
        if let Some(i) = self.sources.iter().position(|s| s == src) {
            return Some(i);
        }
        if self.sources.len() >= cap {
            return None;
        }
        self.sources.push(src.clone());
        self.stats.push(SourceStat::default());
        Some(self.sources.len() - 1)
    }
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
    extents: Vec<Extent>,
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
    /// Entries dropped per capacity category.
    overflow: BTreeMap<String, u64>,
    anomalies_total: u64,
    anomalies: Vec<Anomaly>,
    /// Endpoint announcements not learned because their claimed owner is
    /// not the participant that sent them, keyed by sign-off subject.
    sender_mismatch: BTreeMap<String, MismatchAcc>,
    /// Endpoint announcements relayed by a configured discovery server,
    /// keyed by sign-off subject.
    relayed: BTreeMap<String, RelayAcc>,
    /// Participant announcements relayed by a known (untrusted) discovery
    /// server: ignored by the gate, counted per server.
    relayed_spdp_ignored: BTreeMap<String, u64>,
}

/// The three artefacts of commissioning.
#[derive(Debug, Clone, PartialEq)]
pub struct Commissioning {
    pub profile: Profile,
    pub report: CommissioningReport,
    /// What a named operator must confirm before `lock` accepts `profile`.
    pub signoff: Signoff,
}

/// Verdict on one participant.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ParticipantStatus {
    /// Learned.
    Accepted,
    /// Learned only because the operator accepted it despite quarantine.
    OperatorAccepted,
    /// Not learned (nor its endpoints and motion samples).
    Quarantined,
}

/// Presence of a participant (or one of its IPs); see `Learner::presence`.
#[derive(Debug, Clone, Copy, PartialEq)]
struct Presence {
    observed: Option<Duration>,
    duration_applicable: bool,
    max_frac_presence: f64,
    min_first_frac: f64,
}

/// Accepted participants and their commissioned IPs (see `Learner::gate`).
struct Gate<'a> {
    accepted: BTreeSet<&'a str>,
    ips: BTreeMap<&'a str, BTreeSet<&'a str>>,
}

impl Gate<'_> {
    fn ip_ok(&self, g: &str, ip: &str) -> bool {
        self.ips.get(g).is_some_and(|s| s.contains(ip))
    }

    /// May an endpoint announced by `g` (with provenance `origins`) be
    /// learned? `g` must be accepted and at least one announcement must come
    /// from a commissioned IP of `g`, or from input without sender
    /// information (`""`: the sensor's own event recording).
    fn vouches(&self, origins: &Origins, g: &str) -> bool {
        self.accepted.contains(g)
            && origins.get(g).is_some_and(|ips| {
                ips.iter()
                    .any(|ip| ip.is_empty() || ip.starts_with(RELAY_MARK) || self.ip_ok(g, ip))
            })
    }
}

#[derive(Debug, Clone, PartialEq)]
struct Assessment {
    status: ParticipantStatus,
    quarantine: Vec<String>,
    /// `(sign-off kind, reason)`.
    flags: Vec<(&'static str, String)>,
    observed: Option<Duration>,
    runs_seen: usize,
}

impl Assessment {
    fn accepted(&self) -> bool {
        self.status != ParticipantStatus::Quarantined
    }
}

/// Insert into a capped set; `false` if it was full (value not stored).
fn insert_capped(set: &mut BTreeSet<String>, v: &str, cap: usize) -> bool {
    if set.contains(v) {
        return true;
    }
    if set.len() >= cap {
        return false;
    }
    set.insert(v.to_string());
    true
}

fn extend_capped(dst: &mut BTreeSet<String>, src: &BTreeSet<String>, cap: usize) -> u64 {
    let mut dropped = 0;
    for v in src {
        if !insert_capped(dst, v, cap) {
            dropped += 1;
        }
    }
    dropped
}

/// Get or create `key` in a capped map; `None` if full.
fn admit<'m, V: Default>(
    map: &'m mut BTreeMap<String, V>,
    key: &str,
    cap: usize,
) -> Option<&'m mut V> {
    if !map.contains_key(key) {
        if map.len() >= cap {
            return None;
        }
        map.insert(key.to_string(), V::default());
    }
    map.get_mut(key)
}

/// Sign-off subject of an `endpoint_sender_mismatch` item.
fn mismatch_subject(owner: &str, sender: &str, ip: &str) -> String {
    let ip: String = ip.chars().take(64).collect();
    format!("{owner} sent by {sender} from {ip}")
}

fn examples<'a>(names: impl IntoIterator<Item = &'a String>) -> (usize, String) {
    let all: Vec<&String> = names.into_iter().collect();
    let shown: Vec<&str> = all
        .iter()
        .take(EXAMPLES_SHOWN)
        .map(|s| s.as_str())
        .collect();
    let more = all.len().saturating_sub(EXAMPLES_SHOWN);
    let tail = if more > 0 {
        format!(" (+{more} more)")
    } else {
        String::new()
    };
    (all.len(), format!("{shown:?}{tail}"))
}

impl Learner {
    /// New learner; fails on an invalid configuration.
    pub fn new(config: LearnConfig) -> Result<Self, ConfigError> {
        config.validate()?;
        Ok(Self {
            config,
            runs: Vec::new(),
            extents: Vec::new(),
            events_by_kind: BTreeMap::new(),
            participants: BTreeMap::new(),
            writers: BTreeMap::new(),
            readers: BTreeMap::new(),
            services: BTreeMap::new(),
            actions: BTreeMap::new(),
            raw: BTreeMap::new(),
            motion: BTreeMap::new(),
            referenced_guids: BTreeMap::new(),
            overflow: BTreeMap::new(),
            anomalies_total: 0,
            anomalies: Vec::new(),
            sender_mismatch: BTreeMap::new(),
            relayed: BTreeMap::new(),
            relayed_spdp_ignored: BTreeMap::new(),
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
        self.extents.push(Extent::default());
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
        let pos = self.runs[run].events.saturating_add(1);
        self.observe_at_time(event, pos, None);
    }

    /// Observe one event at an explicit position (e.g. JSONL line number).
    pub fn observe_at(&mut self, event: &RobotEvent, position: u64) {
        self.observe_at_time(event, position, None);
    }

    /// Observe one event at an explicit position with an optional capture
    /// timestamp (used for minimum-duration and late/brief checks).
    pub fn observe_at_time(&mut self, event: &RobotEvent, position: u64, ts: Option<Duration>) {
        self.observe_from(event, position, ts, None);
    }

    /// Observe one event from a source, with its timestamp and sender
    /// ([`Origin`]) when the source has them (packet captures).
    pub fn observe_sourced(&mut self, se: &SourcedEvent) {
        self.observe_from(&se.event, se.position, se.ts, se.origin.as_ref());
    }

    fn observe_from(
        &mut self,
        event: &RobotEvent,
        position: u64,
        ts: Option<Duration>,
        origin: Option<&Origin>,
    ) {
        let run = self.current_run();
        self.runs[run].events = self.runs[run].events.saturating_add(1);
        self.extents[run].update(position, ts);
        let at = SeenAt { run, position };
        let kind = match event {
            RobotEvent::Ros2ParticipantDiscovered(_) => "ros2_participant_discovered",
            RobotEvent::Ros2WriterDiscovered(_) => "ros2_writer_discovered",
            RobotEvent::Ros2ReaderDiscovered(_) => "ros2_reader_discovered",
            RobotEvent::MotionCommand(_) => "motion_command",
            RobotEvent::MotionFeedback(_) => "motion_feedback",
        };
        let n = self.events_by_kind.entry(kind.into()).or_insert(0);
        *n = n.saturating_add(1);
        let lim = self.config.limits.clone();

        match event {
            RobotEvent::Ros2ParticipantDiscovered(p) => {
                if !self.check_guid(&p.guid_prefix, at) {
                    return;
                }
                if p.src_ip.starts_with(RELAY_MARK) {
                    let g: String = p.guid_prefix.chars().take(64).collect();
                    self.anomaly(
                        at,
                        "invalid_src_ip",
                        &g,
                        format!("source address may not start with {RELAY_MARK:?}; not learned"),
                    );
                    return;
                }
                let mut src_ip = p.src_ip.clone();
                if let Some(o) = origin.filter(|o| o.sender_prefix != p.guid_prefix) {
                    if let Some(ds) = self.config.discovery_server_for(o) {
                        if ds.trusted {
                            // Counts for the owner, under the server's
                            // pseudo-address (never the server's IP).
                            src_ip = format!("{RELAY_MARK}{}", ds.label());
                        } else {
                            let label = ds.label();
                            let n = self.relayed_spdp_ignored.entry(label).or_insert(0);
                            *n = n.saturating_add(1);
                            return;
                        }
                    }
                }
                let Some(acc) = admit(&mut self.participants, &p.guid_prefix, lim.max_participants)
                else {
                    self.overflowed(at, "participants", &p.guid_prefix);
                    return;
                };
                touch(&mut acc.span, at);
                acc.runs.entry(run).or_default().update(position, ts);
                if insert_capped(&mut acc.src_ips, &src_ip, lim.max_set_entries) {
                    let ip = acc.ip_presence.entry(src_ip).or_default();
                    ip.count = ip.count.saturating_add(1);
                    ip.runs.entry(run).or_default().update(position, ts);
                } else {
                    self.overflowed(at, "participant_src_ips", &p.guid_prefix);
                }
            }
            RobotEvent::Ros2WriterDiscovered(e) | RobotEvent::Ros2ReaderDiscovered(e) => {
                let is_writer = matches!(event, RobotEvent::Ros2WriterDiscovered(_));
                if e.topic.is_empty() {
                    let shown: String = e.guid_prefix.chars().take(64).collect();
                    self.anomaly(at, "empty_topic", &shown, "endpoint with empty topic");
                    return;
                }
                let rn = e.ros_name();
                let slot = ProfileSlot::of(&rn);
                if !slot.is_valid() {
                    let shown: String = e.topic.chars().take(128).collect();
                    let g: String = e.guid_prefix.chars().take(64).collect();
                    self.anomaly(
                        at,
                        "invalid_ros_name",
                        &g,
                        format!(
                            "endpoint name {shown:?} is not a valid ROS name (whitespace or \
                             control characters); not learned"
                        ),
                    );
                    return;
                }
                if !self.check_guid(&e.guid_prefix, at) {
                    return;
                }
                let mut relay_via: Option<String> = None;
                if let Some(o) = origin {
                    if o.sender_prefix != e.guid_prefix {
                        match self.config.discovery_server_for(o).cloned() {
                            Some(ds) => {
                                // Relayed by a configured server: judged at
                                // finish (see `relay_verdicts`); a trusted
                                // server's copy is also recorded for the
                                // owner under the relay pseudo-address.
                                self.relayed_endpoint(at, &e.guid_prefix, o, &ds, &slot, is_writer);
                                if !ds.trusted {
                                    return;
                                }
                                relay_via = Some(format!("{RELAY_MARK}{}", ds.label()));
                            }
                            None => {
                                // Claims a GUID other than its sender's:
                                // quarantined (never learned), reported, and
                                // a sign-off item.
                                self.sender_mismatched(at, &e.guid_prefix, o, slot.name());
                                return;
                            }
                        }
                    }
                }
                self.reference(&e.guid_prefix, at);
                let guid = e.guid_prefix.as_str();
                let via = match &relay_via {
                    Some(v) => v.as_str(),
                    None => origin.map_or("", |o| o.src_ip.as_str()),
                };
                let client = is_client_side(&rn.kind, is_writer);
                let mut dropped: Vec<&'static str> = Vec::new();
                match &slot {
                    ProfileSlot::Topic(topic) => {
                        let (map, cat) = if is_writer {
                            (&mut self.writers, "writer_topics")
                        } else {
                            (&mut self.readers, "reader_topics")
                        };
                        match admit(map, topic, lim.max_names) {
                            None => dropped.push(cat),
                            Some(acc) => {
                                touch(&mut acc.span, at);
                                if !insert_capped(&mut acc.participants, guid, lim.max_set_entries)
                                {
                                    dropped.push("topic_participants");
                                } else if !note_origin(
                                    &mut acc.origins,
                                    guid,
                                    via,
                                    lim.max_set_entries,
                                ) {
                                    dropped.push("endpoint_origins");
                                }
                                if !e.type_name.is_empty()
                                    && !insert_capped(
                                        &mut acc.type_names,
                                        &e.type_name,
                                        lim.max_set_entries,
                                    )
                                {
                                    dropped.push("type_names");
                                }
                            }
                        }
                    }
                    _ => {
                        let (map, cat, side_a) = match &slot {
                            ProfileSlot::Service(_) => {
                                (&mut self.services, "services", client == Some(true))
                            }
                            ProfileSlot::Action(_) => {
                                (&mut self.actions, "actions", client == Some(true))
                            }
                            _ => (&mut self.raw, "raw_dds_topics", is_writer),
                        };
                        match admit(map, slot.name(), lim.max_names) {
                            None => dropped.push(cat),
                            Some(acc) => {
                                touch(&mut acc.span, at);
                                let side = if side_a {
                                    &mut acc.side_a
                                } else {
                                    &mut acc.side_b
                                };
                                let mut ok = insert_capped(side, guid, lim.max_set_entries);
                                if is_writer {
                                    ok &= insert_capped(
                                        &mut acc.writer_guids,
                                        guid,
                                        lim.max_set_entries,
                                    );
                                }
                                if !ok {
                                    dropped.push("name_participants");
                                } else if !note_origin(
                                    if is_writer {
                                        &mut acc.writer_origins
                                    } else {
                                        &mut acc.reader_origins
                                    },
                                    guid,
                                    via,
                                    lim.max_set_entries,
                                ) {
                                    dropped.push("endpoint_origins");
                                }
                                if let RosNameKind::ActionPart { component, .. } = &rn.kind {
                                    // A fixed, small set of component names.
                                    acc.components.insert(component.as_str().to_string());
                                }
                                if !e.type_name.is_empty()
                                    && !insert_capped(
                                        &mut acc.type_names,
                                        &e.type_name,
                                        lim.max_set_entries,
                                    )
                                {
                                    dropped.push("type_names");
                                }
                            }
                        }
                    }
                }
                for cat in dropped {
                    self.overflowed(at, cat, slot.name());
                }
            }
            RobotEvent::MotionCommand(c) => {
                if c.channel.is_empty() {
                    self.anomaly(at, "empty_channel", "", "motion command with empty channel");
                    return;
                }
                if let Some(g) = &c.source_guid {
                    if !self.check_guid(g, at) {
                        // Not attributable to any participant: never learned.
                        return;
                    }
                    self.reference(g, at);
                }
                // A command carrying lateral / vertical axes (holonomic
                // base, or any Twist decoded by robodr-cdr) is learned by
                // its resultant ‖(x, y, z)‖: that is what `max_linear_speed`
                // bounds at evaluation time, and learning only `linear.x`
                // would make every sideways move of a mecanum base a
                // deviation after lock. Legacy x-only commands are learned
                // as before. Per-axis limits and `holonomic` are not
                // learned; the OEM sets them in the draft.
                let lin = if c.linear_y.is_some() || c.linear_z.is_some() {
                    c.linear_resultant()
                } else {
                    c.linear_speed
                };
                let linear = self.speed_sample(at, &c.channel, "linear", lin);
                let joint = self.speed_sample(at, &c.channel, "joint", c.joint_speed);
                let term_values = [c.joint_torque, c.joint_kp, c.joint_position_step];
                let mut terms = [None; 3];
                for (slot, ((dim, _), v)) in
                    terms.iter_mut().zip(JOINT_TERMS.iter().zip(term_values))
                {
                    *slot = self.speed_sample(at, &c.channel, dim, v);
                }
                let Some(acc) = admit(&mut self.motion, &c.channel, lim.max_motion_channels) else {
                    self.overflowed(at, "motion_channels", &c.channel);
                    return;
                };
                touch(&mut acc.span, at);
                let Some(idx) = acc.source_index(&c.source_guid, lim.max_set_entries) else {
                    self.overflowed(at, "motion_sources", &c.channel);
                    return;
                };
                let st = &mut acc.stats[idx];
                st.commands = st.commands.saturating_add(1);
                let tag = idx as u32;
                if let Some(v) = linear {
                    st.linear.record(v);
                    acc.linear.push((v, tag), lim.max_samples);
                }
                if let Some(v) = joint {
                    st.joint.record(v);
                    acc.joint.push((v, tag), lim.max_samples);
                }
                for (i, v) in terms.into_iter().enumerate() {
                    if let (Some(v), Some(s), Some(b)) =
                        (v, st.terms.get_mut(i), acc.terms.get_mut(i))
                    {
                        s.record(v);
                        b.push((v, tag), lim.max_samples);
                    }
                }
            }
            // Feedback is consumed by robodr-motion's consistency monitor; it
            // carries nothing the allowlist profile learns.
            RobotEvent::MotionFeedback(_) => {}
        }
    }

    /// Learn everything from a source as one new run. Strict: stops at and
    /// returns the first input error. Events before the error remain
    /// learned in this learner; callers that need all-or-nothing (the CLI
    /// does) must discard the learner on error.
    pub fn ingest(&mut self, src: &mut dyn EventSource) -> Result<u64, InputError> {
        self.start_run(src.label().to_string());
        let mut n: u64 = 0;
        while let Some(r) = src.next_event() {
            let se = r?;
            self.observe_sourced(&se);
            n = n.saturating_add(1);
        }
        let run = self.runs.len() - 1;
        self.runs[run].capture = src.capture_diagnostics();
        Ok(n)
    }

    /// Union another learner's observations into this one (multi-mission
    /// commissioning). `other`'s runs are appended after ours; this learner's
    /// configuration (margin, caps, gate, model) is kept, and its limits
    /// apply to the union. Below the caps, `a.merge(b)` and `b.merge(a)`
    /// yield the same profile.
    pub fn merge(&mut self, other: &Learner) {
        let off = self.runs.len();
        let lim = self.config.limits.clone();
        let cap = lim.max_set_entries;
        self.runs.extend(other.runs.iter().cloned());
        self.extents.extend(other.extents.iter().copied());
        for (k, v) in &other.events_by_kind {
            let n = self.events_by_kind.entry(k.clone()).or_insert(0);
            *n = n.saturating_add(*v);
        }
        let mut dropped: Vec<(&'static str, String, u64)> = Vec::new();
        for (g, p) in &other.participants {
            let Some(acc) = admit(&mut self.participants, g, lim.max_participants) else {
                dropped.push(("participants", g.clone(), 1));
                continue;
            };
            merge_span(&mut acc.span, &p.span, off);
            let mut d = 0;
            for (ip, pres) in &p.ip_presence {
                if insert_capped(&mut acc.src_ips, ip, cap) {
                    acc.ip_presence
                        .entry(ip.clone())
                        .or_default()
                        .absorb(pres, off);
                } else {
                    d += 1;
                }
            }
            // IPs without presence data (none today; kept for safety).
            for ip in p
                .src_ips
                .iter()
                .filter(|ip| !p.ip_presence.contains_key(*ip))
            {
                if !insert_capped(&mut acc.src_ips, ip, cap) {
                    d += 1;
                }
            }
            if d > 0 {
                dropped.push(("participant_src_ips", g.clone(), d));
            }
            for (r, e) in &p.runs {
                acc.runs.entry(r + off).or_default().absorb(e);
            }
        }
        for (mine, theirs, cat) in [
            (&mut self.writers, &other.writers, "writer_topics"),
            (&mut self.readers, &other.readers, "reader_topics"),
        ] {
            for (t, e) in theirs {
                let Some(acc) = admit(mine, t, lim.max_names) else {
                    dropped.push((cat, t.clone(), 1));
                    continue;
                };
                merge_span(&mut acc.span, &e.span, off);
                let d = extend_capped(&mut acc.participants, &e.participants, cap)
                    + extend_capped(&mut acc.type_names, &e.type_names, cap);
                if d > 0 {
                    dropped.push(("topic_participants", t.clone(), d));
                }
                let d = merge_origins(&mut acc.origins, &e.origins, cap);
                if d > 0 {
                    dropped.push(("endpoint_origins", t.clone(), d));
                }
            }
        }
        for (mine, theirs, cat) in [
            (&mut self.services, &other.services, "services"),
            (&mut self.actions, &other.actions, "actions"),
            (&mut self.raw, &other.raw, "raw_dds_topics"),
        ] {
            for (n, a) in theirs {
                let Some(acc) = admit(mine, n, lim.max_names) else {
                    dropped.push((cat, n.clone(), 1));
                    continue;
                };
                merge_span(&mut acc.span, &a.span, off);
                let d = extend_capped(&mut acc.side_a, &a.side_a, cap)
                    + extend_capped(&mut acc.side_b, &a.side_b, cap)
                    + extend_capped(&mut acc.writer_guids, &a.writer_guids, cap)
                    + extend_capped(&mut acc.type_names, &a.type_names, cap);
                acc.components.extend(a.components.iter().cloned());
                if d > 0 {
                    dropped.push(("name_participants", n.clone(), d));
                }
                let d = merge_origins(&mut acc.writer_origins, &a.writer_origins, cap)
                    + merge_origins(&mut acc.reader_origins, &a.reader_origins, cap);
                if d > 0 {
                    dropped.push(("endpoint_origins", n.clone(), d));
                }
            }
        }
        for (c, m) in &other.motion {
            let Some(acc) = admit(&mut self.motion, c, lim.max_motion_channels) else {
                dropped.push(("motion_channels", c.clone(), 1));
                continue;
            };
            merge_span(&mut acc.span, &m.span, off);
            let mut map: Vec<Option<usize>> = Vec::with_capacity(m.sources.len());
            for (i, src) in m.sources.iter().enumerate() {
                let idx = acc.source_index(src, cap);
                if let Some(j) = idx {
                    let st = &mut acc.stats[j];
                    st.commands = st.commands.saturating_add(m.stats[i].commands);
                    st.linear.absorb(&m.stats[i].linear);
                    st.joint.absorb(&m.stats[i].joint);
                    for (mine, theirs) in st.terms.iter_mut().zip(&m.stats[i].terms) {
                        mine.absorb(theirs);
                    }
                } else {
                    dropped.push(("motion_sources", c.clone(), 1));
                }
                map.push(idx);
            }
            for &(v, tag) in m.linear.retained() {
                if let Some(Some(j)) = map.get(tag as usize) {
                    acc.linear.push((v, *j as u32), lim.max_samples);
                }
            }
            for &(v, tag) in m.joint.retained() {
                if let Some(Some(j)) = map.get(tag as usize) {
                    acc.joint.push((v, *j as u32), lim.max_samples);
                }
            }
            for (mine, theirs) in acc.terms.iter_mut().zip(&m.terms) {
                for &(v, tag) in theirs.retained() {
                    if let Some(Some(j)) = map.get(tag as usize) {
                        mine.push((v, *j as u32), lim.max_samples);
                    }
                }
            }
        }
        for (g, at) in &other.referenced_guids {
            let at = shift(*at, off);
            if let Some(a) = self.referenced_guids.get_mut(g) {
                *a = (*a).min(at);
            } else if self.referenced_guids.len() < lim.max_participants {
                self.referenced_guids.insert(g.clone(), at);
            } else {
                dropped.push(("referenced_guids", g.clone(), 1));
            }
        }
        for (k, m) in &other.sender_mismatch {
            let span = m.span.shifted(off);
            if let Some(mine) = self.sender_mismatch.get_mut(k) {
                mine.span.absorb(&span);
                let d = extend_capped(&mut mine.names, &m.names, cap);
                if d > 0 {
                    dropped.push(("endpoint_sender_mismatch_names", k.clone(), d));
                }
            } else if self.sender_mismatch.len() < lim.max_participants {
                let mut m = m.clone();
                m.span = span;
                self.sender_mismatch.insert(k.clone(), m);
            } else {
                dropped.push(("endpoint_sender_mismatch", k.clone(), 1));
            }
        }
        for (k, m) in &other.relayed {
            let span = m.span.shifted(off);
            if let Some(mine) = self.relayed.get_mut(k) {
                mine.span.absorb(&span);
                for ep in &m.endpoints {
                    if mine.endpoints.contains(ep) {
                        continue;
                    }
                    if mine.endpoints.len() >= cap {
                        dropped.push(("relayed_endpoints", k.clone(), 1));
                    } else {
                        mine.endpoints.insert(ep.clone());
                    }
                }
            } else if self.relayed.len() < lim.max_participants {
                let mut m = m.clone();
                m.span = span;
                self.relayed.insert(k.clone(), m);
            } else {
                dropped.push(("relayed_endpoint_sources", k.clone(), 1));
            }
        }
        for (k, v) in &other.relayed_spdp_ignored {
            let n = self.relayed_spdp_ignored.entry(k.clone()).or_insert(0);
            *n = n.saturating_add(*v);
        }
        for (k, v) in &other.overflow {
            let n = self.overflow.entry(k.clone()).or_insert(0);
            *n = n.saturating_add(*v);
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
        let at = SeenAt {
            run: off,
            position: 0,
        };
        for (cat, subject, n) in dropped {
            for _ in 0..n {
                self.overflowed(at, cat, &subject);
            }
        }
    }

    fn reference(&mut self, guid: &str, at: SeenAt) {
        if let Some(a) = self.referenced_guids.get_mut(guid) {
            *a = (*a).min(at);
        } else if self.referenced_guids.len() < self.config.limits.max_participants {
            self.referenced_guids.insert(guid.to_string(), at);
        } else {
            self.overflowed(at, "referenced_guids", guid);
        }
    }

    /// An endpoint announcement whose claimed owner is not its sender.
    fn sender_mismatched(&mut self, at: SeenAt, owner: &str, o: &Origin, name: &str) {
        let key = mismatch_subject(owner, &o.sender_prefix, &o.src_ip);
        let cap = self.config.limits.max_set_entries;
        let shown: String = name.chars().take(256).collect();
        if let Some(m) = self.sender_mismatch.get_mut(&key) {
            m.span.hit(at);
            if !insert_capped(&mut m.names, &shown, cap) {
                self.overflowed(at, "endpoint_sender_mismatch_names", &key);
            }
        } else if self.sender_mismatch.len() < self.config.limits.max_participants {
            let mut names = BTreeSet::new();
            names.insert(shown);
            self.sender_mismatch.insert(
                key,
                MismatchAcc {
                    owner: owner.to_string(),
                    sender: o.sender_prefix.clone(),
                    src_ip: o.src_ip.clone(),
                    span: Span::new(at),
                    names,
                },
            );
        } else {
            self.overflowed(at, "endpoint_sender_mismatch", &key);
        }
    }

    /// An endpoint announcement relayed for `owner` by configured server
    /// `ds`.
    fn relayed_endpoint(
        &mut self,
        at: SeenAt,
        owner: &str,
        o: &Origin,
        ds: &DiscoveryServer,
        slot: &ProfileSlot,
        is_writer: bool,
    ) {
        let key = mismatch_subject(owner, &o.sender_prefix, &o.src_ip);
        let cap = self.config.limits.max_set_entries;
        let ep = (slot.clone(), is_writer);
        if let Some(m) = self.relayed.get_mut(&key) {
            m.span.hit(at);
            if !m.endpoints.contains(&ep) {
                if m.endpoints.len() >= cap {
                    self.overflowed(at, "relayed_endpoints", &key);
                } else {
                    m.endpoints.insert(ep);
                }
            }
        } else if self.relayed.len() < self.config.limits.max_participants {
            self.relayed.insert(
                key,
                RelayAcc {
                    owner: owner.to_string(),
                    sender: o.sender_prefix.clone(),
                    src_ip: o.src_ip.clone(),
                    server: ds.label(),
                    trusted: ds.trusted,
                    span: Span::new(at),
                    endpoints: [ep].into_iter().collect(),
                },
            );
        } else {
            self.overflowed(at, "relayed_endpoint_sources", &key);
        }
    }

    fn overflowed(&mut self, at: SeenAt, category: &'static str, subject: &str) {
        let n = self.overflow.entry(category.to_string()).or_insert(0);
        *n = n.saturating_add(1);
        let shown: String = subject.chars().take(128).collect();
        self.anomaly(
            at,
            "capacity_exceeded",
            &shown,
            format!("{category} cap reached; entry not learned"),
        );
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

    /// `true` if `guid` is a well-formed GUID prefix; records an anomaly if
    /// not (malformed GUIDs never feed the profile).
    fn check_guid(&mut self, guid: &str, at: SeenAt) -> bool {
        if is_guid_prefix(guid) {
            return true;
        }
        let shown: String = guid.chars().take(64).collect();
        self.anomaly(
            at,
            "malformed_guid_prefix",
            &shown,
            "GUID prefix is not 24 lower-case hex chars; not learned",
        );
        false
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
        let shown: String = channel.chars().take(128).collect();
        if !v.is_finite() {
            self.anomaly(
                at,
                &format!("non_finite_{dim}_speed"),
                &shown,
                format!("{dim} speed {v} ignored"),
            );
            return None;
        }
        if v < 0.0 {
            self.anomaly(
                at,
                &format!("negative_{dim}_speed"),
                &shown,
                format!("{dim} speed {v} ignored (speeds are absolute values)"),
            );
            return None;
        }
        // -0.0 normalised so it serialises as 0.
        Some(if v == 0.0 { 0.0 } else { v })
    }

    // ------------------------------------------------------------ gate ---

    fn assess(&self) -> BTreeMap<String, Assessment> {
        let c = &self.config;
        // Runs that carry participant announcements at all (a motion-only
        // JSONL run says nothing about who was present).
        let discovery_runs: BTreeSet<usize> = self
            .participants
            .values()
            .flat_map(|p| p.runs.keys().copied())
            .collect();
        let mut out = BTreeMap::new();
        for (g, acc) in &self.participants {
            let Some(span) = &acc.span else { continue };
            let mut quarantine = Vec::new();
            let mut flags: Vec<(&'static str, String)> = Vec::new();
            if span.count < c.min_participant_announcements {
                quarantine.push(format!(
                    "announced {} time(s) (< {} required)",
                    span.count, c.min_participant_announcements
                ));
            }
            let pr = self.presence(&acc.runs);
            let (observed, min_first_frac, max_frac_presence) =
                (pr.observed, pr.min_first_frac, pr.max_frac_presence);
            if let Some(why) = self.too_short(&pr) {
                quarantine.push(why);
            }
            if min_first_frac > c.late_fraction {
                flags.push((
                    "participant_late",
                    format!(
                        "first seen {:.0}% into the run (after {:.0}%); joined late: confirm it is \
                         part of the robot, not a tool or intruder",
                        100.0 * min_first_frac,
                        100.0 * c.late_fraction
                    ),
                ));
            }
            if max_frac_presence < c.brief_fraction {
                flags.push((
                    "participant_brief",
                    format!(
                        "present for only {:.0}% of the run (< {:.0}%): transient tool, laptop or \
                         intruder?",
                        100.0 * max_frac_presence,
                        100.0 * c.brief_fraction
                    ),
                ));
            }
            let real_ips: BTreeSet<&String> = acc
                .src_ips
                .iter()
                .filter(|ip| !ip.starts_with(RELAY_MARK))
                .collect();
            if real_ips.len() > 1 {
                flags.push((
                    "participant_multiple_ips",
                    format!(
                        "announced from {} source IPs {:?}: GUID spoofing or a multi-homed host",
                        real_ips.len(),
                        real_ips
                    ),
                ));
            }
            if discovery_runs.len() > 1 && acc.runs.len() < discovery_runs.len() {
                flags.push((
                    "participant_not_in_every_run",
                    format!(
                        "seen in {} of {} runs with discovery",
                        acc.runs.len(),
                        discovery_runs.len()
                    ),
                ));
            }
            let status = if quarantine.is_empty() {
                ParticipantStatus::Accepted
            } else if c.accept_participants.contains(g) {
                flags.push((
                    "participant_operator_accepted",
                    format!(
                        "accepted by operator override despite quarantine: {}",
                        quarantine.join("; ")
                    ),
                ));
                ParticipantStatus::OperatorAccepted
            } else {
                ParticipantStatus::Quarantined
            };
            out.insert(
                g.clone(),
                Assessment {
                    status,
                    quarantine,
                    flags,
                    observed,
                    runs_seen: acc.runs.len(),
                },
            );
        }
        out
    }

    /// Presence of one participant (or one participant IP) over its runs.
    ///
    /// Late / brief fractions use capture time when the run and the
    /// participant both have timestamps (packet captures), so flooding the
    /// capture with frames cannot move the fractions; they fall back to input
    /// positions only for timestamp-less input (JSONL), which the report
    /// flags (`presence_measured_by_position`).
    fn presence(&self, runs: &BTreeMap<usize, Extent>) -> Presence {
        let c = &self.config;
        let mut pr = Presence {
            observed: None,
            duration_applicable: false,
            max_frac_presence: 0.0,
            min_first_frac: 1.0,
        };
        for (r, e) in runs {
            let run = self.extents.get(*r).copied().unwrap_or_default();
            if let Some(d) = e.duration() {
                pr.observed = Some(pr.observed.map_or(d, |o| o.max(d)));
            }
            if let Some(rd) = run.duration() {
                if !c.min_participant_duration.is_zero() && rd >= c.min_participant_duration {
                    pr.duration_applicable = true;
                }
            }
            let (presence, first) = match (run.duration(), run.min_ts, e.min_ts, e.duration()) {
                (Some(rd), Some(rmin), Some(emin), Some(ed)) => {
                    if rd.is_zero() {
                        (1.0, 0.0)
                    } else {
                        let rd = rd.as_secs_f64();
                        (
                            ed.as_secs_f64() / rd,
                            emin.saturating_sub(rmin).as_secs_f64() / rd,
                        )
                    }
                }
                _ => {
                    let rs = run.pos_span();
                    if rs == 0 {
                        (1.0, 0.0)
                    } else {
                        let rmin = run.min_pos.unwrap_or(0);
                        let f = e.min_pos.unwrap_or(rmin).saturating_sub(rmin) as f64 / rs as f64;
                        (e.pos_span() as f64 / rs as f64, f)
                    }
                }
            };
            pr.max_frac_presence = pr.max_frac_presence.max(presence);
            pr.min_first_frac = pr.min_first_frac.min(first);
        }
        pr
    }

    /// The minimum-duration quarantine reason, if it applies.
    fn too_short(&self, pr: &Presence) -> Option<String> {
        let min = self.config.min_participant_duration;
        (pr.duration_applicable && pr.observed.unwrap_or_default() < min).then(|| {
            format!(
                "observed for {:.1}s (< {:.1}s required)",
                pr.observed.unwrap_or_default().as_secs_f64(),
                min.as_secs_f64()
            )
        })
    }

    /// The anti-poisoning gate, applied to `(participant, IP)` pairs: the
    /// IPs from which each accepted participant itself passes the gate
    /// (announced at least `min_participant_announcements` times from that
    /// IP and, with timestamps, present long enough). An operator-accepted
    /// participant has all its IPs commissioned. Endpoints announced from any
    /// other IP are not learned (`endpoint_sender_mismatch`).
    fn gate<'a>(&'a self, assessed: &'a BTreeMap<String, Assessment>) -> Gate<'a> {
        let accepted = Self::accepted_set(assessed);
        let mut ips = BTreeMap::new();
        for g in &accepted {
            let Some(acc) = self.participants.get(*g) else {
                continue;
            };
            let all = assessed
                .get(*g)
                .is_some_and(|a| a.status == ParticipantStatus::OperatorAccepted);
            let ok: BTreeSet<&'a str> = acc
                .ip_presence
                .iter()
                .filter(|(_, p)| {
                    all || (p.count >= self.config.min_participant_announcements
                        && self.too_short(&self.presence(&p.runs)).is_none())
                })
                .map(|(ip, _)| ip.as_str())
                .collect();
            ips.insert(*g, ok);
        }
        Gate { accepted, ips }
    }

    /// Stable identities of the accepted participants
    /// (`Profile::participant_identities`): DDS draws a new GUID prefix per
    /// process start, so the GUIDs in `participants` only match this run.
    ///
    /// Accepted participants are grouped by (commissioned source IPs, RTPS
    /// vendor id = first two bytes of the prefix, ROS nodes they serve
    /// parameters for). The same node seen in several runs (each with its
    /// own prefix) is one identity; `max_instances` is the most members of
    /// a group present in one run. A participant without a commissioned IP
    /// (sensor recordings without sender, relayed only) gets none.
    fn identities(&self, gate: &Gate<'_>) -> BTreeMap<String, ParticipantIdentity> {
        let mut nodes: BTreeMap<&str, BTreeSet<String>> = BTreeMap::new();
        for (name, a) in &self.services {
            let Some(node) = name.strip_suffix("/get_parameters") else {
                continue;
            };
            if node.is_empty() || robodr_events::graph::validate_full_name(node).is_err() {
                continue;
            }
            for g in &a.side_b {
                nodes.entry(g.as_str()).or_default().insert(node.to_owned());
            }
        }
        type Key = (BTreeSet<String>, String, BTreeSet<String>);
        let mut groups: BTreeMap<Key, Vec<&str>> = BTreeMap::new();
        for g in &gate.accepted {
            let ips: BTreeSet<String> = gate
                .ips
                .get(g)
                .into_iter()
                .flatten()
                .filter(|ip| ip.parse::<std::net::IpAddr>().is_ok())
                .take(robodr_events::profile::MAX_IDENTITY_IPS)
                .map(|ip| ip.to_string())
                .collect();
            if ips.is_empty() || g.len() != 24 {
                continue;
            }
            let n: BTreeSet<String> = nodes
                .get(g)
                .into_iter()
                .flatten()
                .take(robodr_events::profile::MAX_IDENTITY_NODES)
                .cloned()
                .collect();
            groups
                .entry((ips, g[..4].to_owned(), n))
                .or_default()
                .push(g);
        }
        let mut out = BTreeMap::new();
        for ((ips, vendor, nodes), members) in groups {
            if out.len() >= robodr_events::profile::MAX_IDENTITIES {
                break;
            }
            let mut per_run: BTreeMap<usize, u32> = BTreeMap::new();
            for m in &members {
                if let Some(acc) = self.participants.get(*m) {
                    for r in acc.runs.keys() {
                        *per_run.entry(*r).or_default() += 1;
                    }
                }
            }
            let max_instances = per_run
                .values()
                .copied()
                .max()
                .unwrap_or(1)
                .clamp(1, robodr_events::profile::MAX_IDENTITY_INSTANCES);
            let base: String = nodes
                .iter()
                .next()
                .map(|n| n.trim_start_matches('/').replace('/', "."))
                .filter(|s| !s.is_empty())
                .unwrap_or_else(|| format!("participant-{}", &members[0][..8]))
                .chars()
                .filter(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '_' | '-'))
                .take(56)
                .collect();
            let mut name = base.clone();
            let mut i = 2;
            while out.contains_key(&name) {
                name = format!("{base}-{i}");
                i += 1;
            }
            out.insert(
                name,
                ParticipantIdentity {
                    ips,
                    vendor,
                    enclave: None,
                    nodes,
                    max_instances,
                },
            );
        }
        out
    }

    /// Accepted announcements whose sender IP is not a commissioned IP of
    /// the claimed owner: `(owner, ip) -> endpoint names`.
    fn ip_mismatches(&self, gate: &Gate<'_>) -> BTreeMap<(String, String), BTreeSet<String>> {
        let mut out: BTreeMap<(String, String), BTreeSet<String>> = BTreeMap::new();
        let mut scan = |origins: &Origins, name: &str| {
            for (g, ips) in origins {
                if !gate.accepted.contains(g.as_str()) {
                    continue;
                }
                for ip in ips {
                    if !ip.is_empty() && !ip.starts_with(RELAY_MARK) && !gate.ip_ok(g, ip) {
                        out.entry((g.clone(), ip.clone()))
                            .or_default()
                            .insert(name.to_string());
                    }
                }
            }
        };
        for m in [&self.writers, &self.readers] {
            for (t, e) in m {
                scan(&e.origins, t);
            }
        }
        for m in [&self.services, &self.actions, &self.raw] {
            for (n, a) in m {
                scan(&a.writer_origins, n);
                scan(&a.reader_origins, n);
            }
        }
        out
    }

    /// Was `(slot, is_writer)` announced for `owner` with provenance the
    /// gate accepts (directly from a commissioned IP, from sender-less
    /// input, or relayed by a trusted discovery server)?
    fn endpoint_vouched(
        &self,
        gate: &Gate<'_>,
        slot: &ProfileSlot,
        is_writer: bool,
        owner: &str,
    ) -> bool {
        match slot {
            ProfileSlot::Topic(t) => {
                let m = if is_writer {
                    &self.writers
                } else {
                    &self.readers
                };
                m.get(t).is_some_and(|a| gate.vouches(&a.origins, owner))
            }
            _ => {
                let m = match slot {
                    ProfileSlot::Service(_) => &self.services,
                    ProfileSlot::Action(_) => &self.actions,
                    _ => &self.raw,
                };
                m.get(slot.name()).is_some_and(|a| {
                    gate.vouches(
                        if is_writer {
                            &a.writer_origins
                        } else {
                            &a.reader_origins
                        },
                        owner,
                    )
                })
            }
        }
    }

    /// Every relayed set: `(subject, acc, attributed?, why not)`. Attributed
    /// = the owner is accepted and every relayed endpoint is vouched for
    /// (see [`Self::endpoint_vouched`]): a copy of a direct announcement,
    /// or (trusted server) relayed for an accepted owner.
    fn relay_verdicts<'s>(&'s self, gate: &Gate<'_>) -> Vec<(String, &'s RelayAcc, bool, String)> {
        let mut out = Vec::new();
        for (subject, r) in &self.relayed {
            let (ok, why) = if !gate.accepted.contains(r.owner.as_str()) {
                (
                    false,
                    format!(
                        "the owner {} is not an accepted participant (quarantined or never \
                         announced itself)",
                        r.owner
                    ),
                )
            } else {
                let missing: Vec<String> = r
                    .endpoints
                    .iter()
                    .filter(|(slot, w)| !self.endpoint_vouched(gate, slot, *w, &r.owner))
                    .map(|(slot, w)| format!("{} {}", if *w { "W" } else { "R" }, slot.name()))
                    .collect();
                if missing.is_empty() {
                    (true, String::new())
                } else {
                    let (n, ex) = examples(&missing);
                    (
                        false,
                        format!(
                            "the owner never announced {n} of them directly from a commissioned \
                             IP ({ex}); a known (untrusted) server's relay only confirms direct \
                             announcements"
                        ),
                    )
                }
            };
            out.push((subject.clone(), r, ok, why));
        }
        out
    }

    fn accepted_set(assessed: &BTreeMap<String, Assessment>) -> BTreeSet<&str> {
        assessed
            .iter()
            .filter(|(_, a)| a.accepted())
            .map(|(g, _)| g.as_str())
            .collect()
    }

    /// Is `src` a source whose samples may shape an envelope?
    fn source_accepted(src: &Option<String>, accepted: &BTreeSet<&str>) -> bool {
        match src {
            None => true,
            Some(g) => accepted.contains(g.as_str()),
        }
    }

    fn role_learned(&self, a: &RoleAcc, gate: &Gate<'_>) -> bool {
        let writers = |s: &BTreeSet<String>| s.iter().any(|g| gate.vouches(&a.writer_origins, g));
        let any = |s: &BTreeSet<String>| {
            s.iter()
                .any(|g| gate.vouches(&a.writer_origins, g) || gate.vouches(&a.reader_origins, g))
        };
        writers(&a.writer_guids)
            || (self.config.learn_readers && (any(&a.side_a) || any(&a.side_b)))
    }

    /// Accepted per-dimension speed statistics of a channel (exact count,
    /// min and max; percentiles from the retained samples).
    fn accepted_stats(
        m: &MotionAcc,
        accepted: &BTreeSet<&str>,
    ) -> (Option<SpeedStats>, Option<SpeedStats>) {
        let (l, j, _) = Self::accepted_motion(m, accepted);
        let idx: BTreeSet<u32> = m
            .sources
            .iter()
            .enumerate()
            .filter(|(_, s)| Self::source_accepted(s, accepted))
            .map(|(i, _)| i as u32)
            .collect();
        let stats = |buf: &SampleBuffer<(f64, u32)>, d: &DimStat| {
            let retained: Vec<f64> = buf
                .retained()
                .iter()
                .filter(|(_, t)| idx.contains(t))
                .map(|(v, _)| *v)
                .collect();
            SpeedStats::from_parts(d.n, d.min, d.max, &retained, buf.is_decimated())
        };
        (stats(&m.linear, &l), stats(&m.joint, &j))
    }

    /// Bound written for a dimension the run never exercised on a channel
    /// that has an envelope: the OEM ceiling if one is configured, else 0
    /// (deny). Never `None`, which would mean "unlimited".
    pub fn unobserved_bound(&self, joint: bool) -> f64 {
        let ceiling = if joint {
            self.config.ceiling_joint
        } else {
            self.config.ceiling_linear
        };
        ceiling.map_or(0.0, |c| c.min(self.config.effective_cap(joint)))
    }

    /// `(max, p99)` when the maximum is more than `outlier_ratio` times the
    /// 99th percentile.
    fn outlier(&self, st: &Option<SpeedStats>) -> Option<(f64, f64)> {
        let st = st.as_ref()?;
        (st.samples >= 2 && st.max > st.p99 * self.config.outlier_ratio).then_some((st.max, st.p99))
    }

    /// Accepted per-dimension stats of a channel: `(linear, joint, commands)`.
    fn accepted_motion(m: &MotionAcc, accepted: &BTreeSet<&str>) -> (DimStat, DimStat, u64) {
        let (mut l, mut j, mut n) = (DimStat::default(), DimStat::default(), 0u64);
        for (src, st) in m.sources.iter().zip(&m.stats) {
            if Self::source_accepted(src, accepted) {
                l.absorb(&st.linear);
                j.absorb(&st.joint);
                n = n.saturating_add(st.commands);
            }
        }
        (l, j, n)
    }

    fn dim_bound(&self, d: &DimStat, joint: bool) -> Option<(f64, f64, bool)> {
        self.capped_bound(d, self.config.effective_cap(joint))
    }

    /// `(max, bound, capped)` of a dimension with `cap`; `None` if never
    /// observed.
    fn capped_bound(&self, d: &DimStat, cap: f64) -> Option<(f64, f64, bool)> {
        if d.n == 0 {
            return None;
        }
        let (bound, capped) = envelope_bound(d.max, self.config.margin, Some(cap));
        Some((d.max, bound, capped))
    }

    /// Accepted stats of a channel's [`JOINT_TERMS`].
    fn accepted_terms(m: &MotionAcc, accepted: &BTreeSet<&str>) -> [DimStat; 3] {
        let mut out = [DimStat::default(); 3];
        for (src, st) in m.sources.iter().zip(&m.stats) {
            if Self::source_accepted(src, accepted) {
                for (o, s) in out.iter_mut().zip(&st.terms) {
                    o.absorb(s);
                }
            }
        }
        out
    }

    /// Percentile stats of a channel's [`JOINT_TERMS`] (accepted sources).
    fn accepted_term_stats(m: &MotionAcc, accepted: &BTreeSet<&str>) -> [Option<SpeedStats>; 3] {
        let d = Self::accepted_terms(m, accepted);
        let idx: BTreeSet<u32> = m
            .sources
            .iter()
            .enumerate()
            .filter(|(_, s)| Self::source_accepted(s, accepted))
            .map(|(i, _)| i as u32)
            .collect();
        let mut out: [Option<SpeedStats>; 3] = [None, None, None];
        for ((o, buf), d) in out.iter_mut().zip(&m.terms).zip(&d) {
            let retained: Vec<f64> = buf
                .retained()
                .iter()
                .filter(|(_, t)| idx.contains(t))
                .map(|(v, _)| *v)
                .collect();
            *o = SpeedStats::from_parts(d.n, d.min, d.max, &retained, buf.is_decimated());
        }
        out
    }

    /// The learned bounds of a channel's [`JOINT_TERMS`] (`None` for a term
    /// never observed).
    fn term_bounds(&self, terms: &[DimStat; 3]) -> [Option<f64>; 3] {
        let caps = self.config.joint_term_caps();
        let mut out = [None; 3];
        for ((o, d), cap) in out.iter_mut().zip(terms).zip(caps) {
            *o = self.capped_bound(d, cap).map(|t| t.1);
        }
        out
    }

    fn build_profile(&self, assessed: &BTreeMap<String, Assessment>) -> Profile {
        let gate = self.gate(assessed);
        let accepted = &gate.accepted;
        let mut p = Profile {
            model: self.config.model.clone(),
            locked: false,
            ..Default::default()
        };
        p.participants = accepted.iter().map(|g| g.to_string()).collect();
        if !self.config.no_identities {
            p.participant_identities = self.identities(&gate);
        }
        let topic_learned =
            |e: &EndpointAcc| e.participants.iter().any(|g| gate.vouches(&e.origins, g));
        p.writer_topics = self
            .writers
            .iter()
            .filter(|(_, e)| topic_learned(e))
            .map(|(t, _)| t.clone())
            .collect();
        if self.config.learn_readers {
            p.reader_topics = self
                .readers
                .iter()
                .filter(|(_, e)| topic_learned(e))
                .map(|(t, _)| t.clone())
                .collect();
        }
        let learned = |m: &BTreeMap<String, RoleAcc>| -> BTreeSet<String> {
            m.iter()
                .filter(|(_, a)| self.role_learned(a, &gate))
                .map(|(n, _)| n.clone())
                .collect()
        };
        p.services = learned(&self.services);
        p.actions = learned(&self.actions);
        p.raw_dds_topics = learned(&self.raw);
        for (ch, m) in &self.motion {
            let (l, j, n) = Self::accepted_motion(m, accepted);
            if n == 0 {
                continue; // only excluded sources: channel not learned
            }
            // A dimension never exercised gets an explicit bound (ceiling or
            // 0 = deny), never `None` = unlimited; sign-off item
            // `envelope_dimension_unobserved`. A channel with no valid sample
            // at all keeps an empty envelope, which `lock` refuses.
            let observed_any = l.n > 0 || j.n > 0;
            let bound = |d: &DimStat, joint: bool| match self.dim_bound(d, joint) {
                Some(t) => Some(t.1),
                None if observed_any => Some(self.unobserved_bound(joint)),
                None => None,
            };
            // Joint terms (Unitree low-level commands): learned where
            // observed, else left `None` (= a command using the term is
            // reported unverifiable, never treated as unlimited).
            let [torque, kp, step] = self.term_bounds(&Self::accepted_terms(m, accepted));
            let env = Envelope {
                max_linear_speed: bound(&l, false),
                max_joint_speed: bound(&j, true),
                max_joint_torque: torque,
                max_joint_kp: kp,
                max_joint_position_step: step,
                ..Default::default()
            };
            p.motion_envelopes.insert(ch.clone(), env);
        }
        // Unitree legacy UDP channels (Go1 generation) have no DDS writer to
        // learn: the protocol has no discovery. A learned legacy channel is
        // writable by construction (only the legacy UDP path of the sensor
        // ever produces commands on it); the sender IPs are configured in
        // the sensor's `unitree_legacy.command_senders`.
        let legacy: Vec<String> = p
            .motion_envelopes
            .keys()
            .filter(|ch| robodr_cdr::unitree_legacy::channels::ALL.contains(&ch.as_str()))
            .cloned()
            .collect();
        p.writer_topics.extend(legacy);
        // A motion channel whose writers were not learned (no accepted
        // participant announced a writer on it) cannot be enveloped: every
        // legitimate publisher would be an unknown writer, and
        // `Profile::validate` rejects the profile
        // (`MotionChannelNotWritable`). Leave it out, fail closed: commands on
        // it are then reported as an unprofiled channel. `build_report` warns
        // (`motion_envelope_dropped_no_writer`).
        for ch in Self::unwritable_motion_channels(&p) {
            p.motion_envelopes.remove(&ch);
        }
        p
    }

    /// Envelope channels of `p` that `Profile::validate` reports as not
    /// writable (same predicate as the runtime writer check).
    fn unwritable_motion_channels(p: &Profile) -> Vec<String> {
        match p.validate() {
            Ok(()) => Vec::new(),
            Err(errs) => errs
                .into_iter()
                .filter_map(|e| match e {
                    ProfileError::MotionChannelNotWritable { channel } => Some(channel),
                    _ => None,
                })
                .collect(),
        }
    }

    /// The draft profile (`locked: false`).
    pub fn profile(&self) -> Profile {
        self.build_profile(&self.assess())
    }

    /// Topics whose writers need sign-off: learned motion channels,
    /// configured motion topics and the name heuristic.
    fn motion_topic(&self, profile: &Profile, t: &str) -> bool {
        profile.motion_envelopes.contains_key(t)
            || self.config.motion_topics.contains(t)
            || is_motion_like(t)
    }

    fn signoff_items(
        &self,
        profile: &Profile,
        assessed: &BTreeMap<String, Assessment>,
    ) -> Vec<SignoffItem> {
        let gate = self.gate(assessed);
        let accepted = &gate.accepted;
        let mut items = Vec::new();
        for (g, a) in assessed {
            if !a.accepted() {
                continue;
            }
            for (kind, reason) in &a.flags {
                items.push(SignoffItem::new(kind, g, reason.clone()));
            }
        }
        // Every identity: from now on any process matching it is accepted
        // with a fresh GUID, including as a writer of whatever its learned
        // participants wrote (motion topics included).
        for (name, id) in &profile.participant_identities {
            items.push(crate::signoff::identity_item(name, id));
        }
        // Motion writers: topic writers on motion topics...
        for t in &profile.writer_topics {
            if !self.motion_topic(profile, t) {
                continue;
            }
            if let Some(e) = self.writers.get(t) {
                for g in e
                    .participants
                    .iter()
                    .filter(|g| gate.vouches(&e.origins, g))
                {
                    items.push(SignoffItem::new(
                        "motion_writer",
                        &format!("{t} {g}"),
                        format!(
                            "participant {g} may publish motion topic {t} once locked: confirm \
                             it is the robot's own controller/planner"
                        ),
                    ));
                }
            }
        }
        // ... and senders of motion commands that shaped an envelope.
        for (ch, m) in &self.motion {
            if !profile.motion_envelopes.contains_key(ch) {
                continue;
            }
            for (src, st) in m.sources.iter().zip(&m.stats) {
                match src {
                    Some(g) if accepted.contains(g.as_str()) => items.push(SignoffItem::new(
                        "motion_writer",
                        &format!("{ch} {g}"),
                        format!(
                            "participant {g} sent {} motion command(s) on {ch} that shaped its \
                             envelope",
                            st.commands
                        ),
                    )),
                    None => items.push(SignoffItem::new(
                        "motion_unattributed",
                        ch,
                        format!(
                            "{} motion command(s) on {ch} carried no source and still shaped the \
                             envelope: confirm the recording came from the robot's own stack",
                            st.commands
                        ),
                    )),
                    Some(_) => {}
                }
            }
            let (l, j, _) = Self::accepted_motion(m, accepted);
            let (ls, js) = Self::accepted_stats(m, accepted);
            let env = &profile.motion_envelopes[ch];
            for (dim, d, st, bound, joint, unit) in [
                ("linear", l, &ls, env.max_linear_speed, false, "m/s"),
                ("joint", j, &js, env.max_joint_speed, true, "rad/s"),
            ] {
                if d.n == 0 {
                    if let Some(b) = bound {
                        items.push(SignoffItem::new(
                            "envelope_dimension_unobserved",
                            &format!("{ch} {dim}"),
                            format!(
                                "no {dim} speed was observed on {ch}; its {dim} bound is set to \
                                 {b} {unit} ({}): confirm, or record a run that exercises it",
                                if b == 0.0 {
                                    "deny: any non-zero command deviates"
                                } else {
                                    "the configured OEM ceiling"
                                }
                            ),
                        ));
                    }
                }
                if let Some((max, p99)) = self.outlier(st) {
                    items.push(SignoffItem::new(
                        "envelope_outlier",
                        &format!("{ch} {dim}"),
                        format!(
                            "{ch} {dim}: max {max} {unit} is more than {}x the p99 {p99} {unit}; \
                             the envelope {} {unit} rests on outlier sample(s) (a stray or \
                             injected command?): confirm the maximum, or re-commission",
                            self.config.outlier_ratio,
                            bound.map_or_else(|| "-".to_string(), |b| b.to_string())
                        ),
                    ));
                }
                if d.n > 0 && d.n < self.config.min_samples {
                    items.push(SignoffItem::new(
                        "few_motion_samples",
                        &format!("{ch} {dim}"),
                        format!(
                            "{ch} {dim} envelope rests on {} sample(s) (< {}): confirm the \
                             bound or record a longer run",
                            d.n, self.config.min_samples
                        ),
                    ));
                }
                if d.n > 0 && d.max > self.config.effective_cap(joint) {
                    items.push(SignoffItem::new(
                        "observed_exceeds_cap",
                        &format!("{ch} {dim}"),
                        format!(
                            "{ch}: observed {dim} max {} exceeds the cap {}; envelope held at \
                             the cap, the clean run itself will deviate",
                            d.max,
                            self.config.effective_cap(joint)
                        ),
                    ));
                }
            }
            // The joint terms: same sign-off rules, their own caps.
            let terms = Self::accepted_terms(m, accepted);
            let term_stats = Self::accepted_term_stats(m, accepted);
            let term_env = [
                env.max_joint_torque,
                env.max_joint_kp,
                env.max_joint_position_step,
            ];
            for ((((dim, unit), d), st), (bound, cap)) in JOINT_TERMS
                .iter()
                .zip(&terms)
                .zip(&term_stats)
                .zip(term_env.into_iter().zip(self.config.joint_term_caps()))
            {
                if let Some((max, p99)) = self.outlier(st) {
                    items.push(SignoffItem::new(
                        "envelope_outlier",
                        &format!("{ch} {dim}"),
                        format!(
                            "{ch} {dim}: max {max} {unit} is more than {}x the p99 {p99} {unit}; \
                             the envelope {} {unit} rests on outlier sample(s) (a stray or \
                             injected command?): confirm the maximum, or re-commission",
                            self.config.outlier_ratio,
                            bound.map_or_else(|| "-".to_string(), |b| b.to_string())
                        ),
                    ));
                }
                if d.n > 0 && d.n < self.config.min_samples {
                    items.push(SignoffItem::new(
                        "few_motion_samples",
                        &format!("{ch} {dim}"),
                        format!(
                            "{ch} {dim} envelope rests on {} sample(s) (< {}): confirm the \
                             bound or record a longer run",
                            d.n, self.config.min_samples
                        ),
                    ));
                }
                if d.n > 0 && d.max > cap {
                    items.push(SignoffItem::new(
                        "observed_exceeds_cap",
                        &format!("{ch} {dim}"),
                        format!(
                            "{ch}: observed {dim} max {} exceeds the cap {cap}; envelope held \
                             at the cap, the clean run itself will deviate",
                            d.max
                        ),
                    ));
                }
            }
        }
        for (subject, reason) in self.mismatch_items(&gate) {
            items.push(SignoffItem::new(
                "endpoint_sender_mismatch",
                &subject,
                reason,
            ));
        }
        for (cat, n) in &self.overflow {
            items.push(SignoffItem::new(
                "capacity_exceeded",
                cat,
                format!(
                    "{n} {cat} entr(ies) dropped at the cap: a flood during commissioning is \
                     not a clean run; re-commission unless explained"
                ),
            ));
        }
        if self.anomalies_total > 0 {
            items.push(SignoffItem::new(
                "anomalies_present",
                "run",
                format!(
                    "{} anomalies in what should be a clean run",
                    self.anomalies_total
                ),
            ));
        }
        items
    }

    /// `(subject, reason)` of every `endpoint_sender_mismatch`: endpoint
    /// announcements claiming a GUID other than their sender's, and
    /// announcements from an IP that is not a commissioned IP of their
    /// owner. None of them were learned.
    fn mismatch_items(&self, gate: &Gate<'_>) -> Vec<(String, String)> {
        let mut out = Vec::new();
        for (subject, m) in &self.sender_mismatch {
            let (n, ex) = examples(&m.names);
            out.push((
                subject.clone(),
                format!(
                    "{} endpoint announcement(s) ({n} name(s): {ex}) sent by participant {} from \
                     {} claim to belong to participant {} (first at {}): NOT learned. A \
                     participant announcing endpoints under another's GUID is GUID spoofing (or \
                     a discovery relay); investigate before locking",
                    m.span.count, m.sender, m.src_ip, m.owner, m.span.first
                ),
            ));
        }
        for (subject, r, ok, why) in self.relay_verdicts(gate) {
            if ok {
                continue;
            }
            let names: BTreeSet<String> = r
                .endpoints
                .iter()
                .map(|(slot, w)| format!("{} {}", if *w { "W" } else { "R" }, slot.name()))
                .collect();
            let (n, ex) = examples(&names);
            out.push((
                subject,
                format!(
                    "{} endpoint announcement(s) ({n} endpoint(s): {ex}) relayed for participant \
                     {} by the configured {} discovery server {} (sender {} from {}, first at \
                     {}): {why}; NOT learned from the relay. Investigate before locking",
                    r.span.count,
                    r.owner,
                    if r.trusted { "trusted" } else { "known" },
                    r.server,
                    r.sender,
                    r.src_ip,
                    r.span.first
                ),
            ));
        }
        for ((g, ip), names) in self.ip_mismatches(gate) {
            let (n, ex) = examples(&names);
            out.push((
                mismatch_subject(&g, &g, &ip),
                format!(
                    "endpoint announcement(s) of participant {g} ({n} name(s): {ex}) came from \
                     {ip}, which is not one of its commissioned IPs (it did not pass the \
                     anti-poisoning gate from there): not learned from that IP; GUID spoofing \
                     from another host?"
                ),
            ));
        }
        out
    }

    /// The commissioning report.
    pub fn report(&self) -> CommissioningReport {
        let assessed = self.assess();
        let profile = self.build_profile(&assessed);
        let signoff = Signoff::new(&profile, self.signoff_items(&profile, &assessed));
        self.build_report(&assessed, &profile, &signoff)
    }

    /// Profile, report and sign-off list together.
    pub fn finish(&self) -> Commissioning {
        let assessed = self.assess();
        let profile = self.build_profile(&assessed);
        let signoff = Signoff::new(&profile, self.signoff_items(&profile, &assessed));
        let report = self.build_report(&assessed, &profile, &signoff);
        Commissioning {
            profile,
            report,
            signoff,
        }
    }

    fn build_report(
        &self,
        assessed: &BTreeMap<String, Assessment>,
        profile: &Profile,
        signoff: &Signoff,
    ) -> CommissioningReport {
        let gate = self.gate(assessed);
        let accepted = &gate.accepted;
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
        for (cat, n) in &self.overflow {
            warn(
                Warn,
                "capacity_exceeded",
                cat,
                format!("{n} {cat} entr(ies) dropped at the configured cap (flood?)"),
            );
        }

        // Reverse index participant -> topics, built once.
        let mut writes: BTreeMap<&str, BTreeSet<String>> = BTreeMap::new();
        let mut reads: BTreeMap<&str, BTreeSet<String>> = BTreeMap::new();
        for (idx, m) in [(&mut writes, &self.writers), (&mut reads, &self.readers)] {
            for (t, e) in m {
                for g in &e.participants {
                    idx.entry(g.as_str()).or_default().insert(t.clone());
                }
            }
        }

        // Participants.
        let mut participants = BTreeMap::new();
        for (g, acc) in &self.participants {
            let Some(span) = &acc.span else { continue };
            let Some(a) = assessed.get(g) else { continue };
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
            if a.status == ParticipantStatus::Quarantined {
                warn(
                    Warn,
                    "quarantined_participant",
                    g,
                    format!(
                        "participant {g} NOT learned ({}); nor are its endpoints and motion \
                         samples. If it belongs on the robot, re-run learn with \
                         --accept-participant {g}",
                        a.quarantine.join("; ")
                    ),
                );
            }
            for (kind, reason) in &a.flags {
                if a.accepted() {
                    warn(Warn, kind, g, format!("participant {g}: {reason}"));
                }
            }
            participants.insert(
                g.clone(),
                ParticipantReport {
                    announcements: span.count,
                    first_seen: span.first,
                    last_seen: span.last,
                    src_ips: acc.src_ips.clone(),
                    writer_topics: writes.get(g.as_str()).cloned().unwrap_or_default(),
                    reader_topics: reads.get(g.as_str()).cloned().unwrap_or_default(),
                    status: a.status,
                    quarantine_reasons: a.quarantine.clone(),
                    flags: a.flags.iter().map(|(k, _)| k.to_string()).collect(),
                    runs_seen: a.runs_seen,
                    observed_ms: a
                        .observed
                        .map(|d| u64::try_from(d.as_millis()).unwrap_or(u64::MAX)),
                },
            );
        }
        for g in &self.config.accept_participants {
            if !self.participants.contains_key(g) {
                warn(
                    Warn,
                    "accepted_participant_not_seen",
                    g,
                    format!(
                        "--accept-participant {g} given but it never announced itself; not added"
                    ),
                );
            }
        }
        for (g, at) in &self.referenced_guids {
            if !self.participants.contains_key(g) {
                warn(
                    Warn,
                    "unannounced_participant",
                    g,
                    format!(
                        "GUID {g} used by an endpoint or motion command (first at {at}) but never \
                         announced as a participant; neither it nor what it announced or \
                         commanded is in the profile"
                    ),
                );
            }
        }
        for (subject, reason) in self.mismatch_items(&gate) {
            warn(Warn, "endpoint_sender_mismatch", &subject, reason);
        }
        for (subject, r, ok, _) in self.relay_verdicts(&gate) {
            if ok {
                warn(
                    Info,
                    "discovery_relay_attributed",
                    &subject,
                    format!(
                        "{} announcement(s) of {} endpoint(s) relayed for {} by the {} discovery \
                         server {} were attributed to their owner ({})",
                        r.span.count,
                        r.endpoints.len(),
                        r.owner,
                        if r.trusted { "trusted" } else { "known" },
                        r.server,
                        if r.trusted {
                            "trusted relay of an accepted participant"
                        } else {
                            "copies of the owner's direct announcements"
                        }
                    ),
                );
            }
        }
        for (server, n) in &self.relayed_spdp_ignored {
            warn(
                Info,
                "discovery_relay_participants_ignored",
                server,
                format!(
                    "{n} participant announcement(s) relayed by the known discovery server \
                     {server} were ignored by the anti-poisoning gate (only participants' own \
                     announcements count; trust the server to count them)"
                ),
            );
        }
        // Run-level gate diagnostics.
        let discovery_runs: BTreeSet<usize> = self
            .participants
            .values()
            .flat_map(|p| p.runs.keys().copied())
            .collect();
        for i in discovery_runs {
            if self.extents.get(i).is_some_and(|e| e.min_ts.is_none()) {
                warn(
                    Info,
                    "presence_measured_by_position",
                    &format!("run{i}"),
                    format!(
                        "run{i} has no timestamps (event recording): late/brief participant \
                         flags are measured in input positions (lines), which a flood of input \
                         can skew; prefer a packet capture for the participant review"
                    ),
                );
            }
        }
        for (i, e) in self.extents.iter().enumerate() {
            if let Some(d) = e.duration() {
                let min = self.config.min_participant_duration;
                if !min.is_zero() && d < min && e.min_ts.is_some() {
                    warn(
                        Warn,
                        "run_shorter_than_min_duration",
                        &format!("run{i}"),
                        format!(
                            "run{i} spans {:.1}s of capture time, less than the {:.1}s minimum \
                             participant duration: the duration check could not be applied",
                            d.as_secs_f64(),
                            min.as_secs_f64()
                        ),
                    );
                }
            }
        }

        // Endpoints.
        let endpoint_reports = |m: &BTreeMap<String, EndpointAcc>, learned: bool| {
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
                            in_profile: learned
                                && e.participants.iter().any(|g| gate.vouches(&e.origins, g)),
                        },
                    ))
                })
                .collect::<BTreeMap<_, _>>()
        };
        // Channels with accepted commands that `build_profile` left out
        // because no accepted writer was learned on them.
        for (ch, m) in &self.motion {
            if Self::accepted_motion(m, accepted).2 > 0
                && !profile.motion_envelopes.contains_key(ch)
            {
                warn(
                    Warn,
                    "motion_envelope_dropped_no_writer",
                    ch,
                    format!(
                        "commands seen on {ch} but no learned writer announced it: no envelope \
                         learned (commands on it will be reported as an unprofiled channel); \
                         check discovery coverage (capture) before locking"
                    ),
                );
            }
        }
        let writer_topics = endpoint_reports(&self.writers, true);
        let reader_topics = endpoint_reports(&self.readers, self.config.learn_readers);
        let not_learned: Vec<&String> = writer_topics
            .iter()
            .filter(|(_, r)| !r.in_profile)
            .map(|(t, _)| t)
            .collect();
        if !not_learned.is_empty() {
            let (n, ex) = examples(not_learned);
            warn(
                Warn,
                "endpoints_not_learned",
                "writer_topics",
                format!(
                    "{n} writer topic(s) announced only by quarantined or unannounced \
                     participants, NOT learned: {ex}"
                ),
            );
        }
        for (t, rep) in &writer_topics {
            // Nothing subscribes to /rosout on a robot without a log tool.
            if rep.in_profile && !reader_topics.contains_key(t) && t != "/rosout" {
                warn(
                    Info,
                    "writer_without_reader",
                    t,
                    format!("writer on {t} but no reader seen anywhere (dead topic? exfil path?)"),
                );
            }
            if rep.type_names.len() > 1 {
                warn(
                    Warn,
                    "topic_type_conflict",
                    t,
                    format!(
                        "writers on {t} announce several types: {:?}",
                        rep.type_names
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
                            in_profile: self.role_learned(a, &gate),
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
            let in_profile = self.role_learned(a, &gate);
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
                    in_profile,
                },
            );
            if !ros_internal && in_profile {
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
            let mut gated = Vec::new();
            for (n, a) in m {
                // Raw topics may legitimately have only subscribers.
                if a.writer_guids.is_empty() && !all && what != "raw DDS topic" {
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
                } else if !a.writer_guids.is_empty() && !self.role_learned(a, &gate) {
                    gated.push(n);
                }
            }
            if !gated.is_empty() {
                let (k, ex) = examples(gated);
                warn(
                    Warn,
                    "endpoints_not_learned",
                    what,
                    format!(
                        "{k} {what}(s) written only by quarantined or unannounced participants, \
                         NOT learned: {ex}"
                    ),
                );
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
        let reader_enforcement = !profile.reader_topics.is_empty();
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
            if c.frames == 0 {
                warn(
                    Warn,
                    "empty_capture",
                    &subject,
                    format!("{}: the capture contains no frames", r.label),
                );
            }
            if c.zenoh_packets > 0 {
                let what = if c.rtps_datagrams == 0 {
                    "and no RTPS at all: this robot runs rmw_zenoh, which RoboDR does not \
                     decode; nothing was learned from it, and a RoboDR sensor on this bus \
                     would be blind (it reports robot.capture.unsupported_middleware)"
                } else {
                    "besides RTPS: that part of the bus (rmw_zenoh) is not decoded and was not \
                     learned"
                };
                warn(
                    Warn,
                    "unsupported_middleware",
                    &subject,
                    format!(
                        "{}: {} Zenoh packet(s) (TCP/UDP 7447, scouting UDP 7446) {what}",
                        r.label, c.zenoh_packets
                    ),
                );
            }
            if c.frames > 0 && c.rtps_datagrams == 0 {
                warn(
                    Warn,
                    "no_rtps_in_capture",
                    &subject,
                    format!(
                        "{}: {} frame(s) but no RTPS traffic: wrong interface or filter?",
                        r.label, c.frames
                    ),
                );
            }
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
            if c.unsupported_linktype_frames > 0 || c.malformed_frames > 0 {
                warn(
                    Warn,
                    "undecodable_frames",
                    &subject,
                    format!(
                        "{}: {} frame(s) with an unsupported link type and {} malformed \
                         frame(s) were skipped",
                        r.label, c.unsupported_linktype_frames, c.malformed_frames
                    ),
                );
            }
            if c.rtps_anomalies > 0 || c.not_rtps > 0 {
                warn(
                    Warn,
                    "malformed_rtps",
                    &subject,
                    format!(
                        "{}: {} datagram(s) on RTPS ports did not parse as RTPS and {} RTPS \
                         parser anomalies: a clean bus has none",
                        r.label, c.not_rtps, c.rtps_anomalies
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
            let in_profile = profile.motion_envelopes.contains_key(ch);
            let excluded_sources: BTreeSet<String> = m
                .sources
                .iter()
                .flatten()
                .filter(|g| !accepted.contains(g.as_str()))
                .cloned()
                .collect();
            let (l, j, cmds) = Self::accepted_motion(m, accepted);
            let (ls, js) = Self::accepted_stats(m, accepted);
            let excluded_commands = span.count.saturating_sub(cmds);
            if !excluded_sources.is_empty() {
                warn(
                    Warn,
                    "motion_samples_excluded",
                    ch,
                    format!(
                        "{ch}: {excluded_commands} command(s) from quarantined or unannounced \
                         source(s) {excluded_sources:?} did not shape the envelope"
                    ),
                );
            }
            if !in_profile {
                warn(
                    Warn,
                    "motion_channel_not_learned",
                    ch,
                    format!(
                        "{ch}: every command came from an excluded source; channel NOT learned"
                    ),
                );
            }
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
            let mut capped_flags = [false, false];
            for (k, (dim, d, joint, unit)) in
                [("linear", l, false, "m/s"), ("joint", j, true, "rad/s")]
                    .into_iter()
                    .enumerate()
            {
                if !in_profile {
                    continue;
                }
                if d.n > 0 && d.n < self.config.min_samples {
                    warn(
                        Warn,
                        "few_motion_samples",
                        ch,
                        format!(
                            "motion channel {ch} has {} {dim} samples (< {}): envelope not trustworthy",
                            d.n, self.config.min_samples
                        ),
                    );
                }
                if let Some((max, bound, capped)) = self.dim_bound(&d, joint) {
                    capped_flags[k] = capped;
                    let cap = self.config.effective_cap(joint);
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
                    if max > cap {
                        warn(
                            Warn,
                            "observed_exceeds_ceiling",
                            ch,
                            format!(
                                "{ch}: observed {dim} max {max} {unit} exceeds the cap {cap} \
                                 (OEM ceiling or hard cap); envelope held at the cap, the clean \
                                 run itself would deviate"
                            ),
                        );
                    } else if capped {
                        warn(
                            Info,
                            "margin_capped_by_ceiling",
                            ch,
                            format!(
                                "{ch}: {dim} envelope capped at {cap} {unit} (margin wanted {})",
                                envelope_bound(max, self.config.margin, None).0
                            ),
                        );
                    }
                    let _ = bound;
                }
            }
            for (dim, d, st, b) in [
                ("linear", &l, &ls, env.max_linear_speed),
                ("joint", &j, &js, env.max_joint_speed),
            ] {
                if !in_profile {
                    break;
                }
                if d.n == 0 && b.is_some() {
                    warn(
                        Info,
                        "envelope_dimension_unobserved",
                        ch,
                        format!(
                            "{ch}: no {dim} sample observed; {dim} bound set to {} (0 = deny), \
                             never left unlimited",
                            opt(b)
                        ),
                    );
                }
                if let Some((max, p99)) = self.outlier(st) {
                    warn(
                        Warn,
                        "envelope_outlier",
                        ch,
                        format!(
                            "{ch}: {dim} max {max} is more than {}x the p99 {p99}: the envelope \
                             rests on outlier sample(s)",
                            self.config.outlier_ratio
                        ),
                    );
                }
            }
            if in_profile && l.n == 0 && j.n == 0 {
                warn(
                    Warn,
                    "motion_channel_without_envelope",
                    ch,
                    format!("{ch}: no valid speed sample; envelope empty, lock will refuse"),
                );
            }
            let terms = Self::accepted_terms(m, accepted);
            let term_stats = Self::accepted_term_stats(m, accepted);
            for ((((dim, unit), d), st), cap) in JOINT_TERMS
                .iter()
                .zip(&terms)
                .zip(&term_stats)
                .zip(self.config.joint_term_caps())
            {
                if !in_profile {
                    break;
                }
                if d.n > 0 && d.n < self.config.min_samples {
                    warn(
                        Warn,
                        "few_motion_samples",
                        ch,
                        format!(
                            "motion channel {ch} has {} {dim} samples (< {}): envelope not trustworthy",
                            d.n, self.config.min_samples
                        ),
                    );
                }
                if d.n > 0 && d.max > cap {
                    warn(
                        Warn,
                        "observed_exceeds_ceiling",
                        ch,
                        format!(
                            "{ch}: observed {dim} max {} {unit} exceeds the hard cap {cap}; \
                             envelope held at the cap, the clean run itself would deviate",
                            d.max
                        ),
                    );
                }
                if let Some((max, p99)) = self.outlier(st) {
                    warn(
                        Warn,
                        "envelope_outlier",
                        ch,
                        format!(
                            "{ch}: {dim} max {max} is more than {}x the p99 {p99}: the envelope \
                             rests on outlier sample(s)",
                            self.config.outlier_ratio
                        ),
                    );
                }
            }
            let [joint_torque, joint_kp, joint_position_step] = term_stats;
            motion_channels.insert(
                ch.clone(),
                MotionReport {
                    commands: span.count,
                    first_seen: span.first,
                    last_seen: span.last,
                    sources: m.sources.iter().flatten().cloned().collect(),
                    linear: ls,
                    joint: js,
                    envelope: env,
                    linear_capped_by_ceiling: capped_flags[0],
                    joint_capped_by_ceiling: capped_flags[1],
                    joint_torque,
                    joint_kp,
                    joint_position_step,
                    in_profile,
                    excluded_sources,
                    excluded_commands,
                },
            );
        }

        CommissioningReport {
            model: self.config.model.clone(),
            config: ReportConfig {
                margin: self.config.margin,
                ceiling_linear: self.config.ceiling_linear,
                ceiling_joint: self.config.ceiling_joint,
                hard_cap_linear: self.config.hard_cap_linear,
                hard_cap_joint: self.config.hard_cap_joint,
                hard_cap_torque: self.config.hard_cap_torque,
                hard_cap_kp: self.config.hard_cap_kp,
                hard_cap_position_step: self.config.hard_cap_position_step,
                min_samples: self.config.min_samples,
                learn_readers: self.config.learn_readers,
                min_participant_announcements: self.config.min_participant_announcements,
                min_participant_duration_ms: u64::try_from(
                    self.config.min_participant_duration.as_millis(),
                )
                .unwrap_or(u64::MAX),
                late_fraction: self.config.late_fraction,
                brief_fraction: self.config.brief_fraction,
                outlier_ratio: self.config.outlier_ratio,
                accept_participants: self.config.accept_participants.clone(),
                motion_topics: self.config.motion_topics.clone(),
                limits: self.config.limits.clone(),
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
            overflow: self.overflow.clone(),
            anomalies_total: self.anomalies_total,
            anomalies: self.anomalies.clone(),
            warnings,
            signoff: signoff.items.clone(),
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
    pub hard_cap_linear: f64,
    pub hard_cap_joint: f64,
    #[serde(default)]
    pub hard_cap_torque: f64,
    #[serde(default)]
    pub hard_cap_kp: f64,
    #[serde(default)]
    pub hard_cap_position_step: f64,
    pub min_samples: u64,
    pub learn_readers: bool,
    pub min_participant_announcements: u64,
    pub min_participant_duration_ms: u64,
    pub late_fraction: f64,
    pub brief_fraction: f64,
    pub outlier_ratio: f64,
    pub accept_participants: BTreeSet<String>,
    pub motion_topics: BTreeSet<String>,
    pub limits: Limits,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ParticipantReport {
    pub announcements: u64,
    pub first_seen: SeenAt,
    pub last_seen: SeenAt,
    pub src_ips: BTreeSet<String>,
    pub writer_topics: BTreeSet<String>,
    pub reader_topics: BTreeSet<String>,
    /// Learned, learned by operator override, or quarantined.
    pub status: ParticipantStatus,
    /// Why it was quarantined (empty if it passed the gate).
    pub quarantine_reasons: Vec<String>,
    /// Sign-off kinds raised for it (`participant_late`, ...).
    pub flags: Vec<String>,
    /// Runs it was seen in.
    pub runs_seen: usize,
    /// Longest capture-time presence in one run (pcap input only).
    pub observed_ms: Option<u64>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct EndpointReport {
    pub announcements: u64,
    pub first_seen: SeenAt,
    pub last_seen: SeenAt,
    pub participants: BTreeSet<String>,
    pub type_names: BTreeSet<String>,
    /// Learned into the profile (announced by an accepted participant; for
    /// reader topics also only with `learn_readers`).
    pub in_profile: bool,
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
    /// Low-level joint commands: stats of the commanded max |tau| (N·m),
    /// max |kp| and position-target step (rad) ([`JOINT_TERMS`]); `None`
    /// on channels whose commands do not carry the term.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub joint_torque: Option<SpeedStats>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub joint_kp: Option<SpeedStats>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub joint_position_step: Option<SpeedStats>,
    /// The channel is in the profile (some command came from an accepted
    /// source).
    pub in_profile: bool,
    /// Sources whose commands were excluded (quarantined or unannounced).
    pub excluded_sources: BTreeSet<String>,
    /// Commands that did not shape the envelope because of their source.
    pub excluded_commands: u64,
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
    /// Entries dropped at a capacity cap, per category.
    pub overflow: BTreeMap<String, u64>,
    pub anomalies_total: u64,
    /// First [`MAX_STORED_ANOMALIES`] anomalies, in observation order.
    pub anomalies: Vec<Anomaly>,
    pub warnings: Vec<Warning>,
    /// The operator confirmation list (also written as the sign-off file).
    pub signoff: Vec<SignoffItem>,
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
            let status = match p.status {
                ParticipantStatus::Accepted => String::new(),
                ParticipantStatus::OperatorAccepted => "  [ACCEPTED BY OPERATOR]".into(),
                ParticipantStatus::Quarantined => {
                    format!("  [QUARANTINED: {}]", p.quarantine_reasons.join("; "))
                }
            };
            writeln!(
                f,
                "  {g}  seen {}x [{} .. {}]  ip {:?}  writes {:?}  reads {:?}{status}",
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
                "  {c}  {} commands [{} .. {}]{}",
                m.commands,
                m.first_seen,
                m.last_seen,
                if m.in_profile {
                    ""
                } else {
                    "  [NOT in profile]"
                }
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
                        "    {dim}: n={} min={} p50={} p99={} max={}{} -> envelope {} {unit}{}",
                        s.samples,
                        s.min,
                        s.p50,
                        s.p99,
                        s.max,
                        if s.decimated {
                            " (percentiles approx.)"
                        } else {
                            ""
                        },
                        opt(env),
                        if capped {
                            " (capped by ceiling / hard cap)"
                        } else {
                            ""
                        }
                    )?;
                }
            }
            for ((dim, unit), s, env) in [
                (JOINT_TERMS[0], &m.joint_torque, m.envelope.max_joint_torque),
                (JOINT_TERMS[1], &m.joint_kp, m.envelope.max_joint_kp),
                (
                    JOINT_TERMS[2],
                    &m.joint_position_step,
                    m.envelope.max_joint_position_step,
                ),
            ] {
                if let Some(s) = s {
                    writeln!(
                        f,
                        "    {dim}: n={} min={} p50={} p99={} max={} -> envelope {} {unit}",
                        s.samples,
                        s.min,
                        s.p50,
                        s.p99,
                        s.max,
                        opt(env)
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
        writeln!(
            f,
            "\nOperator sign-off required before lock: {} item(s)",
            self.signoff.len()
        )?;
        for i in &self.signoff {
            writeln!(f, "  [ ] {}: {}", i.id, i.reason)?;
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
            angular_speed: None,
            ..Default::default()
        })
    }

    /// Routing-focused tests use a gate that accepts single announcements;
    /// the poisoning tests below use the defaults.
    fn cfg() -> LearnConfig {
        LearnConfig {
            model: "ugv-test".into(),
            min_participant_announcements: 1,
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
        // Periodic announcements: both participants present the whole run.
        v.extend([part(A), part(B)]);
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
        // Never exercised: deny (0), not unlimited (None).
        assert_eq!(env.max_joint_speed, Some(0.0));
        let r = l.report();
        assert_eq!(r.anomalies_total, 0);
        assert_eq!(r.warn_count(), 0, "{r}");
        // The clean run evaluates clean against its own (unlocked) profile.
        for e in clean() {
            assert!(p.evaluate(&e).is_none(), "{e:?}");
        }
    }

    /// Review item 2: low-level joint commands are learned with their
    /// torque / gain / position-step terms, and a locked profile then
    /// catches a torque-only or gain-only attack.
    #[test]
    fn learns_joint_terms_of_low_level_commands() {
        let joint = |tau: f64, kp: f64, step: Option<f64>| {
            RobotEvent::MotionCommand(MotionCommand {
                channel: "/lowcmd".into(),
                source_guid: Some(A.into()),
                joint_speed: Some(0.5),
                joint_torque: Some(tau),
                joint_kp: Some(kp),
                joint_position_step: step,
                ..Default::default()
            })
        };
        let mut evs = clean();
        evs.push(writer(A, "rt/lowcmd"));
        for i in 0..40 {
            let s = (i > 0).then_some(0.01);
            evs.push(joint(10.0 + f64::from(i) * 0.25, 60.0, s));
        }
        let l = learn(cfg(), &evs);
        let mut p = l.profile();
        let env = &p.motion_envelopes["/lowcmd"];
        // max * 1.1, rounded up.
        assert_eq!(env.max_joint_torque, Some(21.725));
        assert_eq!(env.max_joint_kp, Some(66.0));
        assert_eq!(env.max_joint_position_step, Some(0.011));
        // A Twist channel never carries the terms: left unset.
        let tw = &p.motion_envelopes["/cmd_vel"];
        assert_eq!(tw.max_joint_torque, None);
        assert_eq!(tw.max_joint_kp, None);
        let r = l.report();
        assert_eq!(r.warn_count(), 0, "{r}");
        assert!(r.motion_channels["/lowcmd"].joint_torque.is_some());
        assert!(r.to_string().contains("joint_torque"));
        // learn -> lock -> check over the same run is clean ...
        p.locked = true;
        for e in &evs {
            assert!(p.evaluate(e).is_none(), "{e:?}");
        }
        // ... and the attack frames deviate.
        for e in [
            joint(500.0, 0.0, None),
            joint(0.0, 500.0, Some(0.0)),
            joint(0.0, 60.0, Some(1.0)),
        ] {
            assert_eq!(
                p.evaluate(&e).map(|d| d.rule.to_string()),
                Some("robot.motion.joint_over_envelope".to_string()),
                "{e:?}"
            );
        }
        // A term above its hard cap is held at the cap and needs sign-off.
        let mut c = cfg();
        c.hard_cap_torque = 15.0;
        let out = learn(c, &evs).finish();
        assert_eq!(
            out.profile.motion_envelopes["/lowcmd"].max_joint_torque,
            Some(15.0)
        );
        assert!(out
            .signoff
            .items
            .iter()
            .any(|i| i.id == "observed_exceeds_cap:/lowcmd joint_torque"));
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
        evs.push(writer(A, "rt/arm"));
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
        assert_eq!(p.motion_envelopes["/cmd_vel"].max_joint_speed, Some(0.0));
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
    fn holonomic_commands_are_learned_by_their_resultant() {
        let mut evs = clean();
        let lateral = |x: f64, y: f64| {
            RobotEvent::MotionCommand(MotionCommand {
                channel: "/cmd_vel".into(),
                source_guid: Some(A.into()),
                linear_speed: Some(x),
                linear_y: Some(y),
                linear_z: Some(0.0),
                ..Default::default()
            })
        };
        let base = learn(cfg(), &evs).profile().motion_envelopes["/cmd_vel"]
            .max_linear_speed
            .unwrap();
        // Sideways and reversing-diagonal moves are magnitudes, not
        // negative-speed anomalies; a NaN lateral axis is an anomaly.
        for _ in 0..50 {
            evs.push(lateral(0.0, -0.6));
            evs.push(lateral(-0.3, 0.4));
        }
        evs.push(lateral(0.1, f64::NAN));
        let l = learn(cfg(), &evs);
        let learned = l.profile().motion_envelopes["/cmd_vel"]
            .max_linear_speed
            .unwrap();
        assert!(learned >= 0.6 && learned > base, "{learned} vs {base}");
        let kinds: Vec<_> = l
            .report()
            .anomalies
            .iter()
            .map(|a| a.kind.clone())
            .collect();
        assert_eq!(kinds, vec!["non_finite_linear_speed".to_string()]);
    }

    #[test]
    fn channel_without_valid_samples_has_empty_envelope() {
        let mut evs = clean();
        evs.push(writer(A, "rt/arm"));
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
        const D: &str = "dddddddddddddddddddddddd";
        let evs = vec![
            part(A),
            part(B),
            part(D),
            writer(A, "rt/cmd_vel"),
            writer(B, "rt/diag"),
            reader(B, "rt/cmd_vel"),
            writer("cccccccccccccccccccccccc", "rt/x"),
            mv("/cmd_vel", Some(0.2), None),
            mv("rt/mangled", Some(0.0), None),
            part(A),
            part(B),
        ];
        let r = learn(LearnConfig::default(), &evs).report();
        let has = |code: &str, subj: &str| {
            r.warnings
                .iter()
                .any(|w| w.code == code && w.subject == subj)
        };
        assert!(has("participant_seen_once", D), "{r}");
        assert!(has("quarantined_participant", D), "{r}");
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
    fn motion_channel_without_learned_writer_gets_no_envelope() {
        let mut evs = clean();
        // Commands on /arm, but no accepted participant announced a writer.
        evs.extend((0..40).map(|_| mv("/arm", None, Some(1.0))));
        let out = learn(cfg(), &evs).finish();
        assert!(!out.profile.motion_envelopes.contains_key("/arm"));
        assert!(out.profile.motion_envelopes.contains_key("/cmd_vel"));
        assert_eq!(out.profile.validate(), Ok(()));
        assert!(out
            .report
            .warnings
            .iter()
            .any(|w| w.code == "motion_envelope_dropped_no_writer" && w.subject == "/arm"));
        assert!(!out
            .report
            .warnings
            .iter()
            .any(|w| w.code == "motion_envelope_dropped_no_writer" && w.subject == "/cmd_vel"));
    }

    #[test]
    fn malformed_ros_names_are_never_learned_as_ros_names() {
        // robodr-events `demangle` classifies a prefixed name whose ROS part
        // is malformed (whitespace, control characters) as a raw DDS topic
        // with the exact input as its name, so it can only ever match the
        // raw set verbatim: never a ROS topic / service.
        let evs = vec![
            part(A),
            writer(A, "rt/bad name"),
            writer(A, "rq/ctl\u{7}Request"),
            writer(A, "rt/ok"),
            // Raw names are exact and may contain anything but must be non-empty.
            writer(A, "raw with space"),
        ];
        let l = learn(cfg(), &evs);
        let p = l.profile();
        assert_eq!(p.writer_topics.iter().collect::<Vec<_>>(), vec!["/ok"]);
        assert!(p.services.is_empty());
        assert!(p.raw_dds_topics.contains("raw with space"));
        assert!(p.raw_dds_topics.contains("rt/bad name"));
        assert!(p.raw_dds_topics.contains("rq/ctl\u{7}Request"));
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
                ts: None,
                origin: None,
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

    // ---------------------------------------------------- poisoning gate --

    fn defaults() -> LearnConfig {
        LearnConfig {
            model: "ugv-test".into(),
            ..Default::default()
        }
    }

    const EVIL: &str = "eeeeeeeeeeeeeeeeeeeeeeee";

    /// A clean run with an intruder that announces once mid-run, publishes
    /// /cmd_vel and /exfil, and injects a fast motion command.
    fn poisoned() -> Vec<RobotEvent> {
        let mut v = clean();
        let mid = v.len() / 2;
        let evil = [
            part(EVIL),
            writer(EVIL, "rt/cmd_vel"),
            writer(EVIL, "rt/exfil"),
            writer(EVIL, "rq/backdoorRequest"),
            RobotEvent::MotionCommand(MotionCommand {
                channel: "/cmd_vel".into(),
                source_guid: Some(EVIL.into()),
                linear_speed: Some(9.0),
                joint_speed: None,
                angular_speed: None,
                ..Default::default()
            }),
            RobotEvent::MotionCommand(MotionCommand {
                channel: "/evil_channel".into(),
                source_guid: Some(EVIL.into()),
                linear_speed: Some(5.0),
                joint_speed: None,
                angular_speed: None,
                ..Default::default()
            }),
        ];
        for (i, e) in evil.into_iter().enumerate() {
            v.insert(mid + i, e);
        }
        v
    }

    #[test]
    fn single_announcement_intruder_is_quarantined_with_everything_it_did() {
        let l = learn(defaults(), &poisoned());
        let c = l.finish();
        let p = &c.profile;
        assert!(!p.participants.contains(EVIL));
        assert!(!p.writer_topics.contains("/exfil"));
        assert!(!p.services.contains("/backdoor"));
        assert!(!p.motion_envelopes.contains_key("/evil_channel"));
        // The injected 9 m/s never widened the envelope.
        assert_eq!(p.motion_envelopes["/cmd_vel"].max_linear_speed, Some(0.429));
        // The legit graph is intact.
        assert!(p.participants.contains(A) && p.participants.contains(B));
        assert!(p.writer_topics.contains("/cmd_vel"));
        let r = &c.report;
        assert_eq!(r.participants[EVIL].status, ParticipantStatus::Quarantined);
        assert!(!r.writer_topics["/exfil"].in_profile);
        assert!(!r.motion_channels["/evil_channel"].in_profile);
        assert!(r.motion_channels["/cmd_vel"]
            .excluded_sources
            .contains(EVIL));
        assert_eq!(r.motion_channels["/cmd_vel"].excluded_commands, 1);
        let has = |code: &str, subj: &str| {
            r.warnings
                .iter()
                .any(|w| w.code == code && w.subject == subj)
        };
        assert!(has("quarantined_participant", EVIL), "{r}");
        assert!(has("endpoints_not_learned", "writer_topics"), "{r}");
        assert!(has("endpoints_not_learned", "service"), "{r}");
        assert!(has("motion_samples_excluded", "/cmd_vel"));
        assert!(has("motion_channel_not_learned", "/evil_channel"));
        assert!(r.to_string().contains("[QUARANTINED"));
        // The intruder is not on the sign-off list (nothing to confirm).
        assert!(!c.signoff.items.iter().any(|i| i.subject.contains(EVIL)));
        // The locked profile flags the intruder later.
        let d = p.evaluate(&writer(EVIL, "rt/cmd_vel")).unwrap();
        assert_eq!(d.rule, "robot.ros2.unauthorized_motion_writer");
    }

    #[test]
    fn operator_can_accept_a_quarantined_participant_with_signoff() {
        let mut c = defaults();
        c.accept_participants.insert(EVIL.into());
        let out = learn(c, &poisoned()).finish();
        assert!(out.profile.participants.contains(EVIL));
        assert!(out.profile.writer_topics.contains("/exfil"));
        // Still never wider than the hard cap... and here 9.0 * 1.1 = 9.9.
        assert_eq!(
            out.profile.motion_envelopes["/cmd_vel"].max_linear_speed,
            Some(9.9)
        );
        assert_eq!(
            out.report.participants[EVIL].status,
            ParticipantStatus::OperatorAccepted
        );
        let ids: Vec<&str> = out.signoff.items.iter().map(|i| i.id.as_str()).collect();
        assert!(
            ids.contains(&"participant_operator_accepted:eeeeeeeeeeeeeeeeeeeeeeee"),
            "{ids:?}"
        );
        assert!(
            ids.contains(&"motion_writer:/cmd_vel eeeeeeeeeeeeeeeeeeeeeeee"),
            "{ids:?}"
        );
        // Late and brief (one announcement mid-run).
        assert!(ids.contains(&"participant_late:eeeeeeeeeeeeeeeeeeeeeeee"));
        assert!(ids.contains(&"participant_brief:eeeeeeeeeeeeeeeeeeeeeeee"));
        // Accepting an unseen GUID adds nothing and warns.
        let mut c = defaults();
        c.accept_participants.insert("f".repeat(24));
        let r = learn(c, &clean()).report();
        assert!(r
            .warnings
            .iter()
            .any(|w| w.code == "accepted_participant_not_seen"));
        assert!(!learn(defaults(), &clean())
            .profile()
            .participants
            .contains(&"f".repeat(24)));
    }

    #[test]
    fn motion_writers_always_need_signoff() {
        let out = learn(defaults(), &clean()).finish();
        let ids: Vec<&str> = out.signoff.items.iter().map(|i| i.id.as_str()).collect();
        // A writes /cmd_vel and sends its commands.
        assert!(
            ids.contains(&"motion_writer:/cmd_vel aaaaaaaaaaaaaaaaaaaaaaaa"),
            "{ids:?}"
        );
        // B only reads it: no sign-off for B.
        assert!(!ids.iter().any(|i| i.contains(B)), "{ids:?}");
        assert_eq!(
            out.signoff.profile_sha256,
            crate::signoff::draft_digest(&out.profile)
        );
        assert!(out.signoff.unconfirmed().count() > 0);
        // Heuristic and configured motion topics, even without envelopes
        // (pcap-only learning).
        let evs = vec![
            part(A),
            part(A),
            writer(A, "rt/mast/pan_tilt_cmd"),
            writer(A, "rt/odom"),
            writer(A, "rt/arm/joint_trajectory"),
            writer(A, "rt/special_motion"),
        ];
        let mut c = defaults();
        c.motion_topics.insert("/special_motion".into());
        let ids: Vec<String> = learn(c, &evs)
            .finish()
            .signoff
            .items
            .iter()
            .map(|i| i.id.clone())
            .collect();
        for t in [
            "/mast/pan_tilt_cmd",
            "/arm/joint_trajectory",
            "/special_motion",
        ] {
            assert!(
                ids.contains(&format!("motion_writer:{t} {A}")),
                "{t}: {ids:?}"
            );
        }
        assert!(!ids.iter().any(|i| i.contains("/odom")));
        assert!(is_motion_like("/cmd_vel") && is_motion_like("/x/JointCommand"));
        assert!(!is_motion_like("/odom") && !is_motion_like("/scan"));
    }

    #[test]
    fn unattributed_and_thin_motion_need_signoff() {
        let mut evs = vec![part(A), part(A), writer(A, "rt/cmd_vel")];
        evs.extend((0..5).map(|_| {
            RobotEvent::MotionCommand(MotionCommand {
                channel: "/cmd_vel".into(),
                source_guid: None,
                linear_speed: Some(0.5),
                joint_speed: None,
                angular_speed: None,
                ..Default::default()
            })
        }));
        let ids: Vec<String> = learn(defaults(), &evs)
            .finish()
            .signoff
            .items
            .iter()
            .map(|i| i.id.clone())
            .collect();
        assert!(
            ids.contains(&"motion_unattributed:/cmd_vel".to_string()),
            "{ids:?}"
        );
        assert!(ids.contains(&"few_motion_samples:/cmd_vel linear".to_string()));
    }

    #[test]
    fn late_brief_and_multi_ip_participants_are_flagged() {
        const L: &str = "1111111111111111111111aa";
        let mut evs = vec![part(A)];
        evs.extend((0..100).map(|_| writer(A, "rt/odom")));
        // L joins at 80% and announces twice (passes the count gate).
        evs.insert(80, part(L));
        evs.insert(85, part(L));
        evs.push(part(A));
        // A second IP for A.
        evs.push(RobotEvent::Ros2ParticipantDiscovered(Participant {
            guid_prefix: A.into(),
            src_ip: "10.0.0.66".into(),
            locators: vec![],
        }));
        let out = learn(defaults(), &evs).finish();
        assert!(out.profile.participants.contains(L));
        let r = &out.report;
        let flags = &r.participants[L].flags;
        assert!(flags.contains(&"participant_late".to_string()), "{flags:?}");
        assert!(
            flags.contains(&"participant_brief".to_string()),
            "{flags:?}"
        );
        assert!(!r.participants[A]
            .flags
            .contains(&"participant_late".to_string()));
        assert!(r.participants[A]
            .flags
            .contains(&"participant_multiple_ips".to_string()));
        assert!(r.warn_count() > 0);
        let ids: Vec<&str> = out.signoff.items.iter().map(|i| i.id.as_str()).collect();
        assert!(ids.contains(&"participant_late:1111111111111111111111aa"));
        assert!(ids.contains(&"participant_multiple_ips:aaaaaaaaaaaaaaaaaaaaaaaa"));
    }

    #[test]
    fn duration_gate_uses_capture_time_when_available() {
        const S: &str = "5555555555555555555555aa";
        let mut l = Learner::new(defaults()).unwrap();
        l.start_run("cap");
        let t = Duration::from_secs;
        // A: present for 60 s. S: 10 announcements within 1 s.
        for i in 0..=60u64 {
            l.observe_at_time(&part(A), i * 10 + 1, Some(t(1000 + i)));
        }
        for i in 0..10u64 {
            l.observe_at_time(
                &part(S),
                300 + i,
                Some(Duration::from_millis(1_030_000 + i * 100)),
            );
        }
        let r = l.report();
        assert_eq!(r.participants[A].status, ParticipantStatus::Accepted);
        assert_eq!(
            r.participants[S].status,
            ParticipantStatus::Quarantined,
            "{r}"
        );
        assert!(r.participants[S].quarantine_reasons[0].contains("observed for"));
        assert_eq!(r.participants[A].observed_ms, Some(60_000));

        // A run shorter than the minimum: the duration check cannot apply,
        // the count gate still does, and the report says so.
        let mut l = Learner::new(defaults()).unwrap();
        l.start_run("short");
        for i in 0..3u64 {
            l.observe_at_time(&part(A), i + 1, Some(Duration::from_millis(i * 100)));
        }
        let r = l.report();
        assert_eq!(r.participants[A].status, ParticipantStatus::Accepted);
        assert!(r
            .warnings
            .iter()
            .any(|w| w.code == "run_shorter_than_min_duration"));
        // Disabled duration gate.
        let mut c = defaults();
        c.min_participant_duration = Duration::ZERO;
        let mut l = Learner::new(c).unwrap();
        for i in 0..2u64 {
            l.observe_at_time(&part(S), i, Some(t(i)));
        }
        assert!(l.profile().participants.contains(S));
    }

    #[test]
    fn hard_cap_bounds_every_envelope() {
        let mut evs = vec![part(A), part(A), writer(A, "rt/cmd_vel")];
        evs.extend((0..40).map(|_| mv("/cmd_vel", Some(1e300), Some(f64::MAX))));
        evs.push(part(A));
        let out = learn(defaults(), &evs).finish();
        let env = &out.profile.motion_envelopes["/cmd_vel"];
        assert_eq!(env.max_linear_speed, Some(DEFAULT_HARD_CAP_LINEAR));
        assert_eq!(env.max_joint_speed, Some(DEFAULT_HARD_CAP_JOINT));
        assert!(out.report.motion_channels["/cmd_vel"].linear_capped_by_ceiling);
        assert!(out
            .signoff
            .items
            .iter()
            .any(|i| i.id == "observed_exceeds_cap:/cmd_vel linear"));
        // An OEM ceiling above the hard cap does not loosen it.
        let mut c = defaults();
        c.ceiling_linear = Some(1e6);
        c.hard_cap_linear = 2.0;
        assert_eq!(c.effective_cap(false), 2.0);
        let p = learn(c, &evs).profile();
        assert_eq!(p.motion_envelopes["/cmd_vel"].max_linear_speed, Some(2.0));
        assert_eq!(p.validate(), Ok(()));
    }

    #[test]
    fn envelope_bound_never_yields_garbage() {
        for x in [f64::NAN, f64::INFINITY, f64::NEG_INFINITY, -1.0] {
            let (b, _) = envelope_bound(x, 1.1, Some(3.0));
            assert_eq!(b, 3.0);
            let (b, _) = envelope_bound(x, 1.1, None);
            assert_eq!(b, 0.0);
        }
        for m in [f64::NAN, f64::INFINITY, 0.5] {
            let (b, _) = envelope_bound(2.0, m, None);
            assert_eq!(b, 2.0);
        }
        assert_eq!(envelope_bound(2.0, 1.0, Some(f64::NAN)), (2.0, false));
    }

    #[test]
    fn new_config_fields_are_validated() {
        let bad = |f: fn(&mut LearnConfig)| {
            let mut c = defaults();
            f(&mut c);
            Learner::new(c).unwrap_err()
        };
        assert!(matches!(
            bad(|c| c.hard_cap_linear = f64::INFINITY),
            ConfigError::InvalidHardCap { .. }
        ));
        assert!(matches!(
            bad(|c| c.hard_cap_joint = 0.0),
            ConfigError::InvalidHardCap { .. }
        ));
        assert!(matches!(
            bad(|c| c.hard_cap_joint = f64::NAN),
            ConfigError::InvalidHardCap { .. }
        ));
        assert!(matches!(
            bad(|c| c.late_fraction = f64::NAN),
            ConfigError::InvalidFraction { .. }
        ));
        assert!(matches!(
            bad(|c| c.brief_fraction = 1.5),
            ConfigError::InvalidFraction { .. }
        ));
        assert_eq!(
            bad(|c| c.min_participant_announcements = 0),
            ConfigError::InvalidMinAnnouncements
        );
        assert!(matches!(
            bad(|c| c.limits.max_samples = 1),
            ConfigError::InvalidLimit {
                name: "max_samples"
            }
        ));
        assert!(matches!(
            bad(|c| {
                c.accept_participants.insert("XYZ".into());
            }),
            ConfigError::InvalidAcceptedParticipant(_)
        ));
        assert!(matches!(
            bad(|c| {
                c.motion_topics.insert("rt/cmd_vel".into());
            }),
            ConfigError::InvalidMotionTopic(_)
        ));
        for e in [
            ConfigError::InvalidHardCap {
                dimension: "joint",
                value: 0.0,
            },
            ConfigError::InvalidMinAnnouncements,
        ] {
            assert!(!e.to_string().is_empty());
        }
    }

    #[test]
    fn floods_are_bounded_and_reported() {
        let mut c = defaults();
        c.limits = Limits {
            max_participants: 8,
            max_names: 16,
            max_motion_channels: 4,
            max_set_entries: 4,
            max_samples: 64,
        };
        let mut l = Learner::new(c).unwrap();
        for i in 0..1000u32 {
            let g = format!("{i:024x}");
            l.observe(&part(&g));
            l.observe(&writer(&g, &format!("rt/t{i}")));
            l.observe(&writer(A, &format!("rq/s{i}Request")));
            l.observe(&writer(&g, "rt/shared"));
            l.observe(&RobotEvent::Ros2ParticipantDiscovered(Participant {
                guid_prefix: A.into(),
                src_ip: format!("10.1.{}.{}", i / 250, i % 250),
                locators: vec![],
            }));
            l.observe(&mv(&format!("/ch{i}"), Some(0.1), None));
            l.observe(&RobotEvent::MotionCommand(MotionCommand {
                channel: "/ch0".into(),
                source_guid: Some(g.clone()),
                linear_speed: Some(0.2),
                joint_speed: None,
                angular_speed: None,
                ..Default::default()
            }));
        }
        for _ in 0..100_000 {
            l.observe(&mv("/ch0", Some(0.3), Some(0.1)));
        }
        let out = l.finish();
        let r = &out.report;
        assert!(r.participants.len() <= 8);
        assert!(r.writer_topics.len() <= 16);
        assert!(r.services.len() <= 16);
        assert!(r.motion_channels.len() <= 4);
        assert!(r.writer_topics["/shared"].participants.len() <= 4);
        for p in r.participants.values() {
            assert!(p.src_ips.len() <= 4);
        }
        assert!(r.motion_channels["/ch0"].sources.len() <= 4);
        for (cat, n) in &r.overflow {
            assert!(*n > 0, "{cat}");
        }
        for cat in [
            "participants",
            "writer_topics",
            "services",
            "motion_channels",
            "participant_src_ips",
            "topic_participants",
            "motion_sources",
        ] {
            assert!(r.overflow.contains_key(cat), "{cat}: {:?}", r.overflow);
        }
        assert!(out
            .signoff
            .items
            .iter()
            .any(|i| i.kind == "capacity_exceeded"));
        assert!(r.anomalies.len() <= MAX_STORED_ANOMALIES);
        // Stats exact in count/max, percentiles flagged approximate.
        let lin = r.motion_channels["/ch0"].linear.as_ref().unwrap();
        assert!(lin.samples >= 100_000);
        assert!(lin.decimated);
        assert_eq!(lin.max, 0.3);
        // The report stays bounded: one summary warning per kind, not per name.
        assert!(
            r.warnings
                .iter()
                .filter(|w| w.code == "endpoints_not_learned")
                .count()
                <= 4,
            "{:?}",
            r.warnings
        );
        serde_json::to_string(r).unwrap();
        assert_eq!(out.profile.validate(), Ok(()));
    }

    #[test]
    fn merge_respects_caps_and_keeps_profile_order_independent() {
        let mut c = defaults();
        c.limits.max_participants = 3;
        let mk = |gs: &[&str]| {
            let mut l = Learner::new(c.clone()).unwrap();
            for g in gs {
                l.observe(&part(g));
                l.observe(&part(g));
            }
            l
        };
        let mut a = mk(&[A, B]);
        a.merge(&mk(&[EVIL, "cccccccccccccccccccccccc"]));
        assert_eq!(a.report().participants.len(), 3);
        assert_eq!(a.report().overflow["participants"], 1);
        // Below caps the gate gives the same verdict whichever way round.
        let x = learn(defaults(), &poisoned());
        let y = learn(defaults(), &clean());
        let mut xy = x.clone();
        xy.merge(&y);
        let mut yx = y.clone();
        yx.merge(&x);
        assert_eq!(xy.profile(), yx.profile());
        assert!(!xy.profile().participants.contains(EVIL));
    }

    #[test]
    fn malformed_motion_source_never_shapes_envelope() {
        let mut evs = clean();
        evs.push(RobotEvent::MotionCommand(MotionCommand {
            channel: "/cmd_vel".into(),
            source_guid: Some("NOT-A-GUID".into()),
            linear_speed: Some(7.0),
            joint_speed: None,
            angular_speed: None,
            ..Default::default()
        }));
        let l = learn(defaults(), &evs);
        assert_eq!(
            l.profile().motion_envelopes["/cmd_vel"].max_linear_speed,
            Some(0.429)
        );
        assert!(l
            .report()
            .anomalies
            .iter()
            .any(|a| a.kind == "malformed_guid_prefix"));
    }

    // ---------------------------------------------- review 3 (F1, F2) ---

    /// One event as a capture would deliver it: sender prefix and IP.
    fn sourced(ev: RobotEvent, pos: u64, sender: &str, ip: &str) -> SourcedEvent {
        SourcedEvent {
            position: pos,
            event: ev,
            ts: Some(Duration::from_secs(pos)),
            origin: Some(Origin {
                sender_prefix: sender.into(),
                src_ip: ip.into(),
            }),
        }
    }
    fn part_ip(g: &str, ip: &str) -> RobotEvent {
        RobotEvent::Ros2ParticipantDiscovered(Participant {
            guid_prefix: g.into(),
            src_ip: ip.into(),
            locators: vec![],
        })
    }

    /// A from 10.0.0.1 for 100 s (two announcements), plus `extra`.
    fn provenance_run(extra: Vec<SourcedEvent>) -> Learner {
        let mut l = Learner::new(LearnConfig {
            model: "m".into(),
            ..Default::default()
        })
        .unwrap();
        l.start_run("cap");
        let mut evs = vec![
            sourced(part_ip(A, "10.0.0.1"), 1, A, "10.0.0.1"),
            sourced(writer(A, "rt/odom"), 1, A, "10.0.0.1"),
            sourced(writer(A, "rq/a/get_parametersRequest"), 1, A, "10.0.0.1"),
            sourced(part_ip(A, "10.0.0.1"), 100, A, "10.0.0.1"),
        ];
        evs.extend(extra);
        evs.sort_by_key(|e| e.position);
        for e in &evs {
            l.observe_sourced(e);
        }
        l
    }

    #[test]
    fn endpoint_provenance_applies_to_services_and_merges() {
        let x = "eeeeeeeeeeeeeeeeeeeeeeee";
        // A service request writer claiming A, sent by x; and a topic writer
        // claiming A from an uncommissioned IP (header spoof).
        let attack = vec![
            sourced(part_ip(x, "10.9.9.9"), 50, x, "10.9.9.9"),
            sourced(writer(A, "rq/evil/setRequest"), 50, x, "10.9.9.9"),
            sourced(part_ip(A, "10.9.9.9"), 51, A, "10.9.9.9"),
            sourced(writer(A, "rt/exfil"), 51, A, "10.9.9.9"),
        ];
        let l = provenance_run(attack.clone());
        let out = l.finish();
        let p = &out.profile;
        assert!(p.writer_topics.contains("/odom"));
        assert!(p.services.contains("/a/get_parameters"));
        assert!(!p.services.contains("/evil/set"));
        assert!(!p.writer_topics.contains("/exfil"));
        let subjects: Vec<&str> = out
            .signoff
            .items
            .iter()
            .filter(|i| i.kind == "endpoint_sender_mismatch")
            .map(|i| i.subject.as_str())
            .collect();
        assert_eq!(
            subjects,
            vec![
                format!("{A} sent by {A} from 10.9.9.9"),
                format!("{A} sent by {x} from 10.9.9.9"),
            ]
        );
        assert!(!out.report.writer_topics["/exfil"].in_profile);
        // A claimed-but-not-sent announcement is not even recorded.
        assert!(!out.report.services.contains_key("/evil/set"));

        // Merging learners keeps provenance and mismatches.
        let mut left = provenance_run(Vec::new());
        let mut right = Learner::new(LearnConfig {
            model: "m".into(),
            ..Default::default()
        })
        .unwrap();
        right.start_run("cap2");
        for e in &attack {
            right.observe_sourced(e);
        }
        left.merge(&right);
        let m = left.finish();
        assert!(!m.profile.writer_topics.contains("/exfil"));
        assert!(!m.profile.services.contains("/evil/set"));
        assert_eq!(
            m.signoff
                .items
                .iter()
                .filter(|i| i.kind == "endpoint_sender_mismatch")
                .count(),
            2
        );
    }

    #[test]
    fn operator_accepted_participant_has_all_ips_commissioned() {
        let extra = vec![
            sourced(part_ip(A, "10.0.0.2"), 60, A, "10.0.0.2"),
            sourced(writer(A, "rt/second_nic"), 60, A, "10.0.0.2"),
        ];
        // Gate-accepted: the second IP is not commissioned.
        let l = provenance_run(extra.clone());
        assert!(!l.profile().writer_topics.contains("/second_nic"));
        // Operator-accepted (A quarantined by a strict gate, then accepted):
        // every IP of A counts.
        let mut l = Learner::new(LearnConfig {
            model: "m".into(),
            min_participant_announcements: 10,
            accept_participants: [A.to_string()].into_iter().collect(),
            ..Default::default()
        })
        .unwrap();
        l.start_run("cap");
        for e in [
            sourced(part_ip(A, "10.0.0.1"), 1, A, "10.0.0.1"),
            sourced(writer(A, "rt/odom"), 1, A, "10.0.0.1"),
            sourced(part_ip(A, "10.0.0.2"), 60, A, "10.0.0.2"),
            sourced(writer(A, "rt/second_nic"), 60, A, "10.0.0.2"),
            sourced(part_ip(A, "10.0.0.1"), 100, A, "10.0.0.1"),
        ] {
            l.observe_sourced(&e);
        }
        let out = l.finish();
        assert_eq!(
            out.report.participants[A].status,
            ParticipantStatus::OperatorAccepted
        );
        assert!(out.profile.writer_topics.contains("/second_nic"));
        assert!(!out
            .signoff
            .items
            .iter()
            .any(|i| i.kind == "endpoint_sender_mismatch"));
    }

    #[test]
    fn late_and_brief_use_capture_time_not_positions() {
        // Positions say "early and long" (B appears at frame 2 and stays to
        // frame 9000), timestamps say "late and brief" (90 s .. 95 s of a
        // 100 s run): timestamps win.
        let mut l = Learner::new(LearnConfig {
            model: "m".into(),
            min_participant_duration: Duration::ZERO,
            ..Default::default()
        })
        .unwrap();
        l.start_run("cap");
        let t = Duration::from_secs;
        l.observe_at_time(&part(A), 1, Some(t(0)));
        l.observe_at_time(&part(B), 2, Some(t(90)));
        l.observe_at_time(&part(B), 9000, Some(t(95)));
        l.observe_at_time(&part(A), 9001, Some(t(100)));
        let a = l.assess();
        let kinds: Vec<&str> = a[B].flags.iter().map(|(k, _)| *k).collect();
        assert!(kinds.contains(&"participant_late"), "{kinds:?}");
        assert!(kinds.contains(&"participant_brief"), "{kinds:?}");
        assert!(a[A].flags.is_empty(), "{:?}", a[A].flags);
        // Identical timestamps: everyone present for the whole (zero) run.
        let mut l = Learner::new(cfg()).unwrap();
        l.start_run("cap");
        l.observe_at_time(&part(A), 1, Some(t(5)));
        l.observe_at_time(&part(B), 500, Some(t(5)));
        assert!(l.assess()[B].flags.is_empty());
    }

    // ------------------------------------------- discovery-server relay ---

    const S: &str = "cccccccccccccccccccccccc";
    const SIP: &str = "10.0.0.9";

    /// [`provenance_run`] with discovery servers configured.
    fn ds_run(servers: Vec<DiscoveryServer>, extra: Vec<SourcedEvent>) -> Learner {
        let mut l = Learner::new(LearnConfig {
            model: "m".into(),
            discovery_servers: servers,
            ..Default::default()
        })
        .unwrap();
        l.start_run("cap");
        let mut evs = vec![
            sourced(part_ip(A, "10.0.0.1"), 1, A, "10.0.0.1"),
            sourced(writer(A, "rt/odom"), 1, A, "10.0.0.1"),
            sourced(part_ip(A, "10.0.0.1"), 100, A, "10.0.0.1"),
        ];
        evs.extend(extra);
        evs.sort_by_key(|e| e.position);
        for e in &evs {
            l.observe_sourced(e);
        }
        l
    }

    fn relay_items(c: &Commissioning) -> Vec<&SignoffItem> {
        c.signoff
            .items
            .iter()
            .filter(|i| i.kind == "endpoint_sender_mismatch")
            .collect()
    }

    /// The server relays A's /odom (a copy of a direct announcement) and a
    /// /relayed_only writer A never announced itself.
    fn relays_of_a() -> Vec<SourcedEvent> {
        vec![
            sourced(writer(A, "rt/odom"), 10, S, SIP),
            sourced(writer(A, "rt/relayed_only"), 11, S, SIP),
        ]
    }

    #[test]
    fn discovery_server_spec_parsing() {
        let d = DiscoveryServer::parse(S, false).unwrap();
        assert_eq!(d.prefix.as_deref(), Some(S));
        assert!(d.ip.is_none() && !d.trusted);
        let d = DiscoveryServer::parse(&format!("{S}@{SIP}"), true).unwrap();
        assert_eq!(d.label(), format!("{S}@{SIP}"));
        assert!(d.trusted);
        let d = DiscoveryServer::parse("@::ffff:10.0.0.9", false).unwrap();
        assert_eq!(
            d.ip,
            Some("10.0.0.9".parse().unwrap()),
            "v4-mapped canonical"
        );
        assert_eq!(
            DiscoveryServer::parse("10.0.0.9", false).unwrap().label(),
            "@10.0.0.9"
        );
        for bad in [
            "",
            "@",
            "nope",
            "CCCCCCCCCCCCCCCCCCCCCCCC",
            "ccc@10.0.0.9",
            &format!("{S}@not-an-ip"),
            "0.0.0.0",
            "@::",
        ] {
            assert!(
                matches!(
                    DiscoveryServer::parse(bad, false),
                    Err(ConfigError::InvalidDiscoveryServer(_))
                ),
                "{bad:?}"
            );
        }
        // Matching: every configured part must match.
        let both = DiscoveryServer::parse(&format!("{S}@{SIP}"), false).unwrap();
        let o = |p: &str, ip: &str| Origin {
            sender_prefix: p.into(),
            src_ip: ip.into(),
        };
        assert!(both.matches(&o(S, SIP)));
        assert!(!both.matches(&o(S, "10.0.0.8")));
        assert!(!both.matches(&o(B, SIP)));
        assert!(!both.matches(&o(S, "garbage")));
        let ip_only = DiscoveryServer::parse(SIP, false).unwrap();
        assert!(ip_only.matches(&o(B, SIP)));
        assert!(ip_only.matches(&o(S, "::ffff:10.0.0.9")));
        // Config validation: count and hand-built invalid entries.
        let mut c = cfg();
        c.discovery_servers = vec![ip_only.clone(); MAX_DISCOVERY_SERVERS + 1];
        assert!(c.validate().is_err());
        c.discovery_servers = vec![DiscoveryServer {
            prefix: None,
            ip: None,
            trusted: true,
        }];
        assert!(Learner::new(c.clone()).is_err());
        c.discovery_servers = vec![DiscoveryServer {
            prefix: Some("xyz".into()),
            ip: None,
            trusted: false,
        }];
        assert!(c.validate().is_err());
        assert!(ConfigError::InvalidDiscoveryServer("x".into())
            .to_string()
            .contains("PREFIX@IP"));
        // A trusted server must be pinned by IP; prefix-only is refused for
        // trusted (by parse and by validate), fine for known.
        let e = DiscoveryServer::parse(S, true).unwrap_err();
        assert!(e.to_string().contains("pinned by IP"), "{e}");
        assert!(DiscoveryServer::parse(&format!("@{SIP}"), true).is_ok());
        let mut c = cfg();
        c.discovery_servers = vec![DiscoveryServer {
            prefix: Some(S.into()),
            ip: None,
            trusted: true,
        }];
        assert!(c.validate().is_err());
        // A trusted match wins over a known one.
        let mut c = cfg();
        c.discovery_servers = vec![
            DiscoveryServer::parse(SIP, false).unwrap(),
            DiscoveryServer::parse(&format!("{S}@{SIP}"), true).unwrap(),
        ];
        assert!(c.discovery_server_for(&o(S, SIP)).unwrap().trusted);
        assert!(!c.discovery_server_for(&o(B, SIP)).unwrap().trusted);
        assert!(c.discovery_server_for(&o(B, "10.1.1.1")).is_none());
    }

    #[test]
    fn unconfigured_relay_is_still_a_mismatch() {
        let c = ds_run(Vec::new(), relays_of_a()).finish();
        assert!(!c.profile.writer_topics.contains("/relayed_only"));
        let items = relay_items(&c);
        assert_eq!(items.len(), 1);
        assert_eq!(items[0].subject, format!("{A} sent by {S} from {SIP}"));
        assert!(items[0].reason.contains("GUID spoofing"));
    }

    #[test]
    fn known_server_confirms_copies_and_flags_the_rest() {
        let known = DiscoveryServer::parse(&format!("{S}@{SIP}"), false).unwrap();
        // Copy of a direct announcement only: attributed, no item.
        let only_copy = vec![sourced(writer(A, "rt/odom"), 10, S, SIP)];
        let c = ds_run(vec![known.clone()], only_copy).finish();
        assert!(relay_items(&c).is_empty(), "{:?}", relay_items(&c));
        assert!(c.profile.writer_topics.contains("/odom"));
        assert!(c
            .report
            .warnings
            .iter()
            .any(|w| w.code == "discovery_relay_attributed"));
        // Plus an endpoint A never announced directly: flagged, not learned.
        let c = ds_run(vec![known.clone()], relays_of_a()).finish();
        assert!(!c.profile.writer_topics.contains("/relayed_only"));
        let items = relay_items(&c);
        assert_eq!(items.len(), 1);
        assert!(items[0].reason.contains("known discovery server"));
        assert!(
            items[0].reason.contains("W /relayed_only"),
            "{}",
            items[0].reason
        );
        assert!(
            items[0].reason.contains("never announced 1 of them"),
            "{}",
            items[0].reason
        );
        // A known server's relayed SPDP is ignored: B, seen only through
        // the server, is not a participant; its relayed endpoints flagged.
        let b_only = vec![
            sourced(part_ip(B, SIP), 20, S, SIP),
            sourced(part_ip(B, SIP), 90, S, SIP),
            sourced(writer(B, "rt/scan"), 21, S, SIP),
        ];
        let c = ds_run(vec![known], b_only).finish();
        assert!(!c.profile.participants.contains(B));
        assert!(!c.profile.writer_topics.contains("/scan"));
        let items = relay_items(&c);
        assert_eq!(items.len(), 1);
        assert!(items[0].reason.contains("not an accepted participant"));
        assert!(c
            .report
            .warnings
            .iter()
            .any(|w| w.code == "discovery_relay_participants_ignored"));
        // A's IPs do not include the server's.
        assert!(!c.report.participants[A].src_ips.contains(SIP));
    }

    #[test]
    fn trusted_server_attributes_relays_of_accepted_owners() {
        let trusted = DiscoveryServer::parse(SIP, true).unwrap();
        let c = ds_run(vec![trusted.clone()], relays_of_a()).finish();
        assert!(c.profile.writer_topics.contains("/relayed_only"));
        assert!(relay_items(&c).is_empty(), "{:?}", relay_items(&c));
        // Relayed SPDP counts for B under the relay pseudo-address (never
        // the server's IP), so B is accepted and its relayed writer learned;
        // the pseudo-address is not a second IP.
        let b_relayed = vec![
            sourced(part_ip(B, SIP), 20, S, SIP),
            sourced(part_ip(B, "10.0.0.2"), 30, B, "10.0.0.2"),
            sourced(part_ip(B, SIP), 90, S, SIP),
            sourced(writer(B, "rt/scan"), 21, S, SIP),
        ];
        let c = ds_run(vec![trusted.clone()], b_relayed).finish();
        assert!(c.profile.participants.contains(B));
        assert!(c.profile.writer_topics.contains("/scan"));
        let pr = &c.report.participants[B];
        assert!(pr.src_ips.contains(&format!("{RELAY_MARK}@{SIP}")));
        assert!(!pr.src_ips.contains(SIP));
        assert!(!pr.flags.iter().any(|f| f == "participant_multiple_ips"));
        assert!(relay_items(&c).is_empty());
        // Owner announced once (quarantined): relayed endpoints flagged,
        // not learned, even from a trusted server.
        let q = vec![
            sourced(part_ip(B, SIP), 20, S, SIP),
            sourced(writer(B, "rt/scan"), 21, S, SIP),
        ];
        let c = ds_run(vec![trusted], q).finish();
        assert!(!c.profile.writer_topics.contains("/scan"));
        let items = relay_items(&c);
        assert_eq!(items.len(), 1);
        assert!(items[0].reason.contains("trusted discovery server"));
        assert!(items[0].reason.contains("not an accepted participant"));
    }

    #[test]
    fn relays_survive_merge_and_marker_addresses_are_refused() {
        let known = DiscoveryServer::parse(S, false).unwrap();
        let mut left = ds_run(vec![known.clone()], Vec::new());
        let mut right = Learner::new(LearnConfig {
            model: "m".into(),
            discovery_servers: vec![known],
            ..Default::default()
        })
        .unwrap();
        right.start_run("cap2");
        for e in relays_of_a() {
            right.observe_sourced(&e);
        }
        right.observe_sourced(&sourced(part_ip(B, SIP), 5, S, SIP));
        left.merge(&right);
        let c = left.finish();
        assert_eq!(relay_items(&c).len(), 1);
        assert!(!c.profile.writer_topics.contains("/relayed_only"));
        assert!(c
            .report
            .warnings
            .iter()
            .any(|w| w.code == "discovery_relay_participants_ignored"));
        // An input that claims the relay pseudo-address as a source IP
        // (JSONL is free text) is an anomaly, not learned.
        let mut l = Learner::new(cfg()).unwrap();
        l.observe(&part_ip(A, &format!("{RELAY_MARK}x")));
        let r = l.report();
        assert!(r.anomalies.iter().any(|a| a.kind == "invalid_src_ip"));
        assert!(!r.participants.contains_key(A));
    }

    #[test]
    fn relayed_endpoint_caps_are_counted() {
        let known = DiscoveryServer::parse(S, false).unwrap();
        let mut l = Learner::new(LearnConfig {
            model: "m".into(),
            discovery_servers: vec![known],
            limits: Limits {
                max_set_entries: 2,
                max_participants: 2,
                ..Default::default()
            },
            ..Default::default()
        })
        .unwrap();
        for i in 0..4 {
            l.observe_sourced(&sourced(writer(A, &format!("rt/t{i}")), i, S, SIP));
        }
        for g in ["dddddddddddddddddddddddd", "eeeeeeeeeeeeeeeeeeeeeeee"] {
            l.observe_sourced(&sourced(writer(g, "rt/x"), 9, S, SIP));
        }
        let r = l.report();
        assert!(r
            .anomalies
            .iter()
            .any(|a| a.subject.contains("relayed_endpoints")
                || a.detail.contains("relayed_endpoints")));
        assert!(r
            .anomalies
            .iter()
            .any(|a| a.detail.contains("relayed_endpoint_sources")));
    }

    // ------------------------------------- security review regression --

    /// Regression (was a PoC): a trusted discovery server given by GUID
    /// prefix only was matched on the RTPS header prefix alone, which any
    /// host can put in its packets, so an intruder at an unrelated IP got
    /// its own participant and endpoints, and endpoints it attributed to
    /// the legitimate A, learned with no sign-off item. Now a prefix-only
    /// trusted server is refused at configuration, the same prefix as a
    /// *known* server launders nothing, and pinned by IP the spoofed
    /// traffic is refused and reported.
    #[test]
    fn prefix_only_trusted_server_cannot_launder_spoofed_relays() {
        const X: &str = "dddddddddddddddddddddddd";
        const EVIL_IP: &str = "10.6.6.6";
        let spoofed = || {
            vec![
                sourced(part_ip(X, EVIL_IP), 20, S, EVIL_IP),
                sourced(writer(X, "rt/intruder_topic"), 21, S, EVIL_IP),
                sourced(writer(A, "rt/laundered_for_a"), 22, S, EVIL_IP),
                sourced(part_ip(X, EVIL_IP), 90, S, EVIL_IP),
            ]
        };
        assert!(matches!(
            DiscoveryServer::parse(S, true),
            Err(ConfigError::InvalidDiscoveryServer(_))
        ));
        // Hand-built, bypassing parse: the learner refuses the config.
        let bypass = LearnConfig {
            model: "m".into(),
            discovery_servers: vec![DiscoveryServer {
                prefix: Some(S.into()),
                ip: None,
                trusted: true,
            }],
            ..Default::default()
        };
        assert!(Learner::new(bypass).is_err());
        // The prefix as a known server: nothing of the spoofer is learned.
        let known = DiscoveryServer::parse(S, false).unwrap();
        let c = ds_run(vec![known], spoofed()).finish();
        assert!(!c.profile.participants.contains(X), "intruder not accepted");
        assert!(!c.profile.writer_topics.contains("/intruder_topic"));
        assert!(!c.profile.writer_topics.contains("/laundered_for_a"));
        assert!(!relay_items(&c).is_empty());
        // Pinned by IP as trusted: the same traffic is refused and reported.
        let pinned = DiscoveryServer::parse(&format!("{S}@{SIP}"), true).unwrap();
        let c = ds_run(vec![pinned], spoofed()).finish();
        assert!(!c.profile.writer_topics.contains("/intruder_topic"));
        assert!(!c.profile.writer_topics.contains("/laundered_for_a"));
        assert!(!relay_items(&c).is_empty());
    }
}
