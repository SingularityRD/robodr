//! Live safety-state feed: the robot's physical safety state (idle / moving
//! / e-stop / safe stop / human nearby), as the responder grades every plan
//! by it, read **passively** instead of from static configuration.
//!
//! RoboDR only ever *reads* this state. Nothing here publishes, subscribes,
//! connects to the robot or talks to the safety system: bus sources are
//! decoded from the copy of the traffic the daemon already captures, and
//! the socket source is a local socket the daemon listens on (a safety-PLC
//! gateway writes to it).
//!
//! # Sources
//!
//! * **ROS 2 topics** (`safety_feed.topics`), decoded from RTPS user DATA on
//!   the captured bus (the same datagrams the pipeline sees), by the type
//!   SEDP announced for the writer:
//!   * `std_msgs/msg/Bool`: `values` maps `"true"` / `"false"` to a claim
//!     (both required), e.g. `/estop`: `true` -> `estop_active`,
//!     `false` -> `none`;
//!   * `std_msgs/msg/UInt8`: `values` maps decimal codes to claims, e.g.
//!     `/robot_mode`: `"0"` -> `idle`, `"3"` -> `safe_state_active`;
//!   * `std_msgs/msg/String`: `values` maps exact strings (at most
//!     [`MAX_VALUE_KEY_LEN`] bytes, compared as bytes) to claims;
//!   * `nav_msgs/msg/Odometry`: `motion` thresholds derive `idle` /
//!     `moving_slow` / `moving_fast` from `‖twist.linear‖` (and optionally
//!     `|twist.angular|`) with hysteresis ([`next_level`]).
//! * **A unix socket** (`safety_feed.socket`): JSON lines
//!   `{"state":"estop_active"}` from a local safety-PLC gateway. The socket
//!   is created mode 0600 (only the daemon's user and root can connect),
//!   like the event socket.
//!
//! A claim is a [`SafetyState`] or `none` ("this value says nothing", e.g.
//! e-stop released). A value that the mapping does not list is **not**
//! ignored: it is an `unknown` claim (and a Low finding,
//! [`rules::UNMAPPED_VALUE`]).
//!
//! # Combining (never more aggressive)
//!
//! Every evaluation ([`SafetyFeed::evaluate`]):
//!
//! 1. per source, per writer: the latest claim, if younger than the
//!    source's `stale_after_ms`. A source with no fresh reading claims
//!    **`unknown`** (a silent, latched-only or dead publisher is not
//!    "fine"); a source whose writers disagree claims the most
//!    conservative of them;
//! 2. over all sources: the most conservative claim; `none` claims are
//!    skipped; if nothing claims a state, the result is `unknown`.
//!
//! "Most conservative" ([`conservativeness`]) is fixed in code, highest
//! first:
//!
//! 1. `estop_active`, then `safe_state_active`: the safety system has
//!    authority, the planner caps every plan at Record;
//! 2. `unknown`: the planner gates every motion-affecting step on human
//!    approval and never terminates a process;
//! 3. `collaborative_human_nearby`, `moving_fast`, `moving_slow` (physical
//!    hazard order);
//! 4. `idle`, the only state in which a process may be terminated.
//!
//! So no source can make the responder *more* active than any other fresh
//! source allows, and losing a source only moves the state towards
//! `unknown` or beyond. (Among the non-engaged known states the policy's
//! matrix rows may differ; the order above was chosen by hazard and is only
//! used when fresh sources genuinely disagree.)
//!
//! # Trust (spoofing)
//!
//! RTPS has no authentication here (no DDS-Security), so a sample is only
//! taken from a writer that the commissioning profile vouches for. A bus
//! sample is **ignored** and reported ([`rules::UNTRUSTED_SOURCE`], High,
//! once per source + writer + reason) unless all hold:
//!
//! * its writer was announced via SEDP for this topic, unambiguously (no
//!   alternate readings, no participant-GUID conflict), with the configured
//!   type;
//! * the writer's participant (GUID prefix) is in `profile.participants` and
//!   the topic is in `profile.writer_topics`;
//! * if the source lists `writers` (GUID prefixes or full GUIDs), the writer
//!   matches one;
//! * the datagram's source IP is not outside the participant's binding
//!   (`robodr-ros2-pipeline`'s binding table, which the pipeline updated
//!   from the same datagram just before).
//!
//! A writer that was never announced cannot be attributed to a topic at
//! all: its samples are not decoded (the pipeline reports unknown
//! participants / writers on its own). An ignored or undecodable sample
//! never refreshes a source, so a spoofer can at most make a source go
//! stale, i.e. `unknown`, never fresh-and-permissive. A trusted sample that
//! fails to decode sets that writer's claim to `unknown`
//! ([`rules::UNDECODABLE`]).
//!
//! # Recording
//!
//! Every change of the combined state is appended to the black box as a
//! `robodr.safety_state_transition` note ([`Transition`]: from, to, whether
//! fresh sources disagreed, and each source's claim and age), and the
//! current view is in `status.json` (`safety_feed`).
//!
//! # Limits
//!
//! * Only RTPS over UDP that the capture sees; shared memory, TCP and
//!   DDS-Security-protected payloads are invisible (sources go stale ->
//!   `unknown`). Publishers must publish **periodically** (faster than
//!   `stale_after_ms`); a latched, publish-on-change topic reads as
//!   `unknown` between changes.
//! * A writer announced before the daemon started is unknown until it
//!   re-announces (SEDP is not periodic), so its source reads `unknown`.
//! * The discovery of safety writers is parsed here a second time (own
//!   reassembler and user-DATA walker), because the pipeline's motion path
//!   only keeps motion and feedback topics.
//! * Synthetic traffic only (hand-built RTPS + CDR); not run against a real
//!   RMW, a real safety PLC or real e-stop hardware.
//! * Only the safety state is live; the rest of the operational context
//!   (control mode, mission phase, connectivity) is still configuration.

use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::net::IpAddr;
use std::path::PathBuf;

use robodr_cdr::{decode_payload, decode_std, Limits, MessageKind, MotionMessage, StdKind};
use robodr_cdr::{StdDecodeError, StdValue};
use robodr_events::graph::{demangle, RosNameKind};
use robodr_events::profile::Profile;
use robodr_events::{Deviation, Severity};
use robodr_responder::SafetyState;
use robodr_ros2_pipeline::{sanitize, BindingTable, Datagram};
use robodr_rtps::{
    hex12, hex_guid, EndpointKind, FragmentReassembler, Guid, PayloadKind, ReassemblyLimits,
    UserDataLimits, UserDataWalker,
};
use serde::{Deserialize, Serialize, Serializer};

/// Rule ids raised by the feed.
pub mod rules {
    /// A sample on a safety-state topic from a writer the profile does not
    /// vouch for (or announced ambiguously, with the wrong type, from an
    /// unbound IP). Ignored. High.
    pub const UNTRUSTED_SOURCE: &str = "robot.safety_state.untrusted_source";
    /// A trusted writer's sample that could not be decoded: its claim
    /// becomes `unknown`. Medium.
    pub const UNDECODABLE: &str = "robot.safety_state.undecodable_sample";
    /// A trusted writer sent a value the mapping does not list: its claim
    /// becomes `unknown`. Low.
    pub const UNMAPPED_VALUE: &str = "robot.safety_state.unmapped_value";
}

/// Default `stale_after_ms` of every source.
pub const DEFAULT_STALE_AFTER_MS: u64 = 1_000;
/// Bounds of any `stale_after_ms`.
pub const MIN_STALE_AFTER_MS: u64 = 10;
pub const MAX_STALE_AFTER_MS: u64 = 600_000;
/// Most topic sources.
pub const MAX_TOPIC_SOURCES: usize = 16;
/// Most entries of one `values` map.
pub const MAX_VALUES: usize = 64;
/// Longest `values` key (a `std_msgs/String` value), bytes.
pub const MAX_VALUE_KEY_LEN: usize = 64;
/// Most entries of one `writers` allowlist.
pub const MAX_ALLOWED_WRITERS: usize = 64;
/// Writers whose latest claim is kept per source (least recent evicted).
pub const MAX_WRITERS_PER_SOURCE: usize = 8;
/// SEDP writers on safety topics remembered (least recent evicted).
pub const MAX_KNOWN_WRITERS: usize = 256;
/// Distinct (topic, type) readings kept per writer.
const MAX_READINGS_PER_WRITER: usize = 4;
/// Dedup keys of reported findings (cleared when full).
const MAX_REPORTED: usize = 1024;
/// Most connections on the safety socket.
pub const MAX_SOCKET_CONNECTIONS: usize = 8;
/// Writer key of the socket source.
const SOCKET_WRITER: &str = "socket";

// ------------------------------------------------------------------ claims --

/// What one reading says about the safety state.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Claim {
    /// Nothing (e.g. e-stop released): does not constrain the result.
    None,
    State(SafetyState),
}

impl Claim {
    /// Parse a configured claim: `"none"` or a [`SafetyState`] name.
    pub fn parse(s: &str) -> Result<Self, String> {
        if s == "none" {
            return Ok(Claim::None);
        }
        serde_json::from_value::<SafetyState>(serde_json::Value::String(s.to_string()))
            .map(Claim::State)
            .map_err(|_| {
                format!(
                    "{:?} is not a safety state (idle, moving_slow, moving_fast, \
                     collaborative_human_nearby, estop_active, safe_state_active, unknown) \
                     or none",
                    sanitize(s)
                )
            })
    }

    pub fn as_str(self) -> &'static str {
        match self {
            Claim::None => "none",
            Claim::State(s) => state_name(s),
        }
    }
}

impl Serialize for Claim {
    fn serialize<S: Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        s.serialize_str(self.as_str())
    }
}

/// The configuration / serde name of a state.
pub fn state_name(s: SafetyState) -> &'static str {
    match s {
        SafetyState::Idle => "idle",
        SafetyState::MovingSlow => "moving_slow",
        SafetyState::MovingFast => "moving_fast",
        SafetyState::CollaborativeHumanNearby => "collaborative_human_nearby",
        SafetyState::EStopActive => "estop_active",
        SafetyState::SafeStateActive => "safe_state_active",
        SafetyState::Unknown => "unknown",
    }
}

/// How conservative a state is for the responder: higher = RoboDR may do
/// less on its own (see the module docs for the order and why).
pub fn conservativeness(s: SafetyState) -> u8 {
    match s {
        SafetyState::EStopActive => 6,
        SafetyState::SafeStateActive => 5,
        SafetyState::Unknown => 4,
        SafetyState::CollaborativeHumanNearby => 3,
        SafetyState::MovingFast => 2,
        SafetyState::MovingSlow => 1,
        SafetyState::Idle => 0,
    }
}

/// The most conservative of `states`, `None` if there are none.
pub fn most_conservative(states: impl IntoIterator<Item = SafetyState>) -> Option<SafetyState> {
    states.into_iter().max_by_key(|s| conservativeness(*s))
}

// ------------------------------------------------------------------ config --

/// `safety_feed` as written in the daemon configuration.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SafetyFeedSection {
    /// Default freshness bound of every source (ms).
    #[serde(default = "default_stale")]
    pub stale_after_ms: u64,
    #[serde(default)]
    pub topics: Vec<TopicSourceSection>,
    #[serde(default)]
    pub socket: Option<SocketSourceSection>,
}

fn default_stale() -> u64 {
    DEFAULT_STALE_AFTER_MS
}

/// One ROS 2 topic source.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TopicSourceSection {
    /// Plain ROS topic name, e.g. `/estop`.
    pub topic: String,
    /// ROS or DDS type name: `std_msgs/msg/Bool`, `std_msgs/msg/UInt8`,
    /// `std_msgs/msg/String` or `nav_msgs/msg/Odometry`.
    #[serde(rename = "type")]
    pub type_name: String,
    /// Value -> claim (`Bool` / `UInt8` / `String`).
    #[serde(default)]
    pub values: BTreeMap<String, String>,
    /// Speed thresholds (`Odometry`).
    #[serde(default)]
    pub motion: Option<MotionThresholds>,
    /// Optional allowlist: GUID prefixes (24 hex) or full writer GUIDs (32
    /// hex). Empty = every profiled writer on the topic.
    #[serde(default)]
    pub writers: Vec<String>,
    #[serde(default)]
    pub stale_after_ms: Option<u64>,
}

/// Odometry -> idle / moving_slow / moving_fast.
#[derive(Debug, Clone, Copy, PartialEq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MotionThresholds {
    /// `‖linear‖` above this (m/s) = moving.
    pub moving_above: f64,
    /// `‖linear‖` above this (m/s) = moving fast. Default: never fast.
    #[serde(default)]
    pub fast_above: Option<f64>,
    /// `‖angular‖` above this (rad/s) = moving (turning on the spot).
    #[serde(default)]
    pub angular_moving_above: Option<f64>,
    /// A level is left only once the value falls this far below the
    /// threshold that entered it (same units as the threshold).
    #[serde(default = "default_hysteresis")]
    pub hysteresis: f64,
}

fn default_hysteresis() -> f64 {
    0.02
}

/// The safety-PLC gateway socket.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SocketSourceSection {
    /// Absolute path; created mode 0600 by the daemon.
    pub path: PathBuf,
    #[serde(default = "default_socket_connections")]
    pub max_connections: usize,
    #[serde(default)]
    pub stale_after_ms: Option<u64>,
}

fn default_socket_connections() -> usize {
    2
}

/// How a topic source turns a sample into a claim.
#[derive(Debug, Clone, PartialEq)]
pub enum Decoder {
    Bool { on_true: Claim, on_false: Claim },
    UInt8(BTreeMap<u8, Claim>),
    Text(BTreeMap<Vec<u8>, Claim>),
    Odometry(MotionThresholds),
}

impl Decoder {
    fn type_label(&self) -> &'static str {
        match self {
            Decoder::Bool { .. } => StdKind::Bool.ros_type_name(),
            Decoder::UInt8(_) => StdKind::UInt8.ros_type_name(),
            Decoder::Text(_) => StdKind::String.ros_type_name(),
            Decoder::Odometry(_) => MessageKind::Odometry.ros_type_name(),
        }
    }

    /// Does an announced (DDS or ROS) type name match?
    fn accepts_type(&self, announced: &str) -> bool {
        match self {
            Decoder::Bool { .. } => StdKind::from_type_name(announced) == Some(StdKind::Bool),
            Decoder::UInt8(_) => StdKind::from_type_name(announced) == Some(StdKind::UInt8),
            Decoder::Text(_) => StdKind::from_type_name(announced) == Some(StdKind::String),
            Decoder::Odometry(_) => {
                MessageKind::from_type_name(announced) == Some(MessageKind::Odometry)
            }
        }
    }
}

/// A validated topic source.
#[derive(Debug, Clone, PartialEq)]
pub struct TopicSpec {
    pub topic: String,
    pub decoder: Decoder,
    /// Lower-case hex prefixes / GUIDs; empty = no allowlist.
    pub writers: BTreeSet<String>,
    pub stale_after_ms: u64,
}

/// A validated socket source.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SocketSpec {
    pub path: PathBuf,
    pub max_connections: usize,
    pub stale_after_ms: u64,
}

/// The validated feed configuration.
#[derive(Debug, Clone, PartialEq)]
pub struct FeedSpec {
    pub topics: Vec<TopicSpec>,
    pub socket: Option<SocketSpec>,
}

fn is_hex_lower(s: &str) -> bool {
    s.bytes().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f'))
}

fn check_stale(what: &str, v: u64) -> Result<u64, String> {
    if (MIN_STALE_AFTER_MS..=MAX_STALE_AFTER_MS).contains(&v) {
        Ok(v)
    } else {
        Err(format!(
            "{what} = {v}: must be {MIN_STALE_AFTER_MS}..={MAX_STALE_AFTER_MS}"
        ))
    }
}

/// A fully qualified, plain ROS topic name (`/estop`).
pub fn is_ros_topic(name: &str) -> bool {
    let rn = demangle(&format!("rt{name}"));
    name.starts_with('/') && rn.kind == RosNameKind::Topic && rn.name == name
}

fn claims(what: &str, values: &BTreeMap<String, String>) -> Result<Vec<(String, Claim)>, String> {
    if values.is_empty() {
        return Err(format!("{what}.values must not be empty"));
    }
    if values.len() > MAX_VALUES {
        return Err(format!("{what}.values: at most {MAX_VALUES} entries"));
    }
    values
        .iter()
        .map(|(k, v)| {
            Claim::parse(v)
                .map(|c| (k.clone(), c))
                .map_err(|e| format!("{what}.values[{:?}]: {e}", sanitize(k)))
        })
        .collect()
}

fn check_motion(what: &str, m: &MotionThresholds) -> Result<(), String> {
    let pos = |name: &str, v: f64| {
        if v.is_finite() && v > 0.0 {
            Ok(())
        } else {
            Err(format!("{what}.motion.{name} must be finite and > 0"))
        }
    };
    pos("moving_above", m.moving_above)?;
    if let Some(f) = m.fast_above {
        pos("fast_above", f)?;
        if f <= m.moving_above {
            return Err(format!(
                "{what}.motion.fast_above must be greater than moving_above"
            ));
        }
    }
    if let Some(a) = m.angular_moving_above {
        pos("angular_moving_above", a)?;
    }
    let min_threshold = m
        .angular_moving_above
        .map_or(m.moving_above, |a| a.min(m.moving_above));
    if !(m.hysteresis.is_finite() && m.hysteresis >= 0.0 && m.hysteresis < min_threshold) {
        return Err(format!(
            "{what}.motion.hysteresis must be finite, >= 0 and below every threshold"
        ));
    }
    Ok(())
}

impl SafetyFeedSection {
    /// Validate. Returns the spec and warnings (e.g. a topic the profile does
    /// not list as a writer topic: every sample on it would be ignored).
    pub fn resolve(&self, profile: &Profile) -> Result<(FeedSpec, Vec<String>), String> {
        let mut warnings = Vec::new();
        let default_stale = check_stale("safety_feed.stale_after_ms", self.stale_after_ms)?;
        if self.topics.is_empty() && self.socket.is_none() {
            return Err("safety_feed: configure at least one of topics, socket".into());
        }
        if self.topics.len() > MAX_TOPIC_SOURCES {
            return Err(format!(
                "safety_feed.topics: at most {MAX_TOPIC_SOURCES} entries"
            ));
        }
        let mut topics = Vec::new();
        let mut seen = BTreeSet::new();
        for (i, t) in self.topics.iter().enumerate() {
            let what = format!("safety_feed.topics[{i}]");
            if !is_ros_topic(&t.topic) {
                return Err(format!(
                    "{what}.topic {:?} is not a plain ROS topic name (e.g. /estop)",
                    sanitize(&t.topic)
                ));
            }
            if !seen.insert(t.topic.clone()) {
                return Err(format!("{what}: topic {} listed twice", t.topic));
            }
            let stale = match t.stale_after_ms {
                Some(v) => check_stale(&format!("{what}.stale_after_ms"), v)?,
                None => default_stale,
            };
            let std = StdKind::from_type_name(&t.type_name);
            let odom = MessageKind::from_type_name(&t.type_name) == Some(MessageKind::Odometry);
            if !odom && t.motion.is_some() {
                return Err(format!("{what}.motion is only for nav_msgs/msg/Odometry"));
            }
            let decoder = match (std, odom) {
                (Some(StdKind::Bool), _) => {
                    let c = claims(&what, &t.values)?;
                    let get = |k: &str| c.iter().find(|(key, _)| key == k).map(|(_, c)| *c);
                    if c.len() != 2 {
                        return Err(format!(
                            "{what}.values for a Bool must map exactly \"true\" and \"false\""
                        ));
                    }
                    match (get("true"), get("false")) {
                        (Some(on_true), Some(on_false)) => Decoder::Bool { on_true, on_false },
                        _ => {
                            return Err(format!(
                                "{what}.values for a Bool must map exactly \"true\" and \"false\""
                            ))
                        }
                    }
                }
                (Some(StdKind::UInt8), _) => {
                    let mut m = BTreeMap::new();
                    for (k, c) in claims(&what, &t.values)? {
                        let v: u8 = k.parse().map_err(|_| {
                            format!(
                                "{what}.values: key {:?} is not a decimal 0..=255",
                                sanitize(&k)
                            )
                        })?;
                        if m.insert(v, c).is_some() {
                            return Err(format!("{what}.values: value {v} listed twice"));
                        }
                    }
                    Decoder::UInt8(m)
                }
                (Some(StdKind::String), _) => {
                    let mut m = BTreeMap::new();
                    for (k, c) in claims(&what, &t.values)? {
                        if k.len() > MAX_VALUE_KEY_LEN || k.chars().any(char::is_control) {
                            return Err(format!(
                                "{what}.values: key {:?} is longer than {MAX_VALUE_KEY_LEN} \
                                 bytes or has control characters",
                                sanitize(&k)
                            ));
                        }
                        m.insert(k.into_bytes(), c);
                    }
                    Decoder::Text(m)
                }
                (None, true) => {
                    if !t.values.is_empty() {
                        return Err(format!(
                            "{what}.values is not used for Odometry (use motion)"
                        ));
                    }
                    let m = t.motion.ok_or_else(|| {
                        format!("{what}: Odometry needs motion.moving_above (m/s)")
                    })?;
                    check_motion(&what, &m)?;
                    Decoder::Odometry(m)
                }
                (None, false) => {
                    return Err(format!(
                        "{what}.type {:?}: supported are std_msgs/msg/Bool, std_msgs/msg/UInt8, \
                         std_msgs/msg/String and nav_msgs/msg/Odometry (ROS or DDS names)",
                        sanitize(&t.type_name)
                    ))
                }
            };
            if t.writers.len() > MAX_ALLOWED_WRITERS {
                return Err(format!(
                    "{what}.writers: at most {MAX_ALLOWED_WRITERS} entries"
                ));
            }
            let mut writers = BTreeSet::new();
            for w in &t.writers {
                let w = w.to_ascii_lowercase();
                if !(matches!(w.len(), 24 | 32) && is_hex_lower(&w)) {
                    return Err(format!(
                        "{what}.writers: {:?} is not a GUID prefix (24 hex) or a GUID (32 hex)",
                        sanitize(&w)
                    ));
                }
                writers.insert(w);
            }
            if !profile.writer_topics.contains(&t.topic) {
                warnings.push(format!(
                    "safety_feed: {} is not a writer topic of the profile: every sample on it \
                     will be ignored as unprofiled (the source stays unknown)",
                    t.topic
                ));
            }
            topics.push(TopicSpec {
                topic: t.topic.clone(),
                decoder,
                writers,
                stale_after_ms: stale,
            });
        }
        let socket = match &self.socket {
            None => None,
            Some(s) => {
                if s.path.as_os_str().is_empty() || !s.path.is_absolute() {
                    return Err("safety_feed.socket.path must be an absolute path".into());
                }
                if !(1..=MAX_SOCKET_CONNECTIONS).contains(&s.max_connections) {
                    return Err(format!(
                        "safety_feed.socket.max_connections must be 1..={MAX_SOCKET_CONNECTIONS}"
                    ));
                }
                let stale = match s.stale_after_ms {
                    Some(v) => check_stale("safety_feed.socket.stale_after_ms", v)?,
                    None => default_stale,
                };
                Some(SocketSpec {
                    path: s.path.clone(),
                    max_connections: s.max_connections,
                    stale_after_ms: stale,
                })
            }
        };
        Ok((FeedSpec { topics, socket }, warnings))
    }
}

/// One line of the safety socket: `{"state":"estop_active"}`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SafetyReport {
    pub state: SafetyState,
}

// ------------------------------------------------------------- motion level --

/// Motion level derived from odometry.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum Level {
    #[default]
    Idle,
    Slow,
    Fast,
}

impl Level {
    fn claim(self) -> SafetyState {
        match self {
            Level::Idle => SafetyState::Idle,
            Level::Slow => SafetyState::MovingSlow,
            Level::Fast => SafetyState::MovingFast,
        }
    }
}

/// The next motion level for `speed` (m/s, `‖linear‖`) and `angular`
/// (rad/s, `‖angular‖`), given the previous one. A level is entered above
/// its threshold and left only below `threshold - hysteresis`. Inputs must
/// be finite (the caller maps non-finite to `unknown`).
pub fn next_level(prev: Level, speed: f64, angular: f64, t: &MotionThresholds) -> Level {
    let h = t.hysteresis;
    let fast_on = t.fast_above.is_some_and(|f| speed > f);
    let fast_hold = t.fast_above.is_some_and(|f| speed > f - h);
    let ang_on = t.angular_moving_above.is_some_and(|a| angular > a);
    let ang_hold = t.angular_moving_above.is_some_and(|a| angular > a - h);
    let slow_on = speed > t.moving_above || ang_on;
    let slow_hold = speed > t.moving_above - h || ang_hold;
    match prev {
        Level::Fast if fast_hold => Level::Fast,
        _ if fast_on => Level::Fast,
        Level::Fast | Level::Slow if slow_hold => Level::Slow,
        _ if slow_on => Level::Slow,
        _ => Level::Idle,
    }
}

// ------------------------------------------------------------------- state --

#[derive(Debug, Clone, Copy)]
struct Reading {
    claim: Claim,
    at_ms: u64,
    level: Level,
}

#[derive(Debug)]
struct Source {
    name: String,
    stale_after_ms: u64,
    readings: BTreeMap<String, Reading>,
    evicted: u64,
}

impl Source {
    fn new(name: String, stale_after_ms: u64) -> Self {
        Self {
            name,
            stale_after_ms,
            readings: BTreeMap::new(),
            evicted: 0,
        }
    }

    fn fresh(&self, r: &Reading, now_ms: u64) -> bool {
        now_ms.saturating_sub(r.at_ms) <= self.stale_after_ms
    }

    /// The source's claim: `unknown` without a fresh reading, else the most
    /// conservative fresh state claim (`none` if every fresh one is none).
    fn claim(&self, now_ms: u64) -> Claim {
        let fresh: Vec<&Reading> = self
            .readings
            .values()
            .filter(|r| self.fresh(r, now_ms))
            .collect();
        if fresh.is_empty() {
            return Claim::State(SafetyState::Unknown);
        }
        match most_conservative(fresh.iter().filter_map(|r| match r.claim {
            Claim::State(s) => Some(s),
            Claim::None => None,
        })) {
            Some(s) => Claim::State(s),
            None => Claim::None,
        }
    }

    fn set(&mut self, writer: &str, claim: Claim, level: Level, now_ms: u64) {
        if !self.readings.contains_key(writer) && self.readings.len() >= MAX_WRITERS_PER_SOURCE {
            let oldest = self
                .readings
                .iter()
                .min_by_key(|(_, r)| r.at_ms)
                .map(|(k, _)| k.clone());
            if let Some(k) = oldest {
                self.readings.remove(&k);
                self.evicted += 1;
            }
        }
        self.readings.insert(
            writer.to_string(),
            Reading {
                claim,
                at_ms: now_ms,
                level,
            },
        );
    }
}

/// One source in a [`Transition`] / the status.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct SourceView {
    pub name: String,
    /// The source's claim now (`unknown` when stale).
    pub claim: Claim,
    /// Has a reading younger than `stale_after_ms`.
    pub fresh: bool,
    /// Age of the newest reading, if any.
    pub age_ms: Option<u64>,
    pub writers: usize,
}

/// A change of the combined state (black-box note).
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Transition {
    pub kind: &'static str,
    pub from: Claim,
    pub to: Claim,
    /// Daemon uptime (ms) of the evaluation.
    pub at_ms: u64,
    /// Fresh sources claimed different states (the most conservative won).
    pub conflict: bool,
    pub sources: Vec<SourceView>,
}

/// Counters.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize)]
pub struct FeedStats {
    /// Bus samples on safety topics examined.
    pub samples: u64,
    /// Samples / socket reports that updated a source.
    pub applied: u64,
    pub untrusted: u64,
    pub undecodable: u64,
    pub unmapped: u64,
    /// Key-only / no-payload samples skipped.
    pub not_data: u64,
    pub socket_reports: u64,
    pub transitions: u64,
    pub writers_known: u64,
    pub writers_evicted: u64,
}

/// The feed's current view (status file).
#[derive(Debug, Clone, Serialize)]
pub struct FeedStatus {
    pub state: Claim,
    pub sources: Vec<SourceView>,
    pub stats: FeedStats,
}

/// A deviation the feed raised, with what the finding's subject needs.
#[derive(Debug, Clone)]
pub struct FeedFinding {
    pub deviation: Deviation,
    pub src_ip: String,
    pub topic: String,
    pub writer: String,
}

#[derive(Debug, Clone)]
struct WriterInfo {
    /// (ROS topic, announced type) readings on safety topics.
    readings: Vec<(String, String)>,
    /// An announcement had alternates or a participant-GUID conflict.
    ambiguous: bool,
    last_seen: u64,
}

/// The passive bus tap: SEDP writers on safety topics, user DATA walker.
struct BusTap {
    reassembler: FragmentReassembler,
    walker: UserDataWalker,
    writers: HashMap<Guid, WriterInfo>,
    clock: u64,
    evicted: u64,
}

impl BusTap {
    fn new() -> Self {
        Self {
            reassembler: FragmentReassembler::new(ReassemblyLimits::default()),
            walker: UserDataWalker::new(UserDataLimits::default()),
            writers: HashMap::new(),
            clock: 0,
            evicted: 0,
        }
    }

    fn learn(&mut self, guid: Guid, topic: String, type_name: String, ambiguous: bool) {
        self.clock += 1;
        let clock = self.clock;
        if let Some(w) = self.writers.get_mut(&guid) {
            w.last_seen = clock;
            w.ambiguous |= ambiguous;
            let r = (topic, type_name);
            if !w.readings.contains(&r) {
                if w.readings.len() < MAX_READINGS_PER_WRITER {
                    w.readings.push(r);
                } else {
                    w.ambiguous = true;
                }
            }
            return;
        }
        if self.writers.len() >= MAX_KNOWN_WRITERS {
            let victim = self
                .writers
                .iter()
                .min_by_key(|(_, w)| w.last_seen)
                .map(|(g, _)| *g);
            if let Some(g) = victim {
                self.writers.remove(&g);
                self.evicted += 1;
            }
        }
        self.writers.insert(
            guid,
            WriterInfo {
                readings: vec![(topic, type_name)],
                ambiguous,
                last_seen: clock,
            },
        );
    }
}

/// The live feed. Owned by the daemon's main thread.
pub struct SafetyFeed {
    spec: FeedSpec,
    /// One per topic (same index), then the socket source if any.
    sources: Vec<Source>,
    tap: BusTap,
    current: SafetyState,
    stats: FeedStats,
    reported: BTreeSet<String>,
    limits_std: Limits,
    limits_odom: Limits,
}

impl std::fmt::Debug for SafetyFeed {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SafetyFeed")
            .field("current", &self.current)
            .field("stats", &self.stats)
            .finish()
    }
}

fn short(s: &str) -> String {
    sanitize(&s.chars().take(96).collect::<String>())
}

impl SafetyFeed {
    /// A feed with no readings yet: the state is `unknown`.
    pub fn new(spec: FeedSpec) -> Self {
        let mut sources: Vec<Source> = spec
            .topics
            .iter()
            .map(|t| Source::new(t.topic.clone(), t.stale_after_ms))
            .collect();
        if let Some(s) = &spec.socket {
            sources.push(Source::new(
                format!("socket:{}", s.path.display()),
                s.stale_after_ms,
            ));
        }
        Self {
            spec,
            sources,
            tap: BusTap::new(),
            current: SafetyState::Unknown,
            stats: FeedStats::default(),
            reported: BTreeSet::new(),
            limits_std: Limits {
                max_payload_len: 4096,
                ..Limits::default()
            },
            limits_odom: Limits::default(),
        }
    }

    pub fn spec(&self) -> &FeedSpec {
        &self.spec
    }

    /// The combined state as of the last [`SafetyFeed::evaluate`].
    pub fn state(&self) -> SafetyState {
        self.current
    }

    pub fn stats(&self) -> FeedStats {
        let mut s = self.stats;
        s.writers_known = self.tap.writers.len() as u64;
        s.writers_evicted = self.tap.evicted;
        s
    }

    fn views(&self, now_ms: u64) -> Vec<SourceView> {
        self.sources
            .iter()
            .map(|s| SourceView {
                name: s.name.clone(),
                claim: s.claim(now_ms),
                fresh: s.readings.values().any(|r| s.fresh(r, now_ms)),
                age_ms: s
                    .readings
                    .values()
                    .map(|r| now_ms.saturating_sub(r.at_ms))
                    .min(),
                writers: s.readings.len(),
            })
            .collect()
    }

    /// The current view for the status file.
    pub fn status(&self, now_ms: u64) -> FeedStatus {
        FeedStatus {
            state: Claim::State(self.current),
            sources: self.views(now_ms),
            stats: self.stats(),
        }
    }

    /// Recompute the combined state at `now_ms` (daemon uptime). Returns the
    /// transition if it changed.
    pub fn evaluate(&mut self, now_ms: u64) -> Option<Transition> {
        let views = self.views(now_ms);
        let states: Vec<SafetyState> = views
            .iter()
            .filter_map(|v| match v.claim {
                Claim::State(s) => Some(s),
                Claim::None => None,
            })
            .collect();
        // Disagreement among fresh sources (stale ones are just unknown),
        // or among one source's fresh writers.
        let fresh_states: BTreeSet<&'static str> = views
            .iter()
            .filter(|v| v.fresh)
            .filter_map(|v| match v.claim {
                Claim::State(s) => Some(state_name(s)),
                Claim::None => None,
            })
            .collect();
        let writer_conflict = self.sources.iter().any(|s| {
            let set: BTreeSet<&'static str> = s
                .readings
                .values()
                .filter(|r| s.fresh(r, now_ms))
                .map(|r| r.claim.as_str())
                .collect();
            set.len() > 1
        });
        let next = most_conservative(states).unwrap_or(SafetyState::Unknown);
        if next == self.current {
            return None;
        }
        let from = self.current;
        self.current = next;
        self.stats.transitions += 1;
        Some(Transition {
            kind: "robodr.safety_state_transition",
            from: Claim::State(from),
            to: Claim::State(next),
            at_ms: now_ms,
            conflict: fresh_states.len() > 1 || writer_conflict,
            sources: views,
        })
    }

    /// A report from the safety socket.
    pub fn observe_report(&mut self, report: SafetyReport, now_ms: u64) {
        self.stats.socket_reports += 1;
        if self.spec.socket.is_none() {
            return;
        }
        if let Some(src) = self.sources.last_mut() {
            src.set(
                SOCKET_WRITER,
                Claim::State(report.state),
                Level::Idle,
                now_ms,
            );
            self.stats.applied += 1;
        }
    }

    fn finding(
        &mut self,
        out: &mut Vec<FeedFinding>,
        key: String,
        dev: Deviation,
        src_ip: &str,
        topic: &str,
        writer: &str,
    ) {
        if self.reported.len() >= MAX_REPORTED {
            self.reported.clear();
        }
        if self.reported.insert(key) {
            out.push(FeedFinding {
                deviation: dev,
                src_ip: src_ip.to_string(),
                topic: topic.to_string(),
                writer: writer.to_string(),
            });
        }
    }

    /// Why `writer` (on `topic`, announced as `info`) is not trusted, if so.
    fn distrust(
        &self,
        spec: &TopicSpec,
        guid: &Guid,
        info: &WriterInfo,
        profile: &Profile,
        binding: &BindingTable,
        datagram: &Datagram,
    ) -> Option<String> {
        if info.ambiguous || info.readings.len() > 1 {
            return Some("its SEDP announcement is ambiguous (several readings)".into());
        }
        let announced = info
            .readings
            .iter()
            .find(|(t, _)| *t == spec.topic)
            .map(|(_, ty)| ty.as_str())
            .unwrap_or("");
        if !spec.decoder.accepts_type(announced) {
            return Some(format!(
                "it was announced with type {}, not {}",
                short(announced),
                spec.decoder.type_label()
            ));
        }
        let prefix: [u8; 12] = guid[..12].try_into().unwrap_or_default();
        let prefix_hex = hex12(&prefix);
        if !profile.participants.contains(&prefix_hex) {
            return Some("its participant is not in the profile".into());
        }
        if !profile.writer_topics.contains(&spec.topic) {
            return Some("the profile does not allow writers on this topic".into());
        }
        if !spec.writers.is_empty()
            && !spec.writers.contains(&prefix_hex)
            && !spec.writers.contains(&hex_guid(guid))
        {
            return Some("it is not in the safety_feed writers allowlist".into());
        }
        if let Ok(ip) = datagram.src_ip.parse::<IpAddr>() {
            if binding.allows_from(&prefix, ip, datagram.ingress) == Some(false) {
                return Some(format!(
                    "it arrived from {}, an IP not bound to its participant",
                    short(&datagram.src_ip)
                ));
            }
        }
        None
    }

    /// Learn this datagram's SEDP and apply its samples on safety topics.
    /// Call after the pipeline has processed the same datagram (its binding
    /// table then includes this datagram's SPDP). Returns findings.
    pub fn observe_datagram(
        &mut self,
        datagram: &Datagram,
        profile: &Profile,
        binding: &BindingTable,
        now_ms: u64,
    ) -> Vec<FeedFinding> {
        let mut out = Vec::new();
        if self.spec.topics.is_empty() {
            return out;
        }
        let payload = &datagram.payload;
        let Some(report) = self.tap.reassembler.parse_datagram_detailed(payload) else {
            return out;
        };
        for ep in &report.endpoints {
            if ep.kind != EndpointKind::Writer {
                continue;
            }
            let ambiguous = !ep.alternates.is_empty() || ep.guid_conflict;
            let mut readings = Vec::new();
            if let Some(g) = ep.guid {
                readings.push((g, ep.topic.clone(), ep.type_name.clone()));
            }
            for a in &ep.alternates {
                if let Some(g) = a.guid.or(ep.guid) {
                    readings.push((g, a.topic.clone(), a.type_name.clone()));
                }
            }
            for (g, topic, ty) in readings {
                let rn = demangle(&topic);
                if rn.kind == RosNameKind::Topic
                    && self.spec.topics.iter().any(|t| t.topic == rn.name)
                {
                    self.tap.learn(g, rn.name, ty, ambiguous);
                }
            }
        }
        let user = {
            let writers = &self.tap.writers;
            self.tap
                .walker
                .walk_with(payload, |a| writers.contains_key(&a.writer))
        };
        let Some(user) = user else {
            return out;
        };
        for s in &user.samples {
            let Some(info) = self.tap.writers.get(&s.address.writer).cloned() else {
                continue;
            };
            let writer = hex_guid(&s.address.writer);
            for idx in 0..self.spec.topics.len() {
                let spec = self.spec.topics[idx].clone();
                if !info.readings.iter().any(|(t, _)| *t == spec.topic) {
                    continue;
                }
                if s.payload_kind != PayloadKind::Data {
                    self.stats.not_data += 1;
                    continue;
                }
                self.stats.samples += 1;
                if let Some(why) =
                    self.distrust(&spec, &s.address.writer, &info, profile, binding, datagram)
                {
                    self.stats.untrusted += 1;
                    let dev = Deviation::new(
                        rules::UNTRUSTED_SOURCE,
                        Severity::High,
                        format!(
                            "safety-state sample on {} from writer {writer} (from {}) was \
                             ignored: {why}",
                            spec.topic,
                            short(&datagram.src_ip)
                        ),
                    );
                    let key = format!("u|{}|{writer}|{why}", spec.topic);
                    self.finding(&mut out, key, dev, &datagram.src_ip, &spec.topic, &writer);
                    continue;
                }
                let prev = self.sources[idx]
                    .readings
                    .get(&writer)
                    .map(|r| r.level)
                    .unwrap_or_default();
                let decoded = if s.non_standard_payload {
                    Err("non-standard payload (N flag)".to_string())
                } else {
                    self.decode(&spec.decoder, &s.payload, prev)
                };
                let (claim, level) = match decoded {
                    Ok((Some(claim), level)) => (claim, level),
                    Ok((None, level)) => {
                        self.stats.unmapped += 1;
                        let dev = Deviation::new(
                            rules::UNMAPPED_VALUE,
                            Severity::Low,
                            format!(
                                "safety-state topic {} carried a value the safety_feed mapping \
                                 does not list (writer {writer}); read as unknown",
                                spec.topic
                            ),
                        );
                        let key = format!("m|{}|{writer}", spec.topic);
                        self.finding(&mut out, key, dev, &datagram.src_ip, &spec.topic, &writer);
                        (Claim::State(SafetyState::Unknown), level)
                    }
                    Err(why) => {
                        self.stats.undecodable += 1;
                        let dev = Deviation::new(
                            rules::UNDECODABLE,
                            Severity::Medium,
                            format!(
                                "safety-state sample on {} from writer {writer} could not be \
                                 decoded ({why}); read as unknown",
                                spec.topic
                            ),
                        );
                        let key = format!("d|{}|{writer}|{why}", spec.topic);
                        self.finding(&mut out, key, dev, &datagram.src_ip, &spec.topic, &writer);
                        (Claim::State(SafetyState::Unknown), prev)
                    }
                };
                self.sources[idx].set(&writer, claim, level, now_ms);
                self.stats.applied += 1;
            }
        }
        out
    }

    /// Decode one payload: `Ok((Some(claim), level))`, `Ok((None, _))` for a
    /// value the mapping does not list, `Err(reason)` if undecodable.
    fn decode(
        &self,
        decoder: &Decoder,
        payload: &[u8],
        prev: Level,
    ) -> Result<(Option<Claim>, Level), String> {
        let std_value = |kind: StdKind| std_value(kind, payload, &self.limits_std);
        match decoder {
            Decoder::Bool { on_true, on_false } => match std_value(StdKind::Bool)? {
                StdValue::Bool(true) => Ok((Some(*on_true), prev)),
                StdValue::Bool(false) => Ok((Some(*on_false), prev)),
                _ => Err("wrong value type".into()),
            },
            Decoder::UInt8(m) => match std_value(StdKind::UInt8)? {
                StdValue::UInt8(v) => Ok((m.get(&v).copied(), prev)),
                _ => Err("wrong value type".into()),
            },
            Decoder::Text(m) => match std_value(StdKind::String)? {
                StdValue::String(s) => Ok((m.get(s.as_bytes()).copied(), prev)),
                _ => Err("wrong value type".into()),
            },
            Decoder::Odometry(t) => {
                let d = decode_payload(MessageKind::Odometry, payload, &self.limits_odom)
                    .map_err(|e| short(&e.to_string()))?;
                let MotionMessage::Odometry(o) = d.message else {
                    return Err("wrong message type".into());
                };
                let speed = o.twist.twist.linear.norm();
                let angular = o.twist.twist.angular.norm();
                if !(speed.is_finite() && angular.is_finite()) {
                    // A non-finite speed says nothing trustworthy.
                    return Ok((Some(Claim::State(SafetyState::Unknown)), prev));
                }
                let level = next_level(prev, speed, angular, t);
                Ok((Some(Claim::State(level.claim())), level))
            }
        }
    }
}

/// Decode a `std_msgs` value; the error is a short, value-free reason.
fn std_value<'p>(
    kind: StdKind,
    payload: &'p [u8],
    limits: &Limits,
) -> Result<StdValue<'p>, String> {
    decode_std(kind, payload, limits)
        .map(|d| d.value)
        .map_err(|e| match e {
            StdDecodeError::InvalidBool { .. } => "boolean neither 0 nor 1".to_string(),
            StdDecodeError::Cdr(e) => short(&e.to_string()),
        })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn thresholds() -> MotionThresholds {
        MotionThresholds {
            moving_above: 0.05,
            fast_above: Some(1.0),
            angular_moving_above: Some(0.1),
            hysteresis: 0.02,
        }
    }

    #[test]
    fn conservative_order_is_total_and_puts_engaged_and_unknown_first() {
        let mut all = SafetyState::ALL.to_vec();
        all.sort_by_key(|s| conservativeness(*s));
        assert_eq!(
            all,
            vec![
                SafetyState::Idle,
                SafetyState::MovingSlow,
                SafetyState::MovingFast,
                SafetyState::CollaborativeHumanNearby,
                SafetyState::Unknown,
                SafetyState::SafeStateActive,
                SafetyState::EStopActive,
            ]
        );
        // Unknown beats every state the planner may act on without approval.
        for s in SafetyState::ALL {
            if !s.safety_system_engaged() && s != SafetyState::Unknown {
                assert_eq!(
                    most_conservative([s, SafetyState::Unknown]),
                    Some(SafetyState::Unknown)
                );
            }
            assert_eq!(
                most_conservative([s, SafetyState::EStopActive]),
                Some(SafetyState::EStopActive)
            );
            assert_eq!(state_name(s), Claim::State(s).as_str());
            assert_eq!(Claim::parse(state_name(s)), Ok(Claim::State(s)));
        }
        assert_eq!(most_conservative([]), None);
        assert_eq!(Claim::parse("none"), Ok(Claim::None));
        assert!(Claim::parse("flying").is_err());
        assert!(Claim::parse("EStopActive").is_err());
    }

    #[test]
    fn hysteresis_levels() {
        let t = thresholds();
        let mut l = Level::Idle;
        let mut seq = Vec::new();
        for v in [0.0, 0.04, 0.06, 0.04, 0.03, 0.02, 1.1, 0.99, 0.97, 0.5, 0.0] {
            l = next_level(l, v, 0.0, &t);
            seq.push(l);
        }
        use Level::*;
        assert_eq!(
            seq,
            vec![Idle, Idle, Slow, Slow, Idle, Idle, Fast, Fast, Slow, Slow, Idle]
        );
        // Turning on the spot is moving.
        assert_eq!(next_level(Idle, 0.0, 0.2, &t), Slow);
        assert_eq!(next_level(Slow, 0.0, 0.09, &t), Slow);
        assert_eq!(next_level(Slow, 0.0, 0.07, &t), Idle);
        // No fast threshold: never fast.
        let t2 = MotionThresholds {
            fast_above: None,
            ..t
        };
        assert_eq!(next_level(Idle, 100.0, 0.0, &t2), Slow);
        // Jump straight from idle to fast.
        assert_eq!(next_level(Idle, 5.0, 0.0, &t), Fast);
    }

    fn feed_with_socket(stale: u64) -> SafetyFeed {
        SafetyFeed::new(FeedSpec {
            topics: vec![TopicSpec {
                topic: "/estop".into(),
                decoder: Decoder::Bool {
                    on_true: Claim::State(SafetyState::EStopActive),
                    on_false: Claim::None,
                },
                writers: BTreeSet::new(),
                stale_after_ms: stale,
            }],
            socket: Some(SocketSpec {
                path: "/run/x.sock".into(),
                max_connections: 1,
                stale_after_ms: stale,
            }),
        })
    }

    #[test]
    fn staleness_conflict_and_none() {
        let mut f = feed_with_socket(100);
        assert_eq!(f.state(), SafetyState::Unknown);
        assert_eq!(f.evaluate(0), None, "starts unknown, no transition");
        // Socket says moving; the topic source has never spoken: unknown.
        f.observe_report(
            SafetyReport {
                state: SafetyState::MovingSlow,
            },
            10,
        );
        assert_eq!(f.evaluate(10), None);
        assert_eq!(f.state(), SafetyState::Unknown);
        // The e-stop topic speaks "released" (none): moving_slow.
        f.sources[0].set("w1", Claim::None, Level::Idle, 20);
        let t = f.evaluate(20).unwrap();
        assert_eq!(
            (t.from, t.to),
            (
                Claim::State(SafetyState::Unknown),
                Claim::State(SafetyState::MovingSlow)
            )
        );
        assert!(!t.conflict);
        // A second (trusted) writer on /estop says engaged: conflict among
        // writers -> e-stop wins.
        f.sources[0].set(
            "w2",
            Claim::State(SafetyState::EStopActive),
            Level::Idle,
            30,
        );
        let t = f.evaluate(30).unwrap();
        assert_eq!(t.to, Claim::State(SafetyState::EStopActive));
        assert!(t.conflict);
        // Everything goes stale: unknown.
        let t = f.evaluate(500).unwrap();
        assert_eq!(t.to, Claim::State(SafetyState::Unknown));
        assert!(t.sources.iter().all(|s| !s.fresh));
        assert!(t
            .sources
            .iter()
            .all(|s| s.claim == Claim::State(SafetyState::Unknown)));
        // Only "none" claims fresh -> unknown, never idle.
        let mut g = SafetyFeed::new(FeedSpec {
            socket: None,
            ..feed_with_socket(100).spec
        });
        g.sources[0].set("w", Claim::None, Level::Idle, 0);
        assert_eq!(g.evaluate(1), None);
        assert_eq!(g.state(), SafetyState::Unknown);
        // Sources disagree (socket idle vs topic estop): estop.
        let mut h = feed_with_socket(1000);
        h.observe_report(
            SafetyReport {
                state: SafetyState::Idle,
            },
            0,
        );
        h.sources[0].set("w", Claim::State(SafetyState::EStopActive), Level::Idle, 0);
        let t = h.evaluate(0).unwrap();
        assert_eq!(t.to, Claim::State(SafetyState::EStopActive));
        assert!(t.conflict);
        let json = serde_json::to_string(&t).unwrap();
        assert!(json.contains("\"to\":\"estop_active\""), "{json}");
        assert!(json.contains("robodr.safety_state_transition"));
    }

    #[test]
    fn per_source_writer_table_is_bounded() {
        let mut f = feed_with_socket(1000);
        for i in 0..50u64 {
            f.sources[0].set(&format!("w{i}"), Claim::None, Level::Idle, i);
        }
        assert_eq!(f.sources[0].readings.len(), MAX_WRITERS_PER_SOURCE);
        assert!(f.sources[0].readings.contains_key("w49"));
        assert!(!f.sources[0].readings.contains_key("w0"));
    }

    fn section(v: serde_json::Value) -> Result<(FeedSpec, Vec<String>), String> {
        let s: SafetyFeedSection = serde_json::from_value(v).map_err(|e| e.to_string())?;
        let mut p = Profile::default();
        p.writer_topics.insert("/estop".into());
        s.resolve(&p)
    }

    #[test]
    fn config_validation() {
        let (spec, w) = section(serde_json::json!({
            "topics": [
                {"topic": "/estop", "type": "std_msgs/msg/Bool",
                 "values": {"true": "estop_active", "false": "none"},
                 "writers": ["AAAAAAAAAAAAAAAAAAAAAAAA"]},
                {"topic": "/robot_mode", "type": "std_msgs::msg::dds_::UInt8_",
                 "values": {"0": "idle", "1": "moving_slow", "7": "safe_state_active"},
                 "stale_after_ms": 500},
                {"topic": "/mode_name", "type": "std_msgs/msg/String",
                 "values": {"AUTO": "moving_slow", "PROTECTIVE_STOP": "safe_state_active"}},
                {"topic": "/odom", "type": "nav_msgs/msg/Odometry",
                 "motion": {"moving_above": 0.05, "fast_above": 1.0}}
            ],
            "socket": {"path": "/run/robodr/safety.sock"}
        }))
        .unwrap();
        assert_eq!(spec.topics.len(), 4);
        assert_eq!(
            spec.topics[0].writers.iter().next().unwrap(),
            "aaaaaaaaaaaaaaaaaaaaaaaa"
        );
        assert_eq!(spec.topics[1].stale_after_ms, 500);
        assert_eq!(spec.topics[0].stale_after_ms, DEFAULT_STALE_AFTER_MS);
        match &spec.topics[1].decoder {
            Decoder::UInt8(m) => assert_eq!(m[&7], Claim::State(SafetyState::SafeStateActive)),
            d => panic!("{d:?}"),
        }
        assert_eq!(spec.socket.as_ref().unwrap().max_connections, 2);
        // Three topics are not profiled writer topics.
        assert_eq!(w.len(), 3, "{w:?}");

        let bad = [
            serde_json::json!({}),
            serde_json::json!({"topics": [{"topic": "estop", "type": "std_msgs/msg/Bool",
                "values": {"true": "estop_active", "false": "none"}}]}),
            serde_json::json!({"topics": [{"topic": "/estop", "type": "std_msgs/msg/Bool",
                "values": {"true": "estop_active"}}]}),
            serde_json::json!({"topics": [{"topic": "/estop", "type": "std_msgs/msg/Bool",
                "values": {"true": "estop_active", "false": "none", "maybe": "idle"}}]}),
            serde_json::json!({"topics": [{"topic": "/estop", "type": "std_msgs/msg/Bool",
                "values": {"true": "stopped", "false": "none"}}]}),
            serde_json::json!({"topics": [{"topic": "/m", "type": "std_msgs/msg/UInt8",
                "values": {"256": "idle"}}]}),
            serde_json::json!({"topics": [{"topic": "/m", "type": "std_msgs/msg/UInt8",
                "values": {}}]}),
            serde_json::json!({"topics": [{"topic": "/m", "type": "std_msgs/msg/Int32",
                "values": {"1": "idle"}}]}),
            serde_json::json!({"topics": [{"topic": "/odom", "type": "nav_msgs/msg/Odometry"}]}),
            serde_json::json!({"topics": [{"topic": "/odom", "type": "nav_msgs/msg/Odometry",
                "motion": {"moving_above": 0.0}}]}),
            serde_json::json!({"topics": [{"topic": "/odom", "type": "nav_msgs/msg/Odometry",
                "motion": {"moving_above": 0.5, "fast_above": 0.4}}]}),
            serde_json::json!({"topics": [{"topic": "/odom", "type": "nav_msgs/msg/Odometry",
                "motion": {"moving_above": 0.05, "hysteresis": 0.05}}]}),
            serde_json::json!({"topics": [{"topic": "/s", "type": "std_msgs/msg/String",
                "values": {"a\u{1b}": "idle"}}]}),
            serde_json::json!({"topics": [{"topic": "/estop", "type": "std_msgs/msg/Bool",
                "values": {"true": "estop_active", "false": "none"}, "writers": ["xyz"]}]}),
            serde_json::json!({"topics": [{"topic": "/estop", "type": "std_msgs/msg/Bool",
                "values": {"true": "estop_active", "false": "none"}, "stale_after_ms": 0}]}),
            serde_json::json!({"topics": [{"topic": "/estop", "type": "std_msgs/msg/Bool",
                "values": {"true": "estop_active", "false": "none"}, "typo": 1}]}),
            serde_json::json!({"topics": [{"topic": "/estop", "type": "std_msgs/msg/Bool",
                "values": {"true": "estop_active", "false": "none"},
                "motion": {"moving_above": 1.0}}]}),
            serde_json::json!({"topics": [
                {"topic": "/estop", "type": "std_msgs/msg/Bool",
                 "values": {"true": "estop_active", "false": "none"}},
                {"topic": "/estop", "type": "std_msgs/msg/Bool",
                 "values": {"true": "estop_active", "false": "none"}}]}),
            serde_json::json!({"socket": {"path": "relative.sock"}}),
            serde_json::json!({"socket": {"path": "/a.sock", "max_connections": 0}}),
            serde_json::json!({"socket": {"path": "/a.sock"}, "stale_after_ms": 999999999}),
        ];
        for b in bad {
            assert!(section(b.clone()).is_err(), "{b}");
        }
    }

    #[test]
    fn socket_report_is_strict() {
        let r: SafetyReport = serde_json::from_str(r#"{"state":"estop_active"}"#).unwrap();
        assert_eq!(r.state, SafetyState::EStopActive);
        for bad in [
            r#"{"state":"none"}"#,
            r#"{"state":"estop"}"#,
            r#"{"state":"idle","extra":1}"#,
            r#"{}"#,
            r#"[]"#,
        ] {
            assert!(serde_json::from_str::<SafetyReport>(bad).is_err(), "{bad}");
        }
    }
}
