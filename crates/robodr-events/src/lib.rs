//! RoboDR robot event taxonomy and the *model-profile* detection logic.
//!
//! This crate is deliberately **pure**: no network, no kernel, no Pulsar
//! dependency. It defines what a robot-layer event *is* and decides, given a
//! model profile, whether an event is a deviation. The sensor crates
//! (`robodr-sensor-ros2`, …) do the I/O and feed typed events in here; the
//! Pulsar glue turns a [`Deviation`] into a Pulsar threat.
//!
//! Keeping the decision here means it is unit-testable on any machine, and the
//! same logic runs identically on a controller, in the Sentinel Box, and in CI.
//!
//! # Map of the crate
//!
//! * [`RobotEvent`] — one observation from one sensor (discovery, motion
//!   command, motion feedback).
//! * [`graph`] — the DDS/ROS 2 graph model and ROS 2 name de-mangling
//!   ([`graph::demangle`], [`graph::RosName`]).
//! * [`profile`] — the model profile, [`profile::Profile::evaluate`] (the
//!   detection core) and [`profile::Profile::validate`] (load-time checks).
//! * [`Deviation`] — the output: rule id, [`Severity`], detail and [`Mode`].
//!
//! # Fail-closed conventions
//!
//! * Floats from the wire are hostile. A non-finite (NaN / ±inf) commanded
//!   speed is always a `Critical` deviation (`robot.motion.non_finite_command`),
//!   never "not greater than the limit".
//! * Commanded speeds are magnitudes. A negative value is compared by its
//!   **absolute value** (a decoder that forgot `abs()` must not create a bypass
//!   via `-5.0 > 0.5 == false`).
//! * A profile whose envelope limit is negative / NaN / ±inf cannot be
//!   enforced: every command on that channel is reported as
//!   `robot.profile.invalid_envelope`, and [`profile::Profile::validate`]
//!   rejects the profile at load time.
//! * Raw DDS topics (no ROS 2 `rt/`/`rq/`/`rr/` prefix) are never matched
//!   against ROS topic allowlists.
//!
//! # Observe vs enforce
//!
//! While `profile.locked == false` the profile is still being learned
//! (commissioning). [`profile::Profile::evaluate`] then stamps every deviation
//! with [`Mode::Observe`]; consumers must treat such deviations as
//! informational and never propose an action for them. A locked profile
//! produces [`Mode::Enforce`].
//!
//! # API stability notes for downstream crates
//!
//! * Construct [`Deviation`] only through [`Deviation::new`] (plus
//!   [`Deviation::with_mode`]); fields may be added.
//! * [`Deviation::rule`] is a `Cow<'static, str>` so that deviations can be
//!   deserialized from JSON at runtime. Compare it with `==` against a string
//!   literal or use [`Deviation::rule_str`]; `match dev.rule { "x" => .. }` does
//!   not compile — use `match dev.rule_str()`.
//! * [`RobotEvent`] is intentionally **not** `#[non_exhaustive]` (the sensor and
//!   motion crates want compile errors when a variant is added so they handle
//!   it). New variants are therefore a breaking change for exhaustive matches;
//!   [`RobotEvent::MotionFeedback`] was added before any downstream crate
//!   matched exhaustively.

pub mod graph;
pub mod profile;

use serde::{Deserialize, Serialize};
use std::borrow::Cow;

/// A robot-layer event, above the process/file/network events Pulsar already
/// emits. One `RobotEvent` is one observation from one sensor.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum RobotEvent {
    /// A DDS participant announced itself on the robot's RTPS discovery bus.
    Ros2ParticipantDiscovered(graph::Participant),
    /// A writer (publisher, service client request writer, service server
    /// reply writer, …) was announced. See [`graph::RosName`].
    Ros2WriterDiscovered(graph::Endpoint),
    /// A reader (subscriber, …) was announced.
    Ros2ReaderDiscovered(graph::Endpoint),
    /// A motion command observed on a control topic, with its source and the
    /// commanded magnitude the Motion Firewall will check against the envelope.
    MotionCommand(MotionCommand),
    /// Measured motion (odometry / joint states) reported by the platform.
    /// [`profile::Profile::evaluate`] returns `None` for it: command-vs-feedback
    /// consistency is stateful and is checked in `robodr-motion`.
    MotionFeedback(MotionFeedback),
}

/// A single motion command, normalised across robot kinds.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct MotionCommand {
    /// Topic (ROS 2, de-mangled, e.g. `/cmd_vel`) or bus id the command
    /// arrived on. Must match a key of `Profile::motion_envelopes` exactly.
    pub channel: String,
    /// The announcing endpoint's GUID, if known (ties back to the graph).
    pub source_guid: Option<String>,
    /// Commanded linear speed in m/s, as a magnitude. Negative values are
    /// compared by absolute value; non-finite values are a Critical deviation.
    pub linear_speed: Option<f64>,
    /// Commanded joint speed in rad/s (max magnitude across joints). Same
    /// sign / finiteness rules as `linear_speed`.
    pub joint_speed: Option<f64>,
}

/// Measured motion reported by the platform (e.g. from `/odom` or
/// `/joint_states`), used by `robodr-motion` to check that the robot actually
/// does what it was commanded to do.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct MotionFeedback {
    /// Topic or bus id the feedback arrived on.
    pub channel: String,
    /// Measured linear speed in m/s (magnitude), if applicable.
    #[serde(default)]
    pub measured_linear_speed: Option<f64>,
    /// Measured joint speed in rad/s (max magnitude across joints), if applicable.
    #[serde(default)]
    pub measured_joint_speed: Option<f64>,
    /// Measurement time, nanoseconds (monotonic or epoch — the producer must
    /// document which; `robodr-motion` only uses differences).
    pub timestamp_ns: u64,
}

/// Severity of a deviation, mapped 1:1 onto Pulsar/AutoSecOps severities.
/// Ordered by declaration: `Low < Medium < High < Critical`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Severity {
    Low,
    Medium,
    High,
    Critical,
}

/// Whether a deviation came from a locked (enforcing) profile or from a
/// profile still in observe mode (commissioning).
///
/// `Observe` deviations are informational only: the responder must never
/// propose a safe-state request for them. The default is `Enforce` so that a
/// deviation deserialized from an older producer (no `mode` field) is never
/// silently downgraded.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Mode {
    /// Profile not locked: report only, never act.
    Observe,
    /// Profile locked: the deviation may be acted upon by the responder.
    #[default]
    Enforce,
}

/// A detected deviation from the model profile. This is what the Pulsar glue
/// turns into a threat event and what the Cyber-Jidoka responder grades.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Deviation {
    /// Stable rule id, e.g. `robot.ros2.unknown_participant`. Borrowed for the
    /// built-in rules, owned when deserialized.
    pub rule: Cow<'static, str>,
    pub severity: Severity,
    /// One-line, human-readable description.
    pub detail: String,
    /// Observe-only vs enforce. Set by [`profile::Profile::evaluate`] from
    /// `profile.locked`; [`Deviation::new`] defaults to [`Mode::Enforce`].
    #[serde(default)]
    pub mode: Mode,
}

impl Deviation {
    /// A new deviation in [`Mode::Enforce`]. `rule` accepts a `&'static str`
    /// literal or an owned `String`.
    pub fn new(
        rule: impl Into<Cow<'static, str>>,
        severity: Severity,
        detail: impl Into<String>,
    ) -> Self {
        Self {
            rule: rule.into(),
            severity,
            detail: detail.into(),
            mode: Mode::Enforce,
        }
    }

    /// Builder: the same deviation with `mode` set.
    #[must_use]
    pub fn with_mode(mut self, mode: Mode) -> Self {
        self.mode = mode;
        self
    }

    /// The rule id as a plain `&str` (handy for `match`).
    pub fn rule_str(&self) -> &str {
        &self.rule
    }

    /// `true` if this deviation must only be reported, never acted upon.
    pub fn is_observe_only(&self) -> bool {
        self.mode == Mode::Observe
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn deviation_new_defaults_to_enforce_and_accepts_literal_and_string() {
        let a = Deviation::new("robot.x", Severity::Low, "d");
        assert_eq!(a.mode, Mode::Enforce);
        assert!(!a.is_observe_only());
        assert_eq!(a.rule, "robot.x");
        assert!(matches!(a.rule, Cow::Borrowed(_)));
        let b = Deviation::new(String::from("robot.y"), Severity::High, String::from("e"));
        assert_eq!(b.rule_str(), "robot.y");
        let c = b.with_mode(Mode::Observe);
        assert!(c.is_observe_only());
    }

    #[test]
    fn deviation_round_trips_through_owned_json() {
        let d = Deviation::new("robot.motion.non_finite_command", Severity::Critical, "nan")
            .with_mode(Mode::Observe);
        let json = serde_json::to_string(&d).unwrap();
        assert!(json.contains("\"mode\":\"observe\""));
        // Deserialize from a runtime (non-'static) String.
        let owned: String = json.clone();
        let back: Deviation = serde_json::from_str(&owned).unwrap();
        drop(owned);
        assert_eq!(back, d);
        assert_eq!(back.severity, Severity::Critical);
    }

    #[test]
    fn deviation_without_mode_deserializes_as_enforce() {
        let back: Deviation =
            serde_json::from_str(r#"{"rule":"r","severity":"high","detail":"x"}"#).unwrap();
        assert_eq!(back.mode, Mode::Enforce);
        assert!(serde_json::from_str::<Deviation>(
            r#"{"rule":"r","severity":"bogus","detail":"x"}"#
        )
        .is_err());
        assert!(serde_json::from_str::<Deviation>(
            r#"{"rule":"r","severity":"high","detail":"x","mode":"lol"}"#
        )
        .is_err());
    }

    #[test]
    fn robot_event_json_round_trips() {
        let events = vec![
            RobotEvent::Ros2ParticipantDiscovered(graph::Participant {
                guid_prefix: "aaaaaaaaaaaaaaaaaaaaaaaa".into(),
                src_ip: "10.0.0.1".into(),
                locators: vec!["10.0.0.1:7410".into()],
            }),
            RobotEvent::Ros2WriterDiscovered(graph::Endpoint {
                guid_prefix: "bb".into(),
                topic: "rt/cmd_vel".into(),
                type_name: "geometry_msgs::msg::dds_::Twist_".into(),
            }),
            RobotEvent::Ros2ReaderDiscovered(graph::Endpoint {
                guid_prefix: "cc".into(),
                topic: "rr/add_two_intsReply".into(),
                type_name: String::new(),
            }),
            RobotEvent::MotionCommand(MotionCommand {
                channel: "/cmd_vel".into(),
                source_guid: None,
                linear_speed: Some(-0.25),
                joint_speed: None,
            }),
            RobotEvent::MotionFeedback(MotionFeedback {
                channel: "/odom".into(),
                measured_linear_speed: Some(0.2),
                measured_joint_speed: None,
                timestamp_ns: 1_700_000_000_000_000_000,
            }),
        ];
        for e in events {
            let json = serde_json::to_string(&e).unwrap();
            let back: RobotEvent = serde_json::from_str(&json).unwrap();
            assert_eq!(back, e, "{json}");
        }
    }

    #[test]
    fn robot_event_json_shape_is_stable() {
        let e: RobotEvent = serde_json::from_str(
            r#"{"kind":"motion_feedback","channel":"/odom","timestamp_ns":5}"#,
        )
        .unwrap();
        assert_eq!(
            e,
            RobotEvent::MotionFeedback(MotionFeedback {
                channel: "/odom".into(),
                measured_linear_speed: None,
                measured_joint_speed: None,
                timestamp_ns: 5,
            })
        );
        let e: RobotEvent = serde_json::from_str(
            r#"{"kind":"ros2_writer_discovered","guid_prefix":"aa","topic":"rt/x"}"#,
        )
        .unwrap();
        assert!(matches!(e, RobotEvent::Ros2WriterDiscovered(ref p) if p.ros_topic() == "/x"));
        // Hostile / malformed input fails cleanly, never panics.
        for bad in [
            "",
            "{}",
            r#"{"kind":"nope"}"#,
            r#"{"kind":"motion_command"}"#,
            r#"{"kind":"motion_feedback","channel":"/odom","timestamp_ns":-1}"#,
            r#"{"kind":"motion_command","channel":"/c","source_guid":null,"linear_speed":1e999,"joint_speed":null}"#,
            "[1,2,3]",
        ] {
            assert!(serde_json::from_str::<RobotEvent>(bad).is_err(), "{bad}");
        }
    }
}
