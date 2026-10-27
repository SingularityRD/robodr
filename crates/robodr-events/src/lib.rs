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
//!   This covers every axis of a command (forward, lateral, vertical, yaw,
//!   roll, pitch, joint).
//! * Commanded speeds are signed. A negative value is compared by its
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

// S10: this crate has no `unsafe` code and must stay that way.
#![forbid(unsafe_code)]
// Review L3 (S10, R9): agentd links this library and release builds use
// `panic = "abort"`, so a panic here kills the daemon. Non-test code has no
// unwrap / expect / panic!-family call; slice indexing and arithmetic are
// left to review and fuzzing.
#![cfg_attr(
    not(test),
    deny(
        clippy::unwrap_used,
        clippy::expect_used,
        clippy::panic,
        clippy::unreachable,
        clippy::todo,
        clippy::unimplemented
    )
)]

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
///
/// Linear and angular values are **signed body-frame velocities** taken from
/// the command message as is (`geometry_msgs/Twist`, ROS REP 103: +x forward,
/// +y left, +z up, +yaw counter-clockwise). `linear_speed` is always
/// `linear.x` and `angular_speed` is always `angular.z`; the other four Twist
/// axes are carried in `linear_y`, `linear_z`, `angular_x` and `angular_y`
/// (holonomic / mecanum / omni bases move along `y`; a hostile writer can
/// put anything in any axis). Producers must keep the sign: the motion
/// monitor uses it to see a robot driving or turning against its command,
/// and a magnitude sent for a reversing command would look like a direction
/// reversal. Envelope checks compare `|v|` per axis plus the resultant
/// `‖(x, y, z)‖` against `max_linear_speed` (see [`profile`]).
///
/// The four extra axes are `#[serde(default)]`: an event serialised before
/// they existed deserialises with `None` (= "the command says nothing about
/// that axis"), and a producer with only a forward speed leaves them `None`.
/// Construct with `..Default::default()` so further axes do not break call
/// sites.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct MotionCommand {
    /// Topic (ROS 2, de-mangled, e.g. `/cmd_vel`) the command arrived on.
    /// Must match a key of `Profile::motion_envelopes` exactly. Profile keys
    /// must be well-formed ROS names that are also writer topics (see
    /// [`profile::Profile::validate`]), so a non-ROS bus id cannot currently
    /// be given an envelope; a command on one is `robot.motion.unprofiled_channel`.
    pub channel: String,
    /// The announcing endpoint's GUID, if known (ties back to the graph).
    pub source_guid: Option<String>,
    /// Commanded forward velocity in m/s, signed (`Twist.linear.x`).
    /// Envelopes compare the absolute value; non-finite values are a
    /// Critical deviation.
    pub linear_speed: Option<f64>,
    /// Commanded joint speed in rad/s (max magnitude across joints). Same
    /// sign / finiteness rules as `linear_speed`.
    pub joint_speed: Option<f64>,
    /// Commanded yaw rate in rad/s, signed (`Twist.angular.z`); `None` when
    /// the command says nothing about rotation. The profile envelope has no
    /// yaw limit (the Motion Firewall's per-channel `max_angular_speed`
    /// bounds it); a non-finite value is a Critical deviation.
    #[serde(default)]
    pub angular_speed: Option<f64>,
    /// Commanded lateral velocity in m/s, signed (`Twist.linear.y`, +left).
    /// Bounded by the envelope's `max_lateral_speed` and, together with
    /// `linear_speed` / `linear_z`, by `max_linear_speed` (resultant).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub linear_y: Option<f64>,
    /// Commanded vertical velocity in m/s, signed (`Twist.linear.z`, +up).
    /// Bounded by `max_vertical_speed` and by the resultant check.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub linear_z: Option<f64>,
    /// Commanded roll rate in rad/s, signed (`Twist.angular.x`). Bounded,
    /// with `angular_y`, by `max_roll_pitch_rate`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub angular_x: Option<f64>,
    /// Commanded pitch rate in rad/s, signed (`Twist.angular.y`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub angular_y: Option<f64>,
    /// Low-level joint commands only: the largest feed-forward torque
    /// `|tau|` (N·m) over the command's joint slots. A Unitree motor applies
    /// `T = kp·(q − q_measured) + kd·(dq − dq_measured) + tau`, so a
    /// torque-only command (`kp = kd = 0`) moves a joint without any
    /// commanded speed. Bounded by the envelope's `max_joint_torque`.
    /// `None` for commands that carry no joint torque (Twist, API calls).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub joint_torque: Option<f64>,
    /// Low-level joint commands only: the largest position gain `|kp|`
    /// over the command's joint slots (stiffness of the position loop).
    /// Bounded by the envelope's `max_joint_kp`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub joint_kp: Option<f64>,
    /// Low-level joint commands only: the largest position-target step
    /// `|q − q_previous|` (rad) over the joints whose position target acts
    /// (`kp != 0`) in this and the previous command on the channel. Needs
    /// state, so only a stateful producer (the ROS 2 pipeline) fills it;
    /// `None` on the first command of a channel. Bounded by the envelope's
    /// `max_joint_position_step`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub joint_position_step: Option<f64>,
    /// For commands decoded from a robot API call (e.g. a Unitree sport /
    /// loco request): what kind of effect the call has. `None` for plain
    /// velocity / joint messages. [`profile::Profile::evaluate`] reports the
    /// classes whose motion the envelope cannot bound (see
    /// [`CommandClass`]).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub command_class: Option<CommandClass>,
    /// The API call's name (`"FrontFlip"`, `"api_id 4242"`, ...), for the
    /// finding's detail. Informational only: never matched by a rule.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub command_name: Option<String>,
}

/// What kind of effect a robot API call has on motion (carried in
/// [`MotionCommand::command_class`]). Mirrors `robodr_cdr::unitree::ApiClass`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CommandClass {
    /// Commands a body velocity (the command's speed fields carry it).
    Velocity,
    /// Stops motion.
    Stop,
    /// Changes posture through the robot's own controller.
    Posture,
    /// Changes gait / speed level / control parameters.
    Config,
    /// A pre-programmed whole-body motion (flip, jump, dance, arm action):
    /// nothing in the request bounds it. `robot.motion.unverifiable_command`
    /// (High).
    Trick,
    /// Goes to a target position / follows a path: no speed in the
    /// request. `robot.motion.unverifiable_command` (Medium).
    Trajectory,
    /// Hands motor control to / takes it from another channel (motion
    /// switcher release, user control, arm SDK). `robot.motion.control_handover`
    /// (High).
    ControlHandover,
    /// Reads state; no motion.
    Query,
    /// Not a known call of a motion service. `robot.motion.unverifiable_command`
    /// (High).
    Unknown,
    /// A known motion call whose arguments cannot be read.
    /// `robot.motion.unverifiable_command` (High).
    Malformed,
}

impl MotionCommand {
    /// Every signed component with its name, for checks that must look at
    /// all of them (non-finite detection): the seven motion axes, then the
    /// three joint-command magnitudes (`joint_torque`, `joint_kp`,
    /// `joint_position_step`).
    pub fn components(&self) -> [(&'static str, Option<f64>); 10] {
        [
            ("linear", self.linear_speed),
            ("joint", self.joint_speed),
            ("angular", self.angular_speed),
            ("linear_y", self.linear_y),
            ("linear_z", self.linear_z),
            ("angular_x", self.angular_x),
            ("angular_y", self.angular_y),
            ("joint_torque", self.joint_torque),
            ("joint_kp", self.joint_kp),
            ("joint_position_step", self.joint_position_step),
        ]
    }

    /// `true` if the command carries any axis beyond forward speed / yaw
    /// rate / joint speed (a holonomic or 6-DoF command).
    pub fn has_extra_axes(&self) -> bool {
        self.linear_y.is_some()
            || self.linear_z.is_some()
            || self.angular_x.is_some()
            || self.angular_y.is_some()
    }

    /// Resultant linear speed `‖(x, y, z)‖` in m/s over the axes present
    /// (`None` axes count as 0), or `None` if no linear axis is present.
    /// Non-finite if any present axis is; a finite vector whose norm
    /// overflows is `+inf`.
    pub fn linear_resultant(&self) -> Option<f64> {
        if self.linear_speed.is_none() && self.linear_y.is_none() && self.linear_z.is_none() {
            return None;
        }
        let x = self.linear_speed.unwrap_or(0.0);
        let y = self.linear_y.unwrap_or(0.0);
        let z = self.linear_z.unwrap_or(0.0);
        if x.is_nan() || y.is_nan() || z.is_nan() {
            return Some(f64::NAN);
        }
        Some(x.hypot(y).hypot(z))
    }

    /// Roll/pitch rate magnitude `‖(angular_x, angular_y)‖` in rad/s, or
    /// `None` if neither is present. Same non-finite rules as
    /// [`MotionCommand::linear_resultant`].
    pub fn roll_pitch_rate(&self) -> Option<f64> {
        if self.angular_x.is_none() && self.angular_y.is_none() {
            return None;
        }
        let x = self.angular_x.unwrap_or(0.0);
        let y = self.angular_y.unwrap_or(0.0);
        if x.is_nan() || y.is_nan() {
            return Some(f64::NAN);
        }
        Some(x.hypot(y))
    }
}

/// Measured motion reported by the platform (e.g. from `/odom` or
/// `/joint_states`), used by `robodr-motion` to check that the robot actually
/// does what it was commanded to do.
///
/// `measured_linear_speed` is a **magnitude** (kept for producers that only
/// have a speed, e.g. GNSS speed over ground). Producers that have the
/// velocity vector (`nav_msgs/Odometry` `twist.twist`, IMU angular rates)
/// should also fill the signed per-axis fields: `linear_velocity` (x) /
/// `angular_velocity` (yaw) as before, plus `linear_velocity_y` /
/// `linear_velocity_z` / `angular_velocity_x` / `angular_velocity_y` so a
/// holonomic base moving sideways can be compared axis by axis with its
/// command. The motion monitor compares signed values by default and only
/// uses the magnitude for sources configured as unsigned. All per-axis
/// fields are `#[serde(default)]` (old events deserialise with `None`).
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct MotionFeedback {
    /// Topic or bus id the feedback arrived on.
    pub channel: String,
    /// Measured linear speed in m/s (magnitude), if applicable.
    #[serde(default)]
    pub measured_linear_speed: Option<f64>,
    /// Measured joint speed in rad/s (max magnitude across joints), if applicable.
    #[serde(default)]
    pub measured_joint_speed: Option<f64>,
    /// Measured forward velocity in m/s, signed (body frame, REP 103).
    #[serde(default)]
    pub linear_velocity: Option<f64>,
    /// Measured yaw rate in rad/s, signed (REP 103).
    #[serde(default)]
    pub angular_velocity: Option<f64>,
    /// Measured lateral velocity in m/s, signed (body frame, +left).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub linear_velocity_y: Option<f64>,
    /// Measured vertical velocity in m/s, signed (body frame, +up).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub linear_velocity_z: Option<f64>,
    /// Measured roll rate in rad/s, signed.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub angular_velocity_x: Option<f64>,
    /// Measured pitch rate in rad/s, signed.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub angular_velocity_y: Option<f64>,
    /// GUID of the DDS writer that published this sample, if known. Lets the
    /// motion monitor keep per-publisher state and see a second (injected)
    /// publisher interleaving on the same feedback topic.
    #[serde(default)]
    pub publisher_guid: Option<String>,
    /// Measurement time, nanoseconds (monotonic or epoch — the producer must
    /// document which; `robodr-motion` only uses differences).
    pub timestamp_ns: u64,
}

/// Severity of a deviation, mapped 1:1 onto Pulsar severities and the
/// findings contract's `severity` (OCSF `severity_id` 2..=5).
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
                angular_speed: None,
                ..Default::default()
            }),
            RobotEvent::MotionFeedback(MotionFeedback {
                channel: "/odom".into(),
                measured_linear_speed: Some(0.2),
                measured_joint_speed: None,
                linear_velocity: None,
                angular_velocity: None,
                publisher_guid: None,
                timestamp_ns: 1_700_000_000_000_000_000,
                ..Default::default()
            }),
        ];
        for e in events {
            let json = serde_json::to_string(&e).unwrap();
            let back: RobotEvent = serde_json::from_str(&json).unwrap();
            assert_eq!(back, e, "{json}");
        }
    }

    #[test]
    fn motion_events_back_compat_and_holonomic_round_trip() {
        // Events serialised before the per-axis fields existed.
        let old: RobotEvent = serde_json::from_str(
            r#"{"kind":"motion_command","channel":"/cmd_vel","source_guid":null,"linear_speed":0.3,"joint_speed":null,"angular_speed":-0.1}"#,
        )
        .unwrap();
        let RobotEvent::MotionCommand(c) = &old else {
            panic!()
        };
        assert!(!c.has_extra_axes());
        assert_eq!(c.linear_speed, Some(0.3));
        // ... re-serialise byte-identically (absent axes are not written).
        assert_eq!(
            serde_json::to_string(&old).unwrap(),
            r#"{"kind":"motion_command","channel":"/cmd_vel","source_guid":null,"linear_speed":0.3,"joint_speed":null,"angular_speed":-0.1}"#
        );
        let old_fb: RobotEvent = serde_json::from_str(
            r#"{"kind":"motion_feedback","channel":"/odom","measured_linear_speed":0.2,"linear_velocity":-0.2,"timestamp_ns":1}"#,
        )
        .unwrap();
        let RobotEvent::MotionFeedback(f) = &old_fb else {
            panic!()
        };
        assert_eq!(
            (
                f.linear_velocity_y,
                f.linear_velocity_z,
                f.angular_velocity_x,
                f.angular_velocity_y
            ),
            (None, None, None, None)
        );
        // Holonomic command / feedback round-trip with every axis.
        let events = [
            RobotEvent::MotionCommand(MotionCommand {
                channel: "/cmd_vel".into(),
                linear_speed: Some(0.1),
                linear_y: Some(-0.4),
                linear_z: Some(0.0),
                angular_x: Some(0.01),
                angular_y: Some(-0.02),
                angular_speed: Some(0.3),
                ..Default::default()
            }),
            RobotEvent::MotionFeedback(MotionFeedback {
                channel: "/odom".into(),
                linear_velocity: Some(0.1),
                linear_velocity_y: Some(-0.39),
                linear_velocity_z: Some(0.0),
                angular_velocity_x: Some(0.0),
                angular_velocity_y: Some(0.0),
                angular_velocity: Some(0.29),
                timestamp_ns: 9,
                ..Default::default()
            }),
        ];
        for e in events {
            let json = serde_json::to_string(&e).unwrap();
            assert_eq!(
                serde_json::from_str::<RobotEvent>(&json).unwrap(),
                e,
                "{json}"
            );
        }
        // Hostile per-axis values fail to parse cleanly.
        for bad in [
            r#"{"kind":"motion_command","channel":"/c","source_guid":null,"linear_speed":null,"joint_speed":null,"linear_y":1e999}"#,
            r#"{"kind":"motion_command","channel":"/c","source_guid":null,"linear_speed":null,"joint_speed":null,"angular_x":"x"}"#,
            r#"{"kind":"motion_feedback","channel":"/o","timestamp_ns":1,"linear_velocity_y":[1]}"#,
        ] {
            assert!(serde_json::from_str::<RobotEvent>(bad).is_err(), "{bad}");
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
                linear_velocity: None,
                angular_velocity: None,
                publisher_guid: None,
                timestamp_ns: 5,
                ..Default::default()
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
