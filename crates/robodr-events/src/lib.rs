//! RoboDR robot event taxonomy and the *model-profile* detection logic.
//!
//! This crate is deliberately **pure**: no network, no kernel, no Pulsar
//! dependency. It defines what a robot-layer event *is* and decides, given a
//! locked model profile, whether an event is a deviation. The sensor crates
//! (`robodr-sensor-ros2`, …) do the I/O and feed typed events in here; the
//! Pulsar glue turns a [`Deviation`] into a Pulsar threat.
//!
//! Keeping the decision here means it is unit-testable on any machine, and the
//! same logic runs identically on a controller, in the Sentinel Box, and in CI.

pub mod graph;
pub mod profile;

use serde::{Deserialize, Serialize};

/// A robot-layer event, above the process/file/network events Pulsar already
/// emits. One `RobotEvent` is one observation from one sensor.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum RobotEvent {
    /// A DDS participant announced itself on the robot's RTPS discovery bus.
    Ros2ParticipantDiscovered(graph::Participant),
    /// A writer (publisher) for a topic was announced.
    Ros2WriterDiscovered(graph::Endpoint),
    /// A reader (subscriber) for a topic was announced.
    Ros2ReaderDiscovered(graph::Endpoint),
    /// A motion command observed on a control topic, with its source and the
    /// commanded magnitude the Motion Firewall will check against the envelope.
    MotionCommand(MotionCommand),
}

/// A single motion command, normalised across robot kinds.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct MotionCommand {
    /// Topic (ROS 2) or bus id the command arrived on.
    pub channel: String,
    /// The announcing endpoint's GUID, if known (ties back to the graph).
    pub source_guid: Option<String>,
    /// Commanded linear speed in m/s (absolute value), if applicable.
    pub linear_speed: Option<f64>,
    /// Commanded joint speed in rad/s (absolute max across joints), if applicable.
    pub joint_speed: Option<f64>,
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

/// A detected deviation from the locked model profile. This is what the Pulsar
/// glue turns into a threat event and what the Cyber-Jidoka responder grades.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Deviation {
    /// Stable rule id, e.g. `robot.ros2.unknown_participant`.
    pub rule: &'static str,
    pub severity: Severity,
    /// One-line, human-readable description.
    pub detail: String,
}

impl Deviation {
    pub fn new(rule: &'static str, severity: Severity, detail: impl Into<String>) -> Self {
        Self {
            rule,
            severity,
            detail: detail.into(),
        }
    }
}
