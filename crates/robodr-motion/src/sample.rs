//! Input types: what the sensor hands the monitor.
//!
//! These are deliberately *our own* types rather than variants of
//! [`robodr_events::RobotEvent`]: the monitor needs a timestamp, per-axis
//! values and a feedback provenance that the event taxonomy does not (yet)
//! carry, and keeping them here lets the detector evolve without touching the
//! shared event crate. A [`CommandSample`] can be built from a
//! [`robodr_events::MotionCommand`] plus a timestamp.
//!
//! Units: linear m/s, angular rad/s, joint rad/s. Times are `u64` nanoseconds,
//! which makes negative time unrepresentable; use [`stamp_from_ros`] /
//! [`stamp_from_secs_f64`] to convert untrusted wire stamps (they return
//! `None` for negative, non-finite or out-of-range input instead of
//! wrapping).

use robodr_events::MotionCommand;
use serde::{Deserialize, Serialize};

/// Where a feedback sample comes from. The provenance matters: see the
/// crate docs, "Sensor-authored vs process-authored".
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FeedbackSource {
    /// Wheel odometry (e.g. `/odom` from `diff_drive_controller`). Computed by
    /// a controller *process* from encoder ticks: process-authored.
    WheelOdometry,
    /// IMU (gyro yaw rate as `angular`; `linear` only if the caller supplies a
    /// fused/integrated estimate). A separate hardware device: sensor-authored.
    Imu,
    /// Joint state (max |joint velocity|). Published by the controller
    /// process: process-authored.
    JointState,
    /// GNSS speed over ground. Separate hardware, but its input is an RF
    /// signal an outside adversary can spoof.
    Gnss,
    /// Anything else (visual odometry, lidar odometry, ...). Least trusted by
    /// default.
    Other,
}

impl FeedbackSource {
    /// All sources, in index order.
    pub const ALL: [FeedbackSource; 5] = [
        FeedbackSource::WheelOdometry,
        FeedbackSource::Imu,
        FeedbackSource::JointState,
        FeedbackSource::Gnss,
        FeedbackSource::Other,
    ];

    /// Dense index in `0..5`, used for fixed-size state tables.
    pub const fn index(self) -> usize {
        match self {
            FeedbackSource::WheelOdometry => 0,
            FeedbackSource::Imu => 1,
            FeedbackSource::JointState => 2,
            FeedbackSource::Gnss => 3,
            FeedbackSource::Other => 4,
        }
    }

    /// Stable snake_case name (matches the serde representation).
    pub const fn as_str(self) -> &'static str {
        match self {
            FeedbackSource::WheelOdometry => "wheel_odometry",
            FeedbackSource::Imu => "imu",
            FeedbackSource::JointState => "joint_state",
            FeedbackSource::Gnss => "gnss",
            FeedbackSource::Other => "other",
        }
    }
}

/// A motion axis the monitor tracks.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Axis {
    /// Body-frame forward speed, m/s.
    Linear,
    /// Yaw rate, rad/s.
    Angular,
    /// Max |joint velocity| across joints, rad/s.
    Joint,
}

impl Axis {
    /// All axes, in index order.
    pub const ALL: [Axis; 3] = [Axis::Linear, Axis::Angular, Axis::Joint];

    /// Dense index in `0..3`.
    pub const fn index(self) -> usize {
        match self {
            Axis::Linear => 0,
            Axis::Angular => 1,
            Axis::Joint => 2,
        }
    }

    /// Stable snake_case name.
    pub const fn as_str(self) -> &'static str {
        match self {
            Axis::Linear => "linear",
            Axis::Angular => "angular",
            Axis::Joint => "joint",
        }
    }

    /// Unit string for human-readable detail.
    pub const fn unit(self) -> &'static str {
        match self {
            Axis::Linear => "m/s",
            Axis::Angular | Axis::Joint => "rad/s",
        }
    }
}

/// One observed motion command.
///
/// Per-axis semantics:
/// * `Some(v)` - this command sets the axis to `v` (`Some(0.0)` is an
///   explicit stop).
/// * `None` - this command says nothing about the axis; while it is in effect
///   the monitor has **no expectation** for that axis and skips
///   command-based checks on it (cross-sensor checks still run).
///
/// "No command at all" (none observed yet, or the last one is older than the
/// configured command timeout) is different: it means *rest* on every axis.
#[derive(Debug, Clone, Copy, PartialEq, Serialize, Deserialize)]
pub struct CommandSample<'a> {
    /// Observer (monotonic) time the command was seen, ns.
    pub t_ns: u64,
    /// Topic / bus id. Compared against the configured command channels.
    pub channel: &'a str,
    /// Commanded forward speed, m/s.
    pub linear: Option<f64>,
    /// Commanded yaw rate, rad/s.
    pub angular: Option<f64>,
    /// Commanded max |joint speed|, rad/s.
    pub joint_speed_max: Option<f64>,
}

impl<'a> CommandSample<'a> {
    /// The command's value on one axis.
    pub fn axis(&self, axis: Axis) -> Option<f64> {
        match axis {
            Axis::Linear => self.linear,
            Axis::Angular => self.angular,
            Axis::Joint => self.joint_speed_max,
        }
    }

    /// Build from the shared event type. `MotionCommand` carries magnitudes
    /// only (no sign, no yaw rate), so `angular` is `None` and the result is
    /// only meaningful with `compare_magnitudes = true` (the default).
    pub fn from_motion_command(cmd: &'a MotionCommand, t_ns: u64) -> Self {
        CommandSample {
            t_ns,
            channel: &cmd.channel,
            linear: cmd.linear_speed,
            angular: None,
            joint_speed_max: cmd.joint_speed,
        }
    }
}

impl<'a> From<(&'a MotionCommand, u64)> for CommandSample<'a> {
    fn from((cmd, t_ns): (&'a MotionCommand, u64)) -> Self {
        CommandSample::from_motion_command(cmd, t_ns)
    }
}

/// One feedback (telemetry) sample.
#[derive(Debug, Clone, Copy, PartialEq, Serialize, Deserialize)]
pub struct FeedbackSample {
    /// The sample's own stamp (e.g. ROS `header.stamp`), ns, in the **same
    /// time base** as the observer clock passed to
    /// [`crate::ConsistencyMonitor::on_feedback`]. Source-authored and
    /// therefore untrusted: used only for integrity checks (backwards,
    /// duplicate, future, late), never for the motion model.
    pub t_ns: u64,
    /// Provenance.
    pub source: FeedbackSource,
    /// Measured forward speed, m/s.
    pub linear: Option<f64>,
    /// Measured yaw rate, rad/s.
    pub angular: Option<f64>,
    /// Measured max |joint speed|, rad/s.
    pub joint_speed_max: Option<f64>,
}

impl FeedbackSample {
    /// The sample's value on one axis.
    pub fn axis(&self, axis: Axis) -> Option<f64> {
        match axis {
            Axis::Linear => self.linear,
            Axis::Angular => self.angular,
            Axis::Joint => self.joint_speed_max,
        }
    }
}

/// Convert a ROS 2 `builtin_interfaces/Time` (`int32 sec`, `uint32 nanosec`)
/// to ns. `None` for negative seconds or `nanosec >= 1e9` (malformed).
pub fn stamp_from_ros(sec: i32, nanosec: u32) -> Option<u64> {
    if sec < 0 || nanosec >= 1_000_000_000 {
        return None;
    }
    // i32::MAX * 1e9 + 1e9 fits comfortably in u64.
    Some(sec as u64 * 1_000_000_000 + nanosec as u64)
}

/// Convert seconds as `f64` to ns. `None` for NaN, infinities, negative
/// values and values beyond `u64::MAX` ns.
pub fn stamp_from_secs_f64(secs: f64) -> Option<u64> {
    if !secs.is_finite() || secs < 0.0 {
        return None;
    }
    let ns = secs * 1e9;
    // u64::MAX as f64 rounds up to 2^64, so `>=` rejects everything that
    // would not fit.
    if ns >= u64::MAX as f64 {
        return None;
    }
    Some(ns as u64)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn indices_are_dense_and_consistent() {
        for (i, s) in FeedbackSource::ALL.iter().enumerate() {
            assert_eq!(s.index(), i);
        }
        for (i, a) in Axis::ALL.iter().enumerate() {
            assert_eq!(a.index(), i);
        }
    }

    #[test]
    fn serde_names_match_as_str() {
        for s in FeedbackSource::ALL {
            let j = serde_json::to_string(&s).unwrap();
            assert_eq!(j, format!("\"{}\"", s.as_str()));
        }
        for a in Axis::ALL {
            let j = serde_json::to_string(&a).unwrap();
            assert_eq!(j, format!("\"{}\"", a.as_str()));
        }
    }

    #[test]
    fn from_motion_command() {
        let mc = MotionCommand {
            channel: "/cmd_vel".into(),
            source_guid: Some("01.0f".into()),
            linear_speed: Some(0.8),
            joint_speed: None,
        };
        let c: CommandSample = (&mc, 42).into();
        assert_eq!(c.t_ns, 42);
        assert_eq!(c.channel, "/cmd_vel");
        assert_eq!(c.axis(Axis::Linear), Some(0.8));
        assert_eq!(c.axis(Axis::Angular), None);
        assert_eq!(c.axis(Axis::Joint), None);
    }

    #[test]
    fn command_sample_json_roundtrip_borrows() {
        let c = CommandSample {
            t_ns: 1,
            channel: "/cmd_vel",
            linear: Some(1.0),
            angular: Some(-0.5),
            joint_speed_max: None,
        };
        let j = serde_json::to_string(&c).unwrap();
        let back: CommandSample = serde_json::from_str(&j).unwrap();
        assert_eq!(back, c);
    }

    #[test]
    fn ros_stamp_conversion() {
        assert_eq!(stamp_from_ros(0, 0), Some(0));
        assert_eq!(stamp_from_ros(1, 5), Some(1_000_000_005));
        assert_eq!(stamp_from_ros(-1, 0), None);
        assert_eq!(stamp_from_ros(0, 1_000_000_000), None);
        assert_eq!(
            stamp_from_ros(i32::MAX, 999_999_999),
            Some(i32::MAX as u64 * 1_000_000_000 + 999_999_999)
        );
    }

    #[test]
    fn f64_stamp_conversion_rejects_hostile_values() {
        assert_eq!(stamp_from_secs_f64(1.5), Some(1_500_000_000));
        assert_eq!(stamp_from_secs_f64(0.0), Some(0));
        assert_eq!(stamp_from_secs_f64(-0.0), Some(0));
        assert_eq!(stamp_from_secs_f64(-1e-9), None);
        assert_eq!(stamp_from_secs_f64(f64::NAN), None);
        assert_eq!(stamp_from_secs_f64(f64::INFINITY), None);
        assert_eq!(stamp_from_secs_f64(f64::NEG_INFINITY), None);
        assert_eq!(stamp_from_secs_f64(1e300), None);
        assert_eq!(stamp_from_secs_f64(18_446_744_073.709_553), None);
    }
}
