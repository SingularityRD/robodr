//! Mapping decoded messages to `robodr-events` types.
//!
//! | message | event | fields |
//! |---|---|---|
//! | `Twist`, `TwistStamped` | [`MotionCommand`] | `linear_speed = linear.x`, `linear_y = linear.y`, `linear_z = linear.z`, `angular_x = angular.x`, `angular_y = angular.y`, `angular_speed = angular.z` (all signed) |
//! | `JointTrajectory` | [`MotionCommand`] | `joint_speed` = [`crate::JointTrajectory::max_joint_speed`]: max of \|velocity\| and \|Δposition\|/Δt over all points/joints; `Some(0.0)` for no points; `None` only when unverifiable (reported as [`crate::DecodeAnomaly::UnverifiableCommand`]) |
//! | `Odometry` | [`MotionFeedback`] | `linear_velocity{,_y,_z} = twist.twist.linear.{x,y,z}`, `angular_velocity_{x,y} = twist.twist.angular.{x,y}`, `angular_velocity = twist.twist.angular.z`, `measured_linear_speed = ‖twist.twist.linear‖` |
//! | `Imu` | [`MotionFeedback`] | `angular_velocity_x/_y = angular_velocity.x/.y`, `angular_velocity = angular_velocity.z` |
//! | `JointState` | [`MotionFeedback`] | `measured_joint_speed` = max \|velocity\| (`None` if `velocity` is empty) |
//!
//! # Twist: every axis, signed
//!
//! A Twist is mapped component by component. `linear_speed` / `angular_speed`
//! are exactly `linear.x` / `angular.z` (as for a differential / skid-steer
//! base), and the other four axes go to the per-axis fields, so a holonomic
//! (mecanum / omni) base moving sideways is compared axis by axis by the
//! motion monitor instead of as a magnitude against `linear.x`. Every
//! Twist-derived command carries all six axes (`Some`, possibly `0.0`).
//!
//! A hostile writer can put anything in any axis. That no longer needs a
//! folded magnitude: `Profile::evaluate` reports a non-finite value on
//! **any** axis as Critical, bounds the resultant `‖linear‖` by
//! `max_linear_speed` and checks the per-axis limits (`max_lateral_speed`,
//! `max_vertical_speed`, `max_roll_pitch_rate`; mandatory on holonomic
//! channels). Consumers that read only `linear_speed` / `angular_speed`
//! (rather than the whole command) see only the x / yaw components and
//! must look at the extra fields themselves.
//!
//! Values are copied faithfully: NaN / ±inf stay NaN / ±inf (the Motion
//! Firewall and `Profile::evaluate` treat a non-finite command as Critical;
//! the motion monitor decides for feedback). Aggregates (max, norm)
//! propagate non-finite input instead of skipping it.
//!
//! `TwistStamped`'s header stamp is **not** used as the event time: it is a
//! wire claim. The caller passes the observation time (`timestamp_ns`).

use robodr_events::{MotionCommand, MotionFeedback, RobotEvent};

use crate::msgs::Twist;
use crate::{MotionMessage, MotionRole};

/// Who/where/when a sample was observed. All of it comes from the transport
/// (RTPS writer GUID, topic from SEDP, capture clock), never from the payload.
#[derive(Debug, Clone, Copy)]
pub struct EventContext<'c> {
    /// De-mangled ROS topic, e.g. `/cmd_vel` (must match the profile's
    /// `motion_envelopes` keys for commands).
    pub channel: &'c str,
    /// The DATA writer's GUID, if known.
    pub writer_guid: Option<&'c str>,
    /// Observation time in ns (the caller documents mono vs epoch).
    pub timestamp_ns: u64,
}

fn twist_command(t: &Twist, ctx: &EventContext<'_>) -> MotionCommand {
    MotionCommand {
        channel: ctx.channel.to_owned(),
        source_guid: ctx.writer_guid.map(str::to_owned),
        linear_speed: Some(t.linear.x),
        joint_speed: None,
        angular_speed: Some(t.angular.z),
        linear_y: Some(t.linear.y),
        linear_z: Some(t.linear.z),
        angular_x: Some(t.angular.x),
        angular_y: Some(t.angular.y),
    }
}

fn feedback(ctx: &EventContext<'_>) -> MotionFeedback {
    MotionFeedback {
        channel: ctx.channel.to_owned(),
        measured_linear_speed: None,
        measured_joint_speed: None,
        publisher_guid: ctx.writer_guid.map(str::to_owned),
        timestamp_ns: ctx.timestamp_ns,
        ..MotionFeedback::default()
    }
}

impl MotionMessage<'_> {
    /// Whether the message type is a command or a measurement.
    pub fn role(&self) -> MotionRole {
        self.kind().role()
    }

    /// The command this message carries, if it is a command type.
    pub fn to_command(&self, ctx: &EventContext<'_>) -> Option<MotionCommand> {
        match self {
            MotionMessage::Twist(t) => Some(twist_command(t, ctx)),
            MotionMessage::TwistStamped(t) => Some(twist_command(&t.twist, ctx)),
            MotionMessage::JointTrajectory(j) => Some(MotionCommand {
                channel: ctx.channel.to_owned(),
                source_guid: ctx.writer_guid.map(str::to_owned),
                linear_speed: None,
                joint_speed: j.max_joint_speed(),
                ..MotionCommand::default()
            }),
            MotionMessage::Odometry(_) | MotionMessage::Imu(_) | MotionMessage::JointState(_) => {
                None
            }
        }
    }

    /// The feedback this message carries, if it is a measurement type.
    pub fn to_feedback(&self, ctx: &EventContext<'_>) -> Option<MotionFeedback> {
        match self {
            MotionMessage::Odometry(o) => {
                let v = &o.twist.twist;
                Some(MotionFeedback {
                    measured_linear_speed: Some(v.linear.norm()),
                    linear_velocity: Some(v.linear.x),
                    linear_velocity_y: Some(v.linear.y),
                    linear_velocity_z: Some(v.linear.z),
                    angular_velocity_x: Some(v.angular.x),
                    angular_velocity_y: Some(v.angular.y),
                    angular_velocity: Some(v.angular.z),
                    ..feedback(ctx)
                })
            }
            MotionMessage::Imu(i) => Some(MotionFeedback {
                angular_velocity_x: Some(i.angular_velocity.x),
                angular_velocity_y: Some(i.angular_velocity.y),
                angular_velocity: Some(i.angular_velocity.z),
                ..feedback(ctx)
            }),
            MotionMessage::JointState(j) => Some(MotionFeedback {
                measured_joint_speed: j.velocity.max_abs(),
                ..feedback(ctx)
            }),
            MotionMessage::Twist(_)
            | MotionMessage::TwistStamped(_)
            | MotionMessage::JointTrajectory(_) => None,
        }
    }

    /// The event for this message, by its type's [`MotionRole`].
    pub fn to_event(&self, ctx: &EventContext<'_>) -> RobotEvent {
        match (self.to_command(ctx), self.to_feedback(ctx)) {
            (Some(c), _) => RobotEvent::MotionCommand(c),
            (None, Some(f)) => RobotEvent::MotionFeedback(f),
            // Unreachable by construction (every kind is one or the other);
            // fall back to an empty feedback rather than panicking.
            (None, None) => RobotEvent::MotionFeedback(feedback(ctx)),
        }
    }
}
