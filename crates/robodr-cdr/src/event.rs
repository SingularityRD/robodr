//! Mapping decoded messages to `robodr-events` types.
//!
//! | message | event | fields |
//! |---|---|---|
//! | `Twist`, `TwistStamped` | [`MotionCommand`] | `linear_speed = linear.x`, `angular_speed = angular.z` (signed, REP 103) |
//! | `JointTrajectory` | [`MotionCommand`] | `joint_speed` = max \|velocity\| over all points/joints (`None` if no point has velocities) |
//! | `Odometry` | [`MotionFeedback`] | `linear_velocity = twist.twist.linear.x`, `angular_velocity = twist.twist.angular.z`, `measured_linear_speed = ‖twist.twist.linear‖` |
//! | `Imu` | [`MotionFeedback`] | `angular_velocity = angular_velocity.z` |
//! | `JointState` | [`MotionFeedback`] | `measured_joint_speed` = max \|velocity\| (`None` if `velocity` is empty) |
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
    }
}

fn feedback(ctx: &EventContext<'_>) -> MotionFeedback {
    MotionFeedback {
        channel: ctx.channel.to_owned(),
        measured_linear_speed: None,
        measured_joint_speed: None,
        linear_velocity: None,
        angular_velocity: None,
        publisher_guid: ctx.writer_guid.map(str::to_owned),
        timestamp_ns: ctx.timestamp_ns,
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
                joint_speed: j.max_abs_velocity(),
                angular_speed: None,
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
                    angular_velocity: Some(v.angular.z),
                    ..feedback(ctx)
                })
            }
            MotionMessage::Imu(i) => Some(MotionFeedback {
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
