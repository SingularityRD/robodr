//! Pure, no-panic XCDR1 / XCDR2 decoder for the ROS 2 motion messages that
//! RoboDR's Motion Firewall and motion monitor need to see.
//!
//! RTPS discovery tells RoboDR *who* writes `/cmd_vel`; this crate decodes
//! *what* they write. Input is one RTPS serialized payload (the
//! `serializedPayload` of a user DATA submessage, or a reassembled
//! DATA_FRAG sample), starting with its 4-byte encapsulation header. Output
//! is a borrowed, typed [`MotionMessage`] and, through [`EventContext`], a
//! `robodr_events::MotionCommand` / `MotionFeedback`.
//!
//! Read-only and passive: nothing is ever encoded or sent.
//!
//! # Supported types
//!
//! | DDS type name | ROS type | role |
//! |---|---|---|
//! | `geometry_msgs::msg::dds_::Twist_` | `geometry_msgs/msg/Twist` | command |
//! | `geometry_msgs::msg::dds_::TwistStamped_` | `geometry_msgs/msg/TwistStamped` | command |
//! | `trajectory_msgs::msg::dds_::JointTrajectory_` | `trajectory_msgs/msg/JointTrajectory` | command |
//! | `nav_msgs::msg::dds_::Odometry_` | `nav_msgs/msg/Odometry` | feedback |
//! | `sensor_msgs::msg::dds_::Imu_` | `sensor_msgs/msg/Imu` | feedback |
//! | `sensor_msgs::msg::dds_::JointState_` | `sensor_msgs/msg/JointState` | feedback |
//!
//! # Encodings
//!
//! Identifiers follow DDS-XTypes 1.3 Table 60 (the values Cyclone DDS
//! `DDSI_RTPS_*` and Fast CDR use): see [`Representation`]. Any other
//! identifier is [`DecodeError::UnknownRepresentation`], which the pipeline
//! reports as an undecodable sample.
//!
//! * `CDR_BE` / `CDR_LE` (`0x0000` / `0x0001`, XCDR1): primitives align to
//!   `min(size, 8)` relative to the first octet after the encapsulation
//!   header.
//! * `CDR2_BE` / `CDR2_LE` (`0x0006` / `0x0007`, XCDR2 plain): primitives align to
//!   `min(size, 4)` (so `double` is 4-aligned); a sequence whose element type
//!   is not primitive (`string[]`, `JointTrajectoryPoint[]`) is preceded by a
//!   DHEADER (`uint32` byte size of the sequence).
//! * `D_CDR2_BE` / `D_CDR2_LE` (`0x0008` / `0x0009`, XCDR2 delimited): as
//!   plain XCDR2, and the top-level struct is preceded by a DHEADER. Whether
//!   **nested** structs (`Vector3` inside `Twist`, `Header`, `Time`, ...)
//!   carry one too depends on their extensibility, which the ROS IDL does not
//!   annotate: by XTypes 1.3 an unannotated type is `@appendable`, so every
//!   nested struct gets a DHEADER ([`DelimitedNesting::AllStructs`], the
//!   default). An RMW / IDL generator that marks the nested types `@final`
//!   would send DHEADERs on the top level only
//!   ([`DelimitedNesting::TopLevelOnly`]). This cannot be settled offline;
//!   choose with [`Limits::d_cdr2_nesting`] after checking a real capture. A
//!   wrong choice makes samples fail to decode (reported as undecodable), it
//!   never silently decodes wrong values for the common sizes, because the
//!   DHEADER values are checked against the bytes. Members past those this
//!   crate knows (a newer appendable version) are skipped by the DHEADER.
//! * `PL_CDR*` (mutable) and XML are recognised and rejected as
//!   [`DecodeError::UnsupportedRepresentation`]: ROS motion types are never
//!   mutable, so such a payload on a motion topic is itself suspicious.
//!
//! Strings: `uint32` length including the NUL, the bytes, the NUL. A length
//! of 0 is malformed ([`DecodeError::StringLengthZero`]: the minimum, for
//! `""`, is 1); the last byte must be NUL. Bytes are kept as sent
//! ([`CdrStr`]); UTF-8 is not required.
//!
//! # Hostile input
//!
//! * No panics: no direct indexing, checked arithmetic, every bound checked
//!   (`clippy::indexing_slicing`, `unwrap_used`, `expect_used`, `panic` and
//!   `arithmetic_side_effects` are denied in non-test code).
//! * [`Limits`] caps payload size, string length, sequence length and
//!   trajectory points; a sequence count is also checked against the bytes
//!   actually left before anything iterates.
//! * The only allocation is `JointTrajectory::points` (bounded). Strings,
//!   `string[]` and `float64[]` are zero-copy views.
//! * NaN / ±inf are decoded faithfully and exposed; the consumer decides.
//!   Aggregates ([`F64Seq::max_abs`], [`Vector3::norm`]) propagate them.
//! * Trailing bytes after the message are allowed (XCDR padding, appended
//!   members) and reported in [`Decoded::trailing_bytes`]. More than
//!   [`MAX_END_PADDING`] (3, the most XCDR end padding can be) is a
//!   [`DecodeAnomaly::ExcessTrailingBytes`] ([`Decoded::anomalies`]): a
//!   DDS reader ignores those bytes, but nothing standard puts them there.
//! * A command whose speed cannot be bounded from the message (a
//!   `JointTrajectory` with no velocities and no two timed points to derive
//!   one from) is a [`DecodeAnomaly::UnverifiableCommand`], never a silent
//!   `None`.
//!
//! # Not verified
//!
//! The byte layouts were derived by hand from DDS-XTypes 1.3 §7.4.3 and
//! DDSI-RTPS 2.5 §10 and are checked against hand-written vectors in the
//! tests. They have **not** been checked against captures from Fast DDS or
//! Cyclone DDS (none are available in this environment). In particular,
//! whether an RMW sends `CDR2` or `D_CDR2` for ROS types, and whether it
//! wraps nested structs in DHEADERs ([`Limits::d_cdr2_nesting`]), must be
//! confirmed on a real capture before relying on XCDR2. Default ROS 2 RMWs
//! send XCDR1 (`CDR_LE`). The encapsulation identifiers are those of XTypes
//! 1.3 Table 60 (the values Cyclone DDS and Fast CDR define); they were not
//! checked against a live stack here.

#![cfg_attr(
    not(test),
    deny(
        clippy::indexing_slicing,
        clippy::unwrap_used,
        clippy::expect_used,
        clippy::panic,
        clippy::arithmetic_side_effects
    )
)]
#![forbid(unsafe_code)]

pub mod encap;
pub mod error;
pub mod event;
pub mod msgs;
mod reader;
pub mod registry;

pub use encap::{Encapsulation, Endian, Representation, XcdrVersion};
pub use error::DecodeError;
pub use event::EventContext;
pub use msgs::{
    F64Seq, Header, Imu, JointState, JointTrajectory, JointTrajectoryPoint, Odometry, Pose,
    PoseWithCovariance, Quaternion, StringSeq, Time, Twist, TwistStamped, TwistWithCovariance,
    Vector3,
};
pub use reader::CdrStr;
pub use registry::{DecodeFn, Registry};

use reader::Reader;

/// Decoding caps. Every limit is checked before the corresponding bytes are
/// touched or any memory is reserved.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Limits {
    /// Max serialized payload (header included), bytes.
    pub max_payload_len: usize,
    /// Max string length prefix (NUL included).
    pub max_string_len: u32,
    /// Max element count of any `string[]` / `float64[]`.
    pub max_sequence_len: u32,
    /// Max `JointTrajectory::points` count.
    pub max_trajectory_points: u32,
    /// Which structs carry a DHEADER under `D_CDR2_*` (see the crate docs).
    /// Not a cap, but kept here so that it travels with every decode call.
    pub d_cdr2_nesting: DelimitedNesting,
}

/// Which structs carry an XCDR2 DHEADER in a `D_CDR2_*` payload.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default)]
pub enum DelimitedNesting {
    /// The top-level struct and every nested struct (XTypes 1.3: types
    /// without an extensibility annotation, as ROS IDL types are, are
    /// `@appendable`). The default.
    #[default]
    AllStructs,
    /// Only the top-level struct; nested structs are treated as `@final`.
    TopLevelOnly,
}

impl Default for Limits {
    /// 256 KiB payload, 256-byte strings (ROS names are short), 1024
    /// elements per sequence (joints), 1024 trajectory points.
    fn default() -> Self {
        Limits {
            max_payload_len: 256 * 1024,
            max_string_len: 256,
            max_sequence_len: 1024,
            max_trajectory_points: 1024,
            d_cdr2_nesting: DelimitedNesting::AllStructs,
        }
    }
}

/// Whether a type carries commands or measurements.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum MotionRole {
    Command,
    Feedback,
}

/// The supported message types.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum MessageKind {
    Twist,
    TwistStamped,
    Odometry,
    Imu,
    JointState,
    JointTrajectory,
}

impl MessageKind {
    pub const ALL: [MessageKind; 6] = [
        MessageKind::Twist,
        MessageKind::TwistStamped,
        MessageKind::Odometry,
        MessageKind::Imu,
        MessageKind::JointState,
        MessageKind::JointTrajectory,
    ];

    /// DDS-mangled type name as announced in SEDP `PID_TYPE_NAME`.
    pub fn dds_type_name(self) -> &'static str {
        match self {
            MessageKind::Twist => "geometry_msgs::msg::dds_::Twist_",
            MessageKind::TwistStamped => "geometry_msgs::msg::dds_::TwistStamped_",
            MessageKind::Odometry => "nav_msgs::msg::dds_::Odometry_",
            MessageKind::Imu => "sensor_msgs::msg::dds_::Imu_",
            MessageKind::JointState => "sensor_msgs::msg::dds_::JointState_",
            MessageKind::JointTrajectory => "trajectory_msgs::msg::dds_::JointTrajectory_",
        }
    }

    /// ROS interface name.
    pub fn ros_type_name(self) -> &'static str {
        match self {
            MessageKind::Twist => "geometry_msgs/msg/Twist",
            MessageKind::TwistStamped => "geometry_msgs/msg/TwistStamped",
            MessageKind::Odometry => "nav_msgs/msg/Odometry",
            MessageKind::Imu => "sensor_msgs/msg/Imu",
            MessageKind::JointState => "sensor_msgs/msg/JointState",
            MessageKind::JointTrajectory => "trajectory_msgs/msg/JointTrajectory",
        }
    }

    /// Kind for a DDS or ROS type name (exact match).
    pub fn from_type_name(name: &str) -> Option<Self> {
        Self::ALL
            .into_iter()
            .find(|k| k.dds_type_name() == name || k.ros_type_name() == name)
    }

    pub fn role(self) -> MotionRole {
        match self {
            MessageKind::Twist | MessageKind::TwistStamped | MessageKind::JointTrajectory => {
                MotionRole::Command
            }
            MessageKind::Odometry | MessageKind::Imu | MessageKind::JointState => {
                MotionRole::Feedback
            }
        }
    }
}

/// A decoded message, borrowing from the payload.
///
/// Not boxed on purpose: `Odometry` (two 6x6 covariances) is ~720 bytes,
/// which is cheaper on the stack than a heap allocation per sample.
#[allow(clippy::large_enum_variant)]
#[derive(Debug, Clone, PartialEq)]
pub enum MotionMessage<'a> {
    Twist(Twist),
    TwistStamped(TwistStamped<'a>),
    Odometry(Odometry<'a>),
    Imu(Imu<'a>),
    JointState(JointState<'a>),
    JointTrajectory(JointTrajectory<'a>),
}

impl MotionMessage<'_> {
    /// Why this command's speed cannot be bounded, if so: a non-empty
    /// `JointTrajectory` with no velocities and no pair of points to derive
    /// a speed from (see [`JointTrajectory::max_joint_speed`]). `None` for
    /// feedback types and for every command whose speed is known.
    pub fn unverifiable_reason(&self) -> Option<&'static str> {
        match self {
            MotionMessage::JointTrajectory(j) if j.max_joint_speed().is_none() => Some(
                "JointTrajectory has no velocities and fewer than two points with positions \
                 (the start position is not in the message)",
            ),
            _ => None,
        }
    }

    pub fn kind(&self) -> MessageKind {
        match self {
            MotionMessage::Twist(_) => MessageKind::Twist,
            MotionMessage::TwistStamped(_) => MessageKind::TwistStamped,
            MotionMessage::Odometry(_) => MessageKind::Odometry,
            MotionMessage::Imu(_) => MessageKind::Imu,
            MotionMessage::JointState(_) => MessageKind::JointState,
            MotionMessage::JointTrajectory(_) => MessageKind::JointTrajectory,
        }
    }
}

/// A successful decode.
#[derive(Debug, Clone, PartialEq)]
pub struct Decoded<'a> {
    pub encapsulation: Encapsulation,
    pub message: MotionMessage<'a>,
    /// Body bytes consumed by the message.
    pub consumed: usize,
    /// Body bytes left after the message. XCDR end padding (see
    /// [`Encapsulation::padding`]) shows up here; more than
    /// [`MAX_END_PADDING`] is a [`DecodeAnomaly::ExcessTrailingBytes`].
    pub trailing_bytes: usize,
}

/// The most end padding XCDR can add (to round the payload up to a multiple
/// of 4; XTypes 1.3 announces it in the options' two low bits).
pub const MAX_END_PADDING: usize = 3;

/// Something odd about a payload that decoded fine. Consumers report these
/// (the ROS 2 pipeline raises `robot.motion.decode_anomaly` /
/// `robot.motion.unverifiable_command`); they never block decoding.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum DecodeAnomaly {
    /// More bytes after the message than XCDR end padding can explain.
    /// A DDS reader ignores them; they may hide data (a covert channel, or
    /// members of a different type version than the one announced).
    ExcessTrailingBytes { trailing: usize, allowed: usize },
    /// A command whose speed cannot be bounded from the message, so no
    /// envelope can check it (see [`MotionMessage::unverifiable_reason`]).
    UnverifiableCommand { reason: &'static str },
}

impl std::fmt::Display for DecodeAnomaly {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            DecodeAnomaly::ExcessTrailingBytes { trailing, allowed } => write!(
                f,
                "{trailing} bytes after the message (XCDR end padding is at most {allowed})"
            ),
            DecodeAnomaly::UnverifiableCommand { reason } => {
                write!(f, "command speed cannot be verified: {reason}")
            }
        }
    }
}

impl Decoded<'_> {
    /// The anomalies of this decode (empty for a well-formed sample).
    pub fn anomalies(&self) -> Vec<DecodeAnomaly> {
        let mut v = Vec::new();
        if self.trailing_bytes > MAX_END_PADDING {
            v.push(DecodeAnomaly::ExcessTrailingBytes {
                trailing: self.trailing_bytes,
                allowed: MAX_END_PADDING,
            });
        }
        if let Some(reason) = self.message.unverifiable_reason() {
            v.push(DecodeAnomaly::UnverifiableCommand { reason });
        }
        v
    }
}

/// Decodes one serialized payload (encapsulation header included) as `kind`.
pub fn decode_payload<'a>(
    kind: MessageKind,
    payload: &'a [u8],
    limits: &Limits,
) -> Result<Decoded<'a>, DecodeError> {
    if payload.len() > limits.max_payload_len {
        return Err(DecodeError::PayloadTooLarge {
            len: payload.len(),
            max: limits.max_payload_len,
        });
    }
    let (encapsulation, body) = Encapsulation::parse(payload)?;
    let rep = encapsulation.representation;
    let (endian, version) = match (rep.endian(), rep.version()) {
        (Some(e), Some(v)) if !rep.is_parameter_list() => (e, v),
        _ => return Err(DecodeError::UnsupportedRepresentation(rep)),
    };
    let mut r = Reader::new(body, endian, version, rep.is_delimited(), *limits);
    let message = match kind {
        MessageKind::Twist => MotionMessage::Twist(Twist::read(&mut r)?),
        MessageKind::TwistStamped => MotionMessage::TwistStamped(TwistStamped::read(&mut r)?),
        MessageKind::Odometry => MotionMessage::Odometry(Odometry::read(&mut r)?),
        MessageKind::Imu => MotionMessage::Imu(Imu::read(&mut r)?),
        MessageKind::JointState => MotionMessage::JointState(JointState::read(&mut r)?),
        MessageKind::JointTrajectory => {
            MotionMessage::JointTrajectory(JointTrajectory::read(&mut r)?)
        }
    };
    Ok(Decoded {
        encapsulation,
        message,
        consumed: r.pos(),
        trailing_bytes: r.remaining(),
    })
}

/// Decodes a payload by DDS (or ROS) type name using the built-in kinds.
/// Use a [`Registry`] to add or override decoders.
pub fn decode_by_type_name<'a>(
    type_name: &str,
    payload: &'a [u8],
    limits: &Limits,
) -> Result<Decoded<'a>, DecodeError> {
    let kind = MessageKind::from_type_name(type_name).ok_or(DecodeError::UnknownType)?;
    decode_payload(kind, payload, limits)
}
