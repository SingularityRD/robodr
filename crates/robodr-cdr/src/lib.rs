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
//! Unitree robots ([`unitree`]): `unitree_go` / `unitree_hg` low-level
//! command and state, sport-mode state, hand command / state, IMU, and
//! `unitree_api` requests (sport / loco `Move`, `SetVelocity`, ...) are
//! motion kinds too (`MessageKind::Unitree*`); the legacy UDP generation
//! (Go1) is decoded by [`unitree_legacy`]. Status: decoded from Unitree's
//! published IDL / msg definitions and hand-built vectors, not yet verified
//! against traffic captured from a real robot.
//!
//! Separately from the motion types (not in [`MessageKind`] / [`Registry`]),
//! [`std_msgs`] decodes `std_msgs/msg/Bool`, `UInt8` and `String` (bounded),
//! the scalar types robots use to publish e-stop flags and operating modes
//! ([`decode_std`]); `robodr-agentd`'s safety-state feed reads them.
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
//! tests. `geometry_msgs/Twist` in XCDR1 (`CDR_LE`) is also confirmed on
//! real samples from Fast DDS 2.14 and Cyclone DDS 0.10 under ROS 2 Jazzy
//! (`fixtures/captures/ros2-jazzy/`); the other types and XCDR2 have
//! **not** been checked against real captures. In particular,
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
        clippy::unreachable,
        clippy::todo,
        clippy::unimplemented,
        clippy::arithmetic_side_effects
    )
)]
#![forbid(unsafe_code)]

pub mod encap;
pub mod error;
pub mod event;
pub mod lifecycle;
pub mod msgs;
mod reader;
pub mod registry;
pub mod std_msgs;
pub mod unitree;
pub mod unitree_legacy;

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
pub use std_msgs::{
    decode_std, decode_std_by_type_name, StdDecodeError, StdDecoded, StdKind, StdValue,
};
pub use unitree::{
    decode_unitree, decode_unitree_by_type_name, ApiCall, ApiRequest, JointCommandFrame,
    JointStateFrame, UnitreeKind, UnitreeMessage, UnitreeModel,
};

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
    /// `unitree_go::msg::dds_::LowCmd_` (command).
    UnitreeGoLowCmd,
    /// `unitree_go::msg::dds_::LowState_` (feedback).
    UnitreeGoLowState,
    /// `unitree_go::msg::dds_::SportModeState_` (feedback).
    UnitreeGoSportModeState,
    /// `unitree_hg::msg::dds_::LowCmd_` (command).
    UnitreeHgLowCmd,
    /// `unitree_hg::msg::dds_::LowState_` (feedback).
    UnitreeHgLowState,
    /// `unitree_hg::msg::dds_::HandCmd_` (command).
    UnitreeHgHandCmd,
    /// `unitree_hg::msg::dds_::HandState_` (feedback).
    UnitreeHgHandState,
    /// `unitree_hg::msg::dds_::IMUState_` (feedback).
    UnitreeHgImuState,
    /// `unitree_hg_doubleimu::msg::dds_::doubleIMUState_` (feedback).
    UnitreeHgDoubleImuState,
    /// `unitree_api::msg::dds_::Request_` (command).
    UnitreeApiRequest,
    /// `unitree_go::msg::dds_::MotorCmds_` (command, `rt/hand_sdk`).
    UnitreeGoMotorCmds,
    /// `unitree_hg::msg::dds_::MotorCmd_` (command, `rt/waistpitchcmd`).
    UnitreeHgMotorCmd,
    /// `unitree_hg::msg::dds_::MotorState_` (feedback, `rt/waistpitchstate`).
    UnitreeHgMotorState,
}

impl MessageKind {
    pub const ALL: [MessageKind; 19] = [
        MessageKind::Twist,
        MessageKind::TwistStamped,
        MessageKind::Odometry,
        MessageKind::Imu,
        MessageKind::JointState,
        MessageKind::JointTrajectory,
        MessageKind::UnitreeGoLowCmd,
        MessageKind::UnitreeGoLowState,
        MessageKind::UnitreeGoSportModeState,
        MessageKind::UnitreeHgLowCmd,
        MessageKind::UnitreeHgLowState,
        MessageKind::UnitreeHgHandCmd,
        MessageKind::UnitreeHgHandState,
        MessageKind::UnitreeHgImuState,
        MessageKind::UnitreeHgDoubleImuState,
        MessageKind::UnitreeApiRequest,
        MessageKind::UnitreeGoMotorCmds,
        MessageKind::UnitreeHgMotorCmd,
        MessageKind::UnitreeHgMotorState,
    ];

    /// The standard ROS 2 kinds (the six this crate decoded before the
    /// Unitree types were added).
    pub const ROS: [MessageKind; 6] = [
        MessageKind::Twist,
        MessageKind::TwistStamped,
        MessageKind::Odometry,
        MessageKind::Imu,
        MessageKind::JointState,
        MessageKind::JointTrajectory,
    ];

    /// The Unitree type this kind decodes, if it is a Unitree kind.
    pub fn unitree_kind(self) -> Option<UnitreeKind> {
        Some(match self {
            MessageKind::Twist
            | MessageKind::TwistStamped
            | MessageKind::Odometry
            | MessageKind::Imu
            | MessageKind::JointState
            | MessageKind::JointTrajectory => return None,
            MessageKind::UnitreeGoLowCmd => UnitreeKind::GoLowCmd,
            MessageKind::UnitreeGoLowState => UnitreeKind::GoLowState,
            MessageKind::UnitreeGoSportModeState => UnitreeKind::GoSportModeState,
            MessageKind::UnitreeHgLowCmd => UnitreeKind::HgLowCmd,
            MessageKind::UnitreeHgLowState => UnitreeKind::HgLowState,
            MessageKind::UnitreeHgHandCmd => UnitreeKind::HgHandCmd,
            MessageKind::UnitreeHgHandState => UnitreeKind::HgHandState,
            MessageKind::UnitreeHgImuState => UnitreeKind::HgImuState,
            MessageKind::UnitreeHgDoubleImuState => UnitreeKind::HgDoubleImuState,
            MessageKind::UnitreeApiRequest => UnitreeKind::ApiRequest,
            MessageKind::UnitreeGoMotorCmds => UnitreeKind::GoMotorCmds,
            MessageKind::UnitreeHgMotorCmd => UnitreeKind::HgMotorCmd,
            MessageKind::UnitreeHgMotorState => UnitreeKind::HgMotorState,
        })
    }

    /// DDS-mangled type name as announced in SEDP `PID_TYPE_NAME`.
    pub fn dds_type_name(self) -> &'static str {
        match self {
            MessageKind::Twist => "geometry_msgs::msg::dds_::Twist_",
            MessageKind::TwistStamped => "geometry_msgs::msg::dds_::TwistStamped_",
            MessageKind::Odometry => "nav_msgs::msg::dds_::Odometry_",
            MessageKind::Imu => "sensor_msgs::msg::dds_::Imu_",
            MessageKind::JointState => "sensor_msgs::msg::dds_::JointState_",
            MessageKind::JointTrajectory => "trajectory_msgs::msg::dds_::JointTrajectory_",
            k => k.unitree_kind().map_or("", UnitreeKind::dds_type_name),
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
            k => k.unitree_kind().map_or("", UnitreeKind::ros_type_name),
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
            MessageKind::Twist
            | MessageKind::TwistStamped
            | MessageKind::JointTrajectory
            | MessageKind::UnitreeGoLowCmd
            | MessageKind::UnitreeHgLowCmd
            | MessageKind::UnitreeHgHandCmd
            | MessageKind::UnitreeApiRequest
            | MessageKind::UnitreeGoMotorCmds
            | MessageKind::UnitreeHgMotorCmd => MotionRole::Command,
            MessageKind::Odometry
            | MessageKind::Imu
            | MessageKind::JointState
            | MessageKind::UnitreeGoLowState
            | MessageKind::UnitreeGoSportModeState
            | MessageKind::UnitreeHgLowState
            | MessageKind::UnitreeHgHandState
            | MessageKind::UnitreeHgImuState
            | MessageKind::UnitreeHgDoubleImuState
            | MessageKind::UnitreeHgMotorState => MotionRole::Feedback,
        }
    }
}

/// A decoded message, borrowing from the payload.
///
/// Not boxed on purpose: `Odometry` (two 6x6 covariances) is ~720 bytes
/// and the largest Unitree variant (`unitree_hg` `LowState_`, 35 motors)
/// ~2.1 KB, which is cheaper on the stack than a heap allocation per
/// sample (Unitree low-level topics run at 500 Hz).
#[allow(clippy::large_enum_variant)]
#[derive(Debug, Clone, PartialEq)]
pub enum MotionMessage<'a> {
    Twist(Twist),
    TwistStamped(TwistStamped<'a>),
    Odometry(Odometry<'a>),
    Imu(Imu<'a>),
    JointState(JointState<'a>),
    JointTrajectory(JointTrajectory<'a>),
    UnitreeGoLowCmd(unitree::GoLowCmd),
    UnitreeGoLowState(unitree::GoLowState),
    UnitreeGoSportModeState(unitree::GoSportModeState),
    UnitreeHgLowCmd(unitree::HgLowCmd),
    UnitreeHgLowState(unitree::HgLowState),
    UnitreeHgHandCmd(unitree::HgHandCmd),
    UnitreeHgHandState(unitree::HgHandState),
    UnitreeHgImuState(unitree::HgImuState),
    UnitreeHgDoubleImuState(unitree::HgDoubleImuState),
    UnitreeApiRequest(unitree::ApiRequest<'a>),
    UnitreeGoMotorCmds(unitree::GoMotorCmds),
    UnitreeHgMotorCmd(unitree::HgMotorCmd),
    UnitreeHgMotorState(unitree::HgMotorState),
}

impl<'a> MotionMessage<'a> {
    /// The motion message for a decoded Unitree message; `None` for the
    /// two non-motion types (`WirelessController_`, `Response_`).
    pub fn from_unitree(m: UnitreeMessage<'a>) -> Option<Self> {
        Some(match m {
            UnitreeMessage::GoLowCmd(x) => MotionMessage::UnitreeGoLowCmd(x),
            UnitreeMessage::GoLowState(x) => MotionMessage::UnitreeGoLowState(x),
            UnitreeMessage::GoSportModeState(x) => MotionMessage::UnitreeGoSportModeState(x),
            UnitreeMessage::HgLowCmd(x) => MotionMessage::UnitreeHgLowCmd(x),
            UnitreeMessage::HgLowState(x) => MotionMessage::UnitreeHgLowState(x),
            UnitreeMessage::HgHandCmd(x) => MotionMessage::UnitreeHgHandCmd(x),
            UnitreeMessage::HgHandState(x) => MotionMessage::UnitreeHgHandState(x),
            UnitreeMessage::HgImuState(x) => MotionMessage::UnitreeHgImuState(x),
            UnitreeMessage::HgDoubleImuState(x) => MotionMessage::UnitreeHgDoubleImuState(x),
            UnitreeMessage::ApiRequest(x) => MotionMessage::UnitreeApiRequest(x),
            UnitreeMessage::GoMotorCmds(x) => MotionMessage::UnitreeGoMotorCmds(x),
            UnitreeMessage::HgMotorCmd(x) => MotionMessage::UnitreeHgMotorCmd(x),
            UnitreeMessage::HgMotorState(x) => MotionMessage::UnitreeHgMotorState(x),
            UnitreeMessage::GoWirelessController(_) | UnitreeMessage::ApiResponse(_) => {
                return None
            }
        })
    }

    /// The per-motor command frame of a Unitree low-level / hand command
    /// (`None` for every other message).
    pub fn joint_command_frame(&self) -> Option<JointCommandFrame> {
        match self {
            MotionMessage::UnitreeGoLowCmd(m) => Some(m.joint_frame()),
            MotionMessage::UnitreeHgLowCmd(m) => Some(m.joint_frame()),
            MotionMessage::UnitreeHgHandCmd(m) => Some(m.joint_frame()),
            MotionMessage::UnitreeGoMotorCmds(m) => Some(m.joint_frame()),
            MotionMessage::UnitreeHgMotorCmd(m) => Some(m.joint_frame()),
            _ => None,
        }
    }

    /// The frame-level `(mode_pr, mode_machine)` octets of a Unitree `hg`
    /// `LowCmd_` (G1 / H1-2 / H2 / R1: ankle control mode and robot
    /// variant), `None` for every other message. A joint firewall pins them
    /// per channel.
    pub fn unitree_frame_modes(&self) -> Option<(u8, u8)> {
        match self {
            MotionMessage::UnitreeHgLowCmd(m) => Some((m.mode_pr, m.mode_machine)),
            _ => None,
        }
    }

    /// The per-motor state frame of a Unitree low-level / hand state.
    pub fn joint_state_frame(&self) -> Option<JointStateFrame> {
        match self {
            MotionMessage::UnitreeGoLowState(m) => Some(m.joint_frame()),
            MotionMessage::UnitreeHgLowState(m) => Some(m.joint_frame()),
            MotionMessage::UnitreeHgHandState(m) => Some(m.joint_frame()),
            MotionMessage::UnitreeHgMotorState(m) => Some(m.joint_frame()),
            _ => None,
        }
    }

    /// `Some(crc_ok)` for Unitree go / hg `LowCmd_` / `LowState_`, `None`
    /// for types without a CRC. **Advisory**, and not part of
    /// [`Decoded::anomalies`]: the CRC is recomputed over the C++ struct
    /// image with zeroed padding ([`crate::unitree::crc`]), but the SDK
    /// hashes the in-memory struct, whose padding bytes C++ leaves
    /// indeterminate on some builds (go `LowCmd_` 22-23 and 803, go
    /// `LowState_` 22-23, 77-79, 1145-1147, 1154-1155, hg `LowCmd_` 2-3,
    /// hg `LowState_` 10-11, 70-71). So `false` may be a padding artefact of
    /// the sender's build, not a forged frame, and must be validated
    /// against captured traffic before it is relied on; nothing in this
    /// crate or the ROS 2 pipeline changes a severity because of it. (A
    /// firewall that chooses to require it does so knowingly.)
    pub fn unitree_crc_ok(&self) -> Option<bool> {
        match self {
            MotionMessage::UnitreeGoLowCmd(m) => Some(m.crc_ok()),
            MotionMessage::UnitreeGoLowState(m) => Some(m.crc_ok()),
            MotionMessage::UnitreeHgLowCmd(m) => Some(m.crc_ok()),
            MotionMessage::UnitreeHgLowState(m) => Some(m.crc_ok()),
            _ => None,
        }
    }

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
            // The parameter of a Unitree API request is not readable JSON
            // (an object, or an array where the SDK sends one): whatever
            // the call is, its arguments cannot be checked.
            MotionMessage::UnitreeApiRequest(q) => q.parameter_document().err().map(|e| e.reason()),
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
            MotionMessage::UnitreeGoLowCmd(_) => MessageKind::UnitreeGoLowCmd,
            MotionMessage::UnitreeGoLowState(_) => MessageKind::UnitreeGoLowState,
            MotionMessage::UnitreeGoSportModeState(_) => MessageKind::UnitreeGoSportModeState,
            MotionMessage::UnitreeHgLowCmd(_) => MessageKind::UnitreeHgLowCmd,
            MotionMessage::UnitreeHgLowState(_) => MessageKind::UnitreeHgLowState,
            MotionMessage::UnitreeHgHandCmd(_) => MessageKind::UnitreeHgHandCmd,
            MotionMessage::UnitreeHgHandState(_) => MessageKind::UnitreeHgHandState,
            MotionMessage::UnitreeHgImuState(_) => MessageKind::UnitreeHgImuState,
            MotionMessage::UnitreeHgDoubleImuState(_) => MessageKind::UnitreeHgDoubleImuState,
            MotionMessage::UnitreeApiRequest(_) => MessageKind::UnitreeApiRequest,
            MotionMessage::UnitreeGoMotorCmds(_) => MessageKind::UnitreeGoMotorCmds,
            MotionMessage::UnitreeHgMotorCmd(_) => MessageKind::UnitreeHgMotorCmd,
            MotionMessage::UnitreeHgMotorState(_) => MessageKind::UnitreeHgMotorState,
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
    /// A Unitree API request / response whose wire `api_id` (`int64`) is
    /// outside the `int32` range. The SDK server dispatches on the low 32
    /// bits, so the robot executes a different id than the one sent
    /// (`2^32 + 1008` is `Move`): an evasion attempt. The call is
    /// interpreted as the robot reads it ([`ApiRequest::call`]).
    ApiIdOutOfRange { api_id: i64 },
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
            DecodeAnomaly::ApiIdOutOfRange { api_id } => write!(
                f,
                "api_id {api_id} is outside int32; the robot dispatches it as {}",
                unitree::api::dispatched_id(*api_id)
            ),
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
        if let MotionMessage::UnitreeApiRequest(q) = &self.message {
            if !q.api_id_in_range() {
                v.push(DecodeAnomaly::ApiIdOutOfRange { api_id: q.api_id });
            }
        }
        v
    }
}

/// Checks the payload cap, parses the encapsulation header and positions a
/// reader at the CDR body.
pub(crate) fn open_reader<'a>(
    payload: &'a [u8],
    limits: &Limits,
) -> Result<(Encapsulation, Reader<'a>), DecodeError> {
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
    let r = Reader::new(body, endian, version, rep.is_delimited(), *limits);
    Ok((encapsulation, r))
}

/// Decodes one serialized payload (encapsulation header included) as `kind`.
pub fn decode_payload<'a>(
    kind: MessageKind,
    payload: &'a [u8],
    limits: &Limits,
) -> Result<Decoded<'a>, DecodeError> {
    let (encapsulation, mut r) = open_reader(payload, limits)?;
    let message = match kind {
        MessageKind::Twist => MotionMessage::Twist(Twist::read(&mut r)?),
        MessageKind::TwistStamped => MotionMessage::TwistStamped(TwistStamped::read(&mut r)?),
        MessageKind::Odometry => MotionMessage::Odometry(Odometry::read(&mut r)?),
        MessageKind::Imu => MotionMessage::Imu(Imu::read(&mut r)?),
        MessageKind::JointState => MotionMessage::JointState(JointState::read(&mut r)?),
        MessageKind::JointTrajectory => {
            MotionMessage::JointTrajectory(JointTrajectory::read(&mut r)?)
        }
        other => {
            // Every remaining kind is a Unitree motion kind.
            let k = other.unitree_kind().ok_or(DecodeError::UnknownType)?;
            let m = unitree::read_message(k, &mut r)?;
            MotionMessage::from_unitree(m).ok_or(DecodeError::UnknownType)?
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
