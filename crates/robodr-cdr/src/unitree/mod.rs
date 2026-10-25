//! Unitree robots: decoders for the DDS (`unitree_sdk2`) message types that
//! carry motion, the Unitree CRC, the API request interpretation and a
//! model table. The legacy UDP generation (Go1 / A1 / Aliengo / B1) is in
//! [`crate::unitree_legacy`].
//!
//! | DDS type name | role | event |
//! |---|---|---|
//! | `unitree_go::msg::dds_::LowCmd_` | command | `MotionCommand.joint_speed` / `joint_torque` / `joint_kp` over every slot ([`JointCommandFrame::to_motion_command`]) |
//! | `unitree_go::msg::dds_::LowState_` | feedback | `measured_joint_speed` = max \|dq\|, IMU gyro → angular rates |
//! | `unitree_go::msg::dds_::SportModeState_` | feedback | `velocity` / `yaw_speed` → linear / angular velocity |
//! | `unitree_hg::msg::dds_::LowCmd_` | command | as go `LowCmd_` (35 slots) |
//! | `unitree_hg::msg::dds_::LowState_` | feedback | as go `LowState_` |
//! | `unitree_hg::msg::dds_::HandCmd_` | command | as `LowCmd_` over the hand motors |
//! | `unitree_hg::msg::dds_::HandState_` | feedback | joint speed of the hand motors |
//! | `unitree_hg::msg::dds_::IMUState_` | feedback | gyro → angular rates |
//! | `unitree_hg_doubleimu::msg::dds_::doubleIMUState_` | feedback | gyro → angular rates |
//! | `unitree_go::msg::dds_::MotorCmds_` | command (`rt/hand_sdk`) | as `LowCmd_` over the sequence |
//! | `unitree_hg::msg::dds_::MotorCmd_` | command (`rt/waistpitchcmd`) | as `LowCmd_`, one joint |
//! | `unitree_hg::msg::dds_::MotorState_` | feedback (`rt/waistpitchstate`) | `measured_joint_speed` = \|dq\| |
//! | `unitree_api::msg::dds_::Request_` | command | velocity calls → twist; every call's [`ApiClass`] → `command_class` (see [`ApiCall`]) |
//! | `unitree_go::msg::dds_::WirelessController_` | (not motion) | [`decode_unitree`] only |
//! | `unitree_api::msg::dds_::Response_` | (not motion) | [`decode_unitree`] only |
//!
//! The motion types are also [`crate::MessageKind`]s (registered in
//! [`crate::Registry::with_builtin`] under their DDS and ROS names) and
//! decode through [`crate::decode_payload`] / [`crate::decode_by_type_name`]
//! into [`crate::MotionMessage`]. [`decode_unitree`] decodes all fifteen
//! types into [`UnitreeMessage`].
//!
//! # Status
//!
//! Decoded from Unitree's published IDL / msg definitions and hand-built
//! vectors; **not yet verified against traffic captured from a real
//! robot.**

pub mod api;
pub mod crc;
pub mod go;
pub mod hg;
pub mod joint;
pub mod json;
pub mod model;

pub use api::{ApiCall, ApiClass, ApiRequest, ApiResponse, ApiService, FsmMeaning};
pub use crc::{crc32_core, crc32_core_le_bytes, frame_crc, UNITREE_CRC_POLY};
pub use go::{
    GoBmsCmd, GoBmsState, GoImuState, GoLowCmd, GoLowState, GoMotorCmd, GoMotorCmds, GoMotorState,
    GoPathPoint, GoSportModeState, GoWirelessController, MAX_MOTOR_CMDS,
};
pub use hg::{
    Dex3Mode, HgDoubleImuState, HgHandCmd, HgHandState, HgImuState, HgLowCmd, HgLowState,
    HgMotorCmd, HgMotorState, HgPressSensorState, MAX_HAND_ELEMENTS,
};
pub use joint::{
    Bounded, JointCommand, JointCommandFrame, JointMeasurement, JointStateFrame, MAX_FRAME_JOINTS,
};
pub use json::{validate_document, JsonError, JsonObject, JsonTop, JsonValue};
pub use model::{Generation, IdlFamily, ModelInfo, Morphology, UnitreeModel};

use crate::encap::Encapsulation;
use crate::error::DecodeError;
use crate::reader::Reader;
use crate::{DecodeAnomaly, Limits, MessageKind, MAX_END_PADDING};

/// Motor slots in `unitree_go` `LowCmd_` / `LowState_` (`MotorCmd_[20]`).
pub const MOTOR_SLOTS_GO: usize = 20;
/// Motor slots in `unitree_hg` `LowCmd_` / `LowState_` (`MotorCmd_[35]`).
pub const MOTOR_SLOTS_HG: usize = 35;

/// Default topic names from the SDK (`#define TOPIC_*` / `static const
/// std::string` in `unitree_sdk2/example/**`).
pub mod topics {
    /// `example/go2/go2_low_level.cpp` and every low-level example.
    pub const LOWCMD: &str = "rt/lowcmd";
    pub const LOWSTATE: &str = "rt/lowstate";
    /// `example/go2/go2_sport_client.cpp`.
    pub const SPORTMODESTATE: &str = "rt/sportmodestate";
    /// Low-frequency sport state (`example/go2w`, `a2`, `as2`).
    pub const LF_SPORTMODESTATE: &str = "rt/lf/sportmodestate";
    /// Arm SDK blend channel (`example/{g1,h1,h2,r1}/high_level/*arm*_sdk_dds_example.cpp`).
    pub const ARM_SDK: &str = "rt/arm_sdk";
    /// G1 user-control low-level channel, `unitree_hg` `LowCmd_`
    /// (`example/g1/high_level/g1_userctrl_dds_example.cpp`).
    pub const USER_LOWCMD: &str = "rt/user_lowcmd";
    /// G1 hand-SDK blend channel, `unitree_go` `MotorCmds_`
    /// (`example/g1/high_level/g1_hand_sdk_example.cpp`).
    pub const HAND_SDK: &str = "rt/hand_sdk";
    /// G1-D waist pitch motor, standalone `unitree_hg` `MotorCmd_` /
    /// `MotorState_` (`example/g1/g1d/g1d_waist_example.cpp`).
    pub const WAIST_PITCH_CMD: &str = "rt/waistpitchcmd";
    pub const WAIST_PITCH_STATE: &str = "rt/waistpitchstate";
    /// Low-frequency low state (`unitree_sdk2_python/example/wireless_controller`).
    pub const LF_LOWSTATE: &str = "rt/lf/lowstate";
    /// `example/wireless_controller/main.cpp`.
    pub const WIRELESS_CONTROLLER: &str = "rt/wirelesscontroller";
    /// Torso IMU (`example/{g1,h2,r1}/low_level/*`).
    pub const SECONDARY_IMU: &str = "rt/secondary_imu";
    /// API request topic prefix / suffix (`unitree/robot/channel/channel_namer.hpp`).
    pub const API_PREFIX: &str = "rt/api/";
    pub const API_REQUEST_SUFFIX: &str = "/request";
    pub const API_RESPONSE_SUFFIX: &str = "/response";
}

/// The Unitree DDS types this crate decodes.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum UnitreeKind {
    GoLowCmd,
    GoLowState,
    GoSportModeState,
    GoWirelessController,
    HgLowCmd,
    HgLowState,
    HgHandCmd,
    HgHandState,
    HgImuState,
    HgDoubleImuState,
    ApiRequest,
    ApiResponse,
    GoMotorCmds,
    HgMotorCmd,
    HgMotorState,
}

impl UnitreeKind {
    pub const ALL: [UnitreeKind; 15] = [
        UnitreeKind::GoLowCmd,
        UnitreeKind::GoLowState,
        UnitreeKind::GoSportModeState,
        UnitreeKind::GoWirelessController,
        UnitreeKind::HgLowCmd,
        UnitreeKind::HgLowState,
        UnitreeKind::HgHandCmd,
        UnitreeKind::HgHandState,
        UnitreeKind::HgImuState,
        UnitreeKind::HgDoubleImuState,
        UnitreeKind::ApiRequest,
        UnitreeKind::ApiResponse,
        UnitreeKind::GoMotorCmds,
        UnitreeKind::HgMotorCmd,
        UnitreeKind::HgMotorState,
    ];

    /// DDS type name (`TopicTraits<...>::getTypeName()` in the SDK IDL
    /// headers).
    pub fn dds_type_name(self) -> &'static str {
        match self {
            UnitreeKind::GoLowCmd => "unitree_go::msg::dds_::LowCmd_",
            UnitreeKind::GoLowState => "unitree_go::msg::dds_::LowState_",
            UnitreeKind::GoSportModeState => "unitree_go::msg::dds_::SportModeState_",
            UnitreeKind::GoWirelessController => "unitree_go::msg::dds_::WirelessController_",
            UnitreeKind::HgLowCmd => "unitree_hg::msg::dds_::LowCmd_",
            UnitreeKind::HgLowState => "unitree_hg::msg::dds_::LowState_",
            UnitreeKind::HgHandCmd => "unitree_hg::msg::dds_::HandCmd_",
            UnitreeKind::HgHandState => "unitree_hg::msg::dds_::HandState_",
            UnitreeKind::HgImuState => "unitree_hg::msg::dds_::IMUState_",
            UnitreeKind::HgDoubleImuState => "unitree_hg_doubleimu::msg::dds_::doubleIMUState_",
            UnitreeKind::ApiRequest => "unitree_api::msg::dds_::Request_",
            UnitreeKind::ApiResponse => "unitree_api::msg::dds_::Response_",
            UnitreeKind::GoMotorCmds => "unitree_go::msg::dds_::MotorCmds_",
            UnitreeKind::HgMotorCmd => "unitree_hg::msg::dds_::MotorCmd_",
            UnitreeKind::HgMotorState => "unitree_hg::msg::dds_::MotorState_",
        }
    }

    /// ROS 2 interface name (`unitree_ros2`).
    pub fn ros_type_name(self) -> &'static str {
        match self {
            UnitreeKind::GoLowCmd => "unitree_go/msg/LowCmd",
            UnitreeKind::GoLowState => "unitree_go/msg/LowState",
            UnitreeKind::GoSportModeState => "unitree_go/msg/SportModeState",
            UnitreeKind::GoWirelessController => "unitree_go/msg/WirelessController",
            UnitreeKind::HgLowCmd => "unitree_hg/msg/LowCmd",
            UnitreeKind::HgLowState => "unitree_hg/msg/LowState",
            UnitreeKind::HgHandCmd => "unitree_hg/msg/HandCmd",
            UnitreeKind::HgHandState => "unitree_hg/msg/HandState",
            UnitreeKind::HgImuState => "unitree_hg/msg/IMUState",
            UnitreeKind::HgDoubleImuState => "unitree_hg_doubleimu/msg/doubleIMUState",
            UnitreeKind::ApiRequest => "unitree_api/msg/Request",
            UnitreeKind::ApiResponse => "unitree_api/msg/Response",
            UnitreeKind::GoMotorCmds => "unitree_go/msg/MotorCmds",
            UnitreeKind::HgMotorCmd => "unitree_hg/msg/MotorCmd",
            UnitreeKind::HgMotorState => "unitree_hg/msg/MotorState",
        }
    }

    /// Kind for a DDS or ROS type name (exact match).
    pub fn from_type_name(name: &str) -> Option<Self> {
        Self::ALL
            .into_iter()
            .find(|k| k.dds_type_name() == name || k.ros_type_name() == name)
    }

    /// The motion [`MessageKind`], `None` for the two non-motion types.
    pub fn message_kind(self) -> Option<MessageKind> {
        Some(match self {
            UnitreeKind::GoLowCmd => MessageKind::UnitreeGoLowCmd,
            UnitreeKind::GoLowState => MessageKind::UnitreeGoLowState,
            UnitreeKind::GoSportModeState => MessageKind::UnitreeGoSportModeState,
            UnitreeKind::HgLowCmd => MessageKind::UnitreeHgLowCmd,
            UnitreeKind::HgLowState => MessageKind::UnitreeHgLowState,
            UnitreeKind::HgHandCmd => MessageKind::UnitreeHgHandCmd,
            UnitreeKind::HgHandState => MessageKind::UnitreeHgHandState,
            UnitreeKind::HgImuState => MessageKind::UnitreeHgImuState,
            UnitreeKind::HgDoubleImuState => MessageKind::UnitreeHgDoubleImuState,
            UnitreeKind::ApiRequest => MessageKind::UnitreeApiRequest,
            UnitreeKind::GoMotorCmds => MessageKind::UnitreeGoMotorCmds,
            UnitreeKind::HgMotorCmd => MessageKind::UnitreeHgMotorCmd,
            UnitreeKind::HgMotorState => MessageKind::UnitreeHgMotorState,
            UnitreeKind::GoWirelessController | UnitreeKind::ApiResponse => return None,
        })
    }
}

/// A decoded Unitree message, borrowing from the payload where it has
/// strings / octet sequences (the API types). Not boxed: the largest
/// variant (`HgLowState`, ~2.1 KB) is cheaper on the stack than a heap
/// allocation per frame at 500 Hz.
#[allow(clippy::large_enum_variant)]
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum UnitreeMessage<'a> {
    GoLowCmd(GoLowCmd),
    GoLowState(GoLowState),
    GoSportModeState(GoSportModeState),
    GoWirelessController(GoWirelessController),
    HgLowCmd(HgLowCmd),
    HgLowState(HgLowState),
    HgHandCmd(HgHandCmd),
    HgHandState(HgHandState),
    HgImuState(HgImuState),
    HgDoubleImuState(HgDoubleImuState),
    ApiRequest(ApiRequest<'a>),
    ApiResponse(ApiResponse<'a>),
    GoMotorCmds(GoMotorCmds),
    HgMotorCmd(HgMotorCmd),
    HgMotorState(HgMotorState),
}

impl UnitreeMessage<'_> {
    pub fn kind(&self) -> UnitreeKind {
        match self {
            UnitreeMessage::GoLowCmd(_) => UnitreeKind::GoLowCmd,
            UnitreeMessage::GoLowState(_) => UnitreeKind::GoLowState,
            UnitreeMessage::GoSportModeState(_) => UnitreeKind::GoSportModeState,
            UnitreeMessage::GoWirelessController(_) => UnitreeKind::GoWirelessController,
            UnitreeMessage::HgLowCmd(_) => UnitreeKind::HgLowCmd,
            UnitreeMessage::HgLowState(_) => UnitreeKind::HgLowState,
            UnitreeMessage::HgHandCmd(_) => UnitreeKind::HgHandCmd,
            UnitreeMessage::HgHandState(_) => UnitreeKind::HgHandState,
            UnitreeMessage::HgImuState(_) => UnitreeKind::HgImuState,
            UnitreeMessage::HgDoubleImuState(_) => UnitreeKind::HgDoubleImuState,
            UnitreeMessage::ApiRequest(_) => UnitreeKind::ApiRequest,
            UnitreeMessage::ApiResponse(_) => UnitreeKind::ApiResponse,
            UnitreeMessage::GoMotorCmds(_) => UnitreeKind::GoMotorCmds,
            UnitreeMessage::HgMotorCmd(_) => UnitreeKind::HgMotorCmd,
            UnitreeMessage::HgMotorState(_) => UnitreeKind::HgMotorState,
        }
    }

    /// `Some(crc_ok)` for the four types that carry a CRC (go / hg
    /// `LowCmd_` / `LowState_`), `None` otherwise.
    pub fn crc_ok(&self) -> Option<bool> {
        match self {
            UnitreeMessage::GoLowCmd(m) => Some(m.crc_ok()),
            UnitreeMessage::GoLowState(m) => Some(m.crc_ok()),
            UnitreeMessage::HgLowCmd(m) => Some(m.crc_ok()),
            UnitreeMessage::HgLowState(m) => Some(m.crc_ok()),
            _ => None,
        }
    }
}

/// A successful [`decode_unitree`].
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct UnitreeDecoded<'a> {
    pub encapsulation: Encapsulation,
    pub message: UnitreeMessage<'a>,
    /// Body bytes consumed by the message.
    pub consumed: usize,
    /// Body bytes left after the message.
    pub trailing_bytes: usize,
}

impl UnitreeDecoded<'_> {
    /// [`DecodeAnomaly::ExcessTrailingBytes`] when more than
    /// [`MAX_END_PADDING`] bytes follow the message, and
    /// [`DecodeAnomaly::ApiIdOutOfRange`] for an API request / response
    /// whose `api_id` does not fit `int32`.
    pub fn anomalies(&self) -> Vec<DecodeAnomaly> {
        let mut v = Vec::new();
        if self.trailing_bytes > MAX_END_PADDING {
            v.push(DecodeAnomaly::ExcessTrailingBytes {
                trailing: self.trailing_bytes,
                allowed: MAX_END_PADDING,
            });
        }
        let api_id = match &self.message {
            UnitreeMessage::ApiRequest(q) if !q.api_id_in_range() => Some(q.api_id),
            UnitreeMessage::ApiResponse(r) if !r.api_id_in_range() => Some(r.api_id),
            _ => None,
        };
        if let Some(api_id) = api_id {
            v.push(DecodeAnomaly::ApiIdOutOfRange { api_id });
        }
        v
    }
}

pub(crate) fn read_message<'a>(
    kind: UnitreeKind,
    r: &mut Reader<'a>,
) -> Result<UnitreeMessage<'a>, DecodeError> {
    // Every Unitree IDL type is `@final` (the generated TypeObjects carry
    // IS_FINAL; the Python IDL is `@annotate.final`).
    r.set_final_types(true);
    Ok(match kind {
        UnitreeKind::GoLowCmd => UnitreeMessage::GoLowCmd(GoLowCmd::read(r)?),
        UnitreeKind::GoLowState => UnitreeMessage::GoLowState(GoLowState::read(r)?),
        UnitreeKind::GoSportModeState => {
            UnitreeMessage::GoSportModeState(GoSportModeState::read(r)?)
        }
        UnitreeKind::GoWirelessController => {
            UnitreeMessage::GoWirelessController(GoWirelessController::read(r)?)
        }
        UnitreeKind::HgLowCmd => UnitreeMessage::HgLowCmd(HgLowCmd::read(r)?),
        UnitreeKind::HgLowState => UnitreeMessage::HgLowState(HgLowState::read(r)?),
        UnitreeKind::HgHandCmd => UnitreeMessage::HgHandCmd(HgHandCmd::read(r)?),
        UnitreeKind::HgHandState => UnitreeMessage::HgHandState(HgHandState::read(r)?),
        UnitreeKind::HgImuState => UnitreeMessage::HgImuState(HgImuState::read(r)?),
        UnitreeKind::HgDoubleImuState => {
            UnitreeMessage::HgDoubleImuState(HgDoubleImuState::read(r)?)
        }
        UnitreeKind::ApiRequest => UnitreeMessage::ApiRequest(ApiRequest::read(r)?),
        UnitreeKind::ApiResponse => UnitreeMessage::ApiResponse(ApiResponse::read(r)?),
        UnitreeKind::GoMotorCmds => UnitreeMessage::GoMotorCmds(GoMotorCmds::read(r)?),
        UnitreeKind::HgMotorCmd => UnitreeMessage::HgMotorCmd(HgMotorCmd::read(r)?),
        UnitreeKind::HgMotorState => UnitreeMessage::HgMotorState(HgMotorState::read(r)?),
    })
}

/// Decodes one serialized payload (encapsulation header included) as
/// `kind`. Same encapsulations and caps as [`crate::decode_payload`].
pub fn decode_unitree<'a>(
    kind: UnitreeKind,
    payload: &'a [u8],
    limits: &Limits,
) -> Result<UnitreeDecoded<'a>, DecodeError> {
    let (encapsulation, mut r) = crate::open_reader(payload, limits)?;
    let message = read_message(kind, &mut r)?;
    Ok(UnitreeDecoded {
        encapsulation,
        message,
        consumed: r.pos(),
        trailing_bytes: r.remaining(),
    })
}

/// [`decode_unitree`] by DDS or ROS type name; an unsupported name is
/// [`DecodeError::UnknownType`].
pub fn decode_unitree_by_type_name<'a>(
    type_name: &str,
    payload: &'a [u8],
    limits: &Limits,
) -> Result<UnitreeDecoded<'a>, DecodeError> {
    let kind = UnitreeKind::from_type_name(type_name).ok_or(DecodeError::UnknownType)?;
    decode_unitree(kind, payload, limits)
}

// ---------------------------------------------------------------- helpers

/// A fixed-size array of `N` elements read with `f` (no length prefix).
pub(crate) fn arr<'a, T: Copy + Default, const N: usize>(
    r: &mut Reader<'a>,
    mut f: impl FnMut(&mut Reader<'a>) -> Result<T, DecodeError>,
) -> Result<[T; N], DecodeError> {
    let mut out = [T::default(); N];
    for slot in out.iter_mut() {
        *slot = f(r)?;
    }
    Ok(out)
}

/// A fixed-size array of structs: under XCDR2 an array whose element type
/// is not primitive is preceded by a DHEADER (DDS-XTypes 1.3 §7.4.3.5.3;
/// the SDK's generated code calls `start_consecutive(true, false)` for
/// these members), under XCDR1 it is not.
pub(crate) fn read_struct_array<'a, T: Copy + Default, const N: usize>(
    r: &mut Reader<'a>,
    f: impl FnMut(&mut Reader<'a>) -> Result<T, DecodeError>,
) -> Result<[T; N], DecodeError> {
    r.nonprimitive_seq(|r| arr(r, f))
}

/// A `sequence<struct>` into a fixed-capacity [`Bounded`]: the count is
/// checked against `min(N, limits.max_sequence_len)` and against the bytes
/// left (`min_elem_size` each) before anything is read.
pub(crate) fn read_struct_seq<'a, T: Copy + Default, const N: usize>(
    r: &mut Reader<'a>,
    min_elem_size: usize,
    mut f: impl FnMut(&mut Reader<'a>) -> Result<T, DecodeError>,
) -> Result<Bounded<T, N>, DecodeError> {
    r.nonprimitive_seq(|r| {
        let cap = u32::try_from(N)
            .unwrap_or(u32::MAX)
            .min(r.limits.max_sequence_len);
        let n = r.seq_len(cap, min_elem_size)?;
        let mut out = Bounded::default();
        for _ in 0..n {
            // Cannot fail: n <= N.
            out.push(f(r)?);
        }
        Ok(out)
    })
}
