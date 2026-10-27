//! `unitree_api::msg::dds_::{Request_, Response_}`: Unitree's RPC over DDS,
//! and the interpretation of motion requests (sport / loco / arm / motion
//! switcher services) into [`ApiCall`].
//!
//! # Wire layout
//!
//! From `unitree_sdk2/include/unitree/robot/internal/internal_idl_decl/`
//! (`Request_.hpp`, `RequestHeader_.hpp`, `RequestIdentity_.hpp`,
//! `RequestLease_.hpp`, `RequestPolicy_.hpp`, `Response_.hpp`,
//! `ResponseHeader_.hpp`, `ResponseStatus_.hpp`), matching
//! `unitree_ros2/.../unitree_api/msg/*.msg`:
//!
//! ```text
//! Request_  { RequestHeader_ header { RequestIdentity_ identity { int64 id; int64 api_id; }
//!                                     RequestLease_ lease { int64 id; }
//!                                     RequestPolicy_ policy { int32 priority; bool noreply; } }
//!             string parameter; sequence<uint8> binary; }
//! Response_ { ResponseHeader_ header { RequestIdentity_ identity; ResponseStatus_ status { int32 code; } }
//!             string data; sequence<uint8> binary; }
//! ```
//!
//! A client of service `<svc>` writes requests on `rt/api/<svc>/request` and
//! reads responses on `rt/api/<svc>/response`
//! (`unitree/robot/channel/channel_namer.hpp`). The **same type** carries
//! every service, and api ids are reused across services (`1003` is
//! `StopMove` on `sport` but `ReleaseMode` on `motion_switcher`; `7106` is
//! `SetArmTask` on the humanoid `sport` service but `ExecuteAction` on
//! `arm`), so a request can only be interpreted together with its topic
//! ([`ApiService::from_topic`]) and, for some ids, the robot model.
//!
//! # Interpretation
//!
//! [`ApiRequest::call`] maps `(service, model, api_id, parameter JSON)` to an
//! [`ApiCall`]. The api ids and JSON keys come from the SDK headers cited on
//! each table below. An id that is not in the table for the service (and
//! model, when given) is [`ApiCall::Unknown`], never an error. With no
//! model, only ids whose meaning is the same for every model using that
//! service are interpreted.

use std::fmt;

use crate::error::DecodeError;
use crate::reader::{CdrStr, Reader};
use crate::unitree::json::{
    validate_document, JsonError, JsonObject, JsonTop, JsonValue, MAX_JSON_LEN,
};
use crate::unitree::model::UnitreeModel;

/// Cap on `Request_::parameter` / `Response_::data` (NUL included): at
/// least the JSON reader's [`MAX_JSON_LEN`] (a B2 `TrajectoryFollow` is
/// about 3 KB), or `Limits::max_string_len` if that is larger.
fn json_string_cap(r: &Reader<'_>) -> u32 {
    let json = u32::try_from(MAX_JSON_LEN.saturating_add(1)).unwrap_or(u32::MAX);
    r.limits.max_string_len.max(json)
}

/// `unitree_api::msg::dds_::Request_`, borrowing from the payload.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ApiRequest<'a> {
    /// `header.identity.id`: the request id (client-chosen).
    pub id: i64,
    /// `header.identity.api_id`: which API of the service, as sent. The
    /// SDK server dispatches on its **low 32 bits** (`int32_t` api ids,
    /// `robot/server/server.hpp`), so interpretation uses
    /// [`ApiRequest::dispatched_api_id`]; an id outside the `i32` range is
    /// an anomaly ([`ApiRequest::api_id_in_range`]).
    pub api_id: i64,
    /// `header.lease.id`.
    pub lease_id: i64,
    /// `header.policy.priority`.
    pub priority: i32,
    /// `header.policy.noreply`, as the raw octet (DDS `boolean` is 0 or 1;
    /// anything else is kept for the consumer to judge).
    pub noreply_octet: u8,
    /// The JSON parameter string, as sent (UTF-8 not required).
    pub parameter: CdrStr<'a>,
    /// The opaque `binary` member.
    pub binary: &'a [u8],
}

/// `unitree_api::msg::dds_::Response_`, borrowing from the payload.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ApiResponse<'a> {
    pub id: i64,
    pub api_id: i64,
    /// `header.status.code` (0 = success in the SDK clients).
    pub status_code: i32,
    /// The JSON result string, as sent.
    pub data: CdrStr<'a>,
    pub binary: &'a [u8],
}

fn identity(r: &mut Reader<'_>) -> Result<(i64, i64), DecodeError> {
    r.structure(|r| Ok((r.i64()?, r.i64()?)))
}

fn octets<'a>(r: &mut Reader<'a>) -> Result<&'a [u8], DecodeError> {
    let n = r.seq_len(r.limits.max_sequence_len, 1)?;
    r.bytes(n as usize)
}

impl<'a> ApiRequest<'a> {
    pub(crate) fn read(r: &mut Reader<'a>) -> Result<Self, DecodeError> {
        r.structure(|r| {
            let (id, api_id, lease_id, priority, noreply_octet) = r.structure(|r| {
                let (id, api_id) = identity(r)?;
                let lease_id = r.structure(|r| r.i64())?;
                let (priority, noreply) = r.structure(|r| Ok((r.i32()?, r.u8()?)))?;
                Ok((id, api_id, lease_id, priority, noreply))
            })?;
            Ok(ApiRequest {
                id,
                api_id,
                lease_id,
                priority,
                noreply_octet,
                parameter: r.string_capped(json_string_cap(r))?,
                binary: octets(r)?,
            })
        })
    }

    /// The api id the SDK server dispatches on: the low 32 bits of the wire
    /// `int64`, as `int32` (wrapping).
    pub fn dispatched_api_id(&self) -> i32 {
        dispatched(self.api_id)
    }

    /// The wire api id fits `int32` (so it means what it says). An id that
    /// does not is aliased by the robot onto its low 32 bits: a hostile
    /// writer can hide `Move` (1008) as `2^32 + 1008`.
    pub fn api_id_in_range(&self) -> bool {
        i32::try_from(self.api_id).is_ok()
    }

    /// The parameter as a validated JSON document whose top level is an
    /// object or an array ([`validate_document`]; `""` is the empty
    /// object).
    pub fn parameter_document(&self) -> Result<JsonTop, JsonError> {
        validate_document(self.parameter.as_bytes())
    }

    /// `noreply_octet != 0`.
    pub fn noreply(&self) -> bool {
        self.noreply_octet != 0
    }

    /// The parameter as a validated JSON object (an empty string is the
    /// empty object: the SDK sends `""` for calls without arguments).
    pub fn parameter_json(&self) -> Result<JsonObject<'a>, JsonError> {
        let p = self.parameter.as_bytes();
        if p.is_empty() {
            Ok(JsonObject::empty())
        } else {
            JsonObject::parse(p)
        }
    }

    /// Interprets the request for a service and (optionally) a model. The
    /// tables are searched with [`ApiRequest::dispatched_api_id`], as the
    /// robot does; the returned call keeps the wire id.
    pub fn call(&self, service: ApiService, model: Option<UnitreeModel>) -> ApiCall {
        interpret(self.api_id, service, model, self.parameter.as_bytes())
    }

    /// [`ApiRequest::call`] with the service taken from the topic the
    /// request was written on (`rt/api/<svc>/request` or, de-mangled,
    /// `/api/<svc>/request`); [`ApiService::Unspecified`] otherwise.
    pub fn call_for_topic(&self, topic: &str, model: Option<UnitreeModel>) -> ApiCall {
        self.call(ApiService::from_topic(topic), model)
    }
}

/// The low 32 bits of a wire api id, as the SDK server reads them.
pub fn dispatched_id(api_id: i64) -> i32 {
    dispatched(api_id)
}

fn dispatched(api_id: i64) -> i32 {
    // Truncation is the point: it reproduces the server's int32 dispatch.
    #[allow(clippy::cast_possible_truncation)]
    let low = api_id as i32;
    low
}

impl<'a> ApiResponse<'a> {
    /// The wire api id fits `int32` (see [`ApiRequest::api_id_in_range`]).
    pub fn api_id_in_range(&self) -> bool {
        i32::try_from(self.api_id).is_ok()
    }

    pub(crate) fn read(r: &mut Reader<'a>) -> Result<Self, DecodeError> {
        r.structure(|r| {
            let (id, api_id, status_code) = r.structure(|r| {
                let (id, api_id) = identity(r)?;
                let code = r.structure(|r| r.i32())?;
                Ok((id, api_id, code))
            })?;
            Ok(ApiResponse {
                id,
                api_id,
                status_code,
                data: r.string_capped(json_string_cap(r))?,
                binary: octets(r)?,
            })
        })
    }
}

/// The Unitree service a request is addressed to.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ApiService {
    /// `sport`: Go2 / Go2-W / B2 / B2-W / A2 / AS2 sport mode (ids
    /// 1001..2058) and the G1 / H2 / R1 locomotion client (ids 7001..7111,
    /// `LOCO_SERVICE_NAME = "sport"`).
    Sport,
    /// `loco`: the H1 locomotion client (ids 8001..8204).
    Loco,
    /// `arm`: G1 / H2 arm actions.
    Arm,
    /// `motion_switcher`: selects / releases the built-in motion service
    /// (releasing it hands the motors to `rt/lowcmd`).
    MotionSwitcher,
    /// `obstacles_avoid` (Go2): `Move` with `mode` 0 = velocity, 1 / 2 =
    /// relative / absolute position target.
    ObstaclesAvoid,
    /// `agv` (G1-D wheeled base): `Move` velocity, `HeightAdjust`.
    Agv,
    /// `robot_state` (Go2 / B2): `ServiceSwitch` starts / stops on-board
    /// services, the sport service included.
    RobotState,
    /// `uwbswitch` (Go2 UWB tracking): `SwitchSet` makes the robot follow
    /// the UWB remote.
    UwbSwitch,
    /// Any other service (vui, voice, videohub, config, ...): never
    /// interpreted as motion (see the crate README for the list checked).
    Other,
    /// The service is not known (the topic was not given or is not an
    /// `api/<svc>/request` name). Only ids that mean the same thing on
    /// every motion service are interpreted.
    Unspecified,
}

impl ApiService {
    /// `rt/api/<svc>/request`, `rt/api/<svc>/response`, or the de-mangled
    /// ROS forms `/api/<svc>/request|response`.
    pub fn from_topic(topic: &str) -> ApiService {
        let rest = topic
            .strip_prefix("rt/api/")
            .or_else(|| topic.strip_prefix("/api/"));
        let svc = rest.and_then(|r| {
            r.strip_suffix("/request")
                .or_else(|| r.strip_suffix("/response"))
        });
        match svc {
            Some("sport") => ApiService::Sport,
            Some("loco") => ApiService::Loco,
            Some("arm") => ApiService::Arm,
            Some("motion_switcher") => ApiService::MotionSwitcher,
            Some("obstacles_avoid") => ApiService::ObstaclesAvoid,
            Some("agv") => ApiService::Agv,
            Some("robot_state") => ApiService::RobotState,
            Some("uwbswitch") => ApiService::UwbSwitch,
            Some(s) if !s.is_empty() && !s.contains('/') => ApiService::Other,
            _ => ApiService::Unspecified,
        }
    }
}

/// What kind of effect an API call has on motion (for policy).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum ApiClass {
    /// Commands a body velocity (`Move`, `SetVelocity`).
    Velocity,
    /// Stops motion (`StopMove`, `StopCustomAction`).
    Stop,
    /// Changes posture through the built-in controller (stand, sit,
    /// damp, zero torque, body height / attitude).
    Posture,
    /// Changes gait / speed level / balance / control parameters.
    Config,
    /// A pre-programmed whole-body motion (flips, jumps, dances, arm
    /// gestures): the motion is not bounded by anything in the request.
    Trick,
    /// Follows a path or goes to a target position.
    Trajectory,
    /// Hands motor control to / takes it from another channel (motion
    /// switcher, user / internal control, arm SDK).
    ControlHandover,
    /// Reads state; no motion.
    Query,
    /// Not a known API of the service.
    Unknown,
    /// A known API whose parameter could not be read.
    Malformed,
}

/// Fixed meanings of `SetFsmId` values, per the clients' high-level
/// helpers (`Damp() { return SetFsmId(1); }`, ...).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum FsmMeaning {
    ZeroTorque,
    Damp,
    Squat,
    Sit,
    StandUp,
    /// The "Start" (walking controller) state.
    Start,
    /// Lie down (R1 `StandUp2Lie`, 702, `unitree_sdk2py/r1/loco`).
    LieDown,
    /// G1 706: `Squat2StandUp` / `StandUp2Squat` (the same id toggles,
    /// `unitree_sdk2py/g1/loco/g1_loco_client.py`).
    SquatStandToggle,
    /// Not one of the helpers' values for this model, or the model is not
    /// known and the value differs between models.
    Other,
}

/// An interpreted Unitree API request.
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum ApiCall {
    /// A body-velocity `Move`: sport 1008 `{"x": vx, "y": vy, "z": vyaw}`,
    /// obstacles_avoid 1003 `{"x","y","yaw","mode": 0}`, agv 1001
    /// `{"vx","vy","vyaw"}`.
    Move { vx: f64, vy: f64, vyaw: f64 },
    /// Loco `SetVelocity` (7105 / H1 8105):
    /// `{"velocity": [vx, vy, omega], "duration": s}`.
    SetVelocity {
        vx: f64,
        vy: f64,
        vyaw: f64,
        duration: f64,
    },
    /// Sport `StopMove` (1003).
    StopMove,
    /// Sport `Euler` (1007): body attitude, `{"x": roll, "y": pitch, "z": yaw}`.
    Euler { roll: f64, pitch: f64, yaw: f64 },
    /// Loco `SetFsmId` (7101 / H1 8101): `{"data": id}`.
    SetFsmId { fsm_id: i64, meaning: FsmMeaning },
    /// H1 `SetTargetPosition` (8204): `{"x","y","yaw","relative"}`.
    SetTargetPosition {
        x: f64,
        y: f64,
        yaw: f64,
        relative: bool,
    },
    /// A known API: its class, name, and its `data` argument when it has a
    /// scalar one (`SpeedLevel`, `BodyHeight`, `SetStandHeight`, ...).
    Other {
        api_id: i64,
        name: &'static str,
        class: ApiClass,
        data: Option<f64>,
    },
    /// Not in the table for this service / model.
    Unknown { api_id: i64 },
    /// A known API whose parameter is missing or unreadable.
    Malformed {
        api_id: i64,
        name: &'static str,
        /// The class the call would have had.
        intended: ApiClass,
        reason: &'static str,
    },
}

impl ApiCall {
    pub fn class(&self) -> ApiClass {
        match self {
            ApiCall::Move { .. } | ApiCall::SetVelocity { .. } => ApiClass::Velocity,
            ApiCall::StopMove => ApiClass::Stop,
            ApiCall::Euler { .. } => ApiClass::Posture,
            ApiCall::SetFsmId { meaning, .. } => match meaning {
                FsmMeaning::Other => ApiClass::ControlHandover,
                _ => ApiClass::Posture,
            },
            ApiCall::SetTargetPosition { .. } => ApiClass::Trajectory,
            ApiCall::Other { class, .. } => *class,
            ApiCall::Unknown { .. } => ApiClass::Unknown,
            ApiCall::Malformed { .. } => ApiClass::Malformed,
        }
    }

    /// The API's name as in the SDK (`"Move"`, `"SetVelocity"`, ...);
    /// `None` for an unknown id.
    pub fn name(&self) -> Option<&'static str> {
        Some(match self {
            ApiCall::Move { .. } => "Move",
            ApiCall::SetVelocity { .. } => "SetVelocity",
            ApiCall::StopMove => "StopMove",
            ApiCall::Euler { .. } => "Euler",
            ApiCall::SetFsmId { .. } => "SetFsmId",
            ApiCall::SetTargetPosition { .. } => "SetTargetPosition",
            ApiCall::Other { name, .. } | ApiCall::Malformed { name, .. } => name,
            ApiCall::Unknown { .. } => return None,
        })
    }

    /// The commanded body velocity `(vx, vy, vyaw)` of a velocity call; a
    /// malformed velocity call is `(NaN, NaN, NaN)` (its speed cannot be
    /// read, which the firewall treats like a non-finite command);
    /// `StopMove` is zero. `None` for everything else.
    pub fn body_velocity(&self) -> Option<(f64, f64, f64)> {
        match *self {
            ApiCall::Move { vx, vy, vyaw } | ApiCall::SetVelocity { vx, vy, vyaw, .. } => {
                Some((vx, vy, vyaw))
            }
            ApiCall::StopMove => Some((0.0, 0.0, 0.0)),
            ApiCall::Malformed {
                intended: ApiClass::Velocity,
                ..
            } => Some((f64::NAN, f64::NAN, f64::NAN)),
            _ => None,
        }
    }
}

impl fmt::Display for ApiCall {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ApiCall::Unknown { api_id } => write!(f, "unknown api_id {api_id}"),
            ApiCall::Malformed {
                api_id,
                name,
                reason,
                ..
            } => write!(f, "{name} ({api_id}) with unreadable parameter: {reason}"),
            other => write!(f, "{other:?}"),
        }
    }
}

// ---------------------------------------------------------------- tables

/// How a call's parameter is read.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Param {
    /// No argument; the parameter is ignored.
    None,
    /// `{"x","y","z"}` → Move.
    MoveXyz,
    /// `{"x","y","z"}` → Euler.
    EulerXyz,
    /// `{"data": number}` (int or float).
    Data,
    /// `{"data": bool}`.
    DataBool,
    /// `{"velocity": [3], "duration": s}`.
    Velocity,
    /// `{"data": fsm_id}`.
    FsmId,
    /// `{"x","y","yaw","relative"}`.
    TargetPosition,
    /// `{"action_id": n}`.
    ActionId,
    /// obstacles_avoid `Move`: `{"x","y","yaw","mode"}`, mode 0 velocity,
    /// 1 / 2 relative / absolute position.
    ObstaclesMove,
    /// agv `Move`: `{"vx","vy","vyaw"}`.
    AgvMove,
    /// An argument this crate does not interpret (paths, names, arrays);
    /// the parameter must still be valid JSON.
    Opaque,
}

type Entry = (i64, &'static str, ApiClass, Param);

use ApiClass::{Config, ControlHandover, Posture, Query, Stop, Trajectory, Trick, Velocity as Vel};

/// Quadruped `sport` ids with the same meaning and JSON on Go2, B2, A2 and
/// AS2: `unitree/robot/go2/sport/sport_api.hpp`,
/// `unitree/robot/b2/sport/sport_api.hpp`, `unitree/robot/a2/sport/sport_api.hpp`,
/// `unitree/robot/as2/sport/sport_api.hpp`. JSON keys: `Move` uses
/// `go2::JsonizeVec3` (`x`, `y`, `z`) in `a2/sport/sport_client.hpp` /
/// `as2/sport/sport_client.hpp` and `p["x"], p["y"], p["z"]` in
/// `unitree_sdk2py/go2/sport/sport_client.py` / `.../b2/sport/sport_client.py`;
/// `SpeedLevel` uses `JsonizeDataInt` (`data`).
const SPORT_COMMON: &[Entry] = &[
    (1001, "Damp", Posture, Param::None),
    (1002, "BalanceStand", Posture, Param::None),
    (1003, "StopMove", Stop, Param::None),
    (1004, "StandUp", Posture, Param::None),
    (1005, "StandDown", Posture, Param::None),
    (1006, "RecoveryStand", Posture, Param::None),
    (1008, "Move", Vel, Param::MoveXyz),
    (1015, "SpeedLevel", Config, Param::Data),
];

/// Go2 (and Go2-W, whose example uses `go2::SportClient`):
/// `unitree/robot/go2/sport/sport_api.hpp`; keys from
/// `unitree_sdk2py/go2/sport/sport_client.py` (`Euler` x/y/z, `data`).
const SPORT_GO2: &[Entry] = &[
    (1007, "Euler", Posture, Param::EulerXyz),
    (1009, "Sit", Posture, Param::None),
    (1010, "RiseSit", Posture, Param::None),
    (1016, "Hello", Trick, Param::None),
    (1017, "Stretch", Trick, Param::None),
    (1020, "Content", Trick, Param::None),
    (1022, "Dance1", Trick, Param::None),
    (1023, "Dance2", Trick, Param::None),
    (1027, "SwitchJoystick", ControlHandover, Param::DataBool),
    (1028, "Pose", Posture, Param::DataBool),
    (1029, "Scrape", Trick, Param::None),
    (1030, "FrontFlip", Trick, Param::None),
    (1031, "FrontJump", Trick, Param::None),
    (1032, "FrontPounce", Trick, Param::None),
    (1036, "Heart", Trick, Param::None),
    (1061, "StaticWalk", Config, Param::None),
    (1062, "TrotRun", Config, Param::None),
    (1063, "EconomicGait", Config, Param::None),
    (2041, "LeftFlip", Trick, Param::None),
    (2043, "BackFlip", Trick, Param::None),
    (2044, "HandStand", Trick, Param::DataBool),
    (2045, "FreeWalk", Config, Param::None),
    (2046, "FreeBound", Config, Param::DataBool),
    (2047, "FreeJump", Trick, Param::DataBool),
    (2048, "FreeAvoid", Config, Param::DataBool),
    (2049, "ClassicWalk", Config, Param::DataBool),
    (2050, "WalkUpright", Trick, Param::DataBool),
    (2051, "CrossStep", Trick, Param::DataBool),
    (2054, "AutoRecoverySet", Config, Param::DataBool),
    (2055, "AutoRecoveryGet", Query, Param::None),
    (2058, "SwitchAvoidMode", Config, Param::None),
];

/// B2 (and B2-W): `unitree/robot/b2/sport/sport_api.hpp`. The C++ client
/// is compiled; keys from `unitree_sdk2py/b2/sport/sport_client.py`
/// (`SwitchGait` / `BodyHeight` use `data`). `MoveToPos`, `FreeEuler`,
/// `TrajectoryFollow`: argument keys not in the headers, kept opaque.
const SPORT_B2: &[Entry] = &[
    (1011, "SwitchGait", Config, Param::Data),
    (1013, "BodyHeight", Posture, Param::Data),
    (1018, "TrajectoryFollow", Trajectory, Param::Opaque),
    (1019, "ContinuousGait", Config, Param::DataBool),
    (1036, "MoveToPos", Trajectory, Param::Opaque),
    (1038, "SwitchMoveMode", Config, Param::DataBool),
    (1039, "HandStand", Trick, Param::DataBool),
    (1040, "AutoRecoverySet", Config, Param::DataBool),
    (1045, "FreeWalk", Config, Param::None),
    (1049, "ClassicWalk", Config, Param::DataBool),
    (1050, "FastWalk", Config, Param::DataBool),
    (1051, "FreeEuler", Posture, Param::Opaque),
    (1052, "FreeHeight", Config, Param::DataBool),
    (1053, "GaitHeight", Config, Param::DataBool),
    (1101, "VisionWalk", Config, Param::DataBool),
];

/// A2: `unitree/robot/a2/sport/sport_api.hpp`, keys from
/// `a2/sport/sport_client.hpp` (header-only client).
const SPORT_A2: &[Entry] = &[
    (1007, "Euler", Posture, Param::EulerXyz),
    (1009, "BodyPosition", Posture, Param::Opaque),
    (1011, "SwitchGait", Config, Param::Data),
    (1013, "BodyHeight", Posture, Param::Data),
    (1016, "LeftSideGait", Config, Param::Opaque),
    (1017, "RightSideGait", Config, Param::Opaque),
    (1018, "HandStand", Trick, Param::Opaque),
    (1019, "BipedStand", Trick, Param::Opaque),
    (1020, "FrontFlip", Trick, Param::Opaque),
    (1021, "BackFlip", Trick, Param::Opaque),
    (1034, "GetState", Query, Param::Opaque),
    (1035, "Trajectory", Trajectory, Param::Opaque),
    (1040, "SetAutoRecovery", Config, Param::Opaque),
    (1111, "ResetEstimator", Config, Param::Opaque),
];

/// AS2: `unitree/robot/as2/sport/sport_api.hpp`, keys from
/// `as2/sport/sport_client.hpp`.
const SPORT_AS2: &[Entry] = &[
    (1007, "Euler", Posture, Param::EulerXyz),
    (1009, "BodyPosition", Posture, Param::Opaque),
    (1011, "SwitchGait", Config, Param::Data),
    (1013, "BodyHeight", Posture, Param::Data),
    (1016, "LeftSideGait", Config, Param::Opaque),
    (1017, "RightSideGait", Config, Param::Opaque),
    (1018, "HandStand", Trick, Param::Opaque),
    (1019, "BipedStand", Trick, Param::Opaque),
    (1020, "FrontFlip", Trick, Param::Opaque),
    (1021, "BackFlip", Trick, Param::Opaque),
    (1022, "Greeting", Trick, Param::Opaque),
    (1023, "Heart", Trick, Param::Opaque),
    (1024, "Content", Trick, Param::Opaque),
    (1025, "Dance1", Trick, Param::Opaque),
    (1026, "Dance2", Trick, Param::Opaque),
    (1027, "HandShake", Trick, Param::Opaque),
    (1028, "Stretch", Trick, Param::Opaque),
    (1029, "Sit", Posture, Param::Opaque),
    (1030, "FrontJump", Trick, Param::Opaque),
    (1031, "PushUp", Trick, Param::Opaque),
    (1032, "UpJump", Trick, Param::Opaque),
    (1034, "GetState", Query, Param::Opaque),
    (1040, "SetAutoRecovery", Config, Param::Opaque),
    (1041, "SwitchJoystick", ControlHandover, Param::Opaque),
];

/// Humanoid loco on service `sport`, ids shared by G1, H2 and R1
/// (`unitree/robot/{g1,h2,r1}/loco/*_loco_api.hpp`); `SetVelocity` uses
/// `JsonizeVelocityCommand` (`velocity`, `duration`), the setters
/// `go2::JsonizeDataInt` / `JsonizeDataFloat` (`data`).
const LOCO_COMMON: &[Entry] = &[
    (7001, "GetFsmId", Query, Param::None),
    (7002, "GetFsmMode", Query, Param::None),
    (7101, "SetFsmId", Posture, Param::FsmId),
    (7105, "SetVelocity", Vel, Param::Velocity),
    (7107, "SetSpeedMode", Config, Param::Data),
];

/// G1 and H2 (`g1_loco_api.hpp`, `h2_loco_api.hpp`), not R1.
const LOCO_G1_H2: &[Entry] = &[
    (7003, "GetBalanceMode", Query, Param::None),
    (7004, "GetSwingHeight", Query, Param::None),
    (7005, "GetStandHeight", Query, Param::None),
    (7006, "GetPhase", Query, Param::None),
    (7102, "SetBalanceMode", Config, Param::Data),
    (7103, "SetSwingHeight", Config, Param::Data),
    (7104, "SetStandHeight", Posture, Param::Data),
    (7106, "SetArmTask", Trick, Param::Data),
];

/// G1 only (`g1_loco_api.hpp`).
const LOCO_G1: &[Entry] = &[
    (7100, "FsmApi", Trick, Param::Opaque),
    (7110, "SwitchToUserCtrl", ControlHandover, Param::Opaque),
    (7111, "SwitchToInternalCtrl", ControlHandover, Param::Data),
];

/// H2 only (`h2_loco_api.hpp`).
const LOCO_H2: &[Entry] = &[
    (7007, "GetArmSdkStatus", Query, Param::None),
    (7008, "GetAvailableFsmIds", Query, Param::None),
    (7108, "SetPunchApi", Trick, Param::Opaque),
    (7109, "SetArmSdkStatus", ControlHandover, Param::DataBool),
];

/// H1 loco on service `loco` (`unitree/robot/h1/loco/h1_loco_api.hpp`,
/// keys in `h1_loco_client.hpp` / `JsonizeTargetPos`).
const LOCO_H1: &[Entry] = &[
    (8001, "GetFsmId", Query, Param::None),
    (8002, "GetFsmMode", Query, Param::None),
    (8003, "GetBalanceMode", Query, Param::None),
    (8004, "GetSwingHeight", Query, Param::None),
    (8005, "GetStandHeight", Query, Param::None),
    (8006, "GetPhase", Query, Param::None),
    (8101, "SetFsmId", Posture, Param::FsmId),
    (8102, "SetBalanceMode", Config, Param::Data),
    (8103, "SetSwingHeight", Config, Param::Data),
    (8104, "SetStandHeight", Posture, Param::Data),
    (8105, "SetVelocity", Vel, Param::Velocity),
    (8106, "SetPhase", Config, Param::Opaque),
    (8107, "SetArmTask", Trick, Param::Data),
    (8201, "EnableOdom", Config, Param::None),
    (8202, "DisableOdom", Config, Param::None),
    (8203, "GetOdom", Query, Param::None),
    (8204, "SetTargetPosition", Trajectory, Param::TargetPosition),
];

/// Arm actions on service `arm` (G1 `g1_arm_action_api.hpp`, H2
/// `h2_arm_action_api.hpp`; `{"action_id": n}` /
/// `{"action_name": "..."}` in the clients).
const ARM: &[Entry] = &[
    (7106, "ExecuteAction", Trick, Param::ActionId),
    (7107, "GetActionList", Query, Param::None),
    (7108, "ExecuteCustomAction", Trick, Param::Opaque),
    (7113, "StopCustomAction", Stop, Param::None),
];

/// R1 only (`unitree_sdk2py/r1/loco/r1_loco_api.py`: `SetArmTask` 7106,
/// `{"data": task_id}` in `r1_loco_client.py`; not in the C++ header).
const LOCO_R1: &[Entry] = &[(7106, "SetArmTask", Trick, Param::Data)];

/// Go2 `obstacles_avoid` (`unitree/robot/go2/obstacles_avoid/obstacles_avoid_api.hpp`,
/// `unitree_sdk2py/go2/obstacles_avoid/obstacles_avoid_client.py`).
const OBSTACLES_AVOID: &[Entry] = &[
    (1001, "SwitchSet", Config, Param::Opaque),
    (1002, "SwitchGet", Query, Param::None),
    (1003, "Move", Vel, Param::ObstaclesMove),
    (
        1004,
        "UseRemoteCommandFromApi",
        ControlHandover,
        Param::Opaque,
    ),
];

/// G1-D `agv` (`unitree/robot/g1/agv/g1_agv_api.hpp`, `g1_agv_client.hpp`).
/// `HeightAdjust` is a normalised column speed in `[-1, 1]` (`{"data": vz}`),
/// not m/s: kept as a posture call with its value.
const AGV: &[Entry] = &[
    (1001, "Move", Vel, Param::AgvMove),
    (1002, "HeightAdjust", Posture, Param::Data),
];

/// `robot_state` (`unitree/robot/{go2,b2}/robot_state/robot_state_api.hpp`).
/// `ServiceSwitch` (`{"name","switch"}`) can stop or start the sport
/// service, i.e. who drives the motors. `LowPowerSwitch` (B2) is kept as
/// configuration (its motion effect is not documented in the SDK).
const ROBOT_STATE: &[Entry] = &[
    (1001, "ServiceSwitch", ControlHandover, Param::Opaque),
    (1002, "SetReportFreq", Config, Param::Opaque),
    (1003, "ServiceList", Query, Param::None),
    (1004, "LowPowerSwitch", Config, Param::Opaque),
    (1005, "LowPowerStatus", Query, Param::None),
    (1006, "GetPkgVersion", Query, Param::None),
];

/// Go2 UWB tracking, service `uwbswitch` (`unitree/robot/go2/utrack/utrack_api.hpp`):
/// `SwitchSet {"enable"}` makes the robot follow the UWB remote.
const UWB_SWITCH: &[Entry] = &[
    (1001, "SwitchSet", ControlHandover, Param::Opaque),
    (1002, "SwitchGet", Query, Param::None),
    (1003, "IsTracking", Query, Param::None),
];

/// `motion_switcher` (`unitree/robot/b2/motion_switcher/motion_switcher_api.hpp`).
const MOTION_SWITCHER: &[Entry] = &[
    (1001, "CheckMode", Query, Param::None),
    (1002, "SelectMode", ControlHandover, Param::Opaque),
    (1003, "ReleaseMode", ControlHandover, Param::None),
    (1004, "SetSilent", Config, Param::Opaque),
    (1005, "GetSilent", Query, Param::None),
];

fn find(tables: &[&[Entry]], api_id: i64) -> Option<Entry> {
    tables
        .iter()
        .flat_map(|t| t.iter())
        .find(|e| e.0 == api_id)
        .copied()
}

/// The table lookup for `(service, model, api_id)`.
fn lookup(service: ApiService, model: Option<UnitreeModel>, api_id: i64) -> Option<Entry> {
    use UnitreeModel as M;
    // The server dispatches on the low 32 bits (see `ApiRequest::api_id`).
    let api_id = i64::from(dispatched(api_id));
    match service {
        ApiService::Sport if (1000..7000).contains(&api_id) => {
            let specific: &[Entry] = match model {
                Some(M::Go2 | M::Go2W) => SPORT_GO2,
                Some(M::B2 | M::B2W) => SPORT_B2,
                Some(M::A2) => SPORT_A2,
                Some(M::As2) => SPORT_AS2,
                Some(_) => return None,
                None => &[],
            };
            find(&[SPORT_COMMON, specific], api_id)
        }
        ApiService::Sport => {
            let specific: &[&[Entry]] = match model {
                Some(M::G1) => &[LOCO_G1_H2, LOCO_G1],
                Some(M::H2) => &[LOCO_G1_H2, LOCO_H2],
                Some(M::R1) => &[LOCO_R1],
                Some(_) => return None,
                None => &[],
            };
            let mut all: [&[Entry]; 3] = [LOCO_COMMON, &[], &[]];
            for (slot, t) in all.iter_mut().skip(1).zip(specific) {
                *slot = t;
            }
            find(&all, api_id)
        }
        ApiService::Loco => match model {
            Some(M::H1) | None => find(&[LOCO_H1], api_id),
            Some(_) => None,
        },
        ApiService::Arm => match model {
            Some(M::G1 | M::H2) | None => find(&[ARM], api_id),
            Some(_) => None,
        },
        ApiService::MotionSwitcher => find(&[MOTION_SWITCHER], api_id),
        ApiService::ObstaclesAvoid => match model {
            Some(M::Go2 | M::Go2W) | None => find(&[OBSTACLES_AVOID], api_id),
            Some(_) => None,
        },
        ApiService::Agv => match model {
            Some(M::G1) | None => find(&[AGV], api_id),
            Some(_) => None,
        },
        ApiService::RobotState => find(&[ROBOT_STATE], api_id),
        ApiService::UwbSwitch => find(&[UWB_SWITCH], api_id),
        ApiService::Other => None,
        ApiService::Unspecified => {
            // Interpret only ids that no other known service reuses.
            let tables: [&[Entry]; 4] = [SPORT_COMMON, LOCO_COMMON, LOCO_H1, MOTION_SWITCHER];
            let hits = tables
                .iter()
                .chain(
                    [
                        ARM,
                        LOCO_G1_H2,
                        LOCO_R1,
                        OBSTACLES_AVOID,
                        AGV,
                        ROBOT_STATE,
                        UWB_SWITCH,
                    ]
                    .iter(),
                )
                .filter(|t| t.iter().any(|e| e.0 == api_id))
                .count();
            if hits == 1 {
                find(&tables, api_id)
            } else {
                None
            }
        }
    }
}

/// `SetFsmId` value meanings from the clients' helpers:
/// G1 `g1_loco_client.hpp` (ZeroTorque 0, Damp 1, Squat 2, Sit 3,
/// StandUp 4, Start 500), H2 `h2_loco_client.hpp` (Start 601), R1
/// `r1_loco_client.hpp` (0, 1, StandUp 4, Start 811; Squat / Sit commented
/// out), H1 `h1_loco_client.hpp` (0, 1, StandUp 2, Start 204). Python-only
/// helpers (`unitree_sdk2py`): G1 `Lie2StandUp` 702, `Squat2StandUp` /
/// `StandUp2Squat` 706; R1 `Lie2StandUp` 701, `StandUp2Lie` 702.
fn fsm_meaning(model: Option<UnitreeModel>, h1_ids: bool, id: i64) -> FsmMeaning {
    use FsmMeaning as F;
    use UnitreeModel as M;
    let h1 = model == Some(M::H1) || h1_ids;
    match (id, model) {
        (0, _) => F::ZeroTorque,
        (1, _) => F::Damp,
        (2, _) if h1 => F::StandUp,
        (204, _) if h1 => F::Start,
        (_, _) if h1 => F::Other,
        (2, Some(M::G1 | M::H2)) => F::Squat,
        (3, Some(M::G1 | M::H2)) => F::Sit,
        (4, _) => F::StandUp,
        (500, Some(M::G1)) | (601, Some(M::H2)) | (811, Some(M::R1)) => F::Start,
        (702, Some(M::G1)) | (701, Some(M::R1)) => F::StandUp,
        (706, Some(M::G1)) => F::SquatStandToggle,
        (702, Some(M::R1)) => F::LieDown,
        _ => F::Other,
    }
}

fn num(o: &JsonObject<'_>, key: &str) -> Option<f64> {
    o.get(key).and_then(|v| v.as_f64())
}

fn interpret(
    api_id: i64,
    service: ApiService,
    model: Option<UnitreeModel>,
    parameter: &[u8],
) -> ApiCall {
    let Some((_, name, class, param)) = lookup(service, model, api_id) else {
        return ApiCall::Unknown { api_id };
    };
    let malformed = |reason: &'static str| ApiCall::Malformed {
        api_id,
        name,
        intended: class,
        reason,
    };
    // Every known call must carry valid JSON (or nothing): an unparsable
    // parameter is never silently ignored. Calls without an interpreted
    // argument accept a top-level array too (B2 `TrajectoryFollow`); the
    // others need an object.
    let o = if matches!(param, Param::None | Param::Opaque) {
        match validate_document(parameter) {
            Ok(_) => JsonObject::empty(),
            Err(e) => return malformed(e.reason()),
        }
    } else if parameter.is_empty() {
        JsonObject::empty()
    } else {
        match JsonObject::parse(parameter) {
            Ok(o) => o,
            Err(e) => return malformed(e.reason()),
        }
    };
    let other = |data: Option<f64>| ApiCall::Other {
        api_id,
        name,
        class,
        data,
    };
    match param {
        Param::None | Param::Opaque => {
            if name == "StopMove" {
                ApiCall::StopMove
            } else {
                other(None)
            }
        }
        Param::MoveXyz => match (num(&o, "x"), num(&o, "y"), num(&o, "z")) {
            (Some(vx), Some(vy), Some(vyaw)) => ApiCall::Move { vx, vy, vyaw },
            _ => malformed("Move needs numeric x, y, z"),
        },
        Param::EulerXyz => match (num(&o, "x"), num(&o, "y"), num(&o, "z")) {
            (Some(roll), Some(pitch), Some(yaw)) => ApiCall::Euler { roll, pitch, yaw },
            _ => malformed("Euler needs numeric x, y, z"),
        },
        Param::Data => match num(&o, "data") {
            Some(d) => other(Some(d)),
            None => malformed("needs a numeric data member"),
        },
        Param::DataBool => match o.get("data").and_then(|v| v.as_bool()) {
            Some(b) => other(Some(if b { 1.0 } else { 0.0 })),
            None => malformed("needs a boolean data member"),
        },
        Param::Velocity => {
            let v = o.get("velocity").and_then(|v| v.as_f64_array::<3>());
            match (v, num(&o, "duration")) {
                (Some(([vx, vy, vyaw], 3)), Some(duration)) => ApiCall::SetVelocity {
                    vx,
                    vy,
                    vyaw,
                    duration,
                },
                _ => malformed("SetVelocity needs velocity[3] and a numeric duration"),
            }
        }
        Param::FsmId => match o.get("data").and_then(|v: JsonValue<'_>| v.as_i64()) {
            Some(fsm_id) => ApiCall::SetFsmId {
                fsm_id,
                // H1's loco ids are 8xxx (service `loco`).
                meaning: fsm_meaning(model, (8000..9000).contains(&dispatched(api_id)), fsm_id),
            },
            None => malformed("SetFsmId needs an integer data member"),
        },
        Param::TargetPosition => match (
            num(&o, "x"),
            num(&o, "y"),
            num(&o, "yaw"),
            o.get("relative").and_then(|v| v.as_bool()),
        ) {
            (Some(x), Some(y), Some(yaw), Some(relative)) => ApiCall::SetTargetPosition {
                x,
                y,
                yaw,
                relative,
            },
            _ => malformed("SetTargetPosition needs x, y, yaw, relative"),
        },
        Param::ActionId => match o.get("action_id").and_then(|v| v.as_i64()) {
            Some(id) => other(Some(id as f64)),
            None => malformed("ExecuteAction needs an integer action_id"),
        },
        Param::ObstaclesMove => match (
            num(&o, "x"),
            num(&o, "y"),
            num(&o, "yaw"),
            o.get("mode").and_then(|v| v.as_i64()),
        ) {
            (Some(vx), Some(vy), Some(vyaw), Some(0)) => ApiCall::Move { vx, vy, vyaw },
            (Some(_), Some(_), Some(_), Some(mode @ (1 | 2))) => ApiCall::Other {
                api_id,
                name: if mode == 1 {
                    "MoveToIncrementPosition"
                } else {
                    "MoveToAbsolutePosition"
                },
                class: Trajectory,
                data: None,
            },
            _ => malformed("obstacles_avoid Move needs numeric x, y, yaw and mode 0, 1 or 2"),
        },
        Param::AgvMove => match (num(&o, "vx"), num(&o, "vy"), num(&o, "vyaw")) {
            (Some(vx), Some(vy), Some(vyaw)) => ApiCall::Move { vx, vy, vyaw },
            _ => malformed("agv Move needs numeric vx, vy, vyaw"),
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn service_from_topic() {
        assert_eq!(
            ApiService::from_topic("rt/api/sport/request"),
            ApiService::Sport
        );
        assert_eq!(
            ApiService::from_topic("/api/loco/request"),
            ApiService::Loco
        );
        assert_eq!(
            ApiService::from_topic("rt/api/motion_switcher/response"),
            ApiService::MotionSwitcher
        );
        assert_eq!(
            ApiService::from_topic("rt/api/vui/request"),
            ApiService::Other
        );
        assert_eq!(ApiService::from_topic("/cmd_vel"), ApiService::Unspecified);
        assert_eq!(
            ApiService::from_topic("rt/api//request"),
            ApiService::Unspecified
        );
        assert_eq!(
            ApiService::from_topic("rt/api/a/b/request"),
            ApiService::Unspecified
        );
    }

    #[test]
    fn tables_have_no_duplicate_ids() {
        for t in [
            SPORT_COMMON,
            SPORT_GO2,
            SPORT_B2,
            SPORT_A2,
            SPORT_AS2,
            LOCO_COMMON,
            LOCO_G1_H2,
            LOCO_G1,
            LOCO_H2,
            LOCO_H1,
            LOCO_R1,
            ARM,
            MOTION_SWITCHER,
            OBSTACLES_AVOID,
            AGV,
            ROBOT_STATE,
            UWB_SWITCH,
        ] {
            for (i, a) in t.iter().enumerate() {
                assert!(t[i + 1..].iter().all(|b| b.0 != a.0), "{a:?}");
            }
        }
        // Model tables never redefine a common id.
        for t in [SPORT_GO2, SPORT_B2, SPORT_A2, SPORT_AS2] {
            assert!(t.iter().all(|e| SPORT_COMMON.iter().all(|c| c.0 != e.0)));
        }
        for t in [LOCO_G1_H2, LOCO_G1, LOCO_H2] {
            assert!(t.iter().all(|e| LOCO_COMMON.iter().all(|c| c.0 != e.0)));
        }
    }

    #[test]
    fn unspecified_service_skips_reused_ids() {
        // 1003 = StopMove (sport) and ReleaseMode (motion_switcher).
        assert_eq!(lookup(ApiService::Unspecified, None, 1003), None);
        // 1008 Move is unique to sport.
        assert_eq!(
            lookup(ApiService::Unspecified, None, 1008).map(|e| e.1),
            Some("Move")
        );
        // 7106 = SetArmTask (sport) and ExecuteAction (arm).
        assert_eq!(lookup(ApiService::Unspecified, None, 7106), None);
        assert_eq!(
            lookup(ApiService::Unspecified, None, 7105).map(|e| e.1),
            Some("SetVelocity")
        );
        assert_eq!(
            lookup(ApiService::Unspecified, None, 8105).map(|e| e.1),
            Some("SetVelocity")
        );
    }
}
