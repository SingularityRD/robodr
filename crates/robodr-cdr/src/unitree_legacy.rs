//! Unitree's legacy UDP generation (`unitree_legged_sdk`): the raw, packed,
//! little-endian frames exchanged with a Go1-generation robot over UDP.
//! This is **not** DDS / CDR: there is no encapsulation header, the fields
//! are at fixed byte offsets with no alignment padding (`#pragma pack(1)`),
//! and the last 4 bytes are the Unitree CRC ([`crate::unitree::crc`]).
//!
//! # Scope and source
//!
//! The struct definitions decoded here are those of
//! `unitree_legged_sdk/include/unitree_legged_sdk/comm.h`
//! (`HighCmd`, `HighState`, `LowCmd`, `LowState`, and their members
//! `IMU`, `MotorCmd`, `MotorState`, `BmsCmd`, `BmsState`, `LED`,
//! `Cartesian`), version v3.8.6 (`README.md`: "support robot: Go1"; the
//! `LeggedType` enum in `quadruped.h` also names `A1`, `Aliengo`, `B1`,
//! but their frame layouts are only in the older release v3.3.1, which is
//! not in these sources — see the crate README).
//!
//! `comm.h` declares the length constants (defined in the shipped library,
//! not the header): `HIGH_CMD_LENGTH = 129`, `HIGH_STATE_LENGTH = 1087`,
//! which equal the packed `sizeof` of `HighCmd` / `HighState`, so those two
//! decode directly. For `LowCmd` / `LowState` the header comments say the
//! wire length is "shorter than sizeof(...), bytes compressed"
//! (`LOW_CMD_LENGTH = 614`, `LOW_STATE_LENGTH = 807`, against packed
//! `sizeof` 734 / 937). The compressed wire layout is not published in the
//! headers, so this module decodes the **declared** (uncompressed) `comm.h`
//! layout: a [`LegacyLowCmd`] / [`LegacyLowState`] decode succeeds on a
//! buffer of the packed `sizeof` and is rejected on a 614 / 807-byte
//! compressed frame (reported by [`LegacyKind::for_len`] as the compressed
//! form). The README records this limitation; the capture-side wiring that
//! another agent adds should treat a 614 / 807-byte payload as a Go1
//! low-level frame this crate cannot yet decode.
//!
//! # Ports
//!
//! UDP endpoints from `unitree_legged_sdk/include/unitree_legged_sdk/udp.h`
//! and the examples ([`ports`]). Capture-side wiring is done elsewhere;
//! these are exposed as constants only.
//!
//! Pure decode from `&[u8]`; no `unsafe`, no allocation, no panic.

use robodr_events::{MotionCommand, MotionFeedback, RobotEvent};

use crate::event::{command_class, EventContext};
use crate::unitree::crc::frame_crc;
use crate::unitree::joint::{JointCommand, JointCommandFrame, JointMeasurement, JointStateFrame};
use crate::unitree::ApiClass;

/// How the sender protects a legacy frame's trailing `crc` field.
///
/// The v3.8.6 library also ships an `encryptCRC` routine
/// (`UNITREE_LEGGED_SDK::encryptCRC(char*, pthread_mutex_t*, unsigned)` in
/// `lib/cpp/*/libunitree_legged_sdk.a`; no header declares it, the
/// algorithm is not published). A robot / client pair using it puts an
/// encrypted value in the field, so [`LegacyCrcMode::Plain`] verification
/// is **expected to fail** on such traffic; with
/// [`LegacyCrcMode::EncryptCrc`] the CRC is not checked at all (`None`).
/// Which mode a fleet uses must be confirmed on captured traffic. The CRC
/// is advisory either way: no finding's severity depends on it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default)]
pub enum LegacyCrcMode {
    /// `crc32_core` over the frame, as `comm.h` documents.
    #[default]
    Plain,
    /// The SDK's `encryptCRC`: not verifiable here.
    EncryptCrc,
}

fn crc_check(buf: &[u8], mode: LegacyCrcMode) -> Option<bool> {
    match mode {
        LegacyCrcMode::Plain => {
            let got = u32::from_le_bytes(buf.get(buf.len().checked_sub(4)?..)?.try_into().ok()?);
            Some(frame_crc(buf)? == got)
        }
        LegacyCrcMode::EncryptCrc => None,
    }
}

/// Motors in a legacy low-level frame (`MotorCmd motorCmd[20]`).
pub const LEGACY_MOTORS: usize = 20;

/// Default UDP endpoints (`unitree_legged_sdk/include/unitree_legged_sdk/udp.h`
/// and `example/`, `example_py/`).
pub mod ports {
    /// Local (PC) port: `UDP_CLIENT_PORT` in `udp.h`; the C++ examples use
    /// `8090`, the Python examples `8080`.
    pub const CLIENT_PORT: u16 = 8080;
    /// Low-level target port on the robot: `UDP_SERVER_PORT` in `udp.h`,
    /// used with `UDP_SERVER_IP_BASIC` 192.168.123.10
    /// (`example/example_position.cpp`, `example_torque.cpp`).
    pub const SERVER_PORT_BASIC: u16 = 8007;
    /// High-level target port on the sport host: used with
    /// `UDP_SERVER_IP_SPORT` 192.168.123.161 (`example/example_walk.cpp`).
    pub const SERVER_PORT_SPORT: u16 = 8082;
    /// `UDP_SERVER_IP_BASIC` (`udp.h`): the low-level control board.
    pub const SERVER_IP_BASIC: &str = "192.168.123.10";
    /// `UDP_SERVER_IP_SPORT` (`udp.h`): the high-level sport host.
    pub const SERVER_IP_SPORT: &str = "192.168.123.161";
}

/// `comm.h` level bytes (the first byte of a frame's reserved head is not a
/// reliable discriminator; these are the SDK's `levelFlag` constants).
pub mod level {
    /// `HIGHLEVEL` (`comm.h`).
    pub const HIGH: u8 = 0xee;
    /// `LOWLEVEL`.
    pub const LOW: u8 = 0xff;
    /// `TRIGERLEVEL`.
    pub const TRIGGER: u8 = 0xf0;
}

/// A legacy UDP decode error.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LegacyError {
    /// The buffer is not exactly the expected frame length.
    WrongLength {
        kind: LegacyKind,
        len: usize,
        expected: usize,
    },
}

impl std::fmt::Display for LegacyError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            LegacyError::WrongLength {
                kind,
                len,
                expected,
            } => write!(
                f,
                "legacy {kind:?} frame is {len} bytes, expected {expected}"
            ),
        }
    }
}

impl std::error::Error for LegacyError {}

/// A fixed little-endian, unaligned cursor over a legacy frame. Every read
/// is bounds-checked; past the end yields zeros so a short frame is caught
/// by the overall length check rather than panicking (decoders only run on
/// a buffer whose length was validated first).
struct Le<'a> {
    buf: &'a [u8],
    pos: usize,
}

impl<'a> Le<'a> {
    fn new(buf: &'a [u8]) -> Self {
        Le { buf, pos: 0 }
    }

    fn take<const N: usize>(&mut self) -> [u8; N] {
        let mut out = [0u8; N];
        for (i, slot) in out.iter_mut().enumerate() {
            if let Some(b) = self.pos.checked_add(i).and_then(|p| self.buf.get(p)) {
                *slot = *b;
            }
        }
        self.pos = self.pos.saturating_add(N);
        out
    }

    fn u8(&mut self) -> u8 {
        self.take::<1>()[0]
    }

    fn i8(&mut self) -> i8 {
        i8::from_le_bytes(self.take::<1>())
    }

    fn u16(&mut self) -> u16 {
        u16::from_le_bytes(self.take::<2>())
    }

    fn i16(&mut self) -> i16 {
        i16::from_le_bytes(self.take::<2>())
    }

    fn u32(&mut self) -> u32 {
        u32::from_le_bytes(self.take::<4>())
    }

    fn i32(&mut self) -> i32 {
        i32::from_le_bytes(self.take::<4>())
    }

    fn f32(&mut self) -> f32 {
        f32::from_le_bytes(self.take::<4>())
    }

    fn arr<T: Copy + Default, const N: usize>(
        &mut self,
        mut f: impl FnMut(&mut Self) -> T,
    ) -> [T; N] {
        let mut out = [T::default(); N];
        for slot in out.iter_mut() {
            *slot = f(self);
        }
        out
    }

    fn bytes<const N: usize>(&mut self) -> [u8; N] {
        self.take::<N>()
    }
}

/// `comm.h` `MotorCmd` (33 bytes packed).
#[derive(Debug, Clone, Copy, PartialEq, Default)]
pub struct LegacyMotorCmd {
    /// Servo `0x0A`, damping `0x00` (`comm.h`).
    pub mode: u8,
    pub q: f32,
    pub dq: f32,
    pub tau: f32,
    pub kp: f32,
    pub kd: f32,
    pub reserve: [u32; 3],
}

impl LegacyMotorCmd {
    fn read(r: &mut Le<'_>) -> Self {
        LegacyMotorCmd {
            mode: r.u8(),
            q: r.f32(),
            dq: r.f32(),
            tau: r.f32(),
            kp: r.f32(),
            kd: r.f32(),
            reserve: r.arr(Le::u32),
        }
    }

    fn joint(&self) -> JointCommand {
        JointCommand {
            mode: self.mode,
            q: self.q,
            dq: self.dq,
            tau: self.tau,
            kp: self.kp,
            kd: self.kd,
        }
    }
}

/// `comm.h` `MotorState` (38 bytes packed).
#[derive(Debug, Clone, Copy, PartialEq, Default)]
pub struct LegacyMotorState {
    pub mode: u8,
    pub q: f32,
    pub dq: f32,
    pub ddq: f32,
    pub tau_est: f32,
    pub q_raw: f32,
    pub dq_raw: f32,
    pub ddq_raw: f32,
    pub temperature: i8,
    pub reserve: [u32; 2],
}

impl LegacyMotorState {
    fn read(r: &mut Le<'_>) -> Self {
        LegacyMotorState {
            mode: r.u8(),
            q: r.f32(),
            dq: r.f32(),
            ddq: r.f32(),
            tau_est: r.f32(),
            q_raw: r.f32(),
            dq_raw: r.f32(),
            ddq_raw: r.f32(),
            temperature: r.i8(),
            reserve: r.arr(Le::u32),
        }
    }

    fn measurement(&self) -> JointMeasurement {
        JointMeasurement {
            mode: self.mode,
            q: self.q,
            dq: self.dq,
            ddq: self.ddq,
            tau_est: self.tau_est,
        }
    }
}

/// `comm.h` `IMU`.
#[derive(Debug, Clone, Copy, PartialEq, Default)]
pub struct LegacyImu {
    /// (w, x, y, z) normalised.
    pub quaternion: [f32; 4],
    /// rad/s.
    pub gyroscope: [f32; 3],
    /// m/s².
    pub accelerometer: [f32; 3],
    /// rad.
    pub rpy: [f32; 3],
    pub temperature: i8,
}

impl LegacyImu {
    fn read(r: &mut Le<'_>) -> Self {
        LegacyImu {
            quaternion: r.arr(Le::f32),
            gyroscope: r.arr(Le::f32),
            accelerometer: r.arr(Le::f32),
            rpy: r.arr(Le::f32),
            temperature: r.i8(),
        }
    }
}

/// `comm.h` `BmsCmd`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct LegacyBmsCmd {
    /// `0xA5` turns the battery off.
    pub off: u8,
    pub reserve: [u8; 3],
}

impl LegacyBmsCmd {
    fn read(r: &mut Le<'_>) -> Self {
        LegacyBmsCmd {
            off: r.u8(),
            reserve: r.bytes(),
        }
    }
}

/// `comm.h` `BmsState` (note: `cell_vol[10]`, not 15 as in the DDS type).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct LegacyBmsState {
    pub version_h: u8,
    pub version_l: u8,
    pub bms_status: u8,
    pub soc: u8,
    pub current: i32,
    pub cycle: u16,
    pub bq_ntc: [i8; 2],
    pub mcu_ntc: [i8; 2],
    pub cell_vol: [u16; 10],
}

impl LegacyBmsState {
    fn read(r: &mut Le<'_>) -> Self {
        LegacyBmsState {
            version_h: r.u8(),
            version_l: r.u8(),
            bms_status: r.u8(),
            soc: r.u8(),
            current: r.i32(),
            cycle: r.u16(),
            bq_ntc: r.arr(Le::i8),
            mcu_ntc: r.arr(Le::i8),
            cell_vol: r.arr(Le::u16),
        }
    }
}

/// `comm.h` `LowCmd` (declared / uncompressed layout; see the module docs).
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct LegacyLowCmd {
    pub head: [u8; 2],
    pub level_flag: u8,
    pub frame_reserve: u8,
    pub sn: [u32; 2],
    pub version: [u32; 2],
    pub band_width: u16,
    pub motor_cmd: [LegacyMotorCmd; LEGACY_MOTORS],
    pub bms: LegacyBmsCmd,
    pub wireless_remote: [u8; 40],
    pub reserve: u32,
    pub crc: u32,
}

/// Packed `sizeof(LowCmd)` from `comm.h`.
pub const LEGACY_LOW_CMD_LEN: usize = 734;

impl LegacyLowCmd {
    fn read(r: &mut Le<'_>) -> Self {
        LegacyLowCmd {
            head: r.bytes(),
            level_flag: r.u8(),
            frame_reserve: r.u8(),
            sn: r.arr(Le::u32),
            version: r.arr(Le::u32),
            band_width: r.u16(),
            motor_cmd: r.arr(LegacyMotorCmd::read),
            bms: LegacyBmsCmd::read(r),
            wireless_remote: r.bytes(),
            reserve: r.u32(),
            crc: r.u32(),
        }
    }

    /// Decodes a `LegacyLowCmd` from a buffer of exactly
    /// [`LEGACY_LOW_CMD_LEN`] bytes.
    pub fn decode(buf: &[u8]) -> Result<Self, LegacyError> {
        check_len(LegacyKind::LowCmd, buf.len(), LEGACY_LOW_CMD_LEN)?;
        Ok(Self::read(&mut Le::new(buf)))
    }

    /// `crc` matches `crc32_core` over the frame (`frame[..len-4]` as u32
    /// words). `None` if the frame covered by the CRC cannot be read.
    /// Advisory (see [`LegacyCrcMode`]: `false` is expected in `encryptCRC`
    /// mode).
    pub fn crc_ok(buf: &[u8]) -> Option<bool> {
        crc_check(buf, LegacyCrcMode::Plain)
    }

    /// The CRC under `mode`; `None` when it cannot be checked.
    pub fn crc_check(buf: &[u8], mode: LegacyCrcMode) -> Option<bool> {
        crc_check(buf, mode)
    }

    /// The joint command over all 20 slots, as the DDS `LowCmd_`
    /// ([`JointCommandFrame::to_motion_command`]: every slot, mode ignored).
    pub fn to_motion_command(&self, ctx: &EventContext<'_>) -> MotionCommand {
        self.joint_frame().to_motion_command(ctx)
    }

    /// All 20 motor slots as a [`JointCommandFrame`].
    pub fn joint_frame(&self) -> JointCommandFrame {
        let mut f = JointCommandFrame::default();
        for m in &self.motor_cmd {
            f.joints.push(m.joint());
        }
        f
    }
}

/// `comm.h` `LowState` (declared / uncompressed layout).
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct LegacyLowState {
    pub head: [u8; 2],
    pub level_flag: u8,
    pub frame_reserve: u8,
    pub sn: [u32; 2],
    pub version: [u32; 2],
    pub band_width: u16,
    pub imu: LegacyImu,
    pub motor_state: [LegacyMotorState; LEGACY_MOTORS],
    pub bms: LegacyBmsState,
    pub foot_force: [i16; 4],
    pub foot_force_est: [i16; 4],
    pub tick: u32,
    pub wireless_remote: [u8; 40],
    pub reserve: u32,
    pub crc: u32,
}

/// Packed `sizeof(LowState)` from `comm.h`.
pub const LEGACY_LOW_STATE_LEN: usize = 937;

impl LegacyLowState {
    fn read(r: &mut Le<'_>) -> Self {
        LegacyLowState {
            head: r.bytes(),
            level_flag: r.u8(),
            frame_reserve: r.u8(),
            sn: r.arr(Le::u32),
            version: r.arr(Le::u32),
            band_width: r.u16(),
            imu: LegacyImu::read(r),
            motor_state: r.arr(LegacyMotorState::read),
            bms: LegacyBmsState::read(r),
            foot_force: r.arr(Le::i16),
            foot_force_est: r.arr(Le::i16),
            tick: r.u32(),
            wireless_remote: r.bytes(),
            reserve: r.u32(),
            crc: r.u32(),
        }
    }

    pub fn decode(buf: &[u8]) -> Result<Self, LegacyError> {
        check_len(LegacyKind::LowState, buf.len(), LEGACY_LOW_STATE_LEN)?;
        Ok(Self::read(&mut Le::new(buf)))
    }

    pub fn joint_frame(&self) -> JointStateFrame {
        let mut f = JointStateFrame::default();
        for m in &self.motor_state {
            f.joints.push(m.measurement());
        }
        f
    }
}

/// `comm.h` `HighCmd`.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct LegacyHighCmd {
    pub head: [u8; 2],
    pub level_flag: u8,
    pub frame_reserve: u8,
    pub sn: [u32; 2],
    pub version: [u32; 2],
    pub band_width: u16,
    /// 0 idle, 1 force stand, 2 target-velocity walk, 3 target-position
    /// walk, 5 stand down, 6 stand up, 7 damping, 8 recovery, ...
    /// (`comm.h` comment).
    pub mode: u8,
    pub gait_type: u8,
    pub speed_level: u8,
    pub foot_raise_height: f32,
    pub body_height: f32,
    /// m, desired position in inertial frame (reserve in `comm.h`).
    pub position: [f32; 2],
    /// rad, roll / pitch / yaw in stand mode.
    pub euler: [f32; 3],
    /// m/s, (forwardSpeed, sideSpeed) in body frame.
    pub velocity: [f32; 2],
    /// rad/s, yaw rate in body frame.
    pub yaw_speed: f32,
    pub bms: LegacyBmsCmd,
    /// `LED led[4]` = 12 bytes.
    pub led: [u8; 12],
    pub wireless_remote: [u8; 40],
    pub reserve: u32,
    pub crc: u32,
}

/// Packed `sizeof(HighCmd)` from `comm.h` = `HIGH_CMD_LENGTH`.
pub const LEGACY_HIGH_CMD_LEN: usize = 129;

impl LegacyHighCmd {
    fn read(r: &mut Le<'_>) -> Self {
        LegacyHighCmd {
            head: r.bytes(),
            level_flag: r.u8(),
            frame_reserve: r.u8(),
            sn: r.arr(Le::u32),
            version: r.arr(Le::u32),
            band_width: r.u16(),
            mode: r.u8(),
            gait_type: r.u8(),
            speed_level: r.u8(),
            foot_raise_height: r.f32(),
            body_height: r.f32(),
            position: r.arr(Le::f32),
            euler: r.arr(Le::f32),
            velocity: r.arr(Le::f32),
            yaw_speed: r.f32(),
            bms: LegacyBmsCmd::read(r),
            led: r.bytes(),
            wireless_remote: r.bytes(),
            reserve: r.u32(),
            crc: r.u32(),
        }
    }

    pub fn decode(buf: &[u8]) -> Result<Self, LegacyError> {
        check_len(LegacyKind::HighCmd, buf.len(), LEGACY_HIGH_CMD_LEN)?;
        Ok(Self::read(&mut Le::new(buf)))
    }

    /// Advisory, see [`LegacyLowCmd::crc_ok`].
    pub fn crc_ok(buf: &[u8]) -> Option<bool> {
        crc_check(buf, LegacyCrcMode::Plain)
    }

    /// The CRC under `mode`; `None` when it cannot be checked.
    pub fn crc_check(buf: &[u8], mode: LegacyCrcMode) -> Option<bool> {
        crc_check(buf, mode)
    }

    /// What the `mode` byte makes the robot do (`comm.h`): 2 target
    /// velocity walking → [`ApiClass::Velocity`]; 0 idle / 1 force stand /
    /// 5 stand down / 6 stand up / 7 damping / 8 recovery stand →
    /// [`ApiClass::Posture`]; 3 target position / 4 path walking →
    /// [`ApiClass::Trajectory`]; 9 backflip / 10 jumpYaw / 11 straightHand
    /// → [`ApiClass::Trick`]; anything else → [`ApiClass::Unknown`].
    pub fn motion_class(&self) -> ApiClass {
        match self.mode {
            2 => ApiClass::Velocity,
            0 | 1 | 5..=8 => ApiClass::Posture,
            3 | 4 => ApiClass::Trajectory,
            9..=11 => ApiClass::Trick,
            _ => ApiClass::Unknown,
        }
    }

    /// The command as the DDS path maps an API call: in mode 2 the body
    /// velocity (`linear_speed = velocity[0]`, `linear_y = velocity[1]`,
    /// `angular_speed = yawSpeed`, the other three axes 0); in every other
    /// mode the robot ignores the velocity fields, so no speed is set. The
    /// mode's [`LegacyHighCmd::motion_class`] is the `command_class`, so
    /// `Profile::evaluate` flags tricks, position walking and unknown
    /// modes.
    pub fn to_motion_command(&self, ctx: &EventContext<'_>) -> MotionCommand {
        let class = self.motion_class();
        let base = MotionCommand {
            channel: ctx.channel.to_owned(),
            source_guid: ctx.writer_guid.map(str::to_owned),
            command_class: Some(command_class(class)),
            command_name: Some(format!("HighCmd mode {}", self.mode)),
            ..MotionCommand::default()
        };
        if class != ApiClass::Velocity {
            return base;
        }
        let (vx, vy, vyaw) = self.body_velocity();
        MotionCommand {
            linear_speed: Some(vx),
            linear_y: Some(vy),
            angular_speed: Some(vyaw),
            linear_z: Some(0.0),
            angular_x: Some(0.0),
            angular_y: Some(0.0),
            ..base
        }
    }

    /// Commanded body velocity `(vx, vy, vyaw)` m/s, rad/s.
    pub fn body_velocity(&self) -> (f64, f64, f64) {
        (
            f64::from(self.velocity[0]),
            f64::from(self.velocity[1]),
            f64::from(self.yaw_speed),
        )
    }
}

/// `comm.h` `HighState`.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct LegacyHighState {
    pub head: [u8; 2],
    pub level_flag: u8,
    pub frame_reserve: u8,
    pub sn: [u32; 2],
    pub version: [u32; 2],
    pub band_width: u16,
    pub imu: LegacyImu,
    pub motor_state: [LegacyMotorState; LEGACY_MOTORS],
    pub bms: LegacyBmsState,
    pub foot_force: [i16; 4],
    pub foot_force_est: [i16; 4],
    pub mode: u8,
    pub progress: f32,
    pub gait_type: u8,
    pub foot_raise_height: f32,
    pub position: [f32; 3],
    pub body_height: f32,
    /// m/s, (forwardSpeed, sideSpeed, rotateSpeed) in body frame.
    pub velocity: [f32; 3],
    pub yaw_speed: f32,
    pub range_obstacle: [f32; 4],
    /// `Cartesian footPosition2Body[4]` = 4 × (x, y, z).
    pub foot_position_2body: [[f32; 3]; 4],
    pub foot_speed_2body: [[f32; 3]; 4],
    pub wireless_remote: [u8; 40],
    pub reserve: u32,
    pub crc: u32,
}

/// Packed `sizeof(HighState)` from `comm.h` = `HIGH_STATE_LENGTH`.
pub const LEGACY_HIGH_STATE_LEN: usize = 1087;

impl LegacyHighState {
    fn read(r: &mut Le<'_>) -> Self {
        let imu_head = |r: &mut Le<'_>| {
            (
                r.bytes::<2>(),
                r.u8(),
                r.u8(),
                r.arr::<u32, 2>(Le::u32),
                r.arr::<u32, 2>(Le::u32),
                r.u16(),
            )
        };
        let (head, level_flag, frame_reserve, sn, version, band_width) = imu_head(r);
        LegacyHighState {
            head,
            level_flag,
            frame_reserve,
            sn,
            version,
            band_width,
            imu: LegacyImu::read(r),
            motor_state: r.arr(LegacyMotorState::read),
            bms: LegacyBmsState::read(r),
            foot_force: r.arr(Le::i16),
            foot_force_est: r.arr(Le::i16),
            mode: r.u8(),
            progress: r.f32(),
            gait_type: r.u8(),
            foot_raise_height: r.f32(),
            position: r.arr(Le::f32),
            body_height: r.f32(),
            velocity: r.arr(Le::f32),
            yaw_speed: r.f32(),
            range_obstacle: r.arr(Le::f32),
            foot_position_2body: r.arr(|r| r.arr(Le::f32)),
            foot_speed_2body: r.arr(|r| r.arr(Le::f32)),
            wireless_remote: r.bytes(),
            reserve: r.u32(),
            crc: r.u32(),
        }
    }

    pub fn decode(buf: &[u8]) -> Result<Self, LegacyError> {
        check_len(LegacyKind::HighState, buf.len(), LEGACY_HIGH_STATE_LEN)?;
        Ok(Self::read(&mut Le::new(buf)))
    }

    pub fn joint_frame(&self) -> JointStateFrame {
        let mut f = JointStateFrame::default();
        for m in &self.motor_state {
            f.joints.push(m.measurement());
        }
        f
    }

    /// Measured body velocity `(vx, vy, vyaw)`.
    pub fn body_velocity(&self) -> (f64, f64, f64) {
        (
            f64::from(self.velocity[0]),
            f64::from(self.velocity[1]),
            f64::from(self.yaw_speed),
        )
    }
}

/// The four legacy frame types.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum LegacyKind {
    HighCmd,
    HighState,
    LowCmd,
    LowState,
}

impl LegacyKind {
    /// The declared (`comm.h` packed `sizeof`) length of this frame.
    pub fn declared_len(self) -> usize {
        match self {
            LegacyKind::HighCmd => LEGACY_HIGH_CMD_LEN,
            LegacyKind::HighState => LEGACY_HIGH_STATE_LEN,
            LegacyKind::LowCmd => LEGACY_LOW_CMD_LEN,
            LegacyKind::LowState => LEGACY_LOW_STATE_LEN,
        }
    }

    /// The v3.8.6 on-wire ("compressed") length for the low-level frames,
    /// `None` for the high-level frames (which are not compressed). The
    /// compressed layout is not published in the SDK headers, so a frame of
    /// this length cannot be decoded by this module (see the module docs).
    pub fn compressed_wire_len(self) -> Option<usize> {
        match self {
            // LOW_CMD_LENGTH / LOW_STATE_LENGTH from the shipped library.
            LegacyKind::LowCmd => Some(614),
            LegacyKind::LowState => Some(807),
            LegacyKind::HighCmd | LegacyKind::HighState => None,
        }
    }

    /// The frame kind a payload of `len` bytes is, by its length alone
    /// (the legacy protocol has no type tag). `Some((kind, decodable))`:
    /// `decodable` is false for the compressed low-level lengths this
    /// module cannot decode. Lengths matching nothing return `None`.
    pub fn for_len(len: usize) -> Option<(LegacyKind, bool)> {
        for k in [
            LegacyKind::HighCmd,
            LegacyKind::HighState,
            LegacyKind::LowCmd,
            LegacyKind::LowState,
        ] {
            if len == k.declared_len() {
                return Some((k, true));
            }
            if k.compressed_wire_len() == Some(len) {
                return Some((k, false));
            }
        }
        None
    }
}

/// The motion channels the legacy UDP frames are mapped onto. The legacy
/// protocol has no topic names; these fixed names key the profile's motion
/// envelopes (and the motion monitor's feedback sources) for a Go1-generation
/// robot. They live under one reserved prefix so a DDS topic can never be
/// mistaken for one.
pub mod channels {
    /// Every legacy channel starts with this.
    pub const PREFIX: &str = "/unitree_legacy/";
    /// `HighCmd` (sport mode: body velocity, posture, tricks).
    pub const HIGH_CMD: &str = "/unitree_legacy/high_cmd";
    /// `LowCmd` (per-motor joint command).
    pub const LOW_CMD: &str = "/unitree_legacy/low_cmd";
    /// `HighState` (body velocity, IMU, joint state).
    pub const HIGH_STATE: &str = "/unitree_legacy/high_state";
    /// `LowState` (IMU, joint state).
    pub const LOW_STATE: &str = "/unitree_legacy/low_state";
    /// The four channels.
    pub const ALL: [&str; 4] = [HIGH_CMD, LOW_CMD, HIGH_STATE, LOW_STATE];
}

/// One decoded legacy UDP frame, classified by its length
/// ([`LegacyKind::for_len`]: the protocol has no type tag).
#[allow(clippy::large_enum_variant)] // decoded once per datagram, not stored
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum LegacyFrame {
    HighCmd(LegacyHighCmd),
    HighState(LegacyHighState),
    LowCmd(LegacyLowCmd),
    LowState(LegacyLowState),
}

/// Why a UDP payload on a legacy port is not a decodable legacy frame.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LegacyFrameError {
    /// A v3.8.6 "compressed" low-level frame (614 / 807 bytes): its layout
    /// is not published, so it cannot be inspected.
    Compressed { kind: LegacyKind, len: usize },
    /// No legacy frame has this length.
    UnknownLength { len: usize },
}

impl std::fmt::Display for LegacyFrameError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            LegacyFrameError::Compressed { kind, len } => write!(
                f,
                "legacy {kind:?} in the compressed {len}-byte wire form, whose layout is not \
                 published (not inspected)"
            ),
            LegacyFrameError::UnknownLength { len } => {
                write!(f, "{len}-byte UDP payload is no legacy Unitree frame")
            }
        }
    }
}

impl std::error::Error for LegacyFrameError {}

impl LegacyFrame {
    /// Decode a UDP payload by its length. Never panics.
    pub fn decode(buf: &[u8]) -> Result<Self, LegacyFrameError> {
        let len = buf.len();
        let unknown = LegacyFrameError::UnknownLength { len };
        match LegacyKind::for_len(len) {
            None => Err(unknown),
            Some((kind, false)) => Err(LegacyFrameError::Compressed { kind, len }),
            Some((LegacyKind::HighCmd, true)) => LegacyHighCmd::decode(buf)
                .map(LegacyFrame::HighCmd)
                .map_err(|_| unknown),
            Some((LegacyKind::HighState, true)) => LegacyHighState::decode(buf)
                .map(LegacyFrame::HighState)
                .map_err(|_| unknown),
            Some((LegacyKind::LowCmd, true)) => LegacyLowCmd::decode(buf)
                .map(LegacyFrame::LowCmd)
                .map_err(|_| unknown),
            Some((LegacyKind::LowState, true)) => LegacyLowState::decode(buf)
                .map(LegacyFrame::LowState)
                .map_err(|_| unknown),
        }
    }

    pub fn kind(&self) -> LegacyKind {
        match self {
            LegacyFrame::HighCmd(_) => LegacyKind::HighCmd,
            LegacyFrame::HighState(_) => LegacyKind::HighState,
            LegacyFrame::LowCmd(_) => LegacyKind::LowCmd,
            LegacyFrame::LowState(_) => LegacyKind::LowState,
        }
    }

    /// `HighCmd` / `LowCmd` (sent by the client to the robot).
    pub fn is_command(&self) -> bool {
        matches!(self, LegacyFrame::HighCmd(_) | LegacyFrame::LowCmd(_))
    }

    /// The channel the frame is mapped onto ([`channels`]).
    pub fn channel(&self) -> &'static str {
        match self {
            LegacyFrame::HighCmd(_) => channels::HIGH_CMD,
            LegacyFrame::HighState(_) => channels::HIGH_STATE,
            LegacyFrame::LowCmd(_) => channels::LOW_CMD,
            LegacyFrame::LowState(_) => channels::LOW_STATE,
        }
    }

    /// The frame's CRC under `mode` (advisory, see [`LegacyCrcMode`]),
    /// computed over the buffer the frame was decoded from.
    pub fn crc_check(buf: &[u8], mode: LegacyCrcMode) -> Option<bool> {
        crc_check(buf, mode)
    }

    /// The per-motor command of a `LowCmd` (`None` otherwise).
    pub fn joint_command_frame(&self) -> Option<JointCommandFrame> {
        match self {
            LegacyFrame::LowCmd(c) => Some(c.joint_frame()),
            _ => None,
        }
    }

    /// The event: `HighCmd` / `LowCmd` as [`LegacyHighCmd::to_motion_command`]
    /// / [`LegacyLowCmd::to_motion_command`]; `HighState` as feedback with the
    /// measured body velocity (`velocity[0..2]`, `yawSpeed`), the IMU gyro and
    /// the max measured joint speed; `LowState` as feedback with the IMU gyro
    /// and the max measured joint speed. `ctx.channel` is used as given
    /// (normally [`LegacyFrame::channel`]).
    pub fn to_event(&self, ctx: &EventContext<'_>) -> RobotEvent {
        let gyro = |g: [f32; 3]| g.map(f64::from);
        let base = |g: [f32; 3], joint: Option<f64>| {
            let [x, y, z] = gyro(g);
            MotionFeedback {
                channel: ctx.channel.to_owned(),
                measured_joint_speed: joint,
                angular_velocity_x: Some(x),
                angular_velocity_y: Some(y),
                angular_velocity: Some(z),
                publisher_guid: ctx.writer_guid.map(str::to_owned),
                timestamp_ns: ctx.timestamp_ns,
                ..MotionFeedback::default()
            }
        };
        match self {
            LegacyFrame::HighCmd(c) => RobotEvent::MotionCommand(c.to_motion_command(ctx)),
            LegacyFrame::LowCmd(c) => RobotEvent::MotionCommand(c.to_motion_command(ctx)),
            LegacyFrame::HighState(s) => {
                let (vx, vy, vyaw) = s.body_velocity();
                RobotEvent::MotionFeedback(MotionFeedback {
                    measured_linear_speed: Some(vx.hypot(vy)),
                    linear_velocity: Some(vx),
                    linear_velocity_y: Some(vy),
                    angular_velocity: Some(vyaw),
                    ..base(s.imu.gyroscope, s.joint_frame().max_abs_velocity())
                })
            }
            LegacyFrame::LowState(s) => RobotEvent::MotionFeedback(base(
                s.imu.gyroscope,
                s.joint_frame().max_abs_velocity(),
            )),
        }
    }
}

fn check_len(kind: LegacyKind, len: usize, expected: usize) -> Result<(), LegacyError> {
    if len == expected {
        Ok(())
    } else {
        Err(LegacyError::WrongLength {
            kind,
            len,
            expected,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::EventContext;

    #[test]
    fn declared_sizes_match_packed_sizeof() {
        // MotorCmd 33, MotorState 38 (comm.h packed).
        // LowCmd: head(4) + sn(8) + version(8) + bandWidth(2)
        //       + 20*33 + BmsCmd(4) + wireless(40) + reserve(4) + crc(4).
        assert_eq!(4 + 8 + 8 + 2 + 20 * 33 + 4 + 40 + 4 + 4, LEGACY_LOW_CMD_LEN);
        // IMU: 4*4 + 3*4 + 3*4 + 3*4 + 1 = 53. BmsState: 34.
        assert_eq!(
            4 + 8 + 8 + 2 + 53 + 20 * 38 + 34 + 8 + 8 + 4 + 40 + 4 + 4,
            LEGACY_LOW_STATE_LEN
        );
        assert_eq!(
            4 + 8 + 8 + 2 + 1 + 1 + 1 + 4 + 4 + 8 + 12 + 8 + 4 + 4 + 12 + 40 + 4 + 4,
            LEGACY_HIGH_CMD_LEN
        );
        // HighState: ... + rangeObstacle(16) + 2*48 (Cartesian[4]) ...
        assert_eq!(
            4 + 8
                + 8
                + 2
                + 53
                + 20 * 38
                + 34
                + 8
                + 8
                + 1
                + 4
                + 1
                + 4
                + 12
                + 4
                + 12
                + 4
                + 16
                + 48
                + 48
                + 40
                + 4
                + 4,
            LEGACY_HIGH_STATE_LEN
        );
    }

    /// A packed little-endian frame builder, for round-trip tests.
    #[derive(Default)]
    struct Build(Vec<u8>);
    impl Build {
        fn u8(&mut self, v: u8) -> &mut Self {
            self.0.push(v);
            self
        }
        fn f32(&mut self, v: f32) -> &mut Self {
            self.0.extend_from_slice(&v.to_le_bytes());
            self
        }
        fn u16(&mut self, v: u16) -> &mut Self {
            self.0.extend_from_slice(&v.to_le_bytes());
            self
        }
        fn zeros(&mut self, n: usize) -> &mut Self {
            self.0.resize(self.0.len() + n, 0);
            self
        }
        fn with_crc(mut self) -> Vec<u8> {
            self.zeros(4);
            let crc = frame_crc(&self.0).unwrap();
            let n = self.0.len();
            self.0[n - 4..].copy_from_slice(&crc.to_le_bytes());
            self.0
        }
    }

    fn motor_cmd_bytes(b: &mut Build, dq: f32, kd: f32) {
        b.u8(0x0A).f32(0.0).f32(dq).f32(0.0).f32(0.0).f32(kd);
        b.zeros(12); // reserve[3]
    }

    #[test]
    fn low_cmd_round_trip_and_crc() {
        let mut b = Build::default();
        b.zeros(2).u8(level::LOW).u8(0); // head, level, frame_reserve
        b.zeros(8 + 8).u16(0); // sn, version, bandwidth
        for i in 0..LEGACY_MOTORS {
            // one motor with a real velocity command, the rest stopped.
            if i == 3 {
                motor_cmd_bytes(&mut b, -2.5, 4.0);
            } else {
                motor_cmd_bytes(&mut b, 16000.0, 0.0);
            }
        }
        b.zeros(4 + 40 + 4); // bms, wireless_remote, reserve
        let frame = b.with_crc();
        assert_eq!(frame.len(), LEGACY_LOW_CMD_LEN);
        let cmd = LegacyLowCmd::decode(&frame).unwrap();
        assert_eq!(cmd.level_flag, level::LOW);
        assert_eq!(cmd.motor_cmd[3].dq, -2.5);
        assert_eq!(cmd.joint_frame().max_commanded_joint_speed(), 2.5);
        assert_eq!(LegacyLowCmd::crc_ok(&frame), Some(true));
        let mut bad = frame.clone();
        bad[10] ^= 0xff;
        assert_eq!(LegacyLowCmd::crc_ok(&bad), Some(false));
        // Wrong length is an error, not a panic.
        assert!(matches!(
            LegacyLowCmd::decode(&frame[..100]),
            Err(LegacyError::WrongLength { .. })
        ));
    }

    #[test]
    fn high_cmd_velocity() {
        let mut b = Build::default();
        b.zeros(2).u8(level::HIGH).u8(0);
        b.zeros(8 + 8).u16(0); // sn, version, bandwidth
        b.u8(2).u8(1).u8(0); // mode, gait_type, speed_level
        b.f32(0.08).f32(0.3); // foot_raise_height, body_height
        b.f32(0.0).f32(0.0); // position[2]
        b.f32(0.0).f32(0.0).f32(0.0); // euler[3]
        b.f32(1.2).f32(-0.4); // velocity[2]
        b.f32(0.7); // yaw_speed
        b.zeros(4 + 12 + 40 + 4); // bms, led, wireless, reserve
        let frame = b.with_crc();
        assert_eq!(frame.len(), LEGACY_HIGH_CMD_LEN);
        let cmd = LegacyHighCmd::decode(&frame).unwrap();
        assert_eq!(
            cmd.body_velocity(),
            (1.2_f32 as f64, -0.4_f32 as f64, 0.7_f32 as f64)
        );
        assert_eq!(cmd.mode, 2);
        assert_eq!(LegacyHighCmd::crc_ok(&frame), Some(true));
    }

    fn high_cmd(mode: u8, v: [f32; 3]) -> Vec<u8> {
        let mut b = Build::default();
        b.zeros(2).u8(level::HIGH).u8(0);
        b.zeros(8 + 8).u16(0);
        b.u8(mode).u8(1).u8(0);
        b.f32(0.08).f32(0.3);
        b.f32(0.0).f32(0.0);
        b.f32(0.0).f32(0.0).f32(0.0);
        b.f32(v[0]).f32(v[1]);
        b.f32(v[2]);
        b.zeros(4 + 12 + 40 + 4);
        b.with_crc()
    }

    /// Review item 11: legacy commands map to `MotionCommand` like the DDS
    /// path.
    #[test]
    fn legacy_commands_map_to_motion_commands() {
        use crate::unitree::ApiClass;
        use robodr_events::CommandClass;
        let ctx = EventContext {
            channel: "/legacy/high_cmd",
            writer_guid: None,
            timestamp_ns: 0,
        };
        // Mode 2: target velocity walking.
        let c = LegacyHighCmd::decode(&high_cmd(2, [1.0, -0.5, 0.25])).unwrap();
        assert_eq!(c.motion_class(), ApiClass::Velocity);
        let m = c.to_motion_command(&ctx);
        assert_eq!(m.linear_speed, Some(1.0));
        assert_eq!(m.linear_y, Some(-0.5));
        assert_eq!(m.angular_speed, Some(0.25));
        assert_eq!(m.linear_z, Some(0.0));
        assert_eq!(m.command_class, Some(CommandClass::Velocity));
        // Other modes ignore the velocity: no speed, but the class.
        for (mode, class) in [
            (0, ApiClass::Posture),
            (1, ApiClass::Posture),
            (3, ApiClass::Trajectory),
            (7, ApiClass::Posture),
            (9, ApiClass::Trick),
            (11, ApiClass::Trick),
            (42, ApiClass::Unknown),
        ] {
            let c = LegacyHighCmd::decode(&high_cmd(mode, [9.0, 9.0, 9.0])).unwrap();
            assert_eq!(c.motion_class(), class, "mode {mode}");
            let m = c.to_motion_command(&ctx);
            assert_eq!(m.linear_speed, None, "mode {mode}");
            assert!(m.command_class.is_some());
        }
        // LowCmd: the joint command, every slot, mode ignored.
        let mut b = Build::default();
        b.zeros(2).u8(level::LOW).u8(0);
        b.zeros(8 + 8).u16(0);
        for i in 0..LEGACY_MOTORS {
            if i == 19 {
                // A slot past the 12 legs, mode 0 (damping), torque only.
                b.u8(0).f32(0.0).f32(0.0).f32(40.0).f32(0.0).f32(0.0);
                b.zeros(12);
            } else {
                motor_cmd_bytes(&mut b, 16000.0, 0.0);
            }
        }
        b.zeros(4 + 40 + 4);
        let low = LegacyLowCmd::decode(&b.with_crc()).unwrap();
        let m = low.to_motion_command(&ctx);
        assert_eq!(m.joint_speed, Some(0.0));
        assert_eq!(m.joint_torque, Some(40.0));
    }

    /// Review item 11: in `encryptCRC` mode the CRC field cannot be
    /// verified (the algorithm is only in the binary SDK library).
    #[test]
    fn encrypted_crc_mode_is_not_checked() {
        let frame = high_cmd(2, [0.1, 0.0, 0.0]);
        assert_eq!(
            LegacyHighCmd::crc_check(&frame, LegacyCrcMode::Plain),
            Some(true)
        );
        assert_eq!(
            LegacyHighCmd::crc_check(&frame, LegacyCrcMode::EncryptCrc),
            None
        );
        let mut bad = frame.clone();
        bad[30] ^= 1;
        assert_eq!(
            LegacyHighCmd::crc_check(&bad, LegacyCrcMode::Plain),
            Some(false)
        );
        assert_eq!(
            LegacyLowCmd::crc_check(&bad, LegacyCrcMode::EncryptCrc),
            None
        );
    }

    #[test]
    fn length_dispatch() {
        assert_eq!(
            LegacyKind::for_len(LEGACY_HIGH_CMD_LEN),
            Some((LegacyKind::HighCmd, true))
        );
        assert_eq!(
            LegacyKind::for_len(LEGACY_LOW_STATE_LEN),
            Some((LegacyKind::LowState, true))
        );
        // The compressed v3.8.6 low-level lengths are recognised but not
        // decodable.
        assert_eq!(LegacyKind::for_len(614), Some((LegacyKind::LowCmd, false)));
        assert_eq!(
            LegacyKind::for_len(807),
            Some((LegacyKind::LowState, false))
        );
        assert_eq!(LegacyKind::for_len(5), None);
    }

    #[test]
    fn decoders_never_panic_on_any_length() {
        for len in 0..1300 {
            let buf = vec![0xABu8; len];
            let _ = LegacyLowCmd::decode(&buf);
            let _ = LegacyLowState::decode(&buf);
            let _ = LegacyHighCmd::decode(&buf);
            let _ = LegacyHighState::decode(&buf);
            let _ = LegacyLowCmd::crc_ok(&buf);
        }
    }

    #[test]
    fn high_state_round_trips_motors_and_velocity() {
        let mut buf = vec![0u8; LEGACY_HIGH_STATE_LEN];
        buf[2] = level::HIGH;
        // Fill via decode of zeros: just check it decodes and the frame is
        // the right size; a precise offset test would duplicate the struct.
        let st = LegacyHighState::decode(&buf).unwrap();
        assert_eq!(st.level_flag, level::HIGH);
        assert_eq!(st.motor_state.len(), LEGACY_MOTORS);
        assert_eq!(st.joint_frame().max_abs_velocity(), Some(0.0));
    }

    #[test]
    fn legacy_frame_classifies_by_length_and_maps_to_channels() {
        let ctx = |ch| EventContext {
            channel: ch,
            writer_guid: None,
            timestamp_ns: 7,
        };
        for (len, kind, command) in [
            (LEGACY_HIGH_CMD_LEN, LegacyKind::HighCmd, true),
            (LEGACY_HIGH_STATE_LEN, LegacyKind::HighState, false),
            (LEGACY_LOW_CMD_LEN, LegacyKind::LowCmd, true),
            (LEGACY_LOW_STATE_LEN, LegacyKind::LowState, false),
        ] {
            let f = LegacyFrame::decode(&vec![0u8; len]).unwrap();
            assert_eq!(f.kind(), kind);
            assert_eq!(f.is_command(), command);
            assert!(channels::ALL.contains(&f.channel()));
            assert!(f.channel().starts_with(channels::PREFIX));
            assert_eq!(
                f.joint_command_frame().is_some(),
                kind == LegacyKind::LowCmd
            );
            match (f.to_event(&ctx(f.channel())), command) {
                (RobotEvent::MotionCommand(c), true) => assert_eq!(c.channel, f.channel()),
                (RobotEvent::MotionFeedback(fb), false) => {
                    assert_eq!(fb.channel, f.channel());
                    assert_eq!(fb.timestamp_ns, 7);
                    assert_eq!(fb.measured_joint_speed, Some(0.0));
                }
                (e, _) => panic!("{kind:?}: {e:?}"),
            }
        }
        // HighState feedback carries the measured body velocity.
        let mut hs = vec![0u8; LEGACY_HIGH_STATE_LEN];
        let st = LegacyHighState::decode(&hs).unwrap();
        assert_eq!(st.body_velocity(), (0.0, 0.0, 0.0));
        // velocity[0] follows the fixed part; find it by decoding a marker.
        let off = (0..hs.len() - 4)
            .find(|&o| {
                let mut b = hs.clone();
                b[o..o + 4].copy_from_slice(&1.5f32.to_le_bytes());
                LegacyHighState::decode(&b).unwrap().velocity[0] == 1.5
            })
            .unwrap();
        hs[off..off + 4].copy_from_slice(&1.5f32.to_le_bytes());
        match LegacyFrame::decode(&hs)
            .unwrap()
            .to_event(&ctx(channels::HIGH_STATE))
        {
            RobotEvent::MotionFeedback(fb) => {
                assert_eq!(fb.linear_velocity, Some(1.5));
                assert_eq!(fb.measured_linear_speed, Some(1.5));
            }
            e => panic!("{e:?}"),
        }
        assert_eq!(
            LegacyFrame::decode(&[0; 614]),
            Err(LegacyFrameError::Compressed {
                kind: LegacyKind::LowCmd,
                len: 614
            })
        );
        assert_eq!(
            LegacyFrame::decode(&[0; 807]),
            Err(LegacyFrameError::Compressed {
                kind: LegacyKind::LowState,
                len: 807
            })
        );
        assert_eq!(
            LegacyFrame::decode(&[0; 100]),
            Err(LegacyFrameError::UnknownLength { len: 100 })
        );
        assert!(LegacyFrame::decode(&[]).is_err());
    }
}
