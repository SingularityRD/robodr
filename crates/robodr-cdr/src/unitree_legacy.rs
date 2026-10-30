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
//! `sizeof` 734 / 937).
//!
//! **Compressed `LowCmd` (614 bytes).** Its layout is not in any header,
//! but it is in the shipped static library: `UDP::SetSend(LowCmd&)` calls
//! `refineCmd(LowCmd_refine&, LowCmd&)` and sends the first
//! `LOW_CMD_LENGTH` bytes of the result. [`LegacyLowCmdCompressed`]
//! decodes it as read from that function's machine code (offsets in
//! [`compressed_layout`], scales in [`compressed_scale`]; the tests pin
//! every offset, and the same code confirms the `comm.h` offsets of the
//! declared struct it reads from). [`LegacyFrame::decode`] expands a
//! 614-byte payload into a [`LegacyLowCmd`] with exact values, so it gets
//! the same motion checks as the declared layout.
//!
//! **Compressed `LowState` (807 bytes)** is still not decoded (state, not a
//! command; [`LegacyFrameError::Compressed`]).
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

/// One motor of the v3.8.6 compressed `LowCmd` (the library's internal
/// `MotorCmd_refine`, 27 bytes packed): `mode`, `q` and `dq` as in
/// `comm.h`, `tau` / `Kp` / `Kd` as signed 16-bit fixed point.
///
/// Recovered from `UNITREE_LEGGED_SDK::refineCmd(LowCmd_refine&, LowCmd&)`
/// in the shipped `libunitree_legged_sdk.a` (v3.8.6, amd64 `udp.cpp.o`;
/// no header declares it): for each motor the library copies `mode`, `q`,
/// `dq` and the three reserve words and stores `(int)(tau * 256.0f)`,
/// `(int)(Kp * 32.0f)`, `(int)(Kd * 16.0f)` (`cvttss2si`: truncation
/// toward zero, the low 16 bits kept). `refineState` reads the
/// corresponding `int16` fields of the state sign-extended (`movswl`), so
/// the three fields are decoded as `i16`. A `Kp` / `Kd` beyond the 16-bit
/// range wraps on the sender; what the robot receives is what is decoded
/// here.
///
/// The sender's conversion depends on its CPU for `|value × scale| ≥ 2^31`
/// or NaN: amd64 `cvttss2si` gives `0x80000000` (low half 0), arm64
/// `fcvtzs` saturates (`0x7FFFFFFF` → low half -1, `0x80000000` → 0; NaN →
/// 0). Only the amd64 object was disassembled. This changes what a sender
/// puts on the wire, not how it is decoded: the decoder (and the gateway)
/// read the wire value, so there is no safety impact.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct LegacyMotorCmdCompressed {
    /// Servo `0x0A`, damping `0x00` (`comm.h`).
    pub mode: u8,
    /// `q` (rad), IEEE f32 bits (kept as bits so `Eq` holds for NaN).
    pub q_bits: u32,
    /// `dq` (rad/s), IEEE f32 bits.
    pub dq_bits: u32,
    /// `tau * 256` (N·m, Q8).
    pub tau_q: i16,
    /// `Kp * 32` (Q5).
    pub kp_q: i16,
    /// `Kd * 16` (Q4).
    pub kd_q: i16,
    pub reserve: [u32; 3],
}

/// Fixed-point scales of [`LegacyMotorCmdCompressed`] (`.rodata.cst4` of
/// `udp.cpp.o`: `0x43800000` = 256, `0x42000000` = 32, `0x41800000` = 16).
pub mod compressed_scale {
    /// `tau` (Q8: 1/256 N·m steps, range about ±128 N·m).
    pub const TAU: f32 = 256.0;
    /// `Kp` (Q5: 1/32 steps, range about ±1024).
    pub const KP: f32 = 32.0;
    /// `Kd` (Q4: 1/16 steps, range about ±2048).
    pub const KD: f32 = 16.0;
}

/// Byte offsets of the compressed `LowCmd` (`LowCmd_refine`), as read from
/// `refineCmd`'s stores; the tests pin them, and the gateway's own writer
/// (`robodr-firewall-gw`) is cross-checked against them.
pub mod compressed_layout {
    /// First motor (after `head[2]`, `levelFlag`, `frameReserve`, `SN[2]`,
    /// `version[2]`, `bandWidth`: the same 22-byte header as `comm.h`).
    pub const MOTOR_AT: usize = 22;
    /// Bytes per motor (`add $0x1b` in the loop).
    pub const MOTOR_LEN: usize = 27;
    /// Within a motor: `mode` u8, `q` f32, `dq` f32, `tau` i16, `Kp` i16,
    /// `Kd` i16, `reserve[3]` u32.
    pub const M_MODE: usize = 0;
    pub const M_Q: usize = 1;
    pub const M_DQ: usize = 5;
    pub const M_TAU: usize = 9;
    pub const M_KP: usize = 11;
    pub const M_KD: usize = 13;
    pub const M_RESERVE: usize = 15;
    /// `BmsCmd bms` (`0x232`).
    pub const BMS_AT: usize = 562;
    /// `wirelessRemote[40]` (`0x236`).
    pub const WIRELESS_AT: usize = 566;
    /// `reserve` u32 (`0x25e`).
    pub const RESERVE_AT: usize = 606;
    /// `crc` u32 (`0x262`).
    pub const CRC_AT: usize = 610;
    /// `crc32(frame, 0x98)`: 152 words = the first 608 bytes (the last two
    /// bytes of `reserve` are not covered, as for every legacy frame whose
    /// length is not a multiple of 4: `frame_crc`).
    pub const CRC_WORDS: usize = 152;
}

impl LegacyMotorCmdCompressed {
    fn read(r: &mut Le<'_>) -> Self {
        LegacyMotorCmdCompressed {
            mode: r.u8(),
            q_bits: r.u32(),
            dq_bits: r.u32(),
            tau_q: r.i16(),
            kp_q: r.i16(),
            kd_q: r.i16(),
            reserve: r.arr(Le::u32),
        }
    }

    pub fn q(&self) -> f32 {
        f32::from_bits(self.q_bits)
    }

    pub fn dq(&self) -> f32 {
        f32::from_bits(self.dq_bits)
    }

    /// `tau` in N·m (exact: an `i16` over a power of two).
    pub fn tau(&self) -> f32 {
        f32::from(self.tau_q) / compressed_scale::TAU
    }

    pub fn kp(&self) -> f32 {
        f32::from(self.kp_q) / compressed_scale::KP
    }

    pub fn kd(&self) -> f32 {
        f32::from(self.kd_q) / compressed_scale::KD
    }

    /// The motor as the declared `comm.h` `MotorCmd` (values exact).
    pub fn expand(&self) -> LegacyMotorCmd {
        LegacyMotorCmd {
            mode: self.mode,
            q: self.q(),
            dq: self.dq(),
            tau: self.tau(),
            kp: self.kp(),
            kd: self.kd(),
            reserve: self.reserve,
        }
    }
}

/// The v3.8.6 on-wire `LowCmd` ("compressed", [`LEGACY_LOW_CMD_COMPRESSED_LEN`]
/// = `LOW_CMD_LENGTH` = 614 bytes): the library's `LowCmd_refine`, which
/// `UDP::SetSend(LowCmd&)` builds with `refineCmd` and sends instead of the
/// `comm.h` struct. Same header and trailer as [`LegacyLowCmd`]; each motor
/// is a [`LegacyMotorCmdCompressed`]. Offsets: [`compressed_layout`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct LegacyLowCmdCompressed {
    pub head: [u8; 2],
    pub level_flag: u8,
    pub frame_reserve: u8,
    pub sn: [u32; 2],
    pub version: [u32; 2],
    pub band_width: u16,
    pub motor_cmd: [LegacyMotorCmdCompressed; LEGACY_MOTORS],
    pub bms: LegacyBmsCmd,
    pub wireless_remote: [u8; 40],
    pub reserve: u32,
    pub crc: u32,
}

/// `LOW_CMD_LENGTH` of the shipped v3.8.6 library (`.rodata` of
/// `udp.cpp.o`: `0x266`): the compressed `LowCmd`.
pub const LEGACY_LOW_CMD_COMPRESSED_LEN: usize = 614;

/// `LOW_STATE_LENGTH` of the shipped v3.8.6 library (`0x327`): the
/// compressed `LowState`, not decoded (see the module docs).
pub const LEGACY_LOW_STATE_COMPRESSED_LEN: usize = 807;

impl LegacyLowCmdCompressed {
    fn read(r: &mut Le<'_>) -> Self {
        LegacyLowCmdCompressed {
            head: r.bytes(),
            level_flag: r.u8(),
            frame_reserve: r.u8(),
            sn: r.arr(Le::u32),
            version: r.arr(Le::u32),
            band_width: r.u16(),
            motor_cmd: r.arr(LegacyMotorCmdCompressed::read),
            bms: LegacyBmsCmd::read(r),
            wireless_remote: r.bytes(),
            reserve: r.u32(),
            crc: r.u32(),
        }
    }

    /// Decodes a buffer of exactly [`LEGACY_LOW_CMD_COMPRESSED_LEN`] bytes.
    /// Never panics; every byte pattern of that length is a frame (the
    /// protocol has no type tag), so a caller that needs integrity checks
    /// the CRC ([`LegacyLowCmdCompressed::crc_check`]).
    pub fn decode(buf: &[u8]) -> Result<Self, LegacyError> {
        check_len(LegacyKind::LowCmd, buf.len(), LEGACY_LOW_CMD_COMPRESSED_LEN)?;
        Ok(Self::read(&mut Le::new(buf)))
    }

    /// The CRC under `mode` (`crc32_core` over the first 608 bytes, stored
    /// at 610); `None` when it cannot be checked.
    pub fn crc_check(buf: &[u8], mode: LegacyCrcMode) -> Option<bool> {
        crc_check(buf, mode)
    }

    /// The frame as the declared `comm.h` `LowCmd` (every value exact; the
    /// `crc` field is copied, it is the compressed frame's CRC).
    pub fn expand(&self) -> LegacyLowCmd {
        LegacyLowCmd {
            head: self.head,
            level_flag: self.level_flag,
            frame_reserve: self.frame_reserve,
            sn: self.sn,
            version: self.version,
            band_width: self.band_width,
            motor_cmd: self.motor_cmd.map(|m| m.expand()),
            bms: self.bms,
            wireless_remote: self.wireless_remote,
            reserve: self.reserve,
            crc: self.crc,
        }
    }

    /// Serialise (the inverse of [`LegacyLowCmdCompressed::decode`]; the
    /// `crc` field is written as stored, not recomputed).
    pub fn encode(&self) -> [u8; LEGACY_LOW_CMD_COMPRESSED_LEN] {
        let mut w = LeOut::new();
        w.put(&self.head);
        w.put(&[self.level_flag, self.frame_reserve]);
        for v in self.sn.iter().chain(self.version.iter()) {
            w.put(&v.to_le_bytes());
        }
        w.put(&self.band_width.to_le_bytes());
        for m in &self.motor_cmd {
            w.put(&[m.mode]);
            w.put(&m.q_bits.to_le_bytes());
            w.put(&m.dq_bits.to_le_bytes());
            w.put(&m.tau_q.to_le_bytes());
            w.put(&m.kp_q.to_le_bytes());
            w.put(&m.kd_q.to_le_bytes());
            for r in &m.reserve {
                w.put(&r.to_le_bytes());
            }
        }
        w.put(&[self.bms.off]);
        w.put(&self.bms.reserve);
        w.put(&self.wireless_remote);
        w.put(&self.reserve.to_le_bytes());
        w.put(&self.crc.to_le_bytes());
        w.buf
    }
}

/// A bounds-checked writer over a fixed compressed-`LowCmd` buffer (bytes
/// past the end are ignored; `encode` writes exactly the frame length).
struct LeOut {
    buf: [u8; LEGACY_LOW_CMD_COMPRESSED_LEN],
    pos: usize,
}

impl LeOut {
    fn new() -> Self {
        LeOut {
            buf: [0; LEGACY_LOW_CMD_COMPRESSED_LEN],
            pos: 0,
        }
    }

    fn put(&mut self, b: &[u8]) {
        for x in b {
            if let Some(slot) = self.buf.get_mut(self.pos) {
                *slot = *x;
            }
            self.pos = self.pos.saturating_add(1);
        }
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
    /// A DDS-style type label for this frame (the legacy protocol has no
    /// type names; used where a type name is expected, e.g.
    /// `robodr_events::profile::Profile::motion_types`).
    pub fn type_label(self) -> &'static str {
        match self {
            LegacyKind::HighCmd => "unitree_legged_sdk::HighCmd",
            LegacyKind::HighState => "unitree_legged_sdk::HighState",
            LegacyKind::LowCmd => "unitree_legged_sdk::LowCmd",
            LegacyKind::LowState => "unitree_legged_sdk::LowState",
        }
    }

    /// The legacy frame kind of a [`LegacyKind::type_label`].
    pub fn from_type_label(label: &str) -> Option<Self> {
        [
            LegacyKind::HighCmd,
            LegacyKind::HighState,
            LegacyKind::LowCmd,
            LegacyKind::LowState,
        ]
        .into_iter()
        .find(|k| k.type_label() == label)
    }

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
    /// `None` for the high-level frames (which are not compressed).
    pub fn compressed_wire_len(self) -> Option<usize> {
        match self {
            // LOW_CMD_LENGTH / LOW_STATE_LENGTH from the shipped library.
            LegacyKind::LowCmd => Some(LEGACY_LOW_CMD_COMPRESSED_LEN),
            LegacyKind::LowState => Some(LEGACY_LOW_STATE_COMPRESSED_LEN),
            LegacyKind::HighCmd | LegacyKind::HighState => None,
        }
    }

    /// The frame kind a payload of `len` bytes is, by its length alone
    /// (the legacy protocol has no type tag). `Some((kind, decodable))`:
    /// `decodable` is false only for the compressed `LowState` (807 bytes),
    /// whose layout this module does not decode; the compressed `LowCmd`
    /// (614 bytes) is decodable ([`LegacyLowCmdCompressed`]). Lengths
    /// matching nothing return `None`.
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
                return Some((k, k == LegacyKind::LowCmd));
            }
        }
        None
    }

    /// The wire form a payload of `len` bytes of this kind is in.
    pub fn wire_form(self, len: usize) -> Option<LegacyWireForm> {
        if len == self.declared_len() {
            Some(LegacyWireForm::Declared)
        } else if self.compressed_wire_len() == Some(len) {
            Some(LegacyWireForm::Compressed)
        } else {
            None
        }
    }
}

/// Which of the two v3.8.6 encodings a low-level frame was in.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum LegacyWireForm {
    /// The packed `comm.h` struct (734 / 937 bytes for `LowCmd` /
    /// `LowState`; the only form of `HighCmd` / `HighState`).
    Declared,
    /// The library's compressed form (614 / 807 bytes), what a v3.8.6
    /// client actually sends.
    Compressed,
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
    /// A v3.8.6 "compressed" `LowState` (807 bytes): not decoded (its
    /// layout is only in the shipped library, and it is state, not a
    /// command). A compressed `LowCmd` (614 bytes) decodes.
    Compressed { kind: LegacyKind, len: usize },
    /// No legacy frame has this length.
    UnknownLength { len: usize },
}

impl std::fmt::Display for LegacyFrameError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            LegacyFrameError::Compressed { kind, len } => write!(
                f,
                "legacy {kind:?} in the compressed {len}-byte wire form, which is not decoded \
                 (not inspected)"
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
            Some((LegacyKind::LowCmd, true)) if len == LEGACY_LOW_CMD_COMPRESSED_LEN => {
                LegacyLowCmdCompressed::decode(buf)
                    .map(|c| LegacyFrame::LowCmd(c.expand()))
                    .map_err(|_| unknown)
            }
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
        // The compressed v3.8.6 LowCmd decodes; the compressed LowState is
        // recognised but not decoded.
        assert_eq!(LegacyKind::for_len(614), Some((LegacyKind::LowCmd, true)));
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
        let c = LegacyFrame::decode(&[0; 614]).unwrap();
        assert_eq!(c.kind(), LegacyKind::LowCmd);
        assert_eq!(c.channel(), channels::LOW_CMD);
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

    // ---- compressed LowCmd (v3.8.6 LowCmd_refine) ---------------------

    /// What `refineCmd` does to one f32 field: `mulss` in f32, then
    /// `cvttss2si` (truncation; NaN / out of i32 range gives 0x80000000),
    /// then a 16-bit store (low half).
    fn sdk_fixed(v: f32, scale: f32) -> i16 {
        let x = v * scale;
        let i = if x.is_finite() && x > -2_147_483_649.0 && x < 2_147_483_648.0 {
            x as i32
        } else {
            i32::MIN
        };
        i as i16
    }

    /// Reference encoder: a byte-for-byte transcription of
    /// `refineCmd(LowCmd_refine&, LowCmd&)` (udp.cpp.o, v3.8.6), reading the
    /// declared struct at the offsets the machine code uses (`0x16 + 33 i`
    /// motors, `0x2aa` bms, `0x2ae` wireless, `0x2d6` reserve) and writing
    /// the compressed one at `0x16 + 27 i`, `0x232`, `0x236`, `0x25e`, CRC of
    /// 0x98 words at `0x262`.
    fn sdk_refine(declared: &[u8]) -> Vec<u8> {
        assert_eq!(declared.len(), LEGACY_LOW_CMD_LEN);
        let mut out = vec![0u8; LEGACY_LOW_CMD_COMPRESSED_LEN];
        out[..0x16].copy_from_slice(&declared[..0x16]);
        let f = |b: &[u8], at: usize| f32::from_le_bytes(b[at..at + 4].try_into().unwrap());
        for i in 0..LEGACY_MOTORS {
            let s = 0x16 + 33 * i;
            let d = 0x16 + 27 * i;
            out[d] = declared[s];
            out[d + 1..d + 9].copy_from_slice(&declared[s + 1..s + 9]); // q, dq
            let tau = sdk_fixed(f(declared, s + 9), 256.0);
            let kp = sdk_fixed(f(declared, s + 13), 32.0);
            let kd = sdk_fixed(f(declared, s + 17), 16.0);
            out[d + 9..d + 11].copy_from_slice(&tau.to_le_bytes());
            out[d + 11..d + 13].copy_from_slice(&kp.to_le_bytes());
            out[d + 13..d + 15].copy_from_slice(&kd.to_le_bytes());
            out[d + 15..d + 27].copy_from_slice(&declared[s + 21..s + 33]);
        }
        out[0x232..0x236].copy_from_slice(&declared[0x2aa..0x2ae]);
        out[0x236..0x25e].copy_from_slice(&declared[0x2ae..0x2d6]);
        out[0x25e..0x262].copy_from_slice(&declared[0x2d6..0x2da]);
        let words: Vec<u8> = out[..0x98 * 4].to_vec();
        let crc = crate::unitree::crc::crc32_core_le_bytes(&words);
        out[0x262..0x266].copy_from_slice(&crc.to_le_bytes());
        out
    }

    fn declared_low(motors: &[(u8, [f32; 5])], bms_off: u8) -> Vec<u8> {
        let mut b = Build::default();
        b.u8(0xFE).u8(0xEF).u8(level::LOW).u8(0);
        b.zeros(8 + 8).u16(0);
        for i in 0..LEGACY_MOTORS {
            let (m, v) = motors.get(i).copied().unwrap_or((0, [0.0; 5]));
            b.u8(m);
            for x in v {
                b.f32(x);
            }
            b.zeros(12);
        }
        b.u8(bms_off).zeros(3).zeros(40 + 4);
        b.with_crc()
    }

    #[test]
    fn compressed_offset_table_matches_the_sdk_machine_code() {
        use compressed_layout as L;
        // Sizes: 22-byte header + 20 x 27 + BmsCmd 4 + wireless 40 +
        // reserve 4 + crc 4 = 614 = LOW_CMD_LENGTH (0x266).
        assert_eq!(
            22 + LEGACY_MOTORS * 27 + 4 + 40 + 4 + 4,
            LEGACY_LOW_CMD_COMPRESSED_LEN
        );
        assert_eq!(LEGACY_LOW_CMD_COMPRESSED_LEN, 0x266);
        assert_eq!(LEGACY_LOW_STATE_COMPRESSED_LEN, 0x327);
        // (offset, value from the disassembly of refineCmd)
        for (ours, sdk) in [
            (L::MOTOR_AT, 0x16),
            (L::MOTOR_LEN, 0x1b),
            (L::M_Q, 1),
            (L::M_DQ, 5),
            (L::M_TAU, 9),
            (L::M_KP, 11),
            (L::M_KD, 13),
            (L::M_RESERVE, 15),
            (L::MOTOR_AT + LEGACY_MOTORS * L::MOTOR_LEN, 0x232),
            (L::BMS_AT, 0x232),
            (L::WIRELESS_AT, 0x236),
            (L::RESERVE_AT, 0x25e),
            (L::CRC_AT, 0x262),
            (L::CRC_WORDS, 0x98),
        ] {
            assert_eq!(ours, sdk);
        }
        // The CRC covers the 152 words before it, as frame_crc computes.
        assert_eq!(
            (LEGACY_LOW_CMD_COMPRESSED_LEN / 4 - 1) * 4,
            L::CRC_WORDS * 4
        );
        // Per-field probe: a marker written at each offset lands in exactly
        // that field.
        let mut buf = vec![0u8; LEGACY_LOW_CMD_COMPRESSED_LEN];
        let m = L::MOTOR_AT + 7 * L::MOTOR_LEN;
        buf[m + L::M_MODE] = 0x0A;
        buf[m + L::M_Q..m + L::M_Q + 4].copy_from_slice(&0.5f32.to_le_bytes());
        buf[m + L::M_DQ..m + L::M_DQ + 4].copy_from_slice(&(-1.25f32).to_le_bytes());
        buf[m + L::M_TAU..m + L::M_TAU + 2].copy_from_slice(&(-640i16).to_le_bytes());
        buf[m + L::M_KP..m + L::M_KP + 2].copy_from_slice(&1280i16.to_le_bytes());
        buf[m + L::M_KD..m + L::M_KD + 2].copy_from_slice(&24i16.to_le_bytes());
        buf[m + L::M_RESERVE..m + L::M_RESERVE + 4].copy_from_slice(&7u32.to_le_bytes());
        buf[L::BMS_AT] = 0xA5;
        buf[L::WIRELESS_AT + 39] = 0x77;
        buf[L::RESERVE_AT..L::RESERVE_AT + 4].copy_from_slice(&9u32.to_le_bytes());
        buf[L::CRC_AT..L::CRC_AT + 4].copy_from_slice(&0xdead_beefu32.to_le_bytes());
        let c = LegacyLowCmdCompressed::decode(&buf).unwrap();
        let mc = c.motor_cmd[7];
        assert_eq!(mc.mode, 0x0A);
        assert_eq!((mc.q(), mc.dq()), (0.5, -1.25));
        assert_eq!((mc.tau(), mc.kp(), mc.kd()), (-2.5, 40.0, 1.5));
        assert_eq!(mc.reserve, [7, 0, 0]);
        assert_eq!(c.motor_cmd[6], LegacyMotorCmdCompressed::default());
        assert_eq!(c.motor_cmd[8], LegacyMotorCmdCompressed::default());
        assert_eq!(
            (c.bms.off, c.wireless_remote[39], c.reserve),
            (0xA5, 0x77, 9)
        );
        assert_eq!(c.crc, 0xdead_beef);
        // encode is the exact inverse.
        assert_eq!(c.encode().to_vec(), buf);
    }

    #[test]
    fn compressed_matches_the_sdk_encoder_and_expands_exactly() {
        let mut motors = vec![(0x0Au8, [0.0f32; 5]); 12];
        motors[0] = (0x0A, [0.1, 0.2, 1.5, 20.0, 0.5]);
        motors[5] = (0x0A, [-1.3, 16000.0, -3.75, 60.0, 2.0]);
        motors[11] = (0x0A, [2.146e9, 0.0, 0.3, 33.3, 0.7]);
        let declared = declared_low(&motors, 0);
        let wire = sdk_refine(&declared);
        assert_eq!(
            LegacyLowCmdCompressed::crc_check(&wire, LegacyCrcMode::Plain),
            Some(true)
        );
        let c = LegacyLowCmdCompressed::decode(&wire).unwrap();
        let d = LegacyLowCmd::decode(&declared).unwrap();
        let x = c.expand();
        for i in 0..LEGACY_MOTORS {
            let (a, b) = (x.motor_cmd[i], d.motor_cmd[i]);
            assert_eq!(a.mode, b.mode);
            assert_eq!(a.q.to_bits(), b.q.to_bits(), "{i}");
            assert_eq!(a.dq.to_bits(), b.dq.to_bits(), "{i}");
            // Fixed point: truncation toward zero, at most one step off.
            for (got, want, step) in [
                (a.tau, b.tau, 1.0 / 256.0),
                (a.kp, b.kp, 1.0 / 32.0),
                (a.kd, b.kd, 1.0 / 16.0),
            ] {
                assert!(
                    got.abs() <= want.abs() && (want - got).abs() < step,
                    "{i} {got} {want}"
                );
            }
        }
        // Exactly representable values round-trip bit for bit.
        assert_eq!(x.motor_cmd[0].tau, 1.5);
        assert_eq!(x.motor_cmd[5].tau, -3.75);
        assert_eq!(x.motor_cmd[5].kp, 60.0);
        assert_eq!(x.motor_cmd[0].kd, 0.5);
        // Legacy frame dispatch gives the same frame and the same events.
        let f = LegacyFrame::decode(&wire).unwrap();
        assert_eq!(f, LegacyFrame::LowCmd(x));
        assert_eq!(
            LegacyKind::LowCmd.wire_form(614),
            Some(LegacyWireForm::Compressed)
        );
        assert_eq!(
            LegacyKind::LowCmd.wire_form(734),
            Some(LegacyWireForm::Declared)
        );
        assert_eq!(LegacyKind::LowCmd.wire_form(733), None);
        let jf = f.joint_command_frame().unwrap();
        assert_eq!(jf.joints.len(), LEGACY_MOTORS);
    }

    #[test]
    fn compressed_adversarial_inputs() {
        let declared = declared_low(&[(0x0A, [0.0, 0.0, 1.0, 10.0, 1.0])], 0);
        let wire = sdk_refine(&declared);
        // Truncation / extension: exact length only.
        for n in [0, 1, 22, 613, 615, 733] {
            let mut b = wire.clone();
            b.resize(n, 0);
            assert!(LegacyLowCmdCompressed::decode(&b).is_err(), "{n}");
        }
        assert!(LegacyFrame::decode(&wire[..613]).is_err());
        // CRC mismatch is reported (and not under encryptCRC).
        let mut bad = wire.clone();
        bad[100] ^= 1;
        assert_eq!(
            LegacyLowCmdCompressed::crc_check(&bad, LegacyCrcMode::Plain),
            Some(false)
        );
        assert_eq!(
            LegacyLowCmdCompressed::crc_check(&bad, LegacyCrcMode::EncryptCrc),
            None
        );
        // Bytes 608..610 (the last half of `reserve`) are outside the CRC,
        // as on the SDK: flipping them keeps the CRC valid.
        let mut tail = wire.clone();
        tail[608] ^= 0xff;
        assert_eq!(
            LegacyLowCmdCompressed::crc_check(&tail, LegacyCrcMode::Plain),
            Some(true)
        );
        // NaN / inf in the f32 fields survive decoding (the motion checks
        // reject them); the fixed-point fields cannot be NaN.
        let mut nan = wire.clone();
        let q = compressed_layout::MOTOR_AT + compressed_layout::M_Q;
        nan[q..q + 4].copy_from_slice(&f32::NAN.to_le_bytes());
        let d = LegacyLowCmdCompressed::decode(&nan).unwrap().expand();
        assert!(d.motor_cmd[0].q.is_nan());
        assert!(d.joint_frame().as_slice()[0].q.is_nan());
        assert!(!d.joint_frame().is_finite());
        // A NaN torque on the sender becomes 0 on the wire (cvttss2si
        // gives 0x80000000, the low half is 0): the SDK cannot send NaN in
        // the fixed-point fields.
        assert_eq!(sdk_fixed(f32::NAN, 256.0), 0);
        // Out of range: the sender's value wraps, the decoder reports what
        // is on the wire (a Kp of 1100 arrives as a negative gain).
        assert_eq!(sdk_fixed(1100.0, 32.0), (35200i32 as i16));
        let big = declared_low(&[(0x0A, [0.0, 0.0, 0.0, 1100.0, 0.0])], 0);
        let c = LegacyLowCmdCompressed::decode(&sdk_refine(&big)).unwrap();
        assert!(c.motor_cmd[0].kp() < 0.0);
        // Extreme fixed-point values stay finite and exact.
        let mut ext = wire.clone();
        let t = compressed_layout::MOTOR_AT + compressed_layout::M_TAU;
        ext[t..t + 2].copy_from_slice(&i16::MIN.to_le_bytes());
        let c = LegacyLowCmdCompressed::decode(&ext).unwrap();
        assert_eq!(c.motor_cmd[0].tau(), -128.0);
        // Aliasing between lengths: a compressed LowCmd is never read as
        // another legacy kind and vice versa.
        assert_eq!(LegacyKind::for_len(614), Some((LegacyKind::LowCmd, true)));
        for len in [
            LEGACY_HIGH_CMD_LEN,
            LEGACY_LOW_CMD_LEN,
            LEGACY_HIGH_STATE_LEN,
            LEGACY_LOW_STATE_LEN,
            807,
        ] {
            assert!(LegacyLowCmdCompressed::decode(&vec![0u8; len]).is_err());
        }
        // BMS off survives expansion (the firewall's battery-off check).
        let off = sdk_refine(&declared_low(&[], 0xA5));
        assert_eq!(
            LegacyLowCmdCompressed::decode(&off)
                .unwrap()
                .expand()
                .bms
                .off,
            0xA5
        );
    }

    #[test]
    fn compressed_decoder_never_panics() {
        let mut x = 0x9e37_79b9_7f4a_7c15u64;
        let mut buf = vec![0u8; LEGACY_LOW_CMD_COMPRESSED_LEN];
        for _ in 0..2000 {
            for b in buf.iter_mut() {
                x ^= x << 13;
                x ^= x >> 7;
                x ^= x << 17;
                *b = x as u8;
            }
            let c = LegacyLowCmdCompressed::decode(&buf).unwrap();
            assert_eq!(c.encode().to_vec(), buf);
            let e = c.expand();
            for m in &e.motor_cmd {
                assert!(m.tau.is_finite() && m.kp.is_finite() && m.kd.is_finite());
            }
            let _ = LegacyFrame::decode(&buf);
        }
    }
}
