//! `unitree_hg::msg::dds_` types (G1, H1-2, H2, R1 humanoids and the Dex3
//! hands) and `unitree_hg_doubleimu::msg::dds_::doubleIMUState_`.
//!
//! Field order and types follow
//! `unitree_sdk2/include/unitree/idl/hg/*.hpp` and
//! `unitree_sdk2/include/unitree/idl/hg_doubleimu/doubleIMUState_.hpp`,
//! cross-checked against
//! `unitree_ros2/cyclonedds_ws/src/unitree/unitree_hg/msg/*.msg` (no
//! difference for the types decoded here). `doubleIMUState_` is the hg
//! `IMUState_` plus a trailing `uint32 tick`; no SDK example publishes or
//! subscribes it, so its topic is unknown.

use crate::error::DecodeError;
use crate::reader::Reader;
use crate::unitree::crc::CrcImage;
use crate::unitree::joint::{
    Bounded, JointCommand, JointCommandFrame, JointMeasurement, JointStateFrame,
};
use crate::unitree::{arr, read_struct_array, read_struct_seq, MOTOR_SLOTS_HG};

/// Capacity for the `MotorCmd_[]` / `MotorState_[]` / `PressSensorState_[]`
/// sequences of `HandCmd_` / `HandState_`. The Dex3 example drives 7
/// motors per hand (`example/g1/dex3/g1_dex3_example.cpp`, `MOTOR_MAX 7`);
/// a longer sequence is refused as [`DecodeError::SequenceTooLong`].
pub const MAX_HAND_ELEMENTS: usize = 16;

/// `unitree_hg::msg::dds_::MotorCmd_`.
#[derive(Debug, Clone, Copy, PartialEq, Default)]
pub struct HgMotorCmd {
    pub mode: u8,
    pub q: f32,
    pub dq: f32,
    pub tau: f32,
    pub kp: f32,
    pub kd: f32,
    pub reserve: u32,
}

/// The Dex3 hand's `MotorCmd_::mode` octet, a bitfield
/// `id | status << 4 | timeout << 7` (`RIS_Mode_t` in
/// `example/g1/dex3/g1_dex3_example.cpp`). Informational: no check depends
/// on it (a mode octet of 0 is motor 0 with status 0, still driven by its
/// kp / kd / dq).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default)]
pub struct Dex3Mode {
    /// Motor id (low 4 bits).
    pub id: u8,
    /// Status (3 bits; the example uses `0x01`).
    pub status: u8,
    /// Timeout flag (top bit).
    pub timeout: bool,
}

impl Dex3Mode {
    pub fn from_octet(mode: u8) -> Self {
        Dex3Mode {
            id: mode & 0x0F,
            status: (mode >> 4) & 0x07,
            timeout: mode & 0x80 != 0,
        }
    }
}

impl HgMotorCmd {
    /// The mode octet read as the Dex3 bitfield (`rt/dex3/*/cmd`).
    pub fn dex3_mode(&self) -> Dex3Mode {
        Dex3Mode::from_octet(self.mode)
    }

    pub(crate) fn read(r: &mut Reader<'_>) -> Result<Self, DecodeError> {
        r.structure(|r| {
            Ok(HgMotorCmd {
                mode: r.u8()?,
                q: r.f32()?,
                dq: r.f32()?,
                tau: r.f32()?,
                kp: r.f32()?,
                kd: r.f32()?,
                reserve: r.u32()?,
            })
        })
    }

    fn image(&self, img: &mut CrcImage) {
        img.pad(4);
        img.u8(self.mode);
        for v in [self.q, self.dq, self.tau, self.kp, self.kd] {
            img.f32(v);
        }
        img.u32(self.reserve);
    }

    pub fn joint(&self) -> JointCommand {
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

/// `unitree_hg::msg::dds_::LowCmd_` (topics `rt/lowcmd`, `rt/arm_sdk`).
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct HgLowCmd {
    /// Ankle control mode: 0 = PR (serial pitch/roll), 1 = AB (parallel
    /// motors) (`example/g1/low_level/g1_ankle_swing_example.cpp`).
    pub mode_pr: u8,
    /// Robot type echo of `LowState_::mode_machine` (same example).
    pub mode_machine: u8,
    pub motor_cmd: [HgMotorCmd; MOTOR_SLOTS_HG],
    pub reserve: [u32; 4],
    pub crc: u32,
}

impl HgLowCmd {
    /// C++ `sizeof(unitree_hg::msg::dds_::LowCmd_)` (Python SDK
    /// `__packFmtHGLowCmd`, "size 1004").
    pub const IMAGE_SIZE: usize = 1004;

    pub(crate) fn read(r: &mut Reader<'_>) -> Result<Self, DecodeError> {
        r.structure(|r| {
            Ok(HgLowCmd {
                mode_pr: r.u8()?,
                mode_machine: r.u8()?,
                motor_cmd: read_struct_array(r, HgMotorCmd::read)?,
                reserve: arr(r, Reader::u32)?,
                crc: r.u32()?,
            })
        })
    }

    /// The CRC the SDK computes for this message.
    pub fn computed_crc(&self) -> u32 {
        let mut img = CrcImage::new();
        img.u8(self.mode_pr);
        img.u8(self.mode_machine);
        for m in &self.motor_cmd {
            m.image(&mut img);
        }
        for v in self.reserve {
            img.u32(v);
        }
        debug_assert_eq!(img.len(), Self::IMAGE_SIZE - 4);
        img.finish()
    }

    /// `crc == computed_crc()`.
    pub fn crc_ok(&self) -> bool {
        self.crc == self.computed_crc()
    }

    /// All 35 motor slots as a [`JointCommandFrame`].
    pub fn joint_frame(&self) -> JointCommandFrame {
        let mut f = JointCommandFrame::default();
        for m in &self.motor_cmd {
            f.joints.push(m.joint());
        }
        f
    }
}

/// `unitree_hg::msg::dds_::IMUState_` (also published alone on
/// `rt/secondary_imu`, the torso IMU, in the G1 / H2 / R1 examples).
#[derive(Debug, Clone, Copy, PartialEq, Default)]
pub struct HgImuState {
    pub quaternion: [f32; 4],
    pub gyroscope: [f32; 3],
    pub accelerometer: [f32; 3],
    pub rpy: [f32; 3],
    pub temperature: i16,
}

impl HgImuState {
    pub(crate) fn read(r: &mut Reader<'_>) -> Result<Self, DecodeError> {
        r.structure(|r| {
            Ok(HgImuState {
                quaternion: arr(r, Reader::f32)?,
                gyroscope: arr(r, Reader::f32)?,
                accelerometer: arr(r, Reader::f32)?,
                rpy: arr(r, Reader::f32)?,
                temperature: r.i16()?,
            })
        })
    }

    fn image(&self, img: &mut CrcImage) {
        img.pad(4);
        for v in self
            .quaternion
            .iter()
            .chain(&self.gyroscope)
            .chain(&self.accelerometer)
            .chain(&self.rpy)
        {
            img.f32(*v);
        }
        img.i16(self.temperature);
        img.pad(4);
    }
}

/// `unitree_hg_doubleimu::msg::dds_::doubleIMUState_`.
#[derive(Debug, Clone, Copy, PartialEq, Default)]
pub struct HgDoubleImuState {
    pub quaternion: [f32; 4],
    pub gyroscope: [f32; 3],
    pub accelerometer: [f32; 3],
    pub rpy: [f32; 3],
    pub temperature: i16,
    pub tick: u32,
}

impl HgDoubleImuState {
    pub(crate) fn read(r: &mut Reader<'_>) -> Result<Self, DecodeError> {
        r.structure(|r| {
            Ok(HgDoubleImuState {
                quaternion: arr(r, Reader::f32)?,
                gyroscope: arr(r, Reader::f32)?,
                accelerometer: arr(r, Reader::f32)?,
                rpy: arr(r, Reader::f32)?,
                temperature: r.i16()?,
                tick: r.u32()?,
            })
        })
    }
}

/// `unitree_hg::msg::dds_::MotorState_`.
#[derive(Debug, Clone, Copy, PartialEq, Default)]
pub struct HgMotorState {
    pub mode: u8,
    pub q: f32,
    pub dq: f32,
    pub ddq: f32,
    pub tau_est: f32,
    pub temperature: [i16; 2],
    pub vol: f32,
    pub sensor: [u32; 2],
    pub motorstate: u32,
    pub reserve: [u32; 4],
}

impl HgMotorState {
    pub(crate) fn read(r: &mut Reader<'_>) -> Result<Self, DecodeError> {
        r.structure(|r| {
            Ok(HgMotorState {
                mode: r.u8()?,
                q: r.f32()?,
                dq: r.f32()?,
                ddq: r.f32()?,
                tau_est: r.f32()?,
                temperature: arr(r, Reader::i16)?,
                vol: r.f32()?,
                sensor: arr(r, Reader::u32)?,
                motorstate: r.u32()?,
                reserve: arr(r, Reader::u32)?,
            })
        })
    }

    fn image(&self, img: &mut CrcImage) {
        img.pad(4);
        img.u8(self.mode);
        for v in [self.q, self.dq, self.ddq, self.tau_est] {
            img.f32(v);
        }
        for v in self.temperature {
            img.i16(v);
        }
        img.f32(self.vol);
        for v in self.sensor {
            img.u32(v);
        }
        img.u32(self.motorstate);
        for v in self.reserve {
            img.u32(v);
        }
    }

    pub fn measurement(&self) -> JointMeasurement {
        JointMeasurement {
            mode: self.mode,
            q: self.q,
            dq: self.dq,
            ddq: self.ddq,
            tau_est: self.tau_est,
        }
    }
}

/// `unitree_hg::msg::dds_::LowState_` (topic `rt/lowstate`).
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct HgLowState {
    pub version: [u32; 2],
    pub mode_pr: u8,
    pub mode_machine: u8,
    pub tick: u32,
    pub imu_state: HgImuState,
    pub motor_state: [HgMotorState; MOTOR_SLOTS_HG],
    pub wireless_remote: [u8; 40],
    pub reserve: [u32; 4],
    pub crc: u32,
}

impl HgLowState {
    /// C++ `sizeof(unitree_hg::msg::dds_::LowState_)` (Python SDK
    /// `__packFmtHGLowState`, "size 2092").
    pub const IMAGE_SIZE: usize = 2092;

    pub(crate) fn read(r: &mut Reader<'_>) -> Result<Self, DecodeError> {
        r.structure(|r| {
            Ok(HgLowState {
                version: arr(r, Reader::u32)?,
                mode_pr: r.u8()?,
                mode_machine: r.u8()?,
                tick: r.u32()?,
                imu_state: HgImuState::read(r)?,
                motor_state: read_struct_array(r, HgMotorState::read)?,
                wireless_remote: arr(r, Reader::u8)?,
                reserve: arr(r, Reader::u32)?,
                crc: r.u32()?,
            })
        })
    }

    /// The CRC the SDK computes for this message.
    pub fn computed_crc(&self) -> u32 {
        let mut img = CrcImage::new();
        for v in self.version {
            img.u32(v);
        }
        img.u8(self.mode_pr);
        img.u8(self.mode_machine);
        img.u32(self.tick);
        self.imu_state.image(&mut img);
        for m in &self.motor_state {
            m.image(&mut img);
        }
        img.bytes(&self.wireless_remote);
        for v in self.reserve {
            img.u32(v);
        }
        debug_assert_eq!(img.len(), Self::IMAGE_SIZE - 4);
        img.finish()
    }

    pub fn crc_ok(&self) -> bool {
        self.crc == self.computed_crc()
    }

    /// All 35 motor slots as a [`JointStateFrame`].
    pub fn joint_frame(&self) -> JointStateFrame {
        let mut f = JointStateFrame::default();
        for m in &self.motor_state {
            f.joints.push(m.measurement());
        }
        f
    }
}

/// `unitree_hg::msg::dds_::HandCmd_` (Dex3: `rt/dex3/{left,right}/cmd`).
/// Each motor's mode octet is the [`Dex3Mode`] bitfield; it never gates a
/// check (the joint frame evaluates every motor's q / dq / tau / kp / kd).
#[derive(Debug, Clone, Copy, PartialEq, Default)]
pub struct HgHandCmd {
    pub motor_cmd: Bounded<HgMotorCmd, MAX_HAND_ELEMENTS>,
    pub reserve: [u32; 4],
}

impl HgHandCmd {
    pub(crate) fn read(r: &mut Reader<'_>) -> Result<Self, DecodeError> {
        r.structure(|r| {
            Ok(HgHandCmd {
                motor_cmd: read_struct_seq(r, 1 + 4 * 5 + 4, HgMotorCmd::read)?,
                reserve: arr(r, Reader::u32)?,
            })
        })
    }

    pub fn joint_frame(&self) -> JointCommandFrame {
        let mut f = JointCommandFrame::default();
        for m in self.motor_cmd.as_slice() {
            f.joints.push(m.joint());
        }
        f
    }
}

impl HgMotorCmd {
    /// A one-joint frame (the standalone `MotorCmd_` of `rt/waistpitchcmd`,
    /// `example/g1/g1d/g1d_waist_example.cpp`).
    pub fn joint_frame(&self) -> JointCommandFrame {
        let mut f = JointCommandFrame::default();
        f.joints.push(self.joint());
        f
    }
}

impl HgMotorState {
    /// A one-joint frame (the standalone `MotorState_` of
    /// `rt/waistpitchstate`).
    pub fn joint_frame(&self) -> JointStateFrame {
        let mut f = JointStateFrame::default();
        f.joints.push(self.measurement());
        f
    }
}

/// `unitree_hg::msg::dds_::PressSensorState_`.
#[derive(Debug, Clone, Copy, PartialEq, Default)]
pub struct HgPressSensorState {
    pub pressure: [f32; 12],
    pub temperature: [f32; 12],
    pub lost: u32,
    pub reserve: u32,
}

impl HgPressSensorState {
    fn read(r: &mut Reader<'_>) -> Result<Self, DecodeError> {
        r.structure(|r| {
            Ok(HgPressSensorState {
                pressure: arr(r, Reader::f32)?,
                temperature: arr(r, Reader::f32)?,
                lost: r.u32()?,
                reserve: r.u32()?,
            })
        })
    }
}

/// `unitree_hg::msg::dds_::HandState_` (Dex3: `rt/dex3/{left,right}/state`,
/// `rt/lf/dex3/{left,right}/state`).
#[derive(Debug, Clone, Copy, PartialEq, Default)]
pub struct HgHandState {
    pub motor_state: Bounded<HgMotorState, MAX_HAND_ELEMENTS>,
    pub press_sensor_state: Bounded<HgPressSensorState, MAX_HAND_ELEMENTS>,
    pub imu_state: HgImuState,
    pub power_v: f32,
    pub power_a: f32,
    pub system_v: f32,
    pub device_v: f32,
    pub error: [u32; 2],
    pub reserve: [u32; 2],
}

impl HgHandState {
    pub(crate) fn read(r: &mut Reader<'_>) -> Result<Self, DecodeError> {
        r.structure(|r| {
            Ok(HgHandState {
                motor_state: read_struct_seq(
                    r,
                    1 + 4 * 4 + 4 + 4 + 8 + 4 + 16,
                    HgMotorState::read,
                )?,
                press_sensor_state: read_struct_seq(r, 4 * 24 + 8, HgPressSensorState::read)?,
                imu_state: HgImuState::read(r)?,
                power_v: r.f32()?,
                power_a: r.f32()?,
                system_v: r.f32()?,
                device_v: r.f32()?,
                error: arr(r, Reader::u32)?,
                reserve: arr(r, Reader::u32)?,
            })
        })
    }

    pub fn joint_frame(&self) -> JointStateFrame {
        let mut f = JointStateFrame::default();
        for m in self.motor_state.as_slice() {
            f.joints.push(m.measurement());
        }
        f
    }
}
