//! Go1-generation `unitree_legged_sdk` UDP frames (packed little-endian C
//! structs, Unitree CRC in the last 4 octets): strict decode and in-place
//! rewrite of `HighCmd` (129 octets), the declared `LowCmd` (734 octets)
//! and the **compressed** `LowCmd` (614 octets) a v3.8.6 client actually
//! sends.
//!
//! The datagram payload *is* the frame, so "suppress" means dropping the
//! datagram. Offsets are those of `comm.h` v3.8.6 (`#pragma pack(1)`) and,
//! for the compressed form, of the library's `refineCmd`
//! (`robodr_cdr::unitree_legacy::compressed_layout`), cross-checked in the
//! tests against `robodr-cdr`'s independent decoder.
//!
//! - `HighCmd`: `mode` at 22; `velocity[2]` at 53 / 57 (m/s, forward /
//!   side), `yawSpeed` at 61 (rad/s), `bms.off` at 65. Only mode 2
//!   (target-velocity walking) moves the robot by those fields.
//! - `LowCmd`: 20 motors from offset 22, 33 octets each (`mode` u8, `q`,
//!   `dq`, `tau`, `Kp`, `Kd` f32, 3 reserve words); `bms.off` at 682.
//! - compressed `LowCmd`: 20 motors from offset 22, 27 octets each (`mode`
//!   u8, `q`, `dq` f32, `tau` × 256, `Kp` × 32, `Kd` × 16 as `i16`, 3
//!   reserve words); `bms.off` at 562. A limited value is written as the
//!   fixed-point step on the safe side of the firewall's output
//!   ([`crate::round::fixed_away_from`]); a value outside `i16` cannot be
//!   written (the frame is suppressed instead).
//!
//! `bms.off` (`0xA5` turns the battery off, `comm.h`) is never forwarded
//! non-zero on a legacy channel: such a frame is decided as an integrity
//! failure (the firewall's substitute applies), as on `unitree_go_lowcmd`.
//!
//! CRC: `crc32_core` over the frame's 32-bit little-endian words before
//! the CRC (`robodr_cdr::unitree::frame_crc`). Only the plain CRC is
//! supported; a fleet using the SDK's unpublished `encryptCRC` cannot be
//! enforced (a rewritten frame would carry a CRC the robot rejects).

use robodr_cdr::unitree::frame_crc;
use robodr_cdr::unitree_legacy::{
    compressed_scale, LegacyHighCmd, LegacyLowCmd, LegacyLowCmdCompressed, LEGACY_HIGH_CMD_LEN,
    LEGACY_LOW_CMD_COMPRESSED_LEN, LEGACY_LOW_CMD_LEN, LEGACY_MOTORS,
};
use robodr_firewall::{JointFrame, MotorCmd, MotorMode};

use crate::lowcmd::RewriteError;
use crate::round;

pub const HIGH_MODE_AT: usize = 22;
pub const HIGH_VX_AT: usize = 53;
pub const HIGH_VY_AT: usize = 57;
pub const HIGH_YAW_AT: usize = 61;
pub const HIGH_BMS_AT: usize = 65;
pub const LOW_MOTOR_AT: usize = 22;
pub const LOW_MOTOR_LEN: usize = 33;
pub const LOW_BMS_AT: usize = 682;
/// Compressed `LowCmd`: first motor, octets per motor, `bms.off`.
pub const LOWC_MOTOR_AT: usize = 22;
pub const LOWC_MOTOR_LEN: usize = 27;
pub const LOWC_BMS_AT: usize = 562;

fn f32_at(b: &[u8], at: usize) -> Option<f32> {
    Some(f32::from_le_bytes(b.get(at..at + 4)?.try_into().ok()?))
}

fn put_f32(b: &mut [u8], at: usize, v: f32) -> Option<()> {
    b.get_mut(at..at + 4)?.copy_from_slice(&v.to_le_bytes());
    Some(())
}

/// The CRC field matches the frame (plain mode).
pub fn crc_ok(frame: &[u8]) -> bool {
    let Some(stored) = frame
        .len()
        .checked_sub(4)
        .and_then(|at| frame.get(at..))
        .and_then(|s| <[u8; 4]>::try_from(s).ok())
        .map(u32::from_le_bytes)
    else {
        return false;
    };
    frame_crc(frame) == Some(stored)
}

/// Recompute the CRC field.
pub fn seal(frame: &mut [u8]) -> Option<()> {
    let c = frame_crc(frame)?;
    let at = frame.len().checked_sub(4)?;
    frame.get_mut(at..)?.copy_from_slice(&c.to_le_bytes());
    Some(())
}

/// A decided `HighCmd`.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct High {
    pub mode: u8,
    pub vx: f32,
    pub vy: f32,
    pub yaw: f32,
    pub crc_ok: bool,
    /// `bms.off` is zero (a non-zero value asks the robot to turn its
    /// battery off).
    pub bms_ok: bool,
}

/// Decode a `HighCmd` (exact length).
pub fn decode_high(frame: &[u8]) -> Option<High> {
    let d = LegacyHighCmd::decode(frame).ok()?;
    Some(High {
        mode: d.mode,
        vx: d.velocity[0],
        vy: d.velocity[1],
        yaw: d.yaw_speed,
        crc_ok: crc_ok(frame),
        bms_ok: d.bms.off == 0,
    })
}

/// Write `(vx, vy, yaw)` into a `HighCmd` (rounded away from `input`'s
/// values when given, toward zero otherwise), reseal and verify.
pub fn write_high(frame: &mut [u8], v: [f64; 3], input: Option<&High>) -> Result<(), RewriteError> {
    if frame.len() != LEGACY_HIGH_CMD_LEN {
        return Err(RewriteError::Length);
    }
    let r = |o: f64, i: Option<f32>| match i {
        Some(i) => round::away_from(o, f64::from(i)),
        None => round::toward_zero(o),
    };
    let vx = r(v[0], input.map(|h| h.vx)).ok_or(RewriteError::Value)?;
    let vy = r(v[1], input.map(|h| h.vy)).ok_or(RewriteError::Value)?;
    let yaw = r(v[2], input.map(|h| h.yaw)).ok_or(RewriteError::Value)?;
    put_f32(frame, HIGH_VX_AT, vx).ok_or(RewriteError::Length)?;
    put_f32(frame, HIGH_VY_AT, vy).ok_or(RewriteError::Length)?;
    put_f32(frame, HIGH_YAW_AT, yaw).ok_or(RewriteError::Length)?;
    seal(frame).ok_or(RewriteError::Length)?;
    let back = decode_high(frame).ok_or(RewriteError::Verify)?;
    if !back.crc_ok
        || back.vx.to_bits() != vx.to_bits()
        || back.vy.to_bits() != vy.to_bits()
        || back.yaw.to_bits() != yaw.to_bits()
    {
        return Err(RewriteError::Verify);
    }
    Ok(())
}

/// The firewall's frame of an uncompressed `LowCmd` (all 20 slots).
/// `None` (undecidable) for a frame of another length or with a non-zero
/// `bms.off`.
pub fn decode_low(frame: &[u8]) -> Option<JointFrame> {
    let d = LegacyLowCmd::decode(frame).ok()?;
    if d.bms.off != 0 {
        return None;
    }
    let mut motors = [MotorCmd::OFF; LEGACY_MOTORS];
    for (dst, m) in motors.iter_mut().zip(d.motor_cmd.iter()) {
        *dst = MotorCmd {
            mode: MotorMode::from_u8(m.mode),
            q: f64::from(m.q),
            dq: f64::from(m.dq),
            tau: f64::from(m.tau),
            kp: f64::from(m.kp),
            kd: f64::from(m.kd),
        };
    }
    JointFrame::from_slice(&motors, Some(crc_ok(frame)))
}

/// One wire motor slot of a `LowCmd`: `(mode, [q, dq, tau, kp, kd])`.
pub fn low_motor(frame: &[u8], i: usize) -> Option<(u8, [f32; 5])> {
    let at = LOW_MOTOR_AT + i * LOW_MOTOR_LEN;
    let mode = *frame.get(at)?;
    let mut v = [0f32; 5];
    for (k, x) in v.iter_mut().enumerate() {
        *x = f32_at(frame, at + 1 + 4 * k)?;
    }
    Some((mode, v))
}

fn put_low_motor(frame: &mut [u8], i: usize, mode: u8, v: [f32; 5]) -> Option<()> {
    let at = LOW_MOTOR_AT + i * LOW_MOTOR_LEN;
    *frame.get_mut(at)? = mode;
    for (k, x) in v.iter().enumerate() {
        put_f32(frame, at + 1 + 4 * k, *x)?;
    }
    Some(())
}

/// How a `LowCmd` field is converted (see [`crate::round`]).
pub enum LowSource<'a> {
    /// A limited frame: `frame` holds the input; round away from it.
    Limited,
    /// A substitute: `held` is the last accepted (firewall frame, wire
    /// frame) whose values are copied bit-exact where they match.
    Substitute {
        held: Option<(&'a JointFrame, &'a [u8])>,
    },
}

/// Write the firewall frame `out` into the `LowCmd` `frame` (which holds
/// the input for a limited frame, or the base for a substitute), reseal
/// and verify.
pub fn write_low(
    frame: &mut [u8],
    out: &JointFrame,
    how: LowSource<'_>,
) -> Result<(), RewriteError> {
    if frame.len() != LEGACY_LOW_CMD_LEN || out.slots() != LEGACY_MOTORS {
        return Err(RewriteError::Length);
    }
    let mut written = [(0u8, [0f32; 5]); LEGACY_MOTORS];
    for (i, o) in out.motors().iter().enumerate() {
        let (in_mode, input) = low_motor(frame, i).ok_or(RewriteError::Length)?;
        let want = [o.q, o.dq, o.tau, o.kp, o.kd];
        let mut v = [0f32; 5];
        let mode = match &how {
            LowSource::Limited => {
                if MotorMode::from_u8(in_mode) != o.mode {
                    return Err(RewriteError::Value);
                }
                for k in 0..5 {
                    v[k] = round::away_from(want[k], f64::from(input[k]))
                        .ok_or(RewriteError::Value)?;
                }
                in_mode
            }
            LowSource::Substitute { held } => {
                let h = held.and_then(|(f, w)| Some((*f.motor(i)?, low_motor(w, i)?)));
                for k in 0..5 {
                    v[k] = match h {
                        Some((fm, (_, wv)))
                            if [fm.q, fm.dq, fm.tau, fm.kp, fm.kd][k].to_bits()
                                == want[k].to_bits() =>
                        {
                            wv[k]
                        }
                        _ => round::toward_zero(want[k]).ok_or(RewriteError::Value)?,
                    };
                }
                match o.mode {
                    MotorMode::Disabled => 0,
                    MotorMode::Enabled => match h {
                        Some((_, (m, _))) if m != 0 => m,
                        _ if in_mode != 0 => in_mode,
                        _ => 0x0A,
                    },
                }
            }
        };
        put_low_motor(frame, i, mode, v).ok_or(RewriteError::Length)?;
        written[i] = (mode, v);
    }
    seal(frame).ok_or(RewriteError::Length)?;
    if !crc_ok(frame) || LegacyLowCmd::decode(frame).is_err() {
        return Err(RewriteError::Verify);
    }
    for (i, (mode, v)) in written.iter().enumerate() {
        let (m, b) = low_motor(frame, i).ok_or(RewriteError::Verify)?;
        if m != *mode || b.iter().zip(v).any(|(x, y)| x.to_bits() != y.to_bits()) {
            return Err(RewriteError::Verify);
        }
    }
    Ok(())
}

/// The SDK-default `LowCmd` (head `FE EF`, level `0xFF`, all motors off,
/// BMS `off = 0`, CRC sealed): the base of a substitute when no frame was
/// forwarded yet.
pub fn low_template() -> Vec<u8> {
    let mut f = vec![0u8; LEGACY_LOW_CMD_LEN];
    f[0] = 0xFE;
    f[1] = 0xEF;
    f[2] = 0xFF;
    let _ = seal(&mut f);
    f
}

// ---------------------------------------------------------- compressed

/// One wire motor slot of a compressed `LowCmd`: `(mode, [q, dq],
/// [tau, kp, kd] fixed point)`.
pub type WireMotorC = (u8, [f32; 2], [i16; 3]);

/// The fixed-point scales of `[tau, kp, kd]`.
pub const LOWC_SCALES: [f64; 3] = [
    compressed_scale::TAU as f64,
    compressed_scale::KP as f64,
    compressed_scale::KD as f64,
];

fn i16_at(b: &[u8], at: usize) -> Option<i16> {
    Some(i16::from_le_bytes(b.get(at..at + 2)?.try_into().ok()?))
}

/// One wire motor slot of a compressed `LowCmd`.
pub fn lowc_motor(frame: &[u8], i: usize) -> Option<WireMotorC> {
    let at = LOWC_MOTOR_AT + i * LOWC_MOTOR_LEN;
    let mode = *frame.get(at)?;
    let q = f32_at(frame, at + 1)?;
    let dq = f32_at(frame, at + 5)?;
    let tau = i16_at(frame, at + 9)?;
    let kp = i16_at(frame, at + 11)?;
    let kd = i16_at(frame, at + 13)?;
    Some((mode, [q, dq], [tau, kp, kd]))
}

fn put_lowc_motor(frame: &mut [u8], i: usize, m: WireMotorC) -> Option<()> {
    let at = LOWC_MOTOR_AT + i * LOWC_MOTOR_LEN;
    *frame.get_mut(at)? = m.0;
    put_f32(frame, at + 1, m.1[0])?;
    put_f32(frame, at + 5, m.1[1])?;
    for (k, v) in m.2.iter().enumerate() {
        frame
            .get_mut(at + 9 + 2 * k..at + 11 + 2 * k)?
            .copy_from_slice(&v.to_le_bytes());
    }
    Some(())
}

/// The firewall's frame of a compressed `LowCmd` (all 20 slots, values
/// exact). `None` (undecidable) for a frame of another length or with a
/// non-zero `bms.off`.
pub fn decode_low_compressed(frame: &[u8]) -> Option<JointFrame> {
    let d = LegacyLowCmdCompressed::decode(frame).ok()?;
    if d.bms.off != 0 {
        return None;
    }
    let mut motors = [MotorCmd::OFF; LEGACY_MOTORS];
    for (dst, m) in motors.iter_mut().zip(d.motor_cmd.iter()) {
        *dst = MotorCmd {
            mode: MotorMode::from_u8(m.mode),
            q: f64::from(m.q()),
            dq: f64::from(m.dq()),
            tau: f64::from(m.tau()),
            kp: f64::from(m.kp()),
            kd: f64::from(m.kd()),
        };
    }
    JointFrame::from_slice(&motors, Some(crc_ok(frame)))
}

fn fixed_value(q: i16, k: usize) -> f64 {
    f64::from(q) / LOWC_SCALES.get(k).copied().unwrap_or(1.0)
}

/// Write the firewall frame `out` into the compressed `LowCmd` `frame`
/// (the input for a limited frame, or the base for a substitute), reseal
/// and verify. Same rules as [`write_low`]; the fixed-point fields round
/// to the safe side (`crate::round::fixed_away_from` /
/// `fixed_toward_zero`) and a value beyond `i16` is a
/// [`RewriteError::Value`].
pub fn write_low_compressed(
    frame: &mut [u8],
    out: &JointFrame,
    how: LowSource<'_>,
) -> Result<(), RewriteError> {
    if frame.len() != LEGACY_LOW_CMD_COMPRESSED_LEN || out.slots() != LEGACY_MOTORS {
        return Err(RewriteError::Length);
    }
    let mut written = [(0u8, [0f32; 2], [0i16; 3]); LEGACY_MOTORS];
    for (i, o) in out.motors().iter().enumerate() {
        let (in_mode, in_f, in_x) = lowc_motor(frame, i).ok_or(RewriteError::Length)?;
        let want_f = [o.q, o.dq];
        let want_x = [o.tau, o.kp, o.kd];
        let mut f = [0f32; 2];
        let mut x = [0i16; 3];
        let mode = match &how {
            LowSource::Limited => {
                if MotorMode::from_u8(in_mode) != o.mode {
                    return Err(RewriteError::Value);
                }
                for k in 0..2 {
                    f[k] = round::away_from(want_f[k], f64::from(in_f[k]))
                        .ok_or(RewriteError::Value)?;
                }
                for k in 0..3 {
                    x[k] =
                        round::fixed_away_from(want_x[k], fixed_value(in_x[k], k), LOWC_SCALES[k])
                            .ok_or(RewriteError::Value)?;
                }
                in_mode
            }
            LowSource::Substitute { held } => {
                let h = held.and_then(|(fr, w)| Some((*fr.motor(i)?, lowc_motor(w, i)?)));
                for k in 0..2 {
                    f[k] = match h {
                        Some((fm, (_, wf, _)))
                            if [fm.q, fm.dq][k].to_bits() == want_f[k].to_bits() =>
                        {
                            wf[k]
                        }
                        _ => round::toward_zero(want_f[k]).ok_or(RewriteError::Value)?,
                    };
                }
                for k in 0..3 {
                    x[k] = match h {
                        Some((fm, (_, _, wx)))
                            if [fm.tau, fm.kp, fm.kd][k].to_bits() == want_x[k].to_bits() =>
                        {
                            wx[k]
                        }
                        _ => round::fixed_toward_zero(want_x[k], LOWC_SCALES[k])
                            .ok_or(RewriteError::Value)?,
                    };
                }
                match o.mode {
                    MotorMode::Disabled => 0,
                    MotorMode::Enabled => match h {
                        Some((_, (m, _, _))) if m != 0 => m,
                        _ if in_mode != 0 => in_mode,
                        _ => 0x0A,
                    },
                }
            }
        };
        put_lowc_motor(frame, i, (mode, f, x)).ok_or(RewriteError::Length)?;
        written[i] = (mode, f, x);
    }
    seal(frame).ok_or(RewriteError::Length)?;
    if !crc_ok(frame) || decode_low_compressed(frame).is_none() {
        return Err(RewriteError::Verify);
    }
    for (i, (mode, f, x)) in written.iter().enumerate() {
        let (m, bf, bx) = lowc_motor(frame, i).ok_or(RewriteError::Verify)?;
        if m != *mode || bf.iter().zip(f).any(|(a, b)| a.to_bits() != b.to_bits()) || bx != *x {
            return Err(RewriteError::Verify);
        }
    }
    Ok(())
}

/// The SDK-default compressed `LowCmd` (head `FE EF`, level `0xFF`, all
/// motors off, BMS `off = 0`, CRC sealed): the base of a substitute when no
/// frame was forwarded yet.
pub fn lowc_template() -> Vec<u8> {
    let mut f = vec![0u8; LEGACY_LOW_CMD_COMPRESSED_LEN];
    f[0] = 0xFE;
    f[1] = 0xEF;
    f[2] = 0xFF;
    let _ = seal(&mut f);
    f
}

/// Test / harness helper: a sealed compressed `LowCmd` with the given
/// slots (`(mode, [q, dq, tau, kp, kd])`, the fixed-point fields truncated
/// toward zero as the SDK's `refineCmd` does).
pub fn build_low_compressed(motors: &[(u8, [f32; 5])]) -> Vec<u8> {
    let mut f = lowc_template();
    for (i, (m, v)) in motors.iter().enumerate().take(LEGACY_MOTORS) {
        let fx =
            |k: usize| round::fixed_toward_zero(f64::from(v[k + 2]), LOWC_SCALES[k]).unwrap_or(0);
        let _ = put_lowc_motor(&mut f, i, (*m, [v[0], v[1]], [fx(0), fx(1), fx(2)]));
    }
    let _ = seal(&mut f);
    f
}

/// Test / harness helper: a sealed `HighCmd`.
pub fn build_high(mode: u8, vx: f32, vy: f32, yaw: f32) -> Vec<u8> {
    let mut f = vec![0u8; LEGACY_HIGH_CMD_LEN];
    f[0] = 0xFE;
    f[1] = 0xEF;
    f[2] = 0xEE;
    f[HIGH_MODE_AT] = mode;
    let _ = put_f32(&mut f, HIGH_VX_AT, vx);
    let _ = put_f32(&mut f, HIGH_VY_AT, vy);
    let _ = put_f32(&mut f, HIGH_YAW_AT, yaw);
    let _ = seal(&mut f);
    f
}

/// Test / harness helper: a sealed `LowCmd` with the given slots.
pub fn build_low(motors: &[(u8, [f32; 5])]) -> Vec<u8> {
    let mut f = low_template();
    for (i, (m, v)) in motors.iter().enumerate().take(LEGACY_MOTORS) {
        let _ = put_low_motor(&mut f, i, *m, *v);
    }
    let _ = seal(&mut f);
    f
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn offsets_agree_with_the_independent_decoder() {
        let f = build_high(2, 0.75, -0.25, 1.5);
        let d = LegacyHighCmd::decode(&f).unwrap();
        assert_eq!((d.mode, d.velocity, d.yaw_speed), (2, [0.75, -0.25], 1.5));
        assert_eq!(LegacyHighCmd::crc_ok(&f), Some(true));
        let mut motors = vec![(0u8, [0f32; 5]); 20];
        motors[3] = (0x0A, [0.1, 0.2, 0.3, 40.0, 1.5]);
        motors[19] = (0x0A, [-0.1, -0.2, -0.3, 30.0, 2.5]);
        let l = build_low(&motors);
        let d = LegacyLowCmd::decode(&l).unwrap();
        assert_eq!(d.motor_cmd[3].q, 0.1);
        assert_eq!(d.motor_cmd[3].kp, 40.0);
        assert_eq!(d.motor_cmd[19].kd, 2.5);
        assert_eq!(d.motor_cmd[19].mode, 0x0A);
        assert_eq!(LegacyLowCmd::crc_ok(&l), Some(true));
        let jf = decode_low(&l).unwrap();
        assert_eq!(jf.slots(), 20);
        assert_eq!(jf.crc_ok, Some(true));
    }

    #[test]
    fn high_rewrite_is_verified_and_bounded() {
        let mut f = build_high(2, 2.0, 0.0, 0.0);
        let input = decode_high(&f).unwrap();
        write_high(&mut f, [0.7, 0.0, 0.0], Some(&input)).unwrap();
        let d = decode_high(&f).unwrap();
        assert!(d.crc_ok && f64::from(d.vx) <= 0.7);
        let mut short = vec![0u8; 100];
        assert_eq!(
            write_high(&mut short, [0.0; 3], None),
            Err(RewriteError::Length)
        );
    }

    #[test]
    fn compressed_offsets_agree_with_the_independent_decoder() {
        use robodr_cdr::unitree_legacy::compressed_layout as L;
        assert_eq!(
            (LOWC_MOTOR_AT, LOWC_MOTOR_LEN, LOWC_BMS_AT),
            (L::MOTOR_AT, L::MOTOR_LEN, L::BMS_AT)
        );
        let mut motors = vec![(0u8, [0f32; 5]); 20];
        motors[0] = (0x0A, [0.1, 0.2, 1.5, 40.0, 1.5]);
        motors[19] = (0x0A, [-0.1, -0.2, -0.3, 30.0, 2.5]);
        let f = build_low_compressed(&motors);
        assert_eq!(f.len(), 614);
        let d = LegacyLowCmdCompressed::decode(&f).unwrap();
        assert_eq!(
            (
                d.motor_cmd[0].q(),
                d.motor_cmd[0].tau(),
                d.motor_cmd[0].kp()
            ),
            (0.1, 1.5, 40.0)
        );
        // -0.3 * 256 = -76.8 -> -76 (toward zero, as refineCmd).
        assert_eq!(d.motor_cmd[19].tau_q, -76);
        assert_eq!(d.motor_cmd[19].kd(), 2.5);
        let jf = decode_low_compressed(&f).unwrap();
        assert_eq!(jf.crc_ok, Some(true));
        assert_eq!(jf.motor(19).unwrap().tau, -76.0 / 256.0);
        // The uncompressed decoder rejects it and vice versa (no aliasing).
        assert!(decode_low(&f).is_none());
        assert!(decode_low_compressed(&build_low(&motors)).is_none());
        // Battery off is undecidable on every legacy low form.
        let mut off = f.clone();
        off[LOWC_BMS_AT] = 0xA5;
        seal(&mut off);
        assert!(decode_low_compressed(&off).is_none());
        let mut off = build_low(&motors);
        off[LOW_BMS_AT] = 0xA5;
        seal(&mut off);
        assert_eq!(LegacyLowCmd::decode(&off).unwrap().bms.off, 0xA5);
        assert!(decode_low(&off).is_none());
        let mut h = build_high(2, 0.1, 0.0, 0.0);
        h[HIGH_BMS_AT] = 0xA5;
        seal(&mut h);
        assert_eq!(LegacyHighCmd::decode(&h).unwrap().bms.off, 0xA5);
        assert!(!decode_high(&h).unwrap().bms_ok);
    }

    #[test]
    fn compressed_rewrite_rounds_to_the_safe_side() {
        let mut motors = vec![(0u8, [0f32; 5]); 20];
        motors[2] = (0x0A, [0.5, 1.0, 30.0, 90.0, 4.0]);
        let mut f = build_low_compressed(&motors);
        let mut jf = decode_low_compressed(&f).unwrap();
        let mut out: Vec<MotorCmd> = jf.motors().to_vec();
        // Limited to tau 23.7, kp 33.33, kd 2.01 (none representable).
        out[2].tau = 23.7;
        out[2].kp = 33.33;
        out[2].kd = 2.01;
        let lim = JointFrame::from_slice(&out, Some(true)).unwrap();
        write_low_compressed(&mut f, &lim, LowSource::Limited).unwrap();
        let back = decode_low_compressed(&f).unwrap();
        let m = back.motor(2).unwrap();
        assert!(m.tau <= 23.7 && m.tau > 23.7 - 1.0 / 256.0);
        assert!(m.kp <= 33.33 && m.kp > 33.33 - 1.0 / 32.0);
        // kd was lowered from 4.0 to 2.01: 2.01 * 16 = 32.16 -> 32 (2.0).
        assert!(m.kd <= 2.01);
        // A value the i16 cannot carry is refused, not wrapped.
        out[2].kp = 5000.0;
        jf = JointFrame::from_slice(&out, Some(true)).unwrap();
        assert_eq!(
            write_low_compressed(&mut f, &jf, LowSource::Limited),
            Err(RewriteError::Value)
        );
        // Substitute on the template: everything held / zeroed.
        let mut t = lowc_template();
        let hold = decode_low_compressed(&build_low_compressed(&motors)).unwrap();
        let base = build_low_compressed(&motors);
        write_low_compressed(
            &mut t,
            &hold,
            LowSource::Substitute {
                held: Some((&hold, &base)),
            },
        )
        .unwrap();
        assert_eq!(t, base);
        let mut short = vec![0u8; 600];
        assert_eq!(
            write_low_compressed(&mut short, &hold, LowSource::Limited),
            Err(RewriteError::Length)
        );
    }
}
