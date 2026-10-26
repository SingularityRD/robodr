//! Go1-generation `unitree_legged_sdk` UDP frames (packed little-endian C
//! structs, Unitree CRC in the last 4 octets): strict decode and in-place
//! rewrite of `HighCmd` (129 octets) and the **uncompressed** `LowCmd`
//! (734 octets).
//!
//! The datagram payload *is* the frame, so "suppress" means dropping the
//! datagram. Offsets are those of `comm.h` v3.8.6 (`#pragma pack(1)`),
//! cross-checked in the tests against `robodr-cdr`'s independent decoder.
//!
//! - `HighCmd`: `mode` at 22; `velocity[2]` at 53 / 57 (m/s, forward /
//!   side), `yawSpeed` at 61 (rad/s). Only mode 2 (target-velocity walking)
//!   moves the robot by those fields.
//! - `LowCmd`: 20 motors from offset 22, 33 octets each (`mode` u8, `q`,
//!   `dq`, `tau`, `Kp`, `Kd` f32, 3 reserve words).
//!
//! The 614-octet "compressed" `LowCmd` that real v3.8.6 robots exchange is
//! not published and cannot be decoded: it is undecidable here.
//!
//! CRC: `crc32_core` over the frame's 32-bit little-endian words before
//! the CRC (`robodr_cdr::unitree::frame_crc`). Only the plain CRC is
//! supported; a fleet using the SDK's unpublished `encryptCRC` cannot be
//! enforced (a rewritten frame would carry a CRC the robot rejects).

use robodr_cdr::unitree::frame_crc;
use robodr_cdr::unitree_legacy::{
    LegacyHighCmd, LegacyLowCmd, LEGACY_HIGH_CMD_LEN, LEGACY_LOW_CMD_LEN, LEGACY_MOTORS,
};
use robodr_firewall::{JointFrame, MotorCmd, MotorMode};

use crate::lowcmd::RewriteError;
use crate::round;

pub const HIGH_MODE_AT: usize = 22;
pub const HIGH_VX_AT: usize = 53;
pub const HIGH_VY_AT: usize = 57;
pub const HIGH_YAW_AT: usize = 61;
pub const LOW_MOTOR_AT: usize = 22;
pub const LOW_MOTOR_LEN: usize = 33;

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
pub fn decode_low(frame: &[u8]) -> Option<JointFrame> {
    let d = LegacyLowCmd::decode(frame).ok()?;
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
}
