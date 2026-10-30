//! Hand command channels: the Dex3 hand (`unitree_hg::msg::dds_::HandCmd_`
//! on `rt/dex3/{left,right}/cmd`, `unitree_sdk2`
//! `example/g1/dex3/g1_dex3_example.cpp:34,269`) and the G1 hand SDK
//! (`unitree_go::msg::dds_::MotorCmds_` on `rt/hand_sdk`,
//! `example/g1/high_level/g1_hand_sdk_example.cpp:27`).
//!
//! **Decide, then pass or suppress.** A hand sample is decoded strictly
//! (below) and its finger joints are checked against the channel's joint
//! envelope (`robodr-firewall` joint channel with one motor entry per
//! sequence element). Every element is decided as **enabled** whatever its
//! mode octet: the Dex3 mode is a bitfield (motor id, status, timeout;
//! `robodr_cdr::unitree::Dex3Mode`) and `rt/hand_sdk` puts the blend weight
//! × 100 into `cmds[0].mode`, so the octet never says "this motor is off".
//! A frame the firewall passes is forwarded byte-identical; anything else
//! (limited, rejected, a substitute, an undecodable frame) is
//! **suppressed** (PAD): the hand keeps its last command. The gateway does
//! not rewrite hand frames (no encoder for these types); a hand is not part
//! of the balance loop, so dropping a hand command never makes a robot
//! fall. Counters: `hand_passed`, `hand_suppressed`.
//!
//! **Mode octets** ([`decode_hand`]; review finding F5). Dex3: the SDK
//! builds each element's mode as `id | status << 4 | timeout << 7`
//! (`unitree_sdk2` `example/g1/dex3/g1_dex3_example.cpp:112-121`, the
//! `RIS_Mode_t` bitfield `:45-49`) with `id` the element's index and
//! `status = 0x01` in every helper (`rotateMotors`, `gripHand`,
//! `stopMotors`); `timeout` is 0 or 1 (`stopMotors` sets it). An element
//! whose id is not its index (it would command another finger) or whose
//! status is anything but 1 (undocumented) is refused. Hand SDK: the blend
//! weight × 100 is `cmds[0].mode` (`g1_hand_sdk_example.cpp:34-41`, at most
//! 100), every other element's mode is 0, and the weight may move by at
//! most the channel's `max_weight_step` (× 100, rounded down, at least 1)
//! from the last forwarded frame, and by its rate per second (the
//! gateway's `hand_sdk` state). Anything else is an integrity failure
//! (suppressed).
//!
//! **Strict decode.** `robodr-cdr` decodes; then the layout must be the
//! canonical one: every element is 4-aligned and fixed-size (`hg`
//! `MotorCmd_` 1 + 5·4 + 4 octets after 3 padding octets, `go` `MotorCmd_`
//! 1 + 5·4 + 3·4), so the only freedom is the 3 padding octets after each
//! mode octet, which must be zero; the body must end where the message
//! ends (at most 3 zero octets after it); the element count must equal the
//! firewall channel's motor count. Anything else is an integrity failure.

use robodr_cdr::unitree::{decode_unitree, UnitreeKind, UnitreeMessage};
use robodr_cdr::Limits;
use robodr_firewall::{JointFrame, MotorCmd, MotorMode, MAX_MOTORS};

use crate::config::Codec;
use crate::lowcmd::Undecidable;

/// Octets of one sequence element on the wire (mode + 3 pad + 5 f32 +
/// reserve).
fn element_size(codec: Codec) -> Option<usize> {
    match codec {
        Codec::UnitreeDex3HandCmd => Some(4 + 20 + 4),
        Codec::UnitreeHandSdk => Some(4 + 20 + 12),
        _ => None,
    }
}

/// Decode a hand slot strictly into a joint frame of `slots` motors, every
/// element enabled (module docs).
pub fn decode_strict(slot: &[u8], codec: Codec, slots: usize) -> Result<JointFrame, Undecidable> {
    let kind = match codec {
        Codec::UnitreeDex3HandCmd => UnitreeKind::HgHandCmd,
        Codec::UnitreeHandSdk => UnitreeKind::GoMotorCmds,
        _ => return Err(Undecidable::Decode),
    };
    let e = element_size(codec).ok_or(Undecidable::Decode)?;
    let d = decode_unitree(kind, slot, &Limits::default()).map_err(|_| Undecidable::Decode)?;
    let joints = match d.message {
        UnitreeMessage::HgHandCmd(m) => m.joint_frame(),
        UnitreeMessage::GoMotorCmds(m) => m.joint_frame(),
        _ => return Err(Undecidable::Decode),
    };
    let js = joints.as_slice();
    if js.len() != slots || slots > MAX_MOTORS {
        return Err(Undecidable::Decode);
    }
    let trailer = if codec == Codec::UnitreeDex3HandCmd {
        16
    } else {
        0
    };
    let body = slot.get(4..).ok_or(Undecidable::Decode)?;
    let want = 4 + js.len() * e + trailer;
    if d.consumed != want {
        return Err(Undecidable::NonCanonical);
    }
    for i in 0..js.len() {
        let pad = body
            .get(4 + i * e + 1..4 + i * e + 4)
            .ok_or(Undecidable::Decode)?;
        if pad.iter().any(|b| *b != 0) {
            return Err(Undecidable::NonCanonical);
        }
    }
    if d.trailing_bytes > 3
        || body
            .get(d.consumed..)
            .is_none_or(|t| t.iter().any(|b| *b != 0))
    {
        return Err(Undecidable::Trailing);
    }
    let mut motors = [MotorCmd::OFF; MAX_MOTORS];
    for (dst, j) in motors.iter_mut().zip(js) {
        *dst = MotorCmd {
            mode: MotorMode::Enabled,
            q: f64::from(j.q),
            dq: f64::from(j.dq),
            tau: f64::from(j.tau),
            kp: f64::from(j.kp),
            kd: f64::from(j.kd),
        };
    }
    JointFrame::from_slice(motors.get(..slots).ok_or(Undecidable::Decode)?, None)
        .ok_or(Undecidable::Decode)
}

/// The Dex3 `status` every SDK helper sends.
pub const DEX3_STATUS: u8 = 0x01;
/// The hand-SDK weight scale (`cmds[0].mode` = weight × 100).
pub const HAND_SDK_WEIGHT_SCALE: u8 = 100;

/// A strictly decoded hand frame with its mode octets checked (module
/// docs).
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct HandFrame {
    pub frame: JointFrame,
    /// Hand SDK: the blend weight × 100 (`cmds[0].mode`).
    pub weight: Option<u8>,
}

/// [`decode_strict`], then the mode octets (module docs, F5).
pub fn decode_hand(slot: &[u8], codec: Codec, slots: usize) -> Result<HandFrame, Undecidable> {
    let frame = decode_strict(slot, codec, slots)?;
    let e = element_size(codec).ok_or(Undecidable::Decode)?;
    // Canonical layout (checked above): header 4, count 4, elements.
    let mode = |i: usize| slot.get(8 + i * e).copied().ok_or(Undecidable::Decode);
    let mut weight = None;
    for i in 0..slots {
        let m = mode(i)?;
        let ok = match codec {
            Codec::UnitreeDex3HandCmd => {
                usize::from(m & 0x0f) == i && (m >> 4) & 0x07 == DEX3_STATUS
            }
            Codec::UnitreeHandSdk if i == 0 => {
                weight = Some(m);
                m <= HAND_SDK_WEIGHT_SCALE
            }
            Codec::UnitreeHandSdk => m == 0,
            _ => false,
        };
        if !ok {
            return Err(Undecidable::Mode);
        }
    }
    Ok(HandFrame { frame, weight })
}

/// Lenient classification for the unknown-writer probe (review finding
/// F2): could `slot` be a hand frame of this channel in **any** encoding a
/// DDS reader might accept (any CDR representation, a `DHEADER`, non-zero
/// padding, trailing octets)? The element count is taken from the count
/// field and from the length; either matching the channel's is enough.
/// Only decides channel membership: the sample is then decided strictly
/// (and fails closed).
pub fn plausible(slot: &[u8], codec: Codec, slots: usize) -> bool {
    let Some(e) = element_size(codec) else {
        return false;
    };
    let Some(rep) = slot
        .first_chunk::<2>()
        .and_then(|h| robodr_cdr::Representation::from_id(u16::from_be_bytes(*h)))
    else {
        return false;
    };
    if rep.is_parameter_list() {
        return false;
    }
    let big = rep.endian() == Some(robodr_cdr::Endian::Big);
    let body = slot.get(4..).unwrap_or_default();
    let trailer = if codec == Codec::UnitreeDex3HandCmd {
        16
    } else {
        0
    };
    let u32_at = |off: usize| -> Option<usize> {
        let b: [u8; 4] = body.get(off..off + 4)?.try_into().ok()?;
        Some(if big {
            u32::from_be_bytes(b)
        } else {
            u32::from_le_bytes(b)
        } as usize)
    };
    // The sequence count right after the header, or after a DHEADER.
    for start in [0usize, 4] {
        let Some(after) = body.len().checked_sub(start + 4) else {
            continue;
        };
        let by_len = after.saturating_sub(trailer) / e;
        let by_count = u32_at(start).filter(|n| (1..=MAX_MOTORS).contains(n));
        let fits = |n: usize| after >= n * e + trailer && after <= n * e + trailer + 64;
        if by_count.is_some_and(|n| n == slots && fits(n)) || (by_len == slots && fits(by_len)) {
            return true;
        }
    }
    false
}

/// Test / harness helper: a canonical little-endian payload of `n`
/// elements (`hg` `HandCmd_` or `go` `MotorCmds_`), every element
/// `(mode, q, dq, tau, kp, kd)`.
pub fn encode(codec: Codec, motors: &[(u8, f32, f32, f32, f32, f32)]) -> Vec<u8> {
    let mut v = vec![0x00, 0x01, 0x00, 0x00];
    v.extend_from_slice(&(motors.len() as u32).to_le_bytes());
    for (mode, q, dq, tau, kp, kd) in motors {
        v.extend_from_slice(&[*mode, 0, 0, 0]);
        for x in [q, dq, tau, kp, kd] {
            v.extend_from_slice(&x.to_le_bytes());
        }
        let reserve = if codec == Codec::UnitreeHandSdk {
            12
        } else {
            4
        };
        v.extend(std::iter::repeat_n(0u8, reserve));
    }
    if codec == Codec::UnitreeDex3HandCmd {
        v.extend_from_slice(&[0u8; 16]);
    }
    v
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn decodes_strictly() {
        for codec in [Codec::UnitreeDex3HandCmd, Codec::UnitreeHandSdk] {
            let m: Vec<_> = (0..7)
                .map(|i| (0x11, 0.1 * i as f32, 0.0, 0.0, 1.5, 0.1))
                .collect();
            let p = encode(codec, &m);
            let f = decode_strict(&p, codec, 7).unwrap();
            assert_eq!(f.slots(), 7);
            assert!(f.motors().iter().all(|m| m.mode == MotorMode::Enabled));
            assert_eq!(decode_strict(&p, codec, 6), Err(Undecidable::Decode));
            let mut bad = p.clone();
            bad[4 + 4 + 1] = 1; // padding after the first mode octet
            assert_eq!(
                decode_strict(&bad, codec, 7),
                Err(Undecidable::NonCanonical)
            );
            let mut tr = p.clone();
            tr.extend_from_slice(&[0, 0, 0, 0, 1]);
            assert!(decode_strict(&tr, codec, 7).is_err());
            assert!(decode_strict(&p[..p.len() - 1], codec, 7).is_err());
        }
    }
}
