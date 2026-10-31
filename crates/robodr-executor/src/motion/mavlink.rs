//! A minimal MAVLink 2 codec: the three messages the PX4 adapter needs
//! (`HEARTBEAT` 0, `COMMAND_LONG` 76, `COMMAND_ACK` 77) and the frame
//! (`0xFD` start, length, flags, sequence, system / component ids, 24-bit
//! message id, payload with trailing zero octets truncated on send,
//! CRC-16/MCRF4XX over everything after the start octet plus the message's
//! `CRC_EXTRA`). Signed frames (`incompat_flags & 0x01`) are **refused**:
//! the executor holds no MAVLink signing key, and a vehicle that requires
//! signing must not take unsigned commands (README, "PX4").
//!
//! Decoding is strict on the frame (start octet, known incompatibility
//! flags, length, checksum) and zero-extends a truncated payload as the
//! protocol requires.

/// The start octet of a MAVLink 2 frame.
pub const STX: u8 = 0xFD;
pub const MSG_HEARTBEAT: u32 = 0;
pub const MSG_COMMAND_LONG: u32 = 76;
pub const MSG_COMMAND_ACK: u32 = 77;
/// `MAV_CMD_DO_SET_MODE`.
pub const MAV_CMD_DO_SET_MODE: u16 = 176;
/// `MAV_MODE_FLAG_CUSTOM_MODE_ENABLED`.
pub const MAV_MODE_FLAG_CUSTOM_MODE_ENABLED: f32 = 1.0;
/// `MAV_RESULT_ACCEPTED`.
pub const MAV_RESULT_ACCEPTED: u8 = 0;
/// PX4 `custom_main_mode` AUTO and its sub modes (`px4_custom_mode.h`).
pub const PX4_MAIN_AUTO: u8 = 4;
pub const PX4_SUB_AUTO_LOITER: u8 = 3;
pub const PX4_SUB_AUTO_RTL: u8 = 5;
pub const PX4_SUB_AUTO_LAND: u8 = 6;

/// `CRC_EXTRA` of a message id (`common.xml`), `None` for any other.
pub fn crc_extra(msgid: u32) -> Option<u8> {
    match msgid {
        MSG_HEARTBEAT => Some(50),
        MSG_COMMAND_LONG => Some(152),
        MSG_COMMAND_ACK => Some(143),
        _ => None,
    }
}

/// Full payload length of a message (before truncation).
fn full_len(msgid: u32) -> usize {
    match msgid {
        MSG_HEARTBEAT => 9,
        MSG_COMMAND_LONG => 33,
        // 3 base octets + the extensions (progress, result_param2,
        // target_system, target_component).
        MSG_COMMAND_ACK => 10,
        _ => 0,
    }
}

/// CRC-16/MCRF4XX (X.25, init 0xFFFF, no final xor) as MAVLink uses it.
pub fn crc_accumulate(crc: u16, b: u8) -> u16 {
    let mut tmp = b ^ (crc & 0xff) as u8;
    tmp ^= tmp << 4;
    let t = u16::from(tmp);
    (crc >> 8) ^ (t << 8) ^ (t << 3) ^ (t >> 4)
}

pub fn crc(data: &[u8]) -> u16 {
    data.iter().fold(0xFFFF, |c, b| crc_accumulate(c, *b))
}

/// A decoded frame.
#[derive(Debug, Clone, PartialEq)]
pub struct Frame {
    pub seq: u8,
    pub sysid: u8,
    pub compid: u8,
    pub msgid: u32,
    /// Zero-extended to the message's full length.
    pub payload: Vec<u8>,
}

/// Encode one frame.
pub fn encode(seq: u8, sysid: u8, compid: u8, msgid: u32, payload: &[u8]) -> Option<Vec<u8>> {
    let extra = crc_extra(msgid)?;
    // Truncate trailing zero octets (at least one octet stays).
    let mut len = payload.len();
    while len > 1 && payload.get(len - 1) == Some(&0) {
        len -= 1;
    }
    let mut f = Vec::with_capacity(12 + len);
    f.push(STX);
    f.push(u8::try_from(len).ok()?);
    f.push(0); // incompat_flags: unsigned
    f.push(0); // compat_flags
    f.push(seq);
    f.push(sysid);
    f.push(compid);
    f.extend_from_slice(&msgid.to_le_bytes()[..3]);
    f.extend_from_slice(payload.get(..len)?);
    let mut c = crc(f.get(1..)?);
    c = crc_accumulate(c, extra);
    f.extend_from_slice(&c.to_le_bytes());
    Some(f)
}

/// Decode the frames in one datagram (`Err` on the first bad one).
pub fn decode_all(mut d: &[u8]) -> Result<Vec<Frame>, String> {
    let mut out = Vec::new();
    while !d.is_empty() {
        let (f, used) = decode(d)?;
        out.extend(f);
        d = d.get(used..).unwrap_or_default();
    }
    Ok(out)
}

/// Decode one frame at the start of `d`: `(Some(frame) | None for an
/// unknown message id, octets used)`.
pub fn decode(d: &[u8]) -> Result<(Option<Frame>, usize), String> {
    if d.first() != Some(&STX) {
        return Err("not a MAVLink 2 frame (start octet)".into());
    }
    let (h, rest) = d.split_first_chunk::<10>().ok_or("truncated header")?;
    let len = usize::from(h[1]);
    let incompat = h[2];
    if incompat & 0x01 != 0 {
        return Err("signed MAVLink frame: the executor holds no signing key".into());
    }
    if incompat != 0 {
        return Err(format!("unknown incompatibility flags {incompat:#x}"));
    }
    let msgid = u32::from_le_bytes([h[7], h[8], h[9], 0]);
    let total = 10 + len + 2;
    let frame = d.get(..total).ok_or("truncated frame")?;
    let payload = rest.get(..len).ok_or("truncated frame")?;
    // `frame` is header + payload + 2 checksum octets.
    let (covered, checksum) = frame.split_at_checked(10 + len).ok_or("truncated frame")?;
    let Some(extra) = crc_extra(msgid) else {
        // Unknown message: skipped (its CRC cannot be checked without its
        // CRC_EXTRA), never interpreted.
        return Ok((None, total));
    };
    let mut c = crc(covered.get(1..).unwrap_or_default());
    c = crc_accumulate(c, extra);
    if c.to_le_bytes().as_slice() != checksum {
        return Err("bad checksum".into());
    }
    let full = full_len(msgid);
    if len > full {
        return Err(format!(
            "payload of {len} octets for message {msgid} (max {full})"
        ));
    }
    let mut p = payload.to_vec();
    p.resize(full, 0);
    Ok((
        Some(Frame {
            seq: h[4],
            sysid: h[5],
            compid: h[6],
            msgid,
            payload: p,
        }),
        total,
    ))
}

/// `HEARTBEAT` fields.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Heartbeat {
    pub custom_mode: u32,
    pub mav_type: u8,
    pub autopilot: u8,
    pub base_mode: u8,
    pub system_status: u8,
}

impl Heartbeat {
    pub fn payload(&self) -> Vec<u8> {
        let mut p = self.custom_mode.to_le_bytes().to_vec();
        p.extend_from_slice(&[
            self.mav_type,
            self.autopilot,
            self.base_mode,
            self.system_status,
            3,
        ]);
        p
    }

    pub fn parse(f: &Frame) -> Option<Self> {
        if f.msgid != MSG_HEARTBEAT {
            return None;
        }
        let p = &f.payload;
        Some(Heartbeat {
            custom_mode: u32::from_le_bytes(p.get(..4)?.try_into().ok()?),
            mav_type: *p.get(4)?,
            autopilot: *p.get(5)?,
            base_mode: *p.get(6)?,
            system_status: *p.get(7)?,
        })
    }

    /// PX4 `(main_mode, sub_mode)` of `custom_mode`.
    pub fn px4_mode(&self) -> (u8, u8) {
        let b = self.custom_mode.to_le_bytes();
        (b[2], b[3])
    }
}

/// PX4's `custom_mode` for `(main, sub)`.
pub fn px4_custom_mode(main: u8, sub: u8) -> u32 {
    u32::from_le_bytes([0, 0, main, sub])
}

/// A PX4 mode a pilot flies with sticks (`px4_custom_mode.h`: MANUAL 1,
/// ALTCTL 2, POSCTL 3 (its plain and slow sub modes, not the commanded
/// ORBIT 1), ACRO 5, STABILIZED 7, RATTITUDE 8). The safe_pause latch
/// (T42) never takes such a mode away from the pilot.
pub fn px4_is_manual(custom_mode: u32) -> bool {
    let b = custom_mode.to_le_bytes();
    match (b[2], b[3]) {
        (1 | 2 | 5 | 7 | 8, _) => true,
        (3, sub) => sub != 1,
        _ => false,
    }
}

/// A readable name of a PX4 `custom_mode` (`MAIN.SUB`, numbers for ones
/// not named here).
pub fn px4_mode_name(custom_mode: u32) -> String {
    let b = custom_mode.to_le_bytes();
    let main = match b[2] {
        1 => "MANUAL",
        2 => "ALTCTL",
        3 => "POSCTL",
        4 => "AUTO",
        5 => "ACRO",
        6 => "OFFBOARD",
        7 => "STABILIZED",
        8 => "RATTITUDE",
        _ => "",
    };
    let sub = match (b[2], b[3]) {
        (4, 1) => "READY",
        (4, 2) => "TAKEOFF",
        (4, 3) => "LOITER",
        (4, 4) => "MISSION",
        (4, 5) => "RTL",
        (4, 6) => "LAND",
        (4, 8) => "FOLLOW_TARGET",
        (4, 9) => "PRECLAND",
        (3, 1) => "ORBIT",
        _ => "",
    };
    match (main, sub) {
        ("", _) => format!("custom_mode {custom_mode:#010x}"),
        (m, "") if b[3] == 0 => m.to_string(),
        (m, "") => format!("{m}.{}", b[3]),
        (m, s) => format!("{m}.{s}"),
    }
}

/// `COMMAND_LONG` payload.
pub fn command_long(
    params: [f32; 7],
    command: u16,
    target_system: u8,
    target_component: u8,
) -> Vec<u8> {
    let mut p = Vec::with_capacity(33);
    for x in params {
        p.extend_from_slice(&x.to_le_bytes());
    }
    p.extend_from_slice(&command.to_le_bytes());
    p.push(target_system);
    p.push(target_component);
    p.push(0); // confirmation
    p
}

/// `COMMAND_LONG` fields of a frame (simulated vehicles, tests).
pub fn parse_command_long(f: &Frame) -> Option<([f32; 7], u16, u8, u8)> {
    if f.msgid != MSG_COMMAND_LONG {
        return None;
    }
    let p = &f.payload;
    let mut params = [0f32; 7];
    for (i, x) in params.iter_mut().enumerate() {
        *x = f32::from_le_bytes(p.get(4 * i..4 * i + 4)?.try_into().ok()?);
    }
    let cmd = u16::from_le_bytes(p.get(28..30)?.try_into().ok()?);
    Some((params, cmd, *p.get(30)?, *p.get(31)?))
}

/// `COMMAND_ACK` (command, result, target system, target component).
pub fn parse_command_ack(f: &Frame) -> Option<(u16, u8, u8, u8)> {
    if f.msgid != MSG_COMMAND_ACK {
        return None;
    }
    let p = &f.payload;
    Some((
        u16::from_le_bytes(p.get(..2)?.try_into().ok()?),
        *p.get(2)?,
        *p.get(8)?,
        *p.get(9)?,
    ))
}

/// `COMMAND_ACK` payload (simulated vehicles, tests).
pub fn command_ack(command: u16, result: u8, target_system: u8, target_component: u8) -> Vec<u8> {
    let mut p = command.to_le_bytes().to_vec();
    p.push(result);
    p.push(0); // progress
    p.extend_from_slice(&0i32.to_le_bytes());
    p.push(target_system);
    p.push(target_component);
    p
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn crc_is_mcrf4xx() {
        // The CRC catalogue's check value of CRC-16/MCRF4XX.
        assert_eq!(crc(b"123456789"), 0x6F91);
    }

    #[test]
    fn frames_round_trip_and_bad_ones_are_refused() {
        let hb = Heartbeat {
            custom_mode: px4_custom_mode(PX4_MAIN_AUTO, PX4_SUB_AUTO_LOITER),
            mav_type: 2,
            autopilot: 12,
            base_mode: 0x81,
            system_status: 4,
        };
        let f = encode(7, 1, 1, MSG_HEARTBEAT, &hb.payload()).unwrap();
        let (got, used) = decode(&f).unwrap();
        assert_eq!(used, f.len());
        let got = got.unwrap();
        assert_eq!((got.seq, got.sysid, got.compid), (7, 1, 1));
        assert_eq!(Heartbeat::parse(&got), Some(hb));
        assert_eq!(Heartbeat::parse(&got).unwrap().px4_mode(), (4, 3));
        // COMMAND_LONG with trailing zeros truncated on the wire.
        let cl = command_long(
            [1.0, 4.0, 3.0, 0.0, 0.0, 0.0, 0.0],
            MAV_CMD_DO_SET_MODE,
            1,
            1,
        );
        let f2 = encode(8, 254, 190, MSG_COMMAND_LONG, &cl).unwrap();
        assert!(f2.len() < 12 + 33);
        let (g2, _) = decode(&f2).unwrap();
        let (p, cmd, ts, tc) = parse_command_long(&g2.unwrap()).unwrap();
        assert_eq!(
            (p[1], p[2], cmd, ts, tc),
            (4.0, 3.0, MAV_CMD_DO_SET_MODE, 1, 1)
        );
        let mut both = f.clone();
        both.extend_from_slice(&f2);
        assert_eq!(decode_all(&both).unwrap().len(), 2);
        // Bad checksum, signed, truncated, oversized.
        let mut bad = f.clone();
        let n = bad.len();
        bad[n - 1] ^= 1;
        assert!(decode(&bad).is_err());
        let mut signed = f.clone();
        signed[2] = 1;
        assert!(decode(&signed).is_err());
        assert!(decode(&f[..f.len() - 1]).is_err());
        let ack = command_ack(MAV_CMD_DO_SET_MODE, 0, 254, 190);
        let fa = encode(1, 1, 1, MSG_COMMAND_ACK, &ack).unwrap();
        assert_eq!(
            parse_command_ack(&decode(&fa).unwrap().0.unwrap()),
            Some((MAV_CMD_DO_SET_MODE, 0, 254, 190))
        );
    }
}
