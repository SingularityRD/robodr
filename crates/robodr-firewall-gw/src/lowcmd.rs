//! Unitree SDK2 `LowCmd_` (`unitree_go` 20 slots, `unitree_hg` 35 slots):
//! strict decode, the firewall's [`JointFrame`], and in-place rewrite.
//!
//! # Strict decode ([`decode_strict`])
//!
//! The payload is decoded with `robodr-cdr` (the same decoder the passive
//! sensor uses) and then **re-encoded canonically** with this module's own
//! CDR writer in the payload's representation (CDR / CDR2, either
//! endianness; `D_CDR2` is read as CDR2 because the Unitree types are
//! `@final`). The body must equal that encoding byte for byte (padding
//! octets zero, XCDR2 DHEADERs exact) and at most 3 zero octets may trail
//! it. So the bytes the gateway forwards are exactly the canonical encoding
//! of the values it decided on: a receiver that decodes them differently
//! (a parser differential) would have to disagree with the CDR rules
//! themselves. Anything else is [`Undecidable`].
//!
//! # Rewrite ([`write_slot`])
//!
//! A limited frame or a substitute is encoded into the **same payload
//! slot**, same representation, same length, with the Unitree CRC
//! recomputed over the C++ image (`robodr-cdr`'s `computed_crc`), and then
//! **verified**: the slot is decoded again and must re-encode to the same
//! bytes with a valid CRC. A rewrite that fails verification is never
//! forwarded (the caller falls back to suppressing the sample).
//!
//! # Values
//!
//! The firewall decides in `f64`; the wire is `f32`. See [`crate::round`]:
//! a limited field is rounded away from the input (so the bound is never
//! crossed); a held field is copied bit-exact from the frame the gateway
//! last forwarded; a synthesised field rounds toward zero. Mode octets:
//! a limited frame keeps every input octet (the firewall never changes a
//! mode); a substitute uses the octet of the frame it holds (or `0x01` for
//! an enabled slot with no known octet), `0x00` for a disabled slot.
//! Non-motor fields (head, level flag, `sn`, `version`, `bandwidth`, BMS,
//! wireless remote, LED, fan, GPIO, reserve words, `mode_pr` /
//! `mode_machine` unless the substitute pins them) of a substitute come
//! from the last frame the gateway forwarded as accepted, never from the
//! rejected frame; with none yet, from [`template`] (SDK defaults:
//! `head = FE EF`, `level_flag = 0xFF`, everything else zero, BMS `off = 0`).

use robodr_cdr::unitree::{
    decode_unitree, GoBmsCmd, GoLowCmd, GoMotorCmd, HgLowCmd, HgMotorCmd, UnitreeKind,
    UnitreeMessage, MOTOR_SLOTS_GO, MOTOR_SLOTS_HG,
};
use robodr_cdr::{Encapsulation, Endian, Limits, Representation, XcdrVersion};
use robodr_firewall::{JointFrame, MotorCmd, MotorMode};

use crate::round;

/// Which `LowCmd_`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum LowCmdCodec {
    /// `unitree_go::msg::dds_::LowCmd_` (Go2, Go2-W, B2, B2-W, H1): 20 slots.
    Go,
    /// `unitree_hg::msg::dds_::LowCmd_` (G1, H1-2): 35 slots.
    Hg,
}

impl LowCmdCodec {
    pub fn slots(self) -> usize {
        match self {
            LowCmdCodec::Go => MOTOR_SLOTS_GO,
            LowCmdCodec::Hg => MOTOR_SLOTS_HG,
        }
    }

    pub fn kind(self) -> UnitreeKind {
        match self {
            LowCmdCodec::Go => UnitreeKind::GoLowCmd,
            LowCmdCodec::Hg => UnitreeKind::HgLowCmd,
        }
    }

    pub fn dds_type_name(self) -> &'static str {
        self.kind().dds_type_name()
    }
}

/// A decoded `LowCmd_`.
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum WireLowCmd {
    Go(GoLowCmd),
    Hg(HgLowCmd),
}

/// One motor slot as on the wire.
#[derive(Debug, Clone, Copy, PartialEq, Default)]
pub struct WireMotor {
    pub mode: u8,
    pub q: f32,
    pub dq: f32,
    pub tau: f32,
    pub kp: f32,
    pub kd: f32,
}

impl WireLowCmd {
    pub fn codec(&self) -> LowCmdCodec {
        match self {
            WireLowCmd::Go(_) => LowCmdCodec::Go,
            WireLowCmd::Hg(_) => LowCmdCodec::Hg,
        }
    }

    pub fn crc(&self) -> u32 {
        match self {
            WireLowCmd::Go(m) => m.crc,
            WireLowCmd::Hg(m) => m.crc,
        }
    }

    pub fn crc_ok(&self) -> bool {
        match self {
            WireLowCmd::Go(m) => m.crc_ok(),
            WireLowCmd::Hg(m) => m.crc_ok(),
        }
    }

    /// Recompute and store the CRC.
    pub fn seal(&mut self) {
        match self {
            WireLowCmd::Go(m) => m.crc = m.computed_crc(),
            WireLowCmd::Hg(m) => m.crc = m.computed_crc(),
        }
    }

    pub fn slots(&self) -> usize {
        self.codec().slots()
    }

    pub fn motor(&self, i: usize) -> Option<WireMotor> {
        match self {
            WireLowCmd::Go(m) => m.motor_cmd.get(i).map(|c| WireMotor {
                mode: c.mode,
                q: c.q,
                dq: c.dq,
                tau: c.tau,
                kp: c.kp,
                kd: c.kd,
            }),
            WireLowCmd::Hg(m) => m.motor_cmd.get(i).map(|c| WireMotor {
                mode: c.mode,
                q: c.q,
                dq: c.dq,
                tau: c.tau,
                kp: c.kp,
                kd: c.kd,
            }),
        }
    }

    pub fn set_motor(&mut self, i: usize, w: WireMotor) {
        match self {
            WireLowCmd::Go(m) => {
                if let Some(c) = m.motor_cmd.get_mut(i) {
                    c.mode = w.mode;
                    c.q = w.q;
                    c.dq = w.dq;
                    c.tau = w.tau;
                    c.kp = w.kp;
                    c.kd = w.kd;
                }
            }
            WireLowCmd::Hg(m) => {
                if let Some(c) = m.motor_cmd.get_mut(i) {
                    c.mode = w.mode;
                    c.q = w.q;
                    c.dq = w.dq;
                    c.tau = w.tau;
                    c.kp = w.kp;
                    c.kd = w.kd;
                }
            }
        }
    }

    /// `(mode_pr, mode_machine)` of an hg frame.
    pub fn modes(&self) -> (Option<u8>, Option<u8>) {
        match self {
            WireLowCmd::Go(_) => (None, None),
            WireLowCmd::Hg(m) => (Some(m.mode_pr), Some(m.mode_machine)),
        }
    }

    /// The firewall's view: every slot (mode octet via
    /// [`MotorMode::from_u8`]), the CRC verdict, `mode_pr` / `mode_machine`.
    /// `None` only if the layout were wider than the firewall's
    /// `MAX_MOTORS` (35), which neither layout is.
    pub fn joint_frame(&self) -> Option<JointFrame> {
        let n = self.slots();
        let mut motors = [MotorCmd::OFF; MOTOR_SLOTS_HG];
        for (i, m) in motors.iter_mut().take(n).enumerate() {
            let w = self.motor(i)?;
            *m = MotorCmd {
                mode: MotorMode::from_u8(w.mode),
                q: f64::from(w.q),
                dq: f64::from(w.dq),
                tau: f64::from(w.tau),
                kp: f64::from(w.kp),
                kd: f64::from(w.kd),
            };
        }
        let mut f = JointFrame::from_slice(motors.get(..n)?, Some(self.crc_ok()))?;
        let (pr, mm) = self.modes();
        f.mode_pr = pr;
        f.mode_machine = mm;
        Some(f)
    }
}

/// The SDK-default frame used for a substitute's non-motor fields when no
/// frame was forwarded yet (all slots off).
pub fn template(codec: LowCmdCodec) -> WireLowCmd {
    match codec {
        LowCmdCodec::Go => WireLowCmd::Go(GoLowCmd {
            head: [0xFE, 0xEF],
            level_flag: 0xFF,
            frame_reserve: 0,
            sn: [0; 2],
            version: [0; 2],
            bandwidth: 0,
            motor_cmd: [GoMotorCmd::default(); MOTOR_SLOTS_GO],
            bms_cmd: GoBmsCmd::default(),
            wireless_remote: [0; 40],
            led: [0; 12],
            fan: [0; 2],
            gpio: 0,
            reserve: 0,
            crc: 0,
        }),
        LowCmdCodec::Hg => WireLowCmd::Hg(HgLowCmd {
            mode_pr: 0,
            mode_machine: 0,
            motor_cmd: [HgMotorCmd::default(); MOTOR_SLOTS_HG],
            reserve: [0; 4],
            crc: 0,
        }),
    }
}

// ------------------------------------------------------------ CDR writer

struct W<'a> {
    buf: &'a mut [u8],
    pos: usize,
    big: bool,
    max_align: usize,
}

impl W<'_> {
    fn align(&mut self, n: usize) -> Option<()> {
        let a = n.min(self.max_align).max(1);
        while !self.pos.is_multiple_of(a) {
            *self.buf.get_mut(self.pos)? = 0;
            self.pos += 1;
        }
        Some(())
    }

    fn put<const N: usize>(&mut self, le: [u8; N], be: [u8; N]) -> Option<()> {
        self.align(N)?;
        let end = self.pos.checked_add(N)?;
        self.buf
            .get_mut(self.pos..end)?
            .copy_from_slice(if self.big { &be } else { &le });
        self.pos = end;
        Some(())
    }

    fn u8(&mut self, v: u8) -> Option<()> {
        self.put([v], [v])
    }
    fn u16(&mut self, v: u16) -> Option<()> {
        self.put(v.to_le_bytes(), v.to_be_bytes())
    }
    fn u32(&mut self, v: u32) -> Option<()> {
        self.put(v.to_le_bytes(), v.to_be_bytes())
    }
    fn f32(&mut self, v: f32) -> Option<()> {
        self.put(v.to_le_bytes(), v.to_be_bytes())
    }

    /// A fixed array of structs: under XCDR2 preceded by a DHEADER (the
    /// byte size of the elements), under XCDR1 not.
    fn struct_array(&mut self, xcdr2: bool, f: impl FnOnce(&mut Self) -> Option<()>) -> Option<()> {
        if !xcdr2 {
            return f(self);
        }
        self.align(4)?;
        let at = self.pos;
        self.u32(0)?;
        f(self)?;
        let size = u32::try_from(self.pos.checked_sub(at + 4)?).ok()?;
        let b = if self.big {
            size.to_be_bytes()
        } else {
            size.to_le_bytes()
        };
        self.buf.get_mut(at..at + 4)?.copy_from_slice(&b);
        Some(())
    }
}

/// Encode the message body (no encapsulation header) canonically into
/// `out`; returns its length, `None` if `out` is too small.
pub fn encode_body(
    msg: &WireLowCmd,
    endian: Endian,
    version: XcdrVersion,
    out: &mut [u8],
) -> Option<usize> {
    let xcdr2 = version == XcdrVersion::Xcdr2;
    let mut w = W {
        buf: out,
        pos: 0,
        big: endian == Endian::Big,
        max_align: if xcdr2 { 4 } else { 8 },
    };
    match msg {
        WireLowCmd::Go(m) => {
            for b in m.head {
                w.u8(b)?;
            }
            w.u8(m.level_flag)?;
            w.u8(m.frame_reserve)?;
            for v in m.sn.iter().chain(&m.version) {
                w.u32(*v)?;
            }
            w.u16(m.bandwidth)?;
            w.struct_array(xcdr2, |w| {
                for c in &m.motor_cmd {
                    w.u8(c.mode)?;
                    for v in [c.q, c.dq, c.tau, c.kp, c.kd] {
                        w.f32(v)?;
                    }
                    for r in c.reserve {
                        w.u32(r)?;
                    }
                }
                Some(())
            })?;
            w.u8(m.bms_cmd.off)?;
            for b in m.bms_cmd.reserve {
                w.u8(b)?;
            }
            for b in m.wireless_remote.iter().chain(&m.led).chain(&m.fan) {
                w.u8(*b)?;
            }
            w.u8(m.gpio)?;
            w.u32(m.reserve)?;
            w.u32(m.crc)?;
        }
        WireLowCmd::Hg(m) => {
            w.u8(m.mode_pr)?;
            w.u8(m.mode_machine)?;
            w.struct_array(xcdr2, |w| {
                for c in &m.motor_cmd {
                    w.u8(c.mode)?;
                    for v in [c.q, c.dq, c.tau, c.kp, c.kd] {
                        w.f32(v)?;
                    }
                    w.u32(c.reserve)?;
                }
                Some(())
            })?;
            for r in m.reserve {
                w.u32(r)?;
            }
            w.u32(m.crc)?;
        }
    }
    Some(w.pos)
}

/// Large enough for either body in any representation (go 816, hg 1004).
pub const BODY_SCRATCH: usize = 1280;

/// Why a payload cannot be decided.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Undecidable {
    /// `robodr-cdr` refused it (truncated, unsupported representation, ...).
    Decode,
    /// It decodes, but is not the canonical encoding of what it decodes to.
    NonCanonical,
    /// More than 3 octets, or non-zero octets, after the message.
    Trailing,
}

impl Undecidable {
    pub fn as_str(self) -> &'static str {
        match self {
            Undecidable::Decode => "decode",
            Undecidable::NonCanonical => "non_canonical",
            Undecidable::Trailing => "trailing_bytes",
        }
    }
}

/// A strictly decoded payload slot.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct Slot {
    pub msg: WireLowCmd,
    pub header: [u8; 4],
    pub endian: Endian,
    pub version: XcdrVersion,
    /// Body octets of the message.
    pub body_len: usize,
}

fn representation(header: [u8; 4]) -> Option<(Endian, XcdrVersion)> {
    let rep = Representation::from_id(u16::from_be_bytes([header[0], header[1]]))?;
    if rep.is_parameter_list() {
        return None;
    }
    Some((rep.endian()?, rep.version()?))
}

/// Decode `slot` (a DATA's serialized payload, encapsulation included,
/// possibly followed by submessage padding) strictly (module docs).
pub fn decode_strict(slot: &[u8], codec: LowCmdCodec) -> Result<Slot, Undecidable> {
    let d =
        decode_unitree(codec.kind(), slot, &Limits::default()).map_err(|_| Undecidable::Decode)?;
    let msg = match d.message {
        UnitreeMessage::GoLowCmd(m) if codec == LowCmdCodec::Go => WireLowCmd::Go(m),
        UnitreeMessage::HgLowCmd(m) if codec == LowCmdCodec::Hg => WireLowCmd::Hg(m),
        _ => return Err(Undecidable::Decode),
    };
    let header: [u8; 4] = slot
        .get(..4)
        .and_then(|h| h.try_into().ok())
        .ok_or(Undecidable::Decode)?;
    let (endian, version) = representation(header).ok_or(Undecidable::Decode)?;
    let body = slot.get(4..).ok_or(Undecidable::Decode)?;
    if d.trailing_bytes > 3 {
        return Err(Undecidable::Trailing);
    }
    let trailing = body.get(d.consumed..).ok_or(Undecidable::Decode)?;
    if trailing.iter().any(|b| *b != 0) {
        return Err(Undecidable::Trailing);
    }
    let mut scratch = [0u8; BODY_SCRATCH];
    let n = encode_body(&msg, endian, version, &mut scratch).ok_or(Undecidable::NonCanonical)?;
    if n != d.consumed || scratch.get(..n) != body.get(..n) {
        return Err(Undecidable::NonCanonical);
    }
    Ok(Slot {
        msg,
        header,
        endian,
        version,
        body_len: n,
    })
}

/// Why a rewrite was not done.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum RewriteError {
    /// The slot's encapsulation header is not a representation the encoder
    /// writes.
    Representation,
    /// The encoding does not fit the slot exactly (`4 + body ..= +3`).
    Length,
    /// A value could not be represented without crossing a bound, or the
    /// firewall output does not match the frame's shape / modes.
    Value,
    /// Decoding the written slot did not give back the intended message
    /// with a valid CRC.
    Verify,
}

impl RewriteError {
    pub fn as_str(self) -> &'static str {
        match self {
            RewriteError::Representation => "representation",
            RewriteError::Length => "length",
            RewriteError::Value => "value",
            RewriteError::Verify => "verify",
        }
    }
}

/// Encode `msg` into `slot` behind `header` (the slot keeps its length,
/// trailing octets zeroed), then verify (module docs). On error the slot
/// may be partly written: the caller must suppress the sample.
pub fn write_slot(slot: &mut [u8], header: [u8; 4], msg: &WireLowCmd) -> Result<(), RewriteError> {
    let (endian, version) = representation(header).ok_or(RewriteError::Representation)?;
    let mut scratch = [0u8; BODY_SCRATCH];
    let n = encode_body(msg, endian, version, &mut scratch).ok_or(RewriteError::Length)?;
    let total = 4 + n;
    if slot.len() < total || slot.len() > total + 3 {
        return Err(RewriteError::Length);
    }
    slot[..4].copy_from_slice(&header);
    slot[4..total].copy_from_slice(&scratch[..n]);
    slot[total..].fill(0);
    // Verify with the independent decoder.
    let back = decode_strict(slot, msg.codec()).map_err(|_| RewriteError::Verify)?;
    let mut again = [0u8; BODY_SCRATCH];
    let m = encode_body(&back.msg, endian, version, &mut again).ok_or(RewriteError::Verify)?;
    if m != n || again[..m] != scratch[..n] || !back.msg.crc_ok() {
        return Err(RewriteError::Verify);
    }
    Ok(())
}

/// Build the wire frame for a **limited** firewall output: `input` with
/// every slot's numeric fields replaced by `out`'s (rounded away from the
/// input), mode octets and non-motor fields kept, CRC resealed.
pub fn limited(input: &WireLowCmd, out: &JointFrame) -> Result<WireLowCmd, RewriteError> {
    let n = input.slots();
    if out.slots() != n || out.mode_pr != input.modes().0 || out.mode_machine != input.modes().1 {
        return Err(RewriteError::Value);
    }
    let mut msg = *input;
    for (i, o) in out.motors().iter().enumerate() {
        let w = input.motor(i).ok_or(RewriteError::Value)?;
        if MotorMode::from_u8(w.mode) != o.mode {
            return Err(RewriteError::Value);
        }
        let f = |o: f64, i: f32| round::away_from(o, f64::from(i)).ok_or(RewriteError::Value);
        msg.set_motor(
            i,
            WireMotor {
                mode: w.mode,
                q: f(o.q, w.q)?,
                dq: f(o.dq, w.dq)?,
                tau: f(o.tau, w.tau)?,
                kp: f(o.kp, w.kp)?,
                kd: f(o.kd, w.kd)?,
            },
        );
    }
    msg.seal();
    Ok(msg)
}

/// The last frame the gateway forwarded as **accepted** on a channel: the
/// firewall's output (`f64`) and the wire frame it became (`f32`), so a
/// later hold can copy the wire values bit-exact.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct Forwarded {
    pub frame: JointFrame,
    pub wire: WireLowCmd,
    /// Encapsulation header of the payload it was forwarded in.
    pub header: [u8; 4],
}

/// Build the wire frame for a **substitute** (hold or damping): non-motor
/// fields from `last` (or the [`template`]), motor fields from `sub`; a
/// field equal to the held frame's firewall value is copied from its wire
/// value, anything else rounds toward zero.
pub fn substitute(
    codec: LowCmdCodec,
    sub: &JointFrame,
    last: Option<&Forwarded>,
) -> Result<WireLowCmd, RewriteError> {
    let n = codec.slots();
    if sub.slots() != n {
        return Err(RewriteError::Value);
    }
    let mut msg = match last {
        Some(l) if l.wire.codec() == codec => l.wire,
        _ => template(codec),
    };
    for (i, o) in sub.motors().iter().enumerate() {
        let base = msg.motor(i).unwrap_or_default();
        let held = last.and_then(|l| l.frame.motor(i).copied().zip(l.wire.motor(i)));
        let pick = |o: f64, fw: Option<(f64, f32)>| -> Result<f32, RewriteError> {
            match fw {
                Some((f, w)) if f.to_bits() == o.to_bits() => Ok(w),
                _ => round::toward_zero(o).ok_or(RewriteError::Value),
            }
        };
        let (fq, fdq, ftau, fkp, fkd) = match held {
            Some((f, w)) => (
                Some((f.q, w.q)),
                Some((f.dq, w.dq)),
                Some((f.tau, w.tau)),
                Some((f.kp, w.kp)),
                Some((f.kd, w.kd)),
            ),
            None => (None, None, None, None, None),
        };
        let mode = match o.mode {
            MotorMode::Disabled => 0,
            MotorMode::Enabled if base.mode != 0 => base.mode,
            MotorMode::Enabled => 0x01,
        };
        msg.set_motor(
            i,
            WireMotor {
                mode,
                q: pick(o.q, fq)?,
                dq: pick(o.dq, fdq)?,
                tau: pick(o.tau, ftau)?,
                kp: pick(o.kp, fkp)?,
                kd: pick(o.kd, fkd)?,
            },
        );
    }
    if let WireLowCmd::Hg(m) = &mut msg {
        if let Some(pr) = sub.mode_pr {
            m.mode_pr = pr;
        }
        if let Some(mm) = sub.mode_machine {
            m.mode_machine = mm;
        }
    }
    msg.seal();
    Ok(msg)
}

/// Test / harness helper: a full serialized payload (encapsulation header
/// + canonical body + zero padding to a multiple of 4).
pub fn encode_payload(msg: &WireLowCmd, rep: Representation) -> Vec<u8> {
    let id = rep.id().to_be_bytes();
    let (endian, version) = (
        rep.endian().unwrap_or(Endian::Little),
        rep.version().unwrap_or(XcdrVersion::Xcdr1),
    );
    let mut scratch = [0u8; BODY_SCRATCH];
    let n = encode_body(msg, endian, version, &mut scratch).unwrap_or(0);
    let pad = (4 - n % 4) % 4;
    let mut v = vec![id[0], id[1], 0, pad as u8];
    v.extend_from_slice(&scratch[..n]);
    v.extend(std::iter::repeat_n(0u8, pad));
    v
}

/// The encapsulation header of a payload (for [`Forwarded::header`]).
pub fn header_of(slot: &[u8]) -> Option<[u8; 4]> {
    let h: [u8; 4] = slot.get(..4)?.try_into().ok()?;
    Encapsulation::parse(slot).ok()?;
    Some(h)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample(codec: LowCmdCodec, seed: u32) -> WireLowCmd {
        let mut m = template(codec);
        for i in 0..m.slots() {
            let k = (i as f32 + 1.0) * (seed as f32 + 1.0);
            m.set_motor(
                i,
                WireMotor {
                    mode: if i % 3 == 0 { 0x0A } else { 0x01 },
                    q: 0.01 * k,
                    dq: -0.02 * k,
                    tau: 0.5,
                    kp: 20.0 + k,
                    kd: 0.5,
                },
            );
        }
        if let WireLowCmd::Go(g) = &mut m {
            g.sn = [seed, 7];
            g.wireless_remote[3] = 9;
            g.reserve = 0xdead_beef;
        }
        if let WireLowCmd::Hg(h) = &mut m {
            h.mode_machine = 5;
            h.reserve = [1, 2, 3, seed];
        }
        m.seal();
        m
    }

    const REPS: [Representation; 6] = [
        Representation::CdrLe,
        Representation::CdrBe,
        Representation::Cdr2Le,
        Representation::Cdr2Be,
        Representation::DCdr2Le,
        Representation::DCdr2Be,
    ];

    #[test]
    fn encoder_agrees_with_the_independent_decoder() {
        for codec in [LowCmdCodec::Go, LowCmdCodec::Hg] {
            for rep in REPS {
                for seed in 0..5 {
                    let m = sample(codec, seed);
                    let p = encode_payload(&m, rep);
                    assert_eq!(p.len() % 4, 0);
                    let s = decode_strict(&p, codec)
                        .unwrap_or_else(|e| panic!("{codec:?} {rep:?}: {e:?}"));
                    assert_eq!(s.msg, m);
                    assert!(s.msg.crc_ok());
                }
            }
        }
        // Known sizes: go XCDR1 body 808, hg XCDR1 body 1000 (+4: 812 /
        // 1004, which happen to equal the C++ image sizes).
        let go = encode_payload(&sample(LowCmdCodec::Go, 1), Representation::CdrLe);
        assert_eq!(go.len(), 812);
        let hg = encode_payload(&sample(LowCmdCodec::Hg, 1), Representation::CdrLe);
        assert_eq!(hg.len(), 1004);
    }

    #[test]
    fn non_canonical_and_trailing_are_undecidable() {
        let m = sample(LowCmdCodec::Go, 3);
        let mut p = encode_payload(&m, Representation::CdrLe);
        // Padding octet after the first motor's mode (body offset 23).
        p[4 + 23] = 0x55;
        assert_eq!(
            decode_strict(&p, LowCmdCodec::Go),
            Err(Undecidable::NonCanonical)
        );
        let mut t = encode_payload(&m, Representation::CdrLe);
        t.extend_from_slice(&[0, 0, 0, 0]);
        assert_eq!(
            decode_strict(&t, LowCmdCodec::Go),
            Err(Undecidable::Trailing)
        );
        let mut z = encode_payload(&m, Representation::CdrLe);
        z.extend_from_slice(&[0, 1]);
        assert_eq!(
            decode_strict(&z, LowCmdCodec::Go),
            Err(Undecidable::Trailing)
        );
        // XCDR2 with an oversized DHEADER: robodr-cdr skips the excess, the
        // canonical check refuses it.
        let hg = sample(LowCmdCodec::Hg, 2);
        let mut x = encode_payload(&hg, Representation::Cdr2Le);
        let dh = u32::from_le_bytes([x[8], x[9], x[10], x[11]]);
        x[8..12].copy_from_slice(&(dh + 4).to_le_bytes());
        x.splice(12 + dh as usize..12 + dh as usize, [0u8; 4]);
        assert!(decode_strict(&x, LowCmdCodec::Hg).is_err());
        assert_eq!(
            decode_strict(&p[..100], LowCmdCodec::Go),
            Err(Undecidable::Decode)
        );
    }

    #[test]
    fn write_slot_same_length_and_verified() {
        for codec in [LowCmdCodec::Go, LowCmdCodec::Hg] {
            for rep in REPS {
                let a = sample(codec, 1);
                let b = sample(codec, 9);
                let mut slot = encode_payload(&a, rep);
                let len = slot.len();
                let h = header_of(&slot).unwrap();
                write_slot(&mut slot, h, &b).unwrap();
                assert_eq!(slot.len(), len);
                assert_eq!(decode_strict(&slot, codec).unwrap().msg, b);
                // A slot of another length is refused.
                let mut short = slot[..len - 4].to_vec();
                assert_eq!(write_slot(&mut short, h, &b), Err(RewriteError::Length));
                // A message with a wrong CRC fails verification.
                let mut bad = b;
                if let WireLowCmd::Go(g) = &mut bad {
                    g.crc ^= 1;
                }
                if let WireLowCmd::Hg(g) = &mut bad {
                    g.crc ^= 1;
                }
                assert_eq!(write_slot(&mut slot, h, &bad), Err(RewriteError::Verify));
            }
        }
    }
}
