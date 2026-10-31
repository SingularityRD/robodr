//! Strict, offset-reporting RTPS walker for the in-path gateway.
//!
//! `robodr-rtps` is the *passive* parser: where DDS stacks differ it reads
//! the superset and flags the deviation, so a detector cannot be blinded.
//! An enforcement point has the opposite need: it must know **exactly**
//! which bytes a receiver will read as a sample's payload, so it can decide
//! on them and rewrite them in place. [`walk`] therefore refuses
//! ([`WalkError`]) every datagram whose submessage structure is not
//! unambiguous, and reports, for every DATA / DATA_FRAG, the submessage
//! bounds, the writer GUID (source prefix after INFO_SRC + writerId), the
//! sequence number and the serialized payload range.
//!
//! Refused (the whole datagram is "undecidable", see the gateway's
//! `malformed_datagram` policy):
//!
//! - no `RTPS` magic, a header shorter than 20 octets, protocol major != 2;
//! - a submessage header or length running past the datagram;
//! - `octetsToNextHeader == 0` (= "to the end of the message") on a
//!   submessage that is not the last one cannot happen by construction; on
//!   PAD / INFO_TS it is an empty body (DDSI-RTPS 2.5 §9.4.5.1.3);
//! - INFO_SRC shorter than 20, INFO_DST shorter than 12, INFO_TS (without
//!   the `I` flag) shorter than 8 octets;
//! - DATA shorter than 20 / DATA_FRAG shorter than 32 octets, an
//!   `octetsToInlineQos` below the fixed part or past the submessage, an
//!   inline QoS list that is not 4-aligned or has no sentinel inside the
//!   submessage, both `D` and `K` set, a payload shorter than its 4-octet
//!   encapsulation header;
//! - DDS-Security submessages (`SEC_*`, `SRTPS_*`, 0x30..=0x35) when
//!   [`WalkOptions::refuse_secure`] is set: their content cannot be read,
//!   so nothing in them can be decided;
//! - more than [`MAX_SAMPLES`] DATA / DATA_FRAG submessages.
//!
//! Everything else (HEARTBEAT, ACKNACK, GAP, *_FRAG control, INFO_REPLY*,
//! vendor submessages, unknown ids) is skipped by length and forwarded
//! untouched: a receiver skips them the same way.
//!
//! [`suppress`] turns one DATA / DATA_FRAG into a PAD submessage of the
//! same length, so the receiver skips it as if the sample had been lost in
//! transit (see the crate docs, "What hold means on the wire").

use std::ops::Range;

/// RTPS header length.
pub const HEADER_LEN: usize = 20;
/// Most DATA / DATA_FRAG submessages decided in one datagram.
pub const MAX_SAMPLES: usize = 256;

pub const PAD: u8 = 0x01;
pub const ACKNACK: u8 = 0x06;
pub const HEARTBEAT: u8 = 0x07;
pub const GAP: u8 = 0x08;
pub const INFO_TS: u8 = 0x09;
pub const INFO_SRC: u8 = 0x0c;
pub const INFO_DST: u8 = 0x0e;
pub const DATA: u8 = 0x15;
pub const DATA_FRAG: u8 = 0x16;

const FLAG_E: u8 = 0x01;
/// DATA / DATA_FRAG: inline QoS present.
const FLAG_Q: u8 = 0x02;
/// DATA: serialized data.
const FLAG_DATA_D: u8 = 0x04;
/// DATA: serialized key.
const FLAG_DATA_K: u8 = 0x08;
/// DATA: non-standard payload.
const FLAG_DATA_N: u8 = 0x10;
/// DATA_FRAG: key.
const FLAG_FRAG_K: u8 = 0x04;
/// DATA_FRAG: non-standard payload.
const FLAG_FRAG_N: u8 = 0x08;
/// INFO_TS: invalidate.
const FLAG_TS_I: u8 = 0x02;

const PID_SENTINEL: u16 = 0x0001;

pub type GuidPrefix = [u8; 12];
pub type Guid = [u8; 16];

/// The participant prefix of a GUID (its first 12 octets).
pub fn guid_prefix(g: &Guid) -> GuidPrefix {
    g.first_chunk::<12>().copied().unwrap_or_default()
}

/// The entity id of a GUID (its last 4 octets).
pub fn guid_entity(g: &Guid) -> [u8; 4] {
    g.last_chunk::<4>().copied().unwrap_or_default()
}

/// The GUID of `entity` in participant `prefix`.
pub fn guid_of(prefix: &GuidPrefix, entity: &[u8; 4]) -> Guid {
    let mut g = [0u8; 16];
    for (d, s) in g.iter_mut().zip(prefix.iter().chain(entity)) {
        *d = *s;
    }
    g
}

/// The standard builtin writer entity ids (DDSI-RTPS 2.5 §9.3.1.3,
/// DDS-Security 1.1 §7.4.7.1, DDS-XTypes 1.3 §7.6.3.3.4): SPDP, SEDP
/// topics / publications / subscriptions, participant message, their
/// secure variants, the stateless / volatile-secure message writers and
/// the type-lookup request / reply writers.
pub const BUILTIN_WRITERS: [[u8; 4]; 13] = [
    [0x00, 0x01, 0x00, 0xc2], // SPDP
    [0x00, 0x00, 0x02, 0xc2], // SEDP topics
    [0x00, 0x00, 0x03, 0xc2], // SEDP publications
    [0x00, 0x00, 0x04, 0xc2], // SEDP subscriptions
    [0x00, 0x02, 0x00, 0xc2], // participant message
    [0xff, 0x00, 0x03, 0xc2], // secure publications
    [0xff, 0x00, 0x04, 0xc2], // secure subscriptions
    [0xff, 0x02, 0x00, 0xc2], // secure participant message
    [0xff, 0x01, 0x01, 0xc2], // SPDP reliable secure
    [0x00, 0x02, 0x01, 0xc3], // stateless message
    [0xff, 0x02, 0x02, 0xc3], // volatile message secure
    [0x00, 0x03, 0x00, 0xc3], // type lookup request
    [0x00, 0x03, 0x01, 0xc3], // type lookup reply
];

/// Is this writer entity one of the standard builtin (discovery) writers?
/// Only those: a writer whose entity merely has the builtin kind bits
/// (`0xc0`) but another id is a user writer for the gateway (gateway
/// review, finding 7: a receiver matches it like any writer its SEDP
/// announced), so its samples are decided.
pub fn is_builtin_entity(entity: [u8; 4]) -> bool {
    BUILTIN_WRITERS.contains(&entity)
}

/// DATA or DATA_FRAG.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SampleKind {
    Data,
    DataFrag,
}

/// What a DATA carries.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Content {
    /// `D`: a serialized data payload.
    Data,
    /// `K`: a serialized key only.
    Key,
    /// Neither: no payload (an inline-QoS status change).
    None,
}

/// One DATA / DATA_FRAG of a datagram, with its offsets.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Sample {
    pub kind: SampleKind,
    /// Submessage bounds (header included).
    pub sub: Range<usize>,
    pub little_endian: bool,
    /// Source prefix (header / INFO_SRC) + writerId.
    pub writer: Guid,
    /// `writerSN` as one signed 64-bit value (`high << 32 | low`).
    pub sn: i64,
    /// DATA only: what it carries.
    pub content: Content,
    /// DATA with `D` or `K`: the serialized payload (encapsulation header
    /// included), up to the end of the submessage (so submessage padding
    /// may trail it).
    pub payload: Option<Range<usize>>,
    /// `N` flag (non-standard payload).
    pub non_standard: bool,
    /// The writer is a builtin (discovery) entity.
    pub builtin: bool,
}

impl Sample {
    pub fn writer_prefix(&self) -> GuidPrefix {
        guid_prefix(&self.writer)
    }

    pub fn writer_entity(&self) -> [u8; 4] {
        guid_entity(&self.writer)
    }
}

/// What [`walk`] found besides the samples.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct Summary {
    pub submessages: usize,
    /// Any DATA / DATA_FRAG from a builtin writer (discovery).
    pub has_builtin: bool,
    /// Any DATA / DATA_FRAG from a user writer.
    pub has_user: bool,
}

/// Why a datagram is not decidable.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum WalkError {
    NotRtps,
    UnsupportedVersion,
    Truncated,
    Malformed,
    Secure,
    TooManySamples,
}

impl WalkError {
    pub fn as_str(self) -> &'static str {
        match self {
            WalkError::NotRtps => "not_rtps",
            WalkError::UnsupportedVersion => "rtps_version",
            WalkError::Truncated => "rtps_truncated",
            WalkError::Malformed => "rtps_malformed",
            WalkError::Secure => "rtps_secure_submessage",
            WalkError::TooManySamples => "rtps_too_many_samples",
        }
    }
}

/// Walk options.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct WalkOptions {
    /// Refuse datagrams that contain DDS-Security submessages.
    pub refuse_secure: bool,
}

impl Default for WalkOptions {
    fn default() -> Self {
        Self {
            refuse_secure: true,
        }
    }
}

fn u16_at(b: &[u8], at: usize, le: bool) -> Option<u16> {
    let x = [*b.get(at)?, *b.get(at.checked_add(1)?)?];
    Some(if le {
        u16::from_le_bytes(x)
    } else {
        u16::from_be_bytes(x)
    })
}

fn u32_at(b: &[u8], at: usize, le: bool) -> Option<u32> {
    let x = arr4(b, at)?;
    Some(if le {
        u32::from_le_bytes(x)
    } else {
        u32::from_be_bytes(x)
    })
}

fn arr4(b: &[u8], at: usize) -> Option<[u8; 4]> {
    b.get(at..)?.first_chunk().copied()
}

/// The RTPS header's GUID prefix, if `d` starts with a valid header.
pub fn header_prefix(d: &[u8]) -> Option<GuidPrefix> {
    if d.get(..4)? != b"RTPS" {
        return None;
    }
    let mut p = [0u8; 12];
    p.copy_from_slice(d.get(8..20)?);
    Some(p)
}

/// Walk one datagram (see the module docs). `out` is cleared and receives
/// the samples in wire order.
pub fn walk(d: &[u8], opts: WalkOptions, out: &mut Vec<Sample>) -> Result<Summary, WalkError> {
    out.clear();
    if d.len() < HEADER_LEN || d.get(..4) != Some(b"RTPS") {
        return Err(WalkError::NotRtps);
    }
    if d.get(4) != Some(&2) {
        return Err(WalkError::UnsupportedVersion);
    }
    let mut source: GuidPrefix = header_prefix(d).ok_or(WalkError::NotRtps)?;
    let mut sum = Summary::default();
    let mut pos = HEADER_LEN;
    while pos < d.len() {
        let id = *d.get(pos).ok_or(WalkError::Truncated)?;
        let flags = *d.get(pos + 1).ok_or(WalkError::Truncated)?;
        let le = flags & FLAG_E != 0;
        let otnh = usize::from(u16_at(d, pos + 2, le).ok_or(WalkError::Truncated)?);
        let body = pos + 4;
        let end = if otnh == 0 && id != PAD && id != INFO_TS {
            d.len()
        } else {
            body.checked_add(otnh).ok_or(WalkError::Truncated)?
        };
        if end > d.len() {
            return Err(WalkError::Truncated);
        }
        let blen = end - body;
        sum.submessages += 1;
        match id {
            INFO_SRC => {
                if blen < 20 {
                    return Err(WalkError::Malformed);
                }
                // body + 20 <= end <= d.len() (checked above).
                source = d
                    .get(body + 8..)
                    .and_then(|s| s.first_chunk().copied())
                    .ok_or(WalkError::Malformed)?;
            }
            INFO_DST => {
                if blen < 12 {
                    return Err(WalkError::Malformed);
                }
            }
            INFO_TS => {
                if flags & FLAG_TS_I == 0 && blen < 8 {
                    return Err(WalkError::Malformed);
                }
            }
            DATA | DATA_FRAG => {
                let frag = id == DATA_FRAG;
                let fixed: usize = if frag { 32 } else { 20 };
                if blen < fixed {
                    return Err(WalkError::Malformed);
                }
                let oti = usize::from(u16_at(d, body + 2, le).ok_or(WalkError::Malformed)?);
                // octetsToInlineQos counts from the end of its own field.
                if oti < fixed - 4 {
                    return Err(WalkError::Malformed);
                }
                let qos_start = body + 4 + oti;
                if qos_start > end {
                    return Err(WalkError::Malformed);
                }
                let writer_id = arr4(d, body + 8).ok_or(WalkError::Malformed)?;
                let hi = u32_at(d, body + 12, le).ok_or(WalkError::Malformed)?;
                let lo = u32_at(d, body + 16, le).ok_or(WalkError::Malformed)?;
                let sn = (i64::from(hi as i32) << 32) | i64::from(lo);
                let writer = guid_of(&source, &writer_id);
                let after_qos = if flags & FLAG_Q != 0 {
                    skip_parameter_list(d, qos_start, end, le)?
                } else {
                    qos_start
                };
                let (content, payload, non_standard) = if frag {
                    let _ = flags & FLAG_FRAG_K;
                    (Content::Data, None, flags & FLAG_FRAG_N != 0)
                } else {
                    let dflag = flags & FLAG_DATA_D != 0;
                    let kflag = flags & FLAG_DATA_K != 0;
                    let content = match (dflag, kflag) {
                        (true, true) => return Err(WalkError::Malformed),
                        (true, false) => Content::Data,
                        (false, true) => Content::Key,
                        (false, false) => Content::None,
                    };
                    let payload = if content == Content::None {
                        None
                    } else {
                        if end - after_qos < 4 {
                            return Err(WalkError::Malformed);
                        }
                        Some(after_qos..end)
                    };
                    (content, payload, flags & FLAG_DATA_N != 0)
                };
                let builtin = is_builtin_entity(writer_id);
                sum.has_builtin |= builtin;
                sum.has_user |= !builtin;
                if out.len() >= MAX_SAMPLES {
                    return Err(WalkError::TooManySamples);
                }
                out.push(Sample {
                    kind: if frag {
                        SampleKind::DataFrag
                    } else {
                        SampleKind::Data
                    },
                    sub: pos..end,
                    little_endian: le,
                    writer,
                    sn,
                    content,
                    payload,
                    non_standard,
                    builtin,
                });
            }
            0x30..=0x35 if opts.refuse_secure => return Err(WalkError::Secure),
            _ => {}
        }
        pos = end;
    }
    Ok(sum)
}

/// Skip an inline-QoS parameter list starting at `at`; returns the offset
/// after its sentinel. Strict: every parameter length must be a multiple
/// of 4 and the sentinel must lie inside the submessage.
fn skip_parameter_list(d: &[u8], mut at: usize, end: usize, le: bool) -> Result<usize, WalkError> {
    loop {
        if at.checked_add(4).is_none_or(|e| e > end) {
            return Err(WalkError::Malformed);
        }
        let pid = u16_at(d, at, le).ok_or(WalkError::Malformed)?;
        let len = usize::from(u16_at(d, at + 2, le).ok_or(WalkError::Malformed)?);
        at += 4;
        if pid == PID_SENTINEL {
            return Ok(at);
        }
        if !len.is_multiple_of(4) || at + len > end {
            return Err(WalkError::Malformed);
        }
        at += len;
    }
}

/// Replace the submessage `sub` of `d` by a PAD of the same length (body
/// zeroed), keeping its endianness flag. Receivers skip a PAD, so the
/// sample is gone as if it had been lost in transit. Returns `false` if
/// `sub` is not a valid submessage range of `d`.
pub fn suppress(d: &mut [u8], sub: &Range<usize>, little_endian: bool) -> bool {
    let Some(len) = sub.end.checked_sub(sub.start) else {
        return false;
    };
    if len < 4 || sub.end > d.len() {
        return false;
    }
    let Ok(body) = u16::try_from(len - 4) else {
        return false;
    };
    let Some((head, rest)) = d
        .get_mut(sub.start..sub.end)
        .and_then(|s| s.split_first_chunk_mut::<4>())
    else {
        return false;
    };
    let [b0, b1] = if little_endian {
        body.to_le_bytes()
    } else {
        body.to_be_bytes()
    };
    *head = [PAD, if little_endian { FLAG_E } else { 0 }, b0, b1];
    rest.fill(0);
    true
}

/// Test / harness helper: builds RTPS datagrams.
pub mod build {
    use super::*;

    /// A datagram under construction.
    #[derive(Debug, Clone)]
    pub struct Datagram {
        pub bytes: Vec<u8>,
    }

    impl Datagram {
        /// RTPS 2.3 header, vendor Cyclone DDS (0x0110).
        pub fn new(prefix: GuidPrefix) -> Self {
            let mut bytes = b"RTPS".to_vec();
            bytes.extend_from_slice(&[2, 3, 0x01, 0x10]);
            bytes.extend_from_slice(&prefix);
            Self { bytes }
        }

        fn sub(&mut self, id: u8, flags: u8, body: &[u8]) -> &mut Self {
            self.bytes.push(id);
            self.bytes.push(flags | FLAG_E);
            self.bytes
                .extend_from_slice(&(body.len() as u16).to_le_bytes());
            self.bytes.extend_from_slice(body);
            self
        }

        pub fn info_ts(&mut self, sec: u32, frac: u32) -> &mut Self {
            let mut b = sec.to_le_bytes().to_vec();
            b.extend_from_slice(&frac.to_le_bytes());
            self.sub(INFO_TS, 0, &b)
        }

        pub fn info_src(&mut self, prefix: GuidPrefix) -> &mut Self {
            let mut b = vec![0, 0, 0, 0, 2, 3, 0x01, 0x10];
            b.extend_from_slice(&prefix);
            self.sub(INFO_SRC, 0, &b)
        }

        pub fn heartbeat(&mut self, writer: [u8; 4], first: i64, last: i64) -> &mut Self {
            let mut b = vec![0u8; 4];
            b.extend_from_slice(&writer);
            for sn in [first, last] {
                b.extend_from_slice(&((sn >> 32) as i32).to_le_bytes());
                b.extend_from_slice(&(sn as u32).to_le_bytes());
            }
            b.extend_from_slice(&1u32.to_le_bytes());
            self.sub(HEARTBEAT, 0, &b)
        }

        /// A DATA with a serialized payload (padded to 4 octets), optional
        /// inline QoS parameters (pid, value) before the sentinel.
        pub fn data(
            &mut self,
            writer: [u8; 4],
            sn: i64,
            qos: &[(u16, Vec<u8>)],
            payload: &[u8],
        ) -> &mut Self {
            let mut b = vec![0, 0];
            b.extend_from_slice(&16u16.to_le_bytes());
            b.extend_from_slice(&[0, 0, 0, 0]);
            b.extend_from_slice(&writer);
            b.extend_from_slice(&((sn >> 32) as i32).to_le_bytes());
            b.extend_from_slice(&(sn as u32).to_le_bytes());
            let mut flags = FLAG_DATA_D;
            if !qos.is_empty() {
                flags |= FLAG_Q;
                for (pid, v) in qos {
                    b.extend_from_slice(&pid.to_le_bytes());
                    b.extend_from_slice(&(v.len() as u16).to_le_bytes());
                    b.extend_from_slice(v);
                }
                b.extend_from_slice(&PID_SENTINEL.to_le_bytes());
                b.extend_from_slice(&[0, 0]);
            }
            b.extend_from_slice(payload);
            while !b.len().is_multiple_of(4) {
                b.push(0);
            }
            self.sub(DATA, flags, &b)
        }

        /// One DATA_FRAG carrying `frag` (fragment `num` of a sample of
        /// `sample_size` octets in fragments of `frag_size`).
        #[allow(clippy::too_many_arguments)]
        pub fn data_frag(
            &mut self,
            writer: [u8; 4],
            sn: i64,
            num: u32,
            frag_size: u16,
            sample_size: u32,
            frag: &[u8],
        ) -> &mut Self {
            let mut b = vec![0, 0];
            b.extend_from_slice(&28u16.to_le_bytes());
            b.extend_from_slice(&[0, 0, 0, 0]);
            b.extend_from_slice(&writer);
            b.extend_from_slice(&((sn >> 32) as i32).to_le_bytes());
            b.extend_from_slice(&(sn as u32).to_le_bytes());
            b.extend_from_slice(&num.to_le_bytes());
            b.extend_from_slice(&1u16.to_le_bytes());
            b.extend_from_slice(&frag_size.to_le_bytes());
            b.extend_from_slice(&sample_size.to_le_bytes());
            b.extend_from_slice(frag);
            while !b.len().is_multiple_of(4) {
                b.push(0);
            }
            self.sub(DATA_FRAG, 0, &b)
        }

        /// A raw submessage.
        pub fn raw(&mut self, id: u8, flags: u8, body: &[u8]) -> &mut Self {
            self.sub(id, flags, body)
        }

        pub fn finish(&self) -> Vec<u8> {
            self.bytes.clone()
        }
    }
}

#[cfg(test)]
mod tests {
    use super::build::Datagram;
    use super::*;

    const P: GuidPrefix = [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12];
    const Q: GuidPrefix = [9; 12];
    const W: [u8; 4] = [0, 0, 0x12, 0x03];

    #[test]
    fn walks_data_with_offsets() {
        let payload = [0u8, 1, 0, 0, 0xaa, 0xbb, 0xcc, 0xdd];
        let d = Datagram::new(P)
            .info_ts(1, 2)
            .data(W, 7, &[(0x0070, vec![0; 16])], &payload)
            .heartbeat(W, 1, 7)
            .info_src(Q)
            .data(W, 8, &[], &payload)
            .finish();
        let mut v = Vec::new();
        let s = walk(&d, WalkOptions::default(), &mut v).unwrap();
        assert_eq!(s.submessages, 5);
        assert!(s.has_user && !s.has_builtin);
        assert_eq!(v.len(), 2);
        assert_eq!(v[0].sn, 7);
        assert_eq!(&v[0].writer[..12], &P);
        assert_eq!(&v[1].writer[..12], &Q);
        assert_eq!(&d[v[0].payload.clone().unwrap()], &payload);
        assert_eq!(&d[v[1].payload.clone().unwrap()], &payload);
        assert_eq!(v[1].sub.end, d.len());
    }

    #[test]
    fn suppress_makes_a_pad_that_receivers_skip() {
        let payload = [0u8, 1, 0, 0, 1, 2, 3, 4];
        let mut d = Datagram::new(P)
            .data(W, 1, &[], &payload)
            .heartbeat(W, 1, 1)
            .finish();
        let mut v = Vec::new();
        walk(&d, WalkOptions::default(), &mut v).unwrap();
        let len = d.len();
        assert!(suppress(&mut d, &v[0].sub, true));
        assert_eq!(d.len(), len);
        let s = walk(&d, WalkOptions::default(), &mut v).unwrap();
        assert_eq!(s.submessages, 2);
        assert!(v.is_empty());
        // The independent passive parser agrees: no user sample left.
        let r = robodr_rtps::walk_user_data(&d);
        assert!(r.is_some_and(|r| r.samples.is_empty()));
    }

    #[test]
    fn refusals() {
        let mut v = Vec::new();
        let o = WalkOptions::default();
        assert_eq!(walk(b"RTPX", o, &mut v), Err(WalkError::NotRtps));
        let mut d = Datagram::new(P).data(W, 1, &[], &[0, 1, 0, 0]).finish();
        d.truncate(d.len() - 1);
        // The last submessage now overruns.
        assert_eq!(walk(&d, o, &mut v), Err(WalkError::Truncated));
        let mut d3 = Datagram::new(P).finish();
        d3[4] = 3;
        assert_eq!(walk(&d3, o, &mut v), Err(WalkError::UnsupportedVersion));
        let sec = Datagram::new(P).raw(0x33, 0, &[0; 8]).finish();
        assert_eq!(walk(&sec, o, &mut v), Err(WalkError::Secure));
        assert!(walk(
            &sec,
            WalkOptions {
                refuse_secure: false
            },
            &mut v
        )
        .is_ok());
        // Inline QoS without sentinel.
        let mut body = vec![0, 0, 16, 0, 0, 0, 0, 0];
        body.extend_from_slice(&W);
        body.extend_from_slice(&[0, 0, 0, 0, 1, 0, 0, 0]);
        body.extend_from_slice(&[0x70, 0, 4, 0, 0, 0, 0, 0]);
        let q = Datagram::new(P)
            .raw(DATA, FLAG_Q | FLAG_DATA_D, &body)
            .finish();
        assert_eq!(walk(&q, o, &mut v), Err(WalkError::Malformed));
        // D and K both set.
        let mut body2 = vec![0, 0, 16, 0, 0, 0, 0, 0];
        body2.extend_from_slice(&W);
        body2.extend_from_slice(&[0, 0, 0, 0, 1, 0, 0, 0, 0, 1, 0, 0]);
        let dk = Datagram::new(P)
            .raw(DATA, FLAG_DATA_D | FLAG_DATA_K, &body2)
            .finish();
        assert_eq!(walk(&dk, o, &mut v), Err(WalkError::Malformed));
    }

    #[test]
    fn data_frag_is_reported_without_payload() {
        let d = Datagram::new(P)
            .data_frag(W, 3, 1, 8, 16, &[0, 1, 0, 0, 1, 2, 3, 4])
            .finish();
        let mut v = Vec::new();
        walk(&d, WalkOptions::default(), &mut v).unwrap();
        assert_eq!(v[0].kind, SampleKind::DataFrag);
        assert_eq!(v[0].sn, 3);
        assert!(v[0].payload.is_none());
    }
}
