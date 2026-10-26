//! Wire-level primitives: endian-aware integer reads, the RTPS parameter-list
//! iterator, CDR strings / octet sequences and locators.
//!
//! Everything here works on borrowed slices and returns `None` (or stops
//! iterating) instead of panicking. No function allocates more than the bytes
//! that are actually present in the input: claimed lengths are always checked
//! against the remaining buffer *before* anything is copied.

use std::fmt;
use std::net::{Ipv4Addr, Ipv6Addr};

// ---------------------------------------------------------------------------
// Submessage ids and flags (DDSI-RTPS 2.5 §9.4.5.1.1, Table 9.13).
// ---------------------------------------------------------------------------

pub(crate) const SUBMSG_PAD: u8 = 0x01;
pub(crate) const SUBMSG_ACKNACK: u8 = 0x06;
pub(crate) const SUBMSG_HEARTBEAT: u8 = 0x07;
pub(crate) const SUBMSG_GAP: u8 = 0x08;
pub(crate) const SUBMSG_INFO_TS: u8 = 0x09;
pub(crate) const SUBMSG_INFO_SRC: u8 = 0x0c;
pub(crate) const SUBMSG_INFO_REPLY_IP4: u8 = 0x0d;
pub(crate) const SUBMSG_INFO_DST: u8 = 0x0e;
pub(crate) const SUBMSG_INFO_REPLY: u8 = 0x0f;
pub(crate) const SUBMSG_NACK_FRAG: u8 = 0x12;
pub(crate) const SUBMSG_HEARTBEAT_FRAG: u8 = 0x13;
pub(crate) const SUBMSG_DATA: u8 = 0x15;
pub(crate) const SUBMSG_DATA_FRAG: u8 = 0x16;
/// DDS-Security SEC_BODY..SRTPS_POSTFIX (0x30..=0x34). Content is protected.
pub(crate) const SUBMSG_SECURE_FIRST: u8 = 0x30;
pub(crate) const SUBMSG_SECURE_LAST: u8 = 0x34;
/// Ids 0x80..=0xff are vendor specific and must be skipped by other vendors.
pub(crate) const SUBMSG_VENDOR_FIRST: u8 = 0x80;

/// Endianness flag, common to every submessage: 1 = little-endian.
pub(crate) const FLAG_E: u8 = 0x01;
/// DATA / DATA_FRAG: inline QoS present.
pub(crate) const FLAG_Q: u8 = 0x02;
/// DATA: serialized data present.
pub(crate) const FLAG_D: u8 = 0x04;
/// DATA: serialized *key* present (mutually exclusive with D).
pub(crate) const FLAG_K: u8 = 0x08;
/// DATA_FRAG: the fragments carry the serialized key (bit 2, not bit 3!).
pub(crate) const FLAG_FRAG_K: u8 = 0x04;

// ---------------------------------------------------------------------------
// Parameter ids (DDSI-RTPS 2.5 §9.6.2.2.2 Table 9.12, §9.6.3 Table 9.14).
// ---------------------------------------------------------------------------

pub(crate) const PID_PAD: u16 = 0x0000;
pub(crate) const PID_SENTINEL: u16 = 0x0001;
pub(crate) const PID_PARTICIPANT_LEASE_DURATION: u16 = 0x0002;
pub(crate) const PID_TOPIC_NAME: u16 = 0x0005;
pub(crate) const PID_TYPE_NAME: u16 = 0x0007;
pub(crate) const PID_DOMAIN_ID: u16 = 0x000f;
pub(crate) const PID_PROTOCOL_VERSION: u16 = 0x0015;
pub(crate) const PID_VENDORID: u16 = 0x0016;
pub(crate) const PID_USER_DATA: u16 = 0x002c;
/// Endpoint (SEDP) unicast / multicast locators.
pub(crate) const PID_UNICAST_LOCATOR: u16 = 0x002f;
pub(crate) const PID_MULTICAST_LOCATOR: u16 = 0x0030;
pub(crate) const PID_DEFAULT_UNICAST_LOCATOR: u16 = 0x0031;
pub(crate) const PID_METATRAFFIC_UNICAST_LOCATOR: u16 = 0x0032;
pub(crate) const PID_METATRAFFIC_MULTICAST_LOCATOR: u16 = 0x0033;
pub(crate) const PID_DEFAULT_MULTICAST_LOCATOR: u16 = 0x0048;
pub(crate) const PID_PARTICIPANT_GUID: u16 = 0x0050;
pub(crate) const PID_ENDPOINT_GUID: u16 = 0x005a;
pub(crate) const PID_ENTITY_NAME: u16 = 0x0062;
pub(crate) const PID_KEY_HASH: u16 = 0x0070;
pub(crate) const PID_STATUS_INFO: u16 = 0x0071;
/// XCDR1 extended parameter header. Never legitimately used in discovery
/// data; we stop the list rather than mis-frame what follows it.
pub(crate) const PID_EXTENDED: u16 = 0x3f01;
pub(crate) const PID_DOMAIN_TAG: u16 = 0x4014;

/// Serialized-payload encapsulation identifiers. Always big-endian on the wire.
pub(crate) const CDR_BE: u16 = 0x0000;
pub(crate) const CDR_LE: u16 = 0x0001;
pub(crate) const PL_CDR_BE: u16 = 0x0002;
pub(crate) const PL_CDR_LE: u16 = 0x0003;

pub(crate) fn read_u16(buf: &[u8], pos: usize, le: bool) -> Option<u16> {
    let b: [u8; 2] = buf.get(pos..pos.checked_add(2)?)?.try_into().ok()?;
    Some(if le {
        u16::from_le_bytes(b)
    } else {
        u16::from_be_bytes(b)
    })
}

pub(crate) fn read_u32(buf: &[u8], pos: usize, le: bool) -> Option<u32> {
    let b: [u8; 4] = buf.get(pos..pos.checked_add(4)?)?.try_into().ok()?;
    Some(if le {
        u32::from_le_bytes(b)
    } else {
        u32::from_be_bytes(b)
    })
}

pub(crate) fn read_i32(buf: &[u8], pos: usize, le: bool) -> Option<i32> {
    read_u32(buf, pos, le).map(|v| v as i32)
}

/// Copy a fixed-size array out of `buf` at `pos`, if it fits.
pub(crate) fn read_array<const N: usize>(buf: &[u8], pos: usize) -> Option<[u8; N]> {
    buf.get(pos..pos.checked_add(N)?)?.try_into().ok()
}

/// Why a parameter list stopped before a sentinel.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum PlEnd {
    /// Still iterating.
    Open,
    /// Clean end: a PID_SENTINEL was read.
    Sentinel,
    /// The buffer ended without a sentinel, or a length ran past the buffer.
    Malformed,
    /// PID_EXTENDED: framing we deliberately do not follow.
    Unsupported,
}

/// Iterator over a parameter list: `(parameterId, value)` pairs until the
/// sentinel, the end of the buffer, or a length that does not fit. PID_PAD
/// entries are skipped. After iteration, [`ParameterList::end`] says how it
/// ended and [`ParameterList::pos`] is the offset just past the sentinel.
///
/// Lenient like the stacks we must agree with: a parameter length that is not
/// a multiple of 4 (§9.4.2.11 requires alignment) is accepted, the next
/// parameter is read exactly `length` octets later (what Fast DDS does), and
/// [`ParameterList::misaligned`] records it so the caller can flag it.
pub(crate) struct ParameterList<'a> {
    buf: &'a [u8],
    pos: usize,
    le: bool,
    end: PlEnd,
    misaligned: bool,
}

impl<'a> ParameterList<'a> {
    pub(crate) fn new(buf: &'a [u8], pos: usize, le: bool) -> Self {
        Self {
            buf,
            pos,
            le,
            end: PlEnd::Open,
            misaligned: false,
        }
    }

    pub(crate) fn end(&self) -> PlEnd {
        self.end
    }

    /// A parameter length was not a multiple of 4.
    pub(crate) fn misaligned(&self) -> bool {
        self.misaligned
    }

    pub(crate) fn pos(&self) -> usize {
        self.pos
    }
}

impl<'a> Iterator for ParameterList<'a> {
    type Item = (u16, &'a [u8]);

    fn next(&mut self) -> Option<Self::Item> {
        loop {
            if self.end != PlEnd::Open {
                return None;
            }
            let pid = read_u16(self.buf, self.pos, self.le);
            let plen = read_u16(self.buf, self.pos.saturating_add(2), self.le);
            let (Some(pid), Some(plen)) = (pid, plen) else {
                self.end = PlEnd::Malformed;
                return None;
            };
            let start = self.pos + 4; // cannot overflow: read_u16 at pos+2 succeeded
            if pid == PID_SENTINEL {
                // The sentinel's length is ignored by the spec.
                self.pos = start;
                self.end = PlEnd::Sentinel;
                return None;
            }
            if pid == PID_EXTENDED {
                self.end = PlEnd::Unsupported;
                return None;
            }
            let plen = plen as usize;
            if !plen.is_multiple_of(4) {
                self.misaligned = true;
            }
            let end = start + plen;
            if end > self.buf.len() {
                self.end = PlEnd::Malformed;
                return None;
            }
            self.pos = end;
            if pid == PID_PAD {
                continue;
            }
            return Some((pid, &self.buf[start..end]));
        }
    }
}

/// A CDR string: u32 length (including the trailing NUL), then the bytes.
/// Strict: the length must be at least 1, the bytes must fit in `value`, the
/// last byte must be NUL, no interior NUL, and the text must be UTF-8.
pub(crate) fn cdr_string(value: &[u8], le: bool) -> Option<String> {
    let n = read_u32(value, 0, le)? as usize;
    if n == 0 {
        return None;
    }
    let bytes = value.get(4..4usize.checked_add(n)?)?;
    let (last, text) = bytes.split_last()?;
    if *last != 0 || text.contains(&0) {
        return None;
    }
    std::str::from_utf8(text).ok().map(str::to_owned)
}

/// A CDR string read the way a C-string based stack reads it: the text runs
/// from after the u32 length up to the first NUL in the parameter value (or
/// to the end of the value if there is none); the length field is ignored.
/// Fast DDS reads topic and type names this way, so `"rt/cmd_vel\0x\0"` is
/// `rt/cmd_vel` to it. Returns the text and whether the encoding was
/// canonical (i.e. [`cdr_string`] accepts it and yields the same text).
/// `None` only if there is no length field or the text is not UTF-8.
pub(crate) fn cdr_string_lenient(value: &[u8], le: bool) -> Option<(String, bool)> {
    read_u32(value, 0, le)?;
    let rest = value.get(4..)?;
    let text = match rest.iter().position(|&b| b == 0) {
        Some(n) => &rest[..n],
        None => rest,
    };
    let text = std::str::from_utf8(text).ok()?;
    let canonical = cdr_string(value, le).as_deref() == Some(text);
    Some((text.to_owned(), canonical))
}

/// A CDR `sequence<octet>`: u32 length, then the bytes. Borrowed, never copied.
pub(crate) fn cdr_octets(value: &[u8], le: bool) -> Option<&[u8]> {
    let n = read_u32(value, 0, le)? as usize;
    value.get(4..4usize.checked_add(n)?)
}

/// `LOCATOR_KIND_UDPv4`.
pub const LOCATOR_KIND_UDPV4: i32 = 1;
/// `LOCATOR_KIND_UDPv6`.
pub const LOCATOR_KIND_UDPV6: i32 = 2;
/// `LOCATOR_KIND_INVALID`.
pub const LOCATOR_KIND_INVALID: i32 = -1;

/// An RTPS `Locator_t`: kind(i32) port(u32) address(16 octets).
///
/// Only UDPv4 / UDPv6 locators render to `ip:port`. Other kinds (TCP,
/// vendor shared-memory transports, ...) are kept with their raw `kind` so the
/// sensor can log them, but they have no socket address.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct Locator {
    pub kind: i32,
    pub port: u32,
    pub address: [u8; 16],
}

impl Locator {
    /// Parse a locator parameter value (24 bytes; extra bytes are ignored).
    pub(crate) fn parse(value: &[u8], le: bool) -> Option<Self> {
        Some(Self {
            kind: read_i32(value, 0, le)?,
            port: read_u32(value, 4, le)?,
            address: read_array::<16>(value, 8)?,
        })
    }

    /// A short name for the kind. Kinds other than UDPv4/UDPv6/invalid are
    /// vendor- or transport-specific and are reported as `"other"`.
    pub fn kind_name(&self) -> &'static str {
        match self.kind {
            LOCATOR_KIND_UDPV4 => "udpv4",
            LOCATOR_KIND_UDPV6 => "udpv6",
            LOCATOR_KIND_INVALID => "invalid",
            _ => "other",
        }
    }

    /// `a.b.c.d:port` for UDPv4, `[v6]:port` for UDPv6; `None` for any other
    /// kind or for a port outside 1..=65535 (0 is `LOCATOR_PORT_INVALID`).
    pub fn socket_string(&self) -> Option<String> {
        if self.port == 0 || self.port > u16::MAX as u32 {
            return None;
        }
        match self.kind {
            LOCATOR_KIND_UDPV4 => {
                let a = &self.address;
                Some(format!(
                    "{}:{}",
                    Ipv4Addr::new(a[12], a[13], a[14], a[15]),
                    self.port
                ))
            }
            LOCATOR_KIND_UDPV6 => Some(format!("[{}]:{}", Ipv6Addr::from(self.address), self.port)),
            _ => None,
        }
    }
}

impl fmt::Display for Locator {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self.socket_string() {
            Some(s) => write!(f, "{}://{s}", self.kind_name()),
            None => write!(f, "kind={}/port={}", self.kind, self.port),
        }
    }
}

/// Lower-case hex of any byte slice, no separators.
pub(crate) fn hex(bytes: &[u8]) -> String {
    const DIGITS: &[u8; 16] = b"0123456789abcdef";
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        s.push(DIGITS[(b >> 4) as usize] as char);
        s.push(DIGITS[(b & 0x0f) as usize] as char);
    }
    s
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Drain the list and return the offset just past its sentinel.
    fn skip_to_end(mut it: ParameterList<'_>) -> Option<usize> {
        for _ in it.by_ref() {}
        (it.end() == PlEnd::Sentinel).then_some(it.pos())
    }

    fn pl(le: bool, params: &[(u16, &[u8])], sentinel: bool) -> Vec<u8> {
        let mut v = Vec::new();
        let w16 = |v: &mut Vec<u8>, x: u16| {
            v.extend_from_slice(&if le { x.to_le_bytes() } else { x.to_be_bytes() })
        };
        for (pid, val) in params {
            w16(&mut v, *pid);
            w16(&mut v, val.len() as u16);
            v.extend_from_slice(val);
        }
        if sentinel {
            w16(&mut v, PID_SENTINEL);
            w16(&mut v, 0);
        }
        v
    }

    #[test]
    fn reads_are_endian_aware_and_bounded() {
        let b = [1u8, 2, 3, 4];
        assert_eq!(read_u16(&b, 0, true), Some(0x0201));
        assert_eq!(read_u16(&b, 0, false), Some(0x0102));
        assert_eq!(read_u32(&b, 0, true), Some(0x04030201));
        assert_eq!(read_u32(&b, 1, true), None);
        assert_eq!(read_u16(&b, usize::MAX, true), None);
        assert_eq!(read_u32(&b, usize::MAX - 1, false), None);
        assert_eq!(read_array::<4>(&b, 0), Some(b));
        assert_eq!(read_array::<4>(&b, usize::MAX), None);
    }

    #[test]
    fn parameter_list_both_endians() {
        for le in [true, false] {
            let buf = pl(le, &[(0x0005, &[1, 2, 3, 4]), (0x0007, &[])], true);
            let mut it = ParameterList::new(&buf, 0, le);
            assert_eq!(it.next(), Some((0x0005, &[1u8, 2, 3, 4][..])));
            assert_eq!(it.next(), Some((0x0007, &[][..])));
            assert_eq!(it.next(), None);
            assert_eq!(it.end(), PlEnd::Sentinel);
            assert_eq!(it.pos(), buf.len());
        }
    }

    #[test]
    fn parameter_list_skips_pad() {
        let buf = pl(true, &[(PID_PAD, &[0; 4]), (0x0005, &[9; 4])], true);
        let got: Vec<_> = ParameterList::new(&buf, 0, true).collect();
        assert_eq!(got, vec![(0x0005, &[9u8; 4][..])]);
    }

    #[test]
    fn parameter_list_accepts_misaligned_length_and_flags_it() {
        // Length 3, the next parameter follows immediately (no padding).
        let buf = pl(true, &[(0x0005, &[1, 2, 3]), (0x0007, &[9; 4])], true);
        let mut it = ParameterList::new(&buf, 0, true);
        assert_eq!(it.next(), Some((0x0005, &[1u8, 2, 3][..])));
        assert_eq!(it.next(), Some((0x0007, &[9u8; 4][..])));
        assert_eq!(it.next(), None);
        assert_eq!(it.end(), PlEnd::Sentinel);
        assert!(it.misaligned());
        let aligned = pl(true, &[(0x0005, &[1, 2, 3, 4])], true);
        let mut it = ParameterList::new(&aligned, 0, true);
        for _ in it.by_ref() {}
        assert!(!it.misaligned());
    }

    #[test]
    fn parameter_list_rejects_overrun_and_missing_sentinel() {
        let mut buf = pl(true, &[(0x0005, &[1, 2, 3, 4])], false);
        assert_eq!(skip_to_end(ParameterList::new(&buf, 0, true)), None);
        buf.truncate(6);
        let mut it = ParameterList::new(&buf, 0, true);
        assert_eq!(it.next(), None);
        assert_eq!(it.end(), PlEnd::Malformed);
        // Start offset past the end.
        let mut it = ParameterList::new(&buf, usize::MAX, true);
        assert_eq!(it.next(), None);
        assert_eq!(it.end(), PlEnd::Malformed);
    }

    #[test]
    fn parameter_list_stops_on_extended() {
        let buf = pl(true, &[(PID_EXTENDED, &[0; 8]), (0x0005, &[0; 4])], true);
        let mut it = ParameterList::new(&buf, 0, true);
        assert_eq!(it.next(), None);
        assert_eq!(it.end(), PlEnd::Unsupported);
    }

    #[test]
    fn skip_to_end_returns_offset_after_sentinel() {
        let mut buf = pl(false, &[(0x0070, &[0; 16])], true);
        let n = buf.len();
        buf.extend_from_slice(b"tail");
        assert_eq!(skip_to_end(ParameterList::new(&buf, 0, false)), Some(n));
    }

    #[test]
    fn cdr_string_strictness() {
        let mk = |n: u32, b: &[u8]| {
            let mut v = n.to_le_bytes().to_vec();
            v.extend_from_slice(b);
            v
        };
        assert_eq!(cdr_string(&mk(4, b"abc\0"), true).as_deref(), Some("abc"));
        assert_eq!(cdr_string(&mk(1, b"\0"), true).as_deref(), Some(""));
        assert_eq!(cdr_string(&mk(0, b""), true), None, "length 0 is invalid");
        assert_eq!(cdr_string(&mk(3, b"abc"), true), None, "missing NUL");
        assert_eq!(cdr_string(&mk(4, b"a\0c\0"), true), None, "interior NUL");
        assert_eq!(cdr_string(&mk(5, b"abc\0"), true), None, "overrun");
        assert_eq!(cdr_string(&mk(u32::MAX, b"abc\0"), true), None);
        assert_eq!(
            cdr_string(&mk(3, &[0xff, 0xfe, 0]), true),
            None,
            "not utf-8"
        );
        assert_eq!(cdr_string(&[1, 2], true), None);
        let mut be = 4u32.to_be_bytes().to_vec();
        be.extend_from_slice(b"xyz\0");
        assert_eq!(cdr_string(&be, false).as_deref(), Some("xyz"));
    }

    #[test]
    fn cdr_string_lenient_reads_like_a_c_string() {
        let mk = |n: u32, b: &[u8]| {
            let mut v = n.to_le_bytes().to_vec();
            v.extend_from_slice(b);
            v
        };
        let l = |v: &[u8]| cdr_string_lenient(v, true);
        assert_eq!(l(&mk(4, b"abc\0")), Some(("abc".into(), true)));
        assert_eq!(l(&mk(1, b"\0\0\0\0")), Some(("".into(), true)));
        // Embedded NUL: the C-string view stops there.
        assert_eq!(
            l(&mk(13, b"rt/cmd_vel\0x\0\0\0\0")),
            Some(("rt/cmd_vel".into(), false))
        );
        // Length field lies (too short, zero, too long): ignored.
        assert_eq!(l(&mk(3, b"abc\0")), Some(("abc".into(), false)));
        assert_eq!(l(&mk(0, b"abc\0")), Some(("abc".into(), false)));
        assert_eq!(l(&mk(u32::MAX, b"abc\0")), Some(("abc".into(), false)));
        // No NUL at all: the whole value.
        assert_eq!(l(&mk(4, b"rt/a")), Some(("rt/a".into(), false)));
        assert_eq!(l(&mk(4, b"")), Some(("".into(), false)));
        assert_eq!(l(&[1, 2]), None, "no length field");
        assert_eq!(l(&mk(3, &[0xff, 0xfe, 0])), None, "not utf-8");
    }

    #[test]
    fn cdr_octets_bounds() {
        let mut v = 3u32.to_be_bytes().to_vec();
        v.extend_from_slice(b"abc\0");
        assert_eq!(cdr_octets(&v, false), Some(&b"abc"[..]));
        assert_eq!(cdr_octets(&v, true), None, "LE reading claims 3<<24 bytes");
    }

    #[test]
    fn locator_rendering() {
        let mut addr = [0u8; 16];
        addr[12..].copy_from_slice(&[192, 168, 1, 20]);
        let l = Locator {
            kind: LOCATOR_KIND_UDPV4,
            port: 7410,
            address: addr,
        };
        assert_eq!(l.socket_string().as_deref(), Some("192.168.1.20:7410"));
        assert_eq!(l.to_string(), "udpv4://192.168.1.20:7410");

        let v6 = Locator {
            kind: LOCATOR_KIND_UDPV6,
            port: 7411,
            address: Ipv6Addr::new(0xfe80, 0, 0, 0, 0, 0, 0, 1).octets(),
        };
        assert_eq!(v6.socket_string().as_deref(), Some("[fe80::1]:7411"));

        let shm = Locator {
            kind: 16,
            port: 1,
            address: [0; 16],
        };
        assert_eq!(shm.socket_string(), None);
        assert_eq!(shm.kind_name(), "other");
        assert_eq!(shm.to_string(), "kind=16/port=1");

        for port in [0u32, 65536, u32::MAX] {
            assert_eq!(Locator { port, ..l }.socket_string(), None);
        }
    }

    #[test]
    fn locator_parse_both_endians() {
        let mut le = Vec::new();
        le.extend_from_slice(&1i32.to_le_bytes());
        le.extend_from_slice(&7400u32.to_le_bytes());
        le.extend_from_slice(&[0; 12]);
        le.extend_from_slice(&[10, 0, 0, 1]);
        let mut be = Vec::new();
        be.extend_from_slice(&1i32.to_be_bytes());
        be.extend_from_slice(&7400u32.to_be_bytes());
        be.extend_from_slice(&le[8..]);
        assert_eq!(Locator::parse(&le, true), Locator::parse(&be, false));
        assert_eq!(
            Locator::parse(&le, true)
                .unwrap()
                .socket_string()
                .as_deref(),
            Some("10.0.0.1:7400")
        );
        assert_eq!(Locator::parse(&le[..23], true), None);
    }

    #[test]
    fn hex_is_lowercase() {
        assert_eq!(hex(&[0x00, 0xab, 0x0f, 0xf0]), "00ab0ff0");
        assert_eq!(hex(&[]), "");
    }
}
