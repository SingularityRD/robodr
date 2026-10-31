//! Does a DDS-Security participant's GUID prefix belong to the certificate
//! subject its SPDP identity token claims?
//!
//! DDS-Security 1.1 §9.3.3: the builtin PKI-DH plugin sets the first bit of
//! a secured participant's GUID prefix and fills the next 47 bits with the
//! first 47 bits of SHA-256 over the **DER encoding of the certificate's
//! subject name** (Fast DDS and Cyclone DDS both hash `X509_NAME`'s DER;
//! checked on the Humble SROS 2 captures: `CN=/lab/base_controller` gives
//! `af0c854b646f`).
//!
//! The SPDP carries the subject only as text (`dds.cert.sn`: OpenSSL
//! one-line form `/CN=\/lab\/x` as Fast DDS 2.6 sends it, or RFC 4514 form
//! `CN=/lab/x`), so the DER is rebuilt from it. The string type of each
//! attribute is not in the text: the attributes whose type is fixed by
//! RFC 5280 (`C`, `serialNumber`, `dnQualifier`: PrintableString;
//! `emailAddress`, `DC`: IA5String) get that type, the others are tried as
//! UTF8String (what SROS 2, Python `cryptography` and OpenSSL's default
//! `utf8only` mask write) and, when the value allows it, as
//! PrintableString (older OpenSSL masks).
//!
//! Subjects that can be rebuilt:
//!
//! - attribute types from the table in `attribute_type` by name, and any
//!   type as a numeric OID (`2.5.4.3=x`, `OID.2.5.4.3=x`);
//! - in the RFC 4514 form also multi-valued RDNs (`CN=a+UID=b`, encoded as
//!   a DER SET OF), `#hex` values (the attribute value's complete DER, used
//!   as written, so any string type) and escaped significant spaces
//!   (`CN=a\ `);
//! - escapes: `\c`, and `\xHH` (one-line) or `\HH` (RFC 4514) bytes.
//!
//! Subjects that cannot be rebuilt never match, so a legitimate secured
//! participant with such a subject is not resolved to a learned identity
//! (`robodr-commission learn --pcap` warns about it:
//! `identity_prefix_unverified`):
//!
//! - in the one-line form, a multi-valued RDN (the form does not show the
//!   grouping) and a value containing `/x=` (read as a new attribute);
//! - a value whose string type is neither UTF8String nor PrintableString
//!   (T61String, BMPString, UniversalString) unless given as RFC 4514
//!   `#hex`;
//! - an attribute type outside the table that is not a numeric OID, more
//!   than [`MAX_ATTRIBUTES`] attributes, or malformed text.
//!
//! What this proves: only that the claimed subject and the prefix are
//! consistent. Both are attacker-controlled text in a crafted SPDP; anyone
//! can compute the hash. It ties a prefix-derived profile `vendor` (the
//! first two prefix bytes) to one specific certificate subject, so a sender
//! must claim that subject (which a keystore check then judges) and use a
//! prefix derived from it, instead of copying two prefix bytes next to any
//! security parameter. The handshake that proves the subject is not seen.

use sha2::{Digest, Sha256};

/// Attributes read from one subject.
pub const MAX_ATTRIBUTES: usize = 32;

/// Longest subject text considered (an SPDP token string is at most
/// [`crate::security::MAX_TOKEN_STRING`] bytes).
const MAX_SUBJECT_BYTES: usize = 4096;

/// Most arcs in a numeric attribute type OID.
const MAX_OID_ARCS: usize = 32;

const TAG_UTF8: u8 = 0x0c;
const TAG_PRINTABLE: u8 = 0x13;
const TAG_IA5: u8 = 0x16;

const OID_EMAIL: &[u8] = &[0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x09, 0x01];
const OID_DC: &[u8] = &[0x09, 0x92, 0x26, 0x89, 0x93, 0xf2, 0x2c, 0x64, 0x01, 0x19];
const OID_UID: &[u8] = &[0x09, 0x92, 0x26, 0x89, 0x93, 0xf2, 0x2c, 0x64, 0x01, 0x01];

/// OID content bytes of an attribute type and its fixed string tag (`None`:
/// a DirectoryString, UTF8String or PrintableString). A name from the table
/// below, or a numeric OID (`2.5.4.3`, `OID.2.5.4.3`).
fn attribute_type(name: &str) -> Option<(Vec<u8>, Option<u8>)> {
    let x520 = |n: u8| vec![0x55, 0x04, n];
    let upper = name.to_ascii_uppercase();
    Some(match upper.as_str() {
        "CN" | "COMMONNAME" => (x520(3), None),
        "SN" | "SURNAME" => (x520(4), None),
        "SERIALNUMBER" => (x520(5), Some(TAG_PRINTABLE)),
        "C" | "COUNTRYNAME" => (x520(6), Some(TAG_PRINTABLE)),
        "L" | "LOCALITYNAME" => (x520(7), None),
        "ST" | "S" | "STATEORPROVINCENAME" => (x520(8), None),
        "STREET" | "STREETADDRESS" => (x520(9), None),
        "O" | "ORGANIZATIONNAME" => (x520(10), None),
        "OU" | "ORGANIZATIONALUNITNAME" => (x520(11), None),
        "TITLE" => (x520(12), None),
        "POSTALCODE" => (x520(17), None),
        "GN" | "GIVENNAME" => (x520(42), None),
        "INITIALS" => (x520(43), None),
        "DNQUALIFIER" => (x520(46), Some(TAG_PRINTABLE)),
        "PSEUDONYM" => (x520(65), None),
        "EMAILADDRESS" | "EMAIL" => (OID_EMAIL.to_vec(), Some(TAG_IA5)),
        "DC" | "DOMAINCOMPONENT" => (OID_DC.to_vec(), Some(TAG_IA5)),
        "UID" | "USERID" => (OID_UID.to_vec(), None),
        _ => {
            let oid = numeric_oid(upper.strip_prefix("OID.").unwrap_or(&upper))?;
            // A type with a fixed string tag gets it by number as by name.
            let fixed = match oid.as_slice() {
                [0x55, 0x04, 5 | 6 | 46] => Some(TAG_PRINTABLE),
                o if o == OID_EMAIL || o == OID_DC => Some(TAG_IA5),
                _ => None,
            };
            (oid, fixed)
        }
    })
}

/// DER content bytes of a dotted OID (`2.5.4.3`), or `None` if malformed.
fn numeric_oid(dotted: &str) -> Option<Vec<u8>> {
    let mut arcs = Vec::new();
    for a in dotted.split('.') {
        if a.is_empty() || !a.bytes().all(|b| b.is_ascii_digit()) || arcs.len() >= MAX_OID_ARCS {
            return None;
        }
        arcs.push(a.parse::<u64>().ok()?);
    }
    let (&first, rest) = arcs.split_first()?;
    let (&second, rest) = rest.split_first()?;
    if first > 2 || (first < 2 && second >= 40) {
        return None;
    }
    let head = first.checked_mul(40)?.checked_add(second)?;
    let mut out = Vec::new();
    for arc in std::iter::once(head).chain(rest.iter().copied()) {
        let mut groups = vec![u8::try_from(arc & 0x7f).ok()?];
        let mut v = arc >> 7;
        while v > 0 {
            groups.push(u8::try_from(v & 0x7f).ok()? | 0x80);
            v >>= 7;
        }
        out.extend(groups.iter().rev());
    }
    Some(out)
}

fn hex_val(c: char) -> Option<u8> {
    c.to_digit(16).and_then(|d| u8::try_from(d).ok())
}

/// Decoded subject text: the bytes, and per byte whether it came from an
/// escape (an escaped separator, `=`, `#` or space is data).
#[derive(Debug, Default)]
struct Piece {
    bytes: Vec<u8>,
    escaped: Vec<bool>,
}

impl Piece {
    fn push(&mut self, b: &[u8], escaped: bool) {
        self.bytes.extend_from_slice(b);
        self.escaped.resize(self.bytes.len(), escaped);
    }

    fn unescaped(&self, i: usize, c: u8) -> bool {
        self.bytes.get(i) == Some(&c) && self.escaped.get(i) == Some(&false)
    }

    /// Position of the first unescaped `c`.
    fn find(&self, c: u8) -> Option<usize> {
        (0..self.bytes.len()).find(|i| self.unescaped(*i, c))
    }

    /// Split on every unescaped `sep`.
    fn split(&self, sep: u8) -> Vec<Piece> {
        let mut out = vec![Piece::default()];
        for (b, e) in self.bytes.iter().zip(&self.escaped) {
            if *b == sep && !*e {
                out.push(Piece::default());
            } else if let Some(cur) = out.last_mut() {
                cur.push(&[*b], *e);
            }
        }
        out
    }

    /// `from..len` without the unescaped spaces at either end.
    fn trimmed(&self, from: usize) -> (usize, usize) {
        let (mut a, mut z) = (from, self.bytes.len());
        while a < z && self.unescaped(a, b' ') {
            a += 1;
        }
        while z > a && self.unescaped(z - 1, b' ') {
            z -= 1;
        }
        (a, z)
    }
}

/// Decode escapes (`\c` is `c`; `\xHH` in the one-line form, `\HH` in
/// RFC 4514, are bytes).
fn decode(body: &str, oneline: bool) -> Option<Piece> {
    let mut out = Piece::default();
    let mut chars = body.chars();
    let mut buf = [0u8; 4];
    while let Some(c) = chars.next() {
        if c == '\\' {
            let n = chars.next()?;
            let hex_start = if oneline && n == 'x' {
                Some(chars.next()?)
            } else if !oneline && hex_val(n).is_some() {
                Some(n)
            } else {
                None
            };
            match hex_start {
                Some(h) => {
                    let hi = hex_val(h)?;
                    let lo = hex_val(chars.next()?)?;
                    out.push(&[hi << 4 | lo], true);
                }
                None => out.push(n.encode_utf8(&mut buf).as_bytes(), true),
            }
        } else {
            out.push(c.encode_utf8(&mut buf).as_bytes(), false);
        }
    }
    Some(out)
}

/// An attribute value as the subject text gives it.
#[derive(Debug, PartialEq, Eq)]
enum Value {
    /// A string; its DER string type is chosen by [`name_der`].
    Text(Vec<u8>),
    /// RFC 4514 `#hex`: the value's complete DER (tag, length, content).
    Der(Vec<u8>),
}

/// One attribute: (type name as written, value).
type Atv = (String, Value);

/// Whether `der` is exactly one TLV with a definite length.
fn single_tlv(der: &[u8]) -> bool {
    let len = match der.get(1).copied() {
        Some(n) if n < 0x80 => Some((2, usize::from(n))),
        Some(0x81) => der.get(2).map(|n| (3, usize::from(*n))),
        Some(0x82) => der
            .get(2..4)
            .and_then(|n| <[u8; 2]>::try_from(n).ok())
            .map(|n| (4, usize::from(u16::from_be_bytes(n)))),
        _ => None,
    };
    len.is_some_and(|(h, n)| h + n == der.len())
}

fn parse_hex(hex: &[u8]) -> Option<Vec<u8>> {
    if hex.is_empty() || !hex.len().is_multiple_of(2) {
        return None;
    }
    hex.chunks(2)
        .map(|c| {
            let mut it = c.iter().map(|b| hex_val(char::from(*b)));
            Some(it.next()?? << 4 | it.next()??)
        })
        .collect()
}

fn parse_atv(p: &Piece, rfc4514: bool) -> Option<Atv> {
    let eq = p.find(b'=')?;
    let key = std::str::from_utf8(p.bytes.get(..eq)?)
        .ok()?
        .trim()
        .to_owned();
    let value = if rfc4514 {
        // RFC 4514: unescaped spaces around the value are not part of it;
        // an escaped one is.
        let (a, z) = p.trimmed(eq + 1);
        let v = p.bytes.get(a..z)?;
        if p.unescaped(a, b'#') {
            let der = parse_hex(v.get(1..)?)?;
            if !single_tlv(&der) {
                return None;
            }
            Value::Der(der)
        } else {
            Value::Text(v.to_vec())
        }
    } else {
        Value::Text(p.bytes.get(eq + 1..)?.to_vec())
    };
    if key.is_empty() || value == Value::Text(Vec::new()) {
        return None;
    }
    Some((key, value))
}

/// RDNs in DER order, each a set of attributes, or `None` if the text is
/// not a subject this module can rebuild.
fn parse_subject(subject: &str) -> Option<Vec<Vec<Atv>>> {
    if subject.len() > MAX_SUBJECT_BYTES {
        return None;
    }
    // Only leading spaces: a trailing one may be escaped (RFC 4514 trims
    // each value itself) or data (the one-line form escapes no space).
    let s = subject.trim_start();
    let mut out: Vec<Vec<Atv>> = Vec::new();
    match s.strip_prefix('/') {
        Some(body) => {
            // `X509_NAME_oneline` does not escape a `/` inside a value
            // (`/CN=/lab/x`): a piece without `=` continues the previous
            // value.
            let mut merged: Vec<Piece> = Vec::new();
            for p in decode(body, true)?.split(b'/') {
                match merged.last_mut() {
                    Some(prev) if p.find(b'=').is_none() => {
                        prev.push(b"/", false);
                        prev.bytes.extend_from_slice(&p.bytes);
                        prev.escaped.extend_from_slice(&p.escaped);
                    }
                    _ => merged.push(p),
                }
                if merged.len() > MAX_ATTRIBUTES {
                    return None;
                }
            }
            for p in &merged {
                out.push(vec![parse_atv(p, false)?]);
            }
        }
        None => {
            let mut count = 0usize;
            for rdn in decode(s, false)?.split(b',') {
                let mut set = Vec::new();
                for p in rdn.split(b'+') {
                    count += 1;
                    if count > MAX_ATTRIBUTES {
                        return None;
                    }
                    set.push(parse_atv(&p, true)?);
                }
                out.push(set);
            }
            // RFC 4514 lists the RDNs last-first.
            out.reverse();
        }
    }
    (!out.is_empty()).then_some(out)
}

fn tlv(tag: u8, content: &[u8], out: &mut Vec<u8>) {
    out.push(tag);
    let n = content.len();
    if n < 0x80 {
        out.push(n as u8);
    } else if n <= 0xff {
        out.extend_from_slice(&[0x81, n as u8]);
    } else {
        // Subjects are at most MAX_SUBJECT_BYTES.
        let n = u16::try_from(n).unwrap_or(u16::MAX);
        out.push(0x82);
        out.extend_from_slice(&n.to_be_bytes());
    }
    out.extend_from_slice(content);
}

fn printable(v: &[u8]) -> bool {
    v.iter()
        .all(|b| b.is_ascii_alphanumeric() || b" '()+,-./:=?".contains(b))
}

/// One attribute ready to encode: OID content, fixed string tag, value.
type Attr<'a> = (Vec<u8>, Option<u8>, &'a Value);

/// DER of the Name, every directory string as UTF8String or (when
/// `prefer_printable` and the value allows it) PrintableString. A
/// multi-valued RDN is a DER SET OF: its encodings in ascending order.
fn name_der(rdns: &[Vec<Attr<'_>>], prefer_printable: bool) -> Vec<u8> {
    let mut seq = Vec::new();
    for rdn in rdns {
        let mut encs: Vec<Vec<u8>> = rdn
            .iter()
            .map(|(oid, fixed, value)| {
                let mut atv = Vec::new();
                tlv(0x06, oid, &mut atv);
                match value {
                    Value::Der(der) => atv.extend_from_slice(der),
                    Value::Text(v) => {
                        let tag = fixed.unwrap_or(if prefer_printable && printable(v) {
                            TAG_PRINTABLE
                        } else {
                            TAG_UTF8
                        });
                        tlv(tag, v, &mut atv);
                    }
                }
                let mut enc = Vec::new();
                tlv(0x30, &atv, &mut enc);
                enc
            })
            .collect();
        encs.sort();
        tlv(0x31, &encs.concat(), &mut seq);
    }
    let mut out = Vec::new();
    tlv(0x30, &seq, &mut out);
    out
}

/// The first 6 prefix bytes §9.3.3 derives from a subject's DER.
fn prefix_head(der: &[u8]) -> [u8; 6] {
    let md = Sha256::digest(der);
    let b = |i: usize| md.get(i).copied().unwrap_or(0);
    let mut h = [0u8; 6];
    h[0] = 0x80 | (b(0) >> 1);
    for (i, out) in h.iter_mut().enumerate().skip(1) {
        *out = (b(i - 1) << 7) | (b(i) >> 1);
    }
    h
}

/// Whether `prefix` is the GUID prefix DDS-Security derives from the
/// certificate subject `subject` (first bit and 47 hash bits; see the
/// module docs for which subjects can be rebuilt).
pub fn prefix_matches_subject(prefix: &[u8; 12], subject: &str) -> bool {
    let Some(parsed) = parse_subject(subject) else {
        return false;
    };
    let mut rdns = Vec::with_capacity(parsed.len());
    for rdn in &parsed {
        let mut set = Vec::with_capacity(rdn.len());
        for (k, v) in rdn {
            let Some((oid, fixed)) = attribute_type(k) else {
                return false;
            };
            set.push((oid, fixed, v));
        }
        rdns.push(set);
    }
    let head = prefix.get(..6);
    [false, true]
        .into_iter()
        .any(|p| Some(&prefix_head(&name_der(&rdns, p))[..]) == head)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The controller of the Humble SROS 2 captures
    /// (`fixtures/captures/ros2-humble/sros2/lab/base_controller/cert.pem`).
    const CONTROLLER: [u8; 12] = [0xaf, 0x0c, 0x85, 0x4b, 0x64, 0x6f, 0, 0, 0, 0, 0, 0];

    const CN: &[u8] = &[0x55, 0x04, 0x03];

    fn text(v: &[u8]) -> Value {
        Value::Text(v.to_vec())
    }

    /// The prefix derived from a subject DER.
    fn prefix_of(der: &[u8]) -> [u8; 12] {
        let mut prefix = [0u8; 12];
        prefix[..6].copy_from_slice(&prefix_head(der));
        prefix
    }

    #[test]
    fn rebuilds_the_real_certificate_subject() {
        // Subject DER from the certificate (openssl asn1parse).
        let der = [
            0x30, 0x1f, 0x31, 0x1d, 0x30, 0x1b, 0x06, 0x03, 0x55, 0x04, 0x03, 0x0c, 0x14,
        ]
        .iter()
        .copied()
        .chain(*b"/lab/base_controller")
        .collect::<Vec<u8>>();
        let v = text(b"/lab/base_controller");
        assert_eq!(name_der(&[vec![(CN.to_vec(), None, &v)]], false), der);
        assert_eq!(prefix_head(&der), [0xaf, 0x0c, 0x85, 0x4b, 0x64, 0x6f]);
        for s in [
            r"/CN=\/lab\/base_controller",
            "/CN=/lab/base_controller",
            "CN=/lab/base_controller",
            " CN = /lab/base_controller ",
            "2.5.4.3=/lab/base_controller",
            "oid.2.5.4.3=/lab/base_controller",
            "/2.5.4.3=/lab/base_controller",
            // The same DER as a #hex value.
            "CN=#0c142f6c61622f626173655f636f6e74726f6c6c6572",
        ] {
            assert!(prefix_matches_subject(&CONTROLLER, s), "{s}");
        }
        for s in [
            "CN=/lab/teleop_twist",
            "CN=/lab/base_controller,O=x",
            "XX=/lab/base_controller",
            "2.5.4.4=/lab/base_controller",
            "3.5.4.3=/lab/base_controller",
            "1.40.4.3=/lab/base_controller",
            "2..4.3=/lab/base_controller",
            // `#` escaped: a text value starting with '#'.
            r"CN=\#0c142f6c61622f626173655f636f6e74726f6c6c6572",
            "",
            "/",
            "CN=",
            "CN=  ",
            "\\",
        ] {
            assert!(!prefix_matches_subject(&CONTROLLER, s), "{s}");
        }
    }

    #[test]
    fn multi_attribute_order_and_string_types() {
        // RFC 4514 lists RDNs last-first; the one-line form in DER order.
        let (us, acme, robot) = (text(b"US"), text(b"Acme Robots"), text(b"robot-1"));
        let rdns = [
            vec![(vec![0x55u8, 0x04, 0x06], Some(TAG_PRINTABLE), &us)],
            vec![(vec![0x55u8, 0x04, 0x0a], None, &acme)],
            vec![(CN.to_vec(), None, &robot)],
        ];
        for prefer_printable in [false, true] {
            let prefix = prefix_of(&name_der(&rdns, prefer_printable));
            assert!(prefix_matches_subject(
                &prefix,
                "/C=US/O=Acme Robots/CN=robot-1"
            ));
            assert!(prefix_matches_subject(
                &prefix,
                "CN=robot-1, O=Acme Robots, C=US"
            ));
            assert!(!prefix_matches_subject(
                &prefix,
                "/CN=robot-1/O=Acme Robots/C=US"
            ));
        }
        // Escapes: a comma in RFC 4514, a hex byte in either form.
        let v = text("a,b\u{e9}".as_bytes());
        let prefix = prefix_of(&name_der(&[vec![(CN.to_vec(), None, &v)]], false));
        assert!(prefix_matches_subject(&prefix, r"CN=a\,b\C3\A9"));
        assert!(prefix_matches_subject(&prefix, r"/CN=a,b\xC3\xA9"));
    }

    /// Review (phase 3): RFC 4514 trimmed spaces after unescaping, so an
    /// escaped significant space (`CN=a\ `) was lost and never matched.
    #[test]
    fn escaped_significant_spaces_are_kept() {
        for (value, subjects) in [
            (
                &b"a "[..],
                &[r"CN=a\ ", r"CN=a\20", r"CN= a\ ", "/CN=a "][..],
            ),
            (&b" a"[..], &[r"CN=\ a", r"CN=\20a  "][..]),
        ] {
            let v = text(value);
            let prefix = prefix_of(&name_der(&[vec![(CN.to_vec(), None, &v)]], false));
            for s in subjects {
                assert!(prefix_matches_subject(&prefix, s), "{s}");
            }
            assert!(!prefix_matches_subject(&prefix, "CN=a"));
        }
    }

    /// Review (phase 3): multi-valued RDNs and `#hex` values of other
    /// string types (enterprise PKI) are rebuilt in the RFC 4514 form.
    #[test]
    fn multi_valued_rdns_and_hex_values() {
        // SET OF in DER order: the shorter / smaller encoding first,
        // whatever order the text lists them in.
        let (a, b) = (text(b"robot-1"), text(b"x"));
        let uid = OID_UID.to_vec();
        let rdns = [
            vec![(vec![0x55u8, 0x04, 0x0a], None, &b)],
            vec![(CN.to_vec(), None, &a), (uid, None, &b)],
        ];
        let prefix = prefix_of(&name_der(&rdns, false));
        assert!(prefix_matches_subject(&prefix, "CN=robot-1+UID=x,O=x"));
        assert!(prefix_matches_subject(&prefix, "UID=x + CN=robot-1, O=x"));
        // Not the same name as two single-valued RDNs.
        assert!(!prefix_matches_subject(&prefix, "CN=robot-1,UID=x,O=x"));
        // The one-line form does not show the grouping.
        assert!(!prefix_matches_subject(&prefix, "/O=x/UID=x/CN=robot-1"));
        // An escaped '+' is data.
        let v = text(b"a+b");
        let prefix = prefix_of(&name_der(&[vec![(CN.to_vec(), None, &v)]], false));
        assert!(prefix_matches_subject(&prefix, r"CN=a\+b"));
        // A BMPString CN, only expressible as #hex.
        let bmp = Value::Der(vec![0x1e, 0x04, 0x00, b'h', 0x00, b'i']);
        let prefix = prefix_of(&name_der(&[vec![(CN.to_vec(), None, &bmp)]], false));
        assert!(prefix_matches_subject(&prefix, "CN=#1e0400680069"));
        assert!(prefix_matches_subject(&prefix, "2.5.4.3=#1E0400680069"));
        assert!(!prefix_matches_subject(&prefix, "CN=hi"));
        // Malformed #hex.
        for s in [
            "CN=#",
            "CN=#1e04006800",
            "CN=#1e040068006",
            "CN=#zz",
            "CN=#1e0500680069",
        ] {
            assert!(!prefix_matches_subject(&prefix, s), "{s}");
        }
        // A numeric OID keeps a fixed string type: C is PrintableString.
        let c = text(b"US");
        let prefix = prefix_of(&name_der(
            &[vec![(vec![0x55u8, 0x04, 0x06], Some(TAG_PRINTABLE), &c)]],
            false,
        ));
        assert!(prefix_matches_subject(&prefix, "2.5.4.6=US"));
        // Large arcs encode in base 128.
        assert_eq!(
            numeric_oid("1.2.840.113549.1.9.1").as_deref(),
            Some(OID_EMAIL)
        );
        assert_eq!(numeric_oid("2.999").as_deref(), Some(&[0x88, 0x37][..]));
        assert_eq!(numeric_oid("2.5.18446744073709551616"), None);
    }

    #[test]
    fn hostile_subjects_are_bounded() {
        let many = "/CN=a".repeat(MAX_ATTRIBUTES + 5);
        assert!(!prefix_matches_subject(&CONTROLLER, &many));
        let many = vec!["CN=a"; MAX_ATTRIBUTES + 5].join("+");
        assert!(!prefix_matches_subject(&CONTROLLER, &many));
        let many = format!("CN={}", ".1".repeat(MAX_OID_ARCS + 5));
        assert!(!prefix_matches_subject(&CONTROLLER, &many));
        for s in [r"/CN=\x", r"/CN=\xZZ", r"CN=\G", "CN=a\\", "CN=#\u{e9}0"] {
            assert!(!prefix_matches_subject(&CONTROLLER, s), "{s}");
        }
        let long = format!("CN={}", "x".repeat(70_000));
        assert!(!prefix_matches_subject(&CONTROLLER, &long));
        // Linear in the subject length (the old trim was quadratic).
        let spaces = format!("CN={}a", " ".repeat(MAX_SUBJECT_BYTES - 4));
        assert!(!prefix_matches_subject(&CONTROLLER, &spaces));
    }
}
