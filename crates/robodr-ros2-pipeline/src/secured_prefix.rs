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
//! PrintableString (older OpenSSL masks). An attribute type outside the
//! table below, a multi-valued RDN, or a malformed subject gives no match.
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
const MAX_ATTRIBUTES: usize = 32;

const TAG_UTF8: u8 = 0x0c;
const TAG_PRINTABLE: u8 = 0x13;
const TAG_IA5: u8 = 0x16;

/// OID content bytes of an attribute type and its fixed string tag (`None`:
/// a DirectoryString, UTF8String or PrintableString).
fn attribute_type(name: &str) -> Option<(&'static [u8], Option<u8>)> {
    const EMAIL: &[u8] = &[0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x09, 0x01];
    const DC: &[u8] = &[0x09, 0x92, 0x26, 0x89, 0x93, 0xf2, 0x2c, 0x64, 0x01, 0x19];
    const UID: &[u8] = &[0x09, 0x92, 0x26, 0x89, 0x93, 0xf2, 0x2c, 0x64, 0x01, 0x01];
    let x520 = |n: u8| -> &'static [u8] {
        match n {
            3 => &[0x55, 0x04, 3],
            4 => &[0x55, 0x04, 4],
            5 => &[0x55, 0x04, 5],
            6 => &[0x55, 0x04, 6],
            7 => &[0x55, 0x04, 7],
            8 => &[0x55, 0x04, 8],
            9 => &[0x55, 0x04, 9],
            10 => &[0x55, 0x04, 10],
            11 => &[0x55, 0x04, 11],
            12 => &[0x55, 0x04, 12],
            17 => &[0x55, 0x04, 17],
            42 => &[0x55, 0x04, 42],
            43 => &[0x55, 0x04, 43],
            46 => &[0x55, 0x04, 46],
            _ => &[0x55, 0x04, 65],
        }
    };
    Some(match name.to_ascii_uppercase().as_str() {
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
        "EMAILADDRESS" | "EMAIL" => (EMAIL, Some(TAG_IA5)),
        "DC" | "DOMAINCOMPONENT" => (DC, Some(TAG_IA5)),
        "UID" | "USERID" => (UID, None),
        _ => return None,
    })
}

fn hex_val(c: char) -> Option<u8> {
    c.to_digit(16).and_then(|d| u8::try_from(d).ok())
}

/// Split `body` on the unescaped `sep`, decoding escapes (`\c` is `c`;
/// `\xHH` in the one-line form, `\HH` in RFC 4514, are bytes).
fn split_escaped(body: &str, sep: char, oneline: bool) -> Option<Vec<Vec<u8>>> {
    let mut parts = Vec::new();
    let mut cur: Vec<u8> = Vec::new();
    let mut chars = body.chars().peekable();
    let mut buf = [0u8; 4];
    while let Some(c) = chars.next() {
        if c == '\\' {
            let n = chars.next()?;
            let hex_start = if oneline && n == 'x' {
                chars.next()
            } else if !oneline && hex_val(n).is_some() {
                Some(n)
            } else {
                None
            };
            match hex_start {
                Some(h) => {
                    let hi = hex_val(h)?;
                    let lo = hex_val(chars.next()?)?;
                    cur.push(hi << 4 | lo);
                }
                None => cur.extend_from_slice(n.encode_utf8(&mut buf).as_bytes()),
            }
        } else if c == sep {
            parts.push(std::mem::take(&mut cur));
            if parts.len() > MAX_ATTRIBUTES {
                return None;
            }
        } else {
            cur.extend_from_slice(c.encode_utf8(&mut buf).as_bytes());
        }
    }
    parts.push(cur);
    Some(parts)
}

/// (type, value) pairs in DER order, or `None` if the text is not a subject
/// this module can rebuild.
fn parse_subject(subject: &str) -> Option<Vec<(String, Vec<u8>)>> {
    let s = subject.trim();
    let (parts, reverse) = match s.strip_prefix('/') {
        Some(body) => {
            // `X509_NAME_oneline` does not escape a `/` inside a value
            // (`/CN=/lab/x`): a piece without `=` continues the previous
            // value.
            let mut merged: Vec<Vec<u8>> = Vec::new();
            for p in split_escaped(body, '/', true)? {
                match merged.last_mut() {
                    Some(prev) if !p.contains(&b'=') => {
                        prev.push(b'/');
                        prev.extend_from_slice(&p);
                    }
                    _ => merged.push(p),
                }
            }
            (merged, false)
        }
        None => (split_escaped(s, ',', false)?, true),
    };
    let mut out = Vec::new();
    for p in parts {
        let eq = p.iter().position(|b| *b == b'=')?;
        let (k, v) = p.split_at(eq);
        let k = std::str::from_utf8(k).ok()?.trim().to_owned();
        let mut v = v.get(1..)?.to_vec();
        if reverse {
            // RFC 4514: spaces around the value are not part of it.
            while v.first() == Some(&b' ') {
                v.remove(0);
            }
            while v.last() == Some(&b' ') {
                v.pop();
            }
        }
        if k.is_empty() || v.is_empty() {
            return None;
        }
        out.push((k, v));
    }
    if reverse {
        out.reverse();
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
        // Subjects are at most a few hundred bytes (MAX_TOKEN_STRING).
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

/// DER of the Name, every directory string as UTF8String or (when
/// `prefer_printable` and the value allows it) PrintableString.
fn name_der(attrs: &[(&'static [u8], Option<u8>, &[u8])], prefer_printable: bool) -> Vec<u8> {
    let mut rdns = Vec::new();
    for (oid, fixed, value) in attrs {
        let tag = fixed.unwrap_or(if prefer_printable && printable(value) {
            TAG_PRINTABLE
        } else {
            TAG_UTF8
        });
        let mut atv = Vec::new();
        tlv(0x06, oid, &mut atv);
        tlv(tag, value, &mut atv);
        let mut seq = Vec::new();
        tlv(0x30, &atv, &mut seq);
        tlv(0x31, &seq, &mut rdns);
    }
    let mut out = Vec::new();
    tlv(0x30, &rdns, &mut out);
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
    let mut attrs = Vec::with_capacity(parsed.len());
    for (k, v) in &parsed {
        let Some((oid, fixed)) = attribute_type(k) else {
            return false;
        };
        attrs.push((oid, fixed, v.as_slice()));
    }
    let head = prefix.get(..6);
    [false, true]
        .into_iter()
        .any(|p| Some(&prefix_head(&name_der(&attrs, p))[..]) == head)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The controller of the Humble SROS 2 captures
    /// (`fixtures/captures/ros2-humble/sros2/lab/base_controller/cert.pem`).
    const CONTROLLER: [u8; 12] = [0xaf, 0x0c, 0x85, 0x4b, 0x64, 0x6f, 0, 0, 0, 0, 0, 0];

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
        let attrs = [(
            &[0x55u8, 0x04, 0x03][..],
            None,
            &b"/lab/base_controller"[..],
        )];
        assert_eq!(name_der(&attrs, false), der);
        assert_eq!(prefix_head(&der), [0xaf, 0x0c, 0x85, 0x4b, 0x64, 0x6f]);
        for s in [
            r"/CN=\/lab\/base_controller",
            "/CN=/lab/base_controller",
            "CN=/lab/base_controller",
            " CN = /lab/base_controller ",
        ] {
            assert!(prefix_matches_subject(&CONTROLLER, s), "{s}");
        }
        for s in [
            "CN=/lab/teleop_twist",
            "CN=/lab/base_controller,O=x",
            "XX=/lab/base_controller",
            "",
            "/",
            "CN=",
            "\\",
        ] {
            assert!(!prefix_matches_subject(&CONTROLLER, s), "{s}");
        }
    }

    #[test]
    fn multi_attribute_order_and_string_types() {
        // RFC 4514 lists RDNs last-first; the one-line form in DER order.
        let attrs = [
            (&[0x55u8, 0x04, 0x06][..], Some(TAG_PRINTABLE), &b"US"[..]),
            (&[0x55u8, 0x04, 0x0a][..], None, &b"Acme Robots"[..]),
            (&[0x55u8, 0x04, 0x03][..], None, &b"robot-1"[..]),
        ];
        for prefer_printable in [false, true] {
            let mut prefix = [0u8; 12];
            prefix[..6].copy_from_slice(&prefix_head(&name_der(&attrs, prefer_printable)));
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
        let attrs = [(&[0x55u8, 0x04, 0x03][..], None, "a,b\u{e9}".as_bytes())];
        let mut prefix = [0u8; 12];
        prefix[..6].copy_from_slice(&prefix_head(&name_der(&attrs, false)));
        assert!(prefix_matches_subject(&prefix, r"CN=a\,b\C3\A9"));
        assert!(prefix_matches_subject(&prefix, r"/CN=a,b\xC3\xA9"));
    }

    #[test]
    fn hostile_subjects_are_bounded() {
        let many = "/CN=a".repeat(MAX_ATTRIBUTES + 5);
        assert!(!prefix_matches_subject(&CONTROLLER, &many));
        for s in [r"/CN=\x", r"/CN=\xZZ", r"CN=\G", "CN=a\\"] {
            assert!(!prefix_matches_subject(&CONTROLLER, s), "{s}");
        }
        let long = format!("CN={}", "x".repeat(70_000));
        assert!(!prefix_matches_subject(&CONTROLLER, &long));
    }
}
