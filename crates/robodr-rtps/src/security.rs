//! DDS-Security (SROS 2) parameters of an SPDP announcement
//! (SALES-READINESS T78).
//!
//! With DDS-Security the participant announcement itself stays in clear
//! (it is how peers find each other before authenticating), and carries
//! (OMG DDS-Security 1.1, §7.4.1.4 and §9.3.2.1):
//!
//! | PID | value | what RoboDR reads |
//! |---|---|---|
//! | `PID_IDENTITY_TOKEN` (0x1001) | `DataHolder` class `DDS:Auth:PKI-DH:1.0` | `dds.cert.sn` (the participant certificate's subject, e.g. `CN=/lab/teleop_twist` for an SROS 2 enclave), `dds.ca.sn` (its identity CA's subject) |
//! | `PID_PERMISSIONS_TOKEN` (0x1002) | `DataHolder` class `DDS:Access:Permissions:1.0` | `dds.perm_ca.sn` |
//! | `PID_PARTICIPANT_SECURITY_INFO` (0x1005) | two `u32` masks | that the participant is secured |
//!
//! These are **claims**: the sensor sees the announcement, not the
//! authentication handshake that proves them. A participant without the
//! subject's private key cannot complete the handshake, so a secured robot
//! does not talk to it, but the sensor cannot tell. What the claims give is
//! a stable, policy-checkable name for each participant in a domain whose
//! SEDP (topic names) is encrypted, and a way to see participants that are
//! not part of the deployment's keystore at all.
//!
//! The GUID prefix of a secured participant is derived from its certificate
//! subject (§9.3.3: the first 47 bits of SHA-256 of the subject name, top
//! bit set), so its first bytes do not hold the vendor id; seen on real
//! Fast DDS 2.6 captures (`fixtures/captures/ros2-humble/fastrtps_sros2_*`).
//!
//! Hostile input: every length is checked against the value; at most
//! [`MAX_PROPERTIES`] properties are read per token, each string at most
//! [`MAX_TOKEN_STRING`] bytes; nothing is allocated in proportion to a
//! claimed length.

use crate::wire::read_u32;

/// `PID_IDENTITY_TOKEN`.
pub const PID_IDENTITY_TOKEN: u16 = 0x1001;
/// `PID_PERMISSIONS_TOKEN`.
pub const PID_PERMISSIONS_TOKEN: u16 = 0x1002;
/// `PID_PARTICIPANT_SECURITY_INFO`.
pub const PID_PARTICIPANT_SECURITY_INFO: u16 = 0x1005;
/// Properties read per token.
pub const MAX_PROPERTIES: usize = 16;
/// Longest class id / property name / value kept (longer ones are skipped).
pub const MAX_TOKEN_STRING: usize = 512;

/// What an SPDP announcement says about the participant's DDS-Security.
/// `Default` = nothing was announced (an unsecured participant).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct SpdpSecurity {
    /// Identity token class (`DDS:Auth:PKI-DH:1.0`).
    pub identity_class: Option<String>,
    /// `dds.cert.sn`: the certificate subject the participant claims.
    pub cert_subject: Option<String>,
    /// `dds.ca.sn`: the subject of the identity CA it claims.
    pub ca_subject: Option<String>,
    /// `dds.perm_ca.sn` of the permissions token.
    pub permissions_ca_subject: Option<String>,
    /// `PID_PARTICIPANT_SECURITY_INFO` (participant security attributes,
    /// plugin participant security attributes).
    pub security_info: Option<(u32, u32)>,
}

impl SpdpSecurity {
    /// The participant announced any DDS-Security parameter.
    pub fn is_secured(&self) -> bool {
        self.identity_class.is_some()
            || self.cert_subject.is_some()
            || self.security_info.is_some()
            || self.permissions_ca_subject.is_some()
    }
}

/// A token's class id and its (name, value) string properties.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct DataHolder {
    pub class_id: String,
    pub properties: Vec<(String, String)>,
}

impl DataHolder {
    /// The value of property `name`.
    pub fn property(&self, name: &str) -> Option<&str> {
        self.properties
            .iter()
            .find(|(n, _)| n == name)
            .map(|(_, v)| v.as_str())
    }
}

/// Bounded CDR reader over one parameter value (alignment relative to the
/// value start, which is 4-aligned in a parameter list).
struct Cursor<'a> {
    buf: &'a [u8],
    pos: usize,
    le: bool,
}

impl<'a> Cursor<'a> {
    fn align4(&mut self) -> Option<()> {
        let pad = (4 - self.pos % 4) % 4;
        self.pos = self.pos.checked_add(pad)?;
        (self.pos <= self.buf.len()).then_some(())
    }

    fn u32(&mut self) -> Option<u32> {
        self.align4()?;
        let v = read_u32(self.buf, self.pos, self.le)?;
        self.pos = self.pos.checked_add(4)?;
        Some(v)
    }

    fn bytes(&mut self, n: usize) -> Option<&'a [u8]> {
        let end = self.pos.checked_add(n)?;
        let b = self.buf.get(self.pos..end)?;
        self.pos = end;
        Some(b)
    }

    /// A CDR string; `Some(None)` when it is well-formed but too long or
    /// not UTF-8 (skipped, the reader stays in sync).
    fn string(&mut self) -> Option<Option<String>> {
        let n = usize::try_from(self.u32()?).ok()?;
        let raw = self.bytes(n)?;
        if n == 0 || n > MAX_TOKEN_STRING + 1 {
            return Some(None);
        }
        let text = raw.strip_suffix(&[0]).unwrap_or(raw);
        Some(std::str::from_utf8(text).ok().map(str::to_owned))
    }
}

/// Parse a `DataHolder` (class id, properties; binary properties are not
/// needed and not read). `None` if the value is malformed before the
/// properties end.
pub fn parse_data_holder(value: &[u8], le: bool) -> Option<DataHolder> {
    let mut c = Cursor {
        buf: value,
        pos: 0,
        le,
    };
    let class_id = c.string()?.unwrap_or_default();
    let count = c.u32()?;
    let mut properties = Vec::new();
    for _ in 0..count {
        let name = c.string()?;
        let val = c.string()?;
        if let (Some(n), Some(v)) = (name, val) {
            if properties.len() < MAX_PROPERTIES {
                properties.push((n, v));
            }
        }
    }
    Some(DataHolder {
        class_id,
        properties,
    })
}

/// Fold one security parameter into `out`. Returns `false` when the value
/// is malformed (the caller records an anomaly).
pub(crate) fn apply_param(out: &mut SpdpSecurity, pid: u16, value: &[u8], le: bool) -> bool {
    match pid {
        PID_IDENTITY_TOKEN => {
            let Some(h) = parse_data_holder(value, le) else {
                return false;
            };
            out.cert_subject = h.property("dds.cert.sn").map(str::to_owned);
            out.ca_subject = h.property("dds.ca.sn").map(str::to_owned);
            out.identity_class = Some(h.class_id);
            true
        }
        PID_PERMISSIONS_TOKEN => {
            let Some(h) = parse_data_holder(value, le) else {
                return false;
            };
            out.permissions_ca_subject = h.property("dds.perm_ca.sn").map(str::to_owned);
            true
        }
        PID_PARTICIPANT_SECURITY_INFO => match read_u32(value, 0, le).zip(read_u32(value, 4, le)) {
            Some(v) => {
                out.security_info = Some(v);
                true
            }
            None => false,
        },
        _ => true,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn cdr_string(out: &mut Vec<u8>, s: &str, le: bool) {
        while !out.len().is_multiple_of(4) {
            out.push(0);
        }
        let n = (s.len() + 1) as u32;
        out.extend_from_slice(&if le { n.to_le_bytes() } else { n.to_be_bytes() });
        out.extend_from_slice(s.as_bytes());
        out.push(0);
    }

    pub(crate) fn holder(class: &str, props: &[(&str, &str)], le: bool) -> Vec<u8> {
        let mut v = Vec::new();
        cdr_string(&mut v, class, le);
        while !v.len().is_multiple_of(4) {
            v.push(0);
        }
        let n = props.len() as u32;
        v.extend_from_slice(&if le { n.to_le_bytes() } else { n.to_be_bytes() });
        for (k, val) in props {
            cdr_string(&mut v, k, le);
            cdr_string(&mut v, val, le);
        }
        while !v.len().is_multiple_of(4) {
            v.push(0);
        }
        v.extend_from_slice(&[0; 4]); // binary_properties: empty
        v
    }

    #[test]
    fn identity_token_both_endians() {
        for le in [true, false] {
            let v = holder(
                "DDS:Auth:PKI-DH:1.0",
                &[
                    ("dds.cert.sn", "CN=/lab/teleop_twist"),
                    ("dds.cert.algo", "EC-prime256v1"),
                    ("dds.ca.sn", "CN=sros2CA"),
                    ("dds.ca.algo", "EC-prime256v1"),
                ],
                le,
            );
            let mut s = SpdpSecurity::default();
            assert!(apply_param(&mut s, PID_IDENTITY_TOKEN, &v, le));
            assert_eq!(s.cert_subject.as_deref(), Some("CN=/lab/teleop_twist"));
            assert_eq!(s.ca_subject.as_deref(), Some("CN=sros2CA"));
            assert_eq!(s.identity_class.as_deref(), Some("DDS:Auth:PKI-DH:1.0"));
            assert!(s.is_secured());
        }
    }

    #[test]
    fn hostile_tokens_are_bounded() {
        // Truncated anywhere: refused, no panic.
        let v = holder("DDS:Auth:PKI-DH:1.0", &[("dds.cert.sn", "CN=x")], true);
        for cut in 0..v.len() - 4 {
            let _ = parse_data_holder(&v[..cut], true);
        }
        // A huge claimed count with no data: refused quickly.
        let mut v = holder("c", &[], true);
        v.truncate(8);
        v.extend_from_slice(&u32::MAX.to_le_bytes());
        assert!(parse_data_holder(&v, true).is_none());
        // Over-long strings are skipped, the rest is still read.
        let long = "x".repeat(MAX_TOKEN_STRING + 10);
        let v = holder("c", &[("dds.cert.sn", &long), ("dds.ca.sn", "CN=ok")], true);
        let h = parse_data_holder(&v, true).unwrap();
        assert_eq!(h.property("dds.cert.sn"), None);
        assert_eq!(h.property("dds.ca.sn"), Some("CN=ok"));
        // At most MAX_PROPERTIES kept.
        let many: Vec<(String, String)> = (0..40)
            .map(|i| (format!("p{i}"), "v".to_string()))
            .collect();
        let refs: Vec<(&str, &str)> = many.iter().map(|(a, b)| (a.as_str(), b.as_str())).collect();
        let h = parse_data_holder(&holder("c", &refs, true), true).unwrap();
        assert_eq!(h.properties.len(), MAX_PROPERTIES);
    }

    #[test]
    fn security_info_and_unsecured_default() {
        let mut s = SpdpSecurity::default();
        assert!(!s.is_secured());
        assert!(!apply_param(
            &mut s,
            PID_PARTICIPANT_SECURITY_INFO,
            &[1, 2],
            true
        ));
        assert!(apply_param(
            &mut s,
            PID_PARTICIPANT_SECURITY_INFO,
            &[1, 0, 0, 0, 2, 0, 0, 0],
            true
        ));
        assert_eq!(s.security_info, Some((1, 2)));
        assert!(s.is_secured());
    }
}
