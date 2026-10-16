//! Decoders for three `std_msgs` scalar types used by robots to publish
//! their safety / operational state: `std_msgs/msg/Bool` (an e-stop or
//! protective-stop flag), `std_msgs/msg/UInt8` (an operating-mode code) and
//! `std_msgs/msg/String` (a mode name, bounded by
//! [`crate::Limits::max_string_len`]).
//!
//! These are **not** motion messages: they are not in [`crate::MessageKind`]
//! or the [`crate::Registry`] (whose decoders produce
//! [`crate::MotionMessage`]s for the Motion Firewall). A consumer that reads
//! a safety-state feed from the bus (`robodr-agentd`'s safety feed) calls
//! [`decode_std`] / [`decode_std_by_type_name`] with the type name SEDP
//! announced for the writer.
//!
//! | DDS type name | ROS type | value |
//! |---|---|---|
//! | `std_msgs::msg::dds_::Bool_` | `std_msgs/msg/Bool` | [`StdValue::Bool`] |
//! | `std_msgs::msg::dds_::UInt8_` | `std_msgs/msg/UInt8` | [`StdValue::UInt8`] |
//! | `std_msgs::msg::dds_::String_` | `std_msgs/msg/String` | [`StdValue::String`] (zero-copy) |
//!
//! Layout: each is a one-member struct (`bool data` / `uint8 data` /
//! `string data`), so the body is the member itself, preceded by a DHEADER
//! under `D_CDR2_*` (the struct is `@appendable` by XTypes default, like
//! every ROS IDL type). `boolean` and `uint8` are one octet with no
//! alignment; the string is the usual `uint32` length (NUL included), the
//! bytes and the NUL. The same encapsulations as the motion decoders are accepted
//! (`CDR_*`, `CDR2_*`, `D_CDR2_*`); `PL_CDR*` is rejected.
//!
//! # Hostile input
//!
//! * A `boolean` octet other than 0 or 1 is rejected
//!   ([`StdDecodeError::InvalidBool`]): DDS-XTypes defines only those two
//!   values, and a safety flag must never be "probably true".
//! * Strings obey [`crate::Limits::max_string_len`] (checked before the bytes
//!   are touched), must end in NUL and are not required to be UTF-8 (the
//!   consumer compares bytes).
//! * Trailing bytes are allowed and reported
//!   ([`StdDecoded::trailing_bytes`], [`StdDecoded::anomalies`]) exactly as
//!   for motion messages.
//! * No panics, no allocation.
//!
//! # Not verified
//!
//! As for the motion types: the layouts are derived from DDS-XTypes 1.3 and
//! checked against hand-written vectors only, not against captures of a real
//! RMW.

use std::fmt;

use crate::encap::Encapsulation;
use crate::error::DecodeError;
use crate::reader::{CdrStr, Reader};
use crate::{DecodeAnomaly, Limits, MAX_END_PADDING};

/// The supported `std_msgs` types.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum StdKind {
    Bool,
    UInt8,
    String,
}

impl StdKind {
    pub const ALL: [StdKind; 3] = [StdKind::Bool, StdKind::UInt8, StdKind::String];

    /// DDS-mangled type name as announced in SEDP `PID_TYPE_NAME`.
    pub fn dds_type_name(self) -> &'static str {
        match self {
            StdKind::Bool => "std_msgs::msg::dds_::Bool_",
            StdKind::UInt8 => "std_msgs::msg::dds_::UInt8_",
            StdKind::String => "std_msgs::msg::dds_::String_",
        }
    }

    /// ROS interface name.
    pub fn ros_type_name(self) -> &'static str {
        match self {
            StdKind::Bool => "std_msgs/msg/Bool",
            StdKind::UInt8 => "std_msgs/msg/UInt8",
            StdKind::String => "std_msgs/msg/String",
        }
    }

    /// Kind for a DDS or ROS type name (exact match).
    pub fn from_type_name(name: &str) -> Option<Self> {
        Self::ALL
            .into_iter()
            .find(|k| k.dds_type_name() == name || k.ros_type_name() == name)
    }
}

/// A decoded `std_msgs` value, borrowing from the payload.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum StdValue<'a> {
    Bool(bool),
    UInt8(u8),
    /// Bytes as sent (NUL excluded); UTF-8 is not required.
    String(CdrStr<'a>),
}

impl StdValue<'_> {
    pub fn kind(&self) -> StdKind {
        match self {
            StdValue::Bool(_) => StdKind::Bool,
            StdValue::UInt8(_) => StdKind::UInt8,
            StdValue::String(_) => StdKind::String,
        }
    }
}

/// A successful decode.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct StdDecoded<'a> {
    pub encapsulation: Encapsulation,
    pub value: StdValue<'a>,
    /// Body bytes consumed by the message.
    pub consumed: usize,
    /// Body bytes left after the message (XCDR end padding shows up here).
    pub trailing_bytes: usize,
}

impl StdDecoded<'_> {
    /// [`DecodeAnomaly::ExcessTrailingBytes`] when more than
    /// [`MAX_END_PADDING`] bytes follow the message; empty otherwise.
    pub fn anomalies(&self) -> Vec<DecodeAnomaly> {
        if self.trailing_bytes > MAX_END_PADDING {
            vec![DecodeAnomaly::ExcessTrailingBytes {
                trailing: self.trailing_bytes,
                allowed: MAX_END_PADDING,
            }]
        } else {
            Vec::new()
        }
    }
}

/// Why a `std_msgs` payload was rejected.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StdDecodeError {
    /// The CDR layer rejected it (see [`DecodeError`]).
    Cdr(DecodeError),
    /// A `boolean` octet that is neither 0 nor 1, at body offset `at`.
    InvalidBool { at: usize, value: u8 },
}

impl From<DecodeError> for StdDecodeError {
    fn from(e: DecodeError) -> Self {
        StdDecodeError::Cdr(e)
    }
}

impl fmt::Display for StdDecodeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            StdDecodeError::Cdr(e) => write!(f, "{e}"),
            StdDecodeError::InvalidBool { at, value } => write!(
                f,
                "boolean octet 0x{value:02x} at offset {at} is neither 0 nor 1"
            ),
        }
    }
}

impl std::error::Error for StdDecodeError {}

/// Decodes one serialized payload (encapsulation header included) as `kind`.
pub fn decode_std<'a>(
    kind: StdKind,
    payload: &'a [u8],
    limits: &Limits,
) -> Result<StdDecoded<'a>, StdDecodeError> {
    if payload.len() > limits.max_payload_len {
        return Err(DecodeError::PayloadTooLarge {
            len: payload.len(),
            max: limits.max_payload_len,
        }
        .into());
    }
    let (encapsulation, body) = Encapsulation::parse(payload)?;
    let rep = encapsulation.representation;
    let (endian, version) = match (rep.endian(), rep.version()) {
        (Some(e), Some(v)) if !rep.is_parameter_list() => (e, v),
        _ => return Err(DecodeError::UnsupportedRepresentation(rep).into()),
    };
    let mut r = Reader::new(body, endian, version, rep.is_delimited(), *limits);
    // The bool check runs inside the struct closure, which can only return
    // a `DecodeError`; carry the bad octet out separately.
    let mut bad_bool: Option<(usize, u8)> = None;
    let value = r.structure(|r| {
        Ok(match kind {
            StdKind::Bool => {
                let at = r.pos();
                match r.u8()? {
                    0 => StdValue::Bool(false),
                    1 => StdValue::Bool(true),
                    v => {
                        bad_bool = Some((at, v));
                        StdValue::Bool(false)
                    }
                }
            }
            StdKind::UInt8 => StdValue::UInt8(r.u8()?),
            StdKind::String => StdValue::String(r.string()?),
        })
    })?;
    if let Some((at, value)) = bad_bool {
        return Err(StdDecodeError::InvalidBool { at, value });
    }
    Ok(StdDecoded {
        encapsulation,
        value,
        consumed: r.pos(),
        trailing_bytes: r.remaining(),
    })
}

/// Decodes a payload by DDS (or ROS) type name. An unsupported name is
/// [`DecodeError::UnknownType`].
pub fn decode_std_by_type_name<'a>(
    type_name: &str,
    payload: &'a [u8],
    limits: &Limits,
) -> Result<StdDecoded<'a>, StdDecodeError> {
    let kind = StdKind::from_type_name(type_name).ok_or(DecodeError::UnknownType)?;
    decode_std(kind, payload, limits)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::Representation;

    fn lim() -> Limits {
        Limits::default()
    }

    #[test]
    fn bool_all_encapsulations() {
        // CDR_LE, true, with 3 bytes of end padding.
        let d = decode_std(StdKind::Bool, &[0, 1, 0, 0, 1, 0, 0, 0], &lim()).unwrap();
        assert_eq!(d.value, StdValue::Bool(true));
        assert_eq!(d.encapsulation.representation, Representation::CdrLe);
        assert_eq!((d.consumed, d.trailing_bytes), (1, 3));
        assert!(d.anomalies().is_empty());
        // CDR_BE false, no padding.
        let d = decode_std(StdKind::Bool, &[0, 0, 0, 0, 0], &lim()).unwrap();
        assert_eq!(d.value, StdValue::Bool(false));
        // CDR2_LE.
        let d = decode_std(StdKind::Bool, &[0, 7, 0, 0, 1], &lim()).unwrap();
        assert_eq!(d.value, StdValue::Bool(true));
        // D_CDR2_LE: DHEADER (1) + octet.
        let d = decode_std(StdKind::Bool, &[0, 9, 0, 0, 1, 0, 0, 0, 1], &lim()).unwrap();
        assert_eq!(d.value, StdValue::Bool(true));
        assert_eq!(d.consumed, 5);
        // D_CDR2_BE with an appended member skipped by the DHEADER.
        let d = decode_std(StdKind::Bool, &[0, 8, 0, 0, 0, 0, 0, 2, 0, 0xaa], &lim()).unwrap();
        assert_eq!(d.value, StdValue::Bool(false));
        assert_eq!(d.trailing_bytes, 0);
    }

    #[test]
    fn bool_rejects_other_octets() {
        for v in [2u8, 0x80, 0xff] {
            let e = decode_std(StdKind::Bool, &[0, 1, 0, 0, v], &lim()).unwrap_err();
            assert_eq!(e, StdDecodeError::InvalidBool { at: 0, value: v });
            assert!(e.to_string().contains("neither 0 nor 1"));
        }
        // Inside a DHEADER too.
        let e = decode_std(StdKind::Bool, &[0, 9, 0, 0, 1, 0, 0, 0, 7], &lim()).unwrap_err();
        assert_eq!(e, StdDecodeError::InvalidBool { at: 4, value: 7 });
    }

    #[test]
    fn uint8_and_string() {
        let d = decode_std(StdKind::UInt8, &[0, 1, 0, 0, 0xfe], &lim()).unwrap();
        assert_eq!(d.value, StdValue::UInt8(254));
        assert_eq!(d.value.kind(), StdKind::UInt8);
        let p = [0, 1, 0, 0, 5, 0, 0, 0, b'a', b'u', b't', b'o', 0];
        let d = decode_std(StdKind::String, &p, &lim()).unwrap();
        match d.value {
            StdValue::String(s) => assert_eq!(s.as_str(), Some("auto")),
            v => panic!("{v:?}"),
        }
        // Big-endian length.
        let p = [0, 0, 0, 0, 0, 0, 0, 1, 0];
        let d = decode_std(StdKind::String, &p, &lim()).unwrap();
        assert_eq!(d.value, StdValue::String(CdrStr(b"")));
        // Bounded.
        let small = Limits {
            max_string_len: 4,
            ..lim()
        };
        let p = [0, 1, 0, 0, 5, 0, 0, 0, b'a', b'u', b't', b'o', 0];
        assert!(matches!(
            decode_std(StdKind::String, &p, &small),
            Err(StdDecodeError::Cdr(DecodeError::StringTooLong { .. }))
        ));
        // Huge length prefix: refused before anything is read.
        let p = [0, 1, 0, 0, 0xff, 0xff, 0xff, 0xff];
        assert!(decode_std(StdKind::String, &p, &lim()).is_err());
        // Not NUL-terminated / zero length.
        let p = [0, 1, 0, 0, 2, 0, 0, 0, b'a', b'b'];
        assert!(decode_std(StdKind::String, &p, &lim()).is_err());
        let p = [0, 1, 0, 0, 0, 0, 0, 0];
        assert!(decode_std(StdKind::String, &p, &lim()).is_err());
    }

    #[test]
    fn malformed_and_unsupported() {
        for kind in StdKind::ALL {
            for len in 0..6 {
                // Every truncation of a short payload: an error or a value,
                // never a panic.
                let p = [0u8, 1, 0, 0, 1, 0][..len].to_vec();
                let _ = decode_std(kind, &p, &lim());
            }
            assert!(decode_std(kind, &[0, 1, 0, 0], &lim()).is_err());
            assert!(
                decode_std(kind, &[0, 3, 0, 0, 1], &lim()).is_err(),
                "PL_CDR"
            );
            assert!(decode_std(kind, &[0x7f, 0x7f, 0, 0, 1], &lim()).is_err());
            let tiny = Limits {
                max_payload_len: 4,
                ..lim()
            };
            assert!(decode_std(kind, &[0, 1, 0, 0, 1], &tiny).is_err());
        }
        let d = decode_std(StdKind::UInt8, &[0, 1, 0, 0, 3, 9, 9, 9, 9], &lim()).unwrap();
        assert_eq!(d.anomalies().len(), 1);
    }

    #[test]
    fn type_names() {
        for k in StdKind::ALL {
            assert_eq!(StdKind::from_type_name(k.dds_type_name()), Some(k));
            assert_eq!(StdKind::from_type_name(k.ros_type_name()), Some(k));
        }
        assert_eq!(StdKind::from_type_name("std_msgs/msg/Int8"), None);
        let d = decode_std_by_type_name("std_msgs::msg::dds_::UInt8_", &[0, 1, 0, 0, 2], &lim())
            .unwrap();
        assert_eq!(d.value, StdValue::UInt8(2));
        assert_eq!(
            decode_std_by_type_name("x", &[0, 1, 0, 0, 2], &lim()),
            Err(StdDecodeError::Cdr(DecodeError::UnknownType))
        );
    }

    #[test]
    fn random_bytes_never_panic() {
        let mut x: u64 = 0x9e37_79b9_7f4a_7c15;
        for _ in 0..20_000 {
            x ^= x << 13;
            x ^= x >> 7;
            x ^= x << 17;
            let len = (x % 24) as usize;
            let mut p: Vec<u8> = (0..len).map(|i| (x >> (i % 8 * 8)) as u8).collect();
            if p.len() >= 2 {
                p[0] = 0;
                p[1] = (x % 10) as u8;
            }
            for k in StdKind::ALL {
                let _ = decode_std(k, &p, &lim());
            }
        }
    }
}
