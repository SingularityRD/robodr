//! The 4-byte encapsulation header that starts every RTPS serialized payload
//! (DDSI-RTPS 2.5 §10.2, DDS-XTypes 1.3 §7.6.3.1.2).
//!
//! ```text
//! octet 0..2  representation identifier (always big-endian on the wire)
//! octet 2..4  representation options
//! octet 4..   CDR body; the XCDR alignment origin is octet 4
//! ```
//!
//! XTypes 1.3 uses the two least-significant bits of the options field to say
//! how many padding octets were appended at the end of the body (so that the
//! payload length is a multiple of 4). Writers that predate that rule send
//! `0x0000`. The value is exposed ([`Encapsulation::padding`]) but decoding
//! never depends on it: members are read from the front.

use crate::error::DecodeError;

/// Byte order of the CDR body.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Endian {
    Big,
    Little,
}

/// XCDR encoding version: decides the maximum alignment and whether
/// DHEADERs exist.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum XcdrVersion {
    /// XCDR1 (classic CDR): primitives align to their size, 8 max.
    Xcdr1,
    /// XCDR2: primitives align to `min(size, 4)`; non-primitive sequences and
    /// appendable structs carry a 4-byte DHEADER.
    Xcdr2,
}

/// The known representation identifiers.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Representation {
    /// `0x0000` CDR_BE (XCDR1, final/appendable).
    CdrBe,
    /// `0x0001` CDR_LE.
    CdrLe,
    /// `0x0002` PL_CDR_BE (XCDR1 parameter list, mutable types).
    PlCdrBe,
    /// `0x0003` PL_CDR_LE.
    PlCdrLe,
    /// `0x0004` XML.
    Xml,
    /// `0x0010` CDR2_BE (XCDR2 plain, final types).
    Cdr2Be,
    /// `0x0011` CDR2_LE.
    Cdr2Le,
    /// `0x0012` PL_CDR2_BE (XCDR2 parameter list, mutable types).
    PlCdr2Be,
    /// `0x0013` PL_CDR2_LE.
    PlCdr2Le,
    /// `0x0014` D_CDR2_BE (XCDR2 delimited, appendable types).
    DCdr2Be,
    /// `0x0015` D_CDR2_LE.
    DCdr2Le,
}

impl Representation {
    /// Maps the big-endian identifier to a representation.
    pub fn from_id(id: u16) -> Option<Self> {
        Some(match id {
            0x0000 => Self::CdrBe,
            0x0001 => Self::CdrLe,
            0x0002 => Self::PlCdrBe,
            0x0003 => Self::PlCdrLe,
            0x0004 => Self::Xml,
            0x0010 => Self::Cdr2Be,
            0x0011 => Self::Cdr2Le,
            0x0012 => Self::PlCdr2Be,
            0x0013 => Self::PlCdr2Le,
            0x0014 => Self::DCdr2Be,
            0x0015 => Self::DCdr2Le,
            _ => return None,
        })
    }

    /// The wire identifier.
    pub fn id(self) -> u16 {
        match self {
            Self::CdrBe => 0x0000,
            Self::CdrLe => 0x0001,
            Self::PlCdrBe => 0x0002,
            Self::PlCdrLe => 0x0003,
            Self::Xml => 0x0004,
            Self::Cdr2Be => 0x0010,
            Self::Cdr2Le => 0x0011,
            Self::PlCdr2Be => 0x0012,
            Self::PlCdr2Le => 0x0013,
            Self::DCdr2Be => 0x0014,
            Self::DCdr2Le => 0x0015,
        }
    }

    /// Body byte order (`None` for XML).
    pub fn endian(self) -> Option<Endian> {
        match self {
            Self::CdrBe | Self::PlCdrBe | Self::Cdr2Be | Self::PlCdr2Be | Self::DCdr2Be => {
                Some(Endian::Big)
            }
            Self::CdrLe | Self::PlCdrLe | Self::Cdr2Le | Self::PlCdr2Le | Self::DCdr2Le => {
                Some(Endian::Little)
            }
            Self::Xml => None,
        }
    }

    /// XCDR version (`None` for XML).
    pub fn version(self) -> Option<XcdrVersion> {
        match self {
            Self::CdrBe | Self::CdrLe | Self::PlCdrBe | Self::PlCdrLe => Some(XcdrVersion::Xcdr1),
            Self::Cdr2Be
            | Self::Cdr2Le
            | Self::PlCdr2Be
            | Self::PlCdr2Le
            | Self::DCdr2Be
            | Self::DCdr2Le => Some(XcdrVersion::Xcdr2),
            Self::Xml => None,
        }
    }

    /// Parameter-list (mutable) encoding. Not decodable by this crate: the
    /// ROS 2 message types are not mutable, so a PL payload on a motion topic
    /// is itself a finding.
    pub fn is_parameter_list(self) -> bool {
        matches!(
            self,
            Self::PlCdrBe | Self::PlCdrLe | Self::PlCdr2Be | Self::PlCdr2Le
        )
    }

    /// XCDR2 delimited (appendable) encoding: structs carry DHEADERs.
    pub fn is_delimited(self) -> bool {
        matches!(self, Self::DCdr2Be | Self::DCdr2Le)
    }
}

/// A parsed encapsulation header.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct Encapsulation {
    pub representation: Representation,
    /// The raw options field (big-endian).
    pub options: u16,
}

impl Encapsulation {
    /// Splits `payload` into the header and the CDR body.
    pub fn parse(payload: &[u8]) -> Result<(Self, &[u8]), DecodeError> {
        let (head, body) = match (payload.get(..4), payload.get(4..)) {
            (Some(h), Some(b)) => (h, b),
            _ => return Err(DecodeError::MissingEncapsulation),
        };
        let (id, options) = match head {
            [a, b, c, d] => (u16::from_be_bytes([*a, *b]), u16::from_be_bytes([*c, *d])),
            _ => return Err(DecodeError::MissingEncapsulation),
        };
        let representation =
            Representation::from_id(id).ok_or(DecodeError::UnknownRepresentation(id))?;
        Ok((
            Encapsulation {
                representation,
                options,
            },
            body,
        ))
    }

    /// Number of trailing padding octets announced by the options field
    /// (XTypes 1.3: its two least-significant bits).
    pub fn padding(&self) -> u8 {
        (self.options & 0x0003) as u8
    }
}
