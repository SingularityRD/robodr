//! Decode errors. Every way a payload can be rejected has its own variant so
//! that a consumer can count / report malformed traffic precisely.

use std::fmt;

use crate::encap::Representation;

/// Why a serialized payload could not be decoded.
///
/// Offsets (`at`) are relative to the start of the CDR body, i.e. the first
/// byte **after** the 4-byte encapsulation header (the XCDR alignment origin).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DecodeError {
    /// The payload is shorter than the 4-byte encapsulation header.
    MissingEncapsulation,
    /// The encapsulation identifier is not one this crate knows.
    UnknownRepresentation(u16),
    /// The identifier is known but cannot be decoded for these types
    /// (parameter-list / mutable encodings, XML).
    UnsupportedRepresentation(Representation),
    /// The payload exceeds [`crate::Limits::max_payload_len`].
    PayloadTooLarge { len: usize, max: usize },
    /// A primitive, padding or element run needs `need` bytes at `at` but the
    /// enclosing buffer (or delimited object) ends first.
    Truncated { at: usize, need: usize },
    /// A string's length prefix exceeds [`crate::Limits::max_string_len`].
    StringTooLong { at: usize, len: u32, max: u32 },
    /// A non-empty CDR string whose last byte is not NUL.
    StringNotTerminated { at: usize },
    /// A sequence's element count exceeds the configured cap.
    SequenceTooLong { at: usize, len: u32, max: u32 },
    /// An XCDR2 DHEADER announces more bytes than its container holds.
    DelimiterOutOfBounds { at: usize, size: u32 },
    /// The members read inside an XCDR2 delimited object ran past the end
    /// that its DHEADER announced.
    DelimiterOverrun { at: usize, end: usize },
    /// No decoder is registered for the DDS type name.
    UnknownType,
}

impl fmt::Display for DecodeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match *self {
            DecodeError::MissingEncapsulation => {
                write!(f, "payload shorter than the 4-byte encapsulation header")
            }
            DecodeError::UnknownRepresentation(id) => {
                write!(f, "unknown encapsulation identifier 0x{id:04x}")
            }
            DecodeError::UnsupportedRepresentation(r) => {
                write!(f, "unsupported encapsulation {r:?}")
            }
            DecodeError::PayloadTooLarge { len, max } => {
                write!(f, "payload of {len} bytes exceeds the {max}-byte cap")
            }
            DecodeError::Truncated { at, need } => {
                write!(f, "truncated: {need} bytes needed at offset {at}")
            }
            DecodeError::StringTooLong { at, len, max } => {
                write!(f, "string length {len} at offset {at} exceeds cap {max}")
            }
            DecodeError::StringNotTerminated { at } => {
                write!(f, "string at offset {at} is not NUL-terminated")
            }
            DecodeError::SequenceTooLong { at, len, max } => {
                write!(f, "sequence length {len} at offset {at} exceeds cap {max}")
            }
            DecodeError::DelimiterOutOfBounds { at, size } => {
                write!(
                    f,
                    "DHEADER at offset {at} announces {size} bytes beyond its container"
                )
            }
            DecodeError::DelimiterOverrun { at, end } => {
                write!(f, "members read to offset {at}, past the DHEADER end {end}")
            }
            DecodeError::UnknownType => write!(f, "no decoder registered for this type name"),
        }
    }
}

impl std::error::Error for DecodeError {}
