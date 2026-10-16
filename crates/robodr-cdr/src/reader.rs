//! The bounds-checked CDR cursor every decoder is built on.
//!
//! Positions are offsets into the CDR body (the alignment origin, i.e. the
//! first octet after the encapsulation header). `end` is the current hard
//! limit: the body length, or the end of the innermost XCDR2 delimited
//! object. Nothing here indexes a slice directly or does unchecked
//! arithmetic; every failure is a [`DecodeError`].

use crate::encap::{Endian, XcdrVersion};
use crate::error::DecodeError;
use crate::{DelimitedNesting, Limits};

/// Bytes of a CDR string between its length prefix and its NUL terminator.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default)]
pub struct CdrStr<'a>(pub &'a [u8]);

impl<'a> CdrStr<'a> {
    /// The raw bytes (terminator excluded). May contain embedded NULs or
    /// invalid UTF-8: the wire is hostile, the bytes are kept as sent.
    pub fn as_bytes(&self) -> &'a [u8] {
        self.0
    }

    /// The string, if it is valid UTF-8.
    pub fn as_str(&self) -> Option<&'a str> {
        std::str::from_utf8(self.0).ok()
    }

    /// Lossy UTF-8 rendering (allocates only if invalid).
    pub fn to_string_lossy(&self) -> std::borrow::Cow<'a, str> {
        String::from_utf8_lossy(self.0)
    }

    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }
}

#[derive(Debug, Clone)]
pub(crate) struct Reader<'a> {
    buf: &'a [u8],
    pos: usize,
    end: usize,
    endian: Endian,
    version: XcdrVersion,
    /// XCDR2 only: structs are preceded by a DHEADER (D_CDR2); which ones
    /// is decided by `limits.d_cdr2_nesting`.
    delimited_structs: bool,
    /// Current struct nesting depth (0 = the top-level message).
    depth: u32,
    pub(crate) limits: Limits,
}

impl<'a> Reader<'a> {
    pub(crate) fn new(
        buf: &'a [u8],
        endian: Endian,
        version: XcdrVersion,
        delimited_structs: bool,
        limits: Limits,
    ) -> Self {
        Reader {
            buf,
            pos: 0,
            end: buf.len(),
            endian,
            version,
            delimited_structs: delimited_structs && version == XcdrVersion::Xcdr2,
            depth: 0,
            limits,
        }
    }

    pub(crate) fn pos(&self) -> usize {
        self.pos
    }

    pub(crate) fn endian(&self) -> Endian {
        self.endian
    }

    pub(crate) fn buf(&self) -> &'a [u8] {
        self.buf
    }

    /// Bytes left before `end`.
    pub(crate) fn remaining(&self) -> usize {
        self.end.saturating_sub(self.pos)
    }

    fn max_align(&self) -> usize {
        match self.version {
            XcdrVersion::Xcdr1 => 8,
            XcdrVersion::Xcdr2 => 4,
        }
    }

    /// Aligns to `min(size, max_align)` relative to the origin.
    pub(crate) fn align(&mut self, size: usize) -> Result<(), DecodeError> {
        let a = size.min(self.max_align()).max(1);
        let rem = self.pos.checked_rem(a).unwrap_or(0);
        if rem == 0 {
            return Ok(());
        }
        let pad = a.saturating_sub(rem);
        self.skip(pad)
    }

    fn skip(&mut self, n: usize) -> Result<(), DecodeError> {
        let new =
            self.pos
                .checked_add(n)
                .filter(|&p| p <= self.end)
                .ok_or(DecodeError::Truncated {
                    at: self.pos,
                    need: n,
                })?;
        self.pos = new;
        Ok(())
    }

    /// `n` raw bytes, no alignment.
    pub(crate) fn bytes(&mut self, n: usize) -> Result<&'a [u8], DecodeError> {
        let start = self.pos;
        self.skip(n)?;
        self.buf
            .get(start..self.pos)
            .ok_or(DecodeError::Truncated { at: start, need: n })
    }

    fn array<const N: usize>(&mut self) -> Result<[u8; N], DecodeError> {
        self.align(N)?;
        let at = self.pos;
        let b = self.bytes(N)?;
        <[u8; N]>::try_from(b).map_err(|_| DecodeError::Truncated { at, need: N })
    }

    /// One octet (`octet`, `uint8`, `boolean`): no alignment.
    pub(crate) fn u8(&mut self) -> Result<u8, DecodeError> {
        let [b] = self.array::<1>()?;
        Ok(b)
    }

    pub(crate) fn u32(&mut self) -> Result<u32, DecodeError> {
        let b = self.array::<4>()?;
        Ok(match self.endian {
            Endian::Big => u32::from_be_bytes(b),
            Endian::Little => u32::from_le_bytes(b),
        })
    }

    pub(crate) fn i32(&mut self) -> Result<i32, DecodeError> {
        let b = self.array::<4>()?;
        Ok(match self.endian {
            Endian::Big => i32::from_be_bytes(b),
            Endian::Little => i32::from_le_bytes(b),
        })
    }

    pub(crate) fn f64(&mut self) -> Result<f64, DecodeError> {
        let b = self.array::<8>()?;
        Ok(f64_from(b, self.endian))
    }

    /// A fixed-size `double[N]` array (no length prefix, no DHEADER: the
    /// element type is primitive).
    pub(crate) fn f64_array<const N: usize>(&mut self) -> Result<[f64; N], DecodeError> {
        let mut out = [0.0; N];
        for v in out.iter_mut() {
            *v = self.f64()?;
        }
        Ok(out)
    }

    /// A CDR string: `uint32` length including the NUL, then the bytes.
    /// A length of 0 is rejected: the prefix counts the terminator, so the
    /// empty string is `01 00 00 00 00` (Fast CDR and Cyclone DDS both send
    /// that), and a 0 prefix is malformed.
    pub(crate) fn string(&mut self) -> Result<CdrStr<'a>, DecodeError> {
        self.align(4)?;
        let at = self.pos;
        let len = self.u32()?;
        if len > self.limits.max_string_len {
            return Err(DecodeError::StringTooLong {
                at,
                len,
                max: self.limits.max_string_len,
            });
        }
        if len == 0 {
            return Err(DecodeError::StringLengthZero { at });
        }
        let raw = self.bytes(len as usize)?;
        match raw.split_last() {
            Some((0, body)) => Ok(CdrStr(body)),
            _ => Err(DecodeError::StringNotTerminated { at }),
        }
    }

    /// A sequence length prefix, checked against `max` and against the
    /// bytes left (`min_elem_size` octets per element at least), before any
    /// caller iterates or multiplies.
    pub(crate) fn seq_len(&mut self, max: u32, min_elem_size: usize) -> Result<u32, DecodeError> {
        self.align(4)?;
        let at = self.pos;
        let len = self.u32()?;
        if len > max {
            return Err(DecodeError::SequenceTooLong { at, len, max });
        }
        let need = (len as usize).saturating_mul(min_elem_size);
        if need > self.remaining() {
            return Err(DecodeError::Truncated { at: self.pos, need });
        }
        Ok(len)
    }

    /// Runs `f` inside an XCDR2 delimited object (DHEADER = byte size of
    /// what follows). The cursor ends exactly at the announced end, so
    /// members appended by a newer type version are skipped.
    pub(crate) fn delimited<T>(
        &mut self,
        f: impl FnOnce(&mut Self) -> Result<T, DecodeError>,
    ) -> Result<T, DecodeError> {
        self.align(4)?;
        let at = self.pos;
        let size = self.u32()?;
        let new_end = self
            .pos
            .checked_add(size as usize)
            .filter(|&e| e <= self.end)
            .ok_or(DecodeError::DelimiterOutOfBounds { at, size })?;
        let outer_end = self.end;
        self.end = new_end;
        let r = f(self);
        self.end = outer_end;
        let v = r?;
        if self.pos > new_end {
            return Err(DecodeError::DelimiterOverrun {
                at: self.pos,
                end: new_end,
            });
        }
        self.pos = new_end;
        Ok(v)
    }

    /// A (possibly appendable) struct: DHEADER-wrapped under D_CDR2 (the
    /// top-level struct always; nested ones per
    /// [`Limits::d_cdr2_nesting`]), plain otherwise.
    pub(crate) fn structure<T>(
        &mut self,
        f: impl FnOnce(&mut Self) -> Result<T, DecodeError>,
    ) -> Result<T, DecodeError> {
        let depth = self.depth;
        let wrap = self.delimited_structs
            && (depth == 0 || self.limits.d_cdr2_nesting == DelimitedNesting::AllStructs);
        self.depth = depth.saturating_add(1);
        let r = if wrap { self.delimited(f) } else { f(self) };
        self.depth = depth;
        r
    }

    /// A sequence of non-primitive elements: XCDR2 puts a DHEADER before
    /// it, XCDR1 does not.
    pub(crate) fn nonprimitive_seq<T>(
        &mut self,
        f: impl FnOnce(&mut Self) -> Result<T, DecodeError>,
    ) -> Result<T, DecodeError> {
        match self.version {
            XcdrVersion::Xcdr2 => self.delimited(f),
            XcdrVersion::Xcdr1 => f(self),
        }
    }
}

pub(crate) fn f64_from(b: [u8; 8], endian: Endian) -> f64 {
    match endian {
        Endian::Big => f64::from_be_bytes(b),
        Endian::Little => f64::from_le_bytes(b),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn r(buf: &[u8], v: XcdrVersion) -> Reader<'_> {
        Reader::new(buf, Endian::Little, v, false, Limits::default())
    }

    #[test]
    fn xcdr1_aligns_f64_to_8_xcdr2_to_4() {
        let buf = [0u8; 16];
        let mut a = r(&buf, XcdrVersion::Xcdr1);
        a.u32().unwrap();
        a.f64().unwrap();
        assert_eq!(a.pos(), 16);
        let mut b = r(&buf, XcdrVersion::Xcdr2);
        b.u32().unwrap();
        b.f64().unwrap();
        assert_eq!(b.pos(), 12);
    }

    #[test]
    fn padding_past_end_is_truncation() {
        let buf = [0u8; 9];
        let mut a = r(&buf, XcdrVersion::Xcdr1);
        a.bytes(1).unwrap();
        assert!(matches!(a.f64(), Err(DecodeError::Truncated { .. })));
    }

    #[test]
    fn delimited_restores_outer_end_on_error() {
        // DHEADER 4, then 4 bytes, then a u32 outside.
        let buf = [4, 0, 0, 0, 1, 0, 0, 0, 7, 0, 0, 0];
        let mut a = r(&buf, XcdrVersion::Xcdr2);
        let e = a.delimited(|r| {
            r.u32()?;
            r.u32()
        });
        assert!(matches!(e, Err(DecodeError::Truncated { .. })));
        // Outer limit is back: the trailing u32 (outside the object) is
        // readable again.
        assert_eq!(a.u32().unwrap(), 7);
    }

    #[test]
    fn delimited_skips_appended_members() {
        let buf = [8, 0, 0, 0, 1, 0, 0, 0, 9, 9, 9, 9, 7, 0, 0, 0];
        let mut a = r(&buf, XcdrVersion::Xcdr2);
        assert_eq!(a.delimited(|r| r.u32()).unwrap(), 1);
        assert_eq!(a.u32().unwrap(), 7);
    }

    #[test]
    fn delimiter_beyond_buffer() {
        let buf = [0xff, 0xff, 0xff, 0xff, 0];
        let mut a = r(&buf, XcdrVersion::Xcdr2);
        assert!(matches!(
            a.delimited(|r| r.u32()),
            Err(DecodeError::DelimiterOutOfBounds { .. })
        ));
    }

    #[test]
    fn string_rules() {
        let mut a = r(&[0, 0, 0, 0], XcdrVersion::Xcdr1);
        assert_eq!(a.string(), Err(DecodeError::StringLengthZero { at: 0 }));
        let mut e = r(&[1, 0, 0, 0, 0], XcdrVersion::Xcdr1);
        assert!(e.string().unwrap().is_empty());
        let mut b = r(&[2, 0, 0, 0, b'a', b'b'], XcdrVersion::Xcdr1);
        assert!(matches!(
            b.string(),
            Err(DecodeError::StringNotTerminated { at: 0 })
        ));
        let mut c = r(&[0xff, 0xff, 0xff, 0xff], XcdrVersion::Xcdr1);
        assert!(matches!(c.string(), Err(DecodeError::StringTooLong { .. })));
    }
}
