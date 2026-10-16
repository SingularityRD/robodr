//! Kafka primitive types: big-endian integers, `STRING`, `NULLABLE_STRING`,
//! `BYTES`, `NULLABLE_BYTES`, `ARRAY`, and the zig-zag `VARINT` /
//! `VARLONG` of RecordBatch v2.
//!
//! Only the classic (non-flexible) encodings are implemented: this client
//! negotiates request versions below the first "flexible" version of every
//! API it uses (no compact strings, no tagged fields).
//!
//! The [`Reader`] never panics on hostile input: every length is checked
//! against the remaining bytes before anything is allocated, so a forged
//! array count cannot make it allocate more than the frame it came in.

use std::fmt;

/// Why a frame could not be decoded.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DecodeError(pub String);

impl fmt::Display for DecodeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "decode: {}", self.0)
    }
}

impl std::error::Error for DecodeError {}

pub(crate) fn derr<T>(msg: impl Into<String>) -> Result<T, DecodeError> {
    Err(DecodeError(msg.into()))
}

/// Zig-zag encode a 32-bit signed value.
pub fn zigzag32(v: i32) -> u32 {
    ((v << 1) ^ (v >> 31)) as u32
}

/// Zig-zag encode a 64-bit signed value.
pub fn zigzag64(v: i64) -> u64 {
    ((v << 1) ^ (v >> 63)) as u64
}

/// Append an unsigned LEB128 value.
pub fn put_uvarint(buf: &mut Vec<u8>, mut v: u64) {
    while v >= 0x80 {
        buf.push((v as u8) | 0x80);
        v >>= 7;
    }
    buf.push(v as u8);
}

/// Append a zig-zag `VARINT`.
pub fn put_varint(buf: &mut Vec<u8>, v: i32) {
    put_uvarint(buf, u64::from(zigzag32(v)));
}

/// Append a zig-zag `VARLONG`.
pub fn put_varlong(buf: &mut Vec<u8>, v: i64) {
    put_uvarint(buf, zigzag64(v));
}

/// Encoded size of a zig-zag `VARINT`.
pub fn varint_len(v: i32) -> usize {
    uvarint_len(u64::from(zigzag32(v)))
}

/// Encoded size of a zig-zag `VARLONG`.
pub fn varlong_len(v: i64) -> usize {
    uvarint_len(zigzag64(v))
}

fn uvarint_len(mut v: u64) -> usize {
    let mut n = 1;
    while v >= 0x80 {
        v >>= 7;
        n += 1;
    }
    n
}

/// Big-endian writer for request bodies.
#[derive(Debug, Default, Clone)]
pub struct Writer {
    pub buf: Vec<u8>,
}

impl Writer {
    pub fn new() -> Self {
        Self::default()
    }
    pub fn i8(&mut self, v: i8) -> &mut Self {
        self.buf.push(v as u8);
        self
    }
    pub fn bool(&mut self, v: bool) -> &mut Self {
        self.buf.push(u8::from(v));
        self
    }
    pub fn i16(&mut self, v: i16) -> &mut Self {
        self.buf.extend_from_slice(&v.to_be_bytes());
        self
    }
    pub fn i32(&mut self, v: i32) -> &mut Self {
        self.buf.extend_from_slice(&v.to_be_bytes());
        self
    }
    pub fn u32(&mut self, v: u32) -> &mut Self {
        self.buf.extend_from_slice(&v.to_be_bytes());
        self
    }
    pub fn i64(&mut self, v: i64) -> &mut Self {
        self.buf.extend_from_slice(&v.to_be_bytes());
        self
    }
    /// `STRING` (int16 length). Panics never: strings longer than
    /// `i16::MAX` are a caller bug and are rejected by [`Writer::try_string`].
    pub fn try_string(&mut self, s: &str) -> Result<&mut Self, DecodeError> {
        let n = i16::try_from(s.len()).or_else(|_| derr("string longer than 32767 bytes"))?;
        self.i16(n);
        self.buf.extend_from_slice(s.as_bytes());
        Ok(self)
    }
    /// `NULLABLE_STRING`.
    pub fn try_nullable_string(&mut self, s: Option<&str>) -> Result<&mut Self, DecodeError> {
        match s {
            None => {
                self.i16(-1);
                Ok(self)
            }
            Some(s) => self.try_string(s),
        }
    }
    /// `NULLABLE_BYTES` (int32 length).
    pub fn try_nullable_bytes(&mut self, b: Option<&[u8]>) -> Result<&mut Self, DecodeError> {
        match b {
            None => {
                self.i32(-1);
            }
            Some(b) => {
                let n = i32::try_from(b.len()).or_else(|_| derr("bytes longer than i32::MAX"))?;
                self.i32(n);
                self.buf.extend_from_slice(b);
            }
        }
        Ok(self)
    }
    /// `ARRAY` length prefix.
    pub fn try_array_len(&mut self, n: usize) -> Result<&mut Self, DecodeError> {
        let n = i32::try_from(n).or_else(|_| derr("array longer than i32::MAX"))?;
        self.i32(n);
        Ok(self)
    }
}

/// Bounds-checked big-endian reader.
#[derive(Debug, Clone)]
pub struct Reader<'a> {
    buf: &'a [u8],
    pos: usize,
}

impl<'a> Reader<'a> {
    pub fn new(buf: &'a [u8]) -> Self {
        Self { buf, pos: 0 }
    }
    pub fn remaining(&self) -> usize {
        self.buf.len() - self.pos
    }
    pub fn position(&self) -> usize {
        self.pos
    }
    pub fn is_empty(&self) -> bool {
        self.remaining() == 0
    }
    pub fn take(&mut self, n: usize) -> Result<&'a [u8], DecodeError> {
        if n > self.remaining() {
            return derr(format!(
                "need {n} bytes at offset {}, have {}",
                self.pos,
                self.remaining()
            ));
        }
        let s = &self.buf[self.pos..self.pos + n];
        self.pos += n;
        Ok(s)
    }
    fn arr<const N: usize>(&mut self) -> Result<[u8; N], DecodeError> {
        let s = self.take(N)?;
        let mut a = [0u8; N];
        a.copy_from_slice(s);
        Ok(a)
    }
    pub fn i8(&mut self) -> Result<i8, DecodeError> {
        Ok(self.arr::<1>()?[0] as i8)
    }
    pub fn bool(&mut self) -> Result<bool, DecodeError> {
        match self.arr::<1>()?[0] {
            0 => Ok(false),
            1 => Ok(true),
            b => derr(format!("invalid boolean {b}")),
        }
    }
    pub fn i16(&mut self) -> Result<i16, DecodeError> {
        Ok(i16::from_be_bytes(self.arr()?))
    }
    pub fn i32(&mut self) -> Result<i32, DecodeError> {
        Ok(i32::from_be_bytes(self.arr()?))
    }
    pub fn u32(&mut self) -> Result<u32, DecodeError> {
        Ok(u32::from_be_bytes(self.arr()?))
    }
    pub fn i64(&mut self) -> Result<i64, DecodeError> {
        Ok(i64::from_be_bytes(self.arr()?))
    }
    /// `NULLABLE_STRING` (must be UTF-8).
    pub fn nullable_string(&mut self) -> Result<Option<&'a str>, DecodeError> {
        let n = self.i16()?;
        if n == -1 {
            return Ok(None);
        }
        if n < 0 {
            return derr(format!("negative string length {n}"));
        }
        let b = self.take(n as usize)?;
        std::str::from_utf8(b)
            .map(Some)
            .or_else(|_| derr("string is not UTF-8"))
    }
    /// `STRING`.
    pub fn string(&mut self) -> Result<&'a str, DecodeError> {
        self.nullable_string()?
            .map_or_else(|| derr("null where a string is required"), Ok)
    }
    /// `NULLABLE_BYTES`.
    pub fn nullable_bytes(&mut self) -> Result<Option<&'a [u8]>, DecodeError> {
        let n = self.i32()?;
        if n == -1 {
            return Ok(None);
        }
        if n < 0 {
            return derr(format!("negative bytes length {n}"));
        }
        self.take(n as usize).map(Some)
    }
    /// `ARRAY` length; `min_elem` is the smallest encoded element size, used
    /// to reject counts the remaining bytes cannot hold. `-1` (null array)
    /// reads as 0.
    pub fn array_len(&mut self, min_elem: usize) -> Result<usize, DecodeError> {
        let n = self.i32()?;
        if n == -1 {
            return Ok(0);
        }
        if n < 0 {
            return derr(format!("negative array length {n}"));
        }
        let n = n as usize;
        if n.saturating_mul(min_elem.max(1)) > self.remaining() {
            return derr(format!(
                "array of {n} elements cannot fit in {} bytes",
                self.remaining()
            ));
        }
        Ok(n)
    }
    /// Unsigned LEB128, at most `max_bytes` bytes.
    fn uvarint(&mut self, max_bytes: usize) -> Result<u64, DecodeError> {
        let mut v: u64 = 0;
        for i in 0..max_bytes {
            let b = self.arr::<1>()?[0];
            v |= u64::from(b & 0x7f) << (7 * i);
            if b & 0x80 == 0 {
                return Ok(v);
            }
        }
        derr("varint too long")
    }
    /// Zig-zag `VARINT`.
    pub fn varint(&mut self) -> Result<i32, DecodeError> {
        let u = self.uvarint(5)?;
        let u = u32::try_from(u).or_else(|_| derr("varint out of range"))?;
        Ok(((u >> 1) as i32) ^ -((u & 1) as i32))
    }
    /// Zig-zag `VARLONG`.
    pub fn varlong(&mut self) -> Result<i64, DecodeError> {
        let u = self.uvarint(10)?;
        Ok(((u >> 1) as i64) ^ -((u & 1) as i64))
    }
    /// Varint-length-prefixed bytes (`-1` = null).
    pub fn varbytes(&mut self) -> Result<Option<&'a [u8]>, DecodeError> {
        let n = self.varint()?;
        if n == -1 {
            return Ok(None);
        }
        if n < 0 {
            return derr(format!("negative varint length {n}"));
        }
        self.take(n as usize).map(Some)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn zigzag_known_values() {
        // Protocol Buffers' zig-zag table (Kafka uses the same encoding).
        for (v, z) in [(0, 0u32), (-1, 1), (1, 2), (-2, 3), (2, 4)] {
            assert_eq!(zigzag32(v), z);
        }
        assert_eq!(zigzag32(i32::MAX), 0xFFFF_FFFE);
        assert_eq!(zigzag32(i32::MIN), 0xFFFF_FFFF);
        assert_eq!(zigzag64(i64::MIN), u64::MAX);
    }

    #[test]
    fn varint_bytes_and_round_trip() {
        let mut b = Vec::new();
        put_varint(&mut b, 0);
        put_varint(&mut b, -1);
        put_varint(&mut b, 63);
        put_varint(&mut b, 64);
        put_varint(&mut b, -65);
        put_varint(&mut b, 150);
        // 0 -> 00; -1 -> 01; 63 -> 7e; 64 -> 128 = 80 01; -65 -> 129 = 81 01;
        // 150 -> 300 = ac 02.
        assert_eq!(b, [0x00, 0x01, 0x7e, 0x80, 0x01, 0x81, 0x01, 0xac, 0x02]);
        let mut r = Reader::new(&b);
        for v in [0, -1, 63, 64, -65, 150] {
            assert_eq!(r.varint().unwrap(), v);
        }
        assert!(r.is_empty());
        for v in [i32::MIN, i32::MAX, 0, 1, -1, 1 << 20] {
            let mut b = Vec::new();
            put_varint(&mut b, v);
            assert_eq!(b.len(), varint_len(v));
            assert_eq!(Reader::new(&b).varint().unwrap(), v);
        }
        for v in [i64::MIN, i64::MAX, 0, -1, 1_790_000_000_000] {
            let mut b = Vec::new();
            put_varlong(&mut b, v);
            assert_eq!(b.len(), varlong_len(v));
            assert_eq!(Reader::new(&b).varlong().unwrap(), v);
        }
    }

    #[test]
    fn hostile_input_is_an_error_not_a_panic() {
        // Overlong varint.
        assert!(Reader::new(&[0xff; 11]).varlong().is_err());
        assert!(Reader::new(&[0xff, 0xff, 0xff, 0xff, 0x7f])
            .varint()
            .is_err());
        // Truncated.
        assert!(Reader::new(&[0x80]).varint().is_err());
        assert!(Reader::new(&[0, 5, b'a']).string().is_err());
        // Negative lengths.
        assert!(Reader::new(&[0xff, 0xfe]).nullable_string().is_err());
        assert!(Reader::new(&[0xff, 0xff, 0xff, 0xfe])
            .nullable_bytes()
            .is_err());
        assert!(Reader::new(&[0x03]).varbytes().is_err()); // -2
                                                           // Huge array count in a tiny frame.
        assert!(Reader::new(&[0x7f, 0xff, 0xff, 0xff]).array_len(1).is_err());
        assert_eq!(Reader::new(&[0xff, 0xff, 0xff, 0xff]).array_len(4), Ok(0));
        // Bad UTF-8 / bad bool.
        assert!(Reader::new(&[0, 1, 0xff]).string().is_err());
        assert!(Reader::new(&[2]).bool().is_err());
        // Null where required.
        assert!(Reader::new(&[0xff, 0xff]).string().is_err());
    }

    #[test]
    fn writer_rejects_oversized() {
        let mut w = Writer::new();
        assert!(w.try_string(&"x".repeat(40_000)).is_err());
        assert!(w.try_string("ok").is_ok());
        assert_eq!(w.buf, [0, 2, b'o', b'k']);
    }
}
