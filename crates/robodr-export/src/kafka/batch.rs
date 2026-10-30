//! RecordBatch v2 (magic 2), uncompressed, non-transactional, no idempotence.
//!
//! ```text
//! baseOffset           int64   0 (the broker assigns offsets)
//! batchLength          int32   bytes after this field
//! partitionLeaderEpoch int32   -1
//! magic                int8    2
//! crc                  uint32  CRC-32C of everything after this field
//! attributes           int16   0 (compression NONE, CreateTime, not transactional, not control)
//! lastOffsetDelta      int32   records - 1
//! baseTimestamp        int64   first record's timestamp
//! maxTimestamp         int64   largest record timestamp
//! producerId           int64   -1 (no idempotence)
//! producerEpoch        int16   -1
//! baseSequence         int32   -1
//! records              int32   count, then each record:
//!   length         varint  bytes of the rest of the record
//!   attributes     int8    0
//!   timestampDelta varlong
//!   offsetDelta    varint
//!   keyLength      varint  (-1 = null) + key
//!   valueLength    varint  (-1 = null) + value
//!   headers        varint  count, then each: keyLength varint + key (UTF-8),
//!                          valueLength varint (-1 = null) + value
//! ```

use super::wire::{derr, put_varint, put_varlong, varint_len, varlong_len, DecodeError, Reader};
use crate::crc32c;

/// Bytes before the first record (fixed batch header incl. record count).
pub const BATCH_OVERHEAD: usize = 61;
/// Offset of the CRC field within a batch.
const CRC_OFFSET: usize = 17;
/// Offset of the attributes field (start of the CRC-covered region).
const ATTR_OFFSET: usize = 21;

/// One record to produce.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProduceRecord {
    pub key: Option<Vec<u8>>,
    pub value: Option<Vec<u8>>,
    /// Header keys are UTF-8 strings; values are bytes.
    pub headers: Vec<(String, Vec<u8>)>,
    /// CreateTime, ms since the epoch.
    pub timestamp_ms: i64,
}

impl ProduceRecord {
    /// An upper bound of this record's encoded size inside a batch
    /// (worst-case varints for the timestamp and offset deltas).
    pub fn size_bound(&self) -> usize {
        let body = self.body_len(i64::MIN, i32::MAX);
        body + 5
    }

    fn body_len(&self, ts_delta: i64, offset_delta: i32) -> usize {
        let opt = |b: &Option<Vec<u8>>| match b {
            None => varint_len(-1),
            Some(b) => varint_len(len_i32(b.len())) + b.len(),
        };
        let mut n = 1 + varlong_len(ts_delta) + varint_len(offset_delta);
        n += opt(&self.key) + opt(&self.value);
        n += varint_len(len_i32(self.headers.len()));
        for (k, v) in &self.headers {
            n += varint_len(len_i32(k.len())) + k.len();
            n += varint_len(len_i32(v.len())) + v.len();
        }
        n
    }
}

fn len_i32(n: usize) -> i32 {
    i32::try_from(n).unwrap_or(i32::MAX)
}

/// Why a batch could not be encoded.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum EncodeError {
    Empty,
    /// A key, value, header or the batch exceeds the protocol's i32 lengths.
    TooLarge,
}

/// Encode `records` as one RecordBatch v2.
pub fn encode_batch(records: &[ProduceRecord]) -> Result<Vec<u8>, EncodeError> {
    let first = records.first().ok_or(EncodeError::Empty)?;
    let n = i32::try_from(records.len()).map_err(|_| EncodeError::TooLarge)?;
    let base_ts = first.timestamp_ms;
    let max_ts = records
        .iter()
        .map(|r| r.timestamp_ms)
        .max()
        .unwrap_or(base_ts);
    let mut b =
        Vec::with_capacity(BATCH_OVERHEAD + records.iter().map(|r| r.size_bound()).sum::<usize>());
    b.extend_from_slice(&0i64.to_be_bytes()); // baseOffset
    b.extend_from_slice(&0i32.to_be_bytes()); // batchLength, patched below
    b.extend_from_slice(&(-1i32).to_be_bytes()); // partitionLeaderEpoch
    b.push(2); // magic
    b.extend_from_slice(&0u32.to_be_bytes()); // crc, patched below
    b.extend_from_slice(&0i16.to_be_bytes()); // attributes
    b.extend_from_slice(&(n - 1).to_be_bytes()); // lastOffsetDelta
    b.extend_from_slice(&base_ts.to_be_bytes());
    b.extend_from_slice(&max_ts.to_be_bytes());
    b.extend_from_slice(&(-1i64).to_be_bytes()); // producerId
    b.extend_from_slice(&(-1i16).to_be_bytes()); // producerEpoch
    b.extend_from_slice(&(-1i32).to_be_bytes()); // baseSequence
    b.extend_from_slice(&n.to_be_bytes());
    debug_assert_eq!(b.len(), BATCH_OVERHEAD);
    for (i, r) in records.iter().enumerate() {
        let ts_delta = r.timestamp_ms.wrapping_sub(base_ts);
        let off = i as i32;
        let body = r.body_len(ts_delta, off);
        put_varint(
            &mut b,
            i32::try_from(body).map_err(|_| EncodeError::TooLarge)?,
        );
        let start = b.len();
        b.push(0); // record attributes
        put_varlong(&mut b, ts_delta);
        put_varint(&mut b, off);
        put_opt(&mut b, r.key.as_deref())?;
        put_opt(&mut b, r.value.as_deref())?;
        put_varint(
            &mut b,
            i32::try_from(r.headers.len()).map_err(|_| EncodeError::TooLarge)?,
        );
        for (k, v) in &r.headers {
            put_opt(&mut b, Some(k.as_bytes()))?;
            put_opt(&mut b, Some(v))?;
        }
        debug_assert_eq!(b.len() - start, body);
    }
    let batch_len = i32::try_from(b.len() - 12).map_err(|_| EncodeError::TooLarge)?;
    // The fixed header written above holds both fields.
    if let Some(field) = b.get_mut(8..12) {
        field.copy_from_slice(&batch_len.to_be_bytes());
    }
    let crc = crc32c::crc32c(b.get(ATTR_OFFSET..).unwrap_or_default());
    if let Some(field) = b.get_mut(CRC_OFFSET..CRC_OFFSET + 4) {
        field.copy_from_slice(&crc.to_be_bytes());
    }
    Ok(b)
}

fn put_opt(b: &mut Vec<u8>, v: Option<&[u8]>) -> Result<(), EncodeError> {
    match v {
        None => put_varint(b, -1),
        Some(v) => {
            put_varint(
                b,
                i32::try_from(v.len()).map_err(|_| EncodeError::TooLarge)?,
            );
            b.extend_from_slice(v);
        }
    }
    Ok(())
}

/// A decoded record (used by tests and the fake broker; also a check that
/// what we send parses back).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DecodedRecord {
    pub offset_delta: i32,
    pub timestamp_ms: i64,
    pub key: Option<Vec<u8>>,
    pub value: Option<Vec<u8>>,
    pub headers: Vec<(String, Option<Vec<u8>>)>,
}

/// A decoded batch header plus records.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DecodedBatch {
    pub base_offset: i64,
    pub attributes: i16,
    pub producer_id: i64,
    pub records: Vec<DecodedRecord>,
}

/// Decode every RecordBatch v2 in `buf` (a Produce request's `records`
/// field may hold several). Verifies magic, lengths and CRC-32C, and
/// rejects compression and control batches.
pub fn decode_batches(buf: &[u8]) -> Result<Vec<DecodedBatch>, DecodeError> {
    let mut out = Vec::new();
    let mut r = Reader::new(buf);
    while !r.is_empty() {
        let base_offset = r.i64()?;
        let len = r.i32()?;
        if len < (BATCH_OVERHEAD - 12) as i32 {
            return derr(format!("batch length {len} too small"));
        }
        let body = r.take(len as usize)?;
        out.push(decode_batch_body(base_offset, body)?);
    }
    Ok(out)
}

fn decode_batch_body(base_offset: i64, body: &[u8]) -> Result<DecodedBatch, DecodeError> {
    let mut r = Reader::new(body);
    let _epoch = r.i32()?;
    let magic = r.i8()?;
    if magic != 2 {
        return derr(format!("magic {magic}, only 2 supported"));
    }
    let crc = r.u32()?;
    let Some(covered) = body.get(r.position()..) else {
        return derr("record batch shorter than its header");
    };
    let actual = crc32c::crc32c(covered);
    if crc != actual {
        return derr(format!(
            "crc mismatch: header {crc:#010x}, computed {actual:#010x}"
        ));
    }
    let attributes = r.i16()?;
    if attributes & 0x07 != 0 {
        return derr("compressed batches are not supported");
    }
    if attributes & 0x20 != 0 {
        return derr("control batches are not supported");
    }
    let last_offset_delta = r.i32()?;
    let base_ts = r.i64()?;
    let _max_ts = r.i64()?;
    let producer_id = r.i64()?;
    let _producer_epoch = r.i16()?;
    let _base_seq = r.i32()?;
    let count = r.array_len(7)?;
    let mut records = Vec::with_capacity(count);
    for _ in 0..count {
        let len = r.varint()?;
        if len < 0 {
            return derr("negative record length");
        }
        let mut rr = Reader::new(r.take(len as usize)?);
        let _attr = rr.i8()?;
        let ts_delta = rr.varlong()?;
        let offset_delta = rr.varint()?;
        let key = rr.varbytes()?.map(<[u8]>::to_vec);
        let value = rr.varbytes()?.map(<[u8]>::to_vec);
        let hn = rr.varint()?;
        if hn < 0 || hn as usize > rr.remaining() {
            return derr(format!("bad header count {hn}"));
        }
        let mut headers = Vec::with_capacity(hn as usize);
        for _ in 0..hn {
            let k = rr
                .varbytes()?
                .ok_or_else(|| DecodeError("null header key".into()))?;
            let k = std::str::from_utf8(k)
                .map_err(|_| DecodeError("header key is not UTF-8".into()))?;
            let v = rr.varbytes()?.map(<[u8]>::to_vec);
            headers.push((k.to_string(), v));
        }
        if !rr.is_empty() {
            return derr("trailing bytes in record");
        }
        records.push(DecodedRecord {
            offset_delta,
            timestamp_ms: base_ts.wrapping_add(ts_delta),
            key,
            value,
            headers,
        });
    }
    if !r.is_empty() {
        return derr("trailing bytes in batch");
    }
    if records.last().map(|x| x.offset_delta) != Some(last_offset_delta) && !records.is_empty() {
        return derr("lastOffsetDelta does not match the records");
    }
    Ok(DecodedBatch {
        base_offset,
        attributes,
        producer_id,
        records,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn rec(key: &str, value: &str, ts: i64, headers: &[(&str, &str)]) -> ProduceRecord {
        ProduceRecord {
            key: Some(key.as_bytes().to_vec()),
            value: Some(value.as_bytes().to_vec()),
            headers: headers
                .iter()
                .map(|(k, v)| (k.to_string(), v.as_bytes().to_vec()))
                .collect(),
            timestamp_ms: ts,
        }
    }

    /// One record, derived by hand from the Kafka protocol documentation
    /// ("Record Batch" / "Record" / "Record Header").
    #[test]
    fn single_record_matches_hand_derived_bytes() {
        let b = encode_batch(&[rec("k", "v", 1000, &[("h", "x")])]).unwrap();
        #[rustfmt::skip]
        let mut expected: Vec<u8> = vec![
            0, 0, 0, 0, 0, 0, 0, 0,          // baseOffset 0
            0, 0, 0, 0x3e,                   // batchLength = 74 - 12 = 62
            0xff, 0xff, 0xff, 0xff,          // partitionLeaderEpoch -1
            2,                               // magic
            0, 0, 0, 0,                      // crc (filled in below)
            0, 0,                            // attributes
            0, 0, 0, 0,                      // lastOffsetDelta 0
            0, 0, 0, 0, 0, 0, 0x03, 0xe8,    // baseTimestamp 1000
            0, 0, 0, 0, 0, 0, 0x03, 0xe8,    // maxTimestamp 1000
            0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, // producerId -1
            0xff, 0xff,                      // producerEpoch -1
            0xff, 0xff, 0xff, 0xff,          // baseSequence -1
            0, 0, 0, 1,                      // 1 record
            // record: body = 1+1+1+(1+1)+(1+1)+1+(1+1)+(1+1) = 12 -> zigzag 24
            0x18,
            0,                               // attributes
            0,                               // timestampDelta 0
            0,                               // offsetDelta 0
            0x02, b'k',                      // key length 1 (zigzag 2), "k"
            0x02, b'v',                      // value length 1, "v"
            0x02,                            // 1 header
            0x02, b'h',                      // header key "h"
            0x02, b'x',                      // header value "x"
        ];
        assert_eq!(expected.len(), 74);
        let crc = crate::crc32c::crc32c(&expected[21..]);
        expected[17..21].copy_from_slice(&crc.to_be_bytes());
        assert_eq!(b, expected);
        // Independent check of the CRC field against the RFC 3720-tested
        // implementation is above; here make sure it is not trivially 0.
        assert_ne!(crc, 0);
    }

    #[test]
    fn null_key_value_and_deltas() {
        let recs = vec![
            ProduceRecord {
                key: None,
                value: None,
                headers: vec![],
                timestamp_ms: 5000,
            },
            rec("a", "bb", 4990, &[]),
            rec("c", "", 6000, &[("e", "")]),
        ];
        let b = encode_batch(&recs).unwrap();
        // Second record: timestampDelta -10 -> zigzag 19 (0x13), offsetDelta 1 -> 0x02.
        // First record is: len(0x0c=6 body) attr 0, ts 0, off 0, key -1 (0x01), value -1 (0x01), headers 0.
        assert_eq!(&b[61..68], &[0x0c, 0, 0, 0, 0x01, 0x01, 0x00]);
        assert_eq!(&b[68..73], &[0x12, 0, 0x13, 0x02, 0x02]);
        // maxTimestamp is the largest, not the last.
        assert_eq!(&b[35..43], &6000i64.to_be_bytes());
        // lastOffsetDelta = 2.
        assert_eq!(&b[23..27], &2i32.to_be_bytes());
        let d = decode_batches(&b).unwrap();
        assert_eq!(d.len(), 1);
        let d = &d[0];
        assert_eq!(d.producer_id, -1);
        assert_eq!(d.records.len(), 3);
        assert_eq!(d.records[0].key, None);
        assert_eq!(d.records[0].value, None);
        assert_eq!(d.records[1].timestamp_ms, 4990);
        assert_eq!(d.records[2].headers, vec![("e".into(), Some(vec![]))]);
        for r in &recs {
            assert!(r.size_bound() > r.body_len(0, 0));
        }
    }

    #[test]
    fn round_trip_and_size_bound() {
        let recs: Vec<_> = (0..50)
            .map(|i| {
                rec(
                    &format!("rf1-{i:032x}"),
                    &"{\"x\":1}".repeat(i + 1),
                    1_790_000_000_000 + i as i64,
                    &[
                        ("content-type", "application/json"),
                        ("robot-id", "ugv-007"),
                    ],
                )
            })
            .collect();
        let b = encode_batch(&recs).unwrap();
        let bound: usize = BATCH_OVERHEAD + recs.iter().map(|r| r.size_bound()).sum::<usize>();
        assert!(b.len() <= bound);
        let d = decode_batches(&b).unwrap();
        for (i, (r, x)) in recs.iter().zip(&d[0].records).enumerate() {
            assert_eq!(x.offset_delta, i as i32);
            assert_eq!(x.key, r.key);
            assert_eq!(x.value, r.value);
            assert_eq!(x.timestamp_ms, r.timestamp_ms);
            let h: Vec<_> = r
                .headers
                .iter()
                .map(|(k, v)| (k.clone(), Some(v.clone())))
                .collect();
            assert_eq!(x.headers, h);
        }
        // Two batches back to back decode as two.
        let mut two = b.clone();
        two.extend_from_slice(&b);
        assert_eq!(decode_batches(&two).unwrap().len(), 2);
    }

    #[test]
    fn corruption_is_detected() {
        let b = encode_batch(&[rec("k", "value", 1, &[])]).unwrap();
        assert_eq!(encode_batch(&[]), Err(EncodeError::Empty));
        // Any single flipped bit in the CRC-covered region fails the CRC.
        for i in 21..b.len() {
            let mut c = b.clone();
            c[i] ^= 0x01;
            assert!(decode_batches(&c).is_err(), "flip at {i}");
        }
        let mut c = b.clone();
        c[16] = 1; // magic
        assert!(decode_batches(&c).is_err());
        // Truncations never panic.
        for n in 0..b.len() {
            let _ = decode_batches(&b[..n]);
        }
        // Compressed attribute (with a fixed-up CRC) is refused.
        let mut c = b.clone();
        c[22] = 1;
        let crc = crate::crc32c::crc32c(&c[21..]);
        c[17..21].copy_from_slice(&crc.to_be_bytes());
        assert!(decode_batches(&c).is_err());
    }
}
