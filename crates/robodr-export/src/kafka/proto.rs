//! The three Kafka APIs this producer needs, in their classic
//! (non-flexible) encodings:
//!
//! | API | key | versions | notes |
//! | --- | --- | --- | --- |
//! | ApiVersions | 18 | 0 | always answered with a v0 header; discovers the others |
//! | Metadata | 3 | 1–8 | v9+ are flexible (compact encodings), not implemented |
//! | Produce | 0 | 3–8 | v3 is the first with RecordBatch v2; v9+ are flexible |
//!
//! Request header v1: `api_key int16, api_version int16, correlation_id
//! int32, client_id NULLABLE_STRING`. Response header v0: `correlation_id
//! int32`. Every message is framed by an `int32` size.

use super::wire::{derr, DecodeError, Reader, Writer};

pub const API_PRODUCE: i16 = 0;
pub const API_METADATA: i16 = 3;
pub const API_VERSIONS: i16 = 18;

/// Versions this client implements, per API.
pub const PRODUCE_VERSIONS: (i16, i16) = (3, 8);
pub const METADATA_VERSIONS: (i16, i16) = (1, 8);

/// Build a size-prefixed request frame.
pub fn frame_request(
    api_key: i16,
    api_version: i16,
    correlation_id: i32,
    client_id: &str,
    body: &[u8],
) -> Result<Vec<u8>, DecodeError> {
    let mut w = Writer::new();
    w.i32(0)
        .i16(api_key)
        .i16(api_version)
        .i32(correlation_id)
        .try_nullable_string(Some(client_id))?;
    w.buf.extend_from_slice(body);
    let n = i32::try_from(w.buf.len() - 4).or_else(|_| derr("request too large"))?;
    w.buf[..4].copy_from_slice(&n.to_be_bytes());
    Ok(w.buf)
}

/// Parsed request header (used by the test broker).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RequestHeader {
    pub api_key: i16,
    pub api_version: i16,
    pub correlation_id: i32,
    pub client_id: Option<String>,
}

/// Parse a request header v1 from a frame body (without the size).
pub fn parse_request_header<'a>(
    frame: &'a [u8],
) -> Result<(RequestHeader, Reader<'a>), DecodeError> {
    let mut r = Reader::new(frame);
    let h = RequestHeader {
        api_key: r.i16()?,
        api_version: r.i16()?,
        correlation_id: r.i32()?,
        client_id: r.nullable_string()?.map(str::to_string),
    };
    Ok((h, r))
}

// ---------------------------------------------------------------- ApiVersions

/// One `(api_key, min, max)` entry.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ApiRange {
    pub api_key: i16,
    pub min: i16,
    pub max: i16,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ApiVersionsResponse {
    pub error_code: i16,
    pub apis: Vec<ApiRange>,
}

pub fn encode_api_versions_response(resp: &ApiVersionsResponse) -> Vec<u8> {
    let mut w = Writer::new();
    w.i16(resp.error_code);
    w.i32(resp.apis.len() as i32);
    for a in &resp.apis {
        w.i16(a.api_key).i16(a.min).i16(a.max);
    }
    w.buf
}

/// Decode an ApiVersions v0 response body. (A broker answers an
/// unsupported ApiVersions version with a v0 body too.)
pub fn decode_api_versions(body: &[u8]) -> Result<ApiVersionsResponse, DecodeError> {
    let mut r = Reader::new(body);
    let error_code = r.i16()?;
    let n = r.array_len(6)?;
    let mut apis = Vec::with_capacity(n);
    for _ in 0..n {
        apis.push(ApiRange {
            api_key: r.i16()?,
            min: r.i16()?,
            max: r.i16()?,
        });
    }
    // v1+ appends throttle_time_ms; tolerate (and ignore) trailing bytes.
    Ok(ApiVersionsResponse { error_code, apis })
}

/// Highest version in both `ours` and the broker's range of `api_key`.
pub fn negotiate(apis: &[ApiRange], api_key: i16, ours: (i16, i16)) -> Option<i16> {
    let a = apis.iter().find(|a| a.api_key == api_key)?;
    let hi = a.max.min(ours.1);
    let lo = a.min.max(ours.0);
    (lo <= hi).then_some(hi)
}

// ------------------------------------------------------------------- Metadata

pub fn encode_metadata_request(version: i16, topics: &[&str]) -> Result<Vec<u8>, DecodeError> {
    if !(METADATA_VERSIONS.0..=METADATA_VERSIONS.1).contains(&version) {
        return derr(format!("metadata v{version} not implemented"));
    }
    let mut w = Writer::new();
    w.try_array_len(topics.len())?;
    for t in topics {
        w.try_string(t)?;
    }
    if version >= 4 {
        // Never auto-create the findings topic: a typo must fail loudly.
        w.bool(false);
    }
    if version >= 8 {
        w.bool(false).bool(false);
    }
    Ok(w.buf)
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Broker {
    pub node_id: i32,
    pub host: String,
    pub port: i32,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PartitionMeta {
    pub error_code: i16,
    pub partition: i32,
    pub leader: i32,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TopicMeta {
    pub error_code: i16,
    pub name: String,
    pub partitions: Vec<PartitionMeta>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MetadataResponse {
    pub brokers: Vec<Broker>,
    pub topics: Vec<TopicMeta>,
}

fn skip_i32_array(r: &mut Reader<'_>) -> Result<(), DecodeError> {
    let n = r.array_len(4)?;
    r.take(n * 4)?;
    Ok(())
}

pub fn decode_metadata(version: i16, body: &[u8]) -> Result<MetadataResponse, DecodeError> {
    let mut r = Reader::new(body);
    if version >= 3 {
        let _throttle = r.i32()?;
    }
    let nb = r.array_len(10)?;
    let mut brokers = Vec::with_capacity(nb);
    for _ in 0..nb {
        let node_id = r.i32()?;
        let host = r.string()?.to_string();
        let port = r.i32()?;
        let _rack = r.nullable_string()?;
        brokers.push(Broker {
            node_id,
            host,
            port,
        });
    }
    if version >= 2 {
        let _cluster = r.nullable_string()?;
    }
    let _controller = r.i32()?;
    let nt = r.array_len(9)?;
    let mut topics = Vec::with_capacity(nt);
    for _ in 0..nt {
        let error_code = r.i16()?;
        let name = r.string()?.to_string();
        let _internal = r.bool()?;
        let np = r.array_len(18)?;
        let mut partitions = Vec::with_capacity(np);
        for _ in 0..np {
            let error_code = r.i16()?;
            let partition = r.i32()?;
            let leader = r.i32()?;
            if version >= 7 {
                let _epoch = r.i32()?;
            }
            skip_i32_array(&mut r)?; // replicas
            skip_i32_array(&mut r)?; // isr
            if version >= 5 {
                skip_i32_array(&mut r)?; // offline replicas
            }
            partitions.push(PartitionMeta {
                error_code,
                partition,
                leader,
            });
        }
        if version >= 8 {
            let _ops = r.i32()?;
        }
        topics.push(TopicMeta {
            error_code,
            name,
            partitions,
        });
    }
    if version >= 8 {
        let _cluster_ops = r.i32()?;
    }
    if !r.is_empty() {
        return derr("trailing bytes in metadata response");
    }
    Ok(MetadataResponse { brokers, topics })
}

/// Encode a Metadata response (test broker). Replicas/ISR = `[leader]`.
pub fn encode_metadata_response(version: i16, m: &MetadataResponse) -> Vec<u8> {
    let mut w = Writer::new();
    if version >= 3 {
        w.i32(0);
    }
    w.i32(m.brokers.len() as i32);
    for b in &m.brokers {
        w.i32(b.node_id);
        let _ = w.try_string(&b.host);
        w.i32(b.port);
        w.i16(-1); // rack
    }
    if version >= 2 {
        w.i16(-1);
    }
    w.i32(m.brokers.first().map_or(-1, |b| b.node_id));
    w.i32(m.topics.len() as i32);
    for t in &m.topics {
        w.i16(t.error_code);
        let _ = w.try_string(&t.name);
        w.bool(false);
        w.i32(t.partitions.len() as i32);
        for p in &t.partitions {
            w.i16(p.error_code).i32(p.partition).i32(p.leader);
            if version >= 7 {
                w.i32(0);
            }
            w.i32(1).i32(p.leader);
            w.i32(1).i32(p.leader);
            if version >= 5 {
                w.i32(0);
            }
        }
        if version >= 8 {
            w.i32(i32::MIN);
        }
    }
    if version >= 8 {
        w.i32(i32::MIN);
    }
    w.buf
}

/// Decode a Metadata request's topic list (test broker).
pub fn decode_metadata_request(r: &mut Reader<'_>) -> Result<Vec<String>, DecodeError> {
    let n = r.i32()?;
    if n < 0 {
        return Ok(Vec::new());
    }
    let mut v = Vec::new();
    for _ in 0..n {
        v.push(r.string()?.to_string());
    }
    Ok(v)
}

// -------------------------------------------------------------------- Produce

/// Produce request body: one topic, `(partition, record batch bytes)`.
pub fn encode_produce_request(
    version: i16,
    acks: i16,
    timeout_ms: i32,
    topic: &str,
    partitions: &[(i32, Vec<u8>)],
) -> Result<Vec<u8>, DecodeError> {
    if !(PRODUCE_VERSIONS.0..=PRODUCE_VERSIONS.1).contains(&version) {
        return derr(format!("produce v{version} not implemented"));
    }
    let mut w = Writer::new();
    w.try_nullable_string(None)?; // transactional_id
    w.i16(acks).i32(timeout_ms);
    w.try_array_len(1)?;
    w.try_string(topic)?;
    w.try_array_len(partitions.len())?;
    for (p, batch) in partitions {
        w.i32(*p);
        w.try_nullable_bytes(Some(batch))?;
    }
    Ok(w.buf)
}

/// `(topic, [(partition, record batch bytes)])` of a Produce request.
pub type TopicData = (String, Vec<(i32, Vec<u8>)>);

/// A decoded Produce request (test broker).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProduceRequest {
    pub acks: i16,
    pub timeout_ms: i32,
    pub topics: Vec<TopicData>,
}

pub fn decode_produce_request(r: &mut Reader<'_>) -> Result<ProduceRequest, DecodeError> {
    let _txn = r.nullable_string()?;
    let acks = r.i16()?;
    let timeout_ms = r.i32()?;
    let nt = r.array_len(6)?;
    let mut topics = Vec::with_capacity(nt);
    for _ in 0..nt {
        let name = r.string()?.to_string();
        let np = r.array_len(8)?;
        let mut parts = Vec::with_capacity(np);
        for _ in 0..np {
            let p = r.i32()?;
            let b = r.nullable_bytes()?.unwrap_or_default().to_vec();
            parts.push((p, b));
        }
        topics.push((name, parts));
    }
    Ok(ProduceRequest {
        acks,
        timeout_ms,
        topics,
    })
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PartitionProduceResponse {
    pub partition: i32,
    pub error_code: i16,
    pub base_offset: i64,
    /// v8: per-record errors `(batch_index, message)`.
    pub record_errors: Vec<(i32, Option<String>)>,
    pub error_message: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProduceResponse {
    pub topics: Vec<(String, Vec<PartitionProduceResponse>)>,
}

pub fn decode_produce_response(version: i16, body: &[u8]) -> Result<ProduceResponse, DecodeError> {
    let mut r = Reader::new(body);
    let nt = r.array_len(6)?;
    let mut topics = Vec::with_capacity(nt);
    for _ in 0..nt {
        let name = r.string()?.to_string();
        let np = r.array_len(22)?;
        let mut parts = Vec::with_capacity(np);
        for _ in 0..np {
            let partition = r.i32()?;
            let error_code = r.i16()?;
            let base_offset = r.i64()?;
            let _log_append_time = r.i64()?;
            if version >= 5 {
                let _log_start = r.i64()?;
            }
            let mut record_errors = Vec::new();
            let mut error_message = None;
            if version >= 8 {
                let ne = r.array_len(6)?;
                for _ in 0..ne {
                    let idx = r.i32()?;
                    let msg = r.nullable_string()?.map(str::to_string);
                    record_errors.push((idx, msg));
                }
                error_message = r.nullable_string()?.map(str::to_string);
            }
            parts.push(PartitionProduceResponse {
                partition,
                error_code,
                base_offset,
                record_errors,
                error_message,
            });
        }
        topics.push((name, parts));
    }
    let _throttle = r.i32()?;
    if !r.is_empty() {
        return derr("trailing bytes in produce response");
    }
    Ok(ProduceResponse { topics })
}

/// Encode a Produce response (test broker).
pub fn encode_produce_response(version: i16, resp: &ProduceResponse) -> Vec<u8> {
    let mut w = Writer::new();
    w.i32(resp.topics.len() as i32);
    for (name, parts) in &resp.topics {
        let _ = w.try_string(name);
        w.i32(parts.len() as i32);
        for p in parts {
            w.i32(p.partition)
                .i16(p.error_code)
                .i64(p.base_offset)
                .i64(-1);
            if version >= 5 {
                w.i64(0);
            }
            if version >= 8 {
                w.i32(p.record_errors.len() as i32);
                for (i, m) in &p.record_errors {
                    w.i32(*i);
                    let _ = w.try_nullable_string(m.as_deref());
                }
                let _ = w.try_nullable_string(p.error_message.as_deref());
            }
        }
    }
    w.i32(0);
    w.buf
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn request_frame_layout() {
        let f = frame_request(API_VERSIONS, 0, 7, "rd", &[]).unwrap();
        assert_eq!(f, [0, 0, 0, 12, 0, 18, 0, 0, 0, 0, 0, 7, 0, 2, b'r', b'd']);
        let (h, r) = parse_request_header(&f[4..]).unwrap();
        assert_eq!(h.api_key, 18);
        assert_eq!(h.correlation_id, 7);
        assert_eq!(h.client_id.as_deref(), Some("rd"));
        assert!(r.is_empty());
    }

    #[test]
    fn version_negotiation() {
        let apis = [
            ApiRange {
                api_key: 0,
                min: 3,
                max: 11,
            },
            ApiRange {
                api_key: 3,
                min: 0,
                max: 12,
            },
        ];
        assert_eq!(negotiate(&apis, 0, PRODUCE_VERSIONS), Some(8));
        assert_eq!(negotiate(&apis, 3, METADATA_VERSIONS), Some(8));
        assert_eq!(negotiate(&apis, 18, (0, 0)), None);
        let old = [ApiRange {
            api_key: 0,
            min: 0,
            max: 2,
        }];
        assert_eq!(negotiate(&old, 0, PRODUCE_VERSIONS), None);
        let new_only = [ApiRange {
            api_key: 0,
            min: 9,
            max: 12,
        }];
        assert_eq!(negotiate(&new_only, 0, PRODUCE_VERSIONS), None);
    }

    #[test]
    fn metadata_round_trip_all_versions() {
        let m = MetadataResponse {
            brokers: vec![Broker {
                node_id: 1,
                host: "127.0.0.1".into(),
                port: 9092,
            }],
            topics: vec![TopicMeta {
                error_code: 0,
                name: "robodr.findings".into(),
                partitions: vec![
                    PartitionMeta {
                        error_code: 0,
                        partition: 0,
                        leader: 1,
                    },
                    PartitionMeta {
                        error_code: 5,
                        partition: 1,
                        leader: -1,
                    },
                ],
            }],
        };
        for v in 1..=8 {
            let b = encode_metadata_response(v, &m);
            assert_eq!(decode_metadata(v, &b).unwrap(), m, "v{v}");
            // Truncation is an error, never a panic.
            for n in 0..b.len() {
                assert!(decode_metadata(v, &b[..n]).is_err());
            }
            let req = encode_metadata_request(v, &["t"]).unwrap();
            let mut r = Reader::new(&req);
            assert_eq!(
                decode_metadata_request(&mut r).unwrap(),
                vec!["t".to_string()]
            );
        }
        assert!(encode_metadata_request(9, &["t"]).is_err());
    }

    #[test]
    fn produce_round_trip_all_versions() {
        let resp = ProduceResponse {
            topics: vec![(
                "t".into(),
                vec![PartitionProduceResponse {
                    partition: 2,
                    error_code: 6,
                    base_offset: 42,
                    record_errors: vec![],
                    error_message: None,
                }],
            )],
        };
        for v in 3..=8 {
            let b = encode_produce_response(v, &resp);
            assert_eq!(decode_produce_response(v, &b).unwrap(), resp, "v{v}");
            for n in 0..b.len() {
                assert!(decode_produce_response(v, &b[..n]).is_err());
            }
            let req = encode_produce_request(v, -1, 30_000, "t", &[(2, vec![1, 2, 3])]).unwrap();
            let d = decode_produce_request(&mut Reader::new(&req)).unwrap();
            assert_eq!(d.acks, -1);
            assert_eq!(d.topics, vec![("t".into(), vec![(2, vec![1, 2, 3])])]);
        }
        assert!(encode_produce_request(2, -1, 1, "t", &[]).is_err());
    }

    #[test]
    fn api_versions_decode() {
        let r = ApiVersionsResponse {
            error_code: 0,
            apis: vec![ApiRange {
                api_key: 0,
                min: 3,
                max: 9,
            }],
        };
        let b = encode_api_versions_response(&r);
        assert_eq!(decode_api_versions(&b).unwrap(), r);
        // A count larger than the frame is refused.
        assert!(decode_api_versions(&[0, 0, 0x7f, 0, 0, 0]).is_err());
    }
}
