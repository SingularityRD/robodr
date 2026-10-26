//! Harness: the Kafka wire decoders of `robodr-export` (`kafka::proto`,
//! `kafka::batch`, `kafka::wire`): what the producer parses from a broker
//! (ApiVersions v0, Metadata v1-8 and Produce v3-8 responses) and what the
//! in-process test broker parses from a client (request header, Metadata and
//! Produce requests, RecordBatch v2).
//!
//! Input: `selector body`. `selector % 8` picks the decoder, `selector / 8`
//! the API version (Metadata `1 + s % 8`, Produce `3 + s % 6`):
//!
//! 0. ApiVersions response; 1. Metadata response; 2. Produce response;
//! 3. RecordBatch v2 with the CRC-32C fixed up (so mutations get past the
//!    checksum); 4. RecordBatch v2 as is; 5. request header + Metadata
//!    request; 6. request header + Produce request (+ its record batches);
//! 7. the primitive reader (strings, bytes, varints) on its own.
//!
//! Invariants beyond "no panic" (and no huge allocation: every array length
//! is checked against the bytes left before anything is reserved):
//!
//! * responses: decode -> encode (the test broker's encoders) -> decode is
//!   the identity; version negotiation only ever picks a version inside
//!   both ranges; error-code classification is total;
//! * record batches: a decoded batch has at most one record per 7 bytes,
//!   and the CRC-fixed variant fails only on structure, never on the CRC.
//!
//! This target has no std-only smoke test: `crates/robodr-export` is
//! changed by other work (S10 constraint); it runs under libFuzzer only.
#![allow(dead_code)]

use robodr_export::crc32c::crc32c;
use robodr_export::kafka::batch::decode_batches;
use robodr_export::kafka::errors::{classify, name};
use robodr_export::kafka::proto::{
    decode_api_versions, decode_metadata, decode_metadata_request, decode_produce_request,
    decode_produce_response, encode_api_versions_response, encode_metadata_response,
    encode_produce_response, negotiate, parse_request_header, METADATA_VERSIONS, PRODUCE_VERSIONS,
};
use robodr_export::kafka::wire::Reader;

pub fn run(data: &[u8]) {
    let Some((&sel, body)) = data.split_first() else {
        return;
    };
    let s = sel / 8;
    match sel % 8 {
        0 => api_versions(body),
        1 => metadata(1 + i16::from(s % 8), body),
        2 => produce(3 + i16::from(s % 6), body),
        3 => batches(&fix_crcs(body), true),
        4 => batches(body, false),
        5 => {
            if let Ok((_h, mut r)) = parse_request_header(body) {
                let _ = decode_metadata_request(&mut r);
            }
        }
        6 => {
            if let Ok((_h, mut r)) = parse_request_header(body) {
                if let Ok(req) = decode_produce_request(&mut r) {
                    for (_, parts) in &req.topics {
                        for (_, b) in parts {
                            batches(b, false);
                        }
                    }
                }
            }
        }
        _ => primitives(body),
    }
}

fn api_versions(body: &[u8]) {
    let Ok(r) = decode_api_versions(body) else {
        return;
    };
    let _ = classify(r.error_code);
    let _ = name(r.error_code);
    let again = decode_api_versions(&encode_api_versions_response(&r)).expect("re-decodes");
    assert_eq!(again, r);
    for (key, ours) in [(0i16, PRODUCE_VERSIONS), (3, METADATA_VERSIONS)] {
        if let Some(v) = negotiate(&r.apis, key, ours) {
            assert!((ours.0..=ours.1).contains(&v), "v{v} outside ours {ours:?}");
            let a = r
                .apis
                .iter()
                .find(|a| a.api_key == key)
                .expect("negotiated");
            assert!(a.min <= v && v <= a.max, "v{v} outside the broker's {a:?}");
        }
    }
}

fn metadata(version: i16, body: &[u8]) {
    let Ok(m) = decode_metadata(version, body) else {
        return;
    };
    for t in &m.topics {
        let _ = classify(t.error_code);
        for p in &t.partitions {
            let _ = classify(p.error_code);
            let _ = name(p.error_code);
        }
    }
    let again = decode_metadata(version, &encode_metadata_response(version, &m))
        .expect("re-encoded metadata decodes");
    assert_eq!(again, m, "metadata v{version}");
}

fn produce(version: i16, body: &[u8]) {
    let Ok(p) = decode_produce_response(version, body) else {
        return;
    };
    for (_, parts) in &p.topics {
        for part in parts {
            let _ = classify(part.error_code);
            if version < 8 {
                assert!(part.record_errors.is_empty() && part.error_message.is_none());
            }
        }
    }
    let again = decode_produce_response(version, &encode_produce_response(version, &p))
        .expect("re-encoded produce response decodes");
    assert_eq!(again, p, "produce v{version}");
}

/// Recompute the CRC-32C of every batch the framing can find (offset 8:
/// length, 17: CRC over everything from 21 on), so mutations reach the
/// record parser.
fn fix_crcs(body: &[u8]) -> Vec<u8> {
    let mut v = body.to_vec();
    let mut pos = 0usize;
    while pos + 21 <= v.len() {
        let len = i32::from_be_bytes([v[pos + 8], v[pos + 9], v[pos + 10], v[pos + 11]]);
        let Ok(len) = usize::try_from(len) else { break };
        let end = pos + 12 + len;
        if len < 9 || end > v.len() {
            break;
        }
        let crc = crc32c(&v[pos + 21..end]);
        v[pos + 17..pos + 21].copy_from_slice(&crc.to_be_bytes());
        pos = end;
    }
    v
}

fn batches(body: &[u8], crc_fixed: bool) {
    match decode_batches(body) {
        Ok(bs) => {
            for b in &bs {
                assert!(b.records.len() <= body.len() / 7 + 1);
                for r in &b.records {
                    let _ = (&r.key, &r.value, &r.headers);
                }
            }
        }
        Err(e) => {
            if crc_fixed {
                assert!(!e.0.contains("crc mismatch"), "{e:?} after the CRC fix-up");
            }
        }
    }
}

fn primitives(body: &[u8]) {
    let mut r = Reader::new(body);
    // Walk the input with every primitive in turn until it runs out; each
    // call either advances or fails without moving past the end.
    for i in 0usize.. {
        let before = r.position();
        let ok = match i % 8 {
            0 => r.string().is_ok(),
            1 => r.nullable_string().is_ok(),
            2 => r.nullable_bytes().is_ok(),
            3 => r.varint().is_ok(),
            4 => r.varlong().is_ok(),
            5 => r.varbytes().is_ok(),
            6 => r.array_len(1).is_ok(),
            _ => r.bool().is_ok(),
        };
        assert!(r.position() <= body.len());
        assert_eq!(r.position() + r.remaining(), body.len());
        if !ok || r.position() == before || i > 4096 {
            break;
        }
    }
}
