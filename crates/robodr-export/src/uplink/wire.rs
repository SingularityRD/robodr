//! The `robodr.ingest` HTTP API, contract v1, producer side
//! (`docs/contracts/robodr.ingest-api.md`): header names, limits, the batch
//! signature (§2.2), the NDJSON line (§2.3), the batch id this producer
//! derives, and the `200` response (§6) with its consistency checks.
//!
//! Everything here is pure (no I/O) so that the contract test vectors
//! (`examples/ingest_vectors.rs`) are built with exactly the code the
//! producer runs.

use robodr_blackbox::crypto::{sha256, to_hex};
use robodr_blackbox::sign_ed25519::{
    derive_key_id, verify, Ed25519SigningKey, PUBLIC_KEY_LEN, SIGNATURE_LEN,
};
use robodr_ocsf::FindingSignature;
use serde::{Deserialize, Serialize};

/// Path below the API root (§1).
pub const INGEST_PATH: &str = "/robot-edr/v2/ingest";
/// The only accepted request content type (§2.1, no parameters).
pub const CONTENT_TYPE: &str = "application/x-ndjson";
pub const H_KEY_ID: &str = "X-RoboDR-Key-Id";
pub const H_BATCH_ID: &str = "X-RoboDR-Batch-Id";
pub const H_TIMESTAMP: &str = "X-RoboDR-Timestamp";
pub const H_SIGNATURE: &str = "X-RoboDR-Signature";
/// Domain separator of the batch signature (§2.2), NUL included.
pub const BATCH_SIG_DOMAIN: &[u8] = b"robodr-ingest/batch/v1\0";
/// Largest request body (§2.4).
pub const MAX_BODY_BYTES: usize = 4 * 1024 * 1024;
/// Most lines per batch (§2.4).
pub const MAX_LINES: usize = 1000;
/// Largest decoded `value` the server considers (§2.4; larger: `too_large`).
pub const MAX_VALUE_BYTES: usize = 256 * 1024;
/// Longest batch id (§2.1).
pub const MAX_BATCH_ID: usize = 64;
/// Prefix of the batch ids this producer derives ([`batch_id`]).
pub const BATCH_ID_PREFIX: &str = "rdu1-";
/// Domain separator of [`batch_id`], NUL included.
pub const BATCH_ID_DOMAIN: &[u8] = b"robodr-uplink/batch-id/v1\0";
/// Hex digits of the hash in a batch id (128 bits).
pub const BATCH_ID_HEX: usize = 32;

/// `ed25519:<16 lower-case hex>` (§2.1).
pub fn is_valid_key_id(s: &str) -> bool {
    s.strip_prefix("ed25519:").is_some_and(|h| {
        h.len() == 16
            && h.bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
    })
}

/// 1–64 chars of `[A-Za-z0-9._:-]` (§2.1).
pub fn is_valid_batch_id(s: &str) -> bool {
    !s.is_empty()
        && s.len() <= MAX_BATCH_ID
        && s.bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"._:-".contains(&b))
}

/// The batch signature message (§2.2).
pub fn signing_message(key_id: &str, batch_id: &str, timestamp_ms: u64, body: &[u8]) -> Vec<u8> {
    let mut m = Vec::with_capacity(BATCH_SIG_DOMAIN.len() + 8 + key_id.len() + batch_id.len() + 40);
    m.extend_from_slice(BATCH_SIG_DOMAIN);
    // Both ids are length-checked (<= 64 bytes) by every caller that sends
    // them; the saturating casts only matter for hostile direct callers.
    m.extend_from_slice(
        &u32::try_from(key_id.len())
            .unwrap_or(u32::MAX)
            .to_be_bytes(),
    );
    m.extend_from_slice(key_id.as_bytes());
    m.extend_from_slice(
        &u32::try_from(batch_id.len())
            .unwrap_or(u32::MAX)
            .to_be_bytes(),
    );
    m.extend_from_slice(batch_id.as_bytes());
    m.extend_from_slice(&timestamp_ms.to_be_bytes());
    m.extend_from_slice(&sha256(body));
    m
}

/// Sign a batch: the `X-RoboDR-Signature` value (128 lower-case hex).
pub fn sign_batch(
    key: &Ed25519SigningKey,
    key_id: &str,
    batch_id: &str,
    timestamp_ms: u64,
    body: &[u8],
) -> String {
    to_hex(&key.sign_message(&signing_message(key_id, batch_id, timestamp_ms, body)))
}

/// Verify a batch signature as the server does (strict Ed25519 over the raw
/// body). For tests and the contract vectors.
pub fn verify_batch(
    public: &[u8; PUBLIC_KEY_LEN],
    key_id: &str,
    batch_id: &str,
    timestamp_ms: u64,
    body: &[u8],
    signature_hex: &str,
) -> bool {
    let Some(sig) = robodr_blackbox::crypto::from_hex(signature_hex) else {
        return false;
    };
    if sig.len() != SIGNATURE_LEN || signature_hex.bytes().any(|b| b.is_ascii_uppercase()) {
        return false;
    }
    verify(
        public,
        &signing_message(key_id, batch_id, timestamp_ms, body),
        &sig,
    )
}

/// The key id a sender key must carry: derived from its public key.
pub fn expected_key_id(public: &[u8; PUBLIC_KEY_LEN]) -> String {
    derive_key_id(public)
}

#[derive(Serialize)]
struct Line<'a> {
    value: &'a str,
    sig: Option<&'a FindingSignature>,
}

/// One body line (§2.3), without the terminating LF:
/// `{"value":"<value as a JSON string>","sig":null|{"alg","key_id","sig"}}`.
pub fn encode_line(value: &str, sig: Option<&FindingSignature>) -> String {
    // A struct of a &str and an Option of three Strings cannot fail to
    // serialise.
    serde_json::to_string(&Line { value, sig }).unwrap_or_default()
}

/// The batch id of a body (`rdu1-` + 32 hex): deterministic in the input
/// positions of its lines and in the body bytes.
///
/// ```text
/// batch_id = "rdu1-" || hex(SHA-256(
///              "robodr-uplink/batch-id/v1" 0x00
///              || u32be(len(source)) || source
///              || u32be(n) || u64be(position_1) || ... || u64be(position_n)
///              || SHA-256(body)))[0..32]
/// ```
///
/// `source` names the input stream (`diode:<batch directory>` or `spool`),
/// `position_i` the input position of body line `i` (diode: line number in
/// `records.jsonl`; spool: record seq). The same records re-cut after a
/// crash give the same id (the server then answers with its stored
/// response, §4.3); a different body can never reuse an id, so a stored
/// response always describes exactly the lines that are being acknowledged.
pub fn batch_id(source: &str, positions: &[u64], body: &[u8]) -> String {
    let mut m =
        Vec::with_capacity(BATCH_ID_DOMAIN.len() + 8 + source.len() + 8 * positions.len() + 32);
    m.extend_from_slice(BATCH_ID_DOMAIN);
    m.extend_from_slice(
        &u32::try_from(source.len())
            .unwrap_or(u32::MAX)
            .to_be_bytes(),
    );
    m.extend_from_slice(source.as_bytes());
    m.extend_from_slice(
        &u32::try_from(positions.len())
            .unwrap_or(u32::MAX)
            .to_be_bytes(),
    );
    for p in positions {
        m.extend_from_slice(&p.to_be_bytes());
    }
    m.extend_from_slice(&sha256(body));
    let h = to_hex(&sha256(&m));
    format!("{BATCH_ID_PREFIX}{}", &h[..BATCH_ID_HEX])
}

/// One rejected line of a `200` response (§6).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RejectedLine {
    /// 1-based body line number.
    pub line: u64,
    pub code: String,
    #[serde(default)]
    pub detail: String,
}

/// The `200` response (§6). Unknown fields are ignored (§8: additive).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct IngestResponse {
    pub batch_id: String,
    pub replayed: bool,
    pub accepted: u64,
    pub created: u64,
    pub updated: u64,
    pub duplicates: u64,
    pub rejected: Vec<RejectedLine>,
}

/// Longest rejection code accepted from a server.
pub const MAX_CODE_LEN: usize = 64;

/// A server code is a short `[a-z0-9_]` token.
pub fn is_valid_code(s: &str) -> bool {
    !s.is_empty()
        && s.len() <= MAX_CODE_LEN
        && s.bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'_')
}

impl IngestResponse {
    /// Parse a `200` body and check it against the batch it answers: same
    /// batch id, every rejected line in `1..=lines` and named once, valid
    /// codes, `accepted = created + updated + duplicates` and
    /// `accepted + rejected = lines`. A response failing any check
    /// acknowledges nothing.
    pub fn parse_checked(body: &[u8], batch_id: &str, lines: usize) -> Result<Self, String> {
        let r: IngestResponse =
            serde_json::from_slice(body).map_err(|e| format!("200 response is not valid: {e}"))?;
        if r.batch_id != batch_id {
            return Err(format!(
                "200 response names batch {:?}, sent {batch_id:?}",
                trunc(&r.batch_id)
            ));
        }
        let n = lines as u64;
        let mut seen = std::collections::BTreeSet::new();
        for x in &r.rejected {
            if x.line == 0 || x.line > n {
                return Err(format!(
                    "200 response rejects line {} of a {n}-line batch",
                    x.line
                ));
            }
            if !seen.insert(x.line) {
                return Err(format!("200 response rejects line {} twice", x.line));
            }
            if !is_valid_code(&x.code) {
                return Err(format!(
                    "200 response has an invalid rejection code {:?}",
                    trunc(&x.code)
                ));
            }
        }
        let sum = r
            .created
            .checked_add(r.updated)
            .and_then(|v| v.checked_add(r.duplicates));
        if sum != Some(r.accepted) {
            return Err("200 response: accepted != created + updated + duplicates".into());
        }
        if r.accepted.checked_add(r.rejected.len() as u64) != Some(n) {
            return Err(format!(
                "200 response accounts for {} + {} lines of a {n}-line batch",
                r.accepted,
                r.rejected.len()
            ));
        }
        Ok(r)
    }
}

/// An error response body (`{"code","detail"}`), best effort.
#[derive(Debug, Clone, Default, Deserialize)]
pub struct ErrorBody {
    #[serde(default)]
    pub code: String,
    #[serde(default)]
    pub detail: String,
}

impl ErrorBody {
    /// Parse leniently: anything unparsable yields empty fields.
    pub fn parse(body: &[u8]) -> Self {
        serde_json::from_slice(body).unwrap_or_default()
    }

    /// `code: detail`, both truncated, for messages.
    pub fn describe(&self) -> String {
        match (self.code.is_empty(), self.detail.is_empty()) {
            (true, true) => "no error body".into(),
            (false, true) => trunc(&self.code).to_string(),
            (true, false) => trunc(&self.detail).to_string(),
            (false, false) => format!("{}: {}", trunc(&self.code), trunc(&self.detail)),
        }
    }
}

/// At most 200 bytes of a server-supplied string, cut at a char boundary.
pub fn trunc(s: &str) -> &str {
    let mut end = s.len().min(200);
    while !s.is_char_boundary(end) {
        end -= 1;
    }
    &s[..end]
}

#[cfg(test)]
mod tests {
    use super::*;

    fn key() -> Ed25519SigningKey {
        Ed25519SigningKey::from_seed_with_derived_id(&[7u8; 32])
    }

    #[test]
    fn signing_message_bytes() {
        let body = b"{\"value\":\"x\",\"sig\":null}\n";
        let m = signing_message(
            "ed25519:0011223344556677",
            "b-1",
            0x0102_0304_0506_0708,
            body,
        );
        let mut want = b"robodr-ingest/batch/v1\0".to_vec();
        want.extend_from_slice(&[0, 0, 0, 24]);
        want.extend_from_slice(b"ed25519:0011223344556677");
        want.extend_from_slice(&[0, 0, 0, 3]);
        want.extend_from_slice(b"b-1");
        want.extend_from_slice(&[1, 2, 3, 4, 5, 6, 7, 8]);
        want.extend_from_slice(&sha256(body));
        assert_eq!(m, want);
        assert_eq!(m.len(), 23 + 4 + 24 + 4 + 3 + 8 + 32);
        // Framing: moving a byte between the ids changes the message.
        assert_ne!(
            signing_message("ab", "c", 1, b""),
            signing_message("a", "bc", 1, b"")
        );
    }

    #[test]
    fn sign_and_verify() {
        let k = key();
        let id = expected_key_id(&k.public_key());
        assert!(is_valid_key_id(&id), "{id}");
        let body = b"line\n";
        let s = sign_batch(&k, &id, "b", 1_790_000_000_000, body);
        assert_eq!(s.len(), 128);
        assert!(s
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b)));
        let pk = k.public_key();
        assert!(verify_batch(&pk, &id, "b", 1_790_000_000_000, body, &s));
        assert!(!verify_batch(&pk, &id, "b", 1_790_000_000_001, body, &s));
        assert!(!verify_batch(&pk, &id, "c", 1_790_000_000_000, body, &s));
        assert!(!verify_batch(&pk, &id, "b", 1_790_000_000_000, b"line", &s));
        assert!(!verify_batch(
            &pk,
            &id,
            "b",
            1_790_000_000_000,
            body,
            &s.to_uppercase()
        ));
        assert!(!verify_batch(
            &pk,
            &id,
            "b",
            1_790_000_000_000,
            body,
            &s[..126]
        ));
    }

    #[test]
    fn id_formats() {
        assert!(is_valid_key_id("ed25519:0123456789abcdef"));
        for bad in [
            "ed25519:0123456789ABCDEF",
            "ed25519:0123456789abcde",
            "ed25519:0123456789abcdef0",
            "hmac-sha256:0123456789abcdef",
            "",
        ] {
            assert!(!is_valid_key_id(bad), "{bad}");
        }
        assert!(is_valid_batch_id("rdu1-0123"));
        assert!(is_valid_batch_id(&"a".repeat(64)));
        assert!(is_valid_batch_id("A.b_c:d-9"));
        for bad in ["", "a b", "a/b", "é", &"a".repeat(65)] {
            assert!(!is_valid_batch_id(bad), "{bad}");
        }
    }

    #[test]
    fn batch_id_is_deterministic_and_content_bound() {
        let a = batch_id("spool", &[1, 2, 3], b"x\n");
        assert_eq!(a, batch_id("spool", &[1, 2, 3], b"x\n"));
        assert!(a.starts_with(BATCH_ID_PREFIX));
        assert_eq!(a.len(), BATCH_ID_PREFIX.len() + BATCH_ID_HEX);
        assert!(is_valid_batch_id(&a));
        assert_ne!(a, batch_id("spool", &[1, 2, 3], b"y\n"), "body");
        assert_ne!(a, batch_id("spool", &[1, 2, 4], b"x\n"), "positions");
        assert_ne!(a, batch_id("spool", &[1, 2], b"x\n"), "count");
        assert_ne!(a, batch_id("diode:b", &[1, 2, 3], b"x\n"), "source");
        // Framing: the source/position boundary is unambiguous.
        assert_ne!(batch_id("ab", &[], b""), batch_id("a", &[], b"b"));
        // Pinned value, computed independently (Python hashlib) from the
        // documented layout: a format change is a visible change.
        assert_eq!(
            batch_id("spool", &[1], b"{}\n"),
            "rdu1-73e3181fecd7973208f53697d3de9d2b"
        );
    }

    #[test]
    fn line_encoding() {
        assert_eq!(
            encode_line("{\"a\":\"b\\\\c\"}", None),
            r#"{"value":"{\"a\":\"b\\\\c\"}","sig":null}"#
        );
        let sig = FindingSignature {
            alg: "ed25519".into(),
            key_id: "k".into(),
            sig: "ab".repeat(64),
        };
        let l = encode_line("v\u{e9}\u{1}", Some(&sig));
        assert_eq!(
            l,
            format!(
                "{{\"value\":\"v\u{e9}\\u0001\",\"sig\":{{\"alg\":\"ed25519\",\"key_id\":\"k\",\"sig\":\"{}\"}}}}",
                "ab".repeat(64)
            )
        );
        assert!(!l.contains('\n'));
        // The consumer decodes the value string back to the exact bytes.
        #[derive(Deserialize)]
        struct L {
            value: String,
        }
        let back: L = serde_json::from_str(&l).unwrap();
        assert_eq!(back.value, "v\u{e9}\u{1}");
    }

    #[test]
    fn response_checks() {
        let ok = br#"{"batch_id":"b","replayed":false,"accepted":3,"created":1,"updated":1,"duplicates":1,
            "rejected":[{"line":4,"code":"robot_mismatch","detail":"x"}],"future_field":1}"#;
        let r = IngestResponse::parse_checked(ok, "b", 4).unwrap();
        assert_eq!(r.rejected[0].line, 4);
        assert!(
            IngestResponse::parse_checked(ok, "c", 4).is_err(),
            "batch id"
        );
        assert!(IngestResponse::parse_checked(ok, "b", 5).is_err(), "count");
        assert!(
            IngestResponse::parse_checked(ok, "b", 3).is_err(),
            "line range"
        );
        for bad in [
            &br#"{"batch_id":"b","replayed":false,"accepted":2,"created":1,"updated":1,"duplicates":1,"rejected":[{"line":4,"code":"x"},{"line":3,"code":"y"}]}"#[..],
            br#"{"batch_id":"b","replayed":false,"accepted":2,"created":1,"updated":1,"duplicates":0,"rejected":[{"line":4,"code":"x"},{"line":4,"code":"y"}]}"#,
            br#"{"batch_id":"b","replayed":false,"accepted":3,"created":1,"updated":1,"duplicates":1,"rejected":[{"line":0,"code":"x"}]}"#,
            br#"{"batch_id":"b","replayed":false,"accepted":3,"created":1,"updated":1,"duplicates":1,"rejected":[{"line":4,"code":"Bad Code"}]}"#,
            br#"{"batch_id":"b","replayed":false,"accepted":3,"created":18446744073709551615,"updated":1,"duplicates":1,"rejected":[{"line":4,"code":"x"}]}"#,
            br#"{"batch_id":"b","accepted":4,"created":4,"updated":0,"duplicates":0,"rejected":[]}"#,
            b"not json",
        ] {
            assert!(
                IngestResponse::parse_checked(bad, "b", 4).is_err(),
                "{}",
                String::from_utf8_lossy(bad)
            );
        }
        // Detail is optional (lenient), everything else is required.
        let r = IngestResponse::parse_checked(
            br#"{"batch_id":"b","replayed":true,"accepted":0,"created":0,"updated":0,"duplicates":0,"rejected":[{"line":1,"code":"invalid_line"}]}"#,
            "b",
            1,
        )
        .unwrap();
        assert!(r.replayed);
        assert_eq!(r.rejected[0].detail, "");
    }

    #[test]
    fn error_body() {
        let e = ErrorBody::parse(br#"{"code":"bad_signature","detail":"no"}"#);
        assert_eq!(e.describe(), "bad_signature: no");
        assert_eq!(ErrorBody::parse(b"<html>").describe(), "no error body");
        let long = "é".repeat(300);
        assert!(trunc(&long).len() <= 200);
    }
}
