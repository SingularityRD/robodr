//! Harness: the control-plane request path of `robodr-agentd`
//! (`robodr-control-plane/v2`), everything a network peer reaches before
//! the main loop.
//!
//! Input: byte 0 picks how many bytes each `read` returns (`1 + b % 64`,
//! or everything at once for `b >= 192`); the rest is what the peer sends.
//! The harness then
//!
//! 1. reads it with `control::http::read_request` (bounded parser) and, on
//!    success, checks the bounds (method, target alphabet and length,
//!    header count / names / values, body length) and that re-encoding the
//!    parsed request and reading it again gives the same request;
//! 2. parses the credentials (`auth::credentials`: strict headers), checks
//!    their shapes, and verifies the signature against a fixed SOC key: a
//!    request that verifies for this robot never verifies for another;
//! 3. routes the target (`control::route`): every id it yields is a valid
//!    request / export id;
//! 4. parses the body (and, separately, the whole input) as an action
//!    request (`api::parse_submit`: TTL and text rules hold on success), a
//!    revert (`api::parse_revert`) and an evidence export
//!    (`evidence::parse_export`: one selector, bounds hold), and the input
//!    as an evidence link (`evidence::parse_link`).
//!
//! Hostile bytes must yield an HTTP error code, never a panic, a hang or an
//! allocation beyond the parser's bounds.
#![allow(dead_code)]

use std::io::{self, Cursor, Read, Write};
use std::time::{Duration, Instant};

use robodr_agentd::control::{api, auth, evidence, http, route, Route};

/// The robot the harness routes and verifies for.
pub const ROBOT: &str = "ugv-007";
/// The fixed SOC key of the signed seeds.
pub const SOC_ID: &str = "soc:soc-a:1";
pub const SOC_SEED: [u8; 32] = [0x51; 32];

pub fn soc_key() -> robodr_blackbox::Ed25519SigningKey {
    robodr_blackbox::Ed25519SigningKey::from_seed(SOC_ID, &SOC_SEED).expect("valid seed")
}

/// A peer that sends `input` in steps of `step` bytes, then closes.
pub struct Peer {
    input: Cursor<Vec<u8>>,
    step: usize,
}

impl Read for Peer {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        let n = buf.len().min(self.step);
        self.input.read(&mut buf[..n])
    }
}

impl Write for Peer {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        Ok(buf.len())
    }
    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

impl http::Stream for Peer {
    fn set_read_deadline(&self, _: Duration) -> io::Result<()> {
        Ok(())
    }
}

/// Read one request from `raw` delivered in steps of `step` bytes.
pub fn read(raw: &[u8], step: usize) -> Result<http::Request, http::HttpError> {
    let mut p = Peer {
        input: Cursor::new(raw.to_vec()),
        step: step.max(1),
    };
    http::read_request(&mut p, Instant::now() + Duration::from_secs(5))
}

/// The bytes of `r` as a client would send them.
pub fn encode(r: &http::Request) -> Vec<u8> {
    let mut out = format!("{} {} HTTP/1.1\r\n", r.method, r.target).into_bytes();
    for (n, v) in &r.headers {
        out.extend_from_slice(format!("{n}: {v}\r\n").as_bytes());
    }
    out.extend_from_slice(b"\r\n");
    out.extend_from_slice(&r.body);
    out
}

const STATUSES: [u16; 6] = [400, 408, 413, 431, 505, 501];

fn check_request(r: &http::Request) {
    assert!(
        !r.method.is_empty()
            && r.method.len() <= 16
            && r.method.bytes().all(|b| b.is_ascii_uppercase()),
        "method {:?}",
        r.method
    );
    assert!(r.target.starts_with('/'), "target {:?}", r.target);
    assert!(r.target.len() <= http::MAX_TARGET_BYTES);
    assert!(r.target.bytes().all(http::target_char_ok), "{:?}", r.target);
    assert!(r.headers.len() <= http::MAX_HEADERS);
    for (n, v) in &r.headers {
        assert!(
            !n.is_empty()
                && n.len() <= http::MAX_HEADER_NAME_BYTES
                && n.bytes().all(|b| b.is_ascii_lowercase()
                    || b.is_ascii_digit()
                    || b == b'-'
                    || b == b'_'),
            "header name {n:?}"
        );
        assert!(
            v.bytes().all(|b| (0x20..0x7f).contains(&b) || b == b'\t'),
            "header value {v:?}"
        );
        assert!(!v.starts_with([' ', '\t']) && !v.ends_with([' ', '\t']));
        assert_ne!(n, "transfer-encoding");
    }
    assert!(r.body.len() <= http::MAX_BODY_BYTES);
    if r.method == "GET" || r.method == "DELETE" {
        assert!(r.body.is_empty());
    }
    let declared = r.header("content-length").map(|v| v.parse::<usize>().ok());
    match declared {
        Some(Some(n)) => assert_eq!(n, r.body.len()),
        Some(None) => panic!("an accepted request with an unparsed Content-Length"),
        None => assert!(r.body.is_empty()),
    }
    // Re-encoding and reading again is the identity.
    let again = read(&encode(r), usize::MAX).expect("a parsed request re-reads");
    assert_eq!(&again, r, "re-read differs");
}

fn check_bodies(body: &[u8]) {
    if let Ok(a) = api::parse_submit(body) {
        assert!(api::request_id_ok(&a.request_id));
        match (a.action.time_limited(), a.ttl_seconds) {
            (true, Some(t)) => assert!((1..=api::MAX_TTL_SECONDS).contains(&t)),
            (false, None) => {}
            other => panic!("ttl rule broken: {other:?}"),
        }
        assert!(a.reason.chars().count() <= api::MAX_REASON_CHARS);
        assert!(!a.requested_by.trim().is_empty());
        assert!(!a.reason.chars().any(char::is_control));
        // The digest is a function of the request.
        assert_eq!(a.digest(), a.clone().digest());
    }
    if let Ok(r) = api::parse_revert(body) {
        assert!(!r.requested_by.trim().is_empty());
        assert!(r.requested_by.chars().count() <= api::MAX_REQUESTED_BY_CHARS);
    }
    if let Ok(e) = evidence::parse_export(body, ROBOT) {
        assert!(api::request_id_ok(&e.export_id));
        match &e.selector {
            evidence::Selector::SeqRange { from_seq, to_seq } => assert!(from_seq <= to_seq),
            evidence::Selector::TimeRange { from_ms, to_ms } => {
                assert!(from_ms <= to_ms && to_ms - from_ms <= evidence::MAX_TIME_SPAN_MS)
            }
            evidence::Selector::Finding {
                evidence: refs,
                context_records,
                finding_id,
            } => {
                assert!(!refs.is_empty() && refs.len() <= evidence::MAX_LINKS);
                assert!(*context_records <= evidence::MAX_CONTEXT_RECORDS);
                assert!(!finding_id.is_empty());
                for r in refs {
                    assert_eq!(r.sha256.len(), 64);
                    // A parsed link round-trips through its URI.
                    assert_eq!(evidence::parse_link(&r.uri(ROBOT), ROBOT).as_ref(), Ok(r));
                }
            }
        }
    }
}

pub fn run(data: &[u8]) {
    let Some((&b0, raw)) = data.split_first() else {
        return;
    };
    let step = if b0 >= 192 {
        usize::MAX
    } else {
        1 + usize::from(b0 % 64)
    };
    match read(raw, step) {
        Err(e) => assert!(STATUSES.contains(&e.status), "status {}", e.status),
        Ok(req) => {
            check_request(&req);
            // Delivery in other steps reads the same request.
            assert_eq!(read(raw, usize::MAX).as_ref(), Ok(&req));
            if let Ok(c) = auth::credentials(&req) {
                assert!(!c.key_id.is_empty() && c.key_id.len() <= 128);
                assert!((auth::MIN_NONCE_LEN..=auth::MAX_NONCE_LEN).contains(&c.nonce.len()));
                assert_eq!(c.signature.len(), 64);
                assert_eq!(c.signature_hex.len(), 128);
                let keys = [auth::SocKey {
                    key_id: SOC_ID.into(),
                    public: soc_key().public_key(),
                }];
                if auth::verify(&req, &c, &keys, ROBOT).is_ok() {
                    assert!(auth::verify(&req, &c, &keys, "ugv-008").is_err());
                }
            }
            match route(&req.method, &req.target, ROBOT) {
                Ok(Route::Get(id) | Route::Revert(id))
                | Ok(Route::EvidenceManifest(id) | Route::EvidenceDelete(id))
                | Ok(Route::EvidenceChunk(id, _)) => assert!(api::request_id_ok(&id)),
                Ok(_) => {}
                Err(e) => assert!([404, 405].contains(&e.status), "{e:?}"),
            }
            check_bodies(&req.body);
        }
    }
    check_bodies(raw);
    if let Ok(t) = std::str::from_utf8(raw) {
        let _ = evidence::parse_link(t, ROBOT);
    }
}
