//! Request authentication: Ed25519 signatures by a configured SOC key over
//! the request, bound to this robot, with a timestamp window and a nonce
//! cache against replay, and a per-key rate limit.
//!
//! # What is signed
//!
//! [`signing_message`]: the lines (joined by `\n`, no trailing newline)
//!
//! ```text
//! robodr-control-plane/v1
//! <METHOD>
//! <request target exactly as sent, e.g. /api/v1/robots/ugv-007/action-requests>
//! <robot id this agentd is configured for>
//! <key id>
//! <timestamp: Unix seconds, decimal>
//! <nonce>
//! <SHA-256 of the body, lower-case hex (of the empty string for a GET)>
//! ```
//!
//! sent as the headers `X-RoboDR-Key-Id`, `X-RoboDR-Timestamp`,
//! `X-RoboDR-Nonce` and `X-RoboDR-Signature` (128 hex characters). The robot
//! id is this daemon's own, so a request signed for robot B never verifies
//! on robot A even if the path were rewritten. The target and the body hash
//! bind the action and its parameters.
//!
//! # Replay
//!
//! The timestamp must be within `max_clock_skew_s` of this host's wall
//! clock (both sides need NTP; a wrong clock refuses requests, it never
//! accepts more), and the (key, nonce) pair must not have been seen while
//! that timestamp is in the window. The cache holds at most [`MAX_NONCES`]
//! entries; when it is full of live entries, requests are refused
//! (`replay_cache_full`) rather than accepted unchecked. Only requests whose
//! signature verified enter the cache, so unauthenticated traffic cannot
//! fill it.

use std::collections::HashMap;
use std::time::Instant;

use robodr_blackbox::crypto::{from_hex, sha256, to_hex};

use super::http::Request;

/// API and signature domain.
pub const API_VERSION: &str = "robodr-control-plane/v1";
pub const H_KEY_ID: &str = "x-robodr-key-id";
pub const H_TIMESTAMP: &str = "x-robodr-timestamp";
pub const H_NONCE: &str = "x-robodr-nonce";
pub const H_SIGNATURE: &str = "x-robodr-signature";
/// The answer signature header (with `finding_signing`).
pub const H_ANSWER_SIGNATURE: &str = "X-RoboDR-Answer-Signature";
/// Most live (key, nonce) pairs remembered.
pub const MAX_NONCES: usize = 8192;
/// Nonce length bounds and alphabet (`[A-Za-z0-9_-]`).
pub const MIN_NONCE_LEN: usize = 16;
pub const MAX_NONCE_LEN: usize = 128;

/// A configured SOC public key.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SocKey {
    pub key_id: String,
    pub public: [u8; 32],
}

/// The credentials a request carries.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Credentials {
    pub key_id: String,
    pub timestamp: u64,
    pub nonce: String,
    pub signature: Vec<u8>,
    /// Lower-case hex of `signature`.
    pub signature_hex: String,
}

/// Why a request was not authenticated.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AuthFailure {
    Missing(&'static str),
    Malformed(&'static str),
    UnknownKey,
    BadSignature,
    StaleTimestamp,
    Replayed,
    ReplayCacheFull,
    ClockUnavailable,
}

impl AuthFailure {
    pub fn code(&self) -> &'static str {
        match self {
            AuthFailure::Missing(_) => "missing_credentials",
            AuthFailure::Malformed(_) => "malformed_credentials",
            AuthFailure::UnknownKey => "unknown_key",
            AuthFailure::BadSignature => "bad_signature",
            AuthFailure::StaleTimestamp => "stale_timestamp",
            AuthFailure::Replayed => "replayed_nonce",
            AuthFailure::ReplayCacheFull => "replay_cache_full",
            AuthFailure::ClockUnavailable => "clock_unavailable",
        }
    }

    /// The HTTP status: 401, except 503 when this host cannot check.
    pub fn status(&self) -> u16 {
        match self {
            AuthFailure::ReplayCacheFull | AuthFailure::ClockUnavailable => 503,
            _ => 401,
        }
    }

    pub fn message(&self) -> String {
        match self {
            AuthFailure::Missing(h) => format!("header {h} is missing"),
            AuthFailure::Malformed(h) => format!("header {h} is malformed or repeated"),
            AuthFailure::UnknownKey => "the key id is not a configured SOC key".into(),
            AuthFailure::BadSignature => {
                "the signature does not verify for this robot, request and body".into()
            }
            AuthFailure::StaleTimestamp => {
                "the timestamp is outside the allowed clock skew (check NTP on both sides)".into()
            }
            AuthFailure::Replayed => "this nonce was already used".into(),
            AuthFailure::ReplayCacheFull => {
                "too many recent requests to check for replay; retry later".into()
            }
            AuthFailure::ClockUnavailable => "the robot's wall clock is unavailable".into(),
        }
    }
}

/// The bytes a SOC signs for one request (see the module docs).
#[allow(clippy::too_many_arguments)]
pub fn signing_message(
    method: &str,
    target: &str,
    robot_id: &str,
    key_id: &str,
    timestamp: u64,
    nonce: &str,
    body: &[u8],
) -> Vec<u8> {
    format!(
        "{API_VERSION}\n{method}\n{target}\n{robot_id}\n{key_id}\n{timestamp}\n{nonce}\n{}",
        to_hex(&sha256(body))
    )
    .into_bytes()
}

/// The bytes the robot signs for an answer: bound to the request's own
/// signature (and so to its nonce), the status and the body.
pub fn answer_message(request_signature_hex: &str, status: u16, body: &[u8]) -> Vec<u8> {
    format!(
        "{API_VERSION} answer\n{request_signature_hex}\n{status}\n{}",
        to_hex(&sha256(body))
    )
    .into_bytes()
}

fn one<'a>(req: &'a Request, name: &'static str) -> Result<&'a str, AuthFailure> {
    match req.header_count(name) {
        0 => Err(AuthFailure::Missing(name)),
        1 => req.header(name).ok_or(AuthFailure::Missing(name)),
        _ => Err(AuthFailure::Malformed(name)),
    }
}

/// The credentials headers, strictly parsed.
pub fn credentials(req: &Request) -> Result<Credentials, AuthFailure> {
    let key_id = one(req, H_KEY_ID)?;
    if key_id.is_empty() || key_id.len() > 128 || !key_id.bytes().all(|b| b.is_ascii_graphic()) {
        return Err(AuthFailure::Malformed(H_KEY_ID));
    }
    let ts = one(req, H_TIMESTAMP)?;
    if ts.is_empty() || ts.len() > 12 || !ts.bytes().all(|b| b.is_ascii_digit()) {
        return Err(AuthFailure::Malformed(H_TIMESTAMP));
    }
    let timestamp: u64 = ts
        .parse()
        .map_err(|_| AuthFailure::Malformed(H_TIMESTAMP))?;
    let nonce = one(req, H_NONCE)?;
    if !(MIN_NONCE_LEN..=MAX_NONCE_LEN).contains(&nonce.len())
        || !nonce
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'_' || b == b'-')
    {
        return Err(AuthFailure::Malformed(H_NONCE));
    }
    let sig = one(req, H_SIGNATURE)?;
    if sig.len() != 128 {
        return Err(AuthFailure::Malformed(H_SIGNATURE));
    }
    let signature = from_hex(sig).ok_or(AuthFailure::Malformed(H_SIGNATURE))?;
    Ok(Credentials {
        key_id: key_id.to_string(),
        timestamp,
        nonce: nonce.to_string(),
        signature_hex: to_hex(&signature),
        signature,
    })
}

/// Verify the signature with the configured key named by the request.
pub fn verify(
    req: &Request,
    c: &Credentials,
    keys: &[SocKey],
    robot_id: &str,
) -> Result<(), AuthFailure> {
    let key = keys
        .iter()
        .find(|k| k.key_id == c.key_id)
        .ok_or(AuthFailure::UnknownKey)?;
    let msg = signing_message(
        &req.method,
        &req.target,
        robot_id,
        &c.key_id,
        c.timestamp,
        &c.nonce,
        &req.body,
    );
    if robodr_blackbox::sign_ed25519::verify(&key.public, &msg, &c.signature) {
        Ok(())
    } else {
        Err(AuthFailure::BadSignature)
    }
}

/// Timestamp window and nonce cache.
#[derive(Debug)]
pub struct ReplayGuard {
    /// (key id, nonce) -> Unix second after which the entry is dead.
    seen: HashMap<(String, String), u64>,
    skew_s: u64,
    max: usize,
}

impl ReplayGuard {
    pub fn new(skew_s: u64, max: usize) -> Self {
        Self {
            seen: HashMap::new(),
            skew_s,
            max,
        }
    }

    pub fn len(&self) -> usize {
        self.seen.len()
    }

    pub fn is_empty(&self) -> bool {
        self.seen.is_empty()
    }

    /// Check the window and record the nonce (`now_s`: this host's Unix
    /// seconds). An entry lives until its timestamp leaves the window, after
    /// which the window check alone refuses a replay.
    pub fn check(
        &mut self,
        key_id: &str,
        nonce: &str,
        timestamp: u64,
        now_s: u64,
    ) -> Result<(), AuthFailure> {
        if timestamp.abs_diff(now_s) > self.skew_s {
            return Err(AuthFailure::StaleTimestamp);
        }
        let k = (key_id.to_string(), nonce.to_string());
        if self.seen.contains_key(&k) {
            return Err(AuthFailure::Replayed);
        }
        if self.seen.len() >= self.max {
            self.seen.retain(|_, dead_after| *dead_after >= now_s);
            if self.seen.len() >= self.max {
                return Err(AuthFailure::ReplayCacheFull);
            }
        }
        self.seen
            .insert(k, timestamp.saturating_add(self.skew_s).saturating_add(1));
        Ok(())
    }
}

/// A token bucket per key id.
#[derive(Debug)]
pub struct RateLimiter {
    buckets: HashMap<String, (f64, Instant)>,
    per_s: f64,
    burst: f64,
}

impl RateLimiter {
    pub fn new(per_minute: u32, burst: u32) -> Self {
        Self {
            buckets: HashMap::new(),
            per_s: f64::from(per_minute.max(1)) / 60.0,
            burst: f64::from(burst.max(1)),
        }
    }

    /// Take one token for `key_id`, or say after how many seconds to retry.
    /// The table holds one entry per configured key (only authenticated
    /// requests reach it), so it is bounded by the key list.
    pub fn allow(&mut self, key_id: &str, now: Instant) -> Result<(), u64> {
        let (tokens, at) = self
            .buckets
            .entry(key_id.to_string())
            .or_insert((self.burst, now));
        let dt = now.saturating_duration_since(*at).as_secs_f64();
        *tokens = (*tokens + dt * self.per_s).min(self.burst);
        *at = now;
        if *tokens >= 1.0 {
            *tokens -= 1.0;
            Ok(())
        } else {
            let wait = ((1.0 - *tokens) / self.per_s).ceil();
            Err(if wait.is_finite() && wait >= 1.0 {
                wait as u64
            } else {
                1
            })
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use robodr_blackbox::Ed25519SigningKey;
    use std::time::Duration;

    fn key() -> Ed25519SigningKey {
        Ed25519SigningKey::from_seed("soc-1", &[7; 32]).unwrap()
    }

    fn soc() -> Vec<SocKey> {
        vec![SocKey {
            key_id: "soc-1".into(),
            public: key().public_key(),
        }]
    }

    fn signed(method: &str, target: &str, robot: &str, body: &[u8], ts: u64) -> Request {
        let nonce = "n0nce-0123456789abcdef";
        let sig = key().sign_message(&signing_message(
            method, target, robot, "soc-1", ts, nonce, body,
        ));
        Request {
            method: method.into(),
            target: target.into(),
            headers: vec![
                (H_KEY_ID.into(), "soc-1".into()),
                (H_TIMESTAMP.into(), ts.to_string()),
                (H_NONCE.into(), nonce.into()),
                (H_SIGNATURE.into(), to_hex(&sig)),
            ],
            body: body.to_vec(),
        }
    }

    #[test]
    fn a_signed_request_verifies_and_is_bound() {
        let r = signed(
            "POST",
            "/api/v1/robots/ugv-007/action-requests",
            "ugv-007",
            b"{}",
            100,
        );
        let c = credentials(&r).unwrap();
        assert_eq!(verify(&r, &c, &soc(), "ugv-007"), Ok(()));
        // Another robot, path, method or body: no.
        assert_eq!(
            verify(&r, &c, &soc(), "ugv-008"),
            Err(AuthFailure::BadSignature)
        );
        let edits: [fn(&mut Request); 3] = [
            |r| r.target = "/api/v1/robots/ugv-007/action-requests/x".into(),
            |r| r.method = "GET".into(),
            |r| r.body = b"{ }".to_vec(),
        ];
        for f in edits {
            let mut t = r.clone();
            f(&mut t);
            assert_eq!(
                verify(&t, &c, &soc(), "ugv-007"),
                Err(AuthFailure::BadSignature)
            );
        }
        // A key that is not configured.
        let other = vec![SocKey {
            key_id: "soc-2".into(),
            public: key().public_key(),
        }];
        assert_eq!(
            verify(&r, &c, &other, "ugv-007"),
            Err(AuthFailure::UnknownKey)
        );
        // A configured id with another key's signature.
        let wrong = vec![SocKey {
            key_id: "soc-1".into(),
            public: Ed25519SigningKey::from_seed("x", &[8; 32])
                .unwrap()
                .public_key(),
        }];
        assert_eq!(
            verify(&r, &c, &wrong, "ugv-007"),
            Err(AuthFailure::BadSignature)
        );
    }

    #[test]
    fn credential_headers_are_strict() {
        let base = signed("GET", "/api/v1/robots/r", "r", b"", 5);
        assert!(credentials(&base).is_ok());
        let edit = |name: &str, v: Option<&str>, dup: bool| {
            let mut r = base.clone();
            r.headers.retain(|(n, _)| n != name || dup);
            if let Some(v) = v {
                r.headers.push((name.into(), v.into()));
            }
            credentials(&r)
        };
        assert_eq!(
            edit(H_NONCE, None, false),
            Err(AuthFailure::Missing(H_NONCE))
        );
        assert_eq!(
            edit(H_NONCE, Some("short"), false),
            Err(AuthFailure::Malformed(H_NONCE))
        );
        assert_eq!(
            edit(H_NONCE, Some("has space in it ok?"), false),
            Err(AuthFailure::Malformed(H_NONCE))
        );
        assert_eq!(
            edit(H_NONCE, Some("another-nonce-12345"), true),
            Err(AuthFailure::Malformed(H_NONCE))
        );
        assert_eq!(
            edit(H_TIMESTAMP, Some("-5"), false),
            Err(AuthFailure::Malformed(H_TIMESTAMP))
        );
        assert_eq!(
            edit(H_SIGNATURE, Some("zz"), false),
            Err(AuthFailure::Malformed(H_SIGNATURE))
        );
        assert_eq!(
            edit(H_SIGNATURE, Some(&"g".repeat(128)), false),
            Err(AuthFailure::Malformed(H_SIGNATURE))
        );
        assert_eq!(
            edit(H_KEY_ID, None, false),
            Err(AuthFailure::Missing(H_KEY_ID))
        );
    }

    #[test]
    fn replay_window_and_cache() {
        let mut g = ReplayGuard::new(30, 3);
        assert_eq!(g.check("k", "n1", 1000, 1000), Ok(()));
        assert_eq!(g.check("k", "n1", 1000, 1001), Err(AuthFailure::Replayed));
        // Same nonce under another key is another pair.
        assert_eq!(g.check("k2", "n1", 1000, 1001), Ok(()));
        assert_eq!(
            g.check("k", "n2", 969, 1000),
            Err(AuthFailure::StaleTimestamp)
        );
        assert_eq!(
            g.check("k", "n2", 1031, 1000),
            Err(AuthFailure::StaleTimestamp)
        );
        assert_eq!(g.check("k", "n2", 1030, 1000), Ok(()));
        // Full of live entries: refused, not accepted unchecked.
        assert_eq!(
            g.check("k", "n3", 1000, 1000),
            Err(AuthFailure::ReplayCacheFull)
        );
        // Once the old entries leave the window they are pruned.
        assert_eq!(g.check("k", "n3", 1062, 1062), Ok(()));
        assert!(g.len() <= 3);
    }

    #[test]
    fn rate_limit_refills() {
        let mut l = RateLimiter::new(60, 2);
        let t = Instant::now();
        assert!(l.allow("k", t).is_ok());
        assert!(l.allow("k", t).is_ok());
        assert_eq!(l.allow("k", t), Err(1));
        // Another key has its own bucket.
        assert!(l.allow("k2", t).is_ok());
        assert!(l.allow("k", t + Duration::from_millis(1100)).is_ok());
    }

    #[test]
    fn answer_message_binds_the_request() {
        let a = answer_message("aa", 200, b"{}");
        assert_ne!(a, answer_message("ab", 200, b"{}"));
        assert_ne!(a, answer_message("aa", 401, b"{}"));
        assert_ne!(a, answer_message("aa", 200, b"{ }"));
    }
}
