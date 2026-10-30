//! Request authentication: Ed25519 signatures by a configured SOC key over
//! the request, bound to this robot, with a timestamp window and a
//! persisted nonce store against replay, and a per-key rate limit. On a TLS
//! listener this comes **in addition to** the SOC's client certificate
//! (mutual TLS, [`super::tls`]): both are required.
//!
//! # What is signed
//!
//! [`signing_message`]: the lines (joined by `\n`, no trailing newline)
//!
//! ```text
//! robodr-control-plane/v2
//! <METHOD>
//! <request target exactly as sent, e.g. /api/v2/robots/ugv-007/action-requests>
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
//!
//! The cache is persisted ([`ReplayGuard::persistent`]: `nonces.journal` in
//! the state directory): a pair is appended and fsynced **before** the
//! request goes any further, so a request accepted before a restart is
//! still a replay after it, for as long as its timestamp is in the window.
//! If the store cannot be trusted at start (damaged lines, or missing while
//! the request journal exists: the state was removed), a **fence** refuses
//! every request whose timestamp is not later than the start (it may have
//! been seen before); a failed append refuses the request
//! (`replay_store_unavailable`, 503), never accepts it unrecorded.

use std::collections::HashMap;
use std::path::Path;
use std::time::Instant;

use robodr_blackbox::crypto::{from_hex, sha256, to_hex};
use serde::{Deserialize, Serialize};

use super::http::Request;
use super::journal::{AnchorCheck, Head, Journal, Loaded, Sealing};

/// API and signature domain.
pub const API_VERSION: &str = "robodr-control-plane/v2";
/// The replay store's journal file (in the state directory).
pub const NONCE_JOURNAL: &str = "nonces.journal";
pub const H_KEY_ID: &str = "x-robodr-key-id";
pub const H_TIMESTAMP: &str = "x-robodr-timestamp";
pub const H_NONCE: &str = "x-robodr-nonce";
pub const H_SIGNATURE: &str = "x-robodr-signature";
/// The answer signature header (every answer to an authenticated request).
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
    /// Signed before a restart that found the replay store untrustworthy.
    Fenced,
    /// The nonce could not be made durable.
    ReplayStoreUnavailable,
    /// The TLS handshake failed (no / untrusted / expired / unpinned client
    /// certificate): counted, never answered (there is no channel).
    Tls(String),
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
            AuthFailure::Fenced => "stale_timestamp",
            AuthFailure::ReplayStoreUnavailable => "replay_store_unavailable",
            AuthFailure::Tls(_) => "tls_handshake_failed",
        }
    }

    /// The HTTP status: 401, except 503 when this host cannot check.
    pub fn status(&self) -> u16 {
        match self {
            AuthFailure::ReplayCacheFull
            | AuthFailure::ClockUnavailable
            | AuthFailure::ReplayStoreUnavailable => 503,
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
            AuthFailure::Fenced => {
                "signed before agentd restarted with an untrusted replay store; sign the request \
                 again"
                    .into()
            }
            AuthFailure::ReplayStoreUnavailable => {
                "the replay store could not record the nonce; retry later".into()
            }
            AuthFailure::Tls(why) => format!("TLS handshake failed: {why}"),
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

/// One persisted (key, nonce) pair (`t: "nonce"`), or the wall-clock
/// high-water mark (`t: "clock"`, empty key and nonce, `dead_after` = the
/// latest Unix second at which the store dropped dead pairs; written with
/// every compaction, which is where pairs are dropped).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NonceEntry {
    pub t: String,
    pub key_id: String,
    pub nonce: String,
    /// Unix second after which the pair is dead (its timestamp left the
    /// window); for `clock`, the high-water mark.
    pub dead_after: u64,
}

/// What [`ReplayGuard::persistent`] found.
#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize)]
pub struct ReplayLoad {
    /// Live pairs restored.
    pub restored: usize,
    /// Dead pairs dropped.
    pub expired: usize,
    pub torn_bytes: u64,
    pub damaged: usize,
    pub created: bool,
    /// The persisted wall-clock high-water mark found (Unix seconds).
    pub high_water: Option<u64>,
    /// The wall clock read below the high-water mark at start.
    pub clock_went_back: bool,
    /// The fence set (Unix seconds), if any.
    pub fence: Option<u64>,
    /// Of `damaged`, lines whose seal did not verify (an edit or deletion).
    pub forged: usize,
    /// The store is sealed under another key (named).
    pub wrong_key: Option<String>,
    /// A v1 store was adopted (one-time upgrade).
    pub upgraded_from_v1: bool,
    /// A v1 store after sealing had started (a downgrade): damage.
    pub legacy_refused: bool,
    /// The comparison with the black box's newest head.
    pub anchor: AnchorCheck,
}

/// Timestamp window and nonce cache (optionally persisted).
#[derive(Debug)]
pub struct ReplayGuard {
    /// (key id, nonce) -> Unix second after which the entry is dead.
    seen: HashMap<(String, String), u64>,
    skew_s: u64,
    max: usize,
    journal: Option<Journal>,
    /// Timestamps `<=` this are refused ([`AuthFailure::Fenced`]).
    fence: Option<u64>,
    /// Journal append failures.
    pub store_errors: u64,
    /// Compact (dropping dead pairs) when the journal reaches this many
    /// lines: twice the live set after the last compaction, plus 1024.
    compact_at: usize,
    /// The latest wall-clock second at which dead pairs were dropped
    /// (persisted as the `clock` entry of every compaction). A clock below
    /// it could bring their timestamps back into the window.
    high_water: u64,
}

impl ReplayGuard {
    /// An in-memory guard (tests, and the shape of the persisted one).
    pub fn new(skew_s: u64, max: usize) -> Self {
        Self {
            seen: HashMap::new(),
            skew_s,
            max,
            journal: None,
            fence: None,
            store_errors: 0,
            compact_at: 1024,
            high_water: 0,
        }
    }

    /// Refuse every timestamp up to `at + skew` (whatever was accepted
    /// before `at` had a timestamp at most `skew` ahead of the clock).
    fn fence_from(&mut self, at: u64) {
        let f = at.saturating_add(self.skew_s);
        self.fence = Some(self.fence.map_or(f, |o| o.max(f)));
    }

    /// A guard persisted in `dir/nonces.journal`, fenced (control plane v2
    /// review, finding 5) whenever pairs it should know may be missing:
    ///
    /// * the journal had to be created: a first install and a removed or
    ///   wiped state directory look the same;
    /// * the journal was damaged, edited, sealed under another key, or an
    ///   unsealed v1 store (gap 1: sealed state);
    /// * it does not end exactly at the head a clean stop recorded in the
    ///   black box ([`AnchorCheck::Verified`]): it was rolled back, or pairs
    ///   appended after the newest head (a crash, a kill) may have been cut.
    ///   Without any head in the black box (a new black box) the sealed
    ///   store is taken as it is;
    /// * the wall clock reads below the persisted high-water mark, the
    ///   latest second at which dead pairs were dropped (they would live
    ///   again).
    ///
    /// The fence refuses every timestamp up to `max(now, high-water) +
    /// skew`: a request accepted before may carry a timestamp up to `skew`
    /// ahead of the clock that accepted it.
    pub fn persistent(
        dir: &Path,
        skew_s: u64,
        max: usize,
        now_s: u64,
        sealing: &Sealing,
    ) -> std::io::Result<(Self, ReplayLoad)> {
        let (journal, loaded): (Journal, Loaded<NonceEntry>) = Journal::open(
            dir,
            NONCE_JOURNAL,
            "nonces",
            &sealing.key,
            sealing.nonces.as_ref(),
            sealing.adopt_legacy,
        )?;
        let mut g = Self::new(skew_s, max);
        let mut load = ReplayLoad {
            torn_bytes: loaded.torn_bytes,
            damaged: loaded.damaged,
            created: loaded.created,
            forged: loaded.forged,
            wrong_key: loaded.wrong_key,
            upgraded_from_v1: loaded.upgraded_from_v1,
            legacy_refused: loaded.legacy_refused,
            anchor: loaded.anchor,
            ..ReplayLoad::default()
        };
        let untrusted_store = load.upgraded_from_v1
            || matches!(
                load.anchor,
                AnchorCheck::RolledBack(_) | AnchorCheck::Unanchored(_)
            );
        let mut hwm: Option<u64> = None;
        for e in loaded.entries {
            if e.t == "clock" && e.key_id.is_empty() && e.nonce.is_empty() {
                hwm = Some(hwm.map_or(e.dead_after, |h| h.max(e.dead_after)));
                continue;
            }
            if e.t != "nonce" {
                load.damaged += 1;
                continue;
            }
            if e.dead_after < now_s {
                load.expired += 1;
                continue;
            }
            g.seen.insert((e.key_id, e.nonce), e.dead_after);
        }
        load.restored = g.seen.len();
        load.high_water = hwm;
        let high = hwm.unwrap_or(0);
        load.clock_went_back = now_s < high;
        if load.damaged > 0 || loaded.created || load.clock_went_back || untrusted_store {
            g.fence_from(now_s.max(high));
            load.fence = g.fence;
        }
        g.high_water = high;
        if load.expired > 0 {
            g.high_water = g.high_water.max(now_s);
        }
        g.journal = Some(journal);
        // Start from a compact file.
        g.compact(now_s);
        Ok((g, load))
    }

    pub fn len(&self) -> usize {
        self.seen.len()
    }

    pub fn is_empty(&self) -> bool {
        self.seen.is_empty()
    }

    pub fn fence(&self) -> Option<u64> {
        self.fence
    }

    pub fn is_persistent(&self) -> bool {
        self.journal.is_some()
    }

    /// Where the persisted store ends now (anchored in the black box).
    pub fn head(&self) -> Option<Head> {
        self.journal.as_ref().map(Journal::head)
    }

    fn compact(&mut self, now_s: u64) {
        let before = self.seen.len();
        self.seen.retain(|_, dead_after| *dead_after >= now_s);
        if self.seen.len() < before {
            self.high_water = self.high_water.max(now_s);
        }
        let Some(j) = self.journal.as_mut() else {
            return;
        };
        let clock = NonceEntry {
            t: "clock".into(),
            key_id: String::new(),
            nonce: String::new(),
            dead_after: self.high_water,
        };
        let mut live: Vec<NonceEntry> = self
            .seen
            .iter()
            .map(|((k, n), d)| NonceEntry {
                t: "nonce".into(),
                key_id: k.clone(),
                nonce: n.clone(),
                dead_after: *d,
            })
            .collect();
        live.sort_by(|a, b| {
            (a.dead_after, &a.key_id, &a.nonce).cmp(&(b.dead_after, &b.key_id, &b.nonce))
        });
        live.insert(0, clock);
        if j.compact(&live).is_err() {
            self.store_errors += 1;
        }
        self.compact_at = 2 * self.seen.len() + 1024;
    }

    /// Check the window and record the nonce (`now_s`: this host's Unix
    /// seconds). An entry lives until its timestamp leaves the window, after
    /// which the window check alone refuses a replay. With a journal, the
    /// pair is durable before `Ok` is returned.
    pub fn check(
        &mut self,
        key_id: &str,
        nonce: &str,
        timestamp: u64,
        now_s: u64,
    ) -> Result<(), AuthFailure> {
        // The clock went back below the time dead pairs were dropped: they
        // could be replayed (review finding 5).
        if now_s < self.high_water {
            self.fence_from(self.high_water);
        }
        if timestamp.abs_diff(now_s) > self.skew_s {
            return Err(AuthFailure::StaleTimestamp);
        }
        if self.fence.is_some_and(|f| timestamp <= f) {
            return Err(AuthFailure::Fenced);
        }
        let k = (key_id.to_string(), nonce.to_string());
        if self.seen.contains_key(&k) {
            return Err(AuthFailure::Replayed);
        }
        if self.seen.len() >= self.max {
            // Dropping pairs: compact, which persists the high-water mark
            // with the live set.
            self.compact(now_s);
            if self.seen.len() >= self.max {
                return Err(AuthFailure::ReplayCacheFull);
            }
        }
        let dead_after = timestamp.saturating_add(self.skew_s).saturating_add(1);
        if self
            .journal
            .as_ref()
            .is_some_and(|j| j.lines() >= self.compact_at)
        {
            self.compact(now_s);
        }
        if let Some(j) = self.journal.as_mut() {
            let e = NonceEntry {
                t: "nonce".into(),
                key_id: k.0.clone(),
                nonce: k.1.clone(),
                dead_after,
            };
            if j.append(&e).is_err() {
                self.store_errors += 1;
                // Remembered in memory all the same (refused either way).
                self.seen.insert(k, dead_after);
                return Err(AuthFailure::ReplayStoreUnavailable);
            }
        }
        self.seen.insert(k, dead_after);
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
            "/api/v2/robots/ugv-007/action-requests",
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
            |r| r.target = "/api/v2/robots/ugv-007/action-requests/x".into(),
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
        let base = signed("GET", "/api/v2/robots/r", "r", b"", 5);
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

    fn tmp(tag: &str) -> std::path::PathBuf {
        let d = std::env::temp_dir().join(format!("robodr-cp-n-{tag}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&d);
        std::fs::create_dir_all(&d).unwrap();
        d
    }

    /// A store created long before (a first start then has nothing to
    /// fear): opened again at `now` it is not fenced.
    fn seasoned(tag: &str, now: u64) -> std::path::PathBuf {
        let d = tmp(tag);
        let (_, l) = ReplayGuard::persistent(
            &d,
            30,
            100,
            now - 500,
            &crate::control::journal::tests::sealing(),
        )
        .unwrap();
        assert!(l.created && l.fence.is_some());
        d
    }

    /// A nonce accepted before a restart is still a replay after it, for as
    /// long as its timestamp is in the window; dead pairs are dropped.
    #[test]
    fn replay_after_restart_is_refused() {
        let d = seasoned("restart", 1000);
        let (mut g, l) = ReplayGuard::persistent(
            &d,
            30,
            100,
            1000,
            &crate::control::journal::tests::sealing(),
        )
        .unwrap();
        assert!(!l.created && l.fence.is_none(), "{l:?}");
        assert_eq!(g.check("k", "nonce-aaaaaaaaaaaaaaaa", 1000, 1000), Ok(()));
        assert_eq!(g.check("k", "nonce-bbbbbbbbbbbbbbbb", 995, 1000), Ok(()));
        drop(g);
        // Restart 10 s later: both still live, both refused.
        let (mut g, l) = ReplayGuard::persistent(
            &d,
            30,
            100,
            1010,
            &crate::control::journal::tests::sealing(),
        )
        .unwrap();
        assert_eq!((l.restored, l.expired, l.fence), (2, 0, None));
        assert_eq!(
            g.check("k", "nonce-aaaaaaaaaaaaaaaa", 1000, 1010),
            Err(AuthFailure::Replayed)
        );
        assert_eq!(g.check("k", "nonce-cccccccccccccccc", 1010, 1010), Ok(()));
        drop(g);
        // Restart after the window: the old pairs are dead (dropped), and
        // the window alone refuses their timestamps.
        let (mut g, l) = ReplayGuard::persistent(
            &d,
            30,
            100,
            1035,
            &crate::control::journal::tests::sealing(),
        )
        .unwrap();
        assert_eq!((l.restored, l.expired), (1, 2));
        assert_eq!(l.high_water, Some(0));
        assert_eq!(
            g.check("k", "nonce-aaaaaaaaaaaaaaaa", 1000, 1035),
            Err(AuthFailure::StaleTimestamp)
        );
        assert_eq!(
            g.check("k", "nonce-cccccccccccccccc", 1010, 1035),
            Err(AuthFailure::Replayed)
        );
        let _ = std::fs::remove_dir_all(&d);
    }

    /// An untrusted store (damaged, missing, or behind a clock that went
    /// back) fences: nothing that may have been accepted before is.
    #[test]
    fn an_untrusted_store_fences() {
        let d = seasoned("fence", 1000);
        let (mut g, _) = ReplayGuard::persistent(
            &d,
            30,
            100,
            1000,
            &crate::control::journal::tests::sealing(),
        )
        .unwrap();
        g.check("k", "nonce-aaaaaaaaaaaaaaaa", 1000, 1000).unwrap();
        g.check("k", "nonce-bbbbbbbbbbbbbbbb", 1000, 1000).unwrap();
        drop(g);
        // Damage the first entry after the header (a good line follows).
        let p = d.join(NONCE_JOURNAL);
        let mut b = std::fs::read(&p).unwrap();
        let second = b.iter().position(|&c| c == b'\n').unwrap() + 1;
        b[second + 80] ^= 1;
        std::fs::write(&p, &b).unwrap();
        let (mut g, l) = ReplayGuard::persistent(
            &d,
            30,
            100,
            1005,
            &crate::control::journal::tests::sealing(),
        )
        .unwrap();
        assert_eq!(l.damaged, 1);
        assert_eq!(l.fence, Some(1035), "now + skew");
        // The lost nonce is refused by the fence, and so is a timestamp
        // up to the skew ahead; past it a fresh request is accepted.
        assert_eq!(
            g.check("k", "nonce-aaaaaaaaaaaaaaaa", 1000, 1005),
            Err(AuthFailure::Fenced)
        );
        assert_eq!(
            g.check("k", "nonce-dddddddddddddddd", 1035, 1005),
            Err(AuthFailure::Fenced)
        );
        assert_eq!(g.check("k", "nonce-dddddddddddddddd", 1036, 1006), Ok(()));
        drop(g);
        // Removed (or a first start: the same to the store): fenced.
        std::fs::remove_file(&p).unwrap();
        let (_, l) = ReplayGuard::persistent(
            &d,
            30,
            100,
            1010,
            &crate::control::journal::tests::sealing(),
        )
        .unwrap();
        assert_eq!(l.fence, Some(1040));
        let _ = std::fs::remove_dir_all(&d);
    }

    /// A nonce that cannot be made durable refuses the request (503), and
    /// the pair is still remembered.
    #[test]
    fn a_failing_store_refuses() {
        let d = tmp("fail");
        let (mut g, _) =
            ReplayGuard::persistent(&d, 30, 100, 900, &crate::control::journal::tests::sealing())
                .unwrap();
        crate::control::fsutil::fault::arm("survive.journal.append.short_write", 1);
        let r = g.check("k", "nonce-aaaaaaaaaaaaaaaa", 1000, 1000);
        assert_eq!(r, Err(AuthFailure::ReplayStoreUnavailable));
        assert_eq!(AuthFailure::ReplayStoreUnavailable.status(), 503);
        assert_eq!(
            g.check("k", "nonce-aaaaaaaaaaaaaaaa", 1000, 1000),
            Err(AuthFailure::Replayed)
        );
        assert_eq!(g.store_errors, 1);
        let _ = std::fs::remove_dir_all(&d);
    }

    #[test]
    fn the_store_is_compacted() {
        let d = tmp("compact");
        let (mut g, _) = ReplayGuard::persistent(
            &d,
            30,
            100_000,
            900,
            &crate::control::journal::tests::sealing(),
        )
        .unwrap();
        for i in 0..3000u64 {
            let now = 1000 + i / 10;
            g.check("k", &format!("nonce-{i:016}"), now, now).unwrap();
        }
        drop(g);
        let lines = std::fs::read_to_string(d.join(NONCE_JOURNAL))
            .unwrap()
            .lines()
            .count();
        assert!(lines < 2 * 320 + 1024 + 10, "{lines}");
        let _ = std::fs::remove_dir_all(&d);
    }
}
