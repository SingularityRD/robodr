//! The agentd ↔ executor protocol (`robodr-executor/1`) over a unix stream
//! socket: newline-delimited JSON envelopes, each authenticated with
//! HMAC-SHA-256 under a 32-byte key both sides load from a root-only file
//! (systemd credentials).
//!
//! ```text
//! {"v":"robodr-executor/1","ts":<unix ms>,"nonce":"<32 hex>","reply_to":"<32 hex or empty>",
//!  "msg":"<the message, JSON text>","mac":"<64 hex>"}
//! mac = HMAC-SHA-256(key, "robodr-executor/1" 0x00 ts 0x00 nonce 0x00 reply_to 0x00 msg)
//! ```
//!
//! The message is carried as text, so the MAC covers its exact bytes (no
//! canonicalisation). A receiver checks the MAC (constant time), the
//! timestamp window ([`MAX_SKEW_MS`]) and, for requests, that the nonce is
//! fresh ([`NonceCache`], fails closed when full); a reply must name the
//! request's nonce in `reply_to`. One connection carries one exchange:
//!
//! ```text
//! agentd → submit{order}      executor → confirm{id}        (asks for the safety state now)
//! agentd → safety{state,age}  executor → outcome{...}
//! agentd → events{since}      [executor → confirm{"rearm"} → agentd safety{..}, only while
//!                              actions are held after a reboot]   executor → event_list
//! agentd → revert{id,reason,soc?}  [executor → confirm{id} → agentd safety{..}, only to
//!                              lift an active safe_pause]   executor → outcome
//! agentd → status / ping   executor → outcome / pong
//! ```
//!
//! There is no `rearm` message (review finding 2): agentd holds this key,
//! and ending an operator's emergency disable is the operator's alone
//! (`robodr-executor rearm`, on the journal, with the executor stopped).
//!
//! A request line must arrive whole within [`crate::server::MESSAGE_DEADLINE`]
//! (an absolute deadline, not one per read), and nonces are remembered on
//! the monotonic clock ([`mono_ms`]): a wall-clock step back neither keeps
//! them forever (filling the cache) nor drops them early.

use std::collections::{HashSet, VecDeque};
use std::io::{BufRead, Write};
use std::os::unix::net::UnixStream;
use std::time::Instant;

use robodr_blackbox::crypto::{ct_eq, fill_random, from_hex, hmac_sha256, to_hex};
use robodr_responder::SafetyState;
use serde::{Deserialize, Serialize};

use crate::engine::Outcome;
use crate::journal::Event;
use crate::order::Order;

pub const VERSION: &str = "robodr-executor/1";
/// Longest envelope line.
/// (128 KiB: an order carries the SOC's signed request, body up to 16 KiB.)
pub const MAX_LINE: usize = 128 * 1024;
/// Allowed clock difference between the two processes (same host).
pub const MAX_SKEW_MS: u64 = 30_000;
/// Nonces remembered.
pub const NONCE_CACHE: usize = 4096;
/// Most events per `events` answer.
pub const MAX_EVENTS_PER_ANSWER: usize = 64;

/// A message (the `msg` of an envelope).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(tag = "op", rename_all = "snake_case", deny_unknown_fields)]
pub enum Msg {
    // agentd → executor
    Submit {
        order: Box<Order>,
    },
    Safety {
        state: SafetyState,
        age_ms: u64,
    },
    /// The safety state is not available (agentd has no current view).
    NoSafety {
        reason: String,
    },
    Revert {
        id: String,
        reason: String,
        /// The SOC's signed revert request (control-plane reverts; review
        /// finding F3): required to lift an action the SOC approved.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        soc: Option<Box<crate::soc::SocRequest>>,
    },
    Status {
        id: String,
    },
    Events {
        since: u64,
    },
    Ping,
    // executor → agentd
    Confirm {
        id: String,
    },
    Outcome {
        outcome: Box<Outcome>,
    },
    EventList {
        events: Vec<Event>,
    },
    Pong {
        active: usize,
        boot_id: String,
        /// Status flags (absent from executor v1.0).
        #[serde(default)]
        operator_disabled: bool,
        #[serde(default)]
        journal_reset: bool,
        #[serde(default)]
        held: usize,
    },
    Error {
        code: String,
        message: String,
    },
}

/// The 32-byte shared key.
#[derive(Clone)]
pub struct Key([u8; 32]);

impl std::fmt::Debug for Key {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("Key(..)")
    }
}

impl Drop for Key {
    fn drop(&mut self) {
        robodr_blackbox::crypto::wipe(&mut self.0);
    }
}

impl Key {
    pub fn from_bytes(b: [u8; 32]) -> Self {
        Key(b)
    }

    /// 64 hex digits (surrounding whitespace ignored).
    pub fn parse(text: &str) -> Result<Self, String> {
        let t = text.trim();
        if t.len() != 64 {
            return Err("executor key: expected 64 hex digits".into());
        }
        let mut v = from_hex(t).ok_or("executor key: not hex")?;
        if v.len() != 32 {
            return Err("executor key: expected 32 bytes".into());
        }
        let mut k = [0u8; 32];
        k.copy_from_slice(&v);
        robodr_blackbox::crypto::wipe(&mut v);
        if k.iter().all(|b| *b == 0) {
            return Err("executor key: all zero".into());
        }
        Ok(Key(k))
    }

    /// Load from a file that must be a regular file without group / other
    /// permission bits.
    pub fn load(path: &std::path::Path) -> Result<Self, String> {
        use std::os::unix::fs::PermissionsExt;
        let md = std::fs::metadata(path).map_err(|e| format!("{}: {e}", path.display()))?;
        if !md.is_file() {
            return Err(format!("{}: not a regular file", path.display()));
        }
        if md.permissions().mode() & 0o077 != 0 {
            return Err(format!(
                "{}: readable or writable by group/other (mode {:o}); use 0400 or 0600",
                path.display(),
                md.permissions().mode() & 0o777
            ));
        }
        let mut text = crate::config::read_small(path)?;
        let k = Key::parse(&text);
        // Wipe the text copy of the key.
        let mut b = std::mem::take(&mut text).into_bytes();
        robodr_blackbox::crypto::wipe(&mut b);
        k
    }

    /// A new random key, as the file text.
    pub fn generate_hex() -> Result<String, String> {
        let mut k = [0u8; 32];
        fill_random(&mut k).map_err(|e| format!("getrandom: {e}"))?;
        let s = to_hex(&k);
        robodr_blackbox::crypto::wipe(&mut k);
        Ok(s)
    }

    fn mac(&self, ts: u64, nonce: &str, reply_to: &str, msg: &str) -> [u8; 32] {
        let mut m = Vec::with_capacity(msg.len() + 120);
        m.extend_from_slice(VERSION.as_bytes());
        m.push(0);
        m.extend_from_slice(ts.to_string().as_bytes());
        m.push(0);
        m.extend_from_slice(nonce.as_bytes());
        m.push(0);
        m.extend_from_slice(reply_to.as_bytes());
        m.push(0);
        m.extend_from_slice(msg.as_bytes());
        hmac_sha256(&self.0, &m)
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Envelope {
    v: String,
    ts: u64,
    nonce: String,
    reply_to: String,
    msg: String,
    mac: String,
}

/// A verified incoming message.
#[derive(Debug, Clone, PartialEq)]
pub struct Received {
    pub msg: Msg,
    pub nonce: String,
    pub reply_to: String,
}

fn nonce_ok(s: &str) -> bool {
    s.len() == 32 && s.bytes().all(|b| b.is_ascii_hexdigit())
}

/// A fresh random nonce.
pub fn new_nonce() -> Result<String, String> {
    let mut n = [0u8; 16];
    fill_random(&mut n).map_err(|e| format!("getrandom: {e}"))?;
    Ok(to_hex(&n))
}

/// Encode `msg` as one envelope line (with `\n`).
pub fn seal(
    key: &Key,
    now_ms: u64,
    nonce: &str,
    reply_to: &str,
    msg: &Msg,
) -> Result<Vec<u8>, String> {
    let text = serde_json::to_string(msg).map_err(|e| e.to_string())?;
    seal_text(key, now_ms, nonce, reply_to, text)
}

/// [`seal`] of a message already encoded (tests send messages no longer
/// in [`Msg`]).
pub(crate) fn seal_text(
    key: &Key,
    now_ms: u64,
    nonce: &str,
    reply_to: &str,
    text: String,
) -> Result<Vec<u8>, String> {
    let mac = to_hex(&key.mac(now_ms, nonce, reply_to, &text));
    let env = Envelope {
        v: VERSION.into(),
        ts: now_ms,
        nonce: nonce.into(),
        reply_to: reply_to.into(),
        msg: text,
        mac,
    };
    let mut line = serde_json::to_vec(&env).map_err(|e| e.to_string())?;
    if line.len() >= MAX_LINE {
        return Err("message too large".into());
    }
    line.push(b'\n');
    Ok(line)
}

/// Why a line was not accepted.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Reject {
    Malformed(String),
    BadMac,
    Stale,
    Replayed,
    WrongReply,
}

impl std::fmt::Display for Reject {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Reject::Malformed(m) => write!(f, "malformed message: {m}"),
            Reject::BadMac => f.write_str("bad authentication code"),
            Reject::Stale => f.write_str("timestamp outside the allowed window"),
            Reject::Replayed => f.write_str("replayed nonce"),
            Reject::WrongReply => f.write_str("reply does not answer this request"),
        }
    }
}

/// Verify one envelope line (without its newline). `expect_reply_to`: the
/// nonce this must answer (`None` for a request).
pub fn open(
    key: &Key,
    line: &[u8],
    now_ms: u64,
    expect_reply_to: Option<&str>,
) -> Result<Received, Reject> {
    let env: Envelope =
        serde_json::from_slice(line).map_err(|e| Reject::Malformed(e.to_string()))?;
    if env.v != VERSION {
        return Err(Reject::Malformed("unknown protocol version".into()));
    }
    if !nonce_ok(&env.nonce) || !(env.reply_to.is_empty() || nonce_ok(&env.reply_to)) {
        return Err(Reject::Malformed("bad nonce".into()));
    }
    let got = from_hex(&env.mac).ok_or(Reject::BadMac)?;
    let want = key.mac(env.ts, &env.nonce, &env.reply_to, &env.msg);
    if !ct_eq(&got, &want) {
        return Err(Reject::BadMac);
    }
    if env.ts.abs_diff(now_ms) > MAX_SKEW_MS {
        return Err(Reject::Stale);
    }
    match expect_reply_to {
        Some(n) if env.reply_to != n => return Err(Reject::WrongReply),
        _ => {}
    }
    let msg: Msg = serde_json::from_str(&env.msg).map_err(|e| Reject::Malformed(e.to_string()))?;
    Ok(Received {
        msg,
        nonce: env.nonce,
        reply_to: env.reply_to,
    })
}

/// Remembers request nonces for the timestamp window, on the monotonic
/// clock ([`mono_ms`]).
#[derive(Debug, Default)]
pub struct NonceCache {
    seen: HashSet<String>,
    order: VecDeque<(u64, String)>,
}

impl NonceCache {
    /// Record `nonce` seen at `mono_ms` (monotonic ms, never the wall
    /// clock). `Err(Replayed)` if already seen; fails closed
    /// (`Err(Stale)`) when full of nonces still in the window.
    pub fn check(&mut self, nonce: &str, mono_ms: u64) -> Result<(), Reject> {
        let now_ms = mono_ms;
        while let Some((t, _)) = self.order.front() {
            if now_ms.saturating_sub(*t) > 2 * MAX_SKEW_MS {
                if let Some((_, n)) = self.order.pop_front() {
                    self.seen.remove(&n);
                }
            } else {
                break;
            }
        }
        if self.seen.contains(nonce) {
            return Err(Reject::Replayed);
        }
        if self.seen.len() >= NONCE_CACHE {
            return Err(Reject::Stale);
        }
        self.seen.insert(nonce.to_string());
        self.order.push_back((now_ms, nonce.to_string()));
        Ok(())
    }
}

/// Read one line of at most [`MAX_LINE`] bytes that must be complete by
/// `deadline` (absolute: a peer trickling bytes cannot extend it).
pub fn read_line_by(
    r: &mut std::io::BufReader<UnixStream>,
    deadline: Instant,
) -> Result<Vec<u8>, String> {
    let mut line = Vec::new();
    loop {
        let left = deadline.saturating_duration_since(Instant::now());
        if left.is_zero() {
            return Err("message deadline passed".into());
        }
        r.get_ref()
            .set_read_timeout(Some(left))
            .map_err(|e| format!("read: {e}"))?;
        let buf = r.fill_buf().map_err(|e| format!("read: {e}"))?;
        if buf.is_empty() {
            return Err("connection closed".into());
        }
        if let Some(i) = buf.iter().position(|b| *b == b'\n') {
            line.extend_from_slice(&buf[..i]);
            r.consume(i + 1);
            break;
        }
        let n = buf.len();
        line.extend_from_slice(buf);
        r.consume(n);
        if line.len() > MAX_LINE {
            return Err("line too long".into());
        }
    }
    if line.len() > MAX_LINE {
        return Err("line too long".into());
    }
    Ok(line)
}

/// Read one line of at most [`MAX_LINE`] bytes (without the newline).
pub fn read_line(r: &mut impl BufRead) -> Result<Vec<u8>, String> {
    let mut line = Vec::new();
    loop {
        let buf = r.fill_buf().map_err(|e| format!("read: {e}"))?;
        if buf.is_empty() {
            return Err("connection closed".into());
        }
        if let Some(i) = buf.iter().position(|b| *b == b'\n') {
            line.extend_from_slice(&buf[..i]);
            r.consume(i + 1);
            break;
        }
        let n = buf.len();
        line.extend_from_slice(buf);
        r.consume(n);
        if line.len() > MAX_LINE {
            return Err("line too long".into());
        }
    }
    if line.len() > MAX_LINE {
        return Err("line too long".into());
    }
    Ok(line)
}

/// Write one sealed line.
pub fn write_line(w: &mut impl Write, line: &[u8]) -> Result<(), String> {
    w.write_all(line)
        .and_then(|()| w.flush())
        .map_err(|e| format!("write: {e}"))
}

/// Monotonic ms since the first call in this process.
pub fn mono_ms() -> u64 {
    static START: std::sync::OnceLock<Instant> = std::sync::OnceLock::new();
    let s = START.get_or_init(Instant::now);
    u64::try_from(s.elapsed().as_millis()).unwrap_or(u64::MAX)
}

/// Wall clock, Unix ms.
pub fn wall_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn key() -> Key {
        Key::from_bytes([7u8; 32])
    }

    #[test]
    fn seal_open_round_trip_and_tamper() {
        let k = key();
        let n = new_nonce().unwrap();
        let line = seal(&k, 1000, &n, "", &Msg::Ping).unwrap();
        let body = &line[..line.len() - 1];
        let r = open(&k, body, 1000, None).unwrap();
        assert_eq!(r.msg, Msg::Ping);
        // Wrong key.
        assert_eq!(
            open(&Key::from_bytes([8u8; 32]), body, 1000, None),
            Err(Reject::BadMac)
        );
        // Any byte of the message changed.
        let text = String::from_utf8(body.to_vec()).unwrap();
        let t2 = text.replace("ping", "pong");
        assert!(open(&k, t2.as_bytes(), 1000, None).is_err());
        // Stale.
        assert_eq!(
            open(&k, body, 1000 + MAX_SKEW_MS + 1, None),
            Err(Reject::Stale)
        );
        // Reply binding.
        let reply = seal(&k, 1000, &new_nonce().unwrap(), &n, &Msg::Ping).unwrap();
        assert!(open(&k, &reply[..reply.len() - 1], 1000, Some(&n)).is_ok());
        let other = new_nonce().unwrap();
        assert_eq!(
            open(&k, &reply[..reply.len() - 1], 1000, Some(&other)),
            Err(Reject::WrongReply)
        );
    }

    #[test]
    fn l3_nonce_cache_runs_on_the_monotonic_clock() {
        // Filled at monotonic 1000; 2 * MAX_SKEW_MS later every entry has
        // left the window whatever the wall clock did meanwhile.
        let mut c = NonceCache::default();
        for i in 0..NONCE_CACHE {
            c.check(&format!("n{i}"), 1_000).unwrap();
        }
        assert_eq!(c.check("x", 1_000), Err(Reject::Stale), "fails closed");
        assert!(c.check("x", 1_000 + 2 * MAX_SKEW_MS + 1).is_ok());
        let a = mono_ms();
        std::thread::sleep(std::time::Duration::from_millis(5));
        assert!(mono_ms() >= a + 5);
    }

    #[test]
    fn nonce_cache_refuses_replays_and_expires() {
        let mut c = NonceCache::default();
        assert!(c.check("a", 0).is_ok());
        assert_eq!(c.check("a", 1), Err(Reject::Replayed));
        assert!(c.check("a", 3 * MAX_SKEW_MS).is_ok());
    }

    #[test]
    fn keys_parse_strictly() {
        assert!(Key::parse(&"ab".repeat(32)).is_ok());
        assert!(Key::parse(&"00".repeat(32)).is_err());
        assert!(Key::parse("abc").is_err());
        assert!(Key::parse(&"zz".repeat(32)).is_err());
        assert_eq!(Key::generate_hex().unwrap().len(), 64);
    }
}
