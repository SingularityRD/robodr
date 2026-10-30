//! A [`HeadAnchor`] kept **off the unit**: [`RemoteHeadAnchor`] (the client,
//! on the unit) sends every head mark to an [`AnchorReceiver`] (a small
//! std-only TCP daemon, `robodr-anchor-receiver`, on a base station or
//! fleet host) that stores, per unit, the highest mark it has seen.
//!
//! # Why off the unit
//!
//! `head.json` and the TPM sidecar live on the unit; root there can roll
//! them back to an older authentic copy. The TPM counter exposes that, but
//! needs a TPM. A receiver on another host is out of reach of an attacker
//! who owns only the unit: what it holds can only go up, and the unit
//! consults it at every open, so a cut tail plus rolled-back state files is
//! reported as `TruncationDetected`, and a wiped store as a new chain that
//! declares the gap.
//!
//! # Protocol (`robodr-anchor/v1`)
//!
//! One request per TCP connection: a single JSON line (at most
//! [`MAX_FRAME`] bytes, newline-terminated), answered by a single JSON line.
//! The connection is TLS (see "Transport" below) unless plain TCP is
//! explicitly allowed; either way everything that matters is also
//! authenticated at the application layer with Ed25519, so the guarantees
//! below hold even over plain TCP:
//!
//! - **advance** `{"protocol","op":"advance","mark":{..}}`. The mark is a
//!   [`RemoteMark`]: the recorder's [`Checkpoint`] (chain id, seq, record
//!   hash, key id, the record's own signature) plus `mark_sig`, the unit's
//!   signature over [`mark_message`] = domain || unit || chain id || seq ||
//!   hash || key id. The checkpoint signature alone covers only the record
//!   hash, not `seq` or `chain_id`: anyone who captured one genuine
//!   checkpoint could replay it with an inflated `seq`, which the receiver
//!   would then hold forever (refusing every genuine mark as lower, and
//!   making the unit report a false truncation). `mark_sig` closes that.
//!   The receiver verifies both signatures under the unit's configured
//!   public key, then applies the rule below and persists before it
//!   answers. The answer (`ok`, `held_seq`) is *not* authenticated: a
//!   man-in-the-middle can fake it or drop the mark, which only makes the
//!   receiver lag (see Limits); it can never lower what the receiver holds.
//! - **current** `{"protocol","op":"current","unit","nonce"}` with a fresh
//!   32-byte random nonce. The receiver answers with the stored mark (or
//!   none) and its own Ed25519 signature over [`reply_message`] = domain ||
//!   nonce || unit || the mark. The unit checks the receiver signature
//!   under the configured receiver public key, the nonce and unit, and then
//!   the mark's own signatures under **its own** key
//!   ([`Signer::verify_own`]). So a man-in-the-middle can neither invent a
//!   lower mark (or "no mark") to hide a truncation (no receiver key), nor
//!   replay an older genuine answer (wrong nonce), nor substitute another
//!   unit's mark. It can drop or garble the answer: that is an anchor
//!   *failure* (counted, named in the signed `Resume` record), never "no
//!   anchor".
//!
//! # Transport
//!
//! **TLS by default** ([`crate::tls`]: rustls, TLS 1.3 / 1.2): the client
//! ([`RemoteAnchorConfig::tls`]) verifies the receiver's certificate
//! against the configured CA file only (chain, validity, `serverAuth`, the
//! server name: the address's host or `server_name`), optionally pins its
//! SPKI and presents a client certificate; the receiver
//! ([`ServeOptions::tls`]) can require one (mutual TLS, `client_ca`). TLS
//! adds confidentiality (marks are no longer readable on the wire), makes a
//! man-in-the-middle unable to drop or fake answers silently (it can still
//! cut the connection, which is an anchor failure), and with mutual TLS
//! keeps unknown hosts from reaching the request parser at all.
//!
//! Plain TCP is **refused** on both sides unless explicitly allowed
//! ([`RemoteAnchorConfig::allow_plaintext`], [`ServeOptions::allow_plaintext`]).
//! There is no fallback: a TLS client never retries in plain TCP and a TLS
//! receiver never answers a plain-TCP request (a downgrade is a failed
//! handshake, an anchor failure on the unit).
//!
//! # Receiver rule (per unit)
//!
//! Holding mark `h`, an authentic mark `m` is
//!
//! - stored if there is no `h` or `m.seq > h.seq` (a wiped store reopened
//!   under the same identity keeps its chain id and continues numbering
//!   after the anchor, so it is simply higher; a higher seq under a
//!   different chain id, a store replaced under another identity, is
//!   stored and recorded as a `chain_change` alert);
//! - a no-op if it equals `h` (a retry);
//! - **refused** if `m.seq == h.seq` with another hash or chain (`fork`
//!   alert: two different records were signed at one position) or if
//!   `m.seq < h.seq` (`lower` alert: the unit went back, e.g. it opened
//!   without seeing the anchor, or an old mark is replayed; a replay is
//!   harmless, it changes nothing);
//! - refused if a signature does not verify (`bad_signature` alert).
//!
//! An alert is a log line, a line in `<state_dir>/alerts.jsonl` (fsynced;
//! the file is bounded at [`MAX_ALERTS_BYTES`], beyond that alerts are only
//! counted and logged) and a per-unit counter in the unit's state file.
//! The state file (`<state_dir>/units/<unit>.json`) is replaced atomically
//! (temp file, fsync, rename, fsync directory) **before** the receiver
//! answers `ok`. At start every stored mark is re-verified; a state file
//! that does not verify puts the unit in a *broken* state (logged, alert)
//! where every request for it is refused, so the unit counts anchor
//! failures until an operator investigates. It is never silently reset.
//!
//! # Client behaviour
//!
//! [`RemoteHeadAnchor::advance`] runs inside `append`, so it must not wait
//! for the network: it signs the mark and hands it to a background thread
//! through a one-slot queue that **coalesces to the newest mark** (a mark
//! still unsent is simply replaced). The thread delivers with bounded
//! connect / write / read timeouts and retries transport failures with
//! exponential backoff (250 ms .. 30 s); a mark the receiver *refuses* is
//! not retried. A delivery failure is reported by the next `advance` call
//! (so the recorder counts it as an anchor failure, one mark late).
//! [`RemoteHeadAnchor::current`] (once, at open) is synchronous and bounded
//! by about three (TLS: four) times the configured timeout, DNS included (it runs on a
//! helper thread). Dropping the anchor makes one last bounded attempt to
//! deliver a pending mark (the recorder's final mark at close).
//!
//! # Air-gapped deployments
//!
//! The query at open needs a **reverse channel**: a one-way diode cannot
//! carry the answer. Either run the receiver on a local base station the
//! unit reaches over a private link (the usual choice for a mission), or
//! use the **detect-only** mode: `robodr-blackbox anchor-mark` writes the
//! current `head.json` as a signed mark file (the advance request line),
//! the file rides the diode with the other exports, and
//! `robodr-anchor-receiver ingest` applies it with the same rule. Then the
//! unit is never told about a rollback, but the far side detects it later:
//! a mark lower than one already held, or a fork, raises an alert.
//!
//! # Limits
//!
//! - Detection, not prevention; the window is what the receiver has not
//!   received yet: records after the newest mark (as with every anchor) plus
//!   marks still queued or lost in transit. An attacker who controls the
//!   network can suppress marks (the window grows, the receiver's lag is
//!   visible there) and block the query at open (anchor failure on the
//!   record), but cannot make the receiver go back or make the unit accept a
//!   lower mark.
//! - The receiver trusts the unit's public key it is configured with; the
//!   anchor signs with the key it was built with (the recorder's key at
//!   start). When the unit's key changes, replace its public key on the
//!   receiver; after an in-place rotation (`Recorder::rotate_key`,
//!   `robodr-blackbox rotate`) the chain continues, after a new chain move
//!   the unit's state file aside.
//! - The receiver's own state is only as safe as its host. Its signing key
//!   stays there (0600); the units hold only its public half.
//! - With `allow_plaintext` there is no transport confidentiality: marks
//!   (hashes, seqs) are visible on the wire. They reveal no evidence
//!   content.
//! - Mutual TLS authenticates the host, not the unit: any client
//!   certificate the receiver's `client_ca` accepts may send marks for any
//!   configured unit; they still have to verify under that unit's key.

use crate::crypto::{fill_random, from_hex, hash_from_hex, to_hex};
use crate::export::Checkpoint;
use crate::record::{signing_message, Hash, MAX_SIG_LEN};
use crate::sign::{Signer, Verifier, MAX_KEY_ID_LEN};
use crate::store::{atomic_write, lock_file, read_state, AnchoredHead, Error, HeadAnchor};
use crate::tls::DeadlineTcp;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fmt;
use std::fs::{self, File, OpenOptions};
use std::io::{self, Read, Write};
use std::net::{SocketAddr, TcpListener, TcpStream, ToSocketAddrs};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{mpsc, Arc, Condvar, Mutex, MutexGuard};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

/// Wire protocol tag (every request and answer carries it).
pub const PROTOCOL: &str = "robodr-anchor/v1";
/// Conventional TCP port of the receiver.
pub const DEFAULT_PORT: u16 = 7461;
/// Bound on one request or answer line (without the newline).
pub const MAX_FRAME: usize = 16 * 1024;
/// Bound on the number of units one receiver serves.
pub const MAX_UNITS: usize = 4096;
/// Default client timeout (connect, write and read each).
pub const DEFAULT_TIMEOUT: Duration = Duration::from_secs(2);
/// Default bound on one connection at the receiver (whole request).
pub const DEFAULT_IO_TIMEOUT: Duration = Duration::from_secs(5);
/// Default bound on concurrent connections at the receiver.
pub const DEFAULT_MAX_CONNECTIONS: usize = 64;
/// Length of the client nonce of a `current` query.
pub const NONCE_LEN: usize = 32;
/// Format tag of a receiver state file.
pub const STATE_FORMAT: &str = "robodr-anchor-receiver-state/v1";
/// Alert log in the receiver's state directory.
pub const ALERTS_FILE: &str = "alerts.jsonl";
/// Bound on [`ALERTS_FILE`]; further alerts are counted and logged only.
pub const MAX_ALERTS_BYTES: u64 = 16 << 20;
/// Lock file in the receiver's state directory (single instance).
pub const RECEIVER_LOCK_FILE: &str = "receiver.lock";
/// Per-unit state files live here, under the state directory.
pub const UNITS_DIR: &str = "units";

const MARK_DOMAIN: &[u8] = b"robodr-blackbox/remote-anchor/mark/v1\0";
const REPLY_DOMAIN: &[u8] = b"robodr-blackbox/remote-anchor/current/v1\0";
const MIN_BACKOFF: Duration = Duration::from_millis(250);
const MAX_BACKOFF: Duration = Duration::from_secs(30);
const MAX_ADDRESS_LEN: usize = 255;

/// A unit id the receiver accepts (also a file name): 1..=64 of
/// `[A-Za-z0-9._-]`, not starting with `.` (the robot id rule of agentd).
pub fn valid_unit_id(s: &str) -> bool {
    !s.is_empty()
        && s.len() <= 64
        && !s.starts_with('.')
        && s.bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b'-'))
}

fn valid_key_id(s: &str) -> bool {
    !s.is_empty() && s.len() <= MAX_KEY_ID_LEN && s.bytes().all(|b| b.is_ascii_graphic())
}

/// Syntax check of a `host:port` address (`[v6]:port` for IPv6 literals).
/// Does not resolve anything.
pub fn check_address(s: &str) -> Result<(), String> {
    if s.is_empty() || s.len() > MAX_ADDRESS_LEN || !s.bytes().all(|b| b.is_ascii_graphic()) {
        return Err(format!(
            "address must be 1..={MAX_ADDRESS_LEN} printable characters, host:port"
        ));
    }
    let Some((host, port)) = s.rsplit_once(':') else {
        return Err(format!("address {s:?}: expected host:port"));
    };
    let host_ok = if let Some(h) = host.strip_prefix('[') {
        h.strip_suffix(']')
            .is_some_and(|h| h.parse::<std::net::Ipv6Addr>().is_ok())
    } else {
        !host.is_empty() && !host.contains(':')
    };
    if !host_ok {
        return Err(format!("address {s:?}: bad host (IPv6 needs [brackets])"));
    }
    match port.parse::<u16>() {
        Ok(p) if p > 0 => Ok(()),
        _ => Err(format!("address {s:?}: port must be 1..=65535")),
    }
}

fn put_lp(m: &mut Vec<u8>, b: &[u8]) {
    m.extend_from_slice(&(b.len() as u32).to_be_bytes());
    m.extend_from_slice(b);
}

/// What `mark_sig` covers: `"robodr-blackbox/remote-anchor/mark/v1\0" ||
/// lp(unit) || chain_id || u64_be(seq) || hash || lp(key_id)`, where `lp`
/// is a `u32_be` length prefix. Domain-separated from record, cursor, ack
/// and TPM sidecar signatures.
pub fn mark_message(unit: &str, chain_id: &Hash, seq: u64, hash: &Hash, key_id: &str) -> Vec<u8> {
    let mut m = Vec::with_capacity(MARK_DOMAIN.len() + 4 + unit.len() + 72 + 4 + key_id.len());
    m.extend_from_slice(MARK_DOMAIN);
    put_lp(&mut m, unit.as_bytes());
    m.extend_from_slice(chain_id);
    m.extend_from_slice(&seq.to_be_bytes());
    m.extend_from_slice(hash);
    put_lp(&mut m, key_id.as_bytes());
    m
}

/// What the receiver signs in a `current` answer:
/// `"robodr-blackbox/remote-anchor/current/v1\0" || nonce || lp(unit) ||
/// u8(has mark) || [chain_id || u64_be(seq) || hash || lp(key_id) ||
/// lp(record_sig) || lp(mark_sig)]`.
pub fn reply_message(nonce: &[u8; NONCE_LEN], unit: &str, mark: Option<&RemoteMark>) -> Vec<u8> {
    let mut m = Vec::with_capacity(256);
    m.extend_from_slice(REPLY_DOMAIN);
    m.extend_from_slice(nonce);
    put_lp(&mut m, unit.as_bytes());
    match mark {
        None => m.push(0),
        Some(k) => {
            m.push(1);
            m.extend_from_slice(&k.chain_id);
            m.extend_from_slice(&k.seq.to_be_bytes());
            m.extend_from_slice(&k.hash);
            put_lp(&mut m, k.key_id.as_bytes());
            put_lp(&mut m, &k.record_sig);
            put_lp(&mut m, &k.mark_sig);
        }
    }
    m
}

// ---------------------------------------------------------------------------
// The mark
// ---------------------------------------------------------------------------

/// A head mark as a unit sends it (see the module docs).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RemoteMark {
    pub unit: String,
    pub chain_id: Hash,
    pub seq: u64,
    pub hash: Hash,
    /// Key that signed the record and the mark.
    pub key_id: String,
    /// The record's own signature (the [`Checkpoint`] signature).
    pub record_sig: Vec<u8>,
    /// Signature over [`mark_message`].
    pub mark_sig: Vec<u8>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct MarkJson {
    unit: String,
    chain_id: String,
    seq: u64,
    hash: String,
    key_id: String,
    record_sig: String,
    mark_sig: String,
}

fn sig_from_hex(s: &str, what: &str) -> Result<Vec<u8>, String> {
    from_hex(s)
        .filter(|v| !v.is_empty() && v.len() <= MAX_SIG_LEN)
        .ok_or_else(|| format!("malformed {what}"))
}

impl RemoteMark {
    /// Sign checkpoint `cp` of unit `unit` with `signer` (the recorder's
    /// key: it must be the key the checkpoint names).
    pub fn sign(unit: &str, cp: &Checkpoint, signer: &dyn Signer) -> Result<Self, String> {
        if !valid_unit_id(unit) {
            return Err(format!("unit id {unit:?} is not valid"));
        }
        if cp.key_id != signer.key_id() {
            return Err(format!(
                "mark of seq {} is signed by key {:?}, the anchor holds key {:?} (key rotated? \
                 restart with the new key and reset the receiver's state for this unit)",
                cp.seq,
                cp.key_id,
                signer.key_id()
            ));
        }
        if cp.sig.is_empty() || cp.sig.len() > MAX_SIG_LEN {
            return Err(format!("mark of seq {} has no record signature", cp.seq));
        }
        let msg = mark_message(unit, &cp.chain_id, cp.seq, &cp.hash, &cp.key_id);
        let mark_sig = signer.sign(&msg).map_err(|e| e.to_string())?;
        if mark_sig.is_empty() || mark_sig.len() > MAX_SIG_LEN {
            return Err("mark signature length out of range".into());
        }
        Ok(Self {
            unit: unit.to_string(),
            chain_id: cp.chain_id,
            seq: cp.seq,
            hash: cp.hash,
            key_id: cp.key_id.clone(),
            record_sig: cp.sig.clone(),
            mark_sig,
        })
    }

    fn message(&self) -> Vec<u8> {
        mark_message(
            &self.unit,
            &self.chain_id,
            self.seq,
            &self.hash,
            &self.key_id,
        )
    }

    /// Both signatures under the unit's public key `v` (the receiver's
    /// check).
    pub fn verify(&self, v: &dyn Verifier) -> Result<(), String> {
        if v.key_id() != self.key_id {
            return Err(format!(
                "mark is signed by key {:?}, the unit's key is {:?}",
                self.key_id,
                v.key_id()
            ));
        }
        if !v.verify(&signing_message(&self.hash), &self.record_sig) {
            return Err("record signature does not verify".into());
        }
        if !v.verify(&self.message(), &self.mark_sig) {
            return Err("mark signature does not verify".into());
        }
        Ok(())
    }

    /// Both signatures under the unit's own key (the unit's check of what
    /// the receiver hands back).
    pub fn verify_own(&self, s: &dyn Signer) -> Result<(), String> {
        if s.key_id() != self.key_id {
            return Err(format!(
                "held mark is signed by key {:?}, this unit's key is {:?}",
                self.key_id,
                s.key_id()
            ));
        }
        if s.verify_own(&signing_message(&self.hash), &self.record_sig) != Some(true)
            || s.verify_own(&self.message(), &self.mark_sig) != Some(true)
        {
            return Err("held mark is not signed by this unit's key".into());
        }
        Ok(())
    }

    /// The position as an anchor reports it.
    pub fn anchored(&self) -> AnchoredHead {
        AnchoredHead {
            chain_id: Some(self.chain_id),
            seq: self.seq,
            hash: Some(self.hash),
        }
    }

    fn to_json(&self) -> MarkJson {
        MarkJson {
            unit: self.unit.clone(),
            chain_id: to_hex(&self.chain_id),
            seq: self.seq,
            hash: to_hex(&self.hash),
            key_id: self.key_id.clone(),
            record_sig: to_hex(&self.record_sig),
            mark_sig: to_hex(&self.mark_sig),
        }
    }

    fn from_json(j: &MarkJson) -> Result<Self, String> {
        if !valid_unit_id(&j.unit) {
            return Err("mark: invalid unit id".into());
        }
        if !valid_key_id(&j.key_id) {
            return Err("mark: invalid key id".into());
        }
        Ok(Self {
            unit: j.unit.clone(),
            chain_id: hash_from_hex(&j.chain_id).ok_or("mark: malformed chain_id")?,
            seq: j.seq,
            hash: hash_from_hex(&j.hash).ok_or("mark: malformed hash")?,
            key_id: j.key_id.clone(),
            record_sig: sig_from_hex(&j.record_sig, "record_sig")?,
            mark_sig: sig_from_hex(&j.mark_sig, "mark_sig")?,
        })
    }

    /// The `advance` request line (without newline). Also the format of a
    /// mark file for the one-way mode (`robodr-anchor-receiver ingest`).
    pub fn to_request_line(&self) -> String {
        serde_json::to_string(&RequestJson {
            protocol: PROTOCOL.into(),
            op: "advance".into(),
            mark: Some(self.to_json()),
            unit: None,
            nonce: None,
        })
        .unwrap_or_default()
    }

    /// Parse an `advance` request line / mark file (signatures unchecked).
    pub fn from_request_line(line: &[u8]) -> Result<Self, String> {
        match parse_request(line)? {
            Request::Advance(m) => Ok(m),
            Request::Current { .. } => Err("not an advance request".into()),
        }
    }
}

// ---------------------------------------------------------------------------
// Wire format
// ---------------------------------------------------------------------------

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct RequestJson {
    protocol: String,
    op: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    mark: Option<MarkJson>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    unit: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    nonce: Option<String>,
}

#[derive(Serialize, Deserialize, Default)]
#[serde(deny_unknown_fields)]
struct ResponseJson {
    protocol: String,
    ok: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    op: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    error: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    held_seq: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    unit: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    nonce: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    mark: Option<MarkJson>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    receiver_key_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    sig: Option<String>,
}

enum Request {
    Advance(RemoteMark),
    Current {
        unit: String,
        nonce: [u8; NONCE_LEN],
    },
}

fn parse_nonce(s: &str) -> Option<[u8; NONCE_LEN]> {
    from_hex(s).and_then(|v| <[u8; NONCE_LEN]>::try_from(v.as_slice()).ok())
}

fn parse_request(line: &[u8]) -> Result<Request, String> {
    if line.len() > MAX_FRAME {
        return Err(format!("request exceeds {MAX_FRAME} bytes"));
    }
    let j: RequestJson = serde_json::from_slice(line).map_err(|_| "malformed request")?;
    if j.protocol != PROTOCOL {
        return Err("unsupported protocol".into());
    }
    match (j.op.as_str(), j.mark, j.unit, j.nonce) {
        ("advance", Some(m), None, None) => Ok(Request::Advance(RemoteMark::from_json(&m)?)),
        ("current", None, Some(unit), Some(nonce)) => {
            if !valid_unit_id(&unit) {
                return Err("invalid unit id".into());
            }
            let nonce = parse_nonce(&nonce).ok_or("malformed nonce")?;
            Ok(Request::Current { unit, nonce })
        }
        _ => Err("unknown op or wrong fields".into()),
    }
}

fn current_request_line(unit: &str, nonce: &[u8; NONCE_LEN]) -> String {
    serde_json::to_string(&RequestJson {
        protocol: PROTOCOL.into(),
        op: "current".into(),
        mark: None,
        unit: Some(unit.to_string()),
        nonce: Some(to_hex(nonce)),
    })
    .unwrap_or_default()
}

fn error_line(e: &str) -> Vec<u8> {
    let mut v = serde_json::to_vec(&ResponseJson {
        protocol: PROTOCOL.into(),
        ok: false,
        error: Some(e.to_string()),
        ..Default::default()
    })
    .unwrap_or_default();
    v.push(b'\n');
    v
}

#[derive(Debug, PartialEq, Eq)]
enum FrameError {
    TooLarge,
    Eof,
    Timeout,
    Io(String),
}

impl fmt::Display for FrameError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            FrameError::TooLarge => write!(f, "frame exceeds {MAX_FRAME} bytes"),
            FrameError::Eof => write!(f, "connection closed before a complete line"),
            FrameError::Timeout => write!(f, "timed out"),
            FrameError::Io(e) => write!(f, "{e}"),
        }
    }
}

/// Read one newline-terminated line of at most [`MAX_FRAME`] bytes, giving
/// up at `deadline` (the stream's read timeout bounds each read).
fn read_frame(r: &mut impl Read, deadline: Instant) -> Result<Vec<u8>, FrameError> {
    let mut buf = Vec::with_capacity(512);
    let mut chunk = [0u8; 2048];
    loop {
        if Instant::now() >= deadline {
            return Err(FrameError::Timeout);
        }
        let n = match r.read(&mut chunk) {
            Ok(0) => return Err(FrameError::Eof),
            Ok(n) => n,
            Err(e)
                if matches!(
                    e.kind(),
                    io::ErrorKind::WouldBlock | io::ErrorKind::TimedOut
                ) =>
            {
                return Err(FrameError::Timeout)
            }
            Err(e) if e.kind() == io::ErrorKind::Interrupted => continue,
            Err(e) => return Err(FrameError::Io(e.to_string())),
        };
        if let Some(i) = chunk[..n].iter().position(|&b| b == b'\n') {
            if buf.len() + i > MAX_FRAME {
                return Err(FrameError::TooLarge);
            }
            buf.extend_from_slice(&chunk[..i]);
            return Ok(buf);
        }
        buf.extend_from_slice(&chunk[..n]);
        if buf.len() > MAX_FRAME {
            return Err(FrameError::TooLarge);
        }
    }
}

/// One request/answer exchange with bounded connect, (TLS handshake,)
/// write and read.
fn exchange(cfg: &RemoteAnchorConfig, line: &str) -> Result<Vec<u8>, String> {
    let (address, timeout) = (cfg.address.as_str(), cfg.timeout);
    if cfg.tls.is_none() && !cfg.allow_plaintext {
        return Err("plain TCP is not allowed (configure TLS)".into());
    }
    let addrs: Vec<SocketAddr> = address
        .to_socket_addrs()
        .map_err(|e| format!("resolving {address}: {e}"))?
        .collect();
    // Connect: all addresses together within one timeout.
    let connect_end = Instant::now() + timeout;
    let mut last = format!("{address}: no address");
    let mut stream = None;
    for a in addrs {
        let left = connect_end.saturating_duration_since(Instant::now());
        if left.is_zero() {
            last = format!("{address}: connect timed out");
            break;
        }
        match TcpStream::connect_timeout(&a, left) {
            Ok(s) => {
                stream = Some(s);
                break;
            }
            Err(e) => last = format!("connecting to {a}: {e}"),
        }
    }
    let s = stream.ok_or(last)?;
    let _ = s.set_nodelay(true);
    // Everything after the connect shares one deadline (review F2): each
    // read and write re-arms the socket timeout with the time left, so a
    // peer that trickles bytes cannot stretch the exchange.
    let end = Instant::now() + timeout * if cfg.tls.is_some() { 3 } else { 2 };
    let mut req = Vec::with_capacity(line.len() + 1);
    req.extend_from_slice(line.as_bytes());
    req.push(b'\n');
    let io = |e: io::Error| format!("{address}: {}", crate::tls::describe(&e));
    match &cfg.tls {
        None => {
            let mut d = DeadlineTcp::new(s);
            d.set_deadline(end);
            d.write_all(&req).map_err(io)?;
            d.flush().map_err(io)?;
            read_frame(&mut d, end).map_err(|e| format!("{address}: answer: {e}"))
        }
        Some(tls) => {
            let name = tls.name_for(crate::tls::host_of(address))?;
            let mut t = crate::tls::connect_client(s, tls, name, end)
                .map_err(|e| format!("{address}: {e}"))?;
            t.write_all(&req).map_err(io)?;
            t.flush().map_err(io)?;
            let r = read_frame(&mut t, end).map_err(|e| format!("{address}: answer: {e}"));
            t.conn.send_close_notify();
            let _ = t.conn.complete_io(&mut t.sock);
            r
        }
    }
}

// ---------------------------------------------------------------------------
// Receiver
// ---------------------------------------------------------------------------

/// A unit the receiver serves and the public key its marks must verify
/// under.
pub struct UnitKey {
    pub unit: String,
    pub verifier: Box<dyn Verifier + Send + Sync>,
}

impl fmt::Debug for UnitKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("UnitKey")
            .field("unit", &self.unit)
            .field("key_id", &self.verifier.key_id())
            .finish()
    }
}

/// Why the receiver refused a request.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Refusal {
    UnknownUnit(String),
    BadSignature(String),
    Lower { held: u64, offered: u64 },
    Fork { seq: u64 },
    Broken(String),
    Storage(String),
    BadRequest(String),
}

impl fmt::Display for Refusal {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Refusal::UnknownUnit(u) => write!(f, "unknown unit {u:?}"),
            Refusal::BadSignature(e) => write!(f, "not authentic: {e}"),
            Refusal::Lower { held, offered } => {
                write!(f, "lower: holding seq {held}, offered {offered}")
            }
            Refusal::Fork { seq } => write!(f, "fork: another record at held seq {seq}"),
            Refusal::Broken(e) => write!(f, "unit state unusable, operator action needed: {e}"),
            Refusal::Storage(e) => write!(f, "storage: {e}"),
            Refusal::BadRequest(e) => write!(f, "bad request: {e}"),
        }
    }
}

/// What an accepted `advance` did.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Advanced {
    /// Stored; the seq held before, if any.
    Stored { previous: Option<u64> },
    /// The same mark was already held.
    Duplicate,
}

/// Log sink of the receiver (default: stderr).
pub type LogFn = Box<dyn Fn(&str) + Send + Sync>;

#[derive(Default)]
struct UnitState {
    held: Option<RemoteMark>,
    alerts: u64,
    broken: Option<String>,
}

struct UnitSlot {
    verifier: Box<dyn Verifier + Send + Sync>,
    state: Mutex<UnitState>,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct StateJson {
    format: String,
    unit: String,
    #[serde(default)]
    mark: Option<MarkJson>,
    alerts: u64,
}

#[derive(Serialize)]
struct AlertJson<'a> {
    time_unix: u64,
    unit: &'a str,
    kind: &'a str,
    detail: &'a str,
    #[serde(skip_serializing_if = "Option::is_none")]
    held_seq: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    offered_seq: Option<u64>,
}

/// Connection limits and transport of [`AnchorReceiver::serve`].
#[derive(Debug, Clone)]
pub struct ServeOptions {
    pub max_connections: usize,
    /// Bound on reading one request (from accept to its newline, the TLS
    /// handshake included).
    pub io_timeout: Duration,
    /// TLS server configuration ([`crate::tls::load_server`]); with a
    /// `client_ca` it requires client certificates (mutual TLS).
    pub tls: Option<Arc<rustls::ServerConfig>>,
    /// Serve plain TCP when `tls` is `None` (default `false`: refused).
    pub allow_plaintext: bool,
    /// Most connections open at once from one source address (default
    /// [`DEFAULT_MAX_CONNECTIONS_PER_SOURCE`]): one host cannot take every
    /// slot, before or after authenticating.
    pub max_connections_per_source: usize,
}

/// Default of [`ServeOptions::max_connections_per_source`].
pub const DEFAULT_MAX_CONNECTIONS_PER_SOURCE: usize = 8;

impl Default for ServeOptions {
    fn default() -> Self {
        Self {
            max_connections: DEFAULT_MAX_CONNECTIONS,
            io_timeout: DEFAULT_IO_TIMEOUT,
            tls: None,
            allow_plaintext: false,
            max_connections_per_source: DEFAULT_MAX_CONNECTIONS_PER_SOURCE,
        }
    }
}

/// The receiver: per-unit highest marks, durable, plus alerts. See the
/// module docs for the rule.
pub struct AnchorReceiver {
    dir: PathBuf,
    units: HashMap<String, UnitSlot>,
    signer: Mutex<Box<dyn Signer>>,
    alerts_lock: Mutex<u64>,
    log: LogFn,
    /// Failed TLS handshakes (logged: the first 16, then at powers of two).
    tls_failures: std::sync::atomic::AtomicU64,
    _lock: File,
}

impl fmt::Debug for AnchorReceiver {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("AnchorReceiver")
            .field("dir", &self.dir)
            .field("units", &self.units.len())
            .finish_non_exhaustive()
    }
}

fn now_unix() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| d.as_secs())
}

fn lock<T>(m: &Mutex<T>) -> MutexGuard<'_, T> {
    // A poisoned lock only means another thread panicked mid-update; the
    // state it guards is replaced whole, never left half-written.
    m.lock().unwrap_or_else(|p| p.into_inner())
}

impl AnchorReceiver {
    /// Open the state in `dir` (created if missing; single instance per
    /// directory) for `units`, signing `current` answers with `signer`
    /// (must self-verify). Every stored mark is re-verified.
    pub fn open(
        dir: &Path,
        units: Vec<UnitKey>,
        signer: Box<dyn Signer>,
        log: Option<LogFn>,
    ) -> Result<Self, String> {
        let log = log.unwrap_or_else(|| Box::new(|m: &str| eprintln!("{m}")));
        if units.is_empty() || units.len() > MAX_UNITS {
            return Err(format!("1..={MAX_UNITS} units must be configured"));
        }
        let probe = b"robodr-blackbox/remote-anchor/receiver-self-test";
        if signer
            .sign(probe)
            .ok()
            .and_then(|s| signer.verify_own(probe, &s))
            != Some(true)
        {
            return Err("the receiver key must be able to verify its own signatures".into());
        }
        let udir = dir.join(UNITS_DIR);
        create_private_dir(dir)?;
        create_private_dir(&udir)?;
        let lock_f = lock_file(dir.join(RECEIVER_LOCK_FILE)).map_err(|e| match e {
            Error::Locked { path } => format!(
                "{} is held by another receiver (or ingest) process",
                path.display()
            ),
            e => format!("{}: {e}", dir.display()),
        })?;
        let alerts_len = fs::metadata(dir.join(ALERTS_FILE)).map_or(0, |m| m.len());
        let mut map = HashMap::new();
        let mut broken = Vec::new();
        for u in units {
            if !valid_unit_id(&u.unit) {
                return Err(format!("unit id {:?} is not valid", u.unit));
            }
            if map.contains_key(&u.unit) {
                return Err(format!("unit {:?} configured twice", u.unit));
            }
            let st = match load_unit(&udir, &u.unit, &*u.verifier) {
                Ok(st) => st,
                Err(e) => {
                    broken.push((u.unit.clone(), e.clone()));
                    UnitState {
                        broken: Some(e),
                        ..Default::default()
                    }
                }
            };
            map.insert(
                u.unit,
                UnitSlot {
                    verifier: u.verifier,
                    state: Mutex::new(st),
                },
            );
        }
        let r = Self {
            dir: dir.to_path_buf(),
            units: map,
            signer: Mutex::new(signer),
            alerts_lock: Mutex::new(alerts_len),
            log,
            tls_failures: std::sync::atomic::AtomicU64::new(0),
            _lock: lock_f,
        };
        for (unit, e) in broken {
            r.write_alert(&unit, "state_unusable", &e, None, None);
        }
        Ok(r)
    }

    /// TLS handshakes that failed since start (no, unknown or expired
    /// client certificate, plain TCP, scanners).
    pub fn tls_handshake_failures(&self) -> u64 {
        self.tls_failures.load(Ordering::Relaxed)
    }

    /// The configured units.
    pub fn unit_ids(&self) -> Vec<&str> {
        let mut v: Vec<&str> = self.units.keys().map(String::as_str).collect();
        v.sort_unstable();
        v
    }

    /// The mark held for `unit`.
    pub fn held(&self, unit: &str) -> Option<RemoteMark> {
        self.units
            .get(unit)
            .and_then(|s| lock(&s.state).held.clone())
    }

    /// Alerts recorded for `unit` (persisted with its state).
    pub fn alerts(&self, unit: &str) -> u64 {
        self.units.get(unit).map_or(0, |s| lock(&s.state).alerts)
    }

    /// Why `unit`'s stored state is unusable, if it is.
    pub fn broken(&self, unit: &str) -> Option<String> {
        self.units
            .get(unit)
            .and_then(|s| lock(&s.state).broken.clone())
    }

    fn write_alert(
        &self,
        unit: &str,
        kind: &str,
        detail: &str,
        held: Option<u64>,
        offered: Option<u64>,
    ) {
        (self.log)(&format!(
            "robodr-anchor-receiver: ALERT unit={unit} kind={kind}: {detail}"
        ));
        let a = AlertJson {
            time_unix: now_unix(),
            unit,
            kind,
            detail,
            held_seq: held,
            offered_seq: offered,
        };
        let Ok(mut line) = serde_json::to_vec(&a) else {
            return;
        };
        line.push(b'\n');
        let mut len = lock(&self.alerts_lock);
        if *len + line.len() as u64 > MAX_ALERTS_BYTES {
            (self.log)(&format!(
                "robodr-anchor-receiver: {ALERTS_FILE} is full ({MAX_ALERTS_BYTES} bytes): \
                 alert counted and logged only"
            ));
            return;
        }
        let res = append_synced(&self.dir.join(ALERTS_FILE), &line);
        match res {
            Ok(()) => *len += line.len() as u64,
            Err(e) => (self.log)(&format!(
                "robodr-anchor-receiver: writing {ALERTS_FILE}: {e}"
            )),
        }
    }

    /// Count an alert on `st` and persist the count (not for a broken
    /// unit: its file is kept as found).
    fn alert(
        &self,
        unit: &str,
        st: &mut UnitState,
        kind: &str,
        detail: &str,
        held: Option<u64>,
        offered: Option<u64>,
    ) {
        st.alerts = st.alerts.saturating_add(1);
        self.write_alert(unit, kind, detail, held, offered);
        if st.broken.is_none() {
            if let Err(e) = self.persist(unit, st.held.as_ref(), st.alerts) {
                (self.log)(&format!("robodr-anchor-receiver: unit={unit}: {e}"));
            }
        }
    }

    fn persist(&self, unit: &str, mark: Option<&RemoteMark>, alerts: u64) -> Result<(), String> {
        let j = StateJson {
            format: STATE_FORMAT.into(),
            unit: unit.to_string(),
            mark: mark.map(RemoteMark::to_json),
            alerts,
        };
        let data = serde_json::to_vec(&j).map_err(|e| e.to_string())?;
        atomic_write(&self.dir.join(UNITS_DIR), &unit_file(unit), &data)
            .map_err(|e| format!("writing state: {e}"))
    }

    /// Apply one mark (see the module docs for the rule).
    pub fn advance(&self, m: &RemoteMark) -> Result<Advanced, Refusal> {
        let Some(slot) = self.units.get(&m.unit) else {
            (self.log)(&format!(
                "robodr-anchor-receiver: mark for unknown unit {:?} refused",
                m.unit
            ));
            return Err(Refusal::UnknownUnit(m.unit.clone()));
        };
        let mut st = lock(&slot.state);
        if let Some(b) = &st.broken {
            return Err(Refusal::Broken(b.clone()));
        }
        if let Err(e) = m.verify(&*slot.verifier) {
            let held = st.held.as_ref().map(|h| h.seq);
            self.alert(&m.unit, &mut st, "bad_signature", &e, held, Some(m.seq));
            return Err(Refusal::BadSignature(e));
        }
        let previous = st.held.as_ref().map(|h| h.seq);
        if let Some(h) = st.held.clone() {
            if m.seq < h.seq {
                let d = format!(
                    "authentic mark seq {} below the held seq {}: the unit went back (rollback, \
                     or an open without the anchor) or an old mark was replayed",
                    m.seq, h.seq
                );
                self.alert(&m.unit, &mut st, "lower", &d, Some(h.seq), Some(m.seq));
                return Err(Refusal::Lower {
                    held: h.seq,
                    offered: m.seq,
                });
            }
            if m.seq == h.seq {
                if m.chain_id == h.chain_id && m.hash == h.hash {
                    return Ok(Advanced::Duplicate);
                }
                let d = format!(
                    "two authentic marks at seq {}: held hash {} chain {}, offered hash {} \
                     chain {} (the log was rewritten under the unit's key)",
                    m.seq,
                    to_hex(&h.hash),
                    to_hex(&h.chain_id),
                    to_hex(&m.hash),
                    to_hex(&m.chain_id)
                );
                self.alert(&m.unit, &mut st, "fork", &d, Some(h.seq), Some(m.seq));
                return Err(Refusal::Fork { seq: m.seq });
            }
            if m.chain_id != h.chain_id {
                let d = format!(
                    "new chain {} at seq {} after chain {} at seq {}: the unit's store was \
                     wiped or replaced (it reports the gap itself)",
                    to_hex(&m.chain_id),
                    m.seq,
                    to_hex(&h.chain_id),
                    h.seq
                );
                // Stored below; the alert count goes with it.
                st.alerts = st.alerts.saturating_add(1);
                self.write_alert(&m.unit, "chain_change", &d, Some(h.seq), Some(m.seq));
            }
        }
        self.persist(&m.unit, Some(m), st.alerts)
            .map_err(Refusal::Storage)?;
        st.held = Some(m.clone());
        Ok(Advanced::Stored { previous })
    }

    /// The signed `current` answer for `unit` and `nonce`.
    fn current_reply(&self, unit: &str, nonce: &[u8; NONCE_LEN]) -> Result<ResponseJson, Refusal> {
        let slot = self
            .units
            .get(unit)
            .ok_or_else(|| Refusal::UnknownUnit(unit.to_string()))?;
        let st = lock(&slot.state);
        if let Some(b) = &st.broken {
            return Err(Refusal::Broken(b.clone()));
        }
        let held = st.held.clone();
        drop(st);
        let msg = reply_message(nonce, unit, held.as_ref());
        let signer = lock(&self.signer);
        let sig = signer
            .sign(&msg)
            .map_err(|e| Refusal::Storage(e.to_string()))?;
        Ok(ResponseJson {
            protocol: PROTOCOL.into(),
            ok: true,
            op: Some("current".into()),
            held_seq: held.as_ref().map(|h| h.seq),
            unit: Some(unit.to_string()),
            nonce: Some(to_hex(nonce)),
            mark: held.as_ref().map(RemoteMark::to_json),
            receiver_key_id: Some(signer.key_id().to_string()),
            sig: Some(to_hex(&sig)),
            ..Default::default()
        })
    }

    /// Answer one request line (the answer line ends with a newline).
    pub fn handle(&self, line: &[u8]) -> Vec<u8> {
        let req = match parse_request(line) {
            Ok(r) => r,
            Err(e) => return error_line(&Refusal::BadRequest(e).to_string()),
        };
        let res = match req {
            Request::Advance(m) => self.advance(&m).map(|_| ResponseJson {
                protocol: PROTOCOL.into(),
                ok: true,
                op: Some("advance".into()),
                held_seq: self.held(&m.unit).map(|h| h.seq),
                ..Default::default()
            }),
            Request::Current { unit, nonce } => self.current_reply(&unit, &nonce),
        };
        match res {
            Ok(r) => {
                let mut v = serde_json::to_vec(&r).unwrap_or_default();
                v.push(b'\n');
                v
            }
            Err(e) => error_line(&e.to_string()),
        }
    }

    fn connection(
        &self,
        s: TcpStream,
        io_timeout: Duration,
        tls: Option<Arc<rustls::ServerConfig>>,
        peer: SocketAddr,
    ) {
        let _ = s.set_nonblocking(false);
        let _ = s.set_nodelay(true);
        // Review F1: `io_timeout` bounds the request as a whole (TLS
        // handshake included): every read and write re-arms the socket
        // timeout with the time left, so a trickling peer is cut. Writing
        // the answer gets its own `io_timeout`.
        let deadline = Instant::now() + io_timeout;
        let answer = |r: Result<Vec<u8>, FrameError>| match r {
            Ok(line) => Some(self.handle(&line)),
            Err(FrameError::TooLarge) => {
                Some(error_line(&format!("request exceeds {MAX_FRAME} bytes")))
            }
            Err(_) => None,
        };
        match tls {
            None => {
                let mut s = DeadlineTcp::new(s);
                s.set_deadline(deadline);
                if let Some(a) = answer(read_frame(&mut s, deadline)) {
                    s.set_deadline(Instant::now() + io_timeout);
                    let _ = s.write_all(&a);
                    let _ = s.flush();
                }
            }
            Some(cfg) => {
                let mut t = match crate::tls::accept_server(s, cfg, deadline) {
                    Ok(t) => t,
                    Err(e) => {
                        // A failed handshake (no / unknown client
                        // certificate, plain TCP, scanner) never reaches
                        // the request parser.
                        let n = self.tls_failures.fetch_add(1, Ordering::Relaxed) + 1;
                        if n <= 16 || n.is_power_of_two() {
                            (self.log)(&format!(
                                "robodr-anchor-receiver: {peer}: {e} ({n} failed handshakes)"
                            ));
                        }
                        return;
                    }
                };
                if let Some(a) = answer(read_frame(&mut t, deadline)) {
                    t.sock.set_deadline(Instant::now() + io_timeout);
                    let _ = t.write_all(&a);
                    let _ = t.flush();
                }
                t.conn.send_close_notify();
                let _ = t.conn.complete_io(&mut t.sock);
            }
        }
    }

    /// Accept connections on `listener` until `stop` is set: one thread per
    /// connection, at most `opts.max_connections` at a time (further ones
    /// are closed at once), one request each.
    pub fn serve(
        self: &Arc<Self>,
        listener: TcpListener,
        opts: &ServeOptions,
        stop: &AtomicBool,
    ) -> io::Result<()> {
        type PerSource = Arc<Mutex<HashMap<std::net::IpAddr, usize>>>;
        struct Active(Arc<AtomicUsize>, PerSource, std::net::IpAddr);
        impl Drop for Active {
            fn drop(&mut self) {
                self.0.fetch_sub(1, Ordering::SeqCst);
                let mut m = lock(&self.1);
                if let Some(n) = m.get_mut(&self.2) {
                    *n = n.saturating_sub(1);
                    if *n == 0 {
                        m.remove(&self.2);
                    }
                }
            }
        }
        if opts.tls.is_none() && !opts.allow_plaintext {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "the anchor receiver serves TLS only unless plain TCP is explicitly allowed",
            ));
        }
        listener.set_nonblocking(true)?;
        let active = Arc::new(AtomicUsize::new(0));
        let per_source: PerSource = Arc::new(Mutex::new(HashMap::new()));
        let max = opts.max_connections.max(1);
        let max_src = opts.max_connections_per_source.max(1);
        let mut warned_full = false;
        while !stop.load(Ordering::SeqCst) {
            match listener.accept() {
                Ok((s, peer)) => {
                    if active.load(Ordering::SeqCst) >= max {
                        if !warned_full {
                            (self.log)(&format!(
                                "robodr-anchor-receiver: {max} connections open; closing new \
                                 ones (first: {peer})"
                            ));
                            warned_full = true;
                        }
                        drop(s);
                        continue;
                    }
                    warned_full = false;
                    let src = peer.ip();
                    {
                        let mut m = lock(&per_source);
                        let n = m.entry(src).or_insert(0);
                        if *n >= max_src {
                            drop(m);
                            drop(s);
                            continue;
                        }
                        *n += 1;
                    }
                    active.fetch_add(1, Ordering::SeqCst);
                    let guard = Active(Arc::clone(&active), Arc::clone(&per_source), src);
                    let me = Arc::clone(self);
                    let t = opts.io_timeout;
                    let tls = opts.tls.clone();
                    let r = std::thread::Builder::new()
                        .name("anchor-conn".into())
                        .spawn(move || {
                            let _g = guard;
                            me.connection(s, t, tls, peer);
                        });
                    if let Err(e) = r {
                        (self.log)(&format!("robodr-anchor-receiver: spawning: {e}"));
                    }
                }
                Err(e) if e.kind() == io::ErrorKind::WouldBlock => {
                    std::thread::sleep(Duration::from_millis(10));
                }
                Err(e) if e.kind() == io::ErrorKind::Interrupted => {}
                Err(e) => {
                    // EMFILE and friends: keep serving.
                    (self.log)(&format!("robodr-anchor-receiver: accept: {e}"));
                    std::thread::sleep(Duration::from_millis(100));
                }
            }
        }
        Ok(())
    }
}

fn unit_file(unit: &str) -> String {
    format!("{unit}.json")
}

fn create_private_dir(p: &Path) -> Result<(), String> {
    let mut b = fs::DirBuilder::new();
    b.recursive(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::DirBuilderExt;
        b.mode(0o700);
    }
    b.create(p).map_err(|e| format!("{}: {e}", p.display()))
}

fn append_synced(path: &Path, line: &[u8]) -> io::Result<()> {
    let mut o = OpenOptions::new();
    o.append(true).create(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        o.mode(0o600);
        o.custom_flags(crate::store::sys::O_NOFOLLOW);
    }
    let mut f = o.open(path)?;
    f.write_all(line)?;
    f.sync_data()
}

/// Read (without the lock: a running receiver may hold it) and verify the
/// stored state of `unit` under `state_dir`: the held mark and the alert
/// count.
pub fn read_unit_state(
    state_dir: &Path,
    unit: &str,
    v: &dyn Verifier,
) -> Result<(Option<RemoteMark>, u64), String> {
    if !valid_unit_id(unit) {
        return Err(format!("unit id {unit:?} is not valid"));
    }
    load_unit(&state_dir.join(UNITS_DIR), unit, v).map(|s| (s.held, s.alerts))
}

fn load_unit(udir: &Path, unit: &str, v: &dyn Verifier) -> Result<UnitState, String> {
    let name = unit_file(unit);
    let Some(s) = read_state(udir, &name).map_err(|e| e.to_string())? else {
        return Ok(UnitState::default());
    };
    let bad = |why: &str| format!("{}: {why}", udir.join(&name).display());
    let j: StateJson = serde_json::from_str(&s).map_err(|_| bad("unparseable"))?;
    if j.format != STATE_FORMAT {
        return Err(bad("unknown format"));
    }
    if j.unit != unit {
        return Err(bad("written for another unit"));
    }
    let held = match &j.mark {
        None => None,
        Some(m) => {
            let m = RemoteMark::from_json(m).map_err(|e| bad(&e))?;
            if m.unit != unit {
                return Err(bad("holds a mark of another unit"));
            }
            m.verify(v)
                .map_err(|e| bad(&format!("stored mark: {e} (unit key changed?)")))?;
            Some(m)
        }
    };
    Ok(UnitState {
        held,
        alerts: j.alerts,
        broken: None,
    })
}

// ---------------------------------------------------------------------------
// Client
// ---------------------------------------------------------------------------

/// Settings of a [`RemoteHeadAnchor`].
#[derive(Debug, Clone)]
pub struct RemoteAnchorConfig {
    /// Receiver `host:port` (an IP literal avoids DNS at open).
    pub address: String,
    /// This unit's id at the receiver (agentd: the robot id).
    pub unit: String,
    /// Bound on connect, on the TLS handshake, on write and on read, each.
    pub timeout: Duration,
    /// TLS to the receiver ([`crate::tls::load_client`]).
    pub tls: Option<crate::tls::ClientTls>,
    /// Use plain TCP when `tls` is `None` (default `false`:
    /// [`RemoteHeadAnchor::new`] refuses a configuration without TLS).
    pub allow_plaintext: bool,
}

impl RemoteAnchorConfig {
    /// [`DEFAULT_TIMEOUT`], no TLS and plain TCP not allowed: set
    /// [`Self::tls`] (or, for a lab, [`Self::allow_plaintext`]).
    pub fn new(address: impl Into<String>, unit: impl Into<String>) -> Self {
        Self {
            address: address.into(),
            unit: unit.into(),
            timeout: DEFAULT_TIMEOUT,
            tls: None,
            allow_plaintext: false,
        }
    }
}

#[derive(Default)]
struct Slot {
    pending: Option<RemoteMark>,
    /// A delivery failure not yet reported through `advance`.
    error: Option<String>,
    delivered: Option<u64>,
    failures: u64,
    shutdown: bool,
    worker_gone: bool,
    /// When the delivery attempt in progress started (backstop: one that
    /// outlives its bound, e.g. a hanging name lookup, is reported as a
    /// failure by `advance`).
    attempt_since: Option<Instant>,
    /// That overdue attempt was already counted.
    attempt_reported: bool,
}

struct Shared {
    slot: Mutex<Slot>,
    cv: Condvar,
}

enum SendError {
    Transport(String),
    Refused(String),
}

fn send_mark(cfg: &RemoteAnchorConfig, m: &RemoteMark) -> Result<(), SendError> {
    let raw = exchange(cfg, &m.to_request_line()).map_err(SendError::Transport)?;
    let r: ResponseJson = serde_json::from_slice(&raw)
        .map_err(|_| SendError::Transport("malformed answer".into()))?;
    if r.protocol != PROTOCOL {
        return Err(SendError::Transport("answer: unsupported protocol".into()));
    }
    if !r.ok {
        let e: String = r
            .error
            .unwrap_or_default()
            .chars()
            .map(|c| if c.is_control() { ' ' } else { c })
            .take(300)
            .collect();
        return Err(SendError::Refused(e));
    }
    Ok(())
}

fn worker(shared: Arc<Shared>, cfg: RemoteAnchorConfig, done: mpsc::Sender<()>) {
    let mut backoff = MIN_BACKOFF;
    loop {
        let mark = {
            let mut s = lock(&shared.slot);
            loop {
                if let Some(m) = &s.pending {
                    break m.clone();
                }
                if s.shutdown {
                    s.worker_gone = true;
                    shared.cv.notify_all();
                    drop(s);
                    let _ = done.send(());
                    return;
                }
                s = shared.cv.wait(s).unwrap_or_else(|p| p.into_inner());
            }
        };
        {
            let mut s = lock(&shared.slot);
            s.attempt_since = Some(Instant::now());
            s.attempt_reported = false;
        }
        let res = send_mark(&cfg, &mark);
        let mut s = lock(&shared.slot);
        s.attempt_since = None;
        let same = |s: &Slot| s.pending.as_ref().map(|p| p.seq) == Some(mark.seq);
        match res {
            Ok(()) => {
                if same(&s) {
                    s.pending = None;
                }
                s.delivered = Some(s.delivered.map_or(mark.seq, |d| d.max(mark.seq)));
                backoff = MIN_BACKOFF;
            }
            Err(SendError::Refused(e)) => {
                s.failures += 1;
                s.error = Some(format!("receiver refused mark seq {}: {e}", mark.seq));
                if same(&s) {
                    s.pending = None;
                }
            }
            Err(SendError::Transport(e)) => {
                s.failures += 1;
                s.error = Some(format!("delivering mark seq {}: {e}", mark.seq));
                if s.shutdown {
                    // Last attempt at drop failed: give up.
                    s.pending = None;
                } else {
                    shared.cv.notify_all();
                    let (g, _) = shared
                        .cv
                        .wait_timeout_while(s, backoff, |s| !s.shutdown && same(s))
                        .unwrap_or_else(|p| p.into_inner());
                    s = g;
                    backoff = (backoff * 2).min(MAX_BACKOFF);
                }
            }
        }
        shared.cv.notify_all();
        drop(s);
    }
}

/// [`HeadAnchor`] on a remote [`AnchorReceiver`]. See the module docs.
pub struct RemoteHeadAnchor {
    cfg: RemoteAnchorConfig,
    receiver_key: Box<dyn Verifier + Send + Sync>,
    signer: Mutex<Box<dyn Signer>>,
    shared: Arc<Shared>,
    done: Mutex<Option<mpsc::Receiver<()>>>,
}

impl fmt::Debug for RemoteHeadAnchor {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("RemoteHeadAnchor")
            .field("address", &self.cfg.address)
            .field("unit", &self.cfg.unit)
            .field("receiver_key_id", &self.receiver_key.key_id())
            .finish_non_exhaustive()
    }
}

impl RemoteHeadAnchor {
    /// Anchor at `cfg.address` for unit `cfg.unit`. `receiver_key` checks
    /// the receiver's answers; `signer` must be the recorder's key (it signs
    /// the marks and checks the held one) and must self-verify. Starts the
    /// delivery thread; does not touch the network.
    pub fn new(
        cfg: RemoteAnchorConfig,
        receiver_key: Box<dyn Verifier + Send + Sync>,
        signer: Box<dyn Signer>,
    ) -> Result<Self, Error> {
        check_address(&cfg.address).map_err(Error::Config)?;
        if !valid_unit_id(&cfg.unit) {
            return Err(Error::Config(format!(
                "remote anchor unit id {:?} must match [A-Za-z0-9._-]{{1,64}}",
                cfg.unit
            )));
        }
        if cfg.tls.is_none() && !cfg.allow_plaintext {
            return Err(Error::Config(
                "remote anchor: no TLS configured and plain TCP not explicitly allowed".into(),
            ));
        }
        if cfg.timeout.is_zero() || cfg.timeout > Duration::from_secs(60) {
            return Err(Error::Config(
                "remote anchor timeout must be in (0, 60 s]".into(),
            ));
        }
        let probe = b"robodr-blackbox/remote-anchor/self-test";
        if signer
            .sign(probe)
            .ok()
            .and_then(|s| signer.verify_own(probe, &s))
            != Some(true)
        {
            return Err(Error::Config(
                "the remote anchor needs a signer that can verify its own signatures".into(),
            ));
        }
        let shared = Arc::new(Shared {
            slot: Mutex::new(Slot::default()),
            cv: Condvar::new(),
        });
        let (tx, rx) = mpsc::channel();
        let (sh, c) = (Arc::clone(&shared), cfg.clone());
        std::thread::Builder::new()
            .name("remote-anchor".into())
            .spawn(move || worker(sh, c, tx))
            .map_err(|e| Error::Config(format!("remote anchor thread: {e}")))?;
        Ok(Self {
            cfg,
            receiver_key,
            signer: Mutex::new(signer),
            shared,
            done: Mutex::new(Some(rx)),
        })
    }

    /// Bounded steps of one exchange: connect, (TLS handshake,) write, read.
    fn steps(&self) -> u32 {
        if self.cfg.tls.is_some() {
            4
        } else {
            3
        }
    }

    /// Highest seq the receiver accepted from this process.
    pub fn delivered_seq(&self) -> Option<u64> {
        lock(&self.shared.slot).delivered
    }

    /// Delivery attempts that failed (transport or refusal).
    pub fn delivery_failures(&self) -> u64 {
        lock(&self.shared.slot).failures
    }

    /// Wait up to `wait` until no mark is pending; `true` if none is.
    pub fn flush(&self, wait: Duration) -> bool {
        let s = lock(&self.shared.slot);
        let (s, _) = self
            .shared
            .cv
            .wait_timeout_while(s, wait, |s| s.pending.is_some() && !s.worker_gone)
            .unwrap_or_else(|p| p.into_inner());
        s.pending.is_none()
    }

    /// Check a `current` answer (exposed for tests and tools).
    pub fn check_current_answer(
        &self,
        raw: &[u8],
        nonce: &[u8; NONCE_LEN],
    ) -> Result<Option<AnchoredHead>, String> {
        let signer = lock(&self.signer);
        check_current_answer(raw, &self.cfg.unit, nonce, &*self.receiver_key, &**signer)
    }
}

/// Check a `current` answer: protocol, unit, nonce, the receiver's
/// signature under `receiver_key`, then the held mark under the unit's own
/// `signer`.
pub fn check_current_answer(
    raw: &[u8],
    unit: &str,
    nonce: &[u8; NONCE_LEN],
    receiver_key: &dyn Verifier,
    signer: &dyn Signer,
) -> Result<Option<AnchoredHead>, String> {
    let r: ResponseJson =
        serde_json::from_slice(raw).map_err(|_| "remote anchor: malformed answer".to_string())?;
    if r.protocol != PROTOCOL {
        return Err("remote anchor: unsupported protocol".into());
    }
    if !r.ok {
        let e: String = r
            .error
            .unwrap_or_default()
            .chars()
            .map(|c| if c.is_control() { ' ' } else { c })
            .take(300)
            .collect();
        return Err(format!("remote anchor refused the query: {e}"));
    }
    if r.op.as_deref() != Some("current") || r.unit.as_deref() != Some(unit) {
        return Err("remote anchor: answer is not for this query".into());
    }
    if r.nonce.as_deref().and_then(parse_nonce) != Some(*nonce) {
        return Err("remote anchor: answer carries another nonce (replayed?)".into());
    }
    if r.receiver_key_id.as_deref() != Some(receiver_key.key_id()) {
        return Err(format!(
            "remote anchor: answer signed by key {:?}, expected {:?}",
            r.receiver_key_id.unwrap_or_default(),
            receiver_key.key_id()
        ));
    }
    let mark = match &r.mark {
        None => None,
        Some(j) => Some(RemoteMark::from_json(j).map_err(|e| format!("remote anchor: {e}"))?),
    };
    let sig = r
        .sig
        .as_deref()
        .and_then(|s| sig_from_hex(s, "sig").ok())
        .ok_or("remote anchor: answer is unsigned")?;
    if !receiver_key.verify(&reply_message(nonce, unit, mark.as_ref()), &sig) {
        return Err("remote anchor: receiver signature does not verify".into());
    }
    match mark {
        None => Ok(None),
        Some(m) => {
            if m.unit != unit {
                return Err("remote anchor: held mark is for another unit".into());
            }
            m.verify_own(signer)
                .map_err(|e| format!("remote anchor: {e}"))?;
            Ok(Some(m.anchored()))
        }
    }
}

impl HeadAnchor for RemoteHeadAnchor {
    /// Sign `mark` and queue it (replacing an unsent older one); never
    /// waits for the network. An `Err` reports a delivery failure of an
    /// earlier mark, or a mark that cannot be signed.
    fn advance(&self, mark: &Checkpoint) -> Result<(), String> {
        let m = {
            let signer = lock(&self.signer);
            RemoteMark::sign(&self.cfg.unit, mark, &**signer)?
        };
        let mut s = lock(&self.shared.slot);
        if s.worker_gone {
            return Err("remote anchor delivery thread has stopped".into());
        }
        s.pending = Some(m);
        self.shared.cv.notify_all();
        let bound = self.cfg.timeout * self.steps() + Duration::from_secs(1);
        if !s.attempt_reported
            && s.attempt_since
                .is_some_and(|t| t.elapsed() > bound && s.error.is_none())
        {
            s.attempt_reported = true;
            s.failures += 1;
            return Err(format!(
                "remote anchor {}: a delivery attempt has not finished within {} ms \
                 (name lookup or network stalled)",
                self.cfg.address,
                bound.as_millis()
            ));
        }
        match s.error.take() {
            Some(e) => Err(e),
            None => Ok(()),
        }
    }

    fn current(&self) -> Result<Option<AnchoredHead>, String> {
        let mut nonce = [0u8; NONCE_LEN];
        fill_random(&mut nonce).map_err(|e| format!("remote anchor nonce: {e}"))?;
        let line = current_request_line(&self.cfg.unit, &nonce);
        let (tx, rx) = mpsc::channel();
        let cfg = self.cfg.clone();
        std::thread::Builder::new()
            .name("remote-anchor-q".into())
            .spawn(move || {
                let _ = tx.send(exchange(&cfg, &line));
            })
            .map_err(|e| format!("remote anchor: {e}"))?;
        let bound = self.cfg.timeout * self.steps() + Duration::from_millis(100);
        let raw = rx
            .recv_timeout(bound)
            .map_err(|_| {
                format!(
                    "remote anchor {}: no answer within {} ms",
                    self.cfg.address,
                    bound.as_millis()
                )
            })?
            .map_err(|e| format!("remote anchor: {e}"))?;
        self.check_current_answer(&raw, &nonce)
    }
}

impl Drop for RemoteHeadAnchor {
    fn drop(&mut self) {
        {
            let mut s = lock(&self.shared.slot);
            s.shutdown = true;
            self.shared.cv.notify_all();
        }
        // One last bounded delivery attempt of a pending mark.
        if let Some(rx) = lock(&self.done).take() {
            let _ = rx.recv_timeout(self.cfg.timeout * self.steps() + Duration::from_millis(200));
        }
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::sign::HmacSha256Key;
    use crate::sign_ed25519::Ed25519SigningKey;

    struct TmpDir(PathBuf);
    impl TmpDir {
        fn new(tag: &str) -> Self {
            static N: AtomicUsize = AtomicUsize::new(0);
            let p = std::env::temp_dir().join(format!(
                "robodr-bb-ra-{tag}-{}-{}",
                std::process::id(),
                N.fetch_add(1, Ordering::Relaxed)
            ));
            let _ = fs::remove_dir_all(&p);
            fs::create_dir_all(&p).unwrap();
            TmpDir(p)
        }
    }
    impl Drop for TmpDir {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }

    fn unit_key() -> Ed25519SigningKey {
        Ed25519SigningKey::from_seed("unit-bb", &[7; 32]).unwrap()
    }
    fn receiver_key() -> Ed25519SigningKey {
        Ed25519SigningKey::from_seed("receiver", &[9; 32]).unwrap()
    }

    /// A checkpoint whose record signature is genuine.
    fn cp(seq: u64, chain: u8) -> Checkpoint {
        let k = unit_key();
        let hash = [seq as u8 ^ chain; 32];
        Checkpoint {
            chain_id: [chain; 32],
            seq,
            hash,
            key_id: "unit-bb".into(),
            sig: k.sign(&signing_message(&hash)).unwrap(),
        }
    }
    fn mark(seq: u64, chain: u8) -> RemoteMark {
        RemoteMark::sign("ugv-07", &cp(seq, chain), &unit_key()).unwrap()
    }

    fn quiet() -> Option<LogFn> {
        Some(Box::new(|_m: &str| {}))
    }

    fn receiver(dir: &Path) -> AnchorReceiver {
        AnchorReceiver::open(
            dir,
            vec![UnitKey {
                unit: "ugv-07".into(),
                verifier: Box::new(unit_key().verifying_key()),
            }],
            Box::new(receiver_key()),
            quiet(),
        )
        .unwrap()
    }

    fn alerts(dir: &Path) -> Vec<serde_json::Value> {
        fs::read_to_string(dir.join(ALERTS_FILE))
            .unwrap_or_default()
            .lines()
            .map(|l| serde_json::from_str(l).unwrap())
            .collect()
    }

    #[test]
    fn unit_ids_and_addresses() {
        assert!(valid_unit_id("ugv-07"));
        assert!(valid_unit_id("a.b_c-1"));
        for bad in ["", ".", "..", ".x", "a/b", "a b", "x".repeat(65).as_str()] {
            assert!(!valid_unit_id(bad), "{bad}");
        }
        for ok in ["127.0.0.1:7461", "base.local:1", "[::1]:7461"] {
            assert!(check_address(ok).is_ok(), "{ok}");
        }
        for bad in [
            "",
            "host",
            "host:0",
            "host:70000",
            ":1",
            "::1:7461",
            "a b:1",
            "[x]:1",
        ] {
            assert!(check_address(bad).is_err(), "{bad}");
        }
    }

    #[test]
    fn mark_signature_binds_seq_chain_and_unit() {
        let k = unit_key();
        let v = k.verifying_key();
        let m = mark(5, 1);
        m.verify(&v).unwrap();
        m.verify_own(&k).unwrap();
        let mut bad = m.clone();
        bad.seq = 6;
        assert!(bad.verify(&v).unwrap_err().contains("mark signature"));
        let mut bad = m.clone();
        bad.chain_id = [2; 32];
        assert!(bad.verify(&v).is_err());
        let mut bad = m.clone();
        bad.unit = "ugv-08".into();
        assert!(bad.verify(&v).is_err());
        let mut bad = m.clone();
        bad.hash = [0; 32];
        assert!(bad.verify(&v).unwrap_err().contains("record signature"));
        let other = Ed25519SigningKey::from_seed("unit-bb", &[8; 32]).unwrap();
        assert!(m.verify(&other.verifying_key()).is_err());
        assert!(m.verify_own(&other).is_err());
        // A checkpoint of another key is refused at signing.
        let mut c = cp(1, 1);
        c.key_id = "other".into();
        assert!(RemoteMark::sign("ugv-07", &c, &k).is_err());
        assert!(RemoteMark::sign("bad unit", &cp(1, 1), &k).is_err());
        // Wire round trip.
        let line = m.to_request_line();
        assert_eq!(RemoteMark::from_request_line(line.as_bytes()).unwrap(), m);
    }

    #[test]
    fn receiver_rule_lower_fork_chain_change_and_persistence() {
        let d = TmpDir::new("rule");
        let r = receiver(&d.0);
        assert_eq!(
            r.advance(&mark(10, 1)),
            Ok(Advanced::Stored { previous: None })
        );
        assert_eq!(r.advance(&mark(10, 1)), Ok(Advanced::Duplicate));
        assert_eq!(
            r.advance(&mark(20, 1)),
            Ok(Advanced::Stored { previous: Some(10) })
        );
        // Lower (replay or rollback): refused, alert.
        assert_eq!(
            r.advance(&mark(10, 1)),
            Err(Refusal::Lower {
                held: 20,
                offered: 10
            })
        );
        // Fork: same seq, other chain (other hash too).
        assert_eq!(r.advance(&mark(20, 2)), Err(Refusal::Fork { seq: 20 }));
        assert_eq!(r.held("ugv-07").unwrap().seq, 20);
        // A higher seq of a new chain: stored, with an alert.
        assert!(r.advance(&mark(30, 2)).is_ok());
        assert_eq!(r.held("ugv-07").unwrap().chain_id, [2; 32]);
        // Forged mark: alert, refused.
        let mut f = mark(40, 2);
        f.seq = 1_000_000;
        assert!(matches!(r.advance(&f), Err(Refusal::BadSignature(_))));
        let mut other = mark(50, 2);
        other.unit = "ugv-99".into();
        assert!(matches!(r.advance(&other), Err(Refusal::UnknownUnit(_))));
        assert_eq!(r.alerts("ugv-07"), 4);
        let kinds: Vec<String> = alerts(&d.0)
            .iter()
            .map(|a| a["kind"].as_str().unwrap().to_string())
            .collect();
        assert_eq!(kinds, ["lower", "fork", "chain_change", "bad_signature"]);
        drop(r);

        // Restart: the mark and the count survive.
        let r = receiver(&d.0);
        assert_eq!(r.held("ugv-07"), Some(mark(30, 2)));
        assert_eq!(r.alerts("ugv-07"), 4);
        assert_eq!(
            r.advance(&mark(29, 2)),
            Err(Refusal::Lower {
                held: 30,
                offered: 29
            })
        );
        // A second instance on the same directory is refused.
        let e = AnchorReceiver::open(
            &d.0,
            vec![UnitKey {
                unit: "ugv-07".into(),
                verifier: Box::new(unit_key().verifying_key()),
            }],
            Box::new(receiver_key()),
            quiet(),
        )
        .unwrap_err();
        assert!(e.contains("another receiver"), "{e}");
    }

    #[test]
    fn tampered_or_foreign_state_breaks_the_unit_and_is_never_reset() {
        let d = TmpDir::new("tamper");
        let r = receiver(&d.0);
        r.advance(&mark(20, 1)).unwrap();
        drop(r);
        let p = d.0.join(UNITS_DIR).join("ugv-07.json");
        let mut j: serde_json::Value = serde_json::from_slice(&fs::read(&p).unwrap()).unwrap();
        j["mark"]["seq"] = 5.into();
        fs::write(&p, j.to_string()).unwrap();
        let r = receiver(&d.0);
        assert!(r.broken("ugv-07").unwrap().contains("does not verify"));
        assert!(matches!(r.advance(&mark(30, 1)), Err(Refusal::Broken(_))));
        let ans = r.handle(current_request_line("ugv-07", &[1; 32]).as_bytes());
        assert!(String::from_utf8_lossy(&ans).contains("operator action"));
        // The file is kept as found.
        assert!(fs::read_to_string(&p).unwrap().contains("\"seq\":5"));
        assert!(alerts(&d.0).iter().any(|a| a["kind"] == "state_unusable"));
        drop(r);
        fs::write(&p, b"{garbage").unwrap();
        assert!(receiver(&d.0)
            .broken("ugv-07")
            .unwrap()
            .contains("unparseable"));
    }

    fn client_parts() -> (Ed25519SigningKey, Ed25519SigningKey) {
        (unit_key(), receiver_key())
    }

    #[test]
    fn current_answer_is_authenticated_by_nonce_and_receiver_key() {
        let d = TmpDir::new("answer");
        let r = receiver(&d.0);
        let (uk, rk) = client_parts();
        let rv = rk.verifying_key();
        let n1 = [1u8; NONCE_LEN];
        // No mark yet: an authenticated "none".
        let a = r.handle(current_request_line("ugv-07", &n1).as_bytes());
        assert_eq!(
            check_current_answer(a.trim_ascii_end(), "ugv-07", &n1, &rv, &uk),
            Ok(None)
        );
        r.advance(&mark(10, 1)).unwrap();
        let old = r.handle(current_request_line("ugv-07", &n1).as_bytes());
        r.advance(&mark(20, 1)).unwrap();
        let n2 = [2u8; NONCE_LEN];
        let a = r.handle(current_request_line("ugv-07", &n2).as_bytes());
        let h = check_current_answer(a.trim_ascii_end(), "ugv-07", &n2, &rv, &uk)
            .unwrap()
            .unwrap();
        assert_eq!(h.seq, 20);
        // Replay of an older genuine answer (lower mark): nonce mismatch.
        let e = check_current_answer(old.trim_ascii_end(), "ugv-07", &n2, &rv, &uk).unwrap_err();
        assert!(e.contains("nonce"), "{e}");
        // Another receiver key.
        let wrong = Ed25519SigningKey::from_seed("receiver", &[3; 32]).unwrap();
        let e = check_current_answer(
            a.trim_ascii_end(),
            "ugv-07",
            &n2,
            &wrong.verifying_key(),
            &uk,
        )
        .unwrap_err();
        assert!(e.contains("receiver signature"), "{e}");
        // A MITM swaps in a lower genuine mark (or drops it): signature fails.
        let mut j: serde_json::Value = serde_json::from_slice(a.trim_ascii_end()).unwrap();
        let low: serde_json::Value = serde_json::from_str(&mark(10, 1).to_request_line()).unwrap();
        j["mark"] = low["mark"].clone();
        let e =
            check_current_answer(j.to_string().as_bytes(), "ugv-07", &n2, &rv, &uk).unwrap_err();
        assert!(e.contains("receiver signature"), "{e}");
        j.as_object_mut().unwrap().remove("mark");
        assert!(check_current_answer(j.to_string().as_bytes(), "ugv-07", &n2, &rv, &uk).is_err());
        // A receiver that signs a mark the unit never made: the unit's own
        // check refuses it.
        let other_unit = Ed25519SigningKey::from_seed("unit-bb", &[4; 32]).unwrap();
        let e =
            check_current_answer(a.trim_ascii_end(), "ugv-07", &n2, &rv, &other_unit).unwrap_err();
        assert!(e.contains("not signed by this unit"), "{e}");
        // Another unit's query.
        assert!(check_current_answer(a.trim_ascii_end(), "ugv-08", &n2, &rv, &uk).is_err());
        // Refusals and garbage.
        let a = r.handle(current_request_line("ugv-99", &n2).as_bytes());
        assert!(
            check_current_answer(a.trim_ascii_end(), "ugv-99", &n2, &rv, &uk)
                .unwrap_err()
                .contains("unknown unit")
        );
        assert!(check_current_answer(b"{", "ugv-07", &n2, &rv, &uk).is_err());
    }

    #[test]
    fn malformed_and_oversize_requests_are_refused() {
        let d = TmpDir::new("frames");
        let r = receiver(&d.0);
        let n = to_hex(&[1; NONCE_LEN]);
        for bad in [
            "{".to_string(),
            format!(
                r#"{{"protocol":"robodr-anchor/v2","op":"current","unit":"ugv-07","nonce":"{n}"}}"#
            ),
            r#"{"protocol":"robodr-anchor/v1","op":"current","unit":"ugv-07","nonce":"00"}"#.into(),
            format!(
                r#"{{"protocol":"robodr-anchor/v1","op":"current","unit":"../x","nonce":"{n}"}}"#
            ),
            r#"{"protocol":"robodr-anchor/v1","op":"delete","unit":"ugv-07"}"#.into(),
            format!(
                r#"{{"protocol":"robodr-anchor/v1","op":"current","unit":"ugv-07","nonce":"{n}","x":1}}"#
            ),
            format!(
                r#"{{"protocol":"robodr-anchor/v1","op":"advance","unit":"ugv-07","nonce":"{n}"}}"#
            ),
        ] {
            let bad = bad.as_bytes();
            let a = r.handle(bad);
            let j: serde_json::Value = serde_json::from_slice(&a).unwrap();
            assert_eq!(j["ok"], false, "{}", String::from_utf8_lossy(bad));
        }
        let big = vec![b'x'; MAX_FRAME + 1];
        assert!(String::from_utf8_lossy(&r.handle(&big)).contains("exceeds"));
        // Frames: an endless line is cut at the bound, a slow peer times out.
        let mut endless = io::repeat(b'a');
        assert_eq!(
            read_frame(&mut endless, Instant::now() + Duration::from_secs(5)),
            Err(FrameError::TooLarge)
        );
        let mut empty: &[u8] = b"no newline";
        assert_eq!(
            read_frame(&mut empty, Instant::now() + Duration::from_secs(5)),
            Err(FrameError::Eof)
        );
        let mut ok: &[u8] = b"line\nrest";
        assert_eq!(
            read_frame(&mut ok, Instant::now() + Duration::from_secs(5)),
            Ok(b"line".to_vec())
        );
    }

    struct Server {
        addr: SocketAddr,
        stop: Arc<AtomicBool>,
        recv: Arc<AnchorReceiver>,
        th: Option<std::thread::JoinHandle<()>>,
    }
    impl Drop for Server {
        fn drop(&mut self) {
            self.stop.store(true, Ordering::SeqCst);
            if let Some(t) = self.th.take() {
                let _ = t.join();
            }
        }
    }
    fn serve_at(dir: &Path, io_timeout: Duration, addr: &str) -> Server {
        let recv = Arc::new(receiver(dir));
        let l = TcpListener::bind(addr).unwrap();
        let a = l.local_addr().unwrap();
        let stop = Arc::new(AtomicBool::new(false));
        let (r2, s2) = (Arc::clone(&recv), Arc::clone(&stop));
        let th = std::thread::spawn(move || {
            r2.serve(
                l,
                &ServeOptions {
                    max_connections: 4,
                    io_timeout,
                    tls: None,
                    allow_plaintext: true,
                    ..ServeOptions::default()
                },
                &s2,
            )
            .unwrap();
        });
        Server {
            addr: a,
            stop,
            recv,
            th: Some(th),
        }
    }

    fn client(addr: &str, timeout: Duration) -> RemoteHeadAnchor {
        let mut c = RemoteAnchorConfig::new(addr, "ugv-07");
        c.timeout = timeout;
        c.allow_plaintext = true;
        RemoteHeadAnchor::new(
            c,
            Box::new(receiver_key().verifying_key()),
            Box::new(unit_key()),
        )
        .unwrap()
    }

    #[test]
    fn client_round_trip_over_tcp_and_coalescing() {
        let d = TmpDir::new("tcp");
        let s = serve_at(&d.0, Duration::from_secs(2), "127.0.0.1:0");
        let c = client(&s.addr.to_string(), Duration::from_secs(2));
        assert_eq!(c.current(), Ok(None));
        for seq in 1..=50 {
            c.advance(&cp(seq, 1)).unwrap();
        }
        assert!(c.flush(Duration::from_secs(10)));
        assert_eq!(c.delivered_seq(), Some(50));
        assert_eq!(s.recv.held("ugv-07").unwrap().seq, 50);
        let h = c.current().unwrap().unwrap();
        assert_eq!((h.seq, h.chain_id), (50, Some([1; 32])));
        // A refused mark (lower) is reported by the next advance, not retried.
        c.advance(&cp(10, 1)).unwrap();
        assert!(c.flush(Duration::from_secs(10)));
        let e = c.advance(&cp(60, 1)).unwrap_err();
        assert!(e.contains("refused") && e.contains("lower"), "{e}");
        assert!(c.flush(Duration::from_secs(10)));
        assert_eq!(s.recv.held("ugv-07").unwrap().seq, 60);
        // Drop delivers the last pending mark.
        c.advance(&cp(70, 1)).unwrap();
        drop(c);
        assert_eq!(s.recv.held("ugv-07").unwrap().seq, 70);
    }

    #[test]
    fn unreachable_or_silent_receiver_never_blocks_advance_and_bounds_current() {
        // Nothing listens on a port we just closed.
        let port = {
            let l = TcpListener::bind("127.0.0.1:0").unwrap();
            l.local_addr().unwrap().port()
        };
        let c = client(&format!("127.0.0.1:{port}"), Duration::from_millis(300));
        let t = Instant::now();
        for seq in 1..=100 {
            let _ = c.advance(&cp(seq, 1));
        }
        assert!(t.elapsed() < Duration::from_secs(1), "{:?}", t.elapsed());
        assert!(c.current().is_err());
        std::thread::sleep(Duration::from_millis(300));
        assert!(c.delivery_failures() > 0);
        assert!(c.advance(&cp(101, 1)).is_err(), "the failure is reported");
        drop(c);

        // A peer that accepts and never answers.
        let l = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = l.local_addr().unwrap();
        let hold = std::thread::spawn(move || {
            let conn = l.accept().ok();
            std::thread::sleep(Duration::from_secs(2));
            drop(conn);
        });
        let c = client(&addr.to_string(), Duration::from_millis(300));
        let t = Instant::now();
        let e = c.current().unwrap_err();
        assert!(t.elapsed() < Duration::from_secs(2), "{:?}", t.elapsed());
        assert!(e.contains("timed out") || e.contains("no answer"), "{e}");
        drop(c);
        let _ = hold.join();
    }

    #[test]
    fn receiver_drops_slow_and_oversize_peers() {
        let d = TmpDir::new("slow");
        let s = serve_at(&d.0, Duration::from_millis(300), "127.0.0.1:0");
        // Slow peer: connects, sends nothing; the receiver closes it.
        let mut slow = TcpStream::connect(s.addr).unwrap();
        slow.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
        let t = Instant::now();
        let mut b = [0u8; 16];
        assert_eq!(slow.read(&mut b).unwrap_or(0), 0);
        assert!(t.elapsed() < Duration::from_secs(4));
        // Oversize request: an error answer, then close.
        let mut big = TcpStream::connect(s.addr).unwrap();
        big.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
        let _ = big.write_all(&vec![b'x'; MAX_FRAME + 10]);
        let a = read_frame(&mut big, Instant::now() + Duration::from_secs(5)).unwrap();
        assert!(String::from_utf8_lossy(&a).contains("exceeds"));
        // It still serves.
        let c = client(&s.addr.to_string(), Duration::from_secs(2));
        assert_eq!(c.current(), Ok(None));
    }

    #[test]
    fn hmac_units_work_in_the_library_and_bad_configs_are_refused() {
        let d = TmpDir::new("cfg");
        let k = || HmacSha256Key::new("u", &[1; 32]).unwrap();
        assert!(AnchorReceiver::open(&d.0, vec![], Box::new(receiver_key()), quiet()).is_err());
        let two = vec![
            UnitKey {
                unit: "a".into(),
                verifier: Box::new(k()),
            },
            UnitKey {
                unit: "a".into(),
                verifier: Box::new(k()),
            },
        ];
        assert!(AnchorReceiver::open(&d.0, two, Box::new(receiver_key()), quiet()).is_err());
        let bad = vec![UnitKey {
            unit: "../a".into(),
            verifier: Box::new(k()),
        }];
        assert!(AnchorReceiver::open(&d.0, bad, Box::new(receiver_key()), quiet()).is_err());
        let rv = || Box::new(receiver_key().verifying_key());
        let mk = |a: &str, t: Duration| {
            let mut c = RemoteAnchorConfig::new(a, "ugv-07");
            c.timeout = t;
            c.allow_plaintext = true;
            RemoteHeadAnchor::new(c, rv(), Box::new(k()))
        };
        assert!(mk("127.0.0.1:1", Duration::from_secs(1)).is_ok());
        assert!(mk("nohost", Duration::from_secs(1)).is_err());
        assert!(mk("127.0.0.1:1", Duration::ZERO).is_err());
        assert!(mk("127.0.0.1:1", Duration::from_secs(61)).is_err());
    }
}
