//! `robodr-uplink`: findings to the AutoSecOps ingest API
//! (`docs/contracts/robodr.ingest-api.md`, contract v1, producer side).
//!
//! # Input
//!
//! The same two inputs as `robodr-kafka-publish` ([`crate::publish`]):
//!
//! * an agentd spool (`ready/` → `acked/`), on a connected robot or sensor
//!   box; per-finding signatures (`robodr-finding-sig`, contract
//!   `robodr.findings` §2a) are carried in the line's `sig`;
//! * the diode importer's `out/<batch>/records.jsonl` (SOC side of an
//!   air-gapped site). The diode does not carry per-finding signatures
//!   (`robodr.findings` §8, open item), so these lines have `"sig":null`;
//!   their origin is proven by the diode batch signature the importer
//!   verified, and the SOC registers this sender as a `relay` key.
//!
//! Every record is re-validated exactly as the Kafka publisher does
//! ([`crate::publish::check_record`]: value, key, topic, derived headers, the
//! signature header's shape and position; unsigned contract 1.x upgraded,
//! signed 1.x refused). A record that fails is dead-lettered locally
//! (`code: "local"`) and never sent.
//!
//! # Batches and batch ids
//!
//! Records are cut, in input order, into batches of at most
//! [`UplinkConfig::max_lines`] lines and [`UplinkConfig::max_body_bytes`]
//! bytes (contract maxima 1000 / 4 MiB); a diode batch is never mixed with
//! another one. The batch id ([`wire::batch_id`]) is a hash of the input
//! stream name, the input positions of the lines and the body, so it is the
//! same whenever the same records are cut into the same body, and two
//! different bodies never share an id.
//!
//! # Delivery (at-least-once, crash-safe)
//!
//! `<state>/uplink-state.json` (atomic replace) holds the per-diode-batch
//! committed line counts and at most one **pending** batch:
//!
//! 1. Cut a batch; save `pending = {batch_id, source, last, positions,
//!    body_sha256}`.
//! 2. `POST` it; retry on network errors, `408`, `429` and `5xx` with the
//!    same body and batch id and a fresh timestamp and signature
//!    (exponential backoff with jitter, never sooner than `Retry-After`).
//! 3. On a `200` whose response accounts for every line
//!    ([`wire::IngestResponse::parse_checked`]): save the rejected lines into
//!    `pending.result`; append them to `<state>/dead-letter.jsonl` with the
//!    server's code (deduplicated on (source, position)); acknowledge the
//!    batch (diode: committed line count; spool: rename `ready/` → `acked/`,
//!    rejected ones → `rejected/`); clear `pending`.
//!
//! After a crash, a pending batch **without** a result is rebuilt from the
//! same input positions; if the rebuilt body has the recorded SHA-256 it is
//! re-sent under the **same** batch id (the server answers a known batch id
//! with its stored response, `replayed: true`), otherwise (input or
//! configuration changed) it is dropped and the records are cut afresh under
//! a new id (the server then reports them as `duplicate`s: never a loss, no
//! double case). A pending batch **with** a result is finished idempotently.
//! Nothing leaves the input before a `200` named it accepted or rejected.
//!
//! A `413` halves the line cap for the rest of the run and re-cuts (nothing
//! was processed); a single-line `413` stops. Any other `4xx` (`400`, `401`,
//! `409`, `415`, ...) stops the run without acknowledging anything; the
//! caller retries later with the same pending batch.
//!
//! # Retention
//!
//! After every successful run ([`crate::retention`]): a `done/` marker over
//! [`UplinkConfig::done_retention`] is deleted only once its batch has left
//! `out/`; a rotated dead-letter file past the rotation's `keep` or over
//! [`UplinkConfig::dead_letter_retention`] is deleted only when none of its
//! entries can still be needed for deduplication: a diode entry while its
//! batch is in `out/` without a `done/` marker, a spool entry while its
//! file is in `ready/`, a re-injected entry while its generation is not
//! done (see [`crate::deadletter`]). What is held is reported and looked at
//! again on the next run. Deleted dead letters can no longer be
//! re-injected (`reinject` reads the files present).
//!
//! Opt-in, kept by default: [`UplinkConfig::out_retention`] (diode source,
//! sole consumer of `out/` only) deletes the payload of finished `out/`
//! batches, leaving tombstones ([`crate::retention::prune_diode_out`]), [`UplinkConfig::rejected_retention`]
//! (spool source) bounds `<spool>/rejected/`
//! ([`crate::spool_export::prune_rejected`]), and
//! [`UplinkConfig::reinject_retention`] deletes the `records.jsonl` of
//! finished re-injection generations while their ledger (`origin.jsonl`,
//! `done`) stays ([`crate::retention::prune_reinject_payloads`]). A record
//! whose original copy was pruned is re-injected from its dead letter's
//! `record` copy. The status file's `state_usage` gives the entries and
//! bytes of each (measured at most every [`UplinkConfig::usage_interval`]).

pub mod check;
pub mod http;
pub mod reinject;
pub mod service;
pub mod wire;

use crate::deadletter::{DeadLetters, Rotation};
use crate::fsutil::{self, ReadError};
use crate::publish::{
    check_record, list_diode_batches, list_ready, read_spool_item, LineReader, OpenRecordsError,
    Source, MAX_IN_FLIGHT,
};
use crate::retention::{PruneReport, Retention};
use http::{HttpRequest, Transport};
use robodr_blackbox::crypto::{sha256, to_hex};
use robodr_blackbox::sign_ed25519::{derive_key_id, Ed25519SigningKey};
use robodr_blackbox::{KeyFile, Signer};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, HashSet, VecDeque};
use std::fmt;
use std::fs;
use std::io;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;
use wire::{IngestResponse, RejectedLine};

const STATE_FORMAT: &str = "robodr-uplink-state/1";
pub const STATE_FILE: &str = "uplink-state.json";
pub const DONE_DIR: &str = "done";
pub const DEAD_LETTER_FILE: &str = "dead-letter.jsonl";
/// Lock file of a state directory (`flock`, held for the process lifetime).
pub const LOCK_FILE: &str = "uplink.lock";
/// Directory of re-injected record streams ([`reinject`]).
pub const REINJECT_DIR: &str = "reinject";
/// Smallest dead-letter rotation size (a single larger entry is still
/// written whole: rotation happens before an append, never inside one).
pub const MIN_DEAD_LETTER_BYTES: u64 = crate::deadletter::MIN_ROTATION_BYTES;
/// Default dead-letter rotation: 64 MiB per file, 4 rotated files kept.
pub const DEFAULT_DEAD_LETTER_ROTATION: Rotation = crate::deadletter::DEFAULT_ROTATION;
/// Dead-letter code of a record refused by the local validation.
pub const LOCAL_CODE: &str = "local";
/// Smallest `max_body_bytes`: a single maximal line (64 KiB value, every
/// byte escaped as `\u00XX`, plus a signature) always fits.
pub const MIN_BODY_BYTES: usize = 1024 * 1024;

/// Longest `Retry-After` honoured (contract §7): a server value above it is
/// treated as this bound (an absurd value must not park the uplink for
/// years); anything up to it is honoured in full, never shortened.
pub const MAX_RETRY_AFTER: Duration = Duration::from_secs(24 * 3600);

/// Retry and backoff settings for one batch within one run.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RetryPolicy {
    /// Requests per batch per run (≥ 1); then the run fails and the caller
    /// retries later (the batch stays pending).
    pub max_attempts: u32,
    /// First backoff step.
    pub base: Duration,
    /// Backoff cap (a `Retry-After` may be longer: it wins).
    pub max: Duration,
}

impl Default for RetryPolicy {
    fn default() -> Self {
        Self {
            max_attempts: 6,
            base: Duration::from_millis(500),
            max: Duration::from_secs(60),
        }
    }
}

/// Exponential backoff with "equal jitter": before retry number `retry`
/// (1-based), wait a uniformly random time in `[d/2, d]`,
/// `d = min(max, base · 2^(retry-1))`. `rand` is a random 64-bit value.
pub fn backoff_delay(p: &RetryPolicy, retry: u32, rand: u64) -> Duration {
    let base = p.base.as_millis() as u64;
    let cap = p.max.as_millis() as u64;
    let shift = retry.saturating_sub(1).min(32);
    let d = base.saturating_mul(1u64 << shift).min(cap);
    let half = d / 2;
    Duration::from_millis(half + rand % (d - half + 1))
}

/// `Retry-After` as delay-seconds (contract §2.4; the HTTP-date form is not
/// used by the contract and is ignored). Any number of digits is a valid
/// delay: values too large for a `u64` saturate (and are then honoured as
/// [`MAX_RETRY_AFTER`]); they are never ignored, which would retry sooner.
pub fn parse_retry_after(v: &str) -> Option<Duration> {
    let v = v.trim();
    if v.is_empty() || !v.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    Some(Duration::from_secs(v.parse::<u64>().unwrap_or(u64::MAX)))
}

/// A server `Retry-After` as the producer honours it: in full, values over
/// [`MAX_RETRY_AFTER`] treated as that bound.
pub fn honoured_retry_after(ra: Duration) -> Duration {
    ra.min(MAX_RETRY_AFTER)
}

/// The wait before retry number `retry`: the backoff, but never sooner than
/// the server's `Retry-After` ([`honoured_retry_after`]).
pub fn retry_delay(
    p: &RetryPolicy,
    retry: u32,
    retry_after: Option<Duration>,
    rand: u64,
) -> Duration {
    let b = backoff_delay(p, retry, rand);
    match retry_after {
        Some(ra) => b.max(honoured_retry_after(ra)),
        None => b,
    }
}

/// Uplink settings.
#[derive(Debug, Clone)]
pub struct UplinkConfig {
    pub source: Source,
    /// State file, done markers, dead letters.
    pub state_dir: PathBuf,
    /// Lines per batch (1..=1000).
    pub max_lines: usize,
    /// Body bytes per batch ([`MIN_BODY_BYTES`]..=4 MiB).
    pub max_body_bytes: usize,
    /// Longest input line / spool file accepted.
    pub max_record_bytes: usize,
    /// `data_source` an unsigned contract 1.x record gets when upgraded.
    pub upgrade_data_source: String,
    /// Topic (`ocsf.metadata.log_name`) an upgraded 1.x record names.
    pub upgrade_topic: String,
    pub retry: RetryPolicy,
    /// Dead-letter rotation (`None`: one growing file).
    pub dead_letter_rotation: Option<Rotation>,
    /// Further bounds on rotated dead-letter files (default none beyond
    /// the rotation's `keep`); see "Retention" in the module docs.
    pub dead_letter_retention: Retention,
    /// Bounds on `done/` markers (default
    /// [`crate::publish::DEFAULT_DONE_RETENTION`]: 30 days).
    pub done_retention: Retention,
    /// Bounds on the importer's `out/` batch directories this uplink has
    /// finished (default: unbounded, kept); only when it is the sole
    /// consumer of `out/` ([`crate::retention::prune_diode_out`]).
    pub out_retention: Retention,
    /// Bounds on `<spool>/rejected/` (spool source; default: unbounded),
    /// as `robodr-spool-export`'s ([`crate::spool_export::prune_rejected`]).
    pub rejected_retention: Retention,
    /// Bounds on the `records.jsonl` of finished re-injection generations
    /// (default: unbounded; the ledger stays,
    /// [`crate::retention::prune_reinject_payloads`]).
    pub reinject_retention: Retention,
    /// How often the state's disk usage is measured for the status file
    /// ([`service::Snapshot::state_usage`]; default 60 s).
    pub usage_interval: Duration,
    /// Test hook: fail with [`UplinkError::Injected`] at this point (once).
    #[doc(hidden)]
    pub fail_point: Option<FailPoint>,
}

impl UplinkConfig {
    pub fn new(source: Source, state_dir: impl Into<PathBuf>) -> Self {
        Self {
            source,
            state_dir: state_dir.into(),
            max_lines: wire::MAX_LINES,
            max_body_bytes: wire::MAX_BODY_BYTES,
            max_record_bytes: 1024 * 1024,
            upgrade_data_source: robodr_ocsf::DEFAULT_DATA_SOURCE.into(),
            upgrade_topic: robodr_ocsf::DEFAULT_TOPIC.into(),
            retry: RetryPolicy::default(),
            dead_letter_rotation: Some(DEFAULT_DEAD_LETTER_ROTATION),
            dead_letter_retention: Retention::UNBOUNDED,
            done_retention: crate::publish::DEFAULT_DONE_RETENTION,
            out_retention: Retention::UNBOUNDED,
            rejected_retention: Retention::UNBOUNDED,
            reinject_retention: Retention::UNBOUNDED,
            usage_interval: Duration::from_secs(60),
            fail_point: None,
        }
    }

    /// The static checks of [`Uplink::open`] (ranges, labels, retry
    /// policy, rotation): a caller can refuse a bad configuration at start
    /// (usage error) instead of failing every run.
    pub fn validate(&self) -> Result<(), UplinkError> {
        if !(1..=wire::MAX_LINES).contains(&self.max_lines) {
            return Err(UplinkError::Config(format!(
                "max_lines must be in 1..={}",
                wire::MAX_LINES
            )));
        }
        if !(MIN_BODY_BYTES..=wire::MAX_BODY_BYTES).contains(&self.max_body_bytes) {
            return Err(UplinkError::Config(format!(
                "max_body_bytes must be in {MIN_BODY_BYTES}..={}",
                wire::MAX_BODY_BYTES
            )));
        }
        if !(1024..=16 * 1024 * 1024).contains(&self.max_record_bytes) {
            return Err(UplinkError::Config(
                "max_record_bytes must be in 1024..=16777216".into(),
            ));
        }
        if !robodr_ocsf::validate::is_valid_data_source(&self.upgrade_data_source)
            || !robodr_ocsf::validate::is_valid_topic(&self.upgrade_topic)
        {
            return Err(UplinkError::Config(
                "upgrade topic / data source must be valid deployment labels".into(),
            ));
        }
        if self
            .dead_letter_rotation
            .is_some_and(|r| r.keep == 0 || r.max_bytes < MIN_DEAD_LETTER_BYTES)
        {
            return Err(UplinkError::Config(format!(
                "dead-letter rotation: keep >= 1 and max_bytes >= {MIN_DEAD_LETTER_BYTES} required"
            )));
        }
        let r = &self.retry;
        if r.max_attempts == 0 || r.base.is_zero() || r.max < r.base {
            return Err(UplinkError::Config(
                "retry: max_attempts >= 1 and 0 < base <= max required".into(),
            ));
        }
        Ok(())
    }
}

/// Simulated crash points (tests).
#[doc(hidden)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FailPoint {
    /// The pending batch is saved, nothing sent.
    AfterPendingSaved,
    /// A valid `200` was received, its result not yet saved.
    AfterResponse,
    /// The result is saved, nothing acknowledged.
    AfterResultSaved,
    /// Spool: the first record of the batch was renamed.
    AfterFirstAck,
}

#[derive(Debug)]
pub enum UplinkError {
    Config(String),
    State(String),
    Io(io::Error),
    /// The server refused the request (`4xx` other than 408/413/429):
    /// nothing acknowledged, the batch stays pending.
    Refused {
        status: u16,
        code: String,
        detail: String,
    },
    /// A `200` that does not account for the batch: nothing acknowledged.
    Protocol(String),
    /// Retries exhausted for this run (the batch stays pending).
    /// `retry_after`: the server's `Retry-After` on the last attempt, which
    /// the caller must honour before the next run ([`Self::retry_after`]).
    GaveUp {
        attempts: u32,
        last: String,
        retry_after: Option<Duration>,
    },
    /// Another process holds the state directory's lock.
    Locked(PathBuf),
    #[doc(hidden)]
    Injected,
}

impl UplinkError {
    /// The server's `Retry-After` the next attempt must wait for (already
    /// bounded by [`MAX_RETRY_AFTER`]).
    pub fn retry_after(&self) -> Option<Duration> {
        match self {
            Self::GaveUp { retry_after, .. } => retry_after.map(honoured_retry_after),
            _ => None,
        }
    }

    /// A failure that a retry soon may fix (network, `408`, `429`, `5xx`
    /// exhausted for this run). Everything else (refusals, a malformed
    /// `200`, local state or I/O errors) needs a change somewhere and is
    /// retried on the long backoff ([`service`]).
    pub fn is_transient(&self) -> bool {
        matches!(self, Self::GaveUp { .. })
    }

    /// Short machine-readable class (status file, `STATUS=`).
    pub fn kind(&self) -> &'static str {
        match self {
            Self::Config(_) => "config",
            Self::State(_) => "state",
            Self::Io(_) => "io",
            Self::Refused { .. } => "refused",
            Self::Protocol(_) => "protocol",
            Self::GaveUp { .. } => "gave_up",
            Self::Locked(_) => "locked",
            Self::Injected => "injected",
        }
    }

    /// HTTP status and server code of a refusal.
    pub fn refusal(&self) -> Option<(u16, &str)> {
        match self {
            Self::Refused { status, code, .. } => Some((*status, code.as_str())),
            _ => None,
        }
    }
}

impl fmt::Display for UplinkError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Config(m) => write!(f, "configuration: {m}"),
            Self::State(m) => write!(f, "uplink state: {m}"),
            Self::Io(e) => write!(f, "I/O: {e}"),
            Self::Refused {
                status,
                code,
                detail,
            } => {
                write!(f, "server refused the batch: HTTP {status}")?;
                if !code.is_empty() {
                    write!(f, " {}", wire::trunc(code))?;
                }
                if !detail.is_empty() {
                    write!(f, ": {}", wire::trunc(detail))?;
                }
                match *status {
                    401 => write!(
                        f,
                        " (key not registered for this role / revoked, or clock off by more \
                         than 300 s: check NTP)"
                    ),
                    _ => Ok(()),
                }
            }
            Self::Protocol(m) => write!(f, "server response: {m}"),
            Self::GaveUp {
                attempts,
                last,
                retry_after,
            } => {
                write!(f, "giving up after {attempts} attempt(s): {last}")?;
                match retry_after {
                    Some(ra) => write!(
                        f,
                        " (server Retry-After {} s honoured before the next attempt)",
                        honoured_retry_after(*ra).as_secs()
                    ),
                    None => Ok(()),
                }
            }
            Self::Locked(p) => write!(
                f,
                "{} is held by another robodr-uplink (the service, or a --once or reinject \
                 run on the same --state-dir); stop it first (systemctl stop robodr-uplink)",
                p.display()
            ),
            Self::Injected => write!(f, "injected failure"),
        }
    }
}

impl std::error::Error for UplinkError {}

impl From<io::Error> for UplinkError {
    fn from(e: io::Error) -> Self {
        Self::Io(e)
    }
}

/// Load the sender key: an Ed25519 **secret** key file
/// (`robodr-blackbox keygen`; mode 0600, owned by the caller) whose key id
/// is the derived `ed25519:<16 hex>` (contract §2.1). Its role (`uplink`
/// or `relay`) is decided by the server's registry, not here.
pub fn load_sender_key(path: &Path) -> Result<Ed25519SigningKey, String> {
    let kf = KeyFile::load_secret(path).map_err(|e| format!("key file {}: {e}", path.display()))?;
    if kf.is_symmetric() {
        return Err(format!(
            "key file {}: {} keys are refused; the ingest API takes ed25519 keys only",
            path.display(),
            kf.algorithm
        ));
    }
    let key = kf
        .ed25519_signing_key()
        .map_err(|e| format!("key file {}: {e}", path.display()))?;
    check_sender_key(&key).map_err(|e| format!("key file {}: {e}", path.display()))?;
    Ok(key)
}

fn check_sender_key(key: &Ed25519SigningKey) -> Result<(), String> {
    let want = derive_key_id(&key.public_key());
    if key.key_id() != want {
        return Err(format!(
            "key id {:?} is not the derived id {want:?}; the ingest API identifies keys by the \
             derived ed25519:<16 hex> id (generate with `robodr-blackbox keygen` without --key-id)",
            wire::trunc(key.key_id())
        ));
    }
    Ok(())
}

/// Persisted pending batch (see the module docs).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Pending {
    pub batch_id: String,
    /// `spool` or `diode:<batch directory>`.
    pub source: String,
    /// Diode: last input line the batch consumes (lines after the committed
    /// count up to here, including locally dead-lettered ones). Spool: 0.
    pub last: u64,
    /// Input position of each body line.
    pub positions: Vec<u64>,
    pub body_sha256: String,
    /// The `200`'s rejected lines, once received.
    pub result: Option<Vec<RejectedLine>>,
}

/// Persisted state.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct UplinkState {
    pub format: String,
    /// Diode batch → lines committed (bounded by [`MAX_IN_FLIGHT`]).
    pub in_flight: BTreeMap<String, u64>,
    /// Re-injected stream (generation, [`reinject`]) → lines committed.
    /// Absent from the file while empty, so a state written without
    /// re-injections stays readable by earlier versions.
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub reinject: BTreeMap<String, u64>,
    pub pending: Option<Pending>,
    pub sent_lines_total: u64,
    pub accepted_total: u64,
    pub rejected_total: u64,
    pub dead_lettered_total: u64,
}

impl UplinkState {
    fn empty() -> Self {
        Self {
            format: STATE_FORMAT.into(),
            in_flight: BTreeMap::new(),
            reinject: BTreeMap::new(),
            pending: None,
            sent_lines_total: 0,
            accepted_total: 0,
            rejected_total: 0,
            dead_lettered_total: 0,
        }
    }

    fn parse(bytes: &[u8]) -> Result<Self, String> {
        let s: Self = serde_json::from_slice(bytes).map_err(|e| e.to_string())?;
        if s.format != STATE_FORMAT {
            return Err(format!("unknown format {:?}", wire::trunc(&s.format)));
        }
        if s.in_flight.len() > MAX_IN_FLIGHT || s.reinject.len() > MAX_IN_FLIGHT {
            return Err(format!("more than {MAX_IN_FLIGHT} in-flight batches"));
        }
        if s.reinject.keys().any(|g| !reinject::is_valid_generation(g)) {
            return Err("invalid re-injection generation name".into());
        }
        if let Some(p) = &s.pending {
            if p.positions.is_empty() || p.positions.len() > wire::MAX_LINES {
                return Err("pending batch with an impossible line count".into());
            }
            if !wire::is_valid_batch_id(&p.batch_id) {
                return Err("pending batch with an invalid batch id".into());
            }
            if let Some(r) = &p.result {
                if r.iter()
                    .any(|x| x.line == 0 || x.line > p.positions.len() as u64)
                {
                    return Err("pending result names a line outside the batch".into());
                }
            }
        }
        Ok(s)
    }

    /// Lines of diode batch `batch` committed so far.
    pub fn lines_committed(&self, batch: &str) -> u64 {
        self.in_flight.get(batch).copied().unwrap_or(0)
    }

    fn set_committed(&mut self, batch: &str, lines: u64) {
        self.in_flight.insert(batch.to_string(), lines);
        while self.in_flight.len() > MAX_IN_FLIGHT {
            let victim = self
                .in_flight
                .iter()
                .filter(|(k, _)| k.as_str() != batch)
                .min_by_key(|(_, v)| **v)
                .map(|(k, _)| k.clone());
            match victim {
                Some(k) => {
                    self.in_flight.remove(&k);
                }
                None => break,
            }
        }
    }
}

/// What one run did.
#[derive(Debug, Default, Clone, PartialEq, Eq, Serialize)]
pub struct UplinkReport {
    /// Batches acknowledged by a `200`.
    pub batches: u64,
    pub lines_sent: u64,
    pub accepted: u64,
    pub created: u64,
    pub updated: u64,
    pub duplicates: u64,
    /// Lines the server rejected (dead-lettered with its code).
    pub rejected: u64,
    /// `200`s with `replayed: true`.
    pub replayed: u64,
    /// HTTP requests made (including retries).
    pub requests: u64,
    pub retries: u64,
    /// Records refused by the local validation (dead-lettered, not sent).
    pub dead_lettered_local: u64,
    /// Spool files that could not be read (I/O error after
    /// [`fsutil::READ_ATTEMPTS`] attempts): dead-lettered with the error and
    /// moved to `<spool>/rejected/` (included in `dead_lettered_local`).
    pub quarantined_unreadable: u64,
    /// `413`s that halved the line cap.
    pub split_413: u64,
    /// A pending batch from an earlier run was re-sent / finished.
    pub resumed: u64,
    /// A pending batch from an earlier run no longer matched its input and
    /// was dropped (its records are cut again under a new batch id).
    pub pending_dropped: u64,
    /// Diode batches finished in this run.
    pub batches_done: Vec<String>,
    /// Re-injected streams finished in this run ([`reinject`]).
    pub reinjected_done: Vec<String>,
    /// Malformed lines found in the dead-letter files when they were loaded
    /// in this run (torn fragments, edits; [`crate::deadletter`]).
    pub dead_letter_malformed: u64,
    /// `done/` markers deleted by retention (held: batch still in `out/`).
    pub pruned_done: PruneReport,
    /// Rotated dead-letter files deleted by retention (held: entries still
    /// needed for deduplication).
    pub pruned_dead_letters: PruneReport,
    /// Finished `out/` batch payloads deleted by retention (held: not
    /// finished yet).
    pub pruned_out: PruneReport,
    /// `<spool>/rejected/` records deleted by retention.
    pub pruned_rejected: PruneReport,
    /// `records.jsonl` of finished re-injection generations deleted.
    pub pruned_reinject: PruneReport,
}

impl UplinkReport {
    /// Whether anything happened (for logging). Files merely held by
    /// retention (a standing condition) do not count.
    pub fn is_empty(&self) -> bool {
        let mut s = self.clone();
        s.pruned_done.held = 0;
        s.pruned_dead_letters.held = 0;
        s.pruned_out.held = 0;
        s == Self::default()
    }
}

/// The input stream a batch comes from (its `source` string).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Stream<'a> {
    /// `spool`: the agentd spool's `ready/`.
    Spool,
    /// `diode:<batch>`: `out/<batch>/records.jsonl`.
    Diode(&'a str),
    /// `reinject:<generation>`: `<state>/reinject/<generation>/records.jsonl`.
    Reinject(&'a str),
}

impl<'a> Stream<'a> {
    fn of(source: &'a str) -> Option<Self> {
        if source == "spool" {
            return Some(Self::Spool);
        }
        if let Some(b) = source.strip_prefix("diode:") {
            return Some(Self::Diode(b));
        }
        source
            .strip_prefix(reinject::SOURCE_PREFIX)
            .filter(|g| reinject::is_valid_generation(g))
            .map(Self::Reinject)
    }

    /// Line-numbered streams (diode, re-injected) commit a line count.
    fn is_lines(self) -> bool {
        !matches!(self, Self::Spool)
    }
}

/// The exclusive lock on a state directory (`<state>/uplink.lock`,
/// `flock`). Held by the service for its whole lifetime and by every
/// `--once` / `reinject` run, so two processes never share a state
/// directory. Released when dropped (and by the kernel when the process
/// dies: never stale).
#[derive(Debug)]
pub struct StateLock {
    path: PathBuf,
    _file: fs::File,
}

impl StateLock {
    /// Take the lock of `state_dir` (created if missing), or fail with
    /// [`UplinkError::Locked`].
    pub fn acquire(state_dir: &Path) -> Result<Self, UplinkError> {
        fsutil::mkdir(state_dir)?;
        let path = state_dir.join(LOCK_FILE);
        match fsutil::try_lock(&path)? {
            Some(f) => Ok(Self { path, _file: f }),
            None => Err(UplinkError::Locked(path)),
        }
    }

    pub fn path(&self) -> &Path {
        &self.path
    }
}

/// One input record.
#[derive(Debug, Clone)]
struct Item {
    /// Diode: line number. Spool: seq.
    pos: u64,
    /// Spool file name.
    file: Option<String>,
    raw: Result<Vec<u8>, String>,
}

/// Input with push-back (a record that did not fit goes back to the front).
struct Feed {
    buf: VecDeque<Item>,
    src: FeedSrc,
}

enum FeedSrc {
    Diode(Option<LineReader>),
    Spool {
        ready: PathBuf,
        files: VecDeque<(u64, String)>,
        max: usize,
    },
}

impl Feed {
    fn next(&mut self) -> io::Result<Option<Item>> {
        if let Some(i) = self.buf.pop_front() {
            return Ok(Some(i));
        }
        match &mut self.src {
            FeedSrc::Diode(None) => Ok(None),
            FeedSrc::Diode(Some(r)) => Ok(r.next_line()?.map(|(pos, raw)| Item {
                pos,
                file: None,
                raw,
            })),
            FeedSrc::Spool { ready, files, max } => {
                while let Some((seq, name)) = files.pop_front() {
                    let path = ready.join(&name);
                    // Only this process removes from ready/ (agentd never
                    // does); a file gone since the listing is skipped, never
                    // dead-lettered.
                    match fs::symlink_metadata(&path) {
                        Err(e) if e.kind() == io::ErrorKind::NotFound => continue,
                        Err(e) => return Err(e),
                        Ok(_) => {}
                    }
                    let raw = read_spool_item(&path, seq, *max)?;
                    return Ok(Some(Item {
                        pos: seq,
                        file: Some(name),
                        raw,
                    }));
                }
                Ok(None)
            }
        }
    }

    fn push_front(&mut self, items: Vec<Item>) {
        for i in items.into_iter().rev() {
            self.buf.push_front(i);
        }
    }
}

/// A cut batch.
struct Cut {
    /// `spool` or `diode:<name>`.
    source: String,
    /// Diode: last consumed line. Spool: 0.
    last: u64,
    lines: Vec<Item>,
    body: Vec<u8>,
    batch_id: String,
}

impl Cut {
    fn positions(&self) -> Vec<u64> {
        self.lines.iter().map(|i| i.pos).collect()
    }
}

enum Sent {
    Ok(IngestResponse),
    TooLarge(String),
}

fn spool_file(seq: u64) -> String {
    format!("{seq:020}.json")
}

/// Callback for progress messages (retries, dropped pending batches).
pub type LogFn = Box<dyn FnMut(&str) + Send>;

/// See the module docs.
pub struct Uplink<T: Transport> {
    _lock: Arc<StateLock>,
    cfg: UplinkConfig,
    transport: T,
    key: Ed25519SigningKey,
    key_id: String,
    state: UplinkState,
    dead: DeadLetters,
    dead_loaded: bool,
    dead_malformed_unreported: u64,
    /// The state's disk usage and when it was measured.
    usage: Option<(std::time::Instant, crate::retention::StateUsage)>,
    max_lines_now: usize,
    clock: Box<dyn FnMut() -> u64 + Send>,
    sleeper: Box<dyn FnMut(Duration) + Send>,
    rng: Box<dyn FnMut() -> u64 + Send>,
    log: LogFn,
    fired: bool,
}

fn random_u64() -> u64 {
    let mut b = [0u8; 8];
    // No randomness: no jitter (the delay is still bounded and correct).
    match robodr_blackbox::crypto::fill_random(&mut b) {
        Ok(()) => u64::from_le_bytes(b),
        Err(_) => 0,
    }
}

impl<T: Transport> Uplink<T> {
    /// Open with the state directory's lock taken here ([`StateLock`]).
    pub fn open(
        cfg: UplinkConfig,
        transport: T,
        key: Ed25519SigningKey,
    ) -> Result<Self, UplinkError> {
        let lock = Arc::new(StateLock::acquire(&cfg.state_dir)?);
        Self::open_locked(cfg, transport, key, lock)
    }

    /// Open under a lock the caller already holds (a long-running service
    /// keeps it between runs; it must be the lock of `cfg.state_dir`).
    pub fn open_locked(
        cfg: UplinkConfig,
        transport: T,
        key: Ed25519SigningKey,
        lock: Arc<StateLock>,
    ) -> Result<Self, UplinkError> {
        if lock.path() != cfg.state_dir.join(LOCK_FILE) {
            return Err(UplinkError::Config(format!(
                "the lock {} is not the one of {}",
                lock.path().display(),
                cfg.state_dir.display()
            )));
        }
        cfg.validate()?;
        check_sender_key(&key).map_err(UplinkError::Config)?;
        let key_id = key.key_id().to_string();
        fsutil::mkdir(&cfg.state_dir)?;
        fsutil::mkdir(&cfg.state_dir.join(DONE_DIR))?;
        match &cfg.source {
            Source::Spool(root) => {
                for d in ["ready", "acked"] {
                    if !root.join(d).is_dir() {
                        return Err(UplinkError::Config(format!(
                            "{}: no {d}/ (is this an agentd spool?)",
                            root.display()
                        )));
                    }
                }
                fsutil::mkdir(&root.join("rejected"))?;
            }
            Source::DiodeOut(out) => {
                if !out.is_dir() {
                    return Err(UplinkError::Config(format!(
                        "{}: not a directory",
                        out.display()
                    )));
                }
            }
        }
        let path = cfg.state_dir.join(STATE_FILE);
        let state = match fsutil::read_capped(&path, 8 * 1024 * 1024) {
            Ok(b) => UplinkState::parse(&b)
                .map_err(|e| UplinkError::State(format!("{}: {e}", path.display())))?,
            Err(ReadError::Missing) => UplinkState::empty(),
            Err(e) => return Err(UplinkError::State(format!("{}: {e}", path.display()))),
        };
        if let Some(p) = &state.pending {
            let kind_ok = matches!(
                (&cfg.source, Stream::of(&p.source)),
                (_, Some(Stream::Reinject(_)))
                    | (Source::Spool(_), Some(Stream::Spool))
                    | (Source::DiodeOut(_), Some(Stream::Diode(_)))
            );
            if !kind_ok {
                return Err(UplinkError::State(format!(
                    "{}: pending batch from a {:?} source, configured source differs \
                     (one state directory per input)",
                    path.display(),
                    wire::trunc(&p.source)
                )));
            }
        }
        let max_lines_now = cfg.max_lines;
        let dead = DeadLetters::new(&cfg.state_dir, DEAD_LETTER_FILE, cfg.dead_letter_rotation);
        Ok(Self {
            _lock: lock,
            cfg,
            transport,
            key,
            key_id,
            state,
            dead,
            dead_loaded: false,
            dead_malformed_unreported: 0,
            usage: None,
            max_lines_now,
            clock: Box::new(fsutil::now_ms),
            sleeper: Box::new(std::thread::sleep),
            rng: Box::new(random_u64),
            log: Box::new(|m| eprintln!("robodr-uplink: {m}")),
            fired: false,
        })
    }

    /// Replace the clock (ms since the epoch) used for request timestamps.
    pub fn with_clock(mut self, f: impl FnMut() -> u64 + Send + 'static) -> Self {
        self.clock = Box::new(f);
        self
    }

    /// Replace the sleep used between retries.
    pub fn with_sleeper(mut self, f: impl FnMut(Duration) + Send + 'static) -> Self {
        self.sleeper = Box::new(f);
        self
    }

    /// Replace the jitter source.
    pub fn with_rng(mut self, f: impl FnMut() -> u64 + Send + 'static) -> Self {
        self.rng = Box::new(f);
        self
    }

    /// Replace the progress logger (default: stderr).
    pub fn with_log(mut self, f: impl FnMut(&str) + Send + 'static) -> Self {
        self.log = Box::new(f);
        self
    }

    pub fn state(&self) -> &UplinkState {
        &self.state
    }

    pub fn transport(&self) -> &T {
        &self.transport
    }

    pub fn transport_mut(&mut self) -> &mut T {
        &mut self.transport
    }

    pub fn key_id(&self) -> &str {
        &self.key_id
    }

    /// Pending batch, backlog and totals, for the status file
    /// ([`service`]).
    pub fn snapshot(&mut self) -> Result<service::Snapshot, UplinkError> {
        let mut backlog = service::Backlog::default();
        match &self.cfg.source {
            Source::Spool(root) => {
                backlog.spool_ready = Some(list_ready(&root.join("ready"))?.len() as u64);
            }
            Source::DiodeOut(out) => {
                let done = self.cfg.state_dir.join(DONE_DIR);
                let n = list_diode_batches(out)?
                    .iter()
                    .filter(|b| fs::symlink_metadata(done.join(b)).is_err())
                    .count();
                backlog.diode_batches = Some(n as u64);
            }
        }
        backlog.reinject_generations =
            reinject::list_generations(&self.cfg.state_dir.join(REINJECT_DIR))?
                .iter()
                .filter(|g| !g.done)
                .count() as u64;
        let due = self
            .usage
            .as_ref()
            .is_none_or(|(t, _)| t.elapsed() >= self.cfg.usage_interval);
        if due {
            let u = crate::retention::state_usage(
                &self.cfg.state_dir,
                DEAD_LETTER_FILE,
                &self.cfg.source,
                true,
            )?;
            self.usage = Some((std::time::Instant::now(), u));
        }
        let p = self.state.pending.as_ref();
        Ok(service::Snapshot {
            pending_batch_id: p.map(|p| p.batch_id.clone()),
            pending_source: p.map(|p| p.source.clone()),
            pending_lines: p.map_or(0, |p| p.positions.len() as u64),
            backlog,
            sent_lines_total: self.state.sent_lines_total,
            accepted_total: self.state.accepted_total,
            rejected_total: self.state.rejected_total,
            dead_lettered_total: self.state.dead_lettered_total,
            state_usage: self.usage.as_ref().map(|(_, u)| u.clone()),
        })
    }

    fn fail(&mut self, at: FailPoint) -> Result<(), UplinkError> {
        if self.cfg.fail_point == Some(at) && !self.fired {
            self.fired = true;
            return Err(UplinkError::Injected);
        }
        Ok(())
    }

    fn save(&self) -> Result<(), UplinkError> {
        let b = serde_json::to_vec_pretty(&self.state)
            .map_err(|e| UplinkError::State(e.to_string()))?;
        fsutil::atomic_write(&self.cfg.state_dir.join(STATE_FILE), &b)?;
        Ok(())
    }

    /// Append a dead letter (deduplicated on `(context, pos)`).
    fn dead_letter(
        &mut self,
        context: &str,
        pos: u64,
        code: &str,
        reason: &str,
        batch_id: Option<&str>,
        raw: &[u8],
    ) -> Result<(), UplinkError> {
        if !self.dead_loaded {
            let st = self.dead.stats()?;
            self.dead_loaded = true;
            if st.malformed > 0 {
                // Reported by the run that loaded the file (run_once).
                self.dead_malformed_unreported = st.malformed;
                (self.log)(&format!(
                    "{}: {} malformed line(s) (torn by a crash, or edited); their records \
                     cannot be deduplicated and may be dead-lettered again",
                    self.dead.path().display(),
                    st.malformed
                ));
            }
        }
        self.state.dead_lettered_total += 1;
        if self.dead.contains(context, pos)? {
            return Ok(());
        }
        let raw = String::from_utf8_lossy(raw.get(..self.cfg.max_record_bytes).unwrap_or(raw));
        let mut line = serde_json::to_vec(&serde_json::json!({
            "source": context,
            "position": pos,
            "code": code,
            "reason": wire::trunc(reason),
            "batch_id": batch_id,
            "record": raw,
            "at_ms": fsutil::now_ms(),
        }))
        .map_err(|e| UplinkError::State(e.to_string()))?;
        line.push(b'\n');
        self.dead.append(context, pos, &line)?;
        Ok(())
    }

    /// Dead-letter context of a source: the diode batch name, or the spool
    /// root (as `robodr-kafka-publish` does).
    fn context(&self, source: &str) -> String {
        match Stream::of(source) {
            Some(Stream::Diode(b)) => b.to_string(),
            Some(Stream::Reinject(_)) => source.to_string(),
            _ => match &self.cfg.source {
                Source::Spool(root) => root.display().to_string(),
                Source::DiodeOut(out) => out.display().to_string(),
            },
        }
    }

    fn check(&self, raw: &[u8]) -> Result<String, String> {
        let c = check_record(raw, &self.cfg.upgrade_topic, &self.cfg.upgrade_data_source)?;
        Ok(wire::encode_line(&c.value, c.sig.as_ref()))
    }

    /// Cut the next batch from `feed`. Locally invalid records are
    /// dead-lettered (spool: moved to `rejected/`) on the way. `None`:
    /// nothing consumed.
    fn cut(
        &mut self,
        feed: &mut Feed,
        source: &str,
        report: &mut UplinkReport,
    ) -> Result<Option<Cut>, UplinkError> {
        let context = self.context(source);
        let mut lines: Vec<Item> = Vec::new();
        let mut body = Vec::new();
        let mut last = None;
        let mut moved = false;
        while lines.len() < self.max_lines_now {
            let Some(item) = feed.next()? else { break };
            let encoded = match &item.raw {
                Ok(raw) => self.check(raw),
                Err(e) => Err(e.clone()),
            };
            match encoded {
                Err(reason) => {
                    if reason.starts_with(fsutil::UNREADABLE) {
                        report.quarantined_unreadable += 1;
                        (self.log)(&format!(
                            "WARNING: {context}: spool record {} quarantined: {reason}",
                            item.pos
                        ));
                    }
                    let raw = item.raw.as_deref().unwrap_or(&[]).to_vec();
                    self.dead_letter(&context, item.pos, LOCAL_CODE, &reason, None, &raw)?;
                    report.dead_lettered_local += 1;
                    if let (Some(file), Source::Spool(root)) = (&item.file, &self.cfg.source) {
                        match fs::rename(
                            root.join("ready").join(file),
                            root.join("rejected").join(file),
                        ) {
                            Ok(()) => moved = true,
                            Err(e) if e.kind() == io::ErrorKind::NotFound => {}
                            Err(e) => return Err(e.into()),
                        }
                    }
                    last = Some(item.pos);
                }
                Ok(line) => {
                    if line.len() + 1 > self.cfg.max_body_bytes {
                        // Unreachable with max_body_bytes >= MIN_BODY_BYTES.
                        return Err(UplinkError::Config(format!(
                            "a line of {} bytes does not fit max_body_bytes",
                            line.len()
                        )));
                    }
                    if body.len() + line.len() + 1 > self.cfg.max_body_bytes {
                        feed.push_front(vec![item]);
                        break;
                    }
                    body.extend_from_slice(line.as_bytes());
                    body.push(b'\n');
                    last = Some(item.pos);
                    lines.push(item);
                }
            }
        }
        if moved {
            if let Source::Spool(root) = &self.cfg.source {
                fsutil::fsync_dir(&root.join("rejected"))?;
                fsutil::fsync_dir(&root.join("ready"))?;
            }
        }
        let Some(last) = last else { return Ok(None) };
        let positions: Vec<u64> = lines.iter().map(|i| i.pos).collect();
        let batch_id = if lines.is_empty() {
            String::new()
        } else {
            wire::batch_id(source, &positions, &body)
        };
        Ok(Some(Cut {
            source: source.to_string(),
            last: if Stream::of(source).is_some_and(Stream::is_lines) {
                last
            } else {
                0
            },
            lines,
            body,
            batch_id,
        }))
    }

    /// Send `cut` until a `200`, a `413`, a refusal or the attempt limit.
    fn send(&mut self, cut: &Cut, report: &mut UplinkReport) -> Result<Sent, UplinkError> {
        let mut attempt = 0u32;
        loop {
            attempt += 1;
            let ts = (self.clock)();
            let sig = wire::sign_batch(&self.key, &self.key_id, &cut.batch_id, ts, &cut.body);
            let req = HttpRequest {
                headers: vec![
                    ("Content-Type", wire::CONTENT_TYPE.to_string()),
                    (wire::H_KEY_ID, self.key_id.clone()),
                    (wire::H_BATCH_ID, cut.batch_id.clone()),
                    (wire::H_TIMESTAMP, ts.to_string()),
                    (wire::H_SIGNATURE, sig),
                ],
                body: &cut.body,
            };
            report.requests += 1;
            let (why, retry_after) = match self.transport.post(&req) {
                Err(e) => (format!("transport: {e}"), None),
                Ok(r) => match r.status {
                    200 => {
                        let resp =
                            IngestResponse::parse_checked(&r.body, &cut.batch_id, cut.lines.len())
                                .map_err(UplinkError::Protocol)?;
                        return Ok(Sent::Ok(resp));
                    }
                    413 => return Ok(Sent::TooLarge(wire::ErrorBody::parse(&r.body).describe())),
                    408 | 429 | 500..=599 => (
                        format!(
                            "HTTP {} ({})",
                            r.status,
                            wire::ErrorBody::parse(&r.body).describe()
                        ),
                        r.retry_after.as_deref().and_then(parse_retry_after),
                    ),
                    s => {
                        let e = wire::ErrorBody::parse(&r.body);
                        return Err(UplinkError::Refused {
                            status: s,
                            code: e.code,
                            detail: e.detail,
                        });
                    }
                },
            };
            if attempt >= self.cfg.retry.max_attempts {
                return Err(UplinkError::GaveUp {
                    attempts: attempt,
                    last: why,
                    retry_after,
                });
            }
            let d = retry_delay(&self.cfg.retry, attempt, retry_after, (self.rng)());
            report.retries += 1;
            (self.log)(&format!(
                "batch {} ({} lines): {why}; retry {attempt} in {} ms",
                cut.batch_id,
                cut.lines.len(),
                d.as_millis()
            ));
            (self.sleeper)(d);
        }
    }

    /// Commit a cut that has no body (only local dead letters).
    fn commit_empty(&mut self, cut: &Cut) -> Result<(), UplinkError> {
        self.commit_lines(&cut.source.clone(), cut.last);
        self.save()
    }

    /// Record the committed line count of a line-numbered stream.
    fn commit_lines(&mut self, source: &str, last: u64) {
        match Stream::of(source) {
            Some(Stream::Diode(name)) => self.state.set_committed(name, last),
            Some(Stream::Reinject(g)) => {
                self.state.reinject.insert(g.to_string(), last);
            }
            _ => {}
        }
    }

    /// Send a cut (pending already saved or saved here) and apply the
    /// result. `Ok(false)`: a `413` halved the line cap; the cut's records
    /// were pushed back into `feed` (if any) and must be re-cut.
    fn deliver(
        &mut self,
        cut: Cut,
        feed: Option<&mut Feed>,
        report: &mut UplinkReport,
    ) -> Result<bool, UplinkError> {
        if cut.lines.is_empty() {
            self.commit_empty(&cut)?;
            return Ok(true);
        }
        let pending = Pending {
            batch_id: cut.batch_id.clone(),
            source: cut.source.clone(),
            last: cut.last,
            positions: cut.positions(),
            body_sha256: to_hex(&sha256(&cut.body)),
            result: None,
        };
        if self.state.pending.as_ref() != Some(&pending) {
            self.state.pending = Some(pending);
            self.save()?;
        }
        self.fail(FailPoint::AfterPendingSaved)?;
        match self.send(&cut, report)? {
            Sent::Ok(resp) => {
                self.fail(FailPoint::AfterResponse)?;
                report.batches += 1;
                report.lines_sent += cut.lines.len() as u64;
                report.accepted += resp.accepted;
                report.created += resp.created;
                report.updated += resp.updated;
                report.duplicates += resp.duplicates;
                report.rejected += resp.rejected.len() as u64;
                if resp.replayed {
                    report.replayed += 1;
                }
                let raws: BTreeMap<u64, Vec<u8>> = cut
                    .lines
                    .iter()
                    .map(|i| (i.pos, i.raw.clone().unwrap_or_default()))
                    .collect();
                self.apply(&resp.rejected, &raws)?;
                Ok(true)
            }
            Sent::TooLarge(why) => {
                let n = cut.lines.len();
                if n <= 1 {
                    return Err(UplinkError::Refused {
                        status: 413,
                        code: String::new(),
                        detail: format!(
                            "a single-line batch was refused as too large ({why}); the server's \
                             limits are below the contract's (§2.4)"
                        ),
                    });
                }
                self.max_lines_now = (n / 2).max(1);
                report.split_413 += 1;
                (self.log)(&format!(
                    "batch {} ({n} lines): 413 ({why}); line cap now {}",
                    cut.batch_id, self.max_lines_now
                ));
                self.state.pending = None;
                self.save()?;
                if let Some(feed) = feed {
                    feed.push_front(cut.lines);
                }
                Ok(false)
            }
        }
    }

    /// Record the result, dead-letter the rejected lines, acknowledge the
    /// pending batch, clear it. Idempotent (a crash anywhere re-runs it).
    fn apply(
        &mut self,
        rejected: &[RejectedLine],
        raws: &BTreeMap<u64, Vec<u8>>,
    ) -> Result<(), UplinkError> {
        let Some(mut p) = self.state.pending.clone() else {
            return Err(UplinkError::State("no pending batch to apply".into()));
        };
        if p.result.is_none() {
            p.result = Some(rejected.to_vec());
            self.state.pending = Some(p.clone());
            self.save()?;
        }
        self.fail(FailPoint::AfterResultSaved)?;
        let rejected = p.result.clone().unwrap_or_default();
        let context = self.context(&p.source);
        let stream = Stream::of(&p.source)
            .ok_or_else(|| UplinkError::State(format!("pending source {:?}", p.source)))?;
        let mut is_rejected = vec![false; p.positions.len()];
        for r in &rejected {
            let idx = (r.line - 1) as usize;
            // `IngestResponse::parse_checked` bounds the line numbers.
            let (Some(flag), Some(&pos)) = (is_rejected.get_mut(idx), p.positions.get(idx)) else {
                return Err(UplinkError::State(format!(
                    "rejected line {} outside the batch",
                    r.line
                )));
            };
            *flag = true;
            let raw = match (raws.get(&pos), &self.cfg.source) {
                (Some(r), _) => r.clone(),
                (None, Source::Spool(root)) if !stream.is_lines() => {
                    let path = root.join("ready").join(spool_file(pos));
                    if fs::symlink_metadata(&path).is_err() {
                        // Already moved by an earlier apply, after its dead
                        // letter was written.
                        continue;
                    }
                    read_spool_item(&path, pos, self.cfg.max_record_bytes)?.unwrap_or_default()
                }
                (None, _) => Vec::new(),
            };
            let detail = if r.detail.is_empty() {
                format!("rejected by the server ({})", r.code)
            } else {
                r.detail.clone()
            };
            self.dead_letter(&context, pos, &r.code, &detail, Some(&p.batch_id), &raw)?;
        }
        match (&self.cfg.source, stream.is_lines()) {
            (_, true) => self.commit_lines(&p.source, p.last),
            (Source::DiodeOut(_), false) => {
                return Err(UplinkError::State(
                    "spool batch pending with a diode source".into(),
                ))
            }
            (Source::Spool(root), false) => {
                let ready = root.join("ready");
                let acked = root.join("acked");
                let rej = root.join("rejected");
                for (i, pos) in p.positions.iter().enumerate() {
                    let f = spool_file(*pos);
                    let dest = if is_rejected.get(i) == Some(&true) {
                        &rej
                    } else {
                        &acked
                    };
                    match fs::rename(ready.join(&f), dest.join(&f)) {
                        Ok(()) => {}
                        Err(e) if e.kind() == io::ErrorKind::NotFound => {}
                        Err(e) => return Err(e.into()),
                    }
                    if i == 0 {
                        self.fail(FailPoint::AfterFirstAck)?;
                    }
                }
                fsutil::fsync_dir(&acked)?;
                fsutil::fsync_dir(&rej)?;
                fsutil::fsync_dir(&ready)?;
            }
        }
        let n = p.positions.len() as u64;
        self.state.sent_lines_total += n;
        self.state.rejected_total += rejected.len() as u64;
        self.state.accepted_total += n - rejected.len() as u64;
        self.state.pending = None;
        self.save()
    }

    /// Rebuild the pending batch's cut from its input positions. `None`:
    /// the input no longer yields the same body.
    fn rebuild(&mut self, p: &Pending) -> Result<Option<Cut>, UplinkError> {
        let mut lines = Vec::with_capacity(p.positions.len());
        let stream = Stream::of(&p.source)
            .ok_or_else(|| UplinkError::State(format!("pending source {:?}", p.source)))?;
        let lines_dir = match (stream, &self.cfg.source) {
            (Stream::Diode(name), Source::DiodeOut(out)) => Some((out.clone(), name)),
            (Stream::Reinject(g), _) => Some((self.cfg.state_dir.join(REINJECT_DIR), g)),
            _ => None,
        };
        match (&self.cfg.source, lines_dir) {
            (Source::Spool(root), None) => {
                let ready = root.join("ready");
                for &pos in &p.positions {
                    let path = ready.join(spool_file(pos));
                    if fs::symlink_metadata(&path).is_err() {
                        return Ok(None);
                    }
                    let raw = read_spool_item(&path, pos, self.cfg.max_record_bytes)?;
                    lines.push(Item {
                        pos,
                        file: Some(spool_file(pos)),
                        raw,
                    });
                }
            }
            (Source::DiodeOut(_), None) => return Ok(None),
            (_, Some((dir, name))) => {
                let reader = LineReader::open(&dir, name, self.cfg.max_record_bytes);
                let mut reader = match reader {
                    Ok(Some(r)) => r,
                    Ok(None) | Err(OpenRecordsError::NotRegular(_)) => return Ok(None),
                    Err(OpenRecordsError::Io(e)) => return Err(e.into()),
                };
                let want: HashSet<u64> = p.positions.iter().copied().collect();
                while let Some((pos, raw)) = reader.next_line()? {
                    if pos > p.last {
                        break;
                    }
                    if want.contains(&pos) {
                        lines.push(Item {
                            pos,
                            file: None,
                            raw,
                        });
                    }
                }
            }
        }
        let mut body = Vec::new();
        for it in &lines {
            let Ok(raw) = &it.raw else { return Ok(None) };
            let Ok(line) = self.check(raw) else {
                return Ok(None);
            };
            body.extend_from_slice(line.as_bytes());
            body.push(b'\n');
        }
        let positions: Vec<u64> = lines.iter().map(|i| i.pos).collect();
        if positions != p.positions || to_hex(&sha256(&body)) != p.body_sha256 {
            return Ok(None);
        }
        let batch_id = wire::batch_id(&p.source, &positions, &body);
        if batch_id != p.batch_id {
            return Ok(None);
        }
        Ok(Some(Cut {
            source: p.source.clone(),
            last: p.last,
            lines,
            body,
            batch_id,
        }))
    }

    /// Finish or re-send a pending batch left by an earlier run.
    fn resume(&mut self, report: &mut UplinkReport) -> Result<(), UplinkError> {
        let Some(p) = self.state.pending.clone() else {
            return Ok(());
        };
        let rebuilt = self.rebuild(&p)?;
        if let Some(rejected) = p.result.clone() {
            report.resumed += 1;
            let raws: BTreeMap<u64, Vec<u8>> = rebuilt
                .map(|c| {
                    c.lines
                        .into_iter()
                        .map(|i| (i.pos, i.raw.unwrap_or_default()))
                        .collect()
                })
                .unwrap_or_default();
            return self.apply(&rejected, &raws);
        }
        match rebuilt {
            Some(cut) => {
                report.resumed += 1;
                (self.log)(&format!(
                    "re-sending pending batch {} ({} lines)",
                    cut.batch_id,
                    cut.lines.len()
                ));
                // `false` (a 413): the records are cut again by the normal run.
                self.deliver(cut, None, report)?;
                Ok(())
            }
            None => {
                (self.log)(&format!(
                    "pending batch {} no longer matches its input; its records are cut again \
                     under a new batch id (the server reports repeats as duplicates)",
                    p.batch_id
                ));
                report.pending_dropped += 1;
                self.state.pending = None;
                self.save()
            }
        }
    }

    /// Deliver everything currently available.
    pub fn run_once(&mut self) -> Result<UplinkReport, UplinkError> {
        let mut report = UplinkReport::default();
        let r = self.run_inner(&mut report);
        report.dead_letter_malformed = std::mem::take(&mut self.dead_malformed_unreported);
        r?;
        self.prune(&mut report)?;
        Ok(report)
    }

    /// Whether a dead letter `(source, position)` may still be needed for
    /// deduplication: its record can be processed again (module docs,
    /// "Retention").
    fn dead_letter_needed(&self, source: &str, pos: u64) -> io::Result<bool> {
        use crate::publish::{exists, valid_batch_name};
        if let Some(g) = source.strip_prefix(reinject::SOURCE_PREFIX) {
            let dir = self.cfg.state_dir.join(REINJECT_DIR).join(g);
            return Ok(reinject::is_valid_generation(g)
                && exists(&dir)?
                && !exists(&dir.join(reinject::DONE_FILE))?);
        }
        match &self.cfg.source {
            Source::DiodeOut(out) => {
                if !valid_batch_name(source) {
                    return Ok(false);
                }
                let done = self.cfg.state_dir.join(DONE_DIR).join(source);
                Ok(exists(&out.join(source))? && !exists(&done)?)
            }
            Source::Spool(root) => Ok(source == root.display().to_string()
                && exists(&root.join("ready").join(spool_file(pos)))?),
        }
    }

    /// Retention (module docs).
    fn prune(&mut self, report: &mut UplinkReport) -> Result<(), UplinkError> {
        let now = std::time::SystemTime::now();
        if let Source::DiodeOut(out) = &self.cfg.source {
            report.pruned_done = crate::retention::prune_done_markers(
                &self.cfg.state_dir.join(DONE_DIR),
                out,
                &self.cfg.done_retention,
                now,
            )?;
            report.pruned_out = crate::retention::prune_diode_out(
                out,
                &self.cfg.state_dir.join(DONE_DIR),
                &self.cfg.out_retention,
                now,
            )?;
        }
        if let Source::Spool(root) = &self.cfg.source {
            report.pruned_rejected = crate::spool_export::prune_rejected(
                &root.join("rejected"),
                &root.join("ready"),
                &self.cfg.rejected_retention,
                now,
            )?;
        }
        report.pruned_reinject = crate::retention::prune_reinject_payloads(
            &self.cfg.state_dir.join(REINJECT_DIR),
            &self.cfg.reinject_retention,
            now,
        )?;
        let r = self.cfg.dead_letter_retention;
        let mut dead = std::mem::replace(
            &mut self.dead,
            DeadLetters::new(&self.cfg.state_dir, DEAD_LETTER_FILE, None),
        );
        let res = dead.prune(&r, now, |s, p| self.dead_letter_needed(s, p));
        self.dead = dead;
        report.pruned_dead_letters = res?;
        Ok(())
    }

    fn run_inner(&mut self, report: &mut UplinkReport) -> Result<(), UplinkError> {
        self.resume(report)?;
        match self.cfg.source.clone() {
            Source::DiodeOut(out) => self.run_diode(&out, report)?,
            Source::Spool(root) => self.run_spool(&root, report)?,
        }
        self.run_reinjected(report)
    }

    /// Re-injected streams ([`reinject`]), oldest generation first; each is
    /// marked done (and forgotten by the state) once fully acknowledged.
    fn run_reinjected(&mut self, report: &mut UplinkReport) -> Result<(), UplinkError> {
        let dir = self.cfg.state_dir.join(REINJECT_DIR);
        let gens = reinject::list_generations(&dir)?;
        let before = self.state.reinject.len();
        let open: Vec<&String> = gens.iter().filter(|g| !g.done).map(|g| &g.name).collect();
        self.state.reinject.retain(|g, _| open.contains(&g));
        if self.state.reinject.len() != before {
            self.save()?;
        }
        for g in gens.into_iter().filter(|g| !g.done) {
            let reader = LineReader::open(&dir, &g.name, self.cfg.max_record_bytes).map_err(
                |e| match e {
                    OpenRecordsError::NotRegular(m) => UplinkError::State(m),
                    OpenRecordsError::Io(e) => UplinkError::Io(e),
                },
            )?;
            let mut feed = Feed {
                buf: VecDeque::new(),
                src: FeedSrc::Diode(reader),
            };
            let skip = self.state.reinject.get(&g.name).copied().unwrap_or(0);
            while feed.buf.is_empty() {
                match feed.next()? {
                    Some(it) if it.pos <= skip => continue,
                    Some(it) => feed.push_front(vec![it]),
                    None => break,
                }
            }
            let source = format!("{}{}", reinject::SOURCE_PREFIX, g.name);
            while let Some(cut) = self.cut(&mut feed, &source, report)? {
                self.deliver(cut, Some(&mut feed), report)?;
            }
            reinject::mark_done(&dir, &g.name)?;
            self.state.reinject.remove(&g.name);
            self.save()?;
            report.reinjected_done.push(g.name);
        }
        Ok(())
    }

    fn run_diode(&mut self, out: &Path, report: &mut UplinkReport) -> Result<(), UplinkError> {
        let names = list_diode_batches(out)?;
        let done_dir = self.cfg.state_dir.join(DONE_DIR);
        let before = self.state.in_flight.len();
        self.state.in_flight.retain(|b, _| {
            names.binary_search(b).is_ok() && fs::symlink_metadata(done_dir.join(b)).is_err()
        });
        if self.state.in_flight.len() != before {
            self.save()?;
        }
        for name in names {
            let marker = done_dir.join(&name);
            if fs::symlink_metadata(&marker).is_ok() {
                continue;
            }
            let reader =
                LineReader::open(out, &name, self.cfg.max_record_bytes).map_err(|e| match e {
                    OpenRecordsError::NotRegular(m) => UplinkError::State(m),
                    OpenRecordsError::Io(e) => UplinkError::Io(e),
                })?;
            let mut feed = Feed {
                buf: VecDeque::new(),
                src: FeedSrc::Diode(reader),
            };
            let skip = self.state.lines_committed(&name);
            while feed.buf.is_empty() {
                match feed.next()? {
                    Some(it) if it.pos <= skip => continue,
                    Some(it) => feed.push_front(vec![it]),
                    None => break,
                }
            }
            let source = format!("diode:{name}");
            while let Some(cut) = self.cut(&mut feed, &source, report)? {
                self.deliver(cut, Some(&mut feed), report)?;
            }
            fsutil::atomic_write(&marker, b"")?;
            self.state.in_flight.remove(&name);
            self.save()?;
            report.batches_done.push(name);
        }
        Ok(())
    }

    fn run_spool(&mut self, root: &Path, report: &mut UplinkReport) -> Result<(), UplinkError> {
        let ready = root.join("ready");
        loop {
            let files = list_ready(&ready)?;
            if files.is_empty() {
                return Ok(());
            }
            let mut feed = Feed {
                buf: VecDeque::new(),
                src: FeedSrc::Spool {
                    ready: ready.clone(),
                    files: files.into(),
                    max: self.cfg.max_record_bytes,
                },
            };
            let mut progressed = false;
            while let Some(cut) = self.cut(&mut feed, "spool", report)? {
                progressed = true;
                self.deliver(cut, Some(&mut feed), report)?;
            }
            if !progressed {
                return Ok(());
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn backoff_is_exponential_with_jitter_and_capped() {
        let p = RetryPolicy {
            max_attempts: 10,
            base: Duration::from_millis(100),
            max: Duration::from_millis(1000),
        };
        for (retry, d) in [
            (1, 100u64),
            (2, 200),
            (3, 400),
            (4, 800),
            (5, 1000),
            (40, 1000),
        ] {
            assert_eq!(
                backoff_delay(&p, retry, 0),
                Duration::from_millis(d / 2),
                "{retry}"
            );
            assert_eq!(
                backoff_delay(&p, retry, d - d / 2),
                Duration::from_millis(d),
                "{retry}"
            );
            for r in [1u64, 7, 12345, u64::MAX] {
                let x = backoff_delay(&p, retry, r).as_millis() as u64;
                assert!((d / 2..=d).contains(&x), "{retry} {r} {x}");
            }
        }
        // Huge base: no overflow.
        let big = RetryPolicy {
            base: Duration::from_secs(u64::MAX / 2000),
            max: Duration::from_secs(u64::MAX / 1000),
            ..p
        };
        let _ = backoff_delay(&big, 64, u64::MAX);
    }

    #[test]
    fn retry_after_is_honoured_and_capped() {
        let p = RetryPolicy {
            max_attempts: 3,
            base: Duration::from_millis(100),
            max: Duration::from_secs(1),
        };
        assert_eq!(parse_retry_after("7"), Some(Duration::from_secs(7)));
        assert_eq!(parse_retry_after(" 0 "), Some(Duration::ZERO));
        for bad in ["", "-1", "1.5", "Wed, 21 Oct 2015 07:28:00 GMT", "+5"] {
            assert_eq!(parse_retry_after(bad), None, "{bad}");
        }
        // Long values saturate (honoured as the 24 h bound), never ignored.
        for long in ["99999999999", "18446744073709551616", &"9".repeat(100)] {
            let d = parse_retry_after(long).unwrap();
            assert_eq!(honoured_retry_after(d), MAX_RETRY_AFTER, "{long}");
        }
        assert_eq!(
            retry_delay(&p, 1, Some(Duration::from_secs(7)), 0),
            Duration::from_secs(7)
        );
        assert_eq!(
            retry_delay(&p, 4, Some(Duration::ZERO), 0),
            Duration::from_millis(400),
            "never sooner than the backoff"
        );
    }

    /// Review F1: a `Retry-After` longer than the backoff is never cut
    /// short by a configured cap; only values over the documented 24 h
    /// producer bound are clamped (contract §7).
    #[test]
    fn retry_after_is_never_shortened() {
        let p = RetryPolicy {
            max_attempts: 3,
            base: Duration::from_millis(100),
            max: Duration::from_secs(1),
        };
        assert_eq!(
            retry_delay(&p, 1, Some(Duration::from_secs(3600)), 0),
            Duration::from_secs(3600)
        );
        assert_eq!(
            retry_delay(&p, 1, Some(Duration::from_secs(9_999_999_999)), 0),
            Duration::from_secs(24 * 3600)
        );
    }

    #[test]
    fn state_parsing() {
        let mut s = UplinkState::empty();
        let b = serde_json::to_vec(&s).unwrap();
        assert_eq!(UplinkState::parse(&b).unwrap(), s);
        s.pending = Some(Pending {
            batch_id: "rdu1-00".into(),
            source: "spool".into(),
            last: 0,
            positions: vec![1, 2],
            body_sha256: "00".repeat(32),
            result: Some(vec![RejectedLine {
                line: 2,
                code: "x".into(),
                detail: String::new(),
            }]),
        });
        let b = serde_json::to_vec(&s).unwrap();
        assert_eq!(UplinkState::parse(&b).unwrap(), s);
        let bad_line = String::from_utf8(b.clone())
            .unwrap()
            .replace("\"line\":2", "\"line\":3");
        assert!(UplinkState::parse(bad_line.as_bytes()).is_err());
        let bad_id = String::from_utf8(b.clone())
            .unwrap()
            .replace("rdu1-00", "a b");
        assert!(UplinkState::parse(bad_id.as_bytes()).is_err());
        let empty = String::from_utf8(b).unwrap().replace("[1,2]", "[]");
        assert!(UplinkState::parse(empty.as_bytes()).is_err());
        for bad in [
            &b"{}"[..],
            b"null",
            br#"{"format":"robodr-uplink-state/9","in_flight":{},"pending":null,"sent_lines_total":0,"accepted_total":0,"rejected_total":0,"dead_lettered_total":0}"#,
            br#"{"format":"robodr-uplink-state/1","in_flight":{},"pending":null,"sent_lines_total":0,"accepted_total":0,"rejected_total":0,"dead_lettered_total":0,"x":1}"#,
        ] {
            assert!(UplinkState::parse(bad).is_err(), "{}", String::from_utf8_lossy(bad));
        }
    }

    #[test]
    fn sender_key_must_have_the_derived_id() {
        let k = Ed25519SigningKey::from_seed_with_derived_id(&[3u8; 32]);
        assert!(check_sender_key(&k).is_ok());
        let named = Ed25519SigningKey::from_seed("ed25519:0000000000000000", &[3u8; 32]).unwrap();
        assert!(check_sender_key(&named).is_err());
    }
}
