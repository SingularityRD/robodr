//! Low side: pack validated findings (and black-box bundles) into signed,
//! sequence-numbered, size-bounded batches in an outbox directory.
//!
//! # Publication protocol (crash-consistent)
//!
//! For each batch:
//!
//! 1. create `outbox/.tmp-<batch>/` and write every data file, then
//!    `MANIFEST.json`, then `MANIFEST.sig` (each `create_new` + `fsync`),
//!    then `fsync` the temp directory;
//! 2. atomically replace the packer state file (next seq, this batch's hash);
//! 3. `rename` the temp directory to `outbox/<batch>/` and `fsync` the outbox.
//!
//! The diode transfer agent must ignore dot-entries, so it only ever sees
//! complete batches. A crash after step 2 leaves a complete, already-chained
//! temp directory, which [`Packer::open`] finishes publishing; a crash before
//! step 2 leaves an uncommitted temp directory, which is discarded (its
//! sequence number is reused, but it was never visible). Sequence numbers are
//! therefore never reused for different visible content.
//!
//! If the state file is lost, the packer restarts at sequence 1 with no
//! predecessor: the importer reports that as a conflict/replay rather than
//! accepting it silently (see the crate README).
//!
//! # Single instance
//!
//! [`Packer::open`] takes an exclusive `flock` on `<state>.lock` (next to the
//! state file) and holds it for the packer's lifetime; a second packer (or
//! resend) on the same state fails with [`PackError::Locked`]. The kernel
//! releases the lock when the process exits, so a crash leaves nothing stale.
//!
//! # Parity (optional FEC)
//!
//! With [`PackConfig::parity_shards`] `= m > 0`, every batch also carries `m`
//! Reed-Solomon parity files over its data files ([`crate::fec`], format in
//! [`crate::manifest`]): the importer can rebuild any `m` missing or corrupt
//! files of the batch. Parity is counted against `max_batch_bytes`, and each
//! parity file is as large as the batch's largest data file (rounded up to
//! [`PackConfig::shard_size`]), so parity pays off best with many similarly
//! sized files; a batch holding one large file needs `m` full-size parity
//! files to survive the loss of it.
//!
//! # Archive and resend
//!
//! Before a batch is committed, a copy of it is written to
//! `<state>.archive/<batch>/`; the newest [`PackConfig::archive_keep`]
//! batches are kept. [`Packer::resend`] (CLI: `robodr-diode-pack resend`)
//! re-emits an archived batch into the outbox byte for byte (same manifest,
//! signature, data and parity), after checking that the archived manifests
//! chain to the state's head and that every file still matches its
//! manifest hash. Resending is idempotent: an identical copy already in the
//! outbox is left alone, and the importer treats a re-delivered batch as a
//! duplicate.

use crate::fec::{ReedSolomon, MAX_SHARDS};
use crate::fsutil::{self, ReadError};
use crate::manifest::{
    batch_dir_name, batch_hash, bundle_file_name, file_sha256, is_hex_digest, is_valid_key_id,
    manifest_signing_message, parity_file_name, parity_len, FileEntry, FileKind, Manifest,
    ParitySpec, SignatureFile, FINDINGS_FILE, FORMAT, MANIFEST_FILE, MAX_BATCH_SEQ, MAX_FILES,
    MAX_MANIFEST_BYTES, MAX_PARITY_SHARDS, MAX_SHARD_SIZE, MAX_SIGNATURE_FILE_BYTES, MAX_SIG_LEN,
    MIN_SHARD_SIZE, PARITY_SCHEME, SIGNATURE_FILE,
};
use robodr_blackbox::crypto::to_hex;
use robodr_blackbox::{Bundle, Signer};
use robodr_ocsf::validate::{is_valid_robot_id, MAX_FINDING_BYTES, MAX_TIME_MS, MIN_TIME_MS};
use robodr_ocsf::{FindingEnvelope, ValidationError, CONTRACT_VERSION};
use serde::{Deserialize, Serialize};
use std::fmt;
use std::fs;
use std::io;
use std::path::{Path, PathBuf};

/// Default upper bound on the data bytes of one batch (16 MiB).
pub const DEFAULT_MAX_BATCH_BYTES: u64 = 16 * 1024 * 1024;
/// Default upper bound on findings per batch.
pub const DEFAULT_MAX_FINDINGS_PER_BATCH: usize = 10_000;
/// Smallest allowed `max_batch_bytes`: one maximal finding must fit.
pub const MIN_BATCH_BYTES: u64 = MAX_FINDING_BYTES as u64 + 1;
/// Largest allowed `max_batch_bytes`: the importer's default cap
/// ([`DEFAULT_MAX_IMPORT_BATCH_BYTES`](crate::unpack::DEFAULT_MAX_IMPORT_BATCH_BYTES),
/// 256 MiB), so no packer setting can produce a batch a default-configured
/// importer quarantines as `batch_too_large`. An importer configured with a
/// smaller `max_batch_bytes` must be matched by the packer's setting.
pub const MAX_BATCH_BYTES: u64 = crate::unpack::DEFAULT_MAX_IMPORT_BATCH_BYTES;
/// Default stripe height of parity batches (64 KiB).
pub const DEFAULT_SHARD_SIZE: u64 = 64 * 1024;
/// Default number of published batches kept for [`Packer::resend`].
pub const DEFAULT_ARCHIVE_KEEP: usize = 64;
const STATE_FORMAT: &str = "robodr-diode-pack-state/1";
const MAX_STATE_BYTES: u64 = 64 * 1024;
const TMP_PREFIX: &str = ".tmp-";
const RESEND_PREFIX: &str = ".resend-";

/// `<state>.archive`: where published batches are kept for resend.
pub fn archive_dir(state_path: &Path) -> PathBuf {
    let mut s = state_path.as_os_str().to_os_string();
    s.push(".archive");
    PathBuf::from(s)
}

/// Packer configuration.
#[derive(Debug, Clone)]
pub struct PackConfig {
    /// Exporting unit id (`[A-Za-z0-9._-]{1,64}`).
    pub unit_id: String,
    /// Upper bound on the sum of data file sizes of one batch.
    pub max_batch_bytes: u64,
    /// Upper bound on findings per batch (>= 1).
    pub max_findings_per_batch: usize,
    /// Reed-Solomon parity files per batch (`0` = no parity, the default;
    /// at most [`MAX_PARITY_SHARDS`]). Any this many lost or corrupt files
    /// of a batch can be rebuilt by the importer.
    pub parity_shards: usize,
    /// Stripe height of parity batches ([`MIN_SHARD_SIZE`]..=[`MAX_SHARD_SIZE`]):
    /// parity files are the largest data file rounded up to a multiple of it.
    pub shard_size: u64,
    /// Published batches kept in `<state>.archive/` for [`Packer::resend`]
    /// (`0` = keep none, no archive is written).
    pub archive_keep: usize,
}

impl PackConfig {
    pub fn new(unit_id: impl Into<String>) -> Self {
        Self {
            unit_id: unit_id.into(),
            max_batch_bytes: DEFAULT_MAX_BATCH_BYTES,
            max_findings_per_batch: DEFAULT_MAX_FINDINGS_PER_BATCH,
            parity_shards: 0,
            shard_size: DEFAULT_SHARD_SIZE,
            archive_keep: DEFAULT_ARCHIVE_KEEP,
        }
    }

    /// Bytes a batch of `data` data bytes whose largest file is `max_file`
    /// bytes occupies once its parity files are added.
    fn batch_size(&self, data: u64, max_file: u64) -> u64 {
        let m = self.parity_shards as u64;
        if m == 0 {
            return data;
        }
        data.saturating_add(m.saturating_mul(parity_len(max_file, self.shard_size)))
    }

    /// Most data files per batch (`k + m` must stay within the code).
    fn max_data_files(&self) -> usize {
        if self.parity_shards == 0 {
            MAX_FILES
        } else {
            MAX_SHARDS - self.parity_shards
        }
    }
}

/// Persisted packer state.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PackState {
    pub format: String,
    pub unit_id: String,
    /// Sequence number the next batch will get.
    pub next_seq: u64,
    /// Hash of batch `next_seq - 1`, `None` before the first batch.
    pub last_batch_hash: Option<String>,
}

/// A batch that is now visible in the outbox.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct PublishedBatch {
    pub name: String,
    pub path: PathBuf,
    pub seq: u64,
    pub batch_hash: String,
    pub finding_count: u64,
    pub bundle_count: usize,
    pub data_bytes: u64,
    /// Parity files in the batch (0 without parity).
    pub parity_files: usize,
}

/// A batch re-emitted by [`Packer::resend`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ResentBatch {
    pub name: String,
    pub path: PathBuf,
    pub seq: u64,
    pub batch_hash: String,
    /// An identical copy was already in the outbox; nothing was written.
    pub already_present: bool,
}

/// Why packing failed. Nothing is published for an input that fails
/// validation (inputs are checked before the first batch is written).
#[derive(Debug)]
pub enum PackError {
    Config(String),
    State(String),
    InvalidFinding {
        index: usize,
        errors: Vec<ValidationError>,
    },
    BadBundle {
        index: usize,
        reason: String,
    },
    BundleTooLarge {
        index: usize,
        size: u64,
        max: u64,
    },
    Sign(String),
    /// Another packer holds the lock on this state file.
    Locked(PathBuf),
    /// A batch cannot be resent (not published, not archived, archive
    /// damaged, or a different batch of that name in the outbox).
    Resend(String),
    Io(io::Error),
}

impl fmt::Display for PackError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Config(m) => write!(f, "configuration: {m}"),
            Self::State(m) => write!(f, "packer state: {m}"),
            Self::InvalidFinding { index, errors } => {
                write!(f, "finding #{index} is invalid:")?;
                for e in errors.iter().take(5) {
                    write!(f, " {e};")?;
                }
                Ok(())
            }
            Self::BadBundle { index, reason } => write!(f, "bundle #{index}: {reason}"),
            Self::BundleTooLarge { index, size, max } => {
                write!(f, "bundle #{index} is {size} bytes, batch limit {max}")
            }
            Self::Sign(m) => write!(f, "signing: {m}"),
            Self::Locked(p) => write!(
                f,
                "another robodr-diode-pack instance holds {} (one packer per state file)",
                p.display()
            ),
            Self::Resend(m) => write!(f, "resend: {m}"),
            Self::Io(e) => write!(f, "I/O: {e}"),
        }
    }
}

impl std::error::Error for PackError {}

impl From<io::Error> for PackError {
    fn from(e: io::Error) -> Self {
        Self::Io(e)
    }
}

/// Writes batches into an outbox. One packer per state file, enforced by an
/// exclusive lock on `<state>.lock` held while the packer lives.
pub struct Packer {
    outbox: PathBuf,
    state_path: PathBuf,
    archive: PathBuf,
    cfg: PackConfig,
    /// `None` when opened with [`Packer::open_for_resend`].
    signer: Option<Box<dyn Signer>>,
    state: PackState,
    /// Set when a committed batch could not be renamed into place; the
    /// packer must be re-opened (which finishes that batch) before more work.
    broken: bool,
    /// The `flock` on `<state>.lock`; released on drop.
    _lock: fs::File,
}

struct Planned {
    findings: Vec<String>,
    first: Option<u64>,
    last: Option<u64>,
    bundles: Vec<Vec<u8>>,
    bytes: u64,
    findings_bytes: u64,
    max_file: u64,
}

impl Planned {
    fn new() -> Self {
        Self {
            findings: Vec::new(),
            first: None,
            last: None,
            bundles: Vec::new(),
            bytes: 0,
            findings_bytes: 0,
            max_file: 0,
        }
    }
    fn is_empty(&self) -> bool {
        self.findings.is_empty() && self.bundles.is_empty()
    }
}

impl Packer {
    /// Open (or initialise) the packer state and recover from a crash
    /// between "state committed" and "batch renamed into the outbox".
    ///
    /// Fails with [`PackError::Locked`] while another packer has the same
    /// state file open.
    pub fn open(
        outbox: impl Into<PathBuf>,
        state_path: impl Into<PathBuf>,
        cfg: PackConfig,
        signer: Box<dyn Signer>,
    ) -> Result<Self, PackError> {
        if !is_valid_key_id(signer.key_id()) || !is_valid_key_id(signer.algorithm()) {
            return Err(PackError::Config(
                "signer key id / algorithm invalid".into(),
            ));
        }
        Self::open_inner(outbox.into(), state_path.into(), cfg, Some(signer))
    }

    /// Open without a signing key, for [`Packer::resend`] only (packing
    /// fails). Recovery of an interrupted publish still runs.
    pub fn open_for_resend(
        outbox: impl Into<PathBuf>,
        state_path: impl Into<PathBuf>,
        unit_id: &str,
    ) -> Result<Self, PackError> {
        Self::open_inner(
            outbox.into(),
            state_path.into(),
            PackConfig::new(unit_id),
            None,
        )
    }

    fn open_inner(
        outbox: PathBuf,
        state_path: PathBuf,
        cfg: PackConfig,
        signer: Option<Box<dyn Signer>>,
    ) -> Result<Self, PackError> {
        if !is_valid_robot_id(&cfg.unit_id) {
            return Err(PackError::Config(
                "unit id must match [A-Za-z0-9._-]{1,64}".into(),
            ));
        }
        if !(MIN_BATCH_BYTES..=MAX_BATCH_BYTES).contains(&cfg.max_batch_bytes) {
            return Err(PackError::Config(format!(
                "max_batch_bytes must be in {MIN_BATCH_BYTES}..={MAX_BATCH_BYTES}"
            )));
        }
        if cfg.max_findings_per_batch == 0 {
            return Err(PackError::Config(
                "max_findings_per_batch must be >= 1".into(),
            ));
        }
        if cfg.parity_shards > 0 {
            if cfg.parity_shards > MAX_PARITY_SHARDS {
                return Err(PackError::Config(format!(
                    "parity_shards must be <= {MAX_PARITY_SHARDS}"
                )));
            }
            if !(MIN_SHARD_SIZE..=MAX_SHARD_SIZE).contains(&cfg.shard_size) {
                return Err(PackError::Config(format!(
                    "shard_size must be in {MIN_SHARD_SIZE}..={MAX_SHARD_SIZE}"
                )));
            }
            let need = cfg.batch_size(MIN_BATCH_BYTES, MIN_BATCH_BYTES);
            if need > cfg.max_batch_bytes {
                return Err(PackError::Config(format!(
                    "max_batch_bytes {} cannot hold one maximal finding plus {} parity files \
                     ({need} bytes); raise it or lower parity_shards / shard_size",
                    cfg.max_batch_bytes, cfg.parity_shards
                )));
            }
        }
        fsutil::require_real_dir(&outbox)?;
        let state_dir = state_path
            .parent()
            .filter(|p| !p.as_os_str().is_empty())
            .unwrap_or(Path::new("."));
        if fs::canonicalize(state_dir)?.starts_with(fs::canonicalize(&outbox)?) {
            return Err(PackError::Config(
                "the state file must not be inside the outbox (its lock and archive would be \
                 transferred)"
                    .into(),
            ));
        }
        let lock_path = fsutil::lock_path(&state_path);
        let lock = fsutil::try_lock(&lock_path)?.ok_or(PackError::Locked(lock_path))?;
        let archive = archive_dir(&state_path);
        let state = match fsutil::read_capped(&state_path, MAX_STATE_BYTES) {
            Ok(b) => {
                let s: PackState = serde_json::from_slice(&b)
                    .map_err(|e| PackError::State(format!("unparsable: {e}")))?;
                if s.format != STATE_FORMAT
                    || s.next_seq == 0
                    || s.next_seq > MAX_BATCH_SEQ + 1
                    || (s.next_seq == 1) != s.last_batch_hash.is_none()
                    || s.last_batch_hash
                        .as_deref()
                        .is_some_and(|h| !is_hex_digest(h))
                {
                    return Err(PackError::State("inconsistent state file".into()));
                }
                if s.unit_id != cfg.unit_id {
                    return Err(PackError::State(format!(
                        "state belongs to unit {:?}, not {:?}",
                        s.unit_id, cfg.unit_id
                    )));
                }
                s
            }
            Err(ReadError::Missing) => PackState {
                format: STATE_FORMAT.into(),
                unit_id: cfg.unit_id.clone(),
                next_seq: 1,
                last_batch_hash: None,
            },
            Err(ReadError::Io(e)) => return Err(e.into()),
            Err(e) => return Err(PackError::State(format!("unreadable: {e:?}"))),
        };
        if cfg.archive_keep > 0 {
            fsutil::ensure_real_dir(&archive)?;
        }
        let mut p = Self {
            outbox,
            state_path,
            archive,
            cfg,
            signer,
            state,
            broken: false,
            _lock: lock,
        };
        p.recover()?;
        Ok(p)
    }

    /// The archive directory (`<state>.archive`).
    pub fn archive(&self) -> &Path {
        &self.archive
    }

    pub fn state(&self) -> &PackState {
        &self.state
    }

    /// The configuration this packer was opened with (read-only: a caller
    /// planning batches, e.g. `robodr-export`, checks its own limits against
    /// it).
    pub fn config(&self) -> &PackConfig {
        &self.cfg
    }

    pub fn outbox(&self) -> &Path {
        &self.outbox
    }

    fn recover(&mut self) -> Result<(), PackError> {
        let committed = self.state.next_seq.checked_sub(1).filter(|&s| s > 0);
        for entry in fs::read_dir(&self.outbox)? {
            let entry = entry?;
            let name = entry.file_name();
            let Some(name) = name.to_str() else { continue };
            if let Some(batch) = name.strip_prefix(RESEND_PREFIX) {
                // An interrupted resend: never committed anywhere.
                if self.own_seq(batch).is_some() {
                    remove_entry(&entry.path())?;
                }
                continue;
            }
            let Some(batch) = name.strip_prefix(TMP_PREFIX) else {
                continue;
            };
            let Some(seq) = self.own_seq(batch) else {
                continue;
            };
            let path = entry.path();
            if fs::symlink_metadata(&path)?.file_type().is_symlink() {
                return Err(PackError::State(format!(
                    "{} is a symlink; refusing to touch it",
                    path.display()
                )));
            }
            let final_path = self.outbox.join(batch);
            if Some(seq) == committed && !fsutil::exists_nofollow(&final_path) {
                let hash =
                    fsutil::read_capped(&path.join(MANIFEST_FILE), MAX_MANIFEST_BYTES as u64)
                        .ok()
                        .map(|b| batch_hash(&b));
                if hash.is_some() && hash == self.state.last_batch_hash {
                    fs::rename(&path, &final_path)?;
                    fsutil::fsync_dir(&self.outbox)?;
                    continue;
                }
            }
            if seq >= self.state.next_seq || fsutil::exists_nofollow(&final_path) {
                // Never committed (or already published): discard.
                fs::remove_dir_all(&path)?;
            } else {
                return Err(PackError::State(format!(
                    "{} is a committed batch that cannot be recovered",
                    path.display()
                )));
            }
        }
        self.recover_archive()
    }

    /// Drop archive entries that were never committed (a crash between
    /// archiving and committing) and interrupted archive copies.
    fn recover_archive(&mut self) -> Result<(), PackError> {
        if !fsutil::exists_nofollow(&self.archive) {
            return Ok(());
        }
        fsutil::require_real_dir(&self.archive)?;
        for entry in fs::read_dir(&self.archive)? {
            let entry = entry?;
            let name = entry.file_name();
            let Some(name) = name.to_str() else { continue };
            let (batch, tmp) = match name.strip_prefix(TMP_PREFIX) {
                Some(b) => (b, true),
                None => (name, false),
            };
            let Some(seq) = self.own_seq(batch) else {
                continue;
            };
            if tmp || seq >= self.state.next_seq {
                remove_entry(&entry.path())?;
            }
        }
        Ok(())
    }

    /// Archived batches of this unit, ascending by seq.
    fn archived(&self) -> Result<Vec<(u64, PathBuf)>, PackError> {
        let mut v = Vec::new();
        if !fsutil::exists_nofollow(&self.archive) {
            return Ok(v);
        }
        for entry in fs::read_dir(&self.archive)? {
            let entry = entry?;
            let name = entry.file_name();
            let Some(seq) = name.to_str().and_then(|n| self.own_seq(n)) else {
                continue;
            };
            v.push((seq, entry.path()));
        }
        v.sort();
        Ok(v)
    }

    /// Keep only the newest `archive_keep` archived batches (best effort).
    fn prune_archive(&self) -> Result<(), PackError> {
        let all = self.archived()?;
        let excess = all.len().saturating_sub(self.cfg.archive_keep);
        for (_, p) in &all[..excess] {
            remove_entry(p)?;
        }
        Ok(())
    }

    fn own_seq(&self, batch: &str) -> Option<u64> {
        let rest = batch
            .strip_prefix("rdd_")?
            .strip_prefix(self.cfg.unit_id.as_str())?
            .strip_prefix('_')?;
        if rest.len() == 16 && rest.bytes().all(|b| b.is_ascii_digit()) {
            rest.parse().ok()
        } else {
            None
        }
    }

    /// Validate and pack raw JSON Lines values (each re-validated with
    /// [`robodr_ocsf::parse_and_validate`]). See [`Packer::pack`].
    pub fn pack_lines(
        &mut self,
        lines: &[&str],
        bundles: &[Vec<u8>],
        now_ms: u64,
    ) -> Result<Vec<PublishedBatch>, PackError> {
        let mut envs = Vec::with_capacity(lines.len());
        for (index, l) in lines.iter().enumerate() {
            envs.push(
                robodr_ocsf::parse_and_validate(l)
                    .map_err(|errors| PackError::InvalidFinding { index, errors })?,
            );
        }
        self.pack(&envs, bundles, now_ms)
    }

    /// Pack `findings` (each validated and serialised with
    /// [`robodr_ocsf::to_json`]) and raw black-box bundle bytes (each parsed
    /// with [`Bundle::from_bytes`]) into as many batches as the limits
    /// require, preserving input order (findings first, then bundles).
    /// `now_ms` is the `created_at` of every batch (the library has no clock).
    ///
    /// All inputs are checked before anything is written. Returns the
    /// published batches (empty when there was nothing to pack).
    pub fn pack(
        &mut self,
        findings: &[FindingEnvelope],
        bundles: &[Vec<u8>],
        now_ms: u64,
    ) -> Result<Vec<PublishedBatch>, PackError> {
        if self.broken {
            return Err(PackError::State(
                "a previous publish failed after commit; re-open the packer".into(),
            ));
        }
        if self.signer.is_none() {
            return Err(PackError::Config(
                "packer opened for resend only (no signing key)".into(),
            ));
        }
        if !(MIN_TIME_MS..MAX_TIME_MS).contains(&now_ms) {
            return Err(PackError::Config(
                "now_ms out of range (clock unset?)".into(),
            ));
        }
        let max = self.cfg.max_batch_bytes;
        let mut lines = Vec::with_capacity(findings.len());
        for (index, env) in findings.iter().enumerate() {
            let json = robodr_ocsf::to_json(env)
                .map_err(|errors| PackError::InvalidFinding { index, errors })?;
            lines.push((json, env.ocsf.time));
        }
        for (index, b) in bundles.iter().enumerate() {
            Bundle::from_bytes(b).map_err(|e| PackError::BadBundle {
                index,
                reason: e.to_string(),
            })?;
            let len = b.len() as u64;
            if self.cfg.batch_size(len, len) > max {
                return Err(PackError::BundleTooLarge {
                    index,
                    size: self.cfg.batch_size(len, len),
                    max,
                });
            }
        }

        let mut plans = Vec::new();
        let mut cur = Planned::new();
        for (json, t) in lines {
            let add = json.len() as u64 + 1;
            let grown = self
                .cfg
                .batch_size(cur.bytes + add, cur.max_file.max(cur.findings_bytes + add));
            if !cur.findings.is_empty()
                && (grown > max || cur.findings.len() >= self.cfg.max_findings_per_batch)
            {
                plans.push(std::mem::replace(&mut cur, Planned::new()));
            }
            cur.bytes += add;
            cur.findings_bytes += add;
            cur.max_file = cur.max_file.max(cur.findings_bytes);
            cur.first = Some(cur.first.map_or(t, |f| f.min(t)));
            cur.last = Some(cur.last.map_or(t, |l| l.max(t)));
            cur.findings.push(json);
        }
        for b in bundles {
            let add = b.len() as u64;
            let files = cur.bundles.len() + usize::from(!cur.findings.is_empty());
            let grown = self.cfg.batch_size(cur.bytes + add, cur.max_file.max(add));
            if !cur.is_empty() && (grown > max || files >= self.cfg.max_data_files()) {
                plans.push(std::mem::replace(&mut cur, Planned::new()));
            }
            cur.bytes += add;
            cur.max_file = cur.max_file.max(add);
            cur.bundles.push(b.clone());
        }
        if !cur.is_empty() {
            plans.push(cur);
        }

        let mut out = Vec::with_capacity(plans.len());
        for p in plans {
            out.push(self.publish(p, now_ms)?);
        }
        Ok(out)
    }

    fn publish(&mut self, p: Planned, now_ms: u64) -> Result<PublishedBatch, PackError> {
        let signer = self
            .signer
            .as_ref()
            .ok_or_else(|| PackError::Config("no signing key".into()))?;
        let seq = self.state.next_seq;
        if seq > MAX_BATCH_SEQ {
            return Err(PackError::State(format!(
                "batch sequence exhausted (> {MAX_BATCH_SEQ})"
            )));
        }
        let name = batch_dir_name(&self.cfg.unit_id, seq);
        let mut files: Vec<(String, FileKind, Vec<u8>)> = Vec::new();
        let finding_count = p.findings.len() as u64;
        if !p.findings.is_empty() {
            let mut data = Vec::with_capacity(p.bytes as usize);
            for l in &p.findings {
                data.extend_from_slice(l.as_bytes());
                data.push(b'\n');
            }
            files.push((FINDINGS_FILE.into(), FileKind::Findings, data));
        }
        let bundle_count = p.bundles.len();
        for (i, b) in p.bundles.into_iter().enumerate() {
            files.push((bundle_file_name(i + 1), FileKind::BlackboxBundle, b));
        }
        let data_bytes: u64 = files.iter().map(|(_, _, b)| b.len() as u64).sum();
        let mut parity = None;
        let m = self.cfg.parity_shards;
        if m > 0 {
            let k = files.len();
            let rs = ReedSolomon::new(k, m)
                .map_err(|e| PackError::Config(format!("internal: parity: {e}")))?;
            let max_file = files
                .iter()
                .map(|(_, _, b)| b.len() as u64)
                .max()
                .unwrap_or(0);
            let plen = usize::try_from(parity_len(max_file, self.cfg.shard_size))
                .map_err(|_| PackError::Config("parity length overflows usize".into()))?;
            let shards = {
                let data: Vec<&[u8]> = files.iter().map(|(_, _, b)| b.as_slice()).collect();
                rs.encode(&data, plen)
                    .map_err(|e| PackError::Config(format!("internal: parity: {e}")))?
            };
            for (j, sh) in shards.into_iter().enumerate() {
                files.push((parity_file_name(j + 1), FileKind::Parity, sh));
            }
            parity = Some(ParitySpec {
                scheme: PARITY_SCHEME.into(),
                data_shards: k as u32,
                parity_shards: m as u32,
                shard_size: self.cfg.shard_size,
            });
        }
        let manifest = Manifest {
            format: FORMAT.into(),
            contract_version: CONTRACT_VERSION.into(),
            unit_id: self.cfg.unit_id.clone(),
            batch_seq: seq,
            prev_batch_hash: self.state.last_batch_hash.clone(),
            created_at: robodr_ocsf::builder::rfc3339_ms(now_ms),
            created_at_ms: now_ms,
            key_id: signer.key_id().to_string(),
            algorithm: signer.algorithm().to_string(),
            finding_count,
            first_time: p.first,
            last_time: p.last,
            files: files
                .iter()
                .map(|(n, k, b)| FileEntry {
                    name: n.clone(),
                    kind: *k,
                    size: b.len() as u64,
                    sha256: file_sha256(b),
                })
                .collect(),
            parity,
        };
        manifest
            .check()
            .map_err(|e| PackError::Config(format!("internal: produced bad manifest: {e}")))?;
        let mut mbytes = serde_json::to_vec_pretty(&manifest)
            .map_err(|e| PackError::Config(format!("manifest serialisation: {e}")))?;
        mbytes.push(b'\n');
        if mbytes.len() > MAX_MANIFEST_BYTES {
            return Err(PackError::Config(
                "manifest exceeds MAX_MANIFEST_BYTES".into(),
            ));
        }
        let sig = signer
            .sign(&manifest_signing_message(&mbytes))
            .map_err(|e| PackError::Sign(e.to_string()))?;
        if sig.is_empty() || sig.len() > MAX_SIG_LEN {
            return Err(PackError::Sign(format!("signature length {}", sig.len())));
        }
        let sigfile = SignatureFile {
            format: FORMAT.into(),
            algorithm: signer.algorithm().to_string(),
            key_id: signer.key_id().to_string(),
            sig: to_hex(&sig),
        };
        let mut sbytes = serde_json::to_vec(&sigfile)
            .map_err(|e| PackError::Config(format!("signature serialisation: {e}")))?;
        sbytes.push(b'\n');
        let hash = batch_hash(&mbytes);

        // 1. Stage.
        let tmp = self.outbox.join(format!("{TMP_PREFIX}{name}"));
        let final_path = self.outbox.join(&name);
        if fsutil::exists_nofollow(&final_path) {
            return Err(PackError::State(format!(
                "{} already exists (another packer, or a lost state file?)",
                final_path.display()
            )));
        }
        fs::create_dir(&tmp)?;
        let staged = (|| -> io::Result<()> {
            for (n, _, b) in &files {
                fsutil::write_new(&tmp.join(n), b)?;
            }
            fsutil::write_new(&tmp.join(MANIFEST_FILE), &mbytes)?;
            fsutil::write_new(&tmp.join(SIGNATURE_FILE), &sbytes)?;
            fsutil::fsync_dir(&tmp)
        })();
        if let Err(e) = staged {
            let _ = fs::remove_dir_all(&tmp);
            return Err(e.into());
        }
        // 1b. Archive a copy for resend (still uncommitted: `open` drops it
        //     if we crash before step 2).
        if self.cfg.archive_keep > 0 {
            if let Err(e) = self.archive_batch(&name, &files, &mbytes, &sbytes) {
                let _ = fs::remove_dir_all(&tmp);
                return Err(e.into());
            }
        }
        // 2. Commit the sequence number and chain head.
        let new_state = PackState {
            format: STATE_FORMAT.into(),
            unit_id: self.cfg.unit_id.clone(),
            next_seq: seq + 1,
            last_batch_hash: Some(hash.clone()),
        };
        let sjson = serde_json::to_vec_pretty(&new_state)
            .map_err(|e| PackError::State(format!("serialisation: {e}")))?;
        if let Err(e) = fsutil::atomic_write(&self.state_path, &sjson) {
            let _ = fs::remove_dir_all(&tmp);
            let _ = fs::remove_dir_all(self.archive.join(&name));
            return Err(e.into());
        }
        self.state = new_state;
        // 3. Publish. On failure the temp dir stays; `open` finishes it.
        self.broken = true;
        fs::rename(&tmp, &final_path)?;
        fsutil::fsync_dir(&self.outbox)?;
        self.broken = false;
        if self.cfg.archive_keep > 0 {
            // Best effort: a failed prune only keeps more history.
            let _ = self.prune_archive();
        }
        Ok(PublishedBatch {
            name,
            path: final_path,
            seq,
            batch_hash: hash,
            finding_count,
            bundle_count,
            data_bytes,
            parity_files: m,
        })
    }

    /// Write `archive/<name>/` (via `archive/.tmp-<name>/` and a rename).
    fn archive_batch(
        &self,
        name: &str,
        files: &[(String, FileKind, Vec<u8>)],
        mbytes: &[u8],
        sbytes: &[u8],
    ) -> io::Result<()> {
        fsutil::require_real_dir(&self.archive)?;
        let tmp = self.archive.join(format!("{TMP_PREFIX}{name}"));
        let fin = self.archive.join(name);
        // Leftovers of an uncommitted attempt at this seq (normally removed
        // by `open` already).
        for p in [&tmp, &fin] {
            if fsutil::exists_nofollow(p) {
                remove_entry(p)?;
            }
        }
        fs::create_dir(&tmp)?;
        let res = (|| {
            for (n, _, b) in files {
                fsutil::write_new(&tmp.join(n), b)?;
            }
            fsutil::write_new(&tmp.join(MANIFEST_FILE), mbytes)?;
            fsutil::write_new(&tmp.join(SIGNATURE_FILE), sbytes)?;
            fsutil::fsync_dir(&tmp)?;
            fs::rename(&tmp, &fin)?;
            fsutil::fsync_dir(&self.archive)
        })();
        if res.is_err() {
            let _ = fs::remove_dir_all(&tmp);
        }
        res
    }

    /// Re-emit published batch `seq` from the archive into the outbox, byte
    /// for byte, for manual retransmission.
    ///
    /// The archived manifests from `seq` up to the newest batch must chain
    /// to the state's `last_batch_hash`, and every archived file must match
    /// its manifest size and SHA-256 (checked while copying). If the outbox
    /// already holds an identical copy, nothing is written
    /// (`already_present`); a *different* entry of that name is an error.
    /// The copy is staged under `outbox/.resend-<batch>/` and renamed into
    /// place, so the transfer agent never sees a partial batch.
    pub fn resend(&mut self, seq: u64) -> Result<ResentBatch, PackError> {
        if self.broken {
            return Err(PackError::State(
                "a previous publish failed after commit; re-open the packer".into(),
            ));
        }
        if seq == 0 || seq >= self.state.next_seq {
            return Err(PackError::Resend(format!(
                "batch {seq} has not been published (next seq is {})",
                self.state.next_seq
            )));
        }
        let name = batch_dir_name(&self.cfg.unit_id, seq);
        let src = self.archive.join(&name);
        if fsutil::require_real_dir(&src).is_err() {
            return Err(PackError::Resend(format!(
                "{name} is not in the archive {} (pruned, or archive_keep = 0 when it was published)",
                self.archive.display()
            )));
        }
        let (manifest, mbytes, hash) = self.verify_archive_chain(seq)?;
        let sbytes =
            fsutil::read_capped(&src.join(SIGNATURE_FILE), MAX_SIGNATURE_FILE_BYTES as u64)
                .map_err(|e| PackError::Resend(format!("{name}/{SIGNATURE_FILE}: {e:?}")))?;
        let dst = self.outbox.join(&name);
        if fsutil::exists_nofollow(&dst) {
            return match same_batch(&dst, &manifest, &mbytes, &sbytes) {
                Ok(()) => Ok(ResentBatch {
                    name,
                    path: dst,
                    seq,
                    batch_hash: hash,
                    already_present: true,
                }),
                Err(why) => Err(PackError::Resend(format!(
                    "{} exists and is not this batch ({why}); move it away first",
                    dst.display()
                ))),
            };
        }
        let tmp = self.outbox.join(format!("{RESEND_PREFIX}{name}"));
        if fsutil::exists_nofollow(&tmp) {
            remove_entry(&tmp)?;
        }
        fs::create_dir(&tmp)?;
        let res = (|| -> Result<(), PackError> {
            only_listed(&src, &manifest).map_err(PackError::Resend)?;
            for f in &manifest.files {
                let (len, sha) =
                    fsutil::copy_hashed(&src.join(&f.name), &tmp.join(&f.name), f.size).map_err(
                        |e| PackError::Resend(format!("archived {name}/{}: {e:?}", f.name)),
                    )?;
                if len != f.size || sha != f.sha256 {
                    return Err(PackError::Resend(format!(
                        "archived {name}/{} does not match its manifest (archive damaged)",
                        f.name
                    )));
                }
            }
            fsutil::write_new(&tmp.join(MANIFEST_FILE), &mbytes)?;
            fsutil::write_new(&tmp.join(SIGNATURE_FILE), &sbytes)?;
            fsutil::fsync_dir(&tmp)?;
            fs::rename(&tmp, &dst)?;
            fsutil::fsync_dir(&self.outbox)?;
            Ok(())
        })();
        if res.is_err() {
            let _ = fs::remove_dir_all(&tmp);
        }
        res?;
        Ok(ResentBatch {
            name,
            path: dst,
            seq,
            batch_hash: hash,
            already_present: false,
        })
    }

    /// Walk the archived manifests from the newest batch down to `seq`,
    /// checking each hash against the state head / the successor's
    /// `prev_batch_hash`. Returns batch `seq`'s manifest, bytes and hash.
    fn verify_archive_chain(&self, seq: u64) -> Result<(Manifest, Vec<u8>, String), PackError> {
        let mut expected = self.state.last_batch_hash.clone();
        let mut out = None;
        for s in (seq..self.state.next_seq).rev() {
            let name = batch_dir_name(&self.cfg.unit_id, s);
            let mbytes = fsutil::read_capped(
                &self.archive.join(&name).join(MANIFEST_FILE),
                MAX_MANIFEST_BYTES as u64,
            )
            .map_err(|e| {
                PackError::Resend(format!(
                    "archived {name}/{MANIFEST_FILE}: {e:?} (the archive must hold every batch \
                     from {seq} to the newest)"
                ))
            })?;
            let h = batch_hash(&mbytes);
            if Some(&h) != expected.as_ref() {
                return Err(PackError::Resend(format!(
                    "archived {name} does not chain to the packer state (archive damaged or \
                     from another state file)"
                )));
            }
            let m: Manifest = serde_json::from_slice(&mbytes)
                .map_err(|e| PackError::Resend(format!("archived {name}: {e}")))?;
            m.check()
                .map_err(|e| PackError::Resend(format!("archived {name}: {e}")))?;
            if m.unit_id != self.cfg.unit_id || m.batch_seq != s {
                return Err(PackError::Resend(format!(
                    "archived {name} names another unit or seq"
                )));
            }
            expected = m.prev_batch_hash.clone();
            if s == seq {
                out = Some((m, mbytes, h));
            }
        }
        out.ok_or_else(|| PackError::Resend(format!("batch {seq} not found")))
    }
}

/// Remove a file or directory tree (never following a symlink).
fn remove_entry(p: &Path) -> io::Result<()> {
    let meta = fs::symlink_metadata(p)?;
    if meta.is_dir() {
        fs::remove_dir_all(p)
    } else {
        fs::remove_file(p)
    }
}

/// `dir` holds nothing but the manifest, its signature and the listed files.
fn only_listed(dir: &Path, m: &Manifest) -> Result<(), String> {
    for e in fs::read_dir(dir).map_err(|e| e.to_string())? {
        let n = e.map_err(|e| e.to_string())?.file_name();
        let ok = n.to_str().is_some_and(|n| {
            n == MANIFEST_FILE || n == SIGNATURE_FILE || m.files.iter().any(|f| f.name == n)
        });
        if !ok {
            return Err(format!("unexpected entry {:?}", n.to_string_lossy()));
        }
    }
    Ok(())
}

/// Does `dir` hold exactly this batch (same manifest and signature bytes,
/// every listed file of the right size and hash, nothing else)?
fn same_batch(dir: &Path, m: &Manifest, mbytes: &[u8], sbytes: &[u8]) -> Result<(), String> {
    fsutil::require_real_dir(dir).map_err(|e| e.to_string())?;
    only_listed(dir, m)?;
    let mf = fsutil::read_capped(&dir.join(MANIFEST_FILE), MAX_MANIFEST_BYTES as u64)
        .map_err(|e| format!("{MANIFEST_FILE}: {e:?}"))?;
    if mf != mbytes {
        return Err("different manifest".into());
    }
    let sf = fsutil::read_capped(&dir.join(SIGNATURE_FILE), MAX_SIGNATURE_FILE_BYTES as u64)
        .map_err(|e| format!("{SIGNATURE_FILE}: {e:?}"))?;
    if sf != sbytes {
        return Err("different signature file".into());
    }
    for f in &m.files {
        match fsutil::hash_file(&dir.join(&f.name), f.size) {
            Ok((len, sha)) if len == f.size && sha == f.sha256 => {}
            Ok(_) => return Err(format!("{} differs", f.name)),
            Err(e) => return Err(format!("{}: {e:?}", f.name)),
        }
    }
    Ok(())
}
