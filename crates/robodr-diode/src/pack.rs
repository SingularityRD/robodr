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

use crate::fsutil::{self, ReadError};
use crate::manifest::{
    batch_dir_name, batch_hash, bundle_file_name, file_sha256, is_hex_digest, is_valid_key_id,
    manifest_signing_message, FileEntry, FileKind, Manifest, SignatureFile, FINDINGS_FILE, FORMAT,
    MANIFEST_FILE, MAX_FILES, MAX_MANIFEST_BYTES, MAX_SIG_LEN, SIGNATURE_FILE,
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
/// Largest allowed `max_batch_bytes` (1 GiB).
pub const MAX_BATCH_BYTES: u64 = 1024 * 1024 * 1024;
const STATE_FORMAT: &str = "robodr-diode-pack-state/1";
const MAX_STATE_BYTES: u64 = 64 * 1024;
const TMP_PREFIX: &str = ".tmp-";

/// Packer configuration.
#[derive(Debug, Clone)]
pub struct PackConfig {
    /// Exporting unit id (`[A-Za-z0-9._-]{1,64}`).
    pub unit_id: String,
    /// Upper bound on the sum of data file sizes of one batch.
    pub max_batch_bytes: u64,
    /// Upper bound on findings per batch (>= 1).
    pub max_findings_per_batch: usize,
}

impl PackConfig {
    pub fn new(unit_id: impl Into<String>) -> Self {
        Self {
            unit_id: unit_id.into(),
            max_batch_bytes: DEFAULT_MAX_BATCH_BYTES,
            max_findings_per_batch: DEFAULT_MAX_FINDINGS_PER_BATCH,
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

/// Writes batches into an outbox. One packer per (unit, outbox, state file);
/// running two concurrently is not supported.
pub struct Packer {
    outbox: PathBuf,
    state_path: PathBuf,
    cfg: PackConfig,
    signer: Box<dyn Signer>,
    state: PackState,
    /// Set when a committed batch could not be renamed into place; the
    /// packer must be re-opened (which finishes that batch) before more work.
    broken: bool,
}

struct Planned {
    findings: Vec<String>,
    first: Option<u64>,
    last: Option<u64>,
    bundles: Vec<Vec<u8>>,
    bytes: u64,
}

impl Planned {
    fn new() -> Self {
        Self {
            findings: Vec::new(),
            first: None,
            last: None,
            bundles: Vec::new(),
            bytes: 0,
        }
    }
    fn is_empty(&self) -> bool {
        self.findings.is_empty() && self.bundles.is_empty()
    }
}

impl Packer {
    /// Open (or initialise) the packer state and recover from a crash
    /// between "state committed" and "batch renamed into the outbox".
    pub fn open(
        outbox: impl Into<PathBuf>,
        state_path: impl Into<PathBuf>,
        cfg: PackConfig,
        signer: Box<dyn Signer>,
    ) -> Result<Self, PackError> {
        let outbox = outbox.into();
        let state_path = state_path.into();
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
        if !is_valid_key_id(signer.key_id()) || !is_valid_key_id(signer.algorithm()) {
            return Err(PackError::Config(
                "signer key id / algorithm invalid".into(),
            ));
        }
        fsutil::require_real_dir(&outbox)?;
        let state = match fsutil::read_capped(&state_path, MAX_STATE_BYTES) {
            Ok(b) => {
                let s: PackState = serde_json::from_slice(&b)
                    .map_err(|e| PackError::State(format!("unparsable: {e}")))?;
                if s.format != STATE_FORMAT
                    || s.next_seq == 0
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
        let mut p = Self {
            outbox,
            state_path,
            cfg,
            signer,
            state,
            broken: false,
        };
        p.recover()?;
        Ok(p)
    }

    pub fn state(&self) -> &PackState {
        &self.state
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
            if b.len() as u64 > max {
                return Err(PackError::BundleTooLarge {
                    index,
                    size: b.len() as u64,
                    max,
                });
            }
        }

        let mut plans = Vec::new();
        let mut cur = Planned::new();
        for (json, t) in lines {
            let add = json.len() as u64 + 1;
            if !cur.findings.is_empty()
                && (cur.bytes + add > max || cur.findings.len() >= self.cfg.max_findings_per_batch)
            {
                plans.push(std::mem::replace(&mut cur, Planned::new()));
            }
            cur.bytes += add;
            cur.first = Some(cur.first.map_or(t, |f| f.min(t)));
            cur.last = Some(cur.last.map_or(t, |l| l.max(t)));
            cur.findings.push(json);
        }
        for b in bundles {
            let add = b.len() as u64;
            let files = cur.bundles.len() + usize::from(!cur.findings.is_empty());
            if !cur.is_empty() && (cur.bytes + add > max || files >= MAX_FILES) {
                plans.push(std::mem::replace(&mut cur, Planned::new()));
            }
            cur.bytes += add;
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
        let seq = self.state.next_seq;
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
        let manifest = Manifest {
            format: FORMAT.into(),
            contract_version: CONTRACT_VERSION.into(),
            unit_id: self.cfg.unit_id.clone(),
            batch_seq: seq,
            prev_batch_hash: self.state.last_batch_hash.clone(),
            created_at: robodr_ocsf::builder::rfc3339_ms(now_ms),
            created_at_ms: now_ms,
            key_id: self.signer.key_id().to_string(),
            algorithm: self.signer.algorithm().to_string(),
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
        let sig = self
            .signer
            .sign(&manifest_signing_message(&mbytes))
            .map_err(|e| PackError::Sign(e.to_string()))?;
        if sig.is_empty() || sig.len() > MAX_SIG_LEN {
            return Err(PackError::Sign(format!("signature length {}", sig.len())));
        }
        let sigfile = SignatureFile {
            format: FORMAT.into(),
            algorithm: self.signer.algorithm().to_string(),
            key_id: self.signer.key_id().to_string(),
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
            return Err(e.into());
        }
        self.state = new_state;
        // 3. Publish. On failure the temp dir stays; `open` finishes it.
        self.broken = true;
        fs::rename(&tmp, &final_path)?;
        fsutil::fsync_dir(&self.outbox)?;
        self.broken = false;
        Ok(PublishedBatch {
            name,
            path: final_path,
            seq,
            batch_hash: hash,
            finding_count,
            bundle_count,
            data_bytes: manifest.total_size(),
        })
    }
}
