//! High side (SOC): verify, sequence-check and unpack batches from an inbox.
//!
//! For every entry of the inbox (sorted by unit and sequence number):
//!
//! 1. **Authenticate before parsing.** Only the small signature file is parsed
//!    before authentication; the manifest's raw bytes are verified with the
//!    [`Keyring`] verifier named by the signature's key id, and only then
//!    parsed (`deny_unknown_fields`, [`Manifest::check`]). The key must belong
//!    to the manifest's unit, and the directory name must be exactly
//!    [`batch_dir_name`]`(unit, seq)`.
//! 2. **Sequence check** against the persisted per-unit state:
//!    * `seq == last + 1` and `prev_batch_hash == last hash` → verify files;
//!    * `seq == last + 1` with another `prev_batch_hash` → quarantine (chain break);
//!    * `seq <= last` with the same batch hash as recorded → duplicate
//!      (idempotent re-send / replay of identical content): files are still
//!      verified (a corrupted copy is quarantined), then moved to
//!      `processed/`; nothing is re-emitted;
//!    * `seq <= last` with a different hash → quarantine (conflict), or
//!      (replay) when the sequence number is older than the remembered window;
//!    * `seq > last + 1` → **held** in the inbox and reported as a gap; it is
//!      picked up automatically once the missing batches arrive (reordering),
//!      or accepted when the operator explicitly accepts that gap
//!      ([`ImportConfig::accept_gaps`]), which is recorded in the state.
//! 3. **File checks**: no entry other than the manifest, its signature and the
//!    listed files; every listed file a regular non-symlink file of exactly
//!    the declared size and SHA-256; every findings line re-validated with
//!    [`robodr_ocsf::parse_and_validate`]; every bundle parsed (and verified,
//!    when a black-box verifier for its key is configured).
//! 4. **Emit** `out/<batch>/records.jsonl` (one Kafka record per line: topic,
//!    partition, key, headers, value — the shape of [`robodr_ocsf::Record`]),
//!    the bundles and a copy of the signed manifest, via a temp directory and
//!    a rename; then atomically update the state; then move the batch to
//!    `processed/`. A crash anywhere re-runs idempotently.
//!
//! Anything that fails a check is moved to `quarantine/` with a
//! `<name>.reason.json` next to it; the state does not advance, so an intact
//! re-send of the same batch is accepted later.

use crate::fsutil::{self, ReadError};
use crate::manifest::{
    batch_dir_name, batch_hash, file_sha256, is_hex_digest, manifest_signing_message, trunc,
    FileKind, Manifest, SignatureFile, FORMAT, MANIFEST_FILE, MAX_MANIFEST_BYTES,
    MAX_SIGNATURE_FILE_BYTES, MAX_SIG_LEN, SIGNATURE_FILE,
};
use robodr_blackbox::crypto::from_hex;
use robodr_blackbox::{Bundle, FindingLevel, Verifier};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};
use std::fmt;
use std::fs;
use std::io;
use std::path::{Path, PathBuf};

/// Batch hashes remembered per unit for duplicate/conflict decisions.
pub const RECENT_WINDOW: usize = 1024;
/// Accepted gaps remembered per unit.
pub const MAX_RECORDED_GAPS: usize = 1024;
/// Default cap on the data bytes of one batch on import (256 MiB).
pub const DEFAULT_MAX_IMPORT_BATCH_BYTES: u64 = 256 * 1024 * 1024;
const STATE_FORMAT: &str = "robodr-diode-import-state/1";
const MAX_STATE_BYTES: u64 = 64 * 1024 * 1024;
/// File written into each emitted batch directory.
pub const RECORDS_FILE: &str = "records.jsonl";

/// Verifiers for batch manifests, each bound to the unit it may sign for.
#[derive(Default)]
pub struct Keyring {
    entries: Vec<(String, Box<dyn Verifier>)>,
}

impl Keyring {
    pub fn new() -> Self {
        Self::default()
    }

    /// Trust `verifier` for batches of `unit_id`. A key id may belong to one
    /// unit only (several keys per unit are fine, e.g. during rotation).
    pub fn add(&mut self, unit_id: &str, verifier: Box<dyn Verifier>) -> Result<(), String> {
        if !robodr_ocsf::validate::is_valid_robot_id(unit_id) {
            return Err(format!("invalid unit id {:?}", trunc(unit_id)));
        }
        if self
            .entries
            .iter()
            .any(|(_, v)| v.key_id() == verifier.key_id())
        {
            return Err(format!(
                "key id {:?} is already in the keyring",
                verifier.key_id()
            ));
        }
        self.entries.push((unit_id.to_string(), verifier));
        Ok(())
    }

    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    fn find(&self, key_id: &str) -> Option<(&str, &dyn Verifier)> {
        self.entries
            .iter()
            .find(|(_, v)| v.key_id() == key_id)
            .map(|(u, v)| (u.as_str(), v.as_ref()))
    }
}

/// Importer configuration.
#[derive(Debug, Clone)]
pub struct ImportConfig {
    /// Where complete batches arrive (dot-entries are treated as in transit).
    pub inbox: PathBuf,
    /// Accepted batches: `out/<batch>/records.jsonl`, bundles, manifest copy.
    pub out_dir: PathBuf,
    /// Rejected batches plus `<name>.reason.json`.
    pub quarantine_dir: PathBuf,
    /// Accepted and duplicate batches, moved out of the inbox.
    pub processed_dir: PathBuf,
    /// Persisted per-unit sequence state (JSON, replaced atomically).
    pub state_path: PathBuf,
    /// Kafka partition count of `robot-edr.findings`, if known.
    pub partitions: Option<u32>,
    /// Upper bound on the declared data size of one batch.
    pub max_batch_bytes: u64,
    /// `(unit, seq)` pairs the operator explicitly accepts despite a gap
    /// before them (or on first contact with `seq > 1`).
    pub accept_gaps: Vec<(String, u64)>,
}

impl ImportConfig {
    /// Conventional layout under one root: `inbox/`, `out/`, `quarantine/`,
    /// `processed/`, `state.json`.
    pub fn under(root: &Path) -> Self {
        Self {
            inbox: root.join("inbox"),
            out_dir: root.join("out"),
            quarantine_dir: root.join("quarantine"),
            processed_dir: root.join("processed"),
            state_path: root.join("state.json"),
            partitions: None,
            max_batch_bytes: DEFAULT_MAX_IMPORT_BATCH_BYTES,
            accept_gaps: Vec::new(),
        }
    }
}

/// Why a batch was quarantined (`code` in the reason file).
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(tag = "code", rename_all = "snake_case")]
pub enum QuarantineReason {
    /// Inbox entry name is not UTF-8 / not a batch name.
    BadEntryName,
    /// Inbox entry is a symlink.
    Symlink,
    /// Inbox entry is not a directory.
    NotADirectory,
    MissingManifest,
    MissingSignature,
    ManifestTooLarge {
        size: u64,
        max: u64,
    },
    SignatureFileInvalid {
        detail: String,
    },
    UnknownKey {
        key_id: String,
    },
    AlgorithmMismatch {
        expected: String,
        found: String,
    },
    BadSignature {
        key_id: String,
    },
    ManifestInvalid {
        detail: String,
    },
    UnitKeyMismatch {
        unit_id: String,
        key_unit: String,
    },
    NameMismatch {
        expected: String,
    },
    BatchTooLarge {
        size: u64,
        max: u64,
    },
    UnexpectedFile {
        name: String,
    },
    MissingFile {
        name: String,
    },
    NotRegularFile {
        name: String,
    },
    SizeMismatch {
        name: String,
        expected: u64,
        actual: u64,
    },
    HashMismatch {
        name: String,
    },
    FindingsFormat {
        detail: String,
    },
    InvalidFinding {
        line: usize,
        errors: Vec<String>,
    },
    CountMismatch {
        declared: u64,
        actual: u64,
    },
    TimeRangeMismatch,
    BadBundle {
        name: String,
        detail: String,
    },
    BundleVerifyFailed {
        name: String,
        detail: String,
    },
    /// `seq == last + 1` but `prev_batch_hash` is not the last accepted hash.
    ChainBreak {
        seq: u64,
        expected_prev: Option<String>,
        found_prev: Option<String>,
    },
    /// A different batch claims an already-accepted sequence number.
    Conflict {
        seq: u64,
        accepted_hash: String,
        found_hash: String,
    },
    /// An already-passed sequence number we hold no hash for (older than the
    /// window, or inside an accepted gap).
    Replay {
        seq: u64,
        last_seq: u64,
    },
}

impl fmt::Display for QuarantineReason {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let j = serde_json::to_string(self).unwrap_or_default();
        f.write_str(&j)
    }
}

/// An accepted batch.
#[derive(Debug, Clone, Serialize)]
pub struct AcceptedBatch {
    pub name: String,
    pub unit_id: String,
    pub seq: u64,
    pub batch_hash: String,
    pub findings: u64,
    pub bundles: usize,
    /// Bundles whose black-box signatures/chain were verified here.
    pub bundles_verified: usize,
    /// Sequence range skipped by an operator-accepted gap, if any.
    pub gap_accepted: Option<(u64, u64)>,
    pub output: PathBuf,
}

/// A batch identified only by name, unit and seq.
#[derive(Debug, Clone, Serialize)]
pub struct BatchRef {
    pub name: String,
    pub unit_id: String,
    pub seq: u64,
}

/// A batch left in the inbox because earlier batches are missing.
#[derive(Debug, Clone, Serialize)]
pub struct HeldBatch {
    pub name: String,
    pub unit_id: String,
    pub seq: u64,
    pub expected_seq: u64,
}

/// A quarantined inbox entry.
#[derive(Debug, Clone, Serialize)]
pub struct QuarantinedBatch {
    pub name: String,
    pub reason: QuarantineReason,
    pub moved_to: PathBuf,
}

/// Result of one [`Importer::run`].
#[derive(Debug, Clone, Default, Serialize)]
pub struct ImportReport {
    pub accepted: Vec<AcceptedBatch>,
    pub duplicates: Vec<BatchRef>,
    pub held: Vec<HeldBatch>,
    pub quarantined: Vec<QuarantinedBatch>,
    /// Dot-entries (still being written by the transfer agent).
    pub in_transit: Vec<String>,
}

impl ImportReport {
    /// Nothing quarantined and no gap pending.
    pub fn is_clean(&self) -> bool {
        self.quarantined.is_empty() && self.held.is_empty()
    }
}

/// Per-unit sequence state.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct UnitState {
    pub last_seq: u64,
    pub last_hash: String,
    /// `(seq, batch hash)` of recently accepted batches, ascending.
    pub recent: Vec<(u64, String)>,
    /// Inclusive sequence ranges skipped by operator decision.
    pub accepted_gaps: Vec<(u64, u64)>,
}

/// Persisted importer state.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ImportState {
    pub format: String,
    pub units: BTreeMap<String, UnitState>,
}

impl Default for ImportState {
    fn default() -> Self {
        Self {
            format: STATE_FORMAT.into(),
            units: BTreeMap::new(),
        }
    }
}

/// Importer failure (not a batch problem: those are quarantined).
#[derive(Debug)]
pub enum ImportError {
    Config(String),
    State(String),
    Io(io::Error),
}

impl fmt::Display for ImportError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Config(m) => write!(f, "configuration: {m}"),
            Self::State(m) => write!(f, "importer state: {m}"),
            Self::Io(e) => write!(f, "I/O: {e}"),
        }
    }
}

impl std::error::Error for ImportError {}

impl From<io::Error> for ImportError {
    fn from(e: io::Error) -> Self {
        Self::Io(e)
    }
}

struct Candidate {
    name: String,
    path: PathBuf,
    manifest: Manifest,
    manifest_bytes: Vec<u8>,
    sig_bytes: Vec<u8>,
    hash: String,
}

struct Verified {
    records: Vec<u8>,
    bundles: Vec<(String, Vec<u8>)>,
    bundles_verified: usize,
}

#[derive(Serialize)]
struct OutRecord<'a> {
    topic: &'a str,
    partition: Option<u32>,
    key: &'a str,
    headers: &'a [(&'static str, String)],
    value: &'a str,
    diode: Provenance<'a>,
}

#[derive(Serialize)]
struct Provenance<'a> {
    unit_id: &'a str,
    batch_seq: u64,
    batch_hash: &'a str,
    line: usize,
}

#[derive(Serialize)]
struct ReasonFile<'a> {
    format: &'a str,
    entry: &'a str,
    quarantined_at_ms: u64,
    reason: &'a QuarantineReason,
}

type Checked<T> = Result<Result<T, QuarantineReason>, io::Error>;

/// The SOC-side importer. One instance per state file; concurrent runs on
/// the same directories are not supported.
pub struct Importer {
    cfg: ImportConfig,
    keyring: Keyring,
    bundle_verifiers: Vec<Box<dyn Verifier>>,
    state: ImportState,
}

impl Importer {
    /// Check the directories (creating `out`, `quarantine`, `processed` if
    /// missing; none may be a symlink) and load the state.
    pub fn open(cfg: ImportConfig, keyring: Keyring) -> Result<Self, ImportError> {
        if keyring.is_empty() {
            return Err(ImportError::Config("keyring is empty".into()));
        }
        if cfg.partitions == Some(0) {
            return Err(ImportError::Config("partitions must be >= 1".into()));
        }
        fsutil::require_real_dir(&cfg.inbox)?;
        let dirs = [&cfg.out_dir, &cfg.quarantine_dir, &cfg.processed_dir];
        for d in dirs {
            fsutil::ensure_real_dir(d)?;
        }
        let canon: Vec<PathBuf> = [
            &cfg.inbox,
            &cfg.out_dir,
            &cfg.quarantine_dir,
            &cfg.processed_dir,
        ]
        .iter()
        .map(fs::canonicalize)
        .collect::<Result<_, _>>()?;
        for (i, a) in canon.iter().enumerate() {
            for (j, b) in canon.iter().enumerate() {
                if i != j && a.starts_with(b) {
                    return Err(ImportError::Config(
                        "inbox, out, quarantine and processed must be distinct, non-nested directories"
                            .into(),
                    ));
                }
            }
        }
        let state_parent = cfg
            .state_path
            .parent()
            .filter(|p| !p.as_os_str().is_empty())
            .unwrap_or(Path::new("."));
        if fs::canonicalize(state_parent)?.starts_with(&canon[0]) {
            return Err(ImportError::Config(
                "the state file must not be inside the inbox".into(),
            ));
        }
        let state = match fsutil::read_capped(&cfg.state_path, MAX_STATE_BYTES) {
            Ok(b) => {
                let s: ImportState = serde_json::from_slice(&b)
                    .map_err(|e| ImportError::State(format!("unparsable: {e}")))?;
                if s.format != STATE_FORMAT {
                    return Err(ImportError::State("unknown state format".into()));
                }
                for (u, st) in &s.units {
                    if st.last_seq == 0 || !is_hex_digest(&st.last_hash) {
                        return Err(ImportError::State(format!("bad entry for unit {u:?}")));
                    }
                }
                s
            }
            Err(ReadError::Missing) => ImportState::default(),
            Err(ReadError::Io(e)) => return Err(e.into()),
            Err(e) => return Err(ImportError::State(format!("unreadable: {e:?}"))),
        };
        Ok(Self {
            cfg,
            keyring,
            bundle_verifiers: Vec::new(),
            state,
        })
    }

    /// Also verify black-box bundles signed by `verifier`'s key (matched on
    /// the bundle identity's key id). Bundles of other keys are only parsed.
    pub fn add_bundle_verifier(&mut self, verifier: Box<dyn Verifier>) {
        self.bundle_verifiers.push(verifier);
    }

    pub fn state(&self) -> &ImportState {
        &self.state
    }

    /// Process everything currently in the inbox. `now_ms` is only used to
    /// timestamp quarantine reason files.
    pub fn run(&mut self, now_ms: u64) -> Result<ImportReport, ImportError> {
        let mut report = ImportReport::default();
        let mut entries: Vec<_> = fs::read_dir(&self.cfg.inbox)?
            .collect::<Result<Vec<_>, _>>()?
            .into_iter()
            .map(|e| (e.file_name(), e.path()))
            .collect();
        entries.sort();
        let mut candidates = Vec::new();
        for (os_name, path) in entries {
            let Some(name) = os_name.to_str().map(str::to_string) else {
                let n = os_name.to_string_lossy().into_owned();
                self.quarantine(
                    &path,
                    &n,
                    QuarantineReason::BadEntryName,
                    now_ms,
                    &mut report,
                )?;
                continue;
            };
            if name.starts_with('.') {
                report.in_transit.push(name);
                continue;
            }
            let meta = fs::symlink_metadata(&path)?;
            if meta.file_type().is_symlink() {
                self.quarantine(&path, &name, QuarantineReason::Symlink, now_ms, &mut report)?;
                continue;
            }
            if !meta.is_dir() {
                self.quarantine(
                    &path,
                    &name,
                    QuarantineReason::NotADirectory,
                    now_ms,
                    &mut report,
                )?;
                continue;
            }
            match self.load_header(&path, &name)? {
                Ok(c) => candidates.push(c),
                Err(r) => self.quarantine(&path, &name, r, now_ms, &mut report)?,
            }
        }
        candidates.sort_by(|a, b| {
            (&a.manifest.unit_id, a.manifest.batch_seq)
                .cmp(&(&b.manifest.unit_id, b.manifest.batch_seq))
        });
        for c in candidates {
            self.process(c, now_ms, &mut report)?;
        }
        Ok(report)
    }

    fn load_header(&self, dir: &Path, name: &str) -> Checked<Candidate> {
        use QuarantineReason as Q;
        let sig_bytes =
            match fsutil::read_capped(&dir.join(SIGNATURE_FILE), MAX_SIGNATURE_FILE_BYTES as u64) {
                Ok(b) => b,
                Err(ReadError::Missing) => return Ok(Err(Q::MissingSignature)),
                Err(ReadError::NotRegular) => {
                    return Ok(Err(Q::NotRegularFile {
                        name: SIGNATURE_FILE.into(),
                    }))
                }
                Err(ReadError::TooLarge(n)) => {
                    return Ok(Err(Q::SignatureFileInvalid {
                        detail: format!("{n} bytes > {MAX_SIGNATURE_FILE_BYTES}"),
                    }))
                }
                Err(ReadError::Io(e)) => return Err(e),
            };
        let manifest_bytes =
            match fsutil::read_capped(&dir.join(MANIFEST_FILE), MAX_MANIFEST_BYTES as u64) {
                Ok(b) => b,
                Err(ReadError::Missing) => return Ok(Err(Q::MissingManifest)),
                Err(ReadError::NotRegular) => {
                    return Ok(Err(Q::NotRegularFile {
                        name: MANIFEST_FILE.into(),
                    }))
                }
                Err(ReadError::TooLarge(n)) => {
                    return Ok(Err(Q::ManifestTooLarge {
                        size: n,
                        max: MAX_MANIFEST_BYTES as u64,
                    }))
                }
                Err(ReadError::Io(e)) => return Err(e),
            };
        let sigfile: SignatureFile = match serde_json::from_slice(&sig_bytes) {
            Ok(s) => s,
            Err(e) => {
                return Ok(Err(Q::SignatureFileInvalid {
                    detail: trunc(&e.to_string()),
                }))
            }
        };
        if sigfile.format != FORMAT {
            return Ok(Err(Q::SignatureFileInvalid {
                detail: "unsupported format".into(),
            }));
        }
        let sig = match from_hex(&sigfile.sig) {
            Some(s) if !s.is_empty() && s.len() <= MAX_SIG_LEN => s,
            _ => {
                return Ok(Err(Q::SignatureFileInvalid {
                    detail: "signature is not 1..=1024 bytes of hex".into(),
                }))
            }
        };
        let Some((key_unit, verifier)) = self.keyring.find(&sigfile.key_id) else {
            return Ok(Err(Q::UnknownKey {
                key_id: trunc(&sigfile.key_id),
            }));
        };
        if verifier.algorithm() != sigfile.algorithm {
            return Ok(Err(Q::AlgorithmMismatch {
                expected: verifier.algorithm().to_string(),
                found: trunc(&sigfile.algorithm),
            }));
        }
        if !verifier.verify(&manifest_signing_message(&manifest_bytes), &sig) {
            return Ok(Err(Q::BadSignature {
                key_id: sigfile.key_id.clone(),
            }));
        }
        // Authenticated from here on.
        let manifest: Manifest = match serde_json::from_slice(&manifest_bytes) {
            Ok(m) => m,
            Err(e) => {
                return Ok(Err(Q::ManifestInvalid {
                    detail: trunc(&e.to_string()),
                }))
            }
        };
        if let Err(detail) = manifest.check() {
            return Ok(Err(Q::ManifestInvalid { detail }));
        }
        if manifest.key_id != sigfile.key_id || manifest.algorithm != sigfile.algorithm {
            return Ok(Err(Q::ManifestInvalid {
                detail: "manifest key id/algorithm differ from the signature's".into(),
            }));
        }
        if manifest.unit_id != key_unit {
            return Ok(Err(Q::UnitKeyMismatch {
                unit_id: manifest.unit_id.clone(),
                key_unit: key_unit.to_string(),
            }));
        }
        let expected = batch_dir_name(&manifest.unit_id, manifest.batch_seq);
        if name != expected {
            return Ok(Err(Q::NameMismatch { expected }));
        }
        let hash = batch_hash(&manifest_bytes);
        Ok(Ok(Candidate {
            name: name.to_string(),
            path: dir.to_path_buf(),
            manifest,
            manifest_bytes,
            sig_bytes,
            hash,
        }))
    }

    fn process(
        &mut self,
        c: Candidate,
        now_ms: u64,
        report: &mut ImportReport,
    ) -> Result<(), ImportError> {
        let unit = c.manifest.unit_id.clone();
        let seq = c.manifest.batch_seq;
        let (last_seq, last_hash, known) = match self.state.units.get(&unit) {
            Some(s) => (
                s.last_seq,
                Some(s.last_hash.clone()),
                s.recent
                    .iter()
                    .find(|(q, _)| *q == seq)
                    .map(|(_, h)| h.clone()),
            ),
            None => (0, None, None),
        };
        if seq <= last_seq {
            match known {
                Some(h) if h == c.hash => {
                    // Nothing is re-emitted, but a corrupted copy is still
                    // reported rather than silently filed away.
                    if let Err(r) = self.verify_files(&c)? {
                        return self.quarantine(&c.path, &c.name, r, now_ms, report);
                    }
                    fsutil::move_unique(&c.path, &self.cfg.processed_dir, &c.name)?;
                    report.duplicates.push(BatchRef {
                        name: c.name,
                        unit_id: unit,
                        seq,
                    });
                }
                Some(h) => {
                    let r = QuarantineReason::Conflict {
                        seq,
                        accepted_hash: h,
                        found_hash: c.hash.clone(),
                    };
                    self.quarantine(&c.path, &c.name, r, now_ms, report)?;
                }
                None => {
                    let r = QuarantineReason::Replay { seq, last_seq };
                    self.quarantine(&c.path, &c.name, r, now_ms, report)?;
                }
            }
            return Ok(());
        }
        let mut gap = None;
        if seq == last_seq + 1 {
            if c.manifest.prev_batch_hash != last_hash {
                let r = QuarantineReason::ChainBreak {
                    seq,
                    expected_prev: last_hash,
                    found_prev: c.manifest.prev_batch_hash.clone(),
                };
                return self.quarantine(&c.path, &c.name, r, now_ms, report);
            }
        } else if self
            .cfg
            .accept_gaps
            .iter()
            .any(|(u, s)| *u == unit && *s == seq)
        {
            gap = Some((last_seq + 1, seq - 1));
        } else {
            report.held.push(HeldBatch {
                name: c.name,
                unit_id: unit,
                seq,
                expected_seq: last_seq + 1,
            });
            return Ok(());
        }

        let verified = match self.verify_files(&c)? {
            Ok(v) => v,
            Err(r) => return self.quarantine(&c.path, &c.name, r, now_ms, report),
        };
        let output = self.emit(&c, &verified)?;

        let st = self.state.units.entry(unit.clone()).or_insert(UnitState {
            last_seq: 0,
            last_hash: String::new(),
            recent: Vec::new(),
            accepted_gaps: Vec::new(),
        });
        st.last_seq = seq;
        st.last_hash = c.hash.clone();
        st.recent.push((seq, c.hash.clone()));
        if st.recent.len() > RECENT_WINDOW {
            let excess = st.recent.len() - RECENT_WINDOW;
            st.recent.drain(..excess);
        }
        if let Some(g) = gap {
            st.accepted_gaps.push(g);
            if st.accepted_gaps.len() > MAX_RECORDED_GAPS {
                let excess = st.accepted_gaps.len() - MAX_RECORDED_GAPS;
                st.accepted_gaps.drain(..excess);
            }
        }
        self.save_state()?;
        fsutil::move_unique(&c.path, &self.cfg.processed_dir, &c.name)?;
        report.accepted.push(AcceptedBatch {
            name: c.name,
            unit_id: unit,
            seq,
            batch_hash: c.hash,
            findings: c.manifest.finding_count,
            bundles: verified.bundles.len(),
            bundles_verified: verified.bundles_verified,
            gap_accepted: gap,
            output,
        });
        Ok(())
    }

    fn verify_files(&self, c: &Candidate) -> Checked<Verified> {
        use QuarantineReason as Q;
        let m = &c.manifest;
        let total = m.total_size();
        if total > self.cfg.max_batch_bytes {
            return Ok(Err(Q::BatchTooLarge {
                size: total,
                max: self.cfg.max_batch_bytes,
            }));
        }
        let listed: BTreeSet<&str> = m.files.iter().map(|f| f.name.as_str()).collect();
        for e in fs::read_dir(&c.path)? {
            let e = e?;
            let n = e.file_name();
            let ok = n
                .to_str()
                .is_some_and(|n| n == MANIFEST_FILE || n == SIGNATURE_FILE || listed.contains(n));
            if !ok {
                return Ok(Err(Q::UnexpectedFile {
                    name: trunc(&n.to_string_lossy()),
                }));
            }
        }
        let mut records = Vec::new();
        let mut bundles = Vec::new();
        let mut bundles_verified = 0;
        for f in &m.files {
            let bytes = match fsutil::read_capped(&c.path.join(&f.name), f.size) {
                Ok(b) => b,
                Err(ReadError::Missing) => {
                    return Ok(Err(Q::MissingFile {
                        name: f.name.clone(),
                    }))
                }
                Err(ReadError::NotRegular) => {
                    return Ok(Err(Q::NotRegularFile {
                        name: f.name.clone(),
                    }))
                }
                Err(ReadError::TooLarge(n)) => {
                    return Ok(Err(Q::SizeMismatch {
                        name: f.name.clone(),
                        expected: f.size,
                        actual: n,
                    }))
                }
                Err(ReadError::Io(e)) => return Err(e),
            };
            if bytes.len() as u64 != f.size {
                return Ok(Err(Q::SizeMismatch {
                    name: f.name.clone(),
                    expected: f.size,
                    actual: bytes.len() as u64,
                }));
            }
            if file_sha256(&bytes) != f.sha256 {
                return Ok(Err(Q::HashMismatch {
                    name: f.name.clone(),
                }));
            }
            match f.kind {
                FileKind::Findings => match self.findings_to_records(c, &bytes) {
                    Ok(r) => records = r,
                    Err(q) => return Ok(Err(q)),
                },
                FileKind::BlackboxBundle => {
                    let b = match Bundle::from_bytes(&bytes) {
                        Ok(b) => b,
                        Err(e) => {
                            return Ok(Err(Q::BadBundle {
                                name: f.name.clone(),
                                detail: e.to_string(),
                            }))
                        }
                    };
                    if let Some(v) = self
                        .bundle_verifiers
                        .iter()
                        .find(|v| v.key_id() == b.identity.key_id)
                    {
                        let rep = b.verify(v.as_ref(), None, None);
                        if !rep.is_intact() {
                            let detail = rep
                                .first_at_least(FindingLevel::Tamper)
                                .map(|f| format!("{:?}", f.kind))
                                .unwrap_or_default();
                            return Ok(Err(Q::BundleVerifyFailed {
                                name: f.name.clone(),
                                detail: trunc(&detail),
                            }));
                        }
                        bundles_verified += 1;
                    }
                    bundles.push((f.name.clone(), bytes));
                }
            }
        }
        Ok(Ok(Verified {
            records,
            bundles,
            bundles_verified,
        }))
    }

    fn findings_to_records(
        &self,
        c: &Candidate,
        bytes: &[u8],
    ) -> Result<Vec<u8>, QuarantineReason> {
        use QuarantineReason as Q;
        let m = &c.manifest;
        let Some(body) = bytes.strip_suffix(b"\n") else {
            return Err(Q::FindingsFormat {
                detail: "not newline-terminated".into(),
            });
        };
        let text = std::str::from_utf8(body).map_err(|_| Q::FindingsFormat {
            detail: "not UTF-8".into(),
        })?;
        let mut out = Vec::with_capacity(bytes.len() * 2);
        let mut count = 0u64;
        let (mut first, mut last) = (u64::MAX, 0u64);
        for (i, line) in text.split('\n').enumerate() {
            let line_no = i + 1;
            if line.is_empty() {
                return Err(Q::FindingsFormat {
                    detail: format!("empty line {line_no}"),
                });
            }
            let env = robodr_ocsf::parse_and_validate(line).map_err(|errs| Q::InvalidFinding {
                line: line_no,
                errors: errs.iter().take(5).map(|e| trunc(&e.to_string())).collect(),
            })?;
            let rec = robodr_ocsf::record(&env, self.cfg.partitions).map_err(|errs| {
                Q::InvalidFinding {
                    line: line_no,
                    errors: errs.iter().take(5).map(|e| trunc(&e.to_string())).collect(),
                }
            })?;
            first = first.min(env.ocsf.time);
            last = last.max(env.ocsf.time);
            count += 1;
            let o = OutRecord {
                topic: rec.topic,
                partition: rec.partition,
                key: &rec.key,
                headers: &rec.headers,
                value: &rec.value,
                diode: Provenance {
                    unit_id: &m.unit_id,
                    batch_seq: m.batch_seq,
                    batch_hash: &c.hash,
                    line: line_no,
                },
            };
            serde_json::to_writer(&mut out, &o).map_err(|e| Q::FindingsFormat {
                detail: trunc(&e.to_string()),
            })?;
            out.push(b'\n');
        }
        if count != m.finding_count {
            return Err(Q::CountMismatch {
                declared: m.finding_count,
                actual: count,
            });
        }
        if m.first_time != Some(first) || m.last_time != Some(last) {
            return Err(Q::TimeRangeMismatch);
        }
        Ok(out)
    }

    fn emit(&self, c: &Candidate, v: &Verified) -> io::Result<PathBuf> {
        let out = self.cfg.out_dir.join(&c.name);
        if fsutil::exists_nofollow(&out) {
            // Emitted by an interrupted earlier run (same signed content).
            fsutil::require_real_dir(&out)?;
            return Ok(out);
        }
        let tmp = self.cfg.out_dir.join(format!(".tmp-{}", c.name));
        if let Ok(meta) = fs::symlink_metadata(&tmp) {
            if !meta.is_dir() || meta.file_type().is_symlink() {
                return Err(fsutil::invalid(format!(
                    "{} exists and is not a directory",
                    tmp.display()
                )));
            }
            fs::remove_dir_all(&tmp)?;
        }
        fs::create_dir(&tmp)?;
        fsutil::write_new(&tmp.join(RECORDS_FILE), &v.records)?;
        for (n, b) in &v.bundles {
            fsutil::write_new(&tmp.join(n), b)?;
        }
        fsutil::write_new(&tmp.join(MANIFEST_FILE), &c.manifest_bytes)?;
        fsutil::write_new(&tmp.join(SIGNATURE_FILE), &c.sig_bytes)?;
        fsutil::fsync_dir(&tmp)?;
        fs::rename(&tmp, &out)?;
        fsutil::fsync_dir(&self.cfg.out_dir)?;
        Ok(out)
    }

    fn save_state(&self) -> Result<(), ImportError> {
        let b = serde_json::to_vec_pretty(&self.state)
            .map_err(|e| ImportError::State(format!("serialisation: {e}")))?;
        fsutil::atomic_write(&self.cfg.state_path, &b)?;
        Ok(())
    }

    fn quarantine(
        &self,
        path: &Path,
        name: &str,
        reason: QuarantineReason,
        now_ms: u64,
        report: &mut ImportReport,
    ) -> Result<(), ImportError> {
        let safe = safe_entry_name(name);
        let moved = fsutil::move_unique(path, &self.cfg.quarantine_dir, &safe)?;
        let moved_name = moved
            .file_name()
            .map(|n| n.to_string_lossy().into_owned())
            .unwrap_or(safe);
        let rf = ReasonFile {
            format: FORMAT,
            entry: &trunc(name),
            quarantined_at_ms: now_ms,
            reason: &reason,
        };
        let bytes = serde_json::to_vec_pretty(&rf)
            .map_err(|e| ImportError::State(format!("reason serialisation: {e}")))?;
        fsutil::atomic_write(
            &self
                .cfg
                .quarantine_dir
                .join(format!("{moved_name}.reason.json")),
            &bytes,
        )?;
        report.quarantined.push(QuarantinedBatch {
            name: trunc(name),
            reason,
            moved_to: moved,
        });
        Ok(())
    }
}

/// `[A-Za-z0-9._-]`, at most 128 bytes, never starting with `.`.
fn safe_entry_name(name: &str) -> String {
    let mut s: String = name
        .chars()
        .take(128)
        .map(|c| {
            if c.is_ascii_alphanumeric() || matches!(c, '.' | '_' | '-') {
                c
            } else {
                '_'
            }
        })
        .collect();
    if s.is_empty() || s.starts_with('.') {
        s.insert_str(0, "entry");
    }
    s
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn safe_names() {
        assert_eq!(safe_entry_name("../x"), "entry.._x");
        assert_eq!(safe_entry_name(""), "entry");
        assert_eq!(safe_entry_name("a b\u{202e}"), "a_b_");
        assert_eq!(safe_entry_name(&"x".repeat(500)).len(), 128);
    }

    #[test]
    fn keyring_rejects_duplicate_key_ids_and_bad_units() {
        use robodr_blackbox::HmacSha256Key;
        let mut k = Keyring::new();
        k.add("u1", Box::new(HmacSha256Key::new("k", &[1; 32]).unwrap()))
            .unwrap();
        assert!(k
            .add("u2", Box::new(HmacSha256Key::new("k", &[2; 32]).unwrap()))
            .is_err());
        assert!(k
            .add("a/b", Box::new(HmacSha256Key::new("k2", &[2; 32]).unwrap()))
            .is_err());
        assert_eq!(k.find("k").map(|(u, _)| u), Some("u1"));
    }

    #[test]
    fn reason_serialises_with_code() {
        let r = QuarantineReason::HashMismatch {
            name: "findings.jsonl".into(),
        };
        let s = r.to_string();
        assert!(s.contains("\"code\":\"hash_mismatch\""), "{s}");
    }
}
