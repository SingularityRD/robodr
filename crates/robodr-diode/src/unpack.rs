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
//!      ([`ImportConfig::accept_gaps`], at most
//!      [`ImportConfig::max_accept_gap`] skipped batches), which is recorded
//!      in the state. A batch held longer than
//!      [`ImportConfig::held_max_age_ms`] is quarantined (`held_expired`).
//! 3. **File checks**: no entry other than the manifest, its signature and the
//!    listed files; every listed file a regular non-symlink file of exactly
//!    the declared size and SHA-256; every findings line re-validated with
//!    [`robodr_ocsf::parse_and_validate`] and its `entity_context.robot.id`
//!    allowed for the unit ([`Keyring::robot_allowed`]: the unit itself, plus
//!    an explicit per-unit allow-list); every bundle parsed, its
//!    `device_id` allowed for the unit, and its signatures verified when a
//!    black-box key **bound to this unit** is configured (a bundle signed
//!    with a key bound to another unit is quarantined).
//! 4. **Emit** `out/<batch>/records.jsonl` (one Kafka record per line: topic,
//!    partition, key, headers, value — the shape of [`robodr_ocsf::Record`]),
//!    the bundles and a copy of the signed manifest, via a temp directory and
//!    a rename; then atomically update the state; then move the batch to
//!    `processed/`. A crash anywhere re-runs idempotently. Files are verified
//!    and copied one at a time, and records are streamed into the staging
//!    directory, so peak memory is about one data file (findings are read in
//!    64 KiB chunks), not the whole batch.
//!
//!    If `out/<batch>/` already exists, its `MANIFEST.json` is compared with
//!    this batch's: identical → it was emitted by an interrupted earlier run
//!    and is reused; different (e.g. after an operator reset that unit's
//!    state) → this batch is emitted as `out/<batch>.<first 16 hex of the
//!    batch hash>/`. A batch is never reported as accepted without its own
//!    records on disk.
//!
//! **Parity repair** (batches packed with parity, see [`crate::fec`]): before
//! step 3, every listed file (data and parity) is hashed; a file that is
//! missing, of the wrong size or of the wrong SHA-256 is an *erasure*. Up to
//! `m` erasures are rebuilt from the other files, each rebuilt file is
//! accepted only if its size and SHA-256 equal the signed manifest's, and
//! it then replaces the damaged one in the inbox entry (temp file + rename);
//! step 3 then verifies everything exactly as for any other batch. More
//! than `m` erasures quarantine the batch as `fec_unrecoverable`, naming the
//! damaged files. Entries that are not regular files (symlinks,
//! directories) are never "repaired": they fail step 3 as before.
//!
//! **Single instance**: [`Importer::open`] takes an exclusive `flock` on
//! `<state>.lock` for the importer's lifetime; a second importer on the same
//! state fails with [`ImportError::Locked`].
//!
//! Anything that fails a check is moved to `quarantine/<unique>/entry`, with
//! `quarantine/<unique>/reason.json` beside it (a separate directory per
//! entry, so inbox names cannot collide with or impersonate reason files);
//! the state does not advance, so an intact re-send of the same batch is
//! accepted later. Dot-entries (in transit) older than
//! [`ImportConfig::in_transit_max_age_ms`] are quarantined too.
//!
//! **Per-entry failures never abort a run**: an I/O error while handling one
//! inbox entry is reported in [`ImportReport::errors`] (the entry stays in the
//! inbox and is retried next run; a permission problem reading it is
//! quarantined as `unreadable`), and the run continues with the next entry.
//! Only failing to list the inbox itself is a run error.

use crate::fec::ReedSolomon;
use crate::fsutil::{self, ReadError};
use crate::manifest::{
    batch_dir_name, batch_hash, file_sha256, is_hex_digest, manifest_signing_message, trunc,
    FileEntry, FileKind, Manifest, SignatureFile, FORMAT, MANIFEST_FILE, MAX_BATCH_SEQ,
    MAX_MANIFEST_BYTES, MAX_SIGNATURE_FILE_BYTES, MAX_SIG_LEN, SIGNATURE_FILE,
};
use robodr_blackbox::crypto::{from_hex, to_hex, Sha256};
use robodr_blackbox::{Bundle, FindingLevel, Verifier};
use robodr_ocsf::validate::MAX_FINDING_BYTES;
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};
use std::ffi::OsStr;
use std::fmt;
use std::fs;
use std::io::{self, BufRead, BufReader, BufWriter, Read, Write};
use std::path::{Path, PathBuf};

/// Batch hashes remembered per unit for duplicate/conflict decisions.
pub const RECENT_WINDOW: usize = 1024;
/// Accepted gaps remembered per unit.
pub const MAX_RECORDED_GAPS: usize = 1024;
/// Default cap on the data bytes of one batch on import (256 MiB). The
/// packer's largest allowed `max_batch_bytes` equals this value.
pub const DEFAULT_MAX_IMPORT_BATCH_BYTES: u64 = 256 * 1024 * 1024;
/// Default cap on the number of batches one operator-accepted gap may skip.
pub const DEFAULT_MAX_ACCEPT_GAP: u64 = 100_000;
/// Default age after which a held (gap) batch is quarantined: 30 days.
pub const DEFAULT_HELD_MAX_AGE_MS: u64 = 30 * 24 * 3600 * 1000;
/// Default age after which a dot-entry (in transit) is quarantined: 24 h.
pub const DEFAULT_IN_TRANSIT_MAX_AGE_MS: u64 = 24 * 3600 * 1000;
const STATE_FORMAT: &str = "robodr-diode-import-state/1";
const MAX_STATE_BYTES: u64 = 64 * 1024 * 1024;
/// File written into each emitted batch directory.
pub const RECORDS_FILE: &str = "records.jsonl";
/// Name of the quarantined inbox entry inside its `quarantine/<unique>/`.
pub const QUARANTINE_ENTRY: &str = "entry";
/// Name of the reason file inside each `quarantine/<unique>/`.
pub const REASON_FILE: &str = "reason.json";
const READ_CHUNK: usize = 64 * 1024;
/// Prefix of the temp files parity repair writes inside an inbox entry
/// (`.fec-<pid>-<nonce>-<n>.tmp`: unique per repair, never derived from a
/// file name, so a name planted in the entry cannot block a repair).
const REPAIR_TMP_PREFIX: &str = ".fec-";

/// A repair temp name no earlier repair (or planted entry) can hold.
fn repair_tmp_name(n: usize) -> String {
    use std::sync::atomic::{AtomicU64, Ordering};
    static SEQ: AtomicU64 = AtomicU64::new(0);
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_nanos() as u64)
        .unwrap_or(0);
    format!(
        "{REPAIR_TMP_PREFIX}{}-{nanos:x}-{}-{n}.tmp",
        std::process::id(),
        SEQ.fetch_add(1, Ordering::Relaxed)
    )
}

/// Verifiers for batch manifests, each bound to the unit it may sign for;
/// black-box bundle verifiers, each bound to a unit; and per-unit allow-lists
/// of the robot ids a unit may report on.
#[derive(Default)]
pub struct Keyring {
    entries: Vec<(String, Box<dyn Verifier>)>,
    bundle_keys: Vec<(String, Box<dyn Verifier>)>,
    robots: BTreeMap<String, BTreeSet<String>>,
}

impl Keyring {
    pub fn new() -> Self {
        Self::default()
    }

    /// Trust `verifier` for batches of `unit_id`. A key id may belong to one
    /// unit only (several keys per unit are fine, e.g. during rotation).
    pub fn add(&mut self, unit_id: &str, verifier: Box<dyn Verifier>) -> Result<(), String> {
        check_unit(unit_id)?;
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

    /// Verify black-box bundles signed with `verifier`'s key when they arrive
    /// in batches of `unit_id`. A bundle signed with this key inside another
    /// unit's batch is quarantined (`bundle_key_unit_mismatch`). A key id may
    /// belong to one unit only.
    pub fn add_bundle_key(
        &mut self,
        unit_id: &str,
        verifier: Box<dyn Verifier>,
    ) -> Result<(), String> {
        check_unit(unit_id)?;
        if self
            .bundle_keys
            .iter()
            .any(|(_, v)| v.key_id() == verifier.key_id())
        {
            return Err(format!(
                "bundle key id {:?} is already in the keyring",
                verifier.key_id()
            ));
        }
        self.bundle_keys.push((unit_id.to_string(), verifier));
        Ok(())
    }

    /// Allow batches of `unit_id` to carry findings whose
    /// `entity_context.robot.id` (and bundles whose `device_id`) is
    /// `robot_id`, e.g. a site console exporting for its robots. Without any
    /// entry, a unit may only report on itself.
    pub fn allow_robot(&mut self, unit_id: &str, robot_id: &str) -> Result<(), String> {
        check_unit(unit_id)?;
        if !robodr_ocsf::validate::is_valid_robot_id(robot_id) {
            return Err(format!("invalid robot id {:?}", trunc(robot_id)));
        }
        self.robots
            .entry(unit_id.to_string())
            .or_default()
            .insert(robot_id.to_string());
        Ok(())
    }

    /// May batches of `unit_id` report on `robot_id`? (The unit itself, or
    /// an id added with [`Keyring::allow_robot`].)
    pub fn robot_allowed(&self, unit_id: &str, robot_id: &str) -> bool {
        robot_id == unit_id
            || self
                .robots
                .get(unit_id)
                .is_some_and(|s| s.contains(robot_id))
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

    fn find_bundle_key(&self, key_id: &str) -> Option<(&str, &dyn Verifier)> {
        self.bundle_keys
            .iter()
            .find(|(_, v)| v.key_id() == key_id)
            .map(|(u, v)| (u.as_str(), v.as_ref()))
    }
}

fn check_unit(unit_id: &str) -> Result<(), String> {
    if robodr_ocsf::validate::is_valid_robot_id(unit_id) {
        Ok(())
    } else {
        Err(format!("invalid unit id {:?}", trunc(unit_id)))
    }
}

/// Importer configuration.
#[derive(Debug, Clone)]
pub struct ImportConfig {
    /// Where complete batches arrive (dot-entries are treated as in transit).
    pub inbox: PathBuf,
    /// Accepted batches: `out/<batch>/records.jsonl`, bundles, manifest copy.
    pub out_dir: PathBuf,
    /// Rejected entries: `quarantine/<unique>/{entry, reason.json}`.
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
    /// Largest number of batches one accepted gap may skip; an acceptance
    /// beyond it is refused (`gap_too_large`), so one mistaken or forged
    /// far-future sequence number cannot burn a unit's sequence space.
    pub max_accept_gap: u64,
    /// Quarantine a held (gap) batch whose directory is older than this
    /// (by mtime, against `now_ms`). `None`: hold forever.
    pub held_max_age_ms: Option<u64>,
    /// Quarantine a dot-entry (in transit) older than this. `None`: never.
    pub in_transit_max_age_ms: Option<u64>,
}

impl ImportConfig {
    /// Conventional layout under one root: `inbox/`, `out/`, `quarantine/`,
    /// `processed/`, `state.json`; default limits.
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
            max_accept_gap: DEFAULT_MAX_ACCEPT_GAP,
            held_max_age_ms: Some(DEFAULT_HELD_MAX_AGE_MS),
            in_transit_max_age_ms: Some(DEFAULT_IN_TRANSIT_MAX_AGE_MS),
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
    /// The entry (or a file in it) cannot be read: permission denied.
    Unreadable {
        detail: String,
    },
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
    /// A finding's `entity_context.robot.id` is neither the unit nor on the
    /// unit's allow-list.
    RobotNotAllowed {
        line: usize,
        robot_id: String,
        unit_id: String,
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
    /// A bundle's chain `device_id` is neither the unit nor on its allow-list.
    BundleDeviceNotAllowed {
        name: String,
        device_id: String,
        unit_id: String,
    },
    /// A bundle is signed with a black-box key bound to another unit.
    BundleKeyUnitMismatch {
        name: String,
        key_id: String,
        key_unit: String,
        unit_id: String,
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
    /// The operator accepted a gap larger than [`ImportConfig::max_accept_gap`].
    GapTooLarge {
        seq: u64,
        expected_seq: u64,
        max_gap: u64,
    },
    /// Held for a gap longer than [`ImportConfig::held_max_age_ms`].
    HeldExpired {
        seq: u64,
        expected_seq: u64,
        age_ms: u64,
    },
    /// A dot-entry older than [`ImportConfig::in_transit_max_age_ms`].
    StaleInTransit {
        age_ms: u64,
    },
    /// Both `out/<batch>` and its hash-suffixed alternative hold other
    /// content (not reachable without tampering with `out/`).
    OutputConflict {
        output: String,
    },
    /// More files are missing or damaged than the batch's parity can
    /// rebuild (`damaged` lists them, data and parity files alike).
    FecUnrecoverable {
        damaged: Vec<String>,
        parity_shards: u32,
    },
    /// Parity reconstruction produced a file whose size or SHA-256 differs
    /// from the signed manifest (files changed during repair, or a bug);
    /// nothing reconstructed was kept.
    FecFailed {
        name: String,
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
    /// `out/<batch>/`, or `out/<batch>.<hash16>/` when `out/<batch>/` held
    /// another batch's output.
    pub output: PathBuf,
    /// Files rebuilt from parity before verification (empty if none).
    pub repaired: Vec<String>,
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
    /// Age of the batch directory (mtime) at this run.
    pub age_ms: u64,
}

/// A quarantined inbox entry.
#[derive(Debug, Clone, Serialize)]
pub struct QuarantinedBatch {
    pub name: String,
    pub reason: QuarantineReason,
    /// `quarantine/<unique>/entry`; the reason is in the sibling
    /// [`REASON_FILE`].
    pub moved_to: PathBuf,
}

/// An inbox entry that could not be handled in this run (left in place and
/// retried next run).
#[derive(Debug, Clone, Serialize)]
pub struct EntryError {
    pub name: String,
    pub detail: String,
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
    /// Per-entry failures (I/O); the run carried on with the other entries.
    pub errors: Vec<EntryError>,
}

impl ImportReport {
    /// Nothing quarantined, no gap pending, no per-entry error.
    pub fn is_clean(&self) -> bool {
        self.quarantined.is_empty() && self.held.is_empty() && self.errors.is_empty()
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
    /// Another importer holds the lock on this state file.
    Locked(PathBuf),
    Io(io::Error),
}

impl fmt::Display for ImportError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Config(m) => write!(f, "configuration: {m}"),
            Self::State(m) => write!(f, "importer state: {m}"),
            Self::Locked(p) => write!(
                f,
                "another robodr-diode-unpack instance holds {} (one importer per state file)",
                p.display()
            ),
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
    mtime_ms: u64,
}

/// What the file pass found (the data itself went to the staging dir).
struct Verified {
    bundles: usize,
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

/// Running totals of one findings file.
struct FindingsScan {
    line_no: usize,
    count: u64,
    first: u64,
    last: u64,
    err: Option<QuarantineReason>,
    rec_buf: Vec<u8>,
}

/// What `out/<name>` holds relative to a candidate.
enum OutSlot {
    Free,
    Same,
    Other,
}

type Checked<T> = Result<Result<T, QuarantineReason>, io::Error>;

fn unreadable(e: &io::Error) -> Option<QuarantineReason> {
    (e.kind() == io::ErrorKind::PermissionDenied).then(|| QuarantineReason::Unreadable {
        detail: trunc(&e.to_string()),
    })
}

/// Map a data-file read error to a quarantine reason (or a real I/O error).
fn data_read_error(f: &FileEntry, e: ReadError) -> Checked<std::convert::Infallible> {
    use QuarantineReason as Q;
    Ok(Err(match e {
        ReadError::Missing => Q::MissingFile {
            name: f.name.clone(),
        },
        ReadError::NotRegular => Q::NotRegularFile {
            name: f.name.clone(),
        },
        ReadError::TooLarge(n) => Q::SizeMismatch {
            name: f.name.clone(),
            expected: f.size,
            actual: n,
        },
        ReadError::Io(e) => match unreadable(&e) {
            Some(q) => q,
            None => return Err(e),
        },
    }))
}

/// The SOC-side importer. One instance per state file, enforced by an
/// exclusive lock on `<state>.lock` held while the importer lives.
pub struct Importer {
    cfg: ImportConfig,
    keyring: Keyring,
    state: ImportState,
    /// The `flock` on `<state>.lock`; released on drop.
    _lock: fs::File,
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
        let lock_path = fsutil::lock_path(&cfg.state_path);
        let lock = fsutil::try_lock(&lock_path)?.ok_or(ImportError::Locked(lock_path))?;
        let state = match fsutil::read_capped(&cfg.state_path, MAX_STATE_BYTES) {
            Ok(b) => {
                let s: ImportState = serde_json::from_slice(&b)
                    .map_err(|e| ImportError::State(format!("unparsable: {e}")))?;
                if s.format != STATE_FORMAT {
                    return Err(ImportError::State("unknown state format".into()));
                }
                for (u, st) in &s.units {
                    if st.last_seq == 0
                        || st.last_seq > MAX_BATCH_SEQ
                        || !is_hex_digest(&st.last_hash)
                    {
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
            state,
            _lock: lock,
        })
    }

    /// Also verify black-box bundles signed by `verifier`'s key (matched on
    /// the bundle identity's key id) when they arrive in batches of
    /// `unit_id`; see [`Keyring::add_bundle_key`]. Bundles of unknown keys
    /// are only parsed (and their `device_id` checked).
    pub fn add_bundle_verifier(
        &mut self,
        unit_id: &str,
        verifier: Box<dyn Verifier>,
    ) -> Result<(), ImportError> {
        self.keyring
            .add_bundle_key(unit_id, verifier)
            .map_err(ImportError::Config)
    }

    pub fn state(&self) -> &ImportState {
        &self.state
    }

    /// Process everything currently in the inbox. `now_ms` timestamps
    /// quarantine reason files and is the reference for entry ages.
    ///
    /// Returns an error only if the inbox itself cannot be listed; problems
    /// with individual entries end up in the report.
    pub fn run(&mut self, now_ms: u64) -> Result<ImportReport, ImportError> {
        let mut report = ImportReport::default();
        let mut entries = Vec::new();
        for e in fs::read_dir(&self.cfg.inbox)? {
            match e {
                Ok(e) => entries.push((e.file_name(), e.path())),
                Err(e) => report.errors.push(EntryError {
                    name: String::new(),
                    detail: format!("listing the inbox: {e}"),
                }),
            }
        }
        entries.sort();
        let mut candidates = Vec::new();
        for (os_name, path) in entries {
            match self.scan(&os_name, &path, now_ms, &mut report) {
                Ok(Some(c)) => candidates.push(c),
                Ok(None) => {}
                Err(e) => report.errors.push(EntryError {
                    name: trunc(&os_name.to_string_lossy()),
                    detail: trunc(&e.to_string()),
                }),
            }
        }
        candidates.sort_by(|a, b| {
            (&a.manifest.unit_id, a.manifest.batch_seq)
                .cmp(&(&b.manifest.unit_id, b.manifest.batch_seq))
        });
        for c in candidates {
            let name = c.name.clone();
            if let Err(e) = self.process(c, now_ms, &mut report) {
                report.errors.push(EntryError {
                    name,
                    detail: trunc(&e.to_string()),
                });
            }
        }
        Ok(report)
    }

    /// First look at one inbox entry: quarantine what is obviously bad,
    /// return an authenticated candidate otherwise.
    fn scan(
        &self,
        os_name: &OsStr,
        path: &Path,
        now_ms: u64,
        report: &mut ImportReport,
    ) -> io::Result<Option<Candidate>> {
        use QuarantineReason as Q;
        let Some(name) = os_name.to_str() else {
            let n = os_name.to_string_lossy().into_owned();
            self.quarantine(path, &n, Q::BadEntryName, now_ms, report)?;
            return Ok(None);
        };
        let meta = fs::symlink_metadata(path)?;
        if name.starts_with('.') {
            let age_ms = now_ms.saturating_sub(fsutil::mtime_ms(&meta));
            if self
                .cfg
                .in_transit_max_age_ms
                .is_some_and(|max| age_ms > max)
            {
                self.quarantine(path, name, Q::StaleInTransit { age_ms }, now_ms, report)?;
            } else {
                report.in_transit.push(name.to_string());
            }
            return Ok(None);
        }
        if meta.file_type().is_symlink() {
            self.quarantine(path, name, Q::Symlink, now_ms, report)?;
            return Ok(None);
        }
        if !meta.is_dir() {
            self.quarantine(path, name, Q::NotADirectory, now_ms, report)?;
            return Ok(None);
        }
        let header = match self.load_header(path, name, fsutil::mtime_ms(&meta)) {
            Err(e) => match unreadable(&e) {
                Some(q) => Err(q),
                None => return Err(e),
            },
            Ok(h) => h,
        };
        match header {
            Ok(c) => Ok(Some(c)),
            Err(r) => {
                self.quarantine(path, name, r, now_ms, report)?;
                Ok(None)
            }
        }
    }

    fn load_header(&self, dir: &Path, name: &str, mtime_ms: u64) -> Checked<Candidate> {
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
            mtime_ms,
        }))
    }

    fn process(&mut self, c: Candidate, now_ms: u64, report: &mut ImportReport) -> io::Result<()> {
        use QuarantineReason as Q;
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
                    // reported rather than silently filed away (after the
                    // same parity repair an accepted batch gets).
                    if let Err(r) = self.repair(&c)? {
                        return self.quarantine(&c.path, &c.name, r, now_ms, report);
                    }
                    if let Err(r) = self.verify_files(&c, None)? {
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
                    let r = Q::Conflict {
                        seq,
                        accepted_hash: h,
                        found_hash: c.hash.clone(),
                    };
                    self.quarantine(&c.path, &c.name, r, now_ms, report)?;
                }
                None => {
                    let r = Q::Replay { seq, last_seq };
                    self.quarantine(&c.path, &c.name, r, now_ms, report)?;
                }
            }
            return Ok(());
        }
        // last_seq <= MAX_BATCH_SEQ (checked on load and on every manifest).
        let expected_seq = last_seq + 1;
        let mut gap = None;
        if seq == expected_seq {
            if c.manifest.prev_batch_hash != last_hash {
                let r = Q::ChainBreak {
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
            if seq - expected_seq > self.cfg.max_accept_gap {
                let r = Q::GapTooLarge {
                    seq,
                    expected_seq,
                    max_gap: self.cfg.max_accept_gap,
                };
                return self.quarantine(&c.path, &c.name, r, now_ms, report);
            }
            gap = Some((expected_seq, seq - 1));
        } else {
            let age_ms = now_ms.saturating_sub(c.mtime_ms);
            if self.cfg.held_max_age_ms.is_some_and(|max| age_ms > max) {
                let r = Q::HeldExpired {
                    seq,
                    expected_seq,
                    age_ms,
                };
                return self.quarantine(&c.path, &c.name, r, now_ms, report);
            }
            report.held.push(HeldBatch {
                name: c.name,
                unit_id: unit,
                seq,
                expected_seq,
                age_ms,
            });
            return Ok(());
        }

        let repaired = match self.repair(&c)? {
            Ok(r) => r,
            Err(r) => return self.quarantine(&c.path, &c.name, r, now_ms, report),
        };
        let (output, verified) = match self.emit(&c)? {
            Ok(v) => v,
            Err(r) => return self.quarantine(&c.path, &c.name, r, now_ms, report),
        };

        let previous = self.state.units.get(&unit).cloned();
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
        if let Err(e) = self.save_state() {
            // Keep memory equal to disk so later batches of this unit are
            // judged against the persisted state.
            match previous {
                Some(p) => self.state.units.insert(unit, p),
                None => self.state.units.remove(&unit),
            };
            return Err(e);
        }
        report.accepted.push(AcceptedBatch {
            name: c.name.clone(),
            unit_id: unit,
            seq,
            batch_hash: c.hash.clone(),
            findings: c.manifest.finding_count,
            bundles: verified.bundles,
            bundles_verified: verified.bundles_verified,
            gap_accepted: gap,
            output,
            repaired,
        });
        // A failure here leaves an accepted batch in the inbox; the next run
        // sees it as a duplicate and files it then.
        fsutil::move_unique(&c.path, &self.cfg.processed_dir, &c.name)?;
        Ok(())
    }

    /// Verify every data file of `c`. With `stage`, also write
    /// `records.jsonl` and the bundles into that directory as each file
    /// passes (streamed; nothing is buffered beyond one data file).
    fn verify_files(&self, c: &Candidate, stage: Option<&Path>) -> Checked<Verified> {
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
        let rd = match fs::read_dir(&c.path) {
            Ok(rd) => rd,
            Err(e) => {
                return match unreadable(&e) {
                    Some(q) => Ok(Err(q)),
                    None => Err(e),
                }
            }
        };
        for e in rd {
            let n = e?.file_name();
            let ok = n
                .to_str()
                .is_some_and(|n| n == MANIFEST_FILE || n == SIGNATURE_FILE || listed.contains(n));
            if !ok {
                return Ok(Err(Q::UnexpectedFile {
                    name: trunc(&n.to_string_lossy()),
                }));
            }
        }
        let mut records = match stage {
            Some(d) => Some(BufWriter::new(fsutil::create_new(&d.join(RECORDS_FILE))?)),
            None => None,
        };
        let mut bundles = 0;
        let mut bundles_verified = 0;
        for f in &m.files {
            match f.kind {
                FileKind::Findings => {
                    let mut sink = io::sink();
                    let w: &mut dyn Write = match records.as_mut() {
                        Some(w) => w,
                        None => &mut sink,
                    };
                    if let Err(q) = self.stream_findings(c, f, w)? {
                        return Ok(Err(q));
                    }
                }
                FileKind::BlackboxBundle => {
                    match self.check_bundle(c, f, stage)? {
                        Ok(verified) => bundles_verified += usize::from(verified),
                        Err(q) => return Ok(Err(q)),
                    }
                    bundles += 1;
                }
                // Parity is verified like any file but not emitted: it has
                // done its job once the data files verify.
                FileKind::Parity => match fsutil::hash_file(&c.path.join(&f.name), f.size) {
                    Ok((len, _)) if len != f.size => {
                        return Ok(Err(Q::SizeMismatch {
                            name: f.name.clone(),
                            expected: f.size,
                            actual: len,
                        }))
                    }
                    Ok((_, sha)) if sha != f.sha256 => {
                        return Ok(Err(Q::HashMismatch {
                            name: f.name.clone(),
                        }))
                    }
                    Ok(_) => {}
                    Err(e) => return data_read_error(f, e).map(|r| r.map(|x| match x {})),
                },
            }
        }
        if let Some(w) = records {
            w.into_inner().map_err(|e| e.into_error())?.sync_all()?;
        }
        Ok(Ok(Verified {
            bundles,
            bundles_verified,
        }))
    }

    /// Parity repair (see the module docs). `Ok(Ok(names))`: the files
    /// rebuilt (empty when nothing was damaged, the batch has no parity, or
    /// a damage is of a kind repair must not paper over — step 3 then
    /// reports it).
    fn repair(&self, c: &Candidate) -> Checked<Vec<String>> {
        use QuarantineReason as Q;
        let m = &c.manifest;
        let Some(spec) = &m.parity else {
            return Ok(Ok(Vec::new()));
        };
        if m.total_size() > self.cfg.max_batch_bytes {
            return Ok(Ok(Vec::new())); // verify_files reports batch_too_large
        }
        // Temp files of an interrupted earlier repair: regular files and
        // symlinks with the prefix are removed; anything else (a planted
        // directory) is left for step 3 to quarantine (unexpected file).
        if let Ok(rd) = fs::read_dir(&c.path) {
            for e in rd.flatten() {
                let stale = e
                    .file_name()
                    .to_str()
                    .is_some_and(|n| n.starts_with(REPAIR_TMP_PREFIX));
                if stale && fs::symlink_metadata(e.path()).is_ok_and(|md| !md.is_dir()) {
                    let _ = fs::remove_file(e.path());
                }
            }
        }
        let mut erased = Vec::new();
        for (pos, f) in m.files.iter().enumerate() {
            match fsutil::hash_file(&c.path.join(&f.name), f.size) {
                Ok((len, sha)) if len == f.size && sha == f.sha256 => {}
                Ok(_) | Err(ReadError::Missing) | Err(ReadError::TooLarge(_)) => erased.push(pos),
                // Symlinks, directories, devices: hostile, not lossy.
                Err(ReadError::NotRegular) => return Ok(Ok(Vec::new())),
                Err(ReadError::Io(e)) => {
                    return match unreadable(&e) {
                        Some(_) => Ok(Ok(Vec::new())), // reported by step 3
                        None => Err(e),
                    };
                }
            }
        }
        if erased.is_empty() {
            return Ok(Ok(Vec::new()));
        }
        let k = spec.data_shards as usize;
        let mp = spec.parity_shards as usize;
        if erased.len() > mp {
            return Ok(Err(Q::FecUnrecoverable {
                damaged: erased.iter().map(|&p| m.files[p].name.clone()).collect(),
                parity_shards: spec.parity_shards,
            }));
        }
        let rs = ReedSolomon::new(k, mp).map_err(|e| fsutil::invalid(e.to_string()))?;
        let dec = rs
            .decoder(&erased)
            .map_err(|e| fsutil::invalid(e.to_string()))?;
        let plen = m.parity_files().map(|f| f.size).max().unwrap_or(0);
        // Open the intact files (re-checked against the manifest at the end
        // of the repair and again by step 3).
        let mut readers = Vec::with_capacity(dec.known().len());
        for &pos in dec.known() {
            let f = &m.files[pos];
            match fsutil::open_capped(&c.path.join(&f.name), f.size) {
                Ok((file, _)) => readers.push((file.take(f.size), f.size)),
                Err(e) => return data_read_error(f, e).map(|r| r.map(|x| match x {})),
            }
        }
        let tmps: Vec<PathBuf> = (0..erased.len())
            .map(|i| c.path.join(repair_tmp_name(i)))
            .collect();
        let mut created = 0usize;
        let res = (|| -> Checked<()> {
            let mut outs = Vec::with_capacity(erased.len());
            for (t, &pos) in tmps.iter().zip(&erased) {
                // A temp that cannot be created (name taken, read-only
                // entry, ...) fails this batch's repair: quarantined, never
                // an error that would leave the batch stuck in the inbox.
                match fsutil::create_new(t) {
                    Ok(f) => {
                        created += 1;
                        outs.push((BufWriter::new(f), Sha256::new()));
                    }
                    Err(_) => {
                        return Ok(Err(Q::FecFailed {
                            name: m.files[pos].name.clone(),
                        }))
                    }
                }
            }
            let mut inbufs = vec![vec![0u8; READ_CHUNK]; readers.len()];
            let mut outbufs = vec![vec![0u8; READ_CHUNK]; erased.len()];
            let mut off = 0u64;
            while off < plen {
                let n = (plen - off).min(READ_CHUNK as u64) as usize;
                for ((r, size), buf) in readers.iter_mut().zip(inbufs.iter_mut()) {
                    // Bytes of this file inside [off, off + n); zero beyond its end.
                    let have = size.saturating_sub(off).min(n as u64) as usize;
                    r.read_exact(&mut buf[..have])?;
                    buf[have..n].fill(0);
                }
                {
                    let known: Vec<&[u8]> = inbufs.iter().map(|b| &b[..n]).collect();
                    let mut out: Vec<&mut [u8]> = outbufs.iter_mut().map(|b| &mut b[..n]).collect();
                    dec.reconstruct(&known, &mut out)
                        .map_err(|e| fsutil::invalid(e.to_string()))?;
                }
                for ((&pos, (w, h)), buf) in erased.iter().zip(outs.iter_mut()).zip(&outbufs) {
                    let size = m.files[pos].size;
                    let keep = size.saturating_sub(off).min(n as u64) as usize;
                    w.write_all(&buf[..keep])?;
                    h.update(&buf[..keep]);
                }
                off += n as u64;
            }
            let mut finished = Vec::with_capacity(outs.len());
            for (&pos, (w, h)) in erased.iter().zip(outs) {
                w.into_inner().map_err(|e| e.into_error())?.sync_all()?;
                if to_hex(&h.finalize()) != m.files[pos].sha256 {
                    return Ok(Err(Q::FecFailed {
                        name: m.files[pos].name.clone(),
                    }));
                }
                finished.push(pos);
            }
            // Never install anything unless the intact files are still the
            // ones the manifest describes.
            for &pos in dec.known() {
                let f = &m.files[pos];
                match fsutil::hash_file(&c.path.join(&f.name), f.size) {
                    Ok((len, sha)) if len == f.size && sha == f.sha256 => {}
                    _ => {
                        return Ok(Err(Q::FecFailed {
                            name: f.name.clone(),
                        }))
                    }
                }
            }
            for (&pos, t) in finished.iter().zip(&tmps) {
                fs::rename(t, c.path.join(&m.files[pos].name))?;
            }
            fsutil::fsync_dir(&c.path)?;
            Ok(Ok(()))
        })();
        if !matches!(res, Ok(Ok(()))) {
            // Only the temps this repair created (never someone else's
            // entry that happens to share a name).
            for t in tmps.iter().take(created) {
                let _ = fs::remove_file(t);
            }
        }
        Ok(res?.map(|()| erased.iter().map(|&p| m.files[p].name.clone()).collect()))
    }

    /// Read, hash-check, parse and (if a key bound to this unit is known)
    /// verify one bundle, then copy it into `stage`. `Ok(Ok(true))` when its
    /// signatures were verified.
    fn check_bundle(&self, c: &Candidate, f: &FileEntry, stage: Option<&Path>) -> Checked<bool> {
        use QuarantineReason as Q;
        let unit = &c.manifest.unit_id;
        let bytes = match fsutil::read_capped(&c.path.join(&f.name), f.size) {
            Ok(b) => b,
            Err(e) => return data_read_error(f, e).map(|r| r.map(|x| match x {})),
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
        let b = match Bundle::from_bytes(&bytes) {
            Ok(b) => b,
            Err(e) => {
                return Ok(Err(Q::BadBundle {
                    name: f.name.clone(),
                    detail: e.to_string(),
                }))
            }
        };
        if !self.keyring.robot_allowed(unit, &b.identity.device_id) {
            return Ok(Err(Q::BundleDeviceNotAllowed {
                name: f.name.clone(),
                device_id: trunc(&b.identity.device_id),
                unit_id: unit.clone(),
            }));
        }
        let mut verified = false;
        if let Some((key_unit, v)) = self.keyring.find_bundle_key(&b.identity.key_id) {
            if key_unit != unit {
                return Ok(Err(Q::BundleKeyUnitMismatch {
                    name: f.name.clone(),
                    key_id: trunc(&b.identity.key_id),
                    key_unit: key_unit.to_string(),
                    unit_id: unit.clone(),
                }));
            }
            let rep = b.verify(v, None, None);
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
            verified = true;
        }
        drop(b);
        if let Some(d) = stage {
            fsutil::write_new(&d.join(&f.name), &bytes)?;
        }
        Ok(Ok(verified))
    }

    /// Stream the findings file in chunks: hash it, split lines (each at
    /// most `MAX_FINDING_BYTES`), validate each, write its record to `w`.
    /// The file hash and size are checked before any line-level verdict is
    /// returned, so a corrupted file is reported as such.
    fn stream_findings(&self, c: &Candidate, f: &FileEntry, w: &mut dyn Write) -> Checked<()> {
        use QuarantineReason as Q;
        let m = &c.manifest;
        let (file, len) = match fsutil::open_capped(&c.path.join(&f.name), f.size) {
            Ok(x) => x,
            Err(e) => return data_read_error(f, e).map(|r| r.map(|x| match x {})),
        };
        if len != f.size {
            return Ok(Err(Q::SizeMismatch {
                name: f.name.clone(),
                expected: f.size,
                actual: len,
            }));
        }
        let mut reader = BufReader::with_capacity(READ_CHUNK, file.take(f.size.saturating_add(1)));
        let mut hasher = Sha256::new();
        let mut total = 0u64;
        let mut line: Vec<u8> = Vec::new();
        let mut overlong = false;
        let mut st = FindingsScan {
            line_no: 0,
            count: 0,
            first: u64::MAX,
            last: 0,
            err: None,
            rec_buf: Vec::new(),
        };
        loop {
            let buf = reader.fill_buf()?;
            if buf.is_empty() {
                break;
            }
            let n = buf.len();
            hasher.update(buf);
            total += n as u64;
            let mut rest = buf;
            while !rest.is_empty() {
                let (piece, ended) = match rest.iter().position(|&b| b == b'\n') {
                    Some(i) => (&rest[..i], Some(i + 1)),
                    None => (rest, None),
                };
                if !overlong {
                    if line.len() + piece.len() > MAX_FINDING_BYTES {
                        overlong = true;
                        line = Vec::new();
                    } else {
                        line.extend_from_slice(piece);
                    }
                }
                match ended {
                    Some(skip) => {
                        st.line_no += 1;
                        if st.err.is_none() {
                            if overlong {
                                st.err = Some(Q::FindingsFormat {
                                    detail: format!(
                                        "line {} longer than {MAX_FINDING_BYTES} bytes",
                                        st.line_no
                                    ),
                                });
                            } else {
                                match self.finding_line(c, &line, &mut st) {
                                    Ok(()) => w.write_all(&st.rec_buf)?,
                                    Err(q) => st.err = Some(q),
                                }
                            }
                        }
                        line.clear();
                        overlong = false;
                        rest = &rest[skip..];
                    }
                    None => rest = &[],
                }
            }
            reader.consume(n);
        }
        if total != f.size {
            return Ok(Err(Q::SizeMismatch {
                name: f.name.clone(),
                expected: f.size,
                actual: total,
            }));
        }
        if to_hex(&hasher.finalize()) != f.sha256 {
            return Ok(Err(Q::HashMismatch {
                name: f.name.clone(),
            }));
        }
        if let Some(q) = st.err {
            return Ok(Err(q));
        }
        if !line.is_empty() || overlong || total == 0 {
            return Ok(Err(Q::FindingsFormat {
                detail: "not newline-terminated".into(),
            }));
        }
        if st.count != m.finding_count {
            return Ok(Err(Q::CountMismatch {
                declared: m.finding_count,
                actual: st.count,
            }));
        }
        if m.first_time != Some(st.first) || m.last_time != Some(st.last) {
            return Ok(Err(Q::TimeRangeMismatch));
        }
        Ok(Ok(()))
    }

    /// Validate one findings line and render its record into `st.rec_buf`.
    fn finding_line(
        &self,
        c: &Candidate,
        line: &[u8],
        st: &mut FindingsScan,
    ) -> Result<(), QuarantineReason> {
        use QuarantineReason as Q;
        let m = &c.manifest;
        let line_no = st.line_no;
        if line.is_empty() {
            return Err(Q::FindingsFormat {
                detail: format!("empty line {line_no}"),
            });
        }
        let text = std::str::from_utf8(line).map_err(|_| Q::FindingsFormat {
            detail: format!("line {line_no} is not UTF-8"),
        })?;
        let env = robodr_ocsf::parse_and_validate(text).map_err(|errs| Q::InvalidFinding {
            line: line_no,
            errors: errs.iter().take(5).map(|e| trunc(&e.to_string())).collect(),
        })?;
        let robot = &env.entity_context.robot.id;
        if !self.keyring.robot_allowed(&m.unit_id, robot) {
            return Err(Q::RobotNotAllowed {
                line: line_no,
                robot_id: trunc(robot),
                unit_id: m.unit_id.clone(),
            });
        }
        let rec =
            robodr_ocsf::record(&env, self.cfg.partitions).map_err(|errs| Q::InvalidFinding {
                line: line_no,
                errors: errs.iter().take(5).map(|e| trunc(&e.to_string())).collect(),
            })?;
        st.first = st.first.min(env.ocsf.time);
        st.last = st.last.max(env.ocsf.time);
        st.count += 1;
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
        st.rec_buf.clear();
        serde_json::to_writer(&mut st.rec_buf, &o).map_err(|e| Q::FindingsFormat {
            detail: trunc(&e.to_string()),
        })?;
        st.rec_buf.push(b'\n');
        Ok(())
    }

    /// Does `out` already hold this batch's output, another's, or nothing?
    fn out_slot(&self, out: &Path, c: &Candidate) -> OutSlot {
        if !fsutil::exists_nofollow(out) {
            return OutSlot::Free;
        }
        if fsutil::require_real_dir(out).is_err() {
            return OutSlot::Other;
        }
        match fsutil::read_capped(&out.join(MANIFEST_FILE), MAX_MANIFEST_BYTES as u64) {
            Ok(b) if b == c.manifest_bytes => OutSlot::Same,
            _ => OutSlot::Other,
        }
    }

    /// Verify the batch's files and emit them under `out/`. Returns the
    /// output directory, which always holds *this* batch's records.
    fn emit(&self, c: &Candidate) -> Checked<(PathBuf, Verified)> {
        let primary = c.name.clone();
        let alternate = format!("{}.{}", c.name, &c.hash[..16]);
        for out_name in [&primary, &alternate] {
            let out = self.cfg.out_dir.join(out_name);
            match self.out_slot(&out, c) {
                OutSlot::Free => return Ok(self.stage_and_publish(c, out_name)?.map(|v| (out, v))),
                // Emitted by an interrupted earlier run (same signed
                // content): re-verify the inbox copy, reuse the output.
                OutSlot::Same => return Ok(self.verify_files(c, None)?.map(|v| (out, v))),
                OutSlot::Other => {}
            }
        }
        Ok(Err(QuarantineReason::OutputConflict { output: alternate }))
    }

    fn stage_and_publish(&self, c: &Candidate, out_name: &str) -> Checked<Verified> {
        let out = self.cfg.out_dir.join(out_name);
        let tmp = self.cfg.out_dir.join(format!(".tmp-{out_name}"));
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
        let res = (|| -> Checked<Verified> {
            let v = match self.verify_files(c, Some(&tmp))? {
                Ok(v) => v,
                Err(q) => return Ok(Err(q)),
            };
            fsutil::write_new(&tmp.join(MANIFEST_FILE), &c.manifest_bytes)?;
            fsutil::write_new(&tmp.join(SIGNATURE_FILE), &c.sig_bytes)?;
            fsutil::fsync_dir(&tmp)?;
            fs::rename(&tmp, &out)?;
            fsutil::fsync_dir(&self.cfg.out_dir)?;
            Ok(Ok(v))
        })();
        if !matches!(res, Ok(Ok(_))) {
            let _ = fs::remove_dir_all(&tmp);
        }
        res
    }

    fn save_state(&self) -> io::Result<()> {
        let b = serde_json::to_vec_pretty(&self.state).map_err(io::Error::other)?;
        fsutil::atomic_write(&self.cfg.state_path, &b)
    }

    /// Move `path` to `quarantine/<unique>/entry` and write
    /// `quarantine/<unique>/reason.json`.
    fn quarantine(
        &self,
        path: &Path,
        name: &str,
        reason: QuarantineReason,
        now_ms: u64,
        report: &mut ImportReport,
    ) -> io::Result<()> {
        let safe = safe_entry_name(name);
        let qdir = fsutil::create_unique_dir(&self.cfg.quarantine_dir, &safe)?;
        let moved = qdir.join(QUARANTINE_ENTRY);
        if let Err(e) = fs::rename(path, &moved) {
            let _ = fs::remove_dir(&qdir);
            return Err(e);
        }
        let rf = ReasonFile {
            format: FORMAT,
            entry: &trunc(name),
            quarantined_at_ms: now_ms,
            reason: &reason,
        };
        let bytes = serde_json::to_vec_pretty(&rf).map_err(io::Error::other)?;
        // Report the move even if the reason file cannot be written: the
        // entry has left the inbox either way.
        let written = fsutil::write_new(&qdir.join(REASON_FILE), &bytes)
            .and_then(|()| fsutil::fsync_dir(&qdir))
            .and_then(|()| fsutil::fsync_dir(&self.cfg.quarantine_dir));
        report.quarantined.push(QuarantinedBatch {
            name: trunc(name),
            reason,
            moved_to: moved,
        });
        written
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
        // Bundle keys: bound to one unit each.
        k.add_bundle_key("u1", Box::new(HmacSha256Key::new("b", &[3; 32]).unwrap()))
            .unwrap();
        assert!(k
            .add_bundle_key("u2", Box::new(HmacSha256Key::new("b", &[4; 32]).unwrap()))
            .is_err());
        assert!(k
            .add_bundle_key(
                "../u",
                Box::new(HmacSha256Key::new("b2", &[4; 32]).unwrap())
            )
            .is_err());
        assert_eq!(k.find_bundle_key("b").map(|(u, _)| u), Some("u1"));
    }

    #[test]
    fn robot_allow_list_defaults_to_the_unit_itself() {
        let mut k = Keyring::new();
        assert!(k.robot_allowed("u1", "u1"));
        assert!(!k.robot_allowed("u1", "u2"));
        k.allow_robot("u1", "u2").unwrap();
        assert!(k.robot_allowed("u1", "u2"));
        assert!(!k.robot_allowed("u3", "u2"), "allow-list is per unit");
        assert!(!k.robot_allowed("u2", "u1"), "not symmetric");
        assert!(k.allow_robot("u1", "a b").is_err());
        assert!(k.allow_robot("", "u2").is_err());
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
