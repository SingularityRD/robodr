//! Robot side: move the `robodr-agentd` findings spool into a
//! `robodr-diode` packer outbox, exactly once per record (barring loss of
//! the packer or exporter state files).
//!
//! ```text
//! <spool>/ready/<seq:020>.json ──► Packer ──► <outbox>/rdd_<unit>_<seq:016>/
//!          │                                   (committed + renamed, fsynced)
//!          └── rename ──► <spool>/acked/<seq:020>.json   (only after that)
//! ```
//!
//! # Protocol (crash-safe, idempotent restart)
//!
//! For each batch:
//!
//! 1. Take `ready/` files in name (= sequence) order. Each is parsed as a
//!    [`SpoolRecord`], checked (`schema`, `seq` = file name, topic = the
//!    value's `ocsf.metadata.log_name`) and its `value` re-validated with
//!    [`robodr_ocsf::parse_and_validate`]. A contract 1.x record (spooled
//!    by an agentd before the upgrade) is upgraded to contract 2.0 when it
//!    is unsigned ([`robodr_ocsf::upgrade_legacy`], labels
//!    [`ExportConfig::upgrade_data_source`] / `upgrade_topic`); a signed
//!    one is rejected with the reason "legacy 1.x signed record: re-sign
//!    required". A record
//!    that fails is **moved** to `<spool>/rejected/` with a `.reason.json`
//!    beside it (never deleted). A file that cannot be read (I/O error such
//!    as `EACCES` / `EIO`, [`fsutil::READ_ATTEMPTS`] attempts) is
//!    quarantined there the same way, with the error as its reason, instead
//!    of failing every run (`quarantined_unreadable`). The batch is cut so the packer is
//!    guaranteed to write it as **one** diode batch (same size/count rule
//!    as the packer's planner).
//! 2. Write the **intent** `{batch_seq: packer.next_seq, spool_seqs}` to
//!    the exporter state file (atomic replace).
//! 3. `Packer::pack`: stage, commit the packer state, rename into the
//!    outbox, fsync. When it returns, the batch is durably published.
//! 4. Rename every listed record `ready/ → acked/`, fsync both directories.
//! 5. Clear the intent.
//!
//! Recovery on [`Exporter::open`]: `Packer::open` first finishes a batch
//! that was committed but not renamed. Then, if an intent is pending:
//!
//! * `packer.next_seq <= intent.batch_seq`: nothing was committed; the
//!   intent is dropped (the records are still in `ready/` and are packed
//!   again, under the same diode sequence number, which was never visible).
//! * otherwise at least one batch was committed. A record is acknowledged
//!   only if it is **proven** to be in a committed batch: the batches
//!   `intent.batch_seq .. packer.next_seq` (at most one per intent record)
//!   are read back from the outbox or, once the transfer agent has taken
//!   them, from the packer archive (`<pack-state>.archive/`); the
//!   `findings.jsonl` must match its `MANIFEST.json` entry (size and
//!   SHA-256) and the manifest must name this unit and sequence. A record
//!   still in `ready/` is acknowledged iff its exact packed line
//!   ([`robodr_ocsf::to_json`] of the re-validated value) occurs in one of
//!   them; a record already in `acked/` counts as done. Everything else
//!   stays in `ready/` and is packed again (`recovered = "partial"`).
//!
//! This matters when the packer splits one exporter step into several
//! batches (its limits differ from the exporter's) and a later batch of the
//! same `pack` call fails: the records of the failed batch were never
//! packed and must not be acknowledged. If a committed batch can be found
//! neither in the outbox nor in the archive (`archive_keep = 0` and already
//! transferred), its records cannot be proven and are packed again: a
//! duplicate, never a loss (consumers deduplicate on `event-uid`).
//!
//! `ready/` is never deleted from; records leave it only by rename (to
//! `acked/` after publication, or to `rejected/`).
//!
//! # Retention
//!
//! The rejected directory is kept in full by default. With
//! [`ExportConfig::rejected_retention`] (age, count, bytes;
//! [`crate::retention`]) the oldest rejected records beyond the bounds are
//! deleted after each run, each with its `.reason.json`. A rejected record
//! is never published and never read again by the exporter (it left
//! `ready/` for good), so deleting it loses only its forensic copy; a name
//! that is (again) in `ready/` is never touched. Its age is that of its
//! `.reason.json`, which is written (durably) **before** the record is
//! moved; a record found without one is dated when that is noticed (a
//! missing reason file is written then), never by its spool time.
//!
//! # Planner limits
//!
//! The exporter cuts each step with the packer's planner rule, so the
//! packer writes it as one batch. [`Exporter::open_checked`] (used by the
//! `robodr-spool-export` binary) refuses an [`ExportConfig`] whose limits
//! (`max_batch_bytes`, `max_findings_per_batch`, `parity_shards`,
//! `shard_size`) differ from the [`PackConfig`] the packer was opened with,
//! or a packer state of another unit; [`ExportConfig::for_packer`] derives
//! matching limits. [`Exporter::open`] performs the same limit check against
//! the packer's own configuration (`Packer::config`), so a mismatch is
//! refused before anything is read; should a split `pack` still happen (a
//! packer bug), it is detected after the first batch (an error is returned)
//! and, thanks to the proof-based recovery above, never loses records.
//!
//! # Limits
//!
//! * One exporter per spool and packer state (no lock file).
//! * Losing the exporter state file while an intent is pending can pack
//!   the same records twice (the consumer deduplicates on `event-uid`);
//!   losing the packer state file restarts the diode sequence (see the
//!   diode README).
//! * Black-box bundles and `checkpoint.json` are not exported by this tool.

use crate::fsutil::{self, ReadError};
use crate::retention::{self, file_meta, Candidate, PruneReport, Retention};
use robodr_agentd::spool::{SpoolRecord, SPOOL_SCHEMA};
use robodr_diode::manifest::{
    batch_dir_name, file_sha256, parity_len, FileKind, Manifest, FINDINGS_FILE, MANIFEST_FILE,
    MAX_MANIFEST_BYTES,
};
use robodr_diode::{PackConfig, PackError, Packer, PublishedBatch};
use robodr_ocsf::FindingEnvelope;
use serde::{Deserialize, Serialize};
use std::collections::HashSet;
use std::fmt;
use std::fs;
use std::io;
use std::path::{Path, PathBuf};

const STATE_FORMAT: &str = "robodr-spool-export-state/1";
/// Largest spool record file read (a finding is ≤ 64 KiB; headers add little).
pub const MAX_SPOOL_FILE: u64 = 1024 * 1024;
const MAX_STATE_BYTES: u64 = 64 * 1024 * 1024;

/// Simulated crash points (tests of the recovery protocol only).
#[doc(hidden)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FailPoint {
    /// After the intent is written, before packing.
    AfterIntent,
    /// After the batch is published, before any record is acknowledged.
    AfterPack,
    /// After the first record of the batch is acknowledged.
    AfterFirstAck,
}

/// Exporter settings.
#[derive(Debug, Clone)]
pub struct ExportConfig {
    /// The agentd spool root (`ready/`, `acked/` beneath it).
    pub spool: PathBuf,
    /// Exporter state file (intent journal).
    pub state_path: PathBuf,
    /// Where rejected records are moved (same file system as the spool).
    pub rejected_dir: PathBuf,
    /// Must equal the packer's `max_batch_bytes`.
    pub max_batch_bytes: u64,
    /// Must equal the packer's `max_findings_per_batch`.
    pub max_findings_per_batch: usize,
    /// Must equal the packer's `parity_shards` (parity counts against
    /// `max_batch_bytes`).
    pub parity_shards: usize,
    /// Must equal the packer's `shard_size` (used only with parity).
    pub shard_size: u64,
    /// `data_source` an unsigned contract 1.x record (spooled by an agentd
    /// before the upgrade) gets when it is upgraded to contract 2.0
    /// (default [`robodr_ocsf::DEFAULT_DATA_SOURCE`]).
    pub upgrade_data_source: String,
    /// Topic (`ocsf.metadata.log_name`) an upgraded 1.x record gets
    /// (default [`robodr_ocsf::DEFAULT_TOPIC`]).
    pub upgrade_topic: String,
    /// Bounds on the rejected directory (default: unbounded, keep every
    /// rejected record), see "Retention" in the module docs.
    pub rejected_retention: Retention,
    #[doc(hidden)]
    pub fail_point: Option<FailPoint>,
}

impl ExportConfig {
    /// Defaults matching `PackConfig::new`; rejected records go to
    /// `<spool>/rejected/`.
    pub fn new(spool: impl Into<PathBuf>, state_path: impl Into<PathBuf>) -> Self {
        let spool = spool.into();
        Self {
            rejected_dir: spool.join("rejected"),
            spool,
            state_path: state_path.into(),
            max_batch_bytes: robodr_diode::pack::DEFAULT_MAX_BATCH_BYTES,
            max_findings_per_batch: robodr_diode::pack::DEFAULT_MAX_FINDINGS_PER_BATCH,
            parity_shards: 0,
            shard_size: robodr_diode::pack::DEFAULT_SHARD_SIZE,
            upgrade_data_source: robodr_ocsf::DEFAULT_DATA_SOURCE.into(),
            upgrade_topic: robodr_ocsf::DEFAULT_TOPIC.into(),
            rejected_retention: Retention::UNBOUNDED,
            fail_point: None,
        }
    }

    /// [`ExportConfig::new`] with the planner limits taken from `pack`.
    pub fn for_packer(
        spool: impl Into<PathBuf>,
        state_path: impl Into<PathBuf>,
        pack: &PackConfig,
    ) -> Self {
        let mut c = Self::new(spool, state_path);
        c.max_batch_bytes = pack.max_batch_bytes;
        c.max_findings_per_batch = pack.max_findings_per_batch;
        c.parity_shards = pack.parity_shards;
        c.shard_size = pack.shard_size;
        c
    }

    /// `Err` naming every planner limit that differs from `pack`.
    pub fn check_against(&self, pack: &PackConfig) -> Result<(), ExportError> {
        let mut diff = Vec::new();
        if self.max_batch_bytes != pack.max_batch_bytes {
            diff.push(format!(
                "max_batch_bytes {} != packer {}",
                self.max_batch_bytes, pack.max_batch_bytes
            ));
        }
        if self.max_findings_per_batch != pack.max_findings_per_batch {
            diff.push(format!(
                "max_findings_per_batch {} != packer {}",
                self.max_findings_per_batch, pack.max_findings_per_batch
            ));
        }
        if self.parity_shards != pack.parity_shards {
            diff.push(format!(
                "parity_shards {} != packer {}",
                self.parity_shards, pack.parity_shards
            ));
        }
        if self.parity_shards > 0 && self.shard_size != pack.shard_size {
            diff.push(format!(
                "shard_size {} != packer {}",
                self.shard_size, pack.shard_size
            ));
        }
        if diff.is_empty() {
            Ok(())
        } else {
            Err(ExportError::Config(format!(
                "exporter planner limits differ from the packer's ({}); use \
                 ExportConfig::for_packer",
                diff.join(", ")
            )))
        }
    }

    /// Bytes a findings-only batch of `data` bytes occupies with parity
    /// (the packer's rule: one data file, so parity files are `data` long,
    /// rounded up to `shard_size`).
    fn batch_size(&self, data: u64) -> u64 {
        if self.parity_shards == 0 || self.shard_size == 0 {
            return data;
        }
        data.saturating_add(
            (self.parity_shards as u64).saturating_mul(parity_len(data, self.shard_size)),
        )
    }
}

/// The pending intent.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Intent {
    /// The diode sequence number the batch gets.
    pub batch_seq: u64,
    /// Spool sequence numbers (file names) packed into it, in order.
    pub spool_seqs: Vec<u64>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct ExportState {
    format: String,
    pending: Option<Intent>,
    /// Totals, for operators.
    exported: u64,
    rejected: u64,
}

/// Why an export run failed.
#[derive(Debug)]
pub enum ExportError {
    Config(String),
    State(String),
    Pack(PackError),
    Io(io::Error),
    /// A [`FailPoint`] fired.
    #[doc(hidden)]
    Injected(FailPoint),
}

impl fmt::Display for ExportError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Config(m) => write!(f, "configuration: {m}"),
            Self::State(m) => write!(f, "exporter state: {m}"),
            Self::Pack(e) => write!(f, "packer: {e}"),
            Self::Io(e) => write!(f, "I/O: {e}"),
            Self::Injected(p) => write!(f, "injected failure at {p:?}"),
        }
    }
}

impl std::error::Error for ExportError {}

impl From<io::Error> for ExportError {
    fn from(e: io::Error) -> Self {
        Self::Io(e)
    }
}

impl From<PackError> for ExportError {
    fn from(e: PackError) -> Self {
        Self::Pack(e)
    }
}

/// A record moved to `rejected/`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Rejected {
    pub file: String,
    pub reason: String,
}

/// What one run did.
#[derive(Debug, Default, Clone, PartialEq, Eq, Serialize)]
pub struct ExportReport {
    pub batches: Vec<PublishedBatch>,
    pub exported: u64,
    pub rejected: Vec<Rejected>,
    /// A pending intent found at open: `"acked"` (every record proven
    /// published), `"partial"` (some could not be proven and stay in
    /// `ready/`) or `"dropped"` (nothing had been committed).
    pub recovered: Option<String>,
    /// Spool files that could not be read (I/O error after
    /// [`fsutil::READ_ATTEMPTS`] attempts), quarantined in the rejected
    /// directory with the error (also listed in `rejected`).
    pub quarantined_unreadable: u64,
    /// Rejected records deleted by retention.
    pub pruned_rejected: PruneReport,
}

/// See the module docs.
pub struct Exporter {
    cfg: ExportConfig,
    packer: Packer,
    state: ExportState,
    ready: PathBuf,
    acked: PathBuf,
    recovered: Option<String>,
}

fn record_seq(name: &str) -> Option<u64> {
    let stem = name.strip_suffix(".json")?;
    if stem.len() != 20 || !stem.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    stem.parse().ok()
}

fn record_name(seq: u64) -> String {
    format!("{seq:020}.json")
}

/// `ready/` record files `(seq, name)` in order (regular files only).
fn list_ready(dir: &Path) -> io::Result<Vec<(u64, String)>> {
    let mut v = Vec::new();
    for e in fs::read_dir(dir)? {
        let e = e?;
        let Some(name) = e.file_name().to_str().map(str::to_string) else {
            continue;
        };
        let Some(seq) = record_seq(&name) else {
            continue;
        };
        if e.file_type()?.is_file() {
            v.push((seq, name));
        }
    }
    v.sort();
    Ok(v)
}

fn exists_nofollow(p: &Path) -> io::Result<bool> {
    match fs::symlink_metadata(p) {
        Ok(_) => Ok(true),
        Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(false),
        Err(e) => Err(e),
    }
}

/// The `findings.jsonl` text of batch directory `dir`, if it holds the
/// committed batch `seq` of `unit`: the manifest names that unit and
/// sequence, and the findings file matches its manifest entry (size and
/// SHA-256). `None` when absent, unreadable or not matching (callers then
/// treat its records as unproven, which is safe). The signature is not
/// checked: the exporter only reads back what its own packer wrote.
fn read_verified_findings(dir: &Path, unit: &str, seq: u64) -> io::Result<Option<String>> {
    let mbytes = match fsutil::read_capped(&dir.join(MANIFEST_FILE), MAX_MANIFEST_BYTES as u64) {
        Ok(b) => b,
        Err(ReadError::Io(e)) => return Err(e),
        Err(_) => return Ok(None),
    };
    let Ok(m) = serde_json::from_slice::<Manifest>(&mbytes) else {
        return Ok(None);
    };
    if m.unit_id != unit || m.batch_seq != seq {
        return Ok(None);
    }
    let Some(entry) = m
        .files
        .iter()
        .find(|f| f.name == FINDINGS_FILE && f.kind == FileKind::Findings)
    else {
        // A bundle-only batch holds none of our records.
        return Ok(Some(String::new()));
    };
    let max = entry.size.min(robodr_diode::pack::MAX_BATCH_BYTES);
    let data = match fsutil::read_capped(&dir.join(FINDINGS_FILE), max) {
        Ok(b) => b,
        Err(ReadError::Io(e)) => return Err(e),
        Err(_) => return Ok(None),
    };
    if data.len() as u64 != entry.size || file_sha256(&data) != entry.sha256 {
        return Ok(None);
    }
    Ok(String::from_utf8(data).ok())
}

impl Exporter {
    /// [`Exporter::open`] after checking that `cfg`'s planner limits equal
    /// `pack` (the configuration `packer` was opened with) and that the
    /// packer state belongs to `pack.unit_id`; a mismatch is refused with
    /// [`ExportError::Config`] before anything is touched.
    pub fn open_checked(
        cfg: ExportConfig,
        pack: &PackConfig,
        packer: Packer,
    ) -> Result<Self, ExportError> {
        cfg.check_against(pack)?;
        if packer.state().unit_id != pack.unit_id {
            return Err(ExportError::Config(format!(
                "packer state is for unit {:?}, configuration for {:?}",
                packer.state().unit_id,
                pack.unit_id
            )));
        }
        Self::open(cfg, packer)
    }

    /// Open the packer (which finishes a committed batch) and the exporter
    /// state, then resolve a pending intent (see the module docs).
    ///
    /// Refuses a `cfg` whose planner limits differ from `packer`'s own
    /// configuration ([`Packer::config`], [`ExportConfig::check_against`]):
    /// a planner that thinks batches may be larger than the packer accepts
    /// would plan batches the packer splits or refuses.
    /// [`Exporter::open_checked`] additionally checks the unit id against a
    /// separately loaded [`PackConfig`].
    pub fn open(cfg: ExportConfig, packer: Packer) -> Result<Self, ExportError> {
        cfg.check_against(packer.config())?;
        Self::open_inner(cfg, packer)
    }

    /// [`Exporter::open`] without the planner-limit check. Only with the
    /// non-default `fault-injection` feature (enabled for this crate's own
    /// tests): it reproduces a split `pack` so the recovery path can be
    /// tested. Never enabled in a deployed build.
    #[cfg(feature = "fault-injection")]
    #[doc(hidden)]
    pub fn open_unchecked_for_fault_injection(
        cfg: ExportConfig,
        packer: Packer,
    ) -> Result<Self, ExportError> {
        Self::open_inner(cfg, packer)
    }

    fn open_inner(cfg: ExportConfig, packer: Packer) -> Result<Self, ExportError> {
        if !robodr_ocsf::validate::is_valid_data_source(&cfg.upgrade_data_source)
            || !robodr_ocsf::validate::is_valid_topic(&cfg.upgrade_topic)
        {
            return Err(ExportError::Config(
                "upgrade data source / topic must be valid deployment labels".into(),
            ));
        }
        if cfg.max_findings_per_batch == 0 {
            return Err(ExportError::Config(
                "max_findings_per_batch must be >= 1".into(),
            ));
        }
        let (lo, hi) = (
            robodr_diode::pack::MIN_BATCH_BYTES,
            robodr_diode::pack::MAX_BATCH_BYTES,
        );
        if !(lo..=hi).contains(&cfg.max_batch_bytes) {
            return Err(ExportError::Config(format!(
                "max_batch_bytes must be in {lo}..={hi}"
            )));
        }
        if cfg.parity_shards > 0 && cfg.shard_size == 0 {
            return Err(ExportError::Config("shard_size must be > 0".into()));
        }
        let ready = cfg.spool.join("ready");
        let acked = cfg.spool.join("acked");
        for d in [&ready, &acked] {
            let m = fs::symlink_metadata(d).map_err(|e| {
                ExportError::Config(format!("{}: {e} (is this an agentd spool?)", d.display()))
            })?;
            if !m.is_dir() {
                return Err(ExportError::Config(format!(
                    "{} is not a directory",
                    d.display()
                )));
            }
        }
        fsutil::mkdir(&cfg.rejected_dir)?;
        let state = match fsutil::read_capped(&cfg.state_path, MAX_STATE_BYTES) {
            Ok(b) => {
                let s: ExportState = serde_json::from_slice(&b)
                    .map_err(|e| ExportError::State(format!("unparsable: {e}")))?;
                if s.format != STATE_FORMAT {
                    return Err(ExportError::State(format!("unknown format {:?}", s.format)));
                }
                s
            }
            Err(ReadError::Missing) => ExportState {
                format: STATE_FORMAT.into(),
                pending: None,
                exported: 0,
                rejected: 0,
            },
            Err(e) => return Err(ExportError::State(format!("unreadable: {e}"))),
        };
        let mut x = Self {
            cfg,
            packer,
            state,
            ready,
            acked,
            recovered: None,
        };
        if let Some(intent) = x.state.pending.clone() {
            if x.packer.state().next_seq > intent.batch_seq {
                let (proven, unproven) = x.proven_records(&intent)?;
                x.ack(&proven, false)?;
                x.state.exported += proven.len() as u64;
                x.recovered = Some(if unproven == 0 { "acked" } else { "partial" }.into());
            } else {
                x.recovered = Some("dropped".into());
            }
            x.state.pending = None;
            x.save()?;
        }
        Ok(x)
    }

    pub fn packer(&self) -> &Packer {
        &self.packer
    }

    /// The recovery verdict of [`Exporter::open`] (see
    /// [`ExportReport::recovered`]) until the next [`Exporter::run_once`]
    /// reports it.
    pub fn recovered(&self) -> Option<&str> {
        self.recovered.as_deref()
    }

    /// Split a pending intent whose batch(es) were (at least partly)
    /// committed into `(records proven published, count left in ready/)`.
    fn proven_records(&self, intent: &Intent) -> Result<(Vec<u64>, usize), ExportError> {
        // A split cannot produce more batches than records; a larger gap
        // means someone else used the packer, and those batches are not ours.
        let end = self.packer.state().next_seq.min(
            intent
                .batch_seq
                .saturating_add(intent.spool_seqs.len() as u64),
        );
        let mut lines: HashSet<String> = HashSet::new();
        for seq in intent.batch_seq..end {
            self.committed_lines(seq, &mut lines)?;
        }
        let mut proven = Vec::new();
        let mut unproven = 0;
        for &seq in &intent.spool_seqs {
            let name = record_name(seq);
            if !exists_nofollow(&self.ready.join(&name))? {
                // Already acknowledged (or pruned from acked/ by agentd).
                proven.push(seq);
                continue;
            }
            match self.load(seq, &name)? {
                Ok((_, line)) if lines.contains(&line) => proven.push(seq),
                // Not in a committed batch, or no longer valid (run_once
                // rejects it): leave it in ready/.
                _ => unproven += 1,
            }
        }
        Ok((proven, unproven))
    }

    /// Add the findings lines of committed batch `seq` to `out`, read from
    /// the outbox or else the packer archive and checked against the batch
    /// manifest. A batch found in neither (or failing the check) adds
    /// nothing: its records are then not proven and get packed again.
    fn committed_lines(&self, seq: u64, out: &mut HashSet<String>) -> Result<(), ExportError> {
        let unit = &self.packer.state().unit_id;
        let name = batch_dir_name(unit, seq);
        for dir in [
            self.packer.outbox().join(&name),
            self.packer.archive().join(&name),
        ] {
            if let Some(text) = read_verified_findings(&dir, unit, seq)? {
                out.extend(text.lines().map(str::to_string));
                return Ok(());
            }
        }
        Ok(())
    }

    fn save(&self) -> Result<(), ExportError> {
        let b = serde_json::to_vec_pretty(&self.state)
            .map_err(|e| ExportError::State(e.to_string()))?;
        fsutil::atomic_write(&self.cfg.state_path, &b)?;
        Ok(())
    }

    fn fail(&self, p: FailPoint) -> Result<(), ExportError> {
        if self.cfg.fail_point == Some(p) {
            Err(ExportError::Injected(p))
        } else {
            Ok(())
        }
    }

    /// Rename `ready/<seq>` to `acked/<seq>` for every seq; a record already
    /// in `acked/` (or gone: agentd prunes `acked/`) counts as done.
    fn ack(&self, seqs: &[u64], inject: bool) -> Result<(), ExportError> {
        for (i, &seq) in seqs.iter().enumerate() {
            let name = record_name(seq);
            match fs::rename(self.ready.join(&name), self.acked.join(&name)) {
                Ok(()) => {}
                Err(e) if e.kind() == io::ErrorKind::NotFound => {}
                Err(e) => return Err(e.into()),
            }
            if inject && i == 0 {
                fsutil::fsync_dir(&self.acked)?;
                fsutil::fsync_dir(&self.ready)?;
                self.fail(FailPoint::AfterFirstAck)?;
            }
        }
        fsutil::fsync_dir(&self.acked)?;
        fsutil::fsync_dir(&self.ready)?;
        Ok(())
    }

    fn reject(
        &mut self,
        name: &str,
        reason: String,
        report: &mut ExportReport,
    ) -> Result<(), ExportError> {
        // The reason first (durably: atomic_write fsyncs the file and
        // rejected/), then the rename. A crash in between leaves the record
        // in ready/ (rejected again on the next run) and a reason file that
        // retention never deletes while the name is in ready/. The other
        // order left a record without a reason, which retention dated by
        // the record's spool time and could delete at once.
        let why = serde_json::json!({ "file": name, "reason": reason });
        let reason_path = self.cfg.rejected_dir.join(format!("{name}.reason.json"));
        fsutil::atomic_write(&reason_path, why.to_string().as_bytes())?;
        let dest = self.cfg.rejected_dir.join(name);
        fs::rename(self.ready.join(name), &dest)?;
        fsutil::fsync_dir(&self.cfg.rejected_dir)?;
        fsutil::fsync_dir(&self.ready)?;
        self.state.rejected += 1;
        report.rejected.push(Rejected {
            file: name.to_string(),
            reason,
        });
        Ok(())
    }

    /// Check one spool file; `Err(reason)` rejects it. `Ok` carries the
    /// exact line the packer will write for it (without the newline).
    fn load(
        &self,
        seq: u64,
        name: &str,
    ) -> Result<Result<(FindingEnvelope, String), String>, ExportError> {
        // An I/O error (EACCES, EIO) is retried a bounded number of times,
        // then the file is quarantined in rejected/ with the error rather
        // than failing every run forever.
        let bytes = match fsutil::read_capped_retrying(&self.ready.join(name), MAX_SPOOL_FILE) {
            Ok(b) => b,
            Err(ReadError::Io(e)) => return Ok(Err(fsutil::unreadable_reason(&e))),
            Err(ReadError::Missing) => return Ok(Err("vanished".into())),
            Err(e) => return Ok(Err(format!("unreadable: {e}"))),
        };
        let rec: SpoolRecord = match serde_json::from_slice(&bytes) {
            Ok(r) => r,
            Err(e) => return Ok(Err(format!("not a spool record: {e}"))),
        };
        if rec.schema != SPOOL_SCHEMA {
            return Ok(Err(format!(
                "schema {:?}, expected {SPOOL_SCHEMA}",
                rec.schema
            )));
        }
        if rec.seq != seq {
            return Ok(Err(format!("seq {} does not match file name", rec.seq)));
        }
        let env = match robodr_ocsf::parse_and_validate(&rec.value) {
            Ok(e) => e,
            Err(errs) => {
                let first: Vec<String> = errs.iter().take(3).map(|e| e.to_string()).collect();
                return Ok(Err(format!("invalid finding: {}", first.join("; "))));
            }
        };
        if rec.key != env.finding_id {
            return Ok(Err("record key is not the finding id".into()));
        }
        if rec.topic != env.ocsf.metadata.log_name {
            return Ok(Err(format!(
                "topic {:?} is not the one the value names ({:?})",
                rec.topic, env.ocsf.metadata.log_name
            )));
        }
        // A contract 1.x record spooled before the upgrade: an unsigned one
        // is upgraded to contract 2.0 (same identity, see
        // `robodr_ocsf::upgrade`); a signed one cannot be (the signature
        // covers the 1.x bytes) and is kept in `rejected/`.
        let env = if robodr_ocsf::upgrade::is_legacy_version(&env.contract_version) {
            if !matches!(robodr_ocsf::signature_header(&rec.headers), Ok(None)) {
                return Ok(Err(format!(
                    "{} (contract {}; the finding signature covers the 1.x value, so it \
                     cannot be upgraded here: re-sign it on the robot or drain the spool \
                     before upgrading)",
                    robodr_ocsf::LEGACY_SIGNED_REASON,
                    env.contract_version
                )));
            }
            match robodr_ocsf::upgrade_legacy(
                &env,
                &self.cfg.upgrade_data_source,
                &self.cfg.upgrade_topic,
            ) {
                Ok(up) => up,
                Err(e) => {
                    return Ok(Err(format!(
                        "legacy contract {} record not upgraded: {e}",
                        env.contract_version
                    )))
                }
            }
        } else {
            env
        };
        // Exactly what the packer will write (it re-serialises with to_json).
        let line = match robodr_ocsf::to_json(&env) {
            Ok(l) => l,
            Err(e) => {
                let first: Vec<String> = e.iter().take(3).map(|e| e.to_string()).collect();
                return Ok(Err(format!(
                    "contract {} finding cannot be emitted: {}",
                    env.contract_version,
                    first.join("; ")
                )));
            }
        };
        Ok(Ok((env, line)))
    }

    /// Export everything currently in `ready/`. `now_ms` is the batches'
    /// `created_at`.
    pub fn run_once(&mut self, now_ms: u64) -> Result<ExportReport, ExportError> {
        if self.state.pending.is_some() {
            // An earlier step failed after the intent was written: only
            // `open` (which first lets the packer recover) may resolve it.
            return Err(ExportError::State(
                "an export step failed with an intent pending; re-open the exporter".into(),
            ));
        }
        let mut report = ExportReport {
            recovered: self.recovered.take(),
            ..Default::default()
        };
        loop {
            let files = list_ready(&self.ready)?;
            if files.is_empty() {
                break;
            }
            let mut envs = Vec::new();
            let mut seqs = Vec::new();
            let mut bytes = 0u64;
            for (seq, name) in files {
                match self.load(seq, &name)? {
                    Err(reason) => {
                        if reason != "vanished" {
                            if reason.starts_with(fsutil::UNREADABLE) {
                                report.quarantined_unreadable += 1;
                                eprintln!(
                                    "robodr-spool-export: WARNING: {name} quarantined: {reason}"
                                );
                            }
                            self.reject(&name, reason, &mut report)?;
                        }
                    }
                    Ok((env, line)) => {
                        let len = line.len() as u64 + 1;
                        // The packer's planner: start a new batch when this
                        // finding would overflow either bound.
                        if !envs.is_empty()
                            && (self.cfg.batch_size(bytes + len) > self.cfg.max_batch_bytes
                                || envs.len() >= self.cfg.max_findings_per_batch)
                        {
                            break;
                        }
                        bytes += len;
                        envs.push(env);
                        seqs.push(seq);
                    }
                }
            }
            if envs.is_empty() {
                // Everything left was rejected; list again.
                continue;
            }
            let intent = Intent {
                batch_seq: self.packer.state().next_seq,
                spool_seqs: seqs,
            };
            self.state.pending = Some(intent.clone());
            self.save()?;
            self.fail(FailPoint::AfterIntent)?;
            let published = self.packer.pack(&envs, &[], now_ms)?;
            if !matches!(published.as_slice(), [only] if only.seq == intent.batch_seq) {
                // All of them are committed and published; acknowledge, but
                // report the planner mismatch (crash recovery assumes one).
                self.ack(&intent.spool_seqs, false)?;
                self.state.pending = None;
                self.save()?;
                return Err(ExportError::State(format!(
                    "packer wrote {} batch(es) starting at seq {:?} for intent seq {}; \
                     records acknowledged, but max_batch_bytes / max_findings_per_batch must \
                     match the packer's",
                    published.len(),
                    published.first().map(|b| b.seq),
                    intent.batch_seq
                )));
            }
            self.fail(FailPoint::AfterPack)?;
            self.ack(&intent.spool_seqs, true)?;
            self.state.pending = None;
            self.state.exported += intent.spool_seqs.len() as u64;
            self.save()?;
            report.exported += intent.spool_seqs.len() as u64;
            report.batches.extend(published);
        }
        report.pruned_rejected = prune_rejected(
            &self.cfg.rejected_dir,
            &self.ready,
            &self.cfg.rejected_retention,
            std::time::SystemTime::now(),
        )?;
        Ok(report)
    }
}

/// Retention of the rejected directory (see "Retention" in the module
/// docs): each `<seq>.json` with its `<seq>.json.reason.json` is one item
/// (age: the reason file's time, i.e. when it was rejected; a record found
/// without one gets one now and is dated now), deleted together. A name
/// still in `ready/` is never touched.
pub fn prune_rejected(
    dir: &Path,
    ready: &Path,
    r: &Retention,
    now: std::time::SystemTime,
) -> io::Result<PruneReport> {
    if r.is_unbounded() {
        return Ok(PruneReport::default());
    }
    let rd = match fs::read_dir(dir) {
        Ok(rd) => rd,
        Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(PruneReport::default()),
        Err(e) => return Err(e),
    };
    let mut seqs = std::collections::BTreeSet::new();
    for e in rd {
        let e = e?;
        let Some(name) = e.file_name().to_str().map(str::to_string) else {
            continue;
        };
        let rec = name.strip_suffix(".reason.json").unwrap_or(&name);
        if let Some(seq) = record_seq(rec) {
            seqs.insert(seq);
        }
    }
    let mut items = Vec::new();
    for seq in seqs {
        let name = record_name(seq);
        let rec = dir.join(&name);
        let why = dir.join(format!("{name}.reason.json"));
        let (m_rec, mut m_why) = (file_meta(&rec)?, file_meta(&why)?);
        if m_why.is_none() && m_rec.is_some() && fs::symlink_metadata(ready.join(&name)).is_err() {
            // A record without its reason file (left by an earlier version
            // that renamed before writing the reason, or by an edit): its
            // mtime is when it was spooled, not when it was rejected, so it
            // is dated now, by writing the missing reason file.
            let note = serde_json::json!({
                "file": name,
                "reason": "unknown: the reason file was missing (rejected by a run that was \
                           interrupted before writing it); dated when this was noticed",
            });
            fsutil::atomic_write(&why, note.to_string().as_bytes())?;
            m_why = file_meta(&why)?;
        }
        let Some(modified) = m_why.or(m_rec).map(|m| m.0) else {
            continue;
        };
        let bytes = m_rec.map_or(0, |m| m.1) + m_why.map_or(0, |m| m.1);
        items.push(Candidate {
            name,
            // The record first: a crash in between leaves an orphan reason
            // file, which the next pass deletes.
            paths: vec![rec, why],
            modified,
            bytes,
        });
    }
    retention::prune(dir, &items, r, now, |c| {
        Ok(fs::symlink_metadata(ready.join(&c.name)).is_err())
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn names() {
        assert_eq!(record_seq("00000000000000000042.json"), Some(42));
        assert_eq!(record_seq("42.json"), None);
        assert_eq!(record_seq("00000000000000000042.json.tmp"), None);
        assert_eq!(record_name(42), "00000000000000000042.json");
    }

    #[test]
    fn rejected_retention_deletes_pairs_and_spares_ready() {
        let d = std::env::temp_dir().join(format!("robodr-rej-{}", std::process::id()));
        let _ = fs::remove_dir_all(&d);
        let (rej, ready) = (d.join("rejected"), d.join("ready"));
        fsutil::mkdir(&rej).unwrap();
        fsutil::mkdir(&ready).unwrap();
        for seq in 1..=4u64 {
            fs::write(rej.join(record_name(seq)), b"{}").unwrap();
            fs::write(rej.join(format!("{}.reason.json", record_name(seq))), b"{}").unwrap();
        }
        // An orphan reason file (crash between the two deletions), a name
        // also in ready/ (never touched), an unrelated file.
        fs::write(rej.join(format!("{}.reason.json", record_name(9))), b"{}").unwrap();
        fs::write(rej.join(record_name(7)), b"{}").unwrap();
        fs::write(ready.join(record_name(7)), b"{}").unwrap();
        fs::write(rej.join("notes.txt"), b"x").unwrap();
        let later = std::time::SystemTime::now() + std::time::Duration::from_secs(86_400);
        let none = prune_rejected(&rej, &ready, &Retention::UNBOUNDED, later).unwrap();
        assert_eq!(none, PruneReport::default());
        let r = Retention {
            max_count: Some(2),
            ..Default::default()
        };
        let rep = prune_rejected(&rej, &ready, &r, std::time::SystemTime::now()).unwrap();
        assert_eq!(rep.removed + rep.held, 4, "{rep:?}");
        let r = Retention::max_age(std::time::Duration::from_secs(3600));
        let rep = prune_rejected(&rej, &ready, &r, later).unwrap();
        assert_eq!(rep.held, 1, "seq 7 is in ready/");
        let mut left: Vec<String> = fs::read_dir(&rej)
            .unwrap()
            .map(|e| e.unwrap().file_name().into_string().unwrap())
            .collect();
        left.sort();
        assert_eq!(left, vec![record_name(7), "notes.txt".to_string()]);
        let _ = fs::remove_dir_all(&d);
    }

    /// Review finding: a record moved into rejected/ by a run that crashed
    /// before writing its reason file was dated by its spool mtime and
    /// deleted at once by an age bound. It is now dated when noticed.
    #[test]
    fn rejected_record_without_reason_is_not_deleted_at_once() {
        let d = std::env::temp_dir().join(format!("robodr-rej-noreason-{}", std::process::id()));
        let _ = fs::remove_dir_all(&d);
        let (rej, ready) = (d.join("rejected"), d.join("ready"));
        fsutil::mkdir(&rej).unwrap();
        fsutil::mkdir(&ready).unwrap();
        let rec = rej.join(record_name(5));
        fs::write(&rec, b"{}").unwrap();
        let month_ago = std::time::SystemTime::now() - std::time::Duration::from_secs(30 * 86_400);
        fs::File::options()
            .write(true)
            .open(&rec)
            .unwrap()
            .set_modified(month_ago)
            .unwrap();
        let r = Retention::max_age(std::time::Duration::from_secs(86_400));
        let rep = prune_rejected(&rej, &ready, &r, std::time::SystemTime::now()).unwrap();
        assert_eq!(rep.removed, 0, "{rep:?}");
        assert!(rec.exists());
        let why = rej.join(format!("{}.reason.json", record_name(5)));
        let note = fs::read_to_string(&why).unwrap();
        assert!(note.contains("reason file was missing"), "{note}");
        // Two days later it is old enough.
        let later = std::time::SystemTime::now() + std::time::Duration::from_secs(2 * 86_400);
        let rep = prune_rejected(&rej, &ready, &r, later).unwrap();
        assert_eq!(rep.removed, 1, "{rep:?}");
        assert!(!rec.exists() && !why.exists());
        let _ = fs::remove_dir_all(&d);
    }
}
