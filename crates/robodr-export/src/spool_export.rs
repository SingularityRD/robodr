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
//!    [`SpoolRecord`], checked (`schema`, `seq` = file name, topic) and its
//!    `value` re-validated with [`robodr_ocsf::parse_and_validate`]. A record
//!    that fails is **moved** to `<spool>/rejected/` with a `.reason.json`
//!    beside it (never deleted). The batch is cut so the packer is
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
//! `packer.next_seq > intent.batch_seq` means step 3 committed, so the
//! records are acknowledged (step 4, idempotent: a record already in
//! `acked/` counts as done); otherwise nothing was published and the intent
//! is dropped (the records are still in `ready/` and are packed again, under
//! the same diode sequence number, which was never visible).
//!
//! `ready/` is never deleted from; records leave it only by rename (to
//! `acked/` after publication, or to `rejected/`).
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
use robodr_agentd::spool::{SpoolRecord, SPOOL_SCHEMA};
use robodr_diode::{PackError, Packer, PublishedBatch};
use robodr_ocsf::{FindingEnvelope, KAFKA_TOPIC};
use serde::{Deserialize, Serialize};
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
            fail_point: None,
        }
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
    /// A pending intent found at open: `"acked"` (batch had been published)
    /// or `"dropped"` (it had not).
    pub recovered: Option<String>,
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

impl Exporter {
    /// Open the packer (which finishes a committed batch) and the exporter
    /// state, then resolve a pending intent (see the module docs).
    pub fn open(cfg: ExportConfig, packer: Packer) -> Result<Self, ExportError> {
        if cfg.max_findings_per_batch == 0 {
            return Err(ExportError::Config(
                "max_findings_per_batch must be >= 1".into(),
            ));
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
                x.ack(&intent.spool_seqs, false)?;
                x.state.exported += intent.spool_seqs.len() as u64;
                x.recovered = Some("acked".into());
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
        let dest = self.cfg.rejected_dir.join(name);
        fs::rename(self.ready.join(name), &dest)?;
        let why = serde_json::json!({ "file": name, "reason": reason });
        let reason_path = self.cfg.rejected_dir.join(format!("{name}.reason.json"));
        fsutil::atomic_write(&reason_path, why.to_string().as_bytes())?;
        fsutil::fsync_dir(&self.ready)?;
        self.state.rejected += 1;
        report.rejected.push(Rejected {
            file: name.to_string(),
            reason,
        });
        Ok(())
    }

    /// Check one spool file; `Err(reason)` rejects it.
    fn load(
        &self,
        seq: u64,
        name: &str,
    ) -> Result<Result<(FindingEnvelope, usize), String>, ExportError> {
        let bytes = match fsutil::read_capped(&self.ready.join(name), MAX_SPOOL_FILE) {
            Ok(b) => b,
            Err(ReadError::Io(e)) => return Err(e.into()),
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
        if rec.topic != KAFKA_TOPIC {
            return Ok(Err(format!(
                "topic {:?}, expected {KAFKA_TOPIC}",
                rec.topic
            )));
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
        // Exactly what the packer will write (it re-serialises with to_json).
        let line = match robodr_ocsf::to_json(&env) {
            Ok(l) => l,
            Err(_) => return Ok(Err("finding cannot be emitted (to_json)".into())),
        };
        Ok(Ok((env, line.len() + 1)))
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
                            self.reject(&name, reason, &mut report)?;
                        }
                    }
                    Ok((env, len)) => {
                        let len = len as u64;
                        // The packer's planner: start a new batch when this
                        // finding would overflow either bound.
                        if !envs.is_empty()
                            && (bytes + len > self.cfg.max_batch_bytes
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
            if published.len() != 1 || published[0].seq != intent.batch_seq {
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
        Ok(report)
    }
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
}
