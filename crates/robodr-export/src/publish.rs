//! SOC side: publish findings records (`robodr.findings` contract) to
//! Kafka from
//!
//! * the diode importer's output, `out/<batch>/records.jsonl` (one Kafka
//!   record per line, see `robodr_diode::unpack`), or
//! * a connected site's agentd spool (`ready/` → `acked/`).
//!
//! # Record handling
//!
//! Every record is re-validated before it is sent: the value with
//! [`robodr_ocsf::parse_and_validate`], and the key and headers must be
//! exactly what [`robodr_ocsf::record`] derives from that value (contract
//! §2; a record whose headers disagree with its value is not forwarded).
//! The value must be of the current contract major (1.x findings are
//! parse-only and dead-lettered). The record's `topic` must be the one its
//! value names (`ocsf.metadata.log_name`); the publisher sends to its own
//! configured topic (`--topic`, default `robodr.findings`), whatever topic
//! the producer named, and counts records it relabelled that way
//! (`topic_overridden`).
//! The **value bytes sent are the ones on disk** (the validated bytes).
//! The partition is recomputed from the robot id and the topic's *current*
//! partition count (contract §4); a different `partition` in the input
//! (computed with another count) is overridden and counted. The Kafka
//! CreateTime is the publish time, not the finding time (a finding that
//! spent days crossing a diode must not be born expired under a 7-day
//! retention); the finding time is in the value.
//!
//! A record that fails validation, or that the broker rejects as a record
//! (`MESSAGE_TOO_LARGE`, `INVALID_RECORD`, ...), is appended to
//! `<state>/dead-letter.jsonl` with the reason and is not retried.
//!
//! # Progress (at-least-once, bounded duplication)
//!
//! Diode batches are processed in name order (= per unit, sequence order).
//! Records are sent in chunks of `chunk_records`; after a chunk is fully
//! acknowledged (`acks=all`), `<state>/progress.json` is replaced
//! atomically. It keeps a committed line count **per batch** (`in_flight`:
//! batch name -> lines acknowledged), so a batch interrupted mid-way keeps
//! its offset even when other batches (e.g. another unit's, whose name
//! sorts first) are published before it resumes. A finished batch gets a
//! marker `<state>/done/<batch>` (fsynced), its `in_flight` entry is
//! removed, and it is skipped from then on. After a crash, every batch
//! resumes after its last committed line, so at most one chunk per
//! interrupted batch (plus whatever a lost Produce response covered) is
//! re-sent. Consumers drop duplicates on `event-uid`.
//!
//! `in_flight` is bounded ([`MAX_IN_FLIGHT`] entries): entries of batches
//! that are done or no longer in `out/` are pruned at every run, and if the
//! bound is still exceeded the entry with the fewest committed lines is
//! dropped (that batch is then re-sent from its start: duplicates, never
//! loss). A version-1 progress file (`{batch, lines_committed}`) is
//! migrated on open.
//!
//! The dead-letter file is deduplicated on `(source, position)`: a record
//! dead-lettered in a chunk whose progress was not saved before a crash is
//! processed again after restart, but appended only once. The index of
//! existing entries is loaded from the file on the first dead letter of a
//! publisher (memory: 16 bytes per entry).
//!
//! For a spool source the commit is the rename `ready/ → acked/` of the
//! chunk's files (dead-lettered ones go to `<spool>/rejected/`).

use crate::fsutil::{self, ReadError};
use crate::kafka::{Outcome, ProduceError, ProduceRecord, Producer};
use robodr_agentd::spool::SpoolRecord;
use robodr_ocsf::DEFAULT_TOPIC;
use serde::{Deserialize, Serialize};
use std::collections::hash_map::DefaultHasher;
use std::collections::{BTreeMap, HashSet};
use std::fmt;
use std::fs;
use std::hash::{Hash, Hasher};
use std::io::{self, BufRead, BufReader, Read};
use std::path::{Path, PathBuf};

const STATE_FORMAT: &str = "robodr-kafka-publish-state/2";
const STATE_FORMAT_V1: &str = "robodr-kafka-publish-state/1";
/// Most batches with a persisted partial offset (see the module docs).
pub const MAX_IN_FLIGHT: usize = 1024;
/// File name of the importer's per-batch records.
pub const RECORDS_FILE: &str = robodr_diode::unpack::RECORDS_FILE;
pub const PROGRESS_FILE: &str = "progress.json";
pub const DONE_DIR: &str = "done";
pub const DEAD_LETTER_FILE: &str = "dead-letter.jsonl";

/// Where the publisher sends records. [`Producer`] is the real one; tests
/// may substitute their own.
pub trait Sink {
    fn partition_count(&mut self, topic: &str) -> Result<u32, ProduceError>;
    fn send(
        &mut self,
        topic: &str,
        records: &[(i32, ProduceRecord)],
    ) -> Result<Vec<Outcome>, ProduceError>;
}

impl Sink for Producer {
    fn partition_count(&mut self, topic: &str) -> Result<u32, ProduceError> {
        Producer::partition_count(self, topic)
    }
    fn send(
        &mut self,
        topic: &str,
        records: &[(i32, ProduceRecord)],
    ) -> Result<Vec<Outcome>, ProduceError> {
        Producer::send(self, topic, records)
    }
}

/// What to publish from.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Source {
    /// The importer's `out/` directory.
    DiodeOut(PathBuf),
    /// An agentd spool root.
    Spool(PathBuf),
}

/// Publisher settings.
#[derive(Debug, Clone)]
pub struct PublishConfig {
    pub source: Source,
    /// Progress, done markers, dead letters.
    pub state_dir: PathBuf,
    pub topic: String,
    /// Records per acknowledged chunk (1..=10 000).
    pub chunk_records: usize,
    /// Longest input line / spool file accepted.
    pub max_record_bytes: usize,
    /// Test hook: fail with [`PublishError::Injected`] after the n-th
    /// chunk (1-based) was acknowledged by Kafka but before progress was
    /// saved — a simulated crash.
    #[doc(hidden)]
    pub fail_after_send: Option<u64>,
}

impl PublishConfig {
    pub fn new(source: Source, state_dir: impl Into<PathBuf>) -> Self {
        Self {
            source,
            state_dir: state_dir.into(),
            topic: DEFAULT_TOPIC.into(),
            chunk_records: 500,
            max_record_bytes: 1024 * 1024,
            fail_after_send: None,
        }
    }
}

#[derive(Debug)]
pub enum PublishError {
    Config(String),
    State(String),
    Kafka(ProduceError),
    Io(io::Error),
    #[doc(hidden)]
    Injected,
}

impl fmt::Display for PublishError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Config(m) => write!(f, "configuration: {m}"),
            Self::State(m) => write!(f, "publisher state: {m}"),
            Self::Kafka(e) => write!(f, "kafka: {e}"),
            Self::Io(e) => write!(f, "I/O: {e}"),
            Self::Injected => write!(f, "injected failure"),
        }
    }
}

impl std::error::Error for PublishError {}

impl From<io::Error> for PublishError {
    fn from(e: io::Error) -> Self {
        Self::Io(e)
    }
}

impl From<ProduceError> for PublishError {
    fn from(e: ProduceError) -> Self {
        Self::Kafka(e)
    }
}

/// Persisted progress.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Progress {
    pub format: String,
    /// Lines acknowledged (count from the top) of each diode batch that was
    /// started but is not yet marked done. At most [`MAX_IN_FLIGHT`].
    pub in_flight: BTreeMap<String, u64>,
    pub published_total: u64,
    pub dead_lettered_total: u64,
}

impl Progress {
    fn empty() -> Self {
        Self {
            format: STATE_FORMAT.into(),
            in_flight: BTreeMap::new(),
            published_total: 0,
            dead_lettered_total: 0,
        }
    }

    /// Lines of `batch` acknowledged so far (0 if none / unknown).
    pub fn lines_committed(&self, batch: &str) -> u64 {
        self.in_flight.get(batch).copied().unwrap_or(0)
    }

    /// Record `lines` acknowledged for `batch`, keeping the map bounded.
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

    /// Parse a progress file (current format, or version 1 migrated).
    fn parse(bytes: &[u8]) -> Result<Self, String> {
        #[derive(Deserialize)]
        struct Fmt {
            format: String,
        }
        #[derive(Deserialize)]
        #[serde(deny_unknown_fields)]
        struct V1 {
            #[allow(dead_code)]
            format: String,
            batch: Option<String>,
            lines_committed: u64,
            published_total: u64,
            dead_lettered_total: u64,
        }
        let f: Fmt = serde_json::from_slice(bytes).map_err(|e| e.to_string())?;
        match f.format.as_str() {
            STATE_FORMAT => {
                let p: Progress = serde_json::from_slice(bytes).map_err(|e| e.to_string())?;
                if p.in_flight.len() > MAX_IN_FLIGHT {
                    return Err(format!("more than {MAX_IN_FLIGHT} in-flight batches"));
                }
                Ok(p)
            }
            STATE_FORMAT_V1 => {
                let v: V1 = serde_json::from_slice(bytes).map_err(|e| e.to_string())?;
                let mut p = Progress::empty();
                p.published_total = v.published_total;
                p.dead_lettered_total = v.dead_lettered_total;
                if let Some(b) = v.batch {
                    if v.lines_committed > 0 {
                        p.in_flight.insert(b, v.lines_committed);
                    }
                }
                Ok(p)
            }
            other => Err(format!("unknown format {other:?}")),
        }
    }
}

/// 128-bit key of a dead-letter entry: `(source, position)`.
fn dead_key(source: &str, pos: u64) -> u128 {
    let h = |salt: u8| {
        let mut st = DefaultHasher::new();
        salt.hash(&mut st);
        source.hash(&mut st);
        pos.hash(&mut st);
        st.finish()
    };
    (u128::from(h(1)) << 64) | u128::from(h(2))
}

/// What one run did.
#[derive(Debug, Default, Clone, PartialEq, Eq, Serialize)]
pub struct PublishReport {
    pub published: u64,
    pub dead_lettered: u64,
    pub batches_done: Vec<String>,
    /// Records whose input partition differed from the recomputed one.
    pub partition_overridden: u64,
    /// Records whose producer named another topic than the one published
    /// to (the publisher's configured topic wins).
    pub topic_overridden: u64,
    /// Lines skipped at the start of a resumed batch.
    pub resumed_after: u64,
}

/// One input record, as the importer writes it (and as agentd spools it).
#[derive(Debug, Clone, Deserialize)]
struct InRecord {
    topic: String,
    partition: Option<u32>,
    key: String,
    headers: Vec<(String, String)>,
    value: String,
}

impl From<SpoolRecord> for InRecord {
    fn from(r: SpoolRecord) -> Self {
        Self {
            topic: r.topic,
            partition: r.partition,
            key: r.key,
            headers: r.headers,
            value: r.value,
        }
    }
}

/// A unit of input: where it came from and its raw bytes.
struct Item {
    /// Diode: line number (1-based). Spool: record seq.
    pos: u64,
    /// Spool file name (spool source only).
    file: Option<String>,
    raw: Result<Vec<u8>, String>,
}

/// See the module docs.
pub struct Publisher<S: Sink> {
    cfg: PublishConfig,
    sink: S,
    progress: Progress,
    chunks_sent: u64,
    /// `(source, position)` keys already in the dead-letter file; loaded on
    /// the first dead letter.
    dead_seen: Option<HashSet<u128>>,
}

fn valid_batch_name(n: &str) -> bool {
    !n.is_empty()
        && n.len() <= 128
        && !n.starts_with('.')
        && n.bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"._-".contains(&b))
}

fn spool_seq(name: &str) -> Option<u64> {
    let stem = name.strip_suffix(".json")?;
    if stem.len() != 20 || !stem.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    stem.parse().ok()
}

impl<S: Sink> Publisher<S> {
    pub fn open(cfg: PublishConfig, sink: S) -> Result<Self, PublishError> {
        if !(1..=10_000).contains(&cfg.chunk_records) {
            return Err(PublishError::Config(
                "chunk_records must be in 1..=10000".into(),
            ));
        }
        if cfg.max_record_bytes < 1024 {
            return Err(PublishError::Config(
                "max_record_bytes must be >= 1024".into(),
            ));
        }
        fsutil::mkdir(&cfg.state_dir)?;
        fsutil::mkdir(&cfg.state_dir.join(DONE_DIR))?;
        if let Source::Spool(root) = &cfg.source {
            for d in ["ready", "acked"] {
                if !root.join(d).is_dir() {
                    return Err(PublishError::Config(format!(
                        "{}: no {d}/ (is this an agentd spool?)",
                        root.display()
                    )));
                }
            }
            fsutil::mkdir(&root.join("rejected"))?;
        }
        let path = cfg.state_dir.join(PROGRESS_FILE);
        let progress = match fsutil::read_capped(&path, 1024 * 1024) {
            Ok(b) => Progress::parse(&b)
                .map_err(|e| PublishError::State(format!("{}: {e}", path.display())))?,
            Err(ReadError::Missing) => Progress::empty(),
            Err(e) => return Err(PublishError::State(format!("{}: {e}", path.display()))),
        };
        Ok(Self {
            cfg,
            sink,
            progress,
            chunks_sent: 0,
            dead_seen: None,
        })
    }

    pub fn progress(&self) -> &Progress {
        &self.progress
    }

    pub fn sink(&self) -> &S {
        &self.sink
    }

    pub fn sink_mut(&mut self) -> &mut S {
        &mut self.sink
    }

    fn save(&self) -> Result<(), PublishError> {
        let b = serde_json::to_vec_pretty(&self.progress)
            .map_err(|e| PublishError::State(e.to_string()))?;
        fsutil::atomic_write(&self.cfg.state_dir.join(PROGRESS_FILE), &b)?;
        Ok(())
    }

    /// Keys of the entries already in the dead-letter file (unparsable
    /// lines are ignored).
    fn load_dead_keys(&self) -> Result<HashSet<u128>, PublishError> {
        #[derive(Deserialize)]
        struct Key {
            source: String,
            position: u64,
        }
        let mut seen = HashSet::new();
        let path = self.cfg.state_dir.join(DEAD_LETTER_FILE);
        let f = match fs::File::open(&path) {
            Ok(f) => f,
            Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(seen),
            Err(e) => return Err(e.into()),
        };
        for line in BufReader::new(f).split(b'\n') {
            if let Ok(k) = serde_json::from_slice::<Key>(&line?) {
                seen.insert(dead_key(&k.source, k.position));
            }
        }
        Ok(seen)
    }

    fn dead_letter(
        &mut self,
        context: &str,
        pos: u64,
        reason: &str,
        raw: &[u8],
        report: &mut PublishReport,
    ) -> Result<(), PublishError> {
        if self.dead_seen.is_none() {
            self.dead_seen = Some(self.load_dead_keys()?);
        }
        let key = dead_key(context, pos);
        // Counted either way: the earlier append's count was never saved
        // (its chunk's progress was lost, or we would not be here again).
        self.progress.dead_lettered_total += 1;
        report.dead_lettered += 1;
        if self.dead_seen.as_ref().is_some_and(|s| s.contains(&key)) {
            return Ok(());
        }
        let raw = String::from_utf8_lossy(&raw[..raw.len().min(self.cfg.max_record_bytes)]);
        let mut line = serde_json::to_vec(&serde_json::json!({
            "source": context,
            "position": pos,
            "reason": reason,
            "record": raw,
            "at_ms": fsutil::now_ms(),
        }))
        .map_err(|e| PublishError::State(e.to_string()))?;
        line.push(b'\n');
        fsutil::append_durable(&self.cfg.state_dir.join(DEAD_LETTER_FILE), &line)?;
        if let Some(s) = self.dead_seen.as_mut() {
            s.insert(key);
        }
        Ok(())
    }

    /// Validate one input record and build what is sent. `Err` = reason.
    fn prepare(
        &self,
        raw: &[u8],
        partitions: u32,
        report: &mut PublishReport,
    ) -> Result<(i32, ProduceRecord), String> {
        let rec: InRecord =
            serde_json::from_slice(raw).map_err(|e| format!("not a record: {e}"))?;
        let env = robodr_ocsf::parse_and_validate(&rec.value).map_err(|errs| {
            let v: Vec<String> = errs.iter().take(3).map(|e| e.to_string()).collect();
            format!("invalid finding: {}", v.join("; "))
        })?;
        if !robodr_ocsf::validate::is_emittable_contract_version(&env.contract_version) {
            return Err(format!(
                "contract {} findings are parse-only and not published",
                env.contract_version
            ));
        }
        let want = robodr_ocsf::record(&env, Some(partitions))
            .map_err(|_| "finding cannot be emitted".to_string())?;
        if rec.key != want.key {
            return Err("key is not the finding id".into());
        }
        if rec.topic != want.topic {
            return Err(format!(
                "topic {:?} is not the one the value names ({:?})",
                rec.topic, want.topic
            ));
        }
        if want.topic != self.cfg.topic {
            report.topic_overridden += 1;
        }
        // An optional detached finding signature (contract §2a) is carried
        // verbatim as the last header; every other header is re-derived from
        // the value and must match. The signature is checked for shape here
        // and verified by the consumer (it needs the unit's finding key).
        let sig = robodr_ocsf::signature_header(&rec.headers)
            .map_err(|e| format!("finding signature header: {e}"))?;
        let base = match sig {
            Some(v) => {
                robodr_ocsf::FindingSignature::from_header_value(v)
                    .map_err(|e| format!("finding signature header: {e}"))?;
                let last_is_sig = rec
                    .headers
                    .last()
                    .is_some_and(|(k, _)| k == robodr_ocsf::SIG_HEADER);
                if !last_is_sig {
                    return Err(format!(
                        "{} must be the last header",
                        robodr_ocsf::SIG_HEADER
                    ));
                }
                &rec.headers[..rec.headers.len() - 1]
            }
            None => &rec.headers[..],
        };
        let same_headers = base.len() == want.headers.len()
            && base
                .iter()
                .zip(&want.headers)
                .all(|((k, v), (wk, wv))| k == wk && v == wv);
        if !same_headers {
            return Err("headers disagree with the value".into());
        }
        let p = want
            .partition
            .ok_or_else(|| "no partition (zero partitions?)".to_string())?;
        if rec.partition.is_some_and(|x| x != p) {
            report.partition_overridden += 1;
        }
        Ok((
            p as i32,
            ProduceRecord {
                key: Some(rec.key.into_bytes()),
                value: Some(rec.value.into_bytes()),
                headers: rec
                    .headers
                    .into_iter()
                    .map(|(k, v)| (k, v.into_bytes()))
                    .collect(),
                timestamp_ms: fsutil::now_ms() as i64,
            },
        ))
    }

    /// Send one chunk. Returns the positions handled (delivered or dead-lettered).
    fn send_chunk(
        &mut self,
        context: &str,
        items: &[Item],
        report: &mut PublishReport,
    ) -> Result<Vec<(u64, Option<String>, bool)>, PublishError> {
        let n = self.sink.partition_count(&self.cfg.topic)?;
        if n == 0 {
            return Err(PublishError::Kafka(ProduceError::Config(format!(
                "topic {} has no partitions",
                self.cfg.topic
            ))));
        }
        let mut to_send = Vec::new();
        let mut sent_items = Vec::new();
        let mut done = Vec::new();
        for it in items {
            let prepared = match &it.raw {
                Ok(raw) => self.prepare(raw, n, report),
                Err(e) => Err(e.clone()),
            };
            match prepared {
                Ok(r) => {
                    to_send.push(r);
                    sent_items.push(it);
                }
                Err(reason) => {
                    let raw = it.raw.as_deref().unwrap_or(&[]);
                    self.dead_letter(context, it.pos, &reason, raw, report)?;
                    done.push((it.pos, it.file.clone(), false));
                }
            }
        }
        if !to_send.is_empty() {
            let outcomes = self.sink.send(&self.cfg.topic, &to_send)?;
            self.chunks_sent += 1;
            if outcomes.len() != to_send.len() {
                return Err(PublishError::State(
                    "sink returned wrong outcome count".into(),
                ));
            }
            for (it, o) in sent_items.iter().zip(outcomes) {
                match o {
                    Outcome::Delivered { .. } => {
                        self.progress.published_total += 1;
                        report.published += 1;
                        done.push((it.pos, it.file.clone(), true));
                    }
                    Outcome::Rejected { code, reason } => {
                        let raw = it.raw.as_deref().unwrap_or(&[]);
                        let why = format!("rejected by Kafka ({code}): {reason}");
                        self.dead_letter(context, it.pos, &why, raw, report)?;
                        done.push((it.pos, it.file.clone(), false));
                    }
                }
            }
            if self.cfg.fail_after_send == Some(self.chunks_sent) {
                return Err(PublishError::Injected);
            }
        }
        Ok(done)
    }

    /// Publish everything currently available.
    pub fn run_once(&mut self) -> Result<PublishReport, PublishError> {
        let mut report = PublishReport::default();
        match self.cfg.source.clone() {
            Source::DiodeOut(out) => self.run_diode(&out, &mut report)?,
            Source::Spool(root) => self.run_spool(&root, &mut report)?,
        }
        Ok(report)
    }

    fn run_diode(&mut self, out: &Path, report: &mut PublishReport) -> Result<(), PublishError> {
        let mut names = Vec::new();
        for e in fs::read_dir(out)? {
            let e = e?;
            let Some(name) = e.file_name().to_str().map(str::to_string) else {
                continue;
            };
            // Dot-entries are the importer's staging directories.
            if !valid_batch_name(&name) || !e.file_type()?.is_dir() {
                continue;
            }
            names.push(name);
        }
        names.sort();
        let done_dir = self.cfg.state_dir.join(DONE_DIR);
        // Prune offsets of batches that are done or gone from out/.
        let before = self.progress.in_flight.len();
        self.progress.in_flight.retain(|b, _| {
            names.binary_search(b).is_ok() && fs::symlink_metadata(done_dir.join(b)).is_err()
        });
        if self.progress.in_flight.len() != before {
            self.save()?;
        }
        for name in names {
            let marker = done_dir.join(&name);
            if fs::symlink_metadata(&marker).is_ok() {
                continue;
            }
            self.publish_batch(out, &name, report)?;
            fsutil::atomic_write(&marker, b"")?;
            self.progress.in_flight.remove(&name);
            self.save()?;
            report.batches_done.push(name);
        }
        Ok(())
    }

    fn publish_batch(
        &mut self,
        out: &Path,
        name: &str,
        report: &mut PublishReport,
    ) -> Result<(), PublishError> {
        let path = out.join(name).join(RECORDS_FILE);
        let file = match fs::symlink_metadata(&path) {
            Ok(m) if m.is_file() => fs::File::open(&path)?,
            // A batch with bundles only has no records.
            Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(()),
            Ok(_) => {
                return Err(PublishError::State(format!(
                    "{} is not a regular file",
                    path.display()
                )))
            }
            Err(e) => return Err(e.into()),
        };
        let skip = self.progress.lines_committed(name);
        report.resumed_after += skip;
        let cap = self.cfg.max_record_bytes as u64;
        let mut reader = BufReader::new(file);
        let mut line_no = 0u64;
        let mut chunk: Vec<Item> = Vec::new();
        loop {
            let mut buf = Vec::new();
            let n = (&mut reader).take(cap + 1).read_until(b'\n', &mut buf)?;
            if n == 0 {
                break;
            }
            let raw = if buf.last() == Some(&b'\n') {
                buf.pop();
                Ok(buf)
            } else if buf.len() as u64 > cap {
                // Overlong line: skip to its end.
                let mut sink = Vec::new();
                loop {
                    sink.clear();
                    let m = (&mut reader).take(cap).read_until(b'\n', &mut sink)?;
                    if m == 0 || sink.last() == Some(&b'\n') {
                        break;
                    }
                }
                Err(format!("line longer than {cap} bytes"))
            } else {
                // Last line without a newline: the importer always ends
                // lines, so this is truncation.
                Err("truncated last line (no newline)".into())
            };
            line_no += 1;
            if line_no <= skip {
                continue;
            }
            chunk.push(Item {
                pos: line_no,
                file: None,
                raw,
            });
            if chunk.len() >= self.cfg.chunk_records {
                self.commit_lines(name, &std::mem::take(&mut chunk), report)?;
            }
        }
        if !chunk.is_empty() {
            self.commit_lines(name, &chunk, report)?;
        }
        Ok(())
    }

    fn commit_lines(
        &mut self,
        name: &str,
        chunk: &[Item],
        report: &mut PublishReport,
    ) -> Result<(), PublishError> {
        self.send_chunk(name, chunk, report)?;
        if let Some(last) = chunk.last() {
            self.progress.set_committed(name, last.pos);
        }
        self.save()
    }

    fn run_spool(&mut self, root: &Path, report: &mut PublishReport) -> Result<(), PublishError> {
        let ready = root.join("ready");
        let acked = root.join("acked");
        let rejected = root.join("rejected");
        loop {
            let mut files = Vec::new();
            for e in fs::read_dir(&ready)? {
                let e = e?;
                let Some(name) = e.file_name().to_str().map(str::to_string) else {
                    continue;
                };
                if let Some(seq) = spool_seq(&name) {
                    if e.file_type()?.is_file() {
                        files.push((seq, name));
                    }
                }
            }
            if files.is_empty() {
                return Ok(());
            }
            files.sort();
            files.truncate(self.cfg.chunk_records);
            let mut items = Vec::with_capacity(files.len());
            for (seq, name) in files {
                let raw =
                    match fsutil::read_capped(&ready.join(&name), self.cfg.max_record_bytes as u64)
                    {
                        Ok(b) => serde_json::from_slice::<SpoolRecord>(&b)
                            .map_err(|e| format!("not a spool record: {e}"))
                            .and_then(|r| {
                                if r.seq == seq {
                                    serde_json::to_vec(&serde_json::json!({
                                        "topic": r.topic, "partition": r.partition, "key": r.key,
                                        "headers": r.headers, "value": r.value,
                                    }))
                                    .map_err(|e| e.to_string())
                                } else {
                                    Err(format!("seq {} does not match file name", r.seq))
                                }
                            }),
                        Err(ReadError::Io(e)) => return Err(e.into()),
                        Err(e) => Err(format!("unreadable: {e}")),
                    };
                items.push(Item {
                    pos: seq,
                    file: Some(name),
                    raw,
                });
            }
            let done = self.send_chunk(&root.display().to_string(), &items, report)?;
            for (_, file, delivered) in done {
                let Some(file) = file else { continue };
                let dest = if delivered { &acked } else { &rejected };
                match fs::rename(ready.join(&file), dest.join(&file)) {
                    Ok(()) => {}
                    Err(e) if e.kind() == io::ErrorKind::NotFound => {}
                    Err(e) => return Err(e.into()),
                }
            }
            fsutil::fsync_dir(&acked)?;
            fsutil::fsync_dir(&rejected)?;
            fsutil::fsync_dir(&ready)?;
            self.save()?;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn batch_names() {
        assert!(valid_batch_name("rdd_ugv-007_0000000000000001"));
        assert!(valid_batch_name(
            "rdd_ugv-007_0000000000000001.0123456789abcdef"
        ));
        assert!(!valid_batch_name(".tmp-rdd_x_1"));
        assert!(!valid_batch_name("a/b"));
        assert!(!valid_batch_name(""));
        assert!(!valid_batch_name(&"a".repeat(200)));
    }

    #[test]
    fn in_flight_map_is_bounded() {
        let mut p = Progress::empty();
        for i in 0..MAX_IN_FLIGHT as u64 {
            p.set_committed(&format!("b{i:05}"), i + 10);
        }
        assert_eq!(p.in_flight.len(), MAX_IN_FLIGHT);
        // One more: the entry with the fewest committed lines goes.
        p.set_committed("new", 1);
        assert_eq!(p.in_flight.len(), MAX_IN_FLIGHT);
        assert_eq!(p.lines_committed("new"), 1, "the batch being saved stays");
        assert_eq!(p.lines_committed("b00000"), 0, "smallest evicted");
        assert_eq!(p.lines_committed("b00001"), 11);
        // Updating an existing entry never evicts.
        p.set_committed("b00001", 99);
        assert_eq!(p.in_flight.len(), MAX_IN_FLIGHT);
    }

    #[test]
    fn progress_parsing() {
        let v2 = Progress::parse(
            br#"{"format":"robodr-kafka-publish-state/2","in_flight":{"a":3},"published_total":3,"dead_lettered_total":1}"#,
        )
        .unwrap();
        assert_eq!(v2.lines_committed("a"), 3);
        let v1 = Progress::parse(
            br#"{"format":"robodr-kafka-publish-state/1","batch":null,"lines_committed":0,"published_total":7,"dead_lettered_total":0}"#,
        )
        .unwrap();
        assert!(v1.in_flight.is_empty());
        assert_eq!(v1.published_total, 7);
        assert_eq!(v1.format, STATE_FORMAT, "migrated");
        for bad in [
            &b"{}"[..],
            b"not json",
            br#"{"format":"robodr-kafka-publish-state/9"}"#,
            br#"{"format":"robodr-kafka-publish-state/2","in_flight":{"a":-1},"published_total":0,"dead_lettered_total":0}"#,
            br#"{"format":"robodr-kafka-publish-state/2","in_flight":{},"published_total":0,"dead_lettered_total":0,"x":1}"#,
        ] {
            assert!(Progress::parse(bad).is_err(), "{}", String::from_utf8_lossy(bad));
        }
        let mut huge = String::from(r#"{"format":"robodr-kafka-publish-state/2","in_flight":{"#);
        for i in 0..=MAX_IN_FLIGHT {
            if i > 0 {
                huge.push(',');
            }
            huge.push_str(&format!("\"b{i}\":1"));
        }
        huge.push_str(r#"},"published_total":0,"dead_lettered_total":0}"#);
        assert!(Progress::parse(huge.as_bytes()).is_err());
    }

    #[test]
    fn dead_keys_distinguish_source_and_position() {
        assert_eq!(dead_key("a", 1), dead_key("a", 1));
        assert_ne!(dead_key("a", 1), dead_key("a", 2));
        assert_ne!(dead_key("a", 1), dead_key("b", 1));
    }
}
