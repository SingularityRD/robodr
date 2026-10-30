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
//! The value must be of the current contract major. A contract 1.x record
//! (spooled or imported before an upgrade) is upgraded to contract 2.0 when
//! it is unsigned and consistent with its own value
//! ([`robodr_ocsf::upgrade_legacy`]: `data_source`
//! [`PublishConfig::upgrade_data_source`], topic the publisher's own; same
//! identity) and is then sent as the upgraded value with headers derived
//! from it (counted in `legacy_upgraded`); a signed 1.x record cannot be
//! upgraded (the signature covers the 1.x bytes) and is dead-lettered with
//! the reason "legacy 1.x signed record: re-sign required". The record's `topic` must be the one its
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

use crate::deadletter::DeadLetters;
use crate::fsutil::{self, ReadError};
use crate::kafka::{Outcome, ProduceError, ProduceRecord, Producer};
use robodr_agentd::spool::SpoolRecord;
use robodr_ocsf::{DEFAULT_DATA_SOURCE, DEFAULT_TOPIC};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::fmt;
use std::fs;
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
    /// `data_source` an unsigned contract 1.x record gets when it is
    /// upgraded to contract 2.0 (default [`DEFAULT_DATA_SOURCE`]); its topic
    /// becomes [`topic`](Self::topic).
    pub upgrade_data_source: String,
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
            upgrade_data_source: DEFAULT_DATA_SOURCE.into(),
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
    /// Unsigned contract 1.x records upgraded to contract 2.0 and sent.
    pub legacy_upgraded: u64,
    /// Malformed lines found in the dead-letter file when it was loaded in
    /// this run (torn fragments, edits; [`crate::deadletter`]).
    pub dead_letter_malformed: u64,
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

/// Batch directories of the importer's `out/` (complete by construction;
/// dot-entries are its staging directories), in name order.
pub(crate) fn list_diode_batches(out: &Path) -> io::Result<Vec<String>> {
    let mut names = Vec::new();
    for e in fs::read_dir(out)? {
        let e = e?;
        let Some(name) = e.file_name().to_str().map(str::to_string) else {
            continue;
        };
        if !valid_batch_name(&name) || !e.file_type()?.is_dir() {
            continue;
        }
        names.push(name);
    }
    names.sort();
    Ok(names)
}

/// `(seq, file name)` of the spool's `ready/` records, in seq order.
pub(crate) fn list_ready(ready: &Path) -> io::Result<Vec<(u64, String)>> {
    let mut files = Vec::new();
    for e in fs::read_dir(ready)? {
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
    files.sort();
    Ok(files)
}

/// One spool file as an input record (`{topic, partition, key, headers,
/// value}` JSON). Outer `Err`: I/O error (stop); inner `Err`: the record is
/// unusable (reason; dead-letter it).
pub(crate) fn read_spool_item(
    path: &Path,
    seq: u64,
    max: usize,
) -> io::Result<Result<Vec<u8>, String>> {
    Ok(match fsutil::read_capped(path, max as u64) {
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
        Err(ReadError::Io(e)) => return Err(e),
        Err(e) => Err(format!("unreadable: {e}")),
    })
}

/// One input line: `(1-based line number, raw bytes or the reason the line
/// is unusable)`.
pub(crate) type NumberedLine = (u64, Result<Vec<u8>, String>);

/// Why [`LineReader::open`] failed.
pub(crate) enum OpenRecordsError {
    /// `records.jsonl` exists but is not a regular file.
    NotRegular(String),
    Io(io::Error),
}

/// Reads a diode batch's `records.jsonl` line by line (1-based line
/// numbers), each line capped: an overlong line, or a last line without a
/// newline (the importer always ends lines: truncation), is returned as
/// `Err(reason)`.
pub(crate) struct LineReader {
    reader: BufReader<fs::File>,
    cap: u64,
    line_no: u64,
}

impl LineReader {
    /// `Ok(None)`: the batch has no records file (bundles only).
    pub(crate) fn open(
        out: &Path,
        batch: &str,
        max_record_bytes: usize,
    ) -> Result<Option<Self>, OpenRecordsError> {
        let path = out.join(batch).join(RECORDS_FILE);
        let file = match fs::symlink_metadata(&path) {
            Ok(m) if m.is_file() => fs::File::open(&path).map_err(OpenRecordsError::Io)?,
            Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(None),
            Ok(_) => {
                return Err(OpenRecordsError::NotRegular(format!(
                    "{} is not a regular file",
                    path.display()
                )))
            }
            Err(e) => return Err(OpenRecordsError::Io(e)),
        };
        Ok(Some(Self {
            reader: BufReader::new(file),
            cap: max_record_bytes as u64,
            line_no: 0,
        }))
    }

    /// The next line, or `None` at the end of the file.
    pub(crate) fn next_line(&mut self) -> io::Result<Option<NumberedLine>> {
        let cap = self.cap;
        let mut buf = Vec::new();
        let n = (&mut self.reader)
            .take(cap + 1)
            .read_until(b'\n', &mut buf)?;
        if n == 0 {
            return Ok(None);
        }
        let raw = if buf.last() == Some(&b'\n') {
            buf.pop();
            Ok(buf)
        } else if buf.len() as u64 > cap {
            // Overlong line: skip to its end.
            let mut sink = Vec::new();
            loop {
                sink.clear();
                let m = (&mut self.reader).take(cap).read_until(b'\n', &mut sink)?;
                if m == 0 || sink.last() == Some(&b'\n') {
                    break;
                }
            }
            Err(format!("line longer than {cap} bytes"))
        } else {
            Err("truncated last line (no newline)".into())
        };
        self.line_no += 1;
        Ok(Some((self.line_no, raw)))
    }
}

/// An input record that passed [`check_record`]: what a forwarder sends.
#[derive(Debug, Clone)]
pub(crate) struct CheckedRecord {
    /// The value to send: the input bytes verbatim, or (legacy 1.x,
    /// unsigned) the upgraded 2.0 value.
    pub value: String,
    /// Kafka key (= finding id).
    pub key: String,
    /// Headers to send: derived from the value, plus the input's
    /// [`robodr_ocsf::SIG_HEADER`] (shape-checked, verbatim) as the last one.
    pub headers: Vec<(String, String)>,
    /// The per-finding signature (contract §2a), if the input carried one.
    pub sig: Option<robodr_ocsf::FindingSignature>,
    /// `entity_context.robot.id` (partition key).
    pub robot_id: String,
    /// The partition the input named, if any.
    pub input_partition: Option<u32>,
    /// An unsigned contract 1.x record upgraded to contract 2.0.
    pub legacy_upgraded: bool,
    /// The value names another topic than `topic`.
    pub topic_overridden: bool,
}

/// Validate one input record (`{topic, partition, key, headers, value}`,
/// as agentd spools it and the diode importer writes it); `Err` = reason.
/// See the module docs: the value is re-validated, key, topic and headers
/// must be what [`robodr_ocsf::record`] derives from it, an optional finding
/// signature header must be well formed and last, and a contract 1.x record
/// is upgraded (unsigned) or refused (signed). `topic` is the forwarder's
/// own topic (upgraded values name it); `upgrade_data_source` the
/// `data_source` an upgraded value gets.
pub(crate) fn check_record(
    raw: &[u8],
    topic: &str,
    upgrade_data_source: &str,
) -> Result<CheckedRecord, String> {
    let rec: InRecord = serde_json::from_slice(raw).map_err(|e| format!("not a record: {e}"))?;
    let env = robodr_ocsf::parse_and_validate(&rec.value).map_err(|errs| {
        let v: Vec<String> = errs.iter().take(3).map(|e| e.to_string()).collect();
        format!("invalid finding: {}", v.join("; "))
    })?;
    if robodr_ocsf::upgrade::is_legacy_version(&env.contract_version) {
        return check_legacy(rec, env, topic, upgrade_data_source);
    }
    if !robodr_ocsf::validate::is_emittable_contract_version(&env.contract_version) {
        return Err(format!(
            "contract {} findings are parse-only and not published",
            env.contract_version
        ));
    }
    let want =
        robodr_ocsf::record(&env, None).map_err(|_| "finding cannot be emitted".to_string())?;
    if rec.key != want.key {
        return Err("key is not the finding id".into());
    }
    if rec.topic != want.topic {
        return Err(format!(
            "topic {:?} is not the one the value names ({:?})",
            rec.topic, want.topic
        ));
    }
    // An optional detached finding signature (contract §2a) is carried
    // verbatim as the last header; every other header is re-derived from
    // the value and must match. The signature is checked for shape here
    // and verified by the consumer (it needs the unit's finding key).
    let sig = robodr_ocsf::signature_header(&rec.headers)
        .map_err(|e| format!("finding signature header: {e}"))?;
    let (base, sig) = match sig {
        Some(v) => {
            let parsed = robodr_ocsf::FindingSignature::from_header_value(v)
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
            let base = rec.headers.split_last().map_or(&[][..], |(_, base)| base);
            (base, Some(parsed))
        }
        None => (&rec.headers[..], None),
    };
    let same_headers = base.len() == want.headers.len()
        && base
            .iter()
            .zip(&want.headers)
            .all(|((k, v), (wk, wv))| k == wk && v == wv);
    if !same_headers {
        return Err("headers disagree with the value".into());
    }
    Ok(CheckedRecord {
        topic_overridden: want.topic != topic,
        value: rec.value,
        key: rec.key,
        headers: rec.headers,
        sig,
        robot_id: env.entity_context.robot.id,
        input_partition: rec.partition,
        legacy_upgraded: false,
    })
}

/// A contract 1.x record: checked against its own value like any record,
/// then (unsigned only) upgraded to contract 2.0 and re-derived.
fn check_legacy(
    rec: InRecord,
    env: robodr_ocsf::FindingEnvelope,
    topic: &str,
    upgrade_data_source: &str,
) -> Result<CheckedRecord, String> {
    if !matches!(robodr_ocsf::signature_header(&rec.headers), Ok(None)) {
        return Err(format!(
            "{} (contract {}; the finding signature covers the 1.x value, so it cannot be \
             upgraded here: re-sign it on the robot, or drain before upgrading)",
            robodr_ocsf::LEGACY_SIGNED_REASON,
            env.contract_version
        ));
    }
    if rec.key != env.finding_id {
        return Err("key is not the finding id".into());
    }
    if rec.topic != env.ocsf.metadata.log_name {
        return Err(format!(
            "topic {:?} is not the one the value names ({:?})",
            rec.topic, env.ocsf.metadata.log_name
        ));
    }
    let own = robodr_ocsf::headers(&env);
    let same_headers = rec.headers.len() == own.len()
        && rec
            .headers
            .iter()
            .zip(&own)
            .all(|((k, v), (wk, wv))| k == wk && v == wv);
    if !same_headers {
        return Err("headers disagree with the value".into());
    }
    let up = robodr_ocsf::upgrade_legacy(&env, upgrade_data_source, topic).map_err(|e| {
        format!(
            "legacy contract {} record not upgraded: {e}",
            env.contract_version
        )
    })?;
    let want = robodr_ocsf::record(&up, None)
        .map_err(|_| "upgraded finding cannot be emitted".to_string())?;
    Ok(CheckedRecord {
        value: want.value,
        key: want.key,
        headers: want
            .headers
            .into_iter()
            .map(|(k, v)| (k.to_string(), v))
            .collect(),
        sig: None,
        robot_id: up.entity_context.robot.id,
        input_partition: rec.partition,
        legacy_upgraded: true,
        topic_overridden: false,
    })
}

/// See the module docs.
pub struct Publisher<S: Sink> {
    cfg: PublishConfig,
    sink: S,
    progress: Progress,
    chunks_sent: u64,
    /// The dead-letter file (dedup set loaded on the first dead letter).
    dead: DeadLetters,
    dead_loaded: bool,
}

pub(crate) fn valid_batch_name(n: &str) -> bool {
    !n.is_empty()
        && n.len() <= 128
        && !n.starts_with('.')
        && n.bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"._-".contains(&b))
}

pub(crate) fn spool_seq(name: &str) -> Option<u64> {
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
        if !robodr_ocsf::validate::is_valid_data_source(&cfg.upgrade_data_source)
            || !robodr_ocsf::validate::is_valid_topic(&cfg.topic)
        {
            return Err(PublishError::Config(
                "topic / upgrade data source must be valid deployment labels".into(),
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
        let dead = DeadLetters::new(&cfg.state_dir, DEAD_LETTER_FILE, None);
        Ok(Self {
            cfg,
            sink,
            progress,
            chunks_sent: 0,
            dead,
            dead_loaded: false,
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

    fn dead_letter(
        &mut self,
        context: &str,
        pos: u64,
        reason: &str,
        raw: &[u8],
        report: &mut PublishReport,
    ) -> Result<(), PublishError> {
        if !self.dead_loaded {
            // Reported once per process, by the run that loads the file.
            report.dead_letter_malformed = self.dead.stats()?.malformed;
            self.dead_loaded = true;
        }
        // Counted either way: the earlier append's count was never saved
        // (its chunk's progress was lost, or we would not be here again).
        self.progress.dead_lettered_total += 1;
        report.dead_lettered += 1;
        if self.dead.contains(context, pos)? {
            return Ok(());
        }
        let raw = String::from_utf8_lossy(raw.get(..self.cfg.max_record_bytes).unwrap_or(raw));
        let mut line = serde_json::to_vec(&serde_json::json!({
            "source": context,
            "position": pos,
            "reason": reason,
            "record": raw,
            "at_ms": fsutil::now_ms(),
        }))
        .map_err(|e| PublishError::State(e.to_string()))?;
        line.push(b'\n');
        self.dead.append(context, pos, &line)?;
        Ok(())
    }

    /// Validate one input record and build what is sent. `Err` = reason.
    fn prepare(
        &self,
        raw: &[u8],
        partitions: u32,
        report: &mut PublishReport,
    ) -> Result<(i32, ProduceRecord), String> {
        let c = check_record(raw, &self.cfg.topic, &self.cfg.upgrade_data_source)?;
        let p = robodr_ocsf::partition_for(&c.robot_id, partitions)
            .ok_or_else(|| "no partition (zero partitions?)".to_string())?;
        if c.input_partition.is_some_and(|x| x != p) {
            report.partition_overridden += 1;
        }
        if c.topic_overridden {
            report.topic_overridden += 1;
        }
        if c.legacy_upgraded {
            report.legacy_upgraded += 1;
        }
        Ok((
            p as i32,
            ProduceRecord {
                key: Some(c.key.into_bytes()),
                value: Some(c.value.into_bytes()),
                headers: c
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
        let names = list_diode_batches(out)?;
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
        let Some(mut reader) =
            LineReader::open(out, name, self.cfg.max_record_bytes).map_err(|e| match e {
                OpenRecordsError::NotRegular(m) => PublishError::State(m),
                OpenRecordsError::Io(e) => PublishError::Io(e),
            })?
        else {
            // A batch with bundles only has no records.
            return Ok(());
        };
        let skip = self.progress.lines_committed(name);
        report.resumed_after += skip;
        let mut chunk: Vec<Item> = Vec::new();
        while let Some((line_no, raw)) = reader.next_line()? {
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
            let mut files = list_ready(&ready)?;
            if files.is_empty() {
                return Ok(());
            }
            files.truncate(self.cfg.chunk_records);
            let mut items = Vec::with_capacity(files.len());
            for (seq, name) in files {
                let raw = read_spool_item(&ready.join(&name), seq, self.cfg.max_record_bytes)?;
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
}
