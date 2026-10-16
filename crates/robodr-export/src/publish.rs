//! SOC side: publish `robot-edr.findings` records to Kafka from
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
//! acknowledged (`acks=all`), `<state>/progress.json` = `{batch,
//! lines_committed}` is replaced atomically. A finished batch gets a marker
//! `<state>/done/<batch>` (fsynced) and is skipped from then on. After a
//! crash, a batch resumes after its last committed line, so at most one
//! chunk (plus whatever a lost Produce response covered) is re-sent.
//! Consumers drop duplicates on `event-uid`.
//!
//! For a spool source the commit is the rename `ready/ → acked/` of the
//! chunk's files (dead-lettered ones go to `<spool>/rejected/`).

use crate::fsutil::{self, ReadError};
use crate::kafka::{Outcome, ProduceError, ProduceRecord, Producer};
use robodr_agentd::spool::SpoolRecord;
use robodr_ocsf::KAFKA_TOPIC;
use serde::{Deserialize, Serialize};
use std::fmt;
use std::fs;
use std::io::{self, BufRead, BufReader, Read};
use std::path::{Path, PathBuf};

const STATE_FORMAT: &str = "robodr-kafka-publish-state/1";
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
            topic: KAFKA_TOPIC.into(),
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
    /// Batch being published, if any.
    pub batch: Option<String>,
    /// Lines of `batch` acknowledged (1-based count from the top).
    pub lines_committed: u64,
    pub published_total: u64,
    pub dead_lettered_total: u64,
}

/// What one run did.
#[derive(Debug, Default, Clone, PartialEq, Eq, Serialize)]
pub struct PublishReport {
    pub published: u64,
    pub dead_lettered: u64,
    pub batches_done: Vec<String>,
    /// Records whose input partition differed from the recomputed one.
    pub partition_overridden: u64,
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
            Ok(b) => {
                let p: Progress = serde_json::from_slice(&b)
                    .map_err(|e| PublishError::State(format!("{}: {e}", path.display())))?;
                if p.format != STATE_FORMAT {
                    return Err(PublishError::State(format!(
                        "unknown format {:?}",
                        p.format
                    )));
                }
                p
            }
            Err(ReadError::Missing) => Progress {
                format: STATE_FORMAT.into(),
                batch: None,
                lines_committed: 0,
                published_total: 0,
                dead_lettered_total: 0,
            },
            Err(e) => return Err(PublishError::State(format!("{}: {e}", path.display()))),
        };
        Ok(Self {
            cfg,
            sink,
            progress,
            chunks_sent: 0,
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
        self.progress.dead_lettered_total += 1;
        report.dead_lettered += 1;
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
        if rec.topic != self.cfg.topic {
            return Err(format!(
                "topic {:?}, publishing to {:?}",
                rec.topic, self.cfg.topic
            ));
        }
        let env = robodr_ocsf::parse_and_validate(&rec.value).map_err(|errs| {
            let v: Vec<String> = errs.iter().take(3).map(|e| e.to_string()).collect();
            format!("invalid finding: {}", v.join("; "))
        })?;
        let want = robodr_ocsf::record(&env, Some(partitions))
            .map_err(|_| "finding cannot be emitted".to_string())?;
        if rec.key != want.key {
            return Err("key is not the finding id".into());
        }
        let same_headers = rec.headers.len() == want.headers.len()
            && rec
                .headers
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
        for name in names {
            let marker = self.cfg.state_dir.join(DONE_DIR).join(&name);
            if fs::symlink_metadata(&marker).is_ok() {
                continue;
            }
            self.publish_batch(out, &name, report)?;
            fsutil::atomic_write(&marker, b"")?;
            self.progress.batch = None;
            self.progress.lines_committed = 0;
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
        let skip = if self.progress.batch.as_deref() == Some(name) {
            self.progress.lines_committed
        } else {
            self.progress.batch = Some(name.to_string());
            self.progress.lines_committed = 0;
            0
        };
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
        self.progress.batch = Some(name.to_string());
        self.progress.lines_committed = chunk.last().map_or(0, |i| i.pos);
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
}
