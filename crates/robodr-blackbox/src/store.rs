//! The recorder: append-only segment files, crash recovery, rotation,
//! retention (cyclic / saturation) and the export cursor.
//!
//! # Directory layout
//!
//! ```text
//! <dir>/seg-0000000000000000.rbb   segment files (length-prefixed binary frames)
//! <dir>/seg-0000000000000001.rbb
//! <dir>/checkpoint.json            latest seal checkpoint (atomic replace)
//! <dir>/export-cursor.json         last exported position (atomic replace)
//! <dir>/quarantine/                bytes removed by crash recovery
//! ```
//!
//! # Why length-prefixed binary and not JSONL
//!
//! - The hash covers the stored bytes exactly; JSONL would either hash a
//!   re-serialisation (fragile: key order, float formatting, escaping) or need
//!   a second canonical form next to the stored one.
//! - A length prefix makes a torn write unambiguous (the frame ends early),
//!   while a JSON line cut at a structural boundary can still parse.
//! - Payloads are arbitrary bytes; no escaping, no newline hazards.
//! - Forensic readability is kept via [`crate::verify`] and
//!   [`crate::record::Record::payload_json`], which render records on demand.
//!
//! # Crash recovery
//!
//! On [`Recorder::open`] the last segment is scanned. If it ends in an
//! incomplete, zero-filled or otherwise invalid frame **and nothing valid
//! follows**, those bytes are copied to `quarantine/`, the file is truncated
//! to the last good frame, and a signed `Recovery` record (offset, length,
//! SHA-256 of the discarded bytes, quarantine file) is appended. Recovery is
//! never silent. If corruption is followed by valid frames, or any record in
//! the active segment fails its hash/linkage, `open` refuses
//! ([`Error::Corrupt`]) rather than destroy evidence; an operator must move
//! the directory aside (a fresh chain then starts).
//!
//! # Single writer
//!
//! A `Recorder` assumes it is the only writer of its directory. Wrap it in a
//! mutex inside one process; do not open the same directory twice.

use crate::crypto::{sha256, to_hex};
use crate::export::{Anchor, Bundle, Checkpoint};
use crate::record::{
    scan_frames, signing_message, ChainIdentity, DropReason, GenesisPayload, Hash, Record,
    RecordKind, RecoveryPayload, ResumePayload, SaturationClearedPayload, SaturationPayload,
    ScanItem, SealPayload, SealReason, SegmentDroppedPayload, SegmentStartPayload, TailKind,
    FIXED_FIELDS_LEN, FORMAT_VERSION, FRAME_HEADER_LEN, MAX_SIG_LEN, ZERO_HASH,
};
use crate::sign::{SignError, Signer};
use crate::time::Clock;
use robodr_events::{Deviation, RobotEvent, Severity};
use serde::Serialize;
use std::collections::VecDeque;
use std::fmt;
use std::fs::{self, File, OpenOptions};
use std::io::{self, Write};
use std::path::{Path, PathBuf};

/// Latest checkpoint file name.
pub const CHECKPOINT_FILE: &str = "checkpoint.json";
/// Export cursor file name.
pub const CURSOR_FILE: &str = "export-cursor.json";
/// Quarantine directory name.
pub const QUARANTINE_DIR: &str = "quarantine";

const SEG_PREFIX: &str = "seg-";
const SEG_SUFFIX: &str = ".rbb";
/// Allowance for the signature when estimating a frame's size.
const SIG_ESTIMATE: u64 = 72;

/// File name of segment `idx`.
pub fn segment_file_name(idx: u64) -> String {
    format!("{SEG_PREFIX}{idx:016}{SEG_SUFFIX}")
}

/// Inverse of [`segment_file_name`]; strict (exactly 16 digits).
pub fn parse_segment_file_name(name: &str) -> Option<u64> {
    let mid = name.strip_prefix(SEG_PREFIX)?.strip_suffix(SEG_SUFFIX)?;
    if mid.len() != 16 || !mid.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    mid.parse().ok()
}

/// Segment files in `dir`, sorted by index.
pub fn list_segments(dir: &Path) -> io::Result<Vec<(u64, PathBuf)>> {
    let mut v = Vec::new();
    for e in fs::read_dir(dir)? {
        let e = e?;
        if let Some(idx) = e.file_name().to_str().and_then(parse_segment_file_name) {
            if e.file_type()?.is_file() {
                v.push((idx, e.path()));
            }
        }
    }
    v.sort_by_key(|(i, _)| *i);
    Ok(v)
}

/// What to do when storage is full.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RetentionMode {
    /// Keep at most `max_segments`; the oldest is dropped (and the drop is
    /// recorded, with the anchor carried forward) when a new one starts.
    Cyclic { max_segments: u32 },
    /// Keep everything. Once `max_segments` are full, refuse non-critical
    /// records (recording a `Saturation` event) and keep accepting critical
    /// ones into `critical_reserve_segments` extra segments.
    Saturation {
        max_segments: u32,
        critical_reserve_segments: u32,
    },
}

/// When to `fsync` record data.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FsyncPolicy {
    /// After every record.
    Always,
    /// After every N records.
    Every(u32),
    /// Only at seals and rotations (plus critical records if
    /// `fsync_critical`).
    SealsOnly,
}

/// Recorder configuration.
#[derive(Debug, Clone)]
pub struct RecorderConfig {
    pub dir: PathBuf,
    pub device_id: String,
    /// This boot's id (e.g. `/proc/sys/kernel/random/boot_id`).
    pub boot_id: String,
    pub mode: RetentionMode,
    /// Rotate when the next record would make the segment exceed this.
    pub max_segment_bytes: u64,
    pub fsync: FsyncPolicy,
    /// Always fsync critical records regardless of `fsync`.
    pub fsync_critical: bool,
    /// Write a periodic seal after this many records (0 = never periodic).
    pub seal_every_records: u64,
    pub max_payload_bytes: usize,
    /// Deviations at or above this severity are critical.
    pub critical_severity: Severity,
}

impl RecorderConfig {
    /// Defaults: cyclic, 8 x 8 MiB, fsync every 16 records and every critical
    /// one, seal every 256 records, 64 KiB payloads, High+ deviations critical.
    pub fn new(
        dir: impl Into<PathBuf>,
        device_id: impl Into<String>,
        boot_id: impl Into<String>,
    ) -> Self {
        Self {
            dir: dir.into(),
            device_id: device_id.into(),
            boot_id: boot_id.into(),
            mode: RetentionMode::Cyclic { max_segments: 8 },
            max_segment_bytes: 8 * 1024 * 1024,
            fsync: FsyncPolicy::Every(16),
            fsync_critical: true,
            seal_every_records: 256,
            max_payload_bytes: 64 * 1024,
            critical_severity: Severity::High,
        }
    }

    fn validate(&self) -> Result<(), Error> {
        let ok_id = |s: &str| !s.is_empty() && s.len() <= 256 && !s.chars().any(char::is_control);
        if !ok_id(&self.device_id) {
            return Err(Error::Config(
                "device_id must be 1..=256 printable chars".into(),
            ));
        }
        if !ok_id(&self.boot_id) {
            return Err(Error::Config(
                "boot_id must be 1..=256 printable chars".into(),
            ));
        }
        if self.max_segment_bytes < 4096 {
            return Err(Error::Config("max_segment_bytes must be >= 4096".into()));
        }
        if self.max_payload_bytes == 0 || self.max_payload_bytes > 1024 * 1024 {
            return Err(Error::Config("max_payload_bytes must be 1..=1 MiB".into()));
        }
        match self.mode {
            RetentionMode::Cyclic { max_segments: 0 } => {
                Err(Error::Config("cyclic max_segments must be >= 1".into()))
            }
            RetentionMode::Saturation {
                max_segments,
                critical_reserve_segments,
            } if max_segments == 0 || critical_reserve_segments == 0 => Err(Error::Config(
                "saturation needs max_segments >= 1 and critical_reserve_segments >= 1".into(),
            )),
            _ => Ok(()),
        }
    }
}

/// Recorder errors.
#[derive(Debug)]
pub enum Error {
    Io(io::Error),
    Config(String),
    /// The existing log is corrupt in a way recovery must not "fix".
    Corrupt {
        segment: String,
        offset: u64,
        reason: String,
    },
    /// The log was written with a different key/algorithm.
    KeyMismatch {
        log_key_id: String,
        signer_key_id: String,
    },
    /// The log belongs to another device.
    DeviceMismatch {
        log_device_id: String,
        config_device_id: String,
    },
    PayloadTooLarge {
        len: usize,
        max: usize,
    },
    Sign(SignError),
    Encode(String),
    /// A previous write or fsync failed; reopen to recover.
    Poisoned,
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Error::Io(e) => write!(f, "I/O error: {e}"),
            Error::Config(m) => write!(f, "invalid configuration: {m}"),
            Error::Corrupt {
                segment,
                offset,
                reason,
            } => write!(f, "corrupt log {segment}@{offset}: {reason}"),
            Error::KeyMismatch {
                log_key_id,
                signer_key_id,
            } => write!(f, "log is keyed {log_key_id}, signer is {signer_key_id}"),
            Error::DeviceMismatch {
                log_device_id,
                config_device_id,
            } => write!(
                f,
                "log belongs to {log_device_id}, configured {config_device_id}"
            ),
            Error::PayloadTooLarge { len, max } => write!(f, "payload {len} B exceeds {max} B"),
            Error::Sign(e) => write!(f, "{e}"),
            Error::Encode(m) => write!(f, "encoding failed: {m}"),
            Error::Poisoned => write!(f, "recorder poisoned by an earlier I/O failure; reopen"),
        }
    }
}

impl std::error::Error for Error {}

impl From<io::Error> for Error {
    fn from(e: io::Error) -> Self {
        Error::Io(e)
    }
}

/// Result of an append.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AppendOutcome {
    Recorded { seq: u64, hash: Hash },
    Refused(Refusal),
}

/// Why an append was refused (saturation mode only).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Refusal {
    /// Saturated: non-critical records are not stored.
    Saturated,
    /// Even the critical reserve is full.
    Full,
}

/// Caller evidence kinds.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EntryKind {
    Event,
    Deviation,
    Note,
}

impl EntryKind {
    fn record_kind(self) -> RecordKind {
        match self {
            EntryKind::Event => RecordKind::Event,
            EntryKind::Deviation => RecordKind::Deviation,
            EntryKind::Note => RecordKind::Note,
        }
    }
}

struct Written {
    seq: u64,
    hash: Hash,
    sig: Vec<u8>,
}

/// Segment summary used for drops and pruning.
struct SegSummary {
    first_seq: Option<u64>,
    last_seq: Option<u64>,
    last_hash: Option<Hash>,
    records: u64,
}

fn summarize(path: &Path) -> io::Result<SegSummary> {
    let bytes = fs::read(path)?;
    let mut s = SegSummary {
        first_seq: None,
        last_seq: None,
        last_hash: None,
        records: 0,
    };
    for it in scan_frames(&bytes).items {
        if let ScanItem::Record(r) = it {
            s.first_seq.get_or_insert(r.record.seq);
            s.last_seq = Some(r.record.seq);
            s.last_hash = Some(r.record.hash);
            s.records += 1;
        }
    }
    Ok(s)
}

fn sync_dir(dir: &Path) -> io::Result<()> {
    File::open(dir)?.sync_all()
}

fn atomic_write(dir: &Path, name: &str, data: &[u8]) -> io::Result<()> {
    let tmp = dir.join(format!("{name}.tmp"));
    {
        let mut f = File::create(&tmp)?;
        f.write_all(data)?;
        f.sync_all()?;
    }
    fs::rename(&tmp, dir.join(name))?;
    sync_dir(dir)
}

fn to_json<T: Serialize>(v: &T) -> Result<Vec<u8>, Error> {
    serde_json::to_vec(v).map_err(|e| Error::Encode(e.to_string()))
}

fn identity_from(rec: &Record) -> Option<ChainIdentity> {
    match rec.kind {
        RecordKind::Genesis => rec.payload_json::<GenesisPayload>().map(|g| g.identity),
        RecordKind::SegmentStart => rec
            .payload_json::<SegmentStartPayload>()
            .map(|s| s.identity),
        _ => None,
    }
}

/// Good record prefix of a segment, plus `(cut offset, reason)` if it ends badly.
type Analyzed = (Vec<Record>, Option<(u64, String)>);

/// Validate the records of one segment for the recorder's own use: hashes and
/// in-segment linkage. Returns the good prefix and, if the segment ends badly,
/// the cut offset and a reason. Corruption followed by decodable frames is an
/// error.
fn analyze_segment(name: &str, bytes: &[u8]) -> Result<Analyzed, Error> {
    let scan = scan_frames(bytes);
    let mut good: Vec<Record> = Vec::new();
    let mut cut: Option<(u64, String)> = None;
    for it in scan.items {
        match it {
            ScanItem::Record(sr) => {
                if let Some((off, why)) = &cut {
                    return Err(Error::Corrupt {
                        segment: name.into(),
                        offset: *off,
                        reason: format!("{why}, followed by valid frames at {}", sr.offset),
                    });
                }
                let r = sr.record;
                let linked = good
                    .last()
                    .is_none_or(|p| p.seq.checked_add(1) == Some(r.seq) && r.prev_hash == p.hash);
                if r.compute_hash() != r.hash {
                    cut = Some((sr.offset, "record hash mismatch".into()));
                } else if !linked {
                    cut = Some((sr.offset, "record does not link to predecessor".into()));
                } else {
                    good.push(r);
                }
            }
            ScanItem::Malformed { offset, reason, .. } => {
                if cut.is_none() {
                    cut = Some((offset, reason));
                }
            }
        }
    }
    if cut.is_none() {
        if let Some(t) = scan.tail {
            let why = match t.kind {
                TailKind::Incomplete => "incomplete frame (torn write)",
                TailKind::Zeros => "zero-filled tail",
                TailKind::Garbage => "unparseable tail",
            };
            cut = Some((t.offset, why.into()));
        }
    }
    Ok((good, cut))
}

/// The black-box recorder.
pub struct Recorder {
    cfg: RecorderConfig,
    signer: Box<dyn Signer>,
    clock: Box<dyn Clock>,
    identity: ChainIdentity,
    chain_id: Hash,
    file: File,
    seg_index: u64,
    seg_len: u64,
    seg_records: u64,
    segments: VecDeque<u64>,
    head: Option<(u64, Hash)>,
    since_seal: u64,
    last_seal_seq: Option<u64>,
    unsynced: u32,
    saturated: bool,
    refused_noncritical: u64,
    refused_critical: u64,
    export_cursor: Option<Anchor>,
    last_checkpoint: Option<Checkpoint>,
    poisoned: bool,
}

impl fmt::Debug for Recorder {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Recorder")
            .field("dir", &self.cfg.dir)
            .field("chain_id", &to_hex(&self.chain_id))
            .field("segment", &self.seg_index)
            .field("head", &self.head.map(|(s, _)| s))
            .field("saturated", &self.saturated)
            .finish_non_exhaustive()
    }
}

impl Recorder {
    /// Open (or create) the log in `cfg.dir`.
    ///
    /// New directory: writes a genesis record binding device, boot and key.
    /// Existing directory: recovers a torn tail if needed (recorded), checks
    /// the key and device match, and appends a `Resume` record.
    pub fn open(
        cfg: RecorderConfig,
        signer: Box<dyn Signer>,
        clock: Box<dyn Clock>,
    ) -> Result<Self, Error> {
        cfg.validate()?;
        if signer.key_id().is_empty() || signer.algorithm().is_empty() {
            return Err(Error::Config(
                "signer must have a key id and algorithm".into(),
            ));
        }
        fs::create_dir_all(&cfg.dir)?;
        let segs = list_segments(&cfg.dir)?;
        if segs.is_empty() {
            let path = cfg.dir.join(segment_file_name(0));
            let file = OpenOptions::new()
                .create_new(true)
                .append(true)
                .open(&path)?;
            sync_dir(&cfg.dir)?;
            return Self::start_chain(cfg, signer, clock, file, None);
        }
        Self::resume(cfg, signer, clock, segs)
    }

    fn start_chain(
        cfg: RecorderConfig,
        signer: Box<dyn Signer>,
        clock: Box<dyn Clock>,
        file: File,
        recovery: Option<RecoveryPayload>,
    ) -> Result<Self, Error> {
        let identity = ChainIdentity {
            device_id: cfg.device_id.clone(),
            boot_id: cfg.boot_id.clone(),
            key_id: signer.key_id().to_string(),
            algorithm: signer.algorithm().to_string(),
            created_wall_ns: clock.now().wall_ns,
        };
        let chain_id = identity.chain_id();
        let mut r = Recorder {
            cfg,
            signer,
            clock,
            identity: identity.clone(),
            chain_id,
            file,
            seg_index: 0,
            seg_len: 0,
            seg_records: 0,
            segments: VecDeque::from([0]),
            head: None,
            since_seal: 0,
            last_seal_seq: None,
            unsynced: 0,
            saturated: false,
            refused_noncritical: 0,
            refused_critical: 0,
            export_cursor: None,
            last_checkpoint: None,
            poisoned: false,
        };
        let genesis = to_json(&GenesisPayload {
            identity,
            recorder_version: env!("CARGO_PKG_VERSION").to_string(),
            format_version: FORMAT_VERSION,
        })?;
        r.write_record(RecordKind::Genesis, genesis, true, true)?;
        if let Some(rec) = recovery {
            r.write_record(RecordKind::Recovery, to_json(&rec)?, true, true)?;
        }
        Ok(r)
    }

    fn quarantine(
        cfg: &RecorderConfig,
        seg_idx: u64,
        path: &Path,
        bytes: &[u8],
        cut: u64,
        reason: String,
    ) -> Result<RecoveryPayload, Error> {
        let discarded = &bytes[cut as usize..];
        let qdir = cfg.dir.join(QUARANTINE_DIR);
        fs::create_dir_all(&qdir)?;
        let base = format!("torn-seg{seg_idx:016}-off{cut}");
        let mut name = format!("{base}.bin");
        let mut n = 1;
        while qdir.join(&name).exists() {
            name = format!("{base}-{n}.bin");
            n += 1;
        }
        {
            let mut q = OpenOptions::new()
                .create_new(true)
                .write(true)
                .open(qdir.join(&name))?;
            q.write_all(discarded)?;
            q.sync_all()?;
        }
        sync_dir(&qdir)?;
        let f = OpenOptions::new().write(true).open(path)?;
        f.set_len(cut)?;
        f.sync_all()?;
        Ok(RecoveryPayload {
            segment_index: seg_idx,
            offset: cut,
            discarded_bytes: discarded.len() as u64,
            discarded_sha256: to_hex(&sha256(discarded)),
            reason,
            quarantine_file: Some(format!("{QUARANTINE_DIR}/{name}")),
        })
    }

    fn resume(
        cfg: RecorderConfig,
        signer: Box<dyn Signer>,
        clock: Box<dyn Clock>,
        segs: Vec<(u64, PathBuf)>,
    ) -> Result<Self, Error> {
        let (last_idx, last_path) = segs.last().cloned().expect("non-empty");
        let last_name = segment_file_name(last_idx);
        let bytes = fs::read(&last_path)?;
        let (good, cut) = analyze_segment(&last_name, &bytes)?;
        let recovery = match cut {
            Some((off, why)) => Some(Self::quarantine(
                &cfg, last_idx, &last_path, &bytes, off, why,
            )?),
            None => None,
        };

        // Head, identity and seal state.
        let (head_rec, identity, need_segment_start) = if let Some(last) = good.last() {
            let id = identity_from(&good[0]).ok_or_else(|| Error::Corrupt {
                segment: last_name.clone(),
                offset: 0,
                reason: "segment does not begin with genesis or segment-start".into(),
            })?;
            (last.clone(), id, false)
        } else if segs.len() == 1 {
            if last_idx != 0 {
                return Err(Error::Corrupt {
                    segment: last_name,
                    offset: 0,
                    reason: "only segment is empty and is not segment 0".into(),
                });
            }
            // Crash before genesis reached disk: start the chain here.
            let file = OpenOptions::new().append(true).open(&last_path)?;
            return Self::start_chain(cfg, signer, clock, file, recovery);
        } else {
            let (pidx, ppath) = &segs[segs.len() - 2];
            let pname = segment_file_name(*pidx);
            let pbytes = fs::read(ppath)?;
            let (pgood, pcut) = analyze_segment(&pname, &pbytes)?;
            if let Some((off, why)) = pcut {
                return Err(Error::Corrupt {
                    segment: pname,
                    offset: off,
                    reason: why,
                });
            }
            let last = pgood.last().ok_or_else(|| Error::Corrupt {
                segment: pname.clone(),
                offset: 0,
                reason: "previous segment is empty".into(),
            })?;
            let id = identity_from(&pgood[0]).ok_or_else(|| Error::Corrupt {
                segment: pname.clone(),
                offset: 0,
                reason: "segment does not begin with genesis or segment-start".into(),
            })?;
            (last.clone(), id, true)
        };
        if identity.key_id != signer.key_id() || identity.algorithm != signer.algorithm() {
            return Err(Error::KeyMismatch {
                log_key_id: format!("{}/{}", identity.algorithm, identity.key_id),
                signer_key_id: format!("{}/{}", signer.algorithm(), signer.key_id()),
            });
        }
        if identity.device_id != cfg.device_id {
            return Err(Error::DeviceMismatch {
                log_device_id: identity.device_id,
                config_device_id: cfg.device_id,
            });
        }
        let chain_id = identity.chain_id();
        if head_rec.chain_id != chain_id {
            return Err(Error::Corrupt {
                segment: last_name,
                offset: 0,
                reason: "records do not belong to the segment's chain".into(),
            });
        }
        let (since_seal, last_seal_seq) =
            match good.iter().rposition(|r| r.kind == RecordKind::Seal) {
                Some(i) => ((good.len() - 1 - i) as u64, Some(good[i].seq)),
                None => (good.len() as u64, None),
            };
        let file = OpenOptions::new().append(true).open(&last_path)?;
        let seg_len = file.metadata()?.len();
        let export_cursor = fs::read_to_string(cfg.dir.join(CURSOR_FILE))
            .ok()
            .and_then(|s| Anchor::from_json(&s))
            .filter(|a| a.chain_id == chain_id);
        let last_checkpoint = fs::read_to_string(cfg.dir.join(CHECKPOINT_FILE))
            .ok()
            .and_then(|s| Checkpoint::from_json(&s))
            .filter(|c| c.chain_id == chain_id);
        let saturated = matches!(cfg.mode, RetentionMode::Saturation { max_segments, .. }
            if segs.len() as u64 > u64::from(max_segments));
        let chain_boot_id = identity.boot_id.clone();
        let mut r = Recorder {
            cfg,
            signer,
            clock,
            identity,
            chain_id,
            file,
            seg_index: last_idx,
            seg_len,
            seg_records: good.len() as u64,
            segments: segs.iter().map(|(i, _)| *i).collect(),
            head: Some((head_rec.seq, head_rec.hash)),
            since_seal,
            last_seal_seq,
            unsynced: 0,
            saturated,
            refused_noncritical: 0,
            refused_critical: 0,
            export_cursor,
            last_checkpoint,
            poisoned: false,
        };
        if need_segment_start {
            r.write_segment_start()?;
        }
        let resume = ResumePayload {
            boot_id: r.cfg.boot_id.clone(),
            chain_boot_id,
            resumed_after_seq: head_rec.seq,
            recovered: recovery.is_some(),
        };
        r.write_record(RecordKind::Resume, to_json(&resume)?, true, true)?;
        if let Some(rec) = recovery {
            r.write_record(RecordKind::Recovery, to_json(&rec)?, true, true)?;
        }
        Ok(r)
    }

    fn write_record(
        &mut self,
        kind: RecordKind,
        payload: Vec<u8>,
        critical: bool,
        force_sync: bool,
    ) -> Result<Written, Error> {
        if self.poisoned {
            return Err(Error::Poisoned);
        }
        let (seq, prev_hash) = match self.head {
            None => (0, ZERO_HASH),
            Some((s, h)) => (
                s.checked_add(1)
                    .ok_or_else(|| Error::Config("sequence space exhausted".into()))?,
                h,
            ),
        };
        let mut rec = Record {
            chain_id: self.chain_id,
            seq,
            time: self.clock.now(),
            kind,
            critical,
            payload,
            prev_hash,
            hash: ZERO_HASH,
            sig: Vec::new(),
        };
        rec.hash = rec.compute_hash();
        let sig = self
            .signer
            .sign(&signing_message(&rec.hash))
            .map_err(Error::Sign)?;
        if sig.is_empty() || sig.len() > MAX_SIG_LEN {
            return Err(Error::Sign(SignError::new(format!(
                "signature length {} out of range",
                sig.len()
            ))));
        }
        rec.sig = sig;
        let frame = rec.encode_frame();
        if let Err(e) = self.file.write_all(&frame) {
            self.poisoned = true;
            return Err(e.into());
        }
        self.seg_len += frame.len() as u64;
        self.seg_records += 1;
        self.head = Some((seq, rec.hash));
        self.since_seal += 1;
        self.unsynced = self.unsynced.saturating_add(1);
        let sync = force_sync
            || (critical && self.cfg.fsync_critical)
            || match self.cfg.fsync {
                FsyncPolicy::Always => true,
                FsyncPolicy::Every(n) => self.unsynced >= n.max(1),
                FsyncPolicy::SealsOnly => false,
            };
        if sync {
            self.sync()?;
        }
        Ok(Written {
            seq,
            hash: rec.hash,
            sig: rec.sig,
        })
    }

    fn sync(&mut self) -> Result<(), Error> {
        if let Err(e) = self.file.sync_data() {
            self.poisoned = true;
            return Err(e.into());
        }
        self.unsynced = 0;
        Ok(())
    }

    fn write_segment_start(&mut self) -> Result<(), Error> {
        let p = to_json(&SegmentStartPayload {
            identity: self.identity.clone(),
            segment_index: self.seg_index,
            boot_id: self.cfg.boot_id.clone(),
        })?;
        self.write_record(RecordKind::SegmentStart, p, true, true)?;
        Ok(())
    }

    fn seal_with(&mut self, reason: SealReason) -> Result<Checkpoint, Error> {
        let p = to_json(&SealPayload {
            reason,
            segment_index: self.seg_index,
            records_since_last_seal: self.since_seal,
            prev_seal_seq: self.last_seal_seq,
        })?;
        let w = self.write_record(RecordKind::Seal, p, true, true)?;
        self.since_seal = 0;
        self.last_seal_seq = Some(w.seq);
        let cp = Checkpoint {
            chain_id: self.chain_id,
            seq: w.seq,
            hash: w.hash,
            key_id: self.identity.key_id.clone(),
            sig: w.sig,
        };
        atomic_write(&self.cfg.dir, CHECKPOINT_FILE, cp.to_json().as_bytes())?;
        self.last_checkpoint = Some(cp.clone());
        Ok(cp)
    }

    /// Write a seal now and return its checkpoint. Export the checkpoint off
    /// the unit (or into TPM NV) to make tail truncation detectable.
    pub fn seal(&mut self) -> Result<Checkpoint, Error> {
        self.seal_with(SealReason::Manual)
    }

    fn rotate(&mut self) -> Result<(), Error> {
        self.seal_with(SealReason::Rotation)?;
        if let Err(e) = self.file.sync_all() {
            self.poisoned = true;
            return Err(e.into());
        }
        let idx = self.seg_index + 1;
        let path = self.cfg.dir.join(segment_file_name(idx));
        let file = OpenOptions::new()
            .create_new(true)
            .append(true)
            .open(&path)?;
        sync_dir(&self.cfg.dir)?;
        self.file = file;
        self.seg_index = idx;
        self.seg_len = 0;
        self.seg_records = 0;
        self.segments.push_back(idx);
        self.write_segment_start()?;
        if let RetentionMode::Cyclic { max_segments } = self.cfg.mode {
            while self.segments.len() > max_segments as usize {
                self.drop_oldest(DropReason::Cyclic)?;
            }
        }
        Ok(())
    }

    /// Record the drop of the oldest segment, then delete it.
    fn drop_oldest(&mut self, reason: DropReason) -> Result<(), Error> {
        let Some(&idx) = self.segments.front() else {
            return Ok(());
        };
        if idx == self.seg_index {
            return Ok(());
        }
        let path = self.cfg.dir.join(segment_file_name(idx));
        let (summary, missing) = match summarize(&path) {
            Ok(s) => (s, false),
            Err(e) if e.kind() == io::ErrorKind::NotFound => (
                SegSummary {
                    first_seq: None,
                    last_seq: None,
                    last_hash: None,
                    records: 0,
                },
                true,
            ),
            Err(e) => return Err(e.into()),
        };
        let exported = match (&self.export_cursor, summary.last_seq) {
            (Some(c), Some(l)) => c.seq >= l,
            _ => false,
        };
        let p = to_json(&SegmentDroppedPayload {
            segment_index: idx,
            reason,
            first_seq: summary.first_seq,
            last_seq: summary.last_seq,
            last_hash: summary.last_hash.map(|h| to_hex(&h)),
            records: summary.records,
            exported,
            missing,
        })?;
        self.write_record(RecordKind::SegmentDropped, p, true, true)?;
        if !missing {
            match fs::remove_file(&path) {
                Ok(()) => {}
                Err(e) if e.kind() == io::ErrorKind::NotFound => {}
                Err(e) => return Err(e.into()),
            }
            sync_dir(&self.cfg.dir)?;
        }
        self.segments.pop_front();
        Ok(())
    }

    /// Append caller evidence. `critical` records survive saturation.
    pub fn append(
        &mut self,
        kind: EntryKind,
        payload: Vec<u8>,
        critical: bool,
    ) -> Result<AppendOutcome, Error> {
        if payload.len() > self.cfg.max_payload_bytes {
            return Err(Error::PayloadTooLarge {
                len: payload.len(),
                max: self.cfg.max_payload_bytes,
            });
        }
        if self.poisoned {
            return Err(Error::Poisoned);
        }
        if self.saturated && !critical {
            self.refused_noncritical += 1;
            return Ok(AppendOutcome::Refused(Refusal::Saturated));
        }
        let est = (FRAME_HEADER_LEN + FIXED_FIELDS_LEN + 32 + 2) as u64
            + payload.len() as u64
            + SIG_ESTIMATE;
        // A segment always takes at least one caller record after its header.
        let full = self.seg_len + est > self.cfg.max_segment_bytes && self.seg_records > 1;
        if full {
            match self.cfg.mode {
                RetentionMode::Cyclic { .. } => self.rotate()?,
                RetentionMode::Saturation {
                    max_segments,
                    critical_reserve_segments,
                } => {
                    let normal = max_segments as usize;
                    let total = normal + critical_reserve_segments as usize;
                    if self.segments.len() < normal {
                        self.rotate()?;
                    } else {
                        if !self.saturated {
                            self.saturated = true;
                            if self.segments.len() < total {
                                self.rotate()?;
                            }
                            let p = to_json(&SaturationPayload {
                                segments: self.segments.len() as u64,
                                max_segments: u64::from(max_segments),
                                reserve_segments: u64::from(critical_reserve_segments),
                            })?;
                            self.write_record(RecordKind::Saturation, p, true, true)?;
                            if !critical {
                                self.refused_noncritical += 1;
                                return Ok(AppendOutcome::Refused(Refusal::Saturated));
                            }
                        }
                        // Critical record in saturation.
                        let still_full = self.seg_len + est > self.cfg.max_segment_bytes;
                        if still_full {
                            if self.segments.len() < total {
                                self.rotate()?;
                            } else {
                                self.refused_critical += 1;
                                return Ok(AppendOutcome::Refused(Refusal::Full));
                            }
                        }
                    }
                }
            }
        }
        let w = self.write_record(kind.record_kind(), payload, critical, false)?;
        if self.cfg.seal_every_records > 0 && self.since_seal >= self.cfg.seal_every_records {
            self.seal_with(SealReason::Periodic)?;
        }
        Ok(AppendOutcome::Recorded {
            seq: w.seq,
            hash: w.hash,
        })
    }

    /// Record a robot event.
    pub fn append_event(
        &mut self,
        event: &RobotEvent,
        critical: bool,
    ) -> Result<AppendOutcome, Error> {
        self.append(EntryKind::Event, to_json(event)?, critical)
    }

    /// Record a deviation; critical iff `severity >= cfg.critical_severity`.
    pub fn append_deviation(&mut self, deviation: &Deviation) -> Result<AppendOutcome, Error> {
        let critical = deviation.severity >= self.cfg.critical_severity;
        self.append(EntryKind::Deviation, to_json(deviation)?, critical)
    }

    /// Record free-form JSON evidence.
    pub fn append_note<T: Serialize>(
        &mut self,
        note: &T,
        critical: bool,
    ) -> Result<AppendOutcome, Error> {
        self.append(EntryKind::Note, to_json(note)?, critical)
    }

    /// Bundle every record after the export cursor (at most `max_records`).
    /// Writes an `Export` seal first so an unlimited bundle ends on a seal.
    /// Returns `None` when nothing is pending. Does not move the cursor; call
    /// [`Recorder::mark_exported`] once the bundle has left the unit.
    pub fn export_pending(&mut self, max_records: Option<usize>) -> Result<Option<Bundle>, Error> {
        let Some((head_seq, _)) = self.head else {
            return Ok(None);
        };
        if self
            .export_cursor
            .as_ref()
            .is_some_and(|c| c.seq >= head_seq)
        {
            return Ok(None);
        }
        self.seal_with(SealReason::Export)?;
        let from = self.export_cursor.as_ref().map_or(0, |c| c.seq + 1);
        let limit = max_records.unwrap_or(usize::MAX);
        let mut frames = Vec::new();
        let mut count = 0usize;
        'outer: for &idx in &self.segments {
            let bytes = fs::read(self.cfg.dir.join(segment_file_name(idx)))?;
            for it in scan_frames(&bytes).items {
                if let ScanItem::Record(sr) = it {
                    if sr.record.seq >= from {
                        if count == limit {
                            break 'outer;
                        }
                        let (o, l) = (sr.offset as usize, sr.frame_len as usize);
                        frames.extend_from_slice(&bytes[o..o + l]);
                        count += 1;
                    }
                }
            }
        }
        if count == 0 {
            return Ok(None);
        }
        Ok(Some(Bundle {
            identity: self.identity.clone(),
            anchor: self.export_cursor.clone(),
            frames,
        }))
    }

    /// Advance the export cursor to the end of `bundle` (persisted atomically).
    pub fn mark_exported(&mut self, bundle: &Bundle) -> Result<(), Error> {
        if bundle.identity.chain_id() != self.chain_id {
            return Err(Error::Config("bundle belongs to another chain".into()));
        }
        let Some((seq, hash)) = bundle.last() else {
            return Ok(());
        };
        if self.export_cursor.as_ref().is_some_and(|c| c.seq >= seq) {
            return Ok(());
        }
        let a = Anchor {
            chain_id: self.chain_id,
            seq,
            hash,
        };
        atomic_write(&self.cfg.dir, CURSOR_FILE, a.to_json().as_bytes())?;
        self.export_cursor = Some(a);
        Ok(())
    }

    /// Delete closed segments whose records have all been exported (each
    /// deletion is recorded). Ends saturation if space is freed. Returns the
    /// number of segments deleted.
    pub fn prune_exported(&mut self) -> Result<usize, Error> {
        let Some(cursor) = self.export_cursor.clone() else {
            return Ok(0);
        };
        let mut pruned = 0;
        while let Some(&idx) = self.segments.front() {
            if idx == self.seg_index {
                break;
            }
            let s = summarize(&self.cfg.dir.join(segment_file_name(idx)))?;
            if s.last_seq.is_none_or(|l| l > cursor.seq) {
                break;
            }
            self.drop_oldest(DropReason::Exported)?;
            pruned += 1;
        }
        if let RetentionMode::Saturation { max_segments, .. } = self.cfg.mode {
            if self.saturated && self.segments.len() < max_segments as usize {
                self.saturated = false;
                let p = to_json(&SaturationClearedPayload {
                    refused_noncritical: self.refused_noncritical,
                    refused_critical: self.refused_critical,
                })?;
                self.write_record(RecordKind::SaturationCleared, p, true, true)?;
                self.refused_noncritical = 0;
                self.refused_critical = 0;
            }
        }
        Ok(pruned)
    }

    /// Seal (reason `Shutdown`) and flush. Returns the final checkpoint.
    pub fn close(mut self) -> Result<Checkpoint, Error> {
        let cp = self.seal_with(SealReason::Shutdown)?;
        self.file.sync_all()?;
        Ok(cp)
    }

    pub fn chain_id(&self) -> Hash {
        self.chain_id
    }
    pub fn identity(&self) -> &ChainIdentity {
        &self.identity
    }
    /// `(seq, hash)` of the last record written.
    pub fn head(&self) -> Option<(u64, Hash)> {
        self.head
    }
    /// Segment indices currently on disk (oldest first).
    pub fn segments(&self) -> Vec<u64> {
        self.segments.iter().copied().collect()
    }
    pub fn is_saturated(&self) -> bool {
        self.saturated
    }
    /// `(non-critical, critical)` records refused since saturation began.
    pub fn refused(&self) -> (u64, u64) {
        (self.refused_noncritical, self.refused_critical)
    }
    pub fn export_cursor(&self) -> Option<&Anchor> {
        self.export_cursor.as_ref()
    }
    pub fn last_checkpoint(&self) -> Option<&Checkpoint> {
        self.last_checkpoint.as_ref()
    }
    pub fn dir(&self) -> &Path {
        &self.cfg.dir
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn segment_names_round_trip_strictly() {
        assert_eq!(segment_file_name(7), "seg-0000000000000007.rbb");
        assert_eq!(parse_segment_file_name("seg-0000000000000007.rbb"), Some(7));
        assert_eq!(parse_segment_file_name("seg-7.rbb"), None);
        assert_eq!(parse_segment_file_name("seg-000000000000000x.rbb"), None);
        assert_eq!(
            parse_segment_file_name("seg-0000000000000007.rbb.tmp"),
            None
        );
        assert_eq!(parse_segment_file_name("checkpoint.json"), None);
    }

    #[test]
    fn config_validation() {
        let base = RecorderConfig::new("/nonexistent", "dev", "boot");
        assert!(base.validate().is_ok());
        let mut c = base.clone();
        c.device_id = String::new();
        assert!(c.validate().is_err());
        let mut c = base.clone();
        c.boot_id = "a\nb".into();
        assert!(c.validate().is_err());
        let mut c = base.clone();
        c.max_segment_bytes = 100;
        assert!(c.validate().is_err());
        let mut c = base.clone();
        c.max_payload_bytes = 0;
        assert!(c.validate().is_err());
        let mut c = base.clone();
        c.mode = RetentionMode::Cyclic { max_segments: 0 };
        assert!(c.validate().is_err());
        let mut c = base.clone();
        c.mode = RetentionMode::Saturation {
            max_segments: 2,
            critical_reserve_segments: 0,
        };
        assert!(c.validate().is_err());
    }
}
