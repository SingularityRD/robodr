//! The recorder: append-only segment files, crash recovery, rotation,
//! retention (cyclic / saturation) and the export cursor.
//!
//! # Directory layout
//!
//! ```text
//! <dir>/seg-0000000000000000.rbb   segment files (length-prefixed binary frames)
//! <dir>/seg-0000000000000001.rbb
//! <dir>/checkpoint.json            latest seal checkpoint (atomic replace)
//! <dir>/head.json                  high-water mark: newest durable record (atomic replace)
//! <dir>/recovery-pin.json          only between a recovery cut and its record
//! <dir>/export-cursor.json         last exported position (atomic replace)
//! <dir>/export-ack.json            last receiver acknowledgement (ack mode)
//! <dir>/recorder.lock              single-writer lock (flock)
//! <dir>/quarantine/                bytes removed by crash recovery, damaged
//!                                  closed segments, superseded state files
//! ```
//!
//! Files and directories the recorder creates are mode 0600 / 0700, created
//! exclusively (`O_CREAT|O_EXCL`) with `O_NOFOLLOW`; state files are replaced
//! through a randomly named temp file, so a symlink planted in the directory
//! is never followed.
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
//! # Opening an existing log
//!
//! Before chaining onto anything, [`Recorder::open`] authenticates it with
//! the recorder's own key ([`Signer::verify_own`] or the verifier passed to
//! [`Recorder::open_with_verifier`]): hash, linkage and signature of every
//! record in the active segment; every retained closed segment as described
//! under *Damaged closed segments*; and the drop records that anchor the
//! oldest one. It refuses ([`Error::Corrupt`]) to extend a forged head.
//! Segment indices that should be there but are not (a gap, or a missing
//! predecessor of the oldest segment with no recorded drop) are reported in
//! the `Resume` record and as `SegmentDropped { missing: true }` records.
//! The export cursor and checkpoint files are used only if they authenticate
//! and match the chain; rejected ones are listed in the `Resume` record.
//!
//! # Crash recovery
//!
//! On [`Recorder::open`] the last segment is scanned. Crash artefacts are
//! quarantined (bytes copied to `quarantine/` with their SHA-256 recorded,
//! the file truncated to the last good frame, a signed `Recovery` record
//! appended); recovery is never silent:
//!
//! - an **incomplete frame or zero-filled tail with nothing valid after
//!   it** (torn write): `Recovery`, severity medium, verifier warning;
//! - **zero-filled damage followed by valid frames** (a page whose
//!   write-back was lost while a later page reached disk, possible under
//!   `SealsOnly` / `Every(n)`): the whole suffix from the damage on is
//!   quarantined, authentic records in it are counted and their seqs are
//!   never reused (`discarded_seqs`, `skipped_seqs`). If no record after
//!   the damage was durably synced, a crash explains it: severity high,
//!   verifier warning. Otherwise (a seal, control record, critical record
//!   under `fsync_critical`, or any record under `Always` follows; fsync
//!   flushes every earlier page) it cannot be a crash: severity critical,
//!   verifier tamper (`DamageQuarantined`). Either way the recorder keeps
//!   recording instead of refusing to start. Before the cut, the highest
//!   authentic record in the suffix is pinned in [`RECOVERY_PIN_FILE`]
//!   (removed once the `Recovery` record is durable), so a crash between
//!   the cut and the record still proves the loss at the next open.
//!
//! Anything else in the **active** segment is [`Error::Corrupt`] and nothing
//! is touched: a *complete* frame whose hash or signature fails without zero
//! evidence (a crash cannot produce one: the hash is computed before the
//! frame is written), a record that does not link, non-zero bytes that do
//! not start a frame. The active segment holds the head the recorder would
//! chain onto, so it is never "repaired". An operator must then move the
//! directory aside (a fresh chain starts).
//!
//! # Damaged closed segments (never brick on failing storage)
//!
//! Every retained *closed* segment is verified at open: strict framing,
//! the hash and in-segment linkage of every record, the chain id of every
//! record, its first record (genesis / its own `SegmentStart`), a final
//! `Seal`, that its last record is the one the next segment chains onto,
//! and the signatures of its first and last record and of every
//! `SegmentDropped`, `Recovery` and `KeyRotation` record in it (all
//! signatures with [`RecorderConfig::verify_closed_signatures`]; off by
//! default because the in-crate Ed25519 verifies about 1 ms per record, so
//! a full 64 MiB store would take minutes).
//!
//! A closed segment that fails is **quarantined** and the recorder keeps
//! recording: its bytes are copied to `quarantine/damaged-seg<idx>.rbb`
//! (fsynced), a signed `Recovery` record with `quarantined_segment: true`,
//! the file's SHA-256, size, the count and authenticated seq range of the
//! frames in it, `crash_plausible: false` and a severity is written, and
//! only then is the original unlinked. The severity is `high` only for
//! framing or hash damage (what failing media produces) in a segment older
//! than the one the recorder chains onto; it is `critical` for
//! authentic-looking records that do not belong (foreign chain, bad
//! signature, broken cross-segment link), for a segment that parses
//! cleanly but holds no records or does not end with a seal (whole frames
//! removed on a frame boundary: not media, and no crash leaves a closed
//! segment unsealed), and for any damaged segment *newer* than the newest
//! intact one (the newest records vanishing while older ones survive is
//! not what failing media looks like). The verifier reports it as
//! `SegmentQuarantined` (tamper) and the missing seqs as `Deleted`.
//! Sequence numbers are never reused: a quarantined segment between
//! retained ones is bounded by its successor, and if it was the newest
//! closed segment (active segment still empty) numbering continues after
//! its highest authentic seq.
//!
//! **Stray segment files.** Let H be the newest segment file that holds
//! records. If H does not end with a seal, H is the live segment (the
//! recorder creates a successor only after sealing H and fsyncing it), and
//! every file above it (empty, zeros or garbage) was not written by the
//! recorder: it is quarantined the same way, `critical`, with a reason
//! naming it a stray file. Without this, one empty `seg-<live+1>` file
//! would make the live segment look like a closed segment without a seal.
//! At most 64 stray files are quarantined; more refuse open.
//!
//! **Bounded work.** Frames in a damaged segment and frames after a hole in
//! the active segment are untrusted (anyone with write access can append
//! hash-valid forgeries): their signatures are checked for at most 32
//! frames from each end. A forged frame among those checked makes a hole
//! in the active segment not crash-plausible.
//!
//! Open still refuses when the head itself cannot be trusted: the active
//! segment is corrupt (above), it is empty and no closed segment is intact,
//! a signature fails under a key that verifies nothing in the log (a
//! missing `previous_keys`, not damage), or authentic state contradicts
//! the log (below).
//!
//! # Truncation evidence (never reuse a sequence number)
//!
//! An authentic `checkpoint.json` or `export-cursor.json` whose seq is
//! *beyond* the head proves that the tail was cut (whole frames removed
//! leave a valid but shorter chain). The recorder then keeps working but:
//! copies the state file to `quarantine/state-*.json` before anything can
//! replace it, continues numbering *after* the highest seq that state
//! names (the first record written, normally the `Resume`, declares the
//! skipped range in `skipped_seqs`), and writes a critical
//! `TruncationDetected` record. The verifier reports it as tamper. An
//! authentic checkpoint that names a seq the log has, with another hash, can
//! only come from a key holder rewriting history: open refuses with
//! [`Error::Untrusted`] and touches nothing.
//!
//! Quarantined evidence "explains" a position beyond the head (no
//! truncation is claimed) only when the damage is something a crash or
//! failing media produces: a crash-plausible hole in the active segment,
//! or a `high` quarantine. A `critical` quarantine explains nothing: the
//! state files beyond the head still raise `TruncationDetected`, and the
//! authentic records beyond the head that the quarantine removed are
//! listed as evidence in it too (`file` = the segment, `preserved_as` =
//! its quarantine copy). The same holds for a hole in the active segment
//! that is not crash-plausible (a mark beyond the head also makes a hole
//! not crash-plausible: it names a synced record that is gone).
//! [`Recorder::open_incidents`] summarises what an open found
//! (quarantines with their severity, truncation) for the host to report.
//!
//! # High-water mark (`head.json`) and external anchors
//!
//! Checkpoints are written only at seals, so a tail cut after the newest
//! seal used to leave no trace. The recorder therefore also keeps a
//! lightweight high-water mark: `head.json`, a [`Checkpoint`] of the newest
//! record (its own signature makes it self-authenticating, no extra signing
//! key operation). It is rewritten atomically every
//! [`RecorderConfig::head_mark_every_records`] records (default 16) or when
//! [`RecorderConfig::head_mark_interval_ns`] (default 1 s, measured on the
//! records' monotonic clock) has passed at the next append, at every seal,
//! at open and at close, and on demand with [`Recorder::mark_head`]. The
//! segment is fsynced *before* the mark is written, so a mark never names a
//! record a crash can take away: a mark beyond the head at open is
//! truncation (`TruncationDetected`, critical, numbering continues after the
//! mark), a mark naming a seq the log holds with another hash refuses open
//! ([`Error::Untrusted`]). The mark also proves the records up to it were
//! synced, so a zero-filled hole before it is not crash-plausible.
//!
//! An optional [`HeadAnchor`] ([`RecorderConfig::head_anchor`]) receives
//! every mark too, e.g. a TPM NV monotonic counter or a remote receiver, and
//! is consulted at open the same way. **A deployment that must detect an
//! attacker with write access to the unit needs one** (TPM NV counter or
//! remote receiver); none ships in this crate. [`FileHeadAnchor`] is a
//! simple file-backed implementation, only as strong as the storage its
//! file lives on (useless on the log's own filesystem). It survives an attacker who rewrites
//! or deletes the whole directory, which `head.json` does not: a store with
//! no segments while the anchor holds a mark starts a new chain that
//! declares the gap (`Resume` + `TruncationDetected`), so a wiped store is
//! reported, not silently restarted. Anchor failures never stop recording;
//! they are counted ([`Recorder::anchor_failures`]).
//!
//! Remaining window: records written after the newest mark and destroyed
//! with the tail (by an attacker with write access, or by losing unsynced
//! data in a crash, which is not tampering) leave no trace locally; their
//! seqs may be reused. That is at most `head_mark_every_records` records or
//! `head_mark_interval_ns` of recording (plus records written after the
//! last append while the recorder idles: call [`Recorder::mark_head`] from a
//! timer to bound it in time). An attacker who can rewrite `head.json` can
//! roll it back to an older authentic mark (they cannot forge one); only an
//! external anchor closes that. Only an off-unit copy of lost content could
//! then show a `Fork`.
//!
//! # Saturation counters
//!
//! Refused-append counters are written into every `Seal` and `Resume` and
//! restored at open, so `SaturationCleared` reports totals across restarts.
//! Refusals after the last such record are lost in a crash (a clean
//! [`Recorder::close`] seals them).
//!
//! # Key rotation
//!
//! [`Recorder::rotate_key`] writes a `KeyRotation` record signed by the old
//! key, then signs everything after with the new one; the chain id (which
//! binds the chain's *first* key) does not change, later `SegmentStart`s
//! name the current key. At open the log's current key must be the
//! signer's; records signed by older keys are authenticated with
//! `previous_keys` ([`Recorder::open_with_keys`]).
//!
//! # Single writer
//!
//! [`Recorder::open`] takes `flock(LOCK_EX | LOCK_NB)` on `recorder.lock`
//! (unix) and fails with [`Error::Locked`] if another recorder (in this or
//! another process) holds it. The lock is released when the recorder is
//! dropped or the process dies. Within one process, wrap the recorder in a
//! mutex. On non-unix targets there is no lock.

use crate::crypto::{sha256, to_hex};
use crate::export::{cursor_signing_message, Ack, Anchor, Bundle, Checkpoint, SignedCursor};
use crate::record::{
    scan_frames, signing_message, ChainIdentity, DropReason, GenesisPayload, Hash, KeyRef,
    KeyRotationPayload, Record, RecordKind, RecoveryPayload, ResumePayload,
    SaturationClearedPayload, SaturationPayload, ScanItem, SealPayload, SealReason,
    SegmentDroppedPayload, SegmentStartPayload, StateEvidence, TailKind, TruncationPayload,
    FIXED_FIELDS_LEN, FORMAT_VERSION, FRAME_HEADER_LEN, MAX_SIG_LEN, ZERO_HASH,
};
use crate::sign::{SignError, Signer, Verifier};
use crate::time::Clock;
use robodr_events::{Deviation, RobotEvent, Severity};
use serde::Serialize;
use std::collections::{HashSet, VecDeque};
use std::fmt;
use std::fs::{self, File, OpenOptions};
use std::io::{self, Write};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};

/// A position held by a [`HeadAnchor`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AnchoredHead {
    /// Chain the position belongs to, if the anchor stores it (a bare
    /// monotonic counter does not).
    pub chain_id: Option<Hash>,
    /// Highest sequence number the anchor has seen.
    pub seq: u64,
    /// Hash of record `seq`, if the anchor stores it.
    pub hash: Option<Hash>,
}

/// An external, tamper-resistant home for the high-water mark: e.g. a TPM
/// NV monotonic counter (holds only `seq`) or a remote receiver (can hold
/// the whole signed mark). The anchor is a *trusted* input: what
/// [`HeadAnchor::current`] returns is believed without a signature.
///
/// Implementations use interior mutability; calls come from the recorder's
/// thread, at most once per mark. Neither call may block for long (they run
/// inside `append`).
pub trait HeadAnchor: Send + Sync + fmt::Debug {
    /// Durably record that the log has reached `mark` (a [`Checkpoint`] of
    /// its newest record, already fsynced). Called with increasing `seq`
    /// only. An error is counted, never fatal; the next mark retries.
    fn advance(&self, mark: &Checkpoint) -> Result<(), String>;
    /// The highest mark held, if any. Read once at open.
    fn current(&self) -> Result<Option<AnchoredHead>, String>;
}

/// In-memory [`HeadAnchor`]: a reference implementation for tests and
/// simulation (it does not survive the process). [`MemoryHeadAnchor::counter`]
/// behaves like a monotonic counter: it stores only `seq` and refuses to go
/// down.
#[derive(Debug, Default)]
pub struct MemoryHeadAnchor {
    held: Mutex<Option<AnchoredHead>>,
    counter_only: bool,
}

impl MemoryHeadAnchor {
    /// Stores the full mark (chain, seq, hash).
    pub fn new() -> Self {
        Self::default()
    }
    /// Stores only the sequence number, never decreasing.
    pub fn counter() -> Self {
        Self {
            held: Mutex::new(None),
            counter_only: true,
        }
    }
    /// What the anchor holds now.
    pub fn get(&self) -> Option<AnchoredHead> {
        self.held.lock().map(|g| g.clone()).unwrap_or(None)
    }
    /// Overwrite what the anchor holds (tests: simulate a remote copy).
    pub fn set(&self, v: Option<AnchoredHead>) {
        if let Ok(mut g) = self.held.lock() {
            *g = v;
        }
    }
}

impl HeadAnchor for MemoryHeadAnchor {
    fn advance(&self, mark: &Checkpoint) -> Result<(), String> {
        let mut g = self
            .held
            .lock()
            .map_err(|_| "anchor lock poisoned".to_string())?;
        if self.counter_only {
            if g.as_ref().is_some_and(|h| h.seq > mark.seq) {
                return Err("monotonic counter cannot decrease".into());
            }
            *g = Some(AnchoredHead {
                chain_id: None,
                seq: mark.seq,
                hash: None,
            });
        } else {
            *g = Some(AnchoredHead {
                chain_id: Some(mark.chain_id),
                seq: mark.seq,
                hash: Some(mark.hash),
            });
        }
        Ok(())
    }
    fn current(&self) -> Result<Option<AnchoredHead>, String> {
        Ok(self.get())
    }
}

/// A [`HeadAnchor`] kept in a single file (`{"chain_id","seq","hash"}`,
/// replaced atomically, never decreasing).
///
/// **Limits, read before relying on it.** It is exactly as tamper-resistant
/// as the place the file lives: on the same filesystem as the log, an
/// attacker who can edit the log can edit or delete it too, and it adds
/// nothing over `head.json`. It is useful only when the path is on storage
/// the log's attacker cannot write (a separately mounted, write-restricted
/// partition, a network share replicated off the unit, a removable medium
/// collected after a mission). A deployment that must survive an attacker
/// with write access to the unit needs a TPM NV monotonic counter or a
/// remote receiver behind [`HeadAnchor`]; this type is the simple building
/// block, not that guarantee.
///
/// The file is trusted input (unsigned): a writer to it can make the next
/// open report a false truncation (never hide one that `head.json` shows).
/// A file that exists but cannot be parsed is an anchor failure (counted,
/// noted in the `Resume` record), not "no anchor".
#[derive(Debug)]
pub struct FileHeadAnchor {
    dir: PathBuf,
    name: String,
    lock: Mutex<()>,
}

#[derive(Serialize, serde::Deserialize)]
struct FileAnchorJson {
    chain_id: String,
    seq: u64,
    hash: String,
}

impl FileHeadAnchor {
    /// Anchor in `path` (absolute; its directory must exist). The file is
    /// created at the first mark.
    pub fn new(path: impl Into<PathBuf>) -> Result<Self, Error> {
        let path = path.into();
        if !path.is_absolute() {
            return Err(Error::Config(format!(
                "head anchor file {} must be an absolute path",
                path.display()
            )));
        }
        let (Some(dir), Some(name)) = (path.parent(), path.file_name()) else {
            return Err(Error::Config(format!(
                "head anchor file {} has no directory or file name",
                path.display()
            )));
        };
        let name = name.to_str().ok_or_else(|| {
            Error::Config(format!(
                "head anchor file {} is not valid UTF-8",
                path.display()
            ))
        })?;
        Ok(Self {
            dir: dir.to_path_buf(),
            name: name.to_string(),
            lock: Mutex::new(()),
        })
    }

    /// The anchor file's path.
    pub fn path(&self) -> PathBuf {
        self.dir.join(&self.name)
    }

    fn read(&self) -> Result<Option<AnchoredHead>, String> {
        let Some(s) = read_state(&self.dir, &self.name).map_err(|e| e.to_string())? else {
            return Ok(None);
        };
        let j: FileAnchorJson = serde_json::from_str(&s)
            .map_err(|_| format!("{}: unparseable anchor file", self.path().display()))?;
        let bad = || format!("{}: malformed hash in anchor file", self.path().display());
        Ok(Some(AnchoredHead {
            chain_id: Some(crate::crypto::hash_from_hex(&j.chain_id).ok_or_else(bad)?),
            seq: j.seq,
            hash: Some(crate::crypto::hash_from_hex(&j.hash).ok_or_else(bad)?),
        }))
    }
}

impl HeadAnchor for FileHeadAnchor {
    fn advance(&self, mark: &Checkpoint) -> Result<(), String> {
        let _g = self
            .lock
            .lock()
            .map_err(|_| "anchor lock poisoned".to_string())?;
        // Never go down (a read failure must not let it either).
        if let Some(h) = self.read()? {
            if h.seq > mark.seq {
                return Err(format!(
                    "anchor holds seq {} > {}: refusing to decrease it",
                    h.seq, mark.seq
                ));
            }
        }
        let j = FileAnchorJson {
            chain_id: to_hex(&mark.chain_id),
            seq: mark.seq,
            hash: to_hex(&mark.hash),
        };
        let data = serde_json::to_vec(&j).map_err(|e| e.to_string())?;
        atomic_write(&self.dir, &self.name, &data)
            .map_err(|e| format!("{}: {e}", self.path().display()))
    }
    fn current(&self) -> Result<Option<AnchoredHead>, String> {
        let _g = self
            .lock
            .lock()
            .map_err(|_| "anchor lock poisoned".to_string())?;
        self.read()
    }
}

// ---------------------------------------------------------------------------
// Fault injection (unit tests only): simulate the process dying at a step.
// ---------------------------------------------------------------------------

#[cfg(test)]
pub(crate) mod fault {
    use std::cell::{Cell, RefCell};
    use std::io;

    thread_local! {
        static ARMED: RefCell<Option<(String, u32)>> = const { RefCell::new(None) };
        static FIRED: Cell<bool> = const { Cell::new(false) };
    }

    /// Fail the `nth` (1-based) time `point` is reached on this thread.
    pub fn arm(point: &str, nth: u32) {
        ARMED.with(|a| *a.borrow_mut() = Some((point.to_string(), nth.max(1))));
        FIRED.with(|f| f.set(false));
    }
    pub fn disarm() {
        ARMED.with(|a| *a.borrow_mut() = None);
    }
    pub fn fired() -> bool {
        FIRED.with(|f| f.get())
    }
    pub fn hit(point: &str) -> io::Result<()> {
        ARMED.with(|a| {
            let mut a = a.borrow_mut();
            if let Some((p, n)) = a.as_mut() {
                if p == point {
                    if *n <= 1 {
                        *a = None;
                        FIRED.with(|f| f.set(true));
                        return Err(io::Error::other(format!("injected crash at {point}")));
                    }
                    *n -= 1;
                }
            }
            Ok(())
        })
    }
}

/// A crash point. In unit tests an armed point fails here (the recorder is
/// then dropped: no further disk effects, like a process killed at that
/// step); otherwise a no-op.
#[inline]
fn fault(point: &str) -> io::Result<()> {
    #[cfg(test)]
    {
        fault::hit(point)
    }
    #[cfg(not(test))]
    {
        let _ = point;
        Ok(())
    }
}

/// Latest checkpoint file name.
pub const CHECKPOINT_FILE: &str = "checkpoint.json";
/// Export cursor file name.
pub const CURSOR_FILE: &str = "export-cursor.json";
/// Receiver acknowledgement file name (ack mode).
pub const ACK_FILE: &str = "export-ack.json";
/// Single-writer lock file name.
pub const LOCK_FILE: &str = "recorder.lock";
/// Quarantine directory name.
pub const QUARANTINE_DIR: &str = "quarantine";
/// High-water mark file name (a [`Checkpoint`] of the newest durable record).
pub const HEAD_FILE: &str = "head.json";
/// Pin written by crash recovery right before it cuts authentic records out
/// of the active segment (a [`Checkpoint`] of the highest one), removed once
/// the `Recovery` record is durable. If a crash falls in between, it is the
/// evidence (and the seq floor) for the next open. Unlike [`HEAD_FILE`] it
/// proves nothing about fsync order.
pub const RECOVERY_PIN_FILE: &str = "recovery-pin.json";
/// Name of the external anchor in [`StateEvidence::file`] and rejection notes.
pub const EXTERNAL_ANCHOR: &str = "external-anchor";

const SEG_PREFIX: &str = "seg-";
const SEG_SUFFIX: &str = ".rbb";
/// Allowance for the signature when estimating a frame's size (covers
/// HMAC-SHA256, 32 bytes, and Ed25519, 64 bytes).
const SIG_ESTIMATE: u64 = 72;
/// Upper bound of a [`SealPayload`]'s JSON (every counter at `u64::MAX` and
/// the longest reason is under 200 bytes; tested).
const SEAL_PAYLOAD_MAX: u64 = 256;
/// Estimated size of a frame carrying `payload_len` payload bytes.
const fn frame_estimate(payload_len: u64) -> u64 {
    (FRAME_HEADER_LEN + FIXED_FIELDS_LEN + 32 + 2) as u64 + payload_len + SIG_ESTIMATE
}
/// Room kept free in a segment for the seals that may follow the last
/// caller record into it: a periodic seal right after that record, then the
/// rotation (or shutdown) seal. Without it a full segment ended
/// `max_segment_bytes` + one seal frame long.
const SEAL_RESERVE: u64 = 2 * frame_estimate(SEAL_PAYLOAD_MAX);

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
    /// Rewrite the `head.json` high-water mark after this many records
    /// (0 = only at seals, open and close). Each mark costs an fsync of the
    /// segment plus an atomic file replace.
    pub head_mark_every_records: u64,
    /// Also rewrite it at the first append once this much monotonic time
    /// (ns) has passed since the last mark (0 = no time trigger).
    pub head_mark_interval_ns: u64,
    /// Optional external anchor that receives every mark and is checked at
    /// open (see the module docs).
    pub head_anchor: Option<Arc<dyn HeadAnchor>>,
    /// Verify the signature of every record of every closed segment at open
    /// (default: only the first and last record and the control records the
    /// recorder relies on; hashes and links are always checked in full).
    pub verify_closed_signatures: bool,
}

impl RecorderConfig {
    /// Defaults: cyclic, 8 x 8 MiB, fsync every 16 records and every critical
    /// one, seal every 256 records, 64 KiB payloads, High+ deviations
    /// critical, high-water mark every 16 records or 1 s, no external anchor,
    /// closed segments' signatures sampled (first, last, control records).
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
            head_mark_every_records: 16,
            head_mark_interval_ns: 1_000_000_000,
            head_anchor: None,
            verify_closed_signatures: false,
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
    /// Another recorder holds the directory's single-writer lock.
    Locked {
        path: PathBuf,
    },
    /// An export cursor, bundle position or receiver ack failed
    /// authentication or does not match the chain.
    Untrusted(String),
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
            Error::Locked { path } => write!(
                f,
                "log directory is locked by another recorder ({})",
                path.display()
            ),
            Error::Untrusted(m) => write!(f, "untrusted export state: {m}"),
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

/// One retained segment as the recorder knows it. `start` is the `(seq,
/// prev_hash)` of the segment's first record, which the recorder either wrote
/// itself or authenticated (hash + signature + kind + index) at open. The
/// anchor of segment `i` (its last record) is `start` of segment `i + 1`:
/// `(seq - 1, prev_hash)`. The bytes of segment `i` itself are never trusted
/// for that.
#[derive(Debug, Clone, Copy)]
struct SegInfo {
    index: u64,
    start: Option<(u64, Hash)>,
}

// ---------------------------------------------------------------------------
// File-system hardening
// ---------------------------------------------------------------------------

#[cfg(unix)]
pub(crate) mod sys {
    //! The two libc facts the recorder needs, declared by hand (no libc crate
    //! offline). `flock` is linked by std on every unix target.

    #[cfg(any(target_os = "linux", target_os = "android"))]
    pub const O_NOFOLLOW: i32 = if cfg!(any(
        target_arch = "aarch64",
        target_arch = "arm",
        target_arch = "powerpc",
        target_arch = "powerpc64"
    )) {
        0o100000
    } else {
        0o400000
    };
    #[cfg(any(
        target_os = "macos",
        target_os = "ios",
        target_os = "freebsd",
        target_os = "openbsd",
        target_os = "netbsd",
        target_os = "dragonfly"
    ))]
    pub const O_NOFOLLOW: i32 = 0x100;
    /// Unknown unix: rely on `O_CREAT|O_EXCL` (which never follows a final
    /// symlink) for creation; existing files are opened without the flag.
    #[cfg(not(any(
        target_os = "linux",
        target_os = "android",
        target_os = "macos",
        target_os = "ios",
        target_os = "freebsd",
        target_os = "openbsd",
        target_os = "netbsd",
        target_os = "dragonfly"
    )))]
    pub const O_NOFOLLOW: i32 = 0;

    pub const LOCK_EX: i32 = 2;
    pub const LOCK_NB: i32 = 4;

    extern "C" {
        pub fn flock(fd: i32, operation: i32) -> i32;
    }
}

/// Create `dir` (and parents) with mode 0700. An existing directory keeps
/// its mode: tightening it is the integrator's decision.
fn create_dir_private(dir: &Path) -> io::Result<()> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::DirBuilderExt;
        fs::DirBuilder::new()
            .recursive(true)
            .mode(0o700)
            .create(dir)
    }
    #[cfg(not(unix))]
    {
        fs::create_dir_all(dir)
    }
}

/// Mode 0600 for new files, and never follow a symlink at the final path
/// component.
pub(crate) fn private(o: &mut OpenOptions) -> &mut OpenOptions {
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        o.mode(0o600).custom_flags(sys::O_NOFOLLOW);
    }
    o
}

/// Create a new file exclusively (fails if anything, including a dangling
/// symlink, exists at `path`).
fn create_new_private(path: &Path, append: bool) -> io::Result<File> {
    let mut o = OpenOptions::new();
    o.create_new(true);
    if append {
        o.append(true);
    } else {
        o.write(true);
    }
    private(&mut o).open(path)
}

/// Open an existing segment for appending; refuses symlinks.
fn open_append(path: &Path) -> io::Result<File> {
    let mut o = OpenOptions::new();
    o.append(true);
    private(&mut o).open(path)
}

/// An unpredictable temp-file name next to `name` (kernel randomness mixed
/// with pid, time and a counter; still unique if `/dev/urandom` is absent).
fn tmp_name(name: &str) -> String {
    use std::io::Read;
    use std::sync::atomic::{AtomicU64, Ordering};
    static COUNTER: AtomicU64 = AtomicU64::new(0);
    let mut seed = Vec::with_capacity(48);
    let mut r = [0u8; 16];
    if File::open("/dev/urandom")
        .and_then(|mut f| f.read_exact(&mut r))
        .is_ok()
    {
        seed.extend_from_slice(&r);
    }
    seed.extend_from_slice(&std::process::id().to_be_bytes());
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| d.as_nanos());
    seed.extend_from_slice(&nanos.to_be_bytes());
    seed.extend_from_slice(&COUNTER.fetch_add(1, Ordering::Relaxed).to_be_bytes());
    format!(".{name}.{}.tmp", to_hex(&sha256(&seed)[..12]))
}

fn sync_dir(dir: &Path) -> io::Result<()> {
    File::open(dir)?.sync_all()
}

/// Write `data` to `dir/name` atomically: exclusive create of a random temp
/// file (mode 0600, `O_NOFOLLOW`), fsync, rename, fsync the directory. A
/// planted symlink at any predictable path is never followed.
fn atomic_write(dir: &Path, name: &str, data: &[u8]) -> io::Result<()> {
    let tmp = dir.join(tmp_name(name));
    let res = (|| {
        let mut f = create_new_private(&tmp, false)?;
        f.write_all(data)?;
        f.sync_all()?;
        fault("atomic.after_tmp")?;
        fs::rename(&tmp, dir.join(name))
    })();
    if res.is_err() {
        // A process killed here leaves the temp file behind (removed at the
        // next open); an injected crash must leave it too.
        #[cfg(test)]
        let killed = fault::fired();
        #[cfg(not(test))]
        let killed = false;
        if !killed {
            let _ = fs::remove_file(&tmp);
        }
    }
    res?;
    fault("atomic.after_rename")?;
    sync_dir(dir)
}

/// Remove temp files a crash left behind in [`atomic_write`] (names
/// `.<state file>.<hex>.tmp`). Called with the lock held. Best effort.
fn remove_stale_tmp(dir: &Path) {
    let Ok(rd) = fs::read_dir(dir) else { return };
    for e in rd.flatten() {
        let name = e.file_name();
        let Some(n) = name.to_str() else { continue };
        let ours = [
            CHECKPOINT_FILE,
            CURSOR_FILE,
            ACK_FILE,
            HEAD_FILE,
            RECOVERY_PIN_FILE,
        ]
        .iter()
        .any(|f| n.starts_with(&format!(".{f}.")));
        if ours && n.ends_with(".tmp") {
            let _ = fs::remove_file(e.path());
        }
    }
}

/// Take the single-writer lock on `dir` (`flock(LOCK_EX | LOCK_NB)` on
/// [`LOCK_FILE`]). The lock lives as long as the returned file, i.e. as long
/// as the [`Recorder`]; the kernel drops it if the process dies.
fn lock_dir(dir: &Path) -> Result<File, Error> {
    let path = dir.join(LOCK_FILE);
    let mut o = OpenOptions::new();
    o.read(true).write(true).create(true);
    let f = private(&mut o).open(&path)?;
    #[cfg(unix)]
    {
        use std::os::unix::io::AsRawFd;
        // SAFETY: `flock` only reads its two integer arguments; the fd is
        // owned by `f`, which is alive for the duration of the call.
        let rc = unsafe { sys::flock(f.as_raw_fd(), sys::LOCK_EX | sys::LOCK_NB) };
        if rc != 0 {
            let e = io::Error::last_os_error();
            return Err(if e.kind() == io::ErrorKind::WouldBlock {
                Error::Locked { path }
            } else {
                Error::Io(e)
            });
        }
    }
    Ok(f)
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

/// The identity a segment's first record declares, after checking that the
/// record is the right kind for segment `idx` (genesis at seq 0 for segment
/// 0, a `SegmentStart` naming `idx` otherwise).
fn segment_identity(name: &str, idx: u64, first: &Record) -> Result<ChainIdentity, Error> {
    let bad = |reason: &str| Error::Corrupt {
        segment: name.into(),
        offset: 0,
        reason: reason.into(),
    };
    match first.kind {
        RecordKind::Genesis if idx == 0 && first.seq == 0 && first.prev_hash == ZERO_HASH => {}
        RecordKind::SegmentStart if idx > 0 => {
            let sp: SegmentStartPayload = first
                .payload_json()
                .ok_or_else(|| bad("unparseable segment-start payload"))?;
            if sp.segment_index != idx {
                return Err(bad(&format!(
                    "segment-start names segment {}, file is segment {idx}",
                    sp.segment_index
                )));
            }
        }
        _ => {
            return Err(bad(
                "segment does not begin with genesis (segment 0) or its own segment-start",
            ))
        }
    }
    let id = identity_from(first).ok_or_else(|| bad("unparseable identity"))?;
    if id.chain_id() != first.chain_id {
        return Err(bad(
            "declared identity does not hash to the record's chain id",
        ));
    }
    Ok(id)
}

/// Authenticates records with the recorder's own key: an explicit
/// [`Verifier`] if one was given, else [`Signer::verify_own`]; then any
/// retired key (rotated away from in this run, or passed to
/// [`Recorder::open_with_keys`] for records signed before a rotation).
/// `previous_keys` is a trusted local input (the operator vouches that
/// every key in it belongs to this unit), so a keyring there is consulted
/// with [`Verifier::verify_any`]. Independent verification
/// ([`crate::verify`]) never does that: it names the key per record.
struct KeyCheck<'a> {
    signer: &'a dyn Signer,
    ext: Option<&'a dyn Verifier>,
    retired_signers: &'a [Box<dyn Signer>],
    retired: &'a [Box<dyn Verifier>],
}

impl KeyCheck<'_> {
    fn sig(&self, message: &[u8], sig: &[u8]) -> bool {
        let own = match self.ext {
            Some(v) => v.verify(message, sig),
            None => self.signer.verify_own(message, sig) == Some(true),
        };
        own || self
            .retired_signers
            .iter()
            .any(|s| s.verify_own(message, sig) == Some(true))
            || self.retired.iter().any(|v| v.verify_any(message, sig))
    }
    /// Hash and signature both valid.
    fn record(&self, r: &Record) -> bool {
        r.compute_hash() == r.hash && self.sig(&signing_message(&r.hash), &r.sig)
    }
}

const PROBE_MESSAGE: &[u8] = b"robodr-blackbox/self-test/v1\0";

/// Shortest zero run that counts as "lost write-back" evidence. A frame
/// never holds 16 consecutive zero bytes except in a genesis `prev_hash`
/// (excluded below): payloads are JSON, the rest are hashes and integers.
const ZERO_RUN_MIN: usize = 16;

fn has_zero_run(b: &[u8]) -> bool {
    if !b.is_empty() && b.len() < ZERO_RUN_MIN {
        return b.iter().all(|&x| x == 0);
    }
    let mut run = 0usize;
    for &x in b {
        run = if x == 0 { run + 1 } else { 0 };
        if run >= ZERO_RUN_MIN {
            return true;
        }
    }
    false
}

/// Where the active segment has to be cut.
struct Cut {
    offset: u64,
    reason: String,
    /// Records with a valid hash found *after* the damage (quarantined with
    /// it). Their signatures are checked by the caller.
    after: Vec<Record>,
}

/// Good records of a segment, plus where to cut it (if at all).
struct Analysis {
    good: Vec<Record>,
    cut: Option<Cut>,
}

/// Is `r` (following `p` in one segment) a correct successor? Either
/// `seq + 1` with a linking `prev_hash`, or a `Resume` that declares exactly
/// the sequence numbers it skipped (see [`ResumePayload::skipped_seqs`]).
fn links(p: &Record, r: &Record) -> bool {
    if r.prev_hash != p.hash {
        return false;
    }
    if p.seq.checked_add(1) == Some(r.seq) {
        return true;
    }
    r.kind == RecordKind::Resume
        && r.seq > p.seq
        && r.payload_json::<ResumePayload>()
            .and_then(|x| x.skipped_seqs)
            .is_some_and(|[a, b]| a == p.seq + 1 && b.checked_add(1) == Some(r.seq))
}

/// Structural check of one segment for the recorder's own use: strict
/// framing, record hashes and in-segment linkage (signatures are checked by
/// the caller once the chain's key is known).
///
/// Recoverable crash artefacts (the segment is cut there):
/// - an *incomplete* frame or a *zero-filled* tail with nothing valid after
///   it (torn write);
/// - damage that contains a run of zero bytes (a page whose write-back was
///   lost while a later page reached disk), even with valid frames after
///   it. Everything from the damage on is quarantined; the frames after it
///   are returned in [`Cut::after`] so the caller can account for them.
///
/// Everything else is [`Error::Corrupt`]: a complete frame whose hash fails
/// without zero evidence (modified record), a record that does not link,
/// non-zero bytes that do not start a frame. A crash cannot produce a
/// complete frame with a wrong hash out of non-zero bytes, because the hash
/// is computed before the frame is written; treating one as "torn" would
/// turn tampering with the newest record into a routine recovery.
fn analyze_segment(name: &str, bytes: &[u8]) -> Result<Analysis, Error> {
    let corrupt = |offset: u64, reason: String| Error::Corrupt {
        segment: name.into(),
        offset,
        reason,
    };
    let scan = scan_frames(bytes);
    let mut good: Vec<Record> = Vec::new();
    let mut items = scan.items.into_iter();
    let mut damage: Option<(u64, String)> = None;
    for it in items.by_ref() {
        match it {
            ScanItem::Record(sr) => {
                let r = sr.record;
                let (o, l) = (sr.offset as usize, sr.frame_len as usize);
                if r.compute_hash() != r.hash {
                    let zeros = r.prev_hash != ZERO_HASH && has_zero_run(&bytes[o..o + l]);
                    if !zeros {
                        return Err(corrupt(
                            sr.offset,
                            format!("record {} hash mismatch (complete frame modified)", r.seq),
                        ));
                    }
                    damage = Some((
                        sr.offset,
                        format!("record {} partly zeroed (lost write-back)", r.seq),
                    ));
                    break;
                }
                if !good.last().is_none_or(|p| links(p, &r)) {
                    return Err(corrupt(
                        sr.offset,
                        format!("record {} does not link to its predecessor", r.seq),
                    ));
                }
                good.push(r);
            }
            ScanItem::Malformed {
                offset,
                len,
                reason,
            } => {
                let region = &bytes[offset as usize..(offset + len) as usize];
                if !has_zero_run(region) {
                    return Err(corrupt(
                        offset,
                        format!("{reason}, followed by valid frames"),
                    ));
                }
                damage = Some((
                    offset,
                    format!("zero-filled hole of {len} bytes (lost write-back), followed by valid frames"),
                ));
                break;
            }
        }
    }
    if let Some((offset, reason)) = damage {
        let after = items
            .filter_map(|it| match it {
                ScanItem::Record(sr) if sr.record.compute_hash() == sr.record.hash => {
                    Some(sr.record)
                }
                _ => None,
            })
            .collect();
        return Ok(Analysis {
            good,
            cut: Some(Cut {
                offset,
                reason,
                after,
            }),
        });
    }
    let cut = match scan.tail {
        None => None,
        Some(t) => match t.kind {
            TailKind::Incomplete => Some(Cut {
                offset: t.offset,
                reason: "incomplete frame (torn write)".into(),
                after: Vec::new(),
            }),
            TailKind::Zeros => Some(Cut {
                offset: t.offset,
                reason: "zero-filled tail".into(),
                after: Vec::new(),
            }),
            TailKind::Garbage => {
                return Err(corrupt(
                    t.offset,
                    format!(
                        "{} bytes after the last record are neither a torn frame nor zeros",
                        t.len
                    ),
                ))
            }
        },
    };
    Ok(Analysis { good, cut })
}

/// Refusal counters persisted by the newest `Seal` / `Resume` record (reset
/// by `SaturationCleared`) among `records`, newest first.
fn persisted_refusals<'a>(
    records: impl DoubleEndedIterator<Item = &'a Record>,
) -> Option<(u64, u64)> {
    for r in records.rev() {
        match r.kind {
            RecordKind::Seal => {
                let p: SealPayload = r.payload_json()?;
                return Some((p.refused_noncritical, p.refused_critical));
            }
            RecordKind::Resume => {
                let p: ResumePayload = r.payload_json()?;
                return Some((p.refused_noncritical, p.refused_critical));
            }
            RecordKind::SaturationCleared => return Some((0, 0)),
            _ => {}
        }
    }
    None
}

/// The key that signs records after `tail` (the chain key, or the one named
/// by the segment's `SegmentStart`, updated by every `KeyRotation`).
fn current_key(identity: &ChainIdentity, tail: &[Record]) -> KeyRef {
    let mut k = KeyRef {
        key_id: identity.key_id.clone(),
        algorithm: identity.algorithm.clone(),
    };
    for r in tail {
        match r.kind {
            RecordKind::SegmentStart => {
                if let Some(sk) = r
                    .payload_json::<SegmentStartPayload>()
                    .and_then(|p| p.signing_key)
                {
                    k = sk;
                }
            }
            RecordKind::KeyRotation => {
                if let Some(p) = r.payload_json::<KeyRotationPayload>() {
                    k = p.to;
                }
            }
            _ => {}
        }
    }
    k
}

/// Result of checking a position against the authenticated log.
enum PosCheck {
    Ok,
    Beyond(String),
    Mismatch(String),
    Unknown(String),
    /// Inside the seq range of a segment quarantined at open: it existed,
    /// but cannot be re-read from the log.
    Quarantined,
}

/// A closed segment as read at open.
struct ClosedSeg {
    idx: u64,
    path: PathBuf,
    bytes: Vec<u8>,
    /// Strictly parsed records (empty when structurally damaged).
    records: Vec<Record>,
    /// Why it must be quarantined, and how severe that is.
    damage: Option<(String, Severity)>,
    /// Authentic drop / segment-quarantine records it holds.
    drops: Vec<SegmentDroppedPayload>,
    quarantine_records: Vec<RecoveryPayload>,
}

/// A damaged closed segment about to be quarantined.
struct QInfo {
    pos: usize,
    reason: String,
    severity: Severity,
    sha: String,
    /// Frames with a valid hash and this chain's id.
    records: u64,
    /// Lowest and highest of them whose signature verified.
    range: Option<[u64; 2]>,
    /// Highest authentic record, if the segment is newer than the tail.
    max_auth: Option<Record>,
    /// An authentic `Recovery` already records this exact file (an earlier
    /// open crashed before unlinking it).
    recorded: bool,
}

/// Authentic state that names a position beyond the head.
struct Beyond {
    file: String,
    seq: u64,
    hash: Option<Hash>,
    text: String,
}

/// Strict structure of a closed segment: whole frames only, every hash and
/// in-segment link valid, at least one record, ending with a seal (every
/// rotation seals and fsyncs before the next segment is created).
///
/// The error carries how severe the damage is: framing or hash damage
/// (what failing media produces) is `High`; a segment that parses cleanly
/// but holds no records or does not end with a seal is `Critical`: media
/// does not remove whole frames on a frame boundary, and no crash leaves a
/// closed segment unsealed (the seal is fsynced before the successor
/// exists), so it was cut or the live segment was made to look closed.
fn closed_structure(name: &str, bytes: &[u8]) -> Result<Vec<Record>, (String, Severity)> {
    let a = analyze_segment(name, bytes).map_err(|e| (e.to_string(), Severity::High))?;
    if let Some(c) = a.cut {
        return Err((
            format!("damaged at offset {}: {}", c.offset, c.reason),
            Severity::High,
        ));
    }
    match a.good.last() {
        None => Err(("holds no records".into(), Severity::Critical)),
        Some(r) if r.kind != RecordKind::Seal => Err((
            format!("does not end with a seal (last record {})", r.seq),
            Severity::Critical,
        )),
        Some(_) => Ok(a.good),
    }
}

/// Bounded signature work on untrusted frames (a damaged segment, or the
/// records after a hole in the active segment): at most this many from the
/// top and from the bottom are checked.
const QUARANTINE_SIG_TRIES: usize = 32;

/// Most stray segment files above the live segment the recorder will
/// quarantine; more is refused as corruption.
const MAX_STRAY_SEGMENTS: usize = 64;

/// Segment files `(index, path)` in index order.
type SegmentList = Vec<(u64, PathBuf)>;

/// A segment file found above the live segment (see [`Recorder::resume`]).
struct Stray {
    idx: u64,
    path: PathBuf,
    bytes: Vec<u8>,
    why: String,
}

/// Split `segs` into the segments the log really consists of and stray
/// files above the live one.
///
/// Let H be the newest file that holds records. If H does not end with a
/// seal (or has a torn / zero-damaged tail), H is the live segment: the
/// recorder creates a successor only after sealing and fsyncing. Every
/// file above it holds no record (empty, zeros, garbage) and was not
/// written by the recorder; left in place it would turn the live, unsealed
/// segment into a "closed segment without a seal" and get it quarantined.
/// Such files are returned separately (quarantined as tamper by the
/// caller). If H ends with a seal nothing is split off: the file after it
/// is the active segment (a rotation that crashed before its
/// `SegmentStart` leaves it empty or torn), and anything else is judged by
/// the closed-segment checks.
fn split_strays(mut segs: SegmentList) -> Result<(SegmentList, Vec<Stray>), Error> {
    let mut above: Vec<Stray> = Vec::new();
    for i in (0..segs.len()).rev() {
        let (idx, path) = segs[i].clone();
        let name = segment_file_name(idx);
        let bytes = fs::read(&path)?;
        let a = match analyze_segment(&name, &bytes) {
            Ok(a) if !a.good.is_empty() => a,
            Ok(a) => {
                let why = if bytes.is_empty() {
                    "empty file".to_string()
                } else {
                    a.cut.map_or_else(
                        || "holds no records".to_string(),
                        |c| format!("holds no valid record ({})", c.reason),
                    )
                };
                above.push(Stray {
                    idx,
                    path,
                    bytes,
                    why,
                });
                continue;
            }
            Err(e) => {
                above.push(Stray {
                    idx,
                    path,
                    bytes,
                    why: e.to_string(),
                });
                continue;
            }
        };
        let live_here =
            a.cut.is_some() || a.good.last().is_some_and(|r| r.kind != RecordKind::Seal);
        let keep = i + 1;
        if !live_here || keep >= segs.len() {
            // Sealed: the files above are the (possibly empty) active
            // segment and damaged closed ones; the closed-segment checks
            // classify them (an empty closed segment is critical).
            return Ok((segs, Vec::new()));
        }
        above.reverse(); // ascending: positions i+1 ..
        let strays = above.split_off(keep - (i + 1));
        if strays.len() > MAX_STRAY_SEGMENTS {
            return Err(Error::Corrupt {
                segment: segment_file_name(strays[0].idx),
                offset: 0,
                reason: format!(
                    "{} stray segment files above the live segment {}",
                    strays.len(),
                    segs[keep - 1].0
                ),
            });
        }
        segs.truncate(keep);
        return Ok((segs, strays));
    }
    Ok((segs, Vec::new()))
}

/// Key id expected to sign each record of a segment (its `SegmentStart`
/// names it, a `KeyRotation` changes it for the records after it).
fn expected_keys(identity: &ChainIdentity, recs: &[Record]) -> Vec<String> {
    let mut k = identity.key_id.clone();
    let mut out = Vec::with_capacity(recs.len());
    for r in recs {
        if r.kind == RecordKind::SegmentStart {
            k = r
                .payload_json::<SegmentStartPayload>()
                .and_then(|p| p.signing_key)
                .map_or_else(|| identity.key_id.clone(), |sk| sk.key_id);
        }
        out.push(k.clone());
        if r.kind == RecordKind::KeyRotation {
            if let Some(p) = r.payload_json::<KeyRotationPayload>() {
                k = p.to.key_id;
            }
        }
    }
    out
}

/// Collect an (already authenticated) drop or segment-quarantine record.
fn collect_control(
    r: &Record,
    drops: &mut Vec<SegmentDroppedPayload>,
    quarantines: &mut Vec<RecoveryPayload>,
) {
    match r.kind {
        RecordKind::SegmentDropped => {
            if let Some(d) = r.payload_json::<SegmentDroppedPayload>() {
                drops.push(d);
            }
        }
        RecordKind::Recovery => {
            if let Some(q) = r
                .payload_json::<RecoveryPayload>()
                .filter(|q| q.quarantined_segment)
            {
                quarantines.push(q);
            }
        }
        _ => {}
    }
}

/// Evidence text for a mark held by an external anchor.
fn anchor_evidence_json(h: &AnchoredHead) -> String {
    serde_json::json!({
        "source": EXTERNAL_ANCHOR,
        "chain_id": h.chain_id.map(|c| to_hex(&c)),
        "seq": h.seq,
        "hash": h.hash.map(|x| to_hex(&x)),
    })
    .to_string()
}

/// Evidence trouble a [`Recorder`] found while opening the log
/// ([`Recorder::open_incidents`]), for the host to report. Each one is also
/// a signed record in the log (`Recovery` or `TruncationDetected`); this is
/// only the in-memory summary.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum OpenIncident {
    /// A segment file was quarantined: a closed segment that failed
    /// verification, or a stray file above the live segment. `High` =
    /// framing or hash damage (failing media); `Critical` = tampering.
    SegmentQuarantined {
        segment_index: u64,
        severity: Severity,
        reason: String,
    },
    /// Authentic records after a zero-filled hole in the active segment
    /// were quarantined (`High` if a crash explains it, else `Critical`).
    /// A plain torn tail (medium) is not an incident.
    DamageQuarantined {
        segment_index: u64,
        severity: Severity,
        crash_plausible: bool,
        reason: String,
    },
    /// Authentic evidence (a state file, the external anchor, or authentic
    /// records removed by a critical quarantine) names records beyond the
    /// head: the log was cut. Always `Critical`.
    TruncationDetected {
        head_seq: u64,
        skipped_seqs: [u64; 2],
        /// What proved it, e.g. `head.json names seq 41`.
        evidence: Vec<String>,
    },
}

impl OpenIncident {
    /// How severe the recorder rated it.
    pub fn severity(&self) -> Severity {
        match self {
            OpenIncident::SegmentQuarantined { severity, .. }
            | OpenIncident::DamageQuarantined { severity, .. } => *severity,
            OpenIncident::TruncationDetected { .. } => Severity::Critical,
        }
    }
}

impl fmt::Display for OpenIncident {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            OpenIncident::SegmentQuarantined {
                segment_index,
                reason,
                ..
            } => write!(f, "segment {segment_index} quarantined: {reason}"),
            OpenIncident::DamageQuarantined {
                segment_index,
                reason,
                crash_plausible,
                ..
            } => write!(
                f,
                "records after damage in active segment {segment_index} quarantined \
                 ({reason}; crash plausible: {crash_plausible})"
            ),
            OpenIncident::TruncationDetected {
                head_seq,
                skipped_seqs: [a, b],
                evidence,
            } => write!(
                f,
                "log truncated after seq {head_seq}: seqs {a}..={b} are gone ({})",
                evidence.join("; ")
            ),
        }
    }
}

/// Largest index gap the recorder will record as missing segments; a larger
/// one is refused as corruption (it cannot come from normal operation).
const MAX_SEGMENT_GAP: u64 = 64;

/// The black-box recorder.
pub struct Recorder {
    cfg: RecorderConfig,
    signer: Box<dyn Signer>,
    own_verifier: Option<Box<dyn Verifier>>,
    /// Keys rotated away from in this run (still needed to authenticate
    /// what they signed).
    retired_signers: Vec<Box<dyn Signer>>,
    /// Verifiers for older keys: the one given to [`Recorder::open_with_keys`]
    /// and the explicit verifiers of keys rotated away from.
    retired: Vec<Box<dyn Verifier>>,
    clock: Box<dyn Clock>,
    identity: ChainIdentity,
    chain_id: Hash,
    file: File,
    /// Held for the recorder's lifetime: the single-writer `flock`.
    _lock: File,
    seg_index: u64,
    seg_len: u64,
    seg_records: u64,
    segments: VecDeque<SegInfo>,
    head: Option<(u64, Hash)>,
    since_seal: u64,
    last_seal_seq: Option<u64>,
    unsynced: u32,
    saturated: bool,
    refused_noncritical: u64,
    refused_critical: u64,
    export_cursor: Option<Anchor>,
    ack_verifier: Option<Box<dyn Verifier>>,
    acked: Option<Anchor>,
    last_checkpoint: Option<Checkpoint>,
    poisoned: bool,
    /// Lowest seq the next record may take (set at open when records beyond
    /// the head are known to have existed; consumed by the next write).
    seq_floor: Option<u64>,
    /// Signature and monotonic time of the head record (for marks).
    head_sig: Vec<u8>,
    head_mono: u64,
    /// Last high-water mark written (or authenticated at open).
    mark_seq: Option<u64>,
    since_mark: u64,
    last_mark_mono: u64,
    mark_failures: u64,
    anchor_failures: u64,
    last_anchor_error: Option<String>,
    /// `[first, last]` authenticated seq ranges of segments quarantined at
    /// open (positions inside them cannot be re-read).
    quarantined_ranges: Vec<[u64; 2]>,
    /// Indices of the closed segments quarantined by this open.
    quarantined_now: Vec<u64>,
    /// Evidence trouble found by this open, for the host to report.
    open_incidents: Vec<OpenIncident>,
}

impl fmt::Debug for Recorder {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Recorder")
            .field("dir", &self.cfg.dir)
            .field("chain_id", &to_hex(&self.chain_id))
            .field("segment", &self.seg_index)
            .field("head", &self.head.map(|(s, _)| s))
            .field("saturated", &self.saturated)
            .field("ack_mode", &self.ack_verifier.is_some())
            .field("head_mark", &self.mark_seq)
            .finish_non_exhaustive()
    }
}

struct Parts {
    cfg: RecorderConfig,
    signer: Box<dyn Signer>,
    own_verifier: Option<Box<dyn Verifier>>,
    previous: Option<Box<dyn Verifier>>,
    clock: Box<dyn Clock>,
    lock: File,
}

impl Parts {
    fn keys(&self) -> KeyCheck<'_> {
        KeyCheck {
            signer: &*self.signer,
            ext: self.own_verifier.as_deref(),
            retired_signers: &[],
            retired: self.previous.as_slice(),
        }
    }
}

impl Recorder {
    /// Open (or create) the log in `cfg.dir`.
    ///
    /// New directory: writes a genesis record binding device, boot and key.
    /// Existing directory: checks key and device, authenticates the tail it
    /// will chain onto (hash, linkage **and signature** of every record in
    /// the active segment, the first record of every retained segment, the
    /// drop records anchoring the oldest one), recovers a torn tail if needed
    /// (recorded), reports missing segments, and appends a `Resume` record.
    ///
    /// Takes an exclusive lock on the directory ([`Error::Locked`] if another
    /// recorder holds it). The signer must be able to check its own
    /// signatures ([`Signer::verify_own`]); otherwise use
    /// [`Recorder::open_with_verifier`].
    pub fn open(
        cfg: RecorderConfig,
        signer: Box<dyn Signer>,
        clock: Box<dyn Clock>,
    ) -> Result<Self, Error> {
        Self::open_inner(cfg, signer, None, None, clock)
    }

    /// [`Recorder::open`] with an explicit verifier for the recorder's own
    /// key (needed for signers that cannot self-verify, e.g. a TPM key whose
    /// public half is held separately). The verifier must match the signer's
    /// key id and algorithm and accept a fresh test signature.
    pub fn open_with_verifier(
        cfg: RecorderConfig,
        signer: Box<dyn Signer>,
        verifier: Box<dyn Verifier>,
        clock: Box<dyn Clock>,
    ) -> Result<Self, Error> {
        Self::open_inner(cfg, signer, Some(verifier), None, clock)
    }

    /// The general form of [`Recorder::open`]: `own_verifier` as in
    /// [`Recorder::open_with_verifier`] (or `None` for a self-verifying
    /// signer), and `previous_keys` (typically a
    /// [`crate::keys::Keyring`]) to authenticate retained records signed
    /// before a [`Recorder::rotate_key`] (consulted with
    /// [`Verifier::verify_any`]: put only this unit's own keys in it). The
    /// log's *current* key (the last
    /// rotation's target) must still be `signer`'s key, otherwise
    /// [`Error::KeyMismatch`]: rotation happens only through `rotate_key`,
    /// which needs the old private key.
    pub fn open_with_keys(
        cfg: RecorderConfig,
        signer: Box<dyn Signer>,
        own_verifier: Option<Box<dyn Verifier>>,
        previous_keys: Option<Box<dyn Verifier>>,
        clock: Box<dyn Clock>,
    ) -> Result<Self, Error> {
        Self::open_inner(cfg, signer, own_verifier, previous_keys, clock)
    }

    fn open_inner(
        cfg: RecorderConfig,
        signer: Box<dyn Signer>,
        own_verifier: Option<Box<dyn Verifier>>,
        previous: Option<Box<dyn Verifier>>,
        clock: Box<dyn Clock>,
    ) -> Result<Self, Error> {
        cfg.validate()?;
        if signer.key_id().is_empty() || signer.algorithm().is_empty() {
            return Err(Error::Config(
                "signer must have a key id and algorithm".into(),
            ));
        }
        if let Some(v) = &own_verifier {
            if v.key_id() != signer.key_id() || v.algorithm() != signer.algorithm() {
                return Err(Error::Config(format!(
                    "verifier {}/{} does not match signer {}/{}",
                    v.algorithm(),
                    v.key_id(),
                    signer.algorithm(),
                    signer.key_id()
                )));
            }
        }
        // Self-test: the recorder must be able to authenticate what it reads
        // back, and the verifier must belong to the signer.
        let probe = signer.sign(PROBE_MESSAGE).map_err(Error::Sign)?;
        if own_verifier.is_none() && signer.verify_own(PROBE_MESSAGE, &probe).is_none() {
            return Err(Error::Config(
                "signer cannot verify its own signatures; use Recorder::open_with_verifier".into(),
            ));
        }
        let ok = match own_verifier.as_deref() {
            Some(v) => v.verify(PROBE_MESSAGE, &probe),
            None => signer.verify_own(PROBE_MESSAGE, &probe) == Some(true),
        };
        if !ok {
            return Err(Error::Config(
                "self-test failed: the verifier rejects the signer's signature".into(),
            ));
        }
        create_dir_private(&cfg.dir)?;
        let lock = lock_dir(&cfg.dir)?;
        remove_stale_tmp(&cfg.dir);
        let segs = list_segments(&cfg.dir)?;
        let parts = Parts {
            cfg,
            signer,
            own_verifier,
            previous,
            clock,
            lock,
        };
        if segs.is_empty() {
            let path = parts.cfg.dir.join(segment_file_name(0));
            let file = create_new_private(&path, true)?;
            sync_dir(&parts.cfg.dir)?;
            return Self::start_chain(parts, file, None);
        }
        Self::resume(parts, segs)
    }

    fn keys(&self) -> KeyCheck<'_> {
        KeyCheck {
            signer: &*self.signer,
            ext: self.own_verifier.as_deref(),
            retired_signers: &self.retired_signers,
            retired: &self.retired,
        }
    }

    fn start_chain(
        parts: Parts,
        file: File,
        recovery: Option<RecoveryPayload>,
    ) -> Result<Self, Error> {
        let Parts {
            cfg,
            signer,
            own_verifier,
            previous,
            clock,
            lock,
        } = parts;
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
            own_verifier,
            retired_signers: Vec::new(),
            retired: previous.into_iter().collect(),
            clock,
            identity: identity.clone(),
            chain_id,
            file,
            _lock: lock,
            seg_index: 0,
            seg_len: 0,
            seg_records: 0,
            segments: VecDeque::from([SegInfo {
                index: 0,
                start: None,
            }]),
            head: None,
            since_seal: 0,
            last_seal_seq: None,
            unsynced: 0,
            saturated: false,
            refused_noncritical: 0,
            refused_critical: 0,
            export_cursor: None,
            ack_verifier: None,
            acked: None,
            last_checkpoint: None,
            poisoned: false,
            seq_floor: None,
            head_sig: Vec::new(),
            head_mono: 0,
            mark_seq: None,
            since_mark: 0,
            last_mark_mono: 0,
            mark_failures: 0,
            anchor_failures: 0,
            last_anchor_error: None,
            quarantined_ranges: Vec::new(),
            quarantined_now: Vec::new(),
            open_incidents: Vec::new(),
        };
        let genesis = to_json(&GenesisPayload {
            identity,
            recorder_version: env!("CARGO_PKG_VERSION").to_string(),
            format_version: FORMAT_VERSION,
        })?;
        let g = r.write_record(RecordKind::Genesis, genesis, true, true)?;
        if let Some(rec) = recovery {
            r.write_record(RecordKind::Recovery, to_json(&rec)?, true, true)?;
        }
        r.check_anchor_fresh(g.hash)?;
        r.mark_best_effort();
        Ok(r)
    }

    /// A new chain while the external anchor holds a mark: the store was
    /// wiped or replaced. Declare the anchor's seqs as skipped (never reuse
    /// them: a counter anchor only goes up) and record the truncation.
    fn check_anchor_fresh(&mut self, genesis_hash: Hash) -> Result<(), Error> {
        let Some(anchor) = self.cfg.head_anchor.clone() else {
            return Ok(());
        };
        let held = match anchor.current() {
            Ok(Some(h)) if h.seq > 0 => h,
            Ok(_) => return Ok(()),
            Err(e) => {
                self.anchor_failures += 1;
                self.last_anchor_error = Some(e);
                return Ok(());
            }
        };
        let floor = held
            .seq
            .checked_add(1)
            .ok_or_else(|| Error::Config("external anchor at the end of seq space".into()))?;
        let text = anchor_evidence_json(&held);
        let preserved_as = Some(Self::preserve(
            &self.cfg,
            &format!("state-{EXTERNAL_ANCHOR}-seq{}", held.seq),
            "json",
            text.as_bytes(),
        )?);
        let skipped = [1, held.seq];
        self.seq_floor = Some(floor);
        let resume = ResumePayload {
            boot_id: self.cfg.boot_id.clone(),
            chain_boot_id: self.identity.boot_id.clone(),
            resumed_after_seq: 0,
            recovered: false,
            missing_segments: Vec::new(),
            rejected_state: vec![format!(
                "{EXTERNAL_ANCHOR}: holds seq {} but the log directory held no chain: \
                 the store was wiped or replaced (see the TruncationDetected record)",
                held.seq
            )],
            skipped_seqs: Some(skipped),
            refused_noncritical: 0,
            refused_critical: 0,
        };
        self.write_record(RecordKind::Resume, to_json(&resume)?, true, true)?;
        let p = to_json(&TruncationPayload {
            head_seq: 0,
            head_hash: to_hex(&genesis_hash),
            evidence: vec![StateEvidence {
                file: EXTERNAL_ANCHOR.into(),
                seq: held.seq,
                hash: held.hash.map(|h| to_hex(&h)).unwrap_or_default(),
                preserved_as,
                sha256: to_hex(&sha256(text.as_bytes())),
            }],
            skipped_seqs: skipped,
            severity: Severity::Critical,
        })?;
        self.write_record(RecordKind::TruncationDetected, p, true, true)?;
        self.open_incidents.push(OpenIncident::TruncationDetected {
            head_seq: 0,
            skipped_seqs: skipped,
            evidence: vec![format!("{EXTERNAL_ANCHOR} names seq {}", held.seq)],
        });
        Ok(())
    }

    /// Create a new, uniquely named file `quarantine/<base>[-n].<ext>`.
    fn quarantine_file(
        cfg: &RecorderConfig,
        base: &str,
        ext: &str,
    ) -> Result<(String, File), Error> {
        let qdir = cfg.dir.join(QUARANTINE_DIR);
        create_dir_private(&qdir)?;
        let mut n = 0u32;
        loop {
            let name = if n == 0 {
                format!("{base}.{ext}")
            } else {
                format!("{base}-{n}.{ext}")
            };
            match create_new_private(&qdir.join(&name), false) {
                Ok(f) => return Ok((name, f)),
                Err(e) if e.kind() == io::ErrorKind::AlreadyExists && n < 10_000 => n += 1,
                Err(e) => return Err(e.into()),
            }
        }
    }

    /// Copy `data` into a new quarantine file, durably; returns its path
    /// relative to the log directory.
    fn preserve(cfg: &RecorderConfig, base: &str, ext: &str, data: &[u8]) -> Result<String, Error> {
        let (name, mut q) = Self::quarantine_file(cfg, base, ext)?;
        q.write_all(data)?;
        q.sync_all()?;
        drop(q);
        sync_dir(&cfg.dir.join(QUARANTINE_DIR))?;
        Ok(format!("{QUARANTINE_DIR}/{name}"))
    }

    /// Move `bytes[cut..]` of segment `seg_idx` to `quarantine/` and truncate
    /// the segment to `cut`.
    ///
    /// `mark`: a high-water mark naming the highest authentic record about
    /// to be cut away, written *before* the truncation, so that a crash
    /// between the truncation and the `Recovery` record still leaves
    /// evidence (and a seq floor) for the next open.
    fn quarantine(
        cfg: &RecorderConfig,
        seg_idx: u64,
        path: &Path,
        bytes: &[u8],
        cut: u64,
        reason: String,
        mark: Option<&Checkpoint>,
    ) -> Result<RecoveryPayload, Error> {
        let discarded = &bytes[cut as usize..];
        let file = Self::preserve(
            cfg,
            &format!("torn-seg{seg_idx:016}-off{cut}"),
            "bin",
            discarded,
        )?;
        fault("recovery.after_preserve")?;
        if let Some(m) = mark {
            atomic_write(&cfg.dir, RECOVERY_PIN_FILE, m.to_json().as_bytes())?;
            fault("recovery.after_mark")?;
        }
        let mut o = OpenOptions::new();
        o.write(true);
        let f = private(&mut o).open(path)?;
        f.set_len(cut)?;
        f.sync_all()?;
        fault("recovery.after_truncate")?;
        Ok(RecoveryPayload {
            segment_index: seg_idx,
            offset: cut,
            discarded_bytes: discarded.len() as u64,
            discarded_sha256: to_hex(&sha256(discarded)),
            reason,
            quarantine_file: Some(file),
            discarded_records: 0,
            discarded_seqs: None,
            crash_plausible: true,
            severity: Some(Severity::Medium),
            quarantined_segment: false,
        })
    }

    /// Could a record with these properties have been durably synced when it
    /// was written? Control records always are; critical ones under
    /// `fsync_critical`; every one under [`FsyncPolicy::Always`].
    fn was_synced(cfg: &RecorderConfig, r: &Record) -> bool {
        r.kind.is_control()
            || (r.critical && cfg.fsync_critical)
            || cfg.fsync == FsyncPolicy::Always
    }

    fn resume(parts: Parts, segs: Vec<(u64, PathBuf)>) -> Result<Self, Error> {
        // 0. Files above the live segment that hold no record: not the
        //    recorder's (quarantined as tamper below, never allowed to make
        //    the live segment look closed).
        let (segs, strays) = split_strays(segs)?;
        let (last_idx, last_path) = segs.last().cloned().expect("non-empty");
        let last_name = segment_file_name(last_idx);
        let bytes = fs::read(&last_path)?;
        // 1. Structure, hashes and linkage of the active segment (no writes
        //    yet). Damage here is refused: it holds the head.
        let Analysis { good, cut } = analyze_segment(&last_name, &bytes)?;

        if good.is_empty() && segs.len() == 1 {
            if last_idx != 0 {
                return Err(Error::Corrupt {
                    segment: last_name,
                    offset: 0,
                    reason: "only segment is empty and is not segment 0".into(),
                });
            }
            // Crash before genesis reached disk (or genesis itself lost):
            // start a new chain here. Whatever followed is quarantined.
            let recovery = match cut {
                Some(c) => {
                    let mut rp = Self::quarantine(
                        &parts.cfg, last_idx, &last_path, &bytes, c.offset, c.reason, None,
                    )?;
                    if !c.after.is_empty() {
                        rp.discarded_records = c.after.len() as u64;
                        rp.severity = Some(Severity::High);
                    }
                    Some(rp)
                }
                None => None,
            };
            let file = open_append(&last_path)?;
            return Self::start_chain(parts, file, recovery);
        }

        // 2. Strict structure of every closed segment (no writes yet). A
        //    closed segment was fsynced before its successor was created:
        //    no crash explains damage in it.
        let mut closed: Vec<ClosedSeg> = Vec::with_capacity(segs.len() - 1);
        for (idx, path) in &segs[..segs.len() - 1] {
            let b = fs::read(path)?;
            let (records, damage) = match closed_structure(&segment_file_name(*idx), &b) {
                Ok(r) => (r, None),
                Err(d) => (Vec::new(), Some(d)),
            };
            closed.push(ClosedSeg {
                idx: *idx,
                path: path.clone(),
                bytes: b,
                records,
                damage,
                drops: Vec::new(),
                quarantine_records: Vec::new(),
            });
        }

        // 3. The records we will chain onto: the active segment, or (if it
        //    is empty) the newest intact closed segment. Damaged closed
        //    segments newer than it are quarantined below.
        let (tail, tail_name, tail_idx, need_segment_start, tail_pos) = if good.is_empty() {
            let Some(p) = closed.iter().rposition(|c| c.damage.is_none()) else {
                let why = closed
                    .last()
                    .and_then(|c| c.damage.as_ref())
                    .map_or_else(String::new, |(w, _)| w.clone());
                return Err(Error::Corrupt {
                    segment: segment_file_name(closed.last().map_or(last_idx, |c| c.idx)),
                    offset: 0,
                    reason: format!(
                        "active segment is empty and no closed segment is intact ({why}): \
                         no trustworthy head to chain onto"
                    ),
                });
            };
            let c = &closed[p];
            (
                c.records.clone(),
                segment_file_name(c.idx),
                c.idx,
                true,
                Some(p),
            )
        } else {
            (good, last_name.clone(), last_idx, false, None)
        };
        let identity = segment_identity(&tail_name, tail_idx, &tail[0])?;
        let key = current_key(&identity, &tail);
        if key.key_id != parts.signer.key_id() || key.algorithm != parts.signer.algorithm() {
            return Err(Error::KeyMismatch {
                log_key_id: format!("{}/{}", key.algorithm, key.key_id),
                signer_key_id: format!("{}/{}", parts.signer.algorithm(), parts.signer.key_id()),
            });
        }
        if identity.device_id != parts.cfg.device_id {
            return Err(Error::DeviceMismatch {
                log_device_id: identity.device_id,
                config_device_id: parts.cfg.device_id,
            });
        }
        let chain_id = identity.chain_id();
        let keys = parts.keys();
        // 4. Authenticate every record we chain onto: never extend a forged head.
        for r in &tail {
            if r.chain_id != chain_id {
                return Err(Error::Corrupt {
                    segment: tail_name,
                    offset: 0,
                    reason: format!("record {} belongs to another chain", r.seq),
                });
            }
            if !keys.sig(&signing_message(&r.hash), &r.sig) {
                return Err(Error::Corrupt {
                    segment: tail_name,
                    offset: 0,
                    reason: format!(
                        "record {} signature does not verify (with this key or any \
                         previous key given to open_with_keys); refusing to chain onto it",
                        r.seq
                    ),
                });
            }
        }
        // Keys proven present: any key that verified some record.
        let mut verified_keys: HashSet<String> =
            expected_keys(&identity, &tail).into_iter().collect();
        let mut tail_drops: Vec<SegmentDroppedPayload> = Vec::new();
        let mut tail_quarantines: Vec<RecoveryPayload> = Vec::new();
        for r in &tail {
            collect_control(r, &mut tail_drops, &mut tail_quarantines);
        }

        // 5. Every other closed segment: chain, identity, signatures.
        let verify_all = parts.cfg.verify_closed_signatures;
        let mut sig_failures: Vec<(usize, u64, String)> = Vec::new();
        for (ci, c) in closed.iter_mut().enumerate() {
            if c.damage.is_some() || Some(ci) == tail_pos {
                continue;
            }
            let name = segment_file_name(c.idx);
            if let Some(r) = c.records.iter().find(|r| r.chain_id != chain_id) {
                c.damage = Some((
                    format!("record {} belongs to another chain", r.seq),
                    Severity::Critical,
                ));
                continue;
            }
            if let Err(e) = segment_identity(&name, c.idx, &c.records[0]) {
                c.damage = Some((e.to_string(), Severity::Critical));
                continue;
            }
            let ks = expected_keys(&identity, &c.records);
            let n = c.records.len();
            let mut fail = None;
            for (i, (r, k)) in c.records.iter().zip(ks).enumerate() {
                let control = matches!(
                    r.kind,
                    RecordKind::SegmentDropped | RecordKind::Recovery | RecordKind::KeyRotation
                );
                if !(verify_all || i == 0 || i + 1 == n || control) {
                    continue;
                }
                if keys.sig(&signing_message(&r.hash), &r.sig) {
                    verified_keys.insert(k);
                    collect_control(r, &mut c.drops, &mut c.quarantine_records);
                } else if fail.is_none() {
                    fail = Some((r.seq, k));
                }
            }
            if let Some((seq, k)) = fail {
                sig_failures.push((ci, seq, k));
            }
        }
        for (ci, seq, k) in sig_failures {
            if !verified_keys.contains(&k) {
                // Not damage we can tell from a missing key: refuse, as for
                // the head (pass the old key to open_with_keys).
                return Err(Error::Corrupt {
                    segment: segment_file_name(closed[ci].idx),
                    offset: 0,
                    reason: format!(
                        "record {seq} signature does not verify (with this key or any \
                         previous key given to open_with_keys; key {k} verifies no record); \
                         refusing to open"
                    ),
                });
            }
            closed[ci].damage = Some((
                format!("record {seq} signature does not verify under key {k}"),
                Severity::Critical,
            ));
        }

        // 6. Cross-segment links, newest first: a closed segment must end
        //    with the record its retained successor chains onto.
        let active_first = (!need_segment_start).then(|| (tail[0].seq, tail[0].prev_hash));
        for ci in (0..closed.len()).rev() {
            if closed[ci].damage.is_some() || Some(ci) == tail_pos {
                continue;
            }
            let idx = closed[ci].idx;
            let next = match closed.get(ci + 1) {
                Some(n) if n.idx == idx + 1 && n.damage.is_none() => {
                    Some((n.records[0].seq, n.records[0].prev_hash))
                }
                Some(_) => None,
                None if last_idx == idx + 1 => active_first,
                None => None,
            };
            if let Some((s, prev)) = next {
                let l = closed[ci].records.last().expect("non-empty");
                if prev != l.hash || s <= l.seq {
                    closed[ci].damage = Some((
                        format!(
                            "its last record {} is not the record segment {} chains onto",
                            l.seq,
                            idx + 1
                        ),
                        Severity::Critical,
                    ));
                }
            }
        }

        // 6b. Refusal counters persisted before the restart (before the
        //     strays join `closed`).
        let mut refusals = persisted_refusals(tail.iter());
        if refusals.is_none() && !need_segment_start {
            if let Some(c) = closed
                .last()
                .filter(|c| c.damage.is_none() && c.idx + 1 == last_idx)
            {
                refusals = persisted_refusals(c.records.iter());
            }
        }
        let (refused_noncritical, refused_critical) = refusals.unwrap_or((0, 0));

        // 6c. Stray files above the live segment join the quarantine as
        //     tamper.
        let live_idx = last_idx;
        closed.extend(strays.into_iter().map(|s| ClosedSeg {
            idx: s.idx,
            path: s.path,
            bytes: s.bytes,
            records: Vec::new(),
            damage: Some((
                format!(
                    "stray segment file above the live segment {live_idx} ({}): not written \
                     by the recorder",
                    s.why
                ),
                Severity::Critical,
            )),
            drops: Vec::new(),
            quarantine_records: Vec::new(),
        }));

        // 7. Retained segments and what the quarantined ones held.
        let mut infos: VecDeque<SegInfo> = VecDeque::with_capacity(segs.len());
        let mut drops = tail_drops;
        let mut recorded_q = tail_quarantines;
        for (ci, c) in closed.iter().enumerate() {
            if c.damage.is_some() {
                continue;
            }
            infos.push_back(SegInfo {
                index: c.idx,
                start: Some((c.records[0].seq, c.records[0].prev_hash)),
            });
            if Some(ci) != tail_pos {
                drops.extend(c.drops.iter().cloned());
                recorded_q.extend(c.quarantine_records.iter().cloned());
            }
        }
        let active_start = if need_segment_start {
            None
        } else {
            Some((tail[0].seq, tail[0].prev_hash))
        };
        infos.push_back(SegInfo {
            index: last_idx,
            start: active_start,
        });
        let head_rec = tail.last().expect("non-empty").clone();
        let mut quarantine: Vec<QInfo> = Vec::new();
        for (ci, c) in closed.iter().enumerate() {
            let Some((reason, severity)) = &c.damage else {
                continue;
            };
            let sha = to_hex(&sha256(&c.bytes));
            let mut cands: Vec<Record> = scan_frames(&c.bytes)
                .items
                .into_iter()
                .filter_map(|it| match it {
                    ScanItem::Record(sr)
                        if sr.record.chain_id == chain_id
                            && sr.record.compute_hash() == sr.record.hash =>
                    {
                        Some(sr.record)
                    }
                    _ => None,
                })
                .collect();
            cands.sort_by_key(|r| r.seq);
            // Bounded signature work: the frames are untrusted.
            let hi = cands
                .iter()
                .rev()
                .take(QUARANTINE_SIG_TRIES)
                .find(|r| keys.record(r));
            let lo = cands
                .iter()
                .take(QUARANTINE_SIG_TRIES)
                .find(|r| keys.record(r));
            let range = match (lo, hi) {
                (Some(a), Some(b)) => Some([a.seq, b.seq]),
                _ => None,
            };
            let already = recorded_q
                .iter()
                .any(|q| q.segment_index == c.idx && q.discarded_sha256 == sha);
            // Newer than the segment we chain onto: it held the newest
            // records. Storage that loses a whole newest segment while an
            // older one survives intact is not what failing media looks
            // like, and treating it as such would let its quarantine
            // "explain" the high-water mark away.
            let (reason, severity) = if c.idx > tail_idx && *severity < Severity::Critical {
                (
                    format!("{reason} (newer than the newest intact segment {tail_idx})"),
                    Severity::Critical,
                )
            } else {
                (reason.clone(), *severity)
            };
            quarantine.push(QInfo {
                pos: ci,
                reason,
                severity,
                sha,
                records: cands.len() as u64,
                range,
                max_auth: hi.filter(|_| c.idx > tail_idx).cloned(),
                recorded: already,
            });
        }
        let q_indices: HashSet<u64> = quarantine
            .iter()
            .map(|q| closed[q.pos].idx)
            .chain(recorded_q.iter().map(|q| q.segment_index))
            .collect();

        // 8. Expected segment indices: gaps, and the oldest one's predecessor.
        //    Quarantined segments are reported by their own record.
        let reported = |idx: u64| {
            q_indices.contains(&idx) || drops.iter().any(|d| d.segment_index == idx && d.missing)
        };
        let mut missing: Vec<u64> = Vec::new();
        let oldest = infos[0];
        if oldest.index > 0 {
            let Some((s, prev)) = oldest.start else {
                return Err(Error::Corrupt {
                    segment: segment_file_name(oldest.index),
                    offset: 0,
                    reason: "oldest retained segment holds no records".into(),
                });
            };
            let want = to_hex(&prev);
            let covered = drops.iter().any(|d| {
                d.segment_index + 1 == oldest.index
                    && !d.missing
                    && d.last_seq == s.checked_sub(1)
                    && d.last_hash.as_deref() == Some(want.as_str())
            });
            if !covered && !reported(oldest.index - 1) {
                missing.push(oldest.index - 1);
            }
        }
        for (a, b) in infos.iter().zip(infos.iter().skip(1)) {
            let quarantined_between = q_indices
                .iter()
                .filter(|&&i| i > a.index && i < b.index)
                .count() as u64;
            let gap = (b.index - a.index - 1).saturating_sub(quarantined_between);
            if gap > MAX_SEGMENT_GAP {
                return Err(Error::Corrupt {
                    segment: segment_file_name(b.index),
                    offset: 0,
                    reason: format!("{gap} segments missing before it"),
                });
            }
            missing.extend((a.index + 1..b.index).filter(|&i| !reported(i)));
        }

        // 8b. Authentic records quarantined with a mid-segment hole: their
        //     seqs must never be reused; whether a crash explains the hole.
        //     The frames after the hole are untrusted (an attacker can append
        //     any number of hash-valid forgeries): signatures are checked for
        //     at most QUARANTINE_SIG_TRIES from each end, as for a damaged
        //     closed segment.
        let mut lost_cands: Vec<Record> = cut
            .as_ref()
            .map(|c| {
                c.after
                    .iter()
                    .filter(|r| r.chain_id == chain_id)
                    .cloned()
                    .collect()
            })
            .unwrap_or_default();
        lost_cands.sort_by_key(|r| r.seq);
        let mut forged = false;
        let mut first_authentic = |it: &mut dyn Iterator<Item = &Record>| {
            for r in it.take(QUARANTINE_SIG_TRIES) {
                if keys.record(r) {
                    return Some(r.clone());
                }
                forged = true;
            }
            None
        };
        let lost_hi = first_authentic(&mut lost_cands.iter().rev());
        let lost_lo = first_authentic(&mut lost_cands.iter());
        let lost_top = lost_hi.or(lost_lo).filter(|r| r.seq > head_rec.seq);
        let lost_max = lost_top.as_ref().map(|r| r.seq);
        // The high-water mark proves everything up to it was fsynced.
        let mark_in = read_state(&parts.cfg.dir, HEAD_FILE)?
            .and_then(|s| Checkpoint::from_json(&s))
            .filter(|c| c.chain_id == chain_id && keys.sig(&signing_message(&c.hash), &c.sig));
        // A crash explains the hole only if nothing after it was durably
        // synced: no record that is always synced, nothing at or below the
        // mark (and no mark beyond the head: it names a synced record that
        // is gone), and no forged frame (a crash writes none). The
        // unauthenticated frames count here: they can only make the
        // verdict stricter.
        let crash_plausible = !forged
            && !mark_in.as_ref().is_some_and(|m| m.seq > head_rec.seq)
            && !lost_cands.iter().any(|r| {
                Self::was_synced(&parts.cfg, r) || mark_in.as_ref().is_some_and(|m| r.seq <= m.seq)
            });
        // Seqs held by quarantined records beyond the head (a damaged
        // segment newer than the tail, a stray file): never reuse them.
        let q_top = |explaining_only: bool| {
            quarantine
                .iter()
                .filter(|q| !explaining_only || q.severity < Severity::Critical)
                .filter_map(|q| q.max_auth.as_ref())
                .filter(|r| r.seq > head_rec.seq)
                .map(|r| r.seq)
                .max()
        };
        // Never reuse a seq that quarantined evidence holds.
        let quarantined_max = lost_max.max(q_top(false));
        // Positions up to here are accounted for by quarantined evidence,
        // not by a truncation: only when the damage is something a crash
        // or failing media produces. A critical quarantine explains
        // nothing: authentic state beyond the head is still truncation.
        let explained_max = lost_max.filter(|_| crash_plausible).max(q_top(true));

        // 9. Only now modify anything: quarantine the damaged suffix of the
        //    active segment (after pinning the highest authentic record it
        //    held in RECOVERY_PIN_FILE, so a crash right after the cut still
        //    leaves evidence).
        let recovery = match cut {
            Some(c) => {
                let pin = lost_top
                    .as_ref()
                    .filter(|r| mark_in.as_ref().is_none_or(|m| m.seq < r.seq))
                    .map(|r| Checkpoint {
                        chain_id,
                        seq: r.seq,
                        hash: r.hash,
                        key_id: parts.signer.key_id().to_string(),
                        sig: r.sig.clone(),
                    });
                let mut rp = Self::quarantine(
                    &parts.cfg,
                    last_idx,
                    &last_path,
                    &bytes,
                    c.offset,
                    c.reason,
                    pin.as_ref(),
                )?;
                if !c.after.is_empty() {
                    // Frames with a valid hash and this chain's id (only
                    // the ends were signature-checked).
                    rp.discarded_records = lost_cands.len() as u64;
                    rp.discarded_seqs = lost_max.map(|m| [head_rec.seq + 1, m]);
                    rp.crash_plausible = crash_plausible;
                    rp.severity = Some(if crash_plausible {
                        Severity::High
                    } else {
                        Severity::Critical
                    });
                }
                Some(rp)
            }
            None => None,
        };

        let (since_seal, last_seal_seq) =
            match tail.iter().rposition(|r| r.kind == RecordKind::Seal) {
                Some(i) => ((tail.len() - 1 - i) as u64, Some(tail[i].seq)),
                None => (tail.len() as u64, None),
            };
        let file = open_append(&last_path)?;
        // A log created before files were made private: tighten the segment
        // we keep writing to (through our own fd, so no symlink race).
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            file.set_permissions(fs::Permissions::from_mode(0o600))?;
        }
        let seg_len = file.metadata()?.len();
        let retained = infos.len();
        let saturated = matches!(parts.cfg.mode, RetentionMode::Saturation { max_segments, .. }
            if retained as u64 > u64::from(max_segments));
        let chain_boot_id = identity.boot_id.clone();
        let Parts {
            cfg,
            signer,
            own_verifier,
            previous,
            clock,
            lock,
        } = parts;
        let mut r = Recorder {
            cfg,
            signer,
            own_verifier,
            retired_signers: Vec::new(),
            retired: previous.into_iter().collect(),
            clock,
            identity,
            chain_id,
            file,
            _lock: lock,
            seg_index: last_idx,
            seg_len,
            seg_records: if need_segment_start {
                0
            } else {
                tail.len() as u64
            },
            segments: infos,
            head: Some((head_rec.seq, head_rec.hash)),
            since_seal,
            last_seal_seq,
            unsynced: 0,
            saturated,
            refused_noncritical,
            refused_critical,
            export_cursor: None,
            ack_verifier: None,
            acked: None,
            last_checkpoint: None,
            poisoned: false,
            seq_floor: None,
            head_sig: head_rec.sig.clone(),
            head_mono: head_rec.time.mono_ns,
            mark_seq: None,
            since_mark: 0,
            last_mark_mono: head_rec.time.mono_ns,
            mark_failures: 0,
            anchor_failures: 0,
            last_anchor_error: None,
            quarantined_ranges: quarantine.iter().filter_map(|q| q.range).collect(),
            quarantined_now: Vec::new(),
            open_incidents: Vec::new(),
        };

        // 10. State: trusted only if authenticated and consistent. An
        //     authentic position *beyond* the head proves truncation, unless
        //     quarantined evidence accounts for it.
        let explained = |seq: u64| explained_max.is_some_and(|m| seq <= m);
        let mut rejected = Vec::new();
        let mut beyond: Vec<Beyond> = Vec::new();
        if let Some(s) = read_state(&r.cfg.dir, CURSOR_FILE)? {
            match r.check_cursor(&s) {
                Ok(a) => r.export_cursor = Some(a),
                Err((Some(a), _)) if explained(a.seq) => {}
                Err((Some(a), _)) => beyond.push(Beyond {
                    file: CURSOR_FILE.to_string(),
                    seq: a.seq,
                    hash: Some(a.hash),
                    text: s,
                }),
                Err((None, why)) => rejected.push(format!("{CURSOR_FILE}: {why}")),
            }
        }
        for name in [CHECKPOINT_FILE, HEAD_FILE, RECOVERY_PIN_FILE] {
            let Some(s) = read_state(&r.cfg.dir, name)? else {
                continue;
            };
            match Checkpoint::from_json(&s) {
                Some(c)
                    if c.chain_id == chain_id
                        && r.keys().sig(&signing_message(&c.hash), &c.sig) =>
                {
                    match r.check_position(&c.anchor()) {
                        PosCheck::Ok | PosCheck::Unknown(_) | PosCheck::Quarantined => {
                            if name == CHECKPOINT_FILE {
                                r.last_checkpoint = Some(c);
                            } else if name == HEAD_FILE {
                                r.mark_seq = Some(c.seq);
                            }
                        }
                        PosCheck::Beyond(_) if explained(c.seq) => {}
                        PosCheck::Beyond(_) => beyond.push(Beyond {
                            file: name.to_string(),
                            seq: c.seq,
                            hash: Some(c.hash),
                            text: s,
                        }),
                        PosCheck::Mismatch(why) => {
                            return Err(Error::Untrusted(format!(
                                "{name} is authentic but {why}: the log was \
                                 rewritten under this chain's key; refusing to extend it \
                                 (preserve the directory for analysis)"
                            )))
                        }
                    }
                }
                _ => rejected.push(format!(
                    "{name}: unparseable, foreign or not signed by this key"
                )),
            }
        }
        if let Some(anchor) = r.cfg.head_anchor.clone() {
            match anchor.current() {
                Ok(None) => {}
                Ok(Some(h)) if h.chain_id.is_some_and(|c| c != chain_id) => rejected.push(format!(
                    "{EXTERNAL_ANCHOR}: holds a position of another chain"
                )),
                Ok(Some(h)) if h.seq > head_rec.seq => {
                    if !explained(h.seq) {
                        beyond.push(Beyond {
                            file: EXTERNAL_ANCHOR.to_string(),
                            seq: h.seq,
                            hash: h.hash,
                            text: anchor_evidence_json(&h),
                        });
                    }
                }
                Ok(Some(h)) => {
                    if let Some(hash) = h.hash {
                        let a = Anchor {
                            chain_id,
                            seq: h.seq,
                            hash,
                        };
                        if let PosCheck::Mismatch(why) = r.check_position(&a) {
                            return Err(Error::Untrusted(format!(
                                "{EXTERNAL_ANCHOR} {why}: the log was rewritten under this \
                                 chain's key; refusing to extend it"
                            )));
                        }
                    }
                }
                Err(e) => {
                    r.anchor_failures += 1;
                    rejected.push(format!("{EXTERNAL_ANCHOR}: unreadable: {e}"));
                    r.last_anchor_error = Some(e);
                }
            }
        }

        for b in &beyond {
            rejected.push(format!(
                "{}: authentic but seq {} is beyond the head {}: log truncated \
                 (see the TruncationDetected record)",
                b.file, b.seq, head_rec.seq
            ));
        }
        // Never reuse a sequence number that may exist elsewhere.
        let floor = beyond
            .iter()
            .map(|b| b.seq)
            .chain(quarantined_max)
            .max()
            .and_then(|m| m.checked_add(1));
        let skipped = floor.map(|f| [head_rec.seq + 1, f - 1]);
        r.seq_floor = floor;

        // Keep the evidence before anything replaces it.
        let mut evidence = Vec::new();
        for b in &beyond {
            let base = format!("state-{}-seq{}", b.file.trim_end_matches(".json"), b.seq);
            let preserved_as = Some(Self::preserve(&r.cfg, &base, "json", b.text.as_bytes())?);
            evidence.push(StateEvidence {
                file: b.file.clone(),
                seq: b.seq,
                hash: b.hash.map(|h| to_hex(&h)).unwrap_or_default(),
                preserved_as,
                sha256: to_hex(&sha256(b.text.as_bytes())),
            });
        }

        // 11. Copy damaged closed segments into quarantine (the originals
        //     stay until their records are durable).
        let mut q_records = Vec::new();
        for q in quarantine.iter().filter(|q| !q.recorded) {
            let c = &closed[q.pos];
            let file = Self::preserve(
                &r.cfg,
                &format!("damaged-seg{:016}", c.idx),
                "rbb",
                &c.bytes,
            )?;
            let what = if c.idx > last_idx {
                "segment file quarantined"
            } else {
                "closed segment failed verification"
            };
            // Authentic records beyond the head removed by a critical
            // quarantine: what they held is gone from the log, and nothing
            // explains it (see `explained_max`). Truncation evidence.
            if let Some(m) = q
                .max_auth
                .as_ref()
                .filter(|m| q.severity >= Severity::Critical && m.seq > head_rec.seq)
            {
                evidence.push(StateEvidence {
                    file: segment_file_name(c.idx),
                    seq: m.seq,
                    hash: to_hex(&m.hash),
                    preserved_as: Some(file.clone()),
                    sha256: q.sha.clone(),
                });
            }
            q_records.push(RecoveryPayload {
                segment_index: c.idx,
                offset: 0,
                discarded_bytes: c.bytes.len() as u64,
                discarded_sha256: q.sha.clone(),
                reason: format!("{what}: {}", q.reason),
                quarantine_file: Some(file),
                discarded_records: q.records,
                discarded_seqs: q.range,
                crash_plausible: false,
                severity: Some(q.severity),
                quarantined_segment: true,
            });
        }
        if !quarantine.is_empty() {
            fault("quarantine.after_copy")?;
        }
        // The same for authentic records after a hole in the active
        // segment that no crash explains.
        if let (Some(rp), Some(top)) = (recovery.as_ref(), lost_top.as_ref()) {
            if !rp.crash_plausible {
                evidence.push(StateEvidence {
                    file: segment_file_name(last_idx),
                    seq: top.seq,
                    hash: to_hex(&top.hash),
                    preserved_as: rp.quarantine_file.clone(),
                    sha256: rp.discarded_sha256.clone(),
                });
            }
        }

        // What the host should hear about (each is also a record below).
        if let Some(rp) = recovery.as_ref().filter(|rp| rp.discarded_records > 0) {
            r.open_incidents.push(OpenIncident::DamageQuarantined {
                segment_index: rp.segment_index,
                severity: rp.severity.unwrap_or(Severity::High),
                crash_plausible: rp.crash_plausible,
                reason: rp.reason.clone(),
            });
        }
        for rp in &q_records {
            r.open_incidents.push(OpenIncident::SegmentQuarantined {
                segment_index: rp.segment_index,
                severity: rp.severity.unwrap_or(Severity::Critical),
                reason: rp.reason.clone(),
            });
        }
        if let (false, Some(s)) = (evidence.is_empty(), skipped) {
            r.open_incidents.push(OpenIncident::TruncationDetected {
                head_seq: head_rec.seq,
                skipped_seqs: s,
                evidence: evidence
                    .iter()
                    .map(|e| format!("{} names seq {}", e.file, e.seq))
                    .collect(),
            });
        }

        // 12. Record what was found. The first record written takes the seq
        //     jump; a `Resume` that declares it is the only in-segment jump
        //     the recorder accepts at the next open.
        if need_segment_start {
            r.write_segment_start()?;
        }
        let resume = ResumePayload {
            boot_id: r.cfg.boot_id.clone(),
            chain_boot_id,
            resumed_after_seq: head_rec.seq,
            recovered: recovery.is_some() || !q_records.is_empty(),
            missing_segments: missing.clone(),
            rejected_state: rejected,
            skipped_seqs: skipped,
            refused_noncritical,
            refused_critical,
        };
        r.write_record(RecordKind::Resume, to_json(&resume)?, true, true)?;
        if let Some(rec) = recovery {
            r.write_record(RecordKind::Recovery, to_json(&rec)?, true, true)?;
        }
        for rec in &q_records {
            r.write_record(RecordKind::Recovery, to_json(rec)?, true, true)?;
        }
        if !evidence.is_empty() {
            let p = to_json(&TruncationPayload {
                head_seq: head_rec.seq,
                head_hash: to_hex(&head_rec.hash),
                evidence,
                skipped_seqs: skipped.expect("evidence implies a floor"),
                severity: Severity::Critical,
            })?;
            r.write_record(RecordKind::TruncationDetected, p, true, true)?;
        }
        for idx in missing {
            let p = to_json(&SegmentDroppedPayload {
                segment_index: idx,
                reason: DropReason::Missing,
                first_seq: None,
                last_seq: None,
                last_hash: None,
                records: 0,
                exported: false,
                missing: true,
            })?;
            r.write_record(RecordKind::SegmentDropped, p, true, true)?;
        }

        // 13. The quarantine is recorded (and synced): remove the originals.
        if !quarantine.is_empty() {
            fault("quarantine.after_records")?;
            for q in &quarantine {
                match fs::remove_file(&closed[q.pos].path) {
                    Ok(()) => {}
                    Err(e) if e.kind() == io::ErrorKind::NotFound => {}
                    Err(e) => return Err(e.into()),
                }
                r.quarantined_now.push(closed[q.pos].idx);
                fault("quarantine.after_unlink")?;
            }
            sync_dir(&r.cfg.dir)?;
        }
        // The recovery (or the truncation the pin proved) is on record.
        match fs::remove_file(r.cfg.dir.join(RECOVERY_PIN_FILE)) {
            Ok(()) => sync_dir(&r.cfg.dir)?,
            Err(e) if e.kind() == io::ErrorKind::NotFound => {}
            Err(e) => return Err(e.into()),
        }
        r.mark_best_effort();
        Ok(r)
    }

    /// Parse and authenticate a persisted export cursor. `Err((Some(a), _))`:
    /// authentic and of this chain, but beyond the head (truncation evidence).
    fn check_cursor(&self, s: &str) -> Result<Anchor, (Option<Anchor>, String)> {
        let c = SignedCursor::from_json(s).ok_or((None, "unparseable or unsigned".to_string()))?;
        if !self.keys().sig(&cursor_signing_message(&c.anchor), &c.sig) {
            return Err((
                None,
                "signature does not verify under this recorder's key".into(),
            ));
        }
        match self.check_position(&c.anchor) {
            // Authentic (our signature) and inside a segment quarantined at
            // open: it can only stop the recorder re-exporting records that
            // are gone anyway.
            PosCheck::Ok | PosCheck::Quarantined => Ok(c.anchor),
            PosCheck::Beyond(_) => Err((Some(c.anchor), String::new())),
            PosCheck::Mismatch(why) | PosCheck::Unknown(why) => Err((None, why)),
        }
    }

    /// Is `a` a real position of this chain, no later than the head?
    fn validate_position(&self, a: &Anchor) -> Result<(), String> {
        match self.check_position(a) {
            PosCheck::Ok => Ok(()),
            PosCheck::Beyond(w) | PosCheck::Mismatch(w) | PosCheck::Unknown(w) => Err(w),
            PosCheck::Quarantined => {
                Err(format!("seq {} is in a segment quarantined at open", a.seq))
            }
        }
    }

    /// Checked against authenticated data only: the head, the retained
    /// segments' authenticated first records (whose `prev_hash` is the hash
    /// of the record before), or the record itself, re-read and verified.
    /// A position older than all retained evidence cannot be checked and is
    /// accepted: no retained record is at or before it, so it can make the
    /// recorder neither prune nor skip anything.
    fn check_position(&self, a: &Anchor) -> PosCheck {
        if a.chain_id != self.chain_id {
            return PosCheck::Mismatch("belongs to another chain".into());
        }
        let Some((hs, hh)) = self.head else {
            return PosCheck::Unknown("log is empty".into());
        };
        if a.seq > hs {
            return PosCheck::Beyond(format!("seq {} is beyond the head {hs}", a.seq));
        }
        if a.seq == hs {
            return if a.hash == hh {
                PosCheck::Ok
            } else {
                PosCheck::Mismatch(format!("hash differs from the head record {hs}"))
            };
        }
        let starts: Vec<(u64, u64, Hash)> = self
            .segments
            .iter()
            .filter_map(|s| s.start.map(|(seq, prev)| (s.index, seq, prev)))
            .collect();
        let mismatch = || PosCheck::Mismatch(format!("hash differs from record {}", a.seq));
        // A position right before some retained segment's first record.
        if let Some(&(_, _, prev)) = starts
            .iter()
            .find(|(_, seq, _)| a.seq.checked_add(1) == Some(*seq))
        {
            return if prev == a.hash {
                PosCheck::Ok
            } else {
                mismatch()
            };
        }
        let Some(&(idx, _, _)) = starts.iter().rev().find(|(_, seq, _)| *seq <= a.seq) else {
            return PosCheck::Ok; // older than all retained evidence
        };
        let in_quarantine = self
            .quarantined_ranges
            .iter()
            .any(|[lo, hi]| (*lo..=*hi).contains(&a.seq));
        let bytes = match fs::read(self.cfg.dir.join(segment_file_name(idx))) {
            Ok(b) => b,
            Err(e) => return PosCheck::Unknown(format!("cannot read segment {idx}: {e}")),
        };
        let keys = self.keys();
        for it in scan_frames(&bytes).items {
            if let ScanItem::Record(sr) = it {
                let r = sr.record;
                if r.seq == a.seq && r.chain_id == self.chain_id && keys.record(&r) {
                    return if r.hash == a.hash {
                        PosCheck::Ok
                    } else {
                        mismatch()
                    };
                }
            }
        }
        if in_quarantine {
            return PosCheck::Quarantined;
        }
        PosCheck::Unknown(format!("no authentic record {} in segment {idx}", a.seq))
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
                    .ok_or_else(|| Error::Config("sequence space exhausted".into()))?
                    .max(self.seq_floor.unwrap_or(0)),
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
        if self.seg_records == 0 {
            if let Some(s) = self.segments.back_mut() {
                if s.index == self.seg_index && s.start.is_none() {
                    s.start = Some((seq, prev_hash));
                }
            }
        }
        self.seq_floor = None;
        self.seg_len += frame.len() as u64;
        self.seg_records += 1;
        self.head = Some((seq, rec.hash));
        self.head_sig.clone_from(&rec.sig);
        self.head_mono = rec.time.mono_ns;
        self.since_mark += 1;
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
        let signing_key = (self.signer.key_id() != self.identity.key_id
            || self.signer.algorithm() != self.identity.algorithm)
            .then(|| KeyRef {
                key_id: self.signer.key_id().to_string(),
                algorithm: self.signer.algorithm().to_string(),
            });
        let p = to_json(&SegmentStartPayload {
            identity: self.identity.clone(),
            segment_index: self.seg_index,
            boot_id: self.cfg.boot_id.clone(),
            signing_key,
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
            refused_noncritical: self.refused_noncritical,
            refused_critical: self.refused_critical,
        })?;
        let w = self.write_record(RecordKind::Seal, p, true, true)?;
        self.since_seal = 0;
        self.last_seal_seq = Some(w.seq);
        let cp = Checkpoint {
            chain_id: self.chain_id,
            seq: w.seq,
            hash: w.hash,
            key_id: self.signer.key_id().to_string(),
            sig: w.sig,
        };
        atomic_write(&self.cfg.dir, CHECKPOINT_FILE, cp.to_json().as_bytes())?;
        self.last_checkpoint = Some(cp.clone());
        self.mark_best_effort();
        Ok(cp)
    }

    /// Write the `head.json` high-water mark for the current head (and
    /// advance the external anchor): fsync the segment first, so the mark
    /// never names a record a crash can take away. No-op if the head is
    /// already marked.
    fn write_head_mark(&mut self) -> Result<(), Error> {
        let Some((seq, hash)) = self.head else {
            return Ok(());
        };
        if self.mark_seq.is_some_and(|m| m >= seq) {
            return Ok(());
        }
        self.sync()?;
        fault("mark.after_sync")?;
        let cp = Checkpoint {
            chain_id: self.chain_id,
            seq,
            hash,
            key_id: self.signer.key_id().to_string(),
            sig: self.head_sig.clone(),
        };
        atomic_write(&self.cfg.dir, HEAD_FILE, cp.to_json().as_bytes())?;
        self.mark_seq = Some(seq);
        self.since_mark = 0;
        self.last_mark_mono = self.head_mono;
        if let Some(a) = &self.cfg.head_anchor {
            if let Err(e) = a.advance(&cp) {
                self.anchor_failures += 1;
                self.last_anchor_error = Some(e);
            }
        }
        Ok(())
    }

    /// [`Recorder::write_head_mark`] where a failure must not fail the
    /// operation that triggered it (the record is already written): it is
    /// counted ([`Recorder::mark_failures`]) and retried at the next mark.
    fn mark_best_effort(&mut self) {
        if self.poisoned {
            return;
        }
        if self.write_head_mark().is_err() {
            self.mark_failures += 1;
            // An injected crash must stop the recorder like a dead process,
            // not be absorbed as a failed mark.
            #[cfg(test)]
            if fault::fired() {
                self.poisoned = true;
            }
        }
    }

    /// Mark if `head_mark_every_records` records or `head_mark_interval_ns`
    /// of record time have passed since the last mark.
    fn maybe_mark(&mut self) {
        let n = self.cfg.head_mark_every_records;
        let t = self.cfg.head_mark_interval_ns;
        let due = (n > 0 && self.since_mark >= n)
            || (t > 0 && self.head_mono.saturating_sub(self.last_mark_mono) >= t);
        if due {
            self.mark_best_effort();
        }
    }

    /// Write the high-water mark now (fsync + atomic replace of
    /// `head.json`, then the external anchor). Call it from a timer to bound
    /// the unmarked window in time while no records arrive. A failing
    /// external anchor is counted, not returned.
    pub fn mark_head(&mut self) -> Result<(), Error> {
        if self.poisoned {
            return Err(Error::Poisoned);
        }
        self.write_head_mark()
    }

    /// Write a seal now and return its checkpoint. Export the checkpoint off
    /// the unit (or into TPM NV) to make tail truncation detectable.
    pub fn seal(&mut self) -> Result<Checkpoint, Error> {
        self.seal_with(SealReason::Manual)
    }

    /// Rotate the signing key, keeping the chain.
    ///
    /// Writes a [`RecordKind::KeyRotation`] record signed by the **current**
    /// key that names the new one, switches to `new_signer` for every later
    /// record, and writes a seal (reason `key_rotation`) under the new key;
    /// returns that seal's checkpoint. The chain id keeps naming the key the
    /// chain was created with; every later `SegmentStart` names the current
    /// key. The old key stays usable for authenticating what it signed in
    /// this run; after a restart pass it (or a [`crate::keys::Keyring`]) as
    /// `previous_keys` to [`Recorder::open_with_keys`] while segments it
    /// signed are retained. Verify across the rotation with a keyring that
    /// holds both keys.
    ///
    /// `new_verifier` is required when `new_signer` cannot verify its own
    /// signatures; it must match the signer and pass a self-test.
    pub fn rotate_key(
        &mut self,
        new_signer: Box<dyn Signer>,
        new_verifier: Option<Box<dyn Verifier>>,
        reason: &str,
    ) -> Result<Checkpoint, Error> {
        if self.poisoned {
            return Err(Error::Poisoned);
        }
        let ok_name = |s: &str| {
            !s.is_empty()
                && s.len() <= crate::sign::MAX_KEY_ID_LEN
                && s.bytes().all(|b| b.is_ascii_graphic())
        };
        if !ok_name(new_signer.key_id()) || !ok_name(new_signer.algorithm()) {
            return Err(Error::Config(
                "new signer needs a printable key id and algorithm".into(),
            ));
        }
        if new_signer.key_id() == self.signer.key_id() {
            return Err(Error::Config(
                "new key has the current key's id; rotation needs a new key id".into(),
            ));
        }
        if self
            .retired_signers
            .iter()
            .any(|s| s.key_id() == new_signer.key_id())
            || self
                .retired
                .iter()
                .any(|v| v.key_id() == new_signer.key_id())
        {
            return Err(Error::Config("new key id was used before".into()));
        }
        if let Some(v) = &new_verifier {
            if v.key_id() != new_signer.key_id() || v.algorithm() != new_signer.algorithm() {
                return Err(Error::Config(
                    "verifier does not match the new signer".into(),
                ));
            }
        }
        let probe = new_signer.sign(PROBE_MESSAGE).map_err(Error::Sign)?;
        let ok = match &new_verifier {
            Some(v) => v.verify(PROBE_MESSAGE, &probe),
            None => new_signer.verify_own(PROBE_MESSAGE, &probe) == Some(true),
        };
        if !ok {
            return Err(Error::Config(
                "self-test failed: the new key cannot authenticate its own signature".into(),
            ));
        }
        let p = to_json(&KeyRotationPayload {
            from: KeyRef {
                key_id: self.signer.key_id().to_string(),
                algorithm: self.signer.algorithm().to_string(),
            },
            to: KeyRef {
                key_id: new_signer.key_id().to_string(),
                algorithm: new_signer.algorithm().to_string(),
            },
            reason: reason
                .chars()
                .filter(|c| !c.is_control())
                .take(256)
                .collect(),
        })?;
        self.write_record(RecordKind::KeyRotation, p, true, true)?;
        let old = std::mem::replace(&mut self.signer, new_signer);
        if let Some(v) = std::mem::replace(&mut self.own_verifier, new_verifier) {
            self.retired.push(v);
        }
        self.retired_signers.push(old);
        self.seal_with(SealReason::KeyRotation)
    }

    /// Current signing key id (differs from `identity().key_id` after a
    /// [`Recorder::rotate_key`]).
    pub fn key_id(&self) -> &str {
        self.signer.key_id()
    }

    fn rotate(&mut self) -> Result<(), Error> {
        self.seal_with(SealReason::Rotation)?;
        fault("rotate.after_seal")?;
        if let Err(e) = self.file.sync_all() {
            self.poisoned = true;
            return Err(e.into());
        }
        let idx = self.seg_index + 1;
        let path = self.cfg.dir.join(segment_file_name(idx));
        let file = create_new_private(&path, true)?;
        fault("rotate.after_create")?;
        sync_dir(&self.cfg.dir)?;
        self.file = file;
        self.seg_index = idx;
        self.seg_len = 0;
        self.seg_records = 0;
        self.segments.push_back(SegInfo {
            index: idx,
            start: None,
        });
        self.write_segment_start()?;
        fault("rotate.after_segment_start")?;
        if let RetentionMode::Cyclic { max_segments } = self.cfg.mode {
            while self.segments.len() > max_segments as usize {
                self.drop_oldest(DropReason::Cyclic)?;
            }
        }
        Ok(())
    }

    /// `(seq, hash)` of the last record of retained segment `pos`, from the
    /// authenticated start of the segment after it. `None` if that segment
    /// is not the direct successor (gap) or has no record yet.
    fn segment_end(&self, pos: usize) -> Option<(u64, Hash)> {
        let cur = self.segments.get(pos)?;
        let next = self.segments.get(pos + 1)?;
        if next.index != cur.index + 1 {
            return None;
        }
        let (seq, prev) = next.start?;
        Some((seq.checked_sub(1)?, prev))
    }

    /// The position up to which deletion is allowed: the last valid receiver
    /// ack in ack mode, else the (signed, validated) export cursor.
    fn confirmed_export(&self) -> Option<&Anchor> {
        if self.ack_verifier.is_some() {
            self.acked.as_ref()
        } else {
            self.export_cursor.as_ref()
        }
    }

    /// Record the drop of the oldest segment, then delete it. The anchor in
    /// the record comes from the recorder's authenticated in-memory state,
    /// never from the bytes of the file being deleted.
    fn drop_oldest(&mut self, reason: DropReason) -> Result<(), Error> {
        let Some(&front) = self.segments.front() else {
            return Ok(());
        };
        if front.index == self.seg_index {
            return Ok(());
        }
        let idx = front.index;
        let path = self.cfg.dir.join(segment_file_name(idx));
        let missing = match fs::symlink_metadata(&path) {
            Ok(_) => false,
            Err(e) if e.kind() == io::ErrorKind::NotFound => true,
            Err(e) => return Err(e.into()),
        };
        let first_seq = front.start.map(|(s, _)| s);
        let end = self.segment_end(0);
        let last_seq = end.map(|(s, _)| s);
        let exported = match (self.confirmed_export(), last_seq) {
            (Some(c), Some(l)) => c.seq >= l,
            _ => false,
        };
        let records = match (first_seq, last_seq) {
            (Some(f), Some(l)) if l >= f => l - f + 1,
            _ => 0,
        };
        let p = to_json(&SegmentDroppedPayload {
            segment_index: idx,
            reason,
            first_seq,
            last_seq,
            last_hash: end.map(|(_, h)| to_hex(&h)),
            records,
            exported,
            missing,
        })?;
        self.write_record(RecordKind::SegmentDropped, p, true, true)?;
        fault("drop.after_record")?;
        if !missing {
            match fs::remove_file(&path) {
                Ok(()) => {}
                Err(e) if e.kind() == io::ErrorKind::NotFound => {}
                Err(e) => return Err(e.into()),
            }
            fault("drop.after_unlink")?;
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
        // The record plus the seals that may still have to go into this
        // segment after it (see `SEAL_RESERVE` and the README, "Segment
        // size").
        let est = frame_estimate(payload.len() as u64) + SEAL_RESERVE;
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
        self.maybe_mark();
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
        'outer: for idx in self.segments.iter().map(|s| s.index) {
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

    /// Advance the export cursor to the end of `bundle` (persisted atomically,
    /// signed with the recorder's key). The bundle's last record must be an
    /// authentic record of this chain no later than the head
    /// ([`Error::Untrusted`] otherwise).
    ///
    /// Outside ack mode this cursor also bounds [`Recorder::prune_exported`];
    /// in ack mode only [`Recorder::apply_ack`] does.
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
        self.validate_position(&a)
            .map_err(|why| Error::Untrusted(format!("bundle end: {why}")))?;
        let sig = self
            .signer
            .sign(&cursor_signing_message(&a))
            .map_err(Error::Sign)?;
        let c = SignedCursor {
            anchor: a.clone(),
            sig,
        };
        atomic_write(&self.cfg.dir, CURSOR_FILE, c.to_json().as_bytes())?;
        self.export_cursor = Some(a);
        Ok(())
    }

    /// Switch to *ack mode*: from now on [`Recorder::prune_exported`] (and
    /// the `exported` flag of drop records) only trusts receiver
    /// acknowledgements verified with `verifier` (the receiver's key), never
    /// the local export cursor. Loads a previously persisted ack
    /// ([`ACK_FILE`]) if it authenticates; returns `Some(reason)` if one was
    /// present but rejected (it is then ignored: nothing is pruned on its
    /// account).
    pub fn require_export_acks(
        &mut self,
        verifier: Box<dyn Verifier>,
    ) -> Result<Option<String>, Error> {
        self.ack_verifier = Some(verifier);
        self.acked = None;
        let Some(s) = read_state(&self.cfg.dir, ACK_FILE)? else {
            return Ok(None);
        };
        match Ack::from_json(&s) {
            None => Ok(Some(format!("{ACK_FILE}: unparseable"))),
            Some(ack) => match self.check_ack(&ack) {
                Ok(()) => {
                    self.acked = Some(ack.anchor());
                    Ok(None)
                }
                Err(why) => Ok(Some(format!("{ACK_FILE}: {why}"))),
            },
        }
    }

    fn check_ack(&self, ack: &Ack) -> Result<(), String> {
        let v = self
            .ack_verifier
            .as_ref()
            .ok_or("ack mode is not enabled")?;
        if !ack.verify(&**v) {
            return Err("signature does not verify under the receiver key".into());
        }
        self.validate_position(&ack.anchor())
    }

    /// Apply a receiver acknowledgement (ack mode only). Verifies the
    /// receiver's signature and that the acknowledged position is an
    /// authentic record of this chain no later than the head; persists it
    /// atomically. Returns whether the acknowledged position advanced.
    pub fn apply_ack(&mut self, ack: &Ack) -> Result<bool, Error> {
        if self.ack_verifier.is_none() {
            return Err(Error::Config(
                "ack mode is not enabled; call require_export_acks first".into(),
            ));
        }
        self.check_ack(ack).map_err(Error::Untrusted)?;
        if self.acked.as_ref().is_some_and(|a| a.seq >= ack.seq) {
            return Ok(false);
        }
        atomic_write(&self.cfg.dir, ACK_FILE, ack.to_json().as_bytes())?;
        self.acked = Some(ack.anchor());
        Ok(true)
    }

    /// Delete closed segments whose records have all been exported (each
    /// deletion is recorded). "Exported" means: covered by the last valid
    /// receiver ack in ack mode, else by the signed export cursor. Ends
    /// saturation if space is freed. Returns the number of segments deleted.
    pub fn prune_exported(&mut self) -> Result<usize, Error> {
        let Some(cursor) = self.confirmed_export().cloned() else {
            return Ok(0);
        };
        let mut pruned = 0;
        while let Some(&front) = self.segments.front() {
            if front.index == self.seg_index {
                break;
            }
            match self.segment_end(0) {
                Some((last, _)) if last <= cursor.seq => {}
                _ => break,
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
        self.segments.iter().map(|s| s.index).collect()
    }
    pub fn is_saturated(&self) -> bool {
        self.saturated
    }
    /// `(non-critical, critical)` records refused since saturation began.
    pub fn refused(&self) -> (u64, u64) {
        (self.refused_noncritical, self.refused_critical)
    }
    /// Last position handed to [`Recorder::mark_exported`] (validated).
    pub fn export_cursor(&self) -> Option<&Anchor> {
        self.export_cursor.as_ref()
    }
    /// Last position acknowledged by the receiver (ack mode only).
    pub fn acked_position(&self) -> Option<&Anchor> {
        self.acked.as_ref()
    }
    /// Whether [`Recorder::require_export_acks`] is in effect.
    pub fn ack_mode(&self) -> bool {
        self.ack_verifier.is_some()
    }
    pub fn last_checkpoint(&self) -> Option<&Checkpoint> {
        self.last_checkpoint.as_ref()
    }
    pub fn dir(&self) -> &Path {
        &self.cfg.dir
    }
    /// Seq of the last `head.json` high-water mark written (or found valid
    /// at open).
    pub fn head_mark(&self) -> Option<u64> {
        self.mark_seq
    }
    /// High-water marks that could not be written (recording went on).
    pub fn mark_failures(&self) -> u64 {
        self.mark_failures
    }
    /// External anchor calls that failed (recording went on).
    pub fn anchor_failures(&self) -> u64 {
        self.anchor_failures
    }
    /// The last external anchor error, if any.
    pub fn last_anchor_error(&self) -> Option<&str> {
        self.last_anchor_error.as_deref()
    }
    /// Segment files this open found damaged (closed segments, or stray
    /// files above the live segment) and moved to quarantine (a `Recovery`
    /// record with `quarantined_segment` documents each). Worth an alert:
    /// the storage is failing or someone edited the log. See
    /// [`Recorder::open_incidents`] for severities and truncation.
    pub fn quarantined_at_open(&self) -> &[u64] {
        &self.quarantined_now
    }

    /// Evidence trouble this open found (quarantines with their severity,
    /// truncation), in the order the records were written. Empty for a
    /// clean open.
    pub fn open_incidents(&self) -> &[OpenIncident] {
        &self.open_incidents
    }
}

/// Read a small state file; `None` if absent. Symlinks are not followed.
fn read_state(dir: &Path, name: &str) -> Result<Option<String>, Error> {
    use std::io::Read;
    let mut o = OpenOptions::new();
    o.read(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        o.custom_flags(sys::O_NOFOLLOW);
    }
    let mut f = match o.open(dir.join(name)) {
        Ok(f) => f,
        Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(None),
        // A symlink (ELOOP) or unreadable file: treat as unusable content.
        Err(_) => return Ok(Some(String::new())),
    };
    let mut s = String::new();
    if Read::by_ref(&mut f)
        .take(64 * 1024)
        .read_to_string(&mut s)
        .is_err()
    {
        s.clear();
    }
    Ok(Some(s))
}

#[cfg(test)]
#[path = "store_crash_tests.rs"]
mod crash_tests;

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
    fn seal_payload_fits_its_reserve() {
        for reason in [
            SealReason::Periodic,
            SealReason::Rotation,
            SealReason::Export,
            SealReason::Shutdown,
            SealReason::Manual,
            SealReason::KeyRotation,
        ] {
            let p = to_json(&SealPayload {
                reason,
                segment_index: u64::MAX,
                records_since_last_seal: u64::MAX,
                prev_seal_seq: Some(u64::MAX),
                refused_noncritical: u64::MAX,
                refused_critical: u64::MAX,
            })
            .unwrap();
            assert!(p.len() as u64 <= SEAL_PAYLOAD_MAX, "{} bytes", p.len());
        }
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
