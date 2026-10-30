//! Record model, canonical encoding and on-disk framing.
//!
//! # Canonical record encoding (format version 1)
//!
//! The *hashed fields* of a record are, in order, with all integers
//! big-endian and fixed width:
//!
//! | field        | size       | notes                                         |
//! |--------------|------------|-----------------------------------------------|
//! | version      | u8         | `1`                                           |
//! | chain_id     | 32 bytes   | SHA-256 of the chain identity (see below)     |
//! | seq          | u64        | 0 for genesis, +1 per record                  |
//! | wall_ns      | u64        | ns since Unix epoch (trust per time_source)   |
//! | mono_ns      | u64        | monotonic ns within one recorder run          |
//! | time_source  | u8         | 0 unknown, 1 rtc, 2 gps, 3 ptp                |
//! | kind         | u8         | [`RecordKind`] code                           |
//! | flags        | u8         | bit 0 = critical; other bits must be 0        |
//! | payload_len  | u32        |                                               |
//! | payload      | var        | opaque bytes (UTF-8 JSON by convention)       |
//! | prev_hash    | 32 bytes   | `hash` of record `seq-1`; zeros for genesis   |
//!
//! `hash = SHA-256("robodr-blackbox/record/v1\0" || hashed_fields)`.
//! `sig  = Signer::sign("robodr-blackbox/sig/v1\0" || hash)`.
//!
//! Only one field is variable-length and it is length-prefixed, so the encoding
//! is injective: two different records cannot share hashed bytes. The payload
//! is hashed **exactly as stored**; it is never re-serialised, so serde_json map
//! ordering or float formatting can never change a hash.
//!
//! # Frame (what is stored in a segment file)
//!
//! `"RBF1" | body_len: u32 | body`, where
//! `body = hashed_fields | hash (32) | sig_len: u16 | sig`.
//! The stored bytes *are* the canonical bytes; parsing is strict (no trailing
//! bytes, no unknown codes), so decode followed by encode is the identity.

use crate::crypto::{to_hex, Sha256};
use crate::time::{TimeSource, Timestamp};
use robodr_events::Severity;
use serde::{Deserialize, Serialize};

/// A SHA-256 digest.
pub type Hash = [u8; 32];
/// `prev_hash` of the genesis record.
pub const ZERO_HASH: Hash = [0; 32];
/// Current record format version.
pub const FORMAT_VERSION: u8 = 1;
/// Frame magic.
pub const FRAME_MAGIC: [u8; 4] = *b"RBF1";
/// Frame header length (magic + body length).
pub const FRAME_HEADER_LEN: usize = 8;
/// Upper bound on a frame body; larger declared lengths are malformed.
pub const MAX_FRAME_BODY: usize = 16 * 1024 * 1024;
/// Upper bound on a signature (Ed25519 = 64, ECDSA-P256 DER <= 72, HMAC = 32).
pub const MAX_SIG_LEN: usize = 1024;
/// Size of the fixed part of the hashed fields (everything but the payload).
pub const FIXED_FIELDS_LEN: usize = 1 + 32 + 8 + 8 + 8 + 1 + 1 + 1 + 4 + 32;

const FLAG_CRITICAL: u8 = 0x01;
const RECORD_DOMAIN: &[u8] = b"robodr-blackbox/record/v1\0";
const SIG_DOMAIN: &[u8] = b"robodr-blackbox/sig/v1\0";
const CHAIN_DOMAIN: &[u8] = b"robodr-blackbox/chain/v1\0";

/// What a record is. Codes < 16 are recorder control records; >= 16 carry
/// caller evidence.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RecordKind {
    /// seq 0; payload [`GenesisPayload`].
    Genesis,
    /// First record of every later segment; payload [`SegmentStartPayload`].
    SegmentStart,
    /// Checkpoint; payload [`SealPayload`].
    Seal,
    /// Recorder (re)opened an existing log; payload [`ResumePayload`].
    Resume,
    /// A torn tail was truncated at open; payload [`RecoveryPayload`].
    Recovery,
    /// A segment was deleted by retention; payload [`SegmentDroppedPayload`].
    SegmentDropped,
    /// Storage full in saturation mode; payload [`SaturationPayload`].
    Saturation,
    /// Saturation ended; payload [`SaturationClearedPayload`].
    SaturationCleared,
    /// At open, authenticated local state (checkpoint, export cursor) proved
    /// that records beyond the log's head existed: the log was truncated.
    /// Always critical; payload [`TruncationPayload`].
    TruncationDetected,
    /// The signing key changed; signed by the *old* key, every later record
    /// by the new one. Payload [`KeyRotationPayload`].
    KeyRotation,
    /// A `robodr_events::RobotEvent` (JSON).
    Event,
    /// A `robodr_events::Deviation` (JSON).
    Deviation,
    /// Free-form JSON evidence.
    Note,
}

impl RecordKind {
    pub fn to_u8(self) -> u8 {
        match self {
            RecordKind::Genesis => 0,
            RecordKind::SegmentStart => 1,
            RecordKind::Seal => 2,
            RecordKind::Resume => 3,
            RecordKind::Recovery => 4,
            RecordKind::SegmentDropped => 5,
            RecordKind::Saturation => 6,
            RecordKind::SaturationCleared => 7,
            RecordKind::TruncationDetected => 8,
            RecordKind::KeyRotation => 9,
            RecordKind::Event => 16,
            RecordKind::Deviation => 17,
            RecordKind::Note => 18,
        }
    }

    pub fn from_u8(v: u8) -> Option<Self> {
        Some(match v {
            0 => RecordKind::Genesis,
            1 => RecordKind::SegmentStart,
            2 => RecordKind::Seal,
            3 => RecordKind::Resume,
            4 => RecordKind::Recovery,
            5 => RecordKind::SegmentDropped,
            6 => RecordKind::Saturation,
            7 => RecordKind::SaturationCleared,
            8 => RecordKind::TruncationDetected,
            9 => RecordKind::KeyRotation,
            16 => RecordKind::Event,
            17 => RecordKind::Deviation,
            18 => RecordKind::Note,
            _ => return None,
        })
    }

    /// Recorder-internal record (as opposed to caller evidence).
    pub fn is_control(self) -> bool {
        self.to_u8() < 16
    }
}

/// One black-box record.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Record {
    pub chain_id: Hash,
    pub seq: u64,
    pub time: Timestamp,
    pub kind: RecordKind,
    pub critical: bool,
    pub payload: Vec<u8>,
    pub prev_hash: Hash,
    pub hash: Hash,
    pub sig: Vec<u8>,
}

impl Record {
    /// Canonical hashed fields (see module docs).
    ///
    /// Payloads are bounded well below 4 GiB by the recorder and the parser,
    /// so the u32 length prefix is always exact.
    pub fn hashed_fields(&self) -> Vec<u8> {
        let mut v = Vec::with_capacity(FIXED_FIELDS_LEN + self.payload.len());
        v.push(FORMAT_VERSION);
        v.extend_from_slice(&self.chain_id);
        v.extend_from_slice(&self.seq.to_be_bytes());
        v.extend_from_slice(&self.time.wall_ns.to_be_bytes());
        v.extend_from_slice(&self.time.mono_ns.to_be_bytes());
        v.push(self.time.source.to_u8());
        v.push(self.kind.to_u8());
        v.push(if self.critical { FLAG_CRITICAL } else { 0 });
        v.extend_from_slice(&(self.payload.len() as u32).to_be_bytes());
        v.extend_from_slice(&self.payload);
        v.extend_from_slice(&self.prev_hash);
        v
    }

    /// Recompute the record hash from its fields.
    pub fn compute_hash(&self) -> Hash {
        let mut h = Sha256::new();
        h.update(RECORD_DOMAIN);
        h.update(&self.hashed_fields());
        h.finalize()
    }

    /// Encode the full frame (header + body).
    pub fn encode_frame(&self) -> Vec<u8> {
        let fields = self.hashed_fields();
        let body_len = fields.len() + 32 + 2 + self.sig.len();
        let mut out = Vec::with_capacity(FRAME_HEADER_LEN + body_len);
        out.extend_from_slice(&FRAME_MAGIC);
        out.extend_from_slice(&(body_len as u32).to_be_bytes());
        out.extend_from_slice(&fields);
        out.extend_from_slice(&self.hash);
        out.extend_from_slice(&(self.sig.len() as u16).to_be_bytes());
        out.extend_from_slice(&self.sig);
        out
    }

    /// Strictly decode a frame body. Does not check hash or signature.
    pub fn decode_body(body: &[u8]) -> Result<Record, String> {
        let mut c = Cur { b: body, p: 0 };
        let ver = c.u8()?;
        if ver != FORMAT_VERSION {
            return Err(format!("unsupported format version {ver}"));
        }
        let chain_id = c.hash()?;
        let seq = c.u64()?;
        let wall_ns = c.u64()?;
        let mono_ns = c.u64()?;
        let ts = c.u8()?;
        let source = TimeSource::from_u8(ts).ok_or_else(|| format!("unknown time source {ts}"))?;
        let k = c.u8()?;
        let kind = RecordKind::from_u8(k).ok_or_else(|| format!("unknown record kind {k}"))?;
        let flags = c.u8()?;
        if flags & !FLAG_CRITICAL != 0 {
            return Err(format!("unknown flag bits {flags:#04x}"));
        }
        let plen = c.u32()? as usize;
        let payload = c.take(plen)?;
        let prev_hash = c.hash()?;
        let hash = c.hash()?;
        let slen = c.u16()? as usize;
        if slen > MAX_SIG_LEN {
            return Err(format!("signature length {slen} exceeds {MAX_SIG_LEN}"));
        }
        let sig = c.take(slen)?;
        if c.p != body.len() {
            return Err(format!("{} trailing bytes in frame body", body.len() - c.p));
        }
        Ok(Record {
            chain_id,
            seq,
            time: Timestamp {
                wall_ns,
                mono_ns,
                source,
            },
            kind,
            critical: flags & FLAG_CRITICAL != 0,
            payload: payload.to_vec(),
            prev_hash,
            hash,
            sig: sig.to_vec(),
        })
    }

    /// Parse the payload as JSON (convenience for timelines and control records).
    pub fn payload_json<T: for<'de> Deserialize<'de>>(&self) -> Option<T> {
        serde_json::from_slice(&self.payload).ok()
    }
}

/// The message a [`crate::sign::Signer`] signs for a record with hash `hash`.
pub fn signing_message(hash: &Hash) -> Vec<u8> {
    let mut m = Vec::with_capacity(SIG_DOMAIN.len() + 32);
    m.extend_from_slice(SIG_DOMAIN);
    m.extend_from_slice(hash);
    m
}

struct Cur<'a> {
    b: &'a [u8],
    p: usize,
}

impl<'a> Cur<'a> {
    fn take(&mut self, n: usize) -> Result<&'a [u8], String> {
        let end = self
            .p
            .checked_add(n)
            .filter(|&e| e <= self.b.len())
            .ok_or_else(|| format!("truncated body: need {n} bytes at offset {}", self.p))?;
        let s = &self.b[self.p..end];
        self.p = end;
        Ok(s)
    }
    fn u8(&mut self) -> Result<u8, String> {
        Ok(self.take(1)?[0])
    }
    fn u16(&mut self) -> Result<u16, String> {
        let s = self.take(2)?;
        Ok(u16::from_be_bytes([s[0], s[1]]))
    }
    fn u32(&mut self) -> Result<u32, String> {
        let s = self.take(4)?;
        Ok(u32::from_be_bytes([s[0], s[1], s[2], s[3]]))
    }
    fn u64(&mut self) -> Result<u64, String> {
        let mut a = [0u8; 8];
        a.copy_from_slice(self.take(8)?);
        Ok(u64::from_be_bytes(a))
    }
    fn hash(&mut self) -> Result<Hash, String> {
        let mut a = [0u8; 32];
        a.copy_from_slice(self.take(32)?);
        Ok(a)
    }
}

// ---------------------------------------------------------------------------
// Frame scanning
// ---------------------------------------------------------------------------

/// A structurally valid frame found in a segment.
#[derive(Debug, Clone)]
pub struct ScannedRecord {
    /// Byte offset of the frame header within the segment.
    pub offset: u64,
    /// Total frame length including header.
    pub frame_len: u64,
    pub record: Record,
}

/// One element of a segment scan, in file order.
#[derive(Debug, Clone)]
pub enum ScanItem {
    Record(ScannedRecord),
    /// Bytes that do not form a valid frame, followed by at least one valid frame.
    Malformed {
        offset: u64,
        len: u64,
        reason: String,
    },
}

/// Classification of bytes after the last valid frame.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TailKind {
    /// A frame header/body that ends early: the signature of a torn write.
    Incomplete,
    /// All zero bytes (file extended but data never written).
    Zeros,
    /// Anything else.
    Garbage,
}

/// Bytes after the last valid frame of a segment.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Tail {
    pub offset: u64,
    pub len: u64,
    pub kind: TailKind,
}

/// Result of scanning one segment's bytes.
#[derive(Debug, Clone, Default)]
pub struct SegmentScan {
    pub items: Vec<ScanItem>,
    pub tail: Option<Tail>,
}

enum FrameAt {
    Ok(Record, usize),
    Bad(String),
    Incomplete,
}

fn try_frame(bytes: &[u8], pos: usize) -> FrameAt {
    let rem = &bytes[pos..];
    if rem.len() < FRAME_HEADER_LEN {
        let n = rem.len().min(4);
        return if rem[..n] == FRAME_MAGIC[..n] {
            FrameAt::Incomplete
        } else {
            FrameAt::Bad("bad frame magic".into())
        };
    }
    if rem[..4] != FRAME_MAGIC {
        return FrameAt::Bad("bad frame magic".into());
    }
    let len = u32::from_be_bytes([rem[4], rem[5], rem[6], rem[7]]) as usize;
    if len > MAX_FRAME_BODY {
        return FrameAt::Bad(format!("frame length {len} exceeds limit"));
    }
    if FRAME_HEADER_LEN + len > rem.len() {
        return FrameAt::Incomplete;
    }
    match Record::decode_body(&rem[FRAME_HEADER_LEN..FRAME_HEADER_LEN + len]) {
        Ok(r) => FrameAt::Ok(r, FRAME_HEADER_LEN + len),
        Err(e) => FrameAt::Bad(e),
    }
}

/// Next offset `> from` where a complete, decodable frame starts.
fn find_next_valid(bytes: &[u8], from: usize) -> Option<usize> {
    let mut i = from;
    while i + FRAME_HEADER_LEN <= bytes.len() {
        if bytes[i..i + 4] == FRAME_MAGIC {
            if let FrameAt::Ok(..) = try_frame(bytes, i) {
                return Some(i);
            }
        }
        i += 1;
    }
    None
}

/// Split a segment into frames, malformed regions and a trailing tail.
///
/// Never panics on hostile input. After a malformed region the scanner
/// resynchronises at the next offset holding a complete, decodable frame, so
/// a corrupted length field cannot swallow the records that follow it.
pub fn scan_frames(bytes: &[u8]) -> SegmentScan {
    let mut scan = SegmentScan::default();
    let mut pos = 0usize;
    while pos < bytes.len() {
        match try_frame(bytes, pos) {
            FrameAt::Ok(record, len) => {
                scan.items.push(ScanItem::Record(ScannedRecord {
                    offset: pos as u64,
                    frame_len: len as u64,
                    record,
                }));
                pos += len;
            }
            other => {
                let reason = match other {
                    FrameAt::Bad(r) => r,
                    _ => "frame overruns the following data".to_string(),
                };
                match find_next_valid(bytes, pos + 1) {
                    Some(next) => {
                        scan.items.push(ScanItem::Malformed {
                            offset: pos as u64,
                            len: (next - pos) as u64,
                            reason,
                        });
                        pos = next;
                    }
                    None => {
                        let rest = &bytes[pos..];
                        let kind = if rest.iter().all(|&b| b == 0) {
                            TailKind::Zeros
                        } else if let FrameAt::Incomplete = try_frame(bytes, pos) {
                            TailKind::Incomplete
                        } else {
                            TailKind::Garbage
                        };
                        scan.tail = Some(Tail {
                            offset: pos as u64,
                            len: rest.len() as u64,
                            kind,
                        });
                        break;
                    }
                }
            }
        }
    }
    scan
}

// ---------------------------------------------------------------------------
// Chain identity and control payloads
// ---------------------------------------------------------------------------

/// What a chain is bound to. `chain_id = SHA-256(domain || lp(device_id) ||
/// lp(boot_id) || lp(key_id) || lp(algorithm) || created_wall_ns)` with
/// `lp(x) = u32_be(len(x)) || x`; every record carries the chain id, so every
/// record is bound to the device, the boot that created the chain, and the key.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ChainIdentity {
    pub device_id: String,
    pub boot_id: String,
    pub key_id: String,
    pub algorithm: String,
    pub created_wall_ns: u64,
}

impl ChainIdentity {
    pub fn chain_id(&self) -> Hash {
        let mut h = Sha256::new();
        h.update(CHAIN_DOMAIN);
        for s in [
            &self.device_id,
            &self.boot_id,
            &self.key_id,
            &self.algorithm,
        ] {
            h.update(&(s.len() as u32).to_be_bytes());
            h.update(s.as_bytes());
        }
        h.update(&self.created_wall_ns.to_be_bytes());
        h.finalize()
    }
}

/// Payload of the genesis record.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct GenesisPayload {
    pub identity: ChainIdentity,
    pub recorder_version: String,
    pub format_version: u8,
}

/// Payload of a segment's first record; restates the identity so a retained
/// tail is self-describing after older segments are dropped.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SegmentStartPayload {
    pub identity: ChainIdentity,
    pub segment_index: u64,
    /// Boot during which this segment was opened.
    pub boot_id: String,
    /// Key that signs this segment's records when it differs from
    /// `identity.key_id` (after a [`RecordKind::KeyRotation`]). Lets the
    /// recorder and verifier name the current key of a retained tail whose
    /// rotation record was dropped. Omitted when equal to the chain key.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub signing_key: Option<KeyRef>,
    /// [`key_fingerprint`](crate::sign::key_fingerprint) of `signing_key`'s
    /// public key (payload v2; absent in older logs and for keys without a
    /// public half). A verifier that knows the key checks it.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub signing_key_fingerprint: Option<String>,
}

/// A signing key by id and algorithm.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct KeyRef {
    pub key_id: String,
    pub algorithm: String,
}

/// Why a seal was written.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SealReason {
    Periodic,
    Rotation,
    Export,
    Shutdown,
    Manual,
    /// Written right after a [`RecordKind::KeyRotation`], under the new key.
    KeyRotation,
}

/// Payload of a seal checkpoint.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SealPayload {
    pub reason: SealReason,
    pub segment_index: u64,
    pub records_since_last_seal: u64,
    pub prev_seal_seq: Option<u64>,
    /// Non-critical appends refused since saturation began (persisted so a
    /// restart does not lose them). Omitted when zero.
    #[serde(default, skip_serializing_if = "is_zero")]
    pub refused_noncritical: u64,
    /// Critical appends refused (reserve full) since saturation began.
    #[serde(default, skip_serializing_if = "is_zero")]
    pub refused_critical: u64,
}

fn is_zero(v: &u64) -> bool {
    *v == 0
}

/// Payload written each time the recorder opens an existing log.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ResumePayload {
    /// Current boot.
    pub boot_id: String,
    /// Boot that created the chain.
    pub chain_boot_id: String,
    pub resumed_after_seq: u64,
    pub recovered: bool,
    /// Segment indices the recorder expected but did not find at open (a
    /// gap in the retained indices, or a missing predecessor of the oldest
    /// retained segment with no recorded drop). Each is also recorded as a
    /// `SegmentDropped { missing: true }`. Omitted when empty.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub missing_segments: Vec<u64>,
    /// State files (export cursor, ...) found but rejected because they did
    /// not authenticate or did not match the chain. Omitted when empty.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub rejected_state: Vec<String>,
    /// Sequence numbers `[first, last]` this resume skipped so that none is
    /// ever reused: they belonged to records that were lost (truncated or
    /// quarantined) but may already exist elsewhere (exported bundles, an
    /// off-unit checkpoint). The record carrying this payload is the only
    /// record allowed to follow its predecessor with a seq jump.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub skipped_seqs: Option<[u64; 2]>,
    /// Refusal counters carried over from before the restart (see
    /// [`SealPayload::refused_noncritical`]). Omitted when zero.
    #[serde(default, skip_serializing_if = "is_zero")]
    pub refused_noncritical: u64,
    #[serde(default, skip_serializing_if = "is_zero")]
    pub refused_critical: u64,
}

/// Payload recording a torn-tail truncation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RecoveryPayload {
    pub segment_index: u64,
    pub offset: u64,
    pub discarded_bytes: u64,
    /// SHA-256 of the discarded bytes, hex.
    pub discarded_sha256: String,
    pub reason: String,
    /// File (relative to the log dir) holding the discarded bytes.
    pub quarantine_file: Option<String>,
    /// Complete, authentic records of this chain inside the discarded bytes
    /// (non-zero only when damage in the middle of the segment forced the
    /// recorder to quarantine valid frames after it).
    #[serde(default, skip_serializing_if = "is_zero")]
    pub discarded_records: u64,
    /// `[first, last]` sequence numbers lost with the discarded bytes, when
    /// known (authentic records were found after the damage).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub discarded_seqs: Option<[u64; 2]>,
    /// Whether a crash can explain the damage. `false` when a record after
    /// the damage was durably synced (a seal, a control record, a critical
    /// record under `fsync_critical`, every record under `Always`): an fsync
    /// flushes every earlier page, so the hole cannot be lost write-back.
    #[serde(default = "yes")]
    pub crash_plausible: bool,
    /// `medium` for a torn tail, `high` when authentic records were
    /// quarantined, `critical` when the damage is not crash-plausible.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub severity: Option<Severity>,
    /// The whole *closed* segment `segment_index` failed verification at
    /// open and was moved to `quarantine_file` (`offset` is 0,
    /// `discarded_bytes` its size, `discarded_sha256` the hash of the
    /// file). `discarded_records` then counts frames with a valid hash and
    /// this chain's id; `discarded_seqs` spans the lowest and highest of them
    /// whose signature verified. Never crash-plausible: a closed segment was
    /// fsynced before its successor was created. Omitted when false.
    #[serde(default, skip_serializing_if = "is_false")]
    pub quarantined_segment: bool,
}

fn yes() -> bool {
    true
}

fn is_false(v: &bool) -> bool {
    !*v
}

/// One piece of authenticated local state that points beyond the head.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct StateEvidence {
    /// State file name (`checkpoint.json`, `export-cursor.json`).
    pub file: String,
    pub seq: u64,
    /// Hex hash the state file names for `seq`.
    pub hash: String,
    /// Copy of the file (relative to the log dir) kept as evidence before
    /// the recorder replaces it.
    pub preserved_as: Option<String>,
    /// SHA-256 (hex) of the preserved bytes.
    pub sha256: String,
}

/// Payload of [`RecordKind::TruncationDetected`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TruncationPayload {
    /// Last authentic record found in the log at open.
    pub head_seq: u64,
    pub head_hash: String,
    /// The state that proves records beyond `head_seq` existed.
    pub evidence: Vec<StateEvidence>,
    /// `[first, last]` sequence numbers never to be reused.
    pub skipped_seqs: [u64; 2],
    pub severity: Severity,
}

/// Payload of [`RecordKind::KeyRotation`] (signed by the old key, which
/// must be `from`).
///
/// Version 1 named the new key by id and algorithm only; version 2 adds
/// `to_fingerprint`, the SHA-256 of the new key's public key
/// ([`crate::sign::key_fingerprint`]), so the rotation commits to one key,
/// not to whatever key later carries that id. Absent: a v1 record (still
/// accepted) or a target without a public half (HMAC).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct KeyRotationPayload {
    pub from: KeyRef,
    pub to: KeyRef,
    pub reason: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub to_fingerprint: Option<String>,
}

/// Why a segment was deleted.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DropReason {
    /// Cyclic retention.
    Cyclic,
    /// Fully exported and pruned.
    Exported,
    /// Not deleted by the recorder: found missing when the recorder resumed
    /// (`missing` is then always `true`).
    Missing,
}

/// Payload recording a segment deletion. The `last_seq`/`last_hash` pair is
/// the anchor that lets the verifier accept the retained tail.
///
/// The recorder derives the anchor from its own authenticated state: the
/// signed `prev_hash` of the *next* segment's `SegmentStart` (which it wrote
/// itself, or verified at open), never from the bytes of the segment being
/// deleted. The verifier accepts a drop as covering the retained head only
/// if `segment_index` is the head segment's index minus one, `missing` is
/// false, and the anchor equals the head's `(seq - 1, prev_hash)`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SegmentDroppedPayload {
    pub segment_index: u64,
    pub reason: DropReason,
    pub first_seq: Option<u64>,
    pub last_seq: Option<u64>,
    /// Hex hash of the segment's last record.
    pub last_hash: Option<String>,
    pub records: u64,
    /// Whether every record in it had been exported.
    pub exported: bool,
    /// The file was already gone when the recorder came to delete it.
    pub missing: bool,
}

/// Payload written when saturation mode starts refusing records.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SaturationPayload {
    pub segments: u64,
    pub max_segments: u64,
    pub reserve_segments: u64,
}

/// Payload written when saturation ends (after an export prune).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SaturationClearedPayload {
    pub refused_noncritical: u64,
    pub refused_critical: u64,
}

/// Short hex for messages.
pub(crate) fn short_hex(h: &Hash) -> String {
    to_hex(&h[..8])
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample(seq: u64, payload: &[u8]) -> Record {
        let mut r = Record {
            chain_id: [7; 32],
            seq,
            time: Timestamp {
                wall_ns: 1_700_000_000_000_000_000,
                mono_ns: 42,
                source: TimeSource::Gps,
            },
            kind: RecordKind::Note,
            critical: true,
            payload: payload.to_vec(),
            prev_hash: [9; 32],
            hash: ZERO_HASH,
            sig: vec![1, 2, 3],
        };
        r.hash = r.compute_hash();
        r
    }

    #[test]
    fn kind_codes_round_trip() {
        for c in 0..=255u8 {
            if let Some(k) = RecordKind::from_u8(c) {
                assert_eq!(k.to_u8(), c);
                assert_eq!(k.is_control(), c < 16);
            }
        }
        assert_eq!(RecordKind::from_u8(8), Some(RecordKind::TruncationDetected));
        assert_eq!(RecordKind::from_u8(9), Some(RecordKind::KeyRotation));
        assert!(RecordKind::from_u8(10).is_none());
    }

    #[test]
    fn fixed_len_constant_matches_encoding() {
        assert_eq!(sample(0, b"").hashed_fields().len(), FIXED_FIELDS_LEN);
    }

    #[test]
    fn frame_round_trip_is_identity() {
        let r = sample(5, br#"{"a":1}"#);
        let f = r.encode_frame();
        let back = Record::decode_body(&f[FRAME_HEADER_LEN..]).unwrap();
        assert_eq!(back, r);
        assert_eq!(back.encode_frame(), f);
    }

    #[test]
    fn every_hashed_field_changes_the_hash() {
        let base = sample(1, b"x");
        let h = base.compute_hash();
        let mut variants = Vec::new();
        let mut r = base.clone();
        r.chain_id[0] ^= 1;
        variants.push(r);
        let mut r = base.clone();
        r.seq += 1;
        variants.push(r);
        let mut r = base.clone();
        r.time.wall_ns += 1;
        variants.push(r);
        let mut r = base.clone();
        r.time.mono_ns += 1;
        variants.push(r);
        let mut r = base.clone();
        r.time.source = TimeSource::Rtc;
        variants.push(r);
        let mut r = base.clone();
        r.kind = RecordKind::Event;
        variants.push(r);
        let mut r = base.clone();
        r.critical = false;
        variants.push(r);
        let mut r = base.clone();
        r.payload = b"y".to_vec();
        variants.push(r);
        let mut r = base.clone();
        r.prev_hash[31] ^= 1;
        variants.push(r);
        for v in variants {
            assert_ne!(v.compute_hash(), h);
        }
        // The signature is not hashed.
        let mut r = base.clone();
        r.sig = vec![9];
        assert_eq!(r.compute_hash(), h);
    }

    #[test]
    fn strict_decoding_rejects_bad_bodies() {
        let r = sample(1, b"abc");
        let f = r.encode_frame();
        let body = &f[FRAME_HEADER_LEN..];
        let mut extra = body.to_vec();
        extra.push(0);
        assert!(Record::decode_body(&extra)
            .unwrap_err()
            .contains("trailing"));
        let mut v = body.to_vec();
        v[0] = 2;
        assert!(Record::decode_body(&v).unwrap_err().contains("version"));
        let mut v = body.to_vec();
        v[1 + 32 + 24] = 9; // time source
        assert!(Record::decode_body(&v).is_err());
        let mut v = body.to_vec();
        v[1 + 32 + 24 + 1] = 99; // kind
        assert!(Record::decode_body(&v).is_err());
        let mut v = body.to_vec();
        v[1 + 32 + 24 + 2] = 0x80; // flags
        assert!(Record::decode_body(&v).is_err());
        for cut in 0..body.len() {
            assert!(Record::decode_body(&body[..cut]).is_err());
        }
    }

    #[test]
    fn scan_classifies_tails_and_resyncs() {
        let a = sample(1, b"a").encode_frame();
        let b = sample(2, b"b").encode_frame();
        // Clean.
        let mut seg = a.clone();
        seg.extend_from_slice(&b);
        let s = scan_frames(&seg);
        assert_eq!(s.items.len(), 2);
        assert!(s.tail.is_none());
        // Torn: partial second frame.
        let mut torn = a.clone();
        torn.extend_from_slice(&b[..b.len() - 5]);
        let s = scan_frames(&torn);
        assert_eq!(s.items.len(), 1);
        assert_eq!(s.tail.unwrap().kind, TailKind::Incomplete);
        assert_eq!(s.tail.unwrap().offset, a.len() as u64);
        // Partial magic only.
        let mut torn = a.clone();
        torn.extend_from_slice(b"RB");
        assert_eq!(scan_frames(&torn).tail.unwrap().kind, TailKind::Incomplete);
        // Zeros.
        let mut z = a.clone();
        z.extend_from_slice(&[0; 40]);
        assert_eq!(scan_frames(&z).tail.unwrap().kind, TailKind::Zeros);
        // Garbage.
        let mut g = a.clone();
        g.extend_from_slice(b"hello world, not a frame");
        assert_eq!(scan_frames(&g).tail.unwrap().kind, TailKind::Garbage);
        // Corrupted length in the middle: resync on the next frame.
        let mut m = a.clone();
        m[4..8].copy_from_slice(&u32::MAX.to_be_bytes());
        m.extend_from_slice(&b);
        let s = scan_frames(&m);
        assert!(matches!(s.items[0], ScanItem::Malformed { offset: 0, .. }));
        match &s.items[1] {
            ScanItem::Record(r) => assert_eq!(r.record.seq, 2),
            other => panic!("unexpected {other:?}"),
        }
        assert!(s.tail.is_none());
        // Length enlarged to overrun the following frame: still resyncs.
        let mut m = a.clone();
        let grown = (a.len() - FRAME_HEADER_LEN + b.len() + 3) as u32;
        m[4..8].copy_from_slice(&grown.to_be_bytes());
        m.extend_from_slice(&b);
        let s = scan_frames(&m);
        assert_eq!(s.items.len(), 2);
        assert!(matches!(s.items[0], ScanItem::Malformed { .. }));
    }

    #[test]
    fn scan_never_panics_on_noise() {
        let mut x = 0x9e3779b97f4a7c15u64;
        for len in 0..400usize {
            let mut v = Vec::with_capacity(len);
            for _ in 0..len {
                x ^= x << 13;
                x ^= x >> 7;
                x ^= x << 17;
                v.push(x as u8);
            }
            if len > 8 && len % 3 == 0 {
                v[0..4].copy_from_slice(&FRAME_MAGIC);
            }
            let _ = scan_frames(&v);
        }
    }

    #[test]
    fn chain_id_binds_every_identity_field() {
        let id = ChainIdentity {
            device_id: "ugv-1".into(),
            boot_id: "b1".into(),
            key_id: "k".into(),
            algorithm: "hmac-sha256".into(),
            created_wall_ns: 1,
        };
        let base = id.chain_id();
        let mut v = id.clone();
        v.device_id = "ugv-2".into();
        assert_ne!(v.chain_id(), base);
        let mut v = id.clone();
        v.boot_id = "b2".into();
        assert_ne!(v.chain_id(), base);
        let mut v = id.clone();
        v.key_id = "k2".into();
        assert_ne!(v.chain_id(), base);
        let mut v = id.clone();
        v.algorithm = "ed25519".into();
        assert_ne!(v.chain_id(), base);
        let mut v = id.clone();
        v.created_wall_ns = 2;
        assert_ne!(v.chain_id(), base);
        // Length prefixes prevent field-boundary shifting.
        let mut a = id.clone();
        a.device_id = "ab".into();
        a.boot_id = "c".into();
        let mut b = id.clone();
        b.device_id = "a".into();
        b.boot_id = "bc".into();
        assert_ne!(a.chain_id(), b.chain_id());
    }
}
