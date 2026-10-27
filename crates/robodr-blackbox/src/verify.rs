//! Independent verification of black-box segments and bundles.
//!
//! [`verify_segments`] needs only the segment bytes, a [`Verifier`] for the
//! chain's key and optional trusted inputs ([`VerifyOptions`]). It never
//! trusts the recorder's own bookkeeping files. It returns a [`Report`] of
//! [`Finding`]s, each with a precise [`Location`] (segment, byte offset,
//! position, sequence number) and a [`FindingLevel`]:
//!
//! - `Tamper`: evidence integrity is violated (or cannot be established).
//! - `Warning`: anomalous but explainable by a crash or by recorded data loss
//!   (including a recorded crash recovery: the discarded bytes were the
//!   newest records and their loss cannot be told apart from deliberate
//!   truncation of an unsynced tail).
//! - `Info`: normal, recorded events worth showing (cyclic drops, saturation).
//!
//! [`Report::is_intact`] = no `Tamper` finding: the retained evidence is
//! authentic and complete as far as the log can prove. [`Report::is_clean`] =
//! additionally no `Warning`: nothing was lost or recovered either.
//!
//! # Diagnosis rules
//!
//! 1. Every frame is decoded strictly; undecodable bytes are `Malformed`.
//!    Bytes after the last frame of the *last* segment are a `TornTail`
//!    (warning) if they look like an interrupted write, else `TrailingGarbage`.
//! 2. Recomputed hash != stored hash: `HashMismatch` (content modified).
//! 3. Hash fine, signature invalid: `BadSignature` (modified and re-hashed, or
//!    forged/inserted without the key). If *no* record verifies, a single
//!    `KeyMismatch` is reported instead. Each record is checked under exactly
//!    the key the evidence names for it, never under "any key the verifier
//!    holds" (see *Which key signs a record* below).
//! 4. Records whose `chain_id` differs from the chain's: `ForeignChain`
//!    (replayed from another device, boot or chain).
//! 5. Among authentic records of the chain: same seq twice with the same
//!    hash is a `Duplicate` (replay), with different hashes a `Fork`; a seq
//!    lower than one already seen is `Reordered`; missing seqs not explained
//!    by invalid records at that spot are `Deleted`; consecutive seqs whose
//!    `prev_hash` does not link are a `ChainBreak`.
//! 6. The head must be genesis, or be anchored: by `trusted_anchor`, or by a
//!    signed `SegmentDropped` record for the head's predecessor (cyclic
//!    retention). Such a drop only counts if the head is a `SegmentStart` for
//!    segment `k`, the drop names segment `k - 1`, is not a `missing` report,
//!    comes later in the chain than the head, and its anchor
//!    `(last_seq, last_hash)` equals the head's `(seq - 1, prev_hash)`.
//!    Otherwise `HeadMissing`.
//! 7. Every segment except the last must end with a seal (`SegmentUnsealed`).
//! 8. With a checkpoint, records missing after it are a `TruncatedTail`, and
//!    a different hash at its seq is `CheckpointMismatch`.
//! 9. Recorder-side discoveries are reported from their signed records: a
//!    `TruncationDetected` is `TruncationRecorded` (tamper; the skipped seqs
//!    also show as `Deleted`), a `Recovery` that a crash cannot explain is
//!    `DamageQuarantined` (tamper). A crash-plausible `Recovery` that names
//!    the quarantined seqs (`discarded_seqs`) explains exactly that gap,
//!    which is then a warning (`RecoveryRecorded`), not `Deleted`.
//!    `KeyRotation` records are `KeyRotationRecorded` (info); verify a chain
//!    spanning a rotation with a [`crate::keys::Keyring`] holding both keys.
//!
//! # Which key signs a record
//!
//! Records do not name their key; the chain does. Every record carries its
//! `chain_id`, which is the hash of a [`ChainIdentity`] naming the chain's
//! first key (`key_id` **and** `algorithm`). Per chain, in log order:
//!
//! - The starting key is [`VerifyOptions::signing_key`] (trusted: e.g. a
//!   receiver's state after an earlier bundle) or else the identity's key
//!   (from any `Genesis`/`SegmentStart` that hashes to the chain id, or
//!   [`VerifyOptions::identity`] for a bundle).
//! - A `KeyRotation` that verifies under the current key and whose `from` is
//!   the current key switches to its `to` key. This is the only way an
//!   established key changes.
//! - A `SegmentStart` names the key of its segment (`signing_key`, or the
//!   identity's key). It may set the key when none is established by the
//!   evidence yet (a retained tail after cyclic retention dropped the
//!   rotation). If it names a key other than the identity's, that key is
//!   *unproven*: unless the verifier binds it to the chain's device
//!   ([`Verifier::key_device`]), records it signs give one
//!   `SigningKeyUnproven` warning. A `SegmentStart` (or `Genesis`) that
//!   names another key than an established one is `KeySwitchRefused`
//!   (tamper) and its records are checked under the established key.
//! - Each record is checked with [`Verifier::verify_key`]: that key id, that
//!   algorithm. A key the verifier binds to another device than the chain's
//!   never verifies (`KeyDeviceMismatch`, tamper).
//! - With no identity at all for a chain, the record is checked with
//!   [`Verifier::verify`], which a multi-key keyring refuses (ambiguous).
//!
//! So a keyring that holds unit B's key (or an HMAC key the verifying
//! station could sign with) does not authenticate a log whose identity
//! says `ed25519` / unit A. The remaining limit: an *unbound* key that the
//! evidence itself names in a `SegmentStart` is reported only as a warning;
//! bind fleet keys to their units (`device_id` in the key file) to make
//! that a hard failure.

use crate::crypto::to_hex;
use crate::export::{cursor_signing_message, SignedCursor};
use crate::export::{Anchor, Checkpoint};
use crate::record::{
    scan_frames, short_hex, signing_message, ChainIdentity, GenesisPayload, Hash, KeyRef,
    KeyRotationPayload, Record, RecordKind, RecoveryPayload, ScanItem, SegmentDroppedPayload,
    SegmentStartPayload, TailKind, TruncationPayload, ZERO_HASH,
};
use crate::sign::Verifier;
use crate::store::{
    list_segments, parse_segment_file_name, CHECKPOINT_FILE, CURSOR_FILE, HEAD_FILE,
    RECOVERY_PIN_FILE,
};
use serde::Serialize;
use std::collections::{BTreeMap, HashMap, HashSet};
use std::fmt;
use std::path::Path;

/// One segment's bytes and display name.
#[derive(Debug, Clone)]
pub struct SegmentData {
    pub name: String,
    pub bytes: Vec<u8>,
}

/// Trusted inputs for verification.
#[derive(Debug, Clone, Default)]
pub struct VerifyOptions {
    /// Chain the evidence must belong to. Default: the majority chain found.
    pub expected_chain_id: Option<Hash>,
    /// Device the chain must be bound to.
    pub expected_device_id: Option<String>,
    /// Trusted position immediately before (or within) the evidence.
    pub trusted_anchor: Option<Anchor>,
    /// Trusted checkpoint that must still be present.
    pub checkpoint: Option<Checkpoint>,
    /// Chain identity to use when the evidence holds no `Genesis` or
    /// `SegmentStart` for a chain (an export bundle). Not trusted on its own:
    /// it applies only to records whose `chain_id` it hashes to.
    pub identity: Option<ChainIdentity>,
    /// Trusted key that signs the first records of the expected chain (the
    /// key in effect right after the trusted anchor, e.g.
    /// [`Report::signing_key`] of the previous bundle). Default: the chain
    /// identity's key.
    pub signing_key: Option<KeyRef>,
}

/// Seriousness of a finding.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum FindingLevel {
    Info,
    Warning,
    Tamper,
}

/// Where a finding is.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Location {
    /// Segment name (file name, or "bundle").
    pub segment: String,
    /// Index of the segment in the input.
    pub segment_position: usize,
    /// Byte offset of the frame (or region) in the segment.
    pub offset: u64,
    /// Global position of the frame across all segments (0-based).
    pub position: usize,
    /// Sequence number as stored, if the frame decoded.
    pub seq: Option<u64>,
}

/// What was found.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum FindingKind {
    Malformed {
        reason: String,
        len: u64,
    },
    TornTail {
        len: u64,
    },
    TrailingGarbage {
        len: u64,
    },
    HashMismatch {
        seq: u64,
    },
    BadSignature {
        seq: u64,
    },
    KeyMismatch {
        verifier_key_id: String,
        recorded_key_id: Option<String>,
    },
    IdentityMismatch {
        seq: u64,
    },
    WrongDevice {
        expected: String,
        found: String,
    },
    ForeignChain {
        seq: u64,
        chain_id: String,
        device_id: Option<String>,
    },
    InvalidGenesis {
        seq: u64,
        reason: String,
    },
    Duplicate {
        seq: u64,
        first_position: usize,
    },
    Fork {
        seq: u64,
        other_position: usize,
    },
    Reordered {
        seq: u64,
        after_seq: u64,
    },
    Deleted {
        first_missing: u64,
        last_missing: u64,
    },
    ChainBreak {
        seq: u64,
        expected_prev: String,
        found_prev: String,
    },
    HeadMissing {
        first_seq: u64,
    },
    HeadDropRecorded {
        first_seq: u64,
        drop_record_seq: u64,
    },
    AnchorMismatch {
        anchor_seq: u64,
    },
    DroppedBeforeExport {
        first_missing: u64,
        last_missing: u64,
    },
    StaleBundle {
        anchor_seq: u64,
    },
    AnchorUnverified {
        anchor_seq: u64,
    },
    SegmentUnsealed {
        segment: String,
    },
    SegmentIndexMismatch {
        segment: String,
        recorded_index: u64,
    },
    SegmentMissingReported {
        seq: u64,
        segment_index: u64,
    },
    TruncatedTail {
        checkpoint_seq: u64,
        last_seq: Option<u64>,
    },
    CheckpointMismatch {
        checkpoint_seq: u64,
    },
    CheckpointInvalid {
        reason: String,
    },
    CheckpointNotRetained {
        checkpoint_seq: u64,
    },
    UnsealedTail {
        records: u64,
        after_seal_seq: Option<u64>,
    },
    RecoveryRecorded {
        seq: u64,
        discarded_bytes: u64,
    },
    SegmentDropRecorded {
        seq: u64,
        segment_index: u64,
        exported: bool,
    },
    SaturationRecorded {
        seq: u64,
    },
    /// The recorder found authentic state (checkpoint, export cursor)
    /// beyond the log's head at open: records were truncated.
    TruncationRecorded {
        seq: u64,
        head_seq: u64,
        first_skipped: u64,
        last_skipped: u64,
    },
    /// The recorder quarantined damage that a crash cannot explain (a
    /// durably synced record followed it).
    DamageQuarantined {
        seq: u64,
        discarded_bytes: u64,
        discarded_records: u64,
    },
    /// The recorder found a *closed* segment damaged at open (bit rot,
    /// failing storage, or a malicious edit: indistinguishable) and moved
    /// it to `quarantine/`; its records are missing from the log (their
    /// seqs also show as `Deleted`).
    SegmentQuarantined {
        seq: u64,
        segment_index: u64,
        discarded_bytes: u64,
        discarded_records: u64,
    },
    KeyRotationRecorded {
        seq: u64,
        from_key_id: String,
        to_key_id: String,
    },
    TimeRegression {
        seq: u64,
        prev_mono_ns: u64,
        mono_ns: u64,
    },
    /// A record names a key the verifier binds to another device.
    KeyDeviceMismatch {
        seq: u64,
        key_id: String,
        key_device: String,
        chain_device: String,
    },
    /// A `Genesis`/`SegmentStart` names another signing key than the one
    /// already established for the chain (only an authenticated
    /// `KeyRotation` may change it).
    KeySwitchRefused {
        seq: u64,
        established_key_id: String,
        named_key_id: String,
    },
    /// Records verify under a key named only by a `SegmentStart` (no
    /// authenticated rotation to it in the evidence) and not bound to the
    /// chain's device: the key id attributes them, nothing else does.
    SigningKeyUnproven {
        seq: u64,
        key_id: String,
    },
    Empty,
}

impl FindingKind {
    pub fn level(&self) -> FindingLevel {
        use FindingKind::*;
        match self {
            TornTail { .. }
            | DroppedBeforeExport { .. }
            | StaleBundle { .. }
            | CheckpointInvalid { .. }
            | TimeRegression { .. }
            | RecoveryRecorded { .. }
            | SigningKeyUnproven { .. }
            | Empty => FindingLevel::Warning,
            HeadDropRecorded { .. }
            | AnchorUnverified { .. }
            | CheckpointNotRetained { .. }
            | UnsealedTail { .. }
            | SegmentDropRecorded { .. }
            | SaturationRecorded { .. }
            | KeyRotationRecorded { .. } => FindingLevel::Info,
            _ => FindingLevel::Tamper,
        }
    }
}

impl fmt::Display for FindingKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        use FindingKind::*;
        match self {
            Malformed { reason, len } => write!(f, "malformed bytes ({len} B): {reason}"),
            TornTail { len } => write!(f, "torn tail ({len} B), unrecovered crash?"),
            TrailingGarbage { len } => write!(f, "trailing garbage ({len} B)"),
            HashMismatch { seq } => write!(f, "record {seq} modified (hash mismatch)"),
            BadSignature { seq } => write!(f, "record {seq} has an invalid signature"),
            KeyMismatch {
                verifier_key_id,
                recorded_key_id,
            } => write!(
                f,
                "no signature verifies with key {verifier_key_id} (chain key {recorded_key_id:?})"
            ),
            IdentityMismatch { seq } => {
                write!(f, "record {seq} identity does not hash to its chain id")
            }
            WrongDevice { expected, found } => {
                write!(f, "chain belongs to device {found}, expected {expected}")
            }
            ForeignChain {
                seq,
                chain_id,
                device_id,
            } => write!(
                f,
                "record {seq} belongs to another chain {chain_id} (device {device_id:?})"
            ),
            InvalidGenesis { seq, reason } => write!(f, "invalid genesis at {seq}: {reason}"),
            Duplicate {
                seq,
                first_position,
            } => write!(
                f,
                "record {seq} replayed (first at position {first_position})"
            ),
            Fork {
                seq,
                other_position,
            } => write!(
                f,
                "two different signed records with seq {seq} (other at {other_position})"
            ),
            Reordered { seq, after_seq } => write!(f, "record {seq} appears after {after_seq}"),
            Deleted {
                first_missing,
                last_missing,
            } => write!(f, "records {first_missing}..={last_missing} deleted"),
            ChainBreak { seq, .. } => write!(f, "record {seq} does not link to its predecessor"),
            HeadMissing { first_seq } => write!(
                f,
                "records before {first_seq} missing without a recorded drop"
            ),
            HeadDropRecorded {
                first_seq,
                drop_record_seq,
            } => write!(
                f,
                "head starts at {first_seq}; earlier records dropped (recorded at {drop_record_seq})"
            ),
            AnchorMismatch { anchor_seq } => {
                write!(f, "evidence does not link to trusted anchor {anchor_seq}")
            }
            DroppedBeforeExport {
                first_missing,
                last_missing,
            } => write!(
                f,
                "records {first_missing}..={last_missing} were dropped before export"
            ),
            StaleBundle { anchor_seq } => {
                write!(f, "nothing newer than already-received {anchor_seq}")
            }
            AnchorUnverified { anchor_seq } => {
                write!(f, "starts after unverified anchor {anchor_seq}")
            }
            SegmentUnsealed { segment } => write!(f, "closed segment {segment} not sealed"),
            SegmentIndexMismatch {
                segment,
                recorded_index,
            } => write!(f, "segment {segment} records index {recorded_index}"),
            SegmentMissingReported { seq, segment_index } => write!(
                f,
                "recorder found segment {segment_index} already deleted (record {seq})"
            ),
            TruncatedTail {
                checkpoint_seq,
                last_seq,
            } => write!(
                f,
                "log ends at {last_seq:?} but checkpoint {checkpoint_seq} exists"
            ),
            CheckpointMismatch { checkpoint_seq } => {
                write!(f, "record {checkpoint_seq} differs from checkpoint")
            }
            CheckpointInvalid { reason } => write!(f, "checkpoint ignored: {reason}"),
            CheckpointNotRetained { checkpoint_seq } => {
                write!(f, "checkpoint {checkpoint_seq} precedes retained records")
            }
            UnsealedTail {
                records,
                after_seal_seq,
            } => write!(f, "{records} records after last seal {after_seal_seq:?}"),
            RecoveryRecorded {
                seq,
                discarded_bytes,
            } => write!(
                f,
                "recovery at {seq} discarded {discarded_bytes} torn bytes"
            ),
            SegmentDropRecorded {
                seq,
                segment_index,
                exported,
            } => write!(
                f,
                "segment {segment_index} dropped (record {seq}, exported: {exported})"
            ),
            SaturationRecorded { seq } => write!(f, "storage saturated (record {seq})"),
            TruncationRecorded {
                seq,
                head_seq,
                first_skipped,
                last_skipped,
            } => write!(
                f,
                "recorder found the log truncated after {head_seq} (record {seq}); \
                 seqs {first_skipped}..={last_skipped} lost"
            ),
            DamageQuarantined {
                seq,
                discarded_bytes,
                discarded_records,
            } => write!(
                f,
                "record {seq}: {discarded_bytes} B with {discarded_records} records quarantined; \
                 a crash cannot explain the damage"
            ),
            SegmentQuarantined {
                seq,
                segment_index,
                discarded_bytes,
                discarded_records,
            } => write!(
                f,
                "record {seq}: closed segment {segment_index} failed verification at open and was \
                 quarantined ({discarded_bytes} B, {discarded_records} records)"
            ),
            KeyRotationRecorded {
                seq,
                from_key_id,
                to_key_id,
            } => write!(f, "signing key rotated {from_key_id} -> {to_key_id} (record {seq})"),
            TimeRegression {
                seq,
                prev_mono_ns,
                mono_ns,
            } => write!(
                f,
                "record {seq} monotonic time {mono_ns} < previous {prev_mono_ns}"
            ),
            KeyDeviceMismatch {
                seq,
                key_id,
                key_device,
                chain_device,
            } => write!(
                f,
                "record {seq}: key {key_id} belongs to device {key_device}, \
                 the chain to {chain_device}"
            ),
            KeySwitchRefused {
                seq,
                established_key_id,
                named_key_id,
            } => write!(
                f,
                "record {seq} names key {named_key_id} but {established_key_id} is the \
                 established key (no authenticated rotation)"
            ),
            SigningKeyUnproven { seq, key_id } => write!(
                f,
                "records from {seq} are signed by {key_id}, named only by a segment start \
                 (no rotation record retained, key not bound to the device)"
            ),
            Empty => write!(f, "no records"),
        }
    }
}

/// A located finding.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Finding {
    pub level: FindingLevel,
    pub kind: FindingKind,
    pub location: Option<Location>,
}

impl Finding {
    pub fn new(kind: FindingKind, location: Option<Location>) -> Self {
        Self {
            level: kind.level(),
            kind,
            location,
        }
    }
}

impl fmt::Display for Finding {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "[{:?}] {}", self.level, self.kind)?;
        if let Some(l) = &self.location {
            write!(
                f,
                " at {}+{} (pos {}, seq {:?})",
                l.segment, l.offset, l.position, l.seq
            )?;
        }
        Ok(())
    }
}

/// Verification result.
#[derive(Debug, Clone, Default, Serialize)]
pub struct Report {
    /// Ordered by position in the evidence (unlocated findings last).
    pub findings: Vec<Finding>,
    /// Frames decoded.
    pub frames: usize,
    /// Records that passed hash, signature and chain checks.
    pub verified_records: usize,
    pub first_seq: Option<u64>,
    pub last_seq: Option<u64>,
    /// Hex hash of the last verified record.
    pub last_hash: Option<String>,
    /// Hex chain id the evidence was checked against.
    pub chain_id: Option<String>,
    pub identity: Option<ChainIdentity>,
    pub last_seal_seq: Option<u64>,
    /// Key in effect after the last record of the expected chain (pass it
    /// as [`VerifyOptions::signing_key`] when verifying what follows).
    pub signing_key: Option<KeyRef>,
}

impl Report {
    /// No tamper findings.
    pub fn is_intact(&self) -> bool {
        !self
            .findings
            .iter()
            .any(|f| f.level == FindingLevel::Tamper)
    }

    /// No tamper findings and no warnings.
    pub fn is_clean(&self) -> bool {
        self.findings.iter().all(|f| f.level == FindingLevel::Info)
    }

    /// Tamper findings in order.
    pub fn tamper(&self) -> impl Iterator<Item = &Finding> {
        self.findings
            .iter()
            .filter(|f| f.level == FindingLevel::Tamper)
    }

    /// First finding at `level` or above.
    pub fn first_at_least(&self, level: FindingLevel) -> Option<&Finding> {
        self.findings.iter().find(|f| f.level >= level)
    }

    pub(crate) fn push(&mut self, f: Finding) {
        self.findings.push(f);
    }
}

struct Item {
    seg: usize,
    offset: u64,
    rec: Option<Record>,
}

struct Ctx<'a> {
    segments: &'a [SegmentData],
    items: Vec<Item>,
    findings: Vec<Finding>,
    /// What [`Ctx::rec`] returns for a position that holds no record. Never
    /// reached (callers only pass positions whose hash was checked, i.e.
    /// records); if it ever is, `invariant_broken` fails the report closed
    /// instead of aborting the daemon that links this verifier (review L3).
    placeholder: Record,
    invariant_broken: std::cell::Cell<bool>,
}

/// See [`Ctx::placeholder`].
fn placeholder_record() -> Record {
    Record {
        chain_id: [0; 32],
        seq: 0,
        time: crate::time::Timestamp {
            wall_ns: 0,
            mono_ns: 0,
            source: crate::time::TimeSource::Unknown,
        },
        kind: RecordKind::Event,
        critical: false,
        payload: Vec::new(),
        prev_hash: [0; 32],
        hash: [0; 32],
        sig: Vec::new(),
    }
}

impl Ctx<'_> {
    fn loc(&self, pos: usize) -> Location {
        let it = &self.items[pos];
        Location {
            segment: self.segments[it.seg].name.clone(),
            segment_position: it.seg,
            offset: it.offset,
            position: pos,
            seq: it.rec.as_ref().map(|r| r.seq),
        }
    }
    fn add(&mut self, kind: FindingKind, pos: Option<usize>) {
        let loc = pos.map(|p| self.loc(p));
        self.findings.push(Finding::new(kind, loc));
    }
    fn rec(&self, pos: usize) -> &Record {
        match self.items.get(pos).and_then(|it| it.rec.as_ref()) {
            Some(r) => r,
            None => {
                self.invariant_broken.set(true);
                &self.placeholder
            }
        }
    }
}

/// How far the evidence establishes the current signing key of a chain.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Trust {
    /// The chain identity's key (or none), not yet confirmed by position:
    /// a `SegmentStart` may still name another one.
    Initial,
    /// Established (genesis, authenticated rotation, trusted option, or a
    /// key bound to the chain's device); only a rotation changes it.
    Proven,
    /// Named only by a `SegmentStart`.
    Unproven,
}

struct KeyState {
    key: Option<KeyRef>,
    trust: Trust,
}

fn key_of(id: &ChainIdentity) -> KeyRef {
    KeyRef {
        key_id: id.key_id.clone(),
        algorithm: id.algorithm.clone(),
    }
}

fn identity_of(rec: &Record) -> Option<ChainIdentity> {
    match rec.kind {
        RecordKind::Genesis => rec.payload_json::<GenesisPayload>().map(|g| g.identity),
        RecordKind::SegmentStart => rec
            .payload_json::<SegmentStartPayload>()
            .map(|s| s.identity),
        _ => None,
    }
}

/// Verify segments given in log order (the last one may be the active,
/// unsealed segment).
// Several per-position vectors (hash_ok, sig_ok, usable, ...) are indexed in
// lock-step with `cx.items`; index loops are the clearest form here.
#[allow(clippy::needless_range_loop)]
pub fn verify_segments(
    segments: &[SegmentData],
    verifier: &dyn Verifier,
    opts: &VerifyOptions,
) -> Report {
    let mut cx = Ctx {
        segments,
        items: Vec::new(),
        findings: Vec::new(),
        placeholder: placeholder_record(),
        invariant_broken: std::cell::Cell::new(false),
    };
    let nseg = segments.len();

    // 1. Framing.
    for (si, seg) in segments.iter().enumerate() {
        let scan = scan_frames(&seg.bytes);
        for it in scan.items {
            match it {
                ScanItem::Record(sr) => cx.items.push(Item {
                    seg: si,
                    offset: sr.offset,
                    rec: Some(sr.record),
                }),
                ScanItem::Malformed {
                    offset,
                    len,
                    reason,
                } => {
                    cx.items.push(Item {
                        seg: si,
                        offset,
                        rec: None,
                    });
                    let p = cx.items.len() - 1;
                    cx.add(FindingKind::Malformed { reason, len }, Some(p));
                }
            }
        }
        if let Some(t) = scan.tail {
            cx.items.push(Item {
                seg: si,
                offset: t.offset,
                rec: None,
            });
            let p = cx.items.len() - 1;
            let last = si + 1 == nseg;
            let kind = match (last, t.kind) {
                (true, TailKind::Incomplete | TailKind::Zeros) => {
                    FindingKind::TornTail { len: t.len }
                }
                (true, TailKind::Garbage) => FindingKind::TrailingGarbage { len: t.len },
                (false, _) => FindingKind::Malformed {
                    reason: "invalid bytes at end of a closed segment".into(),
                    len: t.len,
                },
            };
            cx.add(kind, Some(p));
        }
    }
    let n = cx.items.len();
    let frames = cx.items.iter().filter(|i| i.rec.is_some()).count();

    // 2. Hashes.
    let mut hash_ok = vec![false; n];
    for pos in 0..n {
        if let Some(r) = &cx.items[pos].rec {
            hash_ok[pos] = r.compute_hash() == r.hash;
            if !hash_ok[pos] {
                let seq = r.seq;
                cx.add(FindingKind::HashMismatch { seq }, Some(pos));
            }
        }
    }

    // 3. Signatures, each under the key the evidence names for its record
    //    (see "Which key signs a record" in the module docs).
    let mut chain_ids: HashMap<Hash, ChainIdentity> = HashMap::new();
    for pos in 0..n {
        if hash_ok[pos] {
            let r = cx.rec(pos);
            if let Some(id) = identity_of(r).filter(|i| i.chain_id() == r.chain_id) {
                chain_ids.entry(r.chain_id).or_insert(id);
            }
        }
    }
    if let Some(id) = &opts.identity {
        chain_ids.entry(id.chain_id()).or_insert_with(|| id.clone());
    }
    let mut states: HashMap<Hash, KeyState> = HashMap::new();
    // Key findings, emitted once the expected chain is known: (pos, chain, kind).
    let mut key_findings: Vec<(usize, Hash, FindingKind)> = Vec::new();
    let mut reported_keys: HashSet<(Hash, String, u8)> = HashSet::new();
    let mut sig_ok = vec![false; n];
    let mut recorded_key_id = None;
    for pos in 0..n {
        if !hash_ok[pos] {
            continue;
        }
        let r = cx.rec(pos);
        let chain = r.chain_id;
        let chain_identity = chain_ids.get(&chain);
        let st = states
            .entry(chain)
            .or_insert_with(|| match &opts.signing_key {
                Some(k) if opts.expected_chain_id.is_none_or(|c| c == chain) => KeyState {
                    key: Some(k.clone()),
                    trust: Trust::Proven,
                },
                _ => KeyState {
                    key: chain_identity.map(key_of),
                    trust: Trust::Initial,
                },
            });
        if recorded_key_id.is_none() {
            recorded_key_id = identity_of(r).map(|i| i.key_id);
        }
        // A Genesis / SegmentStart names the key of what follows.
        if let Some(id) = identity_of(r).filter(|i| i.chain_id() == chain) {
            let chain_key = key_of(&id);
            let named = match r.kind {
                RecordKind::SegmentStart => r
                    .payload_json::<SegmentStartPayload>()
                    .and_then(|p| p.signing_key)
                    .unwrap_or_else(|| chain_key.clone()),
                _ => chain_key.clone(),
            };
            if st.key.as_ref() != Some(&named) {
                if st.trust == Trust::Proven && st.key.is_some() {
                    key_findings.push((
                        pos,
                        chain,
                        FindingKind::KeySwitchRefused {
                            seq: r.seq,
                            established_key_id: st
                                .key
                                .as_ref()
                                .map(|k| k.key_id.clone())
                                .unwrap_or_default(),
                            named_key_id: named.key_id.clone(),
                        },
                    ));
                } else {
                    st.trust = if named == chain_key {
                        Trust::Initial
                    } else {
                        Trust::Unproven
                    };
                    st.key = Some(named);
                }
            }
            if r.kind == RecordKind::Genesis && st.key.as_ref() == Some(&chain_key) {
                st.trust = Trust::Proven;
            }
        }
        let msg = signing_message(&r.hash);
        let mut ok = match &st.key {
            Some(k) => verifier.verify_key(&k.key_id, &k.algorithm, &msg, &r.sig),
            None => verifier.verify(&msg, &r.sig),
        };
        if let (true, Some(k)) = (ok, &st.key) {
            let chain_device = chain_identity.map(|i| i.device_id.as_str());
            match (verifier.key_device(&k.key_id), chain_device) {
                (Some(kd), Some(cd)) if kd != cd => {
                    ok = false;
                    if reported_keys.insert((chain, k.key_id.clone(), 0)) {
                        key_findings.push((
                            pos,
                            chain,
                            FindingKind::KeyDeviceMismatch {
                                seq: r.seq,
                                key_id: k.key_id.clone(),
                                key_device: kd.to_string(),
                                chain_device: cd.to_string(),
                            },
                        ));
                    }
                }
                // Bound to this very device: as good as a rotation.
                (Some(_), Some(_)) if st.trust == Trust::Unproven => st.trust = Trust::Proven,
                _ => {}
            }
            if ok
                && st.trust == Trust::Unproven
                && reported_keys.insert((chain, k.key_id.clone(), 1))
            {
                key_findings.push((
                    pos,
                    chain,
                    FindingKind::SigningKeyUnproven {
                        seq: r.seq,
                        key_id: k.key_id.clone(),
                    },
                ));
            }
        }
        sig_ok[pos] = ok;
        // An authenticated rotation away from the current key.
        if ok && r.kind == RecordKind::KeyRotation {
            if let Some(p) = r.payload_json::<KeyRotationPayload>() {
                if st.key.as_ref() == Some(&p.from) {
                    st.key = Some(p.to);
                    if st.trust == Trust::Initial {
                        st.trust = Trust::Proven;
                    }
                }
            }
        }
    }
    let hash_ok_count = hash_ok.iter().filter(|&&b| b).count();
    let sig_ok_count = sig_ok.iter().filter(|&&b| b).count();
    let key_mismatch = hash_ok_count > 0 && sig_ok_count == 0;
    if key_mismatch {
        cx.add(
            FindingKind::KeyMismatch {
                verifier_key_id: verifier.key_id().to_string(),
                recorded_key_id,
            },
            None,
        );
    } else {
        for pos in 0..n {
            if hash_ok[pos] && !sig_ok[pos] {
                let seq = cx.rec(pos).seq;
                cx.add(FindingKind::BadSignature { seq }, Some(pos));
            }
        }
    }
    let authentic: Vec<bool> = (0..n)
        .map(|p| hash_ok[p] && (sig_ok[p] || key_mismatch))
        .collect();

    // 4. Chain membership and identity.
    let mut chain_devices: HashMap<Hash, String> = HashMap::new();
    let mut identities: Vec<(usize, ChainIdentity)> = Vec::new();
    for pos in 0..n {
        if !authentic[pos] {
            continue;
        }
        let r = cx.rec(pos);
        if let Some(id) = identity_of(r) {
            if id.chain_id() == r.chain_id {
                chain_devices
                    .entry(r.chain_id)
                    .or_insert_with(|| id.device_id.clone());
                identities.push((pos, id));
            } else {
                let seq = r.seq;
                cx.add(FindingKind::IdentityMismatch { seq }, Some(pos));
            }
        }
    }
    let expected_chain = opts.expected_chain_id.or_else(|| {
        let mut counts: BTreeMap<Hash, usize> = BTreeMap::new();
        for pos in (0..n).filter(|&p| authentic[p]) {
            *counts.entry(cx.rec(pos).chain_id).or_default() += 1;
        }
        counts
            .into_iter()
            .max_by_key(|(_, c)| *c)
            .map(|(chain, _)| chain)
    });
    let identity = identities
        .iter()
        .find(|(_, id)| Some(id.chain_id()) == expected_chain)
        .map(|(_, id)| id.clone());
    if let (Some(want), Some(id)) = (&opts.expected_device_id, &identity) {
        if &id.device_id != want {
            cx.add(
                FindingKind::WrongDevice {
                    expected: want.clone(),
                    found: id.device_id.clone(),
                },
                None,
            );
        }
    }
    for (pos, chain, kind) in key_findings {
        if Some(chain) == expected_chain {
            cx.add(kind, Some(pos));
        }
    }
    let signing_key = expected_chain
        .and_then(|c| states.get(&c))
        .and_then(|st| st.key.clone());
    let mut usable = authentic.clone();
    for pos in 0..n {
        if !authentic[pos] {
            continue;
        }
        let r = cx.rec(pos);
        if Some(r.chain_id) != expected_chain {
            let kind = FindingKind::ForeignChain {
                seq: r.seq,
                chain_id: short_hex(&r.chain_id),
                device_id: chain_devices.get(&r.chain_id).cloned(),
            };
            usable[pos] = false;
            cx.add(kind, Some(pos));
        }
    }
    // "Invalid" items (explain gaps): malformed, bad hash, bad signature.
    let invalid: Vec<bool> = (0..n).map(|p| !authentic[p]).collect();

    // Genesis rules.
    for pos in 0..n {
        if !usable[pos] {
            continue;
        }
        let r = cx.rec(pos);
        let reason = match (r.kind == RecordKind::Genesis, r.seq == 0) {
            (true, false) => Some("genesis record with non-zero seq"),
            (false, true) => Some("seq 0 is not a genesis record"),
            (true, true) if r.prev_hash != ZERO_HASH => Some("genesis prev_hash is not zero"),
            _ => None,
        };
        if let Some(reason) = reason {
            let seq = r.seq;
            cx.add(
                FindingKind::InvalidGenesis {
                    seq,
                    reason: reason.into(),
                },
                Some(pos),
            );
        }
    }

    // 5a. Duplicates / forks.
    let mut by_seq: HashMap<u64, usize> = HashMap::new();
    for pos in 0..n {
        if !usable[pos] {
            continue;
        }
        let (seq, hash) = (cx.rec(pos).seq, cx.rec(pos).hash);
        match by_seq.get(&seq) {
            Some(&first) => {
                let kind = if cx.rec(first).hash == hash {
                    FindingKind::Duplicate {
                        seq,
                        first_position: first,
                    }
                } else {
                    FindingKind::Fork {
                        seq,
                        other_position: first,
                    }
                };
                usable[pos] = false;
                cx.add(kind, Some(pos));
            }
            None => {
                by_seq.insert(seq, pos);
            }
        }
    }

    // 5b. Order.
    let mut max_seq: Option<u64> = None;
    for pos in 0..n {
        if !usable[pos] {
            continue;
        }
        let seq = cx.rec(pos).seq;
        if let Some(m) = max_seq {
            if seq < m {
                cx.add(FindingKind::Reordered { seq, after_seq: m }, Some(pos));
            }
        }
        max_seq = Some(max_seq.map_or(seq, |m| m.max(seq)));
    }

    let mut order: Vec<usize> = (0..n).filter(|&p| usable[p]).collect();
    order.sort_by_key(|&p| cx.rec(p).seq);

    let drops: Vec<(usize, SegmentDroppedPayload)> = order
        .iter()
        .filter(|&&p| cx.rec(p).kind == RecordKind::SegmentDropped)
        .filter_map(|&p| cx.rec(p).payload_json().map(|d| (p, d)))
        .collect();
    // A signed drop of the segment right before the head's segment, whose
    // anchor is exactly the head's predecessor.
    let drop_covering = |head: usize| -> Option<usize> {
        let h = cx.rec(head);
        if h.kind != RecordKind::SegmentStart {
            return None;
        }
        let head_index = h.payload_json::<SegmentStartPayload>()?.segment_index;
        let seq_before = h.seq.checked_sub(1)?;
        let want = to_hex(&h.prev_hash);
        drops
            .iter()
            .find(|(p, d)| {
                !d.missing
                    && d.segment_index.checked_add(1) == Some(head_index)
                    && cx.rec(*p).seq > h.seq
                    && d.last_seq == Some(seq_before)
                    && d.last_hash.as_deref() == Some(&want)
            })
            .map(|(p, _)| *p)
    };

    // 6. Head / anchor.
    if let (Some(&head), Some(&last_pos)) = (order.first(), order.last()) {
        let (s0, prev0) = (cx.rec(head).seq, cx.rec(head).prev_hash);
        let last_seq = cx.rec(last_pos).seq;
        match &opts.trusted_anchor {
            Some(a) if Some(a.chain_id) != expected_chain => {
                cx.add(
                    FindingKind::AnchorMismatch { anchor_seq: a.seq },
                    Some(head),
                );
            }
            Some(a) => {
                let next = a.seq.checked_add(1);
                if Some(s0) == next {
                    if prev0 != a.hash {
                        cx.add(
                            FindingKind::AnchorMismatch { anchor_seq: a.seq },
                            Some(head),
                        );
                    }
                } else if s0 <= a.seq {
                    if let Some(&p) = by_seq.get(&a.seq) {
                        if usable[p] && cx.rec(p).hash != a.hash {
                            cx.add(FindingKind::AnchorMismatch { anchor_seq: a.seq }, Some(p));
                        }
                    }
                    if last_seq <= a.seq {
                        cx.add(FindingKind::StaleBundle { anchor_seq: a.seq }, None);
                    }
                } else {
                    let (first_missing, last_missing) = (a.seq + 1, s0 - 1);
                    if drop_covering(head).is_some() {
                        cx.add(
                            FindingKind::DroppedBeforeExport {
                                first_missing,
                                last_missing,
                            },
                            Some(head),
                        );
                    } else {
                        cx.add(
                            FindingKind::Deleted {
                                first_missing,
                                last_missing,
                            },
                            Some(head),
                        );
                    }
                }
            }
            None => {
                if s0 > 0 {
                    match drop_covering(head) {
                        Some(dp) => {
                            let drop_record_seq = cx.rec(dp).seq;
                            cx.add(
                                FindingKind::HeadDropRecorded {
                                    first_seq: s0,
                                    drop_record_seq,
                                },
                                Some(head),
                            );
                        }
                        None => cx.add(FindingKind::HeadMissing { first_seq: s0 }, Some(head)),
                    }
                }
            }
        }
    } else {
        cx.add(FindingKind::Empty, None);
    }

    // 6b. Gaps and links. A gap is explained only by a signed, crash-
    //     plausible `Recovery` that names exactly those seqs as quarantined
    //     with a lost page (B3); everything else is `Deleted`.
    let explained_gaps: Vec<[u64; 2]> = order
        .iter()
        .filter(|&&p| cx.rec(p).kind == RecordKind::Recovery)
        .filter_map(|&p| cx.rec(p).payload_json::<RecoveryPayload>())
        .filter(|rp| rp.crash_plausible)
        .filter_map(|rp| rp.discarded_seqs)
        .collect();
    for w in order.windows(2) {
        let (pa, pb) = (w[0], w[1]);
        let (a, b) = (cx.rec(pa), cx.rec(pb));
        if b.seq == a.seq + 1 {
            if b.prev_hash != a.hash {
                let kind = FindingKind::ChainBreak {
                    seq: b.seq,
                    expected_prev: short_hex(&a.hash),
                    found_prev: short_hex(&b.prev_hash),
                };
                cx.add(kind, Some(pb));
            }
        } else {
            let missing = b.seq - a.seq - 1;
            let (lo, hi) = (pa.min(pb), pa.max(pb));
            let explained = (lo + 1..hi).filter(|&k| invalid[k]).count() as u64;
            let recovered = explained_gaps.contains(&[a.seq + 1, b.seq - 1]);
            if explained < missing && !recovered {
                let kind = FindingKind::Deleted {
                    first_missing: a.seq + 1,
                    last_missing: b.seq - 1,
                };
                cx.add(kind, Some(pb));
            }
        }
    }

    // 7. Segment structure.
    for si in 0..nseg.saturating_sub(1) {
        let last_item = (0..n).rev().find(|&p| cx.items[p].seg == si);
        let sealed = match last_item {
            Some(p) => match &cx.items[p].rec {
                Some(r) => r.kind == RecordKind::Seal,
                None => true, // already reported as malformed
            },
            None => false,
        };
        if !sealed {
            let segment = segments[si].name.clone();
            cx.add(FindingKind::SegmentUnsealed { segment }, last_item);
        }
    }
    for &p in &order {
        let r = cx.rec(p);
        match r.kind {
            RecordKind::SegmentStart => {
                let seg = &segments[cx.items[p].seg];
                if let (Some(sp), Some(idx)) = (
                    r.payload_json::<SegmentStartPayload>(),
                    parse_segment_file_name(&seg.name),
                ) {
                    if sp.segment_index != idx {
                        let kind = FindingKind::SegmentIndexMismatch {
                            segment: seg.name.clone(),
                            recorded_index: sp.segment_index,
                        };
                        cx.add(kind, Some(p));
                    }
                }
            }
            RecordKind::SegmentDropped => {
                if let Some(d) = r.payload_json::<SegmentDroppedPayload>() {
                    let seq = r.seq;
                    let kind = if d.missing {
                        FindingKind::SegmentMissingReported {
                            seq,
                            segment_index: d.segment_index,
                        }
                    } else {
                        FindingKind::SegmentDropRecorded {
                            seq,
                            segment_index: d.segment_index,
                            exported: d.exported,
                        }
                    };
                    cx.add(kind, Some(p));
                }
            }
            RecordKind::Recovery => {
                let seq = r.seq;
                let rp = r.payload_json::<RecoveryPayload>();
                let discarded_bytes = rp.as_ref().map_or(0, |x| x.discarded_bytes);
                let kind = match rp {
                    Some(x) if x.quarantined_segment => FindingKind::SegmentQuarantined {
                        seq,
                        segment_index: x.segment_index,
                        discarded_bytes,
                        discarded_records: x.discarded_records,
                    },
                    Some(x) if !x.crash_plausible => FindingKind::DamageQuarantined {
                        seq,
                        discarded_bytes,
                        discarded_records: x.discarded_records,
                    },
                    _ => FindingKind::RecoveryRecorded {
                        seq,
                        discarded_bytes,
                    },
                };
                cx.add(kind, Some(p));
            }
            RecordKind::TruncationDetected => {
                let seq = r.seq;
                let (head_seq, [first_skipped, last_skipped]) = r
                    .payload_json::<TruncationPayload>()
                    .map_or((0, [0, 0]), |t| (t.head_seq, t.skipped_seqs));
                cx.add(
                    FindingKind::TruncationRecorded {
                        seq,
                        head_seq,
                        first_skipped,
                        last_skipped,
                    },
                    Some(p),
                );
            }
            RecordKind::KeyRotation => {
                let seq = r.seq;
                let (from_key_id, to_key_id) = r
                    .payload_json::<KeyRotationPayload>()
                    .map_or((String::new(), String::new()), |k| {
                        (k.from.key_id, k.to.key_id)
                    });
                cx.add(
                    FindingKind::KeyRotationRecorded {
                        seq,
                        from_key_id,
                        to_key_id,
                    },
                    Some(p),
                );
            }
            RecordKind::Saturation => {
                let seq = r.seq;
                cx.add(FindingKind::SaturationRecorded { seq }, Some(p));
            }
            _ => {}
        }
    }

    // 8. Checkpoint.
    let last = order.last().map(|&p| (cx.rec(p).seq, cx.rec(p).hash));
    if let Some(cp) = &opts.checkpoint {
        if Some(cp.chain_id) != expected_chain {
            cx.add(
                FindingKind::CheckpointInvalid {
                    reason: "checkpoint is for a different chain".into(),
                },
                None,
            );
        } else if !cp.verify(verifier) {
            cx.add(
                FindingKind::CheckpointInvalid {
                    reason: "checkpoint signature does not verify".into(),
                },
                None,
            );
        } else if let Some(kd) = verifier.key_device(&cp.key_id).filter(|kd| {
            identity
                .as_ref()
                .is_some_and(|id| id.device_id.as_str() != *kd)
        }) {
            cx.add(
                FindingKind::CheckpointInvalid {
                    reason: format!("checkpoint key {} belongs to device {kd}", cp.key_id),
                },
                None,
            );
        } else {
            match by_seq.get(&cp.seq).filter(|&&p| usable[p]) {
                Some(&p) => {
                    if cx.rec(p).hash != cp.hash {
                        cx.add(
                            FindingKind::CheckpointMismatch {
                                checkpoint_seq: cp.seq,
                            },
                            Some(p),
                        );
                    }
                }
                None => {
                    let first = order.first().map(|&p| cx.rec(p).seq);
                    if last.is_none_or(|(l, _)| cp.seq > l) {
                        cx.add(
                            FindingKind::TruncatedTail {
                                checkpoint_seq: cp.seq,
                                last_seq: last.map(|(l, _)| l),
                            },
                            None,
                        );
                    } else if first.is_some_and(|f| cp.seq < f) {
                        cx.add(
                            FindingKind::CheckpointNotRetained {
                                checkpoint_seq: cp.seq,
                            },
                            None,
                        );
                    }
                    // Otherwise it falls in a gap that is already reported.
                }
            }
        }
    }

    // 9. Unsealed tail.
    let last_seal = order
        .iter()
        .rev()
        .find(|&&p| cx.rec(p).kind == RecordKind::Seal)
        .map(|&p| cx.rec(p).seq);
    let after = order
        .iter()
        .filter(|&&p| last_seal.is_none_or(|s| cx.rec(p).seq > s))
        .count() as u64;
    if after > 0 {
        cx.add(
            FindingKind::UnsealedTail {
                records: after,
                after_seal_seq: last_seal,
            },
            None,
        );
    }

    // 10. Monotonic time within one recorder run (baseline reset at Genesis,
    //     Resume and SegmentStart, the records a new run can begin with).
    let mut prev_mono: Option<u64> = None;
    for &p in &order {
        let (kind, seq, mono_ns) = {
            let r = cx.rec(p);
            (r.kind, r.seq, r.time.mono_ns)
        };
        if matches!(
            kind,
            RecordKind::Genesis | RecordKind::Resume | RecordKind::SegmentStart
        ) {
            prev_mono = Some(mono_ns);
            continue;
        }
        if let Some(pm) = prev_mono {
            if mono_ns < pm {
                let kind = FindingKind::TimeRegression {
                    seq,
                    prev_mono_ns: pm,
                    mono_ns,
                };
                cx.add(kind, Some(p));
            }
        }
        prev_mono = Some(mono_ns);
    }

    let first_seq = order.first().map(|&p| cx.rec(p).seq);
    if cx.invariant_broken.get() {
        cx.add(
            FindingKind::Malformed {
                reason: "internal verifier error: a record position held no record; \
                         the verdict is not trustworthy"
                    .into(),
                len: 0,
            },
            None,
        );
    }
    let mut findings = std::mem::take(&mut cx.findings);
    findings.sort_by_key(|f| f.location.as_ref().map_or(usize::MAX, |l| l.position));
    Report {
        findings,
        frames,
        verified_records: order.len(),
        first_seq,
        last_seq: last.map(|(s, _)| s),
        last_hash: last.map(|(_, h)| to_hex(&h)),
        chain_id: expected_chain.map(|c| to_hex(&c)),
        identity,
        last_seal_seq: last_seal,
        signing_key,
    }
}

/// Read a recorder directory's segments in index order.
pub fn read_segments(dir: &Path) -> std::io::Result<Vec<SegmentData>> {
    list_segments(dir)?
        .into_iter()
        .map(|(_, path)| {
            let bytes = std::fs::read(&path)?;
            let name = path
                .file_name()
                .map(|n| n.to_string_lossy().into_owned())
                .unwrap_or_default();
            Ok(SegmentData { name, bytes })
        })
        .collect()
}

/// Verify a recorder directory. If `opts.checkpoint` is unset, the
/// directory's own `checkpoint.json` (written at every seal) is used, or
/// its `head.json` high-water mark (written every few records, see
/// [`crate::store`]) or `recovery-pin.json` when one of those authenticates
/// and names a later record. An authentic `export-cursor.json` beyond the
/// stored head is reported as a `TruncatedTail` too. These are the state
/// files [`crate::Recorder::open`] treats as truncation proof, so a
/// directory is not "intact" here and truncated at its next open.
/// Both are only as trustworthy as the directory, so keep an external copy
/// (or a [`crate::store::HeadAnchor`]) too.
pub fn verify_dir(
    dir: &Path,
    verifier: &dyn Verifier,
    opts: &VerifyOptions,
) -> std::io::Result<Report> {
    let segments = read_segments(dir)?;
    let mut o = opts.clone();
    let mut unreadable = false;
    if o.checkpoint.is_none() {
        match std::fs::read(dir.join(CHECKPOINT_FILE)) {
            Ok(b) => {
                o.checkpoint = std::str::from_utf8(&b).ok().and_then(Checkpoint::from_json);
                unreadable = o.checkpoint.is_none();
            }
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
            Err(e) => return Err(e),
        }
        // The high-water mark replaces the checkpoint only if it is
        // authentic and newer: a forged or stale head.json cannot hide
        // anything the checkpoint shows.
        let mark = match std::fs::read(dir.join(HEAD_FILE)) {
            Ok(b) => std::str::from_utf8(&b).ok().and_then(Checkpoint::from_json),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => None,
            Err(e) => return Err(e),
        };
        // The recovery pin (left by a crash between a recovery cut and its
        // record) is truncation proof to the recorder; same rule.
        let pin = match std::fs::read(dir.join(RECOVERY_PIN_FILE)) {
            Ok(b) => std::str::from_utf8(&b).ok().and_then(Checkpoint::from_json),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => None,
            Err(e) => return Err(e),
        };
        for m in [mark, pin].into_iter().flatten() {
            if !m.verify(verifier) {
                continue;
            }
            let newer = match &o.checkpoint {
                Some(c) if c.chain_id == m.chain_id && c.verify(verifier) => m.seq > c.seq,
                _ => true,
            };
            if newer {
                o.checkpoint = Some(m);
            }
        }
    }
    // The export cursor: an authentic position beyond the stored head is
    // truncation to the recorder (it is signed over a different message,
    // so it cannot stand in for the checkpoint).
    let cursor = match std::fs::read(dir.join(CURSOR_FILE)) {
        Ok(b) => std::str::from_utf8(&b)
            .ok()
            .and_then(SignedCursor::from_json)
            .filter(|c| verifier.verify_any(&cursor_signing_message(&c.anchor), &c.sig)),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => None,
        Err(e) => return Err(e),
    };
    let mut report = verify_segments(&segments, verifier, &o);
    if let Some(c) = cursor {
        let chain = to_hex(&c.anchor.chain_id);
        let shown = report.findings.iter().any(|f| {
            matches!(f.kind, FindingKind::TruncatedTail { checkpoint_seq, .. }
                if checkpoint_seq >= c.anchor.seq)
        });
        if report.chain_id.as_deref() == Some(chain.as_str())
            && report.last_seq.is_none_or(|l| c.anchor.seq > l)
            && !shown
        {
            report.push(Finding::new(
                FindingKind::TruncatedTail {
                    checkpoint_seq: c.anchor.seq,
                    last_seq: report.last_seq,
                },
                None,
            ));
        }
    }
    if unreadable {
        report.push(Finding::new(
            FindingKind::CheckpointInvalid {
                reason: format!("{CHECKPOINT_FILE} is unparseable"),
            },
            None,
        ));
    }
    Ok(report)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::record::{RecoveryPayload, TruncationPayload};
    use crate::sign::{HmacSha256Key, Signer};
    use crate::time::{TimeSource, Timestamp};

    // Review L3: a broken internal invariant fails the report closed, it
    // does not abort the daemon.
    #[test]
    fn rec_on_a_non_record_position_flags_instead_of_panicking() {
        let cx = Ctx {
            segments: &[],
            items: vec![Item {
                seg: 0,
                offset: 0,
                rec: None,
            }],
            findings: Vec::new(),
            placeholder: placeholder_record(),
            invariant_broken: std::cell::Cell::new(false),
        };
        assert_eq!(cx.rec(0).seq, 0);
        assert!(cx.invariant_broken.get());
        let _ = cx.rec(7);
        assert!(cx.invariant_broken.get());
    }
    use robodr_events::Severity;

    fn key() -> HmacSha256Key {
        HmacSha256Key::new("k", &[3; 32]).unwrap()
    }

    fn ident() -> ChainIdentity {
        ChainIdentity {
            device_id: "ugv-1".into(),
            boot_id: "b".into(),
            key_id: "k".into(),
            algorithm: "hmac-sha256".into(),
            created_wall_ns: 5,
        }
    }

    /// A signed chain builder: genesis, then whatever is pushed.
    struct Chain {
        key: HmacSha256Key,
        id: ChainIdentity,
        recs: Vec<Record>,
    }

    impl Chain {
        fn new() -> Self {
            let mut c = Chain {
                key: key(),
                id: ident(),
                recs: Vec::new(),
            };
            let g = serde_json::to_vec(&GenesisPayload {
                identity: c.id.clone(),
                recorder_version: "t".into(),
                format_version: 1,
            })
            .unwrap();
            c.push_at(0, RecordKind::Genesis, g);
            c
        }
        fn push_at(&mut self, seq: u64, kind: RecordKind, payload: Vec<u8>) {
            let prev = self.recs.last().map_or(ZERO_HASH, |r| r.hash);
            let mut r = Record {
                chain_id: self.id.chain_id(),
                seq,
                time: Timestamp {
                    wall_ns: 1_000 + seq,
                    mono_ns: 10 + seq,
                    source: TimeSource::Gps,
                },
                kind,
                critical: kind.is_control(),
                payload,
                prev_hash: prev,
                hash: ZERO_HASH,
                sig: Vec::new(),
            };
            r.hash = r.compute_hash();
            r.sig = self.key.sign(&signing_message(&r.hash)).unwrap();
            self.recs.push(r);
        }
        fn note(&mut self) {
            let seq = self.recs.last().map_or(0, |r| r.seq + 1);
            self.push_at(seq, RecordKind::Note, br#"{"n":1}"#.to_vec());
        }
        fn seg(&self, name: &str) -> SegmentData {
            SegmentData {
                name: name.into(),
                bytes: self.recs.iter().flat_map(|r| r.encode_frame()).collect(),
            }
        }
    }

    fn kinds(r: &Report) -> Vec<&FindingKind> {
        r.findings.iter().map(|f| &f.kind).collect()
    }

    #[test]
    fn level_classifies_every_family() {
        use FindingKind::*;
        assert_eq!(HashMismatch { seq: 1 }.level(), FindingLevel::Tamper);
        assert_eq!(
            Deleted {
                first_missing: 1,
                last_missing: 2
            }
            .level(),
            FindingLevel::Tamper
        );
        assert_eq!(TornTail { len: 1 }.level(), FindingLevel::Warning);
        assert_eq!(
            RecoveryRecorded {
                seq: 1,
                discarded_bytes: 2
            }
            .level(),
            FindingLevel::Warning
        );
        assert_eq!(Empty.level(), FindingLevel::Warning);
        assert_eq!(SaturationRecorded { seq: 1 }.level(), FindingLevel::Info);
        assert_eq!(
            KeyRotationRecorded {
                seq: 1,
                from_key_id: "a".into(),
                to_key_id: "b".into()
            }
            .level(),
            FindingLevel::Info
        );
        assert_eq!(
            TruncationRecorded {
                seq: 9,
                head_seq: 3,
                first_skipped: 4,
                last_skipped: 8
            }
            .level(),
            FindingLevel::Tamper
        );
        assert_eq!(
            DamageQuarantined {
                seq: 1,
                discarded_bytes: 1,
                discarded_records: 1
            }
            .level(),
            FindingLevel::Tamper
        );
        assert_eq!(
            SigningKeyUnproven {
                seq: 1,
                key_id: "k".into()
            }
            .level(),
            FindingLevel::Warning
        );
        assert_eq!(
            KeySwitchRefused {
                seq: 1,
                established_key_id: "a".into(),
                named_key_id: "b".into()
            }
            .level(),
            FindingLevel::Tamper
        );
        let kd = KeyDeviceMismatch {
            seq: 1,
            key_id: "k".into(),
            key_device: "x".into(),
            chain_device: "y".into(),
        };
        assert_eq!(kd.level(), FindingLevel::Tamper);
        assert!(kd.to_string().contains("belongs to device x"));
        assert!(FindingLevel::Info < FindingLevel::Warning);
        assert!(FindingLevel::Warning < FindingLevel::Tamper);
    }

    #[test]
    fn finding_new_takes_level_from_kind_and_displays_location() {
        let loc = Location {
            segment: "s".into(),
            segment_position: 0,
            offset: 12,
            position: 3,
            seq: Some(7),
        };
        let f = Finding::new(FindingKind::BadSignature { seq: 7 }, Some(loc));
        assert_eq!(f.level, FindingLevel::Tamper);
        let s = f.to_string();
        assert!(
            s.contains("Tamper") && s.contains("s+12") && s.contains("seq Some(7)"),
            "{s}"
        );
        let g = Finding::new(FindingKind::Empty, None);
        assert_eq!(g.level, FindingLevel::Warning);
        assert_eq!(g.to_string(), "[Warning] no records");
    }

    #[test]
    fn report_predicates() {
        let mut r = Report::default();
        assert!(r.is_intact() && r.is_clean());
        assert!(r.first_at_least(FindingLevel::Info).is_none());
        r.push(Finding::new(
            FindingKind::SaturationRecorded { seq: 1 },
            None,
        ));
        assert!(r.is_intact() && r.is_clean());
        r.push(Finding::new(FindingKind::TornTail { len: 3 }, None));
        assert!(r.is_intact() && !r.is_clean());
        assert_eq!(r.tamper().count(), 0);
        assert!(matches!(
            r.first_at_least(FindingLevel::Warning).map(|f| &f.kind),
            Some(FindingKind::TornTail { .. })
        ));
        r.push(Finding::new(FindingKind::HashMismatch { seq: 2 }, None));
        r.push(Finding::new(
            FindingKind::Fork {
                seq: 3,
                other_position: 0,
            },
            None,
        ));
        assert!(!r.is_intact() && !r.is_clean());
        let t: Vec<_> = r.tamper().map(|f| f.kind.clone()).collect();
        assert_eq!(
            t,
            vec![
                FindingKind::HashMismatch { seq: 2 },
                FindingKind::Fork {
                    seq: 3,
                    other_position: 0
                }
            ]
        );
        assert!(matches!(
            r.first_at_least(FindingLevel::Tamper).map(|f| &f.kind),
            Some(FindingKind::HashMismatch { .. })
        ));
    }

    #[test]
    fn verify_segments_clean_and_basic_tampering() {
        let mut c = Chain::new();
        for _ in 0..4 {
            c.note();
        }
        let ok = verify_segments(&[c.seg("seg")], &c.key, &VerifyOptions::default());
        assert!(ok.is_intact() && ok.is_clean(), "{:?}", kinds(&ok));
        assert_eq!((ok.first_seq, ok.last_seq), (Some(0), Some(4)));
        assert_eq!(ok.verified_records, 5);
        assert_eq!(ok.identity.as_ref(), Some(&ident()));

        // One byte of a payload flipped.
        let mut s = c.seg("seg");
        let start = s.bytes.len() - c.recs[4].encode_frame().len();
        s.bytes[start + 8 + 64 + 2] ^= 1; // inside the JSON payload
        let r = verify_segments(&[s], &c.key, &VerifyOptions::default());
        assert!(kinds(&r)
            .iter()
            .any(|k| matches!(k, FindingKind::HashMismatch { seq: 4 })));
        assert!(!r.is_intact());

        // Wrong key: one KeyMismatch, not five bad signatures.
        let other = HmacSha256Key::new("x", &[9; 32]).unwrap();
        let r = verify_segments(&[c.seg("seg")], &other, &VerifyOptions::default());
        let km = kinds(&r)
            .iter()
            .filter(|k| matches!(k, FindingKind::KeyMismatch { .. }))
            .count();
        assert_eq!(km, 1);
        assert!(!kinds(&r)
            .iter()
            .any(|k| matches!(k, FindingKind::BadSignature { .. })));

        // A record removed from the middle.
        let mut d = Chain::new();
        for _ in 0..4 {
            d.note();
        }
        d.recs.remove(2);
        let r = verify_segments(&[d.seg("seg")], &d.key, &VerifyOptions::default());
        assert!(kinds(&r).contains(&&FindingKind::Deleted {
            first_missing: 2,
            last_missing: 2
        }));

        // Device pinning.
        let r = verify_segments(
            &[c.seg("seg")],
            &c.key,
            &VerifyOptions {
                expected_device_id: Some("other".into()),
                ..Default::default()
            },
        );
        assert!(kinds(&r)
            .iter()
            .any(|k| matches!(k, FindingKind::WrongDevice { .. })));

        // Nothing at all.
        let r = verify_segments(&[], &c.key, &VerifyOptions::default());
        assert_eq!(kinds(&r), vec![&FindingKind::Empty]);
        // Pure noise never panics and is never intact-and-clean.
        let noise = SegmentData {
            name: "n".into(),
            bytes: (0..2000u32).map(|i| (i * 7919 % 251) as u8).collect(),
        };
        let r = verify_segments(&[noise], &c.key, &VerifyOptions::default());
        assert!(!r.is_clean());
    }

    #[test]
    fn records_verify_only_under_the_named_key_and_algorithm() {
        let mut c = Chain::new();
        c.note();
        let ok = verify_segments(&[c.seg("s")], &c.key, &VerifyOptions::default());
        assert!(ok.is_clean(), "{:?}", kinds(&ok));
        assert_eq!(
            ok.signing_key,
            Some(KeyRef {
                key_id: "k".into(),
                algorithm: "hmac-sha256".into()
            })
        );
        // Same key material and id, but claiming another algorithm.
        struct Claims(HmacSha256Key);
        impl Verifier for Claims {
            fn algorithm(&self) -> &str {
                "ed25519"
            }
            fn key_id(&self) -> &str {
                "k"
            }
            fn verify(&self, m: &[u8], s: &[u8]) -> bool {
                Verifier::verify(&self.0, m, s)
            }
        }
        let r = verify_segments(&[c.seg("s")], &Claims(key()), &VerifyOptions::default());
        assert!(kinds(&r)
            .iter()
            .any(|k| matches!(k, FindingKind::KeyMismatch { .. })));
        // A trusted signing_key for the chain overrides the identity's.
        let r = verify_segments(
            &[c.seg("s")],
            &c.key,
            &VerifyOptions {
                signing_key: Some(KeyRef {
                    key_id: "other".into(),
                    algorithm: "hmac-sha256".into(),
                }),
                ..Default::default()
            },
        );
        assert!(!r.is_intact());
    }

    fn recovery(seqs: Option<[u64; 2]>, plausible: bool) -> Vec<u8> {
        serde_json::to_vec(&RecoveryPayload {
            segment_index: 0,
            offset: 100,
            discarded_bytes: 300,
            discarded_sha256: "00".into(),
            reason: "t".into(),
            quarantine_file: None,
            discarded_records: 2,
            discarded_seqs: seqs,
            crash_plausible: plausible,
            severity: Some(Severity::High),
            quarantined_segment: false,
        })
        .unwrap()
    }

    #[test]
    fn crash_plausible_recovery_explains_exactly_its_gap() {
        let mut c = Chain::new();
        c.note(); // 1
        c.push_at(5, RecordKind::Resume, b"{}".to_vec()); // skips 2..=4
        c.push_at(6, RecordKind::Recovery, recovery(Some([2, 4]), true));
        let r = verify_segments(&[c.seg("s")], &c.key, &VerifyOptions::default());
        assert!(r.is_intact(), "{:?}", kinds(&r));
        assert!(!r.is_clean());
        assert!(kinds(&r)
            .iter()
            .any(|k| matches!(k, FindingKind::RecoveryRecorded { seq: 6, .. })));

        // A range that does not match the gap explains nothing.
        let mut c = Chain::new();
        c.note();
        c.push_at(5, RecordKind::Resume, b"{}".to_vec());
        c.push_at(6, RecordKind::Recovery, recovery(Some([2, 3]), true));
        let r = verify_segments(&[c.seg("s")], &c.key, &VerifyOptions::default());
        assert!(kinds(&r).contains(&&FindingKind::Deleted {
            first_missing: 2,
            last_missing: 4
        }));

        // Not crash-plausible: tamper, and the gap stays unexplained.
        let mut c = Chain::new();
        c.note();
        c.push_at(5, RecordKind::Resume, b"{}".to_vec());
        c.push_at(6, RecordKind::Recovery, recovery(Some([2, 4]), false));
        let r = verify_segments(&[c.seg("s")], &c.key, &VerifyOptions::default());
        assert!(!r.is_intact());
        assert!(kinds(&r)
            .iter()
            .any(|k| matches!(k, FindingKind::DamageQuarantined { seq: 6, .. })));
        assert!(kinds(&r)
            .iter()
            .any(|k| matches!(k, FindingKind::Deleted { .. })));
    }

    #[test]
    fn truncation_record_is_tamper() {
        let mut c = Chain::new();
        c.note();
        c.push_at(9, RecordKind::Resume, b"{}".to_vec());
        let t = serde_json::to_vec(&TruncationPayload {
            head_seq: 1,
            head_hash: "00".into(),
            evidence: Vec::new(),
            skipped_seqs: [2, 8],
            severity: Severity::Critical,
        })
        .unwrap();
        c.push_at(10, RecordKind::TruncationDetected, t);
        let r = verify_segments(&[c.seg("s")], &c.key, &VerifyOptions::default());
        assert!(!r.is_intact());
        assert!(kinds(&r).contains(&&FindingKind::TruncationRecorded {
            seq: 10,
            head_seq: 1,
            first_skipped: 2,
            last_skipped: 8
        }));
        assert!(kinds(&r).contains(&&FindingKind::Deleted {
            first_missing: 2,
            last_missing: 8
        }));
    }

    fn tmpdir(tag: &str) -> std::path::PathBuf {
        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or(0);
        let d = std::env::temp_dir().join(format!(
            "robodr-bb-verify-{tag}-{}-{nanos}",
            std::process::id()
        ));
        std::fs::create_dir_all(&d).unwrap();
        d
    }

    #[test]
    fn read_segments_orders_by_index_and_ignores_other_files() {
        let d = tmpdir("read");
        std::fs::write(d.join("seg-0000000000000002.rbb"), b"b").unwrap();
        std::fs::write(d.join("seg-0000000000000000.rbb"), b"a").unwrap();
        std::fs::write(d.join("seg-2.rbb"), b"x").unwrap();
        std::fs::write(d.join("checkpoint.json"), b"{}").unwrap();
        std::fs::create_dir(d.join("seg-0000000000000005.rbb")).unwrap();
        let s = read_segments(&d).unwrap();
        let names: Vec<_> = s.iter().map(|x| x.name.as_str()).collect();
        assert_eq!(
            names,
            vec!["seg-0000000000000000.rbb", "seg-0000000000000002.rbb"]
        );
        assert_eq!(s[0].bytes, b"a");
        assert!(read_segments(&d.join("missing")).is_err());
        std::fs::remove_dir_all(&d).unwrap();
    }

    #[test]
    fn verify_dir_uses_its_checkpoint_file() {
        let d = tmpdir("dir");
        let mut c = Chain::new();
        for _ in 0..3 {
            c.note();
        }
        std::fs::write(d.join("seg-0000000000000000.rbb"), c.seg("x").bytes).unwrap();
        assert!(verify_dir(&d, &c.key, &VerifyOptions::default())
            .unwrap()
            .is_clean());
        // A checkpoint beyond the stored head: truncation.
        let last = c.recs.last().unwrap();
        let cp = Checkpoint {
            chain_id: c.id.chain_id(),
            seq: last.seq + 2,
            hash: [1; 32],
            key_id: "k".into(),
            sig: c.key.sign(&signing_message(&[1; 32])).unwrap(),
        };
        std::fs::write(d.join(CHECKPOINT_FILE), cp.to_json()).unwrap();
        let r = verify_dir(&d, &c.key, &VerifyOptions::default()).unwrap();
        assert!(kinds(&r)
            .iter()
            .any(|k| matches!(k, FindingKind::TruncatedTail { .. })));
        // An explicit checkpoint wins over the file.
        let good = Checkpoint {
            chain_id: c.id.chain_id(),
            seq: last.seq,
            hash: last.hash,
            key_id: "k".into(),
            sig: last.sig.clone(),
        };
        let r = verify_dir(
            &d,
            &c.key,
            &VerifyOptions {
                checkpoint: Some(good),
                ..Default::default()
            },
        )
        .unwrap();
        assert!(r.is_intact(), "{:?}", kinds(&r));
        // Unparseable checkpoint file: reported, not fatal.
        std::fs::write(d.join(CHECKPOINT_FILE), b"\xff garbage").unwrap();
        let r = verify_dir(&d, &c.key, &VerifyOptions::default()).unwrap();
        assert!(kinds(&r)
            .iter()
            .any(|k| matches!(k, FindingKind::CheckpointInvalid { .. })));
        assert!(verify_dir(&d.join("nope"), &c.key, &VerifyOptions::default()).is_err());
        std::fs::remove_dir_all(&d).unwrap();
    }
}
