//! Independent verification of black-box segments and bundles.
//!
//! [`verify_segments`] needs only the segment bytes, a [`Verifier`] for the
//! chain's key and optional trusted inputs ([`VerifyOptions`]). It never
//! trusts the recorder's own bookkeeping files. It returns a [`Report`] of
//! [`Finding`]s, each with a precise [`Location`] (segment, byte offset,
//! position, sequence number) and a [`FindingLevel`]:
//!
//! - `Tamper`: evidence integrity is violated (or cannot be established).
//! - `Warning`: anomalous but explainable by a crash or by recorded data loss.
//! - `Info`: normal, recorded events worth showing (recovery, cyclic drops).
//!
//! # Diagnosis rules
//!
//! 1. Every frame is decoded strictly; undecodable bytes are `Malformed`.
//!    Bytes after the last frame of the *last* segment are a `TornTail`
//!    (warning) if they look like an interrupted write, else `TrailingGarbage`.
//! 2. Recomputed hash != stored hash: `HashMismatch` (content modified).
//! 3. Hash fine, signature invalid: `BadSignature` (modified and re-hashed, or
//!    forged/inserted without the key). If *no* record verifies, a single
//!    `KeyMismatch` is reported instead.
//! 4. Records whose `chain_id` differs from the chain's: `ForeignChain`
//!    (replayed from another device, boot or chain).
//! 5. Among authentic records of the chain: same seq twice with the same
//!    hash is a `Duplicate` (replay), with different hashes a `Fork`; a seq
//!    lower than one already seen is `Reordered`; missing seqs not explained
//!    by invalid records at that spot are `Deleted`; consecutive seqs whose
//!    `prev_hash` does not link are a `ChainBreak`.
//! 6. The head must be genesis, or be anchored: by `trusted_anchor`, or by a
//!    signed `SegmentDropped` record naming the head's predecessor (cyclic
//!    retention). Otherwise `HeadMissing`.
//! 7. Every segment except the last must end with a seal (`SegmentUnsealed`).
//! 8. With a checkpoint, records missing after it are a `TruncatedTail`, and
//!    a different hash at its seq is `CheckpointMismatch`.

use crate::crypto::to_hex;
use crate::export::{Anchor, Checkpoint};
use crate::record::{
    scan_frames, short_hex, signing_message, ChainIdentity, GenesisPayload, Hash, Record,
    RecordKind, RecoveryPayload, ScanItem, SegmentDroppedPayload, SegmentStartPayload, TailKind,
    ZERO_HASH,
};
use crate::sign::Verifier;
use crate::store::{list_segments, parse_segment_file_name, CHECKPOINT_FILE};
use serde::Serialize;
use std::collections::{BTreeMap, HashMap};
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
    TimeRegression {
        seq: u64,
        prev_mono_ns: u64,
        mono_ns: u64,
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
            | Empty => FindingLevel::Warning,
            HeadDropRecorded { .. }
            | AnchorUnverified { .. }
            | CheckpointNotRetained { .. }
            | UnsealedTail { .. }
            | RecoveryRecorded { .. }
            | SegmentDropRecorded { .. }
            | SaturationRecorded { .. } => FindingLevel::Info,
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
            TimeRegression {
                seq,
                prev_mono_ns,
                mono_ns,
            } => write!(
                f,
                "record {seq} monotonic time {mono_ns} < previous {prev_mono_ns}"
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
        self.items[pos].rec.as_ref().expect("record item")
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

    // 3. Signatures.
    let mut sig_ok = vec![false; n];
    let mut recorded_key_id = None;
    for pos in 0..n {
        if hash_ok[pos] {
            let r = cx.rec(pos);
            sig_ok[pos] = verifier.verify(&signing_message(&r.hash), &r.sig);
            if recorded_key_id.is_none() {
                recorded_key_id = identity_of(r).map(|i| i.key_id);
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
    let drop_covering = |seq_before: u64, prev: &Hash| -> Option<usize> {
        let want = to_hex(prev);
        drops
            .iter()
            .find(|(_, d)| d.last_seq == Some(seq_before) && d.last_hash.as_deref() == Some(&want))
            .map(|(p, _)| *p)
    };

    // 6. Head / anchor.
    if let Some(&head) = order.first() {
        let (s0, prev0) = (cx.rec(head).seq, cx.rec(head).prev_hash);
        let last_seq = cx.rec(*order.last().expect("non-empty")).seq;
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
                    if drop_covering(s0 - 1, &prev0).is_some() {
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
                    match drop_covering(s0 - 1, &prev0) {
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

    // 6b. Gaps and links.
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
            if explained < missing {
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
                let discarded_bytes = r
                    .payload_json::<RecoveryPayload>()
                    .map_or(0, |x| x.discarded_bytes);
                cx.add(
                    FindingKind::RecoveryRecorded {
                        seq,
                        discarded_bytes,
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

    let mut findings = std::mem::take(&mut cx.findings);
    findings.sort_by_key(|f| f.location.as_ref().map_or(usize::MAX, |l| l.position));
    Report {
        findings,
        frames,
        verified_records: order.len(),
        first_seq: order.first().map(|&p| cx.rec(p).seq),
        last_seq: last.map(|(s, _)| s),
        last_hash: last.map(|(_, h)| to_hex(&h)),
        chain_id: expected_chain.map(|c| to_hex(&c)),
        identity,
        last_seal_seq: last_seal,
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
/// directory's own `checkpoint.json` (written at every seal) is used; it is
/// only as trustworthy as the directory, so keep an external copy too.
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
    }
    let mut report = verify_segments(&segments, verifier, &o);
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
