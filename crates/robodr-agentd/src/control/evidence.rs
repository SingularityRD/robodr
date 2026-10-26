//! The evidence API (`control_plane.evidence`, off unless configured): an
//! authenticated SOC lists the black box's retained evidence and exports a
//! finding's records (or a sequence / time range) as an `RBBXBND1` bundle
//! (`robodr_blackbox::Bundle`), downloaded in signed, size-bounded,
//! resumable chunks. Contract: `docs/contracts/robodr.control-plane.md`
//! §11.
//!
//! # What leaves the robot
//!
//! Only black-box **frames** (records exactly as stored: hashed, chained,
//! signed by the black-box key) plus the chain identity, the anchor of the
//! record before the first one, and a manifest. No key material, no file
//! path and nothing outside the black box's segment files is ever read
//! into an export. The SOC verifies the bundle with the robot's black-box
//! **public** key, exactly as `robodr-blackbox verify` does
//! (`Bundle::verify_with_key`: hashes, signatures, chain linkage, chain id,
//! device), and the manifest (chunk hashes, the selection, the export's
//! black-box note) with the robot's finding public key.
//!
//! # How an export is built
//!
//! 1. Index (pass 1): every retained segment file is scanned
//!    (`record::scan_frames`, one segment in memory at a time); records of
//!    the current chain only, with their seq, wall time, hash, frame
//!    position; the chain identity from the newest `Genesis` /
//!    `SegmentStart`; the signing key in effect before every record
//!    (`SegmentStart.signing_key`, `KeyRotation.to`).
//! 2. Selection: a seq range, a time range (the contiguous span from the
//!    first to the last record whose wall time is in it), or a finding's
//!    evidence links (each must name a retained record with that hash) plus
//!    `context_records` on each side. The span must be contiguous (no
//!    dropped or quarantined seqs inside) and at most `max_export_bytes`.
//! 3. Frames (pass 2): the selected frames are copied byte for byte from
//!    the segment files; each is re-decoded and must be the indexed record
//!    (seq and hash), else the export is refused (the store changed under
//!    it: retry).
//! 4. The bundle bytes are cut into `chunk_bytes` chunks, each hashed; the
//!    export is recorded in the black box (`robodr.control_plane_evidence_export`
//!    note, by the main loop); the manifest (with that note's reference) is
//!    signed with the finding key and stored with the bundle under
//!    `<state_dir>/exports/<sha256(export id)[..32]>/` (temp directory,
//!    fsync, rename, fsync).

use std::collections::BTreeMap;
use std::fs::File;
use std::io::{self, Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};
use std::sync::Mutex;

use robodr_blackbox::crypto::{from_hex, sha256, to_hex};
use robodr_blackbox::record::{
    scan_frames, ChainIdentity, GenesisPayload, Hash, KeyRef, KeyRotationPayload, RecordKind,
    ScanItem, SegmentStartPayload,
};
use robodr_blackbox::store::parse_segment_file_name;
use robodr_blackbox::{Anchor, Bundle};
use serde::{Deserialize, Serialize};
use serde_json::Value;

use super::api::{ApiError, MAX_REASON_CHARS, MAX_REQUESTED_BY_CHARS};
use super::auth::API_VERSION;
use super::fsutil;

/// The manifest's `kind`.
pub const MANIFEST_KIND: &str = "robodr.evidence_manifest";
/// Manifest format version.
pub const MANIFEST_VERSION: u32 = 1;
/// Domain of the manifest signature.
pub const MANIFEST_DOMAIN: &str = "robodr-evidence-manifest/v1";
/// The manifest signature header.
pub const H_MANIFEST_SIGNATURE: &str = "X-RoboDR-Manifest-Signature";
/// Bundle format name in the manifest.
pub const BUNDLE_FORMAT: &str = "RBBXBND1";
/// Directory of the exports in the state directory.
pub const EXPORTS_DIR: &str = "exports";
pub const BUNDLE_FILE: &str = "bundle.rbbx";
pub const MANIFEST_FILE: &str = "manifest.json";
pub const MANIFEST_SIG_FILE: &str = "manifest.sig";
/// Largest segment file read.
pub const MAX_SEGMENT_FILE_BYTES: u64 = 256 * 1024 * 1024;
/// Largest manifest file read back.
pub const MAX_MANIFEST_BYTES: u64 = 4 * 1024 * 1024;
/// Most chunks per export.
pub const MAX_CHUNKS: u64 = 4096;
/// Most evidence links in a finding selector.
pub const MAX_LINKS: usize = 64;
/// Most context records on each side of a finding's records.
pub const MAX_CONTEXT_RECORDS: u64 = 1024;
/// Default context records.
pub const DEFAULT_CONTEXT_RECORDS: u64 = 16;
/// Widest time range (7 days).
pub const MAX_TIME_SPAN_MS: u64 = 7 * 24 * 3600 * 1000;
/// Longest `finding_id`.
pub const MAX_FINDING_ID_LEN: usize = 256;
/// Largest `max_export_bytes` a robot may be configured with (review
/// finding 7: an export is built on the robot, next to the detection loop).
pub const MAX_EXPORT_BYTES_LIMIT: u64 = 256 * 1024 * 1024;
/// Free space an export must leave on the state directory's filesystem,
/// so the request and nonce journals (same directory) never starve.
pub const FREE_SPACE_HEADROOM: u64 = 64 * 1024 * 1024;
/// Longest an export build may take; past it (or when the daemon stops)
/// the build is abandoned, so shutdown is never held by an export.
pub const BUILD_DEADLINE: std::time::Duration = std::time::Duration::from_secs(60);

fn default_max_export() -> u64 {
    64 * 1024 * 1024
}
fn default_chunk() -> u64 {
    1024 * 1024
}
fn default_max_exports() -> usize {
    8
}
fn default_storage() -> u64 {
    512 * 1024 * 1024
}
fn default_ttl() -> u64 {
    86_400
}
fn default_chunk_rate() -> u32 {
    600
}
fn default_chunk_burst() -> u32 {
    60
}

/// `control_plane.evidence` (present = the evidence API is on).
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EvidenceSection {
    /// Largest bundle, 64 KiB..=256 MiB ([`MAX_EXPORT_BYTES_LIMIT`]).
    #[serde(default = "default_max_export")]
    pub max_export_bytes: u64,
    /// Chunk size, 16 KiB..=4 MiB; at most 4096 chunks per export.
    #[serde(default = "default_chunk")]
    pub chunk_bytes: u64,
    /// Exports kept at once, 1..=64.
    #[serde(default = "default_max_exports")]
    pub max_exports: usize,
    /// Bytes of all kept bundles, max_export_bytes..=16 GiB.
    #[serde(default = "default_storage")]
    pub max_storage_bytes: u64,
    /// An export is deleted this long after its creation, 600..=604800 s.
    #[serde(default = "default_ttl")]
    pub export_ttl_s: u64,
    /// Chunk downloads per key and minute (own bucket), 1..=6000.
    #[serde(default = "default_chunk_rate")]
    pub chunk_rate_per_minute: u32,
    /// Chunk burst per key, 1..=600.
    #[serde(default = "default_chunk_burst")]
    pub chunk_burst: u32,
}

impl Default for EvidenceSection {
    fn default() -> Self {
        Self {
            max_export_bytes: default_max_export(),
            chunk_bytes: default_chunk(),
            max_exports: default_max_exports(),
            max_storage_bytes: default_storage(),
            export_ttl_s: default_ttl(),
            chunk_rate_per_minute: default_chunk_rate(),
            chunk_burst: default_chunk_burst(),
        }
    }
}

fn range(what: &str, v: u64, lo: u64, hi: u64) -> Result<(), String> {
    if (lo..=hi).contains(&v) {
        Ok(())
    } else {
        Err(format!(
            "control_plane.evidence.{what} = {v}: must be {lo}..={hi}"
        ))
    }
}

impl EvidenceSection {
    pub fn validate(&self) -> Result<(), String> {
        range(
            "max_export_bytes",
            self.max_export_bytes,
            64 * 1024,
            MAX_EXPORT_BYTES_LIMIT,
        )?;
        range("chunk_bytes", self.chunk_bytes, 16 * 1024, 4 * 1024 * 1024)?;
        if self.max_export_bytes.div_ceil(self.chunk_bytes) > MAX_CHUNKS {
            return Err(format!(
                "control_plane.evidence: max_export_bytes / chunk_bytes must be at most \
                 {MAX_CHUNKS} chunks"
            ));
        }
        range("max_exports", self.max_exports as u64, 1, 64)?;
        range(
            "max_storage_bytes",
            self.max_storage_bytes,
            self.max_export_bytes,
            16 * 1024 * 1024 * 1024,
        )?;
        range("export_ttl_s", self.export_ttl_s, 600, 604_800)?;
        range(
            "chunk_rate_per_minute",
            u64::from(self.chunk_rate_per_minute),
            1,
            6000,
        )?;
        range("chunk_burst", u64::from(self.chunk_burst), 1, 600)?;
        Ok(())
    }
}

fn bad(code: &'static str, message: impl Into<String>) -> ApiError {
    ApiError::new(400, code, message)
}

// ---------------------------------------------------------------------------
// Request bodies
// ---------------------------------------------------------------------------

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RawExport {
    export_id: String,
    selector: RawSelector,
    requested_by: String,
    #[serde(default)]
    reason: Option<String>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RawSelector {
    #[serde(default)]
    seq_range: Option<RawSeq>,
    #[serde(default)]
    time_range: Option<RawTime>,
    #[serde(default)]
    finding: Option<RawFinding>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RawSeq {
    from_seq: u64,
    to_seq: u64,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RawTime {
    from_ms: u64,
    to_ms: u64,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RawFinding {
    finding_id: String,
    evidence: Vec<String>,
    #[serde(default)]
    context_records: Option<u64>,
}

/// One black-box reference (`robodr-blackbox://<robot>/<segment>/<seq>?sha256=<hex>`).
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RecordRef {
    pub segment: u64,
    pub seq: u64,
    pub sha256: String,
}

impl RecordRef {
    pub fn uri(&self, robot_id: &str) -> String {
        format!(
            "robodr-blackbox://{robot_id}/{}/{}?sha256={}",
            self.segment, self.seq, self.sha256
        )
    }
}

/// Parse an evidence link of robot `robot_id`.
pub fn parse_link(s: &str, robot_id: &str) -> Result<RecordRef, String> {
    let rest = s
        .strip_prefix("robodr-blackbox://")
        .ok_or("not a robodr-blackbox:// link")?;
    let (path, query) = rest.split_once('?').ok_or("no ?sha256=")?;
    let hex = query.strip_prefix("sha256=").ok_or("no ?sha256=")?;
    let parts: Vec<&str> = path.split('/').collect();
    let [robot, segment, seq] = parts.as_slice() else {
        return Err("expected <robot>/<segment>/<seq>".into());
    };
    if *robot != robot_id {
        return Err("the link names another robot".into());
    }
    let num = |t: &str| -> Result<u64, String> {
        if t.is_empty() || t.len() > 20 || !t.bytes().all(|b| b.is_ascii_digit()) {
            return Err("segment and seq must be decimal numbers".into());
        }
        t.parse::<u64>()
            .map_err(|_| "segment and seq must be decimal numbers".to_string())
    };
    if hex.len() != 64 || from_hex(&hex.to_ascii_lowercase()).is_none() {
        return Err("sha256 must be 64 hex digits".into());
    }
    Ok(RecordRef {
        segment: num(segment)?,
        seq: num(seq)?,
        sha256: hex.to_ascii_lowercase(),
    })
}

/// A validated selector (also its manifest form).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub enum Selector {
    SeqRange {
        from_seq: u64,
        to_seq: u64,
    },
    TimeRange {
        from_ms: u64,
        to_ms: u64,
    },
    Finding {
        finding_id: String,
        evidence: Vec<RecordRef>,
        context_records: u64,
    },
}

/// A validated export request.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ExportRequest {
    pub export_id: String,
    pub selector: Selector,
    pub requested_by: String,
    pub reason: String,
}

impl ExportRequest {
    /// What makes two creations with one id the same export.
    pub fn digest(&self) -> String {
        to_hex(&sha256(
            serde_json::to_string(&self.selector)
                .unwrap_or_default()
                .as_bytes(),
        ))
    }
}

fn text(what: &str, s: &str, max_chars: usize, required: bool) -> Result<String, ApiError> {
    if required && s.trim().is_empty() {
        return Err(bad("invalid_field", format!("{what} is empty")));
    }
    if s.chars().count() > max_chars || s.chars().any(char::is_control) {
        return Err(bad(
            "invalid_field",
            format!("{what}: at most {max_chars} characters, no control characters"),
        ));
    }
    Ok(s.to_string())
}

fn json_error(e: &serde_json::Error) -> ApiError {
    let m = e.to_string();
    let code = if m.contains("unknown field") {
        "unknown_field"
    } else if m.contains("duplicate field") {
        "duplicate_field"
    } else {
        "invalid_request"
    };
    bad(code, robodr_ros2_pipeline::sanitize(&m))
}

/// Parse and validate an export body for robot `robot_id`.
pub fn parse_export(body: &[u8], robot_id: &str) -> Result<ExportRequest, ApiError> {
    let t =
        std::str::from_utf8(body).map_err(|_| bad("invalid_request", "the body is not UTF-8"))?;
    let v: Value = serde_json::from_str(t).map_err(|e| json_error(&e))?;
    let sel_ok = v.get("selector").is_some_and(Value::is_object);
    if !v.is_object() || !sel_ok {
        return Err(bad(
            "invalid_request",
            "the body must be a JSON object with a selector object",
        ));
    }
    let raw: RawExport = serde_json::from_str(t).map_err(|e| json_error(&e))?;
    if !super::api::request_id_ok(&raw.export_id) {
        return Err(bad(
            "invalid_export_id",
            "export_id must match [A-Za-z0-9._:-]{1,128}",
        ));
    }
    let sel = |m: String| bad("invalid_selector", m);
    let selector = match (
        raw.selector.seq_range,
        raw.selector.time_range,
        raw.selector.finding,
    ) {
        (Some(s), None, None) => {
            if s.from_seq > s.to_seq {
                return Err(sel("seq_range: from_seq must be <= to_seq".into()));
            }
            Selector::SeqRange {
                from_seq: s.from_seq,
                to_seq: s.to_seq,
            }
        }
        (None, Some(r), None) => {
            if r.from_ms > r.to_ms || r.to_ms - r.from_ms > MAX_TIME_SPAN_MS {
                return Err(sel(format!(
                    "time_range: from_ms <= to_ms, at most {MAX_TIME_SPAN_MS} ms apart"
                )));
            }
            Selector::TimeRange {
                from_ms: r.from_ms,
                to_ms: r.to_ms,
            }
        }
        (None, None, Some(f)) => {
            if f.finding_id.is_empty()
                || f.finding_id.len() > MAX_FINDING_ID_LEN
                || f.finding_id.chars().any(char::is_control)
            {
                return Err(sel(format!(
                    "finding.finding_id: 1..={MAX_FINDING_ID_LEN} bytes, no control characters"
                )));
            }
            if f.evidence.is_empty() || f.evidence.len() > MAX_LINKS {
                return Err(sel(format!(
                    "finding.evidence: 1..={MAX_LINKS} robodr-blackbox:// links"
                )));
            }
            let mut refs = Vec::new();
            for l in &f.evidence {
                let r = parse_link(l, robot_id).map_err(|e| {
                    sel(format!(
                        "finding.evidence {:?}: {e}",
                        robodr_ros2_pipeline::sanitize(l)
                    ))
                })?;
                if !refs.contains(&r) {
                    refs.push(r);
                }
            }
            refs.sort();
            let ctx = f.context_records.unwrap_or(DEFAULT_CONTEXT_RECORDS);
            if ctx > MAX_CONTEXT_RECORDS {
                return Err(sel(format!(
                    "finding.context_records: at most {MAX_CONTEXT_RECORDS}"
                )));
            }
            Selector::Finding {
                finding_id: f.finding_id,
                evidence: refs,
                context_records: ctx,
            }
        }
        _ => return Err(sel("exactly one of seq_range, time_range, finding".into())),
    };
    Ok(ExportRequest {
        export_id: raw.export_id,
        selector,
        requested_by: text(
            "requested_by",
            &raw.requested_by,
            MAX_REQUESTED_BY_CHARS,
            true,
        )?,
        reason: text(
            "reason",
            raw.reason.as_deref().unwrap_or(""),
            MAX_REASON_CHARS,
            false,
        )?,
    })
}

// ---------------------------------------------------------------------------
// The black box, read only
// ---------------------------------------------------------------------------

/// Where segment files come from (a directory, or memory for tests and
/// the contract vectors).
pub trait SegmentSource {
    /// Segment indices, ascending.
    fn list(&self) -> io::Result<Vec<u64>>;
    /// The bytes of segment `idx` (`None`: it is gone).
    fn read(&self, idx: u64) -> io::Result<Option<Vec<u8>>>;
}

/// The black-box directory (read only; files are never opened through a
/// symlink and only `seg-*.rbb` names are read).
#[derive(Debug, Clone)]
pub struct DirSource(pub PathBuf);

impl SegmentSource for DirSource {
    fn list(&self) -> io::Result<Vec<u64>> {
        let mut out = Vec::new();
        for e in std::fs::read_dir(&self.0)? {
            let e = e?;
            if let Some(i) = e.file_name().to_str().and_then(parse_segment_file_name) {
                out.push(i);
            }
        }
        out.sort_unstable();
        Ok(out)
    }

    fn read(&self, idx: u64) -> io::Result<Option<Vec<u8>>> {
        let p = self.0.join(robodr_blackbox::store::segment_file_name(idx));
        match fsutil::read_capped_nofollow(&p, MAX_SEGMENT_FILE_BYTES) {
            Ok(b) => Ok(Some(b)),
            Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(None),
            Err(e) => Err(e),
        }
    }
}

/// Segments held in memory.
#[derive(Debug, Clone, Default)]
pub struct MemSource(pub BTreeMap<u64, Vec<u8>>);

impl SegmentSource for MemSource {
    fn list(&self) -> io::Result<Vec<u64>> {
        Ok(self.0.keys().copied().collect())
    }
    fn read(&self, idx: u64) -> io::Result<Option<Vec<u8>>> {
        Ok(self.0.get(&idx).cloned())
    }
}

/// One indexed record.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RecMeta {
    pub seq: u64,
    pub segment: u64,
    pub offset: u64,
    pub frame_len: u64,
    pub wall_ms: u64,
    pub hash: Hash,
}

/// Pass 1: the current chain's records.
#[derive(Debug, Clone)]
pub struct Index {
    pub identity: ChainIdentity,
    pub chain_id: Hash,
    /// In seq order (file order).
    pub records: Vec<RecMeta>,
    /// `(first seq it applies to, key)`, ascending: the key in effect for a
    /// record is the last entry whose seq is <= the record's.
    pub keys: Vec<(u64, KeyRef)>,
    /// Records of other chains skipped.
    pub foreign: u64,
    /// Bytes per segment file.
    pub segment_bytes: BTreeMap<u64, u64>,
}

/// Why the index or an export could not be built.
fn unavailable(m: impl Into<String>) -> ApiError {
    ApiError::new(503, "evidence_unavailable", m)
}

/// Index the black box (see the module docs).
pub fn index(src: &dyn SegmentSource) -> Result<Index, ApiError> {
    let ids = src
        .list()
        .map_err(|e| unavailable(format!("listing the black box: {e}")))?;
    // Per segment: (idx, len, records with their chain ids).
    struct Raw {
        meta: RecMeta,
        chain_id: Hash,
        kind: RecordKind,
        identity: Option<(ChainIdentity, Option<KeyRef>)>,
        rotation_to: Option<KeyRef>,
    }
    let mut raw: Vec<Raw> = Vec::new();
    let mut segment_bytes = BTreeMap::new();
    for idx in ids {
        let Some(bytes) = src
            .read(idx)
            .map_err(|e| unavailable(format!("reading black-box segment {idx}: {e}")))?
        else {
            continue; // removed by retention since the listing
        };
        segment_bytes.insert(idx, bytes.len() as u64);
        for item in scan_frames(&bytes).items {
            let ScanItem::Record(r) = item else {
                continue;
            };
            let rec = r.record;
            let identity = match rec.kind {
                RecordKind::Genesis => rec
                    .payload_json::<GenesisPayload>()
                    .map(|p| (p.identity, None)),
                RecordKind::SegmentStart => rec
                    .payload_json::<SegmentStartPayload>()
                    .map(|p| (p.identity, p.signing_key)),
                _ => None,
            };
            let rotation_to = (rec.kind == RecordKind::KeyRotation)
                .then(|| rec.payload_json::<KeyRotationPayload>().map(|p| p.to))
                .flatten();
            raw.push(Raw {
                meta: RecMeta {
                    seq: rec.seq,
                    segment: idx,
                    offset: r.offset,
                    frame_len: r.frame_len,
                    wall_ms: rec.time.wall_ns / 1_000_000,
                    hash: rec.hash,
                },
                chain_id: rec.chain_id,
                kind: rec.kind,
                identity,
                rotation_to,
            });
        }
    }
    let Some(last) = raw.last() else {
        return Err(ApiError::new(
            404,
            "no_records",
            "the black box holds no records",
        ));
    };
    let chain_id = last.chain_id;
    // The newest identity statement that hashes to the chain id.
    let identity = raw
        .iter()
        .rev()
        .filter_map(|r| r.identity.as_ref().map(|(i, _)| i))
        .find(|i| i.chain_id() == chain_id)
        .cloned()
        .ok_or_else(|| {
            unavailable("no retained Genesis or SegmentStart names the current chain")
        })?;
    let mut records = Vec::new();
    let mut keys: Vec<(u64, KeyRef)> = Vec::new();
    let mut foreign = 0u64;
    let chain_key = KeyRef {
        key_id: identity.key_id.clone(),
        algorithm: identity.algorithm.clone(),
    };
    for r in raw {
        if r.chain_id != chain_id {
            foreign += 1;
            continue;
        }
        // The key that signs this record: a SegmentStart names its
        // segment's key (it is signed by it).
        if let (RecordKind::SegmentStart, Some((_, k))) = (r.kind, &r.identity) {
            let k = k.clone().unwrap_or_else(|| chain_key.clone());
            if keys.last().is_none_or(|(_, cur)| *cur != k) {
                keys.push((r.meta.seq, k));
            }
        } else if keys.is_empty() {
            keys.push((r.meta.seq, chain_key.clone()));
        }
        let seq = r.meta.seq;
        records.push(r.meta);
        // A rotation record is signed by the old key; the next one onwards
        // by the new key.
        if let Some(to) = r.rotation_to {
            keys.push((seq.saturating_add(1), to));
        }
    }
    Ok(Index {
        identity,
        chain_id,
        records,
        keys,
        foreign,
        segment_bytes,
    })
}

impl Index {
    /// The key that signs record `seq`.
    pub fn key_at(&self, seq: u64) -> KeyRef {
        self.keys
            .iter()
            .rev()
            .find(|(from, _)| *from <= seq)
            .or_else(|| self.keys.first())
            .map(|(_, k)| k.clone())
            .unwrap_or_else(|| KeyRef {
                key_id: self.identity.key_id.clone(),
                algorithm: self.identity.algorithm.clone(),
            })
    }

    fn pos(&self, seq: u64) -> Option<usize> {
        self.records.binary_search_by_key(&seq, |r| r.seq).ok()
    }
}

/// Retained evidence per segment (the inventory).
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct SegmentSummary {
    pub segment: u64,
    pub first_seq: u64,
    pub last_seq: u64,
    pub first_wall_ms: u64,
    pub last_wall_ms: u64,
    pub records: u64,
    pub bytes: u64,
}

/// The inventory answer (`GET .../evidence`), minus the exports.
pub fn inventory(ix: &Index, robot_id: &str) -> Value {
    let mut segs: Vec<SegmentSummary> = Vec::new();
    for r in &ix.records {
        match segs.last_mut() {
            Some(s) if s.segment == r.segment => {
                s.last_seq = r.seq;
                s.last_wall_ms = r.wall_ms;
                s.records += 1;
            }
            _ => segs.push(SegmentSummary {
                segment: r.segment,
                first_seq: r.seq,
                last_seq: r.seq,
                first_wall_ms: r.wall_ms,
                last_wall_ms: r.wall_ms,
                records: 1,
                bytes: ix.segment_bytes.get(&r.segment).copied().unwrap_or(0),
            }),
        }
    }
    let gaps: Vec<Value> = ix
        .records
        .windows(2)
        .filter(|w| w[1].seq != w[0].seq + 1)
        .map(|w| serde_json::json!({"after_seq": w[0].seq, "next_seq": w[1].seq}))
        .collect();
    let first = ix.records.first();
    let last = ix.records.last();
    serde_json::json!({
        "robot_id": robot_id,
        "api": API_VERSION,
        "chain": {
            "chain_id": to_hex(&ix.chain_id),
            "identity": ix.identity,
            "signing_key": last.map(|r| ix.key_at(r.seq)),
        },
        "retained": {
            "first_seq": first.map(|r| r.seq),
            "last_seq": last.map(|r| r.seq),
            "first_wall_ms": first.map(|r| r.wall_ms),
            "last_wall_ms": last.map(|r| r.wall_ms),
            "records": ix.records.len(),
            "gaps": gaps,
            "segments": segs,
        },
        "head": last.map(|r| serde_json::json!({"seq": r.seq, "sha256": to_hex(&r.hash)})),
    })
}

/// The selected, contiguous span `[lo, hi]` (indices into `ix.records`)
/// and the referenced records (finding selector).
pub fn select(ix: &Index, sel: &Selector) -> Result<(usize, usize, Vec<RecordRef>), ApiError> {
    let n = ix.records.len();
    if n == 0 {
        return Err(ApiError::new(
            404,
            "no_records",
            "the black box holds no records",
        ));
    }
    let first = ix.records[0].seq;
    let last = ix.records[n - 1].seq;
    let out_of_range = |what: String| {
        ApiError::new(
            416,
            "out_of_range",
            format!("{what}; retained seqs are {first}..={last}"),
        )
    };
    let (lo, hi, refs) = match sel {
        Selector::SeqRange { from_seq, to_seq } => {
            if *from_seq < first || *to_seq > last {
                return Err(out_of_range(format!(
                    "seq_range {from_seq}..={to_seq} is not retained"
                )));
            }
            let lo = ix
                .pos(*from_seq)
                .ok_or_else(|| gap_error(*from_seq, *from_seq))?;
            let hi = ix.pos(*to_seq).ok_or_else(|| gap_error(*to_seq, *to_seq))?;
            (lo, hi, Vec::new())
        }
        Selector::TimeRange { from_ms, to_ms } => {
            let mut m = ix
                .records
                .iter()
                .enumerate()
                .filter(|(_, r)| (*from_ms..=*to_ms).contains(&r.wall_ms))
                .map(|(i, _)| i);
            let Some(lo) = m.next() else {
                return Err(ApiError::new(
                    404,
                    "no_records",
                    "no retained record has a wall time in time_range",
                ));
            };
            let hi = m.next_back().unwrap_or(lo);
            (lo, hi, Vec::new())
        }
        Selector::Finding {
            evidence,
            context_records,
            ..
        } => {
            let mut idx = Vec::new();
            for r in evidence {
                let Some(i) = ix.pos(r.seq) else {
                    return Err(ApiError::new(
                        404,
                        "evidence_not_retained",
                        format!(
                            "record {} is not retained (retained seqs {first}..={last})",
                            r.seq
                        ),
                    ));
                };
                let m = &ix.records[i];
                if to_hex(&m.hash) != r.sha256 || m.segment != r.segment {
                    return Err(ApiError::new(
                        409,
                        "evidence_mismatch",
                        format!(
                            "record {} is in segment {} with sha256 {}, not as the link says",
                            r.seq,
                            m.segment,
                            to_hex(&m.hash)
                        ),
                    ));
                }
                idx.push(i);
            }
            let (Some(&a), Some(&b)) = (idx.iter().min(), idx.iter().max()) else {
                return Err(bad("invalid_selector", "no evidence link"));
            };
            // Context, but only as far as the seqs stay contiguous.
            let ctx = *context_records as usize;
            let mut lo = a;
            while lo > 0 && a - lo < ctx && ix.records[lo - 1].seq + 1 == ix.records[lo].seq {
                lo -= 1;
            }
            let mut hi = b;
            while hi + 1 < n && hi - b < ctx && ix.records[hi].seq + 1 == ix.records[hi + 1].seq {
                hi += 1;
            }
            (lo, hi, evidence.clone())
        }
    };
    if let Some(w) = ix.records[lo..=hi]
        .windows(2)
        .find(|w| w[1].seq != w[0].seq + 1)
    {
        return Err(gap_error(w[0].seq + 1, w[1].seq - 1));
    }
    Ok((lo, hi, refs))
}

fn gap_error(a: u64, b: u64) -> ApiError {
    ApiError::new(
        409,
        "evidence_gap",
        format!(
            "seqs {a}..={b} inside the selection are not retained (dropped or quarantined); \
             select a contiguous range"
        ),
    )
}

/// A built (not yet recorded) export.
#[derive(Debug, Clone)]
pub struct Built {
    pub bundle: Vec<u8>,
    pub records: RecordsInfo,
    pub anchor: Option<AnchorInfo>,
    pub referenced: Vec<RecordRef>,
    pub chain: ChainInfo,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RecordsInfo {
    pub first_seq: u64,
    pub last_seq: u64,
    pub count: u64,
    pub first_wall_ms: u64,
    pub last_wall_ms: u64,
    pub last_sha256: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AnchorInfo {
    pub seq: u64,
    pub sha256: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ChainInfo {
    pub chain_id: String,
    pub identity: ChainIdentity,
    /// The key that signs the first exported record (verify with it).
    pub signing_key: KeyRef,
}

/// What a build found besides the bundle bytes.
#[derive(Debug, Clone)]
pub struct BuiltMeta {
    pub records: RecordsInfo,
    pub anchor: Option<AnchorInfo>,
    pub referenced: Vec<RecordRef>,
    pub chain: ChainInfo,
}

/// Bytes of frames a selection exports (the bundle adds a small header).
pub fn selection_bytes(ix: &Index, lo: usize, hi: usize) -> u64 {
    ix.records
        .get(lo..=hi)
        .map(|sel| sel.iter().map(|r| r.frame_len).sum())
        .unwrap_or(0)
}

/// A writer that hashes the whole stream and each `chunk_bytes` chunk of
/// it as it goes (the manifest's bundle section, without holding the
/// bundle in memory).
struct ChunkHasher<'a> {
    out: &'a mut dyn Write,
    chunk_bytes: u64,
    total: robodr_blackbox::crypto::Sha256,
    chunk: robodr_blackbox::crypto::Sha256,
    chunk_len: u64,
    bytes: u64,
    chunks: Vec<ChunkInfo>,
}

impl<'a> ChunkHasher<'a> {
    fn new(out: &'a mut dyn Write, chunk_bytes: u64) -> Self {
        Self {
            out,
            chunk_bytes: chunk_bytes.max(1),
            total: robodr_blackbox::crypto::Sha256::new(),
            chunk: robodr_blackbox::crypto::Sha256::new(),
            chunk_len: 0,
            bytes: 0,
            chunks: Vec::new(),
        }
    }

    fn end_chunk(&mut self) {
        let h = std::mem::replace(&mut self.chunk, robodr_blackbox::crypto::Sha256::new());
        self.chunks.push(ChunkInfo {
            index: self.chunks.len() as u64,
            offset: self.bytes - self.chunk_len,
            bytes: self.chunk_len,
            sha256: to_hex(&h.finalize()),
        });
        self.chunk_len = 0;
    }

    fn put(&mut self, data: &[u8]) -> io::Result<()> {
        self.out.write_all(data)?;
        self.total.update(data);
        let mut rest = data;
        while !rest.is_empty() {
            let room = (self.chunk_bytes - self.chunk_len) as usize;
            let n = room.min(rest.len());
            self.chunk.update(&rest[..n]);
            self.chunk_len += n as u64;
            self.bytes += n as u64;
            rest = &rest[n..];
            if self.chunk_len == self.chunk_bytes {
                self.end_chunk();
            }
        }
        Ok(())
    }

    fn finish(mut self) -> BundleInfo {
        if self.chunk_len > 0 {
            self.end_chunk();
        }
        BundleInfo {
            format: BUNDLE_FORMAT.into(),
            bytes: self.bytes,
            sha256: to_hex(&self.total.finalize()),
            chunk_bytes: self.chunk_bytes,
            chunks: self.chunks,
        }
    }
}

/// Pass 2: copy the frames of `[lo, hi]` into a bundle written to `out`
/// as it is read (one black-box segment in memory at a time, never the
/// bundle; review finding 7), at most `max_bytes` of frames. Returns the
/// bundle's manifest section (`chunk_bytes` chunks) and what it holds.
/// `cancel` is asked before every record: `true` (past the build deadline,
/// or the daemon is stopping) abandons the build with 503
/// `evidence_timeout`.
#[allow(clippy::too_many_arguments)]
pub fn build_into(
    src: &dyn SegmentSource,
    ix: &Index,
    lo: usize,
    hi: usize,
    referenced: Vec<RecordRef>,
    max_bytes: u64,
    chunk_bytes: u64,
    out: &mut dyn Write,
    cancel: &dyn Fn() -> bool,
) -> Result<(BundleInfo, BuiltMeta), ApiError> {
    let sel = ix.records.get(lo..=hi).unwrap_or_default();
    let (Some(f), Some(l)) = (sel.first(), sel.last()) else {
        return Err(unavailable("empty selection"));
    };
    let total = selection_bytes(ix, lo, hi);
    if total > max_bytes {
        return Err(ApiError::new(
            413,
            "export_too_large",
            format!(
                "{} records, {total} bytes of frames: more than max_export_bytes {max_bytes}; \
                 select fewer records",
                sel.len()
            ),
        ));
    }
    let io_err = |e: io::Error| unavailable(format!("writing the export: {e}"));
    let mut w = ChunkHasher::new(out, chunk_bytes);
    let mut anchor: Option<Anchor> = None;
    let mut cur: Option<(u64, Vec<u8>)> = None;
    let changed = || unavailable("the black box changed while exporting (retention); retry");
    for m in sel {
        if cancel() {
            return Err(ApiError::new(
                503,
                "evidence_timeout",
                format!(
                    "the export was abandoned: it took longer than {} s or the daemon is \
                     stopping; select fewer records",
                    BUILD_DEADLINE.as_secs()
                ),
            ));
        }
        if cur.as_ref().is_none_or(|(i, _)| *i != m.segment) {
            let b = src
                .read(m.segment)
                .map_err(|e| unavailable(format!("reading black-box segment {}: {e}", m.segment)))?
                .ok_or_else(changed)?;
            cur = Some((m.segment, b));
        }
        let Some((_, seg)) = cur.as_ref() else {
            return Err(changed());
        };
        let (a, b) = (m.offset as usize, (m.offset + m.frame_len) as usize);
        let frame = seg.get(a..b).ok_or_else(changed)?;
        // The bytes must still be that record.
        let scan = scan_frames(frame);
        let rec = match (scan.items.as_slice(), &scan.tail) {
            ([ScanItem::Record(r)], None) => &r.record,
            _ => return Err(changed()),
        };
        if rec.seq != m.seq || rec.hash != m.hash || rec.chain_id != ix.chain_id {
            return Err(changed());
        }
        if m.seq == f.seq {
            // The header (it carries the anchor: the first record's
            // predecessor), in the bundle's own encoding: a bundle without
            // frames ends with its frame length (0), which is replaced.
            anchor = (f.seq > 0).then(|| Anchor {
                chain_id: ix.chain_id,
                seq: f.seq - 1,
                hash: rec.prev_hash,
            });
            let mut head = Bundle {
                identity: ix.identity.clone(),
                anchor: anchor.clone(),
                frames: Vec::new(),
            }
            .to_bytes();
            let cut = head.len().saturating_sub(8);
            head.truncate(cut);
            head.extend_from_slice(&total.to_be_bytes());
            w.put(&head).map_err(io_err)?;
        }
        w.put(frame).map_err(io_err)?;
    }
    w.out.flush().map_err(io_err)?;
    let info = w.finish();
    Ok((
        info,
        BuiltMeta {
            records: RecordsInfo {
                first_seq: f.seq,
                last_seq: l.seq,
                count: sel.len() as u64,
                first_wall_ms: f.wall_ms,
                last_wall_ms: l.wall_ms,
                last_sha256: to_hex(&l.hash),
            },
            anchor: anchor.map(|a| AnchorInfo {
                seq: a.seq,
                sha256: to_hex(&a.hash),
            }),
            referenced,
            chain: ChainInfo {
                chain_id: to_hex(&ix.chain_id),
                identity: ix.identity.clone(),
                signing_key: ix.key_at(f.seq),
            },
        },
    ))
}

/// [`build_into`] a buffer (tests, the contract vectors).
pub fn build(
    src: &dyn SegmentSource,
    ix: &Index,
    lo: usize,
    hi: usize,
    referenced: Vec<RecordRef>,
    max_bytes: u64,
) -> Result<Built, ApiError> {
    let mut bundle = Vec::new();
    let (_, m) = build_into(
        src,
        ix,
        lo,
        hi,
        referenced,
        max_bytes,
        4 * 1024 * 1024,
        &mut bundle,
        &|| false,
    )?;
    Ok(Built {
        bundle,
        records: m.records,
        anchor: m.anchor,
        referenced: m.referenced,
        chain: m.chain,
    })
}

/// Free bytes for an unprivileged writer on the filesystem holding `dir`
/// (`statvfs`; `None` where it is not available).
#[allow(unsafe_code)]
pub fn free_bytes(dir: &Path) -> Option<u64> {
    #[cfg(all(target_os = "linux", target_pointer_width = "64"))]
    {
        use std::os::unix::ffi::OsStrExt;
        extern "C" {
            fn statvfs(path: *const std::ffi::c_char, buf: *mut u64) -> std::ffi::c_int;
        }
        let c = std::ffi::CString::new(dir.as_os_str().as_bytes()).ok()?;
        // Larger than `struct statvfs` on every 64-bit Linux libc (glibc,
        // musl: 112 bytes); its first fields are f_bsize, f_frsize,
        // f_blocks, f_bfree, f_bavail, all 64-bit here.
        let mut buf = [0u64; 32];
        // SAFETY: `c` is a NUL-terminated path that outlives the call;
        // `buf` is a writable, 8-byte aligned buffer larger than the
        // struct the call fills.
        let rc = unsafe { statvfs(c.as_ptr(), buf.as_mut_ptr()) };
        if rc != 0 {
            return None;
        }
        let (frsize, bavail) = (buf[1], buf[4]);
        Some(frsize.saturating_mul(bavail))
    }
    #[cfg(not(all(target_os = "linux", target_pointer_width = "64")))]
    {
        let _ = dir;
        None
    }
}

/// Whether storing `need` more bytes leaves [`FREE_SPACE_HEADROOM`] free
/// (`free`: [`free_bytes`]; unknown = not checked). 507 `storage_full`
/// otherwise.
pub fn check_free_space(free: Option<u64>, need: u64) -> Result<(), ApiError> {
    match free {
        Some(f) if f < need.saturating_add(FREE_SPACE_HEADROOM) => Err(ApiError::new(
            507,
            "storage_full",
            format!(
                "the state directory's filesystem has {f} bytes free; this export ({need} \
                 bytes) must leave {FREE_SPACE_HEADROOM} free for the request and nonce \
                 journals; delete exports or free space first"
            ),
        )),
        _ => Ok(()),
    }
}

// ---------------------------------------------------------------------------
// Manifest
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ChunkInfo {
    pub index: u64,
    pub offset: u64,
    pub bytes: u64,
    pub sha256: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BundleInfo {
    pub format: String,
    pub bytes: u64,
    pub sha256: String,
    pub chunk_bytes: u64,
    pub chunks: Vec<ChunkInfo>,
}

/// The export manifest (field order is the wire order).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Manifest {
    pub kind: String,
    pub version: u32,
    pub api: String,
    pub robot_id: String,
    pub export_id: String,
    pub created_at_ms: u64,
    pub expires_at_ms: u64,
    pub requested_by: String,
    pub reason: String,
    /// The SOC key that asked for the export.
    pub key_id: String,
    pub selector: Selector,
    pub chain: ChainInfo,
    pub records: RecordsInfo,
    pub anchor: Option<AnchorInfo>,
    pub referenced: Vec<RecordRef>,
    pub bundle: BundleInfo,
    /// The export's `robodr.control_plane_evidence_export` black-box note.
    pub evidence: String,
}

/// Cut `bundle` into chunks of `chunk_bytes`.
pub fn bundle_info(bundle: &[u8], chunk_bytes: u64) -> BundleInfo {
    let cb = chunk_bytes.max(1) as usize;
    let chunks = bundle
        .chunks(cb)
        .enumerate()
        .map(|(i, c)| ChunkInfo {
            index: i as u64,
            offset: (i * cb) as u64,
            bytes: c.len() as u64,
            sha256: to_hex(&sha256(c)),
        })
        .collect();
    BundleInfo {
        format: BUNDLE_FORMAT.into(),
        bytes: bundle.len() as u64,
        sha256: to_hex(&sha256(bundle)),
        chunk_bytes,
        chunks,
    }
}

/// The bytes the finding key signs for a manifest.
pub fn manifest_message(manifest_bytes: &[u8]) -> Vec<u8> {
    format!("{MANIFEST_DOMAIN}\n{}", to_hex(&sha256(manifest_bytes))).into_bytes()
}

/// `ed25519;key_id=<id>;sig=<128 hex>` over [`manifest_message`].
pub fn sign_manifest(
    signer: &dyn robodr_blackbox::Signer,
    manifest_bytes: &[u8],
) -> Result<String, String> {
    let sig = signer
        .sign(&manifest_message(manifest_bytes))
        .map_err(|e| e.to_string())?;
    Ok(format!(
        "ed25519;key_id={};sig={}",
        signer.key_id(),
        to_hex(&sig)
    ))
}

/// Parse a signature header value `ed25519;key_id=<id>;sig=<hex>`.
pub fn parse_signature_header(v: &str) -> Option<(String, Vec<u8>)> {
    let rest = v.strip_prefix("ed25519;key_id=")?;
    let (id, sig) = rest.rsplit_once(";sig=")?;
    let sig = from_hex(sig)?;
    (sig.len() == 64 && !id.is_empty()).then(|| (id.to_string(), sig))
}

// ---------------------------------------------------------------------------
// Stored exports
// ---------------------------------------------------------------------------

/// One stored export.
#[derive(Debug, Clone)]
pub struct Stored {
    pub dir: PathBuf,
    pub manifest: Manifest,
    pub manifest_bytes: Vec<u8>,
    pub signature: String,
    pub digest: String,
}

/// The exports kept in `<state_dir>/exports`.
#[derive(Debug, Default)]
pub struct Store {
    pub dir: PathBuf,
    pub exports: BTreeMap<String, Stored>,
    /// Counters.
    pub created: u64,
    pub deleted: u64,
    pub expired: u64,
    pub discarded_at_open: u64,
    pub chunks_served: u64,
    pub corrupt: u64,
}

/// The directory name of an export id.
pub fn export_dir_name(export_id: &str) -> String {
    to_hex(&sha256(export_id.as_bytes()))[..32].to_string()
}

fn selector_digest(sel: &Selector) -> String {
    to_hex(&sha256(
        serde_json::to_string(sel).unwrap_or_default().as_bytes(),
    ))
}

impl Store {
    /// Open `<state_dir>/exports`: remove temp leftovers, load every export
    /// whose files are consistent, discard the rest and the expired ones.
    pub fn open(state_dir: &Path, now_ms: u64) -> io::Result<Store> {
        let dir = state_dir.join(EXPORTS_DIR);
        fsutil::create_dir_private(&dir)?;
        let mut st = Store {
            dir: dir.clone(),
            ..Store::default()
        };
        for e in std::fs::read_dir(&dir)? {
            let e = e?;
            let name = e.file_name().to_string_lossy().into_owned();
            let p = e.path();
            let ok = (|| -> Option<Stored> {
                if name.starts_with('.') || !e.file_type().ok()?.is_dir() {
                    return None;
                }
                let manifest_bytes =
                    fsutil::read_capped_nofollow(&p.join(MANIFEST_FILE), MAX_MANIFEST_BYTES)
                        .ok()?;
                let manifest: Manifest = serde_json::from_slice(&manifest_bytes).ok()?;
                let sig = fsutil::read_capped_nofollow(&p.join(MANIFEST_SIG_FILE), 4096).ok()?;
                let signature = String::from_utf8(sig).ok()?.trim().to_string();
                let blen = std::fs::symlink_metadata(p.join(BUNDLE_FILE)).ok()?;
                if !blen.is_file()
                    || blen.len() != manifest.bundle.bytes
                    || export_dir_name(&manifest.export_id) != name
                    || manifest.kind != MANIFEST_KIND
                    || manifest.expires_at_ms <= now_ms
                {
                    return None;
                }
                Some(Stored {
                    dir: p.clone(),
                    digest: selector_digest(&manifest.selector),
                    manifest,
                    manifest_bytes,
                    signature,
                })
            })();
            match ok {
                Some(s) => {
                    st.exports.insert(s.manifest.export_id.clone(), s);
                }
                None => {
                    if !name.starts_with('.') {
                        st.discarded_at_open += 1;
                    }
                    let _ = remove_dir(&p);
                }
            }
        }
        let _ = fsutil::sync_dir(&dir);
        Ok(st)
    }

    pub fn bytes(&self) -> u64 {
        self.exports.values().map(|s| s.manifest.bundle.bytes).sum()
    }

    /// Delete what has expired.
    pub fn purge(&mut self, now_ms: u64) {
        let dead: Vec<String> = self
            .exports
            .iter()
            .filter(|(_, s)| s.manifest.expires_at_ms <= now_ms)
            .map(|(k, _)| k.clone())
            .collect();
        for k in dead {
            if let Some(s) = self.exports.remove(&k) {
                let _ = remove_dir(&s.dir);
                self.expired += 1;
            }
        }
    }

    /// Remove export `id`.
    pub fn delete(&mut self, id: &str) -> bool {
        match self.exports.remove(id) {
            Some(s) => {
                let _ = remove_dir(&s.dir);
                let _ = fsutil::sync_dir(&self.dir);
                self.deleted += 1;
                true
            }
            None => false,
        }
    }

    /// Insert an export written by [`write_export`] (replacing one with
    /// the same id).
    pub fn insert(&mut self, s: Stored) {
        self.created += 1;
        self.exports.insert(s.manifest.export_id.clone(), s);
    }

    /// The summary of every export (inventory).
    pub fn list(&self) -> Vec<Value> {
        self.exports
            .values()
            .map(|s| {
                let m = &s.manifest;
                serde_json::json!({
                    "export_id": m.export_id,
                    "created_at_ms": m.created_at_ms,
                    "expires_at_ms": m.expires_at_ms,
                    "first_seq": m.records.first_seq,
                    "last_seq": m.records.last_seq,
                    "bytes": m.bundle.bytes,
                    "chunks": m.bundle.chunks.len(),
                    "manifest_sha256": to_hex(&sha256(&s.manifest_bytes)),
                })
            })
            .collect()
    }
}

/// An export being written: `<exports_dir>/.tmp-<random>/`, removed on
/// drop unless [`TempExport::finish`]ed. The bundle is streamed into
/// [`TempExport::bundle_file`] while it is built (review finding 7).
#[derive(Debug)]
pub struct TempExport {
    exports_dir: PathBuf,
    dir: PathBuf,
    done: bool,
}

impl TempExport {
    pub fn create(exports_dir: &Path) -> io::Result<Self> {
        let dir = exports_dir.join(format!(".tmp-{}", fsutil::random_hex16()?));
        fsutil::create_dir_private(&dir)?;
        Ok(Self {
            exports_dir: exports_dir.to_path_buf(),
            dir,
            done: false,
        })
    }

    /// The bundle file (created exclusively, 0600); the caller fsyncs it.
    pub fn bundle_file(&self) -> io::Result<File> {
        fsutil::create_new_private(&self.dir.join(BUNDLE_FILE))
    }

    /// Write the manifest and its signature, fsync, rename into place,
    /// fsync the directory; the [`Stored`] to insert.
    pub fn finish(
        mut self,
        manifest: Manifest,
        manifest_bytes: Vec<u8>,
        signature: String,
    ) -> io::Result<Stored> {
        let fin = self.exports_dir.join(export_dir_name(&manifest.export_id));
        for (f, data) in [
            (MANIFEST_FILE, manifest_bytes.as_slice()),
            (MANIFEST_SIG_FILE, signature.as_bytes()),
        ] {
            let mut h = fsutil::create_new_private(&self.dir.join(f))?;
            h.write_all(data)?;
            h.sync_all()?;
        }
        fsutil::sync_dir(&self.dir)?;
        remove_dir(&fin)?;
        std::fs::rename(&self.dir, &fin)?;
        self.done = true;
        fsutil::sync_dir(&self.exports_dir)?;
        Ok(Stored {
            dir: fin,
            digest: selector_digest(&manifest.selector),
            manifest,
            manifest_bytes,
            signature,
        })
    }
}

impl Drop for TempExport {
    fn drop(&mut self) {
        if !self.done {
            let _ = remove_dir(&self.dir);
        }
    }
}

/// Write a finished export from an in-memory bundle under `exports_dir`
/// (temp directory, files fsynced, rename, directory fsynced); the
/// [`Stored`] to insert.
pub fn write_export(
    exports_dir: &Path,
    manifest: Manifest,
    manifest_bytes: Vec<u8>,
    signature: String,
    bundle: &[u8],
) -> io::Result<Stored> {
    let t = TempExport::create(exports_dir)?;
    let mut f = t.bundle_file()?;
    f.write_all(bundle)?;
    f.sync_all()?;
    t.finish(manifest, manifest_bytes, signature)
}

/// Read chunk `index` of `s` and check it against the manifest.
pub fn read_chunk(s: &Stored, index: u64) -> Result<Vec<u8>, ApiError> {
    let Some(c) = s.manifest.bundle.chunks.get(index as usize) else {
        return Err(ApiError::new(
            404,
            "unknown_chunk",
            format!(
                "chunk {index} does not exist (the export has {} chunks)",
                s.manifest.bundle.chunks.len()
            ),
        ));
    };
    let corrupt = || {
        ApiError::new(
            500,
            "export_corrupt",
            "the stored export does not match its manifest; it was deleted, create it again",
        )
    };
    let mut f = fsutil::open_read_nofollow(&s.dir.join(BUNDLE_FILE)).map_err(|_| corrupt())?;
    f.seek(SeekFrom::Start(c.offset)).map_err(|_| corrupt())?;
    let mut buf = vec![0u8; c.bytes as usize];
    f.read_exact(&mut buf).map_err(|_| corrupt())?;
    if to_hex(&sha256(&buf)) != c.sha256 {
        return Err(corrupt());
    }
    Ok(buf)
}

fn remove_dir(p: &Path) -> io::Result<()> {
    match std::fs::symlink_metadata(p) {
        Ok(m) if m.is_dir() => std::fs::remove_dir_all(p),
        Ok(_) => std::fs::remove_file(p),
        Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(()),
        Err(e) => Err(e),
    }
}

/// The evidence API's shared state (listener threads).
#[derive(Debug)]
pub struct Service {
    pub spec: EvidenceSection,
    pub blackbox: PathBuf,
    pub store: Mutex<Store>,
    /// One index / build at a time (`evidence_busy` otherwise).
    pub building: Mutex<()>,
}

// ---------------------------------------------------------------------------
// Decision notes (journal reconciliation at start)
// ---------------------------------------------------------------------------

/// Find the black-box notes that carry one of `ids` as `decision_id`; their
/// evidence references (`robodr-blackbox://<robot>/<segment>/<seq>?sha256=`).
pub fn find_decision_notes(
    src: &dyn SegmentSource,
    robot_id: &str,
    ids: &[String],
) -> io::Result<BTreeMap<String, String>> {
    let mut out = BTreeMap::new();
    if ids.is_empty() {
        return Ok(out);
    }
    for idx in src.list()? {
        let Some(bytes) = src.read(idx)? else {
            continue;
        };
        for item in scan_frames(&bytes).items {
            let ScanItem::Record(r) = item else {
                continue;
            };
            let rec = r.record;
            if rec.kind != RecordKind::Note {
                continue;
            }
            // Cheap pre-filter before parsing.
            let Some(id) = ids
                .iter()
                .find(|id| rec.payload.windows(id.len()).any(|w| w == id.as_bytes()))
            else {
                continue;
            };
            let Ok(v) = serde_json::from_slice::<Value>(&rec.payload) else {
                continue;
            };
            if v.get("decision_id").and_then(Value::as_str) == Some(id.as_str()) {
                out.insert(
                    id.clone(),
                    RecordRef {
                        segment: idx,
                        seq: rec.seq,
                        sha256: to_hex(&rec.hash),
                    }
                    .uri(robot_id),
                );
            }
        }
    }
    Ok(out)
}

/// A request or revert note of the control plane, as the black box holds
/// it (control plane v2 review, finding 4: rebuilding a damaged request
/// journal).
#[derive(Debug, Clone)]
pub struct RequestNote {
    pub note: Value,
    /// Its evidence reference.
    pub evidence: String,
    /// The record's wall time (Unix ms).
    pub wall_ms: u64,
}

/// Every `robodr.control_plane_request` and `robodr.control_plane_revert`
/// note of `robot_id` in the black box, oldest first.
pub fn find_request_notes(src: &dyn SegmentSource, robot_id: &str) -> io::Result<Vec<RequestNote>> {
    let mut out = Vec::new();
    for idx in src.list()? {
        let Some(bytes) = src.read(idx)? else {
            continue;
        };
        for item in scan_frames(&bytes).items {
            let ScanItem::Record(r) = item else {
                continue;
            };
            let rec = r.record;
            if rec.kind != RecordKind::Note
                || !rec
                    .payload
                    .windows(23)
                    .any(|w| w == b"robodr.control_plane_re")
            {
                continue;
            }
            let Ok(v) = serde_json::from_slice::<Value>(&rec.payload) else {
                continue;
            };
            let kind = v.get("kind").and_then(Value::as_str);
            if !matches!(
                kind,
                Some("robodr.control_plane_request" | "robodr.control_plane_revert")
            ) || v.get("robot_id").and_then(Value::as_str) != Some(robot_id)
            {
                continue;
            }
            out.push(RequestNote {
                note: v,
                evidence: RecordRef {
                    segment: idx,
                    seq: rec.seq,
                    sha256: to_hex(&rec.hash),
                }
                .uri(robot_id),
                wall_ms: rec.time.wall_ns / 1_000_000,
            });
        }
    }
    Ok(out)
}

/// A file handle helper for tests: the whole bundle file of an export.
pub fn read_bundle(s: &Stored) -> io::Result<Vec<u8>> {
    let mut f = File::open(s.dir.join(BUNDLE_FILE))?;
    let mut b = Vec::new();
    f.read_to_end(&mut b)?;
    Ok(b)
}

#[cfg(test)]
mod tests {
    use super::*;
    use robodr_blackbox::sign_ed25519::Ed25519SigningKey;
    use robodr_blackbox::store::{FsyncPolicy, Recorder, RecorderConfig, RetentionMode};
    use robodr_blackbox::{KeyFile, Keyring, Signer, SteppingClock, TimeSource};

    const ROBOT: &str = "ugv-007";

    fn tmp(tag: &str) -> PathBuf {
        let d = std::env::temp_dir().join(format!("robodr-cp-ev-{tag}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&d);
        std::fs::create_dir_all(&d).unwrap();
        d
    }

    fn key(id: &str, seed: u8) -> Box<dyn Signer> {
        Box::new(Ed25519SigningKey::from_seed(id, &[seed; 32]).unwrap())
    }

    fn ring() -> Keyring {
        let mut k = Keyring::new();
        for (id, seed) in [("bb-1", 1u8), ("bb-2", 2u8)] {
            k.add_key_file(
                &KeyFile::ed25519_from_seed(&[seed; 32], Some(id))
                    .unwrap()
                    .to_public()
                    .unwrap(),
            )
            .unwrap();
        }
        k
    }

    /// A real recorder: small segments (several per test), 1 ms per record
    /// from wall time 1_800_000_000_000 ms.
    fn recorder(dir: &Path, max_segments: u32) -> Recorder {
        let mut cfg = RecorderConfig::new(dir, ROBOT, "boot-1");
        cfg.max_segment_bytes = 8 * 1024;
        cfg.mode = RetentionMode::Cyclic { max_segments };
        cfg.fsync = FsyncPolicy::SealsOnly;
        Recorder::open(
            cfg,
            key("bb-1", 1),
            Box::new(SteppingClock::new(
                1_800_000_000_000_000_000,
                1_000_000,
                TimeSource::Rtc,
            )),
        )
        .unwrap()
    }

    fn notes(r: &mut Recorder, from: u64, n: u64) {
        for i in from..from + n {
            r.append_note(
                &serde_json::json!({"kind": "test", "i": i, "pad": "x".repeat(200)}),
                false,
            )
            .unwrap();
        }
    }

    fn verify(b: &Built, device: &str) -> robodr_blackbox::Report {
        let bundle = Bundle::from_bytes(&b.bundle).unwrap();
        bundle.verify_with_key(&ring(), None, Some(device), Some(&b.chain.signing_key))
    }

    fn export(dir: &Path, sel: &Selector, max: u64) -> Result<Built, ApiError> {
        let src = DirSource(dir.to_path_buf());
        let ix = index(&src)?;
        let (lo, hi, refs) = select(&ix, sel)?;
        build(&src, &ix, lo, hi, refs, max)
    }

    #[test]
    fn an_export_spanning_segments_verifies_with_the_public_key() {
        let d = tmp("span");
        let mut r = recorder(&d, 64);
        notes(&mut r, 0, 200);
        let head = r.head().unwrap().0;
        drop(r);
        let src = DirSource(d.clone());
        let ix = index(&src).unwrap();
        assert!(ix.segment_bytes.len() >= 4, "{:?}", ix.segment_bytes);
        assert_eq!(ix.records.last().unwrap().seq, head);
        // A seq range across several segments.
        let b = export(
            &d,
            &Selector::SeqRange {
                from_seq: 20,
                to_seq: 150,
            },
            1 << 30,
        )
        .unwrap();
        assert_eq!(
            (b.records.first_seq, b.records.last_seq, b.records.count),
            (20, 150, 131)
        );
        assert_eq!(b.anchor.as_ref().unwrap().seq, 19);
        let rep = verify(&b, ROBOT);
        assert!(rep.is_intact(), "{rep:?}");
        assert_eq!(rep.verified_records, 131);
        assert_eq!((rep.first_seq, rep.last_seq), (Some(20), Some(150)));
        // The whole chain from genesis: no anchor.
        let b = export(
            &d,
            &Selector::SeqRange {
                from_seq: 0,
                to_seq: head,
            },
            1 << 30,
        )
        .unwrap();
        assert!(b.anchor.is_none());
        assert!(verify(&b, ROBOT).is_intact());
        // Another device id is refused by the verifier.
        assert!(!verify(&b, "ugv-008").is_intact());
        // Inventory names every segment and the head.
        let inv = inventory(&ix, ROBOT);
        assert_eq!(inv["retained"]["first_seq"], 0);
        assert_eq!(inv["retained"]["last_seq"], head);
        assert_eq!(inv["chain"]["identity"]["device_id"], ROBOT);
        assert_eq!(
            inv["retained"]["segments"].as_array().unwrap().len(),
            ix.segment_bytes.len()
        );
        let _ = std::fs::remove_dir_all(&d);
    }

    #[test]
    fn time_and_finding_selectors() {
        let d = tmp("sel");
        let mut r = recorder(&d, 64);
        notes(&mut r, 0, 100);
        drop(r);
        let ix = index(&DirSource(d.clone())).unwrap();
        // Time: the span from the first to the last record in the window.
        let t0 = ix.records[30].wall_ms;
        let t1 = ix.records[40].wall_ms;
        let b = export(
            &d,
            &Selector::TimeRange {
                from_ms: t0,
                to_ms: t1,
            },
            1 << 30,
        )
        .unwrap();
        assert_eq!(b.records.first_wall_ms, t0);
        assert_eq!(b.records.last_wall_ms, t1);
        assert!(verify(&b, ROBOT).is_intact());
        let none = export(
            &d,
            &Selector::TimeRange {
                from_ms: 1,
                to_ms: 2,
            },
            1 << 30,
        )
        .unwrap_err();
        assert_eq!((none.status, none.code), (404, "no_records"));
        // Finding: the linked records plus context, contiguous.
        let link = |i: usize| RecordRef {
            segment: ix.records[i].segment,
            seq: ix.records[i].seq,
            sha256: to_hex(&ix.records[i].hash),
        };
        let sel = Selector::Finding {
            finding_id: "rf1-x".into(),
            evidence: vec![link(50), link(55)],
            context_records: 3,
        };
        let b = export(&d, &sel, 1 << 30).unwrap();
        assert_eq!(
            (b.records.first_seq, b.records.last_seq),
            (ix.records[47].seq, ix.records[58].seq)
        );
        assert_eq!(b.referenced.len(), 2);
        assert!(verify(&b, ROBOT).is_intact());
        // A link whose hash does not match: refused, not exported.
        let mut bad = link(50);
        bad.sha256 = "00".repeat(32);
        let e = export(
            &d,
            &Selector::Finding {
                finding_id: "rf1-x".into(),
                evidence: vec![bad],
                context_records: 0,
            },
            1 << 30,
        )
        .unwrap_err();
        assert_eq!((e.status, e.code), (409, "evidence_mismatch"));
        let mut gone = link(50);
        gone.seq = 1_000_000;
        let e = export(
            &d,
            &Selector::Finding {
                finding_id: "rf1-x".into(),
                evidence: vec![gone],
                context_records: 0,
            },
            1 << 30,
        )
        .unwrap_err();
        assert_eq!((e.status, e.code), (404, "evidence_not_retained"));
        let e = export(
            &d,
            &Selector::SeqRange {
                from_seq: 0,
                to_seq: 1_000_000,
            },
            1 << 30,
        )
        .unwrap_err();
        assert_eq!((e.status, e.code), (416, "out_of_range"));
        let _ = std::fs::remove_dir_all(&d);
    }

    #[test]
    fn limits_gaps_and_retention() {
        let d = tmp("limits");
        let mut r = recorder(&d, 6);
        notes(&mut r, 0, 400);
        drop(r);
        let ix = index(&DirSource(d.clone())).unwrap();
        let first = ix.records[0].seq;
        assert!(first > 0, "cyclic retention dropped the oldest segments");
        // Before the retained range: out_of_range.
        let e = export(
            &d,
            &Selector::SeqRange {
                from_seq: 0,
                to_seq: first + 1,
            },
            1 << 30,
        )
        .unwrap_err();
        assert_eq!(e.code, "out_of_range");
        // Larger than max_export_bytes: refused.
        let last = ix.records.last().unwrap().seq;
        let e = export(
            &d,
            &Selector::SeqRange {
                from_seq: first,
                to_seq: last,
            },
            4096,
        )
        .unwrap_err();
        assert_eq!((e.status, e.code), (413, "export_too_large"));
        // A missing segment in the middle: a gap is refused, not papered over.
        let segs: Vec<u64> = ix.segment_bytes.keys().copied().collect();
        let mid = segs[segs.len() / 2];
        std::fs::remove_file(d.join(robodr_blackbox::store::segment_file_name(mid))).unwrap();
        let e = export(
            &d,
            &Selector::SeqRange {
                from_seq: first,
                to_seq: last,
            },
            1 << 30,
        )
        .unwrap_err();
        assert_eq!((e.status, e.code), (409, "evidence_gap"));
        let ix2 = index(&DirSource(d.clone())).unwrap();
        assert_eq!(
            inventory(&ix2, ROBOT)["retained"]["gaps"]
                .as_array()
                .unwrap()
                .len(),
            1
        );
        // The span before the gap still exports and verifies.
        let pre = ix2
            .records
            .iter()
            .take_while(|m| m.segment < mid)
            .last()
            .unwrap()
            .seq;
        let b = export(
            &d,
            &Selector::SeqRange {
                from_seq: first,
                to_seq: pre,
            },
            1 << 30,
        )
        .unwrap();
        assert!(verify(&b, ROBOT).is_intact());
        let _ = std::fs::remove_dir_all(&d);
    }

    #[test]
    fn an_export_after_a_key_rotation_names_the_new_key() {
        let d = tmp("rotate");
        let mut r = recorder(&d, 64);
        notes(&mut r, 0, 60);
        r.rotate_key(key("bb-2", 2), None, "test rotation").unwrap();
        notes(&mut r, 60, 60);
        drop(r);
        let ix = index(&DirSource(d.clone())).unwrap();
        let last = ix.records.last().unwrap().seq;
        // Entirely after the rotation: signed by bb-2.
        let b = export(
            &d,
            &Selector::SeqRange {
                from_seq: last - 10,
                to_seq: last,
            },
            1 << 30,
        )
        .unwrap();
        assert_eq!(b.chain.signing_key.key_id, "bb-2");
        let rep = verify(&b, ROBOT);
        assert!(rep.is_intact(), "{rep:?}");
        // Across the rotation: starts with bb-1, the rotation switches.
        let b = export(
            &d,
            &Selector::SeqRange {
                from_seq: 30,
                to_seq: last,
            },
            1 << 30,
        )
        .unwrap();
        assert_eq!(b.chain.signing_key.key_id, "bb-1");
        assert!(verify(&b, ROBOT).is_intact());
        let _ = std::fs::remove_dir_all(&d);
    }

    #[test]
    fn chunks_reassemble_and_tampering_is_detected() {
        let d = tmp("chunks");
        let mut r = recorder(&d, 64);
        notes(&mut r, 0, 100);
        drop(r);
        let b = export(
            &d,
            &Selector::SeqRange {
                from_seq: 5,
                to_seq: 90,
            },
            1 << 30,
        )
        .unwrap();
        let info = bundle_info(&b.bundle, 4096);
        assert!(info.chunks.len() > 3);
        assert_eq!(info.bytes, b.bundle.len() as u64);
        let mut joined = Vec::new();
        for (i, c) in info.chunks.iter().enumerate() {
            assert_eq!(c.index, i as u64);
            assert_eq!(c.offset, joined.len() as u64);
            let part = &b.bundle[c.offset as usize..(c.offset + c.bytes) as usize];
            assert_eq!(to_hex(&sha256(part)), c.sha256);
            joined.extend_from_slice(part);
        }
        assert_eq!(joined, b.bundle);
        assert_eq!(to_hex(&sha256(&joined)), info.sha256);
        // One flipped byte anywhere in the frames: the verifier says
        // tamper (or the bundle does not even parse).
        for pos in [b.bundle.len() / 3, b.bundle.len() / 2, b.bundle.len() - 70] {
            let mut t = b.bundle.clone();
            t[pos] ^= 0x20;
            match Bundle::from_bytes(&t) {
                Err(_) => {}
                Ok(x) => assert!(
                    !x.verify_with_key(&ring(), None, Some(ROBOT), Some(&b.chain.signing_key))
                        .is_intact(),
                    "flip at {pos} not detected"
                ),
            }
        }
        let _ = std::fs::remove_dir_all(&d);
    }

    #[test]
    fn stored_exports_survive_reopen_and_corruption_is_caught() {
        let d = tmp("store");
        let bb = d.join("bb");
        std::fs::create_dir_all(&bb).unwrap();
        let mut r = recorder(&bb, 64);
        notes(&mut r, 0, 50);
        drop(r);
        let state = d.join("state");
        std::fs::create_dir_all(&state).unwrap();
        let b = export(
            &bb,
            &Selector::SeqRange {
                from_seq: 1,
                to_seq: 40,
            },
            1 << 30,
        )
        .unwrap();
        let info = bundle_info(&b.bundle, 16 * 1024);
        let m = Manifest {
            kind: MANIFEST_KIND.into(),
            version: MANIFEST_VERSION,
            api: API_VERSION.into(),
            robot_id: ROBOT.into(),
            export_id: "exp:1".into(),
            created_at_ms: 1000,
            expires_at_ms: 5000,
            requested_by: "a".into(),
            reason: String::new(),
            key_id: "soc".into(),
            selector: Selector::SeqRange {
                from_seq: 1,
                to_seq: 40,
            },
            chain: b.chain.clone(),
            records: b.records.clone(),
            anchor: b.anchor.clone(),
            referenced: Vec::new(),
            bundle: info,
            evidence: "robodr-blackbox://ugv-007/0/1?sha256=00".into(),
        };
        let mb = serde_json::to_vec(&m).unwrap();
        let fk = Ed25519SigningKey::from_seed("finding:1", &[5; 32]).unwrap();
        let sig = sign_manifest(&fk, &mb).unwrap();
        let (id, raw) = parse_signature_header(&sig).unwrap();
        assert_eq!(id, "finding:1");
        assert!(robodr_blackbox::sign_ed25519::verify(
            &fk.public_key(),
            &manifest_message(&mb),
            &raw
        ));
        let mut st = Store::open(&state, 1000).unwrap();
        let exports_dir = st.dir.clone();
        st.insert(write_export(&exports_dir, m.clone(), mb.clone(), sig, &b.bundle).unwrap());
        drop(st);
        let st = Store::open(&state, 2000).unwrap();
        let s = st.exports.get("exp:1").unwrap();
        assert_eq!(s.manifest, m);
        let mut joined = Vec::new();
        for c in &m.bundle.chunks {
            joined.extend(read_chunk(s, c.index).unwrap());
        }
        assert_eq!(joined, b.bundle);
        assert_eq!(read_chunk(s, 99).unwrap_err().code, "unknown_chunk");
        // A byte of the stored bundle changes: the chunk is refused.
        let p = s.dir.join(BUNDLE_FILE);
        let mut raw = std::fs::read(&p).unwrap();
        raw[100] ^= 1;
        std::fs::write(&p, &raw).unwrap();
        assert_eq!(read_chunk(s, 0).unwrap_err().code, "export_corrupt");
        drop(st);
        // Expired at the next open: removed.
        let st = Store::open(&state, 6000).unwrap();
        assert!(st.exports.is_empty());
        assert_eq!(st.discarded_at_open, 1);
        assert_eq!(std::fs::read_dir(&st.dir).unwrap().count(), 0);
        let _ = std::fs::remove_dir_all(&d);
    }

    #[test]
    fn export_bodies_are_strict() {
        let ok = |v: serde_json::Value| parse_export(&serde_json::to_vec(&v).unwrap(), ROBOT);
        let code = |v: serde_json::Value| ok(v).unwrap_err().code;
        let link = format!("robodr-blackbox://{ROBOT}/0/9?sha256={}", "ab".repeat(32));
        let r = ok(serde_json::json!({
            "export_id": "exp-1", "requested_by": "a@soc",
            "selector": {"finding": {"finding_id": "rf1-1", "evidence": [link, link]}}
        }))
        .unwrap();
        match &r.selector {
            Selector::Finding {
                evidence,
                context_records,
                ..
            } => {
                assert_eq!(evidence.len(), 1, "duplicates folded");
                assert_eq!(*context_records, DEFAULT_CONTEXT_RECORDS);
            }
            s => panic!("{s:?}"),
        }
        assert_eq!(
            code(serde_json::json!({"export_id": "e", "requested_by": "a",
                "selector": {"seq_range": {"from_seq": 1, "to_seq": 2}, "time_range": {"from_ms": 1, "to_ms": 2}}})),
            "invalid_selector"
        );
        assert_eq!(
            code(serde_json::json!({"export_id": "e", "requested_by": "a", "selector": {}})),
            "invalid_selector"
        );
        assert_eq!(
            code(serde_json::json!({"export_id": "e", "requested_by": "a",
                "selector": {"seq_range": {"from_seq": 3, "to_seq": 2}}})),
            "invalid_selector"
        );
        assert_eq!(
            code(serde_json::json!({"export_id": "e", "requested_by": "a",
                "selector": {"seq_range": {"from_seq": 1, "to_seq": 2, "all": true}}})),
            "unknown_field"
        );
        assert_eq!(
            code(serde_json::json!({"export_id": "e/1", "requested_by": "a",
                "selector": {"seq_range": {"from_seq": 1, "to_seq": 2}}})),
            "invalid_export_id"
        );
        assert_eq!(
            code(serde_json::json!({"export_id": "e", "requested_by": "",
                "selector": {"seq_range": {"from_seq": 1, "to_seq": 2}}})),
            "invalid_field"
        );
        assert_eq!(
            code(serde_json::json!({"export_id": "e", "requested_by": "a",
                "selector": {"time_range": {"from_ms": 0, "to_ms": MAX_TIME_SPAN_MS + 1}}})),
            "invalid_selector"
        );
        let other = format!("robodr-blackbox://ugv-008/0/9?sha256={}", "ab".repeat(32));
        assert_eq!(
            code(serde_json::json!({"export_id": "e", "requested_by": "a",
                "selector": {"finding": {"finding_id": "f", "evidence": [other]}}})),
            "invalid_selector"
        );
        assert_eq!(
            code(serde_json::json!({"export_id": "e", "requested_by": "a",
                "selector": {"finding": {"finding_id": "f", "evidence": [], "context_records": 1}}})),
            "invalid_selector"
        );
        assert_eq!(code(serde_json::json!([1])), "invalid_request");
        assert_eq!(
            code(serde_json::json!({"export_id": "e", "requested_by": "a", "selector": [1]})),
            "invalid_request"
        );
        for bad in [
            "robodr-blackbox://ugv-007/0/9",
            "robodr-blackbox://ugv-007/0?sha256=00",
            "robodr-blackbox://ugv-007/x/9?sha256=00",
            "http://ugv-007/0/9?sha256=00",
            "robodr-blackbox://ugv-007/0/9?sha256=zz",
        ] {
            assert!(parse_link(bad, ROBOT).is_err(), "{bad}");
        }
    }

    #[test]
    fn decision_notes_are_found_in_the_black_box() {
        let d = tmp("notes");
        let mut r = recorder(&d, 64);
        notes(&mut r, 0, 30);
        let out = r
            .append_note(&serde_json::json!({"kind": "robodr.control_plane_request", "decision_id": "deadbeef00112233deadbeef00112233"}), true)
            .unwrap();
        notes(&mut r, 30, 30);
        drop(r);
        let found = find_decision_notes(
            &DirSource(d.clone()),
            ROBOT,
            &["deadbeef00112233deadbeef00112233".into(), "00".repeat(16)],
        )
        .unwrap();
        assert_eq!(found.len(), 1);
        let uri = &found["deadbeef00112233deadbeef00112233"];
        let robodr_blackbox::store::AppendOutcome::Recorded { seq, hash } = out else {
            panic!("{out:?}");
        };
        let ix = index(&DirSource(d.clone())).unwrap();
        let segment = ix.records.iter().find(|m| m.seq == seq).unwrap().segment;
        assert_eq!(
            *uri,
            RecordRef {
                segment,
                seq,
                sha256: to_hex(&hash)
            }
            .uri(ROBOT)
        );
        let _ = std::fs::remove_dir_all(&d);
    }

    /// Review finding 7: robots cap `max_export_bytes` at 256 MiB.
    #[test]
    fn max_export_bytes_is_capped_on_robots() {
        let mut e = EvidenceSection {
            max_export_bytes: 512 * 1024 * 1024,
            max_storage_bytes: 1024 * 1024 * 1024,
            chunk_bytes: 4 * 1024 * 1024,
            ..EvidenceSection::default()
        };
        let err = e.validate().unwrap_err();
        assert!(err.contains("268435456"), "{err}");
        e.max_export_bytes = MAX_EXPORT_BYTES_LIMIT;
        e.validate().unwrap();
    }

    /// Review finding 7: the bundle is streamed (to a file here) with its
    /// manifest section computed on the way; the bytes are the bundle
    /// format exactly, and an abandoned temp export leaves nothing.
    #[test]
    fn a_streamed_build_is_the_bundle_and_its_manifest_section() {
        let d = tmp("stream");
        let mut r = recorder(&d, 64);
        notes(&mut r, 0, 120);
        drop(r);
        let src = DirSource(d.clone());
        let ix = index(&src).unwrap();
        let (lo, hi, refs) = select(
            &ix,
            &Selector::SeqRange {
                from_seq: 7,
                to_seq: 100,
            },
        )
        .unwrap();
        let exports = d.join("exports-test");
        std::fs::create_dir_all(&exports).unwrap();
        let t = TempExport::create(&exports).unwrap();
        let mut f = std::io::BufWriter::new(t.bundle_file().unwrap());
        let (info, meta) = build_into(&src, &ix, lo, hi, refs, 1 << 30, 16 * 1024, &mut f, &|| {
            false
        })
        .unwrap();
        drop(f);
        let bytes = std::fs::read(t.dir.join(BUNDLE_FILE)).unwrap();
        assert_eq!(info, bundle_info(&bytes, 16 * 1024));
        assert!(info.chunks.len() > 1);
        let bundle = Bundle::from_bytes(&bytes).unwrap();
        assert_eq!(bundle.to_bytes(), bytes, "the bundle format, byte for byte");
        let rep = bundle.verify_with_key(&ring(), None, Some(ROBOT), Some(&meta.chain.signing_key));
        assert!(rep.is_intact(), "{rep:?}");
        assert_eq!(meta.records.count, 94);
        let tmpdir = t.dir.clone();
        drop(t);
        assert!(!tmpdir.exists(), "an unfinished export is removed");
        // Past the deadline / stopping: abandoned.
        let mut sink = Vec::new();
        let (lo, hi, refs) = select(
            &ix,
            &Selector::SeqRange {
                from_seq: 7,
                to_seq: 100,
            },
        )
        .unwrap();
        let e = build_into(
            &src,
            &ix,
            lo,
            hi,
            refs,
            1 << 30,
            16 * 1024,
            &mut sink,
            &|| true,
        )
        .unwrap_err();
        assert_eq!((e.status, e.code), (503, "evidence_timeout"));
        let _ = std::fs::remove_dir_all(&d);
    }

    /// Review finding 7: an export must leave the free-space headroom.
    #[test]
    fn exports_leave_free_space_headroom() {
        let mib = 1024 * 1024;
        assert!(check_free_space(None, 500 * mib).is_ok());
        assert!(check_free_space(Some(1024 * mib), 500 * mib).is_ok());
        let e = check_free_space(Some(100 * mib), 50 * mib).unwrap_err();
        assert_eq!((e.status, e.code), (507, "storage_full"));
        #[cfg(all(target_os = "linux", target_pointer_width = "64"))]
        assert!(free_bytes(&std::env::temp_dir()).is_some_and(|f| f > 0));
    }
}
