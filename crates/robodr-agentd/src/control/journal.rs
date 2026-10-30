//! Crash-safe, sealed append-only journals of the control plane's
//! persistent state (`control_plane.state_dir`): the request-state journal
//! (`requests.journal`, owned by the main loop) and the replay store
//! (`nonces.journal`, owned by the listener threads).
//!
//! # Format (`robodr-cp-journal/v2`)
//!
//! UTF-8 text, one entry per line:
//!
//! ```text
//! <64 lower-case hex: tag> <one JSON object>\n
//! tag = HMAC-SHA256(K, "robodr-cp-journal/v2" 0x00 | len|kind | len|previous line's tag | len|JSON)
//! ```
//!
//! `K` is the state-seal key ([`robodr_blackbox::StateSealKey`], purpose
//! [`SEAL_PURPOSE`]) derived from agentd's black-box key, so whoever can
//! write the state directory but does not hold that key cannot edit,
//! insert, delete or reorder an entry without the next open seeing it. The
//! first line is a header entry `{"t":"header","format":
//! "robodr-cp-journal/v2","kind":"requests"|"nonces","key_id":
//! "hmac-sha256:<16 hex>","generation":<n>}` chained to 32 zero bytes;
//! every rewrite (compaction, repair, upgrade) starts the next
//! `generation`. serde_json never writes a raw newline inside a value, so a
//! line is exactly one entry.
//!
//! A journal's **head** ([`Head`]: generation, number of entries, last tag)
//! is recorded in signed black-box notes (`robodr.control_plane_state_head`,
//! at start, on heartbeats when it moved, and at a clean stop). The next
//! open compares the file with the newest such head ([`Anchor`]) and
//! reports it in [`Loaded::anchor`]: an older generation, fewer entries or
//! another tag at the head's position is a **rollback** (an old copy put
//! back, or the tail cut), see [`AnchorCheck`]. Entries appended after the
//! newest head can still be cut without trace; the callers therefore treat
//! anything but a clean stop's head as "may have lost a tail" (the replay
//! store fences, the request journal is reconciled with the black box).
//!
//! # Durability
//!
//! * **Append:** one `write` of the whole line, then `fdatasync`; the caller
//!   acts on the entry only after that returned.
//! * **Compaction:** the live state is written to a new file
//!   `<name>.tmp-<random>` (created exclusively, mode 0600, no symlink
//!   followed), fsynced, renamed over `<name>`, and the directory is
//!   fsynced; then appends continue on the new file. A crash before the
//!   rename leaves the old journal intact (the temp file is removed at the
//!   next open); after it, the new one, which holds the same live state.
//!   After the rename, appends always go to the new file; if the directory
//!   fsync failed (the rename might not survive a power loss), the journal
//!   refuses every append until it is reopened (fail closed).
//! * **A survived append failure** (short write on a full disk, an fsync
//!   error) is rolled back by cutting the file to its previous length, so
//!   no later line follows a fragment; if that fails too, the journal
//!   refuses every append until it is reopened.
//!
//! # Loading (what a crash, damage or an edit leaves behind)
//!
//! * **One** malformed line after the last good line (with or without its
//!   newline: not `<64 hex> <JSON object>`) is a torn tail (a crash during
//!   an append, whose caller never acted on it): the file is truncated to
//!   the last good line, counted in [`Loaded::torn_bytes`]. A crash can
//!   leave no more than that one line: two or more bad lines at the end are
//!   damage (next point). A **well-formed** line whose tag does not verify
//!   ([`Loaded::forged`]) is never a torn tail: a crash cannot write a
//!   whole line with another tag. That is how a deleted second-to-last
//!   entry is told apart from a crash.
//! * A bad line (tag, JSON, over [`MAX_LINE`]) **followed by** a good one
//!   cannot come from a crash (every append is synced before the next):
//!   storage damage or an edit. The damaged lines are skipped and counted
//!   ([`Loaded::damaged`]), the original file is copied to
//!   `quarantine/<name>.<unix ms>.damaged` and the journal is rewritten
//!   from the good entries. The caller reports it (a finding) and falls
//!   back to a fail-safe state (see the nonce store's fence and the request
//!   journal's rebuild from the black box). A journal sealed under **another
//!   key** (a rotated black-box key, another unit's state) is all damage:
//!   [`Loaded::wrong_key`] names that key.
//!
//! # Upgrade from `robodr-cp-journal/v1` (one time)
//!
//! v1 journals were checksummed (SHA-256 of the JSON), not sealed. When the
//! black box holds **no** head note yet (this is the first start of a
//! release that seals), the caller passes `adopt_legacy`: a v1 journal is
//! read with the v1 rules, rewritten as v2 ([`Loaded::upgraded_from_v1`]) and
//! treated as untrusted once (fence, black-box reconciliation; agentd
//! records a `robodr.control_plane_state_upgraded` note). Once a head note
//! exists, a v1 file can only be a downgrade by someone without the key: it
//! is damage ([`Loaded::legacy_refused`]), never adopted.
//!
//! The journal is operational state, not evidence: every decision it holds
//! is also a signed black-box note; the black box stays the record.

use std::fs::File;
use std::io::{self, BufRead, BufReader, Read, Write};
use std::os::unix::fs::OpenOptionsExt;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};
use serde_json::Value;

use robodr_blackbox::crypto::{from_hex, sha256, to_hex};
use robodr_blackbox::StateSealKey;

use super::fsutil::{self, fault};

/// Journal format name (header line).
pub const FORMAT: &str = "robodr-cp-journal/v2";
/// The checksummed, unsealed format of earlier releases (read once, for
/// the upgrade).
pub const LEGACY_FORMAT: &str = "robodr-cp-journal/v1";
/// Purpose of the state-seal key derived from the black-box key.
pub const SEAL_PURPOSE: &str = "agentd/control-plane-state/v1";
/// Longest line accepted (a longer one is damage).
pub const MAX_LINE: usize = 256 * 1024;
/// Largest journal file loaded.
pub const MAX_FILE_BYTES: u64 = 1024 * 1024 * 1024;
/// The header's chain predecessor.
const GENESIS: [u8; 32] = [0; 32];

#[derive(Serialize, Deserialize)]
struct Header {
    t: String,
    format: String,
    kind: String,
    /// The state-seal key's id (v2).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    key_id: Option<String>,
    /// Rewrite counter (v2): every compaction, repair or upgrade starts the
    /// next one.
    #[serde(default)]
    generation: u64,
}

/// Where a journal ends: its generation, the number of entries in it and
/// the tag of its last line (the header's for an empty one). Recorded in the
/// black box as the journal's anchor.
#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Head {
    pub generation: u64,
    pub seq: u64,
    /// 64 lower-case hex.
    pub tag: String,
}

/// The newest head the black box holds for a journal, and whether it was
/// recorded at a clean stop (nothing could be appended after it).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Anchor {
    pub head: Head,
    pub clean: bool,
}

/// What the comparison of the file with its [`Anchor`] found.
#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize)]
#[serde(tag = "state", content = "reason", rename_all = "snake_case")]
pub enum AnchorCheck {
    /// Not compared: the file was damaged, refused or upgraded (the caller
    /// fails safe for that already).
    #[default]
    NotChecked,
    /// The black box holds no head for it (first sealed start, or a new
    /// black box): the sealed file is taken as it is.
    NoAnchor,
    /// The file ends exactly at a clean stop's head: nothing can be missing.
    Verified,
    /// Consistent with the head, but entries were (or may have been)
    /// appended after it: a cut tail cannot be excluded.
    Unanchored(String),
    /// Older than the head, or shorter, or another entry at its position:
    /// an old copy was put back or entries were cut.
    RolledBack(String),
}

/// How the control plane opens its two journals: the state-seal key, the
/// black box's newest head of each, and whether a v1 journal may still be
/// upgraded (no head in the black box yet).
#[derive(Debug, Clone)]
pub struct Sealing {
    pub key: Arc<StateSealKey>,
    pub requests: Option<Anchor>,
    pub nonces: Option<Anchor>,
    pub adopt_legacy: bool,
}

impl Sealing {
    /// No head known (a first sealed start, tests and tools); a v1 journal
    /// is not adopted.
    pub fn new(key: Arc<StateSealKey>) -> Self {
        Self {
            key,
            requests: None,
            nonces: None,
            adopt_legacy: false,
        }
    }

    /// [`Sealing::new`] with the key agentd derives from the black-box key
    /// file at `path` (tools and tests that prepare a state directory).
    pub fn from_blackbox_key_file(path: &Path) -> Result<Self, String> {
        let k = crate::config::read_key(path)?;
        Ok(Self::new(Self::derive_key(&k.key.0)?))
    }

    /// The key agentd derives from its black-box key (an Ed25519 seed or an
    /// HMAC secret).
    pub fn derive_key(blackbox_key: &[u8]) -> Result<Arc<StateSealKey>, String> {
        StateSealKey::derive(blackbox_key, SEAL_PURPOSE)
            .map(Arc::new)
            .map_err(|e| format!("control-plane state key: {e}"))
    }
}

/// What [`Journal::open`] found.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct Loaded<T> {
    /// The good entries, in order (header excluded).
    pub entries: Vec<T>,
    /// Bytes of a torn tail removed (a crash during an append).
    pub torn_bytes: u64,
    /// Damaged lines skipped (storage damage or an edit; see the module).
    pub damaged: usize,
    /// Of those, well-formed lines whose seal did not verify (an edit, a
    /// deletion before them, another key).
    pub forged: usize,
    /// The file is sealed under this other key (all of it is damage).
    pub wrong_key: Option<String>,
    /// A v1 journal was adopted and rewritten sealed (one-time upgrade).
    pub upgraded_from_v1: bool,
    /// A v1 journal was found after sealing had started: damage.
    pub legacy_refused: bool,
    /// The comparison with the black box's head.
    pub anchor: AnchorCheck,
    /// Where the damaged original was copied.
    pub quarantined: Option<PathBuf>,
    /// The journal did not exist and was created.
    pub created: bool,
}

/// An open journal: appends go to `name` in `dir`.
#[derive(Debug)]
pub struct Journal {
    dir: PathBuf,
    name: String,
    kind: String,
    key: Arc<StateSealKey>,
    file: File,
    generation: u64,
    /// Tag of the last line (the chain predecessor of the next append).
    prev: [u8; 32],
    /// Entries in the file (header excluded).
    lines: usize,
    /// File length after the last good append.
    len: u64,
    /// A failed append could not be rolled back: every later append fails
    /// (fail closed) until the next open repairs the file.
    poisoned: bool,
}

fn tag_of(key: &StateSealKey, kind: &str, prev: &[u8; 32], json: &[u8]) -> [u8; 32] {
    key.tag(FORMAT, &[kind.as_bytes(), prev, json])
}

/// One sealed line chained to `prev`, and its tag.
fn line_of(
    key: &StateSealKey,
    kind: &str,
    prev: &[u8; 32],
    v: &impl Serialize,
) -> io::Result<(Vec<u8>, [u8; 32])> {
    let json = serde_json::to_vec(v).map_err(io::Error::other)?;
    if json.contains(&b'\n') || json.len() > MAX_LINE - 66 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "journal entry too large",
        ));
    }
    let tag = tag_of(key, kind, prev, &json);
    let mut line = Vec::with_capacity(json.len() + 66);
    line.extend_from_slice(to_hex(&tag).as_bytes());
    line.push(b' ');
    line.extend_from_slice(&json);
    line.push(b'\n');
    Ok((line, tag))
}

/// One line (without its newline) as read.
enum Line {
    /// The seal (v2) or checksum (v1) holds.
    Good(Value, [u8; 32]),
    /// `<64 hex> <JSON object>` whose seal does not verify: an edit, never a
    /// crash.
    Forged,
    /// Anything else (a fragment, garbage).
    Malformed,
}

/// Split `<64 hex> <JSON object>`.
fn split_line(line: &[u8]) -> Option<([u8; 32], &[u8], Value)> {
    if line.len() < 66 || line.len() > MAX_LINE {
        return None;
    }
    let (sum, rest) = line.split_at_checked(64)?;
    let json = rest.strip_prefix(b" ")?;
    let sum = std::str::from_utf8(sum).ok()?;
    if sum.bytes().any(|b| b.is_ascii_uppercase()) {
        return None;
    }
    let raw = from_hex(sum)?;
    let mut tag = [0u8; 32];
    if raw.len() != 32 {
        return None;
    }
    tag.copy_from_slice(&raw);
    let v: Value = serde_json::from_slice(json).ok()?;
    v.is_object().then_some((tag, json, v))
}

/// The v1 rule: the checksum is SHA-256 of the JSON bytes.
fn parse_legacy(line: &[u8]) -> Line {
    match split_line(line) {
        Some((sum, json, v)) if robodr_blackbox::crypto::ct_eq(&sha256(json), &sum) => {
            Line::Good(v, sum)
        }
        _ => Line::Malformed,
    }
}

/// The header fields of a line, without checking its seal (to tell a v1
/// file or another key apart from an edit).
fn peek_header(line: &[u8]) -> Option<Header> {
    let (_, _, v) = split_line(line)?;
    (v.get("t").and_then(Value::as_str) == Some("header"))
        .then(|| serde_json::from_value(v).ok())
        .flatten()
}

fn unix_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}

/// What one pass over a file found.
struct Scan {
    /// Good lines with their tags, in order.
    good: Vec<(Value, [u8; 32])>,
    damaged: usize,
    forged: usize,
    /// Bytes up to the end of the last good line.
    good_end: u64,
}

/// One pass: the good lines, how many bad lines precede a good one
/// (damage) and where the last good line ends (the torn tail starts).
fn scan(file: File, parse: &mut dyn FnMut(&[u8]) -> Line) -> io::Result<(Scan, bool)> {
    let mut r = BufReader::new(file);
    let mut s = Scan {
        good: Vec::new(),
        damaged: 0,
        forged: 0,
        good_end: 0,
    };
    let mut pending_bad: usize = 0;
    let mut pending_forged: usize = 0;
    let mut offset: u64 = 0;
    // An unterminated last line (a fragment).
    let mut fragment = false;
    let mut buf = Vec::new();
    loop {
        buf.clear();
        let n = r
            .by_ref()
            .take(MAX_LINE as u64 + 1)
            .read_until(b'\n', &mut buf)?;
        if n == 0 {
            break;
        }
        offset += n as u64;
        if buf.last() != Some(&b'\n') {
            if n > MAX_LINE {
                // An over-long line: skip to its end; bad either way.
                let mut rest = Vec::new();
                let m = r.read_until(b'\n', &mut rest)?;
                offset += m as u64;
                if rest.last() == Some(&b'\n') {
                    pending_bad += 1;
                    // Keep the chain going: the next line names this one's
                    // tag, which is lost; it fails as an edit would.
                    let _ = parse(b"");
                    continue;
                }
            }
            // No newline before EOF.
            fragment = true;
            break;
        }
        match parse(buf.split_last().map_or(&[][..], |(_, line)| line)) {
            Line::Good(v, tag) => {
                s.damaged += pending_bad;
                pending_bad = 0;
                pending_forged = 0;
                s.good.push((v, tag));
                s.good_end = offset;
            }
            Line::Forged => {
                s.forged += 1;
                pending_forged += 1;
                pending_bad += 1;
            }
            Line::Malformed => pending_bad += 1,
        }
    }
    // What follows the last good line. A crash during an append leaves at
    // most that one line, whole or not (every append is a single write,
    // synced before the next), and never a well-formed line under another
    // tag: one malformed line is a torn tail. Anything more cannot come from
    // a crash: damage (review finding 4), so synced entries are never
    // forgotten silently.
    let tail_lines = pending_bad + usize::from(fragment);
    let torn = !(tail_lines > 1 || pending_forged > 0);
    if !torn {
        s.damaged += tail_lines;
    }
    Ok((s, torn))
}

/// Compare a consistent sealed file (header generation `generation`, tags of
/// the header and every entry in `tags`) with the black box's head.
pub fn check_anchor(generation: u64, tags: &[[u8; 32]], anchor: Option<&Anchor>) -> AnchorCheck {
    let Some(a) = anchor else {
        return AnchorCheck::NoAnchor;
    };
    let h = &a.head;
    let seq = tags.len().saturating_sub(1) as u64;
    if generation < h.generation {
        return AnchorCheck::RolledBack(format!(
            "generation {generation} is older than the black box's head (generation {}, entry {})",
            h.generation, h.seq
        ));
    }
    if generation > h.generation {
        return AnchorCheck::Unanchored(format!(
            "rewritten (generation {generation}) after the black box's newest head (generation {})",
            h.generation
        ));
    }
    let at = usize::try_from(h.seq).ok().and_then(|i| tags.get(i));
    match at {
        None => AnchorCheck::RolledBack(format!(
            "ends at entry {seq} of generation {generation}, the black box's head is at entry {}: \
             entries were cut",
            h.seq
        )),
        Some(t) if to_hex(t) != h.tag => AnchorCheck::RolledBack(format!(
            "entry {} of generation {generation} is not the one the black box's head names",
            h.seq
        )),
        Some(_) if seq == h.seq && a.clean => AnchorCheck::Verified,
        Some(_) if seq == h.seq => AnchorCheck::Unanchored(
            "at the black box's head, but the last run did not stop cleanly".into(),
        ),
        Some(_) => AnchorCheck::Unanchored(format!(
            "{} entr(ies) after the black box's newest head",
            seq - h.seq
        )),
    }
}

impl Journal {
    /// Open (or create) `dir/name`, sealed under `key`. `kind` names the
    /// journal in its header; a sealed journal of another kind or format is
    /// refused. Entries that do not deserialize as `T` count as damaged.
    /// `anchor`: the black box's newest head for it; `adopt_legacy`: a v1
    /// journal may be upgraded (see the module).
    pub fn open<T: DeserializeOwned>(
        dir: &Path,
        name: &str,
        kind: &str,
        key: &Arc<StateSealKey>,
        anchor: Option<&Anchor>,
        adopt_legacy: bool,
    ) -> io::Result<(Journal, Loaded<T>)> {
        let path = dir.join(name);
        remove_stale_temps(dir, name);
        let mut loaded = Loaded {
            entries: Vec::new(),
            torn_bytes: 0,
            damaged: 0,
            forged: 0,
            wrong_key: None,
            upgraded_from_v1: false,
            legacy_refused: false,
            anchor: AnchorCheck::NotChecked,
            quarantined: None,
            created: false,
        };
        let next_generation = |seen: u64| seen.max(anchor.map_or(0, |a| a.head.generation)) + 1;
        let file = match fsutil::open_read_nofollow(&path) {
            Ok(f) => f,
            Err(e) if e.kind() == io::ErrorKind::NotFound => {
                let generation = next_generation(0);
                let (file, prev) = create_with_header(dir, name, kind, key, generation)?;
                let len = file.metadata()?.len();
                let j = Journal {
                    dir: dir.to_path_buf(),
                    name: name.to_string(),
                    kind: kind.to_string(),
                    key: key.clone(),
                    file,
                    generation,
                    prev,
                    lines: 0,
                    len,
                    poisoned: false,
                };
                loaded.created = true;
                loaded.anchor = match anchor {
                    None => AnchorCheck::NoAnchor,
                    Some(a) => AnchorCheck::RolledBack(format!(
                        "the journal is missing while the black box holds its head (generation \
                         {}, entry {})",
                        a.head.generation, a.head.seq
                    )),
                };
                return Ok((j, loaded));
            }
            Err(e) => return Err(e),
        };
        let len = file.metadata()?.len();
        if len > MAX_FILE_BYTES {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!("{} is larger than {MAX_FILE_BYTES} bytes", path.display()),
            ));
        }
        // Which rules apply: the first line's header, unchecked.
        let first = {
            let mut r = BufReader::new(fsutil::open_read_nofollow(&path)?);
            let mut b = Vec::new();
            r.by_ref()
                .take(MAX_LINE as u64 + 1)
                .read_until(b'\n', &mut b)?;
            if b.last() == Some(&b'\n') {
                b.pop();
            }
            peek_header(&b)
        };
        let legacy = first.as_ref().is_some_and(|h| h.format == LEGACY_FORMAT);
        if let Some(h) = first.as_ref().filter(|h| h.kind != kind) {
            // Another journal (whatever its seal): refused, never
            // reinterpreted or rewritten.
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!(
                    "{}: a {:?} journal of format {:?}, expected a {kind:?} journal of {FORMAT}",
                    path.display(),
                    robodr_ros2_pipeline::sanitize(&h.kind),
                    robodr_ros2_pipeline::sanitize(&h.format)
                ),
            ));
        }
        if let Some(h) = &first {
            if h.format == FORMAT {
                if let Some(id) = h.key_id.as_deref().filter(|id| *id != key.key_id()) {
                    loaded.wrong_key = Some(robodr_ros2_pipeline::sanitize(id));
                }
            }
        }
        let (mut sc, torn) = if legacy {
            scan(file, &mut parse_legacy)?
        } else {
            let mut prev: [u8; 32] = GENESIS;
            scan(file, &mut |line: &[u8]| match split_line(line) {
                None => {
                    // A damaged JSON part leaves the tag readable: the next
                    // line still chains to it (one damaged line costs one
                    // entry). Without a readable tag the chain cannot go on.
                    prev = line
                        .get(..64)
                        .and_then(|t| std::str::from_utf8(t).ok())
                        .and_then(from_hex)
                        .and_then(|t| <[u8; 32]>::try_from(t.as_slice()).ok())
                        .unwrap_or([0xff; 32]);
                    Line::Malformed
                }
                Some((tag, json, v)) => {
                    let ok = robodr_blackbox::crypto::ct_eq(&tag_of(key, kind, &prev, json), &tag);
                    prev = tag;
                    if ok {
                        Line::Good(v, tag)
                    } else {
                        Line::Forged
                    }
                }
            })?
        };
        if legacy && !adopt_legacy {
            // Sealing has started (the black box holds a head): a v1 file
            // is a downgrade by someone without the key.
            sc.damaged += sc.good.len();
            sc.good.clear();
            sc.good_end = 0;
            loaded.legacy_refused = true;
        }
        if torn {
            loaded.torn_bytes = len.saturating_sub(sc.good_end);
        }
        let mut values = sc.good.into_iter().peekable();
        // The header must be the first good line.
        let mut header_missing = false;
        let mut generation = 0;
        let mut tags: Vec<[u8; 32]> = Vec::new();
        match values.peek() {
            Some((v, _)) if v.get("t").and_then(Value::as_str) == Some("header") => {
                let (hv, ht) = values.next().unwrap_or((Value::Null, GENESIS));
                let h: Header = serde_json::from_value(hv).map_err(|_| {
                    io::Error::new(
                        io::ErrorKind::InvalidData,
                        format!("{}: malformed journal header", path.display()),
                    )
                })?;
                let want = if legacy { LEGACY_FORMAT } else { FORMAT };
                if h.format != want || h.kind != kind {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        format!(
                            "{}: a {:?} journal of format {:?}, expected a {kind:?} journal of \
                             {FORMAT}",
                            path.display(),
                            robodr_ros2_pipeline::sanitize(&h.kind),
                            robodr_ros2_pipeline::sanitize(&h.format)
                        ),
                    ));
                }
                if !legacy && h.key_id.as_deref() != Some(key.key_id()) {
                    // Sealed under our key but naming another: not written
                    // by this code.
                    header_missing = true;
                }
                generation = h.generation;
                tags.push(ht);
            }
            Some(_) => header_missing = true,
            // Nothing good at all: a crash right after the create, or
            // everything damaged (counted above only if a good line
            // followed, so: a crash).
            None => {}
        }
        let mut damaged_lines = sc.damaged;
        let mut kept: Vec<Value> = Vec::new();
        for (v, t) in values {
            tags.push(t);
            match serde_json::from_value::<T>(v.clone()) {
                Ok(e) => {
                    loaded.entries.push(e);
                    kept.push(v);
                }
                Err(_) => damaged_lines += 1,
            }
        }
        if header_missing && damaged_lines == 0 {
            // Entries without a (valid) header: not something this code
            // writes.
            damaged_lines = 1;
        }
        loaded.damaged = damaged_lines;
        loaded.forged = sc.forged;
        loaded.upgraded_from_v1 = legacy && adopt_legacy;
        if damaged_lines == 0 && !legacy {
            loaded.anchor = if tags.is_empty() {
                match anchor {
                    None => AnchorCheck::NoAnchor,
                    Some(_) => AnchorCheck::RolledBack(
                        "the journal holds no sealed entry while the black box holds its head"
                            .into(),
                    ),
                }
            } else {
                check_anchor(generation, &tags, anchor)
            };
        }
        if damaged_lines > 0 {
            let qdir = dir.join("quarantine");
            fsutil::create_dir_private(&qdir)?;
            let q = qdir.join(format!("{name}.{}.damaged", unix_ms()));
            let bytes = fsutil::read_capped_nofollow(&path, MAX_FILE_BYTES)?;
            let mut f = fsutil::create_new_private(&q)?;
            f.write_all(&bytes)?;
            f.sync_all()?;
            fsutil::sync_dir(&qdir)?;
            loaded.quarantined = Some(q);
        }
        let rewritten = damaged_lines > 0 || sc.good_end == 0 || legacy;
        let (file, generation, prev) = if rewritten {
            // Rewrite from the good entries (their exact JSON values), as
            // the next generation.
            let g = next_generation(generation);
            let (f, synced, prev) = rewrite(dir, name, kind, key, g, &kept)?;
            synced?;
            (f, g, prev)
        } else {
            if loaded.torn_bytes > 0 {
                let f = std::fs::OpenOptions::new()
                    .write(true)
                    .custom_flags(fsutil::O_NOFOLLOW)
                    .open(&path)?;
                f.set_len(sc.good_end)?;
                f.sync_all()?;
            }
            let prev = tags.last().copied().unwrap_or(GENESIS);
            (fsutil::open_append_nofollow(&path)?, generation, prev)
        };
        let len = file.metadata()?.len();
        let j = Journal {
            dir: dir.to_path_buf(),
            name: name.to_string(),
            kind: kind.to_string(),
            key: key.clone(),
            file,
            generation,
            prev,
            lines: kept.len(),
            len,
            poisoned: false,
        };
        Ok((j, loaded))
    }

    /// Entries in the file (header excluded).
    pub fn lines(&self) -> usize {
        self.lines
    }

    pub fn path(&self) -> PathBuf {
        self.dir.join(&self.name)
    }

    /// Where the journal ends now (what the black box anchors).
    pub fn head(&self) -> Head {
        Head {
            generation: self.generation,
            seq: self.lines as u64,
            tag: to_hex(&self.prev),
        }
    }

    /// Append one entry and make it durable (`fdatasync`) before returning.
    ///
    /// On failure (a short write on a full disk, an fsync error) the file is
    /// cut back to its length before the append, so a later good line can
    /// never follow a fragment (which the next open would have to call
    /// damage); if even that fails, the journal refuses every further
    /// append until it is reopened.
    pub fn append<T: Serialize>(&mut self, entry: &T) -> io::Result<()> {
        if self.poisoned {
            return Err(io::Error::other(
                "the journal could not be rolled back after a failed append",
            ));
        }
        let (line, tag) = line_of(&self.key, &self.kind, &self.prev, entry)?;
        let res = (|| -> io::Result<()> {
            #[cfg(test)]
            for point in ["journal.append.torn", "survive.journal.append.short_write"] {
                if fault::hit(point).is_err() {
                    // Half the line reaches the file, then the write fails
                    // (the process dies, or lives on: a full disk).
                    let _ = self.file.write_all(&line[..line.len() / 2]);
                    return Err(io::Error::other(format!("injected failure at {point}")));
                }
            }
            self.file.write_all(&line)?;
            fault("journal.append.before_sync")?;
            self.file.sync_data()
        })();
        match res {
            Ok(()) => {
                self.lines += 1;
                self.len += line.len() as u64;
                self.prev = tag;
                Ok(())
            }
            Err(e) => {
                #[cfg(test)]
                if fault::fired() {
                    // A killed process does not clean up.
                    return Err(e);
                }
                if self
                    .file
                    .set_len(self.len)
                    .and_then(|()| self.file.sync_data())
                    .is_err()
                {
                    self.poisoned = true;
                }
                Err(e)
            }
        }
    }

    /// Replace the journal by `entries` (crash-safe, see the module), as
    /// the next generation.
    pub fn compact<T: Serialize>(&mut self, entries: &[T]) -> io::Result<()> {
        let values: Vec<Value> = entries
            .iter()
            .map(|e| serde_json::to_value(e).map_err(io::Error::other))
            .collect::<io::Result<_>>()?;
        let g = self.generation.saturating_add(1);
        let (file, synced, prev) =
            rewrite(&self.dir, &self.name, &self.kind, &self.key, g, &values)?;
        // The rename happened: from now on only the new file is the
        // journal (appending to the old handle would write into the
        // replaced inode). If the rename may not be durable (the directory
        // fsync failed), refuse every append until the next open.
        self.file = file;
        self.generation = g;
        self.prev = prev;
        self.lines = values.len();
        self.len = self.file.metadata()?.len();
        self.poisoned = synced.is_err();
        synced
    }
}

fn header_of(kind: &str, key: &StateSealKey, generation: u64) -> Header {
    Header {
        t: "header".into(),
        format: FORMAT.into(),
        kind: kind.into(),
        key_id: Some(key.key_id().to_string()),
        generation,
    }
}

/// Write `values` under a fresh header of `generation` to a temp file,
/// fsync, rename over `dir/name`, fsync the directory. `Err` if the journal
/// was not replaced; otherwise the append handle of the new file, whether
/// the directory fsync (the rename's durability) succeeded, and the last
/// tag.
fn rewrite(
    dir: &Path,
    name: &str,
    kind: &str,
    key: &StateSealKey,
    generation: u64,
    values: &[Value],
) -> io::Result<(File, io::Result<()>, [u8; 32])> {
    let tmp = dir.join(format!("{name}.tmp-{}", fsutil::random_hex16()?));
    let mut prev = GENESIS;
    let res = (|| {
        let mut f = fsutil::create_new_private(&tmp)?;
        let (mut out, t) = line_of(key, kind, &prev, &header_of(kind, key, generation))?;
        prev = t;
        for v in values {
            let (l, t) = line_of(key, kind, &prev, v)?;
            out.extend_from_slice(&l);
            prev = t;
        }
        f.write_all(&out)?;
        fault("journal.compact.before_sync")?;
        f.sync_all()?;
        fault("journal.compact.before_rename")?;
        std::fs::rename(&tmp, dir.join(name))
    })();
    if let Err(e) = res {
        #[cfg(test)]
        if fault::fired() {
            // A killed process leaves the temp file behind.
            return Err(e);
        }
        let _ = std::fs::remove_file(&tmp);
        return Err(e);
    }
    let synced = fault("journal.compact.before_dir_sync")
        .and_then(|()| fault("survive.journal.compact.dir_sync"))
        .and_then(|()| fsutil::sync_dir(dir));
    let file = fsutil::open_append_nofollow(&dir.join(name))?;
    Ok((file, synced, prev))
}

fn create_with_header(
    dir: &Path,
    name: &str,
    kind: &str,
    key: &StateSealKey,
    generation: u64,
) -> io::Result<(File, [u8; 32])> {
    let path = dir.join(name);
    let mut f = fsutil::create_new_private(&path)?;
    let (line, tag) = line_of(key, kind, &GENESIS, &header_of(kind, key, generation))?;
    f.write_all(&line)?;
    f.sync_all()?;
    fsutil::sync_dir(dir)?;
    drop(f);
    Ok((fsutil::open_append_nofollow(&path)?, tag))
}

fn remove_stale_temps(dir: &Path, name: &str) {
    let prefix = format!("{name}.tmp-");
    if let Ok(rd) = std::fs::read_dir(dir) {
        for e in rd.flatten() {
            if e.file_name().to_string_lossy().starts_with(&prefix) {
                let _ = std::fs::remove_file(e.path());
            }
        }
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use crate::control::fsutil::fault;

    #[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
    #[serde(deny_unknown_fields)]
    struct E {
        t: String,
        n: u64,
    }

    fn e(n: u64) -> E {
        E { t: "e".into(), n }
    }

    fn tmp(tag: &str) -> PathBuf {
        let d = std::env::temp_dir().join(format!("robodr-cp-j-{tag}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&d);
        std::fs::create_dir_all(&d).unwrap();
        d
    }

    pub(crate) fn key() -> Arc<StateSealKey> {
        Arc::new(StateSealKey::derive(&[0x5a; 32], SEAL_PURPOSE).unwrap())
    }

    /// The sealing other modules' tests open their journals with.
    pub(crate) fn sealing() -> Sealing {
        Sealing::new(key())
    }

    fn open(d: &Path) -> (Journal, Loaded<E>) {
        Journal::open(d, "t.journal", "test", &key(), None, false).unwrap()
    }

    fn open_at(d: &Path, anchor: Option<&Anchor>) -> (Journal, Loaded<E>) {
        Journal::open(d, "t.journal", "test", &key(), anchor, false).unwrap()
    }

    /// A sealed line chained to `prev` (hex), as this code writes it.
    fn sealed_line(prev: &str, v: &impl Serialize) -> Vec<u8> {
        let mut p = [0u8; 32];
        p.copy_from_slice(&from_hex(prev).unwrap());
        line_of(&key(), "test", &p, v).unwrap().0
    }

    /// Byte offsets of each line start, plus the end of the file.
    fn starts(text: &[u8]) -> Vec<usize> {
        std::iter::once(0)
            .chain(
                text.iter()
                    .enumerate()
                    .filter(|(_, b)| **b == b'\n')
                    .map(|(i, _)| i + 1),
            )
            .collect()
    }

    fn ns(l: &Loaded<E>) -> Vec<u64> {
        l.entries.iter().map(|e| e.n).collect()
    }

    fn temps(d: &Path) -> usize {
        std::fs::read_dir(d)
            .unwrap()
            .filter(|e| {
                e.as_ref()
                    .unwrap()
                    .file_name()
                    .to_string_lossy()
                    .contains(".tmp-")
            })
            .count()
    }

    #[test]
    fn appends_survive_a_reopen() {
        let d = tmp("basic");
        let (mut j, l) = open(&d);
        assert!(l.created);
        for n in 0..5 {
            j.append(&e(n)).unwrap();
        }
        drop(j);
        let (j, l) = open(&d);
        assert_eq!(ns(&l), [0, 1, 2, 3, 4]);
        assert_eq!((l.torn_bytes, l.damaged, l.created), (0, 0, false));
        assert_eq!(j.lines(), 5);
        // The file is the documented format.
        let text = std::fs::read_to_string(d.join("t.journal")).unwrap();
        let first = text.lines().next().unwrap();
        assert!(
            first.contains(r#""format":"robodr-cp-journal/v2""#) && first.contains("hmac-sha256:"),
            "{first}"
        );
        // Each tag is the sealed chain over the previous line's tag.
        let (h, _) = first.split_once(' ').unwrap();
        let (sum, json) = text.lines().nth(1).unwrap().split_once(' ').unwrap();
        let mut prev = [0u8; 32];
        prev.copy_from_slice(&from_hex(h).unwrap());
        assert_eq!(sum, to_hex(&tag_of(&key(), "test", &prev, json.as_bytes())));
        assert_ne!(sum, to_hex(&sha256(json.as_bytes())), "not a bare checksum");
        let _ = std::fs::remove_dir_all(&d);
    }

    /// Crash point: killed half-way through an append (before its fsync):
    /// the torn line is cut at the next open, the earlier entries stay,
    /// and appending continues on a clean file.
    #[test]
    fn crash_during_append_leaves_a_torn_tail_that_is_cut() {
        let d = tmp("torn");
        let (mut j, _) = open(&d);
        j.append(&e(1)).unwrap();
        fault::arm("journal.append.torn", 1);
        assert!(j.append(&e(2)).is_err());
        assert!(fault::fired());
        drop(j);
        let (mut j, l) = open(&d);
        assert_eq!(ns(&l), [1]);
        assert!(l.torn_bytes > 0);
        assert_eq!(l.damaged, 0, "a torn tail is a crash, not damage");
        j.append(&e(3)).unwrap();
        drop(j);
        let (_, l) = open(&d);
        assert_eq!(ns(&l), [1, 3]);
        assert_eq!(l.torn_bytes, 0);
        let _ = std::fs::remove_dir_all(&d);
    }

    /// Crash point: the line was written but the process died before the
    /// fsync returned. The caller never acted on it; the entry is either
    /// there whole (process crash: the page cache survives) or torn (power
    /// loss, previous test): never half-read.
    #[test]
    fn crash_between_write_and_fsync_keeps_a_whole_entry() {
        let d = tmp("nosync");
        let (mut j, _) = open(&d);
        j.append(&e(1)).unwrap();
        fault::arm("journal.append.before_sync", 1);
        assert!(j.append(&e(2)).is_err());
        drop(j);
        let (_, l) = open(&d);
        assert_eq!(ns(&l), [1, 2]);
        assert_eq!((l.torn_bytes, l.damaged), (0, 0));
        let _ = std::fs::remove_dir_all(&d);
    }

    /// Crash points of a compaction: before the temp file is synced, before
    /// the rename (old journal intact, temp file left over and removed at
    /// the next open), and after the rename before the directory fsync
    /// (the new journal: same live state).
    #[test]
    fn crash_during_compaction_never_loses_the_live_state() {
        for (point, expect) in [
            ("journal.compact.before_sync", vec![0, 1, 2, 3]),
            ("journal.compact.before_rename", vec![0, 1, 2, 3]),
            ("journal.compact.before_dir_sync", vec![2, 3]),
        ] {
            let d = tmp(&format!("compact-{point}"));
            let (mut j, _) = open(&d);
            for n in 0..4 {
                j.append(&e(n)).unwrap();
            }
            fault::arm(point, 1);
            assert!(j.compact(&[e(2), e(3)]).is_err(), "{point}");
            drop(j);
            let leftover = temps(&d);
            let (mut j, l) = open(&d);
            assert_eq!(ns(&l), expect, "{point}");
            assert_eq!((l.torn_bytes, l.damaged), (0, 0), "{point}");
            assert_eq!(temps(&d), 0, "{point}: temp file removed at open");
            if point != "journal.compact.before_dir_sync" {
                assert_eq!(leftover, 1, "{point}: a killed compaction leaves its temp");
            }
            // And a compaction that completes.
            j.compact(&[e(9)]).unwrap();
            j.append(&e(10)).unwrap();
            drop(j);
            let (_, l) = open(&d);
            assert_eq!(ns(&l), [9, 10], "{point}");
            let _ = std::fs::remove_dir_all(&d);
        }
    }

    /// A damaged line followed by good ones is not a crash: it is counted,
    /// the original is quarantined and the journal rewritten without it.
    #[test]
    fn damage_in_the_middle_is_quarantined_and_skipped() {
        let d = tmp("damage");
        let (mut j, _) = open(&d);
        for n in 0..4 {
            j.append(&e(n)).unwrap();
        }
        drop(j);
        let p = d.join("t.journal");
        let mut text = std::fs::read(&p).unwrap();
        // Flip one byte in the third line (entry n = 1).
        let starts = starts(&text);
        text[starts[2] + 70] ^= 0x01;
        std::fs::write(&p, &text).unwrap();
        let (_, l) = open(&d);
        assert_eq!(ns(&l), [0, 2, 3]);
        assert_eq!(l.damaged, 1);
        let q = l.quarantined.clone().expect("quarantined copy");
        assert_eq!(std::fs::read(&q).unwrap(), text);
        // Rewritten: the next open is clean.
        let (_, l) = open(&d);
        assert_eq!(ns(&l), [0, 2, 3]);
        assert_eq!((l.damaged, l.torn_bytes), (0, 0));
        // A line of another shape (valid seal, wrong fields) is damage
        // too.
        let head = open(&d).0.head().tag;
        let odd = sealed_line(&head, &serde_json::json!({"t": "x", "zzz": 1}));
        let odd_tag = String::from_utf8(odd[..64].to_vec()).unwrap();
        let mut f = fsutil::open_append_nofollow(&p).unwrap();
        f.write_all(&odd).unwrap();
        f.write_all(&sealed_line(&odd_tag, &e(4))).unwrap();
        drop(f);
        let (_, l) = open(&d);
        assert_eq!(ns(&l), [0, 2, 3, 4]);
        assert_eq!(l.damaged, 1);
        let _ = std::fs::remove_dir_all(&d);
    }

    /// A failed append the process survives (a short write on a full disk,
    /// an fsync error) is rolled back: no fragment is left for a later
    /// line to follow, so the next open sees no damage.
    #[test]
    fn a_survived_append_failure_leaves_no_fragment() {
        let d = tmp("rollback");
        let (mut j, _) = open(&d);
        j.append(&e(1)).unwrap();
        let before = std::fs::read(d.join("t.journal")).unwrap();
        fault::arm("survive.journal.append.short_write", 1);
        assert!(j.append(&e(2)).is_err());
        assert!(!fault::fired());
        assert_eq!(std::fs::read(d.join("t.journal")).unwrap(), before);
        fault::arm("journal.append.before_sync", 1);
        // A failed fsync of a whole line: rolled back too (it is a death
        // point, so emulate the survivor's cleanup by reopening).
        assert!(j.append(&e(3)).is_err());
        drop(j);
        let (mut j, l) = open(&d);
        assert_eq!(ns(&l), [1, 3]);
        let big = serde_json::json!({"t": "e", "n": 1, "pad": "x".repeat(MAX_LINE)});
        assert!(j.append(&big).is_err());
        j.append(&e(4)).unwrap();
        drop(j);
        let (_, l) = open(&d);
        assert_eq!(ns(&l), [1, 3, 4]);
        assert_eq!((l.damaged, l.torn_bytes), (0, 0));
        let _ = std::fs::remove_dir_all(&d);
    }

    /// A compaction whose rename happened but whose directory fsync failed
    /// (and the process lives on): appends never go to the replaced file;
    /// the journal refuses them until it is reopened, which sees the new
    /// file.
    #[test]
    fn a_failed_directory_sync_after_the_rename_fails_closed() {
        let d = tmp("dirsync");
        let (mut j, _) = open(&d);
        j.append(&e(1)).unwrap();
        fault::arm("survive.journal.compact.dir_sync", 1);
        assert!(j.compact(&[e(2)]).is_err());
        assert!(!fault::fired());
        assert!(
            j.append(&e(3)).is_err(),
            "appends are refused once the rename may not be durable"
        );
        drop(j);
        let (mut j, l) = open(&d);
        assert_eq!(ns(&l), [2]);
        j.append(&e(4)).unwrap();
        drop(j);
        assert_eq!(ns(&open(&d).1), [2, 4]);
        let _ = std::fs::remove_dir_all(&d);
    }

    /// Review finding 4: only a single trailing line can be torn (every
    /// append is one synced write). Two or more bad lines at the end are
    /// damage: counted, quarantined, rewritten, so the caller falls back to
    /// its fail-safe state instead of silently forgetting synced entries.
    #[test]
    fn tail_damage_beyond_one_line_is_damage_not_a_torn_tail() {
        let corrupt_last = |p: &Path, k: usize| {
            let mut text = std::fs::read(p).unwrap();
            let starts = starts(&text);
            // starts has one entry per line plus the end of the file.
            let lines = starts.len() - 1;
            for l in lines - k..lines {
                text[starts[l] + 70] ^= 0x01;
            }
            std::fs::write(p, &text).unwrap();
            text
        };
        // One bad last line: a torn tail, as before.
        let d = tmp("tail1");
        let (mut j, _) = open(&d);
        for n in 0..4 {
            j.append(&e(n)).unwrap();
        }
        drop(j);
        corrupt_last(&d.join("t.journal"), 1);
        let (_, l) = open(&d);
        assert_eq!(ns(&l), [0, 1, 2]);
        assert!(l.torn_bytes > 0);
        assert_eq!(l.damaged, 0);
        let _ = std::fs::remove_dir_all(&d);
        // Two bad last lines: damage.
        let d = tmp("tail2");
        let (mut j, _) = open(&d);
        for n in 0..4 {
            j.append(&e(n)).unwrap();
        }
        drop(j);
        let text = corrupt_last(&d.join("t.journal"), 2);
        let (_, l) = open(&d);
        assert_eq!(ns(&l), [0, 1]);
        assert_eq!(l.damaged, 2, "two bad trailing lines cannot be one crash");
        assert_eq!(l.torn_bytes, 0);
        let q = l.quarantined.clone().expect("quarantined copy");
        assert_eq!(std::fs::read(&q).unwrap(), text);
        let (_, l) = open(&d);
        assert_eq!((l.damaged, l.torn_bytes), (0, 0), "rewritten clean");
        let _ = std::fs::remove_dir_all(&d);
        // A bad whole line followed by an unterminated fragment: damage.
        let d = tmp("tail3");
        let (mut j, _) = open(&d);
        for n in 0..3 {
            j.append(&e(n)).unwrap();
        }
        drop(j);
        corrupt_last(&d.join("t.journal"), 1);
        let mut f = fsutil::open_append_nofollow(&d.join("t.journal")).unwrap();
        f.write_all(b"0123 {\"t\":").unwrap();
        drop(f);
        let (_, l) = open(&d);
        assert_eq!(ns(&l), [0, 1]);
        assert_eq!(l.damaged, 2);
        let _ = std::fs::remove_dir_all(&d);
    }

    #[test]
    fn hostile_files_are_handled() {
        // A journal of another kind is refused, not reinterpreted.
        let d = tmp("kind");
        drop(open(&d));
        let e2 = Journal::open::<E>(&d, "t.journal", "other", &key(), None, false).unwrap_err();
        assert!(e2.to_string().contains("expected"), "{e2}");
        let _ = std::fs::remove_dir_all(&d);
        // An empty file (killed right after creating it): started over.
        let d = tmp("empty");
        std::fs::write(d.join("t.journal"), b"").unwrap();
        let (mut j, l) = open(&d);
        assert!(l.entries.is_empty());
        j.append(&e(1)).unwrap();
        drop(j);
        assert_eq!(ns(&open(&d).1), [1]);
        let _ = std::fs::remove_dir_all(&d);
        // A symlink is never followed.
        let d = tmp("link");
        std::fs::write(d.join("target"), b"x").unwrap();
        std::os::unix::fs::symlink(d.join("target"), d.join("t.journal")).unwrap();
        assert!(Journal::open::<E>(&d, "t.journal", "test", &key(), None, false).is_err());
        assert_eq!(std::fs::read(d.join("target")).unwrap(), b"x");
        let _ = std::fs::remove_dir_all(&d);
        // An over-long line in the middle is damage, garbage at the end a
        // torn tail.
        let d = tmp("long");
        let (mut j, _) = open(&d);
        j.append(&e(1)).unwrap();
        drop(j);
        let p = d.join("t.journal");
        let mut f = fsutil::open_append_nofollow(&p).unwrap();
        f.write_all(&vec![b'a'; MAX_LINE + 10]).unwrap();
        f.write_all(b"\n").unwrap();
        // A sealed line after it: the chain cannot pass a line without a
        // tag, so it fails like an edit (damage, never a torn tail).
        f.write_all(&sealed_line(&"00".repeat(32), &e(2))).unwrap();
        f.write_all(b"garbage without newline").unwrap();
        drop(f);
        let (_, l) = open(&d);
        assert_eq!(ns(&l), [1]);
        assert_eq!((l.damaged, l.forged), (3, 1));
        let _ = std::fs::remove_dir_all(&d);
    }

    fn write_lines(p: &Path, lines: &[Vec<u8>]) {
        std::fs::write(p, lines.concat()).unwrap();
    }

    fn file_lines(p: &Path) -> Vec<Vec<u8>> {
        let text = std::fs::read(p).unwrap();
        let s = starts(&text);
        s.windows(2).map(|w| text[w[0]..w[1]].to_vec()).collect()
    }

    fn anchored(j: &Journal, clean: bool) -> Anchor {
        Anchor {
            head: j.head(),
            clean,
        }
    }

    /// Gap 1 (sealed journal): an entry edited by someone without the key,
    /// even with a correct bare SHA-256 as v1 had, is damage: skipped,
    /// counted as forged, quarantined; the caller fails safe.
    #[test]
    fn a_tampered_entry_is_detected() {
        let d = tmp("seal-tamper");
        let (mut j, _) = open(&d);
        for n in 0..4 {
            j.append(&e(n)).unwrap();
        }
        drop(j);
        let p = d.join("t.journal");
        let mut lines = file_lines(&p);
        // Entry n = 1 rewritten as n = 9 with the v1-style checksum.
        lines[2] = v1_line(&e(9));
        write_lines(&p, &lines);
        let (_, l) = open(&d);
        // The edit is skipped, not believed; the next entry chained to the
        // replaced tag, so it fails too (an edit cannot be confined to one
        // line without the key).
        assert_eq!(ns(&l), [0, 3]);
        assert_eq!((l.damaged, l.forged), (2, 2));
        assert!(l.quarantined.is_some());
        // The last entry edited: a well-formed line under a bad seal is an
        // edit, never a torn tail.
        let (mut j, _) = open(&d);
        j.append(&e(4)).unwrap();
        drop(j);
        let mut lines = file_lines(&p);
        let n = lines.len();
        let pos = lines[n - 1].len() - 3;
        lines[n - 1][pos] = b'7';
        write_lines(&p, &lines);
        let (_, l) = open(&d);
        assert_eq!(ns(&l), [0, 3]);
        assert_eq!((l.damaged, l.forged, l.torn_bytes), (1, 1, 0));
        let _ = std::fs::remove_dir_all(&d);
    }

    /// A deleted entry breaks the chain at the next line: damage, also
    /// when it was the second-to-last line (which a v1 journal took for a
    /// torn tail and forgot silently).
    #[test]
    fn a_deleted_entry_is_detected() {
        for victim in [2usize, 3] {
            let d = tmp(&format!("seal-delete-{victim}"));
            let (mut j, _) = open(&d);
            for n in 0..4 {
                j.append(&e(n)).unwrap();
            }
            drop(j);
            let p = d.join("t.journal");
            let mut lines = file_lines(&p);
            lines.remove(victim);
            write_lines(&p, &lines);
            let (_, l) = open(&d);
            assert_eq!(l.damaged, 1, "victim {victim}");
            assert_eq!(l.forged, 1, "victim {victim}");
            assert_eq!(l.torn_bytes, 0, "victim {victim}: not a torn tail");
            assert!(l.quarantined.is_some());
            let _ = std::fs::remove_dir_all(&d);
        }
    }

    /// Whole entries cut from the end, or the whole file put back from an
    /// older copy, are consistent seals: only the black box's head shows
    /// them (`RolledBack`). A clean stop's head that matches is
    /// `Verified`; entries after a head, `Unanchored`.
    #[test]
    fn truncation_and_a_replayed_old_file_are_caught_by_the_head() {
        let d = tmp("seal-head");
        let p = d.join("t.journal");
        let (mut j, l) = open(&d);
        assert_eq!(l.anchor, AnchorCheck::NoAnchor);
        j.append(&e(0)).unwrap();
        j.append(&e(1)).unwrap();
        let old_copy = std::fs::read(&p).unwrap();
        j.append(&e(2)).unwrap();
        let head = anchored(&j, true);
        drop(j);
        // Untouched: verified against the clean stop's head.
        let (j, l) = open_at(&d, Some(&head));
        assert_eq!(l.anchor, AnchorCheck::Verified);
        assert_eq!(j.head(), head.head);
        drop(j);
        // The same head recorded by a run that did not stop cleanly.
        let unclean = Anchor {
            clean: false,
            ..head.clone()
        };
        let (_, l) = open_at(&d, Some(&unclean));
        assert!(
            matches!(l.anchor, AnchorCheck::Unanchored(_)),
            "{:?}",
            l.anchor
        );
        // Entries after the head.
        let (mut j, _) = open_at(&d, Some(&head));
        j.append(&e(3)).unwrap();
        drop(j);
        let (_, l) = open_at(&d, Some(&head));
        assert!(
            matches!(l.anchor, AnchorCheck::Unanchored(_)),
            "{:?}",
            l.anchor
        );
        assert_eq!(l.damaged, 0);
        // Truncated: the last two entries cut at a line boundary.
        let lines = file_lines(&p);
        write_lines(&p, &lines[..lines.len() - 2]);
        let (_, l) = open_at(&d, Some(&head));
        assert_eq!(ns(&l), [0, 1]);
        assert_eq!(
            (l.damaged, l.torn_bytes),
            (0, 0),
            "the seal alone cannot see it"
        );
        assert!(
            matches!(&l.anchor, AnchorCheck::RolledBack(r) if r.contains("cut")),
            "{:?}",
            l.anchor
        );
        // A replayed old file (same generation, shorter).
        std::fs::write(&p, &old_copy).unwrap();
        let (_, l) = open_at(&d, Some(&head));
        assert!(
            matches!(l.anchor, AnchorCheck::RolledBack(_)),
            "{:?}",
            l.anchor
        );
        // A replayed file of an older generation (the head moved on with a
        // compaction).
        let (mut j, _) = open_at(&d, None);
        j.compact(&[e(5)]).unwrap();
        let newer = anchored(&j, true);
        drop(j);
        std::fs::write(&p, &old_copy).unwrap();
        let (_, l) = open_at(&d, Some(&newer));
        assert!(
            matches!(&l.anchor, AnchorCheck::RolledBack(r) if r.contains("older")),
            "{:?}",
            l.anchor
        );
        // Removed altogether.
        std::fs::remove_file(&p).unwrap();
        let (j, l) = open_at(&d, Some(&newer));
        assert!(l.created);
        assert!(
            matches!(l.anchor, AnchorCheck::RolledBack(_)),
            "{:?}",
            l.anchor
        );
        assert!(
            j.head().generation > newer.head.generation,
            "a fresh generation"
        );
        let _ = std::fs::remove_dir_all(&d);
    }

    /// A journal sealed under another key (another unit's, a rotated
    /// black-box key) is all damage, named, quarantined and started over.
    #[test]
    fn a_journal_under_the_wrong_key_is_refused() {
        let d = tmp("seal-key");
        let other = Arc::new(StateSealKey::derive(&[0x11; 32], SEAL_PURPOSE).unwrap());
        let (mut j, _) = Journal::open::<E>(&d, "t.journal", "test", &other, None, false).unwrap();
        j.append(&e(1)).unwrap();
        j.append(&e(2)).unwrap();
        drop(j);
        let (mut j, l) = open(&d);
        assert!(l.entries.is_empty());
        assert_eq!((l.damaged, l.forged), (3, 3));
        assert_eq!(l.wrong_key.as_deref(), Some(other.key_id()));
        assert!(l.quarantined.is_some());
        j.append(&e(3)).unwrap();
        drop(j);
        let (_, l) = open(&d);
        assert_eq!(ns(&l), [3]);
        assert_eq!((l.damaged, l.wrong_key), (0, None));
        let _ = std::fs::remove_dir_all(&d);
    }

    fn v1_line(v: &impl Serialize) -> Vec<u8> {
        let json = serde_json::to_vec(v).unwrap();
        let mut l = to_hex(&sha256(&json)).into_bytes();
        l.push(b' ');
        l.extend_from_slice(&json);
        l.push(b'\n');
        l
    }

    /// The one-time upgrade: a v1 journal is adopted and rewritten sealed
    /// only while the caller allows it (no head in the black box yet);
    /// afterwards a v1 file is a downgrade and refused as damage.
    #[test]
    fn a_v1_journal_is_upgraded_once_and_refused_afterwards() {
        let d = tmp("seal-v1");
        let p = d.join("t.journal");
        let v1 = vec![
            v1_line(&serde_json::json!({"t": "header", "format": LEGACY_FORMAT, "kind": "test"})),
            v1_line(&e(1)),
            v1_line(&e(2)),
        ];
        write_lines(&p, &v1);
        let (j, l) = Journal::open::<E>(&d, "t.journal", "test", &key(), None, true).unwrap();
        assert_eq!(ns(&l), [1, 2]);
        assert!(l.upgraded_from_v1 && !l.legacy_refused);
        assert_eq!((l.damaged, l.anchor.clone()), (0, AnchorCheck::NotChecked));
        assert_eq!(j.head().generation, 1);
        drop(j);
        // Sealed now.
        let text = std::fs::read_to_string(&p).unwrap();
        assert!(text.contains(FORMAT), "{text}");
        let (_, l) = open(&d);
        assert_eq!(ns(&l), [1, 2]);
        assert!(!l.upgraded_from_v1);
        // A v1 file put back once sealing started: refused.
        write_lines(&p, &v1);
        let (_, l) = open(&d);
        assert!(l.entries.is_empty());
        assert!(l.legacy_refused && !l.upgraded_from_v1);
        assert_eq!(l.damaged, 3);
        assert!(l.quarantined.is_some());
        let _ = std::fs::remove_dir_all(&d);
    }
}
