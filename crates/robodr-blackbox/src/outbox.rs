//! Exporting pending evidence from a black-box directory while its recorder
//! runs (`robodr-blackbox export-pending`, T15).
//!
//! [`crate::Recorder::export_pending`] needs the recorder, and the recorder
//! is held by its writer (`robodr-agentd` takes the directory lock). This
//! module exports from the directory instead, read only, so a timer can
//! move evidence to a diode / media outbox while the writer records:
//!
//! 1. Take `export.lock` in the directory (one exporter at a time; the
//!    recorder's own lock is not touched).
//! 2. Read the signed export cursor (`export-cursor.json`). It counts only
//!    if it verifies under the recorder's **current** key, as the recorder
//!    itself requires; a cursor that does not verify is ignored and the
//!    export starts at the oldest retained record (re-exporting is safe).
//! 3. Walk the retained segments oldest first, one in memory at a time,
//!    and collect the frames of the current chain (the chain of the newest
//!    record) after the cursor: each record's hash is recomputed, its
//!    signature checked with the caller's keys, and it must link to the
//!    one before (`seq + 1`, `prev_hash`). The bundle stops at the first
//!    break (a quarantined or dropped segment, a record half written right
//!    now) or at the size bounds; the next run continues from there.
//! 4. Write the `RBBXBND1` bundle to the outbox (temp file, fsync, rename,
//!    fsync), **then** advance the cursor (signed with the recorder's key,
//!    atomic replace, owned like the directory so the recorder can read
//!    it). A crash in between re-exports the same records next time: the
//!    far side's [`crate::Receiver`] reports the replay instead of
//!    accepting it twice.
//!
//! The recorder re-reads the cursor before cyclic retention would drop an
//! unexported segment ([`crate::RecorderConfig::unexported_reserve_segments`],
//! [`crate::Recorder::refresh_export_state`]), so what this exporter moved
//! out may go, and what it has not may not, within the reserve.
//!
//! **Gaps.** If records between the cursor and the oldest retained record
//! are gone (cyclic retention dropped them before they were exported, or
//! they were quarantined), the bundle carries no anchor and
//! [`PendingExport::gap`] names the missing seqs; the receiver then reports
//! the gap (its trusted position does not link). Nothing is papered over.
//!
//! The bundle is the same format the recorder and the control-plane
//! evidence API produce; the far side verifies it with
//! `robodr-blackbox verify BUNDLE` or [`crate::Receiver::accept`].

use crate::crypto::to_hex;
use crate::export::{cursor_signing_message, Anchor, Bundle, SignedCursor};
use crate::record::{
    scan_frames, signing_message, ChainIdentity, GenesisPayload, Hash, Record, RecordKind,
    ScanItem, SegmentStartPayload,
};
use crate::sign::Signer;
use crate::store::{atomic_write_owned, list_segments, lock_file, read_state, Error, CURSOR_FILE};
use std::fs::{self, File, OpenOptions};
use std::io::{self, Read, Write};
use std::path::{Path, PathBuf};

/// Lock file serialising exporters of one directory.
pub const EXPORT_LOCK_FILE: &str = "export.lock";
/// File name prefix of the bundles written to the outbox.
pub const BUNDLE_PREFIX: &str = "rbbx-";
/// File name suffix of the bundles written to the outbox.
pub const BUNDLE_SUFFIX: &str = ".rbbx";
/// Largest segment file read.
const MAX_SEGMENT_FILE_BYTES: u64 = 256 * 1024 * 1024;

/// Size bounds of one bundle.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PendingOptions {
    /// Most records per bundle.
    pub max_records: usize,
    /// Most frame bytes per bundle (a bundle holds at least one record).
    pub max_bytes: u64,
}

impl Default for PendingOptions {
    /// 100 000 records, 64 MiB.
    fn default() -> Self {
        Self {
            max_records: 100_000,
            max_bytes: 64 * 1024 * 1024,
        }
    }
}

/// What [`collect_pending`] found.
#[derive(Debug, Clone)]
pub struct PendingExport {
    pub bundle: Bundle,
    pub first_seq: u64,
    pub last_seq: u64,
    pub last_hash: Hash,
    pub records: u64,
    /// `[first, last]` seqs after the cursor that are no longer retained
    /// (lost before export).
    pub gap: Option<[u64; 2]>,
    /// Why an existing cursor file was ignored, if it was.
    pub cursor_rejected: Option<String>,
    /// More records are pending than this bundle holds.
    pub more: bool,
}

/// Is `sig` a valid signature over `msg` by one of the caller's keys (the
/// recorder's current key and, after rotations, its previous keys)?
pub type Authentic<'a> = &'a dyn Fn(&[u8], &[u8]) -> bool;

fn read_segment(p: &Path) -> io::Result<Option<Vec<u8>>> {
    let mut o = OpenOptions::new();
    o.read(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        o.custom_flags(crate::store::sys::O_NOFOLLOW);
    }
    let f = match o.open(p) {
        Ok(f) => f,
        Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(None),
        Err(e) => return Err(e),
    };
    if !f.metadata()?.is_file() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("{} is not a regular file", p.display()),
        ));
    }
    let mut b = Vec::new();
    f.take(MAX_SEGMENT_FILE_BYTES + 1).read_to_end(&mut b)?;
    if b.len() as u64 > MAX_SEGMENT_FILE_BYTES {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!(
                "{} is larger than {MAX_SEGMENT_FILE_BYTES} bytes",
                p.display()
            ),
        ));
    }
    Ok(Some(b))
}

fn records_of(bytes: &[u8]) -> impl Iterator<Item = (usize, usize, Record)> + '_ {
    scan_frames(bytes)
        .items
        .into_iter()
        .filter_map(|i| match i {
            ScanItem::Record(r) => Some((r.offset as usize, r.frame_len as usize, r.record)),
            ScanItem::Malformed { .. } => None,
        })
}

/// Collect the records after the export cursor (see the module docs).
/// `None`: nothing is pending. `cursor_key` checks the cursor's signature
/// (the recorder's current key only); `authentic` checks record
/// signatures.
pub fn collect_pending(
    dir: &Path,
    cursor_key: Authentic<'_>,
    authentic: Authentic<'_>,
    opts: PendingOptions,
) -> Result<Option<PendingExport>, Error> {
    let segs = list_segments(dir)?;
    // The current chain: the newest record's.
    let mut chain: Option<Hash> = None;
    for (_, p) in segs.iter().rev() {
        if let Some(b) = read_segment(p)? {
            if let Some((_, _, r)) = records_of(&b).last() {
                chain = Some(r.chain_id);
                break;
            }
        }
    }
    let Some(chain) = chain else {
        return Ok(None);
    };
    let mut cursor_rejected = None;
    let cursor = match read_state(dir, CURSOR_FILE)? {
        None => None,
        Some(s) => match SignedCursor::from_json(&s) {
            Some(c) if c.anchor.chain_id != chain => {
                cursor_rejected = Some("names another chain (the log was restarted)".into());
                None
            }
            Some(c) if cursor_key(&cursor_signing_message(&c.anchor), &c.sig) => Some(c.anchor),
            Some(_) => {
                cursor_rejected =
                    Some("signature does not verify under the recorder's current key".into());
                None
            }
            None => {
                cursor_rejected = Some("unparseable or unsigned".into());
                None
            }
        },
    };
    let from = cursor.as_ref().map_or(0, |c| c.seq.saturating_add(1));
    let mut identity: Option<ChainIdentity> = None;
    let mut frames = Vec::new();
    let mut prev: Option<(u64, Hash)> = None;
    let mut first: Option<(u64, Hash)> = None;
    let mut count = 0usize;
    let mut more = false;
    'segments: for (_, p) in &segs {
        let Some(bytes) = read_segment(p)? else {
            // Dropped by retention since the listing: a break, unless
            // nothing was collected yet.
            if prev.is_some() {
                break;
            }
            continue;
        };
        for (off, len, r) in records_of(&bytes) {
            if r.chain_id != chain {
                continue;
            }
            // The chain identity (needed for the bundle) from any
            // retained statement of it, wherever it is.
            if identity.is_none() {
                let stated = match r.kind {
                    RecordKind::Genesis => r.payload_json::<GenesisPayload>().map(|g| g.identity),
                    RecordKind::SegmentStart => {
                        r.payload_json::<SegmentStartPayload>().map(|s| s.identity)
                    }
                    _ => None,
                };
                identity = stated.filter(|i| i.chain_id() == chain);
            }
            if r.seq < from {
                continue;
            }
            // Authentic, and linked to what came before.
            if r.compute_hash() != r.hash || !authentic(&signing_message(&r.hash), &r.sig) {
                if prev.is_some() {
                    break 'segments;
                }
                continue;
            }
            if let Some((ps, ph)) = prev {
                if r.seq != ps.saturating_add(1) || r.prev_hash != ph {
                    break 'segments;
                }
            }
            if count == opts.max_records
                || (count > 0 && frames.len() as u64 + len as u64 > opts.max_bytes)
            {
                more = true;
                break 'segments;
            }
            let Some(frame) = bytes.get(off..off.saturating_add(len)) else {
                break 'segments;
            };
            frames.extend_from_slice(frame);
            if first.is_none() {
                first = Some((r.seq, r.prev_hash));
            }
            prev = Some((r.seq, r.hash));
            count += 1;
        }
    }
    let (Some((first_seq, first_prev)), Some((last_seq, last_hash))) = (first, prev) else {
        return Ok(None);
    };
    let Some(identity) = identity else {
        return Err(Error::Corrupt {
            segment: dir.display().to_string(),
            offset: 0,
            reason: "no retained Genesis or SegmentStart states the current chain".into(),
        });
    };
    // Does the bundle continue the cursor?
    let (anchor, gap) = match &cursor {
        Some(c) if c.seq.saturating_add(1) == first_seq => {
            if c.hash != first_prev {
                return Err(Error::Untrusted(format!(
                    "record {first_seq} does not chain onto the export cursor (seq {}): the log \
                     was rewritten after it was exported",
                    c.seq
                )));
            }
            (Some(c.clone()), None)
        }
        Some(c) => (
            None,
            Some([c.seq.saturating_add(1), first_seq.saturating_sub(1)]),
        ),
        None if first_seq > 0 => (None, Some([0, first_seq - 1])),
        None => (None, None),
    };
    Ok(Some(PendingExport {
        bundle: Bundle {
            identity,
            anchor,
            frames,
        },
        first_seq,
        last_seq,
        last_hash,
        records: count as u64,
        gap,
        cursor_rejected,
        more,
    }))
}

/// File name of a bundle in the outbox:
/// `rbbx-<device>-<chain id, 16 hex>-<first seq>-<last seq>.rbbx` (device
/// id characters other than `[A-Za-z0-9._-]` become `_`).
pub fn bundle_file_name(p: &PendingExport) -> String {
    let dev: String = p
        .bundle
        .identity
        .device_id
        .chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() || matches!(c, '.' | '_' | '-') {
                c
            } else {
                '_'
            }
        })
        .collect();
    let chain = to_hex(&p.bundle.identity.chain_id());
    format!(
        "{BUNDLE_PREFIX}{dev}-{}-{:020}-{:020}{BUNDLE_SUFFIX}",
        chain.get(..16).unwrap_or(&chain),
        p.first_seq,
        p.last_seq
    )
}

/// Write the bundle into `out_dir` (temp file, fsync, rename, fsync; mode
/// 0640; never over an existing file or through a symlink). Returns its
/// path.
pub fn write_bundle(out_dir: &Path, p: &PendingExport) -> io::Result<PathBuf> {
    let name = bundle_file_name(p);
    let path = out_dir.join(&name);
    let tmp = out_dir.join(format!(".{name}.tmp"));
    let mut o = OpenOptions::new();
    o.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        o.mode(0o640).custom_flags(crate::store::sys::O_NOFOLLOW);
    }
    // A temp file left by a crashed run of this exporter (the export lock
    // is held) is ours to replace.
    match fs::symlink_metadata(&tmp) {
        Ok(m) if m.is_file() => fs::remove_file(&tmp)?,
        Ok(_) => {
            return Err(io::Error::new(
                io::ErrorKind::AlreadyExists,
                format!("{} exists and is not a file", tmp.display()),
            ))
        }
        Err(_) => {}
    }
    let res = (|| {
        let mut f = o.open(&tmp)?;
        f.write_all(&p.bundle.to_bytes())?;
        f.sync_all()?;
        if fs::symlink_metadata(&path).is_ok() {
            return Err(io::Error::new(
                io::ErrorKind::AlreadyExists,
                format!("{} already exists", path.display()),
            ));
        }
        fs::rename(&tmp, &path)
    })();
    if res.is_err() {
        let _ = fs::remove_file(&tmp);
    }
    res?;
    File::open(out_dir)?.sync_all()?;
    Ok(path)
}

/// Advance the export cursor to the end of `p` (signed with the recorder's
/// current key `signer`; atomic replace; owned like the directory).
pub fn advance_cursor(dir: &Path, signer: &dyn Signer, p: &PendingExport) -> Result<(), Error> {
    let a = Anchor {
        chain_id: p.bundle.identity.chain_id(),
        seq: p.last_seq,
        hash: p.last_hash,
    };
    let sig = signer
        .sign(&cursor_signing_message(&a))
        .map_err(Error::Sign)?;
    let c = SignedCursor { anchor: a, sig };
    atomic_write_owned(dir, CURSOR_FILE, c.to_json().as_bytes())?;
    Ok(())
}

/// One export run: lock, collect, write the bundle, advance the cursor.
/// `None`: nothing pending. The lock is held for the run only. With
/// `device`, a log of another unit is refused before anything is written.
pub fn export_pending_to(
    dir: &Path,
    out_dir: &Path,
    signer: &dyn Signer,
    authentic: Authentic<'_>,
    opts: PendingOptions,
    device: Option<&str>,
) -> Result<Option<(PendingExport, PathBuf)>, Error> {
    let _lock = lock_file(dir.join(EXPORT_LOCK_FILE))?;
    let cursor_key = |m: &[u8], s: &[u8]| signer.verify_own(m, s) == Some(true);
    let Some(p) = collect_pending(dir, &cursor_key, authentic, opts)? else {
        return Ok(None);
    };
    if let Some(dev) = device {
        if p.bundle.identity.device_id != dev {
            return Err(Error::DeviceMismatch {
                log_device_id: p.bundle.identity.device_id.clone(),
                config_device_id: dev.to_string(),
            });
        }
    }
    let path = write_bundle(out_dir, &p)?;
    advance_cursor(dir, signer, &p)?;
    Ok(Some((p, path)))
}
