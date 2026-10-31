//! Backup and restore of a RoboDR unit (`robodr-blackbox backup`, T85),
//! following docs/OPERATIONS.md §14: configuration and keys are backed up
//! and restored; evidence is backed up but never restored into the live
//! directories; monotonic and device-bound state (anti-rollback floors,
//! replay stores, security floor, TPM-bound material, exporter sequence
//! state) is **never restored**, whatever the archive holds, because
//! restoring an older copy is exactly the rollback those files exist to
//! notice.
//!
//! # Archive format (`RBKUP001`)
//!
//! `"RBKUP001"`, then entries `u32_be(header_len) | header JSON | data`.
//! A header is `{"path", "kind": "dir"|"file", "mode", "size", "sha256"}`
//! (`data` = `size` bytes for a file, nothing for a directory); the last
//! entry is `{"kind": "end", "entries": N, "headers_sha256": hex}` (SHA-256
//! of every header before it, length-prefixed as stored). Paths are
//! relative to the backed-up root, `/`-separated, without `.`, `..` or
//! empty components. Symlinks, devices, sockets and FIFOs are never
//! archived. The archive is not encrypted: it holds keys only with
//! `--include-keys`, and such an archive goes through the site's encryption
//! (`age`) to offline media (§14.2).
//!
//! # Restore
//!
//! The whole archive is verified first (framing, every path, every file's
//! SHA-256, the end record); nothing is written unless it all checks. Then
//! each entry is classified by [`classify`]:
//!
//! * **config** (`etc/robodr/**`, `etc/systemd/system/robodr-*.service.d/**`,
//!   `etc/robodr-depot/**`, `etc/robodr-anchor-receiver/**`) and the anchor
//!   receiver's state (`var/lib/robodr-anchor-receiver/**`): restored under
//!   the target root (files replaced atomically; key files 0600, key
//!   directories 0700; set-id bits never restored);
//! * **spool** `ready/` findings (`var/lib/robodr/spool/{agentd,pulsard}/ready/*`):
//!   only with `--spool-ready`, and only into an empty `ready/` (§14.1: only
//!   on a unit that never exported them);
//! * **evidence** (black boxes, fleet journal, archive, outboxes, evidence
//!   exports, gateway events, depot database): never into the live tree;
//!   with `--evidence-to DIR` extracted under `DIR` for the archive host;
//! * **never restored** (§14.1 "no" rows, [`NEVER_RESTORE`]) and anything
//!   unknown: refused and listed with the reason.
//!
//! A target path whose existing components include a symlink, or whose
//! final component exists as something other than a regular file /
//! directory, is refused (a planted link cannot redirect the restore).

use crate::crypto::{sha256, to_hex, Sha256};
use serde::{Deserialize, Serialize};
use std::fs::{self, File, OpenOptions};
use std::io::{self, Read, Write};
use std::path::{Component, Path, PathBuf};

/// Archive magic.
pub const MAGIC: &[u8; 8] = b"RBKUP001";
/// Largest header accepted.
const MAX_HEADER: u32 = 64 * 1024;
/// Longest path accepted.
const MAX_PATH: usize = 4096;
/// Most entries accepted.
const MAX_ENTRIES: u64 = 10_000_000;

/// What `create` takes (relative to the root), in this order: OPERATIONS
/// §14.1 "Back up: yes" rows.
pub const BACKUP_SETS: &[(&str, &str)] = &[
    ("etc/robodr", "configuration, trust files, certificates"),
    ("etc/systemd/system", "robodr-*.service.d drop-ins"),
    ("etc/robodr-depot", "depot configuration and keys"),
    (
        "etc/robodr-anchor-receiver",
        "anchor receiver configuration and keys",
    ),
    ("var/lib/robodr/blackbox", "black-box chains (evidence)"),
    ("var/lib/robodr/fleet/journal", "fleet journal (evidence)"),
    ("var/lib/robodr/archive", "archived evidence"),
    ("var/lib/robodr/export", "outboxes and exporter state"),
    (
        "var/lib/robodr/control-plane/agentd/exports",
        "evidence exports",
    ),
    ("var/lib/robodr/spool/agentd", "findings not yet exported"),
    ("var/lib/robodr/spool/pulsard", "findings not yet exported"),
    (
        "var/lib/robodr/firewall-gw/events.jsonl",
        "gateway events (evidence)",
    ),
    ("var/lib/robodr/depot", "depot database (forensics)"),
    (
        "var/lib/robodr-anchor-receiver",
        "robots' anchored heads, alerts",
    ),
];

/// Never restored (OPERATIONS §14.1 "Restore: no"), with the reason shown.
/// Checked before every other rule.
pub const NEVER_RESTORE: &[(&str, &str)] = &[
    (
        "var/lib/robodr/control-plane/agentd",
        "anti-replay state: an older replay store forgets requests seen since (§14.1)",
    ),
    (
        "var/lib/robodr/executor",
        "executor actions of the moment it was written (§14.1)",
    ),
    (
        "var/lib/robodr/firewall-gw",
        "gateway learned writers: let the gateway learn them again (§14.1)",
    ),
    (
        "var/lib/robodr/profile-state",
        "profile anti-rollback floor: re-install the current signed profile (§5.1)",
    ),
    (
        "var/lib/robodr/profile-state-pulsard",
        "profile anti-rollback floor: re-install the current signed profile (§5.1)",
    ),
    (
        "var/lib/robodr/releases",
        "security floor: a restored copy lowers it (§14.1)",
    ),
    (
        "var/lib/robodr/fleet",
        "enrollment and rotation journals: re-enrol (§8.6)",
    ),
    (
        "var/lib/robodr/deliverd",
        "delivery anti-rollback floors: re-enrol and reanchor (§11.3)",
    ),
    (
        "var/lib/robodr-seal",
        "TPM-sealed material bound to that unit's TPM: re-provision (§12)",
    ),
    (
        "var/lib/robodr/anchor",
        "TPM anchor sidecar and lease: re-provision (§12, §6.4)",
    ),
    (
        "var/lib/robodr/export/spool-export",
        "exporter sequence state: start fresh, accept the gap (§8.3)",
    ),
    (
        "var/lib/robodr/export/kafka-publish",
        "exporter sequence state: start fresh, accept the gap (§8.3)",
    ),
    (
        "var/lib/robodr/export/uplink",
        "exporter sequence state: start fresh, accept the gap (§8.3)",
    ),
    (
        "opt/robodr-delivered",
        "delivered again by the depot (§14.1)",
    ),
];

/// Evidence: backed up, never restored into the live tree (only with
/// `--evidence-to`).
const EVIDENCE: &[&str] = &[
    "var/lib/robodr/blackbox",
    "var/lib/robodr/fleet/journal",
    "var/lib/robodr/archive",
    "var/lib/robodr/export",
    "var/lib/robodr/control-plane/agentd/exports",
    "var/lib/robodr/firewall-gw/events.jsonl",
    "var/lib/robodr/depot",
    "var/lib/robodr/spool",
];

/// What restore does with an entry.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Class {
    /// Restored under the target root.
    Restore,
    /// A `ready/` finding (restored only with `--spool-ready`).
    SpoolReady,
    /// Evidence: only under `--evidence-to`.
    Evidence,
    /// Never restored, with the reason.
    Never(String),
}

fn under(path: &str, prefix: &str) -> bool {
    path == prefix
        || path
            .strip_prefix(prefix)
            .is_some_and(|rest| rest.starts_with('/'))
}

/// Ancestors of a restorable tree (directories only; created as needed).
fn is_ancestor_dir(path: &str) -> bool {
    matches!(
        path,
        "etc" | "etc/systemd" | "etc/systemd/system" | "var" | "var/lib" | "var/lib/robodr"
    )
}

/// The rule for `path` (a validated relative path).
pub fn classify(path: &str) -> Class {
    // Evidence nested under a never-restored tree comes first (it is not
    // state, and it has its own destination).
    // The depot database (depot box) is kept for forensics: restoring it
    // locks the depot unless it is re-anchored (§13.6), so it goes to the
    // archive host like evidence.
    if under(path, "var/lib/robodr/control-plane/agentd/exports")
        || under(path, "var/lib/robodr/fleet/journal")
        || under(path, "var/lib/robodr/firewall-gw/events.jsonl")
        || under(path, "var/lib/robodr/depot")
    {
        return Class::Evidence;
    }
    if let Some((_, why)) = NEVER_RESTORE.iter().find(|(p, _)| under(path, p)) {
        return Class::Never((*why).to_string());
    }
    for set in [
        "var/lib/robodr/spool/agentd",
        "var/lib/robodr/spool/pulsard",
    ] {
        if let Some(rest) = path.strip_prefix(set) {
            let rest = rest.trim_start_matches('/');
            if rest == "ready"
                || rest
                    .strip_prefix("ready/")
                    .is_some_and(|f| !f.contains('/'))
            {
                return Class::SpoolReady;
            }
        }
    }
    if EVIDENCE.iter().any(|p| under(path, p)) {
        return Class::Evidence;
    }
    let systemd_dropin = path
        .strip_prefix("etc/systemd/system/")
        .and_then(|r| r.split('/').next())
        .is_some_and(|d| d.starts_with("robodr-") && d.ends_with(".service.d"));
    if under(path, "etc/robodr")
        || under(path, "etc/robodr-depot")
        || under(path, "etc/robodr-anchor-receiver")
        || under(path, "var/lib/robodr-anchor-receiver")
        || systemd_dropin
    {
        return Class::Restore;
    }
    if is_ancestor_dir(path) {
        return Class::Restore;
    }
    Class::Never("not part of a RoboDR backup (§14.1)".into())
}

/// Is `p` a clean relative archive path?
pub fn valid_path(p: &str) -> bool {
    !p.is_empty()
        && p.len() <= MAX_PATH
        && !p.starts_with('/')
        && !p.chars().any(|c| c.is_control() || c == '\\')
        && p.split('/').all(|c| !c.is_empty() && c != "." && c != "..")
}

#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
struct Header {
    kind: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    path: Option<String>,
    #[serde(default)]
    mode: u32,
    #[serde(default)]
    size: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    sha256: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    entries: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    headers_sha256: Option<String>,
}

/// What [`create`] did.
#[derive(Debug, Default, Clone)]
pub struct CreateReport {
    pub files: u64,
    pub dirs: u64,
    pub bytes: u64,
    /// Paths not archived, with the reason (symlinks, special files,
    /// keys without `--include-keys`).
    pub skipped: Vec<(String, String)>,
}

/// Archive writer.
struct Writer<W: Write> {
    out: W,
    headers: Sha256,
    entries: u64,
}

impl<W: Write> Writer<W> {
    fn header(&mut self, h: &Header) -> io::Result<()> {
        let b = serde_json::to_vec(h).map_err(io::Error::other)?;
        let len = u32::try_from(b.len()).map_err(io::Error::other)?;
        let lp = len.to_be_bytes();
        self.headers.update(&lp);
        self.headers.update(&b);
        self.out.write_all(&lp)?;
        self.out.write_all(&b)?;
        self.entries += 1;
        Ok(())
    }
}

#[cfg(unix)]
fn mode_of(m: &fs::Metadata) -> u32 {
    use std::os::unix::fs::PermissionsExt;
    m.permissions().mode() & 0o7777
}
#[cfg(not(unix))]
fn mode_of(_: &fs::Metadata) -> u32 {
    0o644
}

fn rel(root: &Path, p: &Path) -> Option<String> {
    let r = p.strip_prefix(root).ok()?;
    let mut parts = Vec::new();
    for c in r.components() {
        match c {
            Component::Normal(s) => parts.push(s.to_str()?.to_string()),
            _ => return None,
        }
    }
    Some(parts.join("/"))
}

/// Archive the §14.1 backup sets found under `root` into `out`. Keys
/// (`etc/robodr/keys`) only with `include_keys`.
pub fn create(root: &Path, out: impl Write, include_keys: bool) -> io::Result<CreateReport> {
    let mut w = Writer {
        out,
        headers: Sha256::new(),
        entries: 0,
    };
    w.out.write_all(MAGIC)?;
    let mut rep = CreateReport::default();
    let mut seen_dirs = std::collections::BTreeSet::new();
    for (set, _) in BACKUP_SETS {
        let top = root.join(set);
        let Ok(meta) = fs::symlink_metadata(&top) else {
            continue;
        };
        // Parent directories, so a restore recreates the tree.
        let mut acc = String::new();
        for part in set
            .split('/')
            .take(set.split('/').count().saturating_sub(1))
        {
            if !acc.is_empty() {
                acc.push('/');
            }
            acc.push_str(part);
            if seen_dirs.insert(acc.clone()) {
                let m = fs::symlink_metadata(root.join(&acc))?;
                w.header(&Header {
                    kind: "dir".into(),
                    path: Some(acc.clone()),
                    mode: mode_of(&m),
                    ..Header::default()
                })?;
                rep.dirs += 1;
            }
        }
        let mut stack = vec![(top, meta)];
        while let Some((p, m)) = stack.pop() {
            let Some(r) = rel(root, &p) else {
                rep.skipped
                    .push((p.display().to_string(), "not a UTF-8 path".into()));
                continue;
            };
            if !include_keys && under(&r, "etc/robodr/keys") {
                rep.skipped.push((
                    r,
                    "keys: back them up separately, encrypted (--include-keys)".into(),
                ));
                continue;
            }
            // Only the robodr drop-ins of etc/systemd/system.
            if under(&r, "etc/systemd/system") && r != "etc/systemd/system" {
                let first = r
                    .trim_start_matches("etc/systemd/system/")
                    .split('/')
                    .next()
                    .unwrap_or("");
                if !(first.starts_with("robodr-") && first.ends_with(".service.d")) {
                    continue;
                }
            }
            if m.file_type().is_symlink() {
                rep.skipped.push((r, "symlink (never archived)".into()));
                continue;
            }
            if m.is_dir() {
                if seen_dirs.insert(r.clone()) {
                    w.header(&Header {
                        kind: "dir".into(),
                        path: Some(r),
                        mode: mode_of(&m),
                        ..Header::default()
                    })?;
                    rep.dirs += 1;
                }
                let mut kids: Vec<_> = fs::read_dir(&p)?
                    .map(|e| e.map(|e| e.path()))
                    .collect::<io::Result<_>>()?;
                kids.sort();
                for k in kids.into_iter().rev() {
                    let km = fs::symlink_metadata(&k)?;
                    stack.push((k, km));
                }
            } else if m.is_file() {
                let mut f = open_nofollow(&p)?;
                // Hash first, then copy: a file that changes in between is
                // caught by the size / hash check of the copy.
                let (size, digest) = hash_reader(&mut f)?;
                w.header(&Header {
                    kind: "file".into(),
                    path: Some(r.clone()),
                    mode: mode_of(&m),
                    size,
                    sha256: Some(to_hex(&digest)),
                    ..Header::default()
                })?;
                let mut f = open_nofollow(&p)?;
                let mut h = Sha256::new();
                let copied = copy_hashing(&mut (&mut f).take(size), &mut w.out, &mut h)?;
                if copied != size || h.finalize() != digest {
                    return Err(io::Error::other(format!(
                        "{r} changed while it was archived; stop the services and retry"
                    )));
                }
                rep.files += 1;
                rep.bytes += size;
            } else {
                rep.skipped
                    .push((r, "special file (never archived)".into()));
            }
        }
    }
    let digest = std::mem::take(&mut w.headers).finalize();
    let n = w.entries;
    let end = Header {
        kind: "end".into(),
        entries: Some(n),
        headers_sha256: Some(to_hex(&digest)),
        ..Header::default()
    };
    let b = serde_json::to_vec(&end).map_err(io::Error::other)?;
    let len = u32::try_from(b.len()).map_err(io::Error::other)?;
    w.out.write_all(&len.to_be_bytes())?;
    w.out.write_all(&b)?;
    w.out.flush()?;
    Ok(rep)
}

fn open_nofollow(p: &Path) -> io::Result<File> {
    let mut o = OpenOptions::new();
    o.read(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        o.custom_flags(crate::store::sys::O_NOFOLLOW);
    }
    o.open(p)
}

fn hash_reader(r: &mut impl Read) -> io::Result<(u64, [u8; 32])> {
    let mut h = Sha256::new();
    let n = copy_hashing(r, &mut io::sink(), &mut h)?;
    Ok((n, h.finalize()))
}

fn copy_hashing(r: &mut impl Read, w: &mut impl Write, h: &mut Sha256) -> io::Result<u64> {
    let mut buf = vec![0u8; 64 * 1024];
    let mut n = 0u64;
    loop {
        let k = match r.read(&mut buf) {
            Ok(0) => return Ok(n),
            Ok(k) => k,
            Err(e) if e.kind() == io::ErrorKind::Interrupted => continue,
            Err(e) => return Err(e),
        };
        let chunk = buf.get(..k).unwrap_or_default();
        h.update(chunk);
        w.write_all(chunk)?;
        n += k as u64;
    }
}

/// One archive entry as read.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Entry {
    pub path: String,
    pub dir: bool,
    pub mode: u32,
    pub size: u64,
    pub sha256: [u8; 32],
}

fn bad(m: impl Into<String>) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, m.into())
}

/// Read the archive; `visit` gets each entry and, for a file, a reader of
/// exactly its bytes (it may read none or all of them). Fails on any
/// framing, path or hash error; the end record is checked last.
fn walk(
    r: &mut impl Read,
    visit: &mut dyn FnMut(&Entry, &mut dyn Read) -> io::Result<()>,
) -> io::Result<u64> {
    let mut magic = [0u8; 8];
    r.read_exact(&mut magic)
        .map_err(|_| bad("not a RoboDR backup (too short)"))?;
    if &magic != MAGIC {
        return Err(bad("not a RoboDR backup (bad magic)"));
    }
    let mut headers = Sha256::new();
    let mut count = 0u64;
    let mut seen = std::collections::BTreeSet::new();
    loop {
        let mut lp = [0u8; 4];
        r.read_exact(&mut lp)
            .map_err(|_| bad("truncated archive (no end record)"))?;
        let len = u32::from_be_bytes(lp);
        if len == 0 || len > MAX_HEADER {
            return Err(bad(format!("header length {len} out of range")));
        }
        let mut hb = vec![0u8; len as usize];
        r.read_exact(&mut hb).map_err(|_| bad("truncated header"))?;
        let h: Header = serde_json::from_slice(&hb).map_err(|e| bad(format!("bad header: {e}")))?;
        if h.kind == "end" {
            let want = to_hex(&headers.finalize());
            if h.entries != Some(count) || h.headers_sha256.as_deref() != Some(want.as_str()) {
                return Err(bad(
                    "end record does not match the entries (edited archive?)",
                ));
            }
            let mut extra = [0u8; 1];
            if r.read(&mut extra)? != 0 {
                return Err(bad("bytes after the end record"));
            }
            return Ok(count);
        }
        headers.update(&lp);
        headers.update(&hb);
        count += 1;
        if count > MAX_ENTRIES {
            return Err(bad("too many entries"));
        }
        let path = h.path.clone().unwrap_or_default();
        if !valid_path(&path) {
            return Err(bad(format!("unsafe path {path:?}")));
        }
        if !seen.insert(path.clone()) {
            return Err(bad(format!("duplicate path {path:?}")));
        }
        let dir = match h.kind.as_str() {
            "dir" if h.size == 0 => true,
            "file" => false,
            k => return Err(bad(format!("{path}: unknown kind {k:?}"))),
        };
        let digest = match (&h.sha256, dir) {
            (_, true) => [0u8; 32],
            (Some(s), false) => {
                crate::crypto::hash_from_hex(s).ok_or_else(|| bad(format!("{path}: bad sha256")))?
            }
            (None, false) => return Err(bad(format!("{path}: no sha256"))),
        };
        let e = Entry {
            path,
            dir,
            mode: h.mode & 0o7777,
            size: h.size,
            sha256: digest,
        };
        let mut body = HashingTake {
            inner: (&mut *r).take(e.size),
            h: Sha256::new(),
            n: 0,
        };
        visit(&e, &mut body)?;
        // Whatever the visitor left unread is read (and hashed) here.
        io::copy(&mut body, &mut io::sink())?;
        if body.n != e.size {
            return Err(bad(format!("{}: truncated data", e.path)));
        }
        if !e.dir && body.h.finalize() != e.sha256 {
            return Err(bad(format!("{}: SHA-256 mismatch", e.path)));
        }
    }
}

struct HashingTake<R> {
    inner: R,
    h: Sha256,
    n: u64,
}

impl<R: Read> Read for HashingTake<R> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        let k = self.inner.read(buf)?;
        if let Some(c) = buf.get(..k) {
            self.h.update(c);
        }
        self.n += k as u64;
        Ok(k)
    }
}

/// Verify an archive end to end; returns its entries.
pub fn verify(r: &mut impl Read) -> io::Result<Vec<Entry>> {
    let mut out = Vec::new();
    walk(r, &mut |e, _| {
        out.push(e.clone());
        Ok(())
    })?;
    Ok(out)
}

/// Restore options.
#[derive(Debug, Clone, Default)]
pub struct RestoreOptions {
    /// Restore `ready/` findings of the spools (only into an empty
    /// `ready/`).
    pub spool_ready: bool,
    /// Extract evidence under this directory (never into the live tree).
    pub evidence_to: Option<PathBuf>,
    /// Report only.
    pub dry_run: bool,
}

/// What [`restore`] did (or would do).
#[derive(Debug, Default, Clone)]
pub struct RestoreReport {
    pub restored: Vec<String>,
    pub evidence: Vec<String>,
    /// `(path, reason)` of every entry not written.
    pub refused: Vec<(String, String)>,
}

/// Refuse a target whose existing components (below `base`) are not real
/// directories, or whose final component is a symlink / special file.
fn safe_target(base: &Path, rel_path: &str, dir: bool) -> Result<PathBuf, String> {
    let mut p = base.to_path_buf();
    let parts: Vec<&str> = rel_path.split('/').collect();
    for (i, c) in parts.iter().enumerate() {
        p.push(c);
        let last = i + 1 == parts.len();
        match fs::symlink_metadata(&p) {
            Err(_) => {}
            Ok(m) if m.file_type().is_symlink() => {
                return Err(format!("{} is a symlink", p.display()))
            }
            Ok(m) if !last && !m.is_dir() => {
                return Err(format!("{} is not a directory", p.display()))
            }
            Ok(m) if last && dir && !m.is_dir() => {
                return Err(format!("{} exists and is not a directory", p.display()))
            }
            Ok(m) if last && !dir && !m.is_file() => {
                return Err(format!("{} exists and is not a regular file", p.display()))
            }
            Ok(_) => {}
        }
    }
    Ok(p)
}

fn restored_mode(path: &str, e: &Entry) -> u32 {
    let m = e.mode & 0o777; // never set-id / sticky
    if under(path, "etc/robodr/keys") {
        if e.dir {
            0o700
        } else {
            0o600
        }
    } else if e.dir {
        m | 0o700
    } else {
        m
    }
}

fn write_entry(target: &Path, e: &Entry, mode: u32, data: &mut dyn Read) -> io::Result<()> {
    if e.dir {
        // An existing directory keeps the mode the package gave it
        // (`systemd-tmpfiles --create` after the restore, §14.3 step 2).
        if !target.is_dir() {
            fs::create_dir(target)?;
            set_mode(target, mode)?;
        }
        return Ok(());
    }
    let parent = target
        .parent()
        .ok_or_else(|| bad("restore target without a parent"))?;
    let name = target
        .file_name()
        .and_then(|n| n.to_str())
        .ok_or_else(|| bad("bad file name"))?;
    let tmp = parent.join(format!(
        ".{name}.{}.rbkup-tmp",
        to_hex(
            sha256(target.as_os_str().as_encoded_bytes())
                .get(..6)
                .unwrap_or_default()
        )
    ));
    let _ = fs::remove_file(&tmp);
    let mut o = OpenOptions::new();
    o.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        o.mode(0o600).custom_flags(crate::store::sys::O_NOFOLLOW);
    }
    let res = (|| {
        let mut f = o.open(&tmp)?;
        io::copy(data, &mut f)?;
        f.sync_all()?;
        drop(f);
        set_mode(&tmp, mode)?;
        fs::rename(&tmp, target)
    })();
    if res.is_err() {
        let _ = fs::remove_file(&tmp);
    }
    res
}

#[cfg(unix)]
fn set_mode(p: &Path, mode: u32) -> io::Result<()> {
    use std::os::unix::fs::PermissionsExt;
    fs::set_permissions(p, fs::Permissions::from_mode(mode))
}
#[cfg(not(unix))]
fn set_mode(_: &Path, _: u32) -> io::Result<()> {
    Ok(())
}

/// Restore `archive` (read twice: verified first, then written) under
/// `root` following the module docs.
pub fn restore(archive: &Path, root: &Path, opts: &RestoreOptions) -> io::Result<RestoreReport> {
    // Pass 1: verify everything before writing anything.
    verify(&mut io::BufReader::new(File::open(archive)?))?;
    let mut rep = RestoreReport::default();
    // `ready/` dirs that were non-empty before this restore.
    let mut busy_ready: Vec<String> = Vec::new();
    for s in [
        "var/lib/robodr/spool/agentd/ready",
        "var/lib/robodr/spool/pulsard/ready",
    ] {
        if fs::read_dir(root.join(s)).is_ok_and(|mut d| d.next().is_some()) {
            busy_ready.push(s.to_string());
        }
    }
    let mut r = io::BufReader::new(File::open(archive)?);
    walk(&mut r, &mut |e, data| {
        let (base, kind) = match classify(&e.path) {
            Class::Restore => (root.to_path_buf(), "restore"),
            Class::SpoolReady if !opts.spool_ready => {
                rep.refused.push((
                    e.path.clone(),
                    "unexported finding: restored only with --spool-ready (§14.1)".into(),
                ));
                return Ok(());
            }
            Class::SpoolReady => {
                if busy_ready.iter().any(|b| under(&e.path, b)) {
                    rep.refused.push((
                        e.path.clone(),
                        "the unit's ready/ is not empty: it has findings of its own (§14.1)".into(),
                    ));
                    return Ok(());
                }
                (root.to_path_buf(), "restore")
            }
            Class::Evidence => match &opts.evidence_to {
                Some(d) => (d.clone(), "evidence"),
                None => {
                    rep.refused.push((
                        e.path.clone(),
                        "evidence: never restored into the unit; use --evidence-to DIR for \
                         the archive host (§14.1)"
                            .into(),
                    ));
                    return Ok(());
                }
            },
            Class::Never(why) => {
                rep.refused.push((e.path.clone(), why));
                return Ok(());
            }
        };
        let target = match safe_target(&base, &e.path, e.dir) {
            Ok(t) => t,
            Err(why) => {
                rep.refused.push((e.path.clone(), why));
                return Ok(());
            }
        };
        if !opts.dry_run {
            // Evidence goes to a fresh tree: its parents are made as
            // needed (some are never-restored state directories).
            if kind == "evidence" {
                if let Some(p) = target.parent() {
                    fs::create_dir_all(p)?;
                }
            }
            // Directories come before their contents in the archive; a
            // missing parent (a refused directory) refuses the entry.
            if target.parent().is_some_and(|p| !p.is_dir()) {
                rep.refused
                    .push((e.path.clone(), "parent directory not restored".into()));
                return Ok(());
            }
            write_entry(&target, e, restored_mode(&e.path, e), data)?;
        }
        if kind == "evidence" {
            rep.evidence.push(e.path.clone());
        } else {
            rep.restored.push(e.path.clone());
        }
        Ok(())
    })?;
    Ok(rep)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn paths_are_strictly_relative() {
        for ok in [
            "etc/robodr/agentd.json",
            "var/lib/robodr/spool/agentd/ready/1.json",
        ] {
            assert!(valid_path(ok), "{ok}");
        }
        for bad in [
            "",
            "/etc/passwd",
            "../etc",
            "etc/../../x",
            "etc//x",
            "etc/./x",
            "etc/x\n",
            "a\\b",
        ] {
            assert!(!valid_path(bad), "{bad:?}");
        }
    }

    #[test]
    fn classification_follows_operations_14_1() {
        use Class::*;
        assert_eq!(classify("etc/robodr/agentd.json"), Restore);
        assert_eq!(classify("etc/robodr/keys/agentd-blackbox.key"), Restore);
        assert_eq!(
            classify("etc/systemd/system/robodr-agentd.service.d/20-x.conf"),
            Restore
        );
        assert!(matches!(
            classify("etc/systemd/system/sshd.service.d/x.conf"),
            Never(_)
        ));
        assert!(matches!(classify("etc/passwd"), Never(_)));
        assert_eq!(
            classify("var/lib/robodr/blackbox/agentd/seg-0.rbb"),
            Evidence
        );
        assert_eq!(classify("var/lib/robodr/fleet/journal/j.json"), Evidence);
        assert_eq!(
            classify("var/lib/robodr/control-plane/agentd/exports/x/bundle.rbbx"),
            Evidence
        );
        assert_eq!(
            classify("var/lib/robodr/firewall-gw/events.jsonl"),
            Evidence
        );
        assert_eq!(
            classify("var/lib/robodr/spool/agentd/ready/1.json"),
            SpoolReady
        );
        assert_eq!(
            classify("var/lib/robodr/spool/agentd/acked/1.json"),
            Evidence
        );
        for never in [
            "var/lib/robodr/control-plane/agentd/replay.json",
            "var/lib/robodr/executor/journal.json",
            "var/lib/robodr/firewall-gw/writers.json",
            "var/lib/robodr/profile-state/state.json",
            "var/lib/robodr/releases/security-floor",
            "var/lib/robodr/fleet/enrollment.json",
            "var/lib/robodr/deliverd/store.json",
            "var/lib/robodr-seal/blob",
            "var/lib/robodr/anchor/sidecar.json",
            "var/lib/robodr/export/spool-export/state.json",
            "var/lib/robodr/export/uplink/state.json",
        ] {
            assert!(matches!(classify(never), Never(_)), "{never}");
        }
        assert_eq!(classify("var/lib/robodr/export/diode/b.rbdiode"), Evidence);
        assert_eq!(classify("var/lib/robodr/depot/depot.db"), Evidence);
    }
}
