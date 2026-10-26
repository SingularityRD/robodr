//! Bundle: one transfer across the air gap (`robodr-bundle/1`,
//! `docs/SECURE-DELIVERY.md` §3.3).
//!
//! ```text
//! <bundle dir>/
//!   bundle.json                 canonical JSON, signed by the release quorum
//!   bundle.sig                  robodr-sigset/1
//!   rpk_<name>_<serial>_<arch>/ one per RPK (crate::rpk)
//!   parity/g0001-p01.rbpar ...  optional Reed-Solomon parity (crate::parity)
//! ```
//!
//! `bundle.json` lists every RPK (by digest) and **every file** of the
//! tree with its size and SHA-256 (a signed `SHA256SUMS`), so a verifier
//! refuses a missing, extra, swapped or truncated file before it parses
//! anything inside it. File paths follow a fixed grammar (no free-form
//! names: no traversal is expressible). `bundle_seq` and
//! `prev_bundle_hash` chain the bundles of one programme; [`check_chain`]
//! refuses a gap, a replay, an equivocation and a broken link.
//!
//! * signed message: `"robodr-bundle/manifest/v1\0" || bundle.json bytes`
//! * bundle hash: `SHA-256("robodr-bundle/hash/v1\0" || bundle.json bytes)`

use crate::common::{
    domain_hash, invalid, is_hex64, is_label, parse_canonical, strictly_sorted, to_canonical, Code,
    Refusal,
};
use crate::parity::{self, PARITY_DIR};
use crate::rpk::{self, Arch, Manifest, CHUNKS_DIR, CHUNK_SIZE, MANIFEST_FILE, SIGNATURE_FILE};
use crate::sig::{Role, SignatureSet, Signers, MAX_SIGSET_BYTES};
use crate::trust::VerifiedTrust;
use crate::MAX_SAFE_INTEGER;
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};

/// `format` of a bundle manifest.
pub const BUNDLE_FORMAT: &str = "robodr-bundle/1";
/// File names at the bundle root.
pub const BUNDLE_FILE: &str = "bundle.json";
pub const BUNDLE_SIG_FILE: &str = "bundle.sig";
/// Domain of the bundle signatures.
pub const BUNDLE_SIG_DOMAIN: &[u8] = b"robodr-bundle/manifest/v1\0";
/// Domain of the bundle hash (the chain link).
pub const BUNDLE_HASH_DOMAIN: &[u8] = b"robodr-bundle/hash/v1\0";
/// Largest `bundle.json` read.
pub const MAX_BUNDLE_BYTES: usize = 32 * 1024 * 1024;
/// Most RPKs in one bundle.
pub const MAX_RPKS: usize = 256;
/// Most files in one bundle.
pub const MAX_FILES: usize = 131_072;
/// `format` of a chain state file.
pub const CHAIN_FORMAT: &str = "robodr-bundle-chain/1";

/// One RPK of the bundle.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BundleRpk {
    /// `rpk_<name>_<serial>_<arch>`.
    pub dir: String,
    pub name: String,
    pub serial: u64,
    pub arch: Arch,
    /// [`rpk::rpk_digest`] of its `MANIFEST.json`.
    pub digest: String,
}

/// One file of the bundle tree (not `bundle.json` / `bundle.sig`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BundleFile {
    pub path: String,
    pub size: u64,
    pub sha256: String,
}

/// Reed-Solomon parity parameters (see [`crate::parity`]).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BundleParity {
    /// `rs-gf256-0x11d/1` (robodr-diode's code).
    pub scheme: String,
    /// `k`: data files per group (the last group may have fewer).
    pub data_shards: u32,
    /// `m`: parity files per group.
    pub parity_shards: u32,
    /// Stripe height in bytes.
    pub shard_size: u64,
    /// Number of groups.
    pub groups: u32,
}

/// The bundle manifest (members in canonical order).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BundleManifest {
    pub format: String,
    /// Per-programme chain (§3.3).
    pub programme: String,
    /// 1-based, +1 per bundle of the programme.
    pub bundle_seq: u64,
    /// [`bundle_hash`] of bundle `bundle_seq - 1`; `null` iff `bundle_seq == 1`.
    pub prev_bundle_hash: Option<String>,
    /// Unix seconds, informational.
    pub created_at: u64,
    /// Sorted by `dir`.
    pub rpks: Vec<BundleRpk>,
    /// Sorted by `path` (bytewise).
    pub files: Vec<BundleFile>,
    pub parity: Option<BundleParity>,
}

/// Hash of `bundle.json` bytes (the chain link).
pub fn bundle_hash(bytes: &[u8]) -> String {
    domain_hash(BUNDLE_HASH_DOMAIN, bytes)
}

/// What a bundle path is.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PathKind {
    Manifest { dir: String },
    Signature { dir: String },
    Chunk { dir: String, sha256: String },
    Parity { group: u32, index: u32 },
}

/// Classify a path by the fixed grammar; `None` for anything else.
pub fn classify(path: &str) -> Option<PathKind> {
    if let Some(rest) = path
        .strip_prefix(PARITY_DIR)
        .and_then(|r| r.strip_prefix('/'))
    {
        return parity::parse_parity_name(rest)
            .map(|(group, index)| PathKind::Parity { group, index });
    }
    let (dir, rest) = path.split_once('/')?;
    if !is_rpk_dir(dir) {
        return None;
    }
    let dir = dir.to_string();
    match rest {
        MANIFEST_FILE => Some(PathKind::Manifest { dir }),
        SIGNATURE_FILE => Some(PathKind::Signature { dir }),
        _ => {
            let h = rest.strip_prefix(CHUNKS_DIR)?.strip_prefix('/')?;
            is_hex64(h).then(|| PathKind::Chunk {
                dir,
                sha256: h.to_string(),
            })
        }
    }
}

/// `rpk_<pkg name>_<serial>_<arch>` with a canonical decimal serial.
pub fn is_rpk_dir(s: &str) -> bool {
    let Some(rest) = s.strip_prefix("rpk_") else {
        return false;
    };
    let parts: Vec<&str> = rest.split('_').collect();
    let [name, serial, arch] = parts.as_slice() else {
        return false;
    };
    let arch_ok = matches!(*arch, "amd64" | "arm64" | "all");
    let serial_ok = !serial.is_empty()
        && serial.len() <= 16
        && serial.bytes().all(|b| b.is_ascii_digit())
        && !serial.starts_with('0');
    crate::common::is_pkg_name(name) && serial_ok && arch_ok
}

impl BundleManifest {
    /// Structural rules (see the module docs); no file is read.
    pub fn validate(&self) -> Result<(), Refusal> {
        if self.format != BUNDLE_FORMAT {
            return Err(invalid("bundle: unsupported format"));
        }
        if !is_label(&self.programme) {
            return Err(invalid("bundle: bad programme label"));
        }
        if self.bundle_seq == 0 || self.bundle_seq > MAX_SAFE_INTEGER {
            return Err(invalid("bundle: bundle_seq must be 1..=2^53-1"));
        }
        match (&self.prev_bundle_hash, self.bundle_seq) {
            (None, 1) => {}
            (Some(h), s) if s > 1 && is_hex64(h) => {}
            (None, _) => {
                return Err(invalid(
                    "bundle: prev_bundle_hash missing for bundle_seq > 1",
                ))
            }
            (Some(_), 1) => return Err(invalid("bundle: prev_bundle_hash on bundle_seq 1")),
            (Some(_), _) => return Err(invalid("bundle: prev_bundle_hash is not a hex SHA-256")),
        }
        if self.created_at > MAX_SAFE_INTEGER {
            return Err(invalid("bundle: created_at out of range"));
        }
        if self.rpks.is_empty() || self.rpks.len() > MAX_RPKS {
            return Err(invalid(format!("bundle: 1..={MAX_RPKS} RPKs")));
        }
        strictly_sorted(&self.rpks, |r| r.dir.clone(), "rpks (by dir)")?;
        let mut names = BTreeSet::new();
        let mut digests = BTreeSet::new();
        for r in &self.rpks {
            if !crate::common::is_pkg_name(&r.name)
                || r.serial == 0
                || r.serial > MAX_SAFE_INTEGER
                || !is_hex64(&r.digest)
            {
                return Err(invalid("bundle: bad rpk entry"));
            }
            if r.dir != rpk::dir_name(&r.name, r.serial, r.arch) {
                return Err(invalid(format!(
                    "bundle: rpk dir {} does not match its entry",
                    r.dir
                )));
            }
            if !names.insert((r.name.clone(), r.arch)) {
                return Err(invalid(format!(
                    "bundle: two serials of {} {} in one bundle",
                    r.name,
                    r.arch.as_str()
                )));
            }
            if !digests.insert(r.digest.clone()) {
                return Err(invalid("bundle: the same RPK twice"));
            }
        }
        if self.files.is_empty() || self.files.len() > MAX_FILES {
            return Err(invalid(format!("bundle: 1..={MAX_FILES} files")));
        }
        strictly_sorted(&self.files, |f| f.path.clone(), "files (by path)")?;
        let dirs: BTreeSet<&str> = self.rpks.iter().map(|r| r.dir.as_str()).collect();
        let mut has_manifest = BTreeSet::new();
        let mut has_sig = BTreeSet::new();
        for f in &self.files {
            if !is_hex64(&f.sha256) {
                return Err(invalid("bundle: bad file sha256"));
            }
            let kind = classify(&f.path).ok_or_else(|| {
                invalid(format!(
                    "bundle: path {:?} is not a bundle path",
                    crate::common::trunc(&f.path)
                ))
            })?;
            let dir_listed = |d: &str| {
                if dirs.contains(d) {
                    Ok(())
                } else {
                    Err(invalid(format!(
                        "bundle: {} is under no listed RPK",
                        f.path
                    )))
                }
            };
            match &kind {
                PathKind::Manifest { dir } => {
                    dir_listed(dir)?;
                    if f.size == 0 || f.size > rpk::MAX_MANIFEST_BYTES as u64 {
                        return Err(invalid("bundle: manifest size out of range"));
                    }
                    has_manifest.insert(dir.clone());
                }
                PathKind::Signature { dir } => {
                    dir_listed(dir)?;
                    if f.size == 0 || f.size > MAX_SIGSET_BYTES as u64 {
                        return Err(invalid("bundle: signature file size out of range"));
                    }
                    has_sig.insert(dir.clone());
                }
                PathKind::Chunk { dir, sha256 } => {
                    dir_listed(dir)?;
                    if *sha256 != f.sha256 || f.size == 0 || f.size > CHUNK_SIZE {
                        return Err(invalid(format!(
                            "bundle: chunk {} has another hash or a bad size",
                            f.path
                        )));
                    }
                }
                PathKind::Parity { .. } => {
                    if self.parity.is_none() {
                        return Err(invalid("bundle: parity files without a parity section"));
                    }
                }
            }
        }
        if has_manifest.len() != dirs.len() || has_sig.len() != dirs.len() {
            return Err(invalid(
                "bundle: every RPK needs its MANIFEST.json and MANIFEST.sig listed",
            ));
        }
        if self.parity.is_some() {
            parity::plan(self)?;
        }
        Ok(())
    }

    /// Index of the entry for `path`.
    pub fn file(&self, path: &str) -> Option<&BundleFile> {
        self.files
            .binary_search_by(|f| f.path.as_str().cmp(path))
            .ok()
            .map(|i| &self.files[i])
    }

    /// Files of one RPK directory, by path relative to it.
    pub fn files_under(&self, dir: &str) -> BTreeMap<&str, &BundleFile> {
        self.files
            .iter()
            .filter_map(|f| {
                f.path
                    .strip_prefix(dir)
                    .and_then(|r| r.strip_prefix('/'))
                    .map(|r| (r, f))
            })
            .collect()
    }

    /// Canonical bytes.
    pub fn to_bytes(&self) -> Result<Vec<u8>, Refusal> {
        to_canonical(self)
    }
}

/// Parse and validate `bundle.json` bytes (no signature check).
pub fn parse_bundle(bytes: &[u8]) -> Result<BundleManifest, Refusal> {
    let b: BundleManifest = parse_canonical(bytes, MAX_BUNDLE_BYTES, "bundle.json")?;
    b.validate()?;
    Ok(b)
}

/// A bundle manifest signed by the release quorum, for a programme the
/// site accepts.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerifiedBundle {
    pub manifest: BundleManifest,
    pub hash: String,
    pub signers: Signers,
}

/// Parse, validate, check the programme and the release quorum.
pub fn verify_bundle_manifest(
    bytes: &[u8],
    sigset: &[u8],
    trust: &VerifiedTrust,
) -> Result<VerifiedBundle, Refusal> {
    let manifest = parse_bundle(bytes)?;
    if !trust.accepts_programme(&manifest.programme) {
        return Err(Refusal::new(
            Code::WrongScope,
            format!(
                "bundle: programme {} is not accepted at this site",
                manifest.programme
            ),
        ));
    }
    let set = SignatureSet::parse(sigset)?;
    let signers = set.check(trust, &[Role::Release], BUNDLE_SIG_DOMAIN, bytes)?;
    signers.require(
        Role::Release,
        trust.file().quorum.release as usize,
        "bundle",
    )?;
    Ok(VerifiedBundle {
        manifest,
        hash: bundle_hash(bytes),
        signers,
    })
}

/// Cross-check one listed RPK against its parsed manifest: same name,
/// serial and arch, and exactly `MANIFEST.json`, `MANIFEST.sig` and its
/// chunk files (with the manifest's sizes) under its directory.
pub fn check_rpk_files(b: &BundleManifest, entry: &BundleRpk, m: &Manifest) -> Result<(), Refusal> {
    if m.name != entry.name || m.version.serial != entry.serial || m.arch != entry.arch {
        return Err(Refusal::new(
            Code::DigestMismatch,
            format!("bundle: {} holds another package", entry.dir),
        ));
    }
    let listed = b.files_under(&entry.dir);
    let mut want: BTreeMap<String, Option<u64>> = BTreeMap::new();
    want.insert(MANIFEST_FILE.into(), None);
    want.insert(SIGNATURE_FILE.into(), None);
    for c in &m.chunks {
        want.insert(format!("{CHUNKS_DIR}/{}", c.sha256), Some(c.size));
    }
    for (p, f) in &listed {
        match want.get(*p) {
            None => {
                return Err(Refusal::new(
                    Code::UnexpectedFile,
                    format!("bundle: {} is not part of its RPK", f.path),
                ))
            }
            Some(Some(size)) if *size != f.size => {
                return Err(Refusal::new(
                    Code::FileMismatch,
                    format!("bundle: {} size differs from the RPK manifest", f.path),
                ))
            }
            _ => {}
        }
    }
    if let Some(p) = want.keys().find(|p| !listed.contains_key(p.as_str())) {
        return Err(Refusal::new(
            Code::MissingFile,
            format!("bundle: {}/{p} is not listed", entry.dir),
        ));
    }
    Ok(())
}

/// The accepted head of a programme's bundle chain.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ChainState {
    pub format: String,
    pub programme: String,
    pub bundle_seq: u64,
    pub bundle_hash: String,
}

impl ChainState {
    /// The head after accepting `b`.
    pub fn after(b: &VerifiedBundle) -> Self {
        Self {
            format: CHAIN_FORMAT.into(),
            programme: b.manifest.programme.clone(),
            bundle_seq: b.manifest.bundle_seq,
            bundle_hash: b.hash.clone(),
        }
    }

    /// Parse a state file strictly.
    pub fn parse(bytes: &[u8]) -> Result<Self, Refusal> {
        let s: Self = parse_canonical(bytes, 4096, "chain state")?;
        if s.format != CHAIN_FORMAT
            || !is_label(&s.programme)
            || s.bundle_seq == 0
            || s.bundle_seq > MAX_SAFE_INTEGER
            || !is_hex64(&s.bundle_hash)
        {
            return Err(invalid("chain state: bad value"));
        }
        Ok(s)
    }

    pub fn to_bytes(&self) -> Result<Vec<u8>, Refusal> {
        to_canonical(self)
    }
}

/// Where a verifier joins a chain.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ChainAnchor {
    /// No bundle of the programme was accepted yet: only `bundle_seq` 1.
    Genesis,
    /// The accepted head.
    Head(ChainState),
}

/// Outcome of a chain check.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ChainStep {
    /// The next bundle: accept and advance the head.
    Next,
    /// Exactly the accepted head again (same bytes): nothing to do.
    AlreadyAccepted,
}

/// Check `b` against the accepted chain (§3.3: a gap is reported, never
/// silently skipped).
pub fn check_chain(anchor: &ChainAnchor, b: &VerifiedBundle) -> Result<ChainStep, Refusal> {
    let m = &b.manifest;
    let head = match anchor {
        ChainAnchor::Genesis => {
            return if m.bundle_seq == 1 {
                Ok(ChainStep::Next)
            } else {
                Err(Refusal::new(
                    Code::ChainGap,
                    format!(
                        "bundle {} of {}: no earlier bundle accepted (expected 1)",
                        m.bundle_seq, m.programme
                    ),
                ))
            };
        }
        ChainAnchor::Head(h) => h,
    };
    if head.programme != m.programme {
        return Err(Refusal::new(
            Code::WrongScope,
            format!(
                "bundle of {} checked against the chain of {}",
                m.programme, head.programme
            ),
        ));
    }
    let seq = m.bundle_seq;
    if seq == head.bundle_seq {
        return if b.hash == head.bundle_hash {
            Ok(ChainStep::AlreadyAccepted)
        } else {
            Err(Refusal::new(
                Code::Equivocation,
                format!("bundle {seq}: other content than the accepted bundle {seq}"),
            ))
        };
    }
    if seq < head.bundle_seq {
        return Err(Refusal::new(
            Code::Replay,
            format!(
                "bundle {seq} is older than the accepted {}",
                head.bundle_seq
            ),
        ));
    }
    if seq > head.bundle_seq.saturating_add(1) {
        return Err(Refusal::new(
            Code::ChainGap,
            format!(
                "bundle {seq} after {}: bundles {}..={} are missing",
                head.bundle_seq,
                head.bundle_seq + 1,
                seq - 1
            ),
        ));
    }
    if m.prev_bundle_hash.as_deref() != Some(head.bundle_hash.as_str()) {
        return Err(Refusal::new(
            Code::ChainBroken,
            format!(
                "bundle {seq}: prev_bundle_hash is not the accepted bundle {}",
                head.bundle_seq
            ),
        ));
    }
    Ok(ChainStep::Next)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::common::sha256_hex;
    use crate::rpk::test_support::manifest;

    pub(crate) fn bundle_for(m: &Manifest, mbytes: &[u8]) -> BundleManifest {
        let dir = m.dir_name();
        let mut files = vec![
            BundleFile {
                path: format!("{dir}/{MANIFEST_FILE}"),
                size: mbytes.len() as u64,
                sha256: sha256_hex(mbytes),
            },
            BundleFile {
                path: format!("{dir}/{SIGNATURE_FILE}"),
                size: 100,
                sha256: "ab".repeat(32),
            },
        ];
        for c in &m.chunks {
            files.push(BundleFile {
                path: format!("{dir}/{CHUNKS_DIR}/{}", c.sha256),
                size: c.size,
                sha256: c.sha256.clone(),
            });
        }
        files.sort_by(|a, b| a.path.cmp(&b.path));
        BundleManifest {
            format: BUNDLE_FORMAT.into(),
            programme: "ugv-x1".into(),
            bundle_seq: 1,
            prev_bundle_hash: None,
            created_at: 1_790_000_000,
            rpks: vec![BundleRpk {
                dir,
                name: m.name.clone(),
                serial: m.version.serial,
                arch: m.arch,
                digest: rpk::rpk_digest(mbytes),
            }],
            files,
            parity: None,
        }
    }

    fn chunk_ix(b: &BundleManifest) -> usize {
        b.files
            .iter()
            .position(|f| f.path.contains("/chunks/"))
            .unwrap()
    }

    fn fixture() -> (Manifest, BundleManifest) {
        let m = manifest(&[("a", b"alpha"), ("b", b"beta")]);
        let mb = to_canonical(&m).unwrap();
        let b = bundle_for(&m, &mb);
        (m, b)
    }

    #[test]
    fn grammar() {
        assert!(is_rpk_dir("rpk_nav-stack_7_arm64"));
        for bad in [
            "rpk_nav_07_arm64",
            "rpk_nav_7_x86",
            "rpk_nav_7",
            "rpk__7_all",
            "rpk_a_b_7_all",
            "rpk_nav_0_all",
            "nav_7_all",
            "rpk_Nav_7_all",
            "rpk_nav_99999999999999999_all",
        ] {
            assert!(!is_rpk_dir(bad), "{bad}");
        }
        let h = "ab".repeat(32);
        assert!(matches!(
            classify(&format!("rpk_a_1_all/chunks/{h}")),
            Some(PathKind::Chunk { .. })
        ));
        for bad in [
            format!("rpk_a_1_all/chunks/{h}/x"),
            format!("rpk_a_1_all/../chunks/{h}"),
            "rpk_a_1_all/chunks/../../etc/passwd".to_string(),
            "/rpk_a_1_all/MANIFEST.json".to_string(),
            "rpk_a_1_all/manifest.json".to_string(),
            "rpk_a_1_all/x".to_string(),
            "bundle.json".to_string(),
            "parity/../x".to_string(),
            "parity/g0000-p01.rbpar".to_string(),
            format!("rpk_a_1_all/chunks/{}", h.to_uppercase()),
        ] {
            assert!(classify(&bad).is_none(), "{bad}");
        }
    }

    #[test]
    fn structural_rules() {
        let (m, b) = fixture();
        b.validate().unwrap();
        check_rpk_files(&b, &b.rpks[0], &m).unwrap();
        type Mutation = Box<dyn Fn(&mut BundleManifest)>;
        let cases: Vec<(&str, Mutation)> = vec![
            ("format", Box::new(|b| b.format = "x".into())),
            ("programme", Box::new(|b| b.programme = "X".into())),
            ("seq 0", Box::new(|b| b.bundle_seq = 0)),
            ("seq 2 no prev", Box::new(|b| b.bundle_seq = 2)),
            (
                "prev on 1",
                Box::new(|b| b.prev_bundle_hash = Some("ab".repeat(32))),
            ),
            ("no rpks", Box::new(|b| b.rpks.clear())),
            ("dir mismatch", Box::new(|b| b.rpks[0].serial = 8)),
            (
                "dup rpk",
                Box::new(|b| {
                    let mut r = b.rpks[0].clone();
                    r.serial = 8;
                    r.dir = rpk::dir_name(&r.name, 8, r.arch);
                    r.digest = "cd".repeat(32);
                    b.rpks.push(r);
                }),
            ),
            ("files unsorted", Box::new(|b| b.files.swap(0, 1))),
            (
                "dup file",
                Box::new(|b| {
                    let f = b.files[0].clone();
                    b.files.insert(0, f);
                }),
            ),
            ("traversal", Box::new(|b| b.files[0].path = "../x".into())),
            (
                "unknown dir",
                Box::new(|b| {
                    for f in &mut b.files {
                        f.path = f.path.replace("rpk_nav-stack_7_arm64", "rpk_other_1_all");
                    }
                }),
            ),
            (
                "chunk hash",
                Box::new(|b| {
                    let i = chunk_ix(b);
                    b.files[i].sha256 = "cd".repeat(32);
                }),
            ),
            (
                "no sig listed",
                Box::new(|b| b.files.retain(|f| !f.path.ends_with(SIGNATURE_FILE))),
            ),
            (
                "parity file w/o section",
                Box::new(|b| {
                    b.files.push(BundleFile {
                        path: "parity/g0001-p01.rbpar".into(),
                        size: 1,
                        sha256: "ab".repeat(32),
                    })
                }),
            ),
            (
                "huge chunk",
                Box::new(|b| {
                    let i = chunk_ix(b);
                    b.files[i].size = CHUNK_SIZE + 1;
                }),
            ),
            (
                "huge manifest",
                Box::new(|b| b.files[0].size = rpk::MAX_MANIFEST_BYTES as u64 + 1),
            ),
            (
                "empty chunk",
                Box::new(|b| {
                    let i = chunk_ix(b);
                    b.files[i].size = 0;
                }),
            ),
        ];
        for (name, f) in cases {
            let mut x = b.clone();
            f(&mut x);
            x.files.sort_by(|a, b| a.path.cmp(&b.path));
            if name == "files unsorted" || name == "dup file" {
                let mut y = b.clone();
                f(&mut y);
                assert!(y.validate().is_err(), "{name} accepted");
                continue;
            }
            assert!(x.validate().is_err(), "{name} accepted");
        }
        // Cross-check: an extra or a missing chunk file under the dir.
        let mut extra = b.clone();
        extra.files.push(BundleFile {
            path: format!("{}/chunks/{}", b.rpks[0].dir, "ee".repeat(32)),
            size: 3,
            sha256: "ee".repeat(32),
        });
        extra.files.sort_by(|a, b| a.path.cmp(&b.path));
        extra.validate().unwrap();
        assert_eq!(
            check_rpk_files(&extra, &extra.rpks[0], &m)
                .unwrap_err()
                .code,
            Code::UnexpectedFile
        );
        let mut missing = b.clone();
        missing.files.retain(|f| !f.path.contains("/chunks/"));
        missing.validate().unwrap();
        assert_eq!(
            check_rpk_files(&missing, &missing.rpks[0], &m)
                .unwrap_err()
                .code,
            Code::MissingFile
        );
        let mut other = m.clone();
        other.version.serial = 9;
        other.security_floor = 1;
        assert_eq!(
            check_rpk_files(&b, &b.rpks[0], &other).unwrap_err().code,
            Code::DigestMismatch
        );
    }

    fn vb(seq: u64, prev: Option<String>, salt: u64) -> VerifiedBundle {
        let (_, mut b) = fixture();
        b.bundle_seq = seq;
        b.prev_bundle_hash = prev;
        b.created_at += salt;
        let bytes = b.to_bytes().unwrap();
        VerifiedBundle {
            hash: bundle_hash(&bytes),
            manifest: b,
            signers: Signers::default(),
        }
    }

    #[test]
    fn chain_rules() {
        let b1 = vb(1, None, 0);
        assert_eq!(
            check_chain(&ChainAnchor::Genesis, &b1).unwrap(),
            ChainStep::Next
        );
        let h1 = ChainAnchor::Head(ChainState::after(&b1));
        assert_eq!(check_chain(&h1, &b1).unwrap(), ChainStep::AlreadyAccepted);
        let b2 = vb(2, Some(b1.hash.clone()), 0);
        assert_eq!(check_chain(&h1, &b2).unwrap(), ChainStep::Next);
        // Gap: 3 after 1.
        let b3 = vb(3, Some(b2.hash.clone()), 0);
        assert_eq!(check_chain(&h1, &b3).unwrap_err().code, Code::ChainGap);
        assert_eq!(
            check_chain(&ChainAnchor::Genesis, &b2).unwrap_err().code,
            Code::ChainGap
        );
        // Replay of 1 after 2; equivocation on 2; broken link.
        let h2 = ChainAnchor::Head(ChainState::after(&b2));
        assert_eq!(check_chain(&h2, &b1).unwrap_err().code, Code::Replay);
        let b2x = vb(2, Some(b1.hash.clone()), 5);
        assert_eq!(check_chain(&h2, &b2x).unwrap_err().code, Code::Equivocation);
        let b3x = vb(3, Some("cd".repeat(32)), 0);
        assert_eq!(check_chain(&h2, &b3x).unwrap_err().code, Code::ChainBroken);
        assert_eq!(check_chain(&h2, &b3).unwrap(), ChainStep::Next);
        // Another programme.
        let mut other = ChainState::after(&b2);
        other.programme = "other".into();
        assert_eq!(
            check_chain(&ChainAnchor::Head(other), &b3)
                .unwrap_err()
                .code,
            Code::WrongScope
        );
        // State file round trip.
        let s = ChainState::after(&b2);
        assert_eq!(ChainState::parse(&s.to_bytes().unwrap()).unwrap(), s);
        assert!(ChainState::parse(b"{}").is_err());
    }
}
