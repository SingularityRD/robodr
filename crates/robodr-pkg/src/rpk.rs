//! RPK: one deliverable (`robodr-pkg/1`, `docs/SECURE-DELIVERY.md` §3.1).
//!
//! ```text
//! rpk_<name>_<serial>_<arch>/
//!   MANIFEST.json      canonical JSON; its raw bytes are signed and hashed
//!   MANIFEST.sig       robodr-sigset/1, release quorum (crate::sig)
//!   chunks/<sha256>    payload chunks (plain in 13a; sealed is 13c)
//! ```
//!
//! * signed message: `"robodr-pkg/manifest/v1\0" || MANIFEST.json bytes`
//! * RPK digest: `SHA-256("robodr-pkg/digest/v1\0" || MANIFEST.json bytes)`
//!   ([`rpk_digest`]), the RPK's identity everywhere else.
//!
//! Chunking is per file: each content file is cut into [`CHUNK_SIZE`]
//! pieces, the last one short; an empty file has no chunk. `chunks[]`
//! lists each distinct chunk once (sorted by hash, so identical pieces are
//! stored once); a content file names its pieces by index into it.
//!
//! Every value rule is in [`Manifest::validate`]; the decisions where §3.1
//! left room are recorded in §3.5 of the design.

use crate::common::{
    domain_hash, invalid, is_hex64, is_label, is_pkg_name, is_safe_rel_path, is_version_display,
    parse_canonical, sha256_hex, strictly_sorted, Code, Refusal,
};
use crate::sig::{Role, SignatureSet, Signers};
use crate::trust::VerifiedTrust;
use crate::MAX_SAFE_INTEGER;
use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;

/// `format` of an RPK manifest.
pub const RPK_FORMAT: &str = "robodr-pkg/1";
/// Manifest file name inside an RPK directory.
pub const MANIFEST_FILE: &str = "MANIFEST.json";
/// Signature file name inside an RPK directory.
pub const SIGNATURE_FILE: &str = "MANIFEST.sig";
/// Chunk directory inside an RPK directory.
pub const CHUNKS_DIR: &str = "chunks";
/// Domain of the manifest signatures.
pub const MANIFEST_SIG_DOMAIN: &[u8] = b"robodr-pkg/manifest/v1\0";
/// Domain of the RPK digest.
pub const RPK_DIGEST_DOMAIN: &[u8] = b"robodr-pkg/digest/v1\0";
/// Fixed chunk size (4 MiB, §3.1).
pub const CHUNK_SIZE: u64 = 4 * 1024 * 1024;
/// Largest manifest read.
pub const MAX_MANIFEST_BYTES: usize = 8 * 1024 * 1024;
/// Most content files.
pub const MAX_CONTENT_FILES: usize = 16_384;
/// Most distinct chunks (64 GiB of payload).
pub const MAX_CHUNKS: usize = 16_384;
/// Largest total payload (sum of content sizes).
pub const MAX_PAYLOAD: u64 = MAX_CHUNKS as u64 * CHUNK_SIZE;
/// Most `hw_compat` entries, `requires` / `conflicts` entries, health checks.
pub const MAX_HW_COMPAT: usize = 32;
pub const MAX_DEPENDENCIES: usize = 64;
pub const MAX_HEALTH_CHECKS: usize = 16;
/// Probe limits.
pub const MAX_PROBE_ARGS: usize = 16;
pub const MAX_PROBE_ARG_LEN: usize = 256;
pub const MAX_PROBE_TIMEOUT_S: u32 = 300;
/// Largest SBOM content file.
pub const MAX_SBOM_BYTES: u64 = 64 * 1024 * 1024;
/// Suffix the SBOM content file must have.
pub const SBOM_SUFFIX: &str = ".cdx.json";

/// What the package is (closed set, §4.2; no "run this script" kind).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum Kind {
    Deb,
    OciImage,
    Files,
    Model,
    Config,
    RobodrProfile,
    RobodrRules,
    OsImage,
}

impl Kind {
    /// Kinds whose SBOM is mandatory (§3.1).
    pub fn needs_sbom(self) -> bool {
        matches!(self, Kind::Deb | Kind::OciImage | Kind::OsImage)
    }

    /// Data-only kinds: no executable bit on any file.
    pub fn data_only(self) -> bool {
        matches!(
            self,
            Kind::Model | Kind::Config | Kind::RobodrProfile | Kind::RobodrRules
        )
    }
}

/// Target CPU architecture (Debian names), or `all` for architecture-free
/// payloads.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Arch {
    Amd64,
    Arm64,
    All,
}

impl Arch {
    pub fn as_str(self) -> &'static str {
        match self {
            Arch::Amd64 => "amd64",
            Arch::Arm64 => "arm64",
            Arch::All => "all",
        }
    }
}

/// `public` (signed only) or `sealed` (encrypted, §7; Sprint 13c).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Confidentiality {
    Public,
    Sealed,
}

/// Version: ordering uses `serial` only.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Version {
    pub serial: u64,
    pub display: String,
}

/// `requires` / `conflicts` entry: a package name and a minimum serial.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Dependency {
    pub name: String,
    pub min_serial: u64,
}

/// One logical file.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ContentFile {
    pub path: String,
    /// Permission bits only (`0..=0o755`, no group / other write).
    pub mode: u32,
    pub size: u64,
    /// Hex SHA-256 of the plaintext.
    pub sha256: String,
    /// Indices into [`Manifest::chunks`], in order.
    pub chunks: Vec<u32>,
}

/// One stored chunk.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Chunk {
    /// Hex SHA-256 of the stored bytes (ciphertext for sealed RPKs).
    pub sha256: String,
    pub size: u64,
}

/// Declarative install options (§3.2, §6.3); never shell.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Install {
    /// `deb` only: run maintainer scripts.
    pub allow_maintainer_scripts: bool,
    /// Needs a local operator confirmation before installing.
    pub requires_operator_present: bool,
}

/// Post-install health checks (§6.2).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "check", rename_all = "snake_case", deny_unknown_fields)]
pub enum HealthCheck {
    /// A systemd service is active.
    ServiceActive { unit: String },
    /// An absolute path exists.
    FilePresent { path: String },
    /// A ROS 2 node is visible on the bus.
    Ros2Node { node: String },
    /// A command (argv, never a shell) run as an unprivileged user exits 0
    /// within `timeout_s`.
    Probe {
        argv: Vec<String>,
        user: String,
        timeout_s: u32,
    },
}

/// The manifest (members in canonical order).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Manifest {
    pub format: String,
    pub name: String,
    pub version: Version,
    pub kind: Kind,
    pub platform: String,
    pub arch: Arch,
    pub hw_compat: Vec<String>,
    pub requires: Vec<Dependency>,
    pub conflicts: Vec<Dependency>,
    pub security_floor: u64,
    pub confidentiality: Confidentiality,
    pub content: Vec<ContentFile>,
    pub chunks: Vec<Chunk>,
    pub sbom: Option<String>,
    pub install: Install,
    pub health: Vec<HealthCheck>,
    pub expires_at: Option<u64>,
}

/// The RPK digest of manifest bytes.
pub fn rpk_digest(manifest_bytes: &[u8]) -> String {
    domain_hash(RPK_DIGEST_DOMAIN, manifest_bytes)
}

/// The directory name of an RPK in a bundle: `rpk_<name>_<serial>_<arch>`.
pub fn dir_name(name: &str, serial: u64, arch: Arch) -> String {
    format!("rpk_{name}_{serial}_{}", arch.as_str())
}

/// Parse and validate manifest bytes (no signature check).
pub fn parse_manifest(bytes: &[u8]) -> Result<Manifest, Refusal> {
    let m: Manifest = parse_canonical(bytes, MAX_MANIFEST_BYTES, "RPK manifest")?;
    m.validate()?;
    Ok(m)
}

fn is_service_unit(s: &str) -> bool {
    s.len() <= 128
        && s.strip_suffix(".service").is_some_and(|b| {
            !b.is_empty()
                && b.bytes()
                    .all(|c| c.is_ascii_alphanumeric() || matches!(c, b'@' | b'.' | b'_' | b'-'))
        })
}

fn is_abs_path(s: &str) -> bool {
    s.strip_prefix('/').is_some_and(is_safe_rel_path)
}

fn is_ros2_node(s: &str) -> bool {
    s.len() <= 256
        && s.strip_prefix('/').is_some_and(|r| {
            r.split('/').all(|seg| {
                let b = seg.as_bytes();
                !b.is_empty()
                    && (b[0].is_ascii_alphabetic() || b[0] == b'_')
                    && b.iter().all(|c| c.is_ascii_alphanumeric() || *c == b'_')
            })
        })
}

fn is_unprivileged_user(s: &str) -> bool {
    let b = s.as_bytes();
    !b.is_empty()
        && b.len() <= 32
        && (b[0].is_ascii_lowercase() || b[0] == b'_')
        && b.iter()
            .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || matches!(c, b'_' | b'-'))
        && s != "root"
}

impl HealthCheck {
    fn validate(&self) -> Result<(), Refusal> {
        let ok = match self {
            HealthCheck::ServiceActive { unit } => is_service_unit(unit),
            HealthCheck::FilePresent { path } => is_abs_path(path),
            HealthCheck::Ros2Node { node } => is_ros2_node(node),
            HealthCheck::Probe {
                argv,
                user,
                timeout_s,
            } => {
                !argv.is_empty()
                    && argv.len() <= MAX_PROBE_ARGS
                    && is_abs_path(&argv[0])
                    && argv.iter().all(|a| {
                        a.len() <= MAX_PROBE_ARG_LEN
                            && a.bytes().all(|c| c.is_ascii_graphic() || c == b' ')
                    })
                    && is_unprivileged_user(user)
                    && (1..=MAX_PROBE_TIMEOUT_S).contains(timeout_s)
            }
        };
        if ok {
            Ok(())
        } else {
            Err(invalid("RPK manifest: bad health check"))
        }
    }
}

fn check_deps(deps: &[Dependency], own: &str, what: &str) -> Result<(), Refusal> {
    if deps.len() > MAX_DEPENDENCIES {
        return Err(invalid(format!(
            "RPK manifest: more than {MAX_DEPENDENCIES} {what}"
        )));
    }
    for d in deps {
        if !is_pkg_name(&d.name) || d.min_serial == 0 || d.min_serial > MAX_SAFE_INTEGER {
            return Err(invalid(format!("RPK manifest: bad {what} entry")));
        }
        if d.name == own {
            return Err(invalid(format!(
                "RPK manifest: {what} names the package itself"
            )));
        }
    }
    strictly_sorted(deps, |d| d.name.clone(), what)
}

impl Manifest {
    /// Every value rule of `robodr-pkg/1` that needs nothing but the
    /// manifest.
    pub fn validate(&self) -> Result<(), Refusal> {
        if self.format != RPK_FORMAT {
            return Err(invalid("RPK manifest: unsupported format"));
        }
        if !is_pkg_name(&self.name) {
            return Err(invalid("RPK manifest: bad name"));
        }
        let serial = self.version.serial;
        if serial == 0 || serial > MAX_SAFE_INTEGER {
            return Err(invalid("RPK manifest: serial must be 1..=2^53-1"));
        }
        if !is_version_display(&self.version.display) {
            return Err(invalid("RPK manifest: bad version display"));
        }
        if !is_label(&self.platform) {
            return Err(invalid("RPK manifest: bad platform"));
        }
        if self.hw_compat.len() > MAX_HW_COMPAT || !self.hw_compat.iter().all(|h| is_label(h)) {
            return Err(invalid("RPK manifest: bad hw_compat"));
        }
        strictly_sorted(&self.hw_compat, |h| h.clone(), "hw_compat")?;
        check_deps(&self.requires, &self.name, "requires")?;
        check_deps(&self.conflicts, &self.name, "conflicts")?;
        if self
            .requires
            .iter()
            .any(|r| self.conflicts.iter().any(|c| c.name == r.name))
        {
            return Err(invalid(
                "RPK manifest: a package both required and conflicting",
            ));
        }
        if self.security_floor == 0 || self.security_floor > serial {
            return Err(invalid(
                "RPK manifest: security_floor must be 1..=serial (a release cannot forbid itself)",
            ));
        }
        if self.confidentiality == Confidentiality::Sealed {
            return Err(Refusal::new(
                Code::Unsupported,
                "RPK manifest: sealed RPKs need the key-wrap format of Sprint 13c",
            ));
        }
        if let Some(e) = self.expires_at {
            if e > MAX_SAFE_INTEGER {
                return Err(invalid("RPK manifest: expires_at out of range"));
            }
        }
        if self.health.len() > MAX_HEALTH_CHECKS {
            return Err(invalid(format!(
                "RPK manifest: more than {MAX_HEALTH_CHECKS} health checks"
            )));
        }
        for h in &self.health {
            h.validate()?;
        }
        if self.install.allow_maintainer_scripts && self.kind != Kind::Deb {
            return Err(invalid(
                "RPK manifest: allow_maintainer_scripts is only meaningful for kind deb",
            ));
        }
        self.validate_payload()?;
        self.validate_kind()
    }

    fn validate_payload(&self) -> Result<(), Refusal> {
        if self.content.len() > MAX_CONTENT_FILES {
            return Err(invalid(format!(
                "RPK manifest: more than {MAX_CONTENT_FILES} content files"
            )));
        }
        if self.chunks.len() > MAX_CHUNKS {
            return Err(invalid(format!(
                "RPK manifest: more than {MAX_CHUNKS} chunks"
            )));
        }
        for c in &self.chunks {
            if !is_hex64(&c.sha256) || c.size == 0 || c.size > CHUNK_SIZE {
                return Err(invalid("RPK manifest: bad chunk entry"));
            }
        }
        strictly_sorted(&self.chunks, |c| c.sha256.clone(), "chunks (by sha256)")?;
        strictly_sorted(&self.content, |c| c.path.clone(), "content (by path)")?;
        let mut folded = BTreeSet::new();
        let mut used = vec![false; self.chunks.len()];
        let mut total: u64 = 0;
        for f in &self.content {
            if !is_safe_rel_path(&f.path) {
                return Err(invalid(format!(
                    "RPK manifest: unsafe content path {:?}",
                    crate::common::trunc(&f.path)
                )));
            }
            // One file per name on a case-insensitive file system too.
            if !folded.insert(f.path.to_ascii_lowercase()) {
                return Err(invalid(format!(
                    "RPK manifest: content paths collide case-insensitively ({})",
                    f.path
                )));
            }
            if f.mode & !0o777 != 0 || f.mode & 0o022 != 0 || f.mode & 0o400 == 0 {
                return Err(invalid(format!(
                    "RPK manifest: {} mode {:o}: permission bits only, owner-readable, no group or \
                     other write, no setuid / setgid / sticky",
                    f.path, f.mode
                )));
            }
            if self.kind.data_only() && f.mode & 0o111 != 0 {
                return Err(invalid(format!(
                    "RPK manifest: {} is executable in a data-only kind",
                    f.path
                )));
            }
            if !is_hex64(&f.sha256) {
                return Err(invalid("RPK manifest: bad content sha256"));
            }
            total = total
                .checked_add(f.size)
                .filter(|t| *t <= MAX_PAYLOAD)
                .ok_or_else(|| invalid("RPK manifest: payload too large"))?;
            let want = f.size.div_ceil(CHUNK_SIZE);
            if f.chunks.len() as u64 != want {
                return Err(invalid(format!(
                    "RPK manifest: {} needs exactly {want} chunks",
                    f.path
                )));
            }
            let mut sum: u64 = 0;
            for (i, &ci) in f.chunks.iter().enumerate() {
                let Some(c) = self.chunks.get(ci as usize) else {
                    return Err(invalid("RPK manifest: chunk index out of range"));
                };
                let last = i + 1 == f.chunks.len();
                if !last && c.size != CHUNK_SIZE {
                    return Err(invalid(format!(
                        "RPK manifest: {}: only the last chunk may be short",
                        f.path
                    )));
                }
                sum += c.size;
                used[ci as usize] = true;
            }
            if sum != f.size {
                return Err(invalid(format!(
                    "RPK manifest: {}: chunk sizes do not add up to the file size",
                    f.path
                )));
            }
        }
        if used.iter().any(|u| !u) {
            return Err(invalid("RPK manifest: a chunk no content file uses"));
        }
        // A path must not be both a file and a directory of another file.
        for f in &self.content {
            let p = f.path.to_ascii_lowercase();
            let mut at = 0;
            while let Some(i) = p[at..].find('/') {
                let dir = &p[..at + i];
                if folded.contains(dir) {
                    return Err(invalid(format!(
                        "RPK manifest: {dir} is both a file and a directory"
                    )));
                }
                at += i + 1;
            }
        }
        Ok(())
    }

    /// The content entry the `sbom` member names, if any.
    pub fn sbom_entry(&self) -> Option<&ContentFile> {
        let s = self.sbom.as_ref()?;
        self.content.iter().find(|c| &c.sha256 == s)
    }

    /// Content files other than the SBOM.
    pub fn payload_files(&self) -> impl Iterator<Item = &ContentFile> {
        let sbom = self.sbom_entry().map(|c| c.path.clone());
        self.content
            .iter()
            .filter(move |c| Some(&c.path) != sbom.as_ref())
    }

    fn validate_kind(&self) -> Result<(), Refusal> {
        match &self.sbom {
            None if self.kind.needs_sbom() => {
                return Err(invalid("RPK manifest: an SBOM is mandatory for this kind"))
            }
            None => {}
            Some(s) => {
                if !is_hex64(s) {
                    return Err(invalid("RPK manifest: bad sbom digest"));
                }
                let hits: Vec<_> = self.content.iter().filter(|c| &c.sha256 == s).collect();
                match hits.as_slice() {
                    [c] if c.path.ends_with(SBOM_SUFFIX)
                        && c.size > 0
                        && c.size <= MAX_SBOM_BYTES => {}
                    _ => {
                        return Err(invalid(format!(
                            "RPK manifest: sbom must name exactly one non-empty content file \
                             ending in {SBOM_SUFFIX}"
                        )))
                    }
                }
            }
        }
        let payload: Vec<&ContentFile> = self.payload_files().collect();
        let one_with = |suffix: &str| payload.len() == 1 && payload[0].path.ends_with(suffix);
        let ok = match self.kind {
            Kind::Deb => one_with(".deb"),
            Kind::OciImage => one_with(".tar"),
            Kind::OsImage => payload.len() == 1,
            Kind::RobodrProfile => one_with(".json"),
            Kind::RobodrRules => {
                !payload.is_empty() && payload.iter().all(|c| c.path.ends_with(".toml"))
            }
            Kind::Files | Kind::Model | Kind::Config => !payload.is_empty(),
        };
        if !ok {
            return Err(invalid(format!(
                "RPK manifest: content does not fit kind {:?} (deb: one .deb; oci-image: one \
                 .tar; os-image: one file; robodr-profile: one .json; robodr-rules: .toml only; \
                 others: at least one file; the SBOM aside)",
                self.kind
            )));
        }
        Ok(())
    }

    /// Directory name of this RPK in a bundle.
    pub fn dir_name(&self) -> String {
        dir_name(&self.name, self.version.serial, self.arch)
    }

    /// Paths (relative to the RPK directory) of every chunk file.
    pub fn chunk_paths(&self) -> impl Iterator<Item = String> + '_ {
        self.chunks
            .iter()
            .map(|c| format!("{CHUNKS_DIR}/{}", c.sha256))
    }
}

/// Site policy for an RPK: not revoked, not below the site floor, not
/// expired at `now` (Unix seconds).
pub fn check_policy(
    m: &Manifest,
    digest: &str,
    trust: &VerifiedTrust,
    now: u64,
) -> Result<(), Refusal> {
    if trust.is_rpk_revoked(digest) {
        return Err(Refusal::new(
            Code::RevokedRpk,
            format!("RPK {} {} ({digest}) is revoked", m.name, m.version.serial),
        ));
    }
    let floor = trust.floor(&m.name);
    if m.version.serial < floor {
        return Err(Refusal::new(
            Code::BelowFloor,
            format!(
                "RPK {} serial {} is below the site floor {floor}",
                m.name, m.version.serial
            ),
        ));
    }
    if let Some(e) = m.expires_at {
        if now >= e {
            return Err(Refusal::new(
                Code::Expired,
                format!("RPK {} {} expired at {e}", m.name, m.version.serial),
            ));
        }
    }
    Ok(())
}

/// A fully checked manifest: parsed, valid, signed by the release quorum,
/// within site policy.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerifiedManifest {
    pub manifest: Manifest,
    pub digest: String,
    pub signers: Signers,
}

/// Parse, validate, check the release quorum's signatures and the site
/// policy of an RPK manifest.
pub fn verify_manifest(
    manifest_bytes: &[u8],
    sigset_bytes: &[u8],
    trust: &VerifiedTrust,
    now: u64,
) -> Result<VerifiedManifest, Refusal> {
    let manifest = parse_manifest(manifest_bytes)?;
    let digest = rpk_digest(manifest_bytes);
    let set = SignatureSet::parse(sigset_bytes)?;
    let signers = set.check(trust, &[Role::Release], MANIFEST_SIG_DOMAIN, manifest_bytes)?;
    signers.require(
        Role::Release,
        trust.file().quorum.release as usize,
        "RPK manifest",
    )?;
    check_policy(&manifest, &digest, trust, now)?;
    Ok(VerifiedManifest {
        manifest,
        digest,
        signers,
    })
}

/// Check one stored chunk's bytes against its entry.
pub fn check_chunk(c: &Chunk, bytes: &[u8]) -> Result<(), Refusal> {
    if bytes.len() as u64 != c.size || sha256_hex(bytes) != c.sha256 {
        return Err(Refusal::new(
            Code::FileMismatch,
            format!("chunk {} does not match its size or hash", c.sha256),
        ));
    }
    Ok(())
}

/// Recompute every content file's plaintext SHA-256 from its chunks
/// (public RPKs). `chunk` returns the stored bytes of a chunk entry; they
/// are checked against the entry before use.
pub fn verify_content(
    m: &Manifest,
    chunk: &mut dyn FnMut(&Chunk) -> Result<Vec<u8>, Refusal>,
) -> Result<(), Refusal> {
    for f in &m.content {
        let mut h = robodr_blackbox::crypto::Sha256::new();
        for &ci in &f.chunks {
            let c = m
                .chunks
                .get(ci as usize)
                .ok_or_else(|| invalid("chunk index out of range"))?;
            let bytes = chunk(c)?;
            check_chunk(c, &bytes)?;
            h.update(&bytes);
        }
        if robodr_blackbox::crypto::to_hex(&h.finalize()) != f.sha256 {
            return Err(Refusal::new(
                Code::DigestMismatch,
                format!(
                    "content {}: plaintext hash differs from the manifest",
                    f.path
                ),
            ));
        }
    }
    Ok(())
}

#[cfg(test)]
pub(crate) mod test_support {
    use super::*;

    /// A valid `files` manifest of the given (path, bytes) files (each
    /// below one chunk), not signed.
    pub fn manifest(files: &[(&str, &[u8])]) -> Manifest {
        let mut chunks: Vec<Chunk> = Vec::new();
        for (_, b) in files {
            if !b.is_empty() {
                chunks.push(Chunk {
                    sha256: sha256_hex(b),
                    size: b.len() as u64,
                });
            }
        }
        chunks.sort_by(|a, b| a.sha256.cmp(&b.sha256));
        chunks.dedup();
        let mut content: Vec<ContentFile> = files
            .iter()
            .map(|(p, b)| ContentFile {
                path: (*p).into(),
                mode: 0o644,
                size: b.len() as u64,
                sha256: sha256_hex(b),
                chunks: if b.is_empty() {
                    vec![]
                } else {
                    vec![chunks
                        .iter()
                        .position(|c| c.sha256 == sha256_hex(b))
                        .unwrap() as u32]
                },
            })
            .collect();
        content.sort_by(|a, b| a.path.cmp(&b.path));
        Manifest {
            format: RPK_FORMAT.into(),
            name: "nav-stack".into(),
            version: Version {
                serial: 7,
                display: "1.4.0".into(),
            },
            kind: Kind::Files,
            platform: "ugv-x1".into(),
            arch: Arch::Arm64,
            hw_compat: vec![],
            requires: vec![],
            conflicts: vec![],
            security_floor: 5,
            confidentiality: Confidentiality::Public,
            content,
            chunks,
            sbom: None,
            install: Install {
                allow_maintainer_scripts: false,
                requires_operator_present: false,
            },
            health: vec![],
            expires_at: None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::test_support::manifest;
    use super::*;
    use crate::common::to_canonical;

    type Mutation = Box<dyn Fn(&mut Manifest)>;

    fn good() -> Manifest {
        manifest(&[("bin/nav", b"\x7fELF..."), ("etc/nav.yaml", b"a: 1\n")])
    }

    #[test]
    fn valid_manifest_round_trips() {
        let m = good();
        m.validate().unwrap();
        let b = to_canonical(&m).unwrap();
        assert_eq!(parse_manifest(&b).unwrap(), m);
        assert_eq!(m.dir_name(), "rpk_nav-stack_7_arm64");
        assert_ne!(rpk_digest(&b), sha256_hex(&b));
    }

    #[test]
    fn health_checks_parse_strictly() {
        let mut m = good();
        m.health = vec![
            HealthCheck::ServiceActive {
                unit: "nav@1.service".into(),
            },
            HealthCheck::FilePresent {
                path: "/opt/robodr-delivered/nav/current/bin/nav".into(),
            },
            HealthCheck::Ros2Node {
                node: "/nav/planner".into(),
            },
            HealthCheck::Probe {
                argv: vec!["/usr/bin/nav-probe".into(), "--quick".into()],
                user: "robodr-probe".into(),
                timeout_s: 30,
            },
        ];
        let b = to_canonical(&m).unwrap();
        assert!(String::from_utf8_lossy(&b)
            .contains(r#"{"check":"service_active","unit":"nav@1.service"}"#));
        assert_eq!(parse_manifest(&b).unwrap(), m);
        // Unknown member inside a check is refused.
        let s = String::from_utf8(b).unwrap().replace(
            r#""unit":"nav@1.service"}"#,
            r#""unit":"nav@1.service","shell":"rm -rf /"}"#,
        );
        assert_eq!(
            parse_manifest(s.as_bytes()).unwrap_err().code,
            Code::Malformed
        );
    }

    #[test]
    fn every_rule_refuses() {
        let big = |m: &mut Manifest, sizes: &[u64]| {
            // One file of chunks with the given sizes (fake hashes).
            m.chunks = sizes
                .iter()
                .enumerate()
                .map(|(i, &s)| Chunk {
                    sha256: format!("{i:064x}"),
                    size: s,
                })
                .collect();
            m.content = vec![ContentFile {
                path: "x".into(),
                mode: 0o644,
                size: sizes.iter().sum(),
                sha256: "ab".repeat(32),
                chunks: (0..sizes.len() as u32).collect(),
            }];
        };
        let cases: Vec<(&str, Code, Mutation)> = vec![
            (
                "format",
                Code::Invalid,
                Box::new(|m| m.format = "robodr-pkg/2".into()),
            ),
            ("name", Code::Invalid, Box::new(|m| m.name = "Nav".into())),
            (
                "name underscore",
                Code::Invalid,
                Box::new(|m| m.name = "a_b".into()),
            ),
            (
                "serial 0",
                Code::Invalid,
                Box::new(|m| m.version.serial = 0),
            ),
            (
                "serial big",
                Code::Invalid,
                Box::new(|m| m.version.serial = MAX_SAFE_INTEGER + 1),
            ),
            (
                "display",
                Code::Invalid,
                Box::new(|m| m.version.display = "1 0".into()),
            ),
            (
                "platform",
                Code::Invalid,
                Box::new(|m| m.platform = "".into()),
            ),
            (
                "hw unsorted",
                Code::Invalid,
                Box::new(|m| m.hw_compat = vec!["b".into(), "a".into()]),
            ),
            ("floor 0", Code::Invalid, Box::new(|m| m.security_floor = 0)),
            (
                "floor > serial",
                Code::Invalid,
                Box::new(|m| m.security_floor = 8),
            ),
            (
                "sealed",
                Code::Unsupported,
                Box::new(|m| m.confidentiality = Confidentiality::Sealed),
            ),
            (
                "self dep",
                Code::Invalid,
                Box::new(|m| {
                    m.requires = vec![Dependency {
                        name: "nav-stack".into(),
                        min_serial: 1,
                    }]
                }),
            ),
            (
                "dep 0",
                Code::Invalid,
                Box::new(|m| {
                    m.requires = vec![Dependency {
                        name: "x".into(),
                        min_serial: 0,
                    }]
                }),
            ),
            (
                "req+conflict",
                Code::Invalid,
                Box::new(|m| {
                    m.requires = vec![Dependency {
                        name: "x".into(),
                        min_serial: 1,
                    }];
                    m.conflicts = vec![Dependency {
                        name: "x".into(),
                        min_serial: 2,
                    }];
                }),
            ),
            (
                "traversal",
                Code::Invalid,
                Box::new(|m| m.content[0].path = "../../etc/shadow".into()),
            ),
            (
                "absolute",
                Code::Invalid,
                Box::new(|m| m.content[0].path = "/etc/shadow".into()),
            ),
            (
                "dot",
                Code::Invalid,
                Box::new(|m| m.content[0].path = "bin/./nav".into()),
            ),
            (
                "unsorted content",
                Code::Invalid,
                Box::new(|m| m.content.swap(0, 1)),
            ),
            (
                "case collision",
                Code::Invalid,
                Box::new(|m| {
                    m.content[0].path = "Etc/nav.yaml".into();
                }),
            ),
            (
                "file is dir",
                Code::Invalid,
                Box::new(|m| {
                    m.content[0].path = "bin".into();
                    m.content[1].path = "bin/x".into();
                }),
            ),
            (
                "setuid",
                Code::Invalid,
                Box::new(|m| m.content[0].mode = 0o4755),
            ),
            (
                "world write",
                Code::Invalid,
                Box::new(|m| m.content[0].mode = 0o646),
            ),
            (
                "group write",
                Code::Invalid,
                Box::new(|m| m.content[0].mode = 0o664),
            ),
            (
                "unreadable",
                Code::Invalid,
                Box::new(|m| m.content[0].mode = 0o044),
            ),
            (
                "size lie",
                Code::Invalid,
                Box::new(|m| m.content[0].size += 1),
            ),
            (
                "chunk idx",
                Code::Invalid,
                Box::new(|m| m.content[0].chunks = vec![9]),
            ),
            (
                "missing chunk ref",
                Code::Invalid,
                Box::new(|m| m.content[0].chunks.clear()),
            ),
            (
                "orphan chunk",
                Code::Invalid,
                Box::new(|m| {
                    m.chunks.push(Chunk {
                        sha256: "ff".repeat(32),
                        size: 1,
                    });
                }),
            ),
            (
                "chunks unsorted",
                Code::Invalid,
                Box::new(|m| m.chunks.swap(0, 1)),
            ),
            ("chunk 0", Code::Invalid, Box::new(|m| m.chunks[0].size = 0)),
            (
                "chunk too big",
                Code::Invalid,
                Box::new(move |m| big(m, &[CHUNK_SIZE + 1])),
            ),
            (
                "short middle",
                Code::Invalid,
                Box::new(move |m| big(m, &[CHUNK_SIZE - 1, 1])),
            ),
            (
                "chunk hash",
                Code::Invalid,
                Box::new(|m| m.chunks[0].sha256 = "XY".repeat(32)),
            ),
            (
                "maint scripts",
                Code::Invalid,
                Box::new(|m| m.install.allow_maintainer_scripts = true),
            ),
            (
                "deb without sbom",
                Code::Invalid,
                Box::new(|m| m.kind = Kind::Deb),
            ),
            (
                "sbom missing file",
                Code::Invalid,
                Box::new(|m| m.sbom = Some("ab".repeat(32))),
            ),
            (
                "expires big",
                Code::Invalid,
                Box::new(|m| m.expires_at = Some(u64::MAX)),
            ),
            (
                "probe root",
                Code::Invalid,
                Box::new(|m| {
                    m.health = vec![HealthCheck::Probe {
                        argv: vec!["/bin/true".into()],
                        user: "root".into(),
                        timeout_s: 1,
                    }]
                }),
            ),
            (
                "probe rel",
                Code::Invalid,
                Box::new(|m| {
                    m.health = vec![HealthCheck::Probe {
                        argv: vec!["true".into()],
                        user: "x".into(),
                        timeout_s: 1,
                    }]
                }),
            ),
            (
                "probe timeout",
                Code::Invalid,
                Box::new(|m| {
                    m.health = vec![HealthCheck::Probe {
                        argv: vec!["/bin/true".into()],
                        user: "x".into(),
                        timeout_s: 0,
                    }]
                }),
            ),
            (
                "probe ctl",
                Code::Invalid,
                Box::new(|m| {
                    m.health = vec![HealthCheck::Probe {
                        argv: vec!["/bin/true".into(), "a\nb".into()],
                        user: "x".into(),
                        timeout_s: 1,
                    }]
                }),
            ),
            (
                "unit",
                Code::Invalid,
                Box::new(|m| {
                    m.health = vec![HealthCheck::ServiceActive {
                        unit: "x.socket".into(),
                    }]
                }),
            ),
            (
                "node",
                Code::Invalid,
                Box::new(|m| m.health = vec![HealthCheck::Ros2Node { node: "nav".into() }]),
            ),
            (
                "file present",
                Code::Invalid,
                Box::new(|m| {
                    m.health = vec![HealthCheck::FilePresent {
                        path: "/a/../b".into(),
                    }]
                }),
            ),
            (
                "data exec",
                Code::Invalid,
                Box::new(|m| {
                    m.kind = Kind::Config;
                    m.content[0].mode = 0o755;
                }),
            ),
            (
                "rules non-toml",
                Code::Invalid,
                Box::new(|m| m.kind = Kind::RobodrRules),
            ),
            (
                "profile two",
                Code::Invalid,
                Box::new(|m| m.kind = Kind::RobodrProfile),
            ),
        ];
        for (name, code, f) in cases {
            let mut m = good();
            f(&mut m);
            let b = to_canonical(&m).unwrap();
            let e = parse_manifest(&b).unwrap_err();
            assert_eq!(e.code, code, "{name}: {e}");
        }
    }

    #[test]
    fn kinds_with_sbom() {
        let deb = b"!<arch>\ndebian-binary...";
        let sbom = br#"{"bomFormat":"CycloneDX","specVersion":"1.5"}"#;
        let mut m = manifest(&[("nav_1.4.0_arm64.deb", deb), ("sbom.cdx.json", sbom)]);
        m.kind = Kind::Deb;
        m.sbom = Some(sha256_hex(sbom));
        m.install.allow_maintainer_scripts = true;
        m.validate().unwrap();
        assert_eq!(m.payload_files().count(), 1);
        // SBOM pointing at the .deb is refused (wrong suffix).
        let mut bad = m.clone();
        bad.sbom = Some(sha256_hex(deb));
        assert!(bad.validate().is_err());
        // Two .debs.
        let mut two = manifest(&[("a.deb", b"1"), ("b.deb", b"2"), ("sbom.cdx.json", sbom)]);
        two.kind = Kind::Deb;
        two.sbom = Some(sha256_hex(sbom));
        assert!(two.validate().is_err());
    }

    #[test]
    fn duplicate_content_shares_one_chunk() {
        let m = manifest(&[("a", b"same"), ("b", b"same"), ("empty", b"")]);
        m.validate().unwrap();
        assert_eq!(m.chunks.len(), 1);
        let mut n = 0;
        verify_content(&m, &mut |_| {
            n += 1;
            Ok(b"same".to_vec())
        })
        .unwrap();
        assert_eq!(n, 2);
        assert_eq!(
            verify_content(&m, &mut |_| Ok(b"diff".to_vec()))
                .unwrap_err()
                .code,
            Code::FileMismatch
        );
    }
}
