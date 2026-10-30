//! The release operations behind the CLI: build an RPK, assemble a
//! bundle, sign any delivery document, verify and repair. Every content
//! decision is `robodr-pkg`'s; this module reads and writes files.

use crate::fsio::{
    self, ensure_dirs, hash_file, hash_file_listed, io_err, open_regular, read_capped,
    require_exact, sibling, walk, write_new, write_replace, Fail, IO_BUF,
};
use robodr_blackbox::Signer;
use robodr_pkg::bundle::{
    self, check_chain, check_rpk_files, verify_bundle_manifest, BundleFile, BundleManifest,
    BundleParity, BundleRpk, ChainAnchor, ChainStep, VerifiedBundle, BUNDLE_FILE, BUNDLE_FORMAT,
    BUNDLE_SIG_DOMAIN, BUNDLE_SIG_FILE, MAX_BUNDLE_BYTES,
};
use robodr_pkg::common::{is_safe_rel_path, sha256_hex, to_canonical};
use robodr_pkg::deployment::{
    self, VerifiedDeployment, DEPLOYMENT_SIG_DOMAIN, MAX_DEPLOYMENT_BYTES,
};
use robodr_pkg::parity::{self, PARITY_SCHEME};
use robodr_pkg::rpk::{
    self, Arch, Chunk, Confidentiality, ContentFile, Dependency, HealthCheck, Install, Kind,
    Manifest, VerifiedManifest, Version, CHUNKS_DIR, CHUNK_SIZE, MANIFEST_FILE,
    MANIFEST_SIG_DOMAIN, MAX_MANIFEST_BYTES, RPK_FORMAT, SIGNATURE_FILE,
};
use robodr_pkg::sig::{Role, SignatureSet, MAX_SIGSET_BYTES};
use robodr_pkg::trust::{
    self, verify_trust_anchor, verify_trust_pinned, verify_trust_update, VerifiedTrust,
    MAX_TRUST_BYTES, TRUST_SIG_DOMAIN,
};
use robodr_pkg::{Code, Refusal};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};
use std::fs::{self, File, OpenOptions};
use std::io::{Read, Write};
use std::os::unix::fs::{FileExt, MetadataExt};
use std::path::{Path, PathBuf};

/// `format` of an RPK build spec.
pub const SPEC_FORMAT: &str = "robodr-rpk-spec/1";
/// Largest build spec read.
pub const MAX_SPEC_BYTES: usize = 1024 * 1024;

/// The detached signature path of a standalone document (`x.json.sig`).
pub fn sig_path(doc: &Path) -> PathBuf {
    let mut s = doc.as_os_str().to_owned();
    s.push(".sig");
    PathBuf::from(s)
}

// ---------------------------------------------------------------------------
// Trust
// ---------------------------------------------------------------------------

/// Read a trust file and its `.sig`.
pub fn read_trust_files(path: &Path) -> Result<(Vec<u8>, Vec<u8>), Fail> {
    let doc = read_capped(path, MAX_TRUST_BYTES)?;
    let sig = read_capped(&sig_path(path), MAX_SIGSET_BYTES)?;
    Ok((doc, sig))
}

/// Load a trust file (and its `.sig`) and accept it under the pinned
/// roots and site, unexpired at `now`. No anti-rollback: an older,
/// root-signed file is accepted too. Use [`SiteTrust::anchored`] wherever
/// a site has an anchor; this is the explicit `--no-trust-anchor` mode.
pub fn load_trust(
    path: &Path,
    pins: &[String],
    site: &str,
    now: u64,
) -> Result<VerifiedTrust, Fail> {
    let (doc, sig) = read_trust_files(path)?;
    Ok(verify_trust_pinned(&doc, &sig, pins, site, now)?)
}

/// The trust a verifier works under, and how it was accepted.
///
/// A site keeps **one** trust anchor (13a review finding 4): a copy of the
/// last trust file it accepted (`FILE` and `FILE.sig`) on trusted
/// storage, shared by every programme and every command. A presented
/// trust file is accepted only as that anchor or a valid rotation of it
/// ([`verify_trust_update`]: same site, newer version signed by the old
/// and new root quorums, revocations and floors only grow, not expired),
/// so an older file, another site's file or one that drops a revocation
/// is refused everywhere (`verify rpk`, `verify bundle`, `verify
/// deployment`, `repair`, `import`, `build bundle`, `sign`). The anchor
/// moves forward only by [`commit_anchor`] of such a rotation.
#[derive(Debug, Clone)]
pub struct SiteTrust {
    /// The accepted trust file (anchor or rotation of it).
    pub trust: VerifiedTrust,
    /// `None` in the explicit `--no-trust-anchor` mode.
    pub anchor: Option<Anchor>,
}

/// A loaded trust anchor.
#[derive(Debug, Clone)]
pub struct Anchor {
    pub path: PathBuf,
    /// The anchor file as accepted (pins and site; not its expiry).
    pub trust: VerifiedTrust,
    /// Bytes of the presented trust file and signature (written by
    /// [`commit_anchor`] when newer than the anchor).
    doc: Vec<u8>,
    sig: Vec<u8>,
}

impl std::ops::Deref for SiteTrust {
    type Target = VerifiedTrust;
    fn deref(&self) -> &VerifiedTrust {
        &self.trust
    }
}

impl SiteTrust {
    /// Accept `presented` as the site's anchor at `anchor` or a rotation
    /// of it. The anchor must exist (create it with [`init_anchor`]) and
    /// satisfy the pinned roots and site.
    pub fn anchored(
        presented: &Path,
        anchor: &Path,
        pins: &[String],
        site: &str,
        now: u64,
    ) -> Result<Self, Fail> {
        if fs::symlink_metadata(anchor).is_err() {
            return Err(Fail::Io(format!(
                "{}: no trust anchor; create it once with `verify trust --init-anchor`",
                anchor.display()
            )));
        }
        let (adoc, asig) = read_trust_files(anchor).map_err(|e| prefix(e, "trust anchor"))?;
        let a = verify_trust_anchor(&adoc, &asig, pins, site)
            .map_err(|r| Fail::Refused(r.context("trust anchor")))?;
        let (doc, sig) = read_trust_files(presented)?;
        let trust = verify_trust_update(&a, &doc, &sig, now)?;
        Ok(Self {
            trust,
            anchor: Some(Anchor {
                path: anchor.to_path_buf(),
                trust: a,
                doc,
                sig,
            }),
        })
    }

    /// The explicit no-anchor mode (`--no-trust-anchor`): pinned roots,
    /// site and expiry only; an older root-signed file is not detected.
    pub fn unanchored(
        presented: &Path,
        pins: &[String],
        site: &str,
        now: u64,
    ) -> Result<Self, Fail> {
        Ok(Self {
            trust: load_trust(presented, pins, site, now)?,
            anchor: None,
        })
    }

    /// Whether the presented file is newer than the anchor.
    pub fn is_rotation(&self) -> bool {
        self.anchor
            .as_ref()
            .is_some_and(|a| self.trust.file().version > a.trust.file().version)
    }
}

/// Create the site's trust anchor from a trust file accepted under the
/// pinned roots and site (the one-time enrolment step). Refuses to
/// overwrite an existing anchor.
pub fn init_anchor(
    presented: &Path,
    anchor: &Path,
    pins: &[String],
    site: &str,
    now: u64,
) -> Result<VerifiedTrust, Fail> {
    let (doc, sig) = read_trust_files(presented)?;
    let t = verify_trust_pinned(&doc, &sig, pins, site, now)?;
    for p in [anchor.to_path_buf(), sig_path(anchor)] {
        if fs::symlink_metadata(&p).is_ok() {
            return Err(Fail::Io(format!(
                "{}: already exists; an anchor is advanced with --commit, never re-created",
                p.display()
            )));
        }
    }
    write_new(&sig_path(anchor), &sig)?;
    write_new(anchor, &doc)?;
    Ok(t)
}

/// Advance the anchor to the presented file when it is a newer, accepted
/// rotation (no-op otherwise). The signature is written first: a crash
/// between the two renames leaves a pair that fails to load (refused,
/// never trusted), not an older anchor.
pub fn commit_anchor(st: &SiteTrust) -> Result<bool, Fail> {
    let Some(a) = &st.anchor else {
        return Ok(false);
    };
    if !st.is_rotation() {
        return Ok(false);
    }
    write_replace(&sig_path(&a.path), &a.sig)?;
    write_replace(&a.path, &a.doc)?;
    Ok(true)
}

// ---------------------------------------------------------------------------
// Build an RPK
// ---------------------------------------------------------------------------

/// Everything of a manifest except the payload description, as a human
/// writes it (`robodr-rpk-spec/1`; unknown members refused).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RpkSpec {
    pub format: String,
    pub name: String,
    pub version: Version,
    pub kind: Kind,
    pub platform: String,
    pub arch: Arch,
    #[serde(default)]
    pub hw_compat: Vec<String>,
    #[serde(default)]
    pub requires: Vec<Dependency>,
    #[serde(default)]
    pub conflicts: Vec<Dependency>,
    pub security_floor: u64,
    pub install: Install,
    #[serde(default)]
    pub health: Vec<HealthCheck>,
    #[serde(default)]
    pub expires_at: Option<u64>,
    /// Payload-relative path of the CycloneDX SBOM, if any.
    #[serde(default)]
    pub sbom_path: Option<String>,
}

/// Parse a build spec (size-capped, strict members; whitespace allowed).
pub fn parse_spec(bytes: &[u8]) -> Result<RpkSpec, Fail> {
    if bytes.len() > MAX_SPEC_BYTES {
        return Err(Refusal::new(Code::TooLarge, "spec too large").into());
    }
    let s: RpkSpec = serde_json::from_slice(bytes)
        .map_err(|e| Refusal::new(Code::Malformed, format!("spec: {e}")))?;
    if s.format != SPEC_FORMAT {
        return Err(
            Refusal::new(Code::Invalid, format!("spec: format must be {SPEC_FORMAT}")).into(),
        );
    }
    Ok(s)
}

/// A built (unsigned) RPK.
#[derive(Debug, Clone)]
pub struct BuiltRpk {
    pub dir: PathBuf,
    pub digest: String,
    pub manifest: Manifest,
}

fn read_full(f: &mut File, buf: &mut [u8], path: &Path) -> Result<usize, Fail> {
    let mut n = 0;
    while n < buf.len() {
        let r = f.read(&mut buf[n..]).map_err(|e| io_err(path, e))?;
        if r == 0 {
            break;
        }
        n += r;
    }
    Ok(n)
}

/// A staging directory next to `out`, removed on drop unless published.
struct Staging {
    dir: PathBuf,
    published: bool,
}

impl Staging {
    fn new(out: &Path) -> Result<Self, Fail> {
        if fs::symlink_metadata(out).is_ok() {
            return Err(Fail::Io(format!("{}: already exists", out.display())));
        }
        let dir = sibling(out, "staging");
        fs::create_dir(&dir).map_err(|e| io_err(&dir, e))?;
        Ok(Self {
            dir,
            published: false,
        })
    }

    fn publish(mut self, out: &Path) -> Result<(), Fail> {
        if fs::symlink_metadata(out).is_ok() {
            return Err(Fail::Io(format!("{}: already exists", out.display())));
        }
        fs::rename(&self.dir, out).map_err(|e| io_err(out, e))?;
        self.published = true;
        Ok(())
    }
}

impl Drop for Staging {
    fn drop(&mut self) {
        if !self.published {
            let _ = fs::remove_dir_all(&self.dir);
        }
    }
}

/// Build an RPK from `spec` and the files under `payload` into
/// `out_parent/rpk_<name>_<serial>_<arch>/` (must not exist). Deterministic:
/// the same spec and payload give the same bytes on any host (no times,
/// no host paths, sorted traversal).
pub fn build_rpk(spec: &RpkSpec, payload: &Path, out_parent: &Path) -> Result<BuiltRpk, Fail> {
    build_rpk_with(spec, payload, out_parent, None)
}

/// [`build_rpk`], sealed when `seal_to` names depot wrapping keys
/// (X25519 public keys; `docs/SECURE-DELIVERY.md` §7.1, §7.2): a fresh
/// content key encrypts every file but the SBOM (`robodr-seal`), is
/// wrapped to each depot key into the manifest's `seal` member, and is
/// then forgotten. A sealed build is not deterministic (fresh key and
/// `seal_id`); everything else about it is.
pub fn build_rpk_with(
    spec: &RpkSpec,
    payload: &Path,
    out_parent: &Path,
    seal_to: Option<&[[u8; 32]]>,
) -> Result<BuiltRpk, Fail> {
    let sealer = match seal_to {
        Some(_) => Some(robodr_seal::rpk::Sealer::new().map_err(seal_fail)?),
        None => None,
    };
    let tree = walk(payload)?;
    require_exact(payload, &tree, &tree.files)?; // no empty directories
    if tree.files.is_empty() {
        return Err(Refusal::new(Code::Invalid, "payload directory has no files").into());
    }
    let out = out_parent.join(rpk::dir_name(&spec.name, spec.version.serial, spec.arch));
    let staging = Staging::new(&out)?;
    let chunk_dir = staging.dir.join(CHUNKS_DIR);
    fs::create_dir(&chunk_dir).map_err(|e| io_err(&chunk_dir, e))?;
    let mut chunks: BTreeMap<String, u64> = BTreeMap::new();
    let mut files: Vec<(String, u32, u64, String, Vec<String>)> = Vec::new();
    let mut buf = vec![0u8; CHUNK_SIZE as usize];
    for (fi, rel) in tree.files.iter().enumerate() {
        if !is_safe_rel_path(rel) {
            return Err(Refusal::new(
                Code::Invalid,
                format!("payload path {rel:?} is not a safe RPK path"),
            )
            .into());
        }
        let path = payload.join(rel);
        let (mut f, _) = open_regular(&path)?;
        let md = f.metadata().map_err(|e| io_err(&path, e))?;
        let mode = md.mode() & 0o7777;
        // Every file but the SBOM is sealed in a sealed build.
        let seal = sealer
            .as_ref()
            .filter(|_| spec.sbom_path.as_deref() != Some(rel.as_str()));
        let expect = md.len();
        let count = u32::try_from(expect.div_ceil(CHUNK_SIZE))
            .map_err(|_| Refusal::new(Code::TooLarge, format!("{rel}: too large")))?;
        let fi = u32::try_from(fi)
            .map_err(|_| Refusal::new(Code::TooLarge, "too many payload files"))?;
        let mut whole = robodr_blackbox::crypto::Sha256::new();
        let mut keyed = seal.map(|s| s.file_digest());
        let mut size = 0u64;
        let mut refs = Vec::new();
        loop {
            let n = read_full(&mut f, &mut buf, &path)?;
            if n == 0 {
                break;
            }
            let piece = &buf[..n];
            size += n as u64;
            let stored = match (seal, keyed.as_mut()) {
                (Some(s), Some(k)) => {
                    k.update(piece);
                    let pos = refs.len() as u32;
                    if pos >= count {
                        return Err(Fail::Io(format!("{}: changed while read", path.display())));
                    }
                    std::borrow::Cow::Owned(s.seal_piece(fi, pos, count, piece).map_err(seal_fail)?)
                }
                _ => {
                    whole.update(piece);
                    std::borrow::Cow::Borrowed(piece)
                }
            };
            let h = sha256_hex(&stored);
            if !chunks.contains_key(&h) {
                write_new(&chunk_dir.join(&h), &stored)?;
                chunks.insert(h.clone(), stored.len() as u64);
            }
            refs.push(h);
            if n < buf.len() {
                break;
            }
        }
        if seal.is_some() && size != expect {
            return Err(Fail::Io(format!("{}: changed while read", path.display())));
        }
        let digest = match keyed {
            Some(k) => robodr_blackbox::crypto::to_hex(&k.finalize()),
            None => robodr_blackbox::crypto::to_hex(&whole.finalize()),
        };
        files.push((rel.clone(), mode, size, digest, refs));
    }
    let index: BTreeMap<&str, u32> = chunks
        .keys()
        .enumerate()
        .map(|(i, h)| (h.as_str(), i as u32))
        .collect();
    let content: Vec<ContentFile> = files
        .iter()
        .map(|(path, mode, size, sha, refs)| ContentFile {
            path: path.clone(),
            mode: *mode,
            size: *size,
            sha256: sha.clone(),
            chunks: refs.iter().map(|h| index[h.as_str()]).collect(),
        })
        .collect();
    let sbom = match &spec.sbom_path {
        None => None,
        Some(p) => {
            let c = content.iter().find(|c| &c.path == p).ok_or_else(|| {
                Refusal::new(
                    Code::Invalid,
                    format!("sbom_path {p:?} is not a payload file"),
                )
            })?;
            let bytes = read_capped(&payload.join(p), rpk::MAX_SBOM_BYTES as usize)?;
            check_cyclonedx(&bytes)?;
            Some(c.sha256.clone())
        }
    };
    let m = Manifest {
        format: RPK_FORMAT.into(),
        name: spec.name.clone(),
        version: spec.version.clone(),
        kind: spec.kind,
        platform: spec.platform.clone(),
        arch: spec.arch,
        hw_compat: spec.hw_compat.clone(),
        requires: spec.requires.clone(),
        conflicts: spec.conflicts.clone(),
        security_floor: spec.security_floor,
        confidentiality: if sealer.is_some() {
            Confidentiality::Sealed
        } else {
            Confidentiality::Public
        },
        content,
        chunks: chunks
            .iter()
            .map(|(h, s)| Chunk {
                sha256: h.clone(),
                size: *s,
            })
            .collect(),
        sbom,
        install: spec.install.clone(),
        health: spec.health.clone(),
        expires_at: spec.expires_at,
        seal: match (&sealer, seal_to) {
            (Some(s), Some(to)) => Some(s.seal_member(to).map_err(seal_fail)?),
            _ => None,
        },
    };
    drop(sealer);
    let bytes = to_canonical(&m)?;
    // Self-check through the same parser every verifier uses.
    let parsed = rpk::parse_manifest(&bytes)?;
    write_new(&staging.dir.join(MANIFEST_FILE), &bytes)?;
    staging.publish(&out)?;
    Ok(BuiltRpk {
        dir: out,
        digest: rpk::rpk_digest(&bytes),
        manifest: parsed,
    })
}

fn seal_fail(e: robodr_seal::SealError) -> Fail {
    Fail::Refused(Refusal::new(Code::Invalid, format!("sealing: {e}")))
}

/// Minimal CycloneDX check of an SBOM: a JSON object with
/// `"bomFormat": "CycloneDX"` and a string `specVersion`.
pub fn check_cyclonedx(bytes: &[u8]) -> Result<(), Fail> {
    let v: serde_json::Value = serde_json::from_slice(bytes)
        .map_err(|e| Refusal::new(Code::Invalid, format!("SBOM is not JSON: {e}")))?;
    if v.get("bomFormat").and_then(|x| x.as_str()) != Some("CycloneDX")
        || !v.get("specVersion").is_some_and(|x| x.is_string())
    {
        return Err(Refusal::new(Code::Invalid, "SBOM is not a CycloneDX JSON document").into());
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Verify an RPK directory
// ---------------------------------------------------------------------------

/// Read a chunk file of an RPK directory (bounded by its manifest size).
fn read_chunk(dir: &Path, c: &Chunk) -> Result<Vec<u8>, Refusal> {
    read_capped(&dir.join(CHUNKS_DIR).join(&c.sha256), c.size as usize).map_err(|e| match e {
        Fail::Refused(r) => r,
        Fail::Io(s) => Refusal::new(Code::MissingFile, s),
    })
}

/// Verify an RPK directory: exact tree, release quorum, site policy and
/// every chunk and content hash.
pub fn verify_rpk_dir(
    dir: &Path,
    trust: &VerifiedTrust,
    now: u64,
) -> Result<VerifiedManifest, Fail> {
    let mbytes = read_capped(&dir.join(MANIFEST_FILE), MAX_MANIFEST_BYTES)?;
    let sbytes = read_capped(&dir.join(SIGNATURE_FILE), MAX_SIGSET_BYTES)?;
    let v = rpk::verify_manifest(&mbytes, &sbytes, trust, now)?;
    check_rpk_tree(dir, &v.manifest, true)?;
    rpk::verify_content(&v.manifest, &mut |c| read_chunk(dir, c))?;
    Ok(v)
}

fn check_rpk_tree(dir: &Path, m: &Manifest, with_sig: bool) -> Result<(), Fail> {
    let mut want: BTreeSet<String> = m.chunk_paths().collect();
    want.insert(MANIFEST_FILE.into());
    let tree = walk(dir)?;
    if with_sig || tree.files.contains(SIGNATURE_FILE) {
        want.insert(SIGNATURE_FILE.into());
    }
    require_exact(dir, &tree, &want)
}

// ---------------------------------------------------------------------------
// Sign
// ---------------------------------------------------------------------------

/// What `sign` signs.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Target {
    Rpk(PathBuf),
    Bundle(PathBuf),
    Trust(PathBuf),
    Deployment(PathBuf),
}

impl Target {
    /// An RPK or bundle directory, or a trust / deployment file (told
    /// apart by its `format`).
    pub fn detect(path: &Path) -> Result<Self, Fail> {
        let m = fs::symlink_metadata(path).map_err(|e| io_err(path, e))?;
        if m.file_type().is_dir() {
            if path.join(MANIFEST_FILE).exists() {
                return Ok(Target::Rpk(path.into()));
            }
            if path.join(BUNDLE_FILE).exists() {
                return Ok(Target::Bundle(path.into()));
            }
            return Err(Fail::Io(format!(
                "{}: neither an RPK nor a bundle directory",
                path.display()
            )));
        }
        let bytes = read_capped(path, MAX_TRUST_BYTES.max(MAX_DEPLOYMENT_BYTES))?;
        #[derive(Deserialize)]
        struct F {
            format: String,
        }
        let f: F = serde_json::from_slice(&bytes)
            .map_err(|e| Refusal::new(Code::Malformed, format!("{}: {e}", path.display())))?;
        match f.format.as_str() {
            trust::TRUST_FORMAT => Ok(Target::Trust(path.into())),
            deployment::DEPLOYMENT_FORMAT => Ok(Target::Deployment(path.into())),
            _ => Err(Refusal::new(Code::Invalid, "unknown document format").into()),
        }
    }

    /// `(document, signature file, domain)`.
    fn parts(&self) -> (PathBuf, PathBuf, &'static [u8]) {
        match self {
            Target::Rpk(d) => (
                d.join(MANIFEST_FILE),
                d.join(SIGNATURE_FILE),
                MANIFEST_SIG_DOMAIN,
            ),
            Target::Bundle(d) => (
                d.join(BUNDLE_FILE),
                d.join(BUNDLE_SIG_FILE),
                BUNDLE_SIG_DOMAIN,
            ),
            Target::Trust(p) => (p.clone(), sig_path(p), TRUST_SIG_DOMAIN),
            Target::Deployment(p) => (p.clone(), sig_path(p), DEPLOYMENT_SIG_DOMAIN),
        }
    }
}

/// Add `signer`'s signature to `target`, but only after checking what is
/// signed (a signer never signs what was not checked; 13a review finding
/// 9):
///
/// * the document parses and validates;
/// * an RPK: the files on disk are exactly what the manifest describes
///   (every chunk and content hash), the site policy (revocation, floors,
///   expiry) holds and a programme of the site delivers the package;
/// * a bundle: the files on disk are exactly the listing (every hash), the
///   programme is accepted, and every RPK in it verifies completely
///   (digest, its own release quorum, scope, policy, files, content);
/// * every signature already in the set, and the new one, is valid for
///   this document under `trust` (listed key, allowed role, not revoked,
///   verifies; for an RPK or a bundle a release key of the right
///   programme; for a trust file a root of the document or, during a
///   rotation, of `trust`). A stale or foreign entry is refused, never
///   kept.
///
/// `trust` (the site's accepted trust) is required for RPKs, bundles and
/// deployments; for a trust file it is the accepted file a rotation
/// starts from, if any. The chain position of a bundle is not checked
/// here (that needs the verifier's chain state). Returns the signature
/// file and the number of signatures in it.
pub fn sign(
    target: &Target,
    signer: &dyn Signer,
    trust: Option<&VerifiedTrust>,
    now: u64,
) -> Result<(PathBuf, usize), Fail> {
    let (doc_path, sig_file, domain) = target.parts();
    let need = |what: &str| {
        trust.ok_or_else(|| {
            Fail::Io(format!(
                "signing {what} needs the site trust (--trust, --root, --site and \
                 --trust-anchor or --no-trust-anchor)"
            ))
        })
    };
    let mut set = match fs::symlink_metadata(&sig_file) {
        Ok(_) => SignatureSet::parse(&read_capped(&sig_file, MAX_SIGSET_BYTES)?)?,
        Err(_) => SignatureSet::empty(),
    };
    match target {
        Target::Rpk(dir) => {
            let t = need("an RPK")?;
            let b = read_capped(&doc_path, MAX_MANIFEST_BYTES)?;
            let m = rpk::parse_manifest(&b)?;
            check_rpk_tree(dir, &m, false)?;
            rpk::verify_content(&m, &mut |c| read_chunk(dir, c))?;
            rpk::check_policy(&m, &rpk::rpk_digest(&b), t, now)?;
            let programme = t.programme_of_package(&m.name).ok_or_else(|| {
                Refusal::new(
                    Code::WrongScope,
                    format!(
                        "RPK {}: no programme of this site delivers that package",
                        m.name
                    ),
                )
            })?;
            set.add(signer, domain, &b)?;
            let signers = set.check(t, &[Role::Release], domain, &b)?;
            t.check_release_scope(&signers, programme, "RPK manifest")?;
        }
        Target::Bundle(dir) => {
            let t = need("a bundle")?;
            let b = read_capped(&doc_path, MAX_BUNDLE_BYTES)?;
            let m = bundle::parse_bundle(&b)?;
            if !t.accepts_programme(&m.programme) {
                return Err(Refusal::new(
                    Code::WrongScope,
                    format!(
                        "bundle: programme {} is not accepted at this site",
                        m.programme
                    ),
                )
                .into());
            }
            check_bundle_files(dir, &m, false)?;
            for e in &m.rpks {
                verify_listed_rpk(dir, &m, e, t, now)?;
            }
            set.add(signer, domain, &b)?;
            let signers = set.check(t, &[Role::Release], domain, &b)?;
            t.check_release_scope(&signers, &m.programme, "bundle")?;
        }
        Target::Trust(_) => {
            let b = read_capped(&doc_path, MAX_TRUST_BYTES)?;
            trust::parse_trust(&b)?;
            set.add(signer, domain, &b)?;
            trust::check_trust_signatures(&b, &set.to_bytes()?, trust)?;
        }
        Target::Deployment(_) => {
            let t = need("a deployment")?;
            let b = read_capped(&doc_path, MAX_DEPLOYMENT_BYTES)?;
            let d = deployment::parse_deployment(&b)?;
            if d.site != t.file().site {
                return Err(Refusal::new(
                    Code::WrongScope,
                    format!("deployment for site {}, this is {}", d.site, t.file().site),
                )
                .into());
            }
            set.add(signer, domain, &b)?;
            set.check(t, &[Role::Depot, Role::Operator], domain, &b)?;
        }
    }
    write_replace(&sig_file, &set.to_bytes()?)?;
    Ok((sig_file, set.signatures.len()))
}

/// Verify one RPK listed in a bundle completely: `MANIFEST.json` is the
/// digest the bundle names, its release quorum (of the programme owning
/// the package, which must be the bundle's), site policy, its file set in
/// the listing, and every chunk and content hash.
fn verify_listed_rpk(
    dir: &Path,
    m: &BundleManifest,
    e: &BundleRpk,
    trust: &VerifiedTrust,
    now: u64,
) -> Result<VerifiedManifest, Fail> {
    let rdir = dir.join(&e.dir);
    let mbytes = read_capped(&rdir.join(MANIFEST_FILE), MAX_MANIFEST_BYTES)?;
    if rpk::rpk_digest(&mbytes) != e.digest {
        return Err(Refusal::new(
            Code::DigestMismatch,
            format!("{}: MANIFEST.json is not the RPK bundle.json names", e.dir),
        )
        .into());
    }
    let sb = read_capped(&rdir.join(SIGNATURE_FILE), MAX_SIGSET_BYTES)?;
    let v = rpk::verify_manifest(&mbytes, &sb, trust, now).map_err(|r| r.context(&e.dir))?;
    if v.programme != m.programme {
        return Err(Refusal::new(
            Code::WrongScope,
            format!(
                "{}: package {} belongs to programme {}, not {}",
                e.dir, v.manifest.name, v.programme, m.programme
            ),
        )
        .into());
    }
    check_rpk_files(m, e, &v.manifest)?;
    rpk::verify_content(&v.manifest, &mut |c| read_chunk(&rdir, c))
        .map_err(|r| r.context(&e.dir))?;
    Ok(v)
}

// ---------------------------------------------------------------------------
// Bundles
// ---------------------------------------------------------------------------

/// Options of [`build_bundle`].
pub struct BundleOptions<'a> {
    pub programme: String,
    pub seq: u64,
    /// Hash of bundle `seq - 1` (required iff `seq > 1`).
    pub prev_hash: Option<String>,
    pub created_at: u64,
    /// Signed RPK directories.
    pub rpks: Vec<PathBuf>,
    pub trust: &'a VerifiedTrust,
    pub now: u64,
    /// `(k data files per group, m parity files per group, shard size)`.
    pub parity: Option<(usize, usize, u64)>,
    /// The bundle directory to create (must not exist).
    pub out: PathBuf,
}

/// A built (unsigned) bundle.
#[derive(Debug, Clone)]
pub struct BuiltBundle {
    pub dir: PathBuf,
    pub manifest: BundleManifest,
}

fn copy_hashed(from: &Path, to: &Path, max: u64) -> Result<(u64, String), Fail> {
    let (mut f, len) = open_regular(from)?;
    if len > max {
        return Err(Refusal::new(Code::TooLarge, format!("{}: too large", from.display())).into());
    }
    let mut out = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(to)
        .map_err(|e| io_err(to, e))?;
    let mut h = robodr_blackbox::crypto::Sha256::new();
    let mut buf = vec![0u8; IO_BUF];
    let mut n = 0u64;
    loop {
        let r = f.read(&mut buf).map_err(|e| io_err(from, e))?;
        if r == 0 {
            break;
        }
        n += r as u64;
        if n > max {
            return Err(Refusal::new(Code::TooLarge, format!("{}: grew", from.display())).into());
        }
        h.update(&buf[..r]);
        out.write_all(&buf[..r]).map_err(|e| io_err(to, e))?;
    }
    out.sync_all().map_err(|e| io_err(to, e))?;
    Ok((n, robodr_blackbox::crypto::to_hex(&h.finalize())))
}

/// Read `buf.len()` bytes at `off` (zeros past the end).
fn read_block(f: &File, off: u64, buf: &mut [u8], path: &Path) -> Result<(), Refusal> {
    buf.fill(0);
    let mut n = 0;
    while n < buf.len() {
        match f.read_at(&mut buf[n..], off + n as u64) {
            Ok(0) => break,
            Ok(r) => n += r,
            Err(e) => {
                return Err(Refusal::new(
                    Code::FileMismatch,
                    format!("{}: {e}", path.display()),
                ))
            }
        }
    }
    Ok(())
}

/// Assemble a bundle from signed RPK directories: copy each into the
/// bundle, verify the **copy** (exact tree, release quorum, site policy,
/// every hash), list every file with its hash, add parity, write
/// `bundle.json`. Signing it is a separate step ([`sign`]) by each holder
/// of a release key.
pub fn build_bundle(o: &BundleOptions<'_>) -> Result<BuiltBundle, Fail> {
    match (o.seq, &o.prev_hash) {
        (1, None) => {}
        (s, Some(_)) if s > 1 => {}
        _ => {
            return Err(Fail::Io(
                "bundle 1 takes no previous hash; every later bundle needs one".into(),
            ))
        }
    }
    let staging = Staging::new(&o.out)?;
    let mut rpks = Vec::new();
    let mut files: BTreeMap<String, (u64, String)> = BTreeMap::new();
    for src in &o.rpks {
        let mbytes = read_capped(&src.join(MANIFEST_FILE), MAX_MANIFEST_BYTES)?;
        let m = rpk::parse_manifest(&mbytes)?;
        let dir_name = m.dir_name();
        let dst = staging.dir.join(&dir_name);
        if dst.exists() {
            return Err(Refusal::new(Code::Invalid, format!("two RPKs named {dir_name}")).into());
        }
        fs::create_dir(&dst).map_err(|e| io_err(&dst, e))?;
        fs::create_dir(dst.join(CHUNKS_DIR)).map_err(|e| io_err(&dst, e))?;
        let tree = walk(src)?;
        let mut want: BTreeSet<String> = m.chunk_paths().collect();
        want.insert(MANIFEST_FILE.into());
        want.insert(SIGNATURE_FILE.into());
        require_exact(src, &tree, &want)?;
        for rel in &want {
            let (size, sha) = copy_hashed(
                &src.join(rel),
                &dst.join(rel),
                MAX_MANIFEST_BYTES.max(CHUNK_SIZE as usize) as u64,
            )?;
            files.insert(format!("{dir_name}/{rel}"), (size, sha));
        }
        let v = verify_rpk_dir(&dst, o.trust, o.now)
            .map_err(|e| prefix(e, &format!("RPK {}", src.display())))?;
        if v.programme != o.programme {
            return Err(Refusal::new(
                Code::WrongScope,
                format!(
                    "RPK {}: package {} belongs to programme {}, not {}",
                    src.display(),
                    v.manifest.name,
                    v.programme,
                    o.programme
                ),
            )
            .into());
        }
        rpks.push(BundleRpk {
            dir: dir_name,
            name: v.manifest.name.clone(),
            serial: v.manifest.version.serial,
            arch: v.manifest.arch,
            digest: v.digest,
        });
    }
    rpks.sort_by(|a, b| a.dir.cmp(&b.dir));
    let mut manifest = BundleManifest {
        format: BUNDLE_FORMAT.into(),
        programme: o.programme.clone(),
        bundle_seq: o.seq,
        prev_bundle_hash: o.prev_hash.clone(),
        created_at: o.created_at,
        rpks,
        files: Vec::new(),
        parity: None,
    };
    if let Some((k, m, shard)) = o.parity {
        let data: Vec<(&String, &(u64, String))> = files.iter().collect();
        let sizes: Vec<u64> = data.iter().map(|(_, (s, _))| *s).collect();
        let lay = parity::layout(&sizes, k, m, shard)?;
        let pdir = staging.dir.join(parity::PARITY_DIR);
        fs::create_dir(&pdir).map_err(|e| io_err(&pdir, e))?;
        let mut new_files = Vec::new();
        for (g, (range, len)) in lay.iter().enumerate() {
            let members: Vec<PathBuf> = data[range.clone()]
                .iter()
                .map(|(p, _)| staging.dir.join(p))
                .collect();
            let opened: Vec<File> = members
                .iter()
                .map(|p| File::open(p).map_err(|e| io_err(p, e)))
                .collect::<Result<_, _>>()?;
            let ppaths: Vec<PathBuf> = (1..=m)
                .map(|j| staging.dir.join(parity::parity_path(g + 1, j)))
                .collect();
            let pfiles: Vec<File> = ppaths
                .iter()
                .map(|p| {
                    OpenOptions::new()
                        .write(true)
                        .create_new(true)
                        .open(p)
                        .map_err(|e| io_err(p, e))
                })
                .collect::<Result<_, _>>()?;
            let kg = range.len();
            parity::encode_group(
                kg,
                m,
                *len,
                shard,
                &mut |pos, off, buf| read_block(&opened[pos], off, buf, &members[pos]),
                &mut |pos, off, bytes| {
                    pfiles[pos - kg]
                        .write_all_at(bytes, off)
                        .map_err(|e| Refusal::new(Code::FileMismatch, format!("parity write: {e}")))
                },
            )?;
            for (j, p) in ppaths.iter().enumerate() {
                pfiles[j].sync_all().map_err(|e| io_err(p, e))?;
                let (size, sha) = hash_file(p)?;
                new_files.push((parity::parity_path(g + 1, j + 1), (size, sha)));
            }
        }
        files.extend(new_files);
        manifest.parity = Some(BundleParity {
            scheme: PARITY_SCHEME.into(),
            data_shards: k as u32,
            parity_shards: m as u32,
            shard_size: shard,
            groups: lay.len() as u32,
        });
    }
    manifest.files = files
        .into_iter()
        .map(|(path, (size, sha256))| BundleFile { path, size, sha256 })
        .collect();
    let bytes = to_canonical(&manifest)?;
    let parsed = bundle::parse_bundle(&bytes)?;
    if !o.trust.accepts_programme(&parsed.programme) {
        return Err(Refusal::new(Code::WrongScope, "programme not in the trust file").into());
    }
    write_new(&staging.dir.join(BUNDLE_FILE), &bytes)?;
    staging.publish(&o.out)?;
    Ok(BuiltBundle {
        dir: o.out.clone(),
        manifest: parsed,
    })
}

fn prefix(e: Fail, what: &str) -> Fail {
    match e {
        Fail::Refused(r) => Fail::Refused(r.context(what)),
        Fail::Io(s) => Fail::Io(format!("{what}: {s}")),
    }
}

/// The exact tree and every listed file's size and hash.
fn check_bundle_files(dir: &Path, m: &BundleManifest, with_sig: bool) -> Result<(), Fail> {
    let tree = walk(dir)?;
    let mut want: BTreeSet<String> = m.files.iter().map(|f| f.path.clone()).collect();
    want.insert(BUNDLE_FILE.into());
    if with_sig || tree.files.contains(BUNDLE_SIG_FILE) {
        want.insert(BUNDLE_SIG_FILE.into());
    }
    require_exact(dir, &tree, &want)?;
    for f in &m.files {
        // Never read past the listed size (13a review finding 7: a sparse
        // multi-terabyte file must be refused by its size, not hashed).
        let ok =
            matches!(hash_file_listed(&dir.join(&f.path), f.size)?, Some(sha) if sha == f.sha256);
        if !ok {
            let hint = if m.parity.is_some() {
                " (the bundle carries parity: try `robodr-release repair`)"
            } else {
                ""
            };
            return Err(Refusal::new(
                Code::FileMismatch,
                format!("{} differs from bundle.json{hint}", f.path),
            )
            .into());
        }
    }
    Ok(())
}

/// How `verify` joins the programme's chain.
#[derive(Debug, Clone)]
pub enum ChainMode {
    /// First bundle of the programme here.
    Genesis,
    /// The operator names the accepted head.
    After { seq: u64, hash: String },
    /// A chain state file (`robodr-bundle-chain/1`).
    State(PathBuf),
}

/// Result of [`verify_bundle_dir`].
#[derive(Debug, Clone)]
pub struct BundleReport {
    pub bundle: VerifiedBundle,
    pub step: ChainStep,
    pub rpks: Vec<VerifiedManifest>,
}

/// Verify a bundle directory completely: trust, release quorum on
/// `bundle.json`, chain, exact tree, every file hash, then each RPK
/// (digest, release quorum, site policy, file set, content hashes).
pub fn verify_bundle_dir(
    dir: &Path,
    site: &SiteTrust,
    chain: &ChainMode,
    now: u64,
) -> Result<BundleReport, Fail> {
    let trust = &site.trust;
    // The chain state first: it also pins the site and the trust file
    // version the head was accepted under, and an older trust file (e.g.
    // one from before a key revocation) or another site's is refused
    // whatever it would let through. A newer one is acceptable only as a
    // rotation of the site's trust anchor (never on the state's word), so
    // the state path needs the anchor.
    let state = match chain {
        ChainMode::State(p) => {
            let Some(a) = &site.anchor else {
                return Err(Fail::Io(
                    "a chain state needs the site's trust anchor (--trust-anchor)".into(),
                ));
            };
            let st = bundle::ChainState::parse(&read_capped(p, 4096)?)?;
            if st.trust_version > a.trust.file().version {
                return Err(Refusal::new(
                    Code::Replay,
                    format!(
                        "the trust anchor (version {}) is older than the trust file this chain \
                         was accepted under (version {}): the anchor was rolled back or replaced",
                        a.trust.file().version,
                        st.trust_version
                    ),
                )
                .into());
            }
            bundle::check_trust(&st, trust)?;
            Some(st)
        }
        _ => None,
    };
    let bbytes = read_capped(&dir.join(BUNDLE_FILE), MAX_BUNDLE_BYTES)?;
    let sbytes = read_capped(&dir.join(BUNDLE_SIG_FILE), MAX_SIGSET_BYTES)?;
    let vb = verify_bundle_manifest(&bbytes, &sbytes, trust)?;
    let anchor = match (chain, state) {
        (_, Some(st)) => ChainAnchor::Head(st),
        (ChainMode::After { seq, hash }, None) => ChainAnchor::Head(bundle::ChainState {
            // The operator names the head; the trust file is as accepted.
            format: bundle::CHAIN_FORMAT.into(),
            site: trust.file().site.clone(),
            programme: vb.manifest.programme.clone(),
            bundle_seq: *seq,
            bundle_hash: hash.clone(),
            trust_version: trust.file().version,
            trust_digest: trust.digest.clone(),
        }),
        _ => ChainAnchor::Genesis,
    };
    let step = check_chain(&anchor, &vb)?;
    check_bundle_files(dir, &vb.manifest, true)?;
    let mut rpks = Vec::new();
    for e in &vb.manifest.rpks {
        rpks.push(verify_listed_rpk(dir, &vb.manifest, e, trust, now)?);
    }
    Ok(BundleReport {
        bundle: vb,
        step,
        rpks,
    })
}

/// Import a bundle from untrusted media (13a review finding 6): the
/// verify-then-use gap on removable media is closed by never using the
/// media's bytes after a check. `bundle.json` is authenticated first
/// (release quorum, programme), the media tree must be exactly its listing
/// (no symlink, special file, stray file or directory), every listed file
/// is copied into a staging directory next to `to` reading at most its
/// listed size and hashing while copying, and then the **copy** is
/// verified completely (chain, tree, every hash, every RPK) before it is
/// renamed to `to`. Only `to` may be used afterwards; the media may
/// change at will (a malicious USB device serving other bytes on a second
/// read) without effect. `to` must not exist and should be on trusted
/// local storage.
pub fn import_bundle(
    from: &Path,
    to: &Path,
    site: &SiteTrust,
    chain: &ChainMode,
    now: u64,
) -> Result<BundleReport, Fail> {
    let bbytes = read_capped(&from.join(BUNDLE_FILE), MAX_BUNDLE_BYTES)?;
    let sbytes = read_capped(&from.join(BUNDLE_SIG_FILE), MAX_SIGSET_BYTES)?;
    let vb = verify_bundle_manifest(&bbytes, &sbytes, &site.trust)?;
    let tree = walk(from)?;
    let mut want: BTreeSet<String> = vb.manifest.files.iter().map(|f| f.path.clone()).collect();
    want.insert(BUNDLE_FILE.into());
    want.insert(BUNDLE_SIG_FILE.into());
    require_exact(from, &tree, &want)?;
    let staging = Staging::new(to)?;
    write_new(&staging.dir.join(BUNDLE_FILE), &bbytes)?;
    write_new(&staging.dir.join(BUNDLE_SIG_FILE), &sbytes)?;
    for f in &vb.manifest.files {
        // Paths follow the bundle grammar (no traversal is expressible).
        ensure_dirs(&staging.dir, &f.path)?;
        let (n, sha) = copy_hashed(&from.join(&f.path), &staging.dir.join(&f.path), f.size)?;
        if n != f.size || sha != f.sha256 {
            return Err(Refusal::new(
                Code::FileMismatch,
                format!("{} differs from bundle.json", f.path),
            )
            .into());
        }
    }
    let r = verify_bundle_dir(&staging.dir, site, chain, now)
        .map_err(|e| prefix(e, "the imported copy"))?;
    if r.bundle.hash != vb.hash {
        return Err(Refusal::new(Code::DigestMismatch, "the imported copy changed").into());
    }
    staging.publish(to)?;
    Ok(r)
}

/// Persist the chain head after an accepted bundle, with the trust file
/// it was accepted under (atomic replace). The site's trust anchor is
/// advanced first when the bundle was accepted under a rotation of it, so
/// a chain state never records a trust version above the anchor's.
pub fn commit_chain(state: &Path, b: &VerifiedBundle, site: &SiteTrust) -> Result<(), Fail> {
    if site.anchor.is_none() {
        return Err(Fail::Io(
            "committing a chain state needs the site's trust anchor (--trust-anchor)".into(),
        ));
    }
    commit_anchor(site)?;
    write_replace(
        state,
        &bundle::ChainState::after(b, &site.trust).to_bytes()?,
    )
}

/// Rebuild missing or damaged files of a bundle from its parity. The
/// bundle manifest is authenticated first (release quorum), so only files
/// whose hash a valid `bundle.json` names are ever written; each rebuilt
/// file is hash-checked before it is renamed into place. Returns the
/// rebuilt paths. Run `verify` afterwards.
pub fn repair_bundle(dir: &Path, trust: &VerifiedTrust) -> Result<Vec<String>, Fail> {
    let bbytes = read_capped(&dir.join(BUNDLE_FILE), MAX_BUNDLE_BYTES)?;
    let sbytes = read_capped(&dir.join(BUNDLE_SIG_FILE), MAX_SIGSET_BYTES)?;
    let vb = verify_bundle_manifest(&bbytes, &sbytes, trust)?;
    let m = &vb.manifest;
    let p = m
        .parity
        .as_ref()
        .ok_or_else(|| Refusal::new(Code::Invalid, "bundle has no parity"))?;
    let groups = parity::plan(m)?;
    let mut rebuilt = Vec::new();
    for g in &groups {
        let members = g.members();
        let k = g.data.len();
        let mut erased = Vec::new();
        for (pos, &i) in members.iter().enumerate() {
            let f = &m.files[i];
            let ok = matches!(hash_file_listed(&dir.join(&f.path), f.size), Ok(Some(h)) if h == f.sha256);
            if !ok {
                erased.push(pos);
            }
        }
        if erased.is_empty() {
            continue;
        }
        let known: Vec<Option<File>> = members
            .iter()
            .enumerate()
            .map(|(pos, &i)| {
                if erased.contains(&pos) {
                    Ok(None)
                } else {
                    open_regular(&dir.join(&m.files[i].path)).map(|(f, _)| Some(f))
                }
            })
            .collect::<Result<_, _>>()?;
        let mut outs: BTreeMap<usize, (PathBuf, File)> = BTreeMap::new();
        for &pos in &erased {
            let rel = &m.files[members[pos]].path;
            ensure_dirs(dir, rel)?;
            let target = dir.join(rel);
            let tmp = sibling(&target, "repair");
            let f = OpenOptions::new()
                .write(true)
                .create_new(true)
                .open(&tmp)
                .map_err(|e| io_err(&tmp, e))?;
            outs.insert(pos, (tmp, f));
        }
        let res = parity::rebuild_group(
            k,
            p.parity_shards as usize,
            g.len,
            p.shard_size,
            &erased,
            &mut |pos, off, buf| match &known[pos] {
                Some(f) => read_block(f, off, buf, &dir.join(&m.files[members[pos]].path)),
                None => Err(Refusal::new(Code::FileMismatch, "read of an erased member")),
            },
            &mut |pos, off, bytes| {
                let size = m.files[members[pos]].size;
                let keep = if pos < k {
                    size.saturating_sub(off).min(bytes.len() as u64) as usize
                } else {
                    bytes.len()
                };
                let (_, f) = &outs[&pos];
                f.write_all_at(&bytes[..keep], off)
                    .map_err(|e| Refusal::new(Code::FileMismatch, format!("repair write: {e}")))
            },
        );
        let cleanup = |outs: &BTreeMap<usize, (PathBuf, File)>| {
            for (tmp, _) in outs.values() {
                let _ = fs::remove_file(tmp);
            }
        };
        if let Err(e) = res {
            cleanup(&outs);
            return Err(e.into());
        }
        for (pos, (tmp, f)) in &outs {
            let entry = &m.files[members[*pos]];
            f.sync_all().map_err(|e| io_err(tmp, e))?;
            let ok = matches!(hash_file_listed(tmp, entry.size)?, Some(sha) if sha == entry.sha256);
            if !ok {
                cleanup(&outs);
                return Err(Refusal::new(
                    Code::FileMismatch,
                    format!("{}: rebuilt bytes do not match bundle.json", entry.path),
                )
                .into());
            }
        }
        for (pos, (tmp, _)) in &outs {
            let entry = &m.files[members[*pos]];
            let target = dir.join(&entry.path);
            if let Ok(meta) = fs::symlink_metadata(&target) {
                if meta.file_type().is_dir() {
                    fs::remove_dir_all(&target).map_err(|e| io_err(&target, e))?;
                }
            }
            fs::rename(tmp, &target).map_err(|e| io_err(&target, e))?;
            rebuilt.push(entry.path.clone());
        }
    }
    Ok(rebuilt)
}

// ---------------------------------------------------------------------------
// Deployments
// ---------------------------------------------------------------------------

/// Verify a deployment file (and its `.sig`).
pub fn verify_deployment_file(
    path: &Path,
    trust: &VerifiedTrust,
    now: u64,
) -> Result<VerifiedDeployment, Fail> {
    let doc = read_capped(path, MAX_DEPLOYMENT_BYTES)?;
    let sig = read_capped(&sig_path(path), MAX_SIGSET_BYTES)?;
    Ok(deployment::verify_deployment(&doc, &sig, trust, now)?)
}

/// Hash of a bundle directory's `bundle.json` (for `--prev-bundle`), and
/// its sequence number and programme.
pub fn bundle_head(dir: &Path) -> Result<(String, u64, String), Fail> {
    let b = read_capped(&dir.join(BUNDLE_FILE), MAX_BUNDLE_BYTES)?;
    let m = bundle::parse_bundle(&b)?;
    Ok((bundle::bundle_hash(&b), m.bundle_seq, m.programme))
}

/// Re-export for the CLI.
pub use fsio::walk as walk_tree;
