//! Per-unit media packs (`robodr-media-pack/1`) and their import.
//!
//! ```text
//! <pack>/                       a directory under media_dir (untrusted)
//!   trust.json, trust.json.sig            the site trust file (root quorum)
//!   deployment.json, deployment.json.sig  one deployment naming this unit (depot + operators)
//!   bundles/<label>/                      1..=16 robodr-bundle/1 directories (release quorum)
//! ```
//!
//! Nothing else may be in the pack (a stray file, a symlink or a special
//! file anywhere refuses it). The pack carries no signature of its own:
//! every part is a signed document, and the pack is "for this unit" only
//! because its deployment names the unit (14a adds the per-unit key
//! wraps that make it useless elsewhere).
//!
//! # Import: only the verified copy is used
//!
//! As `robodr-release import` (§3.5 item 30): the small documents are read
//! once (bounded) and written into a staging directory in the state
//! directory; the trust file is accepted only as the unit's trust anchor
//! or a rotation of it, under the pinned roots and the unit's own site;
//! the deployment is verified against it (depot + operator quorum, ring
//! bound to targets, revocations, floors, validity) and against the unit
//! (unit id, ring, groups, rollout limits, sequence); each bundle goes
//! through `robodr_release::ops::import_bundle`, which authenticates
//! `bundle.json`, copies every listed file bounded by its size while
//! hashing it, and verifies the **copy** completely. Only after all of it
//! passed is the staging directory renamed to `packs/<seq>-<digest>`;
//! the agent never reads the media again for this pack.
//!
//! # Bundle chains on a unit
//!
//! The authority for *what* a unit installs is the deployment (exact RPK
//! digests, sequence-protected). Bundles chain per programme for
//! detection: the unit keeps a head per programme and reports a gap
//! (`robot.deliver.chain_gap`, accepted: a unit receives only the bundles
//! that carry its packages), refuses an equivocation (same sequence,
//! other bytes) and a broken link (next sequence, other predecessor), and
//! takes an older bundle as a content source without moving its head.

use crate::clock::effective_now;
use crate::config::{ClockTrust, Config};
use crate::state::State;
use robodr_pkg::bundle::{
    self, ChainState, VerifiedBundle, BUNDLE_FILE, BUNDLE_SIG_FILE, MAX_BUNDLE_BYTES,
};
use robodr_pkg::common::{is_label, sha256_hex};
use robodr_pkg::deployment::{
    self, check_seq, is_prod_ring, LastDeployment as PkgLast, SeqStep, VerifiedDeployment,
    MAX_DEPLOYMENT_BYTES,
};
use robodr_pkg::rpk::{Manifest, VerifiedManifest, MANIFEST_FILE};
use robodr_pkg::sig::MAX_SIGSET_BYTES;
use robodr_pkg::trust::MAX_TRUST_BYTES;
use robodr_pkg::{Code, Refusal};
use robodr_release::fsio::{read_capped, Fail};
use robodr_release::ops::{import_bundle, ChainMode, SiteTrust};
use std::collections::BTreeMap;
use std::fs;
use std::path::{Path, PathBuf};

/// `format` name of a media pack (documentation; the layout is fixed).
pub const PACK_FORMAT: &str = "robodr-media-pack/1";
/// Most bundles in a pack.
pub const MAX_BUNDLES: usize = 16;
/// Most media entries looked at per scan.
pub const MAX_MEDIA_ENTRIES: usize = 32;
/// The fixed top-level names of a pack.
pub const TRUST_FILE: &str = "trust.json";
pub const DEPLOYMENT_FILE: &str = "deployment.json";
pub const BUNDLES_DIR: &str = "bundles";

/// A refusal of a pack, with what it means for findings.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Refused {
    pub code: Code,
    pub detail: String,
    /// A freshness problem (`robot.deliver.stale`).
    pub stale: bool,
    /// A chain problem (`robot.deliver.chain_gap`).
    pub chain: bool,
    /// A problem of this host, not of the pack (retried, not remembered).
    pub transient: bool,
}

impl Refused {
    fn of(r: Refusal) -> Self {
        let chain = matches!(r.code, Code::Equivocation | Code::ChainBroken);
        let stale = r.code == Code::Expired;
        Self {
            code: r.code,
            detail: r.detail,
            stale,
            chain,
            transient: false,
        }
    }

    fn new(code: Code, detail: impl Into<String>) -> Self {
        Self::of(Refusal::new(code, detail))
    }

    fn io(detail: impl Into<String>) -> Self {
        Self {
            code: Code::Invalid,
            detail: detail.into(),
            stale: false,
            chain: false,
            transient: true,
        }
    }

    fn from_fail(f: Fail) -> Self {
        match f {
            Fail::Refused(r) => Self::of(r),
            // An I/O problem reading the media: the pack is bad as given.
            Fail::Io(s) => Self::new(Code::Invalid, s),
        }
    }
}

impl std::fmt::Display for Refused {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "refused ({}): {}", self.code.as_str(), self.detail)
    }
}

/// What happened to one bundle of an imported pack.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
pub struct BundleStep {
    pub programme: String,
    pub seq: u64,
    pub hash: String,
    /// `genesis`, `next`, `join` (first bundle seen here), `gap`, `same`,
    /// `older` (content only).
    pub step: &'static str,
    /// For a gap: the head it skipped from.
    pub after: Option<u64>,
}

/// An imported (verified, copied) pack.
#[derive(Debug, Clone)]
pub struct Imported {
    /// Directory name under `<state_dir>/packs/`.
    pub pack: String,
    pub deployment: VerifiedDeployment,
    pub trust: SiteTrust,
    pub ring: String,
    pub bundles: Vec<BundleStep>,
    /// New chain heads (to store).
    pub heads: Vec<ChainState>,
    /// Item digest -> verified manifest.
    pub manifests: BTreeMap<String, VerifiedManifest>,
    /// The effective time the pack was judged at.
    pub now: u64,
    /// The new time floor.
    pub time_floor: u64,
    /// SHA-256 of the media's `deployment.json` bytes.
    pub media_sha: String,
}

/// Outcome of an import attempt.
#[derive(Debug, Clone)]
pub enum Outcome {
    /// This exact deployment is the accepted one already.
    AlreadyAccepted,
    Imported(Box<Imported>),
}

/// The media entries (real directories with label names), sorted.
pub fn list_media(media_dir: &Path) -> Vec<(String, PathBuf)> {
    let Ok(rd) = fs::read_dir(media_dir) else {
        return Vec::new();
    };
    let mut out = Vec::new();
    for e in rd.flatten().take(1024) {
        let Ok(name) = e.file_name().into_string() else {
            continue;
        };
        if !is_label(&name) {
            continue;
        }
        let p = e.path();
        if crate::fsx::is_real_dir(&p) {
            out.push((name, p));
        }
    }
    out.sort();
    out.truncate(MAX_MEDIA_ENTRIES);
    out
}

/// SHA-256 of a pack's `deployment.json` (bounded read), to recognise a
/// pack already handled without judging it again.
pub fn media_key(pack: &Path) -> Option<String> {
    read_capped(&pack.join(DEPLOYMENT_FILE), MAX_DEPLOYMENT_BYTES)
        .ok()
        .map(|b| sha256_hex(&b))
}

/// The exact top-level layout: four files and `bundles/` with 1..=16
/// label-named real directories.
fn check_layout(pack: &Path) -> Result<Vec<(String, PathBuf)>, Refused> {
    let want = [
        TRUST_FILE.to_string(),
        format!("{TRUST_FILE}.sig"),
        DEPLOYMENT_FILE.to_string(),
        format!("{DEPLOYMENT_FILE}.sig"),
        BUNDLES_DIR.to_string(),
    ];
    let rd =
        fs::read_dir(pack).map_err(|e| Refused::new(Code::MissingFile, format!("pack: {e}")))?;
    let mut seen = Vec::new();
    for e in rd.take(64) {
        let e = e.map_err(|e| Refused::new(Code::Invalid, format!("pack: {e}")))?;
        let name = e.file_name().to_string_lossy().into_owned();
        if !want.contains(&name) {
            return Err(Refused::new(
                Code::UnexpectedFile,
                format!(
                    "pack: {} is not part of a media pack",
                    robodr_pkg::common::trunc(&name)
                ),
            ));
        }
        let md = fs::symlink_metadata(e.path())
            .map_err(|e| Refused::new(Code::Invalid, e.to_string()))?;
        let ok = if name == BUNDLES_DIR {
            md.file_type().is_dir()
        } else {
            md.file_type().is_file()
        };
        if !ok {
            return Err(Refused::new(
                Code::FileMismatch,
                format!("pack: {name} is a symlink or of the wrong type"),
            ));
        }
        seen.push(name);
    }
    if let Some(m) = want.iter().find(|w| !seen.contains(w)) {
        return Err(Refused::new(
            Code::MissingFile,
            format!("pack: {m} is missing"),
        ));
    }
    let bdir = pack.join(BUNDLES_DIR);
    let mut bundles = Vec::new();
    let rd = fs::read_dir(&bdir).map_err(|e| Refused::new(Code::Invalid, format!("pack: {e}")))?;
    for e in rd.take(MAX_BUNDLES + 1) {
        let e = e.map_err(|e| Refused::new(Code::Invalid, format!("pack: {e}")))?;
        let name = e.file_name().to_string_lossy().into_owned();
        let md = fs::symlink_metadata(e.path())
            .map_err(|e| Refused::new(Code::Invalid, e.to_string()))?;
        if !is_label(&name) || !md.file_type().is_dir() {
            return Err(Refused::new(
                Code::UnexpectedFile,
                format!(
                    "pack: bundles/{} is not a bundle directory",
                    robodr_pkg::common::trunc(&name)
                ),
            ));
        }
        bundles.push((name, e.path()));
    }
    if bundles.is_empty() || bundles.len() > MAX_BUNDLES {
        return Err(Refused::new(
            Code::Invalid,
            format!("pack: 1..={MAX_BUNDLES} bundles"),
        ));
    }
    bundles.sort();
    Ok(bundles)
}

/// The unit's own ring: from the root-signed trust file, else enrolment
/// (`unit.ring`, a production ring only).
pub fn own_ring(cfg: &Config, trust: &robodr_pkg::trust::VerifiedTrust) -> Option<String> {
    trust
        .ring_of_unit(&cfg.unit.id)
        .map(str::to_string)
        .or_else(|| cfg.unit.ring.clone())
}

/// The deployment is for this unit (§10, 13b requirements 3 and 4).
pub fn check_unit(
    cfg: &Config,
    trust: &robodr_pkg::trust::VerifiedTrust,
    d: &deployment::Deployment,
) -> Result<String, Refused> {
    let Some(ring) = own_ring(cfg, trust) else {
        return Err(Refused::new(
            Code::WrongScope,
            format!(
                "unit {} has no ring (none in the trust file, none enrolled)",
                cfg.unit.id
            ),
        ));
    };
    if d.ring != ring {
        return Err(Refused::new(
            Code::WrongScope,
            format!("deployment for ring {}, this unit is in {ring}", d.ring),
        ));
    }
    let named = d.targets.units.iter().any(|u| u == &cfg.unit.id);
    let by_group =
        is_prod_ring(&ring) && d.targets.groups.iter().any(|g| cfg.unit.groups.contains(g));
    if !named && !by_group {
        return Err(Refused::new(
            Code::WrongScope,
            format!(
                "deployment {} does not target unit {}{}",
                d.deployment_id,
                cfg.unit.id,
                if is_prod_ring(&ring) {
                    ""
                } else {
                    " (lab and canary deployments must name the unit itself)"
                }
            ),
        ));
    }
    if let Some(r) = trust.file().rings.iter().find(|r| r.ring == ring) {
        let size = r.units.len() as u64;
        let ro = &d.rollout;
        if d.targets.units.len() as u64 > size
            || u64::from(ro.batch_size) > size
            || u64::from(ro.max_failures) >= size.max(1)
        {
            return Err(Refused::new(
                Code::Invalid,
                format!(
                    "deployment rollout (targets {}, batch {}, max_failures {}) exceeds ring {ring} \
                     of {size} units",
                    d.targets.units.len(),
                    ro.batch_size,
                    ro.max_failures
                ),
            ));
        }
    }
    Ok(ring)
}

/// The unit-side checks of one item's manifest (architecture, platform,
/// hardware, kind, health checks, the unit's floor, dependencies against
/// the installed state plus the other items).
pub fn check_item(
    cfg: &Config,
    state: &State,
    m: &Manifest,
    items: &[(String, u64)],
) -> Result<(), Refused> {
    let u = &cfg.unit;
    if !crate::install::supported(m.kind) {
        return Err(Refused::new(
            Code::Unsupported,
            format!(
                "{}: kind {:?} is not installed by this agent (13b)",
                m.name, m.kind
            ),
        ));
    }
    if m.arch != robodr_pkg::rpk::Arch::All && m.arch != u.arch {
        return Err(Refused::new(
            Code::WrongScope,
            format!(
                "{}: built for {}, this unit is {}",
                m.name,
                m.arch.as_str(),
                u.arch.as_str()
            ),
        ));
    }
    if m.platform != u.platform {
        return Err(Refused::new(
            Code::WrongScope,
            format!(
                "{}: for platform {}, this unit is {}",
                m.name, m.platform, u.platform
            ),
        ));
    }
    if !m.hw_compat.is_empty() && !u.hw.as_ref().is_some_and(|h| m.hw_compat.contains(h)) {
        return Err(Refused::new(
            Code::WrongScope,
            format!("{}: hardware of this unit is not in hw_compat", m.name),
        ));
    }
    if let Some(h) = m.health.iter().find(|h| !crate::health::supported(h)) {
        return Err(Refused::new(
            Code::Unsupported,
            format!(
                "{}: health check {h:?} cannot be evaluated on the unit",
                m.name
            ),
        ));
    }
    let floor = state.floor(&m.name);
    if m.version.serial < floor {
        return Err(Refused::new(
            Code::BelowFloor,
            format!(
                "{} serial {} is below this unit's floor {floor} (downgrade refused)",
                m.name, m.version.serial
            ),
        ));
    }
    let have = |name: &str| -> Vec<u64> {
        let mut v: Vec<u64> = items
            .iter()
            .filter(|(n, _)| n == name)
            .map(|(_, s)| *s)
            .collect();
        if let Some(i) = state.installed.get(name) {
            v.push(i.ver.serial);
        }
        v
    };
    for r in &m.requires {
        if !have(&r.name).iter().any(|s| *s >= r.min_serial) {
            return Err(Refused::new(
                Code::Invalid,
                format!("{} requires {} >= {}", m.name, r.name, r.min_serial),
            ));
        }
    }
    for c in &m.conflicts {
        if have(&c.name).iter().any(|s| *s >= c.min_serial) {
            return Err(Refused::new(
                Code::Invalid,
                format!("{} conflicts with {} >= {}", m.name, c.name, c.min_serial),
            ));
        }
    }
    Ok(())
}

/// Find the directory of RPK `digest` in an imported pack.
pub fn find_rpk(pack_dir: &Path, digest: &str) -> Option<PathBuf> {
    let rd = fs::read_dir(pack_dir.join(BUNDLES_DIR)).ok()?;
    for e in rd.flatten() {
        let b = read_capped(&e.path().join(BUNDLE_FILE), MAX_BUNDLE_BYTES).ok()?;
        let m = bundle::parse_bundle(&b).ok()?;
        if let Some(r) = m.rpks.iter().find(|r| r.digest == digest) {
            let d = e.path().join(&r.dir);
            let mb =
                read_capped(&d.join(MANIFEST_FILE), robodr_pkg::rpk::MAX_MANIFEST_BYTES).ok()?;
            if robodr_pkg::rpk::rpk_digest(&mb) == digest {
                return Some(d);
            }
        }
    }
    None
}

/// Copy a small signed document and its `.sig` from the media into `dir`.
fn copy_doc(from: &Path, to: &Path, name: &str, max: usize) -> Result<(Vec<u8>, Vec<u8>), Refused> {
    let doc = read_capped(&from.join(name), max).map_err(Refused::from_fail)?;
    let sig_name = format!("{name}.sig");
    let sig = read_capped(&from.join(&sig_name), MAX_SIGSET_BYTES).map_err(Refused::from_fail)?;
    crate::fsx::write_new(&to.join(name), &doc, 0o600).map_err(|e| Refused::io(e.to_string()))?;
    crate::fsx::write_new(&to.join(sig_name), &sig, 0o600)
        .map_err(|e| Refused::io(e.to_string()))?;
    Ok((doc, sig))
}

/// Judge one bundle's place in its programme's chain from its
/// authenticated manifest.
fn chain_mode(
    state: &State,
    trust: &robodr_pkg::trust::VerifiedTrust,
    b: &VerifiedBundle,
) -> Result<(ChainMode, BundleStep, bool), Refused> {
    let m = &b.manifest;
    let join = || match (m.bundle_seq, &m.prev_bundle_hash) {
        (1, _) | (_, None) => ChainMode::Genesis,
        (s, Some(p)) => ChainMode::After {
            seq: s - 1,
            hash: p.clone(),
        },
    };
    let step = |s: &'static str, after: Option<u64>| BundleStep {
        programme: m.programme.clone(),
        seq: m.bundle_seq,
        hash: b.hash.clone(),
        step: s,
        after,
    };
    let Some(h) = state.chain(&m.programme) else {
        let s = if m.bundle_seq == 1 { "genesis" } else { "join" };
        return Ok((join(), step(s, None), true));
    };
    bundle::check_trust(h, trust).map_err(Refused::of)?;
    let head = ChainMode::After {
        seq: h.bundle_seq,
        hash: h.bundle_hash.clone(),
    };
    Ok(if m.bundle_seq == h.bundle_seq {
        if b.hash != h.bundle_hash {
            let mut r = Refused::new(
                Code::Equivocation,
                format!(
                    "bundle {} of {}: other content than the accepted bundle {}",
                    m.bundle_seq, m.programme, m.bundle_seq
                ),
            );
            r.chain = true;
            return Err(r);
        }
        (head, step("same", None), false)
    } else if m.bundle_seq == h.bundle_seq + 1 {
        if m.prev_bundle_hash.as_deref() != Some(h.bundle_hash.as_str()) {
            let mut r = Refused::new(
                Code::ChainBroken,
                format!(
                    "bundle {} of {} does not follow the accepted bundle {}",
                    m.bundle_seq, m.programme, h.bundle_seq
                ),
            );
            r.chain = true;
            return Err(r);
        }
        (head, step("next", None), true)
    } else if m.bundle_seq > h.bundle_seq {
        (join(), step("gap", Some(h.bundle_seq)), true)
    } else {
        (join(), step("older", None), false)
    })
}

/// Import the pack at `media` (see the module docs). `sys_now` is the
/// system clock (Unix seconds).
pub fn import(cfg: &Config, state: &State, media: &Path, sys_now: u64) -> Result<Outcome, Refused> {
    let media_sha = media_key(media)
        .ok_or_else(|| Refused::new(Code::MissingFile, "pack: no deployment.json"))?;
    let bundles = check_layout(media)?;
    let imports = cfg.state_dir.join("import");
    crate::fsx::ensure_dir(&imports, 0o700).map_err(|e| Refused::io(e.to_string()))?;
    let stage = crate::fsx::temp_sibling(&imports.join("pack"), "stage");
    crate::fsx::ensure_dir(&stage, 0o700).map_err(|e| Refused::io(e.to_string()))?;
    let res = import_into(cfg, state, media, &stage, &bundles, sys_now, media_sha);
    match res {
        Ok(Outcome::Imported(mut imp)) => {
            let packs = cfg.state_dir.join("packs");
            crate::fsx::ensure_dir(&packs, 0o700).map_err(|e| Refused::io(e.to_string()))?;
            let name = format!(
                "{}-{}",
                imp.deployment.deployment.deployment_seq,
                &imp.deployment.digest[..16]
            );
            let dst = packs.join(&name);
            let _ = crate::fsx::remove_any(&dst);
            fs::rename(&stage, &dst).map_err(|e| {
                let _ = crate::fsx::remove_any(&stage);
                Refused::io(format!("{}: {e}", dst.display()))
            })?;
            crate::fsx::sync_dir(&packs).map_err(|e| Refused::io(e.to_string()))?;
            imp.pack = name;
            Ok(Outcome::Imported(imp))
        }
        other => {
            let _ = crate::fsx::remove_any(&stage);
            other
        }
    }
}

#[allow(clippy::too_many_arguments)]
fn import_into(
    cfg: &Config,
    state: &State,
    media: &Path,
    stage: &Path,
    bundles: &[(String, PathBuf)],
    sys_now: u64,
    media_sha: String,
) -> Result<Outcome, Refused> {
    let now0 = effective_now(cfg.trust.clock, sys_now, state.time_floor);
    copy_doc(media, stage, TRUST_FILE, MAX_TRUST_BYTES)?;
    let (dbytes, dsig) = copy_doc(media, stage, DEPLOYMENT_FILE, MAX_DEPLOYMENT_BYTES)?;
    // The trust file: the unit's anchor or a rotation of it, pinned roots
    // and site (an expired one is refused at now0).
    let anchor = cfg.anchor_path();
    if fs::symlink_metadata(&anchor).is_err() {
        return Err(Refused::io(format!(
            "{}: no trust anchor (run `robodr-deliverd init-anchor` once at enrolment)",
            anchor.display()
        )));
    }
    let site = SiteTrust::anchored(
        &stage.join(TRUST_FILE),
        &anchor,
        &cfg.trust.roots,
        &cfg.unit.site,
        now0,
    )
    .map_err(|f| match f {
        Fail::Refused(r) => Refused::of(r),
        Fail::Io(s) => Refused::io(s),
    })?;
    // The deployment's signed creation time is the depot's clock.
    let unauth = deployment::parse_deployment(&dbytes).map_err(Refused::of)?;
    let now1 = match cfg.trust.clock {
        ClockTrust::Trusted => now0,
        ClockTrust::Untrusted => now0.max(unauth.created_at),
    };
    let vd = deployment::verify_deployment(&dbytes, &dsig, &site.trust, now1).map_err(|r| {
        let mut x = Refused::of(r);
        x.stale |= x.code == Code::Expired;
        x
    })?;
    if let Err(r) = site.trust.check_fresh(now1) {
        let mut x = Refused::of(r);
        x.stale = true;
        return Err(x);
    }
    let d = &vd.deployment;
    let ring = check_unit(cfg, &site.trust, d)?;
    let last = state.last_deployment.as_ref().map(|l| PkgLast {
        deployment_seq: l.seq,
        digest: l.digest.clone(),
    });
    match check_seq(last.as_ref(), &vd).map_err(Refused::of)? {
        SeqStep::AlreadyAccepted => return Ok(Outcome::AlreadyAccepted),
        SeqStep::Newer => {}
    }
    // Bundles: authenticated first, then the verified-copy import.
    let bdir = stage.join(BUNDLES_DIR);
    crate::fsx::ensure_dir(&bdir, 0o700).map_err(|e| Refused::io(e.to_string()))?;
    let mut steps = Vec::new();
    let mut heads: BTreeMap<String, ChainState> = BTreeMap::new();
    let mut manifests: BTreeMap<String, VerifiedManifest> = BTreeMap::new();
    for (label, from) in bundles {
        let bb =
            read_capped(&from.join(BUNDLE_FILE), MAX_BUNDLE_BYTES).map_err(Refused::from_fail)?;
        let sb = read_capped(&from.join(BUNDLE_SIG_FILE), MAX_SIGSET_BYTES)
            .map_err(Refused::from_fail)?;
        let vb = bundle::verify_bundle_manifest(&bb, &sb, &site.trust).map_err(Refused::of)?;
        if heads.contains_key(&vb.manifest.programme)
            || steps
                .iter()
                .any(|s: &BundleStep| s.programme == vb.manifest.programme)
        {
            return Err(Refused::new(
                Code::Invalid,
                format!("pack: two bundles of programme {}", vb.manifest.programme),
            ));
        }
        let (mode, step, advance) = chain_mode(state, &site.trust, &vb)?;
        let report = import_bundle(from, &bdir.join(label), &site, &mode, now1)
            .map_err(Refused::from_fail)?;
        if report.bundle.hash != vb.hash {
            return Err(Refused::new(
                Code::DigestMismatch,
                "pack: a bundle changed during import",
            ));
        }
        if advance {
            heads.insert(
                vb.manifest.programme.clone(),
                ChainState::after(&report.bundle, &site.trust),
            );
        }
        steps.push(step);
        for v in report.rpks {
            manifests.insert(v.digest.clone(), v);
        }
    }
    // Every item must be in the verified copy, as named, and fit the unit.
    let items: Vec<(String, u64)> = d.items.iter().map(|i| (i.name.clone(), i.serial)).collect();
    for i in &d.items {
        let Some(v) = manifests.get(&i.rpk_digest) else {
            return Err(Refused::new(
                Code::MissingFile,
                format!(
                    "deployment item {} {} is in no bundle of the pack",
                    i.name, i.serial
                ),
            ));
        };
        if v.manifest.name != i.name || v.manifest.version.serial != i.serial {
            return Err(Refused::new(
                Code::DigestMismatch,
                format!(
                    "deployment item {} {}: the RPK with that digest is another package",
                    i.name, i.serial
                ),
            ));
        }
        let others: Vec<(String, u64)> = items
            .iter()
            .filter(|(n, _)| n != &i.name)
            .cloned()
            .collect();
        check_item(cfg, state, &v.manifest, &others)?;
    }
    manifests.retain(|k, _| d.items.iter().any(|i| &i.rpk_digest == k));
    let time_floor = match cfg.trust.clock {
        ClockTrust::Trusted => state.time_floor.max(now1),
        ClockTrust::Untrusted => state.time_floor.max(d.created_at),
    };
    Ok(Outcome::Imported(Box::new(Imported {
        pack: String::new(),
        ring,
        bundles: steps,
        heads: heads.into_values().collect(),
        manifests,
        now: now1,
        time_floor,
        media_sha,
        trust: site,
        deployment: vd,
    })))
}
