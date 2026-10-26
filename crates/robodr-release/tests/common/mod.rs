//! Shared fixture of the robodr-release integration tests: deterministic
//! keys, a site trust file, payloads, signed RPKs and signed bundles.
#![allow(dead_code)]

use robodr_blackbox::{Ed25519SigningKey, Signer};
use robodr_pkg::common::{fingerprint, to_canonical};
use robodr_pkg::rpk::{Arch, Install, Kind, Version};
use robodr_pkg::sig::SignatureSet;
use robodr_pkg::trust::{
    Programme, Quorum, RingAssignment, TrustFile, TrustKey, VerifiedTrust, TRUST_FORMAT,
    TRUST_SIG_DOMAIN,
};
use robodr_release::fsio::Fail;
use robodr_release::ops::{self, BundleOptions, RpkSpec, SiteTrust, Target, SPEC_FORMAT};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicUsize, Ordering};

pub const NOW: u64 = 1_790_000_000;
pub const PROGRAMME: &str = "ugv-x1";
pub const SITE: &str = "site-a";

/// A fresh, empty temp directory, removed on drop.
pub struct Tmp(pub PathBuf);

impl Tmp {
    pub fn new(tag: &str) -> Self {
        static N: AtomicUsize = AtomicUsize::new(0);
        let p = std::env::temp_dir().join(format!(
            "robodr-release-{tag}-{}-{}",
            std::process::id(),
            N.fetch_add(1, Ordering::SeqCst)
        ));
        let _ = std::fs::remove_dir_all(&p);
        std::fs::create_dir_all(&p).unwrap();
        Tmp(p)
    }
    pub fn path(&self) -> &Path {
        &self.0
    }
}

impl Drop for Tmp {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

pub fn key(id: &str, seed: u8) -> Ed25519SigningKey {
    Ed25519SigningKey::from_seed(id, &[seed; 32]).unwrap()
}

/// Every role's keys (deterministic seeds).
pub struct Keys {
    pub roots: Vec<Ed25519SigningKey>,
    pub rel: Vec<Ed25519SigningKey>,
    pub depot: Ed25519SigningKey,
    pub ops: Vec<Ed25519SigningKey>,
    /// A key nobody trusts.
    pub evil: Ed25519SigningKey,
}

pub fn keys() -> Keys {
    Keys {
        roots: (1..=3).map(|i| key(&format!("root-{i}"), i)).collect(),
        rel: ["rel-a", "rel-b", "rel-c"]
            .iter()
            .zip(11..)
            .map(|(n, s)| key(n, s))
            .collect(),
        depot: key("depot-1", 21),
        ops: (1..=3).map(|i| key(&format!("op-{i}"), 30 + i)).collect(),
        evil: key("evil", 99),
    }
}

pub fn tk(k: &Ed25519SigningKey) -> TrustKey {
    TrustKey::new(k.key_id(), &k.public_key())
}

pub fn trust_file(k: &Keys) -> TrustFile {
    TrustFile {
        format: TRUST_FORMAT.into(),
        site: "site-a".into(),
        version: 1,
        issued_at: NOW,
        expires_at: NOW + 90 * 86400,
        programmes: vec![Programme {
            name: PROGRAMME.into(),
            release_keys: k.rel.iter().map(|r| r.key_id().to_string()).collect(),
            packages: vec!["*".into()],
        }],
        quorum: Quorum {
            root: 2,
            release: 2,
            operator_prod: 2,
            operator_lab: 1,
        },
        roots: k.roots.iter().map(tk).collect(),
        release_keys: k.rel.iter().map(tk).collect(),
        depot_keys: vec![tk(&k.depot)],
        operator_keys: k.ops.iter().map(tk).collect(),
        rings: vec![RingAssignment {
            ring: "lab".into(),
            units: vec!["bench-01".into()],
        }],
        revoked_keys: vec![],
        revoked_rpks: vec![],
        revoked_serials: vec![],
        floors: vec![],
    }
}

pub fn pins(k: &Keys) -> Vec<String> {
    k.roots
        .iter()
        .map(|r| fingerprint(&r.public_key()))
        .collect()
}

/// Write `t` to `dir/name` and sign it with `by`.
pub fn write_trust(dir: &Path, name: &str, t: &TrustFile, by: &[&Ed25519SigningKey]) -> PathBuf {
    let p = dir.join(name);
    let doc = to_canonical(t).unwrap();
    std::fs::write(&p, &doc).unwrap();
    let mut s = SignatureSet::empty();
    for k in by {
        s.add(*k, TRUST_SIG_DOMAIN, &doc).unwrap();
    }
    std::fs::write(ops::sig_path(&p), s.to_bytes().unwrap()).unwrap();
    p
}

/// `t` root-signed (roots 1 and 2) into `dir/name`.
pub fn put(dir: &Path, name: &str, t: &TrustFile, k: &Keys) -> PathBuf {
    write_trust(dir, name, t, &[&k.roots[0], &k.roots[1]])
}

/// A trust file accepted under the pins and site, no anchor.
pub fn load(p: &Path, k: &Keys) -> Result<VerifiedTrust, Fail> {
    ops::load_trust(p, &pins(k), SITE, NOW)
}

/// The presented trust file `p` at a site whose anchor is `anchor`.
pub fn anchored(p: &Path, anchor: &Path, k: &Keys) -> Result<SiteTrust, Fail> {
    SiteTrust::anchored(p, anchor, &pins(k), SITE, NOW)
}

/// The explicit no-anchor mode.
pub fn unanchored(p: &Path, k: &Keys) -> Result<SiteTrust, Fail> {
    SiteTrust::unanchored(p, &pins(k), SITE, NOW)
}

/// Create a site anchor at `anchor` from the trust file `p`.
pub fn init_anchor(p: &Path, anchor: &Path, k: &Keys) {
    ops::init_anchor(p, anchor, &pins(k), SITE, NOW).unwrap();
}

/// The default site trust (in memory), for signing in fixtures.
pub fn default_trust() -> VerifiedTrust {
    let k = keys();
    let doc = to_canonical(&trust_file(&k)).unwrap();
    let mut s = SignatureSet::empty();
    for r in &k.roots[..2] {
        s.add(r, TRUST_SIG_DOMAIN, &doc).unwrap();
    }
    robodr_pkg::trust::verify_trust_pinned(&doc, &s.to_bytes().unwrap(), &pins(&k), SITE, NOW)
        .unwrap()
}

/// Sign an RPK's manifest with `by` directly (no checks): what an
/// attacker holding those keys can produce without this tool.
pub fn raw_sign_rpk(dir: &Path, by: &[&Ed25519SigningKey]) {
    let doc = std::fs::read(dir.join(robodr_pkg::rpk::MANIFEST_FILE)).unwrap();
    let mut s = SignatureSet::empty();
    for k in by {
        s.add(*k, robodr_pkg::rpk::MANIFEST_SIG_DOMAIN, &doc)
            .unwrap();
    }
    std::fs::write(
        dir.join(robodr_pkg::rpk::SIGNATURE_FILE),
        s.to_bytes().unwrap(),
    )
    .unwrap();
}

/// Sign a bundle's `bundle.json` with `by` directly (no checks).
pub fn raw_sign_bundle(dir: &Path, by: &[&Ed25519SigningKey]) {
    let doc = std::fs::read(dir.join(robodr_pkg::bundle::BUNDLE_FILE)).unwrap();
    let mut s = SignatureSet::empty();
    for k in by {
        s.add(*k, robodr_pkg::bundle::BUNDLE_SIG_DOMAIN, &doc)
            .unwrap();
    }
    std::fs::write(
        dir.join(robodr_pkg::bundle::BUNDLE_SIG_FILE),
        s.to_bytes().unwrap(),
    )
    .unwrap();
}

/// The default site trust file in `dir`, signed by roots 1 and 2.
pub fn site_trust(dir: &Path, k: &Keys) -> PathBuf {
    write_trust(
        dir,
        "trust.json",
        &trust_file(k),
        &[&k.roots[0], &k.roots[1]],
    )
}

pub fn spec(name: &str, serial: u64) -> RpkSpec {
    RpkSpec {
        format: SPEC_FORMAT.into(),
        name: name.into(),
        version: Version {
            serial,
            display: format!("1.{serial}.0"),
        },
        kind: Kind::Files,
        platform: "ugv-x1".into(),
        arch: Arch::Arm64,
        hw_compat: vec![],
        requires: vec![],
        conflicts: vec![],
        security_floor: 1,
        install: Install {
            allow_maintainer_scripts: false,
            requires_operator_present: false,
        },
        health: vec![],
        expires_at: None,
        sbom_path: None,
    }
}

/// Write `(relative path, bytes)` files under `dir`.
pub fn payload(dir: &Path, files: &[(&str, &[u8])]) -> PathBuf {
    for (p, b) in files {
        let f = dir.join(p);
        std::fs::create_dir_all(f.parent().unwrap()).unwrap();
        std::fs::write(&f, b).unwrap();
    }
    dir.to_path_buf()
}

/// Deterministic pseudo-random bytes.
pub fn bytes(seed: u64, n: usize) -> Vec<u8> {
    let mut x = seed.wrapping_mul(0x9E37_79B9_7F4A_7C15) | 1;
    (0..n)
        .map(|_| {
            x ^= x << 13;
            x ^= x >> 7;
            x ^= x << 17;
            (x >> 24) as u8
        })
        .collect()
}

/// Build `name`/`serial` from `files` under `work` and sign it with `by`.
pub fn signed_rpk(
    work: &Path,
    name: &str,
    serial: u64,
    files: &[(&str, &[u8])],
    by: &[&Ed25519SigningKey],
) -> PathBuf {
    signed_rpk_spec(work, &spec(name, serial), files, by)
}

pub fn signed_rpk_spec(
    work: &Path,
    s: &RpkSpec,
    files: &[(&str, &[u8])],
    by: &[&Ed25519SigningKey],
) -> PathBuf {
    let pl = work.join(format!("payload-{}-{}", s.name, s.version.serial));
    std::fs::create_dir_all(&pl).unwrap();
    payload(&pl, files);
    let out = work.join("rpks");
    std::fs::create_dir_all(&out).unwrap();
    let b = ops::build_rpk(s, &pl, &out).unwrap();
    let t = default_trust();
    for k in by {
        ops::sign(&Target::Rpk(b.dir.clone()), *k, Some(&t), NOW).unwrap();
    }
    b.dir
}

/// Assemble and sign a bundle.
#[allow(clippy::too_many_arguments)]
pub fn signed_bundle(
    work: &Path,
    trust: &robodr_pkg::trust::VerifiedTrust,
    seq: u64,
    prev: Option<String>,
    rpks: &[PathBuf],
    parity: Option<(usize, usize, u64)>,
    out_name: &str,
    by: &[&Ed25519SigningKey],
) -> PathBuf {
    let out = work.join(out_name);
    ops::build_bundle(&BundleOptions {
        programme: PROGRAMME.into(),
        seq,
        prev_hash: prev,
        created_at: NOW,
        rpks: rpks.to_vec(),
        trust,
        now: NOW,
        parity,
        out: out.clone(),
    })
    .unwrap();
    for k in by {
        ops::sign(&Target::Bundle(out.clone()), *k, Some(trust), NOW).unwrap();
    }
    out
}

/// Recursive copy (regular files and directories only).
pub fn copy_tree(from: &Path, to: &Path) {
    std::fs::create_dir_all(to).unwrap();
    for e in std::fs::read_dir(from).unwrap() {
        let e = e.unwrap();
        let t = to.join(e.file_name());
        if e.file_type().unwrap().is_dir() {
            copy_tree(&e.path(), &t);
        } else {
            std::fs::copy(e.path(), &t).unwrap();
        }
    }
}

/// The refusal code of a failed operation.
pub fn code<T: std::fmt::Debug>(r: Result<T, robodr_release::fsio::Fail>) -> robodr_pkg::Code {
    match r {
        Err(robodr_release::fsio::Fail::Refused(x)) => x.code,
        other => panic!("expected a refusal, got {other:?}"),
    }
}
