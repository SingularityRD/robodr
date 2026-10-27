//! Sprint 13a exit criteria and the self-adversarial review
//! (`docs/SECURE-DELIVERY.md` §10, §12): every manifest mutation, missing
//! signature, wrong quorum, revoked key, chain gap and replay is refused,
//! and so are the forgeries tried in review: reordering, truncation,
//! duplicate signatures by one key, swapped payloads and RPKs, key
//! confusion between roles and document types, path traversal, stray
//! files and symlinks, oversized fields.

mod common;

use common::*;
use robodr_blackbox::Signer;
use robodr_pkg::bundle::{
    self, BundleManifest, ChainStep, BUNDLE_FILE, BUNDLE_SIG_DOMAIN, BUNDLE_SIG_FILE,
};
use robodr_pkg::common::{fingerprint, to_canonical};
use robodr_pkg::rpk::{self, MANIFEST_FILE, MANIFEST_SIG_DOMAIN, SIGNATURE_FILE};
use robodr_pkg::sig::SignatureSet;
use robodr_pkg::trust::Floor;
use robodr_pkg::Code;
use robodr_release::ops::{self, ChainMode, SiteTrust, Target};
use std::fs;
use std::path::{Path, PathBuf};

/// A signed two-RPK bundle (seq 1, with parity) and its trust.
struct Site {
    _tmp: Tmp,
    work: PathBuf,
    k: Keys,
    /// The site trust, anchored (anchor: a copy of `trust_path`).
    trust: SiteTrust,
    trust_path: PathBuf,
    anchor: PathBuf,
    bundle: PathBuf,
    rpk_nav: PathBuf,
}

fn site() -> Site {
    let tmp = Tmp::new("forgery");
    let work = tmp.path().to_path_buf();
    let k = keys();
    let trust_path = site_trust(&work, &k);
    let anchor = work.join("anchor.json");
    init_anchor(&trust_path, &anchor, &k);
    let trust = anchored(&trust_path, &anchor, &k).unwrap();
    let big = bytes(1, 300_000);
    let rpk_nav = signed_rpk(
        &work,
        "nav-stack",
        7,
        &[("bin/nav", &big), ("etc/nav.yaml", b"speed: 1\n")],
        &[&k.rel[0], &k.rel[1]],
    );
    let rpk_cfg = signed_rpk(
        &work,
        "mission-cfg",
        3,
        &[("mission.yaml", b"waypoints: []\n")],
        &[&k.rel[1], &k.rel[2]],
    );
    let bundle = signed_bundle(
        &work,
        &trust,
        1,
        None,
        &[rpk_nav.clone(), rpk_cfg],
        Some((2, 2, 512)),
        "bundle-1",
        &[&k.rel[0], &k.rel[2]],
    );
    Site {
        _tmp: tmp,
        work,
        k,
        trust,
        trust_path,
        anchor,
        bundle,
        rpk_nav,
    }
}

fn verify(s: &Site, dir: &Path) -> Result<ops::BundleReport, robodr_release::fsio::Fail> {
    ops::verify_bundle_dir(dir, &s.trust, &ChainMode::Genesis, NOW)
}

/// A fresh copy of the site's bundle to tamper with.
fn copy(s: &Site, name: &str) -> PathBuf {
    let d = s.work.join(name);
    copy_tree(&s.bundle, &d);
    d
}

fn bundle_json(dir: &Path) -> BundleManifest {
    bundle::parse_bundle(&fs::read(dir.join(BUNDLE_FILE)).unwrap()).unwrap()
}

/// Re-sign `bundle.json` bytes with `by` (an insider or a stolen key set).
fn resign(dir: &Path, by: &[&robodr_blackbox::Ed25519SigningKey]) {
    let doc = fs::read(dir.join(BUNDLE_FILE)).unwrap();
    let mut s = SignatureSet::empty();
    for k in by {
        s.add(*k, BUNDLE_SIG_DOMAIN, &doc).unwrap();
    }
    fs::write(dir.join(BUNDLE_SIG_FILE), s.to_bytes().unwrap()).unwrap();
}

fn write_bundle_json(dir: &Path, m: &BundleManifest) {
    fs::write(dir.join(BUNDLE_FILE), to_canonical(m).unwrap()).unwrap();
}

fn nav_dir(dir: &Path) -> PathBuf {
    dir.join("rpk_nav-stack_7_arm64")
}

#[test]
fn the_built_bundle_verifies() {
    let s = site();
    let r = verify(&s, &s.bundle).unwrap();
    assert_eq!(r.step, ChainStep::Next);
    assert_eq!(r.rpks.len(), 2);
    assert_eq!(r.bundle.signers.count(robodr_pkg::sig::Role::Release), 2);
    // The standalone RPK verifies too.
    ops::verify_rpk_dir(&s.rpk_nav, &s.trust, NOW).unwrap();
}

/// Every single-byte change of every signed document is refused (in
/// memory: the parser and the signature check, before any file I/O).
#[test]
fn every_single_byte_mutation_of_a_signed_document_is_refused() {
    let s = site();
    let docs: Vec<(&str, Vec<u8>, Vec<u8>)> = vec![
        (
            "bundle.json",
            fs::read(s.bundle.join(BUNDLE_FILE)).unwrap(),
            fs::read(s.bundle.join(BUNDLE_SIG_FILE)).unwrap(),
        ),
        (
            "MANIFEST.json",
            fs::read(nav_dir(&s.bundle).join(MANIFEST_FILE)).unwrap(),
            fs::read(nav_dir(&s.bundle).join(SIGNATURE_FILE)).unwrap(),
        ),
    ];
    let mut tried = 0;
    for (name, doc, sig) in &docs {
        // The originals pass.
        match *name {
            "bundle.json" => {
                bundle::verify_bundle_manifest(doc, sig, &s.trust).unwrap();
            }
            _ => {
                rpk::verify_manifest(doc, sig, &s.trust, NOW).unwrap();
            }
        }
        for i in 0..doc.len() {
            for x in [0x01u8, 0x20, 0x80, 0xff] {
                let mut m = doc.clone();
                m[i] ^= x;
                let refused = match *name {
                    "bundle.json" => bundle::verify_bundle_manifest(&m, sig, &s.trust).is_err(),
                    _ => rpk::verify_manifest(&m, sig, &s.trust, NOW).is_err(),
                };
                assert!(refused, "{name}: byte {i} ^ {x:#x} accepted");
                tried += 1;
            }
        }
        // Truncations and extensions.
        for n in 0..doc.len() {
            let ok = match *name {
                "bundle.json" => bundle::verify_bundle_manifest(&doc[..n], sig, &s.trust).is_ok(),
                _ => rpk::verify_manifest(&doc[..n], sig, &s.trust, NOW).is_ok(),
            };
            assert!(!ok, "{name} truncated to {n} accepted");
        }
        let mut ext = doc.clone();
        ext.push(b'\n');
        assert!(bundle::verify_bundle_manifest(&ext, sig, &s.trust).is_err());
        assert!(rpk::verify_manifest(&ext, sig, &s.trust, NOW).is_err());
    }
    assert!(tried > 4000, "{tried}");
}

#[test]
fn every_single_byte_mutation_of_a_file_on_disk_is_refused() {
    let s = site();
    // A sample of byte positions in every file of the bundle.
    let m = bundle_json(&s.bundle);
    let mut n = 0;
    for f in &m.files {
        for pos in [0, f.size / 2, f.size.saturating_sub(1)] {
            let d = copy(&s, &format!("flip-{n}"));
            n += 1;
            let p = d.join(&f.path);
            let mut b = fs::read(&p).unwrap();
            b[pos as usize] ^= 0x01;
            fs::write(&p, &b).unwrap();
            let c = code(verify(&s, &d));
            assert!(
                matches!(c, Code::FileMismatch),
                "{} byte {pos}: {c:?}",
                f.path
            );
            fs::remove_dir_all(&d).unwrap();
        }
    }
    // And the signed documents at the root.
    for (file, want) in [
        (BUNDLE_FILE, Code::Malformed),
        (BUNDLE_SIG_FILE, Code::Malformed),
    ] {
        let d = copy(&s, &format!("root-{file}"));
        let p = d.join(file);
        let mut b = fs::read(&p).unwrap();
        b[0] ^= 0x01;
        fs::write(&p, &b).unwrap();
        assert_eq!(code(verify(&s, &d)), want, "{file}");
    }
}

#[test]
fn missing_signatures_and_wrong_quorum_are_refused() {
    let s = site();
    // No bundle.sig.
    let d = copy(&s, "nosig");
    fs::remove_file(d.join(BUNDLE_SIG_FILE)).unwrap();
    assert_eq!(code(verify(&s, &d)), Code::MissingFile);
    // An empty signature set.
    fs::write(
        d.join(BUNDLE_SIG_FILE),
        br#"{"format":"robodr-sigset/1","signatures":[]}"#,
    )
    .unwrap();
    assert_eq!(code(verify(&s, &d)), Code::QuorumNotMet);
    // One release signature only.
    resign(&d, &[&s.k.rel[0]]);
    assert_eq!(code(verify(&s, &d)), Code::QuorumNotMet);
    // RPK MANIFEST.sig missing: bundle lists it -> missing file.
    let d = copy(&s, "norpksig");
    fs::remove_file(nav_dir(&d).join(SIGNATURE_FILE)).unwrap();
    assert_eq!(code(verify(&s, &d)), Code::MissingFile);
    // Standalone RPK with one signature (built here, signed once).
    let one = signed_rpk(&s.work, "single", 1, &[("a", b"a")], &[&s.k.rel[0]]);
    assert_eq!(
        code(ops::verify_rpk_dir(&one, &s.trust, NOW)),
        Code::QuorumNotMet
    );
    let none = signed_rpk(&s.work, "unsigned", 1, &[("a", b"a")], &[]);
    assert_eq!(
        code(ops::verify_rpk_dir(&none, &s.trust, NOW)),
        Code::MissingFile
    );
    // A site that raised the release quorum to 3 refuses a 2-signature bundle.
    let mut t = trust_file(&s.k);
    t.quorum.release = 3;
    let tp = write_trust(
        &s.work,
        "trust-q3.json",
        &t,
        &[&s.k.roots[0], &s.k.roots[1]],
    );
    let t3 = unanchored(&tp, &s.k).unwrap();
    assert_eq!(
        code(ops::verify_bundle_dir(
            &s.bundle,
            &t3,
            &ChainMode::Genesis,
            NOW
        )),
        Code::QuorumNotMet
    );
}

#[test]
fn revoked_keys_and_rpks_and_floors_are_refused() {
    let s = site();
    // rel-a signed the nav RPK and the bundle: revoke it.
    let mut t = trust_file(&s.k);
    t.version = 2;
    t.revoked_keys = vec![fingerprint(&s.k.rel[0].public_key())];
    let tp = write_trust(
        &s.work,
        "trust-rev.json",
        &t,
        &[&s.k.roots[0], &s.k.roots[1]],
    );
    let tr = unanchored(&tp, &s.k).unwrap();
    assert_eq!(
        code(ops::verify_bundle_dir(
            &s.bundle,
            &tr,
            &ChainMode::Genesis,
            NOW
        )),
        Code::RevokedKey
    );
    // Removing the revoked key from the role does not let it back in: unknown.
    t.release_keys.remove(0);
    t.programmes[0].release_keys.remove(0);
    let tp = write_trust(
        &s.work,
        "trust-rev2.json",
        &t,
        &[&s.k.roots[0], &s.k.roots[1]],
    );
    let tr = unanchored(&tp, &s.k).unwrap();
    assert_eq!(
        code(ops::verify_bundle_dir(
            &s.bundle,
            &tr,
            &ChainMode::Genesis,
            NOW
        )),
        Code::UnknownKey
    );
    // A revoked RPK digest.
    let nav = rpk::rpk_digest(&fs::read(nav_dir(&s.bundle).join(MANIFEST_FILE)).unwrap());
    let mut t = trust_file(&s.k);
    t.revoked_rpks = vec![nav];
    let tp = write_trust(
        &s.work,
        "trust-rpk.json",
        &t,
        &[&s.k.roots[0], &s.k.roots[1]],
    );
    let tr = unanchored(&tp, &s.k).unwrap();
    assert!(matches!(
        ops::verify_bundle_dir(&s.bundle, &tr, &ChainMode::Genesis, NOW),
        Err(robodr_release::fsio::Fail::Refused(r)) if r.code == Code::RevokedRpk
    ));
    // A site floor above the serial.
    let mut t = trust_file(&s.k);
    t.floors = vec![Floor {
        name: "nav-stack".into(),
        min_serial: 8,
    }];
    let tp = write_trust(
        &s.work,
        "trust-floor.json",
        &t,
        &[&s.k.roots[0], &s.k.roots[1]],
    );
    let tr = unanchored(&tp, &s.k).unwrap();
    assert_eq!(
        code(ops::verify_bundle_dir(
            &s.bundle,
            &tr,
            &ChainMode::Genesis,
            NOW
        )),
        Code::BelowFloor
    );
    // A revoked root cannot even be expressed; a trust file signed by an
    // unpinned root set is refused.
    let mut t = trust_file(&s.k);
    let r9 = key("root-9", 98);
    t.roots[2] = tk(&r9);
    let tp = write_trust(&s.work, "trust-evil.json", &t, &[&s.k.roots[0], &r9]);
    assert_eq!(code(load(&tp, &s.k)), Code::UnknownKey);
}

#[test]
fn chain_gap_replay_equivocation_and_broken_links_are_refused() {
    let s = site();
    let state = s.work.join("chain.json");
    // Accept bundle 1 (genesis) and commit.
    let r1 = verify(&s, &s.bundle).unwrap();
    ops::commit_chain(&state, &r1.bundle, &s.trust).unwrap();
    let st = ChainMode::State(state.clone());
    assert_eq!(
        ops::verify_bundle_dir(&s.bundle, &s.trust, &st, NOW)
            .unwrap()
            .step,
        ChainStep::AlreadyAccepted
    );
    // Bundle 2 chained to 1; bundle 3 chained to 2.
    let rpk2 = signed_rpk(
        &s.work,
        "nav-stack",
        8,
        &[("bin/nav", b"v8")],
        &[&s.k.rel[0], &s.k.rel[1]],
    );
    let b2 = signed_bundle(
        &s.work,
        &s.trust,
        2,
        Some(r1.bundle.hash.clone()),
        std::slice::from_ref(&rpk2),
        None,
        "bundle-2",
        &[&s.k.rel[0], &s.k.rel[1]],
    );
    let h2 = ops::verify_bundle_dir(
        &b2,
        &s.trust,
        &ChainMode::After {
            seq: 1,
            hash: r1.bundle.hash.clone(),
        },
        NOW,
    )
    .unwrap()
    .bundle
    .hash;
    let rpk3 = signed_rpk(
        &s.work,
        "nav-stack",
        9,
        &[("bin/nav", b"v9")],
        &[&s.k.rel[0], &s.k.rel[1]],
    );
    let b3 = signed_bundle(
        &s.work,
        &s.trust,
        3,
        Some(h2.clone()),
        &[rpk3],
        None,
        "bundle-3",
        &[&s.k.rel[0], &s.k.rel[1]],
    );
    // Gap: 3 while the head is 1.
    assert_eq!(
        code(ops::verify_bundle_dir(&b3, &s.trust, &st, NOW)),
        Code::ChainGap
    );
    // Genesis mode refuses anything but 1.
    assert_eq!(
        code(ops::verify_bundle_dir(
            &b2,
            &s.trust,
            &ChainMode::Genesis,
            NOW
        )),
        Code::ChainGap
    );
    // Accept 2, then replay 1.
    let r2 = ops::verify_bundle_dir(&b2, &s.trust, &st, NOW).unwrap();
    ops::commit_chain(&state, &r2.bundle, &s.trust).unwrap();
    assert_eq!(
        code(ops::verify_bundle_dir(&s.bundle, &s.trust, &st, NOW)),
        Code::Replay
    );
    // Equivocation: another validly signed bundle 2.
    let b2x = signed_bundle(
        &s.work,
        &s.trust,
        2,
        Some(r1.bundle.hash.clone()),
        &[rpk2],
        None,
        "bundle-2x-other-files",
        &[&s.k.rel[1], &s.k.rel[2]],
    );
    // (Same content, other signers: same bundle.json -> already accepted.)
    assert_eq!(
        ops::verify_bundle_dir(&b2x, &s.trust, &st, NOW)
            .unwrap()
            .step,
        ChainStep::AlreadyAccepted
    );
    let rpk2y = signed_rpk(
        &s.work,
        "nav-stack",
        10,
        &[("bin/nav", b"other")],
        &[&s.k.rel[0], &s.k.rel[1]],
    );
    let b2y = signed_bundle(
        &s.work,
        &s.trust,
        2,
        Some(r1.bundle.hash.clone()),
        &[rpk2y],
        None,
        "bundle-2y",
        &[&s.k.rel[0], &s.k.rel[1]],
    );
    assert_eq!(
        code(ops::verify_bundle_dir(&b2y, &s.trust, &st, NOW)),
        Code::Equivocation
    );
    // Broken link: bundle 3 whose prev is not the accepted 2.
    let rpk3z = signed_rpk(
        &s.work,
        "nav-stack",
        11,
        &[("bin/nav", b"z")],
        &[&s.k.rel[0], &s.k.rel[1]],
    );
    let b3z = signed_bundle(
        &s.work,
        &s.trust,
        3,
        Some("cd".repeat(32)),
        &[rpk3z],
        None,
        "bundle-3z",
        &[&s.k.rel[0], &s.k.rel[1]],
    );
    assert_eq!(
        code(ops::verify_bundle_dir(&b3z, &s.trust, &st, NOW)),
        Code::ChainBroken
    );
    // The real 3 is next.
    assert_eq!(
        ops::verify_bundle_dir(&b3, &s.trust, &st, NOW)
            .unwrap()
            .step,
        ChainStep::Next
    );
    // --after names the head explicitly.
    let after = ChainMode::After { seq: 2, hash: h2 };
    assert_eq!(
        ops::verify_bundle_dir(&b3, &s.trust, &after, NOW)
            .unwrap()
            .step,
        ChainStep::Next
    );
}

/// Review finding: the trust file crosses the gap like a bundle, so an
/// older root-signed trust file (from before a revocation) could be
/// paired with a bundle signed by the revoked key. The site's trust anchor
/// and the chain state pin the trust version it was accepted under.
#[test]
fn an_older_trust_file_cannot_reopen_a_revoked_key() {
    let s = site();
    let state = s.work.join("chain.json");
    // Bundle 1 (signed by rel-a and rel-c) is accepted under trust v1; v2,
    // which revokes rel-a, arrives with bundle 2.
    let r1 = verify(&s, &s.bundle).unwrap();
    ops::commit_chain(&state, &r1.bundle, &s.trust).unwrap();
    let mut t2 = trust_file(&s.k);
    t2.version = 2;
    t2.revoked_keys = vec![fingerprint(&s.k.rel[0].public_key())];
    let t2p = write_trust(
        &s.work,
        "trust-v2.json",
        &t2,
        &[&s.k.roots[0], &s.k.roots[1]],
    );
    let v2 = anchored(&t2p, &s.anchor, &s.k).unwrap();
    assert!(v2.is_rotation());
    let rpk2 = signed_rpk(
        &s.work,
        "nav-stack",
        8,
        &[("bin/nav", b"v8")],
        &[&s.k.rel[1], &s.k.rel[2]],
    );
    let b2 = signed_bundle(
        &s.work,
        &v2,
        2,
        Some(r1.bundle.hash.clone()),
        &[rpk2],
        None,
        "bundle-2",
        &[&s.k.rel[1], &s.k.rel[2]],
    );
    let st = ChainMode::State(state.clone());
    let r2 = ops::verify_bundle_dir(&b2, &v2, &st, NOW).unwrap();
    // Committing advances the site's anchor to v2 first.
    ops::commit_chain(&state, &r2.bundle, &v2).unwrap();
    assert_eq!(
        fs::read(&s.anchor).unwrap(),
        fs::read(&t2p).unwrap(),
        "anchor advanced"
    );
    // The attacker's bundle 3 is signed by the revoked rel-a (plus rel-b)
    // and carried in with the old trust v1, under which rel-a is valid.
    let rpk3 = signed_rpk(
        &s.work,
        "nav-stack",
        9,
        &[("bin/nav", b"evil")],
        &[&s.k.rel[0], &s.k.rel[1]],
    );
    let b3 = signed_bundle(
        &s.work,
        &s.trust,
        3,
        Some(r2.bundle.hash.clone()),
        &[rpk3],
        None,
        "bundle-3",
        &[&s.k.rel[0], &s.k.rel[1]],
    );
    let v2 = anchored(&t2p, &s.anchor, &s.k).unwrap();
    assert_eq!(
        code(ops::verify_bundle_dir(&b3, &v2, &st, NOW)),
        Code::RevokedKey
    );
    // v1 is refused by the anchor before anything else is looked at.
    assert_eq!(code(anchored(&s.trust_path, &s.anchor, &s.k)), Code::Replay);
    // So is a re-signed v2 with other content (same version).
    let mut t2b = t2.clone();
    t2b.issued_at += 1;
    let t2bp = write_trust(
        &s.work,
        "trust-v2b.json",
        &t2b,
        &[&s.k.roots[0], &s.k.roots[1]],
    );
    assert_eq!(code(anchored(&t2bp, &s.anchor, &s.k)), Code::Equivocation);
    // An anchor rolled back to v1 under a chain state of v2: refused.
    let rolled = s.work.join("rolled-anchor.json");
    fs::copy(&s.trust_path, &rolled).unwrap();
    fs::copy(ops::sig_path(&s.trust_path), ops::sig_path(&rolled)).unwrap();
    let v1r = anchored(&s.trust_path, &rolled, &s.k).unwrap();
    assert_eq!(
        code(ops::verify_bundle_dir(&b3, &v1r, &st, NOW)),
        Code::Replay
    );
    // A newer trust file is accepted as a rotation and recorded at the
    // next commit; it still refuses the revoked key.
    let mut t3 = t2.clone();
    t3.version = 3;
    let t3p = write_trust(
        &s.work,
        "trust-v3.json",
        &t3,
        &[&s.k.roots[0], &s.k.roots[2]],
    );
    let v3 = anchored(&t3p, &s.anchor, &s.k).unwrap();
    assert_eq!(
        code(ops::verify_bundle_dir(&b3, &v3, &st, NOW)),
        Code::RevokedKey
    );
    let state_now = robodr_pkg::bundle::ChainState::parse(&fs::read(&state).unwrap()).unwrap();
    assert_eq!(state_now.trust_version, 2);
    assert_eq!(state_now.trust_digest, v2.digest);
    // Without an anchor the state path is not available at all.
    let un = unanchored(&t2p, &s.k).unwrap();
    assert!(ops::verify_bundle_dir(&b3, &un, &st, NOW).is_err());
}

#[test]
fn reordering_and_duplicate_signatures_are_refused() {
    let s = site();
    // Two entries by the same key (same key id): not strictly sorted.
    let d = copy(&s, "dupsig");
    let mut set = SignatureSet::parse(&fs::read(d.join(BUNDLE_SIG_FILE)).unwrap()).unwrap();
    set.signatures[1] = set.signatures[0].clone();
    fs::write(d.join(BUNDLE_SIG_FILE), serde_json::to_vec(&set).unwrap()).unwrap();
    assert_eq!(code(verify(&s, &d)), Code::Invalid);
    // Reordered signature entries: not canonical either.
    let mut set = SignatureSet::parse(&fs::read(s.bundle.join(BUNDLE_SIG_FILE)).unwrap()).unwrap();
    set.signatures.reverse();
    fs::write(d.join(BUNDLE_SIG_FILE), serde_json::to_vec(&set).unwrap()).unwrap();
    assert_eq!(code(verify(&s, &d)), Code::Invalid);
    // The same key under a second key id cannot be trusted at all.
    let mut t = trust_file(&s.k);
    let mut alias = tk(&s.k.rel[0]);
    alias.key_id = "rel-a2".into();
    t.release_keys.insert(1, alias);
    let doc = to_canonical(&t).unwrap();
    assert!(robodr_pkg::trust::parse_trust(&doc).is_err());
    // Reordered files / RPK entries in bundle.json, even re-signed by the
    // quorum (an insider), are refused by the parser.
    let d = copy(&s, "reorder");
    let mut m = bundle_json(&d);
    m.files.swap(0, 1);
    write_bundle_json(&d, &m);
    resign(&d, &[&s.k.rel[0], &s.k.rel[1]]);
    assert_eq!(code(verify(&s, &d)), Code::Invalid);
    let mut m = bundle_json(&s.bundle);
    m.rpks.swap(0, 1);
    write_bundle_json(&d, &m);
    resign(&d, &[&s.k.rel[0], &s.k.rel[1]]);
    assert_eq!(code(verify(&s, &d)), Code::Invalid);
}

#[test]
fn swapped_payloads_and_rpks_are_refused() {
    let s = site();
    let m = bundle_json(&s.bundle);
    let chunk = m
        .files
        .iter()
        .find(|f| f.path.contains("/chunks/"))
        .unwrap();
    // A chunk replaced by other bytes.
    let d = copy(&s, "swapchunk");
    fs::write(d.join(&chunk.path), b"evil").unwrap();
    assert_eq!(code(verify(&s, &d)), Code::FileMismatch);
    // ... and its listing updated: a chunk's name is its hash, so the
    // listing is invalid before any signature is looked at.
    let mut mm = m.clone();
    for f in &mut mm.files {
        if f.path == chunk.path {
            f.size = 4;
            f.sha256 = robodr_pkg::common::sha256_hex(b"evil");
        }
    }
    write_bundle_json(&d, &mm);
    assert_eq!(code(verify(&s, &d)), Code::Invalid);
    // A tampered MANIFEST.json with its listing updated: the bundle
    // signature breaks.
    let d = copy(&s, "swapmanifest");
    let mp = nav_dir(&d).join(MANIFEST_FILE);
    let mut man = rpk::parse_manifest(&fs::read(&mp).unwrap()).unwrap();
    man.version.display = "1.7.0-evil".into();
    let mbytes = to_canonical(&man).unwrap();
    fs::write(&mp, &mbytes).unwrap();
    let mut mm = m.clone();
    for f in &mut mm.files {
        if f.path.ends_with("rpk_nav-stack_7_arm64/MANIFEST.json") {
            f.size = mbytes.len() as u64;
            f.sha256 = robodr_pkg::common::sha256_hex(&mbytes);
        }
    }
    write_bundle_json(&d, &mm);
    assert_eq!(code(verify(&s, &d)), Code::BadSignature);
    // ... re-signed by an untrusted key: unknown key.
    resign(&d, &[&s.k.evil, &s.k.rel[0]]);
    assert_eq!(code(verify(&s, &d)), Code::UnknownKey);
    // ... re-signed by the release quorum (an insider): the bundle names
    // the RPK by digest.
    resign(&d, &[&s.k.rel[0], &s.k.rel[1]]);
    assert_eq!(code(verify(&s, &d)), Code::DigestMismatch);
    // An RPK directory replaced by another validly signed RPK of the same
    // name and serial (different content).
    let d = copy(&s, "swaprpk");
    let other = signed_rpk(
        &s.work.join("other"),
        "nav-stack",
        7,
        &[("bin/nav", b"trojan")],
        &[&s.k.rel[0], &s.k.rel[1]],
    );
    fs::remove_dir_all(nav_dir(&d)).unwrap();
    copy_tree(&other, &nav_dir(&d));
    assert_eq!(code(verify(&s, &d)), Code::UnexpectedFile);
    // ... with the same chunk set (only the manifest differs): the listed
    // hash of MANIFEST.json catches it.
    let d = copy(&s, "swaprpk-manifest");
    let mut man = rpk::parse_manifest(&fs::read(nav_dir(&d).join(MANIFEST_FILE)).unwrap()).unwrap();
    man.health = vec![rpk::HealthCheck::FilePresent {
        path: "/tmp/x".into(),
    }];
    fs::write(nav_dir(&d).join(MANIFEST_FILE), to_canonical(&man).unwrap()).unwrap();
    assert_eq!(code(verify(&s, &d)), Code::FileMismatch);
    // An RPK from another bundle added next to the listed ones.
    let d = copy(&s, "addrpk");
    let extra = signed_rpk(
        &s.work,
        "extra",
        1,
        &[("x", b"x")],
        &[&s.k.rel[0], &s.k.rel[1]],
    );
    copy_tree(&extra, &d.join("rpk_extra_1_arm64"));
    assert_eq!(code(verify(&s, &d)), Code::UnexpectedFile);
    // MANIFEST.sig of one RPK copied over another's.
    let d = copy(&s, "swapsig");
    fs::copy(
        d.join("rpk_mission-cfg_3_arm64").join(SIGNATURE_FILE),
        nav_dir(&d).join(SIGNATURE_FILE),
    )
    .unwrap();
    assert_eq!(code(verify(&s, &d)), Code::FileMismatch);
    // A quorum-signed bundle.json whose RPK digest is wrong.
    let d = copy(&s, "digest");
    let mut mm = bundle_json(&d);
    mm.rpks[1].digest = "ee".repeat(32);
    write_bundle_json(&d, &mm);
    resign(&d, &[&s.k.rel[0], &s.k.rel[1]]);
    assert_eq!(code(verify(&s, &d)), Code::DigestMismatch);
}

#[test]
fn key_confusion_is_refused() {
    let s = site();
    // A bundle signed by the depot and an operator.
    let d = copy(&s, "depotsig");
    resign(&d, &[&s.k.depot, &s.k.ops[0]]);
    assert_eq!(code(verify(&s, &d)), Code::WrongRole);
    // ... or by two roots.
    resign(&d, &[&s.k.roots[0], &s.k.roots[1]]);
    assert_eq!(code(verify(&s, &d)), Code::WrongRole);
    // An RPK-manifest-domain signature over bundle.json: other domain.
    let d = copy(&s, "domain");
    let mut set = SignatureSet::empty();
    let doc = fs::read(d.join(BUNDLE_FILE)).unwrap();
    set.add(&s.k.rel[0], MANIFEST_SIG_DOMAIN, &doc).unwrap();
    set.add(&s.k.rel[1], MANIFEST_SIG_DOMAIN, &doc).unwrap();
    fs::write(d.join(BUNDLE_SIG_FILE), set.to_bytes().unwrap()).unwrap();
    assert_eq!(code(verify(&s, &d)), Code::BadSignature);
    // A real MANIFEST.sig placed as bundle.sig.
    fs::copy(nav_dir(&d).join(SIGNATURE_FILE), d.join(BUNDLE_SIG_FILE)).unwrap();
    assert_eq!(code(verify(&s, &d)), Code::BadSignature);
    // Trust file signed by release keys.
    let t = trust_file(&s.k);
    let tp = write_trust(
        &s.work,
        "trust-relsig.json",
        &t,
        &[&s.k.rel[0], &s.k.rel[1]],
    );
    assert_eq!(code(load(&tp, &s.k)), Code::WrongRole);
    // A trust file giving the depot key the release role too is invalid.
    let mut t = trust_file(&s.k);
    let mut d2 = tk(&s.k.depot);
    d2.key_id = "rel-d".into();
    t.release_keys.push(d2);
    t.release_keys.sort_by(|a, b| a.key_id.cmp(&b.key_id));
    assert!(robodr_pkg::trust::parse_trust(&to_canonical(&t).unwrap()).is_err());
    // An HMAC key cannot sign.
    let h = robodr_blackbox::HmacSha256Key::new("h", &[7u8; 32]).unwrap();
    assert_eq!(h.algorithm(), "hmac-sha256");
    let r = ops::sign(&Target::Bundle(s.bundle.clone()), &h, Some(&*s.trust), NOW);
    assert_eq!(code(r), Code::Unsupported);
}

#[test]
fn traversal_stray_files_symlinks_and_oversize_are_refused() {
    let s = site();
    // A quorum-signed bundle.json listing a traversal path is refused by
    // the parser (an insider cannot make the verifier read outside).
    let d = copy(&s, "trav");
    let mut m = bundle_json(&d);
    m.files[0].path = "../../etc/passwd".into();
    m.files.sort_by(|a, b| a.path.cmp(&b.path));
    write_bundle_json(&d, &m);
    resign(&d, &[&s.k.rel[0], &s.k.rel[1]]);
    assert_eq!(code(verify(&s, &d)), Code::Invalid);
    // A stray file, an empty directory, a symlink.
    let d = copy(&s, "stray");
    fs::write(d.join("README"), b"x").unwrap();
    assert_eq!(code(verify(&s, &d)), Code::UnexpectedFile);
    let d = copy(&s, "emptydir");
    fs::create_dir(d.join("rpk_nav-stack_7_arm64/extra")).unwrap();
    assert_eq!(code(verify(&s, &d)), Code::UnexpectedFile);
    let d = copy(&s, "symlink");
    let m = bundle_json(&d);
    let chunk = &m
        .files
        .iter()
        .find(|f| f.path.contains("/chunks/"))
        .unwrap()
        .path;
    let target = s.bundle.join(chunk);
    fs::remove_file(d.join(chunk)).unwrap();
    std::os::unix::fs::symlink(&target, d.join(chunk)).unwrap();
    assert_eq!(code(verify(&s, &d)), Code::UnexpectedFile);
    // A symlinked RPK directory.
    let d = copy(&s, "symdir");
    fs::remove_dir_all(nav_dir(&d)).unwrap();
    std::os::unix::fs::symlink(nav_dir(&s.bundle), nav_dir(&d)).unwrap();
    assert_eq!(code(verify(&s, &d)), Code::UnexpectedFile);
    // A symlinked bundle.json.
    let d = copy(&s, "symjson");
    fs::remove_file(d.join(BUNDLE_FILE)).unwrap();
    std::os::unix::fs::symlink(s.bundle.join(BUNDLE_FILE), d.join(BUNDLE_FILE)).unwrap();
    assert_eq!(code(verify(&s, &d)), Code::FileMismatch);
    // Oversized signature file and manifest: refused before parsing.
    let d = copy(&s, "big");
    fs::write(
        d.join(BUNDLE_SIG_FILE),
        vec![b' '; robodr_pkg::sig::MAX_SIGSET_BYTES + 1],
    )
    .unwrap();
    assert_eq!(code(verify(&s, &d)), Code::TooLarge);
    let d = copy(&s, "bigjson");
    let f = fs::File::create(d.join(BUNDLE_FILE)).unwrap();
    f.set_len(robodr_pkg::bundle::MAX_BUNDLE_BYTES as u64 + 1)
        .unwrap();
    assert_eq!(code(verify(&s, &d)), Code::TooLarge);
    // Payload building refuses symlinks and unsafe names and modes.
    let pl = s.work.join("pl-sym");
    fs::create_dir_all(&pl).unwrap();
    fs::write(pl.join("a"), b"a").unwrap();
    std::os::unix::fs::symlink("/etc/passwd", pl.join("b")).unwrap();
    assert_eq!(
        code(ops::build_rpk(&spec("p", 1), &pl, &s.work)),
        Code::UnexpectedFile
    );
    let pl = s.work.join("pl-hidden");
    fs::create_dir_all(&pl).unwrap();
    fs::write(pl.join(".ssh"), b"a").unwrap();
    assert_eq!(
        code(ops::build_rpk(&spec("p", 1), &pl, &s.work)),
        Code::Invalid
    );
    let pl = s.work.join("pl-suid");
    fs::create_dir_all(&pl).unwrap();
    fs::write(pl.join("x"), b"a").unwrap();
    use std::os::unix::fs::PermissionsExt;
    fs::set_permissions(pl.join("x"), fs::Permissions::from_mode(0o4755)).unwrap();
    assert_eq!(
        code(ops::build_rpk(&spec("p", 1), &pl, &s.work)),
        Code::Invalid
    );
    // An oversized key id in a signature: refused.
    let d = copy(&s, "longkey");
    let mut set = SignatureSet::parse(&fs::read(d.join(BUNDLE_SIG_FILE)).unwrap()).unwrap();
    set.signatures[0].key_id = "k".repeat(65);
    set.signatures.sort_by(|a, b| a.key_id.cmp(&b.key_id));
    fs::write(d.join(BUNDLE_SIG_FILE), serde_json::to_vec(&set).unwrap()).unwrap();
    assert_eq!(code(verify(&s, &d)), Code::Invalid);
}

#[test]
fn truncation_is_refused() {
    let s = site();
    let m = bundle_json(&s.bundle);
    for f in m.files.iter().filter(|f| f.size > 1) {
        let d = copy(&s, "trunc");
        let p = d.join(&f.path);
        let b = fs::read(&p).unwrap();
        fs::write(&p, &b[..b.len() - 1]).unwrap();
        assert_eq!(code(verify(&s, &d)), Code::FileMismatch, "{}", f.path);
        fs::remove_dir_all(&d).unwrap();
    }
    let d = copy(&s, "trunc-sig");
    let p = d.join(BUNDLE_SIG_FILE);
    let b = fs::read(&p).unwrap();
    fs::write(&p, &b[..b.len() / 2]).unwrap();
    assert_eq!(code(verify(&s, &d)), Code::Malformed);
}

#[test]
fn parity_repairs_damage_up_to_m_per_group_and_no_more() {
    let s = site();
    let m = bundle_json(&s.bundle);
    let groups = robodr_pkg::parity::plan(&m).unwrap();
    assert!(groups.len() >= 2);
    // Damage two files of the first group (delete one, corrupt one) and
    // one parity file of another.
    let d = copy(&s, "repair");
    let g0 = &groups[0];
    fs::remove_file(d.join(&m.files[g0.data[0]].path)).unwrap();
    fs::write(d.join(&m.files[g0.data[1]].path), b"garbage").unwrap();
    fs::remove_file(d.join(&m.files[groups[1].parity[0]].path)).unwrap();
    assert!(verify(&s, &d).is_err());
    let rebuilt = ops::repair_bundle(&d, &s.trust).unwrap();
    assert_eq!(rebuilt.len(), 3);
    verify(&s, &d).unwrap();
    // A whole missing RPK directory (directories recreated) when no group
    // loses more than m = 2 files; otherwise refused.
    let d = copy(&s, "repair-dir");
    fs::remove_dir_all(d.join("rpk_mission-cfg_3_arm64")).unwrap();
    let worst = groups
        .iter()
        .map(|g| {
            g.members()
                .iter()
                .filter(|&&i| m.files[i].path.starts_with("rpk_mission-cfg"))
                .count()
        })
        .max()
        .unwrap();
    let r = ops::repair_bundle(&d, &s.trust);
    if worst <= 2 {
        r.unwrap();
        verify(&s, &d).unwrap();
    } else {
        assert_eq!(code(r), Code::FileMismatch);
    }
    // Three damaged files in one group (m = 2): refused, nothing written.
    let d = copy(&s, "repair-too-many");
    for &i in g0.data.iter().take(2).chain(g0.parity.iter().take(1)) {
        fs::remove_file(d.join(&m.files[i].path)).unwrap();
    }
    assert_eq!(code(ops::repair_bundle(&d, &s.trust)), Code::FileMismatch);
    // Repair never trusts an unauthenticated bundle.json.
    let d = copy(&s, "repair-forged");
    resign(&d, &[&s.k.evil, &s.k.rel[0]]);
    assert_eq!(code(ops::repair_bundle(&d, &s.trust)), Code::UnknownKey);
    // Repair refuses to write through a symlinked directory.
    let d = copy(&s, "repair-symlink");
    let victim = s.work.join("victim");
    fs::create_dir_all(&victim).unwrap();
    let f = &m.files[g0.data[0]];
    let parent = Path::new(&f.path).parent().unwrap();
    fs::remove_dir_all(d.join(parent)).unwrap();
    std::os::unix::fs::symlink(&victim, d.join(parent)).unwrap();
    assert!(ops::repair_bundle(&d, &s.trust).is_err());
    assert_eq!(
        fs::read_dir(&victim).unwrap().count(),
        0,
        "wrote through a symlink"
    );
}

#[test]
fn expiry_and_scope_are_enforced() {
    let s = site();
    let mut sp = spec("short-lived", 1);
    sp.expires_at = Some(NOW + 10);
    let r = signed_rpk_spec(&s.work, &sp, &[("a", b"a")], &[&s.k.rel[0], &s.k.rel[1]]);
    ops::verify_rpk_dir(&r, &s.trust, NOW).unwrap();
    assert_eq!(
        code(ops::verify_rpk_dir(&r, &s.trust, NOW + 10)),
        Code::Expired
    );
    // A bundle for a programme the site does not accept.
    let mut t = trust_file(&s.k);
    t.programmes[0].name = "other".into();
    let tp = write_trust(
        &s.work,
        "trust-prog.json",
        &t,
        &[&s.k.roots[0], &s.k.roots[1]],
    );
    let tr = unanchored(&tp, &s.k).unwrap();
    assert_eq!(
        code(ops::verify_bundle_dir(
            &s.bundle,
            &tr,
            &ChainMode::Genesis,
            NOW
        )),
        Code::WrongScope
    );
    // The site's own trust file, re-read from disk, still verifies.
    load(&s.trust_path, &s.k).unwrap();
}

#[test]
fn sign_checks_what_it_signs() {
    let s = site();
    // An RPK whose chunk was altered after build cannot be signed.
    let r = signed_rpk(&s.work, "tampered", 1, &[("a", b"abc")], &[]);
    let chunk = fs::read_dir(r.join("chunks"))
        .unwrap()
        .next()
        .unwrap()
        .unwrap()
        .path();
    fs::write(&chunk, b"abd").unwrap();
    assert_eq!(
        code(ops::sign(
            &Target::Rpk(r.clone()),
            &s.k.rel[0],
            Some(&*s.trust),
            NOW
        )),
        Code::FileMismatch
    );
    // A second signature by the same key is refused.
    let r = signed_rpk(&s.work, "twice", 1, &[("a", b"a")], &[&s.k.rel[0]]);
    assert_eq!(
        code(ops::sign(
            &Target::Rpk(r),
            &s.k.rel[0],
            Some(&*s.trust),
            NOW
        )),
        Code::DuplicateSigner
    );
    // A bundle with a stray file cannot be signed.
    let d = copy(&s, "sign-stray");
    fs::write(d.join("stray"), b"x").unwrap();
    assert_eq!(
        code(ops::sign(
            &Target::Bundle(d),
            &s.k.rel[1],
            Some(&*s.trust),
            NOW
        )),
        Code::UnexpectedFile
    );
}
