//! Regression tests for the independent adversarial review of Sprint 13a
//! (`docs/SECURE-DELIVERY.md` §3.5, "Review of 13a"). Each test replays
//! one attack of the review and must be refused.

mod common;

use common::*;
use robodr_pkg::bundle::{BUNDLE_FILE, BUNDLE_SIG_FILE};
use robodr_pkg::common::{fingerprint, sha256_hex, to_canonical};
use robodr_pkg::deployment::{
    Deployment, Item, Rollout, Targets, DEPLOYMENT_FORMAT, DEPLOYMENT_SIG_DOMAIN,
};
use robodr_pkg::rpk::{self, MANIFEST_FILE, MANIFEST_SIG_DOMAIN, SIGNATURE_FILE};
use robodr_pkg::sig::SignatureSet;
use robodr_pkg::trust::{Programme, TrustFile};
use robodr_pkg::Code;
use robodr_release::fsio::Fail;
use robodr_release::ops::{self, ChainMode, SiteTrust, Target};
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::Duration;

const BIN: &str = env!("CARGO_BIN_EXE_robodr-release");

fn run(args: &[String]) -> (i32, String, String) {
    let o = Command::new(BIN).args(args).output().unwrap();
    (
        o.status.code().unwrap_or(-1),
        String::from_utf8(o.stdout).unwrap(),
        String::from_utf8(o.stderr).unwrap(),
    )
}

fn sv(v: &[&str]) -> Vec<String> {
    v.iter().map(|s| s.to_string()).collect()
}

fn p(x: &Path) -> String {
    x.to_str().unwrap().to_string()
}

/// What a verifier at site-a whose accepted trust anchor is (a copy of)
/// the trust file `anchor` gets when a courier presents `presented`.
fn present(presented: &Path, anchor: &Path, k: &Keys) -> Result<SiteTrust, Fail> {
    let a = anchor.with_extension("anchor.json");
    if !a.exists() {
        init_anchor(anchor, &a, k);
    }
    anchored(presented, &a, k)
}

fn digest_of(rpk_dir: &Path) -> String {
    rpk::rpk_digest(&fs::read(rpk_dir.join(MANIFEST_FILE)).unwrap())
}

// ---------------------------------------------------------------------------
// Finding 1 (High): another site's trust file.
// ---------------------------------------------------------------------------

/// Site A's trust v2 revokes RPK X. A courier pairs bundle 2 (with X) and
/// site B's trust v3 (same roots, no revocation). Site A must refuse it,
/// and its chain state must not be advanced to site B's version.
#[test]
fn f1_another_sites_trust_file_is_refused() {
    let tmp = Tmp::new("f1");
    let w = tmp.path();
    let k = keys();
    let a1p = put(w, "trust-a-v1.json", &trust_file(&k), &k);
    let va1 = load(&a1p, &k).unwrap();
    let rpk7 = signed_rpk(
        w,
        "nav-stack",
        7,
        &[("bin/nav", b"v7")],
        &[&k.rel[0], &k.rel[1]],
    );
    let x = signed_rpk(
        w,
        "nav-stack",
        8,
        &[("bin/nav", b"bad")],
        &[&k.rel[0], &k.rel[1]],
    );
    let mut a2 = trust_file(&k);
    a2.version = 2;
    a2.revoked_rpks = vec![digest_of(&x)];
    let a2p = put(w, "trust-a-v2.json", &a2, &k);
    let mut b3 = trust_file(&k);
    b3.site = "site-b".into();
    b3.version = 3;
    let b3p = put(w, "trust-b-v3.json", &b3, &k);

    let va2 = present(&a2p, &a2p, &k).unwrap();
    let b1 = signed_bundle(
        w,
        &va1,
        1,
        None,
        &[rpk7],
        None,
        "bundle-1",
        &[&k.rel[0], &k.rel[1]],
    );
    let state = w.join("chain.json");
    let r1 = ops::verify_bundle_dir(&b1, &va2, &ChainMode::Genesis, NOW).unwrap();
    ops::commit_chain(&state, &r1.bundle, &va2).unwrap();
    let b2 = signed_bundle(
        w,
        &va1,
        2,
        Some(r1.bundle.hash.clone()),
        &[x],
        None,
        "bundle-2",
        &[&k.rel[0], &k.rel[1]],
    );
    let st = ChainMode::State(state.clone());
    // The site's own trust file refuses X.
    assert_eq!(
        code(ops::verify_bundle_dir(&b2, &va2, &st, NOW)),
        Code::RevokedRpk
    );
    // Site B's file must not get it through: refused by the pinned site
    // (with or without an anchor), and the chain state is untouched.
    let r = present(&b3p, &a2p, &k).and_then(|t| ops::verify_bundle_dir(&b2, &t, &st, NOW));
    assert!(r.is_err(), "site-b trust file accepted at site-a");
    assert_eq!(code(present(&b3p, &a2p, &k)), Code::WrongScope);
    assert_eq!(code(unanchored(&b3p, &k)), Code::WrongScope);
    assert_eq!(code(load(&b3p, &k)), Code::WrongScope);
    let st_now = robodr_pkg::bundle::ChainState::parse(&fs::read(&state).unwrap()).unwrap();
    assert_eq!((st_now.site.as_str(), st_now.trust_version), ("site-a", 2));
    // Site A's own trust v2 is still accepted afterwards (no lockout).
    let va2 = present(&a2p, &a2p, &k).unwrap();
    assert_eq!(
        code(ops::verify_bundle_dir(&b2, &va2, &st, NOW)),
        Code::RevokedRpk
    );
}

// ---------------------------------------------------------------------------
// Finding 4 (Medium): trust rollback outside `verify bundle --state`.
// ---------------------------------------------------------------------------

struct F4 {
    _tmp: Tmp,
    w: PathBuf,
    k: Keys,
    v1: PathBuf,
    v2: PathBuf,
    x: PathBuf,
}

/// Trust v1, and v2 which revokes RPK X and release key rel-a.
fn f4() -> F4 {
    let tmp = Tmp::new("f4");
    let w = tmp.path().to_path_buf();
    let k = keys();
    let v1 = put(&w, "trust-v1.json", &trust_file(&k), &k);
    let x = signed_rpk(
        &w,
        "nav-stack",
        7,
        &[("bin/nav", b"x")],
        &[&k.rel[1], &k.rel[2]],
    );
    let mut t2 = trust_file(&k);
    t2.version = 2;
    t2.revoked_rpks = vec![digest_of(&x)];
    t2.revoked_keys = vec![fingerprint(&k.rel[0].public_key())];
    let v2 = put(&w, "trust-v2.json", &t2, &k);
    F4 {
        _tmp: tmp,
        w,
        k,
        v1,
        v2,
        x,
    }
}

#[test]
fn f4_verify_rpk_refuses_an_older_trust_file() {
    let f = f4();
    let r = present(&f.v1, &f.v2, &f.k).and_then(|t| ops::verify_rpk_dir(&f.x, &t, NOW));
    assert!(
        r.is_err(),
        "revoked RPK accepted under the older trust file"
    );
    assert_eq!(code(present(&f.v1, &f.v2, &f.k)), Code::Replay);
}

/// Freeze (T8): trust files expire, so a withheld newer file is detected
/// within one lifetime; an expired anchor still accepts its successor.
#[test]
fn f4_an_expired_trust_file_is_refused_and_an_expired_anchor_can_rotate() {
    let tmp = Tmp::new("f4exp");
    let w = tmp.path();
    let k = keys();
    let mut old = trust_file(&k);
    old.issued_at = NOW - 100 * 86400;
    old.expires_at = NOW - 10 * 86400;
    let oldp = put(w, "trust-old.json", &old, &k);
    assert_eq!(code(load(&oldp, &k)), Code::Expired);
    assert_eq!(code(unanchored(&oldp, &k)), Code::Expired);
    // An anchor created while it was fresh...
    let a = w.join("anchor.json");
    ops::init_anchor(&oldp, &a, &pins(&k), SITE, NOW - 50 * 86400).unwrap();
    // ...no longer vouches for itself once expired,
    assert_eq!(code(anchored(&oldp, &a, &k)), Code::Expired);
    // ...but accepts a fresh rotation, which every command then uses.
    let mut fresh = trust_file(&k);
    fresh.version = 2;
    let fp = put(w, "trust-fresh.json", &fresh, &k);
    let t = anchored(&fp, &a, &k).unwrap();
    assert!(t.is_rotation());
    assert!(ops::commit_anchor(&t).unwrap());
    anchored(&fp, &a, &k).unwrap();
    assert_eq!(code(anchored(&oldp, &a, &k)), Code::Replay);
}

#[test]
fn f4_verify_deployment_refuses_an_older_trust_file() {
    let f = f4();
    let d = Deployment {
        format: DEPLOYMENT_FORMAT.into(),
        deployment_id: "dep-1".into(),
        site: "site-a".into(),
        deployment_seq: 1,
        created_at: NOW,
        targets: Targets {
            units: vec!["ugv-01".into()],
            groups: vec![],
        },
        ring: "ring-1".into(),
        items: vec![Item {
            rpk_digest: digest_of(&f.x),
            name: "nav-stack".into(),
            serial: 7,
        }],
        not_before: NOW,
        expires_at: NOW + 86400,
        rollout: Rollout {
            batch_size: 1,
            soak_s: 60,
            max_failures: 0,
        },
        maintenance_window: None,
        wrapped_keys: vec![],
    };
    let dp = f.w.join("dep.json");
    let doc = to_canonical(&d).unwrap();
    fs::write(&dp, &doc).unwrap();
    let mut s = SignatureSet::empty();
    for key in [&f.k.depot, &f.k.ops[0], &f.k.ops[1]] {
        s.add(key, DEPLOYMENT_SIG_DOMAIN, &doc).unwrap();
    }
    fs::write(ops::sig_path(&dp), s.to_bytes().unwrap()).unwrap();
    let r = present(&f.v1, &f.v2, &f.k).and_then(|t| ops::verify_deployment_file(&dp, &t, NOW));
    assert!(
        r.is_err(),
        "deployment of a revoked RPK accepted under the older trust file"
    );
}

#[test]
fn f4_repair_refuses_an_older_trust_file() {
    let f = f4();
    let v1 = load(&f.v1, &f.k).unwrap();
    let r = signed_rpk(
        &f.w,
        "mission-cfg",
        1,
        &[("m.yaml", b"m")],
        &[&f.k.rel[1], &f.k.rel[2]],
    );
    // Bundle signed by rel-a (revoked in v2) and rel-b.
    let b = signed_bundle(
        &f.w,
        &v1,
        1,
        None,
        &[r],
        Some((2, 1, 512)),
        "bundle-1",
        &[&f.k.rel[0], &f.k.rel[1]],
    );
    let r = present(&f.v1, &f.v2, &f.k).and_then(|t| ops::repair_bundle(&b, &t));
    assert!(
        r.is_err(),
        "repair trusted a bundle signed by a revoked key"
    );
}

/// On the `--state` path, a newer root-signed trust file must not drop a
/// revocation (§3.5 rule 25: revocations only grow).
#[test]
fn f4_state_path_refuses_a_newer_file_that_drops_a_revocation() {
    let f = f4();
    let v1 = load(&f.v1, &f.k).unwrap();
    let v2 = present(&f.v2, &f.v2, &f.k).unwrap();
    let r = signed_rpk(
        &f.w,
        "mission-cfg",
        1,
        &[("m.yaml", b"m")],
        &[&f.k.rel[1], &f.k.rel[2]],
    );
    let b1 = signed_bundle(
        &f.w,
        &v1,
        1,
        None,
        &[r],
        None,
        "b1",
        &[&f.k.rel[1], &f.k.rel[2]],
    );
    let state = f.w.join("chain.json");
    let r1 = ops::verify_bundle_dir(&b1, &v2, &ChainMode::Genesis, NOW).unwrap();
    ops::commit_chain(&state, &r1.bundle, &v2).unwrap();
    // v3: newer, root-signed, rel-a's revocation dropped.
    let mut t3 = trust_file(&f.k);
    t3.version = 3;
    t3.revoked_rpks = vec![digest_of(&f.x)];
    let v3p = put(&f.w, "trust-v3.json", &t3, &f.k);
    let r2 = signed_rpk(
        &f.w,
        "mission-cfg",
        2,
        &[("m.yaml", b"evil")],
        &[&f.k.rel[0], &f.k.rel[1]],
    );
    let b2 = signed_bundle(
        &f.w,
        &v1,
        2,
        Some(r1.bundle.hash.clone()),
        &[r2],
        None,
        "b2",
        &[&f.k.rel[0], &f.k.rel[1]],
    );
    let st = ChainMode::State(state);
    let r = present(&v3p, &f.v2, &f.k).and_then(|t| ops::verify_bundle_dir(&b2, &t, &st, NOW));
    assert!(
        r.is_err(),
        "a newer trust file dropped a revocation on the state path"
    );
}

// ---------------------------------------------------------------------------
// Finding 5 (Medium): release keys scoped to programmes.
// ---------------------------------------------------------------------------

fn prog(name: &str, keys: &[&str], packages: &[&str]) -> Programme {
    Programme {
        name: name.into(),
        release_keys: keys.iter().map(|x| x.to_string()).collect(),
        packages: packages.iter().map(|x| x.to_string()).collect(),
    }
}

/// Programme ugv-x1 (vendor 1: rel-a, rel-b; nav-stack, mission-cfg) and
/// ugv-y2 (vendor 2: rel-c, rel-d; arm-ctl).
fn two_programmes(k: &Keys, rel_d: &robodr_blackbox::Ed25519SigningKey) -> TrustFile {
    let mut t = trust_file(k);
    t.programmes = vec![
        prog("ugv-x1", &["rel-a", "rel-b"], &["mission-cfg", "nav-stack"]),
        prog("ugv-y2", &["rel-c", "rel-d"], &["arm-ctl"]),
    ];
    t.release_keys.push(tk(rel_d));
    t
}

/// An unsigned RPK built with this tool (the attacker signs it raw).
fn built_rpk(w: &Path, name: &str, serial: u64, body: &[u8]) -> PathBuf {
    signed_rpk(w, name, serial, &[("bin/x", body)], &[])
}

#[test]
fn f5_another_programmes_release_quorum_cannot_sign_for_this_one() {
    let tmp = Tmp::new("f5");
    let w = tmp.path();
    let k = keys();
    let rel_d = key("rel-d", 14);
    let tp = put(w, "trust.json", &two_programmes(&k, &rel_d), &k);
    let t = unanchored(&tp, &k).unwrap();
    // Vendor 2's keys sign a nav-stack RPK (a package of ugv-x1).
    let r = built_rpk(w, "nav-stack", 7, b"trojan");
    raw_sign_rpk(&r, &[&k.rel[2], &rel_d]);
    assert!(
        ops::verify_rpk_dir(&r, &t, NOW).is_err(),
        "vendor 2 signed an RPK of programme ugv-x1"
    );
    assert_eq!(code(ops::verify_rpk_dir(&r, &t, NOW)), Code::WrongScope);
    // ... and this tool refuses to add such a signature.
    let r2 = built_rpk(w, "nav-stack", 8, b"trojan");
    assert_eq!(
        code(ops::sign(&Target::Rpk(r2), &k.rel[2], Some(&*t), NOW)),
        Code::WrongScope
    );
    // Vendor 2 signs bundle 1 of ugv-x1 (built with a permissive trust,
    // since this tool would not assemble it): refused, so the real
    // bundle 1 is not frozen out as an equivocation.
    let mut lax = trust_file(&k);
    lax.release_keys.push(tk(&rel_d));
    lax.programmes = vec![prog(
        "ugv-x1",
        &["rel-a", "rel-b", "rel-c", "rel-d"],
        &["*"],
    )];
    let laxp = put(w, "trust-lax.json", &lax, &k);
    let lt = load(&laxp, &k).unwrap();
    let good = built_rpk(w, "mission-cfg", 1, b"ok");
    raw_sign_rpk(&good, &[&k.rel[0], &k.rel[1]]);
    let b = signed_bundle(
        w,
        &lt,
        1,
        None,
        std::slice::from_ref(&good),
        None,
        "b1",
        &[],
    );
    raw_sign_bundle(&b, &[&k.rel[2], &rel_d]);
    assert!(
        ops::verify_bundle_dir(&b, &t, &ChainMode::Genesis, NOW).is_err(),
        "vendor 2 signed a bundle of programme ugv-x1"
    );
    assert_eq!(
        code(ops::verify_bundle_dir(&b, &t, &ChainMode::Genesis, NOW)),
        Code::WrongScope
    );
    // A ugv-y2 bundle may not carry ugv-x1's package either.
    let mut m = robodr_pkg::bundle::parse_bundle(&fs::read(b.join(BUNDLE_FILE)).unwrap()).unwrap();
    m.programme = "ugv-y2".into();
    fs::write(b.join(BUNDLE_FILE), to_canonical(&m).unwrap()).unwrap();
    raw_sign_bundle(&b, &[&k.rel[2], &rel_d]);
    assert_eq!(
        code(ops::verify_bundle_dir(&b, &t, &ChainMode::Genesis, NOW)),
        Code::WrongScope
    );
    // Positive control: each vendor signs its own programme.
    let b1 = signed_bundle(
        w,
        &t,
        1,
        None,
        &[good],
        None,
        "b1-ok",
        &[&k.rel[0], &k.rel[1]],
    );
    ops::verify_bundle_dir(&b1, &t, &ChainMode::Genesis, NOW).unwrap();
    let arm = built_rpk(w, "arm-ctl", 1, b"arm");
    raw_sign_rpk(&arm, &[&k.rel[2], &rel_d]);
    ops::verify_rpk_dir(&arm, &t, NOW).unwrap();
}

// ---------------------------------------------------------------------------
// Finding 6 (Medium, design): verify-then-use on removable media.
// ---------------------------------------------------------------------------

fn trust_cli(tp: &Path, anchor: &Path, k: &Keys) -> Vec<String> {
    let mut v = sv(&["--trust", tp.to_str().unwrap(), "--site", SITE]);
    for f in pins(k) {
        v.extend(["--root".into(), f]);
    }
    v.extend([
        "--trust-anchor".into(),
        p(anchor),
        "--now".into(),
        NOW.to_string(),
    ]);
    v
}

#[test]
fn f6_import_copies_then_verifies_and_refuses_links() {
    let tmp = Tmp::new("f6");
    let w = tmp.path();
    let k = keys();
    let tp = site_trust(w, &k);
    let t = load(&tp, &k).unwrap();
    let r = signed_rpk(
        w,
        "nav-stack",
        7,
        &[("bin/nav", b"v7")],
        &[&k.rel[0], &k.rel[1]],
    );
    let media = signed_bundle(
        w,
        &t,
        1,
        None,
        &[r],
        None,
        "media-b1",
        &[&k.rel[0], &k.rel[1]],
    );
    fs::create_dir_all(w.join("trusted")).unwrap();
    let anchor = w.join("trusted/anchor.json");
    let mut init = sv(&["verify", "trust", "--init-anchor"]);
    init.extend(trust_cli(&tp, &anchor, &k));
    let (c, _, e) = run(&init);
    assert_eq!(c, 0, "{e}");
    let import = |from: &Path, to: &Path, extra: &[&str]| {
        let mut args = sv(&["import", "--from"]);
        args.extend([p(from), "--to".into(), p(to)]);
        args.extend(trust_cli(&tp, &anchor, &k));
        args.extend(sv(extra));
        run(&args)
    };
    // A symlink or a stray file on the media: refused, and nothing is
    // left at --to.
    let bad = w.join("media-bad");
    copy_tree(&media, &bad);
    let chunk = fs::read_dir(bad.join("rpk_nav-stack_7_arm64/chunks"))
        .unwrap()
        .next()
        .unwrap()
        .unwrap()
        .path();
    let real = w.join("elsewhere");
    fs::copy(&chunk, &real).unwrap();
    fs::remove_file(&chunk).unwrap();
    std::os::unix::fs::symlink(&real, &chunk).unwrap();
    let to_bad = w.join("trusted/bad");
    let (c, _, e) = import(&bad, &to_bad, &["--genesis"]);
    assert_eq!(c, 1, "{e}");
    assert!(e.contains("refused (unexpected_file)"), "{e}");
    assert!(!to_bad.exists());
    let stray = w.join("media-stray");
    copy_tree(&media, &stray);
    fs::write(stray.join("autorun.sh"), b"x").unwrap();
    let (c, _, e) = import(&stray, &to_bad, &["--genesis"]);
    assert_eq!(c, 1, "{e}");
    assert!(!to_bad.exists());
    // The good media: copied, the copy verified, published at --to, the
    // chain state committed.
    let to = w.join("trusted/b1");
    let state = w.join("trusted/chain.json");
    let (c, out, e) = import(
        &media,
        &to,
        &["--state", state.to_str().unwrap(), "--genesis", "--commit"],
    );
    assert_eq!(c, 0, "import failed: {e}");
    assert!(out.contains("\"verified_copy\""), "{out}");
    assert!(out.contains("\"state_committed\": true"), "{out}");
    // The copy is complete and independent of the media: the media
    // serving other bytes afterwards changes nothing.
    let chunk = fs::read_dir(media.join("rpk_nav-stack_7_arm64/chunks"))
        .unwrap()
        .next()
        .unwrap()
        .unwrap()
        .path();
    fs::write(&chunk, b"swapped after verify").unwrap();
    let st = unanchored(&tp, &k).unwrap();
    ops::verify_bundle_dir(&to, &st, &ChainMode::Genesis, NOW).unwrap();
    // --to must not exist (never merged into an existing tree).
    let (c, _, _) = import(&media, &to, &["--genesis"]);
    assert_eq!(c, 1);
}

// ---------------------------------------------------------------------------
// Finding 7 (Low): hash before size.
// ---------------------------------------------------------------------------

#[test]
fn f7_a_huge_sparse_file_is_refused_by_size_before_hashing() {
    let tmp = Tmp::new("f7");
    let w = tmp.path().to_path_buf();
    let k = keys();
    let tp = site_trust(&w, &k);
    let t = unanchored(&tp, &k).unwrap();
    let r = signed_rpk(
        &w,
        "nav-stack",
        7,
        &[("bin/nav", b"v7")],
        &[&k.rel[0], &k.rel[1]],
    );
    let b = signed_bundle(&w, &t, 1, None, &[r], None, "b1", &[&k.rel[0], &k.rel[1]]);
    let chunk = fs::read_dir(b.join("rpk_nav-stack_7_arm64/chunks"))
        .unwrap()
        .next()
        .unwrap()
        .unwrap()
        .path();
    // 1 TiB, sparse: hashing it would take hours.
    let f = fs::OpenOptions::new().write(true).open(&chunk).unwrap();
    f.set_len(1 << 40).unwrap();
    drop(f);
    let (tx, rx) = std::sync::mpsc::channel();
    std::thread::spawn(move || {
        let r = ops::verify_bundle_dir(&b, &t, &ChainMode::Genesis, NOW).map(|_| ());
        let _ = tx.send(r.is_err());
    });
    let refused = rx
        .recv_timeout(Duration::from_secs(20))
        .expect("verify still hashing a 1 TiB sparse file after 20 s");
    assert!(refused);
}

// ---------------------------------------------------------------------------
// Finding 8 (Low): -h / --help inside verify arguments.
// ---------------------------------------------------------------------------

#[test]
fn f8_help_among_other_arguments_is_not_success() {
    for extra in ["-h", "--help"] {
        let (c, _, _) = run(&sv(&[
            "verify",
            "bundle",
            "--dir",
            "/nonexistent",
            "--genesis",
            extra,
        ]));
        assert_ne!(c, 0, "verify ... {extra} exited 0");
        let (c, _, _) = run(&sv(&["verify", extra, "bundle"]));
        assert_ne!(c, 0, "verify {extra} bundle exited 0");
    }
    // --help alone is still the usage, exit 0.
    assert_eq!(run(&sv(&["--help"])).0, 0);
    assert_eq!(run(&sv(&["-h"])).0, 0);
}

// ---------------------------------------------------------------------------
// Finding 9 (Low): sign checks the RPKs inside a bundle and existing
// entries before adding a signature.
// ---------------------------------------------------------------------------

#[test]
fn f9_sign_refuses_a_bundle_with_an_unsigned_rpk_or_a_stale_entry() {
    let tmp = Tmp::new("f9");
    let w = tmp.path();
    let k = keys();
    let tp = site_trust(w, &k);
    let t = load(&tp, &k).unwrap();
    let r = signed_rpk(
        w,
        "nav-stack",
        7,
        &[("bin/nav", b"v7")],
        &[&k.rel[0], &k.rel[1]],
    );
    let b = signed_bundle(w, &t, 1, None, &[r], None, "b1", &[]);
    // Swap the RPK's MANIFEST.sig for a one-signature set and relist it
    // (bundle.json is not signed yet, so the listing is the builder's).
    let rdir = b.join("rpk_nav-stack_7_arm64");
    let doc = fs::read(rdir.join(MANIFEST_FILE)).unwrap();
    let mut one = SignatureSet::empty();
    one.add(&k.rel[0], MANIFEST_SIG_DOMAIN, &doc).unwrap();
    let ob = one.to_bytes().unwrap();
    fs::write(rdir.join(SIGNATURE_FILE), &ob).unwrap();
    let mut m = robodr_pkg::bundle::parse_bundle(&fs::read(b.join(BUNDLE_FILE)).unwrap()).unwrap();
    for f in &mut m.files {
        if f.path.ends_with(SIGNATURE_FILE) {
            f.size = ob.len() as u64;
            f.sha256 = sha256_hex(&ob);
        }
    }
    fs::write(b.join(BUNDLE_FILE), to_canonical(&m).unwrap()).unwrap();
    assert!(
        ops::sign(&Target::Bundle(b.clone()), &k.rel[0], Some(&t), NOW).is_err(),
        "signed a bundle whose RPK lacks the release quorum"
    );
    assert_eq!(
        code(ops::sign(
            &Target::Bundle(b.clone()),
            &k.rel[0],
            Some(&t),
            NOW
        )),
        Code::QuorumNotMet
    );
    assert!(!b.join(BUNDLE_SIG_FILE).exists(), "nothing written");
    // A stale entry already in bundle.sig (over other bytes).
    let cfg = signed_rpk(w, "mission-cfg", 1, &[("m", b"m")], &[&k.rel[0], &k.rel[1]]);
    let b2 = signed_bundle(w, &t, 1, None, &[cfg], None, "b2", &[]);
    let mut stale = SignatureSet::empty();
    stale
        .add(
            &k.rel[1],
            robodr_pkg::bundle::BUNDLE_SIG_DOMAIN,
            b"other bytes",
        )
        .unwrap();
    fs::write(b2.join(BUNDLE_SIG_FILE), stale.to_bytes().unwrap()).unwrap();
    assert!(
        ops::sign(&Target::Bundle(b2.clone()), &k.rel[0], Some(&t), NOW).is_err(),
        "added a signature next to an invalid one"
    );
    assert_eq!(
        code(ops::sign(
            &Target::Bundle(b2.clone()),
            &k.rel[0],
            Some(&t),
            NOW
        )),
        Code::BadSignature
    );
    // A key the site does not trust cannot sign either (checked before
    // anything is written), nor can a depot key sign a bundle.
    fs::remove_file(b2.join(BUNDLE_SIG_FILE)).unwrap();
    assert_eq!(
        code(ops::sign(
            &Target::Bundle(b2.clone()),
            &k.evil,
            Some(&t),
            NOW
        )),
        Code::UnknownKey
    );
    assert_eq!(
        code(ops::sign(
            &Target::Bundle(b2.clone()),
            &k.depot,
            Some(&t),
            NOW
        )),
        Code::WrongRole
    );
    assert!(!b2.join(BUNDLE_SIG_FILE).exists());
    // Signing an RPK, a bundle or a deployment needs the site trust.
    assert!(ops::sign(&Target::Bundle(b2), &k.rel[0], None, NOW).is_err());
}

/// Finding 9 (Low): quorums are capped at the 16-signature limit; a
/// trust file asking for more is refused rather than refusing everything.
#[test]
fn f9_a_quorum_above_the_signature_cap_is_refused() {
    let tmp = Tmp::new("f9q");
    let w = tmp.path();
    let mut k = keys();
    k.rel = (0..17u8)
        .map(|i| key(&format!("rel-{i:02}"), 100 + i))
        .collect();
    let mut t = trust_file(&k);
    t.quorum.release = 17;
    let tp = put(w, "trust.json", &t, &k);
    assert_eq!(code(load(&tp, &k)), Code::Invalid);
}

/// Findings 1 and 4 through the binary: one anchor for every command,
/// advanced only by `verify trust --commit` of a rotation.
#[test]
fn f1_f4_cli_trust_anchor_flow() {
    let f = f4();
    let k = &f.k;
    let anchor = f.w.join("site-anchor.json");
    let cmd = |head: &[&str], trust: &Path, extra: &[&str]| {
        let mut v = sv(head);
        v.extend(trust_cli(trust, &anchor, k));
        v.extend(sv(extra));
        run(&v)
    };
    let (c, _, e) = cmd(&["verify", "trust", "--init-anchor"], &f.v1, &[]);
    assert_eq!(c, 0, "{e}");
    // A second --init-anchor never overwrites the anchor.
    assert_eq!(cmd(&["verify", "trust", "--init-anchor"], &f.v2, &[]).0, 1);
    let xdir = p(&f.x);
    // Under v1, X verifies; then v2 (revokes X) is committed as a rotation.
    assert_eq!(cmd(&["verify", "rpk", "--dir", &xdir], &f.v1, &[]).0, 0);
    let (c, out, e) = cmd(&["verify", "trust", "--commit"], &f.v2, &[]);
    assert_eq!(c, 0, "{e}");
    assert!(out.contains("\"anchor_written\": true"), "{out}");
    // Now v1 is a replay for every command.
    for head in [
        vec!["verify", "rpk", "--dir", xdir.as_str()],
        vec!["verify", "trust"],
        vec!["repair", "--dir", xdir.as_str()],
    ] {
        let (c, _, e) = cmd(&head, &f.v1, &[]);
        assert_eq!(c, 1, "{head:?}");
        assert!(e.contains("refused (replay)"), "{head:?}: {e}");
    }
    let (c, _, e) = cmd(&["verify", "rpk", "--dir", &xdir], &f.v2, &[]);
    assert_eq!(c, 1);
    assert!(e.contains("refused (revoked_rpk)"), "{e}");
    // Another site's newer file: wrong scope, and the anchor is unchanged.
    let mut b3 = trust_file(k);
    b3.site = "site-b".into();
    b3.version = 3;
    let b3p = put(&f.w, "trust-b-v3.json", &b3, k);
    let (c, _, e) = cmd(&["verify", "trust", "--commit"], &b3p, &[]);
    assert_eq!(c, 1);
    assert!(e.contains("refused (wrong_scope)"), "{e}");
    assert_eq!(fs::read(&anchor).unwrap(), fs::read(&f.v2).unwrap());
    // Neither --trust-anchor nor --no-trust-anchor: usage error.
    let mut v = sv(&["verify", "rpk", "--dir", &xdir, "--trust"]);
    v.extend([p(&f.v1), "--site".into(), SITE.into()]);
    for r in pins(k) {
        v.extend(["--root".into(), r]);
    }
    assert_eq!(run(&v).0, 2);
    // The explicit opt-out still checks pins, site and expiry, nothing else.
    v.push("--no-trust-anchor".into());
    v.extend(["--now".into(), NOW.to_string()]);
    assert_eq!(run(&v).0, 0);
}
