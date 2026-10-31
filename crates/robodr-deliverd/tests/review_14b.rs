//! Regressions from the review of the 14a/14b delivery chain (trust
//! anchor on the unit). Each failed on the code before its fix.

mod common;

use common::*;
use robodr_blackbox::Ed25519SigningKey;
use robodr_pkg::common::to_canonical;
use robodr_pkg::sig::SignatureSet;
use robodr_pkg::trust::{TrustFile, TRUST_SIG_DOMAIN};
use std::path::Path;

fn write_signed(path: &Path, t: &TrustFile, by: &[&Ed25519SigningKey]) {
    let doc = to_canonical(t).unwrap();
    std::fs::write(path, &doc).unwrap();
    let mut s = SignatureSet::empty();
    for k in by {
        s.add(*k, TRUST_SIG_DOMAIN, &doc).unwrap();
    }
    std::fs::write(robodr_release::ops::sig_path(path), s.to_bytes().unwrap()).unwrap();
}

/// A unit with `app` v1 imported but not installed (the robot is moving).
fn imported_not_installed(tag: &str) -> (Unit, robodr_deliverd::Engine, String) {
    let u = Unit::new(tag);
    let r1 = u.rpk(&files_spec(&u, "app", 1, true), &[("ok", b"1")]);
    let digest = digest(&r1);
    let b1 = u.bundle(1, None, std::slice::from_ref(&r1));
    u.pack("p1", 1, std::slice::from_ref(&r1), &[b1]);
    u.safety("moving_fast");
    let mut e = u.open();
    u.run(&mut e, 3);
    assert_eq!(e.state().deployment.as_ref().unwrap().seq, 1);
    assert!(u.current(&u.cfg.install.files_root, "app").is_none());
    (u, e, digest)
}

/// Review finding (MED): a root-set rotation made the committed anchor
/// stop verifying under the configured pins; the agent then had no anchor
/// and installed without the site's revocations and floors.
#[test]
fn after_a_root_set_rotation_site_revocations_still_apply_at_install() {
    let (u, e, digest) = imported_not_installed("rootrot-revoked");
    drop(e);
    // Version 2: new roots (signed by the old and the new quorum), and
    // the RPK the unit holds revoked.
    let nr: Vec<Ed25519SigningKey> = (4..=6).map(|i| key(&format!("root-{i}"), 40 + i)).collect();
    let mut t2 = trust_file(&u.keys);
    t2.version = 2;
    t2.roots = nr.iter().map(tk).collect();
    t2.revoked_rpks = vec![digest.clone()];
    let p2 = u.work.join("trust-v2.json");
    write_signed(
        &p2,
        &t2,
        &[&u.keys.roots[0], &u.keys.roots[1], &nr[0], &nr[1]],
    );
    let st = robodr_release::ops::SiteTrust::anchored(
        &p2,
        &u.cfg.anchor_path(),
        &u.cfg.trust.roots,
        SITE,
        NOW,
    )
    .unwrap();
    assert!(robodr_release::ops::commit_anchor(&st).unwrap());
    let mut e = u.open();
    u.safety("idle");
    u.run(&mut e, 5);
    assert!(
        u.current(&u.cfg.install.files_root, "app").is_none(),
        "a revoked RPK was installed after a root-set rotation"
    );
    let refused = u.notes_of("robodr.deliver.refused");
    assert!(
        refused
            .iter()
            .any(|n| n.to_string().contains("revoked_rpk")),
        "{refused:?}"
    );
}

/// Review finding (MED): a missing or invalid anchor silently skipped the
/// site checks at install; it is now a locked state with a High finding.
#[test]
fn a_missing_anchor_locks_installs_with_a_high_finding() {
    let (u, e, _) = imported_not_installed("anchor-missing");
    drop(e);
    let a = u.cfg.anchor_path();
    for p in [
        a.clone(),
        robodr_release::ops::sig_path(&a),
        robodr_release::ops::anchor_chain_path(&a),
    ] {
        std::fs::remove_file(p).unwrap();
    }
    let mut e = u.open();
    u.safety("idle");
    let reps = u.run(&mut e, 4);
    assert!(
        u.current(&u.cfg.install.files_root, "app").is_none(),
        "installed without a trust anchor"
    );
    assert!(
        reps.iter().all(|r| r
            .deferred
            .as_deref()
            .is_some_and(|d| d.contains("trust anchor"))),
        "{reps:?}"
    );
    let f: Vec<_> = u
        .findings()
        .into_iter()
        .filter(|f| f.2.to_string().contains("trust_anchor"))
        .collect();
    assert_eq!(f.len(), 1, "{f:?}");
    assert_eq!(f[0].1, "high");
    // The anchor restored: the unit installs again.
    robodr_release::ops::init_anchor(&u.trust_path, &a, &u.cfg.trust.roots, SITE, NOW).unwrap();
    u.run(&mut e, 6);
    assert_eq!(
        u.current(&u.cfg.install.files_root, "app").as_deref(),
        Some("1")
    );
}
