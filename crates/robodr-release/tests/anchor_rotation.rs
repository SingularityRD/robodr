//! Review finding (MED): the trust anchor across a **root-set rotation**
//! and a crash during its commit.
//!
//! `SiteTrust::anchored` checked the stored anchor against the configured
//! root pins exactly, so once a rotation that replaced the roots was
//! committed, the anchor no longer verified: every later import was
//! refused and, on a unit, the site's revocation and floor checks were
//! silently skipped. And `commit_anchor` wrote the document and its
//! signature with two renames: a crash between them left a pair that did
//! not verify. The anchor now keeps its accepted rotations in one record
//! (`FILE.chain`) committed by a single rename.

mod common;

use common::*;
use robodr_pkg::Code;
use robodr_release::fsio::Fail;
use robodr_release::ops;

fn code<T: std::fmt::Debug>(r: Result<T, Fail>) -> Code {
    match r {
        Err(Fail::Refused(r)) => r.code,
        other => panic!("expected a refusal, got {other:?}"),
    }
}

/// Root keys 4..=6, which replace roots 1..=3.
fn new_roots() -> Vec<robodr_blackbox::Ed25519SigningKey> {
    (4..=6).map(|i| key(&format!("root-{i}"), 40 + i)).collect()
}

#[test]
fn a_root_set_rotation_keeps_the_anchor_verifying_under_the_configured_pins() {
    let tmp = Tmp::new("rootrot");
    let w = tmp.path();
    let k = keys();
    let t1 = put(w, "trust-1.json", &trust_file(&k), &k);
    let a = w.join("anchor.json");
    init_anchor(&t1, &a, &k);
    // Version 2 replaces the roots: signed by two old and two new roots.
    let nr = new_roots();
    let mut t2 = trust_file(&k);
    t2.version = 2;
    t2.roots = nr.iter().map(tk).collect();
    let p2 = write_trust(
        w,
        "trust-2.json",
        &t2,
        &[&k.roots[0], &k.roots[1], &nr[0], &nr[1]],
    );
    let st = anchored(&p2, &a, &k).unwrap();
    assert!(ops::commit_anchor(&st).unwrap());
    // The anchor still loads under the configured (old) pins...
    let now = ops::read_anchor(&a, &pins(&k), SITE).unwrap();
    assert_eq!(now.file().version, 2);
    anchored(&p2, &a, &k).unwrap();
    // ...and accepts the next rotation, signed by the new roots only.
    let mut t3 = t2.clone();
    t3.version = 3;
    t3.revoked_rpks = vec!["ab".repeat(32)];
    let p3 = write_trust(w, "trust-3.json", &t3, &[&nr[0], &nr[1]]);
    let st = anchored(&p3, &a, &k).unwrap();
    assert!(st.is_rotation());
    assert!(ops::commit_anchor(&st).unwrap());
    assert_eq!(
        ops::read_anchor(&a, &pins(&k), SITE)
            .unwrap()
            .file()
            .version,
        3
    );
    // The old roots alone can no longer rotate it.
    let mut t4 = t3.clone();
    t4.version = 4;
    let p4 = put(w, "trust-4.json", &t4, &k);
    assert!(matches!(
        code(anchored(&p4, &a, &k)),
        Code::UnknownKey | Code::QuorumNotMet
    ));
    // Operators may pin the new roots instead; the old pins still work.
    let new_pins: Vec<String> = nr
        .iter()
        .map(|r| robodr_pkg::common::fingerprint(&r.public_key()))
        .collect();
    assert_eq!(
        ops::read_anchor(&a, &new_pins, SITE)
            .unwrap()
            .file()
            .version,
        3
    );
    // A root-signed file of another set of roots is no anchor.
    assert!(ops::read_anchor(&a, &[fingerprint_of(&k.evil)], SITE).is_err());
}

fn fingerprint_of(k: &robodr_blackbox::Ed25519SigningKey) -> String {
    robodr_pkg::common::fingerprint(&k.public_key())
}

#[test]
fn a_crash_between_the_mirror_writes_leaves_a_verifying_anchor() {
    let tmp = Tmp::new("tornanchor");
    let w = tmp.path();
    let k = keys();
    let t1 = put(w, "trust-1.json", &trust_file(&k), &k);
    let a = w.join("anchor.json");
    init_anchor(&t1, &a, &k);
    let old_doc = std::fs::read(&a).unwrap();
    let mut t2 = trust_file(&k);
    t2.version = 2;
    let p2 = put(w, "trust-2.json", &t2, &k);
    let st = anchored(&p2, &a, &k).unwrap();
    assert!(ops::commit_anchor(&st).unwrap());
    // The crash: the new signature is in place, the document is not.
    std::fs::write(&a, &old_doc).unwrap();
    let t = ops::read_anchor(&a, &pins(&k), SITE).unwrap();
    assert_eq!(t.file().version, 2);
    // The mirror was repaired from the record.
    assert_eq!(std::fs::read(&a).unwrap(), std::fs::read(&p2).unwrap());
    assert_eq!(
        std::fs::read(ops::sig_path(&a)).unwrap(),
        std::fs::read(ops::sig_path(&p2)).unwrap()
    );
    anchored(&p2, &a, &k).unwrap();
    assert_eq!(code(anchored(&t1, &a, &k)), Code::Replay);
    // A deleted mirror is rewritten too.
    std::fs::remove_file(&a).unwrap();
    std::fs::remove_file(ops::sig_path(&a)).unwrap();
    assert_eq!(
        ops::read_anchor(&a, &pins(&k), SITE)
            .unwrap()
            .file()
            .version,
        2
    );
    assert!(a.exists());
}

#[test]
fn many_rotations_keep_a_short_record() {
    let tmp = Tmp::new("longchain");
    let w = tmp.path();
    let k = keys();
    let t1 = put(w, "trust-1.json", &trust_file(&k), &k);
    let a = w.join("anchor.json");
    init_anchor(&t1, &a, &k);
    for v in 2..=(ops::MAX_ANCHOR_CHAIN as u64 + 4) {
        let mut t = trust_file(&k);
        t.version = v;
        let p = put(w, &format!("trust-{v}.json"), &t, &k);
        let st = anchored(&p, &a, &k).unwrap();
        assert!(ops::commit_anchor(&st).unwrap());
    }
    let rec: serde_json::Value =
        serde_json::from_slice(&std::fs::read(ops::anchor_chain_path(&a)).unwrap()).unwrap();
    assert_eq!(rec["chain"].as_array().unwrap().len(), 1);
}
