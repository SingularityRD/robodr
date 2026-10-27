//! Harness: delivery trust file, standalone and as a rotation
//! (`robodr_pkg::trust`).
//!
//! Input: `trust.json \0 trust.sig \0 next.json \0 next.sig` (missing parts
//! are empty). Invariants beyond "no panic":
//!
//! * a trust file that parses is exactly its canonical encoding, its roles
//!   are disjoint (one fingerprint, one key id each) and its root and
//!   release quorums are reachable;
//! * a trust file that parses has `issued_at < expires_at`, a bounded
//!   lifetime, quorums within one signature set, programmes whose release
//!   keys are release keys, and each package name owned by at most one
//!   programme;
//! * a file accepted under the harness pins and site has exactly those
//!   roots, that site and has not expired;
//! * an update accepted from the harness site's trust keeps the site, has
//!   a version at least as high (equal only for the same bytes), keeps
//!   every revocation (keys, RPKs, serials), never lowers a floor and has
//!   not expired.
//!
//! Shared via `#[path]` with `crates/robodr-pkg/tests/fuzz_smoke.rs`.
#![allow(dead_code)]

#[path = "pkg_common.rs"]
mod pkg_common;

use pkg_common::*;
use robodr_pkg::common::to_canonical;
use robodr_pkg::trust::{self, verify_trust_pinned, verify_trust_update};
use std::collections::BTreeSet;

fn pf_serials_kept(
    prev: &robodr_pkg::trust::VerifiedTrust,
    n: &robodr_pkg::trust::VerifiedTrust,
) -> bool {
    prev.file()
        .revoked_serials
        .iter()
        .all(|r| n.file().revoked_serials.contains(r))
}

pub fn run(data: &[u8]) {
    let p = split(data, 4);
    let get = |i: usize| p.get(i).copied().unwrap_or(&[]);
    if let Ok(t) = trust::parse_trust(get(0)) {
        assert_eq!(to_canonical(&t.file).expect("ser"), get(0));
        let all: Vec<_> = t
            .file
            .roots
            .iter()
            .chain(&t.file.release_keys)
            .chain(&t.file.depot_keys)
            .chain(&t.file.operator_keys)
            .collect();
        let ids: BTreeSet<_> = all.iter().map(|k| k.key_id.clone()).collect();
        let pubs: BTreeSet<_> = all.iter().map(|k| k.public_hex.clone()).collect();
        assert_eq!(ids.len(), all.len());
        assert_eq!(pubs.len(), all.len());
        assert!(t.file.roots.len() >= t.file.quorum.root as usize);
        assert_eq!(t.root_fingerprints().len(), t.file.roots.len());
        let f = &t.file;
        assert!(f.issued_at < f.expires_at);
        assert!(f.expires_at - f.issued_at <= trust::MAX_TRUST_LIFETIME_S);
        let cap = robodr_pkg::sig::MAX_SIGNATURES as u32;
        assert!(f.quorum.root <= cap && f.quorum.release <= cap && f.quorum.operator_prod < cap);
        let rel: BTreeSet<_> = f.release_keys.iter().map(|k| k.key_id.as_str()).collect();
        let mut exact = BTreeSet::new();
        for p in &f.programmes {
            assert!(p.release_keys.len() >= f.quorum.release as usize);
            assert!(p.release_keys.iter().all(|k| rel.contains(k.as_str())));
            for x in p.packages.iter().filter(|x| !x.ends_with('*')) {
                assert!(exact.insert(x.clone()), "package {x} in two programmes");
            }
        }
    }
    if let Ok(v) = verify_trust_pinned(get(0), get(1), &pins(), SITE, NOW) {
        let want: BTreeSet<String> = pins().into_iter().collect();
        assert_eq!(v.root_fingerprints(), want);
        assert_eq!(v.file().site, SITE);
        assert!(NOW < v.file().expires_at);
    }
    let prev = trust();
    if let Ok(n) = verify_trust_update(prev, get(2), get(3), NOW) {
        assert!(NOW < n.file().expires_at);
        assert!(pf_serials_kept(prev, &n));
        let (pf, nf) = (prev.file(), n.file());
        assert_eq!(nf.site, pf.site);
        assert!(nf.version >= pf.version);
        if nf.version == pf.version {
            assert_eq!(n.digest, prev.digest);
        }
        assert!(pf.revoked_keys.iter().all(|k| nf.revoked_keys.contains(k)));
        assert!(pf.revoked_rpks.iter().all(|k| nf.revoked_rpks.contains(k)));
        for f in &pf.floors {
            assert!(nf
                .floors
                .iter()
                .any(|x| x.name == f.name && x.min_serial >= f.min_serial));
        }
    }
}

/// Seeds: the harness trust file with its signature, followed by a
/// version-2 update (a revocation and a floor) signed by two roots.
pub fn seeds() -> Vec<(&'static str, Vec<u8>)> {
    use robodr_pkg::trust::{Floor, TRUST_SIG_DOMAIN};
    let (doc, sig) = trust_bytes();
    let mut t2 = trust_file();
    t2.version = 2;
    t2.revoked_rpks = vec!["cd".repeat(32)];
    t2.revoked_serials = vec![trust::RevokedSerial {
        name: "nav-stack".into(),
        serial: 6,
    }];
    t2.floors = vec![Floor {
        name: "nav-stack".into(),
        min_serial: 5,
    }];
    let d2 = to_canonical(&t2).expect("ser");
    let r = roots();
    let s2 = sign(&d2, TRUST_SIG_DOMAIN, &[&r[1], &r[2]]);
    vec![("seed-v1-v2.bin", join(&[&doc, &sig, &d2, &s2]))]
}
