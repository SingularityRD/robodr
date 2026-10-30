//! Shared by the `pkg_*` harnesses: a fixed site (keys from constant
//! seeds, a root-signed trust file), so signed seeds take the success
//! paths and mutations explore the signature, quorum and policy checks.
//! Included via `#[path]` by each `pkg_*` harness.
#![allow(dead_code)]

use robodr_blackbox::{Ed25519SigningKey, Signer};
use robodr_pkg::common::{fingerprint, to_canonical};
use robodr_pkg::sig::SignatureSet;
use robodr_pkg::trust::{
    verify_trust_pinned, Programme, Quorum, RingAssignment, TrustFile, TrustKey, VerifiedTrust,
    TRUST_FORMAT, TRUST_SIG_DOMAIN,
};
use std::sync::OnceLock;

/// "Now" for expiry checks (Unix seconds).
pub const NOW: u64 = 1_790_000_100;
pub const SITE: &str = "site-f";
pub const PROGRAMME: &str = "prog";

pub fn key(id: &str, seed: u8) -> Ed25519SigningKey {
    Ed25519SigningKey::from_seed(id, &[seed; 32]).expect("valid key id")
}

pub fn roots() -> Vec<Ed25519SigningKey> {
    (1..=3).map(|i| key(&format!("root-{i}"), i)).collect()
}

pub fn release() -> Vec<Ed25519SigningKey> {
    vec![key("rel-a", 11), key("rel-b", 12)]
}

pub fn depot() -> Ed25519SigningKey {
    key("depot-1", 21)
}

pub fn operators() -> Vec<Ed25519SigningKey> {
    vec![key("op-1", 31), key("op-2", 32)]
}

fn tk(k: &Ed25519SigningKey) -> TrustKey {
    TrustKey::new(k.key_id(), &k.public_key())
}

pub fn trust_file() -> TrustFile {
    TrustFile {
        format: TRUST_FORMAT.into(),
        site: SITE.into(),
        version: 1,
        issued_at: 1_790_000_000,
        expires_at: 1_790_000_000 + 90 * 86400,
        programmes: vec![Programme {
            name: PROGRAMME.into(),
            release_keys: vec!["rel-a".into(), "rel-b".into()],
            packages: vec!["mission-cfg".into(), "nav-*".into()],
        }],
        quorum: Quorum {
            root: 2,
            release: 2,
            operator_prod: 2,
            operator_lab: 1,
        },
        roots: roots().iter().map(tk).collect(),
        release_keys: release().iter().map(tk).collect(),
        depot_keys: vec![tk(&depot())],
        operator_keys: operators().iter().map(tk).collect(),
        rings: vec![RingAssignment {
            ring: "lab".into(),
            units: vec!["ugv-07".into()],
        }],
        revoked_keys: vec![],
        revoked_rpks: vec![],
        revoked_serials: vec![],
        floors: vec![],
        entry_keys: vec![],
        depot_wrap_keys: vec![],
        ek_ca_certs: vec![],
    }
}

/// `domain || doc` signed by `by`, as a canonical signature file.
pub fn sign(doc: &[u8], domain: &[u8], by: &[&Ed25519SigningKey]) -> Vec<u8> {
    let mut s = SignatureSet::empty();
    for k in by {
        s.add(*k, domain, doc).expect("sign");
    }
    s.to_bytes().expect("sigset")
}

pub fn pins() -> Vec<String> {
    roots()
        .iter()
        .map(|r| fingerprint(&r.public_key()))
        .collect()
}

/// The trust file bytes and their root signatures (roots 1 and 2).
pub fn trust_bytes() -> (Vec<u8>, Vec<u8>) {
    let doc = to_canonical(&trust_file()).expect("canonical");
    let r = roots();
    let sig = sign(&doc, TRUST_SIG_DOMAIN, &[&r[0], &r[1]]);
    (doc, sig)
}

/// The harness site's accepted trust.
pub fn trust() -> &'static VerifiedTrust {
    static T: OnceLock<VerifiedTrust> = OnceLock::new();
    T.get_or_init(|| {
        let (doc, sig) = trust_bytes();
        verify_trust_pinned(&doc, &sig, &pins(), SITE, NOW).expect("harness trust verifies")
    })
}

/// Split at NUL bytes into at most `n` parts.
pub fn split(data: &[u8], n: usize) -> Vec<&[u8]> {
    data.splitn(n, |&b| b == 0).collect()
}

/// `parts` joined with NUL.
pub fn join(parts: &[&[u8]]) -> Vec<u8> {
    parts.join(&0u8)
}
