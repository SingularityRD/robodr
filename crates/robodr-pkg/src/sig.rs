//! Detached signature sets (`robodr-sigset/1`) and quorum checks.
//!
//! Every signed document (`MANIFEST.json` of an RPK, `bundle.json`, a
//! deployment, a trust file) has a detached signature file:
//!
//! ```json
//! {"format":"robodr-sigset/1","signatures":[
//!   {"key_id":"rel-a","algorithm":"ed25519","sig":"<128 hex>"}, ...]}
//! ```
//!
//! Each signature is Ed25519 (strict verification, `robodr-blackbox`) over
//! `domain || document bytes`, with a domain per document type, so a
//! signature over one kind of document never verifies as another.
//!
//! # Rules (decision, `docs/SECURE-DELIVERY.md` §3.5)
//!
//! * 1..=[`MAX_SIGNATURES`] entries, sorted by `key_id`, no duplicates
//!   (canonical encoding like every document).
//! * **Every** entry must be valid: a key the trust file lists, of a role
//!   allowed for this document, not revoked, and a signature that verifies.
//!   One bad entry refuses the document; a broken or foreign signature is
//!   never silently skipped. (A courier who can add a garbage entry can
//!   also drop the bundle, so this costs no availability an attacker does
//!   not already have.)
//! * Signers are counted **by public-key fingerprint**, not by key id: two
//!   entries by the same key are refused ([`Code::DuplicateSigner`]), and
//!   the trust file maps key ids to keys one to one.
//! * The quorum is checked per role by the caller ([`Signers::count`]).

use crate::common::{
    domain_message, invalid, is_key_id, parse_canonical, strictly_sorted, to_canonical, Code,
    Refusal,
};
use robodr_blackbox::crypto::{from_hex, to_hex};
use robodr_blackbox::sign_ed25519::{self, ED25519, SIGNATURE_LEN};
use robodr_blackbox::Signer;
use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;

/// `format` of a signature set.
pub const SIGSET_FORMAT: &str = "robodr-sigset/1";
/// Most signatures on one document.
pub const MAX_SIGNATURES: usize = 16;
/// Largest signature file read.
pub const MAX_SIGSET_BYTES: usize = 8 * 1024;

/// One detached signature.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SignatureEntry {
    pub key_id: String,
    /// Always `ed25519`.
    pub algorithm: String,
    /// 128 lower-case hex digits (`R || S`).
    pub sig: String,
}

/// The contents of a detached signature file.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SignatureSet {
    pub format: String,
    pub signatures: Vec<SignatureEntry>,
}

/// The role a trusted key holds (`docs/SECURE-DELIVERY.md` §3.4). Roles
/// are disjoint: a trust file that gives one key two roles is refused.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Role {
    Root,
    Release,
    Depot,
    Operator,
}

impl Role {
    pub fn as_str(self) -> &'static str {
        match self {
            Role::Root => "root",
            Role::Release => "release",
            Role::Depot => "depot",
            Role::Operator => "operator",
        }
    }
}

/// A trusted public key as the verifier resolved it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct KeyInfo {
    pub role: Role,
    pub public: [u8; 32],
    pub fingerprint: String,
}

/// Where signature checks look keys up (a verified trust file, or the
/// union of two during a trust rotation).
pub trait KeyLookup {
    /// The key listed under `key_id`, if any.
    fn key(&self, key_id: &str) -> Option<&KeyInfo>;
    /// Whether a key fingerprint is revoked.
    fn is_revoked(&self, fingerprint: &str) -> bool;
}

/// Distinct valid signers of a document, by role and fingerprint.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Signers(pub BTreeSet<(Role, String)>);

impl Signers {
    /// Number of distinct keys of `role` that signed.
    pub fn count(&self, role: Role) -> usize {
        self.0.iter().filter(|(r, _)| *r == role).count()
    }

    /// Fingerprints of the signers of `role`.
    pub fn of(&self, role: Role) -> Vec<&str> {
        self.0
            .iter()
            .filter(|(r, _)| *r == role)
            .map(|(_, f)| f.as_str())
            .collect()
    }

    /// Refuse unless at least `quorum` distinct `role` keys signed.
    pub fn require(&self, role: Role, quorum: usize, what: &str) -> Result<(), Refusal> {
        let n = self.count(role);
        if n < quorum {
            return Err(Refusal::new(
                Code::QuorumNotMet,
                format!(
                    "{what}: {n} valid {} signature(s), quorum is {quorum}",
                    role.as_str()
                ),
            ));
        }
        Ok(())
    }
}

impl SignatureSet {
    /// An empty set (not valid on its own: a set needs one signature).
    pub fn empty() -> Self {
        Self {
            format: SIGSET_FORMAT.into(),
            signatures: Vec::new(),
        }
    }

    /// Parse a signature file strictly (canonical, sorted, well formed).
    pub fn parse(bytes: &[u8]) -> Result<Self, Refusal> {
        let s: Self = parse_canonical(bytes, MAX_SIGSET_BYTES, "signature file")?;
        s.validate()?;
        Ok(s)
    }

    /// Structural checks (not the signatures themselves).
    pub fn validate(&self) -> Result<(), Refusal> {
        if self.format != SIGSET_FORMAT {
            return Err(invalid("signature file: unsupported format"));
        }
        if self.signatures.is_empty() {
            return Err(Refusal::new(
                Code::QuorumNotMet,
                "signature file has no signatures",
            ));
        }
        if self.signatures.len() > MAX_SIGNATURES {
            return Err(invalid(format!(
                "signature file: more than {MAX_SIGNATURES} signatures"
            )));
        }
        for s in &self.signatures {
            if !is_key_id(&s.key_id) {
                return Err(invalid("signature file: bad key_id"));
            }
            if s.algorithm != ED25519 {
                return Err(Refusal::new(
                    Code::Unsupported,
                    "signature file: only ed25519 signatures are accepted",
                ));
            }
            if s.sig.len() != 2 * SIGNATURE_LEN
                || !s
                    .sig
                    .bytes()
                    .all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f'))
            {
                return Err(invalid(
                    "signature file: sig is not 128 lower-case hex digits",
                ));
            }
        }
        strictly_sorted(
            &self.signatures,
            |s| s.key_id.clone(),
            "signatures (by key_id)",
        )
    }

    /// The canonical bytes of this set.
    pub fn to_bytes(&self) -> Result<Vec<u8>, Refusal> {
        to_canonical(self)
    }

    /// Add a signature by `signer` over `domain || document`. Refuses a
    /// second signature under the same key id, a non-Ed25519 signer and a
    /// full set. Keeps the entries sorted.
    pub fn add(
        &mut self,
        signer: &dyn Signer,
        domain: &[u8],
        document: &[u8],
    ) -> Result<(), Refusal> {
        if signer.algorithm() != ED25519 {
            return Err(Refusal::new(
                Code::Unsupported,
                "only ed25519 keys sign delivery documents",
            ));
        }
        let key_id = signer.key_id().to_string();
        if !is_key_id(&key_id) {
            return Err(invalid(format!(
                "key id {key_id:?} is not [A-Za-z0-9._:-]{{1,64}}"
            )));
        }
        if self.signatures.iter().any(|s| s.key_id == key_id) {
            return Err(Refusal::new(
                Code::DuplicateSigner,
                format!("already signed by {key_id}"),
            ));
        }
        if self.signatures.len() >= MAX_SIGNATURES {
            return Err(invalid(format!("already {MAX_SIGNATURES} signatures")));
        }
        let sig = signer
            .sign(&domain_message(domain, document))
            .map_err(|e| invalid(e.to_string()))?;
        let pos = self
            .signatures
            .partition_point(|s| s.key_id.as_str() < key_id.as_str());
        self.signatures.insert(
            pos,
            SignatureEntry {
                key_id,
                algorithm: ED25519.into(),
                sig: to_hex(&sig),
            },
        );
        Ok(())
    }

    /// Check every entry (see the module docs) against `keys`, allowing
    /// only keys of `allowed` roles, over `domain || document`. Returns the
    /// distinct signers; the caller applies the quorum.
    pub fn check(
        &self,
        keys: &dyn KeyLookup,
        allowed: &[Role],
        domain: &[u8],
        document: &[u8],
    ) -> Result<Signers, Refusal> {
        self.validate()?;
        let message = domain_message(domain, document);
        let mut seen = BTreeSet::new();
        let mut out = Signers::default();
        for s in &self.signatures {
            let Some(k) = keys.key(&s.key_id) else {
                return Err(Refusal::new(
                    Code::UnknownKey,
                    format!(
                        "signature by key {:?}, which the trust file does not list",
                        s.key_id
                    ),
                ));
            };
            if keys.is_revoked(&k.fingerprint) {
                return Err(Refusal::new(
                    Code::RevokedKey,
                    format!("signature by revoked key {} ({})", s.key_id, k.fingerprint),
                ));
            }
            if !allowed.contains(&k.role) {
                return Err(Refusal::new(
                    Code::WrongRole,
                    format!(
                        "signature by {} key {}, which may not sign this document",
                        k.role.as_str(),
                        s.key_id
                    ),
                ));
            }
            if !seen.insert(k.fingerprint.clone()) {
                return Err(Refusal::new(
                    Code::DuplicateSigner,
                    format!("two signatures by the same key ({})", k.fingerprint),
                ));
            }
            let Some(sig) = from_hex(&s.sig) else {
                return Err(invalid("sig is not hex"));
            };
            if !sign_ed25519::verify(&k.public, &message, &sig) {
                return Err(Refusal::new(
                    Code::BadSignature,
                    format!("signature by {} does not verify", s.key_id),
                ));
            }
            out.0.insert((k.role, k.fingerprint.clone()));
        }
        Ok(out)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::common::fingerprint;
    use robodr_blackbox::Ed25519SigningKey;
    use std::collections::BTreeMap;

    struct Keys(BTreeMap<String, KeyInfo>, BTreeSet<String>);
    impl KeyLookup for Keys {
        fn key(&self, key_id: &str) -> Option<&KeyInfo> {
            self.0.get(key_id)
        }
        fn is_revoked(&self, f: &str) -> bool {
            self.1.contains(f)
        }
    }

    fn key(id: &str, seed: u8) -> Ed25519SigningKey {
        Ed25519SigningKey::from_seed(id, &[seed; 32]).unwrap()
    }

    fn keys(list: &[(&Ed25519SigningKey, Role)]) -> Keys {
        let mut m = BTreeMap::new();
        for (k, r) in list {
            let p = k.public_key();
            m.insert(
                k.key_id().to_string(),
                KeyInfo {
                    role: *r,
                    public: p,
                    fingerprint: fingerprint(&p),
                },
            );
        }
        Keys(m, BTreeSet::new())
    }

    const D: &[u8] = b"test/v1\0";

    #[test]
    fn quorum_counts_distinct_valid_keys() {
        let (a, b, c) = (key("a", 1), key("b", 2), key("c", 3));
        let ks = keys(&[(&a, Role::Release), (&b, Role::Release), (&c, Role::Depot)]);
        let mut s = SignatureSet::empty();
        s.add(&b, D, b"doc").unwrap();
        s.add(&a, D, b"doc").unwrap();
        assert_eq!(s.signatures[0].key_id, "a", "kept sorted");
        let bytes = s.to_bytes().unwrap();
        let s = SignatureSet::parse(&bytes).unwrap();
        let signers = s.check(&ks, &[Role::Release], D, b"doc").unwrap();
        assert_eq!(signers.count(Role::Release), 2);
        signers.require(Role::Release, 2, "x").unwrap();
        assert_eq!(
            signers.require(Role::Release, 3, "x").unwrap_err().code,
            Code::QuorumNotMet
        );
        // Other bytes, other domain: bad signature.
        assert_eq!(
            s.check(&ks, &[Role::Release], D, b"doc2").unwrap_err().code,
            Code::BadSignature
        );
        assert_eq!(
            s.check(&ks, &[Role::Release], b"other/v1\0", b"doc")
                .unwrap_err()
                .code,
            Code::BadSignature
        );
        // Wrong role.
        assert_eq!(
            s.check(&ks, &[Role::Depot], D, b"doc").unwrap_err().code,
            Code::WrongRole
        );
        // Revoked.
        let mut ks2 = keys(&[(&a, Role::Release), (&b, Role::Release)]);
        ks2.1.insert(fingerprint(&a.public_key()));
        assert_eq!(
            s.check(&ks2, &[Role::Release], D, b"doc").unwrap_err().code,
            Code::RevokedKey
        );
        // Unknown.
        let ks3 = keys(&[(&b, Role::Release)]);
        assert_eq!(
            s.check(&ks3, &[Role::Release], D, b"doc").unwrap_err().code,
            Code::UnknownKey
        );
        let _ = c;
    }

    #[test]
    fn same_key_under_two_ids_is_one_signer() {
        let a = key("a", 1);
        let a2 = key("a2", 1); // same seed, other id
        let ks = keys(&[(&a, Role::Release), (&a2, Role::Release)]);
        let mut s = SignatureSet::empty();
        s.add(&a, D, b"doc").unwrap();
        s.add(&a2, D, b"doc").unwrap();
        assert_eq!(
            s.check(&ks, &[Role::Release], D, b"doc").unwrap_err().code,
            Code::DuplicateSigner
        );
        // The same id twice cannot be added, and is not canonical when forged.
        assert_eq!(
            s.add(&a, D, b"doc").unwrap_err().code,
            Code::DuplicateSigner
        );
        let mut forged = s.clone();
        forged.signatures[1] = forged.signatures[0].clone();
        assert_eq!(forged.validate().unwrap_err().code, Code::Invalid);
    }

    #[test]
    fn malformed_sets_are_refused() {
        let a = key("a", 1);
        let mut s = SignatureSet::empty();
        assert_eq!(s.validate().unwrap_err().code, Code::QuorumNotMet);
        s.add(&a, D, b"doc").unwrap();
        let good = s.to_bytes().unwrap();
        for (bad, code) in [
            (
                String::from_utf8(good.clone())
                    .unwrap()
                    .replace("ed25519", "rsa"),
                Code::Unsupported,
            ),
            (
                String::from_utf8(good.clone())
                    .unwrap()
                    .replace("robodr-sigset/1", "x"),
                Code::Invalid,
            ),
            (
                String::from_utf8(good.clone())
                    .unwrap()
                    .replace("\"sig\":\"", "\"sig\":\"A"),
                Code::Invalid,
            ),
            (
                String::from_utf8(good.clone())
                    .unwrap()
                    .replace("}]}", ",\"x\":1}]}"),
                Code::Malformed,
            ),
            (
                String::from_utf8(good.clone()).unwrap().replace(",", ", "),
                Code::NonCanonical,
            ),
        ] {
            assert_eq!(
                SignatureSet::parse(bad.as_bytes()).unwrap_err().code,
                code,
                "{bad}"
            );
        }
        let mut many = SignatureSet::empty();
        for i in 0..MAX_SIGNATURES {
            many.add(&key(&format!("k{i:02}"), i as u8 + 1), D, b"d")
                .unwrap();
        }
        assert!(many.add(&key("zz", 99), D, b"d").is_err());
        let mut over = many.clone();
        over.signatures.push(SignatureEntry {
            key_id: "zzz".into(),
            algorithm: ED25519.into(),
            sig: "00".repeat(64),
        });
        assert_eq!(over.validate().unwrap_err().code, Code::Invalid);
    }
}
