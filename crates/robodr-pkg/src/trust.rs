//! The delivery trust file (`robodr-delivery-trust/1`,
//! `docs/SECURE-DELIVERY.md` §3.4): which keys may sign what at one site,
//! quorums, revocations and floors.
//!
//! ```json
//! {"format":"robodr-delivery-trust/1","site":"site-a","version":3,"issued_at":1790000000,
//!  "programmes":["ugv-x1"],
//!  "quorum":{"root":2,"release":2,"operator_prod":2,"operator_lab":1},
//!  "roots":[{"key_id":"root-a","algorithm":"ed25519","public_hex":"<64 hex>"}, ...],
//!  "release_keys":[...],"depot_keys":[...],"operator_keys":[...],
//!  "revoked_keys":["sha256:<fingerprint>"],"revoked_rpks":["<rpk digest>"],
//!  "floors":[{"name":"robodr-agentd","min_serial":12}]}
//! ```
//!
//! Signed (detached, [`crate::sig`]) over [`TRUST_SIG_DOMAIN`] by the
//! delivery roots. Rules (decisions in §3.5 of the design):
//!
//! * **Roles are disjoint**: one public key (by fingerprint) and one key
//!   id appear at most once in the whole file, so a release key can never
//!   also sign deployments, a depot key never releases, and a root never
//!   signs anything but trust files (key confusion).
//! * **Quorum floors**: `root >= 2`, `release >= 2`, `operator_prod >= 2`,
//!   `1 <= operator_lab <= operator_prod`; the root and release quorums
//!   must be reachable with the non-revoked keys listed. The depot quorum
//!   is fixed at 1 (one machine key) and not configurable.
//! * **Revocation by fingerprint**, as `robodr-profile-revocations/v2`. A
//!   revoked key may stay listed in its role (so a refusal can say
//!   "revoked" rather than "unknown"), but it never counts, and any
//!   signature by it refuses the document. Roots cannot be revoked by the
//!   file they sign: rotate them instead.
//! * **Acceptance** of a standalone file ([`verify_trust_pinned`]): its
//!   root set must equal the pinned root fingerprints (carried out of band,
//!   e.g. printed at enrolment) and the root quorum must have signed it.
//! * **Rotation** ([`verify_trust_update`], TUF-style): version strictly
//!   higher, same site, signed by the root quorum of the **accepted** file
//!   *and* by the root quorum of the new one; revocations and floors only
//!   ever grow (a later file cannot un-revoke a key or an RPK, or lower or
//!   drop a floor). An older version is a replay, the same version with
//!   other bytes an equivocation.
//! * `issued_at` is informational: units have no trusted clock.

use crate::common::{
    domain_hash, fingerprint, invalid, is_fingerprint, is_hex64, is_key_id, is_label, is_pkg_name,
    parse_canonical, strictly_sorted, Code, Refusal,
};
use crate::sig::{KeyInfo, KeyLookup, Role, SignatureSet};
use crate::MAX_SAFE_INTEGER;
use robodr_blackbox::crypto::from_hex;
use robodr_blackbox::sign_ed25519::ED25519;
use robodr_blackbox::Ed25519VerifyingKey;
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};

/// `format` of a trust file.
pub const TRUST_FORMAT: &str = "robodr-delivery-trust/1";
/// Domain of the trust file's signatures.
pub const TRUST_SIG_DOMAIN: &[u8] = b"robodr-delivery-trust/v1\0";
/// Domain of the trust file digest (its identity in state and evidence).
pub const TRUST_DIGEST_DOMAIN: &[u8] = b"robodr-delivery-trust/digest/v1\0";
/// Largest trust file read.
pub const MAX_TRUST_BYTES: usize = 1024 * 1024;
/// Most keys per role.
pub const MAX_KEYS_PER_ROLE: usize = 32;
/// Most revoked keys plus revoked RPKs.
pub const MAX_REVOKED: usize = 4096;
/// Most floors.
pub const MAX_FLOORS: usize = 4096;
/// Most programmes a site accepts bundles from.
pub const MAX_PROGRAMMES: usize = 64;
/// Smallest allowed quorums (design defaults, §3.4).
pub const MIN_ROOT_QUORUM: u32 = 2;
pub const MIN_RELEASE_QUORUM: u32 = 2;
pub const MIN_OPERATOR_PROD_QUORUM: u32 = 2;
pub const MIN_OPERATOR_LAB_QUORUM: u32 = 1;

/// One trusted public key.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TrustKey {
    pub key_id: String,
    /// Always `ed25519`.
    pub algorithm: String,
    /// 64 lower-case hex digits: the 32-byte public key.
    pub public_hex: String,
}

/// Quorums per role (the depot's is fixed at 1).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Quorum {
    pub root: u32,
    pub release: u32,
    /// Distinct site operators for a deployment to a production ring.
    pub operator_prod: u32,
    /// Distinct site operators for a deployment to `lab` or `canary`.
    pub operator_lab: u32,
}

/// Lowest serial of a package that may be delivered at this site.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Floor {
    pub name: String,
    pub min_serial: u64,
}

/// A parsed trust file (members in canonical order).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TrustFile {
    pub format: String,
    pub site: String,
    pub version: u64,
    pub issued_at: u64,
    pub programmes: Vec<String>,
    pub quorum: Quorum,
    pub roots: Vec<TrustKey>,
    pub release_keys: Vec<TrustKey>,
    pub depot_keys: Vec<TrustKey>,
    pub operator_keys: Vec<TrustKey>,
    pub revoked_keys: Vec<String>,
    pub revoked_rpks: Vec<String>,
    pub floors: Vec<Floor>,
}

/// A trust file that parsed and validated, with its key index. Signatures
/// are **not** implied: only [`verify_trust_pinned`] and
/// [`verify_trust_update`] return a [`VerifiedTrust`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CheckedTrust {
    pub file: TrustFile,
    /// [`trust_digest`] of the exact bytes.
    pub digest: String,
    keys: BTreeMap<String, KeyInfo>,
    revoked: BTreeSet<String>,
}

/// A trust file accepted under pinned roots or by rotation from an
/// accepted one: the only thing other documents are verified against.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerifiedTrust(CheckedTrust);

/// Digest of a trust file's bytes.
pub fn trust_digest(bytes: &[u8]) -> String {
    domain_hash(TRUST_DIGEST_DOMAIN, bytes)
}

impl TrustKey {
    /// An entry for `public` under `key_id`.
    pub fn new(key_id: &str, public: &[u8; 32]) -> Self {
        Self {
            key_id: key_id.into(),
            algorithm: ED25519.into(),
            public_hex: robodr_blackbox::crypto::to_hex(public),
        }
    }

    fn decode(&self) -> Result<[u8; 32], Refusal> {
        if !is_key_id(&self.key_id) {
            return Err(invalid("trust file: bad key_id"));
        }
        if self.algorithm != ED25519 {
            return Err(Refusal::new(
                Code::Unsupported,
                "trust file: only ed25519 keys",
            ));
        }
        if !is_hex64(&self.public_hex) {
            return Err(invalid(format!(
                "trust file: key {} public_hex is not 64 lower-case hex digits",
                self.key_id
            )));
        }
        let v = from_hex(&self.public_hex).ok_or_else(|| invalid("trust file: hex"))?;
        let p: [u8; 32] = v
            .try_into()
            .map_err(|_| invalid("trust file: key length"))?;
        // Strict: canonical encoding of a point of large order.
        Ed25519VerifyingKey::from_bytes(self.key_id.clone(), &p).map_err(|_| {
            invalid(format!(
                "trust file: key {} is not a valid Ed25519 public key",
                self.key_id
            ))
        })?;
        Ok(p)
    }
}

impl TrustFile {
    /// Keys of `role`.
    pub fn keys_of(&self, role: Role) -> &[TrustKey] {
        match role {
            Role::Root => &self.roots,
            Role::Release => &self.release_keys,
            Role::Depot => &self.depot_keys,
            Role::Operator => &self.operator_keys,
        }
    }

    /// Structural validation and key index (see the module docs).
    pub fn check(self, digest: String) -> Result<CheckedTrust, Refusal> {
        if self.format != TRUST_FORMAT {
            return Err(invalid("trust file: unsupported format"));
        }
        if !is_label(&self.site) {
            return Err(invalid("trust file: bad site label"));
        }
        if self.version == 0 || self.version > MAX_SAFE_INTEGER {
            return Err(invalid("trust file: version must be 1..=2^53-1"));
        }
        if self.issued_at > MAX_SAFE_INTEGER {
            return Err(invalid("trust file: issued_at out of range"));
        }
        if self.programmes.is_empty() || self.programmes.len() > MAX_PROGRAMMES {
            return Err(invalid(format!(
                "trust file: 1..={MAX_PROGRAMMES} programmes"
            )));
        }
        if !self.programmes.iter().all(|p| is_label(p)) {
            return Err(invalid("trust file: bad programme label"));
        }
        strictly_sorted(&self.programmes, |p| p.clone(), "programmes")?;
        let q = self.quorum;
        if q.root < MIN_ROOT_QUORUM
            || q.release < MIN_RELEASE_QUORUM
            || q.operator_prod < MIN_OPERATOR_PROD_QUORUM
            || q.operator_lab < MIN_OPERATOR_LAB_QUORUM
            || q.operator_lab > q.operator_prod
        {
            return Err(invalid(format!(
                "trust file: quorums below the floor (root >= {MIN_ROOT_QUORUM}, release >= \
                 {MIN_RELEASE_QUORUM}, operator_prod >= {MIN_OPERATOR_PROD_QUORUM}, \
                 1 <= operator_lab <= operator_prod)"
            )));
        }
        if self.revoked_keys.len() + self.revoked_rpks.len() > MAX_REVOKED {
            return Err(invalid(format!(
                "trust file: more than {MAX_REVOKED} revocations"
            )));
        }
        if !self.revoked_keys.iter().all(|f| is_fingerprint(f)) {
            return Err(invalid(
                "trust file: revoked_keys must be sha256:<64 hex> fingerprints",
            ));
        }
        strictly_sorted(&self.revoked_keys, |f| f.clone(), "revoked_keys")?;
        if !self.revoked_rpks.iter().all(|d| is_hex64(d)) {
            return Err(invalid("trust file: revoked_rpks must be RPK digests"));
        }
        strictly_sorted(&self.revoked_rpks, |d| d.clone(), "revoked_rpks")?;
        if self.floors.len() > MAX_FLOORS {
            return Err(invalid(format!(
                "trust file: more than {MAX_FLOORS} floors"
            )));
        }
        for f in &self.floors {
            if !is_pkg_name(&f.name) || f.min_serial == 0 || f.min_serial > MAX_SAFE_INTEGER {
                return Err(invalid("trust file: bad floor"));
            }
        }
        strictly_sorted(&self.floors, |f| f.name.clone(), "floors (by name)")?;

        let revoked: BTreeSet<String> = self.revoked_keys.iter().cloned().collect();
        let mut keys = BTreeMap::new();
        let mut fps = BTreeSet::new();
        for role in [Role::Root, Role::Release, Role::Depot, Role::Operator] {
            let list = self.keys_of(role);
            if list.len() > MAX_KEYS_PER_ROLE {
                return Err(invalid(format!(
                    "trust file: more than {MAX_KEYS_PER_ROLE} {} keys",
                    role.as_str()
                )));
            }
            strictly_sorted(list, |k| k.key_id.clone(), "keys (by key_id)")?;
            for k in list {
                let public = k.decode()?;
                let fp = fingerprint(&public);
                if !fps.insert(fp.clone()) {
                    return Err(invalid(format!(
                        "trust file: key {} ({fp}) is listed twice (roles must be disjoint)",
                        k.key_id
                    )));
                }
                if keys
                    .insert(
                        k.key_id.clone(),
                        KeyInfo {
                            role,
                            public,
                            fingerprint: fp.clone(),
                        },
                    )
                    .is_some()
                {
                    return Err(invalid(format!(
                        "trust file: key id {} is used twice",
                        k.key_id
                    )));
                }
                if role == Role::Root && revoked.contains(&fp) {
                    return Err(invalid(
                        "trust file: a root cannot be revoked by the file it signs; rotate it",
                    ));
                }
            }
        }
        let live = |role: Role| {
            keys.values()
                .filter(|k| k.role == role && !revoked.contains(&k.fingerprint))
                .count()
        };
        if live(Role::Root) < q.root as usize {
            return Err(invalid("trust file: fewer roots than the root quorum"));
        }
        if live(Role::Release) < q.release as usize {
            return Err(invalid(
                "trust file: fewer non-revoked release keys than the release quorum",
            ));
        }
        Ok(CheckedTrust {
            file: self,
            digest,
            keys,
            revoked,
        })
    }
}

/// Parse and validate trust file bytes (no signature check).
pub fn parse_trust(bytes: &[u8]) -> Result<CheckedTrust, Refusal> {
    let f: TrustFile = parse_canonical(bytes, MAX_TRUST_BYTES, "trust file")?;
    f.check(trust_digest(bytes))
}

impl KeyLookup for CheckedTrust {
    fn key(&self, key_id: &str) -> Option<&KeyInfo> {
        self.keys.get(key_id)
    }
    fn is_revoked(&self, fingerprint: &str) -> bool {
        self.revoked.contains(fingerprint)
    }
}

impl CheckedTrust {
    /// Root fingerprints, sorted.
    pub fn root_fingerprints(&self) -> BTreeSet<String> {
        self.keys
            .values()
            .filter(|k| k.role == Role::Root)
            .map(|k| k.fingerprint.clone())
            .collect()
    }
}

impl std::ops::Deref for VerifiedTrust {
    type Target = CheckedTrust;
    fn deref(&self) -> &CheckedTrust {
        &self.0
    }
}

impl KeyLookup for VerifiedTrust {
    fn key(&self, key_id: &str) -> Option<&KeyInfo> {
        self.0.key(key_id)
    }
    fn is_revoked(&self, fingerprint: &str) -> bool {
        self.0.is_revoked(fingerprint)
    }
}

impl VerifiedTrust {
    pub fn file(&self) -> &TrustFile {
        &self.0.file
    }

    /// Whether an RPK digest is revoked.
    pub fn is_rpk_revoked(&self, digest: &str) -> bool {
        self.0.file.revoked_rpks.iter().any(|d| d == digest)
    }

    /// The site floor of package `name` (0 when none).
    pub fn floor(&self, name: &str) -> u64 {
        self.0
            .file
            .floors
            .iter()
            .find(|f| f.name == name)
            .map_or(0, |f| f.min_serial)
    }

    /// Whether bundles of `programme` are accepted at this site.
    pub fn accepts_programme(&self, programme: &str) -> bool {
        self.0.file.programmes.iter().any(|p| p == programme)
    }
}

/// Accept a trust file standalone: its roots must be exactly `pinned`
/// (root fingerprints carried out of band) and the root quorum must have
/// signed it.
pub fn verify_trust_pinned(
    doc: &[u8],
    sigset: &[u8],
    pinned: &[String],
) -> Result<VerifiedTrust, Refusal> {
    let t = parse_trust(doc)?;
    let pinned: BTreeSet<String> = pinned.iter().cloned().collect();
    if pinned.is_empty() || t.root_fingerprints() != pinned {
        return Err(Refusal::new(
            Code::UnknownKey,
            "trust file: its roots are not exactly the pinned root fingerprints",
        ));
    }
    let set = SignatureSet::parse(sigset)?;
    let signers = set.check(&t, &[Role::Root], TRUST_SIG_DOMAIN, doc)?;
    signers.require(Role::Root, t.file.quorum.root as usize, "trust file")?;
    Ok(VerifiedTrust(t))
}

/// Keys of two trust files (rotation): a key id must mean the same key in
/// both.
struct Union<'a>(&'a CheckedTrust, &'a CheckedTrust);

impl KeyLookup for Union<'_> {
    fn key(&self, key_id: &str) -> Option<&KeyInfo> {
        match (self.0.key(key_id), self.1.key(key_id)) {
            (Some(a), Some(b)) if a != b => None,
            (Some(a), _) => Some(a),
            (None, b) => b,
        }
    }
    fn is_revoked(&self, fingerprint: &str) -> bool {
        self.0.is_revoked(fingerprint) || self.1.is_revoked(fingerprint)
    }
}

/// Accept `doc` as the successor of the accepted `prev` (see the module
/// docs). The same bytes as `prev` return `prev` unchanged.
pub fn verify_trust_update(
    prev: &VerifiedTrust,
    doc: &[u8],
    sigset: &[u8],
) -> Result<VerifiedTrust, Refusal> {
    let next = parse_trust(doc)?;
    let p = &prev.0.file;
    let n = &next.file;
    if n.site != p.site {
        return Err(Refusal::new(
            Code::WrongScope,
            "trust update: for another site",
        ));
    }
    if n.version < p.version {
        return Err(Refusal::new(
            Code::Replay,
            format!(
                "trust update: version {} < accepted {}",
                n.version, p.version
            ),
        ));
    }
    if n.version == p.version {
        return if next.digest == prev.0.digest {
            Ok(prev.clone())
        } else {
            Err(Refusal::new(
                Code::Equivocation,
                format!("trust update: version {} with other content", n.version),
            ))
        };
    }
    let set = SignatureSet::parse(sigset)?;
    // Old and new roots only; a key id must mean the same key in both.
    let union = Union(&prev.0, &next);
    let signers = set.check(&union, &[Role::Root], TRUST_SIG_DOMAIN, doc)?;
    let old_roots = prev.0.root_fingerprints();
    let new_roots = next.root_fingerprints();
    let old = signers
        .of(Role::Root)
        .into_iter()
        .filter(|f| old_roots.contains(*f))
        .count();
    let new = signers
        .of(Role::Root)
        .into_iter()
        .filter(|f| new_roots.contains(*f))
        .count();
    if old < p.quorum.root as usize || new < n.quorum.root as usize {
        return Err(Refusal::new(
            Code::QuorumNotMet,
            format!(
                "trust update: {old} of the accepted roots (quorum {}) and {new} of the new \
                 roots (quorum {}) signed",
                p.quorum.root, n.quorum.root
            ),
        ));
    }
    for f in &p.revoked_keys {
        if !n.revoked_keys.contains(f) {
            return Err(invalid(format!("trust update: un-revokes key {f}")));
        }
    }
    for d in &p.revoked_rpks {
        if !n.revoked_rpks.contains(d) {
            return Err(invalid(format!("trust update: un-revokes RPK {d}")));
        }
    }
    for f in &p.floors {
        match n.floors.iter().find(|x| x.name == f.name) {
            Some(x) if x.min_serial >= f.min_serial => {}
            _ => {
                return Err(Refusal::new(
                    Code::BelowFloor,
                    format!("trust update: lowers or drops the floor of {}", f.name),
                ))
            }
        }
    }
    Ok(VerifiedTrust(next))
}

#[cfg(test)]
pub(crate) mod test_support {
    use super::*;
    use crate::common::to_canonical;
    use robodr_blackbox::Ed25519SigningKey;

    pub fn key(id: &str, seed: u8) -> Ed25519SigningKey {
        Ed25519SigningKey::from_seed(id, &[seed; 32]).unwrap()
    }

    pub fn tk(k: &Ed25519SigningKey) -> TrustKey {
        TrustKey::new(robodr_blackbox::Signer::key_id(k), &k.public_key())
    }

    /// Roots r1..r3 (seeds 1..3), release a/b/c (11..13), depot d (21),
    /// operators o1..o3 (31..33).
    pub fn base() -> TrustFile {
        TrustFile {
            format: TRUST_FORMAT.into(),
            site: "site-a".into(),
            version: 1,
            issued_at: 1_790_000_000,
            programmes: vec!["ugv-x1".into()],
            quorum: Quorum {
                root: 2,
                release: 2,
                operator_prod: 2,
                operator_lab: 1,
            },
            roots: (1..=3).map(|i| tk(&key(&format!("root-{i}"), i))).collect(),
            release_keys: ["rel-a", "rel-b", "rel-c"]
                .iter()
                .zip(11..)
                .map(|(n, s)| tk(&key(n, s)))
                .collect(),
            depot_keys: vec![tk(&key("depot-1", 21))],
            operator_keys: (1..=3)
                .map(|i| tk(&key(&format!("op-{i}"), 30 + i)))
                .collect(),
            revoked_keys: vec![],
            revoked_rpks: vec![],
            floors: vec![],
        }
    }

    pub fn roots() -> Vec<Ed25519SigningKey> {
        (1..=3).map(|i| key(&format!("root-{i}"), i)).collect()
    }

    pub fn sign(doc: &[u8], domain: &[u8], by: &[&Ed25519SigningKey]) -> Vec<u8> {
        let mut s = SignatureSet::empty();
        for k in by {
            s.add(*k, domain, doc).unwrap();
        }
        s.to_bytes().unwrap()
    }

    pub fn pins(t: &TrustFile) -> Vec<String> {
        t.roots
            .iter()
            .map(|k| fingerprint(&k.decode().unwrap()))
            .collect()
    }

    /// `t` signed by roots 1 and 2, verified against its own pins.
    pub fn verified(t: &TrustFile) -> VerifiedTrust {
        let doc = to_canonical(t).unwrap();
        let r = roots();
        let sig = sign(&doc, TRUST_SIG_DOMAIN, &[&r[0], &r[1]]);
        verify_trust_pinned(&doc, &sig, &pins(t)).unwrap()
    }
}

#[cfg(test)]
mod tests {
    use super::test_support::*;
    use super::*;
    use crate::common::to_canonical;

    type Mutation = Box<dyn Fn(&mut TrustFile)>;

    #[test]
    fn valid_trust_file_verifies_under_pins() {
        let t = base();
        let v = verified(&t);
        assert_eq!(v.file(), &t);
        assert!(v.accepts_programme("ugv-x1"));
        assert!(!v.accepts_programme("other"));
        assert_eq!(v.floor("x"), 0);
    }

    #[test]
    fn standalone_acceptance_needs_pins_and_root_quorum() {
        let t = base();
        let doc = to_canonical(&t).unwrap();
        let r = roots();
        let one = sign(&doc, TRUST_SIG_DOMAIN, &[&r[0]]);
        assert_eq!(
            verify_trust_pinned(&doc, &one, &pins(&t)).unwrap_err().code,
            Code::QuorumNotMet
        );
        let two = sign(&doc, TRUST_SIG_DOMAIN, &[&r[0], &r[2]]);
        verify_trust_pinned(&doc, &two, &pins(&t)).unwrap();
        // Pins must equal the roots exactly.
        let mut fewer = pins(&t);
        fewer.pop();
        assert_eq!(
            verify_trust_pinned(&doc, &two, &fewer).unwrap_err().code,
            Code::UnknownKey
        );
        assert!(verify_trust_pinned(&doc, &two, &[]).is_err());
        // Release keys (even two) cannot sign a trust file.
        let rel = sign(
            &doc,
            TRUST_SIG_DOMAIN,
            &[&key("rel-a", 11), &key("rel-b", 12)],
        );
        assert_eq!(
            verify_trust_pinned(&doc, &rel, &pins(&t)).unwrap_err().code,
            Code::WrongRole
        );
        // An attacker's self-made file with its own roots fails the pins.
        let mut evil = base();
        evil.roots = (40..=42)
            .map(|i| tk(&key(&format!("root-{i}"), i)))
            .collect();
        let edoc = to_canonical(&evil).unwrap();
        let esig = sign(
            &edoc,
            TRUST_SIG_DOMAIN,
            &[&key("root-40", 40), &key("root-41", 41)],
        );
        assert_eq!(
            verify_trust_pinned(&edoc, &esig, &pins(&t))
                .unwrap_err()
                .code,
            Code::UnknownKey
        );
    }

    #[test]
    fn structural_rules() {
        let cases: Vec<(&str, Mutation)> = vec![
            ("format", Box::new(|t| t.format = "x".into())),
            ("site", Box::new(|t| t.site = "A".into())),
            ("version0", Box::new(|t| t.version = 0)),
            (
                "version big",
                Box::new(|t| t.version = MAX_SAFE_INTEGER + 1),
            ),
            ("no programmes", Box::new(|t| t.programmes.clear())),
            (
                "programmes unsorted",
                Box::new(|t| t.programmes = vec!["b".into(), "a".into()]),
            ),
            ("root quorum 1", Box::new(|t| t.quorum.root = 1)),
            ("release quorum 1", Box::new(|t| t.quorum.release = 1)),
            ("op prod 1", Box::new(|t| t.quorum.operator_prod = 1)),
            ("op lab 0", Box::new(|t| t.quorum.operator_lab = 0)),
            ("op lab > prod", Box::new(|t| t.quorum.operator_lab = 3)),
            ("root quorum unreachable", Box::new(|t| t.quorum.root = 4)),
            ("release unreachable", Box::new(|t| t.quorum.release = 4)),
            (
                "same key two roles",
                Box::new(|t| {
                    let mut k = t.release_keys[0].clone();
                    k.key_id = "z-depot".into();
                    t.depot_keys.push(k);
                }),
            ),
            (
                "same key id two roles",
                Box::new(|t| t.depot_keys[0].key_id = "rel-a".into()),
            ),
            ("keys unsorted", Box::new(|t| t.release_keys.swap(0, 1))),
            (
                "bad public",
                Box::new(|t| t.roots[0].public_hex = "00".repeat(32)),
            ),
            (
                "upper hex",
                Box::new(|t| t.roots[0].public_hex = t.roots[0].public_hex.to_uppercase()),
            ),
            (
                "algorithm",
                Box::new(|t| t.roots[0].algorithm = "rsa".into()),
            ),
            (
                "revoked root",
                Box::new(|t| t.revoked_keys = vec![fingerprint(&key("root-1", 1).public_key())]),
            ),
            (
                "revoked not fingerprint",
                Box::new(|t| t.revoked_keys = vec!["root-1".into()]),
            ),
            (
                "release quorum after revocation",
                Box::new(|t| {
                    let mut v = vec![
                        fingerprint(&key("rel-a", 11).public_key()),
                        fingerprint(&key("rel-b", 12).public_key()),
                    ];
                    v.sort();
                    t.revoked_keys = v;
                }),
            ),
            (
                "revoked rpk",
                Box::new(|t| t.revoked_rpks = vec!["xyz".into()]),
            ),
            (
                "floor 0",
                Box::new(|t| {
                    t.floors = vec![Floor {
                        name: "a".into(),
                        min_serial: 0,
                    }]
                }),
            ),
            (
                "floors dup",
                Box::new(|t| {
                    t.floors = vec![
                        Floor {
                            name: "a".into(),
                            min_serial: 1,
                        },
                        Floor {
                            name: "a".into(),
                            min_serial: 2,
                        },
                    ]
                }),
            ),
            (
                "too many keys",
                Box::new(|t| {
                    t.operator_keys = (0..=MAX_KEYS_PER_ROLE as u8)
                        .map(|i| tk(&key(&format!("op-x{i:03}"), 100 + i)))
                        .collect()
                }),
            ),
        ];
        for (name, f) in cases {
            let mut t = base();
            f(&mut t);
            let doc = to_canonical(&t).unwrap();
            assert!(parse_trust(&doc).is_err(), "{name} accepted");
        }
        // One revoked release key of three is fine (quorum 2 still reachable).
        let mut t = base();
        t.revoked_keys = vec![fingerprint(&key("rel-c", 13).public_key())];
        parse_trust(&to_canonical(&t).unwrap()).unwrap();
    }

    fn signed(t: &TrustFile, by: &[&robodr_blackbox::Ed25519SigningKey]) -> (Vec<u8>, Vec<u8>) {
        let doc = to_canonical(t).unwrap();
        let sig = sign(&doc, TRUST_SIG_DOMAIN, by);
        (doc, sig)
    }

    #[test]
    fn rotation_needs_old_and_new_root_quorums() {
        let prev = verified(&base());
        let r = roots();
        // Plain update (same roots), version 2, adds a revocation and floor.
        let mut t2 = base();
        t2.version = 2;
        t2.revoked_keys = vec![fingerprint(&key("rel-c", 13).public_key())];
        t2.floors = vec![Floor {
            name: "pkg".into(),
            min_serial: 5,
        }];
        let (d2, s2) = signed(&t2, &[&r[0], &r[1]]);
        let v2 = verify_trust_update(&prev, &d2, &s2).unwrap();
        assert_eq!(v2.floor("pkg"), 5);
        // Idempotent for the same bytes, equivocation for others.
        assert_eq!(verify_trust_update(&v2, &d2, &s2).unwrap(), v2);
        let mut t2b = t2.clone();
        t2b.issued_at += 1;
        let (d2b, s2b) = signed(&t2b, &[&r[0], &r[1]]);
        assert_eq!(
            verify_trust_update(&v2, &d2b, &s2b).unwrap_err().code,
            Code::Equivocation
        );
        // Replay of version 1 after 2.
        let (d1, s1) = signed(&base(), &[&r[0], &r[1]]);
        assert_eq!(
            verify_trust_update(&v2, &d1, &s1).unwrap_err().code,
            Code::Replay
        );

        // Root rotation: replace root-3 by root-4. Needs 2 old + 2 new.
        let mut t3 = t2.clone();
        t3.version = 3;
        t3.roots = vec![tk(&r[0]), tk(&r[1]), tk(&key("root-4", 4))];
        let r4 = key("root-4", 4);
        let (d3, s3) = signed(&t3, &[&r[2], &r4]); // 1 old (r3) + r4: old quorum not met
        assert_eq!(
            verify_trust_update(&v2, &d3, &s3).unwrap_err().code,
            Code::QuorumNotMet
        );
        let (d3, s3) = signed(&t3, &[&r[0], &r[1]]); // old roots, also 2 new
        let v3 = verify_trust_update(&v2, &d3, &s3).unwrap();
        // Takeover attempt: new file with all-new roots signed only by them.
        let mut evil = t3.clone();
        evil.version = 4;
        evil.roots = (50..=52)
            .map(|i| tk(&key(&format!("root-{i}"), i)))
            .collect();
        let (de, se) = signed(&evil, &[&key("root-50", 50), &key("root-51", 51)]);
        assert_eq!(
            verify_trust_update(&v3, &de, &se).unwrap_err().code,
            Code::QuorumNotMet
        );
        // Un-revoking, lowering or dropping a floor is refused even when signed.
        for (name, m) in [
            (
                "unrevoke",
                Box::new(|t: &mut TrustFile| t.revoked_keys.clear()) as Mutation,
            ),
            (
                "lower",
                Box::new(|t: &mut TrustFile| t.floors[0].min_serial = 4),
            ),
            ("drop", Box::new(|t: &mut TrustFile| t.floors.clear())),
            (
                "site",
                Box::new(|t: &mut TrustFile| t.site = "site-b".into()),
            ),
        ] {
            let mut t = t3.clone();
            t.version = 9;
            m(&mut t);
            let (d, s) = signed(&t, &[&r[0], &r[1]]);
            assert!(verify_trust_update(&v3, &d, &s).is_err(), "{name}");
        }
    }
}
