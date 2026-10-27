//! The delivery trust file (`robodr-delivery-trust/1`,
//! `docs/SECURE-DELIVERY.md` §3.4): which keys may sign what at one site,
//! quorums, revocations and floors.
//!
//! ```json
//! {"format":"robodr-delivery-trust/1","site":"site-a","version":3,
//!  "issued_at":1790000000,"expires_at":1797776000,
//!  "programmes":[{"name":"ugv-x1","release_keys":["rel-a","rel-b"],"packages":["nav-stack","ugv-*"]}],
//!  "quorum":{"root":2,"release":2,"operator_prod":2,"operator_lab":1},
//!  "roots":[{"key_id":"root-a","algorithm":"ed25519","public_hex":"<64 hex>"}, ...],
//!  "release_keys":[...],"depot_keys":[...],"operator_keys":[...],
//!  "rings":[{"ring":"canary","units":["ugv-07"]},{"ring":"lab","units":["bench-01"]}],
//!  "revoked_keys":["sha256:<fingerprint>"],"revoked_rpks":["<rpk digest>"],
//!  "revoked_serials":[{"name":"nav-stack","serial":9}],
//!  "floors":[{"name":"robodr-agentd","min_serial":12}]}
//! ```
//!
//! Signed (detached, [`crate::sig`]) over [`TRUST_SIG_DOMAIN`] by the
//! delivery roots. Rules (decisions in §3.5 of the design):
//!
//! * **Roles are disjoint**: one public key (by fingerprint) and one key
//!   id appear at most once in the whole file, so a release key can never
//!   also sign deployments, a depot key never releases, and a root never
//!   signs anything but trust files (key confusion). Keys must be
//!   torsion-free (`robodr-blackbox`), so one secret has one fingerprint.
//! * **Programmes scope release keys and packages** (13a review finding
//!   5): each programme names the release keys that may sign for it and
//!   the package names it may deliver (exact names, or a prefix ending in
//!   `*`); a package name belongs to at most one programme. An RPK is
//!   verified against the release keys of the programme that owns its
//!   name, a bundle against those of its programme; a signature by any
//!   other release key refuses the document ([`Code::WrongScope`]).
//! * **Quorum floors and caps**: `root >= 2`, `release >= 2`,
//!   `operator_prod >= 2`, `1 <= operator_lab <= operator_prod`; no quorum
//!   above what one signature set can hold ([`MAX_SIGNATURES`], and
//!   `operator_prod` one less: a deployment also carries the depot's). The
//!   root quorum must be reachable with the roots listed and the release
//!   quorum with the non-revoked release keys **of every programme**. The
//!   depot quorum is fixed at 1 (one machine key) and not configurable.
//! * **Rings** (13a review finding 3): a root-signed assignment of units
//!   to rings. A deployment may use the `lab` operator quorum only for
//!   units this file assigns to its (`lab` or `canary`) ring; see
//!   [`crate::deployment`].
//! * **Revocation by fingerprint**, as `robodr-profile-revocations/v2`. A
//!   revoked key may stay listed in its role (so a refusal can say
//!   "revoked" rather than "unknown"), but it never counts, and any
//!   signature by it refuses the document. Roots cannot be revoked by the
//!   file they sign: rotate them instead. RPKs are revoked by digest
//!   (`revoked_rpks`) or by package name and serial (`revoked_serials`,
//!   which also covers the same release re-signed into another manifest).
//! * **Expiry**: `issued_at < expires_at <= issued_at +`
//!   [`MAX_TRUST_LIFETIME_S`]; a file is refused at and after
//!   `expires_at`. A courier who withholds a newer file (a revocation)
//!   is thereby detected within one lifetime (T8 freeze, §6.5).
//! * **Acceptance** of a standalone file ([`verify_trust_pinned`]): its
//!   root set must equal the pinned root fingerprints (carried out of band,
//!   e.g. printed at enrolment), its `site` must equal the pinned site
//!   (13a review finding 1: roots are shared by the sites of a programme
//!   office, so roots alone do not tell one site's file from another's),
//!   the root quorum must have signed it and it must not have expired.
//! * **Rotation** ([`verify_trust_update`], TUF-style): version strictly
//!   higher, same site, signed by the root quorum of the **accepted** file
//!   *and* by the root quorum of the new one; revocations and floors only
//!   ever grow (a later file cannot un-revoke a key, an RPK or a serial,
//!   or lower or drop a floor). An older version is a replay, the same
//!   version with other bytes an equivocation. This is the only way a
//!   verifier's accepted trust (its anchor) moves forward.
//! * `issued_at` and `expires_at` are judged on the verifier's clock;
//!   units have no trusted clock (13b decides how they use them).

use crate::common::{
    domain_hash, fingerprint, invalid, is_fingerprint, is_hex64, is_key_id, is_label, is_pkg_name,
    parse_canonical, strictly_sorted, Code, Refusal,
};
use crate::sig::{KeyInfo, KeyLookup, Role, SignatureSet, Signers, MAX_SIGNATURES};
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
/// Most package names or prefixes per programme.
pub const MAX_PACKAGES: usize = 1024;
/// Most units assigned to rings.
pub const MAX_RING_UNITS: usize = 4096;
/// Longest lifetime of a trust file (`expires_at - issued_at`): one year
/// and a day. Sites should issue shorter ones; this is the hard cap.
pub const MAX_TRUST_LIFETIME_S: u64 = 366 * 24 * 3600;
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

/// A programme whose bundles the site accepts: the release keys that may
/// sign for it and the packages it may deliver.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Programme {
    pub name: String,
    /// Key ids of `release_keys` entries, sorted.
    pub release_keys: Vec<String>,
    /// Package names, or prefixes ending in `*` (`"*"` alone: every
    /// name), sorted.
    pub packages: Vec<String>,
}

/// Units assigned to one ring by the roots.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RingAssignment {
    /// `lab`, `canary` or `ring-<1..99>`.
    pub ring: String,
    /// Unit ids, sorted.
    pub units: Vec<String>,
}

/// One revoked release of a package (whatever manifest carries it).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RevokedSerial {
    pub name: String,
    pub serial: u64,
}

/// A parsed trust file (members in canonical order).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TrustFile {
    pub format: String,
    pub site: String,
    pub version: u64,
    pub issued_at: u64,
    pub expires_at: u64,
    /// Sorted by name.
    pub programmes: Vec<Programme>,
    pub quorum: Quorum,
    pub roots: Vec<TrustKey>,
    pub release_keys: Vec<TrustKey>,
    pub depot_keys: Vec<TrustKey>,
    pub operator_keys: Vec<TrustKey>,
    /// Sorted by ring; a unit appears at most once.
    pub rings: Vec<RingAssignment>,
    pub revoked_keys: Vec<String>,
    pub revoked_rpks: Vec<String>,
    /// Sorted by (name, serial).
    pub revoked_serials: Vec<RevokedSerial>,
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
    /// Programme name -> fingerprints of its release keys.
    scopes: BTreeMap<String, BTreeSet<String>>,
    /// Exact package name -> programme.
    packages: BTreeMap<String, String>,
    /// Package-name prefix (from `prefix*`) -> programme.
    prefixes: BTreeMap<String, String>,
    /// Unit -> ring.
    rings: BTreeMap<String, String>,
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
        if self.issued_at > MAX_SAFE_INTEGER || self.expires_at > MAX_SAFE_INTEGER {
            return Err(invalid("trust file: issued_at / expires_at out of range"));
        }
        if self.expires_at <= self.issued_at
            || self.expires_at - self.issued_at > MAX_TRUST_LIFETIME_S
        {
            return Err(invalid(format!(
                "trust file: need issued_at < expires_at, at most {MAX_TRUST_LIFETIME_S} s apart"
            )));
        }
        if self.programmes.is_empty() || self.programmes.len() > MAX_PROGRAMMES {
            return Err(invalid(format!(
                "trust file: 1..={MAX_PROGRAMMES} programmes"
            )));
        }
        strictly_sorted(&self.programmes, |p| p.name.clone(), "programmes (by name)")?;
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
        // One signature set holds at most MAX_SIGNATURES entries, and a
        // deployment's also carries the depot's (13a review finding 9).
        if q.root as usize > MAX_SIGNATURES
            || q.release as usize > MAX_SIGNATURES
            || q.operator_prod as usize > MAX_SIGNATURES - 1
        {
            return Err(invalid(format!(
                "trust file: quorums above what one signature set can hold (root, release <= \
                 {MAX_SIGNATURES}, operator_prod <= {})",
                MAX_SIGNATURES - 1
            )));
        }
        if self.revoked_keys.len() + self.revoked_rpks.len() + self.revoked_serials.len()
            > MAX_REVOKED
        {
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
        for r in &self.revoked_serials {
            if !is_pkg_name(&r.name) || r.serial == 0 || r.serial > MAX_SAFE_INTEGER {
                return Err(invalid("trust file: bad revoked_serials entry"));
            }
        }
        strictly_sorted(
            &self.revoked_serials,
            |r| (r.name.clone(), r.serial),
            "revoked_serials (by name, serial)",
        )?;
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

        // Programmes: release-key scopes and package ownership.
        let mut scopes = BTreeMap::new();
        let mut packages: BTreeMap<String, String> = BTreeMap::new();
        let mut prefixes: BTreeMap<String, String> = BTreeMap::new();
        let mut n_packages = 0usize;
        for p in &self.programmes {
            if !is_label(&p.name) {
                return Err(invalid("trust file: bad programme label"));
            }
            if p.release_keys.is_empty() || p.release_keys.len() > MAX_KEYS_PER_ROLE {
                return Err(invalid(format!(
                    "trust file: programme {} needs 1..={MAX_KEYS_PER_ROLE} release keys",
                    p.name
                )));
            }
            strictly_sorted(&p.release_keys, |k| k.clone(), "programme release_keys")?;
            let mut scope = BTreeSet::new();
            let mut live = 0usize;
            for id in &p.release_keys {
                match keys.get(id) {
                    Some(k) if k.role == Role::Release => {
                        if !revoked.contains(&k.fingerprint) {
                            live += 1;
                        }
                        scope.insert(k.fingerprint.clone());
                    }
                    _ => {
                        return Err(invalid(format!(
                            "trust file: programme {} names {id:?}, which is not a release key",
                            p.name
                        )))
                    }
                }
            }
            if live < q.release as usize {
                return Err(invalid(format!(
                    "trust file: programme {} has fewer non-revoked release keys than the \
                     release quorum",
                    p.name
                )));
            }
            if p.packages.is_empty() || p.packages.len() > MAX_PACKAGES {
                return Err(invalid(format!(
                    "trust file: programme {} needs 1..={MAX_PACKAGES} packages",
                    p.name
                )));
            }
            n_packages += p.packages.len();
            strictly_sorted(&p.packages, |x| x.clone(), "programme packages")?;
            for pat in &p.packages {
                match pat.strip_suffix('*') {
                    Some(prefix) if is_pkg_prefix(prefix) => {
                        prefixes.insert(prefix.to_string(), p.name.clone());
                    }
                    None if is_pkg_name(pat) => {
                        packages.insert(pat.clone(), p.name.clone());
                    }
                    _ => {
                        return Err(invalid(format!(
                            "trust file: programme {}: {:?} is neither a package name nor a \
                             prefix ending in *",
                            p.name,
                            crate::common::trunc(pat)
                        )))
                    }
                }
            }
            scopes.insert(p.name.clone(), scope);
        }
        // A package name belongs to at most one programme: no pattern may
        // cover another (an exact name under a prefix, a prefix under a
        // shorter one, or one entry twice).
        if packages.len() + prefixes.len() != n_packages {
            return Err(invalid("trust file: a package entry is listed twice"));
        }
        let covered = |s: &str, proper: bool| -> Option<&String> {
            let n = if proper { s.len() } else { s.len() + 1 };
            (0..n).find_map(|i| s.get(..i).and_then(|pre| prefixes.get(pre)))
        };
        for name in packages.keys() {
            if covered(name, false).is_some() {
                return Err(invalid(format!(
                    "trust file: package {name} is also covered by a prefix (a package belongs \
                     to one programme)"
                )));
            }
        }
        for pre in prefixes.keys() {
            if covered(pre, true).is_some() {
                return Err(invalid(format!(
                    "trust file: prefix {pre}* overlaps a shorter prefix"
                )));
            }
        }

        // Rings: each unit in at most one.
        strictly_sorted(&self.rings, |r| r.ring.clone(), "rings (by ring)")?;
        let mut rings = BTreeMap::new();
        for r in &self.rings {
            if !crate::deployment::is_ring(&r.ring) {
                return Err(invalid(
                    "trust file: ring must be lab, canary or ring-<1..99>",
                ));
            }
            if r.units.is_empty() || !r.units.iter().all(|u| is_label(u)) {
                return Err(invalid(format!(
                    "trust file: ring {} needs unit labels",
                    r.ring
                )));
            }
            strictly_sorted(&r.units, |u| u.clone(), "ring units")?;
            for u in &r.units {
                if rings.insert(u.clone(), r.ring.clone()).is_some() {
                    return Err(invalid(format!(
                        "trust file: unit {u} is assigned to two rings"
                    )));
                }
                if rings.len() > MAX_RING_UNITS {
                    return Err(invalid(format!(
                        "trust file: more than {MAX_RING_UNITS} units in rings"
                    )));
                }
            }
        }
        Ok(CheckedTrust {
            file: self,
            digest,
            keys,
            revoked,
            scopes,
            packages,
            prefixes,
            rings,
        })
    }
}

/// A package-name prefix: empty, or the start of a valid package name.
fn is_pkg_prefix(s: &str) -> bool {
    s.is_empty() || is_pkg_name(&format!("{s}a"))
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

    /// Whether release `serial` of package `name` is revoked.
    pub fn is_serial_revoked(&self, name: &str, serial: u64) -> bool {
        self.0
            .file
            .revoked_serials
            .binary_search_by(|r| (r.name.as_str(), r.serial).cmp(&(name, serial)))
            .is_ok()
    }

    /// Whether bundles of `programme` are accepted at this site.
    pub fn accepts_programme(&self, programme: &str) -> bool {
        self.0.scopes.contains_key(programme)
    }

    /// The programme that may deliver package `name` (exact entry first,
    /// then the prefix covering it; at most one exists).
    pub fn programme_of_package(&self, name: &str) -> Option<&str> {
        if let Some(p) = self.0.packages.get(name) {
            return Some(p);
        }
        (0..=name.len())
            .find_map(|i| name.get(..i).and_then(|pre| self.0.prefixes.get(pre)))
            .map(String::as_str)
    }

    /// The ring the roots assigned `unit` to, if any.
    pub fn ring_of_unit(&self, unit: &str) -> Option<&str> {
        self.0.rings.get(unit).map(String::as_str)
    }

    /// Refuse unless every release signer is a release key of
    /// `programme` and at least the release quorum of them signed (13a
    /// review finding 5: a programme's release keys sign for it only).
    pub fn require_release_quorum(
        &self,
        signers: &Signers,
        programme: &str,
        what: &str,
    ) -> Result<(), Refusal> {
        self.check_release_scope(signers, programme, what)?;
        signers.require(Role::Release, self.0.file.quorum.release as usize, what)
    }

    /// Refuse unless every release signer is a release key of `programme`
    /// (no quorum check: `sign` uses it on a partly signed document).
    pub fn check_release_scope(
        &self,
        signers: &Signers,
        programme: &str,
        what: &str,
    ) -> Result<(), Refusal> {
        let Some(scope) = self.0.scopes.get(programme) else {
            return Err(Refusal::new(
                Code::WrongScope,
                format!("{what}: programme {programme} is not accepted at this site"),
            ));
        };
        if let Some(f) = signers
            .of(Role::Release)
            .into_iter()
            .find(|f| !scope.contains(*f))
        {
            return Err(Refusal::new(
                Code::WrongScope,
                format!(
                    "{what}: signed by release key {f}, which may not sign for programme \
                     {programme}"
                ),
            ));
        }
        Ok(())
    }

    /// Refuse a trust file at or after its `expires_at`.
    pub fn check_fresh(&self, now: u64) -> Result<(), Refusal> {
        let f = &self.0.file;
        if now >= f.expires_at {
            return Err(Refusal::new(
                Code::Expired,
                format!(
                    "trust file {} version {} expired at {} (now {now}): a newer one is due",
                    f.site, f.version, f.expires_at
                ),
            ));
        }
        Ok(())
    }
}

/// Accept a trust file standalone: its roots must be exactly `pinned`
/// (root fingerprints carried out of band), its site must be `site`, the
/// root quorum must have signed it and it must not have expired at `now`.
pub fn verify_trust_pinned(
    doc: &[u8],
    sigset: &[u8],
    pinned: &[String],
    site: &str,
    now: u64,
) -> Result<VerifiedTrust, Refusal> {
    let v = verify_trust_anchor(doc, sigset, pinned, site)?;
    v.check_fresh(now)?;
    Ok(v)
}

/// As [`verify_trust_pinned`] without the expiry check: only for loading
/// a verifier's own accepted trust file (its anchor), whose successor is
/// then accepted with [`verify_trust_update`], which checks expiry. An
/// expired anchor must still be able to accept the file that replaces it.
pub fn verify_trust_anchor(
    doc: &[u8],
    sigset: &[u8],
    pinned: &[String],
    site: &str,
) -> Result<VerifiedTrust, Refusal> {
    let t = parse_trust(doc)?;
    let pinned: BTreeSet<String> = pinned.iter().cloned().collect();
    if pinned.is_empty() || t.root_fingerprints() != pinned {
        return Err(Refusal::new(
            Code::UnknownKey,
            "trust file: its roots are not exactly the pinned root fingerprints",
        ));
    }
    if t.file.site != site {
        return Err(Refusal::new(
            Code::WrongScope,
            format!("trust file: for site {}, this is site {site}", t.file.site),
        ));
    }
    let set = SignatureSet::parse(sigset)?;
    let signers = set.check(&t, &[Role::Root], TRUST_SIG_DOMAIN, doc)?;
    signers.require(Role::Root, t.file.quorum.root as usize, "trust file")?;
    Ok(VerifiedTrust(t))
}

/// Check every existing root signature on a trust file being signed
/// (`robodr-release sign`): each entry must be a root of the document
/// itself or of `prev` (the accepted file, during a rotation) and verify.
/// Returns the distinct signers.
pub fn check_trust_signatures(
    doc: &[u8],
    sigset: &[u8],
    prev: Option<&VerifiedTrust>,
) -> Result<Signers, Refusal> {
    let t = parse_trust(doc)?;
    let set = SignatureSet::parse(sigset)?;
    match prev {
        Some(p) => set.check(&Union(&p.0, &t), &[Role::Root], TRUST_SIG_DOMAIN, doc),
        None => set.check(&t, &[Role::Root], TRUST_SIG_DOMAIN, doc),
    }
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
/// docs), unexpired at `now`. The same bytes as `prev` return `prev`
/// unchanged (if it has not expired). `prev` itself may have expired: an
/// expired anchor still accepts the file that replaces it.
pub fn verify_trust_update(
    prev: &VerifiedTrust,
    doc: &[u8],
    sigset: &[u8],
    now: u64,
) -> Result<VerifiedTrust, Refusal> {
    let v = verify_trust_update_at_any_time(prev, doc, sigset)?;
    v.check_fresh(now)?;
    Ok(v)
}

fn verify_trust_update_at_any_time(
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
    for r in &p.revoked_serials {
        if !n.revoked_serials.contains(r) {
            return Err(invalid(format!(
                "trust update: un-revokes {} serial {}",
                r.name, r.serial
            )));
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
            expires_at: 1_790_000_000 + 90 * 86400,
            programmes: vec![Programme {
                name: "ugv-x1".into(),
                release_keys: vec!["rel-a".into(), "rel-b".into(), "rel-c".into()],
                packages: vec!["*".into()],
            }],
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
            rings: vec![
                RingAssignment {
                    ring: "canary".into(),
                    units: vec!["ugv-08".into()],
                },
                RingAssignment {
                    ring: "lab".into(),
                    units: vec!["ugv-07".into()],
                },
            ],
            revoked_keys: vec![],
            revoked_rpks: vec![],
            revoked_serials: vec![],
            floors: vec![],
        }
    }

    /// Pinned-root acceptance of `t` at its own site, at `t.issued_at`.
    pub fn accept(doc: &[u8], sig: &[u8], t: &TrustFile) -> Result<VerifiedTrust, Refusal> {
        verify_trust_pinned(doc, sig, &pins(t), &t.site, t.issued_at)
    }

    pub fn prog(name: &str, keys: &[&str], packages: &[&str]) -> Programme {
        Programme {
            name: name.into(),
            release_keys: keys.iter().map(|k| k.to_string()).collect(),
            packages: packages.iter().map(|k| k.to_string()).collect(),
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
        accept(&doc, &sig, t).unwrap()
    }
}

#[cfg(test)]
mod tests {
    use super::test_support::*;
    use super::*;
    use crate::common::to_canonical;

    type Mutation = Box<dyn Fn(&mut TrustFile)>;
    const T0: u64 = 1_790_000_000;

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
            verify_trust_pinned(&doc, &one, &pins(&t), "site-a", T0)
                .unwrap_err()
                .code,
            Code::QuorumNotMet
        );
        let two = sign(&doc, TRUST_SIG_DOMAIN, &[&r[0], &r[2]]);
        verify_trust_pinned(&doc, &two, &pins(&t), "site-a", T0).unwrap();
        // Pins must equal the roots exactly.
        let mut fewer = pins(&t);
        fewer.pop();
        assert_eq!(
            verify_trust_pinned(&doc, &two, &fewer, "site-a", T0)
                .unwrap_err()
                .code,
            Code::UnknownKey
        );
        assert!(verify_trust_pinned(&doc, &two, &[], "site-a", T0).is_err());
        // Release keys (even two) cannot sign a trust file.
        let rel = sign(
            &doc,
            TRUST_SIG_DOMAIN,
            &[&key("rel-a", 11), &key("rel-b", 12)],
        );
        assert_eq!(
            verify_trust_pinned(&doc, &rel, &pins(&t), "site-a", T0)
                .unwrap_err()
                .code,
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
            verify_trust_pinned(&edoc, &esig, &pins(&t), "site-a", T0)
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
                Box::new(|t| {
                    t.programmes = vec![
                        prog("b", &["rel-a", "rel-b"], &["x"]),
                        prog("a", &["rel-a", "rel-b"], &["y"]),
                    ]
                }),
            ),
            ("expires = issued", Box::new(|t| t.expires_at = t.issued_at)),
            (
                "expires < issued",
                Box::new(|t| t.expires_at = t.issued_at - 1),
            ),
            (
                "lifetime too long",
                Box::new(|t| t.expires_at = t.issued_at + MAX_TRUST_LIFETIME_S + 1),
            ),
            ("root quorum 17", Box::new(|t| t.quorum.root = 17)),
            ("op prod 16", Box::new(|t| t.quorum.operator_prod = 16)),
            (
                "programme names a depot key",
                Box::new(|t| {
                    t.programmes[0].release_keys =
                        vec!["depot-1".into(), "rel-a".into(), "rel-b".into()]
                }),
            ),
            (
                "programme names an unknown key",
                Box::new(|t| t.programmes[0].release_keys.push("rel-z".into())),
            ),
            (
                "programme below the release quorum",
                Box::new(|t| t.programmes[0].release_keys = vec!["rel-a".into()]),
            ),
            (
                "programme quorum unreachable after revocation",
                Box::new(|t| {
                    t.programmes[0].release_keys = vec!["rel-a".into(), "rel-b".into()];
                    t.revoked_keys = vec![fingerprint(&key("rel-a", 11).public_key())];
                }),
            ),
            (
                "no packages",
                Box::new(|t| t.programmes[0].packages.clear()),
            ),
            (
                "bad package pattern",
                Box::new(|t| t.programmes[0].packages = vec!["nav*x".into()]),
            ),
            (
                "upper-case package",
                Box::new(|t| t.programmes[0].packages = vec!["Nav".into()]),
            ),
            (
                "package in two programmes",
                Box::new(|t| {
                    t.programmes = vec![
                        prog("a", &["rel-a", "rel-b"], &["nav"]),
                        prog("b", &["rel-b", "rel-c"], &["nav"]),
                    ]
                }),
            ),
            (
                "package under another's prefix",
                Box::new(|t| {
                    t.programmes = vec![
                        prog("a", &["rel-a", "rel-b"], &["nav-*"]),
                        prog("b", &["rel-b", "rel-c"], &["nav-stack"]),
                    ]
                }),
            ),
            (
                "nested prefixes",
                Box::new(|t| {
                    t.programmes = vec![
                        prog("a", &["rel-a", "rel-b"], &["nav*"]),
                        prog("b", &["rel-b", "rel-c"], &["nav-*"]),
                    ]
                }),
            ),
            (
                "wildcard and anything",
                Box::new(|t| {
                    t.programmes = vec![
                        prog("a", &["rel-a", "rel-b"], &["*"]),
                        prog("b", &["rel-b", "rel-c"], &["x"]),
                    ]
                }),
            ),
            (
                "exact name equals prefix",
                Box::new(|t| t.programmes[0].packages = vec!["nav".into(), "nav*".into()]),
            ),
            (
                "unit in two rings",
                Box::new(|t| t.rings[0].units = vec!["ugv-07".into()]),
            ),
            ("bad ring", Box::new(|t| t.rings[0].ring = "prod".into())),
            ("rings unsorted", Box::new(|t| t.rings.swap(0, 1))),
            ("ring without units", Box::new(|t| t.rings[0].units.clear())),
            (
                "revoked serial 0",
                Box::new(|t| {
                    t.revoked_serials = vec![RevokedSerial {
                        name: "a".into(),
                        serial: 0,
                    }]
                }),
            ),
            (
                "revoked serials unsorted",
                Box::new(|t| {
                    t.revoked_serials = vec![
                        RevokedSerial {
                            name: "a".into(),
                            serial: 2,
                        },
                        RevokedSerial {
                            name: "a".into(),
                            serial: 1,
                        },
                    ]
                }),
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
        let v2 = verify_trust_update(&prev, &d2, &s2, T0).unwrap();
        assert_eq!(v2.floor("pkg"), 5);
        // Idempotent for the same bytes, equivocation for others.
        assert_eq!(verify_trust_update(&v2, &d2, &s2, T0).unwrap(), v2);
        let mut t2b = t2.clone();
        t2b.issued_at += 1;
        let (d2b, s2b) = signed(&t2b, &[&r[0], &r[1]]);
        assert_eq!(
            verify_trust_update(&v2, &d2b, &s2b, T0).unwrap_err().code,
            Code::Equivocation
        );
        // Replay of version 1 after 2.
        let (d1, s1) = signed(&base(), &[&r[0], &r[1]]);
        assert_eq!(
            verify_trust_update(&v2, &d1, &s1, T0).unwrap_err().code,
            Code::Replay
        );

        // Root rotation: replace root-3 by root-4. Needs 2 old + 2 new.
        let mut t3 = t2.clone();
        t3.version = 3;
        t3.roots = vec![tk(&r[0]), tk(&r[1]), tk(&key("root-4", 4))];
        let r4 = key("root-4", 4);
        let (d3, s3) = signed(&t3, &[&r[2], &r4]); // 1 old (r3) + r4: old quorum not met
        assert_eq!(
            verify_trust_update(&v2, &d3, &s3, T0).unwrap_err().code,
            Code::QuorumNotMet
        );
        let (d3, s3) = signed(&t3, &[&r[0], &r[1]]); // old roots, also 2 new
        let v3 = verify_trust_update(&v2, &d3, &s3, T0).unwrap();
        // Takeover attempt: new file with all-new roots signed only by them.
        let mut evil = t3.clone();
        evil.version = 4;
        evil.roots = (50..=52)
            .map(|i| tk(&key(&format!("root-{i}"), i)))
            .collect();
        let (de, se) = signed(&evil, &[&key("root-50", 50), &key("root-51", 51)]);
        assert_eq!(
            verify_trust_update(&v3, &de, &se, T0).unwrap_err().code,
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
            assert!(verify_trust_update(&v3, &d, &s, T0).is_err(), "{name}");
        }
    }

    /// Review 13a finding 1: roots are shared by the sites of a programme
    /// office, so the pinned site is checked too; finding 4: expiry.
    #[test]
    fn site_is_pinned_and_expired_files_are_refused() {
        let t = base();
        let doc = to_canonical(&t).unwrap();
        let r = roots();
        let sig = sign(&doc, TRUST_SIG_DOMAIN, &[&r[0], &r[1]]);
        verify_trust_pinned(&doc, &sig, &pins(&t), "site-a", T0).unwrap();
        assert_eq!(
            verify_trust_pinned(&doc, &sig, &pins(&t), "site-b", T0)
                .unwrap_err()
                .code,
            Code::WrongScope
        );
        // Expired at and after expires_at; the anchor loader ignores time.
        assert_eq!(
            verify_trust_pinned(&doc, &sig, &pins(&t), "site-a", t.expires_at)
                .unwrap_err()
                .code,
            Code::Expired
        );
        verify_trust_pinned(&doc, &sig, &pins(&t), "site-a", t.expires_at - 1).unwrap();
        let anchor = verify_trust_anchor(&doc, &sig, &pins(&t), "site-a").unwrap();
        assert_eq!(
            verify_trust_update(&anchor, &doc, &sig, t.expires_at)
                .unwrap_err()
                .code,
            Code::Expired
        );
        // An expired anchor accepts its fresh successor.
        let mut t2 = base();
        t2.version = 2;
        t2.issued_at = t.expires_at;
        t2.expires_at = t.expires_at + 86400;
        let (d2, s2) = signed(&t2, &[&r[0], &r[1]]);
        verify_trust_update(&anchor, &d2, &s2, t.expires_at).unwrap();
    }

    #[test]
    fn programmes_scope_release_keys_and_packages() {
        let mut t = base();
        t.programmes = vec![
            prog("ugv-x1", &["rel-a", "rel-b"], &["mission-cfg", "nav-*"]),
            prog("ugv-y2", &["rel-b", "rel-c"], &["arm-ctl"]),
        ];
        let v = verified(&t);
        assert_eq!(v.programme_of_package("nav-stack"), Some("ugv-x1"));
        assert_eq!(v.programme_of_package("nav-"), Some("ugv-x1"));
        assert_eq!(v.programme_of_package("mission-cfg"), Some("ugv-x1"));
        assert_eq!(v.programme_of_package("arm-ctl"), Some("ugv-y2"));
        assert_eq!(v.programme_of_package("nav"), None);
        assert_eq!(v.programme_of_package("other"), None);
        assert!(v.accepts_programme("ugv-y2") && !v.accepts_programme("ugv-z3"));
        let fp = |id: &str, seed: u8| (Role::Release, fingerprint(&key(id, seed).public_key()));
        let both = Signers([fp("rel-a", 11), fp("rel-b", 12)].into_iter().collect());
        v.require_release_quorum(&both, "ugv-x1", "x").unwrap();
        // rel-a is not a key of ugv-y2: refused even though rel-b is.
        assert_eq!(
            v.require_release_quorum(&both, "ugv-y2", "x")
                .unwrap_err()
                .code,
            Code::WrongScope
        );
        let one = Signers([fp("rel-b", 12)].into_iter().collect());
        assert_eq!(
            v.require_release_quorum(&one, "ugv-y2", "x")
                .unwrap_err()
                .code,
            Code::QuorumNotMet
        );
        assert_eq!(
            v.require_release_quorum(&both, "ugv-z3", "x")
                .unwrap_err()
                .code,
            Code::WrongScope
        );
        // Rings and serial revocations.
        assert_eq!(v.ring_of_unit("ugv-07"), Some("lab"));
        assert_eq!(v.ring_of_unit("ugv-99"), None);
        let mut t = base();
        t.revoked_serials = vec![RevokedSerial {
            name: "nav-stack".into(),
            serial: 9,
        }];
        let v = verified(&t);
        assert!(v.is_serial_revoked("nav-stack", 9));
        assert!(!v.is_serial_revoked("nav-stack", 8));
    }

    #[test]
    fn rotation_keeps_serial_revocations() {
        let mut t1 = base();
        t1.revoked_serials = vec![RevokedSerial {
            name: "nav-stack".into(),
            serial: 9,
        }];
        let prev = verified(&t1);
        let mut t2 = base();
        t2.version = 2;
        let r = roots();
        let (d, s) = signed(&t2, &[&r[0], &r[1]]);
        assert!(verify_trust_update(&prev, &d, &s, T0).is_err());
        t2.revoked_serials = t1.revoked_serials.clone();
        let (d, s) = signed(&t2, &[&r[0], &r[1]]);
        verify_trust_update(&prev, &d, &s, T0).unwrap();
    }

    /// `sign` checks existing root signatures against the document's roots
    /// and, during a rotation, the accepted file's.
    #[test]
    fn existing_trust_signatures_are_checked() {
        let t = base();
        let doc = to_canonical(&t).unwrap();
        let r = roots();
        let good = sign(&doc, TRUST_SIG_DOMAIN, &[&r[0]]);
        check_trust_signatures(&doc, &good, None).unwrap();
        let stale = sign(b"other", TRUST_SIG_DOMAIN, &[&r[0]]);
        assert_eq!(
            check_trust_signatures(&doc, &stale, None).unwrap_err().code,
            Code::BadSignature
        );
        // A rotation away from root-3: its signature is checked against
        // the accepted file.
        let prev = verified(&base());
        let mut t2 = base();
        t2.version = 2;
        t2.roots = vec![tk(&r[0]), tk(&r[1]), tk(&key("root-4", 4))];
        let d2 = to_canonical(&t2).unwrap();
        let s3 = sign(&d2, TRUST_SIG_DOMAIN, &[&r[2]]);
        assert_eq!(
            check_trust_signatures(&d2, &s3, None).unwrap_err().code,
            Code::UnknownKey
        );
        check_trust_signatures(&d2, &s3, Some(&prev)).unwrap();
    }

    /// A mixed-order "twin" of the key with `seed` (`A + T`, `T` of order
    /// 2) and a signature over `msg` that verifies under the twin, made with
    /// `A`'s secret alone (nonce ground until `k` is even, so `[k]T = 0`).
    pub(crate) fn twin_sign(seed: &[u8; 32], msg: &[u8]) -> ([u8; 32], [u8; 64]) {
        use curve25519_dalek::edwards::CompressedEdwardsY;
        use curve25519_dalek::{EdwardsPoint, Scalar};
        use robodr_blackbox::sign_ed25519::sha512;
        let h = sha512(seed);
        let mut a_bytes = [0u8; 32];
        a_bytes.copy_from_slice(&h[..32]);
        a_bytes[0] &= 248;
        a_bytes[31] &= 127;
        a_bytes[31] |= 64;
        let a = Scalar::from_bytes_mod_order(a_bytes);
        let mut t = [0xffu8; 32];
        t[0] = 0xec;
        t[31] = 0x7f;
        let t = CompressedEdwardsY(t).decompress().unwrap();
        let twin = (EdwardsPoint::mul_base(&a) + t).compress().to_bytes();
        let mut i = 0u32;
        loop {
            let mut nm = h[32..].to_vec();
            nm.extend(i.to_le_bytes());
            nm.extend(msg);
            let r = Scalar::from_bytes_mod_order_wide(&sha512(&nm));
            let big_r = EdwardsPoint::mul_base(&r).compress().to_bytes();
            let mut km = big_r.to_vec();
            km.extend(twin);
            km.extend(msg);
            let k = Scalar::from_bytes_mod_order_wide(&sha512(&km));
            if k.to_bytes()[0] & 1 == 0 {
                let s = r + k * a;
                let mut sig = [0u8; 64];
                sig[..32].copy_from_slice(&big_r);
                sig[32..].copy_from_slice(&s.to_bytes());
                return (twin, sig);
            }
            i += 1;
        }
    }

    /// Review 13a finding 2: one secret enrolled twice (as `A` and as its
    /// mixed-order twin `A + T`, another fingerprint) would be two votes.
    #[test]
    fn a_mixed_order_twin_key_is_refused_in_a_trust_file() {
        let seed = [11u8; 32]; // rel-a
        let msg = crate::common::domain_message(crate::rpk::MANIFEST_SIG_DOMAIN, b"doc");
        let (twin, sig) = twin_sign(&seed, &msg);
        // The twin is another fingerprint than rel-a.
        assert_ne!(
            fingerprint(&twin),
            fingerprint(&key("rel-a", 11).public_key())
        );
        // Its signature, made with rel-a's secret, must not verify.
        assert!(
            !robodr_blackbox::sign_ed25519::verify(&twin, &msg, &sig),
            "a twin-key signature verified"
        );
        // And a trust file listing it next to rel-a is refused.
        let mut t = base();
        t.release_keys.push(TrustKey::new("rel-z", &twin));
        assert!(
            parse_trust(&to_canonical(&t).unwrap()).is_err(),
            "trust file with a twin key accepted"
        );
    }

    /// Review 13a finding 9: a quorum above the 16-signature cap of a
    /// signature set can never be met; such a trust file is refused rather
    /// than accepted and then refusing everything.
    #[test]
    fn quorums_above_the_signature_cap_are_refused() {
        let mut t = base();
        t.release_keys = (0..17u8)
            .map(|i| tk(&key(&format!("rel-{i:02}"), 100 + i)))
            .collect();
        t.quorum.release = 17;
        assert!(
            parse_trust(&to_canonical(&t).unwrap()).is_err(),
            "release quorum 17 accepted"
        );
    }
}
