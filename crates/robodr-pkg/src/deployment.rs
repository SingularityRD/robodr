//! Deployment document (`robodr-deployment/1`, `docs/SECURE-DELIVERY.md`
//! §5.2): "these RPK digests on these units, in this ring", signed by the
//! site depot and, by ring, by site operators.
//!
//! Only the format, its validation and its signature / quorum / freshness
//! checks are Sprint 13a; creating deployments is the depot's job (14a)
//! and acting on them the unit agent's (13b).
//!
//! Rules (decisions in §3.5 of the design):
//!
//! * Signed over [`DEPLOYMENT_SIG_DOMAIN`] by **depot** and **operator**
//!   keys only (a release or root key is refused: [`Code::WrongRole`]). At
//!   least one depot signature (the depot quorum is 1), plus
//!   `quorum.operator_prod` distinct operators, except that
//!   `quorum.operator_lab` suffices for a [`lab_quorum_applies`]
//!   deployment. The table of §3.4 says "1 for lab"; §5.3 reads as if a
//!   depot alone could push to `lab` and `canary`. The stricter reading is
//!   taken: every ring needs at least one operator, so a compromised depot
//!   (T4) alone can push nowhere.
//! * **The ring label is bound to the targets** (13a review finding 3):
//!   `ring` is written by the depot, so it cannot by itself choose the
//!   smaller quorum. The lab quorum applies only when the ring is `lab` or
//!   `canary`, the targets are units only (a group's membership is the
//!   depot's to define, so a group is never authenticated as lab), every
//!   unit is assigned to that very ring by the root-signed trust file
//!   (`rings`), and a `canary` deployment names exactly one unit (§4.3).
//!   Anything else needs the production quorum. The unit agent (13b) must
//!   in addition refuse a deployment whose ring is not its own.
//! * `not_before < expires_at`, at most [`MAX_VALIDITY_S`] apart; a
//!   deployment is valid for `not_before <= now < expires_at`.
//! * Replay: `deployment_seq` increases per site ([`check_seq`]). A unit
//!   only sees the deployments that target it, so a gap is normal and not
//!   reported; an older or equal-but-different sequence number is refused.
//! * `wrapped_keys` (Sprint 13c, §7.3): for each sealed item and each unit
//!   that may install it, `wrap(UWK_unit, CK)` as produced by `robodr-seal`
//!   (opaque here: lower-case hex of at most [`MAX_WRAP_BYTES`] bytes).
//!   Entries are sorted by `(unit, rpk_digest)` without duplicates, name an
//!   item of this deployment, and name a unit the deployment targets
//!   (any unit label when it also targets groups: the depot expands a
//!   group's membership, and the unit only ever looks for its own entry).
//!   Which items are sealed is the manifests' to say, so a missing wrap is
//!   the unit's refusal, not this parser's.

use crate::common::{
    domain_hash, invalid, is_hex64, is_label, is_pkg_name, parse_canonical, strictly_sorted, Code,
    Refusal,
};
use crate::sig::{Role, SignatureSet, Signers};
use crate::trust::VerifiedTrust;
use crate::MAX_SAFE_INTEGER;
use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;

/// `format` of a deployment.
pub const DEPLOYMENT_FORMAT: &str = "robodr-deployment/1";
/// Domain of deployment signatures.
pub const DEPLOYMENT_SIG_DOMAIN: &[u8] = b"robodr-deployment/v1\0";
/// Domain of the deployment digest.
pub const DEPLOYMENT_DIGEST_DOMAIN: &[u8] = b"robodr-deployment/digest/v1\0";
/// Largest deployment read.
pub const MAX_DEPLOYMENT_BYTES: usize = 1024 * 1024;
/// Most targets (units + groups) and items.
pub const MAX_TARGETS: usize = 4096;
pub const MAX_ITEMS: usize = 256;
/// Longest validity window (one year and a day).
pub const MAX_VALIDITY_S: u64 = 366 * 24 * 3600;
/// Longest soak.
pub const MAX_SOAK_S: u32 = 7 * 24 * 3600;

/// Units and groups a deployment targets.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Targets {
    pub units: Vec<String>,
    pub groups: Vec<String>,
}

/// One assigned RPK.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Item {
    pub rpk_digest: String,
    pub name: String,
    pub serial: u64,
}

/// Staged rollout parameters (§6.2).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Rollout {
    pub batch_size: u32,
    pub soak_s: u32,
    /// Failures in the ring that halt the rollout.
    pub max_failures: u32,
}

/// Day of the week.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Weekday {
    Mon,
    Tue,
    Wed,
    Thu,
    Fri,
    Sat,
    Sun,
}

/// When installs that restart anything may run (§6.3), in UTC.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MaintenanceWindow {
    pub days: Vec<Weekday>,
    /// Minutes after 00:00 UTC.
    pub start_minute: u32,
    pub duration_minutes: u32,
}

/// The deployment (members in canonical order).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Deployment {
    pub format: String,
    pub deployment_id: String,
    pub site: String,
    pub deployment_seq: u64,
    pub created_at: u64,
    pub targets: Targets,
    /// `lab`, `canary` or `ring-<1..99>`.
    pub ring: String,
    pub items: Vec<Item>,
    pub not_before: u64,
    pub expires_at: u64,
    pub rollout: Rollout,
    pub maintenance_window: Option<MaintenanceWindow>,
    /// Per-unit content-key wraps of sealed items (Sprint 13c, §7.3).
    pub wrapped_keys: Vec<WrappedKey>,
}

/// One per-unit content-key wrap: `wrap(UWK_unit, CK)` of the sealed RPK
/// `rpk_digest` for `unit` (`robodr-seal`, `docs/SECURE-DELIVERY.md` §7.3).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WrappedKey {
    pub unit: String,
    pub rpk_digest: String,
    /// Lower-case hex of the wrap bytes (`robodr-seal` wrap format).
    pub wrap: String,
}

/// Most wrapped keys in one deployment (every target unit for every item
/// would exceed the 1 MiB document cap long before).
pub const MAX_WRAPPED_KEYS: usize = 8192;
/// Largest wrap (bytes, before hex).
pub const MAX_WRAP_BYTES: usize = 256;

/// Lower-case hex of 1..=`max` bytes.
pub fn is_hex_bytes(s: &str, max: usize) -> bool {
    !s.is_empty()
        && s.len().is_multiple_of(2)
        && s.len() <= 2 * max
        && s.bytes().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f'))
}

/// Whether `ring` is a production ring (needs the production operator quorum).
pub fn is_prod_ring(ring: &str) -> bool {
    !matches!(ring, "lab" | "canary")
}

/// `lab`, `canary` or `ring-<1..99>`.
pub fn is_ring(s: &str) -> bool {
    matches!(s, "lab" | "canary")
        || s.strip_prefix("ring-").is_some_and(|n| {
            !n.is_empty()
                && n.len() <= 2
                && n.bytes().all(|b| b.is_ascii_digit())
                && !n.starts_with('0')
        })
}

/// Whether `d` may be approved with the lab operator quorum under
/// `trust`: a `lab` or `canary` ring, units only (no groups), every unit
/// assigned to exactly that ring in the trust file, and a canary of one
/// unit. Otherwise the production quorum is required.
pub fn lab_quorum_applies(d: &Deployment, trust: &VerifiedTrust) -> bool {
    !is_prod_ring(&d.ring)
        && d.targets.groups.is_empty()
        && !d.targets.units.is_empty()
        && (d.ring != "canary" || d.targets.units.len() == 1)
        && d.targets
            .units
            .iter()
            .all(|u| trust.ring_of_unit(u) == Some(d.ring.as_str()))
}

/// Digest of deployment bytes.
pub fn deployment_digest(bytes: &[u8]) -> String {
    domain_hash(DEPLOYMENT_DIGEST_DOMAIN, bytes)
}

impl Deployment {
    pub fn validate(&self) -> Result<(), Refusal> {
        if self.format != DEPLOYMENT_FORMAT {
            return Err(invalid("deployment: unsupported format"));
        }
        if !is_label(&self.deployment_id) || !is_label(&self.site) {
            return Err(invalid("deployment: bad deployment_id or site"));
        }
        if self.deployment_seq == 0 || self.deployment_seq > MAX_SAFE_INTEGER {
            return Err(invalid("deployment: deployment_seq must be 1..=2^53-1"));
        }
        for t in [self.created_at, self.not_before, self.expires_at] {
            if t > MAX_SAFE_INTEGER {
                return Err(invalid("deployment: time out of range"));
            }
        }
        let t = &self.targets;
        if t.units.len() + t.groups.len() == 0 || t.units.len() + t.groups.len() > MAX_TARGETS {
            return Err(invalid(format!("deployment: 1..={MAX_TARGETS} targets")));
        }
        if !t.units.iter().chain(&t.groups).all(|x| is_label(x)) {
            return Err(invalid("deployment: bad target label"));
        }
        strictly_sorted(&t.units, |u| u.clone(), "targets.units")?;
        strictly_sorted(&t.groups, |g| g.clone(), "targets.groups")?;
        if !is_ring(&self.ring) {
            return Err(invalid(
                "deployment: ring must be lab, canary or ring-<1..99>",
            ));
        }
        if self.items.is_empty() || self.items.len() > MAX_ITEMS {
            return Err(invalid(format!("deployment: 1..={MAX_ITEMS} items")));
        }
        let mut digests = BTreeSet::new();
        for i in &self.items {
            if !is_hex64(&i.rpk_digest)
                || !is_pkg_name(&i.name)
                || i.serial == 0
                || i.serial > MAX_SAFE_INTEGER
            {
                return Err(invalid("deployment: bad item"));
            }
            if !digests.insert(i.rpk_digest.as_str()) {
                return Err(invalid("deployment: the same RPK twice"));
            }
        }
        strictly_sorted(&self.items, |i| i.name.clone(), "items (by name)")?;
        if self.not_before >= self.expires_at || self.expires_at - self.not_before > MAX_VALIDITY_S
        {
            return Err(invalid(format!(
                "deployment: need not_before < expires_at, at most {MAX_VALIDITY_S} s apart"
            )));
        }
        let r = &self.rollout;
        if r.batch_size == 0 || r.soak_s > MAX_SOAK_S {
            return Err(invalid("deployment: bad rollout"));
        }
        if let Some(w) = &self.maintenance_window {
            if w.days.is_empty()
                || w.start_minute >= 1440
                || w.duration_minutes == 0
                || w.duration_minutes > 1440
            {
                return Err(invalid("deployment: bad maintenance_window"));
            }
            strictly_sorted(&w.days, |d| *d, "maintenance_window.days")?;
        }
        if self.wrapped_keys.len() > MAX_WRAPPED_KEYS {
            return Err(invalid(format!(
                "deployment: more than {MAX_WRAPPED_KEYS} wrapped keys"
            )));
        }
        for w in &self.wrapped_keys {
            if !is_label(&w.unit)
                || !is_hex64(&w.rpk_digest)
                || !is_hex_bytes(&w.wrap, MAX_WRAP_BYTES)
            {
                return Err(invalid("deployment: bad wrapped key"));
            }
            if !digests.contains(w.rpk_digest.as_str()) {
                return Err(invalid(
                    "deployment: a wrapped key for an RPK that is not an item",
                ));
            }
            if t.groups.is_empty() && t.units.binary_search(&w.unit).is_err() {
                return Err(invalid(
                    "deployment: a wrapped key for a unit the deployment does not target",
                ));
            }
        }
        strictly_sorted(
            &self.wrapped_keys,
            |w| (w.unit.clone(), w.rpk_digest.clone()),
            "wrapped_keys (by unit, rpk_digest)",
        )?;
        Ok(())
    }
}

/// Parse and validate deployment bytes (no signature check).
pub fn parse_deployment(bytes: &[u8]) -> Result<Deployment, Refusal> {
    let d: Deployment = parse_canonical(bytes, MAX_DEPLOYMENT_BYTES, "deployment")?;
    d.validate()?;
    Ok(d)
}

/// A deployment that passed every check of [`verify_deployment`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerifiedDeployment {
    pub deployment: Deployment,
    pub digest: String,
    pub signers: Signers,
}

/// Parse, validate, check site, signatures (depot + operator quorum by
/// ring), item revocations and floors, and freshness at `now`.
pub fn verify_deployment(
    bytes: &[u8],
    sigset: &[u8],
    trust: &VerifiedTrust,
    now: u64,
) -> Result<VerifiedDeployment, Refusal> {
    let d = parse_deployment(bytes)?;
    if d.site != trust.file().site {
        return Err(Refusal::new(
            Code::WrongScope,
            format!(
                "deployment for site {}, this is {}",
                d.site,
                trust.file().site
            ),
        ));
    }
    let set = SignatureSet::parse(sigset)?;
    let signers = set.check(
        trust,
        &[Role::Depot, Role::Operator],
        DEPLOYMENT_SIG_DOMAIN,
        bytes,
    )?;
    signers.require(Role::Depot, 1, "deployment")?;
    let q = &trust.file().quorum;
    let (ops, why) = if lab_quorum_applies(&d, trust) {
        (q.operator_lab, String::new())
    } else if is_prod_ring(&d.ring) {
        (q.operator_prod, String::new())
    } else {
        (
            q.operator_prod,
            " (its targets are not all units the trust file assigns to that ring, or a \
             canary of more than one unit: production quorum)"
                .to_string(),
        )
    };
    signers.require(
        Role::Operator,
        ops as usize,
        &format!("deployment to {}{why}", d.ring),
    )?;
    for i in &d.items {
        if trust.is_rpk_revoked(&i.rpk_digest) || trust.is_serial_revoked(&i.name, i.serial) {
            return Err(Refusal::new(
                Code::RevokedRpk,
                format!("deployment item {} {} is revoked", i.name, i.serial),
            ));
        }
        if trust.programme_of_package(&i.name).is_none() {
            return Err(Refusal::new(
                Code::WrongScope,
                format!(
                    "deployment item {}: no programme of this site delivers that package",
                    i.name
                ),
            ));
        }
        let floor = trust.floor(&i.name);
        if i.serial < floor {
            return Err(Refusal::new(
                Code::BelowFloor,
                format!(
                    "deployment item {} {} is below the floor {floor}",
                    i.name, i.serial
                ),
            ));
        }
    }
    if now < d.not_before {
        return Err(Refusal::new(Code::NotYetValid, "deployment: not valid yet"));
    }
    if now >= d.expires_at {
        return Err(Refusal::new(Code::Expired, "deployment: expired"));
    }
    Ok(VerifiedDeployment {
        digest: deployment_digest(bytes),
        deployment: d,
        signers,
    })
}

/// The last accepted deployment of a site, for replay checks.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LastDeployment {
    pub deployment_seq: u64,
    pub digest: String,
}

/// Outcome of [`check_seq`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SeqStep {
    Newer,
    AlreadyAccepted,
}

/// Replay check: `deployment_seq` must increase (gaps are normal for one unit).
pub fn check_seq(
    last: Option<&LastDeployment>,
    d: &VerifiedDeployment,
) -> Result<SeqStep, Refusal> {
    let Some(l) = last else {
        return Ok(SeqStep::Newer);
    };
    let s = d.deployment.deployment_seq;
    if s > l.deployment_seq {
        Ok(SeqStep::Newer)
    } else if s == l.deployment_seq && d.digest == l.digest {
        Ok(SeqStep::AlreadyAccepted)
    } else if s == l.deployment_seq {
        Err(Refusal::new(
            Code::Equivocation,
            format!("deployment_seq {s} with other content"),
        ))
    } else {
        Err(Refusal::new(
            Code::Replay,
            format!(
                "deployment_seq {s} is older than the accepted {}",
                l.deployment_seq
            ),
        ))
    }
}

#[cfg(test)]
pub(crate) mod test_support {
    use super::*;

    pub fn deployment(ring: &str) -> Deployment {
        Deployment {
            format: DEPLOYMENT_FORMAT.into(),
            deployment_id: "dep-0001".into(),
            site: "site-a".into(),
            deployment_seq: 1,
            created_at: 1_790_000_000,
            targets: Targets {
                units: vec!["ugv-07".into()],
                groups: vec![],
            },
            ring: ring.into(),
            items: vec![Item {
                rpk_digest: "ab".repeat(32),
                name: "nav-stack".into(),
                serial: 7,
            }],
            not_before: 1_790_000_000,
            expires_at: 1_790_000_000 + 30 * 86400,
            rollout: Rollout {
                batch_size: 1,
                soak_s: 600,
                max_failures: 0,
            },
            maintenance_window: Some(MaintenanceWindow {
                days: vec![Weekday::Mon, Weekday::Wed],
                start_minute: 120,
                duration_minutes: 180,
            }),
            wrapped_keys: vec![],
        }
    }
}

#[cfg(test)]
mod tests {
    use super::test_support::deployment;
    use super::*;
    use crate::common::{fingerprint, to_canonical};
    use crate::trust::test_support::{base, key, sign, verified};
    use crate::trust::Floor;

    const NOW: u64 = 1_790_000_100;

    fn wk(unit: &str, digest: &str, wrap: &str) -> WrappedKey {
        WrappedKey {
            unit: unit.into(),
            rpk_digest: digest.into(),
            wrap: wrap.into(),
        }
    }

    #[test]
    fn wrapped_keys_parse() {
        let mut d = deployment("lab");
        d.wrapped_keys = vec![wk("ugv-07", &"ab".repeat(32), &"5a".repeat(150))];
        let b = to_canonical(&d).unwrap();
        assert_eq!(parse_deployment(&b).unwrap(), d);
        // With a group target, a wrap may name any unit (the depot expands
        // the group).
        d.targets.groups = vec!["all-ugv".into()];
        d.wrapped_keys.push(wk("ugv-99", &"ab".repeat(32), "00"));
        let b = to_canonical(&d).unwrap();
        assert_eq!(parse_deployment(&b).unwrap(), d);
        // An empty list is still the 13a/13b encoding.
        let d = deployment("lab");
        let b = to_canonical(&d).unwrap();
        assert!(std::str::from_utf8(&b)
            .unwrap()
            .ends_with(",\"wrapped_keys\":[]}"));
    }

    fn signed(d: &Deployment, by: &[&robodr_blackbox::Ed25519SigningKey]) -> (Vec<u8>, Vec<u8>) {
        let b = to_canonical(d).unwrap();
        let s = sign(&b, DEPLOYMENT_SIG_DOMAIN, by);
        (b, s)
    }

    #[test]
    fn quorum_by_ring() {
        let t = verified(&base());
        let (depot, o1, o2) = (key("depot-1", 21), key("op-1", 31), key("op-2", 32));
        // lab: depot + 1 operator.
        let (b, s) = signed(&deployment("lab"), &[&depot, &o1]);
        verify_deployment(&b, &s, &t, NOW).unwrap();
        // lab with the depot alone: refused (stricter reading of §3.4 / §5.3).
        let (b, s) = signed(&deployment("lab"), &[&depot]);
        assert_eq!(
            verify_deployment(&b, &s, &t, NOW).unwrap_err().code,
            Code::QuorumNotMet
        );
        // canary likewise.
        let (b, s) = signed(&deployment("canary"), &[&depot]);
        assert_eq!(
            verify_deployment(&b, &s, &t, NOW).unwrap_err().code,
            Code::QuorumNotMet
        );
        // prod: one operator is not enough, two are.
        let (b, s) = signed(&deployment("ring-1"), &[&depot, &o1]);
        assert_eq!(
            verify_deployment(&b, &s, &t, NOW).unwrap_err().code,
            Code::QuorumNotMet
        );
        let (b, s) = signed(&deployment("ring-1"), &[&depot, &o1, &o2]);
        verify_deployment(&b, &s, &t, NOW).unwrap();
        // Operators without the depot.
        let (b, s) = signed(&deployment("ring-1"), &[&o1, &o2]);
        assert_eq!(
            verify_deployment(&b, &s, &t, NOW).unwrap_err().code,
            Code::QuorumNotMet
        );
    }

    #[test]
    fn key_confusion_is_refused() {
        let t = verified(&base());
        let (depot, o1) = (key("depot-1", 21), key("op-1", 31));
        // Release keys cannot sign deployments; roots neither.
        for k in [key("rel-a", 11), key("root-1", 1)] {
            let (b, s) = signed(&deployment("lab"), &[&depot, &o1, &k]);
            assert_eq!(
                verify_deployment(&b, &s, &t, NOW).unwrap_err().code,
                Code::WrongRole
            );
        }
        // An RPK-manifest signature over the same bytes does not verify here.
        let b = to_canonical(&deployment("lab")).unwrap();
        let s = sign(&b, crate::rpk::MANIFEST_SIG_DOMAIN, &[&depot, &o1]);
        assert_eq!(
            verify_deployment(&b, &s, &t, NOW).unwrap_err().code,
            Code::BadSignature
        );
    }

    #[test]
    fn freshness_policy_and_scope() {
        let mut tf = base();
        tf.revoked_rpks = vec!["ab".repeat(32)];
        let t = verified(&tf);
        let (depot, o1) = (key("depot-1", 21), key("op-1", 31));
        let (b, s) = signed(&deployment("lab"), &[&depot, &o1]);
        assert_eq!(
            verify_deployment(&b, &s, &t, NOW).unwrap_err().code,
            Code::RevokedRpk
        );
        let mut tf = base();
        tf.floors = vec![Floor {
            name: "nav-stack".into(),
            min_serial: 8,
        }];
        let t = verified(&tf);
        assert_eq!(
            verify_deployment(&b, &s, &t, NOW).unwrap_err().code,
            Code::BelowFloor
        );
        let t = verified(&base());
        let d = deployment("lab");
        assert_eq!(
            verify_deployment(&b, &s, &t, d.not_before - 1)
                .unwrap_err()
                .code,
            Code::NotYetValid
        );
        assert_eq!(
            verify_deployment(&b, &s, &t, d.expires_at)
                .unwrap_err()
                .code,
            Code::Expired
        );
        let mut other = deployment("lab");
        other.site = "site-b".into();
        let (b2, s2) = signed(&other, &[&depot, &o1]);
        assert_eq!(
            verify_deployment(&b2, &s2, &t, NOW).unwrap_err().code,
            Code::WrongScope
        );
        // A revoked operator key refuses the document.
        let mut tf = base();
        tf.revoked_keys = vec![fingerprint(&o1.public_key())];
        let t = verified(&tf);
        assert_eq!(
            verify_deployment(&b, &s, &t, NOW).unwrap_err().code,
            Code::RevokedKey
        );
    }

    #[test]
    fn replay() {
        let t = verified(&base());
        let (depot, o1) = (key("depot-1", 21), key("op-1", 31));
        let mut d = deployment("lab");
        d.deployment_seq = 5;
        let (b, s) = signed(&d, &[&depot, &o1]);
        let v5 = verify_deployment(&b, &s, &t, NOW).unwrap();
        let last = LastDeployment {
            deployment_seq: 5,
            digest: v5.digest.clone(),
        };
        assert_eq!(check_seq(None, &v5).unwrap(), SeqStep::Newer);
        assert_eq!(
            check_seq(Some(&last), &v5).unwrap(),
            SeqStep::AlreadyAccepted
        );
        d.deployment_seq = 4;
        let (b, s) = signed(&d, &[&depot, &o1]);
        let v4 = verify_deployment(&b, &s, &t, NOW).unwrap();
        assert_eq!(check_seq(Some(&last), &v4).unwrap_err().code, Code::Replay);
        d.deployment_seq = 5;
        d.created_at += 1;
        let (b, s) = signed(&d, &[&depot, &o1]);
        let v5b = verify_deployment(&b, &s, &t, NOW).unwrap();
        assert_eq!(
            check_seq(Some(&last), &v5b).unwrap_err().code,
            Code::Equivocation
        );
        d.deployment_seq = 9;
        let (b, s) = signed(&d, &[&depot, &o1]);
        let v9 = verify_deployment(&b, &s, &t, NOW).unwrap();
        assert_eq!(check_seq(Some(&last), &v9).unwrap(), SeqStep::Newer);
    }

    #[test]
    fn structural_rules() {
        type Mutation = Box<dyn Fn(&mut Deployment)>;
        let cases: Vec<(&str, Code, Mutation)> = vec![
            ("format", Code::Invalid, Box::new(|d| d.format = "x".into())),
            ("seq 0", Code::Invalid, Box::new(|d| d.deployment_seq = 0)),
            (
                "no targets",
                Code::Invalid,
                Box::new(|d| d.targets.units.clear()),
            ),
            (
                "bad unit",
                Code::Invalid,
                Box::new(|d| d.targets.units = vec!["../x".into()]),
            ),
            ("ring", Code::Invalid, Box::new(|d| d.ring = "prod".into())),
            (
                "ring-0",
                Code::Invalid,
                Box::new(|d| d.ring = "ring-0".into()),
            ),
            (
                "ring-100",
                Code::Invalid,
                Box::new(|d| d.ring = "ring-100".into()),
            ),
            ("no items", Code::Invalid, Box::new(|d| d.items.clear())),
            (
                "dup item",
                Code::Invalid,
                Box::new(|d| {
                    let i = d.items[0].clone();
                    d.items.push(i);
                }),
            ),
            (
                "window inverted",
                Code::Invalid,
                Box::new(|d| d.expires_at = d.not_before),
            ),
            (
                "window long",
                Code::Invalid,
                Box::new(|d| d.expires_at = d.not_before + MAX_VALIDITY_S + 1),
            ),
            (
                "batch 0",
                Code::Invalid,
                Box::new(|d| d.rollout.batch_size = 0),
            ),
            (
                "mw minute",
                Code::Invalid,
                Box::new(|d| d.maintenance_window.as_mut().unwrap().start_minute = 1440),
            ),
            (
                "mw days",
                Code::Invalid,
                Box::new(|d| {
                    d.maintenance_window.as_mut().unwrap().days = vec![Weekday::Wed, Weekday::Mon]
                }),
            ),
            (
                "wrap for no item",
                Code::Invalid,
                Box::new(|d| d.wrapped_keys = vec![wk("ugv-07", &"cd".repeat(32), "00")]),
            ),
            (
                "wrap for an untargeted unit",
                Code::Invalid,
                Box::new(|d| d.wrapped_keys = vec![wk("ugv-99", &"ab".repeat(32), "00")]),
            ),
            (
                "wrap not hex",
                Code::Invalid,
                Box::new(|d| d.wrapped_keys = vec![wk("ugv-07", &"ab".repeat(32), "0G")]),
            ),
            (
                "wrap odd hex",
                Code::Invalid,
                Box::new(|d| d.wrapped_keys = vec![wk("ugv-07", &"ab".repeat(32), "000")]),
            ),
            (
                "wrap upper hex",
                Code::Invalid,
                Box::new(|d| d.wrapped_keys = vec![wk("ugv-07", &"ab".repeat(32), "AB")]),
            ),
            (
                "wrap too long",
                Code::Invalid,
                Box::new(|d| {
                    d.wrapped_keys = vec![wk("ugv-07", &"ab".repeat(32), &"00".repeat(257))]
                }),
            ),
            (
                "wrap twice",
                Code::Invalid,
                Box::new(|d| {
                    d.wrapped_keys = vec![
                        wk("ugv-07", &"ab".repeat(32), "00"),
                        wk("ugv-07", &"ab".repeat(32), "01"),
                    ]
                }),
            ),
        ];
        for (name, code, f) in cases {
            let mut d = deployment("lab");
            f(&mut d);
            let b = to_canonical(&d).unwrap();
            assert_eq!(parse_deployment(&b).unwrap_err().code, code, "{name}");
        }
        assert!(is_prod_ring("ring-2"));
        assert!(!is_prod_ring("canary"));
    }

    /// Review 13a finding 3: the ring label picks the operator quorum, so it
    /// must be bound to the targets. A depot plus one operator must not
    /// reach production units or depot-defined groups by labelling the
    /// deployment `lab`, nor more than one unit as `canary`.
    #[test]
    fn a_lab_label_does_not_reach_production_units() {
        let t = verified(&base());
        let (depot, o1, o2) = (key("depot-1", 21), key("op-1", 31), key("op-2", 32));
        let mut d = deployment("lab");
        d.targets.units = vec![
            "prod-ugv-001".into(),
            "prod-ugv-002".into(),
            "prod-ugv-003".into(),
        ];
        d.targets.groups = vec!["ring-2-all-production".into()];
        let (b, s) = signed(&d, &[&depot, &o1]);
        assert_eq!(
            verify_deployment(&b, &s, &t, NOW)
                .map(|_| ())
                .unwrap_err()
                .code,
            Code::QuorumNotMet,
            "lab deployment to production units accepted with one operator"
        );
        // A group (depot-defined membership) is never authenticated as lab.
        let mut d = deployment("lab");
        d.targets.groups = vec!["lab-bench".into()];
        let (b, s) = signed(&d, &[&depot, &o1]);
        assert_eq!(
            verify_deployment(&b, &s, &t, NOW)
                .map(|_| ())
                .unwrap_err()
                .code,
            Code::QuorumNotMet
        );
        // With the production quorum the same deployment is fine.
        let (b, s) = signed(&d, &[&depot, &o1, &o2]);
        verify_deployment(&b, &s, &t, NOW).unwrap();
        // Canary is one unit (§4.3).
        let mut d = deployment("canary");
        d.targets.units = vec!["ugv-08".into(), "ugv-09".into()];
        let (b, s) = signed(&d, &[&depot, &o1]);
        assert_eq!(
            verify_deployment(&b, &s, &t, NOW)
                .map(|_| ())
                .unwrap_err()
                .code,
            Code::QuorumNotMet
        );
    }
}
