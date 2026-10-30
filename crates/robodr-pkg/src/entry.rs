//! Entry report (`robodr-entry-report/1`, `docs/SECURE-DELIVERY.md` §6.1,
//! Sprint 14a): what the entry station found when it scanned one bundle,
//! signed by an entry-station key of the site trust file
//! ([`Role::Entry`]). `robodr-depot import` refuses a bundle without a
//! verifying, passing, unexpired report **for exactly that bundle**.
//!
//! ```json
//! {"format":"robodr-entry-report/1","site":"site-a","station":"entry-1",
//!  "programme":"ugv-x1","bundle_seq":4,"bundle_hash":"<64 hex>",
//!  "scanned_at":1790000000,"expires_at":1790604800,
//!  "vulndb":{"name":"site-vulndb","version":12,"sha256":"<64 hex>"},
//!  "rpks":[{"digest":"<64 hex>","name":"nav-stack","serial":7,
//!           "sbom":{"sha256":"<64 hex>","components":42,"previous_serial":6,
//!                   "added":["libfoo@1.2"],"removed":[],"licence_changes":[]},
//!           "vulnerabilities":[{"id":"CVE-2026-0001","component":"libfoo@1.2","severity":"high"}]}],
//!  "fail_on":"high","verdict":"pass"}
//! ```
//!
//! Rules:
//!
//! * One canonical encoding ([`crate::common::parse_canonical`]); signed
//!   over [`ENTRY_SIG_DOMAIN`] by entry keys only (a release, depot,
//!   operator or root key is [`Code::WrongRole`]); one entry signature is
//!   the quorum (an entry station is one machine, like the depot).
//! * **Bound to one bundle**: `site`, `programme`, `bundle_seq`,
//!   `bundle_hash` (the [`crate::bundle::bundle_hash`] of `bundle.json`)
//!   and the RPK list (digest, name, serial, exactly the bundle's) must all
//!   match the bundle being imported, so a report for one bundle never
//!   admits another (a replayed or relabelled report is
//!   [`Code::DigestMismatch`] or [`Code::WrongScope`]).
//! * `scanned_at < expires_at <= scanned_at +` [`MAX_REPORT_LIFETIME_S`]:
//!   a scan against a stale vulnerability database does not stay good
//!   forever; refused at and after `expires_at`, and before `scanned_at`.
//! * `verdict` must be `pass` ([`Code::ScanFailed`] otherwise), and it
//!   must be consistent with the report itself: a `pass` report listing a
//!   vulnerability at or above `fail_on` is refused (the depot does not
//!   take the station's word for a verdict its own content contradicts).
//! * Lists are sorted and bounded; component names are printable ASCII.

use crate::bundle::VerifiedBundle;
use crate::common::{
    domain_hash, invalid, is_hex64, is_label, is_pkg_name, parse_canonical, strictly_sorted, Code,
    Refusal,
};
use crate::sig::{Role, SignatureSet, Signers};
use crate::trust::VerifiedTrust;
use crate::MAX_SAFE_INTEGER;
use serde::{Deserialize, Serialize};

pub const ENTRY_FORMAT: &str = "robodr-entry-report/1";
pub const ENTRY_SIG_DOMAIN: &[u8] = b"robodr-entry-report/v1\0";
pub const ENTRY_DIGEST_DOMAIN: &[u8] = b"robodr-entry-report/digest/v1\0";
pub const MAX_ENTRY_BYTES: usize = 4 * 1024 * 1024;
/// Longest validity of a report (30 days).
pub const MAX_REPORT_LIFETIME_S: u64 = 30 * 24 * 3600;
pub const MAX_COMPONENT_LIST: usize = 4096;
pub const MAX_VULNS: usize = 4096;
pub const MAX_TEXT: usize = 200;

/// Vulnerability severity (CVSS bands).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Severity {
    Low,
    Medium,
    High,
    Critical,
}

impl Severity {
    pub fn parse(s: &str) -> Option<Self> {
        match s {
            "low" => Some(Self::Low),
            "medium" => Some(Self::Medium),
            "high" => Some(Self::High),
            "critical" => Some(Self::Critical),
            _ => None,
        }
    }
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Low => "low",
            Self::Medium => "medium",
            Self::High => "high",
            Self::Critical => "critical",
        }
    }
}

/// The station's verdict.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Verdict {
    Pass,
    Fail,
}

/// The offline vulnerability database the scan used.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct VulnDbRef {
    pub name: String,
    pub version: u64,
    pub sha256: String,
}

/// SBOM summary and diff against the previous serial of the package.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SbomDiff {
    /// SHA-256 of the SBOM file (the manifest's `sbom`).
    pub sha256: String,
    pub components: u64,
    /// The serial whose SBOM this one was compared with (`null`: first
    /// seen at this station).
    pub previous_serial: Option<u64>,
    /// `name@version`, sorted.
    pub added: Vec<String>,
    pub removed: Vec<String>,
    /// `name@version: old -> new`, sorted.
    pub licence_changes: Vec<String>,
}

/// One known vulnerability matched in an SBOM.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Vuln {
    pub id: String,
    pub component: String,
    pub severity: Severity,
}

/// What was found for one RPK of the bundle.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RpkScan {
    pub digest: String,
    pub name: String,
    pub serial: u64,
    /// `null` for kinds without a mandatory SBOM that carry none.
    pub sbom: Option<SbomDiff>,
    /// Sorted by (id, component).
    pub vulnerabilities: Vec<Vuln>,
}

/// The entry report (members in canonical order).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EntryReport {
    pub format: String,
    pub site: String,
    pub station: String,
    pub programme: String,
    pub bundle_seq: u64,
    pub bundle_hash: String,
    pub scanned_at: u64,
    pub expires_at: u64,
    pub vulndb: Option<VulnDbRef>,
    /// Sorted by digest; exactly the bundle's RPKs.
    pub rpks: Vec<RpkScan>,
    /// The lowest severity that fails the scan.
    pub fail_on: Severity,
    pub verdict: Verdict,
}

/// Digest of report bytes (recorded by the depot).
pub fn entry_digest(bytes: &[u8]) -> String {
    domain_hash(ENTRY_DIGEST_DOMAIN, bytes)
}

fn is_text(s: &str) -> bool {
    !s.is_empty()
        && s.len() <= MAX_TEXT
        && s.bytes().all(|b| (0x21..0x7f).contains(&b) || b == b' ')
}

impl EntryReport {
    pub fn validate(&self) -> Result<(), Refusal> {
        if self.format != ENTRY_FORMAT {
            return Err(invalid("entry report: unsupported format"));
        }
        if !is_label(&self.site) || !is_label(&self.station) || !is_label(&self.programme) {
            return Err(invalid("entry report: bad site, station or programme"));
        }
        if self.bundle_seq == 0
            || self.bundle_seq > MAX_SAFE_INTEGER
            || !is_hex64(&self.bundle_hash)
        {
            return Err(invalid("entry report: bad bundle_seq or bundle_hash"));
        }
        if self.scanned_at > MAX_SAFE_INTEGER
            || self.expires_at > MAX_SAFE_INTEGER
            || self.scanned_at >= self.expires_at
            || self.expires_at - self.scanned_at > MAX_REPORT_LIFETIME_S
        {
            return Err(invalid(format!(
                "entry report: need scanned_at < expires_at, at most {MAX_REPORT_LIFETIME_S} s apart"
            )));
        }
        if let Some(v) = &self.vulndb {
            if !is_label(&v.name) || v.version > MAX_SAFE_INTEGER || !is_hex64(&v.sha256) {
                return Err(invalid("entry report: bad vulndb"));
            }
        }
        if self.rpks.is_empty() || self.rpks.len() > crate::deployment::MAX_ITEMS * 16 {
            return Err(invalid("entry report: bad rpks"));
        }
        strictly_sorted(&self.rpks, |r| r.digest.clone(), "rpks (by digest)")?;
        for r in &self.rpks {
            if !is_hex64(&r.digest)
                || !is_pkg_name(&r.name)
                || r.serial == 0
                || r.serial > MAX_SAFE_INTEGER
            {
                return Err(invalid("entry report: bad rpk entry"));
            }
            if let Some(s) = &r.sbom {
                if !is_hex64(&s.sha256)
                    || s.components > MAX_SAFE_INTEGER
                    || s.previous_serial
                        .is_some_and(|p| p == 0 || p >= r.serial || p > MAX_SAFE_INTEGER)
                {
                    return Err(invalid("entry report: bad sbom summary"));
                }
                for l in [&s.added, &s.removed, &s.licence_changes] {
                    if l.len() > MAX_COMPONENT_LIST || !l.iter().all(|x| is_text(x)) {
                        return Err(invalid("entry report: bad sbom diff list"));
                    }
                    strictly_sorted(l, |x| x.clone(), "sbom diff list")?;
                }
            }
            if r.vulnerabilities.len() > MAX_VULNS
                || !r
                    .vulnerabilities
                    .iter()
                    .all(|v| is_text(&v.id) && is_text(&v.component))
            {
                return Err(invalid("entry report: bad vulnerabilities"));
            }
            strictly_sorted(
                &r.vulnerabilities,
                |v| (v.id.clone(), v.component.clone()),
                "vulnerabilities (by id, component)",
            )?;
        }
        Ok(())
    }

    /// The highest severity listed.
    pub fn worst(&self) -> Option<Severity> {
        self.rpks
            .iter()
            .flat_map(|r| r.vulnerabilities.iter().map(|v| v.severity))
            .max()
    }
}

/// Parse and validate report bytes (no signature check).
pub fn parse_entry_report(bytes: &[u8]) -> Result<EntryReport, Refusal> {
    let r: EntryReport = parse_canonical(bytes, MAX_ENTRY_BYTES, "entry report")?;
    r.validate()?;
    Ok(r)
}

/// A report that passed [`verify_entry_report`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerifiedEntryReport {
    pub report: EntryReport,
    pub digest: String,
    pub signers: Signers,
}

/// Verify an entry report for the authenticated `bundle` at `now`: site,
/// entry-key signature, bundle binding, freshness, verdict.
pub fn verify_entry_report(
    bytes: &[u8],
    sigset: &[u8],
    trust: &VerifiedTrust,
    bundle: &VerifiedBundle,
    now: u64,
) -> Result<VerifiedEntryReport, Refusal> {
    let r = parse_entry_report(bytes)?;
    if r.site != trust.file().site {
        return Err(Refusal::new(
            Code::WrongScope,
            format!(
                "entry report for site {}, this is {}",
                r.site,
                trust.file().site
            ),
        ));
    }
    let set = SignatureSet::parse(sigset)?;
    let signers = set.check(trust, &[Role::Entry], ENTRY_SIG_DOMAIN, bytes)?;
    signers.require(Role::Entry, 1, "entry report")?;
    let m = &bundle.manifest;
    if r.programme != m.programme {
        return Err(Refusal::new(
            Code::WrongScope,
            format!(
                "entry report for programme {}, the bundle is {}",
                r.programme, m.programme
            ),
        ));
    }
    if r.bundle_seq != m.bundle_seq || r.bundle_hash != bundle.hash {
        return Err(Refusal::new(
            Code::DigestMismatch,
            format!(
                "entry report is for bundle {} {}, not this bundle {} {}",
                r.bundle_seq,
                crate::common::trunc(&r.bundle_hash),
                m.bundle_seq,
                bundle.hash
            ),
        ));
    }
    let mut want: Vec<(&str, &str, u64)> = m
        .rpks
        .iter()
        .map(|x| (x.digest.as_str(), x.name.as_str(), x.serial))
        .collect();
    want.sort();
    let got: Vec<(&str, &str, u64)> = r
        .rpks
        .iter()
        .map(|x| (x.digest.as_str(), x.name.as_str(), x.serial))
        .collect();
    if want != got {
        return Err(Refusal::new(
            Code::DigestMismatch,
            "entry report does not list exactly the bundle's RPKs",
        ));
    }
    if now < r.scanned_at {
        return Err(Refusal::new(
            Code::NotYetValid,
            "entry report: scanned in the future",
        ));
    }
    if now >= r.expires_at {
        return Err(Refusal::new(
            Code::Expired,
            "entry report: expired (scan again against a current vulnerability database)",
        ));
    }
    if r.verdict != Verdict::Pass {
        return Err(Refusal::new(
            Code::ScanFailed,
            format!(
                "entry station {} failed the bundle (worst: {})",
                r.station,
                r.worst().map_or("none", Severity::as_str)
            ),
        ));
    }
    if r.worst().is_some_and(|w| w >= r.fail_on) {
        return Err(Refusal::new(
            Code::ScanFailed,
            "entry report says pass but lists a vulnerability at or above its fail_on",
        ));
    }
    Ok(VerifiedEntryReport {
        digest: entry_digest(bytes),
        report: r,
        signers,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::bundle::{BundleManifest, BundleRpk, BUNDLE_FORMAT};
    use crate::common::to_canonical;
    use crate::rpk::Arch;
    use crate::trust::test_support::{base, key, sign, tk, verified};

    const NOW: u64 = 1_790_000_500;

    fn bundle() -> VerifiedBundle {
        VerifiedBundle {
            manifest: BundleManifest {
                format: BUNDLE_FORMAT.into(),
                programme: "ugv-x1".into(),
                bundle_seq: 4,
                prev_bundle_hash: Some("cd".repeat(32)),
                created_at: NOW - 100,
                rpks: vec![BundleRpk {
                    dir: "rpk_nav-stack_7_arm64".into(),
                    name: "nav-stack".into(),
                    serial: 7,
                    arch: Arch::Arm64,
                    digest: "ab".repeat(32),
                }],
                files: vec![],
                parity: None,
            },
            hash: "ef".repeat(32),
            signers: Signers::default(),
        }
    }

    fn report() -> EntryReport {
        EntryReport {
            format: ENTRY_FORMAT.into(),
            site: "site-a".into(),
            station: "entry-1".into(),
            programme: "ugv-x1".into(),
            bundle_seq: 4,
            bundle_hash: "ef".repeat(32),
            scanned_at: NOW - 60,
            expires_at: NOW + 86400,
            vulndb: Some(VulnDbRef {
                name: "site-vulndb".into(),
                version: 3,
                sha256: "01".repeat(32),
            }),
            rpks: vec![RpkScan {
                digest: "ab".repeat(32),
                name: "nav-stack".into(),
                serial: 7,
                sbom: None,
                vulnerabilities: vec![Vuln {
                    id: "CVE-2026-0001".into(),
                    component: "libfoo@1.2".into(),
                    severity: Severity::Medium,
                }],
            }],
            fail_on: Severity::High,
            verdict: Verdict::Pass,
        }
    }

    fn trust() -> VerifiedTrust {
        let mut t = base();
        t.entry_keys = vec![tk(&key("entry-1", 41))];
        verified(&t)
    }

    #[test]
    fn a_signed_passing_report_for_the_bundle_verifies() {
        let t = trust();
        let b = to_canonical(&report()).unwrap();
        let s = sign(&b, ENTRY_SIG_DOMAIN, &[&key("entry-1", 41)]);
        verify_entry_report(&b, &s, &t, &bundle(), NOW).unwrap();
    }

    #[test]
    fn forged_relabelled_and_stale_reports_are_refused() {
        let t = trust();
        let entry = key("entry-1", 41);
        let check = |r: &EntryReport, by: &robodr_blackbox::Ed25519SigningKey| {
            let b = to_canonical(r).unwrap();
            let s = sign(&b, ENTRY_SIG_DOMAIN, &[by]);
            verify_entry_report(&b, &s, &t, &bundle(), NOW)
                .unwrap_err()
                .code
        };
        // Signed by a depot or an operator key: wrong role.
        assert_eq!(check(&report(), &key("depot-1", 21)), Code::WrongRole);
        assert_eq!(check(&report(), &key("op-1", 31)), Code::WrongRole);
        // An unlisted station key.
        assert_eq!(check(&report(), &key("entry-9", 49)), Code::UnknownKey);
        // Another bundle (replay of a report for bundle 3, or another hash).
        let mut r = report();
        r.bundle_seq = 3;
        assert_eq!(check(&r, &entry), Code::DigestMismatch);
        let mut r = report();
        r.bundle_hash = "00".repeat(32);
        assert_eq!(check(&r, &entry), Code::DigestMismatch);
        // An RPK list that is not the bundle's.
        let mut r = report();
        r.rpks[0].serial = 6;
        assert_eq!(check(&r, &entry), Code::DigestMismatch);
        // Another programme or site.
        let mut r = report();
        r.programme = "ugv-y2".into();
        assert_eq!(check(&r, &entry), Code::WrongScope);
        let mut r = report();
        r.site = "site-b".into();
        assert_eq!(check(&r, &entry), Code::WrongScope);
        // Failed, or a pass contradicted by its own content.
        let mut r = report();
        r.verdict = Verdict::Fail;
        assert_eq!(check(&r, &entry), Code::ScanFailed);
        let mut r = report();
        r.rpks[0].vulnerabilities[0].severity = Severity::Critical;
        assert_eq!(check(&r, &entry), Code::ScanFailed);
        // Expired, future, too long-lived.
        let mut r = report();
        r.expires_at = NOW;
        assert_eq!(check(&r, &entry), Code::Expired);
        let mut r = report();
        r.scanned_at = NOW + 10;
        r.expires_at = NOW + 100;
        assert_eq!(check(&r, &entry), Code::NotYetValid);
        let mut r = report();
        r.expires_at = r.scanned_at + MAX_REPORT_LIFETIME_S + 1;
        assert_eq!(check(&r, &entry), Code::Invalid);
        // A byte changed after signing.
        let b = to_canonical(&report()).unwrap();
        let s = sign(&b, ENTRY_SIG_DOMAIN, &[&entry]);
        let mut b2 = b.clone();
        let i = b2.iter().position(|&c| c == b'7').unwrap();
        b2[i] = b'8';
        assert!(verify_entry_report(&b2, &s, &t, &bundle(), NOW).is_err());
        // Another domain's signature (a deployment signature).
        let s = sign(&b, crate::deployment::DEPLOYMENT_SIG_DOMAIN, &[&entry]);
        assert_eq!(
            verify_entry_report(&b, &s, &t, &bundle(), NOW)
                .unwrap_err()
                .code,
            Code::BadSignature
        );
    }

    #[test]
    fn an_entry_key_cannot_sign_deployments() {
        let t = trust();
        let d = crate::deployment::test_support::deployment("lab");
        let b = to_canonical(&d).unwrap();
        let s = sign(
            &b,
            crate::deployment::DEPLOYMENT_SIG_DOMAIN,
            &[&key("entry-1", 41), &key("op-1", 31)],
        );
        assert_eq!(
            crate::deployment::verify_deployment(&b, &s, &t, 1_790_000_100)
                .unwrap_err()
                .code,
            Code::WrongRole
        );
    }

    #[test]
    fn non_canonical_and_unsorted_reports_are_refused() {
        let mut r = report();
        r.rpks[0].vulnerabilities.push(Vuln {
            id: "CVE-2025-0001".into(),
            component: "x".into(),
            severity: Severity::Low,
        });
        assert_eq!(
            parse_entry_report(&to_canonical(&r).unwrap())
                .unwrap_err()
                .code,
            Code::Invalid
        );
        let mut b = to_canonical(&report()).unwrap();
        b.push(b'\n');
        assert_eq!(parse_entry_report(&b).unwrap_err().code, Code::NonCanonical);
    }
}
