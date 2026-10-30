//! The unit's signed install report (`robodr-unit-report/1`,
//! `docs/SECURE-DELIVERY.md` §3.4 "Unit ... signs install reports, health
//! results", §6.2, Sprint 14a): what became of the deployment the unit
//! works on, what is installed, and the TPM's time. Signed by the unit
//! identity key (UIK, TPM-resident, certified by the AK at enrolment), so
//! the depot judges a rollout on statements only that unit's TPM could
//! have signed, whether the report came over the LAN or on media.
//!
//! Envelope: `{"body": "<canonical JSON of the body>", "signature": "<DER
//! ECDSA P-256 hex>"}` over `SHA-256("robodr-unit-report/v1\0" || body)`.
//!
//! Replay: the depot keeps, per unit, the `(tpm_resets, tpm_clock)` of the
//! newest report it accepted and refuses one that is not newer (a TPM's
//! clock never goes back within a reset, its reset count never goes
//! back). A unit without a TPM reports zeros and is ordered by
//! `reported_at` (its own clock: weaker, as everything about such units).
//! The same report is also the unit's lease request (Sprint 14b): the
//! depot bases a lease on the TPM time in it.

use crate::{invalid, unauthentic, SealError};
use robodr_pkg::common::{is_hex64, is_label, is_pkg_name, parse_canonical, to_canonical};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

/// Signs a SHA-256 digest with the unit identity key (DER ECDSA).
pub type DigestSigner<'a> = dyn Fn(&[u8; 32]) -> Result<Vec<u8>, SealError> + 'a;

pub const REPORT_FORMAT: &str = "robodr-unit-report/1";
pub const REPORT_SIG_DOMAIN: &[u8] = b"robodr-unit-report/v1\0";
pub const MAX_REPORT_BYTES: usize = 256 * 1024;
pub const MAX_REPORT_ITEMS: usize = 1024;

/// What became of one item of the deployment.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ItemState {
    Pending,
    Installed,
    /// The health gate failed (rolled back, or blocked by the floor).
    Failed,
    Refused,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ReportItem {
    pub name: String,
    pub serial: u64,
    pub rpk_digest: String,
    pub status: ItemState,
    pub deferrals: u32,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct InstalledItem {
    pub name: String,
    pub serial: u64,
    pub rpk_digest: String,
    pub healthy: bool,
}

/// The report body (members in canonical order).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct UnitReport {
    pub format: String,
    pub site: String,
    pub unit: String,
    pub reported_at: u64,
    pub tpm_resets: u32,
    pub tpm_clock: u64,
    /// The deployment worked on (`null`: none accepted yet).
    pub deployment_id: Option<String>,
    pub deployment_seq: u64,
    pub deployment_digest: Option<String>,
    /// Sorted by name.
    pub items: Vec<ReportItem>,
    /// Sorted by name.
    pub installed: Vec<InstalledItem>,
    /// The unit's keys were crypto-erased.
    pub erased: bool,
    /// TPM units: an attestation by the unit's AK (a restricted key: it
    /// signs only TPM-generated structures) whose `extraData` is
    /// [`UnitReport::time_digest`] of this report and whose `clockInfo`
    /// the TPM filled in itself. The depot bases a lease on the TPM time
    /// only through it: `tpm_clock` and `tpm_resets` alone are whatever
    /// root on the unit had the identity key sign (14b review).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub time: Option<crate::enrol::SignedHex>,
}

/// Domain of [`UnitReport::time_digest`].
pub const REPORT_TIME_DOMAIN: &[u8] = b"robodr-unit-report-time/v1\0";

/// The signed envelope.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SignedReport {
    pub body: String,
    pub signature: String,
}

fn digest(body: &[u8]) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(REPORT_SIG_DOMAIN);
    h.update(body);
    h.finalize().into()
}

impl UnitReport {
    pub fn validate(&self) -> Result<(), SealError> {
        let max = robodr_pkg::MAX_SAFE_INTEGER;
        if self.format != REPORT_FORMAT
            || !is_label(&self.site)
            || !is_label(&self.unit)
            || self.reported_at > max
            || self.tpm_clock > max
            || self.deployment_seq > max
            || self.deployment_id.as_deref().is_some_and(|d| !is_label(d))
            || self
                .deployment_digest
                .as_deref()
                .is_some_and(|d| !is_hex64(d))
            || self.deployment_id.is_some() != self.deployment_digest.is_some()
            || (self.deployment_id.is_some() != (self.deployment_seq > 0))
        {
            return Err(invalid("unit report: header"));
        }
        if self.items.len() > MAX_REPORT_ITEMS || self.installed.len() > MAX_REPORT_ITEMS {
            return Err(invalid("unit report: too many items"));
        }
        let ok = |n: &str, s: u64, d: &str| is_pkg_name(n) && s > 0 && s <= max && is_hex64(d);
        if !self
            .items
            .iter()
            .all(|i| ok(&i.name, i.serial, &i.rpk_digest))
            || !self
                .installed
                .iter()
                .all(|i| ok(&i.name, i.serial, &i.rpk_digest))
        {
            return Err(invalid("unit report: bad item"));
        }
        for w in self.items.windows(2) {
            if w[0].name >= w[1].name {
                return Err(invalid("unit report: items not sorted by name"));
            }
        }
        for w in self.installed.windows(2) {
            if w[0].name >= w[1].name {
                return Err(invalid("unit report: installed not sorted by name"));
            }
        }
        Ok(())
    }

    /// What the TPM time attestation qualifies: SHA-256 of the domain and
    /// the canonical report without `time`.
    pub fn time_digest(&self) -> Result<[u8; 32], SealError> {
        let mut r = self.clone();
        r.time = None;
        let body = to_canonical(&r).map_err(|e| invalid(e.to_string()))?;
        let mut h = Sha256::new();
        h.update(REPORT_TIME_DOMAIN);
        h.update(&body);
        Ok(h.finalize().into())
    }

    /// Check the TPM time attestation against the unit's AK (TPM2B_PUBLIC
    /// bytes from its enrolment): signed by that AK, for this report, and
    /// with the reported reset count and a TPM clock at or after the
    /// reported one, at most `max_skew_ms` later. Returns the attested
    /// time.
    pub fn check_time(
        &self,
        ak_public: &[u8],
        max_skew_ms: u64,
    ) -> Result<crate::attest::Attest, SealError> {
        let t = self
            .time
            .as_ref()
            .ok_or_else(|| unauthentic("unit report: no TPM time attestation"))?;
        let ak = crate::attest::check_ak(&crate::attest::parse_tpm2b_public(ak_public)?)?;
        let attest = crate::from_hex(&t.attest).ok_or_else(|| invalid("time attest hex"))?;
        let sig = crate::from_hex(&t.sig).ok_or_else(|| invalid("time sig hex"))?;
        let a = crate::attest::verify_attest(&ak, &attest, &sig)?;
        if a.extra_data != self.time_digest()? {
            return Err(unauthentic(
                "unit report: the TPM time attestation is for another report",
            ));
        }
        if a.reset_count != self.tpm_resets
            || a.clock < self.tpm_clock
            || a.clock - self.tpm_clock > max_skew_ms
        {
            return Err(unauthentic(format!(
                "unit report: reported TPM time (resets {}, clock {}) differs from the attested \
                 time (resets {}, clock {})",
                self.tpm_resets, self.tpm_clock, a.reset_count, a.clock
            )));
        }
        Ok(a)
    }

    /// Sign with `sign` (the unit identity key over a SHA-256 digest).
    pub fn sign(&self, sign: &DigestSigner<'_>) -> Result<Vec<u8>, SealError> {
        self.validate()?;
        let body = to_canonical(self).map_err(|e| invalid(e.to_string()))?;
        let sig = sign(&digest(&body))?;
        let env = SignedReport {
            body: String::from_utf8(body).map_err(|_| invalid("body is not UTF-8"))?,
            signature: crate::to_hex(&sig),
        };
        serde_json::to_vec(&env).map_err(|e| invalid(e.to_string()))
    }
}

/// Parse a signed report without checking the signature (to find the
/// unit it claims to be from).
pub fn parse_unverified(b: &[u8]) -> Result<(UnitReport, SignedReport), SealError> {
    if b.len() > MAX_REPORT_BYTES {
        return Err(invalid("unit report: too large"));
    }
    let env: SignedReport =
        serde_json::from_slice(b).map_err(|e| invalid(format!("unit report: {e}")))?;
    let r: UnitReport = parse_canonical(env.body.as_bytes(), MAX_REPORT_BYTES, "unit report")
        .map_err(|e| invalid(e.to_string()))?;
    r.validate()?;
    Ok((r, env))
}

/// Verify a signed report with the unit's enrolled identity key.
pub fn verify(b: &[u8], identity: &[u8; 65]) -> Result<UnitReport, SealError> {
    let (r, env) = parse_unverified(b)?;
    let der = crate::from_hex(&env.signature).ok_or_else(|| invalid("signature hex"))?;
    crate::keys::policy_verify(identity, &digest(env.body.as_bytes()), &der)
        .map_err(|_| unauthentic("unit report: not signed by this unit's identity key"))?;
    Ok(r)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn report() -> UnitReport {
        UnitReport {
            format: REPORT_FORMAT.into(),
            site: "site-a".into(),
            unit: "ugv-07".into(),
            reported_at: 1_790_000_000,
            tpm_resets: 2,
            tpm_clock: 5000,
            deployment_id: Some("dep-0001".into()),
            deployment_seq: 1,
            deployment_digest: Some("ab".repeat(32)),
            items: vec![ReportItem {
                name: "nav-stack".into(),
                serial: 2,
                rpk_digest: "cd".repeat(32),
                status: ItemState::Installed,
                deferrals: 0,
            }],
            installed: vec![],
            erased: false,
            time: None,
        }
    }

    #[test]
    fn sign_and_verify() {
        let k = crate::keys::PolicyKey::generate().unwrap();
        let s = report().sign(&|d| k.sign_digest(d)).unwrap();
        assert_eq!(verify(&s, &k.public()).unwrap(), report());
        let k2 = crate::keys::PolicyKey::generate().unwrap();
        assert!(verify(&s, &k2.public()).is_err());
        // A status edited after signing.
        let t = String::from_utf8(s.clone())
            .unwrap()
            .replace("installed", "failed");
        assert!(verify(t.as_bytes(), &k.public()).is_err());
        let mut r = report();
        r.deployment_digest = None;
        assert!(r.sign(&|d| k.sign_digest(d)).is_err());
    }
}
