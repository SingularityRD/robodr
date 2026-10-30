//! Site leases (`docs/SECURE-DELIVERY.md` §7.5, Sprint 14b), enforced by
//! the unit's TPM.
//!
//! A unit enrolled with a lease key (`robodr-seal enroll --lease-key`)
//! has a UWK whose authPolicy is
//! [`crate::policy::uwk_auth_policy_lease`]: `PolicyAuthorize(lease key,
//! H(unit))` then the erase epoch. A **lease** is the depot's ECDSA P-256
//! signature (by that lease key) over the `aHash` of
//! [`crate::policy::lease_approved`]: the unit's 13c authority chain (its
//! signed PCR policy, floor and authority are still required) followed by
//! `TPM clock < clock_before` and `resetCount <= resets_max`. The TPM
//! checks all of it on every unwrap; the unit's own pre-check
//! ([`Lease::check_now`]) only gives a clean refusal
//! ([`crate::ErrorKind::LeaseExpired`], finding `robot.seal.lease_expired`)
//! before the TPM is asked.
//!
//! What this gives against a captured unit (T5, T6): once its TPM clock
//! passes `clock_before`, or it has been reset (rebooted) more often than
//! `resets_max`, nothing sealed to it unseals, whatever is written on its
//! disk: the TPM clock never goes back (`TPM2_ClockSet` only moves it
//! forward) and the lease cannot be extended without the depot's key.
//! **The TPM clock counts time the TPM is powered**, not wall time: a unit
//! kept powered off does not use up its lease (the reset budget bounds how
//! often it can be booted instead). The unit's wall clock is not used at
//! all (it can be set back).
//!
//! Document `robodr-lease/1` (canonical JSON, the `robodr-pkg` rules):
//! `{format, site, unit, lease_seq, issued_at, clock_before, resets_max,
//! signature}`. Only `unit`, `clock_before` and `resets_max` are bound by
//! the TPM (through the approved policy and the lease policyRef); `site`,
//! `lease_seq` and `issued_at` are informational. Replaying an older lease
//! gives nothing (its limits are lower); a lease of another unit fails
//! the policyRef; any edit fails the signature.
//!
//! **What the lease key can do.** It is the last `PolicyAuthorize` in the
//! chain, so it approves the whole policy before it: a holder of the lease
//! key could approve a policy without the PCR check for a unit in its
//! hands. The key is therefore as sensitive as the depot's wrapping key
//! (whose holder can already decrypt every sealed RPK of the site) and
//! lives with it (§5.1).

use crate::policy::{authorization_digest, lease_approved, lease_ref};
use crate::{invalid, SealError};
use robodr_pkg::common::{is_label, parse_canonical, to_canonical};
use serde::{Deserialize, Serialize};

pub const LEASE_FORMAT: &str = "robodr-lease/1";
pub const MAX_LEASE_BYTES: usize = 4096;
/// Longest lease (powered-on time): 366 days.
pub const MAX_LEASE_MS: u64 = 366 * 24 * 3600 * 1000;

/// A lease token.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Lease {
    pub format: String,
    pub site: String,
    pub unit: String,
    pub lease_seq: u64,
    pub issued_at: u64,
    /// TPM clock (ms) the lease ends at (exclusive).
    pub clock_before: u64,
    /// Highest TPM reset count (boots) the lease allows.
    pub resets_max: u32,
    /// DER ECDSA P-256 over the `aHash`, hex.
    pub signature: String,
}

/// The TPM's time: `tpm2_readclock`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct TpmTime {
    pub clock: u64,
    pub reset_count: u32,
    pub restart_count: u32,
    pub safe: bool,
}

impl Lease {
    pub fn parse(b: &[u8]) -> Result<Self, SealError> {
        let l: Lease =
            parse_canonical(b, MAX_LEASE_BYTES, "lease").map_err(|e| invalid(e.to_string()))?;
        if l.format != LEASE_FORMAT
            || !is_label(&l.site)
            || !is_label(&l.unit)
            || l.lease_seq == 0
            || l.lease_seq > robodr_pkg::MAX_SAFE_INTEGER
            || l.issued_at > robodr_pkg::MAX_SAFE_INTEGER
            || l.clock_before > robodr_pkg::MAX_SAFE_INTEGER
            || l.signature.is_empty()
            || l.signature.len() > 2 * 80
            || crate::from_hex(&l.signature).is_none()
        {
            return Err(invalid("lease: malformed"));
        }
        Ok(l)
    }

    pub fn to_bytes(&self) -> Result<Vec<u8>, SealError> {
        to_canonical(self).map_err(|e| invalid(e.to_string()))
    }

    /// The approved policy this lease authorizes for a unit of
    /// `platform` whose policy authority has TPM name `authority_name`.
    pub fn approved(&self, authority_name: &[u8], platform: &str) -> [u8; 32] {
        lease_approved(authority_name, platform, self.clock_before, self.resets_max)
    }

    /// The `aHash` the lease key signs.
    pub fn ahash(&self, authority_name: &[u8], platform: &str) -> [u8; 32] {
        authorization_digest(
            &self.approved(authority_name, platform),
            &lease_ref(&self.unit),
        )
    }

    /// Check the signature with the enrolled lease key and the unit.
    pub fn verify(
        &self,
        lease_key: &[u8; 65],
        unit: &str,
        authority_name: &[u8],
        platform: &str,
    ) -> Result<(), SealError> {
        if self.unit != unit {
            return Err(crate::unauthentic(format!(
                "lease for unit {}, this is {unit}",
                self.unit
            )));
        }
        let der = crate::from_hex(&self.signature).ok_or_else(|| invalid("lease signature"))?;
        crate::keys::policy_verify(lease_key, &self.ahash(authority_name, platform), &der)
            .map_err(|_| crate::unauthentic("lease: not signed by the enrolled lease key"))
    }

    /// Whether the TPM's time is inside the lease.
    pub fn check_now(&self, t: &TpmTime) -> Result<(), SealError> {
        if t.clock >= self.clock_before {
            return Err(SealError::new(
                crate::ErrorKind::LeaseExpired,
                format!(
                    "site lease {} expired: TPM clock {} ms >= {} ms",
                    self.lease_seq, t.clock, self.clock_before
                ),
            ));
        }
        if t.reset_count > self.resets_max {
            return Err(SealError::new(
                crate::ErrorKind::LeaseExpired,
                format!(
                    "site lease {} used up: the TPM was reset {} times, the lease allows {}",
                    self.lease_seq, t.reset_count, self.resets_max
                ),
            ));
        }
        Ok(())
    }
}

/// What the depot needs to issue a lease, and its parameters.
#[derive(Debug, Clone)]
pub struct LeaseGrant<'a> {
    pub site: &'a str,
    pub unit: &'a str,
    pub platform: &'a str,
    /// TPM name of the unit's policy authority (from its enrolment).
    pub authority_name: &'a [u8],
    pub lease_seq: u64,
    pub issued_at: u64,
    /// The unit's TPM time as it reported it.
    pub now: TpmTime,
    pub lifetime_ms: u64,
    /// Boots allowed after `now`.
    pub reboots: u32,
}

/// Issue a lease (depot side) with the lease key.
pub fn issue(g: &LeaseGrant<'_>, key: &crate::keys::PolicyKey) -> Result<Lease, SealError> {
    if g.lifetime_ms == 0 || g.lifetime_ms > MAX_LEASE_MS {
        return Err(invalid("lease lifetime must be in (0, 366 days]"));
    }
    let clock_before = g
        .now
        .clock
        .checked_add(g.lifetime_ms)
        .filter(|c| *c <= robodr_pkg::MAX_SAFE_INTEGER)
        .ok_or_else(|| invalid("lease: clock out of range"))?;
    let mut l = Lease {
        format: LEASE_FORMAT.into(),
        site: g.site.into(),
        unit: g.unit.into(),
        lease_seq: g.lease_seq,
        issued_at: g.issued_at,
        clock_before,
        resets_max: g.now.reset_count.saturating_add(g.reboots),
        signature: String::new(),
    };
    let sig = key.sign_digest(&l.ahash(g.authority_name, g.platform))?;
    l.signature = crate::to_hex(&sig);
    Lease::parse(&l.to_bytes()?)?;
    Ok(l)
}

/// Parse `tpm2_readclock` output.
pub fn parse_readclock(text: &str) -> Option<TpmTime> {
    let mut clock = None;
    let mut reset = None;
    let mut restart = None;
    let mut safe = None;
    for l in text.lines() {
        let Some((k, v)) = l.trim().split_once(':') else {
            continue;
        };
        let v = v.trim();
        match k.trim() {
            "clock" => clock = v.parse().ok(),
            "reset_count" => reset = v.parse().ok(),
            "restart_count" => restart = v.parse().ok(),
            "safe" => {
                safe = match v {
                    "yes" | "1" => Some(true),
                    "no" | "0" => Some(false),
                    _ => None,
                }
            }
            _ => {}
        }
    }
    Some(TpmTime {
        clock: clock?,
        reset_count: reset?,
        restart_count: restart?,
        safe: safe?,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn issue_verify_and_check() {
        let k = crate::keys::PolicyKey::generate().unwrap();
        let name = [7u8; 34];
        let now = TpmTime {
            clock: 1000,
            reset_count: 3,
            restart_count: 0,
            safe: true,
        };
        let g = LeaseGrant {
            site: "site-a",
            unit: "ugv-07",
            platform: "ugv-x1",
            authority_name: &name,
            lease_seq: 1,
            issued_at: 1_790_000_000,
            now,
            lifetime_ms: 3_600_000,
            reboots: 2,
        };
        let l = issue(&g, &k).unwrap();
        let b = l.to_bytes().unwrap();
        let l2 = Lease::parse(&b).unwrap();
        l2.verify(&k.public(), "ugv-07", &name, "ugv-x1").unwrap();
        l2.check_now(&now).unwrap();
        // Another unit, platform or authority: the TPM's aHash differs.
        assert!(l2.verify(&k.public(), "ugv-08", &name, "ugv-x1").is_err());
        assert!(l2.verify(&k.public(), "ugv-07", &name, "ugv-x2").is_err());
        assert!(l2
            .verify(&k.public(), "ugv-07", &[8u8; 34], "ugv-x1")
            .is_err());
        // Extended by editing: signature no longer verifies.
        let mut ext = l2.clone();
        ext.clock_before += 1;
        assert!(ext.verify(&k.public(), "ugv-07", &name, "ugv-x1").is_err());
        let mut ext = l2.clone();
        ext.resets_max += 1;
        assert!(ext.verify(&k.public(), "ugv-07", &name, "ugv-x1").is_err());
        // Another key.
        let k2 = crate::keys::PolicyKey::generate().unwrap();
        assert!(l2.verify(&k2.public(), "ugv-07", &name, "ugv-x1").is_err());
        // Expiry by clock and by reboots.
        let late = TpmTime {
            clock: 1000 + 3_600_000,
            ..now
        };
        assert_eq!(
            l2.check_now(&late).unwrap_err().kind,
            crate::ErrorKind::LeaseExpired
        );
        let booted = TpmTime {
            reset_count: 6,
            ..now
        };
        assert!(l2.check_now(&booted).is_err());
        assert!(l2
            .check_now(&TpmTime {
                reset_count: 5,
                ..now
            })
            .is_ok());
    }

    #[test]
    fn readclock_parses() {
        let t = "time: 65101\nclock_info:\n  clock: 66572\n  reset_count: 2\n  restart_count: 0\n  safe: yes\n";
        assert_eq!(
            parse_readclock(t),
            Some(TpmTime {
                clock: 66572,
                reset_count: 2,
                restart_count: 0,
                safe: true
            })
        );
        assert_eq!(parse_readclock("clock: x"), None);
    }
}
