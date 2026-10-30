//! The depot's configuration (`robodr-depot-config/1`, JSON, unknown
//! members refused). Example: `config/depot.example.json`.

use crate::{err, DepotError};
use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};

pub const CONFIG_FORMAT: &str = "robodr-depot-config/1";

/// Key files (root-owned, `0600`; §5.1: in production in the depot's TPM
/// or an HSM, see `docs/OPERATIONS.md` §13).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct KeysCfg {
    /// Ed25519 (`robodr-blackbox-key/v2`): the depot role of the trust
    /// file; signs deployments.
    pub signing: PathBuf,
    /// X25519 (`robodr-seal keygen depot`): unwraps sealed content keys.
    pub wrap: PathBuf,
    /// P-256 (`robodr-seal keygen lease`): signs site leases (Sprint 14b);
    /// absent: units are enrolled without a lease.
    #[serde(default)]
    pub lease: Option<PathBuf>,
    /// P-256 (`robodr-seal keygen policy` format): the site unit CA.
    pub ca: PathBuf,
}

/// Enrolment policy.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EnrolCfg {
    /// The site's PCR policy authority public key (`FILE.pub`).
    pub policy_authority: PathBuf,
    /// TPM vendor EK CA certificates (PEM or DER files); each is used
    /// only if its SHA-256 is listed in the trust file's `ek_ca_certs`.
    pub ek_cas: PathBuf,
    /// Intermediate EK certificates (optional directory).
    #[serde(default)]
    pub ek_intermediates: Option<PathBuf>,
    /// Accept units without a TPM (unattested; §7.7). Default false.
    #[serde(default)]
    pub allow_without_tpm: bool,
    /// Lifetime of a unit's client certificate, days (default 365).
    #[serde(default = "d_cert_days")]
    pub cert_days: u64,
}

fn d_cert_days() -> u64 {
    365
}

/// Site lease policy (Sprint 14b).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LeaseCfg {
    /// Lease length in TPM time (the unit's powered-on time), seconds.
    pub lifetime_s: u64,
    /// Reboots a lease allows.
    pub reboots: u32,
}

/// LAN serving.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ServeCfg {
    pub listen: String,
    /// The DNS name in the depot's server certificate (what units verify).
    pub server_name: String,
    #[serde(default = "d_conns")]
    pub max_connections: usize,
    /// Most connections open at once from one source address (before or
    /// after authenticating): one host cannot take every slot.
    #[serde(default = "d_conns_per_source")]
    pub max_connections_per_source: usize,
    /// Per-connection deadline, seconds.
    #[serde(default = "d_deadline")]
    pub deadline_s: u64,
}

fn d_conns() -> usize {
    16
}
fn d_conns_per_source() -> usize {
    4
}
fn d_deadline() -> u64 {
    600
}

/// The database anchor (Sprint 14b): an NV counter of the depot's TPM.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AnchorCfg {
    pub tcti: String,
    /// NV counter index (`0x01NNNNNN`).
    pub index: String,
    /// tmpfs directory for TPM session contexts.
    #[serde(default = "d_work")]
    pub work_dir: PathBuf,
    #[serde(default = "d_tools")]
    pub tools_dir: PathBuf,
}

fn d_work() -> PathBuf {
    PathBuf::from("/run/robodr-depot")
}
fn d_tools() -> PathBuf {
    PathBuf::from("/usr/bin")
}

/// The configuration.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Config {
    pub format: String,
    pub site: String,
    /// This depot's name (the `robot` of its findings).
    pub depot_id: String,
    /// Pinned delivery root fingerprints (`sha256:<hex>`).
    pub roots: Vec<String>,
    pub state_dir: PathBuf,
    pub keys: KeysCfg,
    pub enrolment: EnrolCfg,
    #[serde(default)]
    pub lease: Option<LeaseCfg>,
    #[serde(default)]
    pub serve: Option<ServeCfg>,
    #[serde(default)]
    pub anchor: Option<AnchorCfg>,
    /// Findings into the site agentd's spool (optional).
    #[serde(default)]
    pub findings: Option<robodr_deliverd::config::FindingsCfg>,
}

impl Config {
    pub fn parse(b: &[u8]) -> Result<Self, DepotError> {
        if b.len() > 256 * 1024 {
            return Err(err("config: too large"));
        }
        let c: Config = serde_json::from_slice(b).map_err(|e| err(format!("config: {e}")))?;
        c.validate()?;
        Ok(c)
    }

    pub fn load(p: &Path) -> Result<Self, DepotError> {
        let b = std::fs::read(p).map_err(|e| err(format!("{}: {e}", p.display())))?;
        Self::parse(&b)
    }

    pub fn validate(&self) -> Result<(), DepotError> {
        use robodr_pkg::common::{is_fingerprint, is_label};
        if self.format != CONFIG_FORMAT {
            return Err(err("config: unsupported format"));
        }
        if !is_label(&self.site) || !is_label(&self.depot_id) {
            return Err(err("config: site and depot_id must be labels"));
        }
        if self.roots.is_empty() || !self.roots.iter().all(|r| is_fingerprint(r)) {
            return Err(err("config: roots must be sha256:<64 hex> fingerprints"));
        }
        for p in [
            &self.state_dir,
            &self.keys.signing,
            &self.keys.wrap,
            &self.keys.ca,
            &self.enrolment.policy_authority,
            &self.enrolment.ek_cas,
        ] {
            if !p.is_absolute() {
                return Err(err(format!("config: {} must be absolute", p.display())));
            }
        }
        if self.enrolment.cert_days == 0 || self.enrolment.cert_days > 3660 {
            return Err(err("config: enrolment.cert_days in 1..=3660"));
        }
        if let Some(l) = &self.lease {
            if self.keys.lease.is_none() {
                return Err(err("config: lease needs keys.lease"));
            }
            let ms = l.lifetime_s.checked_mul(1000);
            if l.lifetime_s == 0 || ms.is_none_or(|ms| ms > robodr_seal::lease::MAX_LEASE_MS) {
                return Err(err("config: lease.lifetime_s in 1..=366 days"));
            }
        }
        if let Some(s) = &self.serve {
            if s.max_connections == 0
                || s.max_connections > 1024
                || s.max_connections_per_source == 0
                || s.max_connections_per_source > 1024
                || s.deadline_s == 0
            {
                return Err(err(
                    "config: serve.max_connections and max_connections_per_source 1..=1024, \
                     deadline_s > 0",
                ));
            }
            robodr_blackbox::tls::server_name(&s.server_name)
                .map_err(|e| err(format!("config: serve.server_name: {e}")))?;
        }
        if let Some(a) = &self.anchor {
            robodr_seal::unit::parse_handle(&a.index, 0x01)
                .map_err(|e| err(format!("config: anchor.index: {e}")))?;
        }
        Ok(())
    }

    pub fn anchor_path(&self) -> PathBuf {
        self.state_dir.join("trust").join("anchor.json")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The shipped example parses and names the packaged paths.
    #[test]
    fn example_parses() {
        let c = Config::parse(include_bytes!("../../../config/depot.example.json")).unwrap();
        assert_eq!(c.state_dir, Path::new("/var/lib/robodr/depot"));
        assert!(c.keys.signing.starts_with("/etc/robodr-depot/keys"));
        assert_eq!(
            c.anchor.as_ref().map(|a| a.work_dir.clone()),
            Some(PathBuf::from("/run/robodr-depot"))
        );
    }

    #[test]
    fn refuses_bad_values() {
        let base: serde_json::Value =
            serde_json::from_slice(include_bytes!("../../../config/depot.example.json")).unwrap();
        let bad = |f: &dyn Fn(&mut serde_json::Value)| {
            let mut v = base.clone();
            f(&mut v);
            Config::parse(&serde_json::to_vec(&v).unwrap()).unwrap_err()
        };
        bad(&|v| v["lease"]["lifetime_s"] = u64::MAX.into());
        bad(&|v| v["lease"]["lifetime_s"] = 0.into());
        bad(&|v| v["keys"]["lease"] = serde_json::Value::Null);
        bad(&|v| v["state_dir"] = "var/lib/robodr/depot".into());
        bad(&|v| v["roots"] = serde_json::json!([]));
        bad(&|v| v["anchor"]["index"] = "0x81000001".into());
        bad(&|v| v["serve"]["max_connections"] = 0.into());
        bad(&|v| v["serve"]["max_connections_per_source"] = 0.into());
        bad(&|v| v["unknown"] = 1.into());
        bad(&|v| v["format"] = "robodr-depot-config/2".into());
    }
}
