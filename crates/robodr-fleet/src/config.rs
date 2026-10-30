//! `robodr-enroll`'s configuration (`/etc/robodr/fleet.json`) and the few
//! facts it reads from agentd's configuration.
//!
//! ```json
//! {
//!   "format": "robodr-fleet-config/v1",
//!   "state_dir": "/var/lib/robodr/fleet",
//!   "agentd_config": "/etc/robodr/agentd.json",
//!   "soc": { "url": "https://soc.example.org/api", "ca_bundle": "/etc/robodr/uplink-ca.pem",
//!            "spki_sha256": [], "crl_files": [], "keys": ["/etc/robodr/fleet-soc.pub"],
//!            "approval_keys": ["/etc/robodr/fleet-approval.pub"] },
//!   "workspace": null,
//!   "keys": { "uplink": "/etc/robodr/keys/uplink.key",
//!             "finding": "/etc/robodr/keys/agentd-finding.key",
//!             "blackbox": "/etc/robodr/keys/agentd-blackbox.key" }
//! }
//! ```
//!
//! Every key is optional except `format`; the defaults are the values
//! above (`soc.url`, `soc.keys`, `soc.approval_keys` and `workspace` have
//! none). Unknown keys are refused. Paths must be absolute.
//!
//! `soc.crl_files`: CRLs (PEM or DER) of the CAs in `soc.ca_bundle`; a
//! revoked SOC server certificate is refused, and so is every server when
//! a CA has no CRL in them or its CRL is expired or unusable (fail closed,
//! `robodr_blackbox::crl`). OCSP is not used (air-gapped fleets).
//!
//! `soc.keys` are the SOC's online **fleet keys** (tokens, answers, ring
//! information); `soc.approval_keys` are its **approval keys**, the only
//! keys an observe -> enforce profile approval is accepted from. They are
//! distinct keys (a file in both lists, or one key id in both, is refused):
//! a compromised online fleet key must not be able to approve enforcement.
//!
//! From agentd's configuration (read as plain JSON, never executed or
//! validated beyond the members used): `robot.id`, `robot.site`,
//! `sensor.profile_path` and `sensor.profile_trust` (`trusted_keys`,
//! `trust_roots`, `revocation_list`, `revocation_policy`, `state_file`,
//! `expect_platform`, `expect_unit_id`). The fleet tool verifies profiles
//! and revocation lists with exactly the trust inputs agentd will use.

use robodr_commission::trust::RevocationPolicy;
use serde::Deserialize;
use std::path::{Path, PathBuf};

use crate::fsx;

pub const CONFIG_FORMAT: &str = "robodr-fleet-config/v1";
pub const DEFAULT_CONFIG: &str = "/etc/robodr/fleet.json";
const MAX_CONFIG_BYTES: u64 = 256 * 1024;

#[derive(Debug, Clone, Default, Deserialize)]
#[serde(deny_unknown_fields)]
struct SocJson {
    #[serde(default)]
    url: Option<String>,
    #[serde(default)]
    ca_bundle: Option<PathBuf>,
    #[serde(default)]
    spki_sha256: Vec<String>,
    #[serde(default)]
    crl_files: Vec<PathBuf>,
    #[serde(default)]
    keys: Vec<PathBuf>,
    #[serde(default)]
    approval_keys: Vec<PathBuf>,
}

#[derive(Debug, Clone, Default, Deserialize)]
#[serde(deny_unknown_fields)]
struct KeysJson {
    #[serde(default)]
    uplink: Option<PathBuf>,
    #[serde(default)]
    finding: Option<PathBuf>,
    #[serde(default)]
    blackbox: Option<PathBuf>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
struct ConfigJson {
    format: String,
    #[serde(default)]
    state_dir: Option<PathBuf>,
    #[serde(default)]
    agentd_config: Option<PathBuf>,
    #[serde(default)]
    soc: SocJson,
    #[serde(default)]
    workspace: Option<String>,
    #[serde(default)]
    keys: KeysJson,
}

/// The resolved configuration.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Config {
    pub state_dir: PathBuf,
    /// `None`: no agentd configuration (robot id / site / profile trust
    /// come from the token and the command line only).
    pub agentd_config: Option<PathBuf>,
    pub soc_url: Option<String>,
    pub ca_bundle: PathBuf,
    pub spki_sha256: Vec<String>,
    /// CRLs of the SOC server's CAs (empty: no revocation check).
    pub crl_files: Vec<PathBuf>,
    /// SOC fleet public keys (sign tokens, answers, ring info).
    pub soc_keys: Vec<PathBuf>,
    /// SOC approval public keys (sign profile approvals only; distinct
    /// from the fleet keys).
    pub approval_keys: Vec<PathBuf>,
    /// Expected workspace: a token for another workspace is refused.
    pub workspace: Option<String>,
    pub uplink_key: PathBuf,
    pub finding_key: PathBuf,
    pub blackbox_key: PathBuf,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            state_dir: "/var/lib/robodr/fleet".into(),
            agentd_config: Some("/etc/robodr/agentd.json".into()),
            soc_url: None,
            ca_bundle: "/etc/robodr/uplink-ca.pem".into(),
            spki_sha256: Vec::new(),
            crl_files: Vec::new(),
            soc_keys: Vec::new(),
            approval_keys: Vec::new(),
            workspace: None,
            uplink_key: "/etc/robodr/keys/uplink.key".into(),
            finding_key: "/etc/robodr/keys/agentd-finding.key".into(),
            blackbox_key: "/etc/robodr/keys/agentd-blackbox.key".into(),
        }
    }
}

impl Config {
    /// Parse a configuration text.
    pub fn parse(text: &str) -> Result<Self, String> {
        robodr_commission::profile_file::reject_duplicate_keys(text).map_err(|e| e.to_string())?;
        let j: ConfigJson = serde_json::from_str(text).map_err(|e| e.to_string())?;
        if j.format != CONFIG_FORMAT {
            return Err(format!("format {:?}, expected {CONFIG_FORMAT:?}", j.format));
        }
        let d = Self::default();
        let c = Self {
            state_dir: j.state_dir.unwrap_or(d.state_dir),
            agentd_config: j.agentd_config.or(d.agentd_config),
            soc_url: j.soc.url,
            ca_bundle: j.soc.ca_bundle.unwrap_or(d.ca_bundle),
            spki_sha256: j.soc.spki_sha256,
            crl_files: j.soc.crl_files,
            soc_keys: j.soc.keys,
            approval_keys: j.soc.approval_keys,
            workspace: j.workspace,
            uplink_key: j.keys.uplink.unwrap_or(d.uplink_key),
            finding_key: j.keys.finding.unwrap_or(d.finding_key),
            blackbox_key: j.keys.blackbox.unwrap_or(d.blackbox_key),
        };
        c.validate()?;
        Ok(c)
    }

    /// Load `path`; a missing file at the default location gives the
    /// defaults (a missing explicit `--config` is an error).
    pub fn load(path: &Path, explicit: bool) -> Result<Self, String> {
        match fsx::read_optional(path, MAX_CONFIG_BYTES) {
            Ok(Some(b)) => {
                let t =
                    String::from_utf8(b).map_err(|_| format!("{}: not UTF-8", path.display()))?;
                Self::parse(&t).map_err(|e| format!("{}: {e}", path.display()))
            }
            Ok(None) if !explicit => Ok(Self::default()),
            Ok(None) => Err(format!("{}: not found", path.display())),
            Err(e) => Err(format!("{}: {e}", path.display())),
        }
    }

    pub fn validate(&self) -> Result<(), String> {
        let mut paths: Vec<(&str, &Path)> = vec![
            ("state_dir", &self.state_dir),
            ("soc.ca_bundle", &self.ca_bundle),
            ("keys.uplink", &self.uplink_key),
            ("keys.finding", &self.finding_key),
            ("keys.blackbox", &self.blackbox_key),
        ];
        if let Some(a) = &self.agentd_config {
            paths.push(("agentd_config", a));
        }
        for k in &self.soc_keys {
            paths.push(("soc.keys[]", k));
        }
        for k in &self.approval_keys {
            paths.push(("soc.approval_keys[]", k));
        }
        for k in &self.crl_files {
            paths.push(("soc.crl_files[]", k));
        }
        for (what, p) in paths {
            if !p.is_absolute() {
                return Err(format!("{what} must be an absolute path"));
            }
        }
        if let Some(w) = &self.workspace {
            if !crate::wire::is_ident(w) {
                return Err("workspace must be [A-Za-z0-9._:-]{1,64}".into());
            }
        }
        if self.approval_keys.iter().any(|k| self.soc_keys.contains(k)) {
            return Err(
                "soc.approval_keys and soc.keys must be distinct files (an approval key is \
                 never the online fleet key)"
                    .into(),
            );
        }
        let keys = [&self.uplink_key, &self.finding_key, &self.blackbox_key];
        if keys[0] == keys[1] || keys[0] == keys[2] || keys[1] == keys[2] {
            return Err(
                "keys.uplink, keys.finding and keys.blackbox must be distinct files".into(),
            );
        }
        Ok(())
    }

    /// The key path of `role`.
    pub fn key_path(&self, role: &str) -> Option<&Path> {
        match role {
            "uplink" => Some(&self.uplink_key),
            "finding" => Some(&self.finding_key),
            "blackbox" => Some(&self.blackbox_key),
            _ => None,
        }
    }

    /// [`Config::key_path`] for a role that must be known (an error, never a
    /// panic, if a caller passes another).
    pub fn role_key_path(&self, role: &str) -> Result<&Path, String> {
        self.key_path(role)
            .ok_or_else(|| format!("unknown key role {role:?}"))
    }
}

/// What the fleet tool reads from agentd's configuration.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct AgentdFacts {
    pub robot_id: Option<String>,
    pub site: Option<String>,
    pub profile_path: Option<PathBuf>,
    pub trusted_keys: Option<PathBuf>,
    pub trust_roots: Option<PathBuf>,
    pub revocation_list: Option<PathBuf>,
    pub revocation_policy: RevocationPolicy,
    pub state_file: Option<PathBuf>,
    pub expect_platform: Option<String>,
    pub expect_unit_id: Option<String>,
}

impl AgentdFacts {
    /// Extract the facts from agentd's JSON configuration text.
    pub fn parse(text: &str) -> Result<Self, String> {
        let v: serde_json::Value = serde_json::from_str(text).map_err(|e| e.to_string())?;
        let s = |p: &[&str]| -> Result<Option<String>, String> {
            let mut cur = &v;
            for k in p {
                match cur.get(*k) {
                    Some(n) => cur = n,
                    None => return Ok(None),
                }
            }
            match cur {
                serde_json::Value::Null => Ok(None),
                serde_json::Value::String(x) => Ok(Some(x.clone())),
                _ => Err(format!("{} must be a string", p.join("."))),
            }
        };
        let path = |p: &[&str]| -> Result<Option<PathBuf>, String> {
            match s(p)? {
                None => Ok(None),
                Some(x) if Path::new(&x).is_absolute() => Ok(Some(PathBuf::from(x))),
                Some(_) => Err(format!("{} must be an absolute path", p.join("."))),
            }
        };
        let pt = ["sensor", "profile_trust"];
        let policy = match s(&[pt[0], pt[1], "revocation_policy"])?.as_deref() {
            None | Some("optional") => RevocationPolicy::Optional,
            Some("required") => RevocationPolicy::Required,
            Some(o) => return Err(format!("revocation_policy {o:?}")),
        };
        Ok(Self {
            robot_id: s(&["robot", "id"])?,
            site: s(&["robot", "site"])?,
            profile_path: path(&["sensor", "profile_path"])?,
            trusted_keys: path(&[pt[0], pt[1], "trusted_keys"])?,
            trust_roots: path(&[pt[0], pt[1], "trust_roots"])?,
            revocation_list: path(&[pt[0], pt[1], "revocation_list"])?,
            revocation_policy: policy,
            state_file: path(&[pt[0], pt[1], "state_file"])?,
            expect_platform: s(&[pt[0], pt[1], "expect_platform"])?,
            expect_unit_id: s(&[pt[0], pt[1], "expect_unit_id"])?,
        })
    }

    /// Load from `path` (`Ok(default)` when `path` is `None`).
    pub fn load(path: Option<&Path>) -> Result<Self, String> {
        let Some(p) = path else {
            return Ok(Self::default());
        };
        match fsx::read_optional(p, 4 * 1024 * 1024) {
            Ok(Some(b)) => {
                let t = String::from_utf8(b).map_err(|_| format!("{}: not UTF-8", p.display()))?;
                Self::parse(&t).map_err(|e| format!("{}: {e}", p.display()))
            }
            Ok(None) => Ok(Self::default()),
            Err(e) => Err(format!("{}: {e}", p.display())),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn defaults_and_strictness() {
        let c = Config::parse(r#"{"format":"robodr-fleet-config/v1"}"#).unwrap();
        assert_eq!(c, Config::default());
        assert!(Config::parse(r#"{"format":"robodr-fleet-config/v1","x":1}"#).is_err());
        assert!(Config::parse(r#"{"format":"robodr-fleet-config/v2"}"#).is_err());
        assert!(Config::parse(r#"{"format":"robodr-fleet-config/v1","state_dir":"rel"}"#).is_err());
        assert!(Config::parse(
            r#"{"format":"robodr-fleet-config/v1","keys":{"uplink":"/k","finding":"/k"}}"#
        )
        .is_err());
        let c = Config::parse(
            r#"{"format":"robodr-fleet-config/v1","soc":{"keys":["/f.pub"],"approval_keys":["/a.pub"]}}"#,
        )
        .unwrap();
        assert_eq!(c.approval_keys, [PathBuf::from("/a.pub")]);
        assert!(Config::parse(
            r#"{"format":"robodr-fleet-config/v1","soc":{"keys":["/f.pub"],"approval_keys":["/f.pub"]}}"#
        )
        .is_err());
    }

    #[test]
    fn shipped_example_parses() {
        let c = Config::parse(include_str!("../../../config/fleet.example.json")).unwrap();
        assert_eq!(c.soc_keys.len(), 1);
        assert_eq!(c.approval_keys.len(), 1);
    }

    #[test]
    fn agentd_facts() {
        let f = AgentdFacts::parse(
            r#"{"robot":{"id":"ugv-1","site":"lab"},"sensor":{"profile_path":"/etc/robodr/profile.json",
            "profile_trust":{"trusted_keys":"/t","revocation_policy":"required"}},"other":1}"#,
        )
        .unwrap();
        assert_eq!(f.robot_id.as_deref(), Some("ugv-1"));
        assert_eq!(f.revocation_policy, RevocationPolicy::Required);
        assert!(AgentdFacts::parse(r#"{"sensor":{"profile_path":"rel"}}"#).is_err());
    }
}
