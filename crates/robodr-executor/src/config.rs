//! The executor's own configuration (`/etc/robodr/executor.json`, schema
//! `robodr-executor-config/v1`, strict JSON: unknown fields refuse the
//! file).
//!
//! The executor never trusts agentd for anything it can know itself: the
//! robot's morphology and `fall_safe_restrict` come from the **response
//! policy file** (`policy_path`, the same root-owned file agentd reads), and
//! the management / uplink allow-list and the motion control path come from
//! this file. agentd only names the action, its target and the situation it
//! judged the request in.
//!
//! ```json
//! {
//!   "schema": "robodr-executor-config/v1",
//!   "robot_id": "ugv-007",
//!   "socket": "/run/robodr-executor/executor.sock",
//!   "key_file": "/run/credentials/robodr-executor.service/executor.key",
//!   "state_dir": "/var/lib/robodr/executor",
//!   "policy_path": "/etc/robodr/response-policy.json",
//!   "network": {
//!     "management": [{"cidr": "10.20.0.0/24", "proto": "tcp", "port": 443}],
//!     "uplink": [{"cidr": "10.20.0.10"}],
//!     "control_buses": {"exempt": true, "entries": [{"interface": "eth1"}]},
//!     "motion_control_path": [
//!       {"cidr": "192.168.123.0/24", "udp_ports": [7400, 7600], "note": "DDS on the robot bus"}
//!     ]
//!   },
//!   "ttl": {"default_s": 900, "max_s": 86400}
//! }
//! ```

use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

use crate::net::{GuidPrefix, Iface, IpNet, PortRange, Proto};

pub const SCHEMA: &str = "robodr-executor-config/v1";
/// Longest TTL any action may have (24 h, the control plane's limit).
pub const MAX_TTL_S: u64 = 86_400;
/// Most entries per allow / protect list (each becomes a few rules).
pub const MAX_ENTRIES: usize = 64;
/// Largest configuration or policy file.
pub const MAX_FILE_BYTES: u64 = 1 << 20;

fn default_nft() -> PathBuf {
    PathBuf::from("/usr/sbin/nft")
}
fn default_socket_mode() -> String {
    "0660".into()
}
fn default_ttl_s() -> u64 {
    900
}
fn default_max_ttl_s() -> u64 {
    MAX_TTL_S
}
fn default_safety_age_ms() -> u64 {
    500
}
fn default_verify_s() -> u64 {
    10
}
fn default_true() -> bool {
    true
}

/// The file as written.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ExecutorConfig {
    pub schema: String,
    pub robot_id: String,
    /// Unix socket agentd talks to (absolute path).
    pub socket: PathBuf,
    /// `"0660"` (default: agentd connects through the shared group) or
    /// `"0600"`.
    #[serde(default = "default_socket_mode")]
    pub socket_mode: String,
    /// 32-byte shared HMAC key, 64 hex digits (`robodr-executor keygen`).
    pub key_file: PathBuf,
    /// Journal directory (absolute; the unit's only writable path).
    pub state_dir: PathBuf,
    /// The response policy: the robot's morphology and `fall_safe_restrict`.
    pub policy_path: PathBuf,
    /// The `nft` binary (absolute). Default `/usr/sbin/nft`.
    #[serde(default = "default_nft")]
    pub nft: PathBuf,
    pub network: NetworkSection,
    #[serde(default)]
    pub ttl: TtlSection,
    /// Oldest safety state accepted at the moment of apply (ms).
    #[serde(default = "default_safety_age_ms")]
    pub max_safety_age_ms: u64,
    /// How often the installed rules are read back and compared (s).
    #[serde(default = "default_verify_s")]
    pub verify_interval_s: u64,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TtlSection {
    /// TTL of an action that names none (s).
    #[serde(default = "default_ttl_s")]
    pub default_s: u64,
    /// Longest TTL accepted (s, at most 86400).
    #[serde(default = "default_max_ttl_s")]
    pub max_s: u64,
}

impl Default for TtlSection {
    fn default() -> Self {
        Self {
            default_s: default_ttl_s(),
            max_s: default_max_ttl_s(),
        }
    }
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NetworkSection {
    /// The management channel: never cut by `isolate_network`. Required
    /// (non-empty) for `isolate_network` to be executable at all.
    #[serde(default)]
    pub management: Vec<AllowEntry>,
    /// The findings uplink / SOC: never cut.
    #[serde(default)]
    pub uplink: Vec<AllowEntry>,
    #[serde(default)]
    pub control_buses: ControlBuses,
    /// The robot's motion control path: never cut by `isolate_network`,
    /// never matched by `quarantine_node`, unless the response policy lists
    /// the target in `fall_safe_restrict` (a humanoid whose OEM declared it
    /// balance-safe) and the entry is not `low_level`.
    #[serde(default)]
    pub motion_control_path: Vec<ProtectedEntry>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ControlBuses {
    /// Keep the robot's own control buses open during isolation (default).
    #[serde(default = "default_true")]
    pub exempt: bool,
    #[serde(default)]
    pub entries: Vec<AllowEntry>,
}

impl Default for ControlBuses {
    fn default() -> Self {
        Self {
            exempt: true,
            entries: Vec::new(),
        }
    }
}

/// An address / interface that stays reachable during isolation. All given
/// fields must match (AND). `port` matches either the source or the
/// destination port (the service may be on either side).
#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct AllowEntry {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cidr: Option<IpNet>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub interface: Option<Iface>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub proto: Option<Proto>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub port: Option<u16>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub note: Option<String>,
}

/// Part of the motion control path. All given fields must match (AND).
#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ProtectedEntry {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cidr: Option<IpNet>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub interface: Option<Iface>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub udp_ports: Option<PortRange>,
    /// A DDS participant of the motion path (e.g. the `rt/lowcmd` writer).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub guid_prefix: Option<GuidPrefix>,
    /// The low-level balance / motor loop: never cut, whatever the policy
    /// says (Unitree `rt/lowcmd`).
    #[serde(default)]
    pub low_level: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub note: Option<String>,
}

fn note_ok(n: &Option<String>) -> bool {
    n.as_ref()
        .is_none_or(|s| s.chars().count() <= 200 && !s.chars().any(char::is_control))
}

impl AllowEntry {
    pub fn validate(&self, what: &str) -> Result<(), String> {
        if self.cidr.is_none() && self.interface.is_none() {
            return Err(format!("{what}: an entry needs cidr and/or interface"));
        }
        match (self.proto, self.port) {
            (Some(_), Some(0)) => return Err(format!("{what}: port 0")),
            (None, Some(_)) => return Err(format!("{what}: port needs proto")),
            _ => {}
        }
        if !note_ok(&self.note) {
            return Err(format!("{what}: note too long or with control characters"));
        }
        Ok(())
    }
}

impl ProtectedEntry {
    pub fn validate(&self, what: &str) -> Result<(), String> {
        if self.cidr.is_none() && self.interface.is_none() && self.guid_prefix.is_none() {
            return Err(format!(
                "{what}: an entry needs cidr, interface and/or guid_prefix"
            ));
        }
        if !note_ok(&self.note) {
            return Err(format!("{what}: note too long or with control characters"));
        }
        Ok(())
    }
}

/// A validated configuration.
#[derive(Debug, Clone)]
pub struct Resolved {
    pub config: ExecutorConfig,
    pub socket_mode: u32,
}

fn absolute(what: &str, p: &Path) -> Result<(), String> {
    if !p.is_absolute() || p.file_name().is_none() {
        return Err(format!("{what} must be an absolute file path"));
    }
    Ok(())
}

impl ExecutorConfig {
    pub fn parse(text: &str) -> Result<Self, String> {
        serde_json::from_str(text).map_err(|e| format!("executor config: {e}"))
    }

    /// Check every rule the executor relies on. No file is read here.
    pub fn validate(self) -> Result<Resolved, String> {
        if self.schema != SCHEMA {
            return Err(format!("schema must be {SCHEMA:?}"));
        }
        if !crate::net::id_ok(&self.robot_id) {
            return Err("robot_id must be [A-Za-z0-9._:-]{1,128}".into());
        }
        absolute("socket", &self.socket)?;
        absolute("key_file", &self.key_file)?;
        absolute("policy_path", &self.policy_path)?;
        absolute("nft", &self.nft)?;
        if !self.state_dir.is_absolute() {
            return Err("state_dir must be an absolute path".into());
        }
        let socket_mode = match self.socket_mode.as_str() {
            "0600" => 0o600,
            "0660" => 0o660,
            _ => return Err("socket_mode must be \"0600\" or \"0660\"".into()),
        };
        let n = &self.network;
        for (what, list) in [
            ("network.management", &n.management),
            ("network.uplink", &n.uplink),
            ("network.control_buses.entries", &n.control_buses.entries),
        ] {
            if list.len() > MAX_ENTRIES {
                return Err(format!("{what}: more than {MAX_ENTRIES} entries"));
            }
            for (i, e) in list.iter().enumerate() {
                e.validate(&format!("{what}[{i}]"))?;
                if e.cidr.is_some_and(|c| c.len == 0) {
                    return Err(format!(
                        "{what}[{i}]: a /0 prefix would exempt everything (isolation would \
                         isolate nothing)"
                    ));
                }
            }
        }
        if n.motion_control_path.len() > MAX_ENTRIES {
            return Err(format!(
                "network.motion_control_path: more than {MAX_ENTRIES} entries"
            ));
        }
        for (i, e) in n.motion_control_path.iter().enumerate() {
            e.validate(&format!("network.motion_control_path[{i}]"))?;
        }
        let t = &self.ttl;
        if t.max_s == 0 || t.max_s > MAX_TTL_S {
            return Err(format!("ttl.max_s must be 1..={MAX_TTL_S}"));
        }
        if t.default_s == 0 || t.default_s > t.max_s {
            return Err("ttl.default_s must be 1..=ttl.max_s".into());
        }
        if !(50..=5_000).contains(&self.max_safety_age_ms) {
            return Err("max_safety_age_ms must be 50..=5000".into());
        }
        if !(1..=3_600).contains(&self.verify_interval_s) {
            return Err("verify_interval_s must be 1..=3600".into());
        }
        Ok(Resolved {
            config: self,
            socket_mode,
        })
    }
}

/// Read a small file (configuration, policy), refusing anything larger
/// than [`MAX_FILE_BYTES`] or not a regular file.
pub fn read_small(path: &Path) -> Result<String, String> {
    use std::io::Read;
    let f = std::fs::File::open(path).map_err(|e| format!("{}: {e}", path.display()))?;
    let md = f
        .metadata()
        .map_err(|e| format!("{}: {e}", path.display()))?;
    if !md.is_file() {
        return Err(format!("{}: not a regular file", path.display()));
    }
    let mut s = String::new();
    f.take(MAX_FILE_BYTES + 1)
        .read_to_string(&mut s)
        .map_err(|e| format!("{}: {e}", path.display()))?;
    if s.len() as u64 > MAX_FILE_BYTES {
        return Err(format!(
            "{}: larger than {MAX_FILE_BYTES} bytes",
            path.display()
        ));
    }
    Ok(s)
}

/// Load and validate the response policy the executor judges by.
pub fn load_policy(path: &Path) -> Result<robodr_responder::ResponsePolicy, String> {
    let text = read_small(path)?;
    robodr_responder::ResponsePolicy::from_json(&text)
        .map_err(|e| format!("{}: {e}", path.display()))
}

#[cfg(test)]
mod tests {
    use super::*;

    pub fn sample() -> &'static str {
        r#"{
          "schema": "robodr-executor-config/v1",
          "robot_id": "ugv-007",
          "socket": "/run/robodr-executor/executor.sock",
          "key_file": "/run/credentials/robodr-executor.service/executor.key",
          "state_dir": "/var/lib/robodr/executor",
          "policy_path": "/etc/robodr/response-policy.json",
          "network": {
            "management": [{"cidr": "10.20.0.0/24", "proto": "tcp", "port": 443}],
            "uplink": [{"cidr": "10.20.0.10"}],
            "control_buses": {"entries": [{"interface": "eth1"}]},
            "motion_control_path": [{"cidr": "192.168.123.0/24", "udp_ports": [7400, 7600]}]
          }
        }"#
    }

    #[test]
    fn sample_validates_with_defaults() {
        let r = ExecutorConfig::parse(sample()).unwrap().validate().unwrap();
        assert_eq!(r.socket_mode, 0o660);
        assert_eq!(r.config.ttl.default_s, 900);
        assert_eq!(r.config.ttl.max_s, MAX_TTL_S);
        assert!(r.config.network.control_buses.exempt);
        assert_eq!(r.config.nft, PathBuf::from("/usr/sbin/nft"));
    }

    #[test]
    fn bad_configs_are_refused() {
        let base: serde_json::Value = serde_json::from_str(sample()).unwrap();
        let cases: Vec<(&str, serde_json::Value)> = vec![
            ("schema", serde_json::json!("x")),
            ("socket", serde_json::json!("relative.sock")),
            ("nft", serde_json::json!("nft")),
            ("socket_mode", serde_json::json!("0666")),
            ("ttl", serde_json::json!({"default_s": 0})),
            ("ttl", serde_json::json!({"max_s": 86401})),
            ("ttl", serde_json::json!({"default_s": 100, "max_s": 50})),
            ("max_safety_age_ms", serde_json::json!(10)),
            ("verify_interval_s", serde_json::json!(0)),
            (
                "network",
                serde_json::json!({"management": [{"cidr": "0.0.0.0/0"}]}),
            ),
            ("network", serde_json::json!({"management": [{"port": 22}]})),
            (
                "network",
                serde_json::json!({"management": [{"cidr": "10.0.0.1", "port": 22}]}),
            ),
            (
                "network",
                serde_json::json!({"management": [{"interface": "eth*"}]}),
            ),
            (
                "network",
                serde_json::json!({"motion_control_path": [{"low_level": true}]}),
            ),
            (
                "network",
                serde_json::json!({"motion_control_path": [{"udp_ports": [10, 5], "cidr": "10.0.0.1"}]}),
            ),
            ("unknown_field", serde_json::json!(1)),
        ];
        for (k, v) in cases {
            let mut c = base.clone();
            c[k] = v.clone();
            let r = ExecutorConfig::parse(&c.to_string()).and_then(ExecutorConfig::validate);
            assert!(r.is_err(), "{k} = {v} accepted");
        }
    }
}
