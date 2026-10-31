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
//!     ],
//!     "discovery": {"multicast_groups": ["239.255.0.1"], "domains": [0]}
//!   },
//!   "ttl": {"default_s": 900, "max_s": 86400},
//!   "soc": {"keys": ["/etc/robodr/soc/soc.pub"], "max_clock_skew_s": 30,
//!           "robot_keys": ["/etc/robodr/keys/blackbox.pub"],
//!           "key_scopes": {"soc:tier1": {"actions": ["quarantine_node"], "max_ttl_s": 900}}},
//!   "require_approval_for_all_containment": false
//! }
//! ```
//!
//! `commissioning` (sales-readiness T12, [`Commissioning`]): the signed
//! locked profile that binds the response policy and this file's `motion`
//! section, with its trust anchors:
//!
//! ```json
//! "commissioning": {"profile_path": "/etc/robodr/profile.json",
//!                   "trusted_keys": "/etc/robodr/profile-trust.json",
//!                   "trust_roots": "/etc/robodr/trust-roots.json"}
//! ```
//!
//! With it, `oem_validated` (policy and adapters) counts only for the bound
//! files, checked by the executor itself at start and before every order
//! ([`load_commissioned`]). Without it the flags are unsigned (warned).
//! Once a running executor has read the section it keeps verifying against
//! it until restarted, even if the file's section is removed or changed
//! ([`load_commissioned_pinned`]).
//!
//! `network.quarantine` (review finding F4): the participant's locators an
//! order carries come from SPDP (unauthenticated), so a quarantine drops
//! UDP only to / from locators inside `cidrs` (the networks where DDS
//! participants that may be quarantined live; empty: no quarantine at all)
//! and on the robot's DDS ports (`udp_ports`, default the RTPS port ranges
//! of `network.discovery.domains`), all of one address family.

use std::net::IpAddr;
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
/// Most SPDP multicast groups / DDS domains kept open during isolation.
pub const MAX_DISCOVERY: usize = 16;
/// Highest DDS domain id whose ports fit the RTPS port map (7400 + 250 d +
/// 1 <= 65535).
pub const MAX_DOMAIN: u16 = 232;

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
fn default_groups() -> Vec<IpAddr> {
    vec![IpAddr::from([239, 255, 0, 1])]
}
fn default_domains() -> Vec<u16> {
    vec![0]
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
    /// The SOC public keys the executor verifies approvals with itself
    /// (trust boundary M1, [`crate::soc`]). Without keys every control-plane
    /// order is refused (`soc_signature_invalid`).
    #[serde(default)]
    pub soc: SocSection,
    /// Site option: every containment (`isolate_network`,
    /// `quarantine_node`) needs a human's (SOC-signed) approval, on every
    /// morphology: on-robot planner orders are refused (`needs_approval`).
    /// Default `false` (the morphology rules decide).
    #[serde(default)]
    pub require_approval_for_all_containment: bool,
    /// Motion actions through platform adapters (Sprint 8,
    /// [`crate::motion`]). Absent: executor v1 behaviour (`restrict_motion`
    /// advisory, `safe_pause` / `request_safe_state` / `rollback_config`
    /// refused `not_executor_action`).
    #[serde(default)]
    pub motion: Option<crate::motion::MotionSection>,
    /// The signed commissioning the OEM flags must be bound into
    /// ([`Commissioning`]). Absent: the flags are unsigned (legacy; loud
    /// warning at start and in `--check-config`).
    #[serde(default)]
    pub commissioning: Option<Commissioning>,
}

/// `commissioning` in executor.json (sales-readiness T12): where the
/// executor finds the trusted locked profile that binds its response
/// policy (`response_policy`) and its own `motion` section
/// (`executor_motion`, canonical JSON), and the trust anchors to verify it
/// with (the same files as agentd's `sensor.profile_trust`; the profile's
/// `unit_id` must be this `robot_id` or fleet-wide).
///
/// With it the executor **verifies the binding itself** whenever it reads
/// its configuration (at start and before every order): a policy that is
/// not the bound one is treated as `oem_validated: false` (every action
/// refused `observe_mode`), a motion section that is not the bound one has
/// every adapter treated as not validated (`adapter_not_validated`). The
/// anti-rollback state stays agentd's (it reports `profile_locked`).
///
/// **Sticky for the process's lifetime** ([`load_commissioned_pinned`]):
/// once a running executor has read a `commissioning` section, a re-read
/// that finds the section removed or changed (other profile, other trust
/// anchors) still verifies against the section it already had, and says so
/// in a note. Changing or removing the section takes a restart of the
/// executor (which prints the UNSIGNED warning again if it is gone).
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Commissioning {
    pub profile_path: PathBuf,
    pub trusted_keys: PathBuf,
    #[serde(default)]
    pub trust_roots: Option<PathBuf>,
    #[serde(default)]
    pub revocation_list: Option<PathBuf>,
    #[serde(default)]
    pub revocation_policy: robodr_commission::trust::RevocationPolicy,
    #[serde(default)]
    pub expect_platform: Option<String>,
}

fn default_soc_skew_s() -> u64 {
    30
}

/// `soc` in executor.json.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SocSection {
    /// `robodr-blackbox keygen` **public** Ed25519 key files of the SOC
    /// (absolute paths; root-owned, not group/other-writable: the same files
    /// as agentd's `control_plane.soc_keys`). Re-read before every order.
    #[serde(default)]
    pub keys: Vec<PathBuf>,
    /// Allowed difference between the SOC's signature timestamp and this
    /// host's clock (s, 1..=300; default 30, as agentd's).
    #[serde(default = "default_soc_skew_s")]
    pub max_clock_skew_s: u64,
    /// The robot's **own** public keys (its black-box / finding signing
    /// keys: agentd's public key files, read only). A SOC key equal to one
    /// of them is refused (review finding F9 a): whoever holds the robot's
    /// key must not be able to approve containment.
    #[serde(default)]
    pub robot_keys: Vec<PathBuf>,
    /// What each SOC key (by key id) may approve and revert, and for how
    /// long (sales-readiness T67, [`crate::soc::check_scope`]): refused
    /// `key_scope_denied` otherwise. A key without an entry approves every
    /// action up to `ttl.max_s` unless `require_key_scopes` is set or an
    /// entry names a key id no loaded `soc.keys` key has (then nothing).
    #[serde(default)]
    pub key_scopes: std::collections::BTreeMap<String, crate::soc::KeyScope>,
    /// Every SOC key must have a `key_scopes` entry (a key without one
    /// approves nothing).
    #[serde(default)]
    pub require_key_scopes: bool,
}

impl Default for SocSection {
    fn default() -> Self {
        Self {
            keys: Vec::new(),
            max_clock_skew_s: default_soc_skew_s(),
            robot_keys: Vec::new(),
            key_scopes: std::collections::BTreeMap::new(),
            require_key_scopes: false,
        }
    }
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
    /// DDS discovery kept working during isolation (the robot's own SPDP
    /// multicast, IGMP, and SPDP from the protected networks).
    #[serde(default)]
    pub discovery: Discovery,
    /// Where a quarantine may act (module docs, F4).
    #[serde(default)]
    pub quarantine: QuarantineScope,
}

/// The locators a quarantine may drop (review finding F4).
#[derive(Debug, Clone, Default, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct QuarantineScope {
    /// Networks of participants that may be quarantined (no `/0`, none
    /// overlapping a management or uplink entry). Empty (default): every
    /// quarantine is refused (`locator_out_of_scope`).
    #[serde(default)]
    pub cidrs: Vec<IpNet>,
    /// The robot's DDS UDP ports; empty (default): the RTPS port ranges
    /// (`7400 + 250 d ..= +249`) of `network.discovery.domains`.
    #[serde(default)]
    pub udp_ports: Vec<PortRange>,
}

impl QuarantineScope {
    /// The DDS port ranges a quarantined locator must lie in.
    pub fn ports(&self, discovery: &Discovery) -> Vec<PortRange> {
        if !self.udp_ports.is_empty() {
            return self.udp_ports.clone();
        }
        discovery
            .domains
            .iter()
            .filter(|d| **d <= MAX_DOMAIN)
            .filter_map(|d| {
                let lo = 7400 + 250 * d;
                PortRange::new(lo, lo + 249).ok()
            })
            .collect()
    }
}

/// The robot's DDS discovery: what stays open while it is isolated, so the
/// motion stack keeps discovering its peers (SPDP stops otherwise, and with
/// it the participants' leases).
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Discovery {
    /// SPDP multicast groups (default `239.255.0.1`, the RTPS default). An
    /// empty list keeps no multicast open.
    #[serde(default = "default_groups")]
    pub multicast_groups: Vec<IpAddr>,
    /// DDS domain ids: their discovery and user multicast ports
    /// (`7400 + 250 d` and `7401 + 250 d`, RTPS port map) stay open.
    /// Default `[0]`.
    #[serde(default = "default_domains")]
    pub domains: Vec<u16>,
}

impl Default for Discovery {
    fn default() -> Self {
        Self {
            multicast_groups: default_groups(),
            domains: default_domains(),
        }
    }
}

impl Discovery {
    /// The multicast ports of the configured domains, sorted.
    pub fn ports(&self) -> Vec<u16> {
        let mut v: Vec<u16> = self
            .domains
            .iter()
            .filter(|d| **d <= MAX_DOMAIN)
            .flat_map(|d| [7400 + 250 * d, 7401 + 250 * d])
            .collect();
        v.sort_unstable();
        v.dedup();
        v
    }

    fn validate(&self) -> Result<(), String> {
        if self.multicast_groups.len() > MAX_DISCOVERY || self.domains.len() > MAX_DISCOVERY {
            return Err(format!(
                "network.discovery: more than {MAX_DISCOVERY} groups or domains"
            ));
        }
        if let Some(g) = self.multicast_groups.iter().find(|g| !g.is_multicast()) {
            return Err(format!("network.discovery: {g} is not a multicast group"));
        }
        if let Some(d) = self.domains.iter().find(|d| **d > MAX_DOMAIN) {
            return Err(format!(
                "network.discovery: domain {d} is above {MAX_DOMAIN} (RTPS port map)"
            ));
        }
        if !self.multicast_groups.is_empty() && self.domains.is_empty() {
            return Err("network.discovery: multicast groups need at least one domain".into());
        }
        Ok(())
    }
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
/// fields must match (AND). With a `port`, a packet from outside matches
/// when it is addressed to that port (a request to a local service), or
/// when it comes from that port **and** is a reply (TCP: not a bare SYN;
/// UDP: conntrack `established`); the robot's own packets match either
/// port.
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
///
/// An entry needs an address (`cidr`) and/or an `interface`: a
/// `guid_prefix` only narrows it (to RTPS **sent by** that participant), it
/// never stands alone, since anyone can write any prefix into an RTPS
/// header. `udp_ports` are the robot bus ports **as destination**: an
/// inbound (or routed) packet must be addressed to a port in the range; the
/// robot's own outbound packets may have either port in it.
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
        if self.cidr.is_none() && self.interface.is_none() {
            return Err(format!(
                "{what}: an entry needs cidr and/or interface (a guid_prefix only narrows an \
                 entry: anyone can write any prefix into an RTPS header)"
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
        n.discovery.validate()?;
        if n.quarantine.cidrs.len() > MAX_ENTRIES || n.quarantine.udp_ports.len() > MAX_ENTRIES {
            return Err(format!(
                "network.quarantine: more than {MAX_ENTRIES} cidrs or port ranges"
            ));
        }
        for (i, c) in n.quarantine.cidrs.iter().enumerate() {
            if c.len == 0 {
                return Err(format!(
                    "network.quarantine.cidrs[{i}]: a /0 prefix would let a forged locator \
                     blackhole any endpoint"
                ));
            }
            let kept = n
                .management
                .iter()
                .chain(&n.uplink)
                .filter_map(|e| e.cidr)
                .find(|m| m.overlaps(c));
            if let Some(m) = kept {
                return Err(format!(
                    "network.quarantine.cidrs[{i}] ({c}) overlaps the management / uplink \
                     entry {m}: a quarantine must never cut the SOC's path"
                ));
            }
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
        if self.soc.keys.len() > crate::soc::MAX_SOC_KEYS {
            return Err(format!(
                "soc.keys: at most {} keys",
                crate::soc::MAX_SOC_KEYS
            ));
        }
        for k in &self.soc.keys {
            absolute("soc.keys[]", k)?;
        }
        if self.soc.robot_keys.len() > crate::soc::MAX_SOC_KEYS {
            return Err(format!(
                "soc.robot_keys: at most {} keys",
                crate::soc::MAX_SOC_KEYS
            ));
        }
        for k in &self.soc.robot_keys {
            absolute("soc.robot_keys[]", k)?;
        }
        if !(1..=300).contains(&self.soc.max_clock_skew_s) {
            return Err("soc.max_clock_skew_s must be 1..=300".into());
        }
        if self.soc.key_scopes.len() > crate::soc::MAX_SOC_KEYS {
            return Err(format!(
                "soc.key_scopes: at most {} keys",
                crate::soc::MAX_SOC_KEYS
            ));
        }
        for (k, sc) in &self.soc.key_scopes {
            sc.validate(k, t.max_s)?;
        }
        if let Some(m) = &self.motion {
            m.validate(t.max_s)?;
        }
        if let Some(c) = &self.commissioning {
            absolute("commissioning.profile_path", &c.profile_path)?;
            absolute("commissioning.trusted_keys", &c.trusted_keys)?;
            if let Some(p) = &c.trust_roots {
                absolute("commissioning.trust_roots", p)?;
            }
            match &c.revocation_list {
                Some(p) => {
                    absolute("commissioning.revocation_list", p)?;
                    if c.trust_roots.is_none() {
                        return Err("commissioning.revocation_list needs \
                                    commissioning.trust_roots"
                            .into());
                    }
                }
                None if c.revocation_policy
                    == robodr_commission::trust::RevocationPolicy::Required =>
                {
                    return Err("commissioning.revocation_policy \"required\" needs \
                                commissioning.revocation_list"
                        .into());
                }
                None => {}
            }
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

/// Read the configuration at `path` and the policy it names, and apply the
/// signed commissioning ([`apply_commissioning`]). Returns the notes to
/// log (why a flag is not honoured, or that the flags are unsigned).
pub fn load_commissioned(
    path: &Path,
) -> Result<(Resolved, robodr_responder::ResponsePolicy, Vec<String>), String> {
    load_commissioned_pinned(path, None)
}

/// [`load_commissioned`] for a running executor that already holds
/// `pinned`, the `commissioning` section it read before (review WP6: the
/// section sits in the same unbound file as the network settings, so
/// deleting it, or pointing it at other trust anchors, must not restore
/// the flags at runtime). With `pinned`, the file's own section is replaced
/// by `pinned` before the decision; a section that differs or is missing
/// adds a note.
pub fn load_commissioned_pinned(
    path: &Path,
    pinned: Option<&Commissioning>,
) -> Result<(Resolved, robodr_responder::ResponsePolicy, Vec<String>), String> {
    let text = read_small(path)?;
    let mut cfg = ExecutorConfig::parse(&text)?.validate()?;
    let mut sticky_note = None;
    if let Some(pin) = pinned {
        if cfg.config.commissioning.as_ref() != Some(pin) {
            sticky_note = Some(format!(
                "WARNING: the `commissioning` section of {} was {} since this executor read \
                 it; still verifying against the section it had (restart the executor to \
                 apply the change)",
                path.display(),
                if cfg.config.commissioning.is_none() {
                    "removed"
                } else {
                    "changed"
                }
            ));
            cfg.config.commissioning = Some(pin.clone());
        }
    }
    let policy_text = read_small(&cfg.config.policy_path)?;
    let mut policy = robodr_responder::ResponsePolicy::from_json(&policy_text)
        .map_err(|e| format!("{}: {e}", cfg.config.policy_path.display()))?;
    let mut notes = apply_commissioning(&mut cfg, &text, &policy_text, &mut policy);
    if let Some(n) = sticky_note {
        notes.insert(0, n);
    }
    Ok((cfg, policy, notes))
}

/// The commissioning decision (see [`Commissioning`]) on a configuration
/// whose file text is `config_text` and a policy whose file text is
/// `policy_text`. Downgrades `policy` and the motion section in place;
/// returns the notes.
pub fn apply_commissioning(
    cfg: &mut Resolved,
    config_text: &str,
    policy_text: &str,
    policy: &mut robodr_responder::ResponsePolicy,
) -> Vec<String> {
    use robodr_commission::trust::bound::{
        bytes_digest, canonical_json_digest, verify_bindings_report, ROLE_EXECUTOR_MOTION,
        ROLE_RESPONSE_POLICY,
    };
    let mut notes = Vec::new();
    let motion_claims = cfg
        .config
        .motion
        .as_ref()
        .is_some_and(crate::motion::MotionSection::any_validated);
    let Some(c) = cfg.config.commissioning.clone() else {
        if policy.oem_validated || motion_claims {
            notes.push(
                "WARNING: oem_validated flags are UNSIGNED (no `commissioning` section): they \
                 are not bound to a signed, quorum-attested commissioning; configure \
                 `commissioning` (robodr-commission bind) so the executor verifies them itself"
                    .into(),
            );
        }
        return notes;
    };
    let policy_digest = bytes_digest(policy_text.as_bytes());
    let motion_digest = serde_json::from_str::<serde_json::Value>(config_text)
        .ok()
        .and_then(|v| v.get("motion").and_then(canonical_json_digest));
    let mut wanted: Vec<(&str, &str)> = vec![(ROLE_RESPONSE_POLICY, &policy_digest)];
    if let Some(d) = &motion_digest {
        wanted.push((ROLE_EXECUTOR_MOTION, d));
    }
    let robot_id = cfg.config.robot_id.clone();
    let inputs = robodr_commission::trust::TrustInputs {
        trusted_keys: Some(&c.trusted_keys),
        trust_roots: c.trust_roots.as_deref(),
        revocation_list: c.revocation_list.as_deref(),
        revocation_policy: c.revocation_policy,
        expect_platform: c.expect_platform.as_deref(),
        expect_unit_id: Some(&robot_id),
        ..Default::default()
    };
    let report = verify_bindings_report(&c.profile_path, &inputs, &wanted);
    if report.lab_only {
        // The banner agentd and verify-profile print (review WP6: the
        // executor accepted a lab-only chain without a word).
        notes.push(format!(
            "WARNING: {}: {}",
            c.profile_path.display(),
            robodr_commission::poc::LAB_ONLY_BANNER
        ));
    }
    for ((role, _), r) in wanted.iter().zip(report.results) {
        let Err(e) = r else { continue };
        if *role == ROLE_RESPONSE_POLICY && policy.oem_validated {
            policy.oem_validated = false;
            notes.push(format!(
                "response policy {}: {e}; treated as NOT OEM-validated (every action refused)",
                cfg.config.policy_path.display()
            ));
        } else if *role == ROLE_EXECUTOR_MOTION && motion_claims {
            if let Some(m) = &mut cfg.config.motion {
                m.clear_validation();
            }
            notes.push(format!(
                "motion section: {e}; every adapter treated as NOT OEM-validated"
            ));
        }
    }
    if motion_claims && motion_digest.is_none() {
        if let Some(m) = &mut cfg.config.motion {
            m.clear_validation();
        }
        notes.push(
            "motion section: cannot be digested; every adapter treated as NOT OEM-validated".into(),
        );
    }
    notes
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
            ("soc", serde_json::json!({"keys": ["relative.pub"]})),
            ("soc", serde_json::json!({"max_clock_skew_s": 0})),
            ("soc", serde_json::json!({"max_clock_skew_s": 301})),
            ("soc", serde_json::json!({"unknown": 1})),
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
                serde_json::json!({"motion_control_path": [
                    {"guid_prefix": "0110a2b3c4d5e6f701000000", "low_level": true}
                ]}),
            ),
            (
                "network",
                serde_json::json!({"discovery": {"multicast_groups": ["10.0.0.1"]}}),
            ),
            (
                "network",
                serde_json::json!({"discovery": {"domains": [233]}}),
            ),
            ("network", serde_json::json!({"discovery": {"domains": []}})),
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
