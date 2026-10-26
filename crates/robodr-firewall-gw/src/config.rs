//! The gateway configuration (`robodr-firewall-gw.json`).
//!
//! JSON, unknown keys refused everywhere. Example (see
//! `config/firewall-gw.unitree-g1.example.json`):
//!
//! ```json
//! {
//!   "mode": "enforce",
//!   "profile": "/etc/robodr/profile.json",
//!   "profile_trust": { "trusted_keys": "/etc/robodr/profile-trust.json" },
//!   "firewall": "/etc/robodr/firewall.json",
//!   "queue": { "num": 0, "on_gateway_down": "fail_closed",
//!              "controller_port": "enp2s0", "robot_port": "enp3s0" },
//!   "rtps": { "domain_ids": [0] },
//!   "channels": [
//!     { "firewall_channel": "/lowcmd", "codec": "unitree_hg_lowcmd",
//!       "allowed_src_ips": ["192.168.123.164"] }
//!   ]
//! }
//! ```
//!
//! # `queue.on_gateway_down` — what happens when the gateway process is not
//! # there
//!
//! NFQUEUE has no listener when the gateway is stopped, crashed or
//! restarting, and the kernel then applies the rule's own flag:
//!
//! - **`fail_closed`** (**default**): the queued datagrams are dropped. The
//!   robot receives no motion command on the queued channels and its own
//!   command-timeout behaviour applies, exactly as when the controller
//!   itself fails. A security control that disappears must not open the
//!   path an attacker can open by crashing it.
//! - **`bypass`** (`queue ... bypass` / `--queue-bypass`): datagrams pass
//!   **unchecked**. For platforms whose OEM safety case says losing the
//!   command stream is the greater hazard. **Refused for a humanoid
//!   platform with a low-level joint channel** (the firewall refuses
//!   `fail_open` there for the same reason: it would forward unchecked
//!   frames to the motors).
//!
//! The same choice sets the queue's overflow behaviour
//! (`NFQA_CFG_F_FAIL_OPEN`): with `bypass`, datagrams the full queue cannot
//! hold pass; with `fail_closed` they are dropped. The rule flag is part of
//! the rendered ruleset (`robodr-firewall-gw ruleset`), so the two cannot
//! disagree.

use std::collections::BTreeMap;
use std::net::Ipv4Addr;
use std::path::PathBuf;

use robodr_ros2_pipeline::ProfileTrustConfig;
use serde::Deserialize;

/// Largest configuration file read.
pub const MAX_CONFIG_BYTES: u64 = 1 << 20;

/// `enforce` decides and rewrites; `observe` decides (records would-have
/// verdicts) and forwards every datagram unchanged.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum GatewayMode {
    Enforce,
    Observe,
}

/// See the module docs.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum OnGatewayDown {
    #[default]
    FailClosed,
    Bypass,
}

/// NFQUEUE and bridge settings.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct QueueConfig {
    /// NFQUEUE number (`0..=65535`).
    pub num: u16,
    #[serde(default)]
    pub on_gateway_down: OnGatewayDown,
    /// Kernel queue length (packets) before the overflow behaviour applies.
    #[serde(default = "default_max_len")]
    pub max_len: u32,
    /// Bridge port facing the controller (only datagrams **entering** here
    /// are queued; ruleset rendering).
    pub controller_port: String,
    /// Bridge port facing the robot (ruleset rendering).
    pub robot_port: String,
}

fn default_max_len() -> u32 {
    1024
}

/// What to do with a datagram on an RTPS port that is not decidable as a
/// whole (not RTPS, truncated, malformed, DDS-Security, too many samples).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum MalformedPolicy {
    /// **Default.** Drop it. Legitimate DDS stacks do not send such
    /// datagrams to the robot; deciding on part of one could forward a
    /// sample the gateway never saw the way the receiver sees it.
    #[default]
    Drop,
    /// Forward it unchanged (sites that use DDS-Security or another
    /// RTPS-like protocol on these ports; the gateway then enforces
    /// nothing in such datagrams).
    Pass,
}

/// A user DATA from a writer the gateway has no SEDP announcement for.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum UnknownWriters {
    /// **Default.** Try each enforced channel's decoder (a `LowCmd_` must
    /// also carry a valid Unitree CRC, a request must be a known sport
    /// call); a match is decided as that channel (its source is then
    /// resolved as usual, so an unknown writer is a foreign source).
    #[default]
    Probe,
    /// Leave such samples alone (only SEDP-classified writers are decided).
    Pass,
}

/// RTPS settings.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct RtpsConfig {
    /// DDS domain ids whose port range (7400 + 250·d .. +249) is queued.
    pub domain_ids: Vec<u16>,
    pub malformed_datagram: MalformedPolicy,
    pub unknown_writers: UnknownWriters,
    /// Most writers remembered from SEDP (oldest evicted first).
    pub max_writers: usize,
    /// Writers per enforced channel with sequence / replay state.
    pub max_writers_per_channel: usize,
    /// Where the learned writer -> channel map is persisted (so a gateway
    /// restart, which does not see the earlier SEDP again, keeps
    /// classifying the robot's existing writers).
    pub state_file: Option<PathBuf>,
    /// Largest forward step of a bound writer's sequence number that is
    /// decided at once. A larger jump is suppressed until the next sample
    /// of the same binding confirms it (see the crate docs). `1..=2^20`.
    pub max_sn_jump: u64,
    /// How long (ns) the (source IP, MAC) a writer's stream is bound to
    /// must have sent nothing before another (IP, MAC) presenting the same
    /// authorised GUID may continue it; until then such samples are binding
    /// conflicts (suppressed). `1 ms ..= 60 s`, default 1 s.
    pub binding_takeover_ns: u64,
}

impl Default for RtpsConfig {
    fn default() -> Self {
        Self {
            domain_ids: vec![0],
            malformed_datagram: MalformedPolicy::Drop,
            unknown_writers: UnknownWriters::Probe,
            max_writers: 4096,
            max_writers_per_channel: 16,
            state_file: None,
            max_sn_jump: 64,
            binding_takeover_ns: 1_000_000_000,
        }
    }
}

/// The wire format of a channel.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Codec {
    /// RTPS DATA, `unitree_go::msg::dds_::LowCmd_` (20 slots).
    UnitreeGoLowcmd,
    /// RTPS DATA, `unitree_hg::msg::dds_::LowCmd_` (35 slots).
    UnitreeHgLowcmd,
    /// RTPS DATA, `unitree_api::msg::dds_::Request_` of the sport service.
    UnitreeSportRequest,
    /// Legacy UDP `HighCmd` (129 octets).
    Go1HighCmd,
    /// Legacy UDP uncompressed `LowCmd` (734 octets).
    Go1LowCmd,
}

impl Codec {
    pub fn is_rtps(self) -> bool {
        matches!(
            self,
            Codec::UnitreeGoLowcmd | Codec::UnitreeHgLowcmd | Codec::UnitreeSportRequest
        )
    }

    /// `true` for joint-frame channels (checked with `check_joint`).
    pub fn is_joint(self) -> bool {
        matches!(
            self,
            Codec::UnitreeGoLowcmd | Codec::UnitreeHgLowcmd | Codec::Go1LowCmd
        )
    }

    /// Motor slots of a joint codec.
    pub fn slots(self) -> Option<usize> {
        match self {
            Codec::UnitreeGoLowcmd | Codec::Go1LowCmd => Some(20),
            Codec::UnitreeHgLowcmd => Some(35),
            _ => None,
        }
    }

    pub fn default_topic(self) -> Option<&'static str> {
        match self {
            Codec::UnitreeGoLowcmd | Codec::UnitreeHgLowcmd => Some("rt/lowcmd"),
            Codec::UnitreeSportRequest => Some("rt/api/sport/request"),
            _ => None,
        }
    }

    pub fn default_ports(self) -> &'static [u16] {
        match self {
            Codec::Go1HighCmd => &[8082],
            Codec::Go1LowCmd => &[8007],
            _ => &[],
        }
    }

    pub fn as_str(self) -> &'static str {
        match self {
            Codec::UnitreeGoLowcmd => "unitree_go_lowcmd",
            Codec::UnitreeHgLowcmd => "unitree_hg_lowcmd",
            Codec::UnitreeSportRequest => "unitree_sport_request",
            Codec::Go1HighCmd => "go1_high_cmd",
            Codec::Go1LowCmd => "go1_low_cmd",
        }
    }
}

/// One enforced channel.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ChannelConfig {
    /// The channel's name in the firewall configuration / profile (e.g.
    /// `/lowcmd`).
    pub firewall_channel: String,
    pub codec: Codec,
    /// RTPS codecs: the DDS topic (default `rt/lowcmd` /
    /// `rt/api/sport/request`).
    #[serde(default)]
    pub topic: Option<String>,
    /// Legacy codecs: destination UDP ports (default 8082 high / 8007 low).
    #[serde(default)]
    pub udp_ports: Vec<u16>,
    /// If non-empty, a datagram from any other source IP is a foreign
    /// source on this channel whatever its writer GUID says.
    #[serde(default)]
    pub allowed_src_ips: Vec<String>,
    /// Legacy codecs: source IP -> firewall source (`identity:<name>` or a
    /// GUID listed in the channel's `allowed_sources`). Other IPs are
    /// foreign.
    #[serde(default)]
    pub legacy_sources: BTreeMap<String, String>,
    /// Sport requests / Go1 `HighCmd`: if set, a request whose api id (a
    /// `HighCmd` whose mode) is not listed is suppressed. Velocity calls
    /// (`Move`, mode 2) are always decided by the firewall and need not be
    /// listed.
    #[serde(default)]
    pub allowed_api_ids: Option<Vec<i64>>,
    #[serde(default)]
    pub allowed_high_modes: Option<Vec<u8>>,
    /// If non-empty, a datagram whose source MAC (as the kernel reports it
    /// for the bridged frame) is not listed is a foreign source on this
    /// channel; a datagram without a reported MAC then is too. Format
    /// `aa:bb:cc:dd:ee:ff`.
    #[serde(default)]
    pub allowed_src_macs: Vec<String>,
    /// `unitree_go_lowcmd` only: forward frames whose `bms_cmd.off` is not
    /// zero (`0xA5` turns the robot's battery off). Default `false`: such a
    /// frame is refused (decided as an integrity failure, so the platform's
    /// substitute applies).
    #[serde(default)]
    pub allow_battery_off: bool,
}

impl ChannelConfig {
    pub fn topic(&self) -> Option<&str> {
        self.topic.as_deref().or(self.codec.default_topic())
    }

    pub fn ports(&self) -> Vec<u16> {
        if self.udp_ports.is_empty() {
            self.codec.default_ports().to_vec()
        } else {
            self.udp_ports.clone()
        }
    }
}

/// The whole file.
#[derive(Debug, Clone, PartialEq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GatewayConfig {
    pub mode: GatewayMode,
    /// The locked model profile (`robodr-commission lock` output).
    pub profile: PathBuf,
    /// Same keys as agentd's `sensor.profile_trust`. The gateway reads the
    /// anti-rollback `state_file` but never writes it (agentd owns it).
    #[serde(default)]
    pub profile_trust: ProfileTrustConfig,
    /// The Motion Firewall configuration (`robodr_firewall::FirewallConfig`).
    pub firewall: PathBuf,
    pub queue: QueueConfig,
    #[serde(default)]
    pub rtps: RtpsConfig,
    pub channels: Vec<ChannelConfig>,
    /// A datagram older than this when the gateway reads it (kernel queue
    /// timestamp) is not checked: the firewall's fault verdict applies
    /// (per `fault_policy`; a humanoid holds). Default 5 ms.
    #[serde(default = "default_max_queue_delay")]
    pub max_queue_delay_ns: u64,
    /// Deviations (JSON lines). Default: none written (stats only).
    #[serde(default)]
    pub events_path: Option<PathBuf>,
    /// Most bytes written to `events_path` before it stops (and counts).
    #[serde(default = "default_events_max")]
    pub events_max_bytes: u64,
    /// Status / counters JSON, rewritten every housekeeping tick.
    #[serde(default)]
    pub status_path: Option<PathBuf>,
    /// Housekeeping period (drain events, status, watchdog), ms.
    #[serde(default = "default_housekeeping")]
    pub housekeeping_ms: u64,
}

fn default_max_queue_delay() -> u64 {
    5_000_000
}
fn default_events_max() -> u64 {
    64 << 20
}
fn default_housekeeping() -> u64 {
    100
}

/// DDS default port range of a domain (`PB = 7400`, `DG = 250`; every
/// participant id's metatraffic / user, unicast / multicast port).
pub fn domain_ports(domain: u16) -> Option<(u16, u16)> {
    let lo = 7400u32 + 250 * u32::from(domain);
    let hi = lo + 249;
    Some((u16::try_from(lo).ok()?, u16::try_from(hi).ok()?))
}

impl GatewayConfig {
    /// Parse the JSON text (structure only; [`crate::Gateway::new`]
    /// validates it against the firewall configuration and profile).
    pub fn from_json(text: &str) -> Result<Self, String> {
        let c: GatewayConfig = serde_json::from_str(text).map_err(|e| format!("config: {e}"))?;
        c.validate()?;
        Ok(c)
    }

    /// Read and parse a file (size-capped).
    pub fn load(path: &std::path::Path) -> Result<Self, String> {
        use std::io::Read as _;
        let f = std::fs::File::open(path).map_err(|e| format!("{}: {e}", path.display()))?;
        let mut s = String::new();
        f.take(MAX_CONFIG_BYTES + 1)
            .read_to_string(&mut s)
            .map_err(|e| format!("{}: {e}", path.display()))?;
        if s.len() as u64 > MAX_CONFIG_BYTES {
            return Err(format!(
                "{}: larger than {MAX_CONFIG_BYTES} bytes",
                path.display()
            ));
        }
        Self::from_json(&s)
    }

    /// Checks that need nothing but this file.
    pub fn validate(&self) -> Result<(), String> {
        if self.channels.is_empty() {
            return Err("channels: at least one channel is required".into());
        }
        self.profile_trust.validate()?;
        for (what, p) in [("profile", &self.profile), ("firewall", &self.firewall)] {
            if !p.is_absolute() {
                return Err(format!("{what} must be an absolute path"));
            }
        }
        for p in [&self.events_path, &self.status_path, &self.rtps.state_file]
            .into_iter()
            .flatten()
        {
            if !p.is_absolute() {
                return Err(format!("{} must be an absolute path", p.display()));
            }
        }
        if self.queue.controller_port.is_empty()
            || self.queue.robot_port.is_empty()
            || self.queue.controller_port == self.queue.robot_port
        {
            return Err(
                "queue.controller_port and queue.robot_port must be two different interface names"
                    .into(),
            );
        }
        for n in [&self.queue.controller_port, &self.queue.robot_port] {
            if n.len() > 15
                || !n
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b"._-".contains(&b))
            {
                return Err(format!("interface name {n:?} is not valid"));
            }
        }
        if self.queue.max_len == 0 {
            return Err("queue.max_len must be >= 1".into());
        }
        if self.rtps.max_writers == 0 || self.rtps.max_writers_per_channel == 0 {
            return Err("rtps.max_writers and rtps.max_writers_per_channel must be >= 1".into());
        }
        if !(1..=1 << 20).contains(&self.rtps.max_sn_jump) {
            return Err("rtps.max_sn_jump must be in 1..=1048576".into());
        }
        if !(1_000_000..=60_000_000_000).contains(&self.rtps.binding_takeover_ns) {
            return Err("rtps.binding_takeover_ns must be in 1e6..=6e10 (1 ms ..= 60 s)".into());
        }
        let mut domains = self.rtps.domain_ids.clone();
        domains.sort_unstable();
        domains.dedup();
        for d in &domains {
            if domain_ports(*d).is_none() || *d > 232 {
                return Err(format!("rtps.domain_ids: {d} is out of range (0..=232)"));
            }
        }
        if !(1..=10_000).contains(&self.housekeeping_ms) {
            return Err("housekeeping_ms must be in 1..=10000".into());
        }
        if self.max_queue_delay_ns == 0 || self.max_queue_delay_ns > 1_000_000_000 {
            return Err("max_queue_delay_ns must be in 1..=1e9".into());
        }
        let mut topics = std::collections::BTreeSet::new();
        let mut ports = std::collections::BTreeSet::new();
        let mut names = std::collections::BTreeSet::new();
        for (i, c) in self.channels.iter().enumerate() {
            let at = format!("channels[{i}] ({})", c.firewall_channel);
            if !names.insert(c.firewall_channel.clone()) {
                return Err(format!("{at}: firewall_channel listed twice"));
            }
            for ip in &c.allowed_src_ips {
                ip.parse::<Ipv4Addr>().map_err(|_| {
                    format!("{at}: allowed_src_ips entry {ip:?} is not an IPv4 address")
                })?;
            }
            if c.codec.is_rtps() {
                let t = c.topic().unwrap_or("");
                if t.is_empty() {
                    return Err(format!("{at}: topic is empty"));
                }
                if !topics.insert(t.to_string()) {
                    return Err(format!("{at}: topic {t} is used by two channels"));
                }
                if !c.udp_ports.is_empty() || !c.legacy_sources.is_empty() {
                    return Err(format!(
                        "{at}: udp_ports / legacy_sources are for go1_* codecs only"
                    ));
                }
                if domains.is_empty() {
                    return Err(format!("{at}: an RTPS channel needs rtps.domain_ids"));
                }
            } else {
                if c.topic.is_some() {
                    return Err(format!("{at}: topic is for RTPS codecs only"));
                }
                for p in c.ports() {
                    if p == 0 || !ports.insert(p) {
                        return Err(format!("{at}: udp port {p} is invalid or used twice"));
                    }
                    for d in &domains {
                        if let Some((lo, hi)) = domain_ports(*d) {
                            if (lo..=hi).contains(&p) {
                                return Err(format!(
                                    "{at}: udp port {p} is inside the DDS port range of domain {d}"
                                ));
                            }
                        }
                    }
                }
                for ip in c.legacy_sources.keys() {
                    ip.parse::<Ipv4Addr>().map_err(|_| {
                        format!("{at}: legacy_sources key {ip:?} is not an IPv4 address")
                    })?;
                }
            }
            if c.allowed_api_ids.is_some() && c.codec != Codec::UnitreeSportRequest {
                return Err(format!(
                    "{at}: allowed_api_ids is for unitree_sport_request only"
                ));
            }
            for m in &c.allowed_src_macs {
                if crate::gateway::parse_mac(m).is_none() {
                    return Err(format!(
                        "{at}: allowed_src_macs entry {m:?} is not a MAC address (aa:bb:cc:dd:ee:ff)"
                    ));
                }
            }
            if !c.allowed_src_macs.is_empty() && !c.codec.is_rtps() {
                return Err(format!("{at}: allowed_src_macs is for RTPS codecs only"));
            }
            if c.allow_battery_off && c.codec != Codec::UnitreeGoLowcmd {
                return Err(format!(
                    "{at}: allow_battery_off is for unitree_go_lowcmd only"
                ));
            }
            if c.allowed_high_modes.is_some() && c.codec != Codec::Go1HighCmd {
                return Err(format!("{at}: allowed_high_modes is for go1_high_cmd only"));
            }
        }
        Ok(())
    }

    /// The queued DDS port ranges.
    pub fn rtps_port_ranges(&self) -> Vec<(u16, u16)> {
        if !self.channels.iter().any(|c| c.codec.is_rtps()) {
            return Vec::new();
        }
        let mut d = self.rtps.domain_ids.clone();
        d.sort_unstable();
        d.dedup();
        d.into_iter().filter_map(domain_ports).collect()
    }

    /// Every legacy UDP port.
    pub fn legacy_ports(&self) -> Vec<u16> {
        let mut v: Vec<u16> = self
            .channels
            .iter()
            .filter(|c| !c.codec.is_rtps())
            .flat_map(|c| c.ports())
            .collect();
        v.sort_unstable();
        v
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn base() -> serde_json::Value {
        serde_json::json!({
            "mode": "enforce",
            "profile": "/etc/robodr/profile.json",
            "firewall": "/etc/robodr/firewall.json",
            "queue": {"num": 3, "controller_port": "eth0", "robot_port": "eth1"},
            "channels": [{"firewall_channel": "/lowcmd", "codec": "unitree_hg_lowcmd"}]
        })
    }

    #[test]
    fn parses_with_defaults() {
        let c = GatewayConfig::from_json(&base().to_string()).unwrap();
        assert_eq!(c.queue.on_gateway_down, OnGatewayDown::FailClosed);
        assert_eq!(c.rtps.domain_ids, vec![0]);
        assert_eq!(c.channels[0].topic(), Some("rt/lowcmd"));
        assert_eq!(c.rtps_port_ranges(), vec![(7400, 7649)]);
        assert_eq!(c.max_queue_delay_ns, 5_000_000);
        assert_eq!(c.rtps.max_sn_jump, 64);
        assert_eq!(c.rtps.binding_takeover_ns, 1_000_000_000);
        assert!(!c.channels[0].allow_battery_off && c.channels[0].allowed_src_macs.is_empty());
        let mut v = base();
        v["channels"][0]["allowed_src_macs"] =
            serde_json::json!(["02:00:00:00:00:64", "AA-BB-CC-DD-EE-FF"]);
        assert!(GatewayConfig::from_json(&v.to_string()).is_ok());
        assert_eq!(
            crate::gateway::parse_mac("AA-bb-CC-dd-EE-ff"),
            Some([0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff])
        );
        for bad in [
            "",
            "aa:bb:cc:dd:ee",
            "aa:bb:cc:dd:ee:ff:00",
            "aaa:bb:cc:dd:ee:f",
            "zz:bb:cc:dd:ee:ff",
        ] {
            assert_eq!(crate::gateway::parse_mac(bad), None, "{bad}");
        }
    }

    #[test]
    fn refuses_bad_configs() {
        let cases: Vec<(&str, serde_json::Value)> = vec![
            ("unknown key", serde_json::json!({"bogus": 1})),
            (
                "relative path",
                serde_json::json!({"profile": "profile.json"}),
            ),
            (
                "same ports",
                serde_json::json!({"queue": {"num": 1, "controller_port": "eth0", "robot_port": "eth0"}}),
            ),
            ("no channels", serde_json::json!({"channels": []})),
            (
                "bad ip",
                serde_json::json!({"channels": [{"firewall_channel": "/lowcmd", "codec": "unitree_hg_lowcmd", "allowed_src_ips": ["x"]}]}),
            ),
            (
                "dup topic",
                serde_json::json!({"channels": [
                {"firewall_channel": "/a", "codec": "unitree_hg_lowcmd"},
                {"firewall_channel": "/b", "codec": "unitree_go_lowcmd"}]}),
            ),
            (
                "legacy port in dds range",
                serde_json::json!({"channels": [
                {"firewall_channel": "/h", "codec": "go1_high_cmd", "udp_ports": [7410]}]}),
            ),
            (
                "api ids on lowcmd",
                serde_json::json!({"channels": [
                {"firewall_channel": "/lowcmd", "codec": "unitree_hg_lowcmd", "allowed_api_ids": [1008]}]}),
            ),
            (
                "bad domain",
                serde_json::json!({"rtps": {"domain_ids": [300]}}),
            ),
            ("sn jump 0", serde_json::json!({"rtps": {"max_sn_jump": 0}})),
            (
                "takeover too short",
                serde_json::json!({"rtps": {"binding_takeover_ns": 1000}}),
            ),
            (
                "bad mac",
                serde_json::json!({"channels": [{"firewall_channel": "/lowcmd", "codec": "unitree_hg_lowcmd", "allowed_src_macs": ["02:00:00:00:00"]}]}),
            ),
            (
                "mac on legacy",
                serde_json::json!({"channels": [{"firewall_channel": "/h", "codec": "go1_high_cmd", "allowed_src_macs": ["02:00:00:00:00:01"]}]}),
            ),
            (
                "battery off on hg",
                serde_json::json!({"channels": [{"firewall_channel": "/lowcmd", "codec": "unitree_hg_lowcmd", "allow_battery_off": true}]}),
            ),
            (
                "bad ifname",
                serde_json::json!({"queue": {"num": 1, "controller_port": "e;rm", "robot_port": "eth1"}}),
            ),
        ];
        for (what, patch) in cases {
            let mut v = base();
            for (k, val) in patch.as_object().unwrap() {
                v[k] = val.clone();
            }
            assert!(GatewayConfig::from_json(&v.to_string()).is_err(), "{what}");
        }
    }
}
