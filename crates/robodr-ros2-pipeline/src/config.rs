//! Sensor configuration (`[module.robodr-sensor-ros2]` in `pulsar.toml`) and
//! its validation. Pulsar-independent: `std` + `serde` + `robodr-capture`'s
//! port map.
//!
//! Pulsar deserialises the section with `serde` from a TOML table
//! (`ModuleConfig::parse`, via `serde_ignored`, so unknown keys are warned
//! about, not rejected). The module-level `enabled` key is consumed by Pulsar
//! and never reaches [`Config`]; the nested `capture.enabled` does (it is
//! inside the `capture` sub-table). Every field has a default, so a missing
//! section parses cleanly (Pulsar parses the config of disabled modules too).
//!
//! ```toml
//! [module.robodr-sensor-ros2]
//! enabled = true
//! profile_path = "/etc/robodr/profile.json"
//! domain_id = 0
//! max_findings_per_datagram = 64   # 1..=4096
//! rate_limit_burst = 20            # 1..=10000, robot.rtps/capture/sensor.*
//! rate_limit_interval_ms = 6000    # 1..=3600000
//!
//! [module.robodr-sensor-ros2.capture]
//! enabled = true
//! interfaces = ["lo", "eth0"]   # omit for ["lo", <default-route interface>]
//! domain_ids = [0]              # omit for [domain_id]
//! # pcap_replay = "/var/lib/robodr/lab/discovery.pcapng"
//!
//! [module.robodr-sensor-ros2.binding]
//! enabled = true
//! hold_ms = 30000
//! max_participants = 1024
//! # discovery_server = ["10.0.0.2"]
//! detect_local_addresses = true   # this host's IPs from /proc
//! # local_addresses = ["192.168.50.10"]
//! strict_loopback_ingress = false
//!
//! [module.robodr-sensor-ros2.binding.participant_ips]
//! # "010f3a7c2104000001000000" = ["192.168.50.10", "10.8.0.10"]
//!
//! [module.robodr-sensor-ros2.motion]
//! enabled = true                       # decode user DATA on motion topics
//! feedback_topics = ["/odom"]          # decoded as MotionFeedback
//! evaluate_commands = true             # Profile::evaluate on decoded commands
//! max_writers = 4096                   # writer GUID -> topic table bound
//! max_samples_per_datagram = 256
//!
//! # sros2_keystore = "/etc/robodr/sros2/enclaves"  # SROS 2 policy input
//!
//! [module.robodr-sensor-ros2.profile_trust]
//! trusted_keys = "/etc/robodr/profile-trust.json"
//! state_file = "/var/lib/robodr/profile-state-pulsard/pulsard.json"
//! # expect_platform = "ugv-x1"
//! # expect_unit_id = "ugv-007"
//! # allow_rollback = "sha256:<digest>"   # one deliberate rollback, then remove
//! ```
//!
//! ## Profile trust (`profile_trust` sub-table)
//!
//! See [`crate::profile_trust`]. Without `trusted_keys` a locked profile is
//! never enforced (observe-only + `robot.ros2.profile_refused`).
//!
//! ## Motion (`motion` sub-table)
//!
//! See [`crate::motion`]. Commands are decoded on the profile's motion
//! channels (`motion_envelopes`); `feedback_topics` lists the ROS topics
//! (fully qualified, e.g. `/odom`, `/joint_states`) decoded as feedback.
//!
//! ## Binding (`binding` sub-table)
//!
//! See [`crate::binding`]. `participant_ips` pins a GUID prefix (24 hex
//! digits) to the only source IPs allowed to speak for it; it is optional and
//! a **commissioning item**: robots with DHCP, several interfaces, VPNs or
//! containers must list every address a participant can use (or rely on
//! learning only), otherwise their own announcements are reported as
//! mismatches. `discovery_server` lists the IPs of trusted Fast DDS
//! discovery servers / relays whose relayed announcements are accepted.
//! Entries are source IPs only: a GUID prefix (`PREFIX`, `PREFIX@IP`) is
//! refused, because the RTPS sender prefix is chosen by the sender and a
//! prefix-matched relay would let any host launder spoofed announcements
//! (`robodr-commission` likewise requires a trusted server to be pinned by
//! IP). Trust is per source IP, so pin the server's host.
//! `local_addresses` / `detect_local_addresses` tell the sensor which
//! addresses are this host's, so same-host participants talking over `lo`
//! (Fast DDS sends unicast to local peers from `127.0.0.1`) are not reported;
//! `strict_loopback_ingress` (see [`crate::binding`]) is for deployments
//! whose capture always knows the ingress interface.
//!
//! ## Ports
//!
//! DDSI-RTPS 2.2 §9.6.1.1 well-known ports: SPDP multicast is
//! `PB + DG * domainId + d0` (`PB = 7400`, `DG = 250`, `d0 = 0`); the largest
//! domain whose ports fit in a `u16` is 232. ROS 2 documents 0..=101 (and
//! 215..=232) as safe on Linux; other values are accepted with a warning.
//! The capture filter ([`RtpsPortMap`]) covers every well-known port
//! (metatraffic + user, multicast + unicast, participant ids 0..=119) of each
//! configured capture domain, **or** any UDP payload starting with `RTPS`.

use std::collections::BTreeMap;
use std::net::{IpAddr, Ipv4Addr};
use std::path::PathBuf;
use std::time::Duration;

use robodr_capture::ports::{MAX_DOMAIN_ID as PORTMAP_MAX_DOMAIN, MAX_PARTICIPANT_ID};
use robodr_capture::{RtpsFilter, RtpsPortMap};
use robodr_rtps::ReassemblyLimits;
use serde::Deserialize;

use crate::binding::{self, BindingOptions};
use crate::dedup::MAX_DEDUP_CAPACITY;
use crate::motion::MotionOptions;
use crate::pipeline::{
    PipelineOptions, DEFAULT_DEDUP_CAPACITY, DEFAULT_MAX_FINDINGS_PER_DATAGRAM,
    MAX_FINDINGS_PER_DATAGRAM,
};
use crate::profile_trust::ProfileTrustConfig;
use crate::ratelimit;

pub const DEFAULT_PROFILE_PATH: &str = "/etc/robodr/profile.json";
pub const DEFAULT_SPDP_GROUP: Ipv4Addr = Ipv4Addr::new(239, 255, 0, 1);
pub const SPDP_PORT_BASE: u32 = 7400;
pub const SPDP_DOMAIN_GAIN: u32 = 250;
pub const MAX_DOMAIN_ID: u32 = 232;
pub const DEFAULT_READ_TIMEOUT_MS: u64 = 500;
pub const MIN_READ_TIMEOUT_MS: u64 = 10;
pub const MAX_READ_TIMEOUT_MS: u64 = 5_000;
pub const DEFAULT_QUEUE_CAPACITY: usize = 1024;
pub const MAX_QUEUE_CAPACITY: usize = 65_536;
/// Largest `binding.hold_ms`.
pub const MAX_HOLD_MS: u64 = 600_000;
/// Largest `rate_limit_burst`.
pub const MAX_RATE_LIMIT_BURST: u32 = 10_000;
/// Largest `rate_limit_interval_ms` (one hour).
pub const MAX_RATE_LIMIT_INTERVAL_MS: u64 = 3_600_000;
/// Linux `IFNAMSIZ - 1`.
pub const MAX_IFNAME_LEN: usize = 15;
/// Where the default-route interface is read from.
pub const PROC_NET_ROUTE: &str = "/proc/net/route";

/// Raw config block as written by the operator.
#[derive(Debug, Clone, PartialEq, Deserialize)]
#[serde(default)]
pub struct Config {
    /// Absolute path to the model profile (JSON). See `config/profile.example.json`.
    pub profile_path: PathBuf,
    /// RTPS / ROS 2 domain id (`ROS_DOMAIN_ID`). Determines the SPDP port and,
    /// unless `capture.domain_ids` is set, the capture port map.
    pub domain_id: u32,
    /// Explicit SPDP port, overriding the domain-derived one.
    pub spdp_port: Option<u16>,
    /// SPDP multicast group. DDS default is 239.255.0.1.
    pub spdp_group: Ipv4Addr,
    /// Local interface address to join the group on (0.0.0.0 = kernel's choice).
    pub interface: Ipv4Addr,
    /// Listen on the SPDP multicast socket.
    pub listen_spdp: bool,
    /// Max distinct findings remembered for dedup.
    pub dedup_capacity: usize,
    /// Report RTPS parse anomalies (Low).
    pub report_anomalies: bool,
    /// Report fragmented discovery (Low, once per source IP).
    pub report_fragmentation: bool,
    /// Max findings reported per datagram (most severe first; the rest are
    /// summarised in one `robot.sensor.findings_capped` finding). 1..=4096.
    pub max_findings_per_datagram: usize,
    /// Rate limit of `robot.rtps.*` / `robot.capture.*` / `robot.sensor.*`:
    /// burst per rule (1..=10000).
    pub rate_limit_burst: u32,
    /// Rate limit: one more finding per rule per this many ms (1..=3600000).
    pub rate_limit_interval_ms: u64,
    /// Passive capture (sees unicast SEDP and loopback).
    pub capture: CaptureConfig,
    /// Participant ↔ source-IP binding check.
    pub binding: BindingConfig,
    /// User-DATA motion decode path.
    pub motion: MotionConfig,
    /// Profile authenticity and anti-rollback (`profile_trust` sub-table).
    /// See [`crate::profile_trust`]. Default: nothing trusted, so a locked
    /// profile runs observe-only.
    pub profile_trust: ProfileTrustConfig,
    /// Unitree legacy UDP (Go1 generation, `unitree_legacy` sub-table).
    /// See [`crate::legacy`]. Off by default.
    pub unitree_legacy: UnitreeLegacyConfig,
    /// The robot's SROS 2 keystore `enclaves/` directory (absolute; only
    /// `governance.xml` and the `permissions.xml` files are read). SPDP
    /// DDS-Security identities are judged against it
    /// ([`crate::sros2`]). Unset (default) = not checked.
    pub sros2_keystore: Option<PathBuf>,
}

/// `[module.robodr-sensor-ros2.unitree_legacy]`. See [`crate::legacy`].
///
/// ```toml
/// [module.robodr-sensor-ros2.unitree_legacy]
/// enabled = true
/// ports = [8007, 8080, 8082, 8090]          # default: the SDK's ports
/// # The operator's client PC(s) (EXAMPLE address: the SDK docs set the
/// # user PC to 192.168.123.162; .13 / .14 / .15 are the Go1's own internal
/// # computers, list them only if their software sends commands). An entry
/// # may bind the IP to the sender's MAC (checked where the capture sees
/// # link-layer sources, e.g. AF_PACKET / Ethernet pcap).
/// command_senders = [
///   "192.168.123.162",
///   { ip = "192.168.123.163", mac = "02:00:00:00:00:63", label = "lab PC" },
/// ]
/// robot_addresses = ["192.168.123.10", "192.168.123.161"]   # default
/// ```
#[derive(Debug, Clone, PartialEq, Deserialize)]
#[serde(default)]
pub struct UnitreeLegacyConfig {
    /// Decode legacy UDP (default off).
    pub enabled: bool,
    /// UDP ports (source or destination) carrying legacy frames.
    pub ports: Vec<u16>,
    /// Source IPs allowed to send `HighCmd` / `LowCmd`, each optionally
    /// bound to a MAC.
    pub command_senders: Vec<LegacySenderEntry>,
    /// The robot's addresses (state senders).
    pub robot_addresses: Vec<String>,
}

/// One `unitree_legacy.command_senders` entry: an IP address, or a table
/// `{ ip, mac?, label? }`.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(untagged)]
pub enum LegacySenderEntry {
    /// `"192.168.123.162"`.
    Ip(String),
    /// `{ ip = "...", mac = "aa:bb:cc:dd:ee:ff", label = "..." }`.
    Detailed(LegacySender),
}

/// The table form of a [`LegacySenderEntry`].
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LegacySender {
    pub ip: String,
    /// The sender's link-layer source address (`aa:bb:cc:dd:ee:ff`).
    /// Optional; see [`crate::legacy::rules::LEGACY_SENDER_MAC_MISMATCH`].
    #[serde(default)]
    pub mac: Option<String>,
    /// Free text for the operator (not used by the sensor).
    #[serde(default)]
    pub label: Option<String>,
}

impl LegacySenderEntry {
    fn ip(&self) -> &str {
        match self {
            LegacySenderEntry::Ip(ip) => ip,
            LegacySenderEntry::Detailed(d) => &d.ip,
        }
    }

    fn mac(&self) -> Option<&str> {
        match self {
            LegacySenderEntry::Ip(_) => None,
            LegacySenderEntry::Detailed(d) => d.mac.as_deref(),
        }
    }
}

impl From<&str> for LegacySenderEntry {
    fn from(ip: &str) -> Self {
        LegacySenderEntry::Ip(ip.to_string())
    }
}

/// Most characters of a `command_senders` label.
pub const MAX_LEGACY_LABEL_CHARS: usize = 128;

impl Default for UnitreeLegacyConfig {
    fn default() -> Self {
        let d = crate::legacy::LegacyOptions::default();
        Self {
            enabled: d.enabled,
            ports: d.ports.into_iter().collect(),
            command_senders: Vec::new(),
            robot_addresses: d.robot_addresses.iter().map(ToString::to_string).collect(),
        }
    }
}

impl UnitreeLegacyConfig {
    /// Validate into [`crate::legacy::LegacyOptions`].
    pub fn validate(
        &self,
        warnings: &mut Vec<String>,
    ) -> Result<crate::legacy::LegacyOptions, String> {
        use crate::legacy::MAX_LEGACY_ADDRESSES;
        let mut ports = std::collections::BTreeSet::new();
        if self.enabled && self.ports.is_empty() {
            return Err("unitree_legacy.ports is empty: no legacy UDP would be captured".into());
        }
        if self.ports.len() > robodr_capture::MAX_LEGACY_UDP_PORTS {
            return Err(format!(
                "unitree_legacy.ports has {} entries, at most {}",
                self.ports.len(),
                robodr_capture::MAX_LEGACY_UDP_PORTS
            ));
        }
        for p in &self.ports {
            if *p == 0 {
                return Err("unitree_legacy.ports must not contain 0".into());
            }
            if !ports.insert(*p) {
                return Err(format!("unitree_legacy.ports lists {p} twice"));
            }
        }
        let addrs =
            |what: &str, list: &[String]| -> Result<std::collections::BTreeSet<IpAddr>, String> {
                if list.len() > MAX_LEGACY_ADDRESSES {
                    return Err(format!(
                        "unitree_legacy.{what} has {} entries, at most {MAX_LEGACY_ADDRESSES}",
                        list.len()
                    ));
                }
                let mut out = std::collections::BTreeSet::new();
                for a in list {
                    let ip: IpAddr = a.parse().map_err(|_| {
                        format!(
                            "unitree_legacy.{what} entry {:?} is not an IP address",
                            crate::sanitize::sanitize(a)
                        )
                    })?;
                    if !out.insert(ip) {
                        return Err(format!("unitree_legacy.{what} lists {ip} twice"));
                    }
                }
                Ok(out)
            };
        let sender_ips: Vec<String> = self
            .command_senders
            .iter()
            .map(|e| e.ip().to_string())
            .collect();
        let command_senders = addrs("command_senders", &sender_ips)?;
        let robot_addresses = addrs("robot_addresses", &self.robot_addresses)?;
        let mut sender_macs = std::collections::BTreeMap::new();
        for e in &self.command_senders {
            if let LegacySenderEntry::Detailed(d) = e {
                if d.label
                    .as_ref()
                    .is_some_and(|l| l.chars().count() > MAX_LEGACY_LABEL_CHARS)
                {
                    return Err(format!(
                        "unitree_legacy.command_senders label of {} is longer than \
                         {MAX_LEGACY_LABEL_CHARS} characters",
                        crate::sanitize::sanitize(&d.ip)
                    ));
                }
            }
            let Some(mac) = e.mac() else { continue };
            let ip: IpAddr = e.ip().parse().map_err(|_| "unreachable".to_string())?;
            let parsed = crate::legacy::parse_mac(mac)
                .filter(|m| *m != [0; 6] && m[0] & 1 == 0)
                .ok_or_else(|| {
                    format!(
                        "unitree_legacy.command_senders entry {ip}: mac {:?} is not a unicast \
                         MAC address (aa:bb:cc:dd:ee:ff)",
                        crate::sanitize::sanitize(mac)
                    )
                })?;
            sender_macs.insert(ip, parsed);
        }
        if self.enabled && !sender_macs.is_empty() {
            warnings.push(
                "unitree_legacy.command_senders binds senders to a MAC: a mismatch is reported \
                 only where the capture sees link-layer sources (AF_PACKET, Ethernet / cooked \
                 pcap), and a host on the same L2 segment can forge a MAC as easily as an IP; \
                 the binding raises the bar, it does not authenticate"
                    .into(),
            );
        }
        if self.enabled {
            if command_senders.is_empty() {
                warnings.push(
                    "unitree_legacy.command_senders is empty: every legacy HighCmd / LowCmd is \
                     reported as coming from an unknown sender (Critical)"
                        .into(),
                );
            }
            if robot_addresses.is_empty() {
                warnings.push(
                    "unitree_legacy.robot_addresses is empty: every legacy state frame is \
                     reported as coming from an unknown sender"
                        .into(),
                );
            }
            if let Some(both) = command_senders.intersection(&robot_addresses).next() {
                warnings.push(format!(
                    "unitree_legacy: {both} is both a command sender and a robot address"
                ));
            }
        }
        Ok(crate::legacy::LegacyOptions {
            enabled: self.enabled,
            ports,
            command_senders,
            sender_macs,
            robot_addresses,
        })
    }
}

impl Default for Config {
    fn default() -> Self {
        Self {
            profile_path: PathBuf::from(DEFAULT_PROFILE_PATH),
            domain_id: 0,
            spdp_port: None,
            spdp_group: DEFAULT_SPDP_GROUP,
            interface: Ipv4Addr::UNSPECIFIED,
            listen_spdp: true,
            dedup_capacity: DEFAULT_DEDUP_CAPACITY,
            report_anomalies: true,
            report_fragmentation: true,
            max_findings_per_datagram: DEFAULT_MAX_FINDINGS_PER_DATAGRAM,
            rate_limit_burst: ratelimit::DEFAULT_BURST,
            rate_limit_interval_ms: ratelimit::DEFAULT_INTERVAL.as_millis() as u64,
            capture: CaptureConfig::default(),
            binding: BindingConfig::default(),
            motion: MotionConfig::default(),
            profile_trust: ProfileTrustConfig::default(),
            unitree_legacy: UnitreeLegacyConfig::default(),
            sros2_keystore: None,
        }
    }
}

/// `[module.robodr-sensor-ros2.motion]`. See [`crate::motion`].
#[derive(Debug, Clone, PartialEq, Deserialize)]
#[serde(default)]
pub struct MotionConfig {
    /// Decode user DATA on motion / feedback topics (default on).
    pub enabled: bool,
    /// Fully qualified ROS topics decoded as feedback (`/odom`, ...).
    pub feedback_topics: Vec<String>,
    /// Evaluate decoded commands against the profile (default on).
    pub evaluate_commands: bool,
    /// Writer / reader GUID table bound (1..=65536).
    pub max_writers: usize,
    /// Samples decoded per datagram (1..=4096).
    pub max_samples_per_datagram: usize,
}

/// Most entries of `motion.feedback_topics`.
pub const MAX_FEEDBACK_TOPICS: usize = 64;

impl Default for MotionConfig {
    fn default() -> Self {
        let d = MotionOptions::default();
        Self {
            enabled: d.enabled,
            feedback_topics: Vec::new(),
            evaluate_commands: d.evaluate_commands,
            max_writers: d.max_writers,
            max_samples_per_datagram: d.user_data.max_samples_per_datagram,
        }
    }
}

impl MotionConfig {
    /// Validate into [`MotionOptions`].
    pub fn validate(&self, warnings: &mut Vec<String>) -> Result<MotionOptions, String> {
        if !self.enabled {
            warnings.push(
                "motion.enabled = false: motion commands and feedback on the bus are NOT decoded \
                 (no envelope check of live commands)"
                    .into(),
            );
        }
        if self.max_writers == 0 || self.max_writers > crate::motion::MAX_MAX_ENDPOINTS {
            return Err(format!(
                "motion.max_writers {} out of range: must be 1..={}",
                self.max_writers,
                crate::motion::MAX_MAX_ENDPOINTS
            ));
        }
        if self.max_samples_per_datagram == 0
            || self.max_samples_per_datagram > robodr_rtps::HARD_MAX_SAMPLES_PER_DATAGRAM
        {
            return Err(format!(
                "motion.max_samples_per_datagram {} out of range: must be 1..={}",
                self.max_samples_per_datagram,
                robodr_rtps::HARD_MAX_SAMPLES_PER_DATAGRAM
            ));
        }
        if self.feedback_topics.len() > MAX_FEEDBACK_TOPICS {
            return Err(format!(
                "motion.feedback_topics has {} entries, at most {MAX_FEEDBACK_TOPICS}",
                self.feedback_topics.len()
            ));
        }
        let mut topics = std::collections::BTreeSet::new();
        for t in &self.feedback_topics {
            let shown = crate::sanitize::sanitize(t);
            let rn = robodr_events::graph::demangle(&format!("rt{t}"));
            if !t.starts_with('/')
                || rn.kind != robodr_events::graph::RosNameKind::Topic
                || rn.name != *t
            {
                return Err(format!(
                    "motion.feedback_topics entry {shown:?} is not a fully qualified ROS topic \
                     name (e.g. \"/odom\")"
                ));
            }
            if !topics.insert(t.clone()) {
                return Err(format!("motion.feedback_topics lists {shown:?} twice"));
            }
        }
        if !self.evaluate_commands {
            warnings.push(
                "motion.evaluate_commands = false: decoded commands are not checked against the \
                 profile envelope by the sensor (the consumer must do it)"
                    .into(),
            );
        }
        let mut opts = MotionOptions {
            enabled: self.enabled,
            feedback_topics: topics,
            evaluate_commands: self.evaluate_commands,
            max_writers: self.max_writers,
            max_readers: self.max_writers,
            ..MotionOptions::default()
        };
        opts.user_data.max_samples_per_datagram = self.max_samples_per_datagram;
        Ok(opts)
    }
}

/// `[module.robodr-sensor-ros2.binding]`. See [`crate::binding`].
#[derive(Debug, Clone, PartialEq, Deserialize)]
#[serde(default)]
pub struct BindingConfig {
    /// Run the binding check (default on). Off = spoofed endpoint
    /// attribution is not detected.
    pub enabled: bool,
    /// Hold window for SEDP seen before its participant's SPDP, ms
    /// (0..=600000; 0 = report "never announced" at once).
    pub hold_ms: u64,
    /// Max learned participants (1..=65536).
    pub max_participants: usize,
    /// Trusted discovery-server / relay IPs.
    pub discovery_server: Vec<IpAddr>,
    /// Optional pins: GUID prefix (24 hex digits) -> allowed source IPs.
    pub participant_ips: BTreeMap<String, Vec<IpAddr>>,
    /// This host's addresses, in addition to the detected ones: participants
    /// bound to them are same-host, so their traffic over loopback is
    /// accepted (see [`crate::binding`]).
    pub local_addresses: Vec<IpAddr>,
    /// Detect this host's addresses from `/proc` at start (default on).
    pub detect_local_addresses: bool,
    /// Judge loopback-sourced datagrams of unknown ingress like any other
    /// source (default off; see [`crate::binding`]).
    pub strict_loopback_ingress: bool,
}

impl Default for BindingConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            hold_ms: binding::DEFAULT_HOLD.as_millis() as u64,
            max_participants: binding::DEFAULT_MAX_PARTICIPANTS,
            discovery_server: Vec::new(),
            participant_ips: BTreeMap::new(),
            local_addresses: Vec::new(),
            detect_local_addresses: true,
            strict_loopback_ingress: false,
        }
    }
}

/// An address usable as a peer source: not unspecified, multicast or
/// broadcast.
fn valid_peer_ip(ip: IpAddr) -> bool {
    !ip.is_unspecified() && !ip.is_multicast() && ip != IpAddr::V4(Ipv4Addr::BROADCAST)
}

impl BindingConfig {
    /// Validate into [`BindingOptions`].
    pub fn validate(&self, warnings: &mut Vec<String>) -> Result<BindingOptions, String> {
        if !self.enabled {
            warnings.push(
                "binding.enabled = false: endpoints announced under another participant's GUID \
                 prefix (spoofed attribution) are NOT detected"
                    .into(),
            );
        }
        if self.hold_ms > MAX_HOLD_MS {
            return Err(format!(
                "binding.hold_ms {} out of range: must be 0..={MAX_HOLD_MS}",
                self.hold_ms
            ));
        }
        if self.max_participants == 0 || self.max_participants > binding::MAX_MAX_PARTICIPANTS {
            return Err(format!(
                "binding.max_participants {} out of range: must be 1..={}",
                self.max_participants,
                binding::MAX_MAX_PARTICIPANTS
            ));
        }
        if self.discovery_server.len() > binding::MAX_DISCOVERY_SERVERS {
            return Err(format!(
                "binding.discovery_server has {} entries, at most {}",
                self.discovery_server.len(),
                binding::MAX_DISCOVERY_SERVERS
            ));
        }
        let mut servers: Vec<IpAddr> = Vec::new();
        for ip in &self.discovery_server {
            if !valid_peer_ip(*ip) {
                return Err(format!(
                    "binding.discovery_server entry {ip} is not a unicast address"
                ));
            }
            let ip = binding::canonical_ip(*ip);
            if !servers.contains(&ip) {
                servers.push(ip);
            }
        }
        if !servers.is_empty() {
            warnings.push(format!(
                "binding.discovery_server: announcements relayed from {} are trusted",
                servers
                    .iter()
                    .map(ToString::to_string)
                    .collect::<Vec<_>>()
                    .join(", ")
            ));
        }
        if self.participant_ips.len() > binding::MAX_PINNED_PARTICIPANTS {
            return Err(format!(
                "binding.participant_ips has {} entries, at most {}",
                self.participant_ips.len(),
                binding::MAX_PINNED_PARTICIPANTS
            ));
        }
        let mut pins = BTreeMap::new();
        for (key, ips) in &self.participant_ips {
            let shown = crate::sanitize::sanitize(key);
            let prefix = binding::parse_prefix(key).ok_or_else(|| {
                format!("binding.participant_ips key {shown:?} is not a 24-hex-digit GUID prefix")
            })?;
            if ips.is_empty() || ips.len() > binding::MAX_PINNED_IPS {
                return Err(format!(
                    "binding.participant_ips.{shown} must list 1..={} IPs",
                    binding::MAX_PINNED_IPS
                ));
            }
            let mut list: Vec<IpAddr> = Vec::new();
            for ip in ips {
                if !valid_peer_ip(*ip) {
                    return Err(format!(
                        "binding.participant_ips.{shown} entry {ip} is not a unicast address"
                    ));
                }
                let ip = binding::canonical_ip(*ip);
                if !list.contains(&ip) {
                    list.push(ip);
                }
            }
            if pins.insert(prefix, list).is_some() {
                return Err(format!(
                    "binding.participant_ips key {shown:?} is listed twice (keys are case-insensitive)"
                ));
            }
        }
        if self.local_addresses.len() > binding::MAX_LOCAL_ADDRESSES {
            return Err(format!(
                "binding.local_addresses has {} entries, at most {}",
                self.local_addresses.len(),
                binding::MAX_LOCAL_ADDRESSES
            ));
        }
        let mut local: Vec<IpAddr> = Vec::new();
        for ip in &self.local_addresses {
            if !valid_peer_ip(*ip) {
                return Err(format!(
                    "binding.local_addresses entry {ip} is not a unicast address"
                ));
            }
            let ip = binding::canonical_ip(*ip);
            if !local.contains(&ip) {
                local.push(ip);
            }
        }
        if self.strict_loopback_ingress {
            warnings.push(
                "binding.strict_loopback_ingress = true: loopback-sourced discovery from a \
                 capture that cannot tell its interface is judged like remote traffic \
                 (same-host SEDP over lo may be reported as a mismatch)"
                    .into(),
            );
        }
        Ok(BindingOptions {
            enabled: self.enabled,
            discovery_servers: servers,
            participant_ips: pins,
            hold: Duration::from_millis(self.hold_ms),
            max_participants: self.max_participants,
            max_pending: binding::DEFAULT_MAX_PENDING,
            local_addresses: local,
            detect_local_addresses: self.detect_local_addresses,
            strict_loopback_ingress: self.strict_loopback_ingress,
        })
    }
}

/// `[module.robodr-sensor-ros2.capture]`.
#[derive(Debug, Clone, PartialEq, Deserialize)]
#[serde(default)]
pub struct CaptureConfig {
    /// Run the capture source. Off by default (needs `CAP_NET_RAW` live).
    pub enabled: bool,
    /// Interfaces to capture on. Absent = `["lo", <default-route interface>]`;
    /// `[]` = every interface.
    pub interfaces: Option<Vec<String>>,
    /// Lab only: replay this pcap/pcapng file instead of capturing live.
    pub pcap_replay: Option<PathBuf>,
    /// Domains whose well-known ports the capture filter accepts. Empty =
    /// `[domain_id]`.
    pub domain_ids: Vec<u32>,
    /// Live read timeout (stop-flag latency), milliseconds.
    pub read_timeout_ms: u64,
    /// Datagrams buffered between the capture thread and the sensor.
    pub queue_capacity: usize,
}

impl Default for CaptureConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            interfaces: None,
            pcap_replay: None,
            domain_ids: Vec::new(),
            read_timeout_ms: DEFAULT_READ_TIMEOUT_MS,
            queue_capacity: DEFAULT_QUEUE_CAPACITY,
        }
    }
}

/// Where and how to listen for SPDP multicast.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SpdpSettings {
    pub group: Ipv4Addr,
    pub port: u16,
    pub interface: Ipv4Addr,
}

/// What the capture source reads.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CaptureInput {
    /// Live `AF_PACKET`; empty = all interfaces.
    Live { interfaces: Vec<String> },
    /// Lab replay of a capture file.
    Replay { path: PathBuf },
}

/// Validated capture settings.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CaptureSettings {
    pub input: CaptureInput,
    pub domain_ids: Vec<u16>,
    pub port_map: RtpsPortMap,
    pub read_timeout: Duration,
    pub queue_capacity: usize,
    /// Unitree legacy UDP ports the capture filter also accepts (empty
    /// unless `unitree_legacy.enabled`).
    pub legacy_udp_ports: std::collections::BTreeSet<u16>,
}

/// Validated, ready-to-use settings.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Settings {
    pub profile_path: PathBuf,
    pub domain_id: u32,
    /// `None` when `listen_spdp = false`.
    pub spdp: Option<SpdpSettings>,
    /// `None` when `capture.enabled = false`.
    pub capture: Option<CaptureSettings>,
    pub pipeline: PipelineOptions,
    /// Validated `profile_trust` (pass to
    /// [`crate::profile_trust::load_profile_with_trust`]; log its
    /// [`ProfileTrustConfig::warnings`]).
    pub profile_trust: ProfileTrustConfig,
}

impl Settings {
    /// At least one built-in datagram source is configured.
    pub fn has_builtin_source(&self) -> bool {
        self.spdp.is_some() || self.capture.is_some()
    }
}

/// SPDP multicast port for a domain, or `None` if the domain is out of range.
pub fn spdp_multicast_port(domain_id: u32) -> Option<u16> {
    if domain_id > MAX_DOMAIN_ID {
        return None;
    }
    u16::try_from(SPDP_PORT_BASE + SPDP_DOMAIN_GAIN * domain_id).ok()
}

/// The capture port map for some domains (every participant id).
pub fn capture_port_map(domain_ids: &[u16]) -> RtpsPortMap {
    RtpsPortMap::new(domain_ids.iter().copied(), MAX_PARTICIPANT_ID)
}

/// The interface of the first default route (`Destination == 0`, `RTF_UP`)
/// in a `/proc/net/route` table.
pub fn default_route_interface(route_table: &str) -> Option<String> {
    route_table.lines().skip(1).find_map(|line| {
        let cols: Vec<&str> = line.split_whitespace().collect();
        let (iface, dest, flags) = (cols.first()?, cols.get(1)?, cols.get(3)?);
        let flags = u32::from_str_radix(flags, 16).ok()?;
        (*dest == "00000000" && flags & 0x1 != 0 && valid_ifname(iface)).then(|| iface.to_string())
    })
}

/// The default-route interface of this host, if any.
pub fn system_default_route_interface() -> Option<String> {
    std::fs::read_to_string(PROC_NET_ROUTE)
        .ok()
        .and_then(|t| default_route_interface(&t))
}

/// A plausible Linux interface name.
pub fn valid_ifname(name: &str) -> bool {
    !name.is_empty()
        && name.len() <= MAX_IFNAME_LEN
        && name != "."
        && name != ".."
        && name
            .bytes()
            .all(|b| b.is_ascii_graphic() && b != b'/' && b != b':')
}

fn domain_warning(warnings: &mut Vec<String>, what: &str, d: u32) {
    if (102..=214).contains(&d) {
        warnings.push(format!(
            "{what} {d} is outside the ROS 2 recommended ranges 0..=101 and 215..=232"
        ));
    }
}

impl Config {
    /// Validate and resolve, reading the default-route interface from
    /// `/proc/net/route` if `capture.interfaces` is absent.
    pub fn validate(&self) -> Result<(Settings, Vec<String>), String> {
        self.validate_with(system_default_route_interface)
    }

    /// [`Config::validate`] with an injectable default-route lookup (tests).
    /// `Ok` carries the settings plus non-fatal warnings; `Err` is a message
    /// suitable for a module error.
    pub fn validate_with(
        &self,
        default_iface: impl FnOnce() -> Option<String>,
    ) -> Result<(Settings, Vec<String>), String> {
        let mut warnings = Vec::new();

        if self.profile_path.as_os_str().is_empty() {
            return Err("profile_path is empty".into());
        }
        if !self.profile_path.is_absolute() {
            return Err(format!(
                "profile_path must be absolute (the daemon's working directory is not \
                 defined): {}",
                self.profile_path.display()
            ));
        }

        let Some(derived_port) = spdp_multicast_port(self.domain_id) else {
            return Err(format!(
                "domain_id {} out of range: must be 0..={MAX_DOMAIN_ID} \
                 (port = {SPDP_PORT_BASE} + {SPDP_DOMAIN_GAIN} * domain_id must fit in 16 bits)",
                self.domain_id
            ));
        };
        domain_warning(&mut warnings, "domain_id", self.domain_id);

        if self.dedup_capacity == 0 || self.dedup_capacity > MAX_DEDUP_CAPACITY {
            return Err(format!(
                "dedup_capacity {} out of range: must be 1..={MAX_DEDUP_CAPACITY}",
                self.dedup_capacity
            ));
        }

        if self.max_findings_per_datagram == 0
            || self.max_findings_per_datagram > MAX_FINDINGS_PER_DATAGRAM
        {
            return Err(format!(
                "max_findings_per_datagram {} out of range: must be 1..={MAX_FINDINGS_PER_DATAGRAM}",
                self.max_findings_per_datagram
            ));
        }
        if self.rate_limit_burst == 0 || self.rate_limit_burst > MAX_RATE_LIMIT_BURST {
            return Err(format!(
                "rate_limit_burst {} out of range: must be 1..={MAX_RATE_LIMIT_BURST}",
                self.rate_limit_burst
            ));
        }
        if self.rate_limit_interval_ms == 0
            || self.rate_limit_interval_ms > MAX_RATE_LIMIT_INTERVAL_MS
        {
            return Err(format!(
                "rate_limit_interval_ms {} out of range: must be 1..={MAX_RATE_LIMIT_INTERVAL_MS}",
                self.rate_limit_interval_ms
            ));
        }

        let spdp = if self.listen_spdp {
            let port = match self.spdp_port {
                Some(0) => return Err("spdp_port must not be 0".into()),
                Some(p) if p != derived_port => {
                    warnings.push(format!(
                        "spdp_port {p} overrides the port derived from domain_id {} ({derived_port})",
                        self.domain_id
                    ));
                    p
                }
                Some(p) => p,
                None => derived_port,
            };
            if !self.spdp_group.is_multicast() {
                return Err(format!(
                    "spdp_group {} is not an IPv4 multicast address",
                    self.spdp_group
                ));
            }
            if self.interface.is_multicast() || self.interface.is_broadcast() {
                return Err(format!(
                    "interface {} must be a unicast local address or 0.0.0.0",
                    self.interface
                ));
            }
            Some(SpdpSettings {
                group: self.spdp_group,
                port,
                interface: self.interface,
            })
        } else {
            if self.spdp_port.is_some() {
                warnings.push("spdp_port is ignored because listen_spdp = false".into());
            }
            None
        };

        let mut capture = self.validate_capture(&mut warnings, default_iface)?;
        let binding = self.binding.validate(&mut warnings)?;
        let motion = self.motion.validate(&mut warnings)?;
        self.profile_trust.validate()?;
        let legacy = self.unitree_legacy.validate(&mut warnings)?;
        if legacy.enabled {
            // A legacy port inside the DDS port map would make one datagram
            // RTPS by port and legacy by port: refused (choose another
            // ROS_DOMAIN_ID / capture.domain_ids, or other legacy ports).
            let domains: Vec<u16> = match &capture {
                Some(c) => c.domain_ids.clone(),
                None => u16::try_from(self.domain_id).into_iter().collect(),
            };
            let map = capture_port_map(&domains);
            for p in &legacy.ports {
                if let Some((lo, hi)) = map
                    .port_ranges()
                    .into_iter()
                    .find(|(lo, hi)| (*lo..=*hi).contains(p))
                {
                    return Err(format!(
                        "unitree_legacy.ports {p} lies inside the RTPS port range {lo}..={hi} of \
                         DDS domain(s) {domains:?}: the capture could not tell DDS from legacy \
                         traffic on it; use another ROS domain or other legacy ports"
                    ));
                }
            }
        }
        if legacy.enabled {
            match capture.as_mut() {
                Some(c) => c.legacy_udp_ports = legacy.ports.clone(),
                None => warnings.push(
                    "unitree_legacy.enabled needs capture.enabled: legacy UDP is only seen by \
                     the packet capture"
                        .into(),
                ),
            }
        }

        let sros2 = match &self.sros2_keystore {
            None => None,
            Some(dir) if !dir.is_absolute() => {
                return Err(format!(
                    "sros2_keystore must be absolute: {}",
                    dir.display()
                ))
            }
            Some(dir) => {
                let policy = crate::sros2::Sros2Policy::load(dir)
                    .map_err(|e| format!("sros2_keystore: {e}"))?;
                warnings.extend(
                    policy
                        .warnings
                        .iter()
                        .map(|w| format!("sros2_keystore: {w}")),
                );
                Some(std::sync::Arc::new(policy))
            }
        };

        Ok((
            Settings {
                profile_path: self.profile_path.clone(),
                domain_id: self.domain_id,
                spdp,
                capture,
                pipeline: PipelineOptions {
                    dedup_capacity: self.dedup_capacity,
                    reassembly: ReassemblyLimits::default(),
                    report_anomalies: self.report_anomalies,
                    report_fragmentation: self.report_fragmentation,
                    binding,
                    rate_limit_burst: self.rate_limit_burst,
                    rate_limit_interval: Duration::from_millis(self.rate_limit_interval_ms),
                    max_findings_per_datagram: self.max_findings_per_datagram,
                    motion,
                    legacy,
                    sros2,
                },
                profile_trust: self.profile_trust.clone(),
            },
            warnings,
        ))
    }

    fn validate_capture(
        &self,
        warnings: &mut Vec<String>,
        default_iface: impl FnOnce() -> Option<String>,
    ) -> Result<Option<CaptureSettings>, String> {
        let c = &self.capture;
        if !c.enabled {
            if c.pcap_replay.is_some() {
                warnings
                    .push("capture.pcap_replay is ignored because capture.enabled = false".into());
            }
            return Ok(None);
        }

        let mut domains: Vec<u16> = Vec::new();
        let requested: Vec<u32> = if c.domain_ids.is_empty() {
            vec![self.domain_id]
        } else {
            c.domain_ids.clone()
        };
        for d in requested {
            let ok = u16::try_from(d)
                .ok()
                .filter(|d| u32::from(*d) <= MAX_DOMAIN_ID && *d <= PORTMAP_MAX_DOMAIN);
            let Some(d16) = ok else {
                return Err(format!(
                    "capture.domain_ids entry {d} out of range: must be 0..={MAX_DOMAIN_ID}"
                ));
            };
            domain_warning(warnings, "capture.domain_ids entry", d);
            if !domains.contains(&d16) {
                domains.push(d16);
            }
        }
        if !c.domain_ids.is_empty() && !domains.contains(&(self.domain_id as u16)) {
            warnings.push(format!(
                "capture.domain_ids does not include domain_id {}; its unicast discovery is \
                 only caught by the RTPS magic",
                self.domain_id
            ));
        }

        if !(MIN_READ_TIMEOUT_MS..=MAX_READ_TIMEOUT_MS).contains(&c.read_timeout_ms) {
            return Err(format!(
                "capture.read_timeout_ms {} out of range: must be \
                 {MIN_READ_TIMEOUT_MS}..={MAX_READ_TIMEOUT_MS}",
                c.read_timeout_ms
            ));
        }
        if c.queue_capacity == 0 || c.queue_capacity > MAX_QUEUE_CAPACITY {
            return Err(format!(
                "capture.queue_capacity {} out of range: must be 1..={MAX_QUEUE_CAPACITY}",
                c.queue_capacity
            ));
        }

        let input = match &c.pcap_replay {
            Some(path) => {
                if !path.is_absolute() {
                    return Err(format!(
                        "capture.pcap_replay must be an absolute path: {}",
                        path.display()
                    ));
                }
                warnings.push(format!(
                    "capture.pcap_replay is set: replaying {} instead of capturing live \
                     (lab use only; the robot's live traffic is NOT watched by capture)",
                    path.display()
                ));
                if c.interfaces.is_some() {
                    warnings.push("capture.interfaces is ignored while pcap_replay is set".into());
                }
                CaptureInput::Replay { path: path.clone() }
            }
            None => {
                let interfaces = match &c.interfaces {
                    Some(list) => {
                        if list.is_empty() {
                            warnings
                                .push("capture.interfaces = [] captures on every interface".into());
                        }
                        list.clone()
                    }
                    None => {
                        let mut list = vec!["lo".to_string()];
                        match default_iface() {
                            Some(i) if i != "lo" => list.push(i),
                            Some(_) => {}
                            None => warnings.push(
                                "no default-route interface found; capturing on lo only. \
                                 Set capture.interfaces to the robot's DDS interface(s)"
                                    .into(),
                            ),
                        }
                        list
                    }
                };
                let mut uniq: Vec<String> = Vec::new();
                for i in interfaces {
                    if !valid_ifname(&i) {
                        return Err(format!(
                            "capture.interfaces entry {:?} is not a valid interface name",
                            crate::sanitize::sanitize(&i)
                        ));
                    }
                    if !uniq.contains(&i) {
                        uniq.push(i);
                    }
                }
                CaptureInput::Live { interfaces: uniq }
            }
        };

        Ok(Some(CaptureSettings {
            input,
            port_map: capture_port_map(&domains),
            domain_ids: domains,
            read_timeout: Duration::from_millis(c.read_timeout_ms),
            queue_capacity: c.queue_capacity,
            legacy_udp_ports: std::collections::BTreeSet::new(),
        }))
    }
}

impl CaptureSettings {
    /// Open the configured capture as a boxed [`DatagramSource`], stopping
    /// when `stop` is set. Live capture needs Linux and `CAP_NET_RAW`.
    ///
    /// [`DatagramSource`]: crate::DatagramSource
    pub fn open(
        &self,
        stop: std::sync::Arc<std::sync::atomic::AtomicBool>,
    ) -> std::io::Result<Box<dyn crate::DatagramSource + Send>> {
        use crate::source::CaptureDatagramSource;
        match &self.input {
            CaptureInput::Replay { path } => Ok(Box::new(
                CaptureDatagramSource::open_file_with_filter(path, self.filter())?
                    .with_stop_flag(stop),
            )),
            CaptureInput::Live { interfaces } => {
                open_live(interfaces, self.filter(), self.read_timeout, stop)
            }
        }
    }

    /// The capture filter: the port map's RTPS ports or the `RTPS` magic,
    /// plus the Unitree legacy UDP ports when configured.
    pub fn filter(&self) -> RtpsFilter {
        crate::source::rtps_filter(self.port_map.clone())
            .with_legacy_udp_ports(self.legacy_udp_ports.iter().copied())
    }
}

/// Split a live interface list into (loopback, other) so each capture knows
/// its [`crate::binding::Ingress`]. `None` = do not split (empty = every
/// interface, or only one kind).
pub fn split_by_ingress(
    interfaces: &[String],
    is_loopback: impl Fn(&str) -> bool,
) -> Option<(Vec<String>, Vec<String>)> {
    let (lo, other): (Vec<String>, Vec<String>) =
        interfaces.iter().cloned().partition(|i| is_loopback(i));
    (!lo.is_empty() && !other.is_empty()).then_some((lo, other))
}

#[cfg(all(
    target_os = "linux",
    any(
        target_arch = "x86_64",
        target_arch = "x86",
        target_arch = "aarch64",
        target_arch = "arm",
        target_arch = "riscv64"
    )
))]
fn open_live(
    interfaces: &[String],
    filter: RtpsFilter,
    timeout: Duration,
    stop: std::sync::Arc<std::sync::atomic::AtomicBool>,
) -> std::io::Result<Box<dyn crate::DatagramSource + Send>> {
    use crate::source::{is_loopback_interface, CaptureDatagramSource, MergedDatagramSource};
    // A mixed list (the default `["lo", <default-route>]`) becomes two
    // captures, so a loopback source address can be told apart from a forged
    // one on the wire (crate::binding, "Same-host traffic over loopback").
    if let Some((lo, other)) = split_by_ingress(interfaces, is_loopback_interface) {
        let a = CaptureDatagramSource::open_live_with_filter(&lo, filter.clone(), timeout)?
            .with_stop_flag(stop.clone());
        let b = CaptureDatagramSource::open_live_with_filter(&other, filter, timeout)?
            .with_stop_flag(stop.clone());
        return Ok(Box::new(MergedDatagramSource::new(
            vec![Box::new(a), Box::new(b)],
            stop,
        )?));
    }
    Ok(Box::new(
        CaptureDatagramSource::open_live_with_filter(interfaces, filter, timeout)?
            .with_stop_flag(stop),
    ))
}

#[cfg(not(all(
    target_os = "linux",
    any(
        target_arch = "x86_64",
        target_arch = "x86",
        target_arch = "aarch64",
        target_arch = "arm",
        target_arch = "riscv64"
    )
)))]
fn open_live(
    _interfaces: &[String],
    _filter: RtpsFilter,
    _timeout: Duration,
    _stop: std::sync::Arc<std::sync::atomic::AtomicBool>,
) -> std::io::Result<Box<dyn crate::DatagramSource + Send>> {
    Err(std::io::Error::new(
        std::io::ErrorKind::Unsupported,
        "live capture needs Linux AF_PACKET",
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    use robodr_capture::PortKind;

    // Pulsar parses TOML; `toml` is not a dependency here, so these tests
    // drive the same serde derive through JSON (same data model).
    fn parse(json: &str) -> Config {
        serde_json::from_str(json).expect("config should parse")
    }

    fn validate(json: &str) -> Result<(Settings, Vec<String>), String> {
        parse(json).validate_with(|| Some("eth0".into()))
    }

    #[test]
    fn port_formula() {
        assert_eq!(spdp_multicast_port(0), Some(7400));
        assert_eq!(spdp_multicast_port(1), Some(7650));
        assert_eq!(spdp_multicast_port(42), Some(17900));
        assert_eq!(spdp_multicast_port(232), Some(65400));
        assert_eq!(spdp_multicast_port(233), None);
        assert_eq!(spdp_multicast_port(u32::MAX), None);
    }

    #[test]
    fn empty_section_is_valid_defaults() {
        let c = parse("{}");
        assert_eq!(c, Config::default());
        let (s, w) = validate("{}").unwrap();
        assert!(w.is_empty(), "{w:?}");
        assert_eq!(s.profile_path, PathBuf::from(DEFAULT_PROFILE_PATH));
        assert_eq!(
            s.spdp,
            Some(SpdpSettings {
                group: DEFAULT_SPDP_GROUP,
                port: 7400,
                interface: Ipv4Addr::UNSPECIFIED,
            })
        );
        assert!(s.capture.is_none());
        // The deployed sensor detects this host's addresses; the library
        // default (tests, replays of other hosts' captures) does not.
        let mut expected = PipelineOptions::default();
        expected.binding.detect_local_addresses = true;
        assert_eq!(s.pipeline, expected);
        assert!(s.has_builtin_source());
    }

    #[test]
    fn domain_id_sets_port_and_range_checks() {
        let (s, w) = validate(r#"{"domain_id": 7}"#).unwrap();
        assert_eq!(s.spdp.unwrap().port, 7400 + 250 * 7);
        assert!(w.is_empty());
        assert!(validate(r#"{"domain_id": 233}"#)
            .unwrap_err()
            .contains("domain_id 233"));
        let (_, w) = validate(r#"{"domain_id": 150}"#).unwrap();
        assert_eq!(w.len(), 1);
        let (_, w) = validate(r#"{"domain_id": 220}"#).unwrap();
        assert!(w.is_empty());
    }

    #[test]
    fn explicit_port_overrides_with_warning() {
        let (s, w) = validate(r#"{"domain_id": 1, "spdp_port": 7400}"#).unwrap();
        assert_eq!(s.spdp.unwrap().port, 7400);
        assert_eq!(w.len(), 1);
        let (_, w) = validate(r#"{"domain_id": 1, "spdp_port": 7650}"#).unwrap();
        assert!(w.is_empty());
        assert!(validate(r#"{"spdp_port": 0}"#).is_err());
    }

    #[test]
    fn bad_addresses_are_rejected() {
        assert!(validate(r#"{"spdp_group": "10.0.0.1"}"#).is_err());
        assert!(validate(r#"{"interface": "239.255.0.1"}"#).is_err());
        assert!(validate(r#"{"interface": "255.255.255.255"}"#).is_err());
        assert!(validate(r#"{"interface": "10.1.2.3"}"#).is_ok());
    }

    #[test]
    fn unparseable_values_fail_at_parse_time() {
        for bad in [
            r#"{"spdp_group": "not-an-ip"}"#,
            r#"{"domain_id": -1}"#,
            r#"{"spdp_port": 70000}"#,
            r#"{"capture": {"enabled": "yes"}}"#,
            r#"{"capture": {"interfaces": "eth0"}}"#,
            r#"{"capture": {"domain_ids": [-1]}}"#,
        ] {
            assert!(serde_json::from_str::<Config>(bad).is_err(), "{bad}");
        }
    }

    #[test]
    fn profile_path_must_be_absolute_and_non_empty() {
        assert!(validate(r#"{"profile_path": ""}"#).is_err());
        assert!(validate(r#"{"profile_path": "profile.json"}"#).is_err());
        assert!(validate(r#"{"profile_path": "/srv/p.json"}"#).is_ok());
    }

    #[test]
    fn dedup_capacity_bounds() {
        assert!(validate(r#"{"dedup_capacity": 0}"#).is_err());
        assert!(validate(r#"{"dedup_capacity": 1}"#).is_ok());
        let too_big = format!(r#"{{"dedup_capacity": {}}}"#, MAX_DEDUP_CAPACITY + 1);
        assert!(validate(&too_big).is_err());
    }

    #[test]
    fn spdp_can_be_disabled() {
        let (s, w) = validate(r#"{"listen_spdp": false}"#).unwrap();
        assert!(s.spdp.is_none());
        assert!(!s.has_builtin_source());
        assert!(w.is_empty());
        assert!(validate(r#"{"listen_spdp": false, "spdp_group": "10.0.0.1"}"#).is_ok());
        let (_, w) = validate(r#"{"listen_spdp": false, "spdp_port": 7400}"#).unwrap();
        assert_eq!(w.len(), 1);
    }

    #[test]
    fn report_switches_reach_pipeline_options() {
        let (s, _) =
            validate(r#"{"report_anomalies": false, "report_fragmentation": false}"#).unwrap();
        assert!(!s.pipeline.report_anomalies);
        assert!(!s.pipeline.report_fragmentation);
    }

    #[test]
    fn capture_defaults_to_lo_plus_default_route_and_domain_id() {
        let (s, w) = validate(r#"{"domain_id": 3, "capture": {"enabled": true}}"#).unwrap();
        assert!(w.is_empty(), "{w:?}");
        let c = s.capture.unwrap();
        assert_eq!(
            c.input,
            CaptureInput::Live {
                interfaces: vec!["lo".into(), "eth0".into()]
            }
        );
        assert_eq!(c.domain_ids, vec![3]);
        assert_eq!(c.read_timeout, Duration::from_millis(500));
        assert_eq!(c.queue_capacity, DEFAULT_QUEUE_CAPACITY);
        // The port map covers domain 3's SPDP + metatraffic unicast ports...
        let base = 7400 + 250 * 3;
        assert_eq!(
            c.port_map.classify(base).unwrap().kind,
            PortKind::MetatrafficMulticast
        );
        assert_eq!(
            c.port_map.classify(base + 10 + 2 * 5).unwrap().participant,
            Some(5)
        );
        // ...and not domain 0's.
        assert!(!c.port_map.contains(7400));
    }

    #[test]
    fn capture_without_default_route_warns_and_uses_lo() {
        let (s, w) = parse(r#"{"capture": {"enabled": true}}"#)
            .validate_with(|| None)
            .unwrap();
        assert_eq!(w.len(), 1);
        assert!(w[0].contains("lo only"));
        assert_eq!(
            s.capture.unwrap().input,
            CaptureInput::Live {
                interfaces: vec!["lo".into()]
            }
        );
        let (s, _) = parse(r#"{"capture": {"enabled": true}}"#)
            .validate_with(|| Some("lo".into()))
            .unwrap();
        assert_eq!(
            s.capture.unwrap().input,
            CaptureInput::Live {
                interfaces: vec!["lo".into()]
            }
        );
    }

    #[test]
    fn capture_explicit_interfaces_and_domains() {
        let (s, w) = validate(
            r#"{"domain_id": 1, "capture": {"enabled": true, "interfaces": ["eth1", "eth1", "wlan0"],
                "domain_ids": [0, 1, 1, 42]}}"#,
        )
        .unwrap();
        assert!(w.is_empty(), "{w:?}");
        let c = s.capture.unwrap();
        assert_eq!(
            c.input,
            CaptureInput::Live {
                interfaces: vec!["eth1".into(), "wlan0".into()]
            }
        );
        assert_eq!(c.domain_ids, vec![0, 1, 42]);
        assert!(c.port_map.contains(7400) && c.port_map.contains(17900));
        // [] = all interfaces, with a warning.
        let (s, w) = validate(r#"{"capture": {"enabled": true, "interfaces": []}}"#).unwrap();
        assert_eq!(w.len(), 1);
        assert_eq!(
            s.capture.unwrap().input,
            CaptureInput::Live { interfaces: vec![] }
        );
        // domain_ids without domain_id warns.
        let (_, w) =
            validate(r#"{"domain_id": 5, "capture": {"enabled": true, "domain_ids": [0]}}"#)
                .unwrap();
        assert_eq!(w.len(), 1);
    }

    #[test]
    fn capture_rejects_bad_values() {
        for bad in [
            r#"{"capture": {"enabled": true, "interfaces": [""]}}"#,
            r#"{"capture": {"enabled": true, "interfaces": ["../etc"]}}"#,
            r#"{"capture": {"enabled": true, "interfaces": ["a\nb"]}}"#,
            r#"{"capture": {"enabled": true, "interfaces": ["sixteen-chars-xx"]}}"#,
            r#"{"capture": {"enabled": true, "domain_ids": [233]}}"#,
            r#"{"capture": {"enabled": true, "domain_ids": [70000]}}"#,
            r#"{"capture": {"enabled": true, "read_timeout_ms": 0}}"#,
            r#"{"capture": {"enabled": true, "read_timeout_ms": 999999}}"#,
            r#"{"capture": {"enabled": true, "queue_capacity": 0}}"#,
            r#"{"capture": {"enabled": true, "pcap_replay": "relative.pcap"}}"#,
        ] {
            let e = validate(bad).unwrap_err();
            assert!(!e.contains('\n'), "error is sanitised: {e}");
        }
        // Disabled capture is not validated beyond parsing.
        assert!(validate(r#"{"capture": {"interfaces": [""], "domain_ids": [999]}}"#).is_ok());
    }

    #[test]
    fn pcap_replay_takes_over_with_warnings() {
        let (s, w) = validate(
            r#"{"capture": {"enabled": true, "pcap_replay": "/lab/x.pcapng", "interfaces": ["eth0"]}}"#,
        )
        .unwrap();
        assert_eq!(w.len(), 2, "{w:?}");
        assert_eq!(
            s.capture.unwrap().input,
            CaptureInput::Replay {
                path: "/lab/x.pcapng".into()
            }
        );
        let (s, w) = validate(r#"{"capture": {"pcap_replay": "/lab/x.pcapng"}}"#).unwrap();
        assert!(s.capture.is_none());
        assert_eq!(w.len(), 1);
    }

    #[test]
    fn binding_defaults_and_values_reach_pipeline_options() {
        let (s, w) = validate("{}").unwrap();
        assert!(w.is_empty());
        assert_eq!(
            s.pipeline.binding,
            BindingOptions {
                detect_local_addresses: true,
                ..BindingOptions::default()
            }
        );
        let (s, w) = validate(
            r#"{"binding": {"hold_ms": 0, "max_participants": 8,
                "discovery_server": ["10.0.0.2", "::ffff:10.0.0.2"],
                "participant_ips": {"AAAAAAAAAAAAAAAAAAAAAAAA": ["10.0.0.5", "fd00::5", "10.0.0.5"]}}}"#,
        )
        .unwrap();
        assert_eq!(w.len(), 1, "{w:?}");
        assert!(w[0].contains("10.0.0.2"));
        let b = &s.pipeline.binding;
        assert!(b.enabled);
        assert_eq!(b.hold, Duration::ZERO);
        assert_eq!(b.max_participants, 8);
        assert_eq!(b.discovery_servers, vec![IpAddr::from([10, 0, 0, 2])]);
        assert_eq!(
            b.participant_ips[&[0xaa; 12]],
            vec![
                IpAddr::from([10, 0, 0, 5]),
                "fd00::5".parse::<IpAddr>().unwrap()
            ]
        );
        let (s, w) = validate(r#"{"binding": {"enabled": false}}"#).unwrap();
        assert!(!s.pipeline.binding.enabled);
        assert_eq!(w.len(), 1);
    }

    #[test]
    fn binding_local_addresses_and_loopback_policy() {
        let (s, w) = validate(
            r#"{"binding": {"local_addresses": ["192.168.50.10", "::ffff:192.168.50.10", "fd00::1"],
                "detect_local_addresses": false, "strict_loopback_ingress": true}}"#,
        )
        .unwrap();
        let b = &s.pipeline.binding;
        assert_eq!(
            b.local_addresses,
            vec![
                IpAddr::from([192, 168, 50, 10]),
                "fd00::1".parse::<IpAddr>().unwrap()
            ]
        );
        assert!(!b.detect_local_addresses);
        assert!(b.strict_loopback_ingress);
        assert_eq!(w.len(), 1, "{w:?}");
        assert!(w[0].contains("strict_loopback_ingress"));
        for bad in [
            r#"{"binding": {"local_addresses": ["0.0.0.0"]}}"#,
            r#"{"binding": {"local_addresses": ["239.255.0.1"]}}"#,
            r#"{"binding": {"local_addresses": ["255.255.255.255"]}}"#,
        ] {
            assert!(validate(bad).is_err(), "{bad}");
        }
        assert!(serde_json::from_str::<Config>(
            r#"{"binding": {"local_addresses": ["not-an-ip"]}}"#
        )
        .is_err());
        let many: Vec<String> = (0..=binding::MAX_LOCAL_ADDRESSES)
            .map(|i| format!("\"10.1.{}.{}\"", i / 250, i % 250 + 1))
            .collect();
        let json = format!(
            r#"{{"binding": {{"local_addresses": [{}]}}}}"#,
            many.join(",")
        );
        assert!(validate(&json).unwrap_err().contains("at most"));
    }

    #[test]
    fn mixed_interface_lists_are_split_by_ingress() {
        let lo = |n: &str| n == "lo";
        let v = |a: &[&str]| a.iter().map(|s| s.to_string()).collect::<Vec<_>>();
        assert_eq!(
            split_by_ingress(&v(&["lo", "eth0", "wlan0"]), lo),
            Some((v(&["lo"]), v(&["eth0", "wlan0"])))
        );
        assert_eq!(split_by_ingress(&v(&["lo"]), lo), None);
        assert_eq!(split_by_ingress(&v(&["eth0"]), lo), None);
        assert_eq!(split_by_ingress(&[], lo), None);
    }

    #[test]
    fn output_limits_are_validated() {
        let (s, _) = validate(
            r#"{"max_findings_per_datagram": 8, "rate_limit_burst": 3, "rate_limit_interval_ms": 250}"#,
        )
        .unwrap();
        assert_eq!(s.pipeline.max_findings_per_datagram, 8);
        assert_eq!(s.pipeline.rate_limit_burst, 3);
        assert_eq!(s.pipeline.rate_limit_interval, Duration::from_millis(250));
        let (s, _) = validate("{}").unwrap();
        assert_eq!(
            (
                s.pipeline.max_findings_per_datagram,
                s.pipeline.rate_limit_burst,
                s.pipeline.rate_limit_interval
            ),
            (
                PipelineOptions::default().max_findings_per_datagram,
                PipelineOptions::default().rate_limit_burst,
                PipelineOptions::default().rate_limit_interval
            )
        );
        for bad in [
            r#"{"max_findings_per_datagram": 0}"#,
            r#"{"max_findings_per_datagram": 4097}"#,
            r#"{"rate_limit_burst": 0}"#,
            r#"{"rate_limit_burst": 10001}"#,
            r#"{"rate_limit_interval_ms": 0}"#,
            r#"{"rate_limit_interval_ms": 3600001}"#,
        ] {
            assert!(validate(bad).is_err(), "{bad}");
        }
        // Wrong types / negative / non-finite numbers never deserialize.
        for bad in [
            r#"{"rate_limit_burst": -1}"#,
            r#"{"rate_limit_interval_ms": 1.5}"#,
            r#"{"max_findings_per_datagram": 1e999}"#,
            r#"{"binding": {"hold_ms": -5}}"#,
            r#"{"binding": {"max_participants": "many"}}"#,
        ] {
            assert!(serde_json::from_str::<Config>(bad).is_err(), "{bad}");
        }
    }

    #[test]
    fn binding_rejects_bad_values() {
        for bad in [
            r#"{"binding": {"hold_ms": 600001}}"#,
            r#"{"binding": {"max_participants": 0}}"#,
            r#"{"binding": {"max_participants": 65537}}"#,
            r#"{"binding": {"discovery_server": ["0.0.0.0"]}}"#,
            r#"{"binding": {"discovery_server": ["239.255.0.1"]}}"#,
            r#"{"binding": {"participant_ips": {"aa": ["10.0.0.5"]}}}"#,
            r#"{"binding": {"participant_ips": {"zzaaaaaaaaaaaaaaaaaaaaaa": ["10.0.0.5"]}}}"#,
            r#"{"binding": {"participant_ips": {"aaaaaaaaaaaaaaaaaaaaaaaa": []}}}"#,
            r#"{"binding": {"participant_ips": {"aaaaaaaaaaaaaaaaaaaaaaaa": ["255.255.255.255"]}}}"#,
            r#"{"binding": {"participant_ips": {"aaaaaaaaaaaaaaaaaaaaaaaa": ["10.0.0.5"],
                "AAAAAAAAAAAAAAAAAAAAAAAA": ["10.0.0.6"]}}}"#,
            r#"{"binding": {"participant_ips": {"a\naaaaaaaaaaaaaaaaaaaaaa": ["10.0.0.5"]}}}"#,
        ] {
            let e = validate(bad).unwrap_err();
            assert!(!e.contains('\n'), "error is sanitised: {e}");
        }
        let many: Vec<String> = (0..33).map(|i| format!("\"10.0.1.{i}\"")).collect();
        let j = format!(
            r#"{{"binding": {{"discovery_server": [{}]}}}}"#,
            many.join(",")
        );
        assert!(validate(&j).is_err());
        assert!(
            serde_json::from_str::<Config>(r#"{"binding": {"discovery_server": ["x"]}}"#).is_err()
        );
        // A GUID prefix (alone or with an IP) is never a discovery server:
        // the sender prefix is attacker-chosen, trust is by source IP only.
        for spec in [
            "aaaaaaaaaaaaaaaaaaaaaaaa",
            "aaaaaaaaaaaaaaaaaaaaaaaa@10.0.0.2",
            "@10.0.0.2",
        ] {
            let j = format!(r#"{{"binding": {{"discovery_server": ["{spec}"]}}}}"#);
            assert!(serde_json::from_str::<Config>(&j).is_err(), "{spec}");
        }
    }

    #[test]
    fn default_route_parsing() {
        let table = "Iface\tDestination\tGateway \tFlags\tRefCnt\tUse\tMetric\tMask\n\
                     eth1\t0010A8C0\t00000000\t0001\t0\t0\t0\t00FFFFFF\n\
                     eth0\t00000000\t0100A8C0\t0003\t0\t0\t100\t00000000\n";
        assert_eq!(default_route_interface(table).as_deref(), Some("eth0"));
        // Down route (flags without RTF_UP) and garbage are skipped.
        let down = "Iface Destination Gateway Flags\nwg0 00000000 0 0002\nx\n";
        assert_eq!(default_route_interface(down), None);
        assert_eq!(default_route_interface(""), None);
        let weird = "h\nbad/name 00000000 0 0001\n";
        assert_eq!(default_route_interface(weird), None);
        // Does not panic on the real table, whatever it holds.
        let _ = system_default_route_interface();
    }

    #[test]
    fn ifname_rules() {
        assert!(valid_ifname("lo"));
        assert!(valid_ifname("enp3s0f1.100"));
        assert!(valid_ifname("123456789012345"));
        assert!(!valid_ifname("1234567890123456"));
        for bad in ["", ".", "..", "a/b", "a b", "eth0:1", "é"] {
            assert!(!valid_ifname(bad), "{bad}");
        }
    }

    #[test]
    fn motion_section_reaches_pipeline_options() {
        let (s, w) = validate(
            r#"{"motion": {"feedback_topics": ["/odom", "/joint_states"], "max_writers": 10,
                "max_samples_per_datagram": 8}}"#,
        )
        .unwrap();
        let m = &s.pipeline.motion;
        assert!(m.enabled && m.evaluate_commands);
        assert_eq!(
            m.feedback_topics.iter().cloned().collect::<Vec<_>>(),
            vec!["/joint_states".to_string(), "/odom".to_string()]
        );
        assert_eq!((m.max_writers, m.max_readers), (10, 10));
        assert_eq!(m.user_data.max_samples_per_datagram, 8);
        assert!(w.is_empty(), "{w:?}");
        // Defaults: on, no feedback topics.
        let (s, _) = validate("{}").unwrap();
        assert_eq!(s.pipeline.motion, MotionOptions::default());
        let (_, w) =
            validate(r#"{"motion": {"enabled": false, "evaluate_commands": false}}"#).unwrap();
        assert_eq!(w.len(), 2, "{w:?}");
        for bad in [
            r#"{"motion": {"feedback_topics": ["odom"]}}"#,
            r#"{"motion": {"feedback_topics": ["rt/odom"]}}"#,
            r#"{"motion": {"feedback_topics": ["/odom/"]}}"#,
            r#"{"motion": {"feedback_topics": [""]}}"#,
            r#"{"motion": {"feedback_topics": ["/odom", "/odom"]}}"#,
            r#"{"motion": {"max_writers": 0}}"#,
            r#"{"motion": {"max_writers": 1000000}}"#,
            r#"{"motion": {"max_samples_per_datagram": 0}}"#,
            r#"{"motion": {"max_samples_per_datagram": 5000}}"#,
        ] {
            assert!(validate(bad).is_err(), "{bad}");
        }
        let many: Vec<String> = (0..65).map(|i| format!("/t{i}")).collect();
        let json = serde_json::json!({"motion": {"feedback_topics": many}}).to_string();
        assert!(validate(&json).is_err());
    }

    #[test]
    fn capture_settings_open_replay_reports_missing_file() {
        let (s, _) =
            validate(r#"{"capture": {"enabled": true, "pcap_replay": "/nonexistent/x.pcap"}}"#)
                .unwrap();
        let stop = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
        let e = match s.capture.unwrap().open(stop) {
            Err(e) => e,
            Ok(_) => panic!("opening a missing file must fail"),
        };
        assert_eq!(e.kind(), std::io::ErrorKind::NotFound);
    }

    /// Review LOW: a legacy port inside the DDS domain port map would make
    /// the same datagram RTPS by port and legacy by port; refused.
    #[test]
    fn legacy_ports_inside_the_dds_port_map_are_refused() {
        let base = r#""capture": {"enabled": true, "interfaces": ["eth0"]},
                      "unitree_legacy": {"enabled": true, "command_senders": ["192.168.123.162"]}"#;
        assert!(validate(&format!("{{{base}}}")).is_ok());
        let e = validate(&format!(r#"{{"domain_id": 2, {base}}}"#)).unwrap_err();
        assert!(e.contains("8007") && e.contains("domain"), "{e}");
        // Also through capture.domain_ids.
        let e = validate(
            r#"{"capture": {"enabled": true, "interfaces": ["eth0"], "domain_ids": [0, 2]},
                "unitree_legacy": {"enabled": true, "ports": [8090]}}"#,
        )
        .unwrap_err();
        assert!(e.contains("8090"), "{e}");
        // Off: not checked.
        assert!(validate(
            r#"{"domain_id": 2, "capture": {"enabled": true, "interfaces": ["eth0"]}}"#
        )
        .is_ok());
    }

    /// Review M3: `command_senders` entries may bind the sender IP to a MAC
    /// (and carry a label); bad MACs and unknown keys are refused.
    #[test]
    fn legacy_command_senders_with_mac() {
        let (s, w) = validate(
            r#"{"capture": {"enabled": true, "interfaces": ["eth0"]},
                "unitree_legacy": {"enabled": true, "command_senders": [
                    "192.168.123.163",
                    {"ip": "192.168.123.162", "mac": "02:00:00:00:00:62", "label": "operator PC"},
                    {"ip": "192.168.123.164"}
                ]}}"#,
        )
        .unwrap();
        let l = &s.pipeline.legacy;
        assert_eq!(l.command_senders.len(), 3);
        assert_eq!(l.sender_macs.len(), 1);
        assert_eq!(
            l.sender_macs[&"192.168.123.162".parse::<IpAddr>().unwrap()],
            [2, 0, 0, 0, 0, 0x62]
        );
        assert!(
            w.iter().any(|w| w.contains("MAC") && w.contains("same L2")),
            "{w:?}"
        );
        for bad in [
            r#"{"ip": "192.168.123.162", "mac": "02:00:00:00:62"}"#,
            r#"{"ip": "192.168.123.162", "mac": "zz:00:00:00:00:62"}"#,
            r#"{"ip": "192.168.123.162", "mac": "00:00:00:00:00:00"}"#,
            r#"{"ip": "192.168.123.162", "colour": "red"}"#,
            r#"{"ip": "not-an-ip"}"#,
        ] {
            let j = format!(
                r#"{{"capture": {{"enabled": true, "interfaces": ["eth0"]}},
                    "unitree_legacy": {{"enabled": true, "command_senders": [{bad}]}}}}"#
            );
            let r = serde_json::from_str::<Config>(&j)
                .map_err(|e| e.to_string())
                .and_then(|c| c.validate_with(|| Some("eth0".into())).map(|_| ()));
            assert!(r.is_err(), "{bad}");
        }
    }
}
