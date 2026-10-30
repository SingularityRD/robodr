//! Go2 WebRTC control sessions at the inline gateway (`webrtc` section).
//!
//! WebRTC is DTLS-SRTP: the gateway cannot read, limit or rewrite a single
//! command inside a session, so it never tries. What it does, for the
//! session **as a whole**:
//!
//! * **Detect and attribute** (always): the controller-side signalling to
//!   the robot (TCP to `signalling_ports`) and the controller-side UDP to
//!   the robot that is not queued (ICE, DTLS, SRTCP) are copied to NFLOG
//!   group `nflog_group`; the robot-side copies of the observe chain
//!   (STUN responses, DTLS server flights, SRTP, signalling answers) are
//!   added. Both feed `robodr_ros2_pipeline::webrtc::WebRtcMonitor`, whose
//!   findings (`robot.unitree.webrtc_*`) go to the events file and agentd's
//!   gateway feed like the gateway's own. Copies are never queued or
//!   dropped: a stopped gateway changes nothing on this path.
//! * **Refuse unlisted signalling** (`action: block_unlisted`): TCP to the
//!   robot's signalling ports from a source IP that is not a listed
//!   controller is dropped in the bridge (`nft`, table `bridge
//!   robodr_gw_rtc`), so an unlisted host cannot start a local session by
//!   the known methods. ICE / DTLS from an unlisted peer that was signalled
//!   another way (Wi-Fi, a relay) is detected, not blocked by this rule.
//! * **Quarantine by flow** (any action): the table has two timeout sets,
//!   `blocked_peers` (an IPv4 address: every packet between it and the
//!   robot addresses is dropped, both directions) and `blocked_flows`
//!   (`peer ip . peer port . robot ip . robot port`, UDP, both directions).
//!   `robodr-firewall-gw webrtc-block` prints the `nft` command that adds an
//!   element with a timeout (the flows are named in every finding). A
//!   re-applied ruleset recreates the table and forgets the elements.
//!
//! Blocking a running session stops its media and data channel; the robot
//! sees its controller vanish, as on a lost Wi-Fi link, and applies its own
//! behaviour for that (not published by Unitree: check it before relying on
//! a quarantine during motion).

use std::net::{IpAddr, Ipv4Addr};

use robodr_ros2_pipeline::webrtc::{DenyWindow, WebRtcOptions, DEFAULT_SIGNALLING_PORTS};
use serde::Deserialize;

/// What the gateway does besides detecting.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum WebRtcAction {
    /// Detect and report only (quarantine sets still available).
    #[default]
    Observe,
    /// Also drop signalling from sources that are not listed controllers.
    BlockUnlisted,
}

/// A listed controller.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WebRtcController {
    pub ip: String,
    /// Optional link-layer binding (`aa:bb:cc:dd:ee:ff`); checked where the
    /// copy carries the source MAC.
    #[serde(default)]
    pub mac: Option<String>,
    #[serde(default)]
    pub label: Option<String>,
}

/// The `webrtc` section of the gateway configuration.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WebRtcConfig {
    #[serde(default)]
    pub action: WebRtcAction,
    /// The robot's WebRTC addresses (IPv4). Default 192.168.123.161.
    #[serde(default = "default_robots")]
    pub robot_addresses: Vec<String>,
    /// Default 8081, 9991.
    #[serde(default = "default_ports")]
    pub signalling_ports: Vec<u16>,
    #[serde(default)]
    pub controllers: Vec<WebRtcController>,
    /// `[DAYS ]HH:MM-HH:MM` (UTC), see `DenyWindow::parse`.
    #[serde(default)]
    pub deny_windows: Vec<String>,
    /// Most sessions established at once (default 1).
    #[serde(default)]
    pub max_sessions: Option<usize>,
    /// NFLOG group of the controller-side copies (default 4175; must differ
    /// from `observe.nflog_group`).
    #[serde(default = "default_group")]
    pub nflog_group: u16,
}

fn default_robots() -> Vec<String> {
    vec!["192.168.123.161".into()]
}
fn default_ports() -> Vec<u16> {
    DEFAULT_SIGNALLING_PORTS.to_vec()
}
fn default_group() -> u16 {
    4175
}

impl WebRtcConfig {
    /// The robot addresses, parsed.
    pub fn robots(&self) -> Result<Vec<Ipv4Addr>, String> {
        self.robot_addresses
            .iter()
            .map(|s| {
                s.parse::<Ipv4Addr>()
                    .map_err(|_| format!("webrtc.robot_addresses: {s:?} is not an IPv4 address"))
            })
            .collect()
    }

    /// The controller IPs, parsed.
    pub fn controller_ips(&self) -> Result<Vec<Ipv4Addr>, String> {
        self.controllers
            .iter()
            .map(|c| {
                c.ip.parse::<Ipv4Addr>()
                    .map_err(|_| format!("webrtc.controllers: {:?} is not an IPv4 address", c.ip))
            })
            .collect()
    }

    /// Validate and build the monitor's options.
    pub fn monitor_options(&self) -> Result<WebRtcOptions, String> {
        let robots = self.robots()?;
        if robots.is_empty() || robots.len() > 16 {
            return Err("webrtc.robot_addresses: 1 to 16 addresses".into());
        }
        if self.signalling_ports.is_empty()
            || self.signalling_ports.len() > 16
            || self.signalling_ports.contains(&0)
        {
            return Err("webrtc.signalling_ports: 1 to 16 non-zero ports".into());
        }
        if self.controllers.len() > 64 {
            return Err("webrtc.controllers: at most 64".into());
        }
        if self.action == WebRtcAction::BlockUnlisted && self.controllers.is_empty() {
            return Err(
                "webrtc.action block_unlisted needs webrtc.controllers (it would drop every \
                 controller's signalling)"
                    .into(),
            );
        }
        let mut controllers = std::collections::BTreeMap::new();
        for (c, ip) in self.controllers.iter().zip(self.controller_ips()?) {
            let mac = match &c.mac {
                Some(m) => Some(crate::gateway::parse_mac(m).ok_or_else(|| {
                    format!("webrtc.controllers: mac {m:?} is not aa:bb:cc:dd:ee:ff")
                })?),
                None => None,
            };
            if robots.contains(&ip) {
                return Err(format!("webrtc.controllers: {ip} is a robot address"));
            }
            if controllers.insert(IpAddr::V4(ip), mac).is_some() {
                return Err(format!("webrtc.controllers: {ip} listed twice"));
            }
        }
        let deny_windows = self
            .deny_windows
            .iter()
            .map(|w| DenyWindow::parse(w))
            .collect::<Result<Vec<_>, _>>()?;
        let max_sessions = self.max_sessions.unwrap_or(1);
        if !(1..=16).contains(&max_sessions) {
            return Err("webrtc.max_sessions must be in 1..=16".into());
        }
        Ok(WebRtcOptions {
            enabled: true,
            robot_addresses: robots.into_iter().map(IpAddr::V4).collect(),
            signalling_ports: self.signalling_ports.iter().copied().collect(),
            controllers,
            deny_windows,
            max_sessions,
            ..WebRtcOptions::default()
        })
    }
}

fn set_of<T: std::fmt::Display>(v: &[T]) -> String {
    let items: Vec<String> = v.iter().map(ToString::to_string).collect();
    format!("{{ {} }}", items.join(", "))
}

/// The `nft` table of section 6 of the ruleset (see the module docs).
pub fn render_nft(w: &WebRtcConfig) -> String {
    let robots = set_of(&w.robots().unwrap_or_default());
    let ports = set_of(&w.signalling_ports);
    let mut s = String::new();
    s.push_str(
        "nft -f - <<EOF\n\
         table bridge robodr_gw_rtc\n\
         delete table bridge robodr_gw_rtc\n\
         table bridge robodr_gw_rtc {\n\
         \x20 set blocked_peers { type ipv4_addr; flags timeout; }\n\
         \x20 set blocked_flows { type ipv4_addr . inet_service . ipv4_addr . inet_service; flags timeout; }\n\
         \x20 chain forward {\n\
         \x20   type filter hook forward priority -190; policy accept;\n",
    );
    s.push_str(&format!(
        "    iifname \"$CTRL\" ip daddr {robots} ip saddr @blocked_peers counter drop\n\
         \x20   iifname \"$ROBOT\" ip saddr {robots} ip daddr @blocked_peers counter drop\n\
         \x20   iifname \"$CTRL\" ip saddr . udp sport . ip daddr . udp dport @blocked_flows counter drop\n\
         \x20   iifname \"$ROBOT\" ip daddr . udp dport . ip saddr . udp sport @blocked_flows counter drop\n"
    ));
    if w.action == WebRtcAction::BlockUnlisted {
        let ctrl = set_of(&w.controller_ips().unwrap_or_default());
        s.push_str(&format!(
            "    iifname \"$CTRL\" ip daddr {robots} tcp dport {ports} ip saddr != {ctrl} counter drop\n"
        ));
    }
    s.push_str("  }\n}\nEOF\n");
    s
}

/// One quarantine element for `nft add element` (see the module docs).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BlockTarget {
    pub peer: Ipv4Addr,
    /// `(peer port, robot address, robot port)`: one UDP flow; `None`:
    /// every packet between the peer and the robot addresses.
    pub flow: Option<(u16, Ipv4Addr, u16)>,
    /// Seconds, `1..=86400`.
    pub timeout_s: u64,
}

impl BlockTarget {
    /// Parse `--peer IP [--flow PEER_PORT,ROBOT_IP,ROBOT_PORT] [--timeout-s N]`
    /// (default 600 s).
    pub fn parse_args(args: &[String]) -> Result<Self, String> {
        let mut peer = None;
        let mut flow = None;
        let mut timeout_s = 600u64;
        let mut it = args.iter();
        while let Some(a) = it.next() {
            let v = it.next().ok_or_else(|| format!("{a}: missing value"))?;
            match a.as_str() {
                "--peer" => {
                    peer = Some(
                        v.parse::<Ipv4Addr>()
                            .map_err(|_| format!("--peer {v:?}: not an IPv4 address"))?,
                    )
                }
                "--flow" => {
                    let p: Vec<&str> = v.split(',').collect();
                    let bad = || format!("--flow {v:?}: expected PEER_PORT,ROBOT_IP,ROBOT_PORT");
                    let [pp, ip, rp] = p.as_slice() else {
                        return Err(bad());
                    };
                    let port = |s: &str| s.parse::<u16>().ok().filter(|p| *p != 0);
                    flow = Some((
                        port(pp).ok_or_else(bad)?,
                        ip.parse::<Ipv4Addr>().map_err(|_| bad())?,
                        port(rp).ok_or_else(bad)?,
                    ));
                }
                "--timeout-s" => {
                    timeout_s = v
                        .parse()
                        .ok()
                        .filter(|t| (1..=86_400).contains(t))
                        .ok_or_else(|| format!("--timeout-s {v:?}: 1..=86400"))?;
                }
                _ => return Err(format!("unknown argument {a}")),
            }
        }
        Ok(BlockTarget {
            peer: peer.ok_or("--peer is required")?,
            flow,
            timeout_s,
        })
    }

    /// The `nft` argv that adds this element (every value was parsed into
    /// an address or a number, so the words are safe to print or exec).
    pub fn nft_argv(&self) -> Vec<String> {
        let (set, elem) = match self.flow {
            None => ("blocked_peers", self.peer.to_string()),
            Some((pp, rip, rp)) => (
                "blocked_flows",
                format!("{} . {pp} . {rip} . {rp}", self.peer),
            ),
        };
        vec![
            "nft".into(),
            "add".into(),
            "element".into(),
            "bridge".into(),
            "robodr_gw_rtc".into(),
            set.into(),
            format!("{{ {elem} timeout {}s }}", self.timeout_s),
        ]
    }
}
