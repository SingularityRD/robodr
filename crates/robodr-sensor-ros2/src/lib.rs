//! RoboDR ROS 2 / DDS graph sensor, packaged as a Pulsar module.
//!
//! It passively joins the SPDP discovery multicast group, parses participant
//! announcements, and checks each one against the robot's locked model profile
//! ([`robodr_events::profile::Profile`]). A deviation becomes a Pulsar threat
//! on the shared bus, where the rules engine, the loggers, and the AutoSecOps
//! bridge already consume threats — so this sensor needs no new plumbing
//! downstream.
//!
//! It is **read-only on the network**: it opens one receive socket and never
//! transmits. Enforcement (restricting motion, rejecting a participant) is the
//! Motion Firewall's and the responder's job, never this sensor's.
//!
//! ## Known gap: SEDP is usually unicast
//!
//! The parser (`rtps`) handles both SPDP participant and SEDP writer/reader
//! announcements. This listener, however, binds the SPDP **multicast** group,
//! and most DDS implementations send SEDP **unicast** to each participant's
//! metatraffic port. So today this module reliably reports *participants*;
//! writer/reader (topic-level) detection needs a capture-based listener that
//! sees unicast metatraffic on the robot's interfaces and loopback (AF_PACKET or
//! an eBPF socket filter feeding the same `rtps::parse_datagram`). That is the
//! next sensor task (docs/SPRINTS.md, Sprint 2). Whether a given DDS vendor
//! moves local discovery onto shared memory is a lab-validation item, per vendor.

mod rtps;

use std::collections::HashSet;
use std::net::Ipv4Addr;
use std::path::PathBuf;

use pulsar_core::event::Value;
use pulsar_core::pdk::{ModuleContext, ModuleError, SimplePulsarModule};
use pulsar_core::{Pid, Timestamp};
use robodr_events::profile::Profile;
use serde::Deserialize;
use tokio::net::UdpSocket;
use tokio::task::JoinHandle;

/// Config block (under `[robodr-sensor-ros2]` in the Pulsar config).
#[derive(Debug, Clone, Deserialize)]
pub struct Config {
    /// Path to the locked model profile (JSON). See `config/profile.example.json`.
    pub profile_path: PathBuf,
    /// SPDP multicast group. DDS default is 239.255.0.1.
    #[serde(default = "default_group")]
    pub spdp_group: Ipv4Addr,
    /// SPDP port. For RTPS domain 0 the discovery port is 7400.
    #[serde(default = "default_port")]
    pub spdp_port: u16,
    /// Local interface address to join the group on (0.0.0.0 = default route).
    #[serde(default = "default_iface")]
    pub interface: Ipv4Addr,
}

fn default_group() -> Ipv4Addr {
    Ipv4Addr::new(239, 255, 0, 1)
}
fn default_port() -> u16 {
    7400
}
fn default_iface() -> Ipv4Addr {
    Ipv4Addr::UNSPECIFIED
}

pub struct Ros2Sensor;

pub struct State {
    listener: JoinHandle<()>,
}

impl SimplePulsarModule for Ros2Sensor {
    type Config = Config;
    type State = State;

    const MODULE_NAME: &'static str = "robodr-sensor-ros2";
    const DEFAULT_ENABLED: bool = false;

    async fn init_state(
        &self,
        config: &Self::Config,
        ctx: &ModuleContext,
    ) -> Result<Self::State, ModuleError> {
        let profile = load_profile(&config.profile_path)?;
        if !profile.locked {
            log::warn!(
                "robodr: profile '{}' is NOT locked — running in observe mode, \
                 reporting deviations only",
                profile.model
            );
        }

        let socket = bind_spdp(config).await?;
        let ctx = ctx.clone();
        let listener = tokio::spawn(listen_loop(socket, profile, ctx));
        Ok(State { listener })
    }

    async fn graceful_stop(state: Self::State) -> Result<(), ModuleError> {
        state.listener.abort();
        Ok(())
    }
}

fn load_profile(path: &PathBuf) -> Result<Profile, ModuleError> {
    let raw = std::fs::read_to_string(path)
        .map_err(|e| format!("reading profile {}: {e}", path.display()))?;
    let profile: Profile = serde_json::from_str(&raw)
        .map_err(|e| format!("parsing profile {}: {e}", path.display()))?;
    Ok(profile)
}

async fn bind_spdp(config: &Config) -> Result<UdpSocket, ModuleError> {
    // Bind to the SPDP port on all interfaces, then join the multicast group.
    let bind_addr = (Ipv4Addr::UNSPECIFIED, config.spdp_port);
    let socket = UdpSocket::bind(bind_addr)
        .await
        .map_err(|e| format!("binding SPDP {}: {e}", config.spdp_port))?;
    socket
        .join_multicast_v4(config.spdp_group, config.interface)
        .map_err(|e| format!("joining SPDP group {}: {e}", config.spdp_group))?;
    log::info!(
        "robodr: ROS 2 sensor listening on {}:{}",
        config.spdp_group,
        config.spdp_port
    );
    Ok(socket)
}

/// Upper bound on remembered deviations. Discovery beacons repeat every few
/// seconds, so without dedup one rogue participant would raise a threat per
/// beacon; without a bound, an attacker spraying random GUIDs onto the bus
/// could grow the set until the sensor runs out of memory. When the bound is
/// hit the set is cleared: worst case, a still-present deviation is reported
/// again, which is the safe direction to fail.
const MAX_SEEN: usize = 4096;

/// Receive loop: parse each datagram, evaluate against the profile, raise a
/// threat per *new* deviation.
async fn listen_loop(socket: UdpSocket, profile: Profile, ctx: ModuleContext) {
    let mut buf = vec![0u8; 65_535];
    let mut seen: HashSet<String> = HashSet::new();
    loop {
        let (len, peer) = match socket.recv_from(&mut buf).await {
            Ok(v) => v,
            Err(e) => {
                log::warn!("robodr: SPDP recv error: {e}");
                continue;
            }
        };
        let src_ip = peer.ip().to_string();
        for event in rtps::parse_datagram(&buf[..len], &src_ip) {
            let Some(dev) = profile.evaluate(&event) else {
                continue;
            };
            // Dedup on the deviation itself (rule + detail, which names the
            // GUID, topic and source), so each distinct deviation is reported
            // once, not once per beacon — and two different rogue topics from
            // the same host are still two reports.
            if seen.len() >= MAX_SEEN {
                log::warn!("robodr: dedup set reached {MAX_SEEN}, clearing");
                seen.clear();
            }
            if !seen.insert(format!("{}|{}", dev.rule, dev.detail)) {
                continue;
            }
            let extra = Value::try_from(&dev).ok();
            ctx.send_threat(Pid::this(), Timestamp::now(), dev.detail.clone(), extra);
            log::info!("robodr: [{}] {}", dev.rule, dev.detail);
        }
    }
}
