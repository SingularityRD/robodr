//! The per-datagram decision: [`Gateway::process`] (see the crate docs for
//! the full semantics).

use std::collections::HashMap;
use std::net::Ipv4Addr;
use std::time::Instant;

use robodr_cdr::unitree::{decode_unitree, UnitreeKind, UnitreeMessage};
use robodr_cdr::{ApiCall, Limits};
use robodr_events::profile::Profile;
use robodr_firewall::{
    ChannelId, ChannelKind, Command, Firewall, FirewallConfig, JointCommand, JointFrame,
    JointVerdict, Morphology, Motion, SourceId, Twist, Vec3, Verdict as FwVerdict,
    IDENTITY_SOURCE_PREFIX,
};
use robodr_ros2_pipeline::IdentityResolver;
use serde::Serialize;

use crate::config::{
    Codec, GatewayConfig, GatewayMode, LocoModel, MalformedPolicy, OnGatewayDown, UnknownWriters,
};
use crate::discovery::{Discovery, WriterInfo};
use crate::ip::{parse_ipv4_udp, refresh_udp_checksum};
use crate::lowcmd::{self, Forwarded, LowCmdCodec, WireLowCmd};
use crate::rtps::{self, Content, Guid, Sample, SampleKind, WalkOptions};
use crate::{armsdk, hand, legacy, ros2, sport};
use robodr_cdr::unitree::{ApiClass, ApiService};

/// What to tell the kernel about one queued packet.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Verdict {
    /// Forward unchanged.
    Accept,
    /// Forward the (same-length) rewritten packet.
    AcceptModified,
    /// Do not forward.
    Drop,
}

/// Per-packet inputs besides the bytes.
#[derive(Debug, Clone, Copy)]
pub struct PacketMeta {
    /// Gateway clock (monotonic, ns): the firewall's `now` and every
    /// command's stamp (a sender's timestamp is never trusted).
    pub now_ns: u64,
    /// How long the packet waited in the kernel queue, if known.
    pub queue_delay_ns: Option<u64>,
    /// Wall-clock instant (identity leases).
    pub instant: Instant,
    /// Source MAC of the frame (`NFQA_HWADDR`), when the kernel reported
    /// one. Part of a writer's binding (see the crate docs, "Sequence
    /// numbers and writer binding").
    pub src_mac: Option<[u8; 6]>,
}

/// What happened to one decided sample.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Outcome {
    /// Forwarded unchanged.
    Pass,
    /// Rewritten in place (limited or substitute).
    Rewritten,
    /// Removed (PAD, or the datagram dropped for legacy UDP).
    Suppress,
}

/// Counters (status file).
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize)]
pub struct GatewayStats {
    pub packets: u64,
    pub accepted: u64,
    pub modified: u64,
    pub dropped: u64,
    /// Not IPv4 / UDP, IP fragment, bad checksum, bad length.
    pub dropped_ip: u64,
    /// Whole RTPS datagram undecidable (malformed, secure, ...).
    pub rtps_malformed: u64,
    /// Packets on a port no channel covers (the ruleset should not queue
    /// them).
    pub unmatched_port: u64,
    pub discovery_datagrams: u64,
    /// Samples of an enforced channel.
    pub samples: u64,
    pub passed: u64,
    pub limited: u64,
    pub substituted: u64,
    pub suppressed: u64,
    /// Payload not strictly decodable (decided as an integrity failure).
    pub undecidable: u64,
    /// DATA_FRAG / key-only / non-standard samples on an enforced channel.
    pub unsupported_sample: u64,
    /// Old sequence numbers (retransmission or replay).
    pub replays: u64,
    pub replays_reemitted: u64,
    /// Decided with the fault verdict because the packet was too late.
    pub late: u64,
    /// A rewrite the firewall asked for failed (the sample was suppressed).
    pub rewrite_failed: u64,
    /// Unknown writers classified by a content probe.
    pub probed: u64,
    /// Sport requests with an api id outside `i32` (aliasing).
    pub api_alias: u64,
    /// Requests / `HighCmd` modes refused by the allowlist.
    pub not_allowlisted: u64,
    /// Observe mode: packets that enforcement would have changed.
    pub observe_would_modify: u64,
    pub observe_would_drop: u64,
    /// Samples of an authorised GUID from another (IP, MAC) than the one
    /// the writer's stream is bound to (suppressed, state untouched).
    pub binding_conflicts: u64,
    /// Sequence-number jumps beyond `rtps.max_sn_jump` held back until
    /// confirmed (suppressed, state untouched).
    pub sn_jumps: u64,
    /// Writer restarts (lower sequence number after a new SEDP
    /// announcement) that reset a writer's sequence state.
    pub writer_restarts: u64,
    /// Unknown-writer DATA_FRAG / key-only / non-standard samples that
    /// cannot be probed (suppressed in enforce mode).
    pub unknown_undecidable: u64,
    /// `LowCmd_` frames refused for a non-motor field (`bms_cmd.off`).
    pub non_motor_rejected: u64,
    /// Loco requests refused before the firewall: a `SetFsmId` that is not
    /// the model's `Start` and not in `allowed_fsm_ids` (damp, zero torque,
    /// posture changes), a call not in `allowed_api_ids`, an unknown or
    /// malformed non-velocity call.
    pub loco_refused: u64,
    /// `SetVelocity` durations rewritten down to `max_velocity_duration_s`.
    pub duration_capped: u64,
    /// Arm-SDK frames whose blend-weight slot was refused (decided as an
    /// integrity failure).
    pub arm_weight_rejected: u64,
    /// Hand frames forwarded unchanged (the firewall passed them).
    pub hand_passed: u64,
    /// Hand frames suppressed (anything the firewall did not pass as is).
    pub hand_suppressed: u64,
    /// Arm-SDK frames refused for the weight's step per frame (counted in
    /// `arm_weight_rejected` too).
    pub arm_weight_step_rejected: u64,
    /// ... for the weight's rate per second.
    pub arm_weight_rate_rejected: u64,
    /// ... for an engagement that could not be verified (targets away from
    /// `rt/lowstate`, or above the first step without stable targets).
    pub arm_engage_rejected: u64,
    /// Hand frames refused for a mode octet / hand-SDK weight (F5; counted
    /// in `hand_suppressed` too).
    pub hand_mode_rejected: u64,
    /// Arm action requests refused (`unitree_arm_request`).
    pub arm_request_refused: u64,
    /// Loco twist state reset because a `SetVelocity` duration ended.
    pub velocity_expired: u64,
    /// Robot-side packets observed (NFLOG copies; never verdicted).
    pub observed_packets: u64,
    /// `rt/lowstate` samples taken from them.
    pub lowstate_samples: u64,
}

/// One cached decision for a writer's sequence number.
#[derive(Debug, Clone)]
struct CacheEntry {
    sn: i64,
    /// `None` = suppressed; `Some` = the payload bytes forwarded.
    bytes: Option<Vec<u8>>,
}

const RING: usize = 8;

/// Where a sample came from on the wire: its source IP and, when the
/// kernel reported it, its source MAC.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
struct Binding {
    ip: Ipv4Addr,
    mac: Option<[u8; 6]>,
}

/// Per writer GUID and enforced channel: the sequence / replay state of the
/// stream the robot's reader sees under that GUID. Only samples of the
/// authorised source **from the bound (IP, MAC)** change it (see the crate
/// docs, "Sequence numbers and writer binding").
#[derive(Debug, Clone, Default)]
struct WriterState {
    /// The (IP, MAC) of the last sample forwarded under this GUID.
    bound: Option<Binding>,
    /// Gateway clock of the last sample seen from the bound side (forwarded
    /// or not): its liveness for a takeover.
    bound_at: u64,
    /// Highest sequence number forwarded under this GUID (passed, limited
    /// or substitute): the replay boundary and the jump anchor.
    last_sn: Option<i64>,
    /// An unconfirmed jump (> `max_sn_jump` past `last_sn`) and the binding
    /// it came from.
    pending_jump: Option<(i64, Binding)>,
    /// An SEDP announcement / removal of this writer from the bound IP was
    /// seen since the last forwarded sample: the next lower sequence number
    /// may be a restart.
    restart_armed: bool,
    used: u64,
    /// What the GUID resolves to in the policy, whatever IP it came from
    /// (cached per identity epoch).
    claimed: Option<(SourceId, u64)>,
    ring: Vec<CacheEntry>,
    next: usize,
}

impl WriterState {
    /// Forget the sequence state (writer restart); the binding stays.
    fn reset_sequence(&mut self) {
        self.last_sn = None;
        self.pending_jump = None;
        self.restart_armed = false;
        self.ring.clear();
        self.next = 0;
    }

    fn remember(&mut self, sn: i64, bytes: Option<&[u8]>) {
        let entry = if self.ring.len() < RING {
            self.ring.push(CacheEntry { sn, bytes: None });
            self.ring.len() - 1
        } else {
            let i = self.next % RING;
            self.next = (self.next + 1) % RING;
            i
        };
        if let Some(e) = self.ring.get_mut(entry) {
            e.sn = sn;
            match (bytes, &mut e.bytes) {
                (Some(b), Some(v)) => {
                    v.clear();
                    v.extend_from_slice(b);
                }
                (Some(b), slot) => *slot = Some(b.to_vec()),
                (None, slot) => *slot = None,
            }
        }
    }

    fn lookup(&self, sn: i64) -> Option<&CacheEntry> {
        self.ring.iter().find(|e| e.sn == sn)
    }
}

/// Last accepted frame of a legacy channel.
#[derive(Debug, Clone)]
struct LegacyLast {
    frame: Option<JointFrame>,
    bytes: Vec<u8>,
}

#[derive(Debug)]
struct Channel {
    name: String,
    id: ChannelId,
    codec: Codec,
    ports: Vec<u16>,
    allowed_ips: Vec<Ipv4Addr>,
    legacy_sources: Vec<(Ipv4Addr, SourceId)>,
    allowed_api_ids: Option<Vec<i64>>,
    allowed_modes: Option<Vec<u8>>,
    allowed_macs: Vec<[u8; 6]>,
    allow_battery_off: bool,
    /// `unitree_loco_request`.
    robot_model: Option<LocoModel>,
    allowed_fsm_ids: Option<Vec<i64>>,
    max_duration_s: f64,
    /// Arm-SDK codecs: the blend-weight slot and its bound.
    weight_slot: Option<usize>,
    max_weight: f64,
    /// Hand codecs: the element count (the firewall channel's motors).
    hand_slots: usize,
    /// Arm-SDK / hand-SDK: the blend weight's dynamics and state.
    weight_dyn: crate::config::WeightDynamics,
    arm_weight: armsdk::WeightState,
    /// Hand SDK: the last forwarded weight × 100 and when.
    hand_weight: Option<(u8, u64)>,
    /// Loco: when the robot stops on its own (the last forwarded
    /// `SetVelocity`'s duration ends), gateway clock.
    velocity_until: Option<u64>,
    writers: HashMap<Guid, WriterState>,
    max_writers: usize,
    tick: u64,
    last_low: Option<Forwarded>,
    last_legacy: Option<LegacyLast>,
}

impl Channel {
    fn lowcmd_codec(&self) -> Option<LowCmdCodec> {
        match self.codec {
            Codec::UnitreeGoLowcmd | Codec::UnitreeGoArmSdk => Some(LowCmdCodec::Go),
            Codec::UnitreeHgLowcmd | Codec::UnitreeHgArmSdk => Some(LowCmdCodec::Hg),
            _ => None,
        }
    }

    /// The api service and model a request channel decodes for.
    fn api(&self) -> (ApiService, Option<robodr_cdr::unitree::UnitreeModel>) {
        if self.codec == Codec::UnitreeArmRequest {
            return (ApiService::Arm, self.robot_model.map(LocoModel::unitree));
        }
        match self.robot_model {
            Some(LocoModel::H1) => (ApiService::Loco, Some(LocoModel::H1.unitree())),
            Some(m) => (ApiService::Sport, Some(m.unitree())),
            None => (ApiService::Sport, None),
        }
    }

    fn writer_mut(&mut self, g: &Guid) -> &mut WriterState {
        self.tick += 1;
        let tick = self.tick;
        if !self.writers.contains_key(g) && self.writers.len() >= self.max_writers {
            // Evict a writer that never forwarded anything first (least
            // recently used among those), so a flood of spoofed GUIDs
            // cannot push out the authorised writer's sequence / replay
            // state.
            if let Some(old) = self
                .writers
                .iter()
                .min_by_key(|(_, w)| {
                    let authorised =
                        w.bound.is_some() || w.claimed.is_some_and(|(s, _)| s != SourceId::UNKNOWN);
                    (authorised, w.used)
                })
                .map(|(k, _)| *k)
            {
                self.writers.remove(&old);
            }
        }
        let w = self.writers.entry(*g).or_default();
        w.used = tick;
        w
    }

    fn ip_allowed(&self, ip: Ipv4Addr) -> bool {
        self.allowed_ips.is_empty() || self.allowed_ips.contains(&ip)
    }

    fn mac_allowed(&self, mac: Option<[u8; 6]>) -> bool {
        self.allowed_macs.is_empty() || mac.is_some_and(|m| self.allowed_macs.contains(&m))
    }
}

/// Parse `aa:bb:cc:dd:ee:ff` (also `-` separated, any case).
pub fn parse_mac(s: &str) -> Option<[u8; 6]> {
    let mut out = [0u8; 6];
    let mut parts = s.split([':', '-']);
    for b in out.iter_mut() {
        let p = parts.next()?;
        if p.len() != 2 {
            return None;
        }
        *b = u8::from_str_radix(p, 16).ok()?;
    }
    parts.next().is_none().then_some(out)
}

/// The in-path gateway (see the crate docs).
pub struct Gateway {
    mode: GatewayMode,
    fw: Firewall,
    channels: Vec<Channel>,
    rtps_ranges: Vec<(u16, u16)>,
    malformed: MalformedPolicy,
    unknown_writers: UnknownWriters,
    max_sn_jump: i64,
    binding_takeover_ns: u64,
    discovery: Discovery,
    samples: Vec<Sample>,
    scratch: Vec<u8>,
    max_queue_delay_ns: u64,
    /// Robot-side observation (NFLOG copies): `rt/lowstate` and the
    /// robot's discovery (see [`Gateway::observe`]).
    observer: crate::observe::Observer,
    pub stats: GatewayStats,
}

impl std::fmt::Debug for Gateway {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Gateway")
            .field("mode", &self.mode)
            .field("channels", &self.channels.len())
            .field("stats", &self.stats)
            .finish()
    }
}

fn hex(b: &[u8]) -> String {
    let mut s = String::with_capacity(b.len() * 2);
    for x in b {
        s.push_str(&format!("{x:02x}"));
    }
    s
}

fn twist(vx: f64, vy: f64, vyaw: f64) -> Motion {
    Motion::Twist(Twist::new(
        Vec3::new(vx, vy, 0.0),
        Vec3::new(0.0, 0.0, vyaw),
    ))
}

fn twist_values(c: &Command) -> Option<[f64; 3]> {
    match &c.motion {
        Motion::Twist(t) => Some([t.linear.x, t.linear.y, t.angular.z]),
        Motion::Joints(_) => None,
    }
}

impl Gateway {
    /// Build the gateway: compile the firewall policy, check every channel
    /// against it and the profile (fails closed; see the crate docs).
    pub fn new(
        cfg: &GatewayConfig,
        profile: &Profile,
        fwcfg: &FirewallConfig,
    ) -> Result<Self, String> {
        cfg.validate()?;
        let policy = fwcfg
            .compile(profile)
            .map_err(|e| format!("firewall configuration: {e:?}"))?;
        if cfg.mode == GatewayMode::Enforce
            && (policy.is_observe_only() || !policy.profile_locked())
        {
            return Err(
                "mode enforce needs a locked profile and a platform that is not \
                 pass_through_observe_only (the firewall would only observe); use mode observe"
                    .into(),
            );
        }
        let platform = *policy.platform();
        let humanoid = platform.morphology == Morphology::Humanoid;
        let mut channels = Vec::new();
        for c in &cfg.channels {
            let at = format!("channel {}", c.firewall_channel);
            let id = policy
                .channel_id(&c.firewall_channel)
                .ok_or_else(|| format!("{at}: not a channel of the firewall configuration"))?;
            if c.codec.is_joint() {
                let spec = fwcfg
                    .joint_channels
                    .get(&c.firewall_channel)
                    .ok_or_else(|| {
                        format!(
                            "{at}: codec {} needs a firewall joint_channels entry",
                            c.codec.as_str()
                        )
                    })?;
                let want = c.codec.slots().unwrap_or(spec.motors.len());
                if spec.motors.len() != want || want == 0 {
                    return Err(format!(
                        "{at}: the firewall channel has {} motor slots, codec {} carries {want}",
                        spec.motors.len(),
                        c.codec.as_str()
                    ));
                }
                if !spec.balance_critical && !c.codec.is_hand() {
                    return Err(format!(
                        "{at}: balance_critical: false is for hand channels only (a hand is not \
                         in the balance loop; a body channel that may go all-limp lets a humanoid \
                         fall)"
                    ));
                }
                if let Some(w) = c.weight_slot {
                    if spec.motors.get(w).is_none_or(|m| m.enabled) {
                        return Err(format!(
                            "{at}: weight_slot {w} must be a disabled motor of the firewall \
                             channel (it is the arm-SDK blend weight, not a motor)"
                        ));
                    }
                }
                if humanoid && cfg.queue.on_gateway_down == OnGatewayDown::Bypass {
                    return Err(format!(
                        "{at}: queue.on_gateway_down bypass is refused on a humanoid joint channel: \
                         a stopped gateway would forward unchecked frames to the motors \
                         (the firewall refuses fail_open there for the same reason)"
                    ));
                }
            } else {
                let spec = fwcfg.channels.get(&c.firewall_channel).ok_or_else(|| {
                    format!(
                        "{at}: codec {} needs a firewall twist channel",
                        c.codec.as_str()
                    )
                })?;
                if spec.kind != ChannelKind::Twist {
                    return Err(format!("{at}: codec {} needs kind twist", c.codec.as_str()));
                }
                if humanoid && c.codec == Codec::UnitreeSportRequest {
                    return Err(format!(
                        "{at}: a humanoid's locomotion requests (SetVelocity, SetFsmId ...) are \
                         decided by codec unitree_loco_request with robot_model, not \
                         unitree_sport_request"
                    ));
                }
            }
            if let Some(t) = profile.motion_types.get(&c.firewall_channel) {
                let expect = c.codec.dds_type_name();
                if expect != t {
                    return Err(format!(
                        "{at}: the profile says its type is {t}, codec {} decodes {expect}",
                        c.codec.as_str(),
                    ));
                }
            }
            // `identity:` sources need SPDP-based resolution; identities
            // that also require node evidence cannot be confirmed here.
            let allowed: Vec<&String> = fwcfg
                .channels
                .get(&c.firewall_channel)
                .map(|s| s.allowed_sources.iter().collect())
                .or_else(|| {
                    fwcfg
                        .joint_channels
                        .get(&c.firewall_channel)
                        .map(|s| s.allowed_sources.iter().collect())
                })
                .unwrap_or_default();
            for s in allowed {
                if let Some(name) = s.strip_prefix(IDENTITY_SOURCE_PREFIX) {
                    if profile
                        .participant_identities
                        .get(name)
                        .is_some_and(|i| !i.nodes.is_empty())
                        && c.codec.is_rtps()
                    {
                        return Err(format!(
                            "{at}: source {s}: identities with `nodes` cannot be confirmed by the \
                             gateway (it does not track ROS node evidence); list the identity \
                             without nodes, or the writer GUID / participant prefix"
                        ));
                    }
                }
            }
            let mut legacy_sources = Vec::new();
            for (ip, s) in &c.legacy_sources {
                let ip: Ipv4Addr = ip.parse().map_err(|_| format!("{at}: bad IP {ip}"))?;
                let sid = policy.source_id(s).ok_or_else(|| {
                    format!("{at}: legacy source {s} is not a source of the firewall configuration")
                })?;
                legacy_sources.push((ip, sid));
            }
            channels.push(Channel {
                name: c.firewall_channel.clone(),
                id,
                codec: c.codec,
                ports: c.ports(),
                allowed_ips: c
                    .allowed_src_ips
                    .iter()
                    .filter_map(|s| s.parse().ok())
                    .collect(),
                legacy_sources,
                allowed_api_ids: c.allowed_api_ids.clone(),
                allowed_modes: c.allowed_high_modes.clone(),
                allowed_macs: c
                    .allowed_src_macs
                    .iter()
                    .map(|m| parse_mac(m).ok_or_else(|| format!("{at}: bad MAC {m}")))
                    .collect::<Result<_, _>>()?,
                allow_battery_off: c.allow_battery_off,
                robot_model: c.robot_model,
                allowed_fsm_ids: c.allowed_fsm_ids.clone(),
                max_duration_s: c.max_duration_s(),
                weight_slot: c.weight_slot,
                max_weight: c.max_weight.unwrap_or(1.0),
                hand_slots: fwcfg
                    .joint_channels
                    .get(&c.firewall_channel)
                    .map_or(0, |s| s.motors.len()),
                weight_dyn: c.weight_dynamics(),
                arm_weight: armsdk::WeightState::default(),
                hand_weight: None,
                velocity_until: None,
                writers: HashMap::new(),
                max_writers: cfg.rtps.max_writers_per_channel,
                tick: 0,
                last_low: None,
                last_legacy: None,
            });
        }
        let topics = cfg
            .channels
            .iter()
            .map(|c| {
                c.codec
                    .is_rtps()
                    .then(|| c.topic().unwrap_or("").to_string())
            })
            .collect();
        Ok(Self {
            mode: cfg.mode,
            fw: Firewall::new(policy),
            channels,
            rtps_ranges: cfg.rtps_port_ranges(),
            malformed: cfg.rtps.malformed_datagram,
            unknown_writers: cfg.rtps.unknown_writers,
            max_sn_jump: i64::try_from(cfg.rtps.max_sn_jump).unwrap_or(i64::MAX),
            binding_takeover_ns: cfg.rtps.binding_takeover_ns,
            discovery: Discovery::new(topics, cfg.rtps.max_writers, IdentityResolver::new(profile))
                .with_queued_ranges(cfg.rtps_port_ranges()),
            samples: Vec::with_capacity(rtps::MAX_SAMPLES),
            scratch: Vec::with_capacity(65_536),
            max_queue_delay_ns: cfg.max_queue_delay_ns,
            observer: crate::observe::Observer::new(cfg),
            stats: GatewayStats::default(),
        })
    }

    pub fn firewall(&self) -> &Firewall {
        &self.fw
    }

    pub fn firewall_mut(&mut self) -> &mut Firewall {
        &mut self.fw
    }

    pub fn discovery(&self) -> &Discovery {
        &self.discovery
    }

    pub fn discovery_mut(&mut self) -> &mut Discovery {
        &mut self.discovery
    }

    pub fn mode(&self) -> GatewayMode {
        self.mode
    }

    /// Decide one queued packet (the IPv4 packet, rewritten in place when
    /// the verdict is [`Verdict::AcceptModified`]; same length always).
    pub fn process(&mut self, pkt: &mut [u8], meta: PacketMeta) -> Verdict {
        self.stats.packets += 1;
        let v = if self.mode == GatewayMode::Observe {
            let mut scratch = std::mem::take(&mut self.scratch);
            scratch.clear();
            scratch.extend_from_slice(pkt);
            let v = self.decide(&mut scratch, meta);
            self.scratch = scratch;
            match v {
                Verdict::AcceptModified => self.stats.observe_would_modify += 1,
                Verdict::Drop => self.stats.observe_would_drop += 1,
                Verdict::Accept => {}
            }
            Verdict::Accept
        } else {
            self.decide(pkt, meta)
        };
        match v {
            Verdict::Accept => self.stats.accepted += 1,
            Verdict::AcceptModified => self.stats.modified += 1,
            Verdict::Drop => self.stats.dropped += 1,
        }
        v
    }

    fn decide(&mut self, pkt: &mut [u8], meta: PacketMeta) -> Verdict {
        let Ok(ip) = parse_ipv4_udp(pkt) else {
            self.stats.dropped_ip += 1;
            return Verdict::Drop;
        };
        let port = ip.dst_port;
        let modified = if let Some(ci) = self
            .channels
            .iter()
            .position(|c| !c.codec.is_rtps() && c.ports.contains(&port))
        {
            match self.legacy(ci, &mut pkt[ip.payload()], ip.src, meta) {
                Outcome::Pass => false,
                Outcome::Rewritten => true,
                Outcome::Suppress => return Verdict::Drop,
            }
        } else if self
            .rtps_ranges
            .iter()
            .any(|(lo, hi)| (*lo..=*hi).contains(&port))
        {
            match self.rtps(&mut pkt[ip.payload()], ip.src, meta) {
                Ok(m) => m,
                Err(()) => {
                    self.stats.rtps_malformed += 1;
                    return match self.malformed {
                        MalformedPolicy::Drop => Verdict::Drop,
                        MalformedPolicy::Pass => Verdict::Accept,
                    };
                }
            }
        } else {
            self.stats.unmatched_port += 1;
            false
        };
        if modified {
            refresh_udp_checksum(pkt, &ip);
            Verdict::AcceptModified
        } else {
            Verdict::Accept
        }
    }

    /// Observe one robot-side packet (an NFLOG copy of what entered the
    /// bridge from the robot port; `crate::observe`). Never changes or
    /// drops anything: the packet is already on its way. Learns the
    /// robot's discovery (the unqueued-locator check, F7) and its
    /// `rt/lowstate` (the arm-SDK engagement check, F1).
    pub fn observe(&mut self, pkt: &[u8], meta: PacketMeta) {
        self.stats.observed_packets += 1;
        let Some(d) = crate::observe::udp_payload(pkt) else {
            return;
        };
        if d.get(..4) != Some(b"RTPS") {
            return;
        }
        if let Some(report) = self.discovery.observe_robot(d) {
            self.observer.learn(&report);
        }
        let n = self.observer.lowstate(d, meta.now_ns);
        self.stats.lowstate_samples += n;
    }

    /// The robot-side observer (status, tests).
    pub fn observer(&self) -> &crate::observe::Observer {
        &self.observer
    }

    // ------------------------------------------------------------- RTPS

    /// `Ok(modified)`, or `Err` if the datagram is undecidable as a whole.
    fn rtps(&mut self, d: &mut [u8], src: Ipv4Addr, meta: PacketMeta) -> Result<bool, ()> {
        let mut samples = std::mem::take(&mut self.samples);
        let r = rtps::walk(d, WalkOptions::default(), &mut samples);
        let out = match r {
            Err(_) => Err(()),
            Ok(sum) => {
                if sum.has_builtin {
                    self.stats.discovery_datagrams += 1;
                    self.discovery.learn(d, src, meta.instant);
                    self.arm_restarts(Binding {
                        ip: src,
                        mac: meta.src_mac,
                    });
                }
                let mut modified = false;
                for s in samples.iter().filter(|s| !s.builtin) {
                    match self.rtps_sample(d, s, src, meta) {
                        Outcome::Pass => {}
                        Outcome::Rewritten => modified = true,
                        Outcome::Suppress => {
                            if rtps::suppress(d, &s.sub, s.little_endian) {
                                modified = true;
                            }
                        }
                    }
                }
                Ok(modified)
            }
        };
        self.samples = samples;
        out
    }

    /// An SEDP / SPDP datagram from `from` announced or removed writers:
    /// arm a restart for each such writer whose stream is bound to the
    /// same IP (and MAC, when both are known).
    fn arm_restarts(&mut self, from: Binding) {
        let hints = self.discovery.take_announced();
        if hints.is_empty() {
            return;
        }
        for ch in &mut self.channels {
            for (g, w) in ch.writers.iter_mut() {
                let hit = hints.iter().any(|h| {
                    if h.whole_participant {
                        h.guid[..12] == g[..12]
                    } else {
                        h.guid == *g
                    }
                });
                let same = w.bound.is_some_and(|b| {
                    b.ip == from.ip
                        && match (b.mac, from.mac) {
                            (Some(x), Some(y)) => x == y,
                            _ => true,
                        }
                });
                if hit && same {
                    w.restart_armed = true;
                }
            }
        }
    }

    /// The enforced channel of a user sample's writer: its SEDP / persisted
    /// classification, else (`unknown_writers: probe`) a content probe.
    /// `Err(())`: an unknown writer's sample that cannot be probed
    /// (DATA_FRAG, key-only, non-standard): suppressed in enforce mode.
    fn classify(&mut self, d: &[u8], s: &Sample) -> Result<Option<usize>, ()> {
        if let Some(w) = self.discovery.writer(&s.writer) {
            return Ok(w.channel);
        }
        if self.unknown_writers == UnknownWriters::Pass {
            return Ok(None);
        }
        if s.kind == SampleKind::DataFrag || s.non_standard || s.content == Content::Key {
            return Err(());
        }
        Ok(self.probe(d, s))
    }

    /// Classify an unknown writer's sample by content. **Lenient** (review
    /// finding F2): a match decides channel membership only (any
    /// representation, padding and trailing octets ignored, element counts
    /// from the length too); the sample is then decided **strictly** on
    /// that channel, so a non-canonical encoding fails closed instead of
    /// being classified as nothing and passed.
    fn probe(&mut self, d: &[u8], s: &Sample) -> Option<usize> {
        let slot = d.get(s.payload.clone()?)?;
        // Each channel's content match and its priority (lower first): a
        // payload two channels could read goes to the stricter one
        // (`rt/lowcmd` before `rt/arm_sdk`; the motor board ignores a
        // `LowCmd_` with a bad CRC, so only a valid one is a command).
        let matches = |c: &Channel| -> Option<u8> {
            match c.codec {
                Codec::UnitreeGoLowcmd
                | Codec::UnitreeHgLowcmd
                | Codec::UnitreeGoArmSdk
                | Codec::UnitreeHgArmSdk => {
                    let kind = match c.lowcmd_codec()? {
                        LowCmdCodec::Go => UnitreeKind::GoLowCmd,
                        LowCmdCodec::Hg => UnitreeKind::HgLowCmd,
                    };
                    decode_unitree(kind, slot, &Limits::default())
                        .is_ok_and(|m| m.message.crc_ok() == Some(true))
                        .then_some(if c.codec.is_arm_sdk() { 1 } else { 0 })
                }
                // Any request in the sport services' id range (1001..=1199 on
                // every model; model-specific tricks included), or one whose
                // id does not fit i32 (aliasing): decided (and then refused)
                // as sport rather than passed unchecked. Loco: the humanoid
                // locomotion ids (7001..=7199 on service `sport`, 8001..=8299
                // on H1's `loco`).
                Codec::UnitreeSportRequest
                | Codec::UnitreeLocoRequest
                | Codec::UnitreeArmRequest => {
                    match decode_unitree(UnitreeKind::ApiRequest, slot, &Limits::default()) {
                        Ok(m) => match m.message {
                            UnitreeMessage::ApiRequest(r) => {
                                let id = r.dispatched_api_id();
                                let hit = !r.api_id_in_range()
                                    || match c.codec {
                                        Codec::UnitreeSportRequest => (1001..=1199).contains(&id),
                                        Codec::UnitreeArmRequest => (7106..=7113).contains(&id),
                                        _ => {
                                            (7001..=7199).contains(&id)
                                                || (8001..=8299).contains(&id)
                                        }
                                    };
                                hit.then_some(if c.codec == Codec::UnitreeArmRequest {
                                    1
                                } else {
                                    0
                                })
                            }
                            _ => None,
                        },
                        Err(_) => None,
                    }
                }
                Codec::UnitreeDex3HandCmd | Codec::UnitreeHandSdk => {
                    hand::plausible(slot, c.codec, c.hand_slots).then_some(2)
                }
                Codec::Ros2Twist | Codec::Ros2TwistStamped => {
                    ros2::plausible(slot, c.codec == Codec::Ros2TwistStamped).then_some(3)
                }
                Codec::Go1HighCmd | Codec::Go1LowCmd => None,
            }
        };
        let found = self
            .channels
            .iter()
            .enumerate()
            .filter_map(|(i, c)| matches(c).map(|p| (p, i)))
            .min()
            .map(|(_, i)| i)?;
        self.stats.probed += 1;
        self.discovery.insert(
            s.writer,
            WriterInfo {
                channel: Some(found),
                probed: true,
            },
        );
        Some(found)
    }

    /// `(claimed, source)`: what the writer GUID resolves to in the policy,
    /// and the source the sample is decided as (`UNKNOWN` when the IP or
    /// MAC is not allowed on the channel, whatever the GUID claims).
    fn resolve_rtps_source(
        &mut self,
        ci: usize,
        writer: &Guid,
        ip: Ipv4Addr,
        mac: Option<[u8; 6]>,
    ) -> (SourceId, SourceId) {
        let claimed = self.claimed_source(ci, writer);
        let allowed = self
            .channels
            .get(ci)
            .is_some_and(|ch| ch.ip_allowed(ip) && ch.mac_allowed(mac));
        (claimed, if allowed { claimed } else { SourceId::UNKNOWN })
    }

    fn claimed_source(&mut self, ci: usize, writer: &Guid) -> SourceId {
        let epoch = self.discovery.epoch;
        let Some(ch) = self.channels.get_mut(ci) else {
            return SourceId::UNKNOWN;
        };
        if let Some((s, e)) = ch.writers.get(writer).and_then(|w| w.claimed) {
            if e == epoch {
                return s;
            }
        }
        let full = hex(writer);
        let prefix = full.get(..24).unwrap_or("");
        let mut prefix_arr = [0u8; 12];
        prefix_arr.copy_from_slice(&writer[..12]);
        let s = self
            .fw
            .source_id(&full)
            .or_else(|| self.fw.source_id(prefix))
            .or_else(|| {
                let name = self.discovery.identity_of(&prefix_arr)?;
                self.fw
                    .source_id(&format!("{IDENTITY_SOURCE_PREFIX}{name}"))
            })
            .unwrap_or(SourceId::UNKNOWN);
        if let Some(ch) = self.channels.get_mut(ci) {
            ch.writer_mut(writer).claimed = Some((s, epoch));
        }
        s
    }

    fn rtps_sample(
        &mut self,
        d: &mut [u8],
        s: &Sample,
        src: Ipv4Addr,
        meta: PacketMeta,
    ) -> Outcome {
        let ci = match self.classify(d, s) {
            Ok(Some(ci)) => ci,
            Ok(None) => return Outcome::Pass,
            Err(()) => {
                // An unknown writer's fragment / key-only / non-standard
                // sample: the probe cannot read it, so it could be a motion
                // command nobody checked (see the crate docs).
                self.stats.unknown_undecidable += 1;
                self.stats.suppressed += 1;
                return Outcome::Suppress;
            }
        };
        self.stats.samples += 1;
        if s.kind == SampleKind::DataFrag || s.non_standard || s.content == Content::Key {
            // A fragmented / key-only / non-standard sample of a motion
            // channel cannot be decided in place (see the crate docs).
            self.stats.unsupported_sample += 1;
            self.stats.suppressed += 1;
            return Outcome::Suppress;
        }
        let Some(range) = s.payload.clone() else {
            // No payload (inline-QoS status change only): no command.
            self.stats.passed += 1;
            return Outcome::Pass;
        };
        if s.sn <= 0 {
            self.stats.suppressed += 1;
            return Outcome::Suppress;
        }
        let binding = Binding {
            ip: src,
            mac: meta.src_mac,
        };
        let (claimed, source) = self.resolve_rtps_source(ci, &s.writer, src, meta.src_mac);
        let late = meta
            .queue_delay_ns
            .is_some_and(|q| q > self.max_queue_delay_ns);
        if source == SourceId::UNKNOWN {
            // Foreign (unknown GUID, or a GUID from an IP / MAC the channel
            // does not allow): decided so the firewall records it, but it
            // never touches the writer's sequence state, and nothing is
            // forwarded under a GUID the policy authorises or that carries
            // an authorised stream (its sequence number would move the
            // robot reader's for the genuine writer).
            let guarded = claimed != SourceId::UNKNOWN
                || self
                    .channels
                    .get(ci)
                    .and_then(|c| c.writers.get(&s.writer))
                    .is_some_and(|w| w.bound.is_some() || w.last_sn.is_some());
            if late {
                self.stats.late += 1;
            }
            let o = self.decide_sample(ci, &mut d[range], source, meta.now_ns, late, !guarded);
            self.count(o);
            return o;
        }
        let jump = self.max_sn_jump;
        let takeover = self.binding_takeover_ns;
        let now = meta.now_ns;
        let Some(ch) = self.channels.get_mut(ci) else {
            return Outcome::Suppress;
        };
        let w = ch.writer_mut(&s.writer);
        // 1. Binding: while the stream is live from one (IP, MAC), the same
        //    GUID from another one is a conflict, never forwarded.
        if let Some(b) = w.bound {
            if b != binding {
                if now.saturating_sub(w.bound_at) <= takeover {
                    self.stats.binding_conflicts += 1;
                    self.stats.suppressed += 1;
                    return Outcome::Suppress;
                }
                // The bound side has been silent past the takeover time:
                // another binding may continue the GUID's stream (the
                // sequence boundary stays: it is what the robot has seen).
                w.bound = None;
                w.pending_jump = None;
                w.restart_armed = false;
            }
        }
        let from_bound = w.bound == Some(binding);
        if from_bound {
            // Liveness of the bound side: any sample of it, decided or not.
            w.bound_at = now;
        }
        // 2. Replay / retransmission, or a restart the writer announced.
        let below = w.last_sn.is_some_and(|l| s.sn <= l);
        if below && w.restart_armed && from_bound && s.sn <= jump {
            w.reset_sequence();
            self.stats.writer_restarts += 1;
        } else if below || w.lookup(s.sn).is_some() {
            // Re-emit exactly what was forwarded then (or suppress again);
            // the firewall is not consulted and its state does not move.
            self.stats.replays += 1;
            let cached = w.lookup(s.sn).and_then(|e| e.bytes.clone());
            return match cached {
                Some(b) if b.len() == range.len() => {
                    self.stats.replays_reemitted += 1;
                    let slot = &mut d[range];
                    if slot == b.as_slice() {
                        Outcome::Pass
                    } else {
                        slot.copy_from_slice(&b);
                        Outcome::Rewritten
                    }
                }
                _ => {
                    self.stats.suppressed += 1;
                    Outcome::Suppress
                }
            };
        }
        // 3. A jump past the window is held until the next sample of the
        //    same binding confirms it.
        if let Some(l) = w.last_sn {
            if s.sn.saturating_sub(l) > jump {
                let confirmed = w.pending_jump.is_some_and(|(p, pb)| {
                    pb == binding && s.sn > p && s.sn.saturating_sub(p) <= jump
                });
                if !confirmed {
                    w.pending_jump = Some((s.sn, binding));
                    self.stats.sn_jumps += 1;
                    self.stats.suppressed += 1;
                    return Outcome::Suppress;
                }
            }
        }
        // 4. Decide.
        if late {
            self.stats.late += 1;
        }
        let outcome = self.decide_sample(ci, &mut d[range.clone()], source, now, late, true);
        self.count(outcome);
        // 5. Only what was forwarded advances the stream (and binds it);
        //    a suppression is remembered (a retransmission is suppressed
        //    again) only when it came from the bound side.
        let bytes = match outcome {
            Outcome::Suppress => None,
            _ => d.get(range),
        };
        if let Some(ch) = self.channels.get_mut(ci) {
            let w = ch.writer_mut(&s.writer);
            if bytes.is_some() {
                w.last_sn = Some(w.last_sn.map_or(s.sn, |l| l.max(s.sn)));
                w.bound = Some(binding);
                w.bound_at = now;
                w.pending_jump = None;
                w.restart_armed = false;
                w.remember(s.sn, bytes);
            } else if from_bound {
                w.remember(s.sn, None);
            }
        }
        outcome
    }

    /// Decide one enforced payload slot with the channel's codec. `emit`:
    /// whether a substitute may be written into it (never for a foreign
    /// sample under a guarded GUID).
    fn decide_sample(
        &mut self,
        ci: usize,
        slot: &mut [u8],
        source: SourceId,
        now: u64,
        late: bool,
        emit: bool,
    ) -> Outcome {
        match self.channels.get(ci).map(|c| c.codec) {
            Some(
                Codec::UnitreeGoLowcmd
                | Codec::UnitreeHgLowcmd
                | Codec::UnitreeGoArmSdk
                | Codec::UnitreeHgArmSdk,
            ) => self.lowcmd_sample(ci, slot, source, now, late, emit),
            Some(Codec::UnitreeSportRequest) => {
                self.sport_sample(ci, slot, source, now, late, emit)
            }
            Some(Codec::UnitreeLocoRequest) => self.loco_sample(ci, slot, source, now, late, emit),
            Some(Codec::UnitreeArmRequest) => self.arm_request_sample(ci, slot, source, now),
            Some(Codec::Ros2Twist | Codec::Ros2TwistStamped) => {
                self.ros2_sample(ci, slot, source, now, late, emit)
            }
            Some(Codec::UnitreeDex3HandCmd | Codec::UnitreeHandSdk) => {
                self.hand_sample(ci, slot, source, now, late)
            }
            Some(Codec::Go1HighCmd | Codec::Go1LowCmd) | None => Outcome::Suppress,
        }
    }

    fn count(&mut self, o: Outcome) {
        match o {
            Outcome::Pass => self.stats.passed += 1,
            Outcome::Rewritten => {}
            Outcome::Suppress => self.stats.suppressed += 1,
        }
    }

    // ---------------------------------------------------------- LowCmd

    fn lowcmd_sample(
        &mut self,
        ci: usize,
        slot: &mut [u8],
        source: SourceId,
        now: u64,
        late: bool,
        emit: bool,
    ) -> Outcome {
        let Some(ch) = self.channels.get(ci) else {
            return Outcome::Suppress;
        };
        let Some(codec) = ch.lowcmd_codec() else {
            return Outcome::Suppress;
        };
        let id = ch.id;
        let allow_battery_off = ch.allow_battery_off;
        let weight = ch.weight_slot;
        let max_weight = ch.max_weight;
        let mut decoded = lowcmd::decode_strict(slot, codec).ok();
        if decoded
            .as_ref()
            .is_some_and(|d| !lowcmd::non_motor_ok(&d.msg, allow_battery_off))
        {
            // A non-motor field the robot acts on (battery off): refused
            // like an integrity failure, so the platform's substitute (with
            // the last accepted frame's non-motor fields) applies.
            self.stats.non_motor_rejected += 1;
            decoded = None;
        }
        let mut engage_verified = false;
        if let (Some(w), Some(d)) = (weight, decoded.as_ref()) {
            if !armsdk::weight_ok(&d.msg, w, max_weight) {
                // The arm-SDK blend weight out of bounds: an integrity
                // failure (crate::armsdk).
                self.stats.arm_weight_rejected += 1;
                decoded = None;
            } else {
                // Its dynamics (review finding F1): step, rate, engagement.
                let lowstate = self.observer.joint_state(codec);
                match armsdk::weight_gate(&d.msg, w, &ch.arm_weight, &ch.weight_dyn, now, lowstate)
                {
                    Ok(v) => engage_verified = v,
                    Err(r) => {
                        self.stats.arm_weight_rejected += 1;
                        match r {
                            armsdk::WeightRefusal::Step => self.stats.arm_weight_step_rejected += 1,
                            armsdk::WeightRefusal::Rate => self.stats.arm_weight_rate_rejected += 1,
                            armsdk::WeightRefusal::Engage => self.stats.arm_engage_rejected += 1,
                        }
                        decoded = None;
                    }
                }
            }
        }
        let frame = match decoded.as_ref().and_then(|d| match weight {
            Some(w) => armsdk::decision_frame(&d.msg, w),
            None => d.msg.joint_frame(),
        }) {
            Some(f) => f,
            None => {
                // Undecidable: decided as an integrity failure (the frame's
                // CRC is reported invalid), so the firewall applies its
                // source, rate and substitute rules.
                self.stats.undecidable += 1;
                match JointFrame::new(codec.slots(), Some(false)) {
                    Some(f) => f,
                    None => return Outcome::Suppress,
                }
            }
        };
        let cmd = JointCommand::new(source, id, now, frame);
        let v = if late && decoded.is_some() {
            self.fw.joint_fault_verdict(&cmd, now)
        } else {
            self.fw.check_joint(&cmd, now)
        };
        let Some(ch) = self.channels.get_mut(ci) else {
            return Outcome::Suppress;
        };
        match v {
            JointVerdict::Passed { cmd, would_have } => {
                if let (None, Some(d)) = (would_have, decoded.as_ref()) {
                    ch.last_low = Some(Forwarded {
                        frame: cmd.frame,
                        wire: d.msg,
                        header: d.header,
                    });
                }
                if let (Some(w), Some(d)) = (weight, decoded.as_ref()) {
                    ch.arm_weight = armsdk::accepted(
                        &d.msg,
                        w,
                        &ch.arm_weight,
                        &ch.weight_dyn,
                        now,
                        engage_verified,
                    );
                }
                Outcome::Pass
            }
            JointVerdict::Limited { cmd, .. } => {
                let Some(d) = decoded else {
                    self.stats.rewrite_failed += 1;
                    return Outcome::Suppress;
                };
                let wire = match weight {
                    Some(w) => armsdk::limited(&d.msg, &cmd.frame, w),
                    None => lowcmd::limited(&d.msg, &cmd.frame),
                };
                match wire.and_then(|w| lowcmd::write_slot(slot, d.header, &w).map(|()| w)) {
                    Ok(wire) => {
                        ch.last_low = Some(Forwarded {
                            frame: cmd.frame,
                            wire,
                            header: d.header,
                        });
                        if let Some(w) = weight {
                            ch.arm_weight = armsdk::accepted(
                                &wire,
                                w,
                                &ch.arm_weight,
                                &ch.weight_dyn,
                                now,
                                engage_verified,
                            );
                        }
                        self.stats.limited += 1;
                        Outcome::Rewritten
                    }
                    Err(_) => {
                        self.stats.rewrite_failed += 1;
                        Outcome::Suppress
                    }
                }
            }
            JointVerdict::Rejected {
                substitute: Some(_),
                ..
            } if !emit => Outcome::Suppress,
            JointVerdict::Rejected {
                substitute: Some(sub),
                ..
            } => {
                let last = ch.last_low;
                let wire = match weight {
                    Some(w) => armsdk::substitute(codec, &sub.cmd.frame, last.as_ref(), w),
                    None => lowcmd::substitute(codec, &sub.cmd.frame, last.as_ref()),
                };
                let wire = match wire {
                    Ok(w) => w,
                    Err(_) => {
                        self.stats.rewrite_failed += 1;
                        return Outcome::Suppress;
                    }
                };
                let mut headers: [Option<[u8; 4]>; 2] = [
                    decoded
                        .map(|d| d.header)
                        .or_else(|| lowcmd::header_of(slot)),
                    last.map(|l| l.header),
                ];
                if headers[0] == headers[1] {
                    headers[1] = None;
                }
                for h in headers.into_iter().flatten() {
                    if lowcmd::write_slot(slot, h, &wire).is_ok() {
                        self.stats.substituted += 1;
                        return Outcome::Rewritten;
                    }
                }
                self.stats.rewrite_failed += 1;
                Outcome::Suppress
            }
            JointVerdict::Rejected {
                substitute: None, ..
            } => Outcome::Suppress,
        }
    }

    // ----------------------------------------------------------- sport

    fn twist_check(
        &mut self,
        id: ChannelId,
        source: SourceId,
        now: u64,
        motion: Motion,
        late: bool,
    ) -> FwVerdict {
        let cmd = Command {
            source,
            channel: id,
            stamp_ns: now,
            motion,
        };
        if late {
            self.fw.fault_verdict(&cmd, now)
        } else {
            self.fw.check(&cmd, now)
        }
    }

    /// Source / rate check of a request that commands no motion (a query,
    /// an allowlisted call, an unreadable request recorded as non-finite):
    /// the twist state is left as it was (review finding F10 b).
    fn access_check(&mut self, id: ChannelId, source: SourceId, now: u64, motion: Motion) -> bool {
        let cmd = Command {
            source,
            channel: id,
            stamp_ns: now,
            motion,
        };
        self.fw.check_access(&cmd, now)
    }

    fn sport_sample(
        &mut self,
        ci: usize,
        slot: &mut [u8],
        source: SourceId,
        now: u64,
        late: bool,
        emit: bool,
    ) -> Outcome {
        let Some(ch) = self.channels.get(ci) else {
            return Outcome::Suppress;
        };
        let id = ch.id;
        let allow = ch.allowed_api_ids.clone();
        let req = match sport::decode_strict(slot, None) {
            Ok(r) => r,
            Err(_) => {
                self.stats.undecidable += 1;
                // Recorded as an unreadable velocity (non-finite); the
                // request cannot carry a substitute.
                self.access_check(id, source, now, twist(f64::NAN, f64::NAN, f64::NAN));
                return Outcome::Suppress;
            }
        };
        if i32::try_from(req.api_id).is_err() {
            self.stats.api_alias += 1;
            return Outcome::Suppress;
        }
        if let ApiCall::SetVelocity { .. } = req.call {
            // A loco SetVelocity (7105) on a sport channel (model not
            // known): decided as a velocity like on a loco channel, with
            // the default duration cap.
            return self.set_velocity(ci, slot, &req, source, now, late, emit);
        }
        let motion = match req.call {
            ApiCall::Move { vx, vy, vyaw } => twist(vx, vy, vyaw),
            ApiCall::Malformed {
                intended: robodr_cdr::unitree::ApiClass::Velocity,
                ..
            } => {
                // A malformed `Move` is recorded (non-finite) and
                // suppressed, never turned into a substitute (F10 c).
                self.stats.undecidable += 1;
                self.access_check(id, source, now, twist(f64::NAN, f64::NAN, f64::NAN));
                return Outcome::Suppress;
            }
            ApiCall::StopMove => {
                // A stop: checked as the zero velocity it commands (the
                // robot stops, the twist state follows).
                return match self.twist_check(id, source, now, twist(0.0, 0.0, 0.0), late) {
                    FwVerdict::Passed { .. } | FwVerdict::Limited { .. } => Outcome::Pass,
                    FwVerdict::Rejected { .. } => Outcome::Suppress,
                };
            }
            _ => {
                // Not a velocity call: allowlist, then the source / rate
                // check only (the twist state is not touched, F10 b).
                if allow.as_ref().is_some_and(|a| !a.contains(&req.api_id)) {
                    self.stats.not_allowlisted += 1;
                    return Outcome::Suppress;
                }
                return if self.access_check(id, source, now, twist(0.0, 0.0, 0.0)) {
                    Outcome::Pass
                } else {
                    Outcome::Suppress
                };
            }
        };
        match self.twist_check(id, source, now, motion, late) {
            FwVerdict::Passed { .. } => Outcome::Pass,
            FwVerdict::Limited { cmd, .. } => {
                match twist_values(&cmd).map(|v| sport::write_move(slot, &req, v, None)) {
                    Some(Ok(())) => {
                        self.stats.limited += 1;
                        Outcome::Rewritten
                    }
                    _ => {
                        self.stats.rewrite_failed += 1;
                        Outcome::Suppress
                    }
                }
            }
            FwVerdict::Rejected {
                substitute: Some(_),
                ..
            } if !emit => Outcome::Suppress,
            FwVerdict::Rejected {
                substitute: Some(sub),
                ..
            } => match twist_values(&sub.cmd).map(|v| sport::write_move(slot, &req, v, None)) {
                Some(Ok(())) => {
                    self.stats.substituted += 1;
                    Outcome::Rewritten
                }
                _ => {
                    self.stats.rewrite_failed += 1;
                    Outcome::Suppress
                }
            },
            FwVerdict::Rejected {
                substitute: None, ..
            } => Outcome::Suppress,
        }
    }

    // ------------------------------------------------------------ loco

    /// A `SetVelocity` lasts its duration: once the last forwarded one has
    /// ended, the robot stands, and the twist state says so (F10 a).
    fn expire_velocity(&mut self, ci: usize, now: u64) {
        let Some(ch) = self.channels.get_mut(ci) else {
            return;
        };
        if let Some(until) = ch.velocity_until {
            if now > until {
                ch.velocity_until = None;
                let id = ch.id;
                self.fw.twist_at_rest(id, until);
                self.stats.velocity_expired += 1;
            }
        }
    }

    /// A humanoid locomotion request (`unitree_loco_request`; see the
    /// README, "Loco requests", for every SDK id and why).
    fn loco_sample(
        &mut self,
        ci: usize,
        slot: &mut [u8],
        source: SourceId,
        now: u64,
        late: bool,
        emit: bool,
    ) -> Outcome {
        self.expire_velocity(ci, now);
        let Some(ch) = self.channels.get(ci) else {
            return Outcome::Suppress;
        };
        let id = ch.id;
        let (service, model) = ch.api();
        let allow_api = ch.allowed_api_ids.clone();
        let allow_fsm = ch.allowed_fsm_ids.clone();
        let req = match sport::decode_strict_for(slot, service, model) {
            Ok(r) => r,
            Err(_) => {
                self.stats.undecidable += 1;
                self.access_check(id, source, now, twist(f64::NAN, f64::NAN, f64::NAN));
                return Outcome::Suppress;
            }
        };
        if i32::try_from(req.api_id).is_err() {
            self.stats.api_alias += 1;
            return Outcome::Suppress;
        }
        let allowed = match req.call {
            ApiCall::SetVelocity { .. }
            | ApiCall::Malformed {
                intended: ApiClass::Velocity,
                ..
            } => return self.set_velocity(ci, slot, &req, source, now, late, emit),
            // Every FSM state only when the site listed it: `ZeroTorque`,
            // `Damp` (limp, the robot falls), the posture transitions
            // (whole-body motion), and `Start` too (F10 e: it hands the
            // robot to the walking controller from any state).
            ApiCall::SetFsmId { fsm_id, .. } => {
                allow_fsm.as_ref().is_some_and(|a| a.contains(&fsm_id))
            }
            ApiCall::Other {
                class: ApiClass::Query,
                ..
            } => true,
            ApiCall::Other { api_id, .. } => {
                allow_api.as_ref().is_some_and(|a| a.contains(&api_id))
            }
            // Unknown ids, malformed parameters, anything else: refused.
            _ => false,
        };
        if !allowed {
            self.stats.loco_refused += 1;
            return Outcome::Suppress;
        }
        // No motion of its own: source / rate only (F10 b).
        if self.access_check(id, source, now, twist(0.0, 0.0, 0.0)) {
            Outcome::Pass
        } else {
            Outcome::Suppress
        }
    }

    /// The G1 / H2 arm action service (`unitree_arm_request`, F10 f): a
    /// query passes the source / rate check; every other call (an action,
    /// a custom action, its stop, an unknown id, a malformed parameter) only
    /// when `allowed_api_ids` lists it.
    fn arm_request_sample(
        &mut self,
        ci: usize,
        slot: &mut [u8],
        source: SourceId,
        now: u64,
    ) -> Outcome {
        let Some(ch) = self.channels.get(ci) else {
            return Outcome::Suppress;
        };
        let id = ch.id;
        let (service, model) = ch.api();
        let allow_api = ch.allowed_api_ids.clone();
        let req = match sport::decode_strict_for(slot, service, model) {
            Ok(r) => r,
            Err(_) => {
                self.stats.undecidable += 1;
                self.access_check(id, source, now, twist(f64::NAN, f64::NAN, f64::NAN));
                return Outcome::Suppress;
            }
        };
        if i32::try_from(req.api_id).is_err() {
            self.stats.api_alias += 1;
            return Outcome::Suppress;
        }
        let allowed = match req.call {
            ApiCall::Other {
                class: ApiClass::Query,
                ..
            } => true,
            ApiCall::Other { api_id, .. } => {
                allow_api.as_ref().is_some_and(|a| a.contains(&api_id))
            }
            _ => false,
        };
        if !allowed {
            self.stats.arm_request_refused += 1;
            return Outcome::Suppress;
        }
        if self.access_check(id, source, now, twist(0.0, 0.0, 0.0)) {
            Outcome::Pass
        } else {
            Outcome::Suppress
        }
    }

    /// A `SetVelocity`: the body velocity is decided as a twist
    /// `(vx, vy, 0) / (0, 0, vyaw)`, the duration is capped at the
    /// channel's `max_velocity_duration_s` (default 1 s); a limited or
    /// substitute velocity and a capped duration are written in place. A
    /// malformed one (unreadable velocity, negative / non-finite duration)
    /// is recorded as non-finite and suppressed, never turned into a
    /// substitute (F10 c). What is forwarded sets when the robot stops on
    /// its own (F10 a).
    #[allow(clippy::too_many_arguments)]
    fn set_velocity(
        &mut self,
        ci: usize,
        slot: &mut [u8],
        req: &sport::SportRequest,
        source: SourceId,
        now: u64,
        late: bool,
        emit: bool,
    ) -> Outcome {
        self.expire_velocity(ci, now);
        let Some(ch) = self.channels.get(ci) else {
            return Outcome::Suppress;
        };
        let id = ch.id;
        let cap = ch.max_duration_s;
        let (service, model) = ch.api();
        let (motion, duration) = match req.call {
            ApiCall::SetVelocity {
                vx,
                vy,
                vyaw,
                duration,
            } if duration.is_finite() && duration >= 0.0 => (twist(vx, vy, vyaw), duration),
            _ => {
                self.stats.undecidable += 1;
                self.access_check(id, source, now, twist(f64::NAN, f64::NAN, f64::NAN));
                return Outcome::Suppress;
            }
        };
        let d = duration.min(cap);
        let mut write = |gw: &mut Self, v: [f64; 3]| -> bool {
            sport::write_set_velocity(slot, req, v, d, service, model).is_ok() || {
                gw.stats.rewrite_failed += 1;
                false
            }
        };
        let out = match self.twist_check(id, source, now, motion, late) {
            FwVerdict::Passed { cmd, .. } if duration > cap => match twist_values(&cmd) {
                Some(v) if write(self, v) => {
                    self.stats.duration_capped += 1;
                    Outcome::Rewritten
                }
                _ => Outcome::Suppress,
            },
            FwVerdict::Passed { .. } => Outcome::Pass,
            FwVerdict::Limited { cmd, .. } => match twist_values(&cmd) {
                Some(v) if write(self, v) => {
                    self.stats.limited += 1;
                    if duration > cap {
                        self.stats.duration_capped += 1;
                    }
                    Outcome::Rewritten
                }
                _ => Outcome::Suppress,
            },
            FwVerdict::Rejected {
                substitute: Some(_),
                ..
            } if !emit => Outcome::Suppress,
            FwVerdict::Rejected {
                substitute: Some(sub),
                ..
            } => match twist_values(&sub.cmd) {
                Some(v) if write(self, v) => {
                    self.stats.substituted += 1;
                    if duration > cap {
                        self.stats.duration_capped += 1;
                    }
                    Outcome::Rewritten
                }
                _ => Outcome::Suppress,
            },
            FwVerdict::Rejected {
                substitute: None, ..
            } => Outcome::Suppress,
        };
        if out != Outcome::Suppress {
            if let Some(ch) = self.channels.get_mut(ci) {
                let ns = (d * 1e9).min(u64::MAX as f64) as u64;
                ch.velocity_until = Some(now.saturating_add(ns));
            }
        }
        out
    }

    // ------------------------------------------------------------ ROS 2

    /// A ROS 2 `Twist` / `TwistStamped` (`crate::ros2`): the firewall's
    /// twist check; limited / substitute values written in place.
    fn ros2_sample(
        &mut self,
        ci: usize,
        slot: &mut [u8],
        source: SourceId,
        now: u64,
        late: bool,
        emit: bool,
    ) -> Outcome {
        let Some(ch) = self.channels.get(ci) else {
            return Outcome::Suppress;
        };
        let id = ch.id;
        let stamped = ch.codec == Codec::Ros2TwistStamped;
        let w = match ros2::decode_strict(slot, stamped) {
            Ok(w) => w,
            Err(_) => {
                self.stats.undecidable += 1;
                let nan = Motion::Twist(Twist::new(
                    Vec3::new(f64::NAN, f64::NAN, f64::NAN),
                    Vec3::new(f64::NAN, f64::NAN, f64::NAN),
                ));
                let _ = self.twist_check(id, source, now, nan, false);
                return Outcome::Suppress;
            }
        };
        let v = w.values;
        let motion = Motion::Twist(Twist::new(
            Vec3::new(v[0], v[1], v[2]),
            Vec3::new(v[3], v[4], v[5]),
        ));
        let six = |c: &Command| match &c.motion {
            Motion::Twist(t) => Some([
                t.linear.x,
                t.linear.y,
                t.linear.z,
                t.angular.x,
                t.angular.y,
                t.angular.z,
            ]),
            Motion::Joints(_) => None,
        };
        let out = match self.twist_check(id, source, now, motion, late) {
            FwVerdict::Passed { .. } => return Outcome::Pass,
            FwVerdict::Limited { cmd, .. } => six(&cmd).map(|x| (x, true)),
            FwVerdict::Rejected {
                substitute: Some(sub),
                ..
            } if emit => six(&sub.cmd).map(|x| (x, false)),
            FwVerdict::Rejected { .. } => return Outcome::Suppress,
        };
        match out {
            Some((x, limited)) if ros2::write_twist(slot, &w, x, stamped).is_ok() => {
                if limited {
                    self.stats.limited += 1;
                } else {
                    self.stats.substituted += 1;
                }
                Outcome::Rewritten
            }
            _ => {
                self.stats.rewrite_failed += 1;
                Outcome::Suppress
            }
        }
    }

    // ------------------------------------------------------------ hands

    /// A hand command (`crate::hand`): the mode octets and the hand-SDK
    /// weight checked (F5), then decided on the finger joints, forwarded
    /// unchanged when the firewall passes it, else suppressed.
    fn hand_sample(
        &mut self,
        ci: usize,
        slot: &mut [u8],
        source: SourceId,
        now: u64,
        late: bool,
    ) -> Outcome {
        let Some(ch) = self.channels.get(ci) else {
            return Outcome::Suppress;
        };
        let id = ch.id;
        let n = ch.hand_slots;
        let dynamics = ch.weight_dyn;
        let last_weight = ch.hand_weight;
        let mut decoded = match hand::decode_hand(slot, ch.codec, n) {
            Ok(h) => Some(h),
            Err(e) => {
                if e == crate::lowcmd::Undecidable::Mode {
                    self.stats.hand_mode_rejected += 1;
                }
                None
            }
        };
        // Hand SDK: the blend weight's step and rate from the last
        // forwarded frame (none yet: from 0).
        if let Some(w) = decoded.and_then(|h| h.weight) {
            let (w0, t0) = last_weight.map_or((0, None), |(w, t)| (w, Some(t)));
            let dw = f64::from(w.abs_diff(w0)) / f64::from(hand::HAND_SDK_WEIGHT_SCALE);
            let step_ok = dw <= dynamics.max_step + 1e-9;
            let rate_ok = t0.is_none_or(|t| {
                dw <= dynamics.max_rate_per_s * (now.saturating_sub(t) as f64 * 1e-9) + 1e-9
            });
            if !(step_ok && rate_ok) {
                self.stats.hand_mode_rejected += 1;
                decoded = None;
            }
        }
        let frame = match decoded {
            Some(h) => h.frame,
            None => {
                self.stats.undecidable += 1;
                match JointFrame::new(n, Some(false)) {
                    Some(f) => f,
                    None => return Outcome::Suppress,
                }
            }
        };
        let cmd = JointCommand::new(source, id, now, frame);
        let v = if late && decoded.is_some() {
            self.fw.joint_fault_verdict(&cmd, now)
        } else {
            self.fw.check_joint(&cmd, now)
        };
        match (v, decoded) {
            (JointVerdict::Passed { would_have, .. }, Some(h)) => {
                if would_have.is_none() {
                    if let (Some(w), Some(ch)) = (h.weight, self.channels.get_mut(ci)) {
                        ch.hand_weight = Some((w, now));
                    }
                }
                self.stats.hand_passed += 1;
                Outcome::Pass
            }
            _ => {
                self.stats.hand_suppressed += 1;
                Outcome::Suppress
            }
        }
    }

    // ---------------------------------------------------------- legacy

    fn legacy(&mut self, ci: usize, frame: &mut [u8], src: Ipv4Addr, meta: PacketMeta) -> Outcome {
        let Some(ch) = self.channels.get(ci) else {
            return Outcome::Suppress;
        };
        self.stats.samples += 1;
        let source = if ch.ip_allowed(src) {
            ch.legacy_sources
                .iter()
                .find(|(ip, _)| *ip == src)
                .map(|(_, s)| *s)
                .unwrap_or(SourceId::UNKNOWN)
        } else {
            SourceId::UNKNOWN
        };
        let late = meta
            .queue_delay_ns
            .is_some_and(|q| q > self.max_queue_delay_ns);
        if late {
            self.stats.late += 1;
        }
        let o = match ch.codec {
            Codec::Go1HighCmd => self.legacy_high(ci, frame, source, meta.now_ns, late),
            Codec::Go1LowCmd => self.legacy_low(ci, frame, source, meta.now_ns, late),
            _ => Outcome::Suppress,
        };
        self.count(o);
        o
    }

    fn legacy_high(
        &mut self,
        ci: usize,
        frame: &mut [u8],
        source: SourceId,
        now: u64,
        late: bool,
    ) -> Outcome {
        let Some(ch) = self.channels.get(ci) else {
            return Outcome::Suppress;
        };
        let id = ch.id;
        let allow = ch.allowed_modes.clone();
        let decoded = legacy::decode_high(frame).filter(|h| h.crc_ok);
        let Some(h) = decoded else {
            self.stats.undecidable += 1;
            let v = self.twist_check(id, source, now, twist(f64::NAN, f64::NAN, f64::NAN), false);
            return self.legacy_high_substitute(ci, frame, v);
        };
        if h.mode != 2 {
            if allow.as_ref().is_some_and(|a| !a.contains(&h.mode)) {
                self.stats.not_allowlisted += 1;
                return Outcome::Suppress;
            }
            return match self.twist_check(id, source, now, twist(0.0, 0.0, 0.0), late) {
                FwVerdict::Passed { .. } | FwVerdict::Limited { .. } => Outcome::Pass,
                FwVerdict::Rejected { .. } => Outcome::Suppress,
            };
        }
        let v = self.twist_check(
            id,
            source,
            now,
            twist(f64::from(h.vx), f64::from(h.vy), f64::from(h.yaw)),
            late,
        );
        match v {
            FwVerdict::Passed { would_have, .. } => {
                if would_have.is_none() {
                    if let Some(ch) = self.channels.get_mut(ci) {
                        ch.last_legacy = Some(LegacyLast {
                            frame: None,
                            bytes: frame.to_vec(),
                        });
                    }
                }
                Outcome::Pass
            }
            FwVerdict::Limited { cmd, .. } => {
                match twist_values(&cmd).map(|v| legacy::write_high(frame, v, Some(&h))) {
                    Some(Ok(())) => {
                        if let Some(ch) = self.channels.get_mut(ci) {
                            ch.last_legacy = Some(LegacyLast {
                                frame: None,
                                bytes: frame.to_vec(),
                            });
                        }
                        self.stats.limited += 1;
                        Outcome::Rewritten
                    }
                    _ => {
                        self.stats.rewrite_failed += 1;
                        Outcome::Suppress
                    }
                }
            }
            v => self.legacy_high_substitute(ci, frame, v),
        }
    }

    fn legacy_high_substitute(&mut self, ci: usize, frame: &mut [u8], v: FwVerdict) -> Outcome {
        let FwVerdict::Rejected {
            substitute: Some(sub),
            ..
        } = v
        else {
            return Outcome::Suppress;
        };
        // The substitute rides on the last accepted frame (never on the
        // rejected one); with none forwarded yet, nothing is sent.
        let base = self
            .channels
            .get(ci)
            .and_then(|c| c.last_legacy.as_ref())
            .map(|l| l.bytes.clone());
        match (base, twist_values(&sub.cmd)) {
            (Some(b), Some(vals)) if b.len() == frame.len() => {
                frame.copy_from_slice(&b);
                if legacy::write_high(frame, vals, None).is_ok() {
                    self.stats.substituted += 1;
                    Outcome::Rewritten
                } else {
                    self.stats.rewrite_failed += 1;
                    Outcome::Suppress
                }
            }
            _ => Outcome::Suppress,
        }
    }

    fn legacy_low(
        &mut self,
        ci: usize,
        frame: &mut [u8],
        source: SourceId,
        now: u64,
        late: bool,
    ) -> Outcome {
        let Some(ch) = self.channels.get(ci) else {
            return Outcome::Suppress;
        };
        let id = ch.id;
        let decoded = legacy::decode_low(frame);
        let jf = match decoded {
            Some(f) => f,
            None => {
                self.stats.undecidable += 1;
                match JointFrame::new(robodr_cdr::unitree_legacy::LEGACY_MOTORS, Some(false)) {
                    Some(f) => f,
                    None => return Outcome::Suppress,
                }
            }
        };
        let cmd = JointCommand::new(source, id, now, jf);
        let v = if late && decoded.is_some() {
            self.fw.joint_fault_verdict(&cmd, now)
        } else {
            self.fw.check_joint(&cmd, now)
        };
        let Some(ch) = self.channels.get_mut(ci) else {
            return Outcome::Suppress;
        };
        match v {
            JointVerdict::Passed { cmd, would_have } => {
                if would_have.is_none() && decoded.is_some() {
                    ch.last_legacy = Some(LegacyLast {
                        frame: Some(cmd.frame),
                        bytes: frame.to_vec(),
                    });
                }
                Outcome::Pass
            }
            JointVerdict::Limited { cmd, .. } => {
                if decoded.is_none() {
                    self.stats.rewrite_failed += 1;
                    return Outcome::Suppress;
                }
                match legacy::write_low(frame, &cmd.frame, legacy::LowSource::Limited) {
                    Ok(()) => {
                        ch.last_legacy = Some(LegacyLast {
                            frame: Some(cmd.frame),
                            bytes: frame.to_vec(),
                        });
                        self.stats.limited += 1;
                        Outcome::Rewritten
                    }
                    Err(_) => {
                        self.stats.rewrite_failed += 1;
                        Outcome::Suppress
                    }
                }
            }
            JointVerdict::Rejected {
                substitute: Some(sub),
                ..
            } => {
                let last = ch.last_legacy.clone();
                let base = last
                    .as_ref()
                    .map(|l| l.bytes.clone())
                    .unwrap_or_else(legacy::low_template);
                if base.len() != frame.len() {
                    self.stats.rewrite_failed += 1;
                    return Outcome::Suppress;
                }
                frame.copy_from_slice(&base);
                let held = last
                    .as_ref()
                    .and_then(|l| Some((l.frame.as_ref()?, l.bytes.as_slice())));
                match legacy::write_low(
                    frame,
                    &sub.cmd.frame,
                    legacy::LowSource::Substitute { held },
                ) {
                    Ok(()) => {
                        self.stats.substituted += 1;
                        Outcome::Rewritten
                    }
                    Err(_) => {
                        self.stats.rewrite_failed += 1;
                        Outcome::Suppress
                    }
                }
            }
            JointVerdict::Rejected {
                substitute: None, ..
            } => Outcome::Suppress,
        }
    }

    /// The last accepted wire `LowCmd_` of a channel (tests, status).
    pub fn last_accepted_lowcmd(&self, channel: &str) -> Option<WireLowCmd> {
        self.channels
            .iter()
            .find(|c| c.name == channel)
            .and_then(|c| c.last_low.map(|l| l.wire))
    }
}
