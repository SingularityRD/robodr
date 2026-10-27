//! Unitree's legacy UDP generation (`unitree_legged_sdk`, Go1): raw,
//! packed UDP frames instead of DDS. Off by default.
//!
//! With [`LegacyOptions::enabled`] the capture filter also accepts UDP whose
//! source or destination port is one of [`LegacyOptions::ports`]
//! ([`robodr_capture::RtpsFilter::with_legacy_udp_ports`], kernel BPF
//! included), and the pipeline hands those datagrams here instead of to the
//! RTPS parser. Each payload is classified by its length
//! ([`robodr_cdr::unitree_legacy::LegacyFrame::decode`]) and decoded:
//!
//! | frame | event | channel |
//! |---|---|---|
//! | `HighCmd` (129 B) | `MotionCommand`: body velocity in mode 2, every mode's class (`Trick` / `Trajectory` / `Unknown` are flagged by `Profile::evaluate`) | [`channels::HIGH_CMD`] |
//! | `LowCmd` (734 B, declared layout) | `MotionCommand`: joint speed / torque / kp over all 20 slots, plus the position step against the previous frame | [`channels::LOW_CMD`] |
//! | `HighState` (1087 B) | `MotionFeedback`: body velocity, IMU gyro, max joint speed | [`channels::HIGH_STATE`] |
//! | `LowState` (937 B, declared layout) | `MotionFeedback`: IMU gyro, max joint speed | [`channels::LOW_STATE`] |
//!
//! Commands are evaluated against the profile's envelopes for those
//! channels (unless [`crate::MotionOptions::evaluate_commands`] is off, as
//! in `robodr-agentd`, whose agent evaluates them itself); feedback is
//! handed on only for channels listed in `motion.feedback_topics`.
//!
//! # Findings
//!
//! The sender check runs on the class the payload's **length** announces,
//! before decoding: a compressed `LowCmd` (614 B, how every real Go1
//! low-level command is sent) from an unlisted host is a command from an
//! unknown sender even though its content cannot be inspected.
//!
//! | When | Rule | Severity |
//! |---|---|---|
//! | a command frame (decoded or compressed) from a source IP not in [`LegacyOptions::command_senders`] | [`rules::LEGACY_UNKNOWN_SENDER`] | Critical (anyone on the robot's LAN can drive a Go1 this way; the protocol has no authentication) |
//! | a state frame from a source IP not in [`LegacyOptions::robot_addresses`], or a payload of no legacy length from a host in neither list | [`rules::LEGACY_UNKNOWN_SENDER`] | Medium (spoofed telemetry, a scan) |
//! | unlisted senders beyond the first [`MAX_REPORTED_UNKNOWN_SENDERS`] of a class (commands; state / unclassified) | [`rules::LEGACY_SENDER_FLOOD`]: one aggregated finding with the frame count when the count reaches 1, 2, 4, 8, ... | Critical (commands) / Medium |
//! | a command from a listed sender bound to a MAC ([`LegacyOptions::sender_macs`]) whose link-layer source differs, or that was reassembled from IP fragments (cannot be verified) | [`rules::LEGACY_SENDER_MAC_MISMATCH`] (the frame is not attributed) | High |
//! | a datagram on a legacy port that also parses as RTPS (inspected on both paths, [`crate::Pipeline::process_legacy_from_at`]) | [`rules::LEGACY_PORT_RTPS`] | High |
//! | a payload on a legacy port that is no decodable frame: the v3.8.6 "compressed" `LowCmd` / `LowState` (614 / 807 B, layout unpublished) or an unknown length | `robot.motion.undecodable_sample` | Medium, rate limited |
//!
//! Every finding is deduplicated like every other pipeline finding (rule +
//! detail; the sender address is in the detail, so one finding per sender).
//! The sender findings are **not** in the pipeline's shared per-rule rate
//! limiter ([`crate::ratelimit`]): junk on the legacy ports that drains the
//! `undecodable_sample` bucket cannot suppress them. Their own budget is
//! per class and per sender key (at most [`MAX_REPORTED_UNKNOWN_SENDERS`]
//! keys remembered per class), so a spoofed-source flood costs bounded
//! memory and a logarithmic number of findings.
//!
//! # Limits (be honest)
//!
//! * The legacy protocol has no identity: the sender is its source IP, which
//!   is not authenticated (anyone on the LAN can forge it). A forged source
//!   address of an allowed sender is not detected here, unless the sender
//!   is bound to a MAC and the forger uses another one. The MAC binding
//!   raises the bar only: a host on the same L2 segment can forge its
//!   source MAC as easily as its IP, and a capture without link-layer
//!   sources (raw-IP pcap) cannot check it (counted in
//!   [`LegacyStats::mac_unverified`], not reported).
//! * Go1 low-level frames in the v3.8.6 compressed wire form are reported
//!   (sender, "not inspected"), not inspected: neither the profile envelope
//!   nor a joint firewall sees their content. Decodable (declared-layout)
//!   `LowCmd` frames carry their 20-slot joint frame
//!   ([`crate::MotionSample::joint`]).
//! * The CRC is advisory and only reported in the black box via the event;
//!   `encryptCRC` mode is not verifiable ([`robodr_cdr::unitree_legacy::LegacyCrcMode`]).
//! * Only synthetic frames built from the published `comm.h` layout have
//!   gone through this path; no capture of a real Go1 was available.

use std::collections::{BTreeMap, BTreeSet};
use std::net::IpAddr;

use robodr_cdr::unitree_legacy::{channels, LegacyFrame, LegacyFrameError, LegacyKind};
use robodr_cdr::EventContext;
use robodr_events::{Deviation, RobotEvent, Severity};
use serde::Serialize;

use crate::source::LegacyUdp;

/// Rule ids raised by the legacy UDP path.
pub mod rules {
    /// A legacy UDP frame from a source IP the configuration does not list.
    /// Critical (command) / Medium (state or unclassified).
    pub const LEGACY_UNKNOWN_SENDER: &str = "robot.unitree.legacy_unknown_sender";
    /// Legacy frames from more unlisted source addresses than are reported
    /// one by one ([`super::MAX_REPORTED_UNKNOWN_SENDERS`]): aggregated, with
    /// counts. Critical (commands) / Medium (state or unclassified).
    pub const LEGACY_SENDER_FLOOD: &str = "robot.unitree.legacy_sender_flood";
    /// A legacy command from a listed sender IP whose link-layer source
    /// address is not the MAC bound to that IP, or that cannot be verified
    /// (reassembled from IP fragments). High.
    pub const LEGACY_SENDER_MAC_MISMATCH: &str = "robot.unitree.legacy_sender_mac_mismatch";
    /// A datagram on a configured legacy port that also starts with the
    /// RTPS magic: both paths inspect it. High.
    pub const LEGACY_PORT_RTPS: &str = "robot.unitree.legacy_port_rtps";
}

/// The SDK's default legacy UDP ports (`unitree_legged_sdk` `udp.h` and
/// examples): 8007 low-level server, 8082 high-level server, 8080 / 8090
/// client.
pub const DEFAULT_LEGACY_PORTS: [u16; 4] = [8007, 8080, 8082, 8090];

/// Most entries of [`LegacyOptions::command_senders`] /
/// [`LegacyOptions::robot_addresses`].
pub const MAX_LEGACY_ADDRESSES: usize = 64;

/// Unlisted senders reported one by one, per class (commands; state and
/// unclassified payloads; MAC mismatches). Beyond that, frames from further
/// unlisted senders are counted and reported in aggregate
/// ([`rules::LEGACY_SENDER_FLOOD`]) when the count reaches 1, 2, 4, 8, ...
/// (at most 64 such findings per class over the sensor's lifetime).
pub const MAX_REPORTED_UNKNOWN_SENDERS: usize = 16;

/// Knobs of the legacy UDP path.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LegacyOptions {
    /// Decode legacy UDP at all (default **off**).
    pub enabled: bool,
    /// UDP ports (source or destination) whose datagrams are legacy frames.
    pub ports: BTreeSet<u16>,
    /// Source IPs allowed to send `HighCmd` / `LowCmd` (the operator's
    /// client computers). Empty = every command sender is unknown.
    pub command_senders: BTreeSet<IpAddr>,
    /// Optional link-layer (MAC) binding of command senders: a command from
    /// a listed IP must carry this source MAC
    /// ([`rules::LEGACY_SENDER_MAC_MISMATCH`]). Every key is in
    /// `command_senders`.
    pub sender_macs: BTreeMap<IpAddr, [u8; 6]>,
    /// The robot's own addresses (state senders), default the SDK's
    /// `192.168.123.10` (low-level board) and `192.168.123.161` (sport host).
    pub robot_addresses: BTreeSet<IpAddr>,
}

impl Default for LegacyOptions {
    fn default() -> Self {
        Self {
            enabled: false,
            ports: DEFAULT_LEGACY_PORTS.into_iter().collect(),
            command_senders: BTreeSet::new(),
            sender_macs: BTreeMap::new(),
            robot_addresses: default_robot_addresses(),
        }
    }
}

/// `192.168.123.10` and `192.168.123.161` (`udp.h`).
pub fn default_robot_addresses() -> BTreeSet<IpAddr> {
    [
        robodr_cdr::unitree_legacy::ports::SERVER_IP_BASIC,
        robodr_cdr::unitree_legacy::ports::SERVER_IP_SPORT,
    ]
    .iter()
    .filter_map(|s| s.parse().ok())
    .collect()
}

/// `aa:bb:cc:dd:ee:ff`.
pub fn format_mac(mac: &[u8; 6]) -> String {
    mac.iter()
        .map(|b| format!("{b:02x}"))
        .collect::<Vec<_>>()
        .join(":")
}

/// Parse `aa:bb:cc:dd:ee:ff` (or `-` separated; case-insensitive).
pub fn parse_mac(s: &str) -> Option<[u8; 6]> {
    let parts: Vec<&str> = s.split([':', '-']).collect();
    if parts.len() != 6 {
        return None;
    }
    let mut mac = [0u8; 6];
    for (m, p) in mac.iter_mut().zip(parts) {
        if p.len() != 2 {
            return None;
        }
        *m = u8::from_str_radix(p, 16).ok()?;
    }
    Some(mac)
}

/// Counters of the legacy UDP path.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize)]
pub struct LegacyStats {
    /// Legacy datagrams seen (also while disabled).
    pub datagrams: u64,
    /// Seen while the path is disabled (dropped).
    pub ignored: u64,
    /// Decoded command frames.
    pub commands: u64,
    /// Decoded state frames.
    pub states: u64,
    /// Not decodable (compressed form or unknown length).
    pub undecodable: u64,
    /// Frames (decoded or not) from a sender the configuration does not
    /// list.
    pub unknown_sender: u64,
    /// Of those, frames from senders beyond the
    /// [`MAX_REPORTED_UNKNOWN_SENDERS`] reported one by one.
    pub unknown_sender_aggregated: u64,
    /// Commands from a MAC-bound sender whose link-layer source does not
    /// match (or cannot be verified because the datagram was reassembled).
    pub mac_mismatch: u64,
    /// Commands from a MAC-bound sender whose link-layer source the capture
    /// does not know (e.g. a raw-IP pcap): not verified, not reported.
    pub mac_unverified: u64,
    /// Datagrams on a legacy port that also started with the RTPS magic.
    pub rtps_on_legacy_port: u64,
}

/// One class of per-sender findings with its own budget (so a flood in one
/// class cannot hide another, and none of them uses the pipeline's shared
/// rate limiter).
#[derive(Debug, Clone, Default)]
struct SenderBudget {
    /// Keys reported one by one (at most [`MAX_REPORTED_UNKNOWN_SENDERS`]).
    reported: BTreeSet<String>,
    /// Frames from keys beyond the budget.
    aggregated: u64,
    /// `aggregated` count at which the next flood finding is reported
    /// (1, 2, 4, ...; 0 = not started).
    next_report: u64,
}

impl SenderBudget {
    /// `Ok(())`: report this key individually (dedup collapses repeats).
    /// `Err(Some(n))`: aggregate, and report the flood now with `n` frames.
    /// `Err(None)`: aggregate silently.
    fn admit(&mut self, key: &str) -> Result<(), Option<u64>> {
        if self.reported.contains(key) {
            return Ok(());
        }
        if self.reported.len() < MAX_REPORTED_UNKNOWN_SENDERS {
            self.reported.insert(key.to_string());
            return Ok(());
        }
        self.aggregated = self.aggregated.saturating_add(1);
        if self.next_report == 0 {
            self.next_report = 1;
        }
        if self.aggregated >= self.next_report {
            self.next_report = self.next_report.saturating_mul(2);
            Err(Some(self.aggregated))
        } else {
            Err(None)
        }
    }
}

/// Per-sender finding budgets of the legacy path (bounded memory: at most
/// [`MAX_REPORTED_UNKNOWN_SENDERS`] keys per class).
#[derive(Debug, Clone, Default)]
pub(crate) struct LegacyTracker {
    commands: SenderBudget,
    other: SenderBudget,
    mac: SenderBudget,
}

/// One legacy datagram's result (before dedup / profile evaluation).
pub(crate) struct LegacyOutput {
    pub deviations: Vec<Deviation>,
    /// The decoded frame, its event and whether its sender is listed (and,
    /// for a MAC-bound sender, its link-layer source matched).
    pub event: Option<(RobotEvent, LegacyFrame, bool)>,
}

fn is_command_kind(kind: LegacyKind) -> bool {
    matches!(kind, LegacyKind::HighCmd | LegacyKind::LowCmd)
}

/// Decode one legacy datagram. `capture_ns` stamps the event.
///
/// The sender check runs **before** decoding, on the class the payload's
/// length announces (a compressed `LowCmd`, which is how every real Go1
/// low-level command is sent, is still a command): an undecodable frame
/// from an unlisted host is reported as such, not only as "not inspected".
#[allow(clippy::too_many_arguments)]
pub(crate) fn process(
    opts: &LegacyOptions,
    stats: &mut LegacyStats,
    tracker: &mut LegacyTracker,
    payload: &[u8],
    src_ip: &str,
    ip: Option<IpAddr>,
    udp: &LegacyUdp,
    capture_ns: u64,
) -> LegacyOutput {
    let mut out = LegacyOutput {
        deviations: Vec::new(),
        event: None,
    };
    let decoded = LegacyFrame::decode(payload);
    // Some(true) command, Some(false) state, None: no legacy length.
    let class = match &decoded {
        Ok(f) => Some(f.is_command()),
        Err(LegacyFrameError::Compressed { kind, .. }) => Some(is_command_kind(*kind)),
        Err(LegacyFrameError::UnknownLength { .. }) => None,
    };
    let kind_name = match &decoded {
        Ok(f) => format!("{:?}", f.kind()),
        Err(LegacyFrameError::Compressed { kind, .. }) => format!("{kind:?} (compressed)"),
        Err(LegacyFrameError::UnknownLength { len }) => format!("{len}-byte payload"),
    };
    let listed_cmd = ip.is_some_and(|ip| opts.command_senders.contains(&ip));
    let listed_robot = ip.is_some_and(|ip| opts.robot_addresses.contains(&ip));
    let (mut allowed, list, sev, what) = match class {
        Some(true) => (
            listed_cmd,
            "unitree_legacy.command_senders",
            Severity::Critical,
            "command (the legacy protocol is unauthenticated: this host can drive the robot)",
        ),
        Some(false) => (
            listed_robot,
            "unitree_legacy.robot_addresses",
            Severity::Medium,
            "state (spoofed robot telemetry?)",
        ),
        None => (
            listed_cmd || listed_robot,
            "unitree_legacy.command_senders or robot_addresses",
            Severity::Medium,
            "datagram on a legacy port",
        ),
    };
    if !allowed {
        stats.unknown_sender += 1;
        let budget = if class == Some(true) {
            &mut tracker.commands
        } else {
            &mut tracker.other
        };
        match budget.admit(src_ip) {
            Ok(()) => out.deviations.push(Deviation::new(
                rules::LEGACY_UNKNOWN_SENDER,
                sev,
                format!("Unitree legacy {kind_name} {what} from {src_ip}, which is not in {list}"),
            )),
            Err(flood) => {
                stats.unknown_sender_aggregated += 1;
                if let Some(n) = flood {
                    let class_name = if class == Some(true) {
                        "command"
                    } else {
                        "state / unclassified"
                    };
                    out.deviations.push(Deviation::new(
                        rules::LEGACY_SENDER_FLOOD,
                        sev,
                        format!(
                            "Unitree legacy {class_name} frames from more than                              {MAX_REPORTED_UNKNOWN_SENDERS} unlisted source addresses (not in                              {list}): {n} frames from further unlisted senders so far (latest                              {src_ip}); a spoofed-source flood or a scan"
                        ),
                    ));
                }
            }
        }
    } else if class == Some(true) {
        if let Some(want) = ip.and_then(|ip| opts.sender_macs.get(&ip)) {
            let problem = match (udp.src_mac, udp.reassembled) {
                (Some(m), _) if m == *want => None,
                (Some(m), _) => Some(format!(
                    "link-layer source {} is not the bound {}",
                    format_mac(&m),
                    format_mac(want)
                )),
                (None, true) => Some(format!(
                    "the datagram was reassembled from IP fragments, so its link-layer source                      cannot be verified against the bound {} (legacy frames are never                      fragmented by the SDK)",
                    format_mac(want)
                )),
                (None, false) => {
                    stats.mac_unverified += 1;
                    None
                }
            };
            if let Some(problem) = problem {
                stats.mac_mismatch += 1;
                allowed = false;
                let key = format!(
                    "{src_ip}/{}",
                    udp.src_mac.map_or("fragmented".into(), |m| format_mac(&m))
                );
                match tracker.mac.admit(&key) {
                    Ok(()) => out.deviations.push(Deviation::new(
                        rules::LEGACY_SENDER_MAC_MISMATCH,
                        Severity::High,
                        format!(
                            "Unitree legacy {kind_name} command from {src_ip} (a listed command                              sender): {problem}; another host on the LAN may be using the                              sender's IP address"
                        ),
                    )),
                    Err(Some(n)) => out.deviations.push(Deviation::new(
                        rules::LEGACY_SENDER_FLOOD,
                        Severity::High,
                        format!(
                            "Unitree legacy commands from listed sender IPs with more than                              {MAX_REPORTED_UNKNOWN_SENDERS} different wrong link-layer sources:                              {n} further frames so far (latest {src_ip})"
                        ),
                    )),
                    Err(None) => {}
                }
            }
        }
    }
    let frame = match decoded {
        Ok(f) => f,
        Err(e) => {
            stats.undecodable += 1;
            // Value-free except the sender (dedup key is rule + detail).
            let what = match e {
                LegacyFrameError::Compressed { kind, .. } => {
                    format!("legacy {kind:?} in the unpublished compressed wire form")
                }
                LegacyFrameError::UnknownLength { .. } => {
                    "a UDP payload whose length matches no legacy frame".to_string()
                }
            };
            out.deviations.push(Deviation::new(
                crate::motion::rules::MOTION_UNDECODABLE_SAMPLE,
                Severity::Medium,
                format!(
                    "Unitree legacy UDP from {src_ip}:{} to port {} was not inspected: {what}",
                    udp.src_port, udp.dst_port
                ),
            ));
            return out;
        }
    };
    if frame.is_command() {
        stats.commands += 1;
    } else {
        stats.states += 1;
    }
    let event = frame.to_event(&EventContext {
        channel: frame.channel(),
        writer_guid: None,
        timestamp_ns: capture_ns,
    });
    out.event = Some((event, frame, allowed));
    out
}

/// The DDS-style type label of a legacy frame, for [`crate::MotionSample::type_name`].
pub fn type_label(kind: LegacyKind) -> &'static str {
    kind.type_label()
}

/// Whether `channel` is one of the legacy channels.
pub fn is_legacy_channel(channel: &str) -> bool {
    channels::ALL.contains(&channel)
}
