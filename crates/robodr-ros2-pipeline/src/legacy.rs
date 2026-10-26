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
//! | When | Rule | Severity |
//! |---|---|---|
//! | a command frame from a source IP not in [`LegacyOptions::command_senders`] | [`rules::LEGACY_UNKNOWN_SENDER`] | Critical (anyone on the robot's LAN can drive a Go1 this way; the protocol has no authentication) |
//! | a state frame from a source IP not in [`LegacyOptions::robot_addresses`] | [`rules::LEGACY_UNKNOWN_SENDER`] | Medium (spoofed telemetry) |
//! | a payload on a legacy port that is no decodable frame: the v3.8.6 "compressed" `LowCmd` / `LowState` (614 / 807 B, layout unpublished) or an unknown length | `robot.motion.undecodable_sample` | Medium, rate limited |
//!
//! Every finding is deduplicated like every other pipeline finding (rule +
//! detail; the sender address is in the detail, so one finding per sender).
//!
//! # Limits (be honest)
//!
//! * The legacy protocol has no identity: the sender is its source IP, which
//!   is not authenticated (anyone on the LAN can forge it). A forged source
//!   address of an allowed sender is not detected here.
//! * Go1 low-level frames in the v3.8.6 compressed wire form are reported,
//!   not inspected; the joint firewall therefore never sees legacy joint
//!   frames (only the profile envelope of decodable `LowCmd` frames does).
//! * The CRC is advisory and only reported in the black box via the event;
//!   `encryptCRC` mode is not verifiable ([`robodr_cdr::unitree_legacy::LegacyCrcMode`]).
//! * Only synthetic frames built from the published `comm.h` layout have
//!   gone through this path; no capture of a real Go1 was available.

use std::collections::BTreeSet;
use std::net::IpAddr;

use robodr_cdr::unitree_legacy::{channels, LegacyFrame, LegacyFrameError, LegacyKind};
use robodr_cdr::EventContext;
use robodr_events::{Deviation, RobotEvent, Severity};
use serde::Serialize;

use crate::source::LegacyUdp;

/// Rule ids raised by the legacy UDP path.
pub mod rules {
    /// A legacy UDP frame from a source IP the configuration does not list.
    /// Critical (command) / Medium (state).
    pub const LEGACY_UNKNOWN_SENDER: &str = "robot.unitree.legacy_unknown_sender";
}

/// The SDK's default legacy UDP ports (`unitree_legged_sdk` `udp.h` and
/// examples): 8007 low-level server, 8082 high-level server, 8080 / 8090
/// client.
pub const DEFAULT_LEGACY_PORTS: [u16; 4] = [8007, 8080, 8082, 8090];

/// Most entries of [`LegacyOptions::command_senders`] /
/// [`LegacyOptions::robot_addresses`].
pub const MAX_LEGACY_ADDRESSES: usize = 64;

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

/// Counters of the legacy UDP path.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize)]
pub struct LegacyStats {
    /// Legacy datagrams seen (also while disabled).
    pub datagrams: u64,
    /// Seen while the path is disabled (dropped).
    pub ignored: u64,
    pub commands: u64,
    pub states: u64,
    /// Not decodable (compressed form or unknown length).
    pub undecodable: u64,
    /// Frames from a sender the configuration does not list.
    pub unknown_sender: u64,
}

/// One legacy datagram's result (before dedup / profile evaluation).
pub(crate) struct LegacyOutput {
    pub deviations: Vec<Deviation>,
    /// The decoded frame, its event and whether its sender is listed.
    pub event: Option<(RobotEvent, LegacyFrame, bool)>,
}

/// Decode one legacy datagram. `capture_ns` stamps the event.
pub(crate) fn process(
    opts: &LegacyOptions,
    stats: &mut LegacyStats,
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
    let frame = match LegacyFrame::decode(payload) {
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
    let command = frame.is_command();
    if command {
        stats.commands += 1;
    } else {
        stats.states += 1;
    }
    let (allowed, list, sev) = if command {
        (
            ip.is_some_and(|ip| opts.command_senders.contains(&ip)),
            "unitree_legacy.command_senders",
            Severity::Critical,
        )
    } else {
        (
            ip.is_some_and(|ip| opts.robot_addresses.contains(&ip)),
            "unitree_legacy.robot_addresses",
            Severity::Medium,
        )
    };
    if !allowed {
        stats.unknown_sender += 1;
        let what = if command {
            "command (the legacy protocol is unauthenticated: this host can drive the robot)"
        } else {
            "state (spoofed robot telemetry?)"
        };
        out.deviations.push(Deviation::new(
            rules::LEGACY_UNKNOWN_SENDER,
            sev,
            format!(
                "Unitree legacy {:?} {what} from {src_ip}, which is not in {list}",
                frame.kind()
            ),
        ));
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
    match kind {
        LegacyKind::HighCmd => "unitree_legged_sdk::HighCmd",
        LegacyKind::HighState => "unitree_legged_sdk::HighState",
        LegacyKind::LowCmd => "unitree_legged_sdk::LowCmd",
        LegacyKind::LowState => "unitree_legged_sdk::LowState",
    }
}

/// Whether `channel` is one of the legacy channels.
pub fn is_legacy_channel(channel: &str) -> bool {
    channels::ALL.contains(&channel)
}
