//! Input layer: where commissioning events come from.
//!
//! Everything downstream (learner, checker) consumes an [`EventSource`], a
//! minimal pull-style trait. Implementations:
//!
//! * [`JsonlSource`]: JSON Lines of [`RobotEvent`] in the serde tagged format
//!   (`{"kind":"ros2_participant_discovered", ...}`). Position = line number.
//! * [`PcapSource`]: a classic pcap or pcapng capture of the robot bus,
//!   decoded with `robodr-capture` (Ethernet/SLL/raw IP, VLAN, IPv4/IPv6,
//!   bounded IP fragment reassembly, RTPS filter) and parsed with
//!   `robodr-rtps` through one [`FragmentReassembler`] per capture, so SEDP
//!   announcements split into DATA_FRAG submessages (large XTypes type
//!   information, typical of Fast DDS / Connext) are learned too.
//!   Position = 1-based frame ordinal in the capture file; several events
//!   can share one position (one datagram announces a participant and its
//!   endpoints). The source keeps [`CaptureDiagnostics`] (fragmentation,
//!   reassembly failures, protected submessages) that the learner copies
//!   into the report.
//! * [`VecSource`]: in-memory events for tests and library callers.
//!
//! A pcap yields discovery events (participants, writers, readers) and the
//! **motion commands** found in it: user DATA of writers that announced a
//! command type `robodr-cdr` decodes (`geometry_msgs/Twist`,
//! `TwistStamped`, `trajectory_msgs/JointTrajectory`), decoded exactly as
//! the sensor decodes them and attributed to the writer's participant, so a
//! profile learned from a capture alone gets motion envelopes. A sample is
//! used only when its writer was announced (SEDP) under the sending
//! participant and the datagram came from an IP that participant's own SPDP
//! came from; everything else is counted in
//! [`CaptureDiagnostics::motion_samples_unattributed`] and not learned.
//! Undecodable samples are counted in
//! [`CaptureDiagnostics::motion_samples_undecodable`].

//!
//! # Strictness
//!
//! A commissioning run is supposed to be clean, so the reader is strict: the
//! first malformed line is an error that aborts the source (the learner never
//! silently drops input). Blank lines and lines whose first non-blank char is
//! `#` are skipped, so example files can carry a provenance comment; this is
//! an extension to plain JSONL. Lines are capped at [`MAX_LINE_BYTES`] so a
//! hostile or corrupt file cannot make us buffer unbounded memory.
//!
//! # Hostile captures
//!
//! Capture files are treated as untrusted input. `robodr-capture` validates
//! every record/block length before allocating (classic pcap records over
//! 256 KiB and pcapng blocks over 4 MiB are format errors), and a file that
//! ends mid-record is an error (everything before it was delivered, but the
//! CLI aborts the learn: a truncated capture is not a complete clean run).
//! On top of that this source refuses a capture in which **no** frame had a
//! supported link type (a wrong-linktype file would otherwise learn an empty
//! profile silently) and reports partial problems (unsupported, malformed,
//! truncated, non-RTPS frames) through [`CaptureDiagnostics`], which the
//! learner turns into warnings. A single datagram expands into a bounded
//! number of events (bounded by the datagram size), so the event queue is
//! bounded too; memory across the whole capture is bounded by the
//! learner's caps (see `learner`).
//!
//! # Timestamps
//!
//! Packet captures carry a capture time per frame, exposed as
//! [`SourcedEvent::ts`]; the learner uses it for minimum-observation-duration
//! checks. JSONL recordings carry none (`RobotEvent` has no timestamp), so
//! duration checks do not apply to them. Capture timestamps come from the
//! file (written by the commissioning host, not by bus participants); the
//! learner uses them for minimum duration and for the late/brief flags, so a
//! frame flood cannot dilute those (see `learner`).
//!
//! # Senders
//!
//! Packet-capture events also carry an [`Origin`]: the GUID prefix the RTPS
//! message was sent under (header or INFO_SRC) and the source IP. Endpoint
//! events are emitted per announcement with that announcement's own sender,
//! so the learner can refuse endpoints whose claimed owner did not send
//! them (`endpoint_sender_mismatch`).

use robodr_capture::{CaptureError, CaptureFile, RtpsDatagrams};
use robodr_events::RobotEvent;
use robodr_rtps::{hex12, EndpointKind, FragmentReassembler, Guid, PayloadKind, UserDataWalker};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet, HashMap, VecDeque};
use std::fmt;
use std::fs::File;
use std::io::{self, BufRead, BufReader, Read};
use std::path::PathBuf;
use std::time::Duration;

/// Maximum accepted length of one JSONL line, in bytes (newline excluded).
pub const MAX_LINE_BYTES: usize = 1 << 20;

/// One event plus where it came from inside its source (1-based line number
/// for JSONL; 1-based frame ordinal for pcap).
#[derive(Debug, Clone, PartialEq)]
pub struct SourcedEvent {
    pub position: u64,
    pub event: RobotEvent,
    /// Capture time of the frame that carried the event (packet captures
    /// only; `None` for JSONL and in-memory sources).
    pub ts: Option<Duration>,
    /// Who sent the datagram that carried the event (packet captures only;
    /// `None` for JSONL and in-memory sources, whose events carry no sender).
    pub origin: Option<Origin>,
}

/// The sender of the RTPS message an event was decoded from.
///
/// `RobotEvent` endpoints only carry the GUID prefix the announcement
/// *claims* (`PID_ENDPOINT_GUID`, unauthenticated). The learner compares it
/// with the sender (see `learner`, "endpoint provenance") so a participant
/// cannot get endpoints learned under another participant's GUID.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Origin {
    /// GUID prefix the message was sent under: the RTPS header prefix, as
    /// changed by a preceding INFO_SRC (24 lower-case hex chars).
    pub sender_prefix: String,
    /// Source IP address of the datagram.
    pub src_ip: String,
}

/// A stream of robot events. Pull-based so sources can be files, captures or
/// in-memory test vectors without the consumer caring.
pub trait EventSource {
    /// Human-readable name of the source (usually the file path); it appears
    /// in reports so the OEM can trace a finding back to its run.
    fn label(&self) -> &str;
    /// Next event, `None` at end of stream. After an `Err`, a source returns
    /// `None` from then on.
    fn next_event(&mut self) -> Option<Result<SourcedEvent, InputError>>;
    /// Capture-level diagnostics, for packet-capture sources (`None` for
    /// event recordings). Read after the source is drained.
    fn capture_diagnostics(&self) -> Option<CaptureDiagnostics> {
        None
    }
}

/// Errors from reading an event source.
#[derive(Debug)]
pub enum InputError {
    Io {
        source: String,
        error: io::Error,
    },
    LineTooLong {
        source: String,
        line: u64,
    },
    InvalidUtf8 {
        source: String,
        line: u64,
    },
    Parse {
        source: String,
        line: u64,
        message: String,
    },
    /// The capture file could not be read (not a pcap/pcapng, corrupt,
    /// truncated, I/O).
    Capture {
        source: String,
        message: String,
    },
    Unsupported(String),
}

impl fmt::Display for InputError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            InputError::Io { source, error } => write!(f, "{source}: {error}"),
            InputError::LineTooLong { source, line } => {
                write!(
                    f,
                    "{source}:{line}: line longer than {MAX_LINE_BYTES} bytes"
                )
            }
            InputError::InvalidUtf8 { source, line } => {
                write!(f, "{source}:{line}: line is not valid UTF-8")
            }
            InputError::Parse {
                source,
                line,
                message,
            } => write!(f, "{source}:{line}: not a RobotEvent: {message}"),
            InputError::Capture { source, message } => write!(f, "{source}: {message}"),
            InputError::Unsupported(m) => write!(f, "{m}"),
        }
    }
}

impl std::error::Error for InputError {}

/// JSON Lines reader over any `BufRead`.
pub struct JsonlSource<R> {
    label: String,
    reader: R,
    line: u64,
    done: bool,
    buf: Vec<u8>,
}

impl JsonlSource<BufReader<File>> {
    /// Open a JSONL file; the label is the path as given.
    pub fn open(path: &std::path::Path) -> Result<Self, InputError> {
        let label = path.display().to_string();
        let file = File::open(path).map_err(|error| InputError::Io {
            source: label.clone(),
            error,
        })?;
        Ok(Self::new(label, BufReader::new(file)))
    }
}

impl<R: BufRead> JsonlSource<R> {
    pub fn new(label: impl Into<String>, reader: R) -> Self {
        Self {
            label: label.into(),
            reader,
            line: 0,
            done: false,
            buf: Vec::new(),
        }
    }

    fn fail(&mut self, e: InputError) -> Option<Result<SourcedEvent, InputError>> {
        self.done = true;
        Some(Err(e))
    }
}

impl<R: BufRead> EventSource for JsonlSource<R> {
    fn label(&self) -> &str {
        &self.label
    }

    fn next_event(&mut self) -> Option<Result<SourcedEvent, InputError>> {
        while !self.done {
            self.buf.clear();
            self.line += 1;
            let limit = MAX_LINE_BYTES as u64 + 2; // room for "\r\n"
            let n = match (&mut self.reader)
                .take(limit)
                .read_until(b'\n', &mut self.buf)
            {
                Ok(n) => n,
                Err(error) => {
                    let source = self.label.clone();
                    return self.fail(InputError::Io { source, error });
                }
            };
            if n == 0 {
                self.done = true;
                return None;
            }
            if self.buf.last() == Some(&b'\n') {
                self.buf.pop();
            }
            if self.buf.last() == Some(&b'\r') {
                self.buf.pop();
            }
            if self.buf.len() > MAX_LINE_BYTES {
                let (source, line) = (self.label.clone(), self.line);
                return self.fail(InputError::LineTooLong { source, line });
            }
            let Ok(text) = std::str::from_utf8(&self.buf) else {
                let (source, line) = (self.label.clone(), self.line);
                return self.fail(InputError::InvalidUtf8 { source, line });
            };
            let trimmed = text.trim();
            if trimmed.is_empty() || trimmed.starts_with('#') {
                continue;
            }
            return match serde_json::from_str::<RobotEvent>(trimmed) {
                Ok(event) => Some(Ok(SourcedEvent {
                    position: self.line,
                    event,
                    ts: None,
                    origin: None,
                })),
                Err(e) => {
                    let (source, line) = (self.label.clone(), self.line);
                    self.fail(InputError::Parse {
                        source,
                        line,
                        message: e.to_string(),
                    })
                }
            };
        }
        None
    }
}

/// In-memory source, handy for tests and for callers that already hold events.
pub struct VecSource {
    label: String,
    events: std::vec::IntoIter<RobotEvent>,
    position: u64,
}

impl VecSource {
    pub fn new(label: impl Into<String>, events: Vec<RobotEvent>) -> Self {
        Self {
            label: label.into(),
            events: events.into_iter(),
            position: 0,
        }
    }
}

impl EventSource for VecSource {
    fn label(&self) -> &str {
        &self.label
    }
    fn next_event(&mut self) -> Option<Result<SourcedEvent, InputError>> {
        let event = self.events.next()?;
        self.position += 1;
        Some(Ok(SourcedEvent {
            position: self.position,
            event,
            ts: None,
            origin: None,
        }))
    }
}

/// Counters from a packet-capture source, copied into the commissioning
/// report so the OEM can judge whether the capture saw all of discovery.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct CaptureDiagnostics {
    /// Frames read from the file.
    pub frames: u64,
    /// UDP datagrams accepted as RTPS (well-known port or `RTPS` magic).
    pub rtps_datagrams: u64,
    /// Accepted datagrams that did not parse as RTPS at all.
    pub not_rtps: u64,
    /// Frames cut short by the capture snap length (dropped, not parsed).
    pub truncated_frames: u64,
    /// Frames that failed to decode (bad IP/UDP headers).
    pub malformed_frames: u64,
    /// Frames with a link type the decoder does not support.
    pub unsupported_linktype_frames: u64,
    /// IP fragments seen, and datagrams rebuilt from them.
    pub ip_fragments: u64,
    pub ip_reassembled: u64,
    /// IP datagrams lost in reassembly (conflicting overlap, bad geometry,
    /// timeout, capacity).
    pub ip_reassembly_dropped: u64,
    /// DATA_FRAG submessages from builtin discovery writers (SPDP/SEDP).
    pub discovery_data_frag: u64,
    /// Discovery samples rebuilt from DATA_FRAG.
    pub discovery_frag_completed: u64,
    /// Discovery fragments refused (bad geometry, over a cap, conflicting
    /// overlap).
    pub discovery_frag_rejected: u64,
    /// Partial discovery samples evicted to stay within memory caps.
    pub discovery_frag_evicted: u64,
    /// Partial discovery samples still incomplete at end of capture.
    pub discovery_frag_incomplete: u64,
    /// DDS-Security protected submessages (content unreadable).
    pub secure_submessages: u64,
    /// RTPS parser anomalies (malformed discovery data).
    pub rtps_anomalies: u64,
    /// Motion command samples decoded and handed to the learner.
    #[serde(default)]
    pub motion_samples: u64,
    /// Samples of announced motion command writers that did not decode
    /// (not learned).
    #[serde(default)]
    pub motion_samples_undecodable: u64,
    /// Samples of announced motion command writers sent from an IP the
    /// writer's participant never announced itself from (not learned).
    #[serde(default)]
    pub motion_samples_unattributed: u64,
    /// Packets of a robot middleware RoboDR does not decode: Zenoh
    /// (`rmw_zenoh_cpp`, TCP/UDP 7447, scouting UDP 7446). Nothing in them
    /// was learned.
    #[serde(default)]
    pub zenoh_packets: u64,
    /// Unitree legacy UDP datagrams (Go1 generation) seen on the configured
    /// legacy ports (`learn --unitree-legacy`).
    #[serde(default)]
    pub unitree_legacy_frames: u64,
    /// Legacy commands (`HighCmd` / decodable `LowCmd`) learned.
    #[serde(default)]
    pub unitree_legacy_commands: u64,
    /// Legacy datagrams that are no decodable frame (compressed `LowState`
    /// form, unknown length): not learned.
    #[serde(default)]
    pub unitree_legacy_undecodable: u64,
    /// Source IPs that sent legacy commands (at most
    /// [`MAX_LEGACY_SENDERS`]): the candidates for the sensor's
    /// `unitree_legacy.command_senders`, to be confirmed by the operator.
    #[serde(default)]
    pub unitree_legacy_command_senders: BTreeSet<String>,
    /// Source IPs of SPDP announcements that advertise locators a capture
    /// cannot inspect (shared memory, TCP, unknown kinds), with those
    /// transports (`shared memory (shm)`), at most
    /// [`MAX_UNINSPECTED_HOSTS`]: traffic over them is not in the capture
    /// and was not learned (the sensor reports the same SPDP as
    /// `robot.capture.unsupported_transport`).
    #[serde(default)]
    pub uninspected_transports: BTreeMap<String, BTreeSet<String>>,
    /// Participants (GUID prefix hex) whose own SPDP the sensor's identity
    /// resolver would not match to an identity learned from it, at most
    /// [`MAX_UNVERIFIED_PREFIXES`]: the learner takes an identity's
    /// `vendor` from the first two prefix bytes, and the resolver accepts
    /// them only as the SPDP's `PID_VENDORID` or as the subject hash of a
    /// claimed PKI-DH certificate subject it can rebuild
    /// (`robodr_rtps::secured_prefix`). Value: why, for the warning.
    #[serde(default)]
    pub identity_prefix_unverified: BTreeMap<String, String>,
}

/// Most legacy command senders listed in [`CaptureDiagnostics`].
pub const MAX_LEGACY_SENDERS: usize = 64;
/// Most hosts listed in [`CaptureDiagnostics::uninspected_transports`].
pub const MAX_UNINSPECTED_HOSTS: usize = 64;
/// Most participants listed in
/// [`CaptureDiagnostics::identity_prefix_unverified`].
pub const MAX_UNVERIFIED_PREFIXES: usize = 64;

/// Why the sensor's identity resolver would not accept the identity
/// `vendor` the learner takes from this participant's GUID prefix (its
/// first two bytes), or `None` if it would. Same rule as
/// `robodr_ros2_pipeline::identity`: the SPDP's `PID_VENDORID` must be
/// present and equal those bytes, or the PKI-DH certificate subject it
/// claims must hash to the prefix (DDS-Security §9.3.3).
pub fn identity_prefix_unverified(spdp: &robodr_rtps::SpdpInfo) -> Option<String> {
    let p = spdp.guid_prefix;
    let [h0, h1, ..] = p;
    let Some(vendor) = spdp.vendor_id else {
        return Some("its SPDP has no vendor id (PID_VENDORID)".into());
    };
    if vendor == [h0, h1] {
        return None;
    }
    let [v0, v1] = vendor;
    let shown = |s: &str| -> String { s.chars().filter(|c| !c.is_control()).take(128).collect() };
    match spdp.security.pki_identity_subject() {
        Some(s) if robodr_rtps::secured_prefix::prefix_matches_subject(&p, s) => None,
        Some(s) => Some(format!(
            "its GUID prefix does not derive from the certificate subject it claims ({:?}) in \
             a subject form RoboDR rebuilds, and its vendor id {:02x}{:02x} is not the \
             prefix's first two bytes",
            shown(s),
            v0,
            v1
        )),
        None => Some(format!(
            "its vendor id {:02x}{:02x} is not the prefix's first two bytes and it claims no \
             PKI-DH certificate subject",
            v0, v1
        )),
    }
}

impl CaptureDiagnostics {
    /// Fragmented discovery was seen but at least one sample was not
    /// rebuilt: some endpoint announcements are probably missing.
    pub fn discovery_reassembly_failed(&self) -> bool {
        self.discovery_frag_rejected > 0
            || self.discovery_frag_evicted > 0
            || self.discovery_frag_incomplete > 0
    }

    /// Sum of two runs' counters.
    pub fn add(&mut self, o: &CaptureDiagnostics) {
        for ip in &o.unitree_legacy_command_senders {
            if self.unitree_legacy_command_senders.len() < MAX_LEGACY_SENDERS {
                self.unitree_legacy_command_senders.insert(ip.clone());
            }
        }
        let pairs: [(&mut u64, u64); 23] = [
            (&mut self.unitree_legacy_frames, o.unitree_legacy_frames),
            (&mut self.unitree_legacy_commands, o.unitree_legacy_commands),
            (
                &mut self.unitree_legacy_undecodable,
                o.unitree_legacy_undecodable,
            ),
            (&mut self.zenoh_packets, o.zenoh_packets),
            (&mut self.motion_samples, o.motion_samples),
            (
                &mut self.motion_samples_undecodable,
                o.motion_samples_undecodable,
            ),
            (
                &mut self.motion_samples_unattributed,
                o.motion_samples_unattributed,
            ),
            (&mut self.frames, o.frames),
            (&mut self.rtps_datagrams, o.rtps_datagrams),
            (&mut self.not_rtps, o.not_rtps),
            (&mut self.truncated_frames, o.truncated_frames),
            (&mut self.malformed_frames, o.malformed_frames),
            (
                &mut self.unsupported_linktype_frames,
                o.unsupported_linktype_frames,
            ),
            (&mut self.ip_fragments, o.ip_fragments),
            (&mut self.ip_reassembled, o.ip_reassembled),
            (&mut self.ip_reassembly_dropped, o.ip_reassembly_dropped),
            (&mut self.discovery_data_frag, o.discovery_data_frag),
            (
                &mut self.discovery_frag_completed,
                o.discovery_frag_completed,
            ),
            (&mut self.discovery_frag_rejected, o.discovery_frag_rejected),
            (&mut self.discovery_frag_evicted, o.discovery_frag_evicted),
            (
                &mut self.discovery_frag_incomplete,
                o.discovery_frag_incomplete,
            ),
            (&mut self.secure_submessages, o.secure_submessages),
            (&mut self.rtps_anomalies, o.rtps_anomalies),
        ];
        for (a, b) in pairs {
            *a = a.saturating_add(b);
        }
        for (ip, t) in &o.uninspected_transports {
            if self.uninspected_transports.len() < MAX_UNINSPECTED_HOSTS
                || self.uninspected_transports.contains_key(ip)
            {
                self.uninspected_transports
                    .entry(ip.clone())
                    .or_default()
                    .extend(t.iter().cloned());
            }
        }
        for (g, why) in &o.identity_prefix_unverified {
            if self.identity_prefix_unverified.len() < MAX_UNVERIFIED_PREFIXES {
                self.identity_prefix_unverified
                    .entry(g.clone())
                    .or_insert_with(|| why.clone());
            }
        }
    }
}

/// Discovery events from a pcap / pcapng capture. See the module docs.
pub struct PcapSource<R: Read> {
    label: String,
    datagrams: RtpsDatagrams<CaptureFile<R>>,
    frag: FragmentReassembler,
    queue: VecDeque<SourcedEvent>,
    not_rtps: u64,
    discovery_data_frag: u64,
    secure: u64,
    anomalies: u64,
    done: bool,
    /// User-data walker for motion samples (owns its DATA_FRAG reassembler).
    walker: UserDataWalker,
    /// Announced motion command writers: GUID -> (channel, DDS type name).
    motion_writers: HashMap<Guid, (String, String)>,
    /// Previous low-level joint frame per motion channel, for
    /// `MotionCommand::joint_position_step` (same rule as the sensor
    /// pipeline: the previous frame decoded on the channel, any writer).
    last_joint_frames: HashMap<String, robodr_cdr::JointCommandFrame>,
    /// Source IPs each participant's own SPDP came from.
    spdp_ips: HashMap<[u8; 12], BTreeSet<String>>,
    motion_samples: u64,
    motion_undecodable: u64,
    motion_unattributed: u64,
    legacy_commands: u64,
    legacy_undecodable: u64,
    legacy_senders: BTreeSet<String>,
    uninspected_transports: BTreeMap<String, BTreeSet<String>>,
    identity_prefix_unverified: BTreeMap<String, String>,
}

/// Options of the capture inputs.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct InputOptions {
    /// Also learn Unitree legacy UDP (Go1 generation) frames on these UDP
    /// ports (source or destination); empty = off. See
    /// [`PcapSource::new_with_options`].
    pub unitree_legacy_ports: BTreeSet<u16>,
}

/// Most motion writers tracked per capture.
const MAX_MOTION_WRITERS: usize = 4096;
/// Most participants whose SPDP source IPs are tracked per capture.
const MAX_SPDP_PARTICIPANTS: usize = 4096;

impl PcapSource<BufReader<File>> {
    /// Open a capture file (format detected from its magic).
    pub fn open(path: &std::path::Path) -> Result<Self, InputError> {
        Self::open_with_options(path, &InputOptions::default())
    }

    /// [`PcapSource::open`] with [`InputOptions`].
    pub fn open_with_options(
        path: &std::path::Path,
        opts: &InputOptions,
    ) -> Result<Self, InputError> {
        let label = path.display().to_string();
        let file = File::open(path).map_err(|error| InputError::Io {
            source: label.clone(),
            error,
        })?;
        Self::new_with_options(label, BufReader::new(file), opts)
    }
}

impl<R: Read> PcapSource<R> {
    /// Read a capture from any reader (pcap or pcapng, detected).
    pub fn new(label: impl Into<String>, reader: R) -> Result<Self, InputError> {
        Self::new_with_options(label, reader, &InputOptions::default())
    }

    /// [`PcapSource::new`] with [`InputOptions`]. With
    /// `unitree_legacy_ports`, UDP on those ports that is not RTPS is
    /// decoded as Unitree legacy frames
    /// (`robodr_cdr::unitree_legacy::LegacyFrame`, by length): every
    /// `HighCmd` and decodable `LowCmd` becomes a `MotionCommand` on
    /// `/unitree_legacy/high_cmd` / `/unitree_legacy/low_cmd` (no source
    /// GUID: the legacy protocol has none), learned like any other
    /// command; the learner makes those channels writable. State frames are
    /// not learned. The command senders' IPs are listed in
    /// [`CaptureDiagnostics::unitree_legacy_command_senders`].
    pub fn new_with_options(
        label: impl Into<String>,
        reader: R,
        opts: &InputOptions,
    ) -> Result<Self, InputError> {
        let label = label.into();
        let file = CaptureFile::new(reader).map_err(|e| capture_error(&label, &e))?;
        let filter = robodr_capture::RtpsFilter::default()
            .with_legacy_udp_ports(opts.unitree_legacy_ports.iter().copied());
        Ok(Self {
            label,
            datagrams: RtpsDatagrams::new(file, filter),
            frag: FragmentReassembler::default(),
            queue: VecDeque::new(),
            not_rtps: 0,
            discovery_data_frag: 0,
            secure: 0,
            anomalies: 0,
            done: false,
            walker: UserDataWalker::default(),
            motion_writers: HashMap::new(),
            last_joint_frames: HashMap::new(),
            spdp_ips: HashMap::new(),
            motion_samples: 0,
            motion_undecodable: 0,
            motion_unattributed: 0,
            legacy_commands: 0,
            legacy_undecodable: 0,
            legacy_senders: BTreeSet::new(),
            uninspected_transports: BTreeMap::new(),
            identity_prefix_unverified: BTreeMap::new(),
        })
    }
}

fn capture_error(label: &str, e: &CaptureError) -> InputError {
    InputError::Capture {
        source: label.to_string(),
        message: format!("not a readable pcap/pcapng capture: {e}"),
    }
}

impl<R: Read> EventSource for PcapSource<R> {
    fn label(&self) -> &str {
        &self.label
    }

    fn next_event(&mut self) -> Option<Result<SourcedEvent, InputError>> {
        loop {
            if let Some(e) = self.queue.pop_front() {
                return Some(Ok(e));
            }
            if self.done {
                return None;
            }
            let Some(pkt) = self.datagrams.next_packet() else {
                // Files never time out, so `None` means EOF or a fatal error.
                self.done = true;
                if let Some(e) = self.datagrams.last_error() {
                    return Some(Err(capture_error(&self.label, e)));
                }
                // A capture whose every frame has a link type we cannot
                // decode (e.g. 802.11 radiotap, USB) would learn an empty
                // profile without complaint: refuse it instead.
                let st = self.datagrams.stats();
                if st.frames > 0 && st.unsupported_linktype == st.frames {
                    return Some(Err(InputError::Capture {
                        source: self.label.clone(),
                        message: format!(
                            "none of the {} frame(s) has a supported link type (supported: \
                             Ethernet, Linux SLL/SLL2, raw IP, loopback/null); capture on \
                             the robot's wired bus interface",
                            st.frames
                        ),
                    }));
                }
                return None;
            };
            // The frame that completed this datagram (last fragment, if any).
            let position = self.datagrams.stats().frames;
            if pkt.kind == robodr_capture::PacketKind::UnitreeLegacy {
                self.legacy_event(&pkt, position);
                // RTPS on a legacy port (the sensor reports it): learned as
                // RTPS too, as the sensor inspects it on both paths.
                if !pkt.also_rtps {
                    continue;
                }
            }
            let Some(report) = self.frag.parse_datagram_detailed(&pkt.payload) else {
                // Cyclone DDS sends a 1-byte datagram to its own receive
                // sockets to wake its threads on shutdown (seen on every
                // Cyclone capture of a node stopping): not a malformed bus.
                if pkt.payload.len() > 1 {
                    self.not_rtps += 1;
                }
                continue;
            };
            let st = &report.stats;
            self.discovery_data_frag += u64::from(st.discovery_data_frag);
            self.secure += u64::from(st.secure);
            self.anomalies += u64::from(st.anomalies);
            let src_ip = pkt.src.to_string();
            let ts = Some(pkt.ts);
            let header = Origin {
                sender_prefix: hex12(&report.header.guid_prefix),
                src_ip: src_ip.clone(),
            };
            // Participants exactly as the sensor sees them ...
            self.queue.extend(
                report
                    .to_events(&src_ip)
                    .into_iter()
                    .filter(|e| matches!(e, RobotEvent::Ros2ParticipantDiscovered(_)))
                    .map(|event| SourcedEvent {
                        position,
                        event,
                        ts,
                        origin: Some(header.clone()),
                    }),
            );
            // ... and endpoints (same readings as `to_events`, including the
            // copies attributed to a relaying sender), each tagged with the
            // prefix that actually sent its announcement.
            for spdp in &report.participants {
                if spdp.source == spdp.guid_prefix
                    && (self.spdp_ips.len() < MAX_SPDP_PARTICIPANTS
                        || self.spdp_ips.contains_key(&spdp.guid_prefix))
                {
                    let ips = self.spdp_ips.entry(spdp.guid_prefix).or_default();
                    if ips.len() < 16 {
                        ips.insert(src_ip.clone());
                    }
                }
                self.note_spdp(spdp, &src_ip);
            }
            for e in &report.endpoints {
                // A motion command writer announced by its own participant.
                if let (EndpointKind::Writer, Some(g)) = (e.kind, e.guid) {
                    let rn = robodr_events::graph::demangle(&e.topic);
                    let command = robodr_cdr::MessageKind::from_type_name(&e.type_name)
                        .is_some_and(|k| k.role() == robodr_cdr::MotionRole::Command);
                    if command
                        && e.source == e.participant
                        && !e.guid_conflict
                        && rn.kind == robodr_events::graph::RosNameKind::Topic
                        && (self.motion_writers.len() < MAX_MOTION_WRITERS
                            || self.motion_writers.contains_key(&g))
                    {
                        self.motion_writers
                            .insert(g, (rn.name.clone(), e.type_name.clone()));
                    }
                }
                let origin = Origin {
                    sender_prefix: hex12(&e.source),
                    src_ip: src_ip.clone(),
                };
                for ep in e.to_endpoints() {
                    let event = match e.kind {
                        EndpointKind::Writer => RobotEvent::Ros2WriterDiscovered(ep),
                        EndpointKind::Reader => RobotEvent::Ros2ReaderDiscovered(ep),
                    };
                    self.queue.push_back(SourcedEvent {
                        position,
                        event,
                        ts,
                        origin: Some(origin.clone()),
                    });
                }
            }
            self.motion_events(&pkt.payload, &src_ip, position, ts);
        }
    }

    fn capture_diagnostics(&self) -> Option<CaptureDiagnostics> {
        let c = self.datagrams.stats();
        let motion = (
            self.motion_samples,
            self.motion_undecodable,
            self.motion_unattributed,
        );
        let r = self.datagrams.reassembly_stats();
        Some(CaptureDiagnostics {
            frames: c.frames,
            rtps_datagrams: c.rtps,
            not_rtps: self.not_rtps,
            truncated_frames: c.truncated,
            malformed_frames: c.malformed,
            unsupported_linktype_frames: c.unsupported_linktype,
            ip_fragments: c.fragments,
            ip_reassembled: c.reassembled,
            ip_reassembly_dropped: r
                .dropped_overlap
                .saturating_add(r.dropped_invalid)
                .saturating_add(r.dropped_timeout)
                .saturating_add(r.dropped_capacity),
            discovery_data_frag: self.discovery_data_frag,
            discovery_frag_completed: self.frag.completed(),
            discovery_frag_rejected: self.frag.dropped(),
            discovery_frag_evicted: self.frag.evicted(),
            discovery_frag_incomplete: self.frag.pending_samples() as u64,
            secure_submessages: self.secure,
            rtps_anomalies: self.anomalies,
            motion_samples: motion.0,
            motion_samples_undecodable: motion.1,
            motion_samples_unattributed: motion.2,
            zenoh_packets: c.zenoh,
            unitree_legacy_frames: c.legacy_udp,
            unitree_legacy_commands: self.legacy_commands,
            unitree_legacy_undecodable: self.legacy_undecodable,
            unitree_legacy_command_senders: self.legacy_senders.clone(),
            uninspected_transports: self.uninspected_transports.clone(),
            identity_prefix_unverified: self.identity_prefix_unverified.clone(),
        })
    }
}

impl<R: Read> PcapSource<R> {
    /// Transports the capture cannot inspect, and identities the sensor
    /// would not resolve (see [`CaptureDiagnostics`]), from one SPDP.
    fn note_spdp(&mut self, spdp: &robodr_rtps::SpdpInfo, src_ip: &str) {
        let t = spdp.uninspected_transports();
        if !t.is_empty()
            && (self.uninspected_transports.len() < MAX_UNINSPECTED_HOSTS
                || self.uninspected_transports.contains_key(src_ip))
        {
            self.uninspected_transports
                .entry(src_ip.to_owned())
                .or_default()
                .extend(t.iter().map(|(t, k)| format!("{} ({k})", t.name())));
        }
        // Only a participant's own announcement: a relayed copy's vendor
        // id is the relayed participant's claim all the same, but the
        // learner keys identities on own announcements.
        if spdp.source == spdp.guid_prefix
            && self.identity_prefix_unverified.len() < MAX_UNVERIFIED_PREFIXES
        {
            let g = hex12(&spdp.guid_prefix);
            if let std::collections::btree_map::Entry::Vacant(e) =
                self.identity_prefix_unverified.entry(g)
            {
                if let Some(why) = identity_prefix_unverified(spdp) {
                    e.insert(why);
                }
            }
        }
    }

    /// One Unitree legacy UDP datagram (see [`PcapSource::new_with_options`]).
    fn legacy_event(&mut self, pkt: &robodr_capture::RtpsPacket, position: u64) {
        use robodr_cdr::unitree_legacy::LegacyFrame;
        let frame = match LegacyFrame::decode(&pkt.payload) {
            Ok(f) => f,
            Err(_) => {
                self.legacy_undecodable += 1;
                return;
            }
        };
        if !frame.is_command() {
            return;
        }
        let ts = Some(pkt.ts);
        let channel = frame.channel();
        let mut event = frame.to_event(&robodr_cdr::EventContext {
            channel,
            writer_guid: None,
            timestamp_ns: u64::try_from(pkt.ts.as_nanos()).unwrap_or(u64::MAX),
        });
        if let (RobotEvent::MotionCommand(c), Some(jf)) = (&mut event, frame.joint_command_frame())
        {
            if let Some(prev) = self.last_joint_frames.get_mut(channel) {
                c.joint_position_step = jf.max_position_step(prev);
                *prev = jf;
            } else if self.last_joint_frames.len() < MAX_MOTION_WRITERS {
                self.last_joint_frames.insert(channel.to_string(), jf);
            }
        }
        self.legacy_commands += 1;
        if self.legacy_senders.len() < MAX_LEGACY_SENDERS {
            self.legacy_senders.insert(pkt.src.to_string());
        }
        self.queue.push_back(SourcedEvent {
            position,
            event,
            ts,
            origin: None,
        });
    }

    /// Decode the motion command samples of one datagram (see the module
    /// docs) and queue them as `MotionCommand` events.
    fn motion_events(&mut self, payload: &[u8], src_ip: &str, position: u64, ts: Option<Duration>) {
        if self.motion_writers.is_empty() {
            return;
        }
        let writers = &self.motion_writers;
        let Some(report) = self
            .walker
            .walk_with(payload, |a| writers.contains_key(&a.writer))
        else {
            return;
        };
        let limits = robodr_cdr::Limits::default();
        for s in &report.samples {
            let Some((channel, type_name)) = self.motion_writers.get(&s.address.writer) else {
                continue;
            };
            if s.payload_kind != PayloadKind::Data {
                continue;
            }
            let prefix = s.address.writer_prefix();
            if !self
                .spdp_ips
                .get(&prefix)
                .is_some_and(|ips| ips.contains(src_ip))
            {
                self.motion_unattributed += 1;
                continue;
            }
            let decoded = if s.non_standard_payload {
                None
            } else {
                robodr_cdr::decode_by_type_name(type_name, &s.payload, &limits).ok()
            };
            let Some(decoded) =
                decoded.filter(|d| d.message.role() == robodr_cdr::MotionRole::Command)
            else {
                self.motion_undecodable += 1;
                continue;
            };
            let source = hex12(&prefix);
            let mut event = decoded.message.to_event(&robodr_cdr::EventContext {
                channel,
                // The learner attributes commands to participants (prefix).
                writer_guid: Some(&source),
                timestamp_ns: ts
                    .map(|t| u64::try_from(t.as_nanos()).unwrap_or(u64::MAX))
                    .unwrap_or(0),
            });
            if let (RobotEvent::MotionCommand(c), Some(frame)) =
                (&mut event, decoded.message.joint_command_frame())
            {
                if let Some(prev) = self.last_joint_frames.get_mut(channel) {
                    c.joint_position_step = frame.max_position_step(prev);
                    *prev = frame;
                } else if self.last_joint_frames.len() < MAX_MOTION_WRITERS {
                    self.last_joint_frames.insert(channel.clone(), frame);
                }
            }
            if !matches!(event, RobotEvent::MotionCommand(_)) {
                self.motion_undecodable += 1;
                continue;
            }
            self.motion_samples += 1;
            self.queue.push_back(SourcedEvent {
                position,
                event,
                ts,
                origin: Some(Origin {
                    sender_prefix: source,
                    src_ip: src_ip.to_string(),
                }),
            });
        }
    }
}

/// What the user asked us to read.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum InputSpec {
    /// JSON Lines of `RobotEvent`.
    Jsonl(PathBuf),
    /// A packet capture (classic pcap or pcapng), see [`PcapSource`].
    Pcap(PathBuf),
}

/// Open an input. The single place new input kinds are plugged in.
pub fn open(spec: &InputSpec) -> Result<Box<dyn EventSource>, InputError> {
    open_with_options(spec, &InputOptions::default())
}

/// [`open`] with [`InputOptions`] (they apply to captures only).
pub fn open_with_options(
    spec: &InputSpec,
    opts: &InputOptions,
) -> Result<Box<dyn EventSource>, InputError> {
    match spec {
        InputSpec::Jsonl(p) => Ok(Box::new(JsonlSource::open(p)?)),
        InputSpec::Pcap(p) => Ok(Box::new(PcapSource::open_with_options(p, opts)?)),
    }
}

/// Drain a source into a vector (strict: the first error is returned).
pub fn read_all(src: &mut dyn EventSource) -> Result<Vec<SourcedEvent>, InputError> {
    let mut out = Vec::new();
    while let Some(r) = src.next_event() {
        out.push(r?);
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn src(text: &str) -> JsonlSource<&[u8]> {
        JsonlSource::new("mem", text.as_bytes())
    }

    #[test]
    fn reads_tagged_events_with_comments_and_blanks() {
        let text = "# synthetic\n\n{\"kind\":\"ros2_participant_discovered\",\"guid_prefix\":\"aa\",\"src_ip\":\"10.0.0.1\"}\r\n   \n{\"kind\":\"motion_command\",\"channel\":\"/cmd_vel\",\"source_guid\":null,\"linear_speed\":0.5,\"joint_speed\":null}";
        let evs = read_all(&mut src(text)).unwrap();
        assert_eq!(evs.len(), 2);
        assert_eq!(evs[0].position, 3);
        assert_eq!(evs[1].position, 5);
        assert!(matches!(evs[1].event, RobotEvent::MotionCommand(_)));
    }

    #[test]
    fn malformed_line_is_error_with_line_number_then_stops() {
        let mut s = src("{\"kind\":\"ros2_participant_discovered\",\"guid_prefix\":\"aa\",\"src_ip\":\"x\"}\n{\"kind\":\"bogus\"}\n{}\n");
        assert!(s.next_event().unwrap().is_ok());
        let err = s.next_event().unwrap().unwrap_err();
        assert!(matches!(err, InputError::Parse { line: 2, .. }), "{err}");
        assert!(err.to_string().contains("mem:2"));
        assert!(s.next_event().is_none());
    }

    #[test]
    fn invalid_utf8_rejected() {
        let bytes: &[u8] = b"\xff\xfe{}\n";
        let mut s = JsonlSource::new("mem", bytes);
        assert!(matches!(
            s.next_event().unwrap().unwrap_err(),
            InputError::InvalidUtf8 { line: 1, .. }
        ));
    }

    #[test]
    fn overlong_line_rejected_without_buffering_it_all() {
        let long = "x".repeat(MAX_LINE_BYTES + 10);
        let mut s = src(&long);
        assert!(matches!(
            s.next_event().unwrap().unwrap_err(),
            InputError::LineTooLong { line: 1, .. }
        ));
        assert!(s.next_event().is_none());
    }

    #[test]
    fn nan_literal_is_a_parse_error() {
        // JSON has no NaN; serde_json rejects it, so NaN can only reach the
        // learner through non-JSON sources (or as huge exponents -> inf).
        let mut s = src("{\"kind\":\"motion_command\",\"channel\":\"/c\",\"source_guid\":null,\"linear_speed\":NaN,\"joint_speed\":null}");
        assert!(s.next_event().unwrap().is_err());
    }

    #[test]
    fn missing_pcap_is_io_error() {
        let e = open(&InputSpec::Pcap("/nonexistent/robodr/x.pcap".into()))
            .err()
            .unwrap();
        assert!(matches!(e, InputError::Io { .. }), "{e}");
    }

    #[test]
    fn garbage_and_empty_captures_are_errors_not_panics() {
        for bytes in [
            &b""[..],
            b"\x00",
            b"not a capture at all",
            b"\xd4\xc3\xb2\xa1",                 // pcap magic, header cut short
            b"\x0a\x0d\x0d\x0a\xff\xff\xff\xff", // pcapng SHB, absurd length
        ] {
            match PcapSource::new("mem.pcap", bytes) {
                Err(e) => assert!(e.to_string().starts_with("mem.pcap:"), "{e}"),
                Ok(mut s) => {
                    // A header-only reader may open; then reading must fail
                    // cleanly or end, never panic or loop.
                    let mut n = 0;
                    while let Some(r) = s.next_event() {
                        n += 1;
                        assert!(n < 10);
                        if r.is_err() {
                            break;
                        }
                    }
                    assert!(s.next_event().is_none());
                }
            }
        }
    }

    #[test]
    fn diagnostics_lists_merge_within_their_bounds() {
        let one = |i: usize| CaptureDiagnostics {
            uninspected_transports: [(format!("10.0.0.{i}"), ["shm".to_string()].into())].into(),
            identity_prefix_unverified: [(format!("{i:024x}"), "why".to_string())].into(),
            ..CaptureDiagnostics::default()
        };
        let mut sum = CaptureDiagnostics::default();
        for i in 0..MAX_UNINSPECTED_HOSTS.max(MAX_UNVERIFIED_PREFIXES) + 10 {
            sum.add(&one(i));
        }
        assert_eq!(sum.uninspected_transports.len(), MAX_UNINSPECTED_HOSTS);
        assert_eq!(
            sum.identity_prefix_unverified.len(),
            MAX_UNVERIFIED_PREFIXES
        );
        // A listed host still gains transports.
        let mut tcp = one(0);
        tcp.uninspected_transports
            .insert("10.0.0.0".into(), ["tcp".to_string()].into());
        sum.add(&tcp);
        assert_eq!(sum.uninspected_transports["10.0.0.0"].len(), 2);
    }

    #[test]
    fn empty_pcap_has_zero_diagnostics() {
        let mut w = robodr_capture::PcapWriter::new(
            Vec::new(),
            robodr_capture::LinkType::ETHERNET,
            65535,
            false,
        )
        .unwrap();
        let noise = robodr_capture::synth::ethernet(0x0806, b"arp-ish");
        w.write_packet(std::time::Duration::ZERO, &noise, noise.len() as u32)
            .unwrap();
        let bytes = w.into_inner();
        let mut s = PcapSource::new("mem.pcap", &bytes[..]).unwrap();
        assert!(read_all(&mut s).unwrap().is_empty());
        let d = s.capture_diagnostics().unwrap();
        assert_eq!(d.frames, 1);
        assert_eq!(d.rtps_datagrams, 0);
        assert!(!d.discovery_reassembly_failed());
        let mut sum = d.clone();
        sum.add(&d);
        assert_eq!(sum.frames, 2);
        assert!(JsonlSource::new("x", &b""[..])
            .capture_diagnostics()
            .is_none());
    }

    #[test]
    fn missing_file_is_io_error() {
        let e = open(&InputSpec::Jsonl("/nonexistent/robodr/x.jsonl".into()))
            .err()
            .unwrap();
        assert!(matches!(e, InputError::Io { .. }));
    }
}
