//! The datagram walker and the discovery-sample decoder (SPDP + SEDP).
//!
//! See the crate docs for the GUID-attribution rules; this module implements
//! them in [`Report::handle_sample`].

use std::time::Duration;

use robodr_events::graph::{Endpoint, Participant};
use robodr_events::RobotEvent;

use crate::frag::{FragIn, FragOutcome, FragmentReassembler, SampleKey};
use crate::vendor;
use crate::wire::*;

/// 12-octet RTPS GUID prefix (identifies a participant).
pub type GuidPrefix = [u8; 12];
/// 16-octet RTPS GUID: prefix + entity id.
pub type Guid = [u8; 16];
/// 4-octet RTPS entity id. An octet array on the wire: no endianness.
pub type EntityId = [u8; 4];

/// `GUIDPREFIX_UNKNOWN`.
pub const GUIDPREFIX_UNKNOWN: GuidPrefix = [0; 12];
/// `ENTITYID_PARTICIPANT`: the entity id of a participant's own GUID.
pub const ENTITYID_PARTICIPANT: EntityId = [0x00, 0x00, 0x01, 0xc1];
/// Builtin SPDP participant writer.
pub const ENTITYID_SPDP_WRITER: EntityId = [0x00, 0x01, 0x00, 0xc2];
/// Builtin SEDP publications writer (announces DataWriters).
pub const ENTITYID_SEDP_PUBLICATIONS_WRITER: EntityId = [0x00, 0x00, 0x03, 0xc2];
/// Builtin SEDP subscriptions writer (announces DataReaders).
pub const ENTITYID_SEDP_SUBSCRIPTIONS_WRITER: EntityId = [0x00, 0x00, 0x04, 0xc2];
/// DDS-Security reliable SPDP writer. Same payload format when the payload is
/// not encrypted; when it is, the submessage is wrapped in SEC_* and skipped.
pub const ENTITYID_SPDP_SECURE_WRITER: EntityId = [0xff, 0x01, 0x01, 0xc2];
/// DDS-Security SEDP publications writer.
pub const ENTITYID_SEDP_PUBLICATIONS_SECURE_WRITER: EntityId = [0xff, 0x00, 0x03, 0xc2];
/// DDS-Security SEDP subscriptions writer.
pub const ENTITYID_SEDP_SUBSCRIPTIONS_SECURE_WRITER: EntityId = [0xff, 0x00, 0x04, 0xc2];

pub(crate) const RTPS_MAGIC: &[u8; 4] = b"RTPS";
/// magic(4) + version(2) + vendorId(2) + guidPrefix(12).
pub(crate) const RTPS_HEADER_LEN: usize = 20;

/// Locators kept per list per SPDP sample; the rest are dropped (with an
/// [`Anomaly::TooManyLocators`]). Real participants advertise a handful.
pub const MAX_LOCATORS_PER_LIST: usize = 16;
/// Anomalies kept per datagram ([`ParseStats::anomalies`] still counts all).
pub const MAX_ANOMALIES: usize = 32;

/// Which builtin discovery topic a DATA belongs to (from its writer id).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum DiscoveryTopic {
    /// SPDP `DCPSParticipant`.
    Participant,
    /// SEDP `DCPSPublication`.
    Publications,
    /// SEDP `DCPSSubscription`.
    Subscriptions,
}

impl DiscoveryTopic {
    /// Classify a writer entity id; `None` for anything but the builtin
    /// discovery writers (plain or DDS-Security).
    pub fn from_writer(id: EntityId) -> Option<Self> {
        match id {
            ENTITYID_SPDP_WRITER | ENTITYID_SPDP_SECURE_WRITER => Some(Self::Participant),
            ENTITYID_SEDP_PUBLICATIONS_WRITER | ENTITYID_SEDP_PUBLICATIONS_SECURE_WRITER => {
                Some(Self::Publications)
            }
            ENTITYID_SEDP_SUBSCRIPTIONS_WRITER | ENTITYID_SEDP_SUBSCRIPTIONS_SECURE_WRITER => {
                Some(Self::Subscriptions)
            }
            _ => None,
        }
    }
}

/// The RTPS message header.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RtpsHeader {
    /// (major, minor).
    pub version: (u8, u8),
    pub vendor_id: [u8; 2],
    pub guid_prefix: GuidPrefix,
}

impl RtpsHeader {
    pub(crate) fn parse(datagram: &[u8]) -> Option<Self> {
        if datagram.get(..4)? != RTPS_MAGIC {
            return None;
        }
        Some(Self {
            version: (*datagram.get(4)?, *datagram.get(5)?),
            vendor_id: read_array(datagram, 6)?,
            guid_prefix: read_array(datagram, 8)?,
        })
    }

    /// Name of the header's vendor, if known.
    pub fn vendor_name(&self) -> Option<&'static str> {
        vendor::vendor_name(self.vendor_id)
    }
}

/// `PID_STATUS_INFO` (§9.6.3.9): 4 octets, flags in the last octet regardless
/// of endianness.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct StatusInfo {
    pub raw: [u8; 4],
}

impl StatusInfo {
    pub fn disposed(&self) -> bool {
        self.raw[3] & 0x01 != 0
    }
    pub fn unregistered(&self) -> bool {
        self.raw[3] & 0x02 != 0
    }
    pub fn filtered(&self) -> bool {
        self.raw[3] & 0x04 != 0
    }
    /// Disposed or unregistered: the instance (participant / endpoint) is
    /// going away, not being announced.
    pub fn is_removal(&self) -> bool {
        self.disposed() || self.unregistered()
    }
}

/// The inline-QoS parameters we use.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub(crate) struct InlineQos {
    pub key_hash: Option<Guid>,
    pub status: Option<StatusInfo>,
}

impl InlineQos {
    /// Fill in what we do not have yet (DATA_FRAG: QoS may ride on any fragment).
    pub(crate) fn merge(&mut self, other: &InlineQos) {
        self.key_hash = self.key_hash.or(other.key_hash);
        self.status = self.status.or(other.status);
    }
}

/// An RTPS `Duration_t` (seconds + 2^-32 fractions).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RtpsDuration {
    pub seconds: i32,
    pub fraction: u32,
}

impl RtpsDuration {
    /// `DURATION_INFINITE` = {0x7fffffff, 0xffffffff}.
    pub fn is_infinite(&self) -> bool {
        self.seconds == i32::MAX && self.fraction == u32::MAX
    }

    /// As a std `Duration`; `None` if infinite or negative.
    pub fn to_std(&self) -> Option<Duration> {
        if self.is_infinite() || self.seconds < 0 {
            return None;
        }
        let nanos = ((u64::from(self.fraction) * 1_000_000_000) >> 32) as u32;
        Some(Duration::new(self.seconds as u64, nanos))
    }
}

/// Which GUID an endpoint's or participant's identity was taken from, most
/// authoritative first. See the crate docs.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Attribution {
    /// `PID_ENDPOINT_GUID` in the SEDP payload.
    EndpointGuid,
    /// `PID_PARTICIPANT_GUID` in the payload.
    ParticipantGuid,
    /// The instance key (`PID_KEY_HASH` or a serialized key), which for the
    /// builtin topics is the GUID itself.
    KeyHash,
    /// Nothing in the sample named it: the message source (RTPS header
    /// prefix, as changed by INFO_SRC).
    SourcePrefix,
}

/// A writer or reader.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EndpointKind {
    Writer,
    Reader,
}

/// An SEDP endpoint announcement.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EndpointInfo {
    pub kind: EndpointKind,
    /// The endpoint's full GUID, if the sample carried one.
    pub guid: Option<Guid>,
    /// The owning participant (the authoritative attribution).
    pub participant: GuidPrefix,
    pub attribution: Attribution,
    /// The participant that *sent* the announcement (header / INFO_SRC).
    pub source: GuidPrefix,
    /// `PID_PARTICIPANT_GUID`, if present.
    pub participant_guid_param: Option<Guid>,
    /// `PID_PARTICIPANT_GUID`'s prefix disagrees with the endpoint GUID's.
    pub guid_conflict: bool,
    pub topic: String,
    pub type_name: String,
    /// Reassembled from DATA_FRAG.
    pub from_fragments: bool,
}

impl EndpointInfo {
    /// The announcement was sent by someone other than the owner (discovery
    /// server, relay, or a spoofer).
    pub fn relayed(&self) -> bool {
        self.participant != self.source
    }

    /// The `robodr-events` view.
    pub fn to_endpoint(&self) -> Endpoint {
        Endpoint {
            guid_prefix: hex(&self.participant),
            topic: self.topic.clone(),
            type_name: self.type_name.clone(),
        }
    }
}

/// An SEDP dispose / unregister: the endpoint is going away.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EndpointRemoval {
    pub kind: EndpointKind,
    pub guid: Option<Guid>,
    pub participant: GuidPrefix,
    pub attribution: Attribution,
    pub source: GuidPrefix,
    pub status: StatusInfo,
}

/// An SPDP dispose / unregister: the participant is leaving.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ParticipantRemoval {
    pub guid_prefix: GuidPrefix,
    pub attribution: Attribution,
    pub source: GuidPrefix,
    pub status: StatusInfo,
}

/// Everything an SPDP announcement told us about a participant.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SpdpInfo {
    pub guid_prefix: GuidPrefix,
    pub attribution: Attribution,
    /// The participant that sent it (header / INFO_SRC).
    pub source: GuidPrefix,
    /// Entity id of `PID_PARTICIPANT_GUID` (should be `ENTITYID_PARTICIPANT`).
    pub participant_entity: Option<EntityId>,
    pub protocol_version: Option<(u8, u8)>,
    pub vendor_id: Option<[u8; 2]>,
    pub domain_id: Option<u32>,
    pub domain_tag: Option<String>,
    pub entity_name: Option<String>,
    /// `PID_USER_DATA` octets (ROS 2: `enclave=/;`). Bounded by the datagram.
    pub user_data: Option<Vec<u8>>,
    pub lease_duration: Option<RtpsDuration>,
    pub metatraffic_unicast: Vec<Locator>,
    pub metatraffic_multicast: Vec<Locator>,
    pub default_unicast: Vec<Locator>,
    pub default_multicast: Vec<Locator>,
    pub from_fragments: bool,
}

impl SpdpInfo {
    /// The ROS 2 security enclave from user data (`enclave=<path>;`, or the
    /// pre-Foxy `securitycontext=<path>;`).
    pub fn enclave(&self) -> Option<&str> {
        let text = std::str::from_utf8(self.user_data.as_deref()?).ok()?;
        text.trim_end_matches('\0').split(';').find_map(|kv| {
            kv.strip_prefix("enclave=")
                .or_else(|| kv.strip_prefix("securitycontext="))
        })
    }

    /// Name of the advertised vendor, if known.
    pub fn vendor_name(&self) -> Option<&'static str> {
        self.vendor_id.and_then(vendor::vendor_name)
    }

    /// Relayed by someone other than the participant itself.
    pub fn relayed(&self) -> bool {
        self.guid_prefix != self.source
    }

    /// Renderable unicast locators (metatraffic first, then default),
    /// de-duplicated, in `ip:port` / `[v6]:port` form.
    pub fn unicast_locator_strings(&self) -> Vec<String> {
        let mut out: Vec<String> = Vec::new();
        for l in self.metatraffic_unicast.iter().chain(&self.default_unicast) {
            if let Some(s) = l.socket_string() {
                if !out.contains(&s) {
                    out.push(s);
                }
            }
        }
        out
    }
}

/// Something in the datagram that a well-behaved RTPS stack would not send.
/// Useful as a low-severity signal (fuzzing, spoofing attempts, buggy peers).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Anomaly {
    /// The protocol major version is not 2; submessages were not parsed.
    UnsupportedProtocolVersion(u8, u8),
    /// A submessage header or length ran past the end of the datagram.
    TruncatedSubmessage,
    /// INFO_SRC shorter than its fixed 20 octets.
    MalformedInfoSource,
    /// DATA shorter than its fixed part, or inline QoS / payload offset out of range.
    MalformedData,
    /// DATA_FRAG shorter than its fixed part, or payload offset out of range.
    MalformedDataFrag,
    /// octetsToInlineQos smaller than the fixed fields it must skip.
    BadOctetsToInlineQos,
    /// Parameter list without a sentinel, misaligned length, or overrun.
    MalformedParameterList,
    /// PID_EXTENDED in a discovery parameter list.
    UnsupportedParameter,
    /// Payload encapsulation other than PL_CDR (or CDR for a key).
    UnsupportedEncapsulation(u16),
    /// A known parameter whose value does not decode.
    BadParameterValue(u16),
    /// The same parameter twice with different values (first one wins).
    ConflictingDuplicateParameter(u16),
    /// `PID_ENDPOINT_GUID` and `PID_PARTICIPANT_GUID` name different participants.
    EndpointParticipantMismatch,
    /// Inline `PID_KEY_HASH` disagrees with the GUID in the payload.
    KeyHashMismatch,
    /// `PID_PARTICIPANT_GUID` with an entity id other than `ENTITYID_PARTICIPANT`.
    UnexpectedParticipantEntityId,
    /// SEDP announcement without a topic name.
    AnnouncementWithoutTopic,
    /// More than [`MAX_LOCATORS_PER_LIST`] locators in one list.
    TooManyLocators,
}

/// Counters for one datagram.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct ParseStats {
    pub submessages: u32,
    pub pad: u32,
    pub info_ts: u32,
    pub info_dst: u32,
    pub info_src: u32,
    pub data: u32,
    /// All DATA_FRAG submessages.
    pub data_frag: u32,
    /// DATA_FRAG from builtin discovery writers: "fragmented discovery seen".
    pub discovery_data_frag: u32,
    /// Discovery samples completed by the reassembler in this datagram.
    pub frag_completed: u32,
    /// Discovery fragments refused by the reassembler in this datagram.
    pub frag_rejected: u32,
    /// DDS-Security protected submessages (content unreadable to us).
    pub secure: u32,
    pub vendor_specific: u32,
    /// Other standard submessages (HEARTBEAT, ACKNACK, GAP, ...).
    pub other: u32,
    /// Ids not defined by the spec.
    pub unknown: u32,
    /// Total anomalies, including any beyond [`MAX_ANOMALIES`].
    pub anomalies: u32,
}

/// Everything parsed from one datagram. Produced by
/// [`crate::parse_datagram_detailed`] or
/// [`FragmentReassembler::parse_datagram_detailed`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DatagramReport {
    pub header: RtpsHeader,
    /// Distinct source prefixes: the header's, then each non-unknown INFO_SRC.
    pub sources: Vec<GuidPrefix>,
    pub participants: Vec<SpdpInfo>,
    pub endpoints: Vec<EndpointInfo>,
    pub removed_participants: Vec<ParticipantRemoval>,
    pub removed_endpoints: Vec<EndpointRemoval>,
    pub anomalies: Vec<Anomaly>,
    pub stats: ParseStats,
}

impl DatagramReport {
    /// A discovery sample was fragmented (DATA_FRAG from a builtin discovery
    /// writer). Without a [`FragmentReassembler`] its content was not seen.
    pub fn fragmented_discovery_seen(&self) -> bool {
        self.stats.discovery_data_frag > 0
    }

    /// The `robodr-events` view: exactly one `Ros2ParticipantDiscovered` per
    /// distinct participant (message sources first, then SPDP-announced ones,
    /// locators merged), then one writer/reader event per announced endpoint.
    /// Removals produce no events.
    pub fn to_events(&self, src_ip: &str) -> Vec<RobotEvent> {
        let mut parts: Vec<(GuidPrefix, Vec<String>)> = Vec::new();
        let mut upsert = |prefix: GuidPrefix, locs: Vec<String>| {
            let i = match parts.iter().position(|(p, _)| *p == prefix) {
                Some(i) => i,
                None => {
                    parts.push((prefix, Vec::new()));
                    parts.len() - 1
                }
            };
            for l in locs {
                if !parts[i].1.contains(&l) {
                    parts[i].1.push(l);
                }
            }
        };
        for s in &self.sources {
            upsert(*s, Vec::new());
        }
        for p in &self.participants {
            upsert(p.guid_prefix, p.unicast_locator_strings());
        }
        let mut events: Vec<RobotEvent> = parts
            .into_iter()
            .map(|(prefix, locators)| {
                RobotEvent::Ros2ParticipantDiscovered(Participant {
                    guid_prefix: hex(&prefix),
                    src_ip: src_ip.to_string(),
                    locators,
                })
            })
            .collect();
        events.extend(self.endpoints.iter().map(|e| match e.kind {
            EndpointKind::Writer => RobotEvent::Ros2WriterDiscovered(e.to_endpoint()),
            EndpointKind::Reader => RobotEvent::Ros2ReaderDiscovered(e.to_endpoint()),
        }));
        events
    }
}

/// A discovery sample ready to decode, from a DATA or a reassembled DATA_FRAG.
struct Sample<'a> {
    topic: DiscoveryTopic,
    source: GuidPrefix,
    inline: InlineQos,
    payload: Option<&'a [u8]>,
    key_only: bool,
    from_fragments: bool,
}

/// Decoded discovery parameters (first occurrence wins).
#[derive(Default)]
struct Params {
    topic: Option<String>,
    type_name: Option<String>,
    endpoint_guid: Option<Guid>,
    participant_guid: Option<Guid>,
    key_hash: Option<Guid>,
    protocol_version: Option<(u8, u8)>,
    vendor_id: Option<[u8; 2]>,
    domain_id: Option<u32>,
    domain_tag: Option<String>,
    entity_name: Option<String>,
    user_data: Option<Vec<u8>>,
    lease: Option<RtpsDuration>,
    mu: Vec<Locator>,
    mm: Vec<Locator>,
    du: Vec<Locator>,
    dm: Vec<Locator>,
}

type Report = DatagramReport;

impl Report {
    fn new(header: RtpsHeader) -> Self {
        Self {
            header,
            sources: vec![header.guid_prefix],
            participants: Vec::new(),
            endpoints: Vec::new(),
            removed_participants: Vec::new(),
            removed_endpoints: Vec::new(),
            anomalies: Vec::new(),
            stats: ParseStats::default(),
        }
    }

    fn anomaly(&mut self, a: Anomaly) {
        self.stats.anomalies = self.stats.anomalies.saturating_add(1);
        if self.anomalies.len() < MAX_ANOMALIES {
            self.anomalies.push(a);
        }
    }

    fn add_source(&mut self, p: GuidPrefix) {
        if p != GUIDPREFIX_UNKNOWN && !self.sources.contains(&p) {
            self.sources.push(p);
        }
    }

    /// DATA body: extraFlags(2) | octetsToInlineQos(2) | readerId(4) |
    /// writerId(4) | writerSN(8) | [inlineQos] | [serializedPayload].
    fn handle_data(&mut self, body: &[u8], flags: u8, source: GuidPrefix) {
        let le = flags & FLAG_E != 0;
        if body.len() < 20 {
            self.anomaly(Anomaly::MalformedData);
            return;
        }
        let Some(topic) = read_array(body, 8).and_then(DiscoveryTopic::from_writer) else {
            return; // user data or a builtin topic we do not decode
        };
        let Some((inline, pos)) = self.inline_qos(body, 16, flags & FLAG_Q != 0, le) else {
            return;
        };
        let has_payload = flags & (FLAG_D | FLAG_K) != 0;
        let payload = if has_payload {
            match body.get(pos..) {
                Some(p) => Some(p),
                None => {
                    self.anomaly(Anomaly::MalformedData);
                    return;
                }
            }
        } else {
            None
        };
        self.handle_sample(Sample {
            topic,
            source,
            inline,
            payload,
            key_only: flags & FLAG_D == 0 && flags & FLAG_K != 0,
            from_fragments: false,
        });
    }

    /// Validate octetsToInlineQos (>= the `fixed` octets it must skip) and
    /// parse the inline QoS if present. Returns the QoS and the payload offset.
    fn inline_qos(
        &mut self,
        body: &[u8],
        fixed: u16,
        present: bool,
        le: bool,
    ) -> Option<(InlineQos, usize)> {
        let oti = read_u16(body, 2, le)?;
        if oti < fixed {
            self.anomaly(Anomaly::BadOctetsToInlineQos);
            return None;
        }
        let pos = 4 + oti as usize;
        if !present {
            return Some((InlineQos::default(), pos));
        }
        let mut q = InlineQos::default();
        let mut it = ParameterList::new(body, pos, le);
        for (pid, v) in it.by_ref() {
            match pid {
                PID_KEY_HASH => q.key_hash = q.key_hash.or_else(|| read_array(v, 0)),
                PID_STATUS_INFO => {
                    q.status = q
                        .status
                        .or_else(|| read_array(v, 0).map(|raw| StatusInfo { raw }))
                }
                _ => {}
            }
        }
        if it.end() != PlEnd::Sentinel {
            self.anomaly(Anomaly::MalformedParameterList);
            return None;
        }
        Some((q, it.pos()))
    }

    /// DATA_FRAG body: extraFlags(2) | octetsToInlineQos(2) | readerId(4) |
    /// writerId(4) | writerSN(8) | fragmentStartingNum(4) |
    /// fragmentsInSubmessage(2) | fragmentSize(2) | sampleSize(4) |
    /// [inlineQos] | fragments.
    fn handle_data_frag(
        &mut self,
        reasm: Option<&mut FragmentReassembler>,
        body: &[u8],
        flags: u8,
        source: GuidPrefix,
    ) {
        let le = flags & FLAG_E != 0;
        if body.len() < 32 {
            self.anomaly(Anomaly::MalformedDataFrag);
            return;
        }
        let Some(writer) = read_array::<4>(body, 8) else {
            return;
        };
        let Some(topic) = DiscoveryTopic::from_writer(writer) else {
            return;
        };
        self.stats.discovery_data_frag += 1;
        let Some(reasm) = reasm else {
            return; // stateless mode: counted, not reassembled
        };
        let (Some(sn_hi), Some(sn_lo), Some(start), Some(count), Some(frag_size), Some(size)) = (
            read_u32(body, 12, le),
            read_u32(body, 16, le),
            read_u32(body, 20, le),
            read_u16(body, 24, le),
            read_u16(body, 26, le),
            read_u32(body, 28, le),
        ) else {
            return; // unreachable: body.len() >= 32
        };
        let Some((inline, pos)) = self.inline_qos(body, 28, flags & FLAG_Q != 0, le) else {
            return;
        };
        let Some(data) = body.get(pos..) else {
            self.anomaly(Anomaly::MalformedDataFrag);
            return;
        };
        let key_only = flags & FLAG_FRAG_K != 0;
        let outcome = reasm.add(FragIn {
            key: SampleKey {
                source,
                writer,
                sn: (u64::from(sn_hi) << 32) | u64::from(sn_lo),
            },
            start,
            count,
            frag_size,
            sample_size: size,
            data,
            inline,
            key_only,
        });
        match outcome {
            FragOutcome::Pending => {}
            FragOutcome::Rejected => self.stats.frag_rejected += 1,
            FragOutcome::Complete(buf, inline, key_only) => {
                self.stats.frag_completed += 1;
                self.handle_sample(Sample {
                    topic,
                    source,
                    inline,
                    payload: Some(&buf),
                    key_only,
                    from_fragments: true,
                });
            }
        }
    }

    /// Decode the serialized payload. `Ok(Some)` = a parameter list,
    /// `Ok(None)` = no usable list (key-only CDR key goes to `raw_key`).
    fn decode_payload(&mut self, s: &Sample<'_>, raw_key: &mut Option<Guid>) -> Option<Params> {
        let p = s.payload?;
        let Some(encap) = read_u16(p, 0, false) else {
            self.anomaly(Anomaly::MalformedData);
            return None;
        };
        let le = match encap {
            PL_CDR_BE => false,
            PL_CDR_LE => true,
            CDR_BE | CDR_LE if s.key_only => {
                // A bare serialized key: the 16-octet GUID.
                *raw_key = read_array(p, 4);
                return None;
            }
            other => {
                self.anomaly(Anomaly::UnsupportedEncapsulation(other));
                return None;
            }
        };
        let mut out = Params::default();
        let mut it = ParameterList::new(p, 4, le);
        for (pid, v) in it.by_ref() {
            self.decode_param(&mut out, pid, v, le);
        }
        match it.end() {
            PlEnd::Sentinel => Some(out),
            PlEnd::Unsupported => {
                self.anomaly(Anomaly::UnsupportedParameter);
                None
            }
            _ => {
                self.anomaly(Anomaly::MalformedParameterList);
                None
            }
        }
    }

    fn decode_param(&mut self, out: &mut Params, pid: u16, v: &[u8], le: bool) {
        fn set<T: PartialEq>(r: &mut Report, slot: &mut Option<T>, val: Option<T>, pid: u16) {
            match (val, slot.as_ref()) {
                (None, _) => r.anomaly(Anomaly::BadParameterValue(pid)),
                (Some(v), None) => *slot = Some(v),
                (Some(v), Some(old)) if *old != v => {
                    r.anomaly(Anomaly::ConflictingDuplicateParameter(pid))
                }
                _ => {}
            }
        }
        fn push(r: &mut Report, list: &mut Vec<Locator>, v: &[u8], le: bool, pid: u16) {
            match Locator::parse(v, le) {
                None => r.anomaly(Anomaly::BadParameterValue(pid)),
                Some(_) if list.len() >= MAX_LOCATORS_PER_LIST => {
                    r.anomaly(Anomaly::TooManyLocators)
                }
                Some(l) => {
                    if !list.contains(&l) {
                        list.push(l)
                    }
                }
            }
        }
        match pid {
            PID_TOPIC_NAME => set(self, &mut out.topic, cdr_string(v, le), pid),
            PID_TYPE_NAME => set(self, &mut out.type_name, cdr_string(v, le), pid),
            PID_ENDPOINT_GUID => set(self, &mut out.endpoint_guid, read_array(v, 0), pid),
            PID_PARTICIPANT_GUID => set(self, &mut out.participant_guid, read_array(v, 0), pid),
            PID_KEY_HASH => set(self, &mut out.key_hash, read_array(v, 0), pid),
            PID_PROTOCOL_VERSION => {
                let val = read_array::<2>(v, 0).map(|b| (b[0], b[1]));
                set(self, &mut out.protocol_version, val, pid)
            }
            PID_VENDORID => set(self, &mut out.vendor_id, read_array(v, 0), pid),
            PID_DOMAIN_ID => set(self, &mut out.domain_id, read_u32(v, 0, le), pid),
            PID_DOMAIN_TAG => set(self, &mut out.domain_tag, cdr_string(v, le), pid),
            PID_ENTITY_NAME => set(self, &mut out.entity_name, cdr_string(v, le), pid),
            PID_USER_DATA => {
                let val = cdr_octets(v, le).map(<[u8]>::to_vec);
                set(self, &mut out.user_data, val, pid)
            }
            PID_PARTICIPANT_LEASE_DURATION => {
                let val = read_i32(v, 0, le)
                    .zip(read_u32(v, 4, le))
                    .map(|(seconds, fraction)| RtpsDuration { seconds, fraction });
                set(self, &mut out.lease, val, pid)
            }
            PID_METATRAFFIC_UNICAST_LOCATOR => push(self, &mut out.mu, v, le, pid),
            PID_METATRAFFIC_MULTICAST_LOCATOR => push(self, &mut out.mm, v, le, pid),
            PID_DEFAULT_UNICAST_LOCATOR => push(self, &mut out.du, v, le, pid),
            PID_DEFAULT_MULTICAST_LOCATOR => push(self, &mut out.dm, v, le, pid),
            _ => {} // everything else (QoS, vendor-specific 0x8000 PIDs) is ignored
        }
    }

    /// Apply the attribution rules and record the announcement / removal.
    fn handle_sample(&mut self, s: Sample<'_>) {
        let mut raw_key = None;
        let params = self.decode_payload(&s, &mut raw_key);
        let status = s.inline.status.unwrap_or_default();
        let removal = status.is_removal();
        let key = s
            .inline
            .key_hash
            .or(raw_key)
            .or_else(|| params.as_ref().and_then(|p| p.key_hash));
        let prefix_of = |g: &Guid| -> GuidPrefix { read_array(g, 0).unwrap_or_default() };

        match s.topic {
            DiscoveryTopic::Participant => {
                let pg = params.as_ref().and_then(|p| p.participant_guid);
                let (prefix, attribution) = match (pg, key) {
                    (Some(g), _) => (prefix_of(&g), Attribution::ParticipantGuid),
                    (None, Some(k)) => (prefix_of(&k), Attribution::KeyHash),
                    (None, None) => (s.source, Attribution::SourcePrefix),
                };
                if let (Some(g), Some(k)) = (pg, s.inline.key_hash) {
                    if g != k {
                        self.anomaly(Anomaly::KeyHashMismatch);
                    }
                }
                if removal {
                    self.removed_participants.push(ParticipantRemoval {
                        guid_prefix: prefix,
                        attribution,
                        source: s.source,
                        status,
                    });
                    return;
                }
                let Some(p) = params.filter(|_| !s.key_only) else {
                    return; // key-only without status, or undecodable payload
                };
                let entity = pg.and_then(|g| read_array::<4>(&g, 12));
                if entity.is_some_and(|e| e != ENTITYID_PARTICIPANT) {
                    self.anomaly(Anomaly::UnexpectedParticipantEntityId);
                }
                self.participants.push(SpdpInfo {
                    guid_prefix: prefix,
                    attribution,
                    source: s.source,
                    participant_entity: entity,
                    protocol_version: p.protocol_version,
                    vendor_id: p.vendor_id,
                    domain_id: p.domain_id,
                    domain_tag: p.domain_tag,
                    entity_name: p.entity_name,
                    user_data: p.user_data,
                    lease_duration: p.lease,
                    metatraffic_unicast: p.mu,
                    metatraffic_multicast: p.mm,
                    default_unicast: p.du,
                    default_multicast: p.dm,
                    from_fragments: s.from_fragments,
                });
            }
            DiscoveryTopic::Publications | DiscoveryTopic::Subscriptions => {
                let kind = if s.topic == DiscoveryTopic::Publications {
                    EndpointKind::Writer
                } else {
                    EndpointKind::Reader
                };
                let eg = params.as_ref().and_then(|p| p.endpoint_guid);
                let pg = params.as_ref().and_then(|p| p.participant_guid);
                let (guid, guid_attr) = match (eg, key) {
                    (Some(g), _) => (Some(g), Attribution::EndpointGuid),
                    (None, Some(k)) => (Some(k), Attribution::KeyHash),
                    (None, None) => (None, Attribution::SourcePrefix),
                };
                let (participant, attribution) = match (guid, pg) {
                    (Some(g), _) => (prefix_of(&g), guid_attr),
                    (None, Some(p)) => (prefix_of(&p), Attribution::ParticipantGuid),
                    (None, None) => (s.source, Attribution::SourcePrefix),
                };
                let guid_conflict = matches!((guid, pg), (Some(g), Some(p)) if g[..12] != p[..12]);
                if guid_conflict {
                    self.anomaly(Anomaly::EndpointParticipantMismatch);
                }
                if let (Some(g), Some(k)) = (eg, s.inline.key_hash) {
                    if g != k {
                        self.anomaly(Anomaly::KeyHashMismatch);
                    }
                }
                if removal {
                    self.removed_endpoints.push(EndpointRemoval {
                        kind,
                        guid,
                        participant,
                        attribution,
                        source: s.source,
                        status,
                    });
                    return;
                }
                let Some(p) = params.filter(|_| !s.key_only) else {
                    return; // key-only without status, or undecodable payload
                };
                let Some(topic) = p.topic else {
                    self.anomaly(Anomaly::AnnouncementWithoutTopic);
                    return;
                };
                self.endpoints.push(EndpointInfo {
                    kind,
                    guid,
                    participant,
                    attribution,
                    source: s.source,
                    participant_guid_param: pg,
                    guid_conflict,
                    topic,
                    type_name: p.type_name.unwrap_or_default(),
                    from_fragments: s.from_fragments,
                });
            }
        }
    }
}

/// Walk one datagram. `reasm` enables DATA_FRAG reassembly.
pub(crate) fn parse(
    datagram: &[u8],
    mut reasm: Option<&mut FragmentReassembler>,
) -> Option<DatagramReport> {
    let header = RtpsHeader::parse(datagram)?;
    let mut r = Report::new(header);
    if header.version.0 != 2 {
        r.anomaly(Anomaly::UnsupportedProtocolVersion(
            header.version.0,
            header.version.1,
        ));
        return Some(r);
    }
    let mut source = header.guid_prefix;
    let mut buf = &datagram[RTPS_HEADER_LEN..];
    while !buf.is_empty() {
        let (Some(&id), Some(&flags)) = (buf.first(), buf.get(1)) else {
            r.anomaly(Anomaly::TruncatedSubmessage);
            break;
        };
        let le = flags & FLAG_E != 0;
        let Some(len) = read_u16(buf, 2, le) else {
            r.anomaly(Anomaly::TruncatedSubmessage);
            break;
        };
        // octetsToNextHeader == 0: "to end of message", except for PAD and
        // INFO_TS where 0 is a legitimate empty body (§9.4.5.1.3).
        let body_len = if len == 0 && id != SUBMSG_PAD && id != SUBMSG_INFO_TS {
            buf.len() - 4
        } else {
            len as usize
        };
        let Some(body) = buf.get(4..4 + body_len) else {
            r.anomaly(Anomaly::TruncatedSubmessage);
            break;
        };
        r.stats.submessages += 1;
        match id {
            SUBMSG_PAD => r.stats.pad += 1,
            SUBMSG_INFO_TS => r.stats.info_ts += 1,
            SUBMSG_INFO_DST => r.stats.info_dst += 1,
            SUBMSG_INFO_SRC => {
                // unused(4) | version(2) | vendorId(2) | guidPrefix(12)
                r.stats.info_src += 1;
                match read_array::<12>(body, 8) {
                    Some(p) => {
                        source = p;
                        r.add_source(p);
                    }
                    None => r.anomaly(Anomaly::MalformedInfoSource),
                }
            }
            SUBMSG_DATA => {
                r.stats.data += 1;
                r.handle_data(body, flags, source);
            }
            SUBMSG_DATA_FRAG => {
                r.stats.data_frag += 1;
                r.handle_data_frag(reasm.as_deref_mut(), body, flags, source);
            }
            SUBMSG_ACKNACK
            | SUBMSG_HEARTBEAT
            | SUBMSG_GAP
            | SUBMSG_NACK_FRAG
            | SUBMSG_HEARTBEAT_FRAG
            | SUBMSG_INFO_REPLY
            | SUBMSG_INFO_REPLY_IP4 => r.stats.other += 1,
            SUBMSG_SECURE_FIRST..=SUBMSG_SECURE_LAST => r.stats.secure += 1,
            SUBMSG_VENDOR_FIRST..=0xff => r.stats.vendor_specific += 1,
            _ => r.stats.unknown += 1,
        }
        buf = &buf[4 + body_len..];
    }
    Some(r)
}
