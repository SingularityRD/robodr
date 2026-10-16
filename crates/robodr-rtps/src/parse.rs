//! The datagram walker and the discovery-sample decoder (SPDP + SEDP).
//!
//! See the crate docs for the GUID-attribution rules; this module implements
//! them in [`Report::handle_sample`].

use std::collections::{HashMap, HashSet};
use std::time::Duration;

use robodr_events::graph::{Endpoint, Participant};
use robodr_events::RobotEvent;

use crate::frag::{
    FragIn, FragOutcome, FragmentEvent, FragmentEventKind, FragmentReassembler, SampleKey,
};
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
/// Distinct values kept per multi-valued parameter (topic name, type name,
/// endpoint GUID, participant GUID) per sample. The first and the last
/// occurrence are always among them.
pub const MAX_PARAMETER_VALUES: usize = 4;
/// [`FragmentEvent`]s kept per datagram (the stats count all).
pub const MAX_FRAGMENT_EVENTS: usize = 32;

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
    /// The primary `PID_STATUS_INFO` reading (first occurrence; for
    /// DATA_FRAG the fragment that created the sample). `None` = alive.
    pub status: Option<StatusInfo>,
    /// Another status reading that some DDS stack uses, present only when it
    /// differs from `status` (an all-zero value stands for "no status",
    /// i.e. alive): the last occurrence of a repeated `PID_STATUS_INFO` in
    /// one list (last-wins stacks), or the inline QoS of a DATA_FRAG's
    /// fragment 1 when another fragment created the sample.
    pub alt_status: Option<StatusInfo>,
}

impl InlineQos {
    /// Add the readings of `other` (a DATA_FRAG's fragment 1): the key hash
    /// fills a gap, a differing status becomes [`InlineQos::alt_status`].
    pub(crate) fn with_reading(mut self, other: &InlineQos) -> Self {
        self.key_hash = self.key_hash.or(other.key_hash);
        let mine = self.status.unwrap_or_default();
        let theirs = other.status.unwrap_or_default();
        if self.alt_status.is_none() && mine != theirs {
            self.alt_status = Some(theirs);
        }
        self
    }

    /// Some reading says the instance is alive (an announcement).
    pub(crate) fn alive_reading(&self) -> bool {
        !self.status.unwrap_or_default().is_removal()
            || self.alt_status.is_some_and(|a| !a.is_removal())
    }

    /// The first reading that says disposed / unregistered, if any.
    pub(crate) fn removal_reading(&self) -> Option<StatusInfo> {
        self.status
            .into_iter()
            .chain(self.alt_status)
            .find(StatusInfo::is_removal)
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

/// Another reading of an SEDP announcement whose parameters were duplicated
/// with different values (see [`EndpointInfo::alternates`]).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EndpointAlternate {
    pub guid: Option<Guid>,
    pub participant: GuidPrefix,
    pub topic: String,
    pub type_name: String,
}

impl EndpointAlternate {
    /// The `robodr-events` view.
    pub fn to_endpoint(&self) -> Endpoint {
        Endpoint {
            guid_prefix: hex(&self.participant),
            topic: self.topic.clone(),
            type_name: self.type_name.clone(),
        }
    }
}

/// An SEDP endpoint announcement.
///
/// `guid` / `participant` / `topic` / `type_name` are the *first-occurrence*
/// reading. When the sample repeats `PID_TOPIC_NAME`, `PID_TYPE_NAME`,
/// `PID_ENDPOINT_GUID` (or, without an endpoint GUID, `PID_PARTICIPANT_GUID`)
/// with different values, DDS stacks disagree on which one counts (Fast DDS
/// overwrites per occurrence: last wins; others keep the first or reject the
/// sample). A detector must see what *any* of them may see, so every
/// distinct value is kept ([`EndpointInfo::topics`],
/// [`EndpointInfo::type_names`], [`EndpointInfo::alternates`]) and
/// [`DatagramReport::to_events`] emits one event per reading.
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
    /// Every distinct topic name in the sample, first-appearance order
    /// (`topics[0] == topic`). At most [`MAX_PARAMETER_VALUES`].
    pub topics: Vec<String>,
    /// Every distinct type name (empty if none was given).
    pub type_names: Vec<String>,
    /// Other readings than the first-occurrence one, de-duplicated: the
    /// all-last-occurrence reading (what a last-wins stack sees) and one per
    /// remaining distinct value, paired with the first values of the other
    /// parameters. Empty for a well-formed announcement. Linear, not a cross
    /// product, so it stays bounded by the number of parameters present.
    pub alternates: Vec<EndpointAlternate>,
    /// Reassembled from DATA_FRAG.
    pub from_fragments: bool,
}

impl EndpointInfo {
    /// The announcement was sent by someone other than the owner (discovery
    /// server, relay, or a spoofer).
    pub fn relayed(&self) -> bool {
        self.participant != self.source
    }

    /// The `robodr-events` view of the first-occurrence reading.
    pub fn to_endpoint(&self) -> Endpoint {
        Endpoint {
            guid_prefix: hex(&self.participant),
            topic: self.topic.clone(),
            type_name: self.type_name.clone(),
        }
    }

    /// Every reading, first-occurrence one first, as `robodr-events`
    /// endpoints (distinct by participant / topic / type).
    ///
    /// When the announcement was [`relayed`](Self::relayed) (the GUID it
    /// names belongs to a participant other than the one that sent it), each
    /// reading is emitted a second time attributed to the *sender*
    /// ([`EndpointInfo::source`]). The GUID in the payload is
    /// unauthenticated: a rogue participant can name a profiled
    /// participant's prefix there, and the `robodr-events` endpoint has no
    /// field for the sender. The extra event makes a profile check judge the
    /// sender too; a legitimate relay (a discovery server) is itself a
    /// profiled participant, so on learned topics it raises nothing.
    pub fn to_endpoints(&self) -> Vec<Endpoint> {
        let mut out = vec![self.to_endpoint()];
        for a in &self.alternates {
            let e = a.to_endpoint();
            if !out.contains(&e) {
                out.push(e);
            }
        }
        if self.source != GUIDPREFIX_UNKNOWN {
            let sender = hex(&self.source);
            for i in 0..out.len() {
                if out[i].guid_prefix != sender {
                    let e = Endpoint {
                        guid_prefix: sender.clone(),
                        ..out[i].clone()
                    };
                    if !out.contains(&e) {
                        out.push(e);
                    }
                }
            }
        }
        out
    }

    /// The sample carried conflicting duplicates of an identifying parameter.
    pub fn ambiguous(&self) -> bool {
        !self.alternates.is_empty()
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
    /// Prefixes of further, conflicting `PID_PARTICIPANT_GUID` values in the
    /// same sample (a last-wins stack would register the last one). Each also
    /// gets a participant event.
    pub alternate_guid_prefixes: Vec<GuidPrefix>,
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
    /// The protocol major version is not 2. The submessages are still parsed
    /// best-effort with the 2.x layout (some stacks only reject major < 2).
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
    /// Parameter list without a sentinel, or a length past the end. The
    /// parameters before the fault are still used.
    MalformedParameterList,
    /// A parameter length that is not a multiple of 4 (§9.4.2.11). Accepted:
    /// the next parameter is read right after it, as Fast DDS does.
    MisalignedParameterLength,
    /// PID_EXTENDED in a discovery parameter list.
    UnsupportedParameter,
    /// Payload encapsulation other than PL_CDR (or CDR for a key).
    UnsupportedEncapsulation(u16),
    /// A known parameter whose value does not decode.
    BadParameterValue(u16),
    /// The same parameter twice with different values. For topic / type
    /// names and GUIDs all values are kept (see [`EndpointInfo::alternates`]);
    /// for other parameters the first one wins.
    ConflictingDuplicateParameter(u16),
    /// More than [`MAX_PARAMETER_VALUES`] distinct values of one parameter.
    TooManyParameterValues(u16),
    /// A topic / type name whose CDR string is not canonical (embedded NUL,
    /// missing NUL, wrong length field). The name was read up to the first
    /// NUL, the way a C-string based stack reads it.
    NonCanonicalString(u16),
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
    /// The reassembler evicted a partial discovery sample (see
    /// [`DatagramReport::fragment_events`]).
    DiscoveryFragmentEvicted,
    /// A discovery fragment overlapped received bytes with different
    /// content; the first copy was kept.
    ConflictingDiscoveryFragment,
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
    /// Partial discovery samples evicted by the reassembler in this datagram.
    pub frag_evicted: u32,
    /// Conflicting overlapping discovery fragments in this datagram.
    pub frag_conflicts: u32,
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
    /// Discovery samples the reassembler evicted, fragments it refused and
    /// conflicting overlaps, caused by this datagram (at most
    /// [`MAX_FRAGMENT_EVENTS`]; without a [`FragmentReassembler`], those of
    /// the per-datagram one). Each one is a discovery announcement the
    /// sensor could not fully inspect.
    pub fragment_events: Vec<FragmentEvent>,
    pub stats: ParseStats,
}

impl DatagramReport {
    /// A discovery sample was fragmented (DATA_FRAG from a builtin discovery
    /// writer). Without a [`FragmentReassembler`] only samples whose
    /// fragments all sat in this datagram were decoded
    /// ([`ParseStats::frag_completed`]); the rest was not seen.
    pub fn fragmented_discovery_seen(&self) -> bool {
        self.stats.discovery_data_frag > 0
    }

    /// The `robodr-events` view: exactly one `Ros2ParticipantDiscovered` per
    /// distinct participant (message sources first, then SPDP-announced ones
    /// and their alternate GUIDs, locators merged), then one writer/reader
    /// event per reading of each announced endpoint (normally one; see
    /// [`EndpointInfo::alternates`]). Removals produce no events.
    /// Linear time (hash-indexed merging).
    pub fn to_events(&self, src_ip: &str) -> Vec<RobotEvent> {
        let mut parts: Vec<(GuidPrefix, Vec<String>)> = Vec::new();
        let mut index: HashMap<GuidPrefix, (usize, HashSet<String>)> = HashMap::new();
        let mut upsert = |prefix: GuidPrefix, locs: Vec<String>| {
            let (i, seen) = index.entry(prefix).or_insert_with(|| {
                parts.push((prefix, Vec::new()));
                (parts.len() - 1, HashSet::new())
            });
            for l in locs {
                if seen.insert(l.clone()) {
                    parts[*i].1.push(l);
                }
            }
        };
        for s in &self.sources {
            upsert(*s, Vec::new());
        }
        for p in &self.participants {
            upsert(p.guid_prefix, p.unicast_locator_strings());
            for a in &p.alternate_guid_prefixes {
                upsert(*a, Vec::new());
            }
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
        for e in &self.endpoints {
            events.extend(e.to_endpoints().into_iter().map(|ep| match e.kind {
                EndpointKind::Writer => RobotEvent::Ros2WriterDiscovered(ep),
                EndpointKind::Reader => RobotEvent::Ros2ReaderDiscovered(ep),
            }));
        }
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

/// Distinct values of a repeated parameter, first-appearance order, plus the
/// index of the value of the last occurrence.
struct Multi<T> {
    vals: Vec<T>,
    last: usize,
}

impl<T> Default for Multi<T> {
    fn default() -> Self {
        Self {
            vals: Vec::new(),
            last: 0,
        }
    }
}

impl<T: Copy> Multi<T> {
    fn first(&self) -> Option<T> {
        self.vals.first().copied()
    }
}

/// Decoded discovery parameters. Identifying parameters keep every distinct
/// value ([`Multi`]); the others keep the first occurrence.
#[derive(Default)]
struct Params {
    topic: Multi<String>,
    type_name: Multi<String>,
    endpoint_guid: Multi<Guid>,
    participant_guid: Multi<Guid>,
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
            fragment_events: Vec::new(),
            stats: ParseStats::default(),
        }
    }

    fn anomaly(&mut self, a: Anomaly) {
        self.stats.anomalies = self.stats.anomalies.saturating_add(1);
        if self.anomalies.len() < MAX_ANOMALIES {
            self.anomalies.push(a);
        }
    }

    /// Record a source prefix. Membership is hash-indexed (`seen`), so a
    /// datagram of thousands of distinct INFO_SRC stays linear. Not capped:
    /// every sender is reported (a cap would let padding hide one).
    fn add_source(&mut self, seen: &mut HashSet<GuidPrefix>, p: GuidPrefix) {
        if p != GUIDPREFIX_UNKNOWN && seen.insert(p) {
            self.sources.push(p);
        }
    }

    /// Record one value of a multi-valued parameter.
    fn push_multi<T: PartialEq>(&mut self, m: &mut Multi<T>, v: T, pid: u16) {
        if let Some(i) = m.vals.iter().position(|x| *x == v) {
            m.last = i;
            return;
        }
        if !m.vals.is_empty() {
            self.anomaly(Anomaly::ConflictingDuplicateParameter(pid));
        }
        if m.vals.len() < MAX_PARAMETER_VALUES {
            m.vals.push(v);
            m.last = m.vals.len() - 1;
        } else {
            // Keep the first values and always the latest one.
            self.anomaly(Anomaly::TooManyParameterValues(pid));
            m.last = MAX_PARAMETER_VALUES - 1;
            m.vals[m.last] = v;
        }
    }

    fn fragment_event(&mut self, e: FragmentEvent) {
        match e.kind {
            FragmentEventKind::Evicted(_) => {
                self.stats.frag_evicted = self.stats.frag_evicted.saturating_add(1);
                self.anomaly(Anomaly::DiscoveryFragmentEvicted);
            }
            FragmentEventKind::Rejected(_) => {
                self.stats.frag_rejected = self.stats.frag_rejected.saturating_add(1);
            }
            FragmentEventKind::ConflictingOverlap => {
                self.stats.frag_conflicts = self.stats.frag_conflicts.saturating_add(1);
                self.anomaly(Anomaly::ConflictingDiscoveryFragment);
            }
            FragmentEventKind::ConflictingInlineQos(pid) => {
                self.stats.frag_conflicts = self.stats.frag_conflicts.saturating_add(1);
                self.anomaly(Anomaly::ConflictingDuplicateParameter(pid));
            }
        }
        if self.fragment_events.len() < MAX_FRAGMENT_EVENTS {
            self.fragment_events.push(e);
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
        // Last-occurrence status (what a last-wins stack applies).
        let mut last_status: Option<StatusInfo> = None;
        let mut it = ParameterList::new(body, pos, le);
        for (pid, v) in it.by_ref() {
            match pid {
                PID_KEY_HASH => match (q.key_hash, read_array::<16>(v, 0)) {
                    (_, None) => self.anomaly(Anomaly::BadParameterValue(pid)),
                    (None, Some(k)) => q.key_hash = Some(k),
                    (Some(old), Some(k)) if old != k => {
                        self.anomaly(Anomaly::ConflictingDuplicateParameter(pid))
                    }
                    _ => {}
                },
                PID_STATUS_INFO => match read_array(v, 0).map(|raw| StatusInfo { raw }) {
                    None => self.anomaly(Anomaly::BadParameterValue(pid)),
                    Some(st) => {
                        if last_status.is_some_and(|l| l != st) || q.status.is_some_and(|f| f != st)
                        {
                            self.anomaly(Anomaly::ConflictingDuplicateParameter(pid));
                        }
                        q.status.get_or_insert(st);
                        last_status = Some(st);
                    }
                },
                _ => {}
            }
        }
        if let (Some(first), Some(last)) = (q.status, last_status) {
            if first != last {
                q.alt_status = Some(last);
            }
        }
        if it.misaligned() {
            self.anomaly(Anomaly::MisalignedParameterLength);
        }
        if it.end() != PlEnd::Sentinel {
            // Without the sentinel the payload offset is unknown.
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
        reasm: &mut FragmentReassembler,
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
        let mut events = Vec::new();
        let outcome = reasm.add(
            FragIn {
                key: SampleKey {
                    source,
                    writer,
                    sn: (u64::from(sn_hi) << 32) | u64::from(sn_lo),
                },
                topic,
                start,
                count,
                frag_size,
                sample_size: size,
                data,
                inline,
                key_only,
            },
            &mut events,
        );
        for e in events {
            self.fragment_event(e);
        }
        match outcome {
            // Both already reported through the fragment events.
            FragOutcome::Pending | FragOutcome::Rejected => {}
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
        if it.misaligned() {
            self.anomaly(Anomaly::MisalignedParameterLength);
        }
        // Lenient: whatever was decoded before a fault is kept (a stack that
        // processes parameters as it reads them has acted on them too).
        match it.end() {
            PlEnd::Sentinel => {}
            PlEnd::Unsupported => self.anomaly(Anomaly::UnsupportedParameter),
            PlEnd::Malformed | PlEnd::Open => self.anomaly(Anomaly::MalformedParameterList),
        }
        Some(out)
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
        fn name(r: &mut Report, m: &mut Multi<String>, v: &[u8], le: bool, pid: u16) {
            match cdr_string_lenient(v, le) {
                None => r.anomaly(Anomaly::BadParameterValue(pid)),
                Some((s, canonical)) => {
                    if !canonical {
                        r.anomaly(Anomaly::NonCanonicalString(pid));
                    }
                    r.push_multi(m, s, pid);
                }
            }
        }
        fn guid(r: &mut Report, m: &mut Multi<Guid>, v: &[u8], pid: u16) {
            match read_array(v, 0) {
                None => r.anomaly(Anomaly::BadParameterValue(pid)),
                Some(g) => r.push_multi(m, g, pid),
            }
        }
        match pid {
            PID_TOPIC_NAME => name(self, &mut out.topic, v, le, pid),
            PID_TYPE_NAME => name(self, &mut out.type_name, v, le, pid),
            PID_ENDPOINT_GUID => guid(self, &mut out.endpoint_guid, v, pid),
            PID_PARTICIPANT_GUID => guid(self, &mut out.participant_guid, v, pid),
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
        // Status readings (see `InlineQos::alt_status`). A sample is a
        // removal only if no reading says alive. When the readings disagree
        // and the sample can be read as an announcement, it is one (the
        // conflict itself was flagged as ConflictingDuplicateParameter):
        // missing a live rogue endpoint is worse than missing a removal.
        // Otherwise (key-only / no usable payload) the removal reading is
        // recorded.
        let removal_reading = s.inline.removal_reading();
        let announceable = s.inline.alive_reading()
            && !s.key_only
            && params.as_ref().is_some_and(|p| {
                s.topic == DiscoveryTopic::Participant || !p.topic.vals.is_empty()
            });
        let (removal, status) = match removal_reading {
            Some(st) if !announceable => (true, st),
            _ => (false, s.inline.status.unwrap_or_default()),
        };
        let key = s
            .inline
            .key_hash
            .or(raw_key)
            .or_else(|| params.as_ref().and_then(|p| p.key_hash));
        let prefix_of = |g: &Guid| -> GuidPrefix { read_array(g, 0).unwrap_or_default() };

        match s.topic {
            DiscoveryTopic::Participant => {
                let pg = params.as_ref().and_then(|p| p.participant_guid.first());
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
                let mut alternate_guid_prefixes: Vec<GuidPrefix> = Vec::new();
                for g in p.participant_guid.vals.iter().skip(1) {
                    let a = prefix_of(g);
                    if a != prefix && !alternate_guid_prefixes.contains(&a) {
                        alternate_guid_prefixes.push(a);
                    }
                }
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
                    alternate_guid_prefixes,
                    from_fragments: s.from_fragments,
                });
            }
            DiscoveryTopic::Publications | DiscoveryTopic::Subscriptions => {
                let kind = if s.topic == DiscoveryTopic::Publications {
                    EndpointKind::Writer
                } else {
                    EndpointKind::Reader
                };
                let eg = params.as_ref().and_then(|p| p.endpoint_guid.first());
                let pg = params.as_ref().and_then(|p| p.participant_guid.first());
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
                if p.topic.vals.is_empty() {
                    self.anomaly(Anomaly::AnnouncementWithoutTopic);
                    return;
                }
                self.push_endpoint(
                    kind,
                    &s,
                    p,
                    (guid, participant, attribution),
                    pg,
                    guid_conflict,
                );
            }
        }
    }

    /// Record an SEDP announcement with every reading of its (possibly
    /// duplicated) identifying parameters. `primary` is the attribution
    /// computed from the first occurrences.
    fn push_endpoint(
        &mut self,
        kind: EndpointKind,
        s: &Sample<'_>,
        p: Params,
        primary: (Option<Guid>, GuidPrefix, Attribution),
        pg: Option<Guid>,
        guid_conflict: bool,
    ) {
        let prefix_of = |g: &Guid| -> GuidPrefix { read_array(g, 0).unwrap_or_default() };
        // Every candidate owner, in the attribution order; [0] is primary.
        let (owners, o_last): (Vec<(Option<Guid>, GuidPrefix)>, usize) =
            if p.endpoint_guid.vals.len() > 1 {
                let v = p
                    .endpoint_guid
                    .vals
                    .iter()
                    .map(|g| (Some(*g), prefix_of(g)));
                (v.collect(), p.endpoint_guid.last)
            } else if primary.2 == Attribution::ParticipantGuid {
                let v = p.participant_guid.vals.iter().map(|g| (None, prefix_of(g)));
                (v.collect(), p.participant_guid.last)
            } else {
                (vec![(primary.0, primary.1)], 0)
            };
        let topics = p.topic.vals;
        let t_last = p.topic.last;
        let type_names = p.type_name.vals;
        let y_last = p.type_name.last;
        let no_type = [String::new()];
        let types: &[String] = if type_names.is_empty() {
            &no_type
        } else {
            &type_names
        };
        // Readings besides the first-occurrence one: all-last, then each
        // remaining distinct value with the first values of the others.
        let mut combos = Vec::new();
        if (o_last, t_last, y_last) != (0, 0, 0) {
            combos.push((o_last, t_last, y_last));
        }
        combos.extend(
            (1..owners.len())
                .filter(|&i| i != o_last)
                .map(|i| (i, 0, 0)),
        );
        combos.extend(
            (1..topics.len())
                .filter(|&j| j != t_last)
                .map(|j| (0, j, 0)),
        );
        combos.extend((1..types.len()).filter(|&k| k != y_last).map(|k| (0, 0, k)));
        let reading = |(i, j, k): (usize, usize, usize)| EndpointAlternate {
            guid: owners[i].0,
            participant: owners[i].1,
            topic: topics[j].clone(),
            type_name: types[k].clone(),
        };
        let first = reading((0, 0, 0));
        let mut alternates: Vec<EndpointAlternate> = Vec::new();
        for c in combos {
            let a = reading(c);
            if a != first && !alternates.contains(&a) {
                alternates.push(a);
            }
        }
        self.endpoints.push(EndpointInfo {
            kind,
            guid: first.guid,
            participant: first.participant,
            attribution: primary.2,
            source: s.source,
            participant_guid_param: pg,
            guid_conflict,
            topic: first.topic,
            type_name: first.type_name,
            topics,
            type_names,
            alternates,
            from_fragments: s.from_fragments,
        });
    }
}

/// Walk one datagram. `reasm` reassembles DATA_FRAG across datagrams;
/// without it, a throwaway reassembler (default limits) still reassembles the
/// samples whose fragments all sit in this one datagram, so a sample sent as
/// a single DATA_FRAG (or several in one datagram) is never invisible.
pub(crate) fn parse(
    datagram: &[u8],
    reasm: Option<&mut FragmentReassembler>,
) -> Option<DatagramReport> {
    let header = RtpsHeader::parse(datagram)?;
    let mut local;
    let reasm = match reasm {
        Some(r) => r,
        None => {
            local = FragmentReassembler::new(crate::frag::ReassemblyLimits::default());
            &mut local
        }
    };
    let mut r = Report::new(header);
    let mut seen_sources: HashSet<GuidPrefix> = HashSet::from([header.guid_prefix]);
    if header.version.0 != 2 {
        // Flag it, but parse best-effort: a stack that only rejects major < 2
        // (or none at all) acts on these submessages, so we must see them.
        r.anomaly(Anomaly::UnsupportedProtocolVersion(
            header.version.0,
            header.version.1,
        ));
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
                        r.add_source(&mut seen_sources, p);
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
                r.handle_data_frag(reasm, body, flags, source);
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

#[cfg(test)]
mod tests {
    use super::*;

    const A: GuidPrefix = [0xa1; 12];
    const B: GuidPrefix = [0xb2; 12];

    fn guid(prefix: GuidPrefix, entity: EntityId) -> Guid {
        let mut g = [0u8; 16];
        g[..12].copy_from_slice(&prefix);
        g[12..].copy_from_slice(&entity);
        g
    }

    fn v4(ip: [u8; 4], port: u32) -> Locator {
        let mut address = [0u8; 16];
        address[12..].copy_from_slice(&ip);
        Locator {
            kind: LOCATOR_KIND_UDPV4,
            port,
            address,
        }
    }

    fn spdp(prefix: GuidPrefix, source: GuidPrefix) -> SpdpInfo {
        SpdpInfo {
            guid_prefix: prefix,
            attribution: Attribution::ParticipantGuid,
            source,
            participant_entity: Some(ENTITYID_PARTICIPANT),
            protocol_version: Some((2, 3)),
            vendor_id: None,
            domain_id: None,
            domain_tag: None,
            entity_name: None,
            user_data: None,
            lease_duration: None,
            metatraffic_unicast: Vec::new(),
            metatraffic_multicast: Vec::new(),
            default_unicast: Vec::new(),
            default_multicast: Vec::new(),
            alternate_guid_prefixes: Vec::new(),
            from_fragments: false,
        }
    }

    fn endpoint(participant: GuidPrefix, source: GuidPrefix) -> EndpointInfo {
        EndpointInfo {
            kind: EndpointKind::Writer,
            guid: Some(guid(participant, [0, 0, 1, 3])),
            participant,
            attribution: Attribution::EndpointGuid,
            source,
            participant_guid_param: None,
            guid_conflict: false,
            topic: "rt/cmd_vel".into(),
            type_name: "T".into(),
            topics: vec!["rt/cmd_vel".into()],
            type_names: vec!["T".into()],
            alternates: Vec::new(),
            from_fragments: false,
        }
    }

    fn header(prefix: GuidPrefix) -> RtpsHeader {
        RtpsHeader {
            version: (2, 3),
            vendor_id: [0x01, 0x0f],
            guid_prefix: prefix,
        }
    }

    #[test]
    fn discovery_topic_from_writer() {
        use DiscoveryTopic::*;
        for (id, want) in [
            (ENTITYID_SPDP_WRITER, Some(Participant)),
            (ENTITYID_SPDP_SECURE_WRITER, Some(Participant)),
            (ENTITYID_SEDP_PUBLICATIONS_WRITER, Some(Publications)),
            (ENTITYID_SEDP_PUBLICATIONS_SECURE_WRITER, Some(Publications)),
            (ENTITYID_SEDP_SUBSCRIPTIONS_WRITER, Some(Subscriptions)),
            (
                ENTITYID_SEDP_SUBSCRIPTIONS_SECURE_WRITER,
                Some(Subscriptions),
            ),
            (ENTITYID_PARTICIPANT, None),
            ([0, 0, 0x03, 0xc7], None), // SEDP publications *reader*
            ([0, 0, 1, 3], None),       // user writer
            ([0xff; 4], None),
        ] {
            assert_eq!(DiscoveryTopic::from_writer(id), want, "{id:02x?}");
        }
    }

    #[test]
    fn rtps_header_parse_and_vendor() {
        let mut d = b"RTPS\x02\x03\x01\x0f".to_vec();
        d.extend_from_slice(&A);
        let h = RtpsHeader::parse(&d).unwrap();
        assert_eq!(h, header(A));
        assert!(h.vendor_name().is_some_and(|n| n.contains("Fast DDS")));
        assert_eq!(
            RtpsHeader {
                vendor_id: [0xee, 0xee],
                ..h
            }
            .vendor_name(),
            None
        );
        // Too short, wrong magic, empty.
        assert_eq!(RtpsHeader::parse(&d[..19]), None);
        assert_eq!(RtpsHeader::parse(b"RTPX\x02\x03\x01\x0f"), None);
        assert_eq!(RtpsHeader::parse(&[]), None);
        // Extra bytes are fine.
        d.extend_from_slice(&[0; 7]);
        assert_eq!(RtpsHeader::parse(&d), Some(header(A)));
    }

    #[test]
    fn status_info_flags() {
        let s = |b: u8| StatusInfo { raw: [0, 0, 0, b] };
        assert!(!s(0).is_removal());
        assert!(s(1).disposed() && !s(1).unregistered() && s(1).is_removal());
        assert!(s(2).unregistered() && !s(2).disposed() && s(2).is_removal());
        assert!(s(3).disposed() && s(3).unregistered());
        assert!(s(4).filtered() && !s(4).is_removal());
        // Only the last octet carries flags.
        let high = StatusInfo {
            raw: [0xff, 0xff, 0xff, 0],
        };
        assert!(!high.is_removal() && !high.filtered());
        assert_eq!(StatusInfo::default(), s(0));
    }

    #[test]
    fn inline_qos_readings() {
        let st = |b: u8| Some(StatusInfo { raw: [0, 0, 0, b] });
        let q = |status| InlineQos {
            status,
            ..Default::default()
        };
        assert!(q(None).alive_reading());
        assert_eq!(q(None).removal_reading(), None);
        assert!(!q(st(1)).alive_reading());
        assert_eq!(q(st(1)).removal_reading(), st(1));
        // A differing fragment-1 reading becomes the alternate.
        let m = q(st(1)).with_reading(&q(None));
        assert_eq!(m.alt_status, st(0));
        assert!(m.alive_reading());
        assert_eq!(m.removal_reading(), st(1));
        let m = q(None).with_reading(&q(st(2)));
        assert_eq!((m.status, m.alt_status), (None, st(2)));
        assert!(m.alive_reading());
        assert_eq!(m.removal_reading(), st(2));
        // Same reading: no alternate; absent and explicit zero are the same.
        assert_eq!(q(st(1)).with_reading(&q(st(1))).alt_status, None);
        assert_eq!(q(None).with_reading(&q(st(0))).alt_status, None);
        // Key hash fills a gap only.
        let k1 = InlineQos {
            key_hash: Some([1; 16]),
            ..Default::default()
        };
        let k2 = InlineQos {
            key_hash: Some([2; 16]),
            ..Default::default()
        };
        assert_eq!(q(None).with_reading(&k2).key_hash, Some([2; 16]));
        assert_eq!(k1.with_reading(&k2).key_hash, Some([1; 16]));
    }

    #[test]
    fn rtps_duration_conversion() {
        let d = |seconds, fraction| RtpsDuration { seconds, fraction };
        assert!(d(i32::MAX, u32::MAX).is_infinite());
        assert_eq!(d(i32::MAX, u32::MAX).to_std(), None);
        assert!(!d(i32::MAX, 0).is_infinite());
        assert_eq!(
            d(i32::MAX, 0).to_std(),
            Some(Duration::from_secs(i32::MAX as u64))
        );
        assert_eq!(d(-1, 0).to_std(), None);
        assert_eq!(d(i32::MIN, u32::MAX).to_std(), None);
        assert_eq!(d(0, 0).to_std(), Some(Duration::ZERO));
        assert_eq!(d(10, 1 << 31).to_std(), Some(Duration::from_millis(10_500)));
        // The largest fraction stays below one second.
        let max = d(0, u32::MAX).to_std().unwrap();
        assert!(max < Duration::from_secs(1) && max > Duration::from_millis(999));
    }

    #[test]
    fn endpoint_views() {
        let e = endpoint(A, A);
        assert!(!e.relayed());
        assert!(!e.ambiguous());
        let want = Endpoint {
            guid_prefix: hex(&A),
            topic: "rt/cmd_vel".into(),
            type_name: "T".into(),
        };
        assert_eq!(e.to_endpoint(), want);
        assert_eq!(e.to_endpoints(), vec![want.clone()]);

        // Unknown source: no sender copy.
        let e = endpoint(A, GUIDPREFIX_UNKNOWN);
        assert!(e.relayed());
        assert_eq!(e.to_endpoints(), vec![want.clone()]);

        // Relayed: each reading again, attributed to the sender.
        let mut e = endpoint(A, B);
        assert!(e.relayed());
        let alt = EndpointAlternate {
            guid: None,
            participant: A,
            topic: "rt/other".into(),
            type_name: "T".into(),
        };
        e.alternates.push(alt.clone());
        e.alternates.push(alt.clone()); // duplicate reading is de-duplicated
        assert!(e.ambiguous());
        assert_eq!(alt.to_endpoint().topic, "rt/other");
        let got = e.to_endpoints();
        let sender = |ep: &Endpoint| Endpoint {
            guid_prefix: hex(&B),
            ..ep.clone()
        };
        assert_eq!(
            got,
            vec![
                want.clone(),
                alt.to_endpoint(),
                sender(&want),
                sender(&alt.to_endpoint())
            ]
        );
        // An alternate that names the sender itself is not doubled.
        let mut e = endpoint(A, B);
        e.alternates.push(EndpointAlternate {
            participant: B,
            ..alt
        });
        assert_eq!(e.to_endpoints().len(), 3);
    }

    #[test]
    fn spdp_views() {
        let mut p = spdp(A, A);
        assert!(!p.relayed());
        assert!(spdp(A, B).relayed());
        assert_eq!(p.enclave(), None);
        assert_eq!(p.vendor_name(), None);
        p.vendor_id = Some([0x01, 0x10]);
        assert!(p.vendor_name().is_some());
        for (ud, want) in [
            (&b"enclave=/robot;"[..], Some("/robot")),
            (b"securitycontext=/old;", Some("/old")),
            (b"foo=bar;enclave=/x;\0\0", Some("/x")),
            (b"enclave=/;", Some("/")),
            (b"nothing here", None),
            (b"", None),
            (b"\xff\xfe enclave=/x;", None), // not UTF-8
        ] {
            p.user_data = Some(ud.to_vec());
            assert_eq!(p.enclave(), want, "{ud:?}");
        }
        p.metatraffic_unicast = vec![v4([10, 0, 0, 5], 7410), v4([10, 0, 0, 5], 0)];
        p.default_unicast = vec![
            v4([10, 0, 0, 5], 7410), // duplicate of metatraffic
            v4([10, 0, 0, 5], 7411),
            Locator {
                kind: LOCATOR_KIND_UDPV6,
                port: 7412,
                address: [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1],
            },
            Locator {
                kind: 99,
                port: 1,
                address: [0; 16],
            },
            v4([10, 0, 0, 5], 70_000),
        ];
        assert_eq!(
            p.unicast_locator_strings(),
            vec!["10.0.0.5:7410", "10.0.0.5:7411", "[::1]:7412"]
        );
    }

    #[test]
    fn report_to_events_merges_participants() {
        let mut r = DatagramReport::new(header(A));
        assert!(!r.fragmented_discovery_seen());
        r.stats.discovery_data_frag = 1;
        assert!(r.fragmented_discovery_seen());
        r.sources.push(B);
        let mut pa = spdp(A, A);
        pa.metatraffic_unicast = vec![v4([10, 0, 0, 1], 7410)];
        pa.alternate_guid_prefixes = vec![[0xcc; 12], B];
        let mut pa2 = spdp(A, B);
        pa2.default_unicast = vec![v4([10, 0, 0, 1], 7410), v4([10, 0, 0, 2], 7411)];
        r.participants = vec![pa, pa2];
        r.endpoints = vec![endpoint(A, A), {
            let mut e = endpoint(B, B);
            e.kind = EndpointKind::Reader;
            e
        }];
        let ev = r.to_events("192.0.2.1");
        let parts: Vec<&Participant> = ev
            .iter()
            .filter_map(|e| match e {
                RobotEvent::Ros2ParticipantDiscovered(p) => Some(p),
                _ => None,
            })
            .collect();
        assert_eq!(parts.len(), 3, "A, B, cc: one event each");
        assert_eq!(parts[0].guid_prefix, hex(&A));
        assert_eq!(parts[0].locators, vec!["10.0.0.1:7410", "10.0.0.2:7411"]);
        assert_eq!(parts[1].guid_prefix, hex(&B));
        assert_eq!(parts[2].guid_prefix, hex(&[0xcc; 12]));
        assert!(parts.iter().all(|p| p.src_ip == "192.0.2.1"));
        let writers = ev
            .iter()
            .filter(|e| matches!(e, RobotEvent::Ros2WriterDiscovered(_)))
            .count();
        let readers = ev
            .iter()
            .filter(|e| matches!(e, RobotEvent::Ros2ReaderDiscovered(_)))
            .count();
        assert_eq!((writers, readers), (1, 1));
        // Participants come before endpoints.
        assert!(matches!(ev[3], RobotEvent::Ros2WriterDiscovered(_)));
    }

    #[test]
    fn report_anomalies_and_multi_values_are_bounded() {
        let mut r = DatagramReport::new(header(A));
        for _ in 0..(MAX_ANOMALIES + 10) {
            r.anomaly(Anomaly::TooManyLocators);
        }
        assert_eq!(r.anomalies.len(), MAX_ANOMALIES);
        assert_eq!(r.stats.anomalies as usize, MAX_ANOMALIES + 10);

        let mut r = DatagramReport::new(header(A));
        let mut m: Multi<u32> = Multi::default();
        assert_eq!(m.first(), None);
        r.push_multi(&mut m, 1, 7);
        r.push_multi(&mut m, 1, 7);
        assert!(r.anomalies.is_empty(), "same value is no conflict");
        for v in 2..10 {
            r.push_multi(&mut m, v, 7);
        }
        assert_eq!(m.vals.len(), MAX_PARAMETER_VALUES);
        assert_eq!(m.first(), Some(1));
        assert_eq!(m.vals[m.last], 9, "latest value always kept");
        assert!(r
            .anomalies
            .contains(&Anomaly::ConflictingDuplicateParameter(7)));
        assert!(r.anomalies.contains(&Anomaly::TooManyParameterValues(7)));
        // Re-seeing a kept value moves `last` to it.
        r.push_multi(&mut m, 1, 7);
        assert_eq!(m.last, 0);
    }

    #[test]
    fn report_sources_are_distinct_and_skip_unknown() {
        let mut r = DatagramReport::new(header(A));
        let mut seen = HashSet::from([A]);
        r.add_source(&mut seen, A);
        r.add_source(&mut seen, GUIDPREFIX_UNKNOWN);
        r.add_source(&mut seen, B);
        r.add_source(&mut seen, B);
        assert_eq!(r.sources, vec![A, B]);
    }

    #[test]
    fn parse_rejects_non_rtps_and_survives_garbage() {
        assert!(parse(b"", None).is_none());
        assert!(parse(b"RTP", None).is_none());
        assert!(parse(&[0u8; 64], None).is_none());
        let mut d = b"RTPS\x02\x03\x01\x0f".to_vec();
        d.extend_from_slice(&A);
        let r = parse(&d, None).unwrap();
        assert_eq!(r.sources, vec![A]);
        assert_eq!(r.stats, ParseStats::default());
        // Every one-byte tail and a few junk tails: no panic, flagged.
        for tail in [&[0x15u8][..], &[0x15, 0x01], &[0x15, 0x01, 0xff, 0xff]] {
            let mut x = d.clone();
            x.extend_from_slice(tail);
            let r = parse(&x, None).unwrap();
            assert_eq!(r.anomalies, vec![Anomaly::TruncatedSubmessage]);
        }
        // Major version 1: flagged but parsed.
        let mut v1 = d.clone();
        v1[4] = 1;
        let r = parse(&v1, None).unwrap();
        assert_eq!(r.anomalies, vec![Anomaly::UnsupportedProtocolVersion(1, 3)]);
    }
}
