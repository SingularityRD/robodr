//! User DATA walker: the samples of application topics (`rt/cmd_vel`,
//! `rt/odom`, ...), as opposed to the discovery samples decoded by
//! [`crate::parse_datagram_detailed`].
//!
//! [`UserDataWalker::walk_with`] walks one RTPS datagram and yields one
//! [`UserSample`] per user DATA submessage (and per DATA_FRAG sample once it
//! is complete): the writer GUID, the reader GUID, the sequence number, the
//! serialized payload **including** its 4-byte encapsulation header (the
//! input of `robodr-cdr`), the inline QoS that matters for attribution
//! (`PID_KEY_HASH`, `PID_STATUS_INFO`) and the INFO_TS source timestamp.
//! It never decodes the payload: the payload type is only known from SEDP
//! (writer GUID → topic → type name), which is the caller's state.
//!
//! # Receiver state (DDSI-RTPS 2.5 §8.3.4, §8.3.7)
//!
//! The walker keeps the RTPS *receiver* state across the submessages of one
//! message:
//!
//! - **INFO_SRC** sets the source GUID prefix (the writer GUID of the DATA
//!   that follow is `sourceGuidPrefix + writerId`) and clears the timestamp
//!   (`haveTimestamp = false`).
//! - **INFO_DST** sets the destination GUID prefix (the reader GUID is
//!   `destGuidPrefix + readerId`); `GUIDPREFIX_UNKNOWN` = every participant
//!   the message reaches.
//! - **INFO_TS** sets the source timestamp of the DATA that follow; with the
//!   `I` (invalidate) flag it clears it. `octetsToNextHeader == 0` is an
//!   empty body here (as for PAD), not "to end of message".
//! - Endianness is per submessage (`E` flag); INFO_TS / sequence numbers /
//!   inline QoS lengths are read in the submessage's endianness. The
//!   payload's own endianness is in its encapsulation header and is the
//!   decoder's business.
//!
//! None of this is authenticated without DDS-Security: the writer GUID and
//! the timestamp are *claims* of the sender. The caller binds them to source
//! IPs (see `robodr-ros2-pipeline`'s binding table) and must never use the
//! source timestamp as the time of the observation.
//!
//! # Which DATA are user DATA
//!
//! Every DATA / DATA_FRAG whose writer entity id is **not** a builtin one
//! (entityKind octet with both high bits set, `0xc0..=0xff`: SPDP, SEDP,
//! participant message, type lookup, DDS-Security builtins, ...). Those are
//! skipped (counted in [`UserDataStats::builtin_skipped`]). `ENTITYID_UNKNOWN`
//! as a writer id is malformed (a DDS stack drops it, so does the walker).
//!
//! # Fragments
//!
//! DATA_FRAG of user writers is reassembled with the same bounded
//! [`crate::FragmentReassembler`] as discovery (its own instance), with one
//! change: the per-source quota and the pressure rule count **per writer**
//! (source prefix + writer entity), so a camera's 1 MB images cannot evict a
//! fragmented `JointTrajectory`. The `wanted` filter of
//! [`UserDataWalker::walk_with`] is consulted before anything is buffered, so
//! a caller that only inspects motion topics never stores image fragments
//! at all. Refused fragments, evictions and conflicting overlaps are
//! reported as [`UserFragmentEvent`]s with the writer GUID.
//!
//! # Bounds
//!
//! Work is linear in the datagram size. At most `max_samples_per_datagram`
//! samples are returned per datagram (a 64 KiB datagram can carry ~1500
//! tiny DATA); the rest are counted in [`UserDataStats::samples_capped`] and
//! not copied. Payloads of plain DATA are borrowed from the datagram;
//! reassembled payloads are owned and bounded by the reassembler's caps.
//! Anomalies and fragment events are capped at [`MAX_USER_ANOMALIES`] /
//! [`MAX_USER_FRAGMENT_EVENTS`] per datagram (the stats count all).
//!
//! # Not verified
//!
//! Built from the DDSI-RTPS 2.5 text and checked against hand-built
//! datagrams only, not against captures of Fast DDS / Cyclone DDS /
//! Connext user traffic. DDS-Security protected submessages (`SEC_*`,
//! `SRTPS_*`) are counted and skipped: their content cannot be read.

use std::borrow::Cow;

use crate::frag::{
    FragIn, FragOutcome, FragmentEvent, FragmentEventKind, FragmentReassembler, ReassemblyLimits,
    SampleKey,
};
use crate::parse::{
    DiscoveryTopic, EntityId, Guid, GuidPrefix, InlineQos, RtpsHeader, StatusInfo,
    GUIDPREFIX_UNKNOWN, RTPS_HEADER_LEN,
};
use crate::wire::*;

/// Default [`UserDataLimits::max_samples_per_datagram`].
pub const DEFAULT_MAX_SAMPLES_PER_DATAGRAM: usize = 256;
/// Hard ceiling on [`UserDataLimits::max_samples_per_datagram`].
pub const HARD_MAX_SAMPLES_PER_DATAGRAM: usize = 4096;
/// Anomalies kept per datagram ([`UserDataStats::anomalies`] counts all).
pub const MAX_USER_ANOMALIES: usize = 32;
/// Fragment events kept per datagram (the stats count all).
pub const MAX_USER_FRAGMENT_EVENTS: usize = 32;

/// INFO_TS: `I` flag, the timestamp is invalidated (no body).
const FLAG_INFO_TS_I: u8 = 0x02;
/// DATA: `N` flag (non-standard payload, RTPS 2.3+).
const FLAG_DATA_N: u8 = 0x10;
/// DATA_FRAG: `N` flag (non-standard payload, RTPS 2.3+).
const FLAG_FRAG_N: u8 = 0x08;

/// `ENTITYID_UNKNOWN`.
pub const ENTITYID_UNKNOWN: EntityId = [0; 4];

/// Is `id` a builtin entity (entityKind `0xc0..=0xff`)?
pub fn is_builtin_entity(id: EntityId) -> bool {
    id[3] & 0xc0 == 0xc0
}

/// An RTPS `Time_t` (seconds + 2^-32 fractions since the UNIX epoch).
///
/// Seconds are read unsigned (DDSI-RTPS 2.5; 2.2 declared them signed, the
/// encodings agree until 2038).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct RtpsTime {
    pub seconds: u32,
    pub fraction: u32,
}

impl RtpsTime {
    /// `TIME_INVALID` = {0xffffffff, 0xffffffff}.
    pub const INVALID: Self = Self {
        seconds: u32::MAX,
        fraction: u32::MAX,
    };
    /// `TIME_INFINITE` = {0x7fffffff, 0xffffffff}.
    pub const INFINITE: Self = Self {
        seconds: 0x7fff_ffff,
        fraction: u32::MAX,
    };

    /// Nanoseconds since the UNIX epoch; `None` for `TIME_INVALID` /
    /// `TIME_INFINITE`. A wire claim: never use it as the observation time.
    pub fn to_unix_ns(self) -> Option<u64> {
        if self == Self::INVALID || self == Self::INFINITE {
            return None;
        }
        let frac_ns = (u64::from(self.fraction) * 1_000_000_000) >> 32;
        Some(u64::from(self.seconds) * 1_000_000_000 + frac_ns)
    }
}

/// What the sample's serialized payload is.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum PayloadKind {
    /// `D` flag: serialized data.
    Data,
    /// `K` flag: serialized key only (key-only sample; dispose / unregister
    /// of a keyed instance).
    Key,
    /// Neither: no payload (status change carried by the inline QoS).
    None,
}

/// The inline QoS of a user sample, as far as attribution needs it.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct UserInlineQos {
    /// The `Q` flag was set (an inline QoS list was present and complete).
    pub present: bool,
    /// `PID_KEY_HASH` (first occurrence).
    pub key_hash: Option<Guid>,
    /// `PID_STATUS_INFO` (first occurrence; for DATA_FRAG the creating
    /// fragment's). `None` = alive.
    pub status: Option<StatusInfo>,
    /// Another `PID_STATUS_INFO` reading differs (a repeated parameter, or
    /// another fragment of the sample): stacks may disagree on whether the
    /// sample is a dispose.
    pub status_conflict: bool,
}

impl UserInlineQos {
    fn from_reading(q: &InlineQos, present: bool) -> Self {
        Self {
            present,
            key_hash: q.key_hash,
            status: q.status,
            status_conflict: q.alt_status.is_some(),
        }
    }

    /// Some reading says the instance was disposed or unregistered.
    pub fn removal(&self) -> bool {
        self.status.is_some_and(|s| s.is_removal())
    }
}

/// The identity of a sample, as known before its payload is touched: what
/// [`UserDataWalker::walk_with`]'s filter is given.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct SampleAddress {
    /// Source prefix (header / INFO_SRC) + writerId.
    pub writer: Guid,
    /// Destination prefix (INFO_DST; [`GUIDPREFIX_UNKNOWN`] when none) +
    /// readerId (`ENTITYID_UNKNOWN` = every matched reader).
    pub reader: Guid,
    /// `writerSN` (high:low as one signed 64-bit value).
    pub sequence_number: i64,
}

impl SampleAddress {
    pub fn writer_prefix(&self) -> GuidPrefix {
        read_array(&self.writer, 0).unwrap_or_default()
    }

    pub fn writer_entity(&self) -> EntityId {
        read_array(&self.writer, 12).unwrap_or_default()
    }

    pub fn reader_prefix(&self) -> GuidPrefix {
        read_array(&self.reader, 0).unwrap_or_default()
    }

    pub fn reader_entity(&self) -> EntityId {
        read_array(&self.reader, 12).unwrap_or_default()
    }
}

/// One user sample.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UserSample<'a> {
    pub address: SampleAddress,
    pub payload_kind: PayloadKind,
    /// The serialized payload, encapsulation header included (empty for
    /// [`PayloadKind::None`]). Plain DATA: up to the end of the submessage,
    /// so submessage padding may trail it. DATA_FRAG: exactly `sampleSize`.
    pub payload: Cow<'a, [u8]>,
    pub inline_qos: UserInlineQos,
    /// The INFO_TS in effect for this submessage (a sender claim). For a
    /// reassembled sample, the one of the fragment that completed it.
    pub source_timestamp: Option<RtpsTime>,
    /// The submessage's `E` flag (the fragment that completed the sample).
    pub little_endian: bool,
    /// The `N` flag: the payload is not a standard serialized payload.
    pub non_standard_payload: bool,
    /// Reassembled from DATA_FRAG.
    pub from_fragments: bool,
}

impl UserSample<'_> {
    /// Lower-case hex of the writer GUID (the form `robodr-events` uses).
    pub fn writer_hex(&self) -> String {
        hex(&self.address.writer)
    }

    /// Detach from the datagram.
    pub fn into_owned(self) -> UserSample<'static> {
        UserSample {
            payload: Cow::Owned(self.payload.into_owned()),
            address: self.address,
            payload_kind: self.payload_kind,
            inline_qos: self.inline_qos,
            source_timestamp: self.source_timestamp,
            little_endian: self.little_endian,
            non_standard_payload: self.non_standard_payload,
            from_fragments: self.from_fragments,
        }
    }
}

/// Something the walker had to drop or could not read.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum UserAnomalyKind {
    /// A submessage header or length ran past the end of the datagram; the
    /// rest of the datagram was not walked.
    TruncatedSubmessage,
    /// INFO_SRC shorter than 20 octets (source unchanged).
    MalformedInfoSource,
    /// INFO_DST shorter than 12 octets (destination unchanged).
    MalformedInfoDestination,
    /// INFO_TS without `I` flag shorter than 8 octets (timestamp cleared).
    MalformedInfoTimestamp,
    /// DATA shorter than its fixed part, or payload offset out of range.
    MalformedData,
    /// DATA_FRAG shorter than its fixed part, or payload offset out of range.
    MalformedDataFrag,
    /// `octetsToInlineQos` smaller than the fixed fields it must skip.
    BadOctetsToInlineQos,
    /// Inline QoS without sentinel (the payload offset is unknown).
    MalformedInlineQos,
    /// `writerSN` <= 0 (invalid per §8.3.5.4; stacks drop the sample).
    InvalidSequenceNumber,
    /// `writerId` = `ENTITYID_UNKNOWN`.
    UnknownWriterEntity,
}

/// An anomaly, with the writer of the submessage when it was readable.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct UserAnomaly {
    pub kind: UserAnomalyKind,
    /// The sample's address, when the fixed fields were readable.
    pub address: Option<SampleAddress>,
}

/// A user-data fragment the reassembler could not take in (see
/// [`FragmentEventKind`]).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct UserFragmentEvent {
    pub kind: FragmentEventKind,
    /// Source prefix + writer entity of the sample.
    pub writer: Guid,
    pub sequence_number: u64,
    pub received_fragments: u32,
    pub total_fragments: u32,
}

impl UserFragmentEvent {
    fn from_event(e: &FragmentEvent) -> Self {
        Self {
            kind: e.kind,
            writer: guid_of(e.source, e.writer),
            sequence_number: e.sn,
            received_fragments: e.received_fragments,
            total_fragments: e.total_fragments,
        }
    }
}

/// Counters for one datagram.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct UserDataStats {
    pub submessages: u32,
    pub info_ts: u32,
    pub info_src: u32,
    pub info_dst: u32,
    /// User DATA submessages (builtin ones excluded).
    pub data: u32,
    /// User DATA_FRAG submessages (builtin ones excluded).
    pub data_frag: u32,
    /// DATA / DATA_FRAG from builtin writers (discovery etc.), skipped.
    pub builtin_skipped: u32,
    /// Samples the caller's filter did not want (not copied / buffered).
    pub not_wanted: u32,
    /// Samples returned.
    pub samples: u32,
    /// Samples beyond `max_samples_per_datagram` (not returned).
    pub samples_capped: u32,
    /// User samples completed by the reassembler in this datagram.
    pub frag_completed: u32,
    /// User fragments refused by the reassembler in this datagram.
    pub frag_rejected: u32,
    /// Partial user samples evicted in this datagram.
    pub frag_evicted: u32,
    /// Conflicting overlapping fragments / inline QoS in this datagram.
    pub frag_conflicts: u32,
    /// DDS-Security protected submessages (content unreadable).
    pub secure: u32,
    /// Total anomalies, including any beyond [`MAX_USER_ANOMALIES`].
    pub anomalies: u32,
}

/// Everything the walker found in one datagram.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UserDataReport<'a> {
    pub header: RtpsHeader,
    pub samples: Vec<UserSample<'a>>,
    pub anomalies: Vec<UserAnomaly>,
    pub fragment_events: Vec<UserFragmentEvent>,
    pub stats: UserDataStats,
}

/// Caps of a [`UserDataWalker`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct UserDataLimits {
    /// Caps of the user-data reassembler (`max_pending_per_source` is a
    /// per-writer quota here).
    pub reassembly: ReassemblyLimits,
    /// Most samples returned per datagram (clamped to
    /// 1..=[`HARD_MAX_SAMPLES_PER_DATAGRAM`]).
    pub max_samples_per_datagram: usize,
}

impl Default for UserDataLimits {
    fn default() -> Self {
        Self {
            reassembly: ReassemblyLimits::default(),
            max_samples_per_datagram: DEFAULT_MAX_SAMPLES_PER_DATAGRAM,
        }
    }
}

/// Stateful user-data walker (one per capture: it owns the DATA_FRAG
/// reassembler). See the module docs.
pub struct UserDataWalker {
    reasm: FragmentReassembler,
    max_samples: usize,
}

impl Default for UserDataWalker {
    fn default() -> Self {
        Self::new(UserDataLimits::default())
    }
}

impl std::fmt::Debug for UserDataWalker {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("UserDataWalker")
            .field("max_samples", &self.max_samples)
            .field("pending_samples", &self.reasm.pending_samples())
            .field("pending_bytes", &self.reasm.pending_bytes())
            .finish()
    }
}

fn guid_of(prefix: GuidPrefix, entity: EntityId) -> Guid {
    let mut g = [0u8; 16];
    g[..12].copy_from_slice(&prefix);
    g[12..].copy_from_slice(&entity);
    g
}

/// Receiver state of one message (§8.3.4).
struct Receiver {
    source: GuidPrefix,
    dest: GuidPrefix,
    timestamp: Option<RtpsTime>,
}

struct Walk<'a> {
    report: UserDataReport<'a>,
    max_samples: usize,
}

impl<'a> Walk<'a> {
    fn anomaly(&mut self, kind: UserAnomalyKind, address: Option<SampleAddress>) {
        self.report.stats.anomalies = self.report.stats.anomalies.saturating_add(1);
        if self.report.anomalies.len() < MAX_USER_ANOMALIES {
            self.report.anomalies.push(UserAnomaly { kind, address });
        }
    }

    fn fragment_event(&mut self, e: &FragmentEvent) {
        let s = &mut self.report.stats;
        match e.kind {
            FragmentEventKind::Evicted(_) => s.frag_evicted = s.frag_evicted.saturating_add(1),
            FragmentEventKind::Rejected(_) => s.frag_rejected = s.frag_rejected.saturating_add(1),
            FragmentEventKind::ConflictingOverlap | FragmentEventKind::ConflictingInlineQos(_) => {
                s.frag_conflicts = s.frag_conflicts.saturating_add(1)
            }
        }
        if self.report.fragment_events.len() < MAX_USER_FRAGMENT_EVENTS {
            self.report
                .fragment_events
                .push(UserFragmentEvent::from_event(e));
        }
    }

    /// Room for one more sample? Counts the overflow.
    fn room(&mut self) -> bool {
        if self.report.samples.len() < self.max_samples {
            true
        } else {
            self.report.stats.samples_capped = self.report.stats.samples_capped.saturating_add(1);
            false
        }
    }

    fn push(&mut self, s: UserSample<'a>) {
        self.report.stats.samples = self.report.stats.samples.saturating_add(1);
        self.report.samples.push(s);
    }

    /// Read the fixed fields shared by DATA and DATA_FRAG (`body` is at
    /// least 20 octets): the address, or the anomaly that drops it.
    fn address(
        &mut self,
        body: &[u8],
        le: bool,
        rx: &Receiver,
    ) -> Option<Result<SampleAddress, ()>> {
        let reader: EntityId = read_array(body, 4)?;
        let writer: EntityId = read_array(body, 8)?;
        let hi = read_i32(body, 12, le)?;
        let lo = read_u32(body, 16, le)?;
        let address = SampleAddress {
            writer: guid_of(rx.source, writer),
            reader: guid_of(rx.dest, reader),
            sequence_number: (i64::from(hi) << 32) | i64::from(lo),
        };
        if is_builtin_entity(writer) {
            self.report.stats.builtin_skipped = self.report.stats.builtin_skipped.saturating_add(1);
            return Some(Err(()));
        }
        if writer == ENTITYID_UNKNOWN {
            self.anomaly(UserAnomalyKind::UnknownWriterEntity, Some(address));
            return Some(Err(()));
        }
        if address.sequence_number <= 0 {
            self.anomaly(UserAnomalyKind::InvalidSequenceNumber, Some(address));
            return Some(Err(()));
        }
        Some(Ok(address))
    }

    /// Validate `octetsToInlineQos` and parse the inline QoS. Returns the
    /// readings and the payload offset, or `None` (anomaly recorded).
    fn inline_qos(
        &mut self,
        body: &[u8],
        fixed: u16,
        present: bool,
        le: bool,
        address: SampleAddress,
    ) -> Option<(InlineQos, usize)> {
        let oti = read_u16(body, 2, le)?;
        if oti < fixed {
            self.anomaly(UserAnomalyKind::BadOctetsToInlineQos, Some(address));
            return None;
        }
        let pos = 4 + oti as usize;
        if !present {
            return Some((InlineQos::default(), pos));
        }
        let mut q = InlineQos::default();
        let mut last_status: Option<StatusInfo> = None;
        let mut it = ParameterList::new(body, pos, le);
        for (pid, v) in it.by_ref() {
            match pid {
                PID_KEY_HASH => {
                    if q.key_hash.is_none() {
                        q.key_hash = read_array::<16>(v, 0);
                    }
                }
                PID_STATUS_INFO => {
                    if let Some(raw) = read_array::<4>(v, 0) {
                        let st = StatusInfo { raw };
                        q.status.get_or_insert(st);
                        last_status = Some(st);
                    }
                }
                _ => {}
            }
        }
        if let (Some(first), Some(last)) = (q.status, last_status) {
            if first != last {
                q.alt_status = Some(last);
            }
        }
        if it.end() != PlEnd::Sentinel {
            self.anomaly(UserAnomalyKind::MalformedInlineQos, Some(address));
            return None;
        }
        Some((q, it.pos()))
    }

    fn data<F: FnMut(&SampleAddress) -> bool>(
        &mut self,
        body: &'a [u8],
        flags: u8,
        rx: &Receiver,
        wanted: &mut F,
    ) {
        let le = flags & FLAG_E != 0;
        if body.len() < 20 {
            // Too short to tell whose it is; a builtin DATA this short is
            // the discovery parser's anomaly too.
            self.anomaly(UserAnomalyKind::MalformedData, None);
            return;
        }
        let address = match self.address(body, le, rx) {
            Some(Ok(a)) => a,
            Some(Err(())) => return,
            None => {
                self.anomaly(UserAnomalyKind::MalformedData, None);
                return;
            }
        };
        self.report.stats.data = self.report.stats.data.saturating_add(1);
        if !wanted(&address) {
            self.report.stats.not_wanted = self.report.stats.not_wanted.saturating_add(1);
            return;
        }
        let Some((q, pos)) = self.inline_qos(body, 16, flags & FLAG_Q != 0, le, address) else {
            return;
        };
        let payload_kind = if flags & FLAG_D != 0 {
            PayloadKind::Data
        } else if flags & FLAG_K != 0 {
            PayloadKind::Key
        } else {
            PayloadKind::None
        };
        let payload: &'a [u8] = if payload_kind == PayloadKind::None {
            &[]
        } else {
            match body.get(pos..) {
                Some(p) => p,
                None => {
                    self.anomaly(UserAnomalyKind::MalformedData, Some(address));
                    return;
                }
            }
        };
        if !self.room() {
            return;
        }
        self.push(UserSample {
            address,
            payload_kind,
            payload: Cow::Borrowed(payload),
            inline_qos: UserInlineQos::from_reading(&q, flags & FLAG_Q != 0),
            source_timestamp: rx.timestamp,
            little_endian: le,
            non_standard_payload: flags & FLAG_DATA_N != 0,
            from_fragments: false,
        });
    }

    fn data_frag<F: FnMut(&SampleAddress) -> bool>(
        &mut self,
        reasm: &mut FragmentReassembler,
        body: &'a [u8],
        flags: u8,
        rx: &Receiver,
        wanted: &mut F,
    ) {
        let le = flags & FLAG_E != 0;
        if body.len() < 32 {
            self.anomaly(UserAnomalyKind::MalformedDataFrag, None);
            return;
        }
        let address = match self.address(body, le, rx) {
            Some(Ok(a)) => a,
            Some(Err(())) => return,
            None => {
                self.anomaly(UserAnomalyKind::MalformedDataFrag, None);
                return;
            }
        };
        self.report.stats.data_frag = self.report.stats.data_frag.saturating_add(1);
        if !wanted(&address) {
            self.report.stats.not_wanted = self.report.stats.not_wanted.saturating_add(1);
            return;
        }
        let (Some(start), Some(count), Some(frag_size), Some(size)) = (
            read_u32(body, 20, le),
            read_u16(body, 24, le),
            read_u16(body, 26, le),
            read_u32(body, 28, le),
        ) else {
            return; // unreachable: body.len() >= 32
        };
        let Some((q, pos)) = self.inline_qos(body, 28, flags & FLAG_Q != 0, le, address) else {
            return;
        };
        let Some(data) = body.get(pos..) else {
            self.anomaly(UserAnomalyKind::MalformedDataFrag, Some(address));
            return;
        };
        let key_only = flags & FLAG_FRAG_K != 0;
        let mut events = Vec::new();
        let outcome = reasm.add(
            FragIn {
                key: SampleKey {
                    source: address.writer_prefix(),
                    destination: read_array(&address.reader, 0).unwrap_or_default(),
                    writer: address.writer_entity(),
                    sn: address.sequence_number as u64, // > 0, checked
                },
                // The reassembler's tag type is the discovery topic; user
                // samples are tagged with a placeholder that never leaves
                // this module (events are converted, the tag dropped).
                topic: DiscoveryTopic::Publications,
                start,
                count,
                frag_size,
                sample_size: size,
                data,
                inline: q,
                key_only,
            },
            &mut events,
        );
        for e in &events {
            self.fragment_event(e);
        }
        if let FragOutcome::Complete(buf, inline, key_only) = outcome {
            self.report.stats.frag_completed = self.report.stats.frag_completed.saturating_add(1);
            if !self.room() {
                return;
            }
            self.push(UserSample {
                address,
                payload_kind: if key_only {
                    PayloadKind::Key
                } else {
                    PayloadKind::Data
                },
                payload: Cow::Owned(buf),
                inline_qos: UserInlineQos::from_reading(&inline, inline != InlineQos::default()),
                source_timestamp: rx.timestamp,
                little_endian: le,
                non_standard_payload: flags & FLAG_FRAG_N != 0,
                from_fragments: true,
            });
        }
    }
}

impl UserDataWalker {
    /// A walker with the given caps.
    pub fn new(limits: UserDataLimits) -> Self {
        Self {
            reasm: FragmentReassembler::new_per_writer(limits.reassembly),
            max_samples: limits
                .max_samples_per_datagram
                .clamp(1, HARD_MAX_SAMPLES_PER_DATAGRAM),
        }
    }

    /// The user-data reassembler (for its counters).
    pub fn reassembler(&self) -> &FragmentReassembler {
        &self.reasm
    }

    /// Effective per-datagram sample cap.
    pub fn max_samples_per_datagram(&self) -> usize {
        self.max_samples
    }

    /// Every user sample of `datagram`. `None` if it is not RTPS.
    pub fn walk<'a>(&mut self, datagram: &'a [u8]) -> Option<UserDataReport<'a>> {
        self.walk_with(datagram, |_| true)
    }

    /// The user samples of `datagram` that `wanted` accepts. `wanted` sees
    /// each user DATA / DATA_FRAG's [`SampleAddress`] before its inline QoS
    /// or payload is read and before anything is buffered; a refused
    /// fragment is never stored. `None` if the datagram is not RTPS.
    /// Never panics.
    pub fn walk_with<'a, F: FnMut(&SampleAddress) -> bool>(
        &mut self,
        datagram: &'a [u8],
        mut wanted: F,
    ) -> Option<UserDataReport<'a>> {
        let header = RtpsHeader::parse(datagram)?;
        let mut w = Walk {
            report: UserDataReport {
                header,
                samples: Vec::new(),
                anomalies: Vec::new(),
                fragment_events: Vec::new(),
                stats: UserDataStats::default(),
            },
            max_samples: self.max_samples,
        };
        let mut rx = Receiver {
            source: header.guid_prefix,
            dest: GUIDPREFIX_UNKNOWN,
            timestamp: None,
        };
        let mut buf = datagram.get(RTPS_HEADER_LEN..).unwrap_or_default();
        while !buf.is_empty() {
            let (Some(&id), Some(&flags)) = (buf.first(), buf.get(1)) else {
                w.anomaly(UserAnomalyKind::TruncatedSubmessage, None);
                break;
            };
            let le = flags & FLAG_E != 0;
            let Some(len) = read_u16(buf, 2, le) else {
                w.anomaly(UserAnomalyKind::TruncatedSubmessage, None);
                break;
            };
            let body_len = if len == 0 && id != SUBMSG_PAD && id != SUBMSG_INFO_TS {
                buf.len() - 4
            } else {
                len as usize
            };
            let Some(body) = buf.get(4..4 + body_len) else {
                w.anomaly(UserAnomalyKind::TruncatedSubmessage, None);
                break;
            };
            w.report.stats.submessages = w.report.stats.submessages.saturating_add(1);
            match id {
                SUBMSG_INFO_TS => {
                    w.report.stats.info_ts = w.report.stats.info_ts.saturating_add(1);
                    rx.timestamp = if flags & FLAG_INFO_TS_I != 0 {
                        None
                    } else {
                        match (read_u32(body, 0, le), read_u32(body, 4, le)) {
                            (Some(seconds), Some(fraction)) => Some(RtpsTime { seconds, fraction }),
                            _ => {
                                w.anomaly(UserAnomalyKind::MalformedInfoTimestamp, None);
                                None
                            }
                        }
                    };
                }
                SUBMSG_INFO_SRC => {
                    w.report.stats.info_src = w.report.stats.info_src.saturating_add(1);
                    match read_array::<12>(body, 8) {
                        Some(p) => {
                            rx.source = p;
                            rx.timestamp = None;
                        }
                        None => w.anomaly(UserAnomalyKind::MalformedInfoSource, None),
                    }
                }
                SUBMSG_INFO_DST => {
                    w.report.stats.info_dst = w.report.stats.info_dst.saturating_add(1);
                    match read_array::<12>(body, 0) {
                        Some(p) => rx.dest = p,
                        None => w.anomaly(UserAnomalyKind::MalformedInfoDestination, None),
                    }
                }
                SUBMSG_DATA => w.data(body, flags, &rx, &mut wanted),
                SUBMSG_DATA_FRAG => w.data_frag(&mut self.reasm, body, flags, &rx, &mut wanted),
                SUBMSG_SECURE_FIRST..=SUBMSG_SECURE_LAST => {
                    w.report.stats.secure = w.report.stats.secure.saturating_add(1)
                }
                _ => {}
            }
            buf = buf.get(4 + body_len..).unwrap_or_default();
        }
        Some(w.report)
    }
}

/// Stateless [`UserDataWalker::walk`]: DATA_FRAG samples are reassembled
/// only when all their fragments sit in this datagram.
pub fn walk_user_data(datagram: &[u8]) -> Option<UserDataReport<'_>> {
    UserDataWalker::default().walk(datagram)
}

#[cfg(test)]
mod tests {
    use super::*;

    const W: GuidPrefix = [0xaa; 12];
    const CMD_WRITER: EntityId = [0, 0, 0x12, 0x03];
    const CMD_READER: EntityId = [0, 0, 0x13, 0x04];

    fn header(prefix: GuidPrefix) -> Vec<u8> {
        let mut d = b"RTPS".to_vec();
        d.extend_from_slice(&[2, 3, 0x01, 0x0f]);
        d.extend_from_slice(&prefix);
        d
    }

    fn sub(id: u8, flags: u8, body: &[u8]) -> Vec<u8> {
        let le = flags & FLAG_E != 0;
        let mut s = vec![id, flags];
        let n = body.len() as u16;
        s.extend_from_slice(&if le { n.to_le_bytes() } else { n.to_be_bytes() });
        s.extend_from_slice(body);
        s
    }

    fn u16b(v: u16, le: bool) -> [u8; 2] {
        if le {
            v.to_le_bytes()
        } else {
            v.to_be_bytes()
        }
    }

    fn u32b(v: u32, le: bool) -> [u8; 4] {
        if le {
            v.to_le_bytes()
        } else {
            v.to_be_bytes()
        }
    }

    /// A CDR_LE Twist payload (encapsulation + 6 doubles).
    fn twist(vx: f64, wz: f64) -> Vec<u8> {
        let mut p = vec![0x00, 0x01, 0, 0];
        for v in [vx, 0.0, 0.0, 0.0, 0.0, wz] {
            p.extend_from_slice(&v.to_le_bytes());
        }
        p
    }

    fn data_body(
        le: bool,
        reader: EntityId,
        writer: EntityId,
        sn: (i32, u32),
        inline: &[u8],
        payload: &[u8],
    ) -> Vec<u8> {
        let mut b = vec![0, 0];
        b.extend_from_slice(&u16b(16, le));
        b.extend_from_slice(&reader);
        b.extend_from_slice(&writer);
        b.extend_from_slice(&u32b(sn.0 as u32, le));
        b.extend_from_slice(&u32b(sn.1, le));
        b.extend_from_slice(inline);
        b.extend_from_slice(payload);
        b
    }

    fn data(le: bool, writer: EntityId, sn: u32, payload: &[u8]) -> Vec<u8> {
        let flags = FLAG_D | if le { FLAG_E } else { 0 };
        sub(
            SUBMSG_DATA,
            flags,
            &data_body(le, CMD_READER, writer, (0, sn), &[], payload),
        )
    }

    #[allow(clippy::too_many_arguments)]
    fn data_frag(
        le: bool,
        writer: EntityId,
        sn: u32,
        start: u32,
        count: u16,
        frag_size: u16,
        sample_size: u32,
        frag: &[u8],
    ) -> Vec<u8> {
        let mut b = vec![0, 0];
        b.extend_from_slice(&u16b(28, le));
        b.extend_from_slice(&CMD_READER);
        b.extend_from_slice(&writer);
        b.extend_from_slice(&u32b(0, le));
        b.extend_from_slice(&u32b(sn, le));
        b.extend_from_slice(&u32b(start, le));
        b.extend_from_slice(&u16b(count, le));
        b.extend_from_slice(&u16b(frag_size, le));
        b.extend_from_slice(&u32b(sample_size, le));
        b.extend_from_slice(frag);
        sub(SUBMSG_DATA_FRAG, if le { FLAG_E } else { 0 }, &b)
    }

    fn info_ts(le: bool, secs: u32, frac: u32) -> Vec<u8> {
        let mut b = u32b(secs, le).to_vec();
        b.extend_from_slice(&u32b(frac, le));
        sub(SUBMSG_INFO_TS, if le { FLAG_E } else { 0 }, &b)
    }

    fn info_src(prefix: GuidPrefix) -> Vec<u8> {
        let mut b = vec![0; 4];
        b.extend_from_slice(&[2, 3, 1, 0x0f]);
        b.extend_from_slice(&prefix);
        sub(SUBMSG_INFO_SRC, FLAG_E, &b)
    }

    fn info_dst(prefix: GuidPrefix) -> Vec<u8> {
        sub(SUBMSG_INFO_DST, FLAG_E, &prefix)
    }

    fn dgram(parts: &[Vec<u8>]) -> Vec<u8> {
        let mut d = header(W);
        for p in parts {
            d.extend_from_slice(p);
        }
        d
    }

    #[test]
    fn data_yields_writer_reader_sn_payload_in_both_endiannesses() {
        let payload = twist(0.5, -0.25);
        for le in [true, false] {
            let d = dgram(&[data(le, CMD_WRITER, 7, &payload)]);
            let r = walk_user_data(&d).unwrap();
            assert_eq!(r.samples.len(), 1, "le={le}");
            let s = &r.samples[0];
            assert_eq!(s.address.writer, guid_of(W, CMD_WRITER));
            assert_eq!(s.address.reader, guid_of(GUIDPREFIX_UNKNOWN, CMD_READER));
            assert_eq!(s.address.sequence_number, 7);
            assert_eq!(s.payload_kind, PayloadKind::Data);
            assert_eq!(&s.payload[..], &payload[..]);
            assert_eq!(s.little_endian, le);
            assert!(!s.from_fragments);
            assert_eq!(s.source_timestamp, None);
            assert_eq!(s.writer_hex(), format!("{}00001203", "aa".repeat(12)));
            assert_eq!(r.stats.data, 1);
        }
    }

    #[test]
    fn builtin_writers_are_skipped() {
        let d = dgram(&[
            data(true, [0, 0, 3, 0xc2], 1, &[0, 3, 0, 0, 1, 0, 0, 0]),
            data(true, [0, 1, 0, 0xc2], 1, &[0, 3, 0, 0, 1, 0, 0, 0]),
            data(true, [0xff, 0, 3, 0xc2], 1, &[0, 3, 0, 0]),
            data(true, [0, 2, 0, 0xc3], 1, &[0, 3, 0, 0]), // participant message
        ]);
        let r = walk_user_data(&d).unwrap();
        assert!(r.samples.is_empty());
        assert_eq!(r.stats.builtin_skipped, 4);
        assert_eq!(r.stats.data, 0);
        assert!(is_builtin_entity([0, 0, 0, 0xc7]));
        assert!(!is_builtin_entity(CMD_WRITER));
        assert!(!is_builtin_entity([0, 0, 1, 0x43])); // vendor-specific user kind
    }

    #[test]
    fn info_ts_applies_until_changed_invalidated_or_info_src() {
        let p = twist(0.1, 0.0);
        let d = dgram(&[
            data(true, CMD_WRITER, 1, &p),
            info_ts(true, 1_760_000_000, 0x8000_0000),
            data(true, CMD_WRITER, 2, &p),
            info_ts(false, 1_760_000_001, 0),
            data(true, CMD_WRITER, 3, &p),
            sub(SUBMSG_INFO_TS, FLAG_E | FLAG_INFO_TS_I, &[]),
            data(true, CMD_WRITER, 4, &p),
            info_ts(true, 5, 0),
            info_src([0xbb; 12]),
            data(true, CMD_WRITER, 5, &p),
        ]);
        let r = walk_user_data(&d).unwrap();
        let ts: Vec<_> = r.samples.iter().map(|s| s.source_timestamp).collect();
        assert_eq!(
            ts,
            vec![
                None,
                Some(RtpsTime {
                    seconds: 1_760_000_000,
                    fraction: 0x8000_0000
                }),
                Some(RtpsTime {
                    seconds: 1_760_000_001,
                    fraction: 0
                }),
                None,
                None,
            ]
        );
        assert_eq!(ts[1].unwrap().to_unix_ns(), Some(1_760_000_000_500_000_000));
        assert_eq!(RtpsTime::INVALID.to_unix_ns(), None);
        assert_eq!(RtpsTime::INFINITE.to_unix_ns(), None);
        // INFO_SRC changed the writer prefix of the last sample.
        assert_eq!(r.samples[4].address.writer_prefix(), [0xbb; 12]);
        assert_eq!(r.stats.info_ts, 4);
        // A short INFO_TS without I flag clears it and is flagged.
        let d = dgram(&[
            info_ts(true, 9, 9),
            sub(SUBMSG_INFO_TS, FLAG_E, &[1, 2, 3, 4]),
            data(true, CMD_WRITER, 1, &p),
        ]);
        let r = walk_user_data(&d).unwrap();
        assert_eq!(r.samples[0].source_timestamp, None);
        assert_eq!(r.anomalies[0].kind, UserAnomalyKind::MalformedInfoTimestamp);
    }

    #[test]
    fn info_dst_sets_the_reader_prefix() {
        let p = twist(0.1, 0.0);
        let d = dgram(&[info_dst([0xcc; 12]), data(true, CMD_WRITER, 1, &p)]);
        let r = walk_user_data(&d).unwrap();
        assert_eq!(r.samples[0].address.reader, guid_of([0xcc; 12], CMD_READER));
        assert_eq!(r.samples[0].address.reader_entity(), CMD_READER);
        let d = dgram(&[
            sub(SUBMSG_INFO_DST, FLAG_E, &[1; 4]),
            data(true, CMD_WRITER, 1, &p),
        ]);
        let r = walk_user_data(&d).unwrap();
        assert_eq!(r.samples[0].address.reader_prefix(), GUIDPREFIX_UNKNOWN);
        assert_eq!(
            r.anomalies[0].kind,
            UserAnomalyKind::MalformedInfoDestination
        );
    }

    #[test]
    fn inline_qos_status_and_key_hash_are_read() {
        let mut q = Vec::new();
        q.extend_from_slice(&PID_KEY_HASH.to_le_bytes());
        q.extend_from_slice(&16u16.to_le_bytes());
        q.extend_from_slice(&[7; 16]);
        q.extend_from_slice(&PID_STATUS_INFO.to_le_bytes());
        q.extend_from_slice(&4u16.to_le_bytes());
        q.extend_from_slice(&[0, 0, 0, 1]);
        q.extend_from_slice(&PID_STATUS_INFO.to_le_bytes());
        q.extend_from_slice(&4u16.to_le_bytes());
        q.extend_from_slice(&[0, 0, 0, 0]);
        q.extend_from_slice(&[1, 0, 0, 0]);
        let body = data_body(true, CMD_READER, CMD_WRITER, (0, 3), &q, &[]);
        let d = dgram(&[sub(SUBMSG_DATA, FLAG_E | FLAG_Q, &body)]);
        let r = walk_user_data(&d).unwrap();
        let s = &r.samples[0];
        assert_eq!(s.payload_kind, PayloadKind::None);
        assert!(s.payload.is_empty());
        assert!(s.inline_qos.present);
        assert_eq!(s.inline_qos.key_hash, Some([7; 16]));
        assert!(s.inline_qos.removal());
        assert!(s.inline_qos.status_conflict);
        // Without a sentinel the payload offset is unknown: dropped.
        let body = data_body(true, CMD_READER, CMD_WRITER, (0, 3), &q[..q.len() - 4], &[]);
        let d = dgram(&[sub(SUBMSG_DATA, FLAG_E | FLAG_Q | FLAG_D, &body)]);
        let r = walk_user_data(&d).unwrap();
        assert!(r.samples.is_empty());
        assert_eq!(r.anomalies[0].kind, UserAnomalyKind::MalformedInlineQos);
        assert_eq!(
            r.anomalies[0].address.map(|a| a.writer),
            Some(guid_of(W, CMD_WRITER))
        );
    }

    #[test]
    fn invalid_sequence_numbers_and_unknown_writer_are_dropped() {
        let p = twist(0.1, 0.0);
        for sn in [(0, 0), (-1, 5), (i32::MIN, 0)] {
            let body = data_body(true, CMD_READER, CMD_WRITER, sn, &[], &p);
            let d = dgram(&[sub(SUBMSG_DATA, FLAG_E | FLAG_D, &body)]);
            let r = walk_user_data(&d).unwrap();
            assert!(r.samples.is_empty(), "{sn:?}");
            assert_eq!(r.anomalies[0].kind, UserAnomalyKind::InvalidSequenceNumber);
        }
        let body = data_body(true, CMD_READER, CMD_WRITER, (1, 0), &[], &p);
        let d = dgram(&[sub(SUBMSG_DATA, FLAG_E | FLAG_D, &body)]);
        assert_eq!(
            walk_user_data(&d).unwrap().samples[0]
                .address
                .sequence_number,
            1 << 32
        );
        let d = dgram(&[data(true, ENTITYID_UNKNOWN, 1, &p)]);
        let r = walk_user_data(&d).unwrap();
        assert!(r.samples.is_empty());
        assert_eq!(r.anomalies[0].kind, UserAnomalyKind::UnknownWriterEntity);
    }

    #[test]
    fn data_frag_reassembles_across_datagrams_in_both_endiannesses() {
        let payload = twist(3.0, 0.5); // 52 bytes
        for le in [true, false] {
            let mut w = UserDataWalker::default();
            let chunks: Vec<&[u8]> = payload.chunks(20).collect();
            let mut got = Vec::new();
            for (i, c) in chunks.iter().enumerate() {
                let d = dgram(&[
                    info_ts(le, 100 + i as u32, 0),
                    data_frag(le, CMD_WRITER, 9, i as u32 + 1, 1, 20, 52, c),
                ]);
                let r = w.walk(&d).unwrap();
                got.extend(r.samples.into_iter().map(UserSample::into_owned));
            }
            assert_eq!(got.len(), 1, "le={le}");
            let s = &got[0];
            assert!(s.from_fragments);
            assert_eq!(&s.payload[..], &payload[..]);
            assert_eq!(s.address.sequence_number, 9);
            assert_eq!(s.source_timestamp.map(|t| t.seconds), Some(102));
            assert_eq!(w.reassembler().pending_samples(), 0);
        }
    }

    #[test]
    fn unwanted_fragments_are_never_buffered() {
        let mut w = UserDataWalker::default();
        let d = dgram(&[data_frag(true, CMD_WRITER, 1, 1, 1, 100, 1000, &[0; 100])]);
        let r = w.walk_with(&d, |_| false).unwrap();
        assert_eq!(r.stats.not_wanted, 1);
        assert_eq!(w.reassembler().pending_samples(), 0);
        let r = w.walk(&d).unwrap();
        assert!(r.samples.is_empty());
        assert_eq!(w.reassembler().pending_samples(), 1);
    }

    #[test]
    fn oversized_fragmented_sample_is_rejected_and_reported_per_writer() {
        let mut w = UserDataWalker::new(UserDataLimits {
            reassembly: ReassemblyLimits {
                max_sample_bytes: 1000,
                ..Default::default()
            },
            ..Default::default()
        });
        let d = dgram(&[data_frag(true, CMD_WRITER, 4, 1, 1, 100, 5000, &[0; 100])]);
        let r = w.walk(&d).unwrap();
        assert!(r.samples.is_empty());
        assert_eq!(r.stats.frag_rejected, 1);
        assert_eq!(r.fragment_events[0].writer, guid_of(W, CMD_WRITER));
        assert_eq!(r.fragment_events[0].sequence_number, 4);
    }

    #[test]
    fn per_writer_quota_protects_other_writers_of_the_same_participant() {
        let mut w = UserDataWalker::default();
        // A motion writer's first fragment ...
        let d = dgram(&[data_frag(true, CMD_WRITER, 1, 1, 1, 8, 16, &[1; 8])]);
        w.walk(&d).unwrap();
        // ... then a camera writer of the same participant floods partial
        // samples: it only ever evicts its own.
        let camera: EntityId = [0, 0, 0x20, 0x03];
        let mut evicted_writers = Vec::new();
        for sn in 1..100 {
            let d = dgram(&[data_frag(true, camera, sn, 1, 1, 8, 16, &[2; 8])]);
            let r = w.walk(&d).unwrap();
            evicted_writers.extend(r.fragment_events.iter().map(|e| e.writer));
        }
        assert!(!evicted_writers.is_empty());
        assert!(evicted_writers.iter().all(|g| *g == guid_of(W, camera)));
        let d = dgram(&[data_frag(true, CMD_WRITER, 1, 2, 1, 8, 16, &[1; 8])]);
        let r = w.walk(&d).unwrap();
        assert_eq!(r.samples.len(), 1);
        assert_eq!(&r.samples[0].payload[..], &[1; 16][..]);
    }

    #[test]
    fn samples_per_datagram_are_capped() {
        let mut w = UserDataWalker::new(UserDataLimits {
            max_samples_per_datagram: 3,
            ..Default::default()
        });
        let p = twist(0.0, 0.0);
        let parts: Vec<Vec<u8>> = (1..=10).map(|sn| data(true, CMD_WRITER, sn, &p)).collect();
        let d = dgram(&parts);
        let r = w.walk(&d).unwrap();
        assert_eq!(r.samples.len(), 3);
        assert_eq!(r.stats.samples_capped, 7);
        assert_eq!(
            UserDataWalker::new(UserDataLimits {
                max_samples_per_datagram: 0,
                ..Default::default()
            })
            .max_samples_per_datagram(),
            1
        );
    }

    #[test]
    fn hostile_input_never_panics() {
        let p = twist(1.0, 1.0);
        let good = dgram(&[
            info_ts(true, 1, 1),
            info_dst([3; 12]),
            data(true, CMD_WRITER, 1, &p),
            data_frag(false, CMD_WRITER, 2, 1, 1, 16, 32, &p[..16]),
            info_src([9; 12]),
            data(false, CMD_WRITER, 3, &p),
        ]);
        let mut w = UserDataWalker::default();
        // Every truncation, and every single-byte mutation.
        for cut in 0..good.len() {
            let _ = w.walk(&good[..cut]);
        }
        let mut seed = 0x1234_5678_9abc_def0u64;
        for i in 0..good.len() * 8 {
            let mut m = good.clone();
            seed ^= seed << 13;
            seed ^= seed >> 7;
            seed ^= seed << 17;
            let at = RTPS_HEADER_LEN + (i % (good.len() - RTPS_HEADER_LEN));
            m[at] = seed as u8;
            if let Some(r) = w.walk(&m) {
                assert!(r.samples.len() <= DEFAULT_MAX_SAMPLES_PER_DATAGRAM);
                assert!(r.anomalies.len() <= MAX_USER_ANOMALIES);
            }
        }
        // Zero-length "to end of message" DATA and absurd lengths.
        let mut d = header(W);
        d.extend_from_slice(&[SUBMSG_DATA, FLAG_E | FLAG_D, 0, 0]);
        d.extend_from_slice(&data_body(true, CMD_READER, CMD_WRITER, (0, 1), &[], &p));
        assert_eq!(walk_user_data(&d).unwrap().samples.len(), 1);
        let mut d = header(W);
        d.extend_from_slice(&[SUBMSG_DATA, FLAG_E, 0xff, 0xff]);
        let r = walk_user_data(&d).unwrap();
        assert_eq!(r.anomalies[0].kind, UserAnomalyKind::TruncatedSubmessage);
        assert!(walk_user_data(b"not rtps").is_none());
        assert!(walk_user_data(b"RTPS").is_none());
    }
}
