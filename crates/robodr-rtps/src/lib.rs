//! A read-only RTPS discovery parser (SPDP + SEDP) for RoboDR.
//!
//! DDS participants announce themselves with SPDP (Simple Participant Discovery
//! Protocol) and each of their writers and readers with SEDP (Simple Endpoint
//! Discovery Protocol). Both ride in RTPS datagrams. RoboDR only *reads* this
//! traffic; it never writes to the bus. This crate is pure: no I/O, no clock,
//! no global state.
//!
//! # API
//!
//! - [`parse_datagram`]: datagram -> `RobotEvent`s (unchanged signature).
//! - [`parse_datagram_detailed`]: datagram -> [`DatagramReport`] with the
//!   full SPDP data ([`SpdpInfo`]: locators, entity name, ROS 2 enclave, domain
//!   id, vendor, lease), endpoint attribution details ([`EndpointInfo`]),
//!   dispose/unregister signals ([`EndpointRemoval`], [`ParticipantRemoval`]),
//!   [`Anomaly`]s, reassembly [`FragmentEvent`]s and per-submessage
//!   [`ParseStats`].
//! - [`FragmentReassembler`]: optional, stateful, memory-capped DATA_FRAG
//!   reassembly for large discovery samples, with an eviction policy that
//!   resists spoofed-prefix floods (see its module docs).
//! - [`vendor`]: known DDS vendor ids.
//! - [`UserDataWalker`] / [`walk_user_data`]: the **user DATA** walker
//!   (application topics such as `rt/cmd_vel`): writer / reader GUID,
//!   sequence number, serialized payload (encapsulation included), inline
//!   QoS and INFO_TS source timestamp per sample, honouring INFO_SRC /
//!   INFO_DST / INFO_TS, both endiannesses, DATA and (bounded, per-writer
//!   quota) DATA_FRAG. It does not decode payloads (`robodr-cdr` does, by
//!   the type name learned from SEDP). See the `user` module docs.
//!
//! # What is parsed
//!
//! Submessages are walked per DDSI-RTPS 2.5 §8.3 / §9.4 with per-submessage
//! endianness (E flag). INFO_SRC changes the *source* GUID prefix for the
//! submessages that follow it; INFO_DST, INFO_TS, PAD, HEARTBEAT, ACKNACK,
//! GAP, *_FRAG control, INFO_REPLY*, DDS-Security (0x30..0x34, counted) and
//! vendor-specific (0x80..) submessages are skipped by length. Per §9.4.5.1.3,
//! `octetsToNextHeader == 0` means "to end of message" except for PAD and
//! INFO_TS, where it is an empty body.
//!
//! DATA from the builtin SPDP writer (`0x000100c2`) and SEDP publications /
//! subscriptions writers (`0x000003c2` / `0x000004c2`, plus their DDS-Security
//! `0xff..` variants when the payload is not encrypted) is decoded as a PL_CDR
//! (BE or LE) parameter list. DATA_FRAG from those writers is counted
//! ([`DatagramReport::fragmented_discovery_seen`]) and, with a
//! [`FragmentReassembler`], reassembled within strict memory caps.
//!
//! # Which GUID is authoritative
//!
//! Discovery data can be *relayed*: a Fast DDS discovery server re-sends other
//! participants' SPDP/SEDP from its own builtin writers, and INFO_SRC lets a
//! message speak for another prefix. So the RTPS header prefix says who sent
//! the bytes, not who owns the announced entity. The rules:
//!
//! - **Endpoint owner** = prefix of `PID_ENDPOINT_GUID`; else the instance key
//!   (inline `PID_KEY_HASH` or serialized key, which for builtin topics *is* the
//!   GUID); else prefix of `PID_PARTICIPANT_GUID`; else the current source
//!   prefix (header, as changed by INFO_SRC). The endpoint GUID wins because
//!   RTPS requires an endpoint's GUID prefix to equal its participant's and it
//!   is the GUID that matching and user traffic use. A disagreeing
//!   `PID_PARTICIPANT_GUID` is flagged ([`EndpointInfo::guid_conflict`],
//!   [`Anomaly::EndpointParticipantMismatch`]).
//! - **Participant (SPDP)** = prefix of `PID_PARTICIPANT_GUID`; else the
//!   instance key; else the source prefix.
//! - The *sender* is kept separately ([`EndpointInfo::source`],
//!   [`EndpointInfo::relayed`]).
//!
//! None of these are authenticated without DDS-Security: every GUID here is a
//! *claim*. The attribution only decides whose claim it is.
//!
//! # Events
//!
//! [`parse_datagram`] emits exactly one `Ros2ParticipantDiscovered` per
//! distinct participant per datagram: the header prefix (always, as before),
//! each distinct non-zero INFO_SRC prefix, and each SPDP-announced participant
//! (plus the prefixes of any conflicting duplicate `PID_PARTICIPANT_GUID`);
//! the same prefix seen several ways is merged into one event whose `locators`
//! are the SPDP unicast locators (metatraffic, then default; UDPv4 as
//! `a.b.c.d:port`, UDPv6 as `[v6]:port`; other kinds such as shared memory are
//! not rendered but are kept with their `kind` in [`SpdpInfo`]). Then one
//! writer/reader event per *reading* of each SEDP announcement: normally
//! one, but a sample that repeats `PID_TOPIC_NAME` / `PID_TYPE_NAME` /
//! `PID_ENDPOINT_GUID` with different values yields one event for the
//! first-occurrence reading, one for the last-occurrence reading (Fast DDS
//! overwrites, so last wins there) and one for each other distinct value
//! (see [`EndpointInfo::alternates`]). So a profile check sees `rt/cmd_vel`
//! whichever duplicate a stack honours. An announcement whose GUID names a
//! participant other than its sender (header / INFO_SRC prefix) yields each
//! reading a second time attributed to the sender (see
//! [`EndpointInfo::to_endpoints`]): the GUID is unauthenticated, so a rogue
//! participant cannot hide behind a profiled participant's prefix that way.
//! Disposed / unregistered
//! instances (`PID_STATUS_INFO`) produce **no** discovered event; they appear
//! only in the detailed report. (The header participant of a datagram that
//! carries its own SPDP dispose is still reported, because it did send the
//! datagram.)
//!
//! When DDS stacks may read the status differently (`PID_STATUS_INFO`
//! repeated with different values in one inline QoS: first-wins vs.
//! last-wins stacks; or a DATA_FRAG sample whose creating fragment and
//! fragment 1 carry different statuses, see the `frag` module docs), the
//! sample is a removal only if *every* reading is one. If any reading says
//! alive and the payload is a usable announcement, it is reported as an
//! announcement (a hidden live writer is worse than a missed removal) and
//! the disagreement is flagged as
//! [`Anomaly::ConflictingDuplicateParameter`]`(0x0071)`. Inline QoS of a
//! duplicate DATA_FRAG fragment (no new bytes) is ignored, as DDS stacks
//! drop such fragments whole.
//!
//! # Robustness
//!
//! Every length is checked against the remaining buffer; nothing is allocated
//! in proportion to a claimed length (strings, user data and locators are
//! copied only after they are known to be inside the datagram; reassembly
//! buffers are capped). Work per datagram is linear in its size: source and
//! participant merging is hash-indexed, values per parameter are capped.
//! Nothing that names a participant or an endpoint is dropped for being too
//! many (a cap would let padding hide the one that matters).
//!
//! # Leniency: see what the most lenient stack sees
//!
//! A detector that is stricter than the DDS stack it protects can be blinded:
//! the stack acts on an announcement the detector discarded. So where stacks
//! differ, the parser takes the *superset* and flags the deviation as an
//! [`Anomaly`] (never silently):
//!
//! - parameter length not a multiple of 4 (§9.4.2.11): accepted, next
//!   parameter read right after it ([`Anomaly::MisalignedParameterLength`]);
//! - parameter list overrun / missing sentinel / `PID_EXTENDED`: the
//!   parameters before the fault are used ([`Anomaly::MalformedParameterList`],
//!   [`Anomaly::UnsupportedParameter`]);
//! - topic / type names are read as C strings, up to the first NUL, whatever
//!   the CDR length says (`"rt/cmd_vel\0x\0"` is `rt/cmd_vel`;
//!   [`Anomaly::NonCanonicalString`]);
//! - duplicate identifying parameters: all distinct values are kept (see
//!   Events); other duplicates keep the first value
//!   ([`Anomaly::ConflictingDuplicateParameter`]);
//! - protocol major version other than 2: parsed with the 2.x layout
//!   ([`Anomaly::UnsupportedProtocolVersion`]);
//! - DATA_FRAG: the stateless functions reassemble samples whose fragments
//!   all sit in one datagram; [`FragmentReassembler`] also across datagrams.
//!
//! Still strict (documented limits): names must be UTF-8 (a stack would take
//! the raw bytes; such names cannot match a ROS 2 profile entry anyway, but
//! the endpoint is then not reported, only the anomaly);
//! `octetsToInlineQos` must cover the fixed fields; an inline QoS list without
//! a sentinel drops the sample (the payload offset is unknown).
//!
//! # Not handled / not verified
//!
//! - XCDR2 (`PL_CDR2`) discovery payloads and `PID_EXTENDED` are not decoded
//!   (reported as anomalies). Vendor-specific PIDs (bit 15) are ignored.
//! - Protected (DDS-Security encrypted) discovery is opaque; only counted.
//! - Full impersonation is not detectable from the bytes: a datagram whose
//!   header prefix *and* GUIDs all name a profiled participant looks exactly
//!   like that participant. Only the source IP (carried in every
//!   `Ros2ParticipantDiscovered`) can tell them apart, so binding prefixes to
//!   commissioned addresses / SPDP locators is the consumer's job.
//! - UDP checksums are the capture layer's business; a corrupted datagram
//!   that the kernel would drop is parsed like any other.
//! - Verified against hand-built datagrams from the spec layout, not yet
//!   against pcaps from real Fast DDS / Cyclone / Connext stacks.
//!
//! Reference: OMG DDSI-RTPS 2.2 / 2.5, §8.3 (messages), §8.5 (discovery),
//! §9.4 (submessage encoding), §9.6 (parameter ids, builtin topic data).

// S10: this crate has no `unsafe` code and must stay that way.
#![forbid(unsafe_code)]
// S10 (R9): release builds use `panic = "abort"`, so any panic kills the
// daemon (systemd restarts it; docs/OPERATIONS.md, "Crashes and restarts").
// Non-test code has no unwrap / expect / panic!-family call and no
// unchecked indexing (a proven bound carries a local allow and a `// bound:`
// note); arithmetic is left to review and fuzzing (fuzz/README.md).
#![cfg_attr(
    not(test),
    deny(
        clippy::indexing_slicing,
        clippy::unwrap_used,
        clippy::expect_used,
        clippy::panic,
        clippy::unreachable,
        clippy::todo,
        clippy::unimplemented
    )
)]

mod frag;
mod parse;
pub mod security;
mod user;
pub mod vendor;
mod wire;

#[cfg(test)]
mod discovery_tests;
#[cfg(test)]
mod review3_regressions;
#[cfg(test)]
mod review_regressions;
#[cfg(test)]
mod testutil;

pub use frag::{
    EvictionReason, FragmentEvent, FragmentEventKind, FragmentReassembler, ReassemblyLimits,
    RejectReason, DEFAULT_MAX_SAMPLE_BYTES, DEFAULT_MAX_TOTAL_BYTES, HARD_MAX_PENDING_SAMPLES,
    HARD_MAX_SAMPLE_BYTES,
};
pub use parse::{
    Anomaly, Attribution, DatagramReport, DiscoveryTopic, EndpointAlternate, EndpointInfo,
    EndpointKind, EndpointRemoval, EntityId, Guid, GuidPrefix, ParseStats, ParticipantRemoval,
    RtpsDuration, RtpsHeader, SpdpInfo, StatusInfo, ENTITYID_PARTICIPANT,
    ENTITYID_SEDP_PUBLICATIONS_SECURE_WRITER, ENTITYID_SEDP_PUBLICATIONS_WRITER,
    ENTITYID_SEDP_SUBSCRIPTIONS_SECURE_WRITER, ENTITYID_SEDP_SUBSCRIPTIONS_WRITER,
    ENTITYID_SPDP_SECURE_WRITER, ENTITYID_SPDP_WRITER, GUIDPREFIX_UNKNOWN, MAX_ANOMALIES,
    MAX_FRAGMENT_EVENTS, MAX_LOCATORS_PER_LIST, MAX_PARAMETER_VALUES,
};
pub use security::SpdpSecurity;
pub use user::{
    is_builtin_entity, walk_user_data, PayloadKind, RtpsTime, SampleAddress, UserAnomaly,
    UserAnomalyKind, UserDataLimits, UserDataReport, UserDataStats, UserDataWalker,
    UserFragmentEvent, UserInlineQos, UserSample, DEFAULT_MAX_SAMPLES_PER_DATAGRAM,
    ENTITYID_UNKNOWN, HARD_MAX_SAMPLES_PER_DATAGRAM, MAX_USER_ANOMALIES, MAX_USER_FRAGMENT_EVENTS,
};
pub use wire::{
    Locator, LocatorTransport, LOCATOR_KIND_INVALID, LOCATOR_KIND_RTI_SHMEM, LOCATOR_KIND_SHM,
    LOCATOR_KIND_TCPV4, LOCATOR_KIND_TCPV6, LOCATOR_KIND_UDPV4, LOCATOR_KIND_UDPV6,
};

use robodr_events::RobotEvent;

/// Lower-case hex of a 12-byte GUID prefix, no separators.
pub fn hex12(prefix: &GuidPrefix) -> String {
    wire::hex(prefix)
}

/// Lower-case hex of a 16-byte GUID, no separators.
pub fn hex_guid(guid: &Guid) -> String {
    wire::hex(guid)
}

/// Pull the GUID prefix out of a well-formed RTPS header. `None` if the buffer
/// is too short or the magic is wrong (not RTPS, so not ours to read).
pub fn guid_prefix(datagram: &[u8]) -> Option<GuidPrefix> {
    parse::RtpsHeader::parse(datagram).map(|h| h.guid_prefix)
}

/// Parse one RTPS datagram into robot events: one participant event per
/// distinct participant, then one writer or reader event per SEDP endpoint
/// announcement. Stateless: DATA_FRAG samples are reassembled only when all
/// their fragments are in this datagram (use
/// [`FragmentReassembler::parse_datagram`] for samples spread over several).
/// Non-RTPS input -> empty.
pub fn parse_datagram(datagram: &[u8], src_ip: &str) -> Vec<RobotEvent> {
    parse_datagram_detailed(datagram)
        .map(|r| r.to_events(src_ip))
        .unwrap_or_default()
}

/// Parse one RTPS datagram into a full [`DatagramReport`]. `None` if it is
/// not RTPS. Stateless (DATA_FRAG reassembled within this datagram only).
pub fn parse_datagram_detailed(datagram: &[u8]) -> Option<DatagramReport> {
    parse::parse(datagram, None)
}

impl FragmentReassembler {
    /// Like [`crate::parse_datagram_detailed`], reassembling discovery
    /// DATA_FRAG across calls.
    pub fn parse_datagram_detailed(&mut self, datagram: &[u8]) -> Option<DatagramReport> {
        parse::parse(datagram, Some(self))
    }

    /// Like [`crate::parse_datagram`], reassembling discovery DATA_FRAG
    /// across calls.
    pub fn parse_datagram(&mut self, datagram: &[u8], src_ip: &str) -> Vec<RobotEvent> {
        self.parse_datagram_detailed(datagram)
            .map(|r| r.to_events(src_ip))
            .unwrap_or_default()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::parse::{
        ENTITYID_SEDP_PUBLICATIONS_WRITER as ENTITY_SEDP_PUBLICATIONS_WRITER,
        ENTITYID_SEDP_SUBSCRIPTIONS_WRITER as ENTITY_SEDP_SUBSCRIPTIONS_WRITER,
    };
    use crate::wire::{
        cdr_string, FLAG_D, FLAG_E, PID_ENDPOINT_GUID, PID_SENTINEL, PID_TOPIC_NAME, PID_TYPE_NAME,
        PL_CDR_BE, PL_CDR_LE, SUBMSG_DATA,
    };
    use robodr_events::profile::{Envelope, Profile};
    use robodr_events::Severity;

    /// A 20-byte RTPS header: "RTPS" + version 2.2 + vendor 0x010f (eProsima) +
    /// a known 12-byte guid prefix, with no submessages.
    fn rtps_header(prefix: [u8; 12]) -> Vec<u8> {
        let mut d = Vec::new();
        d.extend_from_slice(b"RTPS");
        d.extend_from_slice(&[2, 2]); // protocol version
        d.extend_from_slice(&[0x01, 0x0f]); // vendor id
        d.extend_from_slice(&prefix);
        d
    }

    /// A little-endian parameter carrying a CDR string, padded to 4 bytes.
    fn string_param(pid: u16, s: &str) -> Vec<u8> {
        let mut value = Vec::new();
        value.extend_from_slice(&((s.len() + 1) as u32).to_le_bytes());
        value.extend_from_slice(s.as_bytes());
        value.push(0);
        while !value.len().is_multiple_of(4) {
            value.push(0);
        }
        let mut p = Vec::new();
        p.extend_from_slice(&pid.to_le_bytes());
        p.extend_from_slice(&(value.len() as u16).to_le_bytes());
        p.extend_from_slice(&value);
        p
    }

    /// One complete little-endian SEDP DATA submessage (header + body).
    fn sedp_data(
        writer_entity: [u8; 4],
        topic: &str,
        type_name: &str,
        ep_guid: [u8; 16],
    ) -> Vec<u8> {
        wrap_data(&sedp_body(writer_entity, topic, type_name, ep_guid))
    }

    /// Prefix a DATA body with a consistent little-endian submessage header.
    fn wrap_data(body: &[u8]) -> Vec<u8> {
        let mut sub = vec![SUBMSG_DATA, FLAG_E | FLAG_D];
        sub.extend_from_slice(&(body.len() as u16).to_le_bytes());
        sub.extend_from_slice(body);
        sub
    }

    /// The body of a little-endian SEDP DATA submessage.
    fn sedp_body(
        writer_entity: [u8; 4],
        topic: &str,
        type_name: &str,
        ep_guid: [u8; 16],
    ) -> Vec<u8> {
        let mut body = Vec::new();
        body.extend_from_slice(&[0, 0]); // extraFlags
        body.extend_from_slice(&16u16.to_le_bytes()); // octetsToInlineQos
        body.extend_from_slice(&[0, 0, 0, 0]); // readerId (unknown)
        body.extend_from_slice(&writer_entity); // writerId
        body.extend_from_slice(&0i32.to_le_bytes()); // writerSN high
        body.extend_from_slice(&1u32.to_le_bytes()); // writerSN low
        body.extend_from_slice(&PL_CDR_LE.to_be_bytes()); // encapsulation id
        body.extend_from_slice(&[0, 0]); // encapsulation options
                                         // PID_ENDPOINT_GUID
        body.extend_from_slice(&PID_ENDPOINT_GUID.to_le_bytes());
        body.extend_from_slice(&16u16.to_le_bytes());
        body.extend_from_slice(&ep_guid);
        body.extend_from_slice(&string_param(PID_TOPIC_NAME, topic));
        body.extend_from_slice(&string_param(PID_TYPE_NAME, type_name));
        body.extend_from_slice(&PID_SENTINEL.to_le_bytes());
        body.extend_from_slice(&0u16.to_le_bytes());
        body
    }

    fn guid(prefix_byte: u8) -> [u8; 16] {
        let mut g = [prefix_byte; 16];
        g[12..].copy_from_slice(&[0, 0, 0x01, 0x03]); // a writer entity id
        g
    }

    #[test]
    fn rejects_non_rtps() {
        assert!(guid_prefix(b"not an rtps packet at all").is_none());
    }

    #[test]
    fn rejects_short() {
        assert!(guid_prefix(b"RTPS").is_none());
    }

    #[test]
    fn extracts_guid_prefix() {
        let prefix = [1u8, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12];
        assert_eq!(guid_prefix(&rtps_header(prefix)), Some(prefix));
        assert_eq!(hex12(&prefix), "0102030405060708090a0b0c");
    }

    #[test]
    fn parse_datagram_yields_participant() {
        let events = parse_datagram(&rtps_header([0xaa; 12]), "10.0.0.5");
        assert_eq!(events.len(), 1);
        match &events[0] {
            RobotEvent::Ros2ParticipantDiscovered(p) => {
                assert_eq!(p.guid_prefix, "aaaaaaaaaaaaaaaaaaaaaaaa");
                assert_eq!(p.src_ip, "10.0.0.5");
            }
            other => panic!("unexpected event: {other:?}"),
        }
    }

    #[test]
    fn sedp_publication_yields_writer() {
        let mut d = rtps_header([0xaa; 12]);
        d.extend(sedp_data(
            ENTITY_SEDP_PUBLICATIONS_WRITER,
            "rt/cmd_vel",
            "geometry_msgs::msg::dds_::Twist_",
            guid(0xcc),
        ));
        let events = parse_datagram(&d, "10.0.0.5");
        assert_eq!(events.len(), 3);
        match &events[1] {
            RobotEvent::Ros2WriterDiscovered(e) => {
                assert_eq!(e.topic, "rt/cmd_vel");
                assert_eq!(e.ros_topic(), "/cmd_vel");
                assert_eq!(e.type_name, "geometry_msgs::msg::dds_::Twist_");
                // The endpoint GUID is the owner ...
                assert_eq!(e.guid_prefix, "cccccccccccccccccccccccc");
            }
            other => panic!("unexpected event: {other:?}"),
        }
        // ... and, as the GUID is unauthenticated, the sender is judged too.
        match &events[2] {
            RobotEvent::Ros2WriterDiscovered(e) => {
                assert_eq!(e.topic, "rt/cmd_vel");
                assert_eq!(e.guid_prefix, "aaaaaaaaaaaaaaaaaaaaaaaa");
            }
            other => panic!("unexpected event: {other:?}"),
        }
    }

    #[test]
    fn sedp_subscription_yields_reader() {
        let mut d = rtps_header([0xaa; 12]);
        d.extend(sedp_data(
            ENTITY_SEDP_SUBSCRIPTIONS_WRITER,
            "rt/odom",
            "nav_msgs::msg::dds_::Odometry_",
            guid(0xaa),
        ));
        let events = parse_datagram(&d, "10.0.0.5");
        assert!(
            matches!(&events[1], RobotEvent::Ros2ReaderDiscovered(e) if e.ros_topic() == "/odom")
        );
    }

    #[test]
    fn non_sedp_data_is_ignored() {
        // Same shape, but sent by a user writer, not a builtin SEDP writer.
        let mut d = rtps_header([0xaa; 12]);
        d.extend(sedp_data(
            [0x00, 0x00, 0x12, 0x03],
            "rt/cmd_vel",
            "x",
            guid(0xaa),
        ));
        assert_eq!(parse_datagram(&d, "10.0.0.5").len(), 1);
    }

    #[test]
    fn big_endian_payload_is_parsed() {
        // Build a BE-encapsulated parameter list by hand.
        let mut body = Vec::new();
        body.extend_from_slice(&[0, 0]);
        body.extend_from_slice(&16u16.to_le_bytes()); // submessage itself is LE
        body.extend_from_slice(&[0, 0, 0, 0]);
        body.extend_from_slice(&ENTITY_SEDP_PUBLICATIONS_WRITER);
        body.extend_from_slice(&[0; 8]);
        body.extend_from_slice(&PL_CDR_BE.to_be_bytes());
        body.extend_from_slice(&[0, 0]);
        let topic = b"rt/scan\0"; // 8 bytes, already 4-aligned
        body.extend_from_slice(&PID_TOPIC_NAME.to_be_bytes());
        body.extend_from_slice(&(4 + topic.len() as u16).to_be_bytes());
        body.extend_from_slice(&(topic.len() as u32).to_be_bytes());
        body.extend_from_slice(topic);
        body.extend_from_slice(&PID_SENTINEL.to_be_bytes());
        body.extend_from_slice(&0u16.to_be_bytes());
        let mut d = rtps_header([0xdd; 12]);
        d.extend_from_slice(&[SUBMSG_DATA, FLAG_E | FLAG_D]);
        d.extend_from_slice(&(body.len() as u16).to_le_bytes());
        d.extend_from_slice(&body);

        let events = parse_datagram(&d, "10.0.0.7");
        match &events[1] {
            RobotEvent::Ros2WriterDiscovered(e) => {
                assert_eq!(e.ros_topic(), "/scan");
                // No endpoint GUID parameter: falls back to the header prefix.
                assert_eq!(e.guid_prefix, "dddddddddddddddddddddddd");
            }
            other => panic!("unexpected event: {other:?}"),
        }
    }

    #[test]
    fn submessage_walk_does_not_overread_on_crafted_length() {
        let mut d = rtps_header([0xbb; 12]);
        d.extend_from_slice(&[SUBMSG_DATA, 0x01, 0xff, 0xff]); // LE len 65535
        assert_eq!(parse_datagram(&d, "10.0.0.6").len(), 1);
    }

    #[test]
    fn truncated_body_never_panics() {
        let header = rtps_header([0xaa; 12]);
        let body = sedp_body(
            ENTITY_SEDP_PUBLICATIONS_WRITER,
            "rt/cmd_vel",
            "t",
            guid(0xcc),
        );
        // Every truncation of the body, wrapped with a *consistent* submessage
        // length, so the cut lands inside the DATA and parameter-list parsers
        // rather than being caught by the outer length check.
        for cut in 0..body.len() {
            let mut d = header.clone();
            d.extend(wrap_data(&body[..cut]));
            let events = parse_datagram(&d, "10.0.0.5");
            assert!(!events.is_empty(), "participant must still be reported");
        }
        let mut d = header;
        d.extend(wrap_data(&body));
        // Participant + writer (owner 0xcc) + writer attributed to the sender.
        assert_eq!(parse_datagram(&d, "10.0.0.5").len(), 3);
    }

    #[test]
    fn crafted_string_length_is_rejected() {
        // A CDR string claiming 4 GB must not allocate or over-read.
        let mut value = Vec::new();
        value.extend_from_slice(&u32::MAX.to_le_bytes());
        value.extend_from_slice(b"abc\0");
        assert!(cdr_string(&value, true).is_none());
    }

    /// End to end: raw discovery bytes from a foreign participant announcing a
    /// `cmd_vel` writer -> the locked profile flags it Critical.
    #[test]
    fn foreign_cmd_vel_writer_on_the_wire_is_critical() {
        let mut profile = Profile {
            model: "ugv-v1".into(),
            locked: true,
            ..Default::default()
        };
        profile
            .participants
            .insert("aaaaaaaaaaaaaaaaaaaaaaaa".into());
        profile.writer_topics.insert("/cmd_vel".into());
        profile.motion_envelopes.insert(
            "/cmd_vel".into(),
            Envelope {
                max_linear_speed: Some(1.0),
                max_joint_speed: None,
                ..Default::default()
            },
        );

        let mut d = rtps_header([0xee; 12]);
        d.extend(sedp_data(
            ENTITY_SEDP_PUBLICATIONS_WRITER,
            "rt/cmd_vel",
            "geometry_msgs::msg::dds_::Twist_",
            guid(0xee),
        ));

        let deviations: Vec<_> = parse_datagram(&d, "10.0.0.66")
            .iter()
            .filter_map(|e| profile.evaluate(e))
            .collect();

        assert!(deviations
            .iter()
            .any(|d| d.rule == "robot.ros2.unauthorized_motion_writer"
                && d.severity == Severity::Critical));
        assert!(deviations
            .iter()
            .any(|d| d.rule == "robot.ros2.unknown_participant"));
    }
}
