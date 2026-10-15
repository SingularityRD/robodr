//! A minimal, read-only RTPS discovery parser (SPDP + SEDP).
//!
//! DDS participants announce themselves with SPDP (Simple Participant Discovery
//! Protocol), and announce each of their writers and readers with SEDP (Simple
//! Endpoint Discovery Protocol). Both ride in RTPS datagrams. RoboDR only
//! *reads* this traffic; it never writes to the bus.
//!
//! What we extract:
//! - From the RTPS header: the sender's 12-byte GUID prefix
//!   -> `Ros2ParticipantDiscovered`.
//! - From SEDP DATA submessages sent by the builtin publications writer
//!   (entity `0x000003c2`) and subscriptions writer (`0x000004c2`): topic name,
//!   type name and endpoint GUID -> `Ros2WriterDiscovered` /
//!   `Ros2ReaderDiscovered`.
//!
//! Everything else in the datagram (INFO_TS, INFO_DST, HEARTBEAT, ACKNACK,
//! user data) is skipped. The parser is defensive: every length is checked
//! against the remaining buffer, so a truncated or crafted packet yields fewer
//! events, never a panic or an out-of-bounds read.
//!
//! Reference: OMG DDSI-RTPS 2.2, §8.3 (structure), §8.5 (discovery), §9.4.5.3
//! (DATA submessage), §9.6.2 (parameter IDs).

use robodr_events::graph::{Endpoint, Participant};
use robodr_events::RobotEvent;

/// RTPS datagrams begin with this magic.
const RTPS_MAGIC: &[u8; 4] = b"RTPS";
/// Header is magic(4) + version(2) + vendorId(2) + guidPrefix(12) = 20 bytes.
const RTPS_HEADER_LEN: usize = 20;
const GUID_PREFIX_LEN: usize = 12;

/// DATA submessage id.
const SUBMSG_DATA: u8 = 0x15;
/// Submessage flags (byte 1 of the submessage header).
const FLAG_E: u8 = 0x01; // endianness: 1 = little-endian
const FLAG_Q: u8 = 0x02; // inline QoS present
const FLAG_D: u8 = 0x04; // serialized data present

/// Builtin SEDP writer entity ids (EntityId is an octet array: no endianness).
const ENTITY_SEDP_PUBLICATIONS_WRITER: [u8; 4] = [0x00, 0x00, 0x03, 0xc2];
const ENTITY_SEDP_SUBSCRIPTIONS_WRITER: [u8; 4] = [0x00, 0x00, 0x04, 0xc2];

/// Parameter ids we read.
const PID_SENTINEL: u16 = 0x0001;
const PID_TOPIC_NAME: u16 = 0x0005;
const PID_TYPE_NAME: u16 = 0x0007;
const PID_ENDPOINT_GUID: u16 = 0x005a;

/// Serialized-payload encapsulation identifiers for parameter lists. The
/// identifier itself is always big-endian on the wire.
const PL_CDR_BE: u16 = 0x0002;
const PL_CDR_LE: u16 = 0x0003;

/// Lower-case hex of a 12-byte GUID prefix, no separators.
pub fn hex12(prefix: &[u8; GUID_PREFIX_LEN]) -> String {
    let mut s = String::with_capacity(GUID_PREFIX_LEN * 2);
    for b in prefix {
        s.push(char::from_digit((b >> 4) as u32, 16).unwrap());
        s.push(char::from_digit((b & 0x0f) as u32, 16).unwrap());
    }
    s
}

/// Pull the GUID prefix out of a well-formed RTPS header. `None` if the buffer
/// is too short or the magic is wrong (not RTPS, so not ours to read).
pub fn guid_prefix(datagram: &[u8]) -> Option<[u8; GUID_PREFIX_LEN]> {
    if datagram.len() < RTPS_HEADER_LEN || &datagram[0..4] != RTPS_MAGIC {
        return None;
    }
    let mut prefix = [0u8; GUID_PREFIX_LEN];
    prefix.copy_from_slice(&datagram[8..8 + GUID_PREFIX_LEN]);
    Some(prefix)
}

/// Parse one RTPS datagram into robot events: the sending participant, plus one
/// writer or reader event per SEDP endpoint announcement it carries.
pub fn parse_datagram(datagram: &[u8], src_ip: &str) -> Vec<RobotEvent> {
    let Some(prefix) = guid_prefix(datagram) else {
        return Vec::new();
    };
    let mut events = vec![RobotEvent::Ros2ParticipantDiscovered(Participant {
        guid_prefix: hex12(&prefix),
        src_ip: src_ip.to_string(),
        locators: Vec::new(),
    })];
    events.extend(walk_submessages(&datagram[RTPS_HEADER_LEN..], &prefix));
    events
}

/// Walk the RTPS submessages after the header. Each submessage is:
/// `submessageId(1) | flags(1) | octetsToNextHeader(2) | body`.
/// The flags' E bit sets the endianness of the length field and of the body.
fn walk_submessages(mut buf: &[u8], header_prefix: &[u8; GUID_PREFIX_LEN]) -> Vec<RobotEvent> {
    let mut events = Vec::new();
    while buf.len() >= 4 {
        let id = buf[0];
        let flags = buf[1];
        let le = flags & FLAG_E != 0;
        let len = read_u16(buf, 2, le).unwrap_or(0) as usize;
        // octetsToNextHeader == 0 means "to end of message" for the last one.
        let body_len = if len == 0 { buf.len() - 4 } else { len };
        if 4 + body_len > buf.len() {
            break; // truncated or crafted length: stop rather than over-read.
        }
        let body = &buf[4..4 + body_len];
        if id == SUBMSG_DATA {
            if let Some(event) = parse_sedp_data(body, flags, header_prefix) {
                events.push(event);
            }
        }
        buf = &buf[4 + body_len..];
    }
    events
}

/// Which side of the graph an SEDP announcement describes.
enum EndpointKind {
    Writer,
    Reader,
}

/// Parse a DATA submessage body. Returns an endpoint event only when the DATA
/// comes from a builtin SEDP writer and carries a topic name; anything else
/// (SPDP, user data, disposals, malformed input) is `None`.
///
/// Body layout: extraFlags(2) | octetsToInlineQos(2) | readerId(4) |
/// writerId(4) | writerSN(8) | [inlineQos] | [serializedPayload].
fn parse_sedp_data(
    body: &[u8],
    flags: u8,
    header_prefix: &[u8; GUID_PREFIX_LEN],
) -> Option<RobotEvent> {
    let le = flags & FLAG_E != 0;
    if body.len() < 20 || flags & FLAG_D == 0 {
        return None; // too short, or no data (e.g. a key-only disposal)
    }

    let mut writer_id = [0u8; 4];
    writer_id.copy_from_slice(&body[8..12]);
    let kind = match writer_id {
        ENTITY_SEDP_PUBLICATIONS_WRITER => EndpointKind::Writer,
        ENTITY_SEDP_SUBSCRIPTIONS_WRITER => EndpointKind::Reader,
        _ => return None,
    };

    // octetsToInlineQos counts from the end of its own field (body offset 4).
    let octets_to_inline_qos = read_u16(body, 2, le)? as usize;
    let mut pos = 4usize.checked_add(octets_to_inline_qos)?;
    if flags & FLAG_Q != 0 {
        pos = skip_parameter_list(body, pos, le)?;
    }

    // Serialized payload: encapsulation id (always BE) + options(2), then a
    // parameter list in the endianness the id names.
    let rep = read_u16(body, pos, false)?;
    let pl_le = match rep {
        PL_CDR_LE => true,
        PL_CDR_BE => false,
        _ => return None,
    };
    pos = pos.checked_add(4)?;

    let mut topic = None;
    let mut type_name = None;
    let mut endpoint_prefix = None;
    for (pid, value) in ParameterList::new(body, pos, pl_le) {
        match pid {
            PID_TOPIC_NAME => topic = cdr_string(value, pl_le),
            PID_TYPE_NAME => type_name = cdr_string(value, pl_le),
            PID_ENDPOINT_GUID if value.len() >= 16 => {
                let mut p = [0u8; GUID_PREFIX_LEN];
                p.copy_from_slice(&value[..GUID_PREFIX_LEN]);
                endpoint_prefix = Some(p);
            }
            _ => {}
        }
    }

    let endpoint = Endpoint {
        // Prefer the endpoint's own GUID; fall back to the sending participant.
        guid_prefix: hex12(endpoint_prefix.as_ref().unwrap_or(header_prefix)),
        topic: topic?,
        type_name: type_name.unwrap_or_default(),
    };
    Some(match kind {
        EndpointKind::Writer => RobotEvent::Ros2WriterDiscovered(endpoint),
        EndpointKind::Reader => RobotEvent::Ros2ReaderDiscovered(endpoint),
    })
}

/// Iterator over a parameter list: `(parameterId, value)` pairs until the
/// sentinel, the end of the buffer, or a length that does not fit.
struct ParameterList<'a> {
    buf: &'a [u8],
    pos: usize,
    le: bool,
    done: bool,
}

impl<'a> ParameterList<'a> {
    fn new(buf: &'a [u8], pos: usize, le: bool) -> Self {
        Self {
            buf,
            pos,
            le,
            done: false,
        }
    }
}

impl<'a> Iterator for ParameterList<'a> {
    type Item = (u16, &'a [u8]);

    fn next(&mut self) -> Option<Self::Item> {
        if self.done {
            return None;
        }
        let pid = read_u16(self.buf, self.pos, self.le);
        let plen = read_u16(self.buf, self.pos + 2, self.le);
        let (Some(pid), Some(plen)) = (pid, plen) else {
            self.done = true;
            return None;
        };
        if pid == PID_SENTINEL {
            self.done = true;
            return None;
        }
        let start = self.pos + 4;
        let end = start + plen as usize;
        if end > self.buf.len() {
            self.done = true; // length runs past the buffer: stop
            return None;
        }
        self.pos = end;
        Some((pid, &self.buf[start..end]))
    }
}

/// Skip an inline-QoS parameter list; returns the offset just past its sentinel.
fn skip_parameter_list(buf: &[u8], mut pos: usize, le: bool) -> Option<usize> {
    loop {
        let pid = read_u16(buf, pos, le)?;
        let plen = read_u16(buf, pos + 2, le)? as usize;
        pos = pos.checked_add(4)?;
        if pid == PID_SENTINEL {
            return Some(pos);
        }
        pos = pos.checked_add(plen)?;
        if pos > buf.len() {
            return None;
        }
    }
}

/// A CDR string: u32 length (including the trailing NUL), then the bytes.
fn cdr_string(value: &[u8], le: bool) -> Option<String> {
    let n = read_u32(value, 0, le)? as usize;
    let bytes = value.get(4..4usize.checked_add(n)?)?;
    let bytes = bytes.strip_suffix(&[0]).unwrap_or(bytes);
    String::from_utf8(bytes.to_vec()).ok()
}

fn read_u16(buf: &[u8], pos: usize, le: bool) -> Option<u16> {
    let b: [u8; 2] = buf.get(pos..pos.checked_add(2)?)?.try_into().ok()?;
    Some(if le {
        u16::from_le_bytes(b)
    } else {
        u16::from_be_bytes(b)
    })
}

fn read_u32(buf: &[u8], pos: usize, le: bool) -> Option<u32> {
    let b: [u8; 4] = buf.get(pos..pos.checked_add(4)?)?.try_into().ok()?;
    Some(if le {
        u32::from_le_bytes(b)
    } else {
        u32::from_be_bytes(b)
    })
}

#[cfg(test)]
mod tests {
    use super::*;
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
        while value.len() % 4 != 0 {
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
        assert_eq!(events.len(), 2);
        match &events[1] {
            RobotEvent::Ros2WriterDiscovered(e) => {
                assert_eq!(e.topic, "rt/cmd_vel");
                assert_eq!(e.ros_topic(), "/cmd_vel");
                assert_eq!(e.type_name, "geometry_msgs::msg::dds_::Twist_");
                // The endpoint GUID wins over the sender's header prefix.
                assert_eq!(e.guid_prefix, "cccccccccccccccccccccccc");
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
        assert_eq!(parse_datagram(&d, "10.0.0.5").len(), 2);
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
