//! A minimal, read-only RTPS/SPDP parser.
//!
//! DDS participants announce themselves with SPDP (Simple Participant Discovery
//! Protocol) messages carried in RTPS datagrams on a well-known multicast
//! address. RoboDR only *reads* this traffic; it never writes to the bus.
//!
//! Scope of v1: we parse the RTPS header, which is fixed and well-defined, to
//! learn the sender's 12-byte GUID prefix — enough to detect "a participant
//! that is not in the profile joined the graph". Walking the submessages to
//! extract per-endpoint topic/type from DATA(w)/DATA(r) inline QoS is the next
//! step and is scaffolded (`walk_submessages`) with the parameter IDs it needs,
//! so topic-level detection drops in without reshaping this module.
//!
//! Reference: OMG DDSI-RTPS 2.2, §8.3 (structure) and §8.5 (discovery).

use robodr_events::graph::Participant;
use robodr_events::RobotEvent;

/// RTPS datagrams begin with this magic.
const RTPS_MAGIC: &[u8; 4] = b"RTPS";
/// Header is magic(4) + version(2) + vendorId(2) + guidPrefix(12) = 20 bytes.
const RTPS_HEADER_LEN: usize = 20;
const GUID_PREFIX_LEN: usize = 12;

/// Submessage kind for participant announcements is carried in DATA (0x15);
/// we keep the id so `walk_submessages` can select DATA submessages.
const SUBMSG_DATA: u8 = 0x15;

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

/// Parse one RTPS datagram into robot events. v1 yields the participant the
/// datagram came from; endpoint/topic events are added by `walk_submessages`
/// as that parser is completed.
pub fn parse_datagram(datagram: &[u8], src_ip: &str) -> Vec<RobotEvent> {
    let Some(prefix) = guid_prefix(datagram) else {
        return Vec::new();
    };
    let mut events = vec![RobotEvent::Ros2ParticipantDiscovered(Participant {
        guid_prefix: hex12(&prefix),
        src_ip: src_ip.to_string(),
        locators: Vec::new(),
    })];
    events.extend(walk_submessages(
        &datagram[RTPS_HEADER_LEN..],
        &prefix,
        src_ip,
    ));
    events
}

/// Walk the RTPS submessages after the header. Each submessage is:
/// `submessageId(1) | flags(1) | octetsToNextHeader(2) | payload`.
/// The flags' bit0 is endianness (1 = little-endian) for the length field.
///
/// v1 returns nothing: it establishes the correct, bounded walk over
/// submessages (so a malformed length can never read out of bounds) and marks
/// where DATA(w)/DATA(r) inline-QoS extraction of topic and type names plugs in
/// (PID_TOPIC_NAME = 0x0005, PID_TYPE_NAME = 0x0007, PID_ENDPOINT_GUID = 0x005a).
fn walk_submessages(
    mut buf: &[u8],
    _prefix: &[u8; GUID_PREFIX_LEN],
    _src_ip: &str,
) -> Vec<RobotEvent> {
    let events = Vec::new();
    while buf.len() >= 4 {
        let id = buf[0];
        let little_endian = buf[1] & 0x01 == 1;
        let len = if little_endian {
            u16::from_le_bytes([buf[2], buf[3]]) as usize
        } else {
            u16::from_be_bytes([buf[2], buf[3]]) as usize
        };
        // octetsToNextHeader == 0 means "to end of message" for the last one.
        let body_len = if len == 0 { buf.len() - 4 } else { len };
        if 4 + body_len > buf.len() {
            break; // truncated or crafted length: stop rather than over-read.
        }
        if id == SUBMSG_DATA {
            // TODO(topic-extraction): parse the DATA submessage's inline QoS
            // parameter list for PID_TOPIC_NAME / PID_TYPE_NAME / endpoint GUID
            // and push Ros2WriterDiscovered / Ros2ReaderDiscovered here.
        }
        buf = &buf[4 + body_len..];
    }
    events
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A 20-byte RTPS header: "RTPS" + version 2.2 + vendor 0x010f (eProsima) +
    /// a known 12-byte guid prefix, with no submessages.
    fn spdp_header(prefix: [u8; 12]) -> Vec<u8> {
        let mut d = Vec::new();
        d.extend_from_slice(b"RTPS");
        d.extend_from_slice(&[2, 2]); // protocol version
        d.extend_from_slice(&[0x01, 0x0f]); // vendor id
        d.extend_from_slice(&prefix);
        d
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
        let d = spdp_header(prefix);
        assert_eq!(guid_prefix(&d), Some(prefix));
        assert_eq!(hex12(&prefix), "0102030405060708090a0b0c");
    }

    #[test]
    fn parse_datagram_yields_participant() {
        let prefix = [0xaa; 12];
        let events = parse_datagram(&spdp_header(prefix), "10.0.0.5");
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
    fn submessage_walk_does_not_overread_on_crafted_length() {
        // header + one DATA submessage claiming a 0xffff body it does not have.
        let mut d = spdp_header([0xbb; 12]);
        d.extend_from_slice(&[SUBMSG_DATA, 0x01, 0xff, 0xff]); // LE len 65535
                                                               // Must not panic / must stop cleanly; still yields the participant.
        let events = parse_datagram(&d, "10.0.0.6");
        assert_eq!(events.len(), 1);
    }
}
