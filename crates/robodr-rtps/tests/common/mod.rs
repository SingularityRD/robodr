//! Shared support for the `robodr-rtps` integration tests: the generator for
//! the SYNTHETIC RTPS fixtures in `tests/fixtures/`, plus the invariants every
//! `parse_datagram` output must satisfy (used by the mutation fuzz test and
//! mirrored in `fuzz/fuzz_targets/parse_datagram.rs`).
//!
//! # These are not captures
//!
//! Every fixture here is built by hand, byte by byte, from the OMG DDSI-RTPS
//! 2.3 specification (§8.3 message structure, §9.4 submessage encoding, §9.6
//! parameter ids) and from the field values Fast DDS 2.x and Cyclone DDS 0.10
//! put on the wire for ROS 2 Humble discovery. They are *protocol-faithful*,
//! not *vendor-exact*: vendor-specific parameters, exact parameter ordering
//! and padding quirks of a real stack may differ. Real Gazebo captures
//! (Sprint 1, E2) must replace or augment them; see `tests/fixtures/README.md`.
//!
//! # Layout conventions used below
//!
//! ```text
//! RTPS header (20 B):  "RTPS" | major minor | vendorId(2) | guidPrefix(12)
//! submessage:          id(1) | flags(1) | octetsToNextHeader(u16, E-endian) | body
//!   flags bit 0 (E) = 1 -> little-endian lengths and body
//! DATA body:           extraFlags(2) | octetsToInlineQos(u16)=16 | readerId(4)
//!                      | writerId(4) | writerSN(high i32, low u32)
//!                      | [inline QoS parameter list, if flag Q]
//!                      | encapsulation id (u16, ALWAYS big-endian) | options(2)
//!                      | parameter list (endianness named by encapsulation)
//! parameter:           pid(u16) | length(u16) | value padded to 4 bytes
//! CDR string:          u32 length incl. NUL | bytes | NUL | pad to 4
//! Locator_t (24 B):    kind(i32, 1 = UDPv4) | port(u32) | address(16, v4 in last 4)
//! ```

#![allow(dead_code)] // each integration test binary uses a different subset

use robodr_events::RobotEvent;

// ---- RTPS constants (DDSI-RTPS 2.3) ------------------------------------------

pub const SUBMSG_ACKNACK: u8 = 0x06;
pub const SUBMSG_HEARTBEAT: u8 = 0x07;
pub const SUBMSG_INFO_TS: u8 = 0x09;
pub const SUBMSG_INFO_DST: u8 = 0x0e;
pub const SUBMSG_DATA: u8 = 0x15;

pub const FLAG_E: u8 = 0x01; // little-endian
pub const FLAG_Q: u8 = 0x02; // DATA: inline QoS present
pub const FLAG_D: u8 = 0x04; // DATA: serialized data present

// Builtin entity ids (octet arrays, no endianness).
pub const ENTITYID_UNKNOWN: [u8; 4] = [0x00, 0x00, 0x00, 0x00];
pub const ENTITYID_PARTICIPANT: [u8; 4] = [0x00, 0x00, 0x01, 0xc1];
pub const SPDP_WRITER: [u8; 4] = [0x00, 0x01, 0x00, 0xc2];
pub const SPDP_READER: [u8; 4] = [0x00, 0x01, 0x00, 0xc7];
pub const SEDP_PUB_WRITER: [u8; 4] = [0x00, 0x00, 0x03, 0xc2];
pub const SEDP_PUB_READER: [u8; 4] = [0x00, 0x00, 0x03, 0xc7];
pub const SEDP_SUB_WRITER: [u8; 4] = [0x00, 0x00, 0x04, 0xc2];
pub const SEDP_SUB_READER: [u8; 4] = [0x00, 0x00, 0x04, 0xc7];

// Parameter ids (§9.6.2.2 table 9.12, plus the vendor ids noted).
pub const PID_SENTINEL: u16 = 0x0001;
pub const PID_PARTICIPANT_LEASE_DURATION: u16 = 0x0002;
pub const PID_TOPIC_NAME: u16 = 0x0005;
pub const PID_TYPE_NAME: u16 = 0x0007;
pub const PID_DOMAIN_ID: u16 = 0x000f;
pub const PID_PROTOCOL_VERSION: u16 = 0x0015;
pub const PID_VENDORID: u16 = 0x0016;
pub const PID_RELIABILITY: u16 = 0x001a;
pub const PID_DURABILITY: u16 = 0x001d;
pub const PID_USER_DATA: u16 = 0x002c;
pub const PID_UNICAST_LOCATOR: u16 = 0x002f;
pub const PID_DEFAULT_UNICAST_LOCATOR: u16 = 0x0031;
pub const PID_METATRAFFIC_UNICAST_LOCATOR: u16 = 0x0032;
pub const PID_METATRAFFIC_MULTICAST_LOCATOR: u16 = 0x0033;
pub const PID_PARTICIPANT_GUID: u16 = 0x0050;
pub const PID_BUILTIN_ENDPOINT_SET: u16 = 0x0058;
pub const PID_ENDPOINT_GUID: u16 = 0x005a;
pub const PID_ENTITY_NAME: u16 = 0x0062;
pub const PID_KEY_HASH: u16 = 0x0070;
/// Cyclone DDS vendor-specific (`PID_ADLINK_PARTICIPANT_VERSION_INFO`):
/// a parser must skip it, never choke on it.
pub const PID_CYCLONE_PARTICIPANT_VERSION_INFO: u16 = 0x8007;

pub const PL_CDR_BE: u16 = 0x0002;
pub const PL_CDR_LE: u16 = 0x0003;

/// `BUILTIN_ENDPOINT_SET`: participant announcer/detector, publications and
/// subscriptions announcer/detector, participant message writer/reader
/// (bits 0-5, 10, 11) = 0x0000_0c3f.
pub const BUILTIN_ENDPOINTS: u32 = 0x0000_0c3f;

/// `INFO_TS` timestamp used everywhere: 2025-10-16T07:33:20Z, fraction 0.
pub const TS_SECONDS: u32 = 1_760_600_000;

// ---- The participants that appear in the fixtures ----------------------------

/// Fast DDS 2.x style prefix: vendor(01 0f) | host id(3a 7c) | pid(21 04 00 00)
/// | participant id (01 00 00 00).
pub const FASTDDS_PREFIX: [u8; 12] = [
    0x01, 0x0f, 0x3a, 0x7c, 0x21, 0x04, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00,
];
/// A second Fast DDS participant on the same host (a service client).
pub const FASTDDS_CLIENT_PREFIX: [u8; 12] = [
    0x01, 0x0f, 0x3a, 0x7c, 0x55, 0x09, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00,
];
/// Cyclone DDS style prefix: vendor(01 10) followed by 10 pseudo-random bytes.
pub const CYCLONE_PREFIX: [u8; 12] = [
    0x01, 0x10, 0x5e, 0x2b, 0x9c, 0x41, 0xa7, 0xd3, 0x8e, 0x6f, 0x1c, 0x22,
];
/// RTI Connext style prefix (vendor 01 01) used for the big-endian fixture.
pub const CONNEXT_PREFIX: [u8; 12] = [
    0x01, 0x01, 0xc0, 0xa8, 0x0a, 0x17, 0x00, 0x00, 0x2a, 0x11, 0x00, 0x01,
];

pub const VENDOR_FASTDDS: [u8; 2] = [0x01, 0x0f];
pub const VENDOR_CYCLONE: [u8; 2] = [0x01, 0x10];
pub const VENDOR_CONNEXT: [u8; 2] = [0x01, 0x01];

// ---- Low-level writer --------------------------------------------------------

/// An append-only byte writer with a fixed endianness.
pub struct W {
    pub buf: Vec<u8>,
    pub le: bool,
}

impl W {
    pub fn new(le: bool) -> Self {
        Self {
            buf: Vec::new(),
            le,
        }
    }
    pub fn u16(&mut self, v: u16) -> &mut Self {
        let b = if self.le {
            v.to_le_bytes()
        } else {
            v.to_be_bytes()
        };
        self.buf.extend_from_slice(&b);
        self
    }
    pub fn u32(&mut self, v: u32) -> &mut Self {
        let b = if self.le {
            v.to_le_bytes()
        } else {
            v.to_be_bytes()
        };
        self.buf.extend_from_slice(&b);
        self
    }
    pub fn i32(&mut self, v: i32) -> &mut Self {
        self.u32(v as u32)
    }
    pub fn bytes(&mut self, b: &[u8]) -> &mut Self {
        self.buf.extend_from_slice(b);
        self
    }
    pub fn pad4(&mut self) -> &mut Self {
        while !self.buf.len().is_multiple_of(4) {
            self.buf.push(0);
        }
        self
    }
    pub fn take(&mut self) -> Vec<u8> {
        std::mem::take(&mut self.buf)
    }
}

// ---- Parameter values --------------------------------------------------------

/// CDR string value: u32 length including the NUL, bytes, NUL, pad to 4.
pub fn v_string(s: &str, le: bool) -> Vec<u8> {
    let mut w = W::new(le);
    w.u32(s.len() as u32 + 1)
        .bytes(s.as_bytes())
        .bytes(&[0])
        .pad4();
    w.take()
}

/// CDR `sequence<octet>` value (USER_DATA): u32 length, bytes, pad to 4.
pub fn v_octets(b: &[u8], le: bool) -> Vec<u8> {
    let mut w = W::new(le);
    w.u32(b.len() as u32).bytes(b).pad4();
    w.take()
}

pub fn v_u32(v: u32, le: bool) -> Vec<u8> {
    let mut w = W::new(le);
    w.u32(v);
    w.take()
}

/// `Locator_t` for UDPv4: kind 1, port, 12 zero bytes, then the IPv4 octets.
pub fn v_locator_udpv4(ip: [u8; 4], port: u32, le: bool) -> Vec<u8> {
    let mut w = W::new(le);
    w.i32(1).u32(port).bytes(&[0; 12]).bytes(&ip);
    w.take()
}

/// `Duration_t`: seconds (i32) then fraction (u32, 2^-32 s).
pub fn v_duration(seconds: i32, fraction: u32, le: bool) -> Vec<u8> {
    let mut w = W::new(le);
    w.i32(seconds).u32(fraction);
    w.take()
}

/// A 16-byte GUID: prefix + entity id.
pub fn guid(prefix: [u8; 12], entity: [u8; 4]) -> Vec<u8> {
    let mut g = prefix.to_vec();
    g.extend_from_slice(&entity);
    g
}

/// A parameter list: each `(pid, value)` with the value padded to 4 bytes and
/// its padded length in the header, then `PID_SENTINEL` with length 0.
pub fn param_list(params: &[(u16, Vec<u8>)], le: bool) -> Vec<u8> {
    let mut w = W::new(le);
    for (pid, value) in params {
        let mut v = value.clone();
        while !v.len().is_multiple_of(4) {
            v.push(0);
        }
        w.u16(*pid).u16(v.len() as u16).bytes(&v);
    }
    w.u16(PID_SENTINEL).u16(0);
    w.take()
}

// ---- Message and submessage builders -----------------------------------------

/// RTPS header: "RTPS", protocol version 2.3, vendor id, GUID prefix.
pub fn header(vendor: [u8; 2], prefix: [u8; 12]) -> Vec<u8> {
    let mut h = b"RTPS".to_vec();
    h.extend_from_slice(&[2, 3]);
    h.extend_from_slice(&vendor);
    h.extend_from_slice(&prefix);
    h
}

/// A submessage: id, flags, octetsToNextHeader (endianness from flag E), body.
pub fn submsg(id: u8, flags: u8, body: &[u8]) -> Vec<u8> {
    let mut w = W::new(flags & FLAG_E != 0);
    w.bytes(&[id, flags]).u16(body.len() as u16).bytes(body);
    w.take()
}

/// INFO_TS (0x09): seconds (u32) + fraction (u32).
pub fn info_ts(le: bool) -> Vec<u8> {
    let mut w = W::new(le);
    w.u32(TS_SECONDS).u32(0);
    submsg(SUBMSG_INFO_TS, if le { FLAG_E } else { 0 }, &w.take())
}

/// INFO_DST (0x0e): 12-byte destination GUID prefix.
pub fn info_dst(dest: [u8; 12], le: bool) -> Vec<u8> {
    submsg(SUBMSG_INFO_DST, if le { FLAG_E } else { 0 }, &dest)
}

/// A DATA submessage.
///
/// * `le`: endianness of the submessage header/body (flag E).
/// * `inline_qos`: optional parameter list (sets flag Q), written in `le`.
/// * `pl_le`: endianness of the serialized parameter list; the encapsulation
///   id (`PL_CDR_LE` 00 03 / `PL_CDR_BE` 00 02) is always written big-endian.
pub fn data(
    le: bool,
    reader: [u8; 4],
    writer: [u8; 4],
    sn: u32,
    inline_qos: Option<&[(u16, Vec<u8>)]>,
    pl_le: bool,
    params: &[(u16, Vec<u8>)],
) -> Vec<u8> {
    let mut w = W::new(le);
    w.u16(0) // extraFlags
        .u16(16) // octetsToInlineQos: readerId + writerId + writerSN
        .bytes(&reader)
        .bytes(&writer)
        .i32(0) // writerSN.high
        .u32(sn); // writerSN.low
    let mut flags = FLAG_D | if le { FLAG_E } else { 0 };
    if let Some(q) = inline_qos {
        flags |= FLAG_Q;
        w.bytes(&param_list(q, le));
    }
    let encap = if pl_le { PL_CDR_LE } else { PL_CDR_BE };
    w.bytes(&encap.to_be_bytes()).bytes(&[0, 0]);
    w.bytes(&param_list(params, pl_le));
    submsg(SUBMSG_DATA, flags, &w.take())
}

/// SPDP participant parameters common to both vendors' announcements.
fn spdp_params(
    vendor: [u8; 2],
    prefix: [u8; 12],
    ip: [u8; 4],
    port_base: u32,
) -> Vec<(u16, Vec<u8>)> {
    vec![
        (PID_PROTOCOL_VERSION, vec![2, 3, 0, 0]),
        (PID_VENDORID, vec![vendor[0], vendor[1], 0, 0]),
        (PID_PARTICIPANT_GUID, guid(prefix, ENTITYID_PARTICIPANT)),
        (
            PID_METATRAFFIC_UNICAST_LOCATOR,
            v_locator_udpv4(ip, port_base + 10, true),
        ),
        (
            PID_METATRAFFIC_MULTICAST_LOCATOR,
            v_locator_udpv4([239, 255, 0, 1], port_base, true),
        ),
        (
            PID_DEFAULT_UNICAST_LOCATOR,
            v_locator_udpv4(ip, port_base + 11, true),
        ),
        (PID_PARTICIPANT_LEASE_DURATION, v_duration(20, 0, true)),
        (PID_BUILTIN_ENDPOINT_SET, v_u32(BUILTIN_ENDPOINTS, true)),
        // ROS 2 Humble puts the security enclave in USER_DATA.
        (PID_USER_DATA, v_octets(b"enclave=/;", true)),
    ]
}

/// Endpoint (SEDP) parameters in the order Fast DDS emits the important ones.
fn sedp_params(
    owner: [u8; 12],
    endpoint_entity: [u8; 4],
    topic: &str,
    type_name: &str,
    ip: [u8; 4],
    pl_le: bool,
) -> Vec<(u16, Vec<u8>)> {
    let mut reliability = W::new(pl_le);
    // kind = RELIABLE (wire value 2), max_blocking_time = 0 s + 0.1 s.
    reliability.u32(2).i32(0).u32(0x1999_999a);
    vec![
        (PID_ENDPOINT_GUID, guid(owner, endpoint_entity)),
        (PID_PARTICIPANT_GUID, guid(owner, ENTITYID_PARTICIPANT)),
        (PID_TOPIC_NAME, v_string(topic, pl_le)),
        (PID_TYPE_NAME, v_string(type_name, pl_le)),
        (PID_RELIABILITY, reliability.take()),
        (PID_DURABILITY, v_u32(0, pl_le)), // VOLATILE
        (PID_UNICAST_LOCATOR, v_locator_udpv4(ip, 7411, pl_le)),
    ]
}

// ---- The fixtures ------------------------------------------------------------

/// One synthetic fixture: file stem, one-line description, the bytes.
pub struct Fixture {
    pub name: &'static str,
    pub description: &'static str,
    pub bytes: Vec<u8>,
}

/// Source address passed to the parser for every fixture.
pub const SRC_IP: &str = "192.168.10.21";

pub fn fastdds_spdp_participant() -> Vec<u8> {
    let mut d = header(VENDOR_FASTDDS, FASTDDS_PREFIX);
    d.extend(info_ts(true));
    d.extend(data(
        true,
        SPDP_READER,
        SPDP_WRITER,
        1,
        None,
        true,
        &spdp_params(VENDOR_FASTDDS, FASTDDS_PREFIX, [192, 168, 10, 21], 7400),
    ));
    d
}

pub fn cyclonedds_spdp_participant() -> Vec<u8> {
    let mut params = vec![(PID_DOMAIN_ID, v_u32(0, true))];
    params.extend(spdp_params(
        VENDOR_CYCLONE,
        CYCLONE_PREFIX,
        [192, 168, 10, 22],
        7400,
    ));
    params.push((PID_ENTITY_NAME, v_string("", true)));
    // Vendor-specific version info: version, flags, 2 x unused, then a string.
    let mut info = W::new(true);
    info.u32(0).u32(0x0000_0007).u32(0).u32(0);
    info.bytes(&v_string("robot-host/0.10.5/Linux/Linux", true));
    params.push((PID_CYCLONE_PARTICIPANT_VERSION_INFO, info.take()));

    let mut d = header(VENDOR_CYCLONE, CYCLONE_PREFIX);
    d.extend(info_ts(true));
    d.extend(data(
        true,
        ENTITYID_UNKNOWN,
        SPDP_WRITER,
        1,
        None,
        true,
        &params,
    ));
    d
}

pub fn sedp_pub_cmd_vel() -> Vec<u8> {
    let mut d = header(VENDOR_FASTDDS, FASTDDS_PREFIX);
    d.extend(info_dst(CYCLONE_PREFIX, true));
    d.extend(info_ts(true));
    d.extend(data(
        true,
        SEDP_PUB_READER,
        SEDP_PUB_WRITER,
        3,
        None,
        true,
        &sedp_params(
            FASTDDS_PREFIX,
            [0x00, 0x00, 0x12, 0x03], // user writer, no key
            "rt/cmd_vel",
            "geometry_msgs::msg::dds_::Twist_",
            [192, 168, 10, 21],
            true,
        ),
    ));
    d
}

pub fn sedp_sub_odom() -> Vec<u8> {
    let endpoint = [0x00, 0x00, 0x13, 0x04]; // user reader, no key
    let mut d = header(VENDOR_CYCLONE, CYCLONE_PREFIX);
    d.extend(info_dst(FASTDDS_PREFIX, true));
    d.extend(info_ts(true));
    d.extend(data(
        true,
        SEDP_SUB_READER,
        SEDP_SUB_WRITER,
        2,
        // Inline QoS carrying the key hash (the endpoint GUID): flag Q set.
        Some(&[(PID_KEY_HASH, guid(CYCLONE_PREFIX, endpoint))]),
        true,
        &sedp_params(
            CYCLONE_PREFIX,
            endpoint,
            "rt/odom",
            "nav_msgs::msg::dds_::Odometry_",
            [192, 168, 10, 22],
            true,
        ),
    ));
    d
}

pub fn sedp_pub_service_request() -> Vec<u8> {
    let mut d = header(VENDOR_FASTDDS, FASTDDS_CLIENT_PREFIX);
    d.extend(info_ts(true));
    d.extend(data(
        true,
        SEDP_PUB_READER,
        SEDP_PUB_WRITER,
        1,
        None,
        true,
        &sedp_params(
            FASTDDS_CLIENT_PREFIX,
            [0x00, 0x00, 0x14, 0x03],
            "rq/add_two_intsRequest",
            "example_interfaces::srv::dds_::AddTwoInts_Request_",
            [192, 168, 10, 21],
            true,
        ),
    ));
    d
}

pub fn sedp_pub_action_feedback() -> Vec<u8> {
    // An action server announcing two writers in one datagram: feedback, then
    // the goal status array. Exercises multiple DATA submessages per datagram.
    let mut d = header(VENDOR_CYCLONE, CYCLONE_PREFIX);
    d.extend(info_ts(true));
    d.extend(data(
        true,
        SEDP_PUB_READER,
        SEDP_PUB_WRITER,
        4,
        None,
        true,
        &sedp_params(
            CYCLONE_PREFIX,
            [0x00, 0x00, 0x15, 0x03],
            "rt/fibonacci/_action/feedback",
            "action_tutorials_interfaces::action::dds_::Fibonacci_FeedbackMessage_",
            [192, 168, 10, 22],
            true,
        ),
    ));
    d.extend(data(
        true,
        SEDP_PUB_READER,
        SEDP_PUB_WRITER,
        5,
        None,
        true,
        &sedp_params(
            CYCLONE_PREFIX,
            [0x00, 0x00, 0x16, 0x03],
            "rt/fibonacci/_action/status",
            "action_msgs::msg::dds_::GoalStatusArray_",
            [192, 168, 10, 22],
            true,
        ),
    ));
    d
}

pub fn sedp_pub_big_endian() -> Vec<u8> {
    // Everything big-endian: flag E clear on every submessage, PL_CDR_BE.
    let mut d = header(VENDOR_CONNEXT, CONNEXT_PREFIX);
    d.extend(info_ts(false));
    d.extend(data(
        false,
        SEDP_PUB_READER,
        SEDP_PUB_WRITER,
        1,
        None,
        false,
        &sedp_params(
            CONNEXT_PREFIX,
            [0x80, 0x00, 0x00, 0x02], // vendor-chosen writer key, no key kind
            "rt/scan",
            "sensor_msgs::msg::dds_::LaserScan_",
            [192, 168, 10, 23],
            false,
        ),
    ));
    d
}

pub fn heartbeat_acknack_only() -> Vec<u8> {
    let mut d = header(VENDOR_FASTDDS, FASTDDS_PREFIX);
    d.extend(info_dst(CYCLONE_PREFIX, true));
    // ACKNACK, flags E|F(0x02 final): readerId, writerId, readerSNState
    // (bitmapBase = 4, numBits = 0, no bitmap words), count = 2.
    let mut w = W::new(true);
    w.bytes(&SEDP_PUB_READER)
        .bytes(&SEDP_PUB_WRITER)
        .i32(0)
        .u32(4)
        .u32(0)
        .u32(2);
    d.extend(submsg(SUBMSG_ACKNACK, FLAG_E | 0x02, &w.take()));
    // HEARTBEAT: readerId, writerId, firstSN = 1, lastSN = 3, count = 5.
    w.bytes(&SEDP_PUB_READER)
        .bytes(&SEDP_PUB_WRITER)
        .i32(0)
        .u32(1)
        .i32(0)
        .u32(3)
        .u32(5);
    d.extend(submsg(SUBMSG_HEARTBEAT, FLAG_E, &w.take()));
    d
}

/// Every synthetic fixture, in a stable order.
pub fn all() -> Vec<Fixture> {
    vec![
        Fixture {
            name: "fastdds_spdp_participant",
            description: "Fast DDS SPDP participant announcement (vendor 0x010f)",
            bytes: fastdds_spdp_participant(),
        },
        Fixture {
            name: "cyclonedds_spdp_participant",
            description: "Cyclone DDS SPDP participant announcement (vendor 0x0110)",
            bytes: cyclonedds_spdp_participant(),
        },
        Fixture {
            name: "sedp_pub_cmd_vel",
            description: "SEDP publication: rt/cmd_vel Twist writer (Fast DDS)",
            bytes: sedp_pub_cmd_vel(),
        },
        Fixture {
            name: "sedp_sub_odom",
            description: "SEDP subscription: rt/odom reader, inline QoS (Cyclone)",
            bytes: sedp_sub_odom(),
        },
        Fixture {
            name: "sedp_pub_service_request",
            description: "SEDP publication: rq/add_two_intsRequest service request writer",
            bytes: sedp_pub_service_request(),
        },
        Fixture {
            name: "sedp_pub_action_feedback",
            description: "SEDP publications: action feedback + status writers in one datagram",
            bytes: sedp_pub_action_feedback(),
        },
        Fixture {
            name: "sedp_pub_big_endian",
            description: "Big-endian SEDP publication rt/scan (vendor 0x0101, PL_CDR_BE)",
            bytes: sedp_pub_big_endian(),
        },
        Fixture {
            name: "heartbeat_acknack_only",
            description: "INFO_DST + ACKNACK + HEARTBEAT, no DATA",
            bytes: heartbeat_acknack_only(),
        },
    ]
}

/// Absolute path of `tests/fixtures/`.
pub fn fixtures_dir() -> std::path::PathBuf {
    std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures")
}

/// Absolute path of the cargo-fuzz seed corpus (`<repo>/fuzz/corpus/parse_datagram`).
pub fn fuzz_corpus_dir() -> std::path::PathBuf {
    std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../fuzz/corpus/parse_datagram")
}

/// Set to `1` to rewrite fixture `.bin`, golden `.json` and fuzz seed files
/// from the generator instead of comparing against them.
pub fn bless() -> bool {
    std::env::var("ROBODR_BLESS")
        .map(|v| v == "1")
        .unwrap_or(false)
}

// ---- Output invariants -------------------------------------------------------

/// Smallest submessage that can yield an endpoint event: 4-byte submessage
/// header + 20-byte DATA body minimum.
pub const MIN_EVENT_SUBMSG: usize = 24;

/// Upper bound on how many events one datagram may produce: the header's
/// participant, plus at most one per minimal DATA submessage.
pub fn max_events(len: usize) -> usize {
    if len < 20 {
        0
    } else {
        1 + (len - 20) / MIN_EVENT_SUBMSG
    }
}

fn is_guid_hex(s: &str) -> bool {
    s.len() == 24 && s.bytes().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f'))
}

/// Check every invariant `parse_datagram` promises on arbitrary input.
/// Returns a description of the first violation.
pub fn check_invariants(
    datagram: &[u8],
    src_ip: &str,
    events: &[RobotEvent],
) -> Result<(), String> {
    let rtps = datagram.len() >= 20 && &datagram[..4] == b"RTPS";
    if !rtps && !events.is_empty() {
        return Err(format!("{} events from a non-RTPS datagram", events.len()));
    }
    if events.len() > max_events(datagram.len()) {
        return Err(format!(
            "{} events from {} bytes (bound {})",
            events.len(),
            datagram.len(),
            max_events(datagram.len())
        ));
    }
    for e in events {
        match e {
            RobotEvent::Ros2ParticipantDiscovered(p) => {
                if !is_guid_hex(&p.guid_prefix) {
                    return Err(format!("bad participant guid {:?}", p.guid_prefix));
                }
                if p.src_ip != src_ip {
                    return Err(format!("src_ip not echoed: {:?}", p.src_ip));
                }
            }
            RobotEvent::Ros2WriterDiscovered(ep) | RobotEvent::Ros2ReaderDiscovered(ep) => {
                if !is_guid_hex(&ep.guid_prefix) {
                    return Err(format!("bad endpoint guid {:?}", ep.guid_prefix));
                }
                // Strings are copied out of the datagram, so they can never be
                // longer than it (String guarantees valid UTF-8 already; the
                // explicit check documents the contract).
                for (what, s) in [("topic", &ep.topic), ("type", &ep.type_name)] {
                    if std::str::from_utf8(s.as_bytes()).is_err() {
                        return Err(format!("{what} not UTF-8"));
                    }
                    if s.len() >= datagram.len() {
                        return Err(format!("{what} of {} bytes exceeds datagram", s.len()));
                    }
                }
            }
            RobotEvent::MotionCommand(_) | RobotEvent::MotionFeedback(_) => {
                return Err("discovery parser emitted a motion event".into());
            }
        }
    }
    Ok(())
}

/// `(kind, guid_prefix, topic)` — the stable projection of an event that the
/// regression and golden tests compare. Deliberately excludes locators,
/// src_ip and anything else the parser may legitimately start filling in.
pub fn key(e: &RobotEvent) -> (&'static str, String, Option<String>) {
    match e {
        RobotEvent::Ros2ParticipantDiscovered(p) => ("participant", p.guid_prefix.clone(), None),
        RobotEvent::Ros2WriterDiscovered(ep) => {
            ("writer", ep.guid_prefix.clone(), Some(ep.topic.clone()))
        }
        RobotEvent::Ros2ReaderDiscovered(ep) => {
            ("reader", ep.guid_prefix.clone(), Some(ep.topic.clone()))
        }
        RobotEvent::MotionCommand(m) => ("motion", String::new(), Some(m.channel.clone())),
        RobotEvent::MotionFeedback(f) => ("feedback", String::new(), Some(f.channel.clone())),
    }
}

pub fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}
