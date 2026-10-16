//! Test-only builders: hand-built RTPS discovery datagrams (DDSI-RTPS 2.3
//! §8.3/§9.4/§9.6 layout, little-endian) wrapped into Ethernet/IPv4/UDP
//! frames and written to classic pcap with `robodr-capture`'s `PcapWriter`.
//! Nothing here touches the network.

#![allow(dead_code)]

use std::net::Ipv4Addr;
use std::path::{Path, PathBuf};
use std::time::Duration;

use robodr_capture::{synth, LinkType, PcapWriter};
use robodr_events::profile::{Envelope, Profile};

pub const ENTITY_SPDP_WRITER: [u8; 4] = [0x00, 0x01, 0x00, 0xc2];
pub const ENTITY_SEDP_PUB_WRITER: [u8; 4] = [0x00, 0x00, 0x03, 0xc2];
pub const TWIST: &str = "geometry_msgs::msg::dds_::Twist_";
pub const ODOM: &str = "nav_msgs::msg::dds_::Odometry_";

pub const LEGIT: [u8; 12] = [0xaa; 12];
pub const LEGIT_HEX: &str = "aaaaaaaaaaaaaaaaaaaaaaaa";
pub const ROGUE: [u8; 12] = [0xee; 12];
pub const ROGUE_HEX: &str = "eeeeeeeeeeeeeeeeeeeeeeee";
pub const ROBOT_IP: Ipv4Addr = Ipv4Addr::new(192, 168, 50, 10);
pub const ROGUE_IP: Ipv4Addr = Ipv4Addr::new(192, 168, 50, 66);
pub const SPDP_GROUP: Ipv4Addr = Ipv4Addr::new(239, 255, 0, 1);

pub fn header(prefix: [u8; 12]) -> Vec<u8> {
    let mut d = b"RTPS".to_vec();
    d.extend_from_slice(&[2, 3, 0x01, 0x0f]); // v2.3, eProsima
    d.extend_from_slice(&prefix);
    d
}

pub fn param(pid: u16, value: &[u8]) -> Vec<u8> {
    assert!(value.len().is_multiple_of(4));
    let mut p = pid.to_le_bytes().to_vec();
    p.extend_from_slice(&(value.len() as u16).to_le_bytes());
    p.extend_from_slice(value);
    p
}

pub fn string_param(pid: u16, s: &str) -> Vec<u8> {
    let mut v = ((s.len() + 1) as u32).to_le_bytes().to_vec();
    v.extend_from_slice(s.as_bytes());
    v.push(0);
    while !v.len().is_multiple_of(4) {
        v.push(0);
    }
    param(pid, &v)
}

pub fn guid(prefix: [u8; 12], entity: [u8; 4]) -> [u8; 16] {
    let mut g = [0u8; 16];
    g[..12].copy_from_slice(&prefix);
    g[12..].copy_from_slice(&entity);
    g
}

pub fn locator_v4(ip: Ipv4Addr, port: u32) -> Vec<u8> {
    let mut v = 1i32.to_le_bytes().to_vec(); // LOCATOR_KIND_UDPv4
    v.extend_from_slice(&port.to_le_bytes());
    v.extend_from_slice(&[0; 12]);
    v.extend_from_slice(&ip.octets());
    v
}

/// PL_CDR_LE serialized payload: encapsulation header + params + sentinel.
pub fn pl_payload(params: &[Vec<u8>]) -> Vec<u8> {
    let mut p = vec![0x00, 0x03, 0, 0];
    for x in params {
        p.extend_from_slice(x);
    }
    p.extend_from_slice(&[1, 0, 0, 0]);
    p
}

/// SPDP participant data payload.
pub fn spdp_payload(prefix: [u8; 12], ip: Ipv4Addr) -> Vec<u8> {
    pl_payload(&[
        param(0x0015, &[2, 3, 0, 0]),       // PROTOCOL_VERSION
        param(0x0016, &[0x01, 0x0f, 0, 0]), // VENDORID
        param(0x0050, &guid(prefix, [0, 0, 1, 0xc1])),
        param(0x0032, &locator_v4(ip, 7410)),
        param(0x0031, &locator_v4(ip, 7411)),
    ])
}

/// SEDP publication payload for an endpoint of `prefix`. `pad` adds a
/// vendor-specific parameter of about that many bytes.
pub fn sedp_payload(prefix: [u8; 12], topic: &str, type_name: &str, pad: usize) -> Vec<u8> {
    let mut params = vec![param(0x005a, &guid(prefix, [0, 0, 0x12, 0x03]))];
    if pad > 0 {
        params.push(param(0x8001, &vec![0x5a; pad.div_ceil(4) * 4]));
    }
    params.push(string_param(0x0005, topic));
    params.push(string_param(0x0007, type_name));
    pl_payload(&params)
}

/// One DATA submessage from `writer` carrying `payload`.
pub fn data(writer: [u8; 4], sn: u32, payload: &[u8]) -> Vec<u8> {
    let mut body = vec![0, 0];
    body.extend_from_slice(&16u16.to_le_bytes());
    body.extend_from_slice(&[0, 0, 0, 0]);
    body.extend_from_slice(&writer);
    body.extend_from_slice(&0u32.to_le_bytes());
    body.extend_from_slice(&sn.to_le_bytes());
    body.extend_from_slice(payload);
    let mut s = vec![0x15, 0x05]; // DATA, E|D
    s.extend_from_slice(&(body.len() as u16).to_le_bytes());
    s.extend_from_slice(&body);
    s
}

/// One DATA_FRAG submessage carrying one fragment.
pub fn data_frag(
    writer: [u8; 4],
    sn: u32,
    start: u32,
    frag_size: u16,
    sample_size: u32,
    frag: &[u8],
) -> Vec<u8> {
    let mut body = vec![0, 0];
    body.extend_from_slice(&28u16.to_le_bytes());
    body.extend_from_slice(&[0, 0, 0, 0]);
    body.extend_from_slice(&writer);
    body.extend_from_slice(&0u32.to_le_bytes());
    body.extend_from_slice(&sn.to_le_bytes());
    body.extend_from_slice(&start.to_le_bytes());
    body.extend_from_slice(&1u16.to_le_bytes());
    body.extend_from_slice(&frag_size.to_le_bytes());
    body.extend_from_slice(&sample_size.to_le_bytes());
    body.extend_from_slice(frag);
    while !body.len().is_multiple_of(4) {
        body.push(0);
    }
    let mut s = vec![0x16, 0x01]; // DATA_FRAG, E
    s.extend_from_slice(&(body.len() as u16).to_le_bytes());
    s.extend_from_slice(&body);
    s
}

/// A complete SPDP beacon datagram.
pub fn spdp_datagram(prefix: [u8; 12], ip: Ipv4Addr) -> Vec<u8> {
    let mut d = header(prefix);
    d.extend(data(ENTITY_SPDP_WRITER, 1, &spdp_payload(prefix, ip)));
    d
}

/// A complete SEDP publication datagram.
pub fn sedp_datagram(prefix: [u8; 12], topic: &str, type_name: &str) -> Vec<u8> {
    let mut d = header(prefix);
    d.extend(data(
        ENTITY_SEDP_PUB_WRITER,
        1,
        &sedp_payload(prefix, topic, type_name, 0),
    ));
    d
}

/// The SEDP publication split into DATA_FRAG datagrams of `frag_size` bytes
/// (one fragment per RTPS message, in order).
pub fn sedp_fragmented(
    prefix: [u8; 12],
    topic: &str,
    type_name: &str,
    pad: usize,
    frag_size: u16,
) -> Vec<Vec<u8>> {
    let payload = sedp_payload(prefix, topic, type_name, pad);
    payload
        .chunks(frag_size as usize)
        .enumerate()
        .map(|(i, chunk)| {
            let mut d = header(prefix);
            d.extend(data_frag(
                ENTITY_SEDP_PUB_WRITER,
                7,
                i as u32 + 1,
                frag_size,
                payload.len() as u32,
                chunk,
            ));
            d
        })
        .collect()
}

/// An Ethernet/IPv4/UDP frame.
pub fn frame(src: Ipv4Addr, dst: Ipv4Addr, dport: u16, payload: &[u8]) -> Vec<u8> {
    synth::ethernet(0x0800, &synth::ipv4_udp(src, dst, 49152, dport, payload))
}

/// A classic pcap (Ethernet) of `frames`, one second apart.
pub fn pcap(frames: &[Vec<u8>]) -> Vec<u8> {
    let mut w = PcapWriter::new(Vec::new(), LinkType::ETHERNET, 65535, false).unwrap();
    for (i, f) in frames.iter().enumerate() {
        w.write_packet(
            Duration::new(1_760_000_000 + i as u64, 0),
            f,
            f.len() as u32,
        )
        .unwrap();
    }
    w.into_inner()
}

/// The lab scenario: a legit participant + `rt/cmd_vel` and `rt/odom`
/// writers, non-RTPS noise, then a rogue participant beaconing SPDP
/// `beacons` times and announcing a `rt/cmd_vel` writer (unicast SEDP).
pub fn scenario_frames(beacons: usize) -> Vec<Vec<u8>> {
    let mut f = vec![
        frame(ROBOT_IP, SPDP_GROUP, 7400, &spdp_datagram(LEGIT, ROBOT_IP)),
        frame(
            ROBOT_IP,
            ROBOT_IP,
            7410,
            &sedp_datagram(LEGIT, "rt/cmd_vel", TWIST),
        ),
        frame(
            ROBOT_IP,
            ROBOT_IP,
            7410,
            &sedp_datagram(LEGIT, "rt/odom", ODOM),
        ),
        frame(ROBOT_IP, ROGUE_IP, 53, b"not rtps at all"),
    ];
    for _ in 0..beacons {
        f.push(frame(
            ROGUE_IP,
            SPDP_GROUP,
            7400,
            &spdp_datagram(ROGUE, ROGUE_IP),
        ));
    }
    f.push(frame(
        ROGUE_IP,
        ROBOT_IP,
        7410,
        &sedp_datagram(ROGUE, "rt/cmd_vel", TWIST),
    ));
    // The legit participant keeps beaconing too.
    f.push(frame(
        ROBOT_IP,
        SPDP_GROUP,
        7400,
        &spdp_datagram(LEGIT, ROBOT_IP),
    ));
    f
}

/// The robot's profile: the legit participant, `/cmd_vel` (with an envelope)
/// and `/odom`.
pub fn robot_profile(locked: bool) -> Profile {
    let mut p = Profile {
        model: "ugv-lab".into(),
        locked,
        ..Default::default()
    };
    p.participants.insert(LEGIT_HEX.into());
    p.writer_topics.insert("/cmd_vel".into());
    p.writer_topics.insert("/odom".into());
    p.motion_envelopes.insert(
        "/cmd_vel".into(),
        Envelope {
            max_linear_speed: Some(1.0),
            max_joint_speed: None,
            ..Default::default()
        },
    );
    p
}

/// A fresh, empty, per-test directory under the system temp dir.
pub fn temp_dir(tag: &str) -> PathBuf {
    let d = std::env::temp_dir().join(format!("robodr-pipeline-{tag}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&d);
    std::fs::create_dir_all(&d).unwrap();
    d
}

pub fn write(path: &Path, bytes: &[u8]) {
    std::fs::write(path, bytes).unwrap();
}

/// The synthetic RTPS fixtures of `robodr-rtps`.
pub fn rtps_fixtures_dir() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../robodr-rtps/tests/fixtures")
}

/// An INFO_SRC submessage (E flag): the following submessages are sent on
/// behalf of `prefix`.
pub fn info_src(prefix: [u8; 12]) -> Vec<u8> {
    let mut s = vec![0x0c, 0x01];
    s.extend_from_slice(&20u16.to_le_bytes());
    s.extend_from_slice(&[0; 4]); // unused
    s.extend_from_slice(&[2, 3, 0x01, 0x0f]); // version + vendor
    s.extend_from_slice(&prefix);
    s
}

/// SPDP payload for `prefix` advertising unicast locators on every `ips`.
pub fn spdp_payload_multi(prefix: [u8; 12], ips: &[Ipv4Addr]) -> Vec<u8> {
    let mut params = vec![
        param(0x0015, &[2, 3, 0, 0]),
        param(0x0016, &[0x01, 0x0f, 0, 0]),
        param(0x0050, &guid(prefix, [0, 0, 1, 0xc1])),
    ];
    for ip in ips {
        params.push(param(0x0032, &locator_v4(*ip, 7410)));
        params.push(param(0x0031, &locator_v4(*ip, 7411)));
    }
    pl_payload(&params)
}

/// An RTPS datagram from header prefix `sender` carrying `subs`.
pub fn datagram(sender: [u8; 12], subs: &[Vec<u8>]) -> Vec<u8> {
    let mut d = header(sender);
    for s in subs {
        d.extend_from_slice(s);
    }
    d
}

/// SPDP DATA submessage announcing `prefix` with locators on `ips`.
pub fn spdp_sub(prefix: [u8; 12], ips: &[Ipv4Addr]) -> Vec<u8> {
    data(ENTITY_SPDP_WRITER, 1, &spdp_payload_multi(prefix, ips))
}

/// SEDP publication DATA submessage for an endpoint of `owner`.
pub fn sedp_sub(owner: [u8; 12], topic: &str) -> Vec<u8> {
    data(
        ENTITY_SEDP_PUB_WRITER,
        1,
        &sedp_payload(owner, topic, TWIST, 0),
    )
}

/// SEDP publication whose `PID_PARTICIPANT_GUID` names `claimed`, while the
/// endpoint GUID names `owner` (a GUID conflict).
pub fn sedp_sub_conflict(owner: [u8; 12], claimed: [u8; 12], topic: &str) -> Vec<u8> {
    let payload = pl_payload(&[
        param(0x005a, &guid(owner, [0, 0, 0x12, 0x03])),
        param(0x0050, &guid(claimed, [0, 0, 1, 0xc1])),
        string_param(0x0005, topic),
        string_param(0x0007, TWIST),
    ]);
    data(ENTITY_SEDP_PUB_WRITER, 1, &payload)
}

/// SEDP publication dispose (inline KEY_HASH + STATUS_INFO, no payload) of
/// `owner`'s writer.
pub fn sedp_dispose_sub(owner: [u8; 12]) -> Vec<u8> {
    let mut body = vec![0, 0];
    body.extend_from_slice(&16u16.to_le_bytes());
    body.extend_from_slice(&[0, 0, 0, 0]);
    body.extend_from_slice(&ENTITY_SEDP_PUB_WRITER);
    body.extend_from_slice(&0u32.to_le_bytes());
    body.extend_from_slice(&2u32.to_le_bytes());
    body.extend_from_slice(&param(0x0070, &guid(owner, [0, 0, 0x12, 0x03])));
    body.extend_from_slice(&param(0x0071, &[0, 0, 0, 1])); // disposed
    body.extend_from_slice(&[1, 0, 0, 0]); // sentinel
    let mut s = vec![0x15, 0x03]; // DATA, E|Q
    s.extend_from_slice(&(body.len() as u16).to_le_bytes());
    s.extend_from_slice(&body);
    s
}

/// An RTPS header with an explicit protocol version.
pub fn header_v(prefix: [u8; 12], major: u8, minor: u8) -> Vec<u8> {
    let mut d = b"RTPS".to_vec();
    d.extend_from_slice(&[major, minor, 0x01, 0x0f]);
    d.extend_from_slice(&prefix);
    d
}

/// A PL_CDR_LE payload from already-encoded parameter bytes (no alignment
/// checks: for malformed-input tests).
pub fn pl_raw(params: &[u8]) -> Vec<u8> {
    let mut p = vec![0x00, 0x03, 0, 0];
    p.extend_from_slice(params);
    p.extend_from_slice(&[1, 0, 0, 0]);
    p
}

/// Writer entity id used for hand-built rogue endpoints.
pub const ROGUE_ENTITY: [u8; 4] = [0, 0, 0x77, 0x03];

// ------------------------------------------------- user DATA (motion path) --

/// Builtin SEDP subscriptions writer (announces DataReaders).
pub const ENTITY_SEDP_SUB_WRITER: [u8; 4] = [0x00, 0x00, 0x04, 0xc2];
/// User writer / reader entity ids of the hand-built motion endpoints.
pub const CMD_WRITER: [u8; 4] = [0, 0, 0x10, 0x03];
pub const ODOM_WRITER: [u8; 4] = [0, 0, 0x11, 0x03];
pub const CMD_READER: [u8; 4] = [0, 0, 0x10, 0x04];

/// SEDP payload announcing endpoint `prefix`+`entity` on `topic`.
pub fn sedp_endpoint_payload(
    prefix: [u8; 12],
    entity: [u8; 4],
    topic: &str,
    type_name: &str,
) -> Vec<u8> {
    pl_payload(&[
        param(0x005a, &guid(prefix, entity)),
        string_param(0x0005, topic),
        string_param(0x0007, type_name),
    ])
}

/// SEDP publication DATA submessage for writer `prefix`+`entity`.
pub fn sedp_writer_sub(prefix: [u8; 12], entity: [u8; 4], topic: &str, type_name: &str) -> Vec<u8> {
    data(
        ENTITY_SEDP_PUB_WRITER,
        1,
        &sedp_endpoint_payload(prefix, entity, topic, type_name),
    )
}

/// SEDP subscription DATA submessage for reader `prefix`+`entity`.
pub fn sedp_reader_sub(prefix: [u8; 12], entity: [u8; 4], topic: &str, type_name: &str) -> Vec<u8> {
    data(
        ENTITY_SEDP_SUB_WRITER,
        1,
        &sedp_endpoint_payload(prefix, entity, topic, type_name),
    )
}

/// A `geometry_msgs/Twist` serialized payload, CDR_LE (encapsulation
/// 0x0001) or CDR_BE (0x0000): linear (vx, 0, 0), angular (0, 0, wz).
pub fn twist_cdr(vx: f64, wz: f64, le: bool) -> Vec<u8> {
    let mut p = vec![0x00, if le { 0x01 } else { 0x00 }, 0, 0];
    for v in [vx, 0.0, 0.0, 0.0, 0.0, wz] {
        p.extend_from_slice(&if le { v.to_le_bytes() } else { v.to_be_bytes() });
    }
    p
}

/// A user DATA submessage (E flag = `le`) from `writer` to `reader`.
pub fn user_data(writer: [u8; 4], reader: [u8; 4], sn: u32, payload: &[u8], le: bool) -> Vec<u8> {
    let u16b = |v: u16| if le { v.to_le_bytes() } else { v.to_be_bytes() };
    let u32b = |v: u32| if le { v.to_le_bytes() } else { v.to_be_bytes() };
    let mut body = vec![0, 0];
    body.extend_from_slice(&u16b(16));
    body.extend_from_slice(&reader);
    body.extend_from_slice(&writer);
    body.extend_from_slice(&u32b(0));
    body.extend_from_slice(&u32b(sn));
    body.extend_from_slice(payload);
    let mut s = vec![0x15, if le { 0x05 } else { 0x04 }]; // DATA, (E|)D
    s.extend_from_slice(&u16b(body.len() as u16));
    s.extend_from_slice(&body);
    s
}

/// A user DATA_FRAG submessage carrying fragment `start` (1-based).
pub fn user_data_frag(
    writer: [u8; 4],
    sn: u32,
    start: u32,
    frag_size: u16,
    sample_size: u32,
    frag: &[u8],
) -> Vec<u8> {
    let mut body = vec![0, 0];
    body.extend_from_slice(&28u16.to_le_bytes());
    body.extend_from_slice(&CMD_READER);
    body.extend_from_slice(&writer);
    body.extend_from_slice(&0u32.to_le_bytes());
    body.extend_from_slice(&sn.to_le_bytes());
    body.extend_from_slice(&start.to_le_bytes());
    body.extend_from_slice(&1u16.to_le_bytes());
    body.extend_from_slice(&frag_size.to_le_bytes());
    body.extend_from_slice(&sample_size.to_le_bytes());
    body.extend_from_slice(frag);
    let mut s = vec![0x16, 0x01]; // DATA_FRAG, E
    s.extend_from_slice(&(body.len() as u16).to_le_bytes());
    s.extend_from_slice(&body);
    s
}

/// An INFO_TS submessage (little-endian).
pub fn info_ts(seconds: u32, fraction: u32) -> Vec<u8> {
    let mut s = vec![0x09, 0x01, 8, 0];
    s.extend_from_slice(&seconds.to_le_bytes());
    s.extend_from_slice(&fraction.to_le_bytes());
    s
}

/// The lab motion scenario's discovery: the legit participant's SPDP (from
/// the robot's IP) with a `rt/cmd_vel` writer, a `rt/odom` writer and a
/// `rt/cmd_vel` reader (the base controller).
pub fn motion_discovery() -> Vec<u8> {
    datagram(
        LEGIT,
        &[
            spdp_sub(LEGIT, &[ROBOT_IP]),
            sedp_writer_sub(LEGIT, CMD_WRITER, "rt/cmd_vel", TWIST),
            sedp_writer_sub(LEGIT, ODOM_WRITER, "rt/odom", ODOM),
            sedp_reader_sub(LEGIT, CMD_READER, "rt/cmd_vel", TWIST),
        ],
    )
}

/// A datagram from `prefix` carrying one Twist command from `writer`.
pub fn cmd_vel_datagram(prefix: [u8; 12], writer: [u8; 4], sn: u32, vx: f64) -> Vec<u8> {
    datagram(
        prefix,
        &[user_data(
            writer,
            CMD_READER,
            sn,
            &twist_cdr(vx, 0.1, true),
            true,
        )],
    )
}
