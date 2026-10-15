//! End to end: capture files containing an SEDP DATA announcing a writer on
//! `rt/cmd_vel` -> capture pipeline -> `robodr_rtps::parse_datagram` ->
//! `Ros2WriterDiscovered`.

use std::net::{Ipv4Addr, Ipv6Addr};
use std::time::Duration;

use robodr_capture::{
    pcap::PcapWriter, rtps_datagrams, synth, CaptureFile, LinkType, PortKind, RtpsDatagrams,
};
use robodr_events::RobotEvent;

const ENTITY_SEDP_PUBLICATIONS_WRITER: [u8; 4] = [0x00, 0x00, 0x03, 0xc2];

fn string_param(pid: u16, s: &str) -> Vec<u8> {
    let mut value = ((s.len() + 1) as u32).to_le_bytes().to_vec();
    value.extend_from_slice(s.as_bytes());
    value.push(0);
    while !value.len().is_multiple_of(4) {
        value.push(0);
    }
    let mut p = pid.to_le_bytes().to_vec();
    p.extend_from_slice(&(value.len() as u16).to_le_bytes());
    p.extend_from_slice(&value);
    p
}

/// A complete RTPS message: header from participant `prefix` + one
/// little-endian SEDP publication DATA for `topic`. `pad` adds a vendor
/// parameter of that many bytes (to force IP fragmentation).
fn sedp_writer_datagram(prefix: [u8; 12], topic: &str, type_name: &str, pad: usize) -> Vec<u8> {
    let mut body = Vec::new();
    body.extend_from_slice(&[0, 0]); // extraFlags
    body.extend_from_slice(&16u16.to_le_bytes()); // octetsToInlineQos
    body.extend_from_slice(&[0, 0, 0, 0]); // readerId
    body.extend_from_slice(&ENTITY_SEDP_PUBLICATIONS_WRITER); // writerId
    body.extend_from_slice(&0i32.to_le_bytes());
    body.extend_from_slice(&1u32.to_le_bytes());
    body.extend_from_slice(&0x0003u16.to_be_bytes()); // PL_CDR_LE
    body.extend_from_slice(&[0, 0]);
    let mut guid = [0xcc; 16];
    guid[12..].copy_from_slice(&[0, 0, 0x01, 0x03]);
    body.extend_from_slice(&0x005au16.to_le_bytes()); // PID_ENDPOINT_GUID
    body.extend_from_slice(&16u16.to_le_bytes());
    body.extend_from_slice(&guid);
    if pad > 0 {
        let pad = pad.div_ceil(4) * 4;
        body.extend_from_slice(&0x8001u16.to_le_bytes()); // vendor-specific PID
        body.extend_from_slice(&(pad as u16).to_le_bytes());
        body.extend(std::iter::repeat_n(0x5a, pad));
    }
    body.extend_from_slice(&string_param(0x0005, topic)); // PID_TOPIC_NAME
    body.extend_from_slice(&string_param(0x0007, type_name)); // PID_TYPE_NAME
    body.extend_from_slice(&0x0001u16.to_le_bytes()); // PID_SENTINEL
    body.extend_from_slice(&0u16.to_le_bytes());

    let mut d = b"RTPS".to_vec();
    d.extend_from_slice(&[2, 3, 0x01, 0x0f]); // version 2.3, vendor eProsima
    d.extend_from_slice(&prefix);
    d.extend_from_slice(&[0x15, 0x05]); // DATA, flags E|D
    d.extend_from_slice(&(body.len() as u16).to_le_bytes());
    d.extend_from_slice(&body);
    d
}

const ATTACKER: Ipv4Addr = Ipv4Addr::new(192, 168, 50, 66);
const ROBOT: Ipv4Addr = Ipv4Addr::new(192, 168, 50, 10);
const TWIST: &str = "geometry_msgs::msg::dds_::Twist_";

/// Run the whole pipeline and return every event the parser produced.
fn events_from<S: robodr_capture::PacketSource>(
    it: &mut RtpsDatagrams<S>,
) -> Vec<(String, RobotEvent)> {
    let mut out = Vec::new();
    for (ip, payload) in it.by_ref() {
        for ev in robodr_rtps::parse_datagram(&payload, &ip) {
            out.push((ip.clone(), ev));
        }
    }
    out
}

fn assert_cmd_vel_writer(events: &[(String, RobotEvent)], src: &str) {
    let writer = events.iter().find_map(|(ip, e)| match e {
        RobotEvent::Ros2WriterDiscovered(ep) => Some((ip, ep)),
        _ => None,
    });
    let (ip, ep) = writer.expect("Ros2WriterDiscovered emitted");
    assert_eq!(ip, src);
    assert_eq!(ep.topic, "rt/cmd_vel");
    assert_eq!(ep.ros_topic(), "/cmd_vel");
    assert_eq!(ep.type_name, TWIST);
    assert_eq!(ep.guid_prefix, "cccccccccccccccccccccccc");
    assert!(events.iter().any(|(_, e)| matches!(
        e,
        RobotEvent::Ros2ParticipantDiscovered(p) if p.src_ip == src && p.guid_prefix == "eeeeeeeeeeeeeeeeeeeeeeee"
    )));
}

#[test]
fn classic_pcap_ethernet_sedp_yields_cmd_vel_writer() {
    let sedp = sedp_writer_datagram([0xee; 12], "rt/cmd_vel", TWIST, 0);
    // Unicast to the robot's participant-1 metatraffic port (7412).
    let frame = synth::ethernet(
        0x0800,
        &synth::ipv4_udp(ATTACKER, ROBOT, 49152, 7412, &sedp),
    );
    let noise = synth::ethernet(0x0800, &synth::ipv4_udp(ROBOT, ATTACKER, 53, 53, b"dns"));

    let mut w = PcapWriter::new(Vec::new(), LinkType::ETHERNET, 65535, false).unwrap();
    w.write_packet(Duration::new(1_760_000_000, 0), &noise, noise.len() as u32)
        .unwrap();
    w.write_packet(Duration::new(1_760_000_001, 0), &frame, frame.len() as u32)
        .unwrap();
    let file = w.into_inner();

    let mut it = rtps_datagrams(CaptureFile::new(&file[..]).unwrap());
    let events = events_from(&mut it);
    assert_cmd_vel_writer(&events, "192.168.50.66");
    assert_eq!(it.stats().rtps, 1);
    assert_eq!(it.stats().filtered_out, 1);
    assert!(it.is_finished() && it.last_error().is_none());
}

#[test]
fn classic_pcap_reports_port_class() {
    let sedp = sedp_writer_datagram([0xee; 12], "rt/cmd_vel", TWIST, 0);
    let frame = synth::ipv4_udp(ATTACKER, ROBOT, 49152, 7412, &sedp);
    let mut w = PcapWriter::new(Vec::new(), LinkType::RAW, 65535, true).unwrap();
    w.write_packet(Duration::ZERO, &frame, frame.len() as u32)
        .unwrap();
    let file = w.into_inner();
    let mut it = rtps_datagrams(CaptureFile::new(&file[..]).unwrap());
    let p = it.next_packet().unwrap();
    let class = p.port_class.unwrap();
    assert_eq!(class.kind, PortKind::MetatrafficUnicast);
    assert_eq!(class.participant, Some(1));
}

/// Minimal big-endian pcapng: SHB, IDB (LINUX_SLL2, ns resolution), EPB.
fn pcapng_be(frames: &[&[u8]]) -> Vec<u8> {
    fn block(out: &mut Vec<u8>, t: u32, body: &[u8]) {
        let mut body = body.to_vec();
        while !body.len().is_multiple_of(4) {
            body.push(0);
        }
        let len = (12 + body.len()) as u32;
        out.extend_from_slice(&t.to_be_bytes());
        out.extend_from_slice(&len.to_be_bytes());
        out.extend_from_slice(&body);
        out.extend_from_slice(&len.to_be_bytes());
    }
    let mut out = Vec::new();
    let mut shb = 0x1a2b_3c4du32.to_be_bytes().to_vec();
    shb.extend_from_slice(&[0, 1, 0, 0]);
    shb.extend_from_slice(&[0xff; 8]);
    block(&mut out, 0x0a0d_0d0a, &shb);
    let mut idb = 276u16.to_be_bytes().to_vec();
    idb.extend_from_slice(&[0, 0, 0, 0, 0, 0]);
    idb.extend_from_slice(&[0, 9, 0, 1, 9, 0, 0, 0, 0, 0, 0, 0]);
    block(&mut out, 1, &idb);
    for f in frames {
        let mut epb = vec![0u8; 4];
        epb.extend_from_slice(&0u32.to_be_bytes());
        epb.extend_from_slice(&1u32.to_be_bytes());
        epb.extend_from_slice(&(f.len() as u32).to_be_bytes());
        epb.extend_from_slice(&(f.len() as u32).to_be_bytes());
        epb.extend_from_slice(f);
        block(&mut out, 6, &epb);
    }
    out
}

#[test]
fn pcapng_sll2_sedp_yields_cmd_vel_writer() {
    let sedp = sedp_writer_datagram([0xee; 12], "rt/cmd_vel", TWIST, 0);
    let frame = synth::linux_sll2(
        0x0800,
        &synth::ipv4_udp(ATTACKER, ROBOT, 49152, 7410, &sedp),
    );
    let file = pcapng_be(&[&frame]);
    let mut it = rtps_datagrams(CaptureFile::new(&file[..]).unwrap());
    assert_cmd_vel_writer(&events_from(&mut it), "192.168.50.66");
}

#[test]
fn vlan_ipv6_with_extension_headers_yields_writer() {
    let sedp = sedp_writer_datagram([0xee; 12], "rt/cmd_vel", TWIST, 0);
    let a: Ipv6Addr = "fd00:50::66".parse().unwrap();
    let r: Ipv6Addr = "fd00:50::10".parse().unwrap();
    let ip = synth::ipv6_udp(a, r, 49152, 7410, &[(0, 8), (60, 16)], &sedp);
    let frame = synth::ethernet_vlan(&[(0x8100, 42)], 0x86dd, &ip);
    let mut w = PcapWriter::new(Vec::new(), LinkType::ETHERNET, 65535, false).unwrap();
    w.write_packet(Duration::ZERO, &frame, frame.len() as u32)
        .unwrap();
    let file = w.into_inner();
    let mut it = rtps_datagrams(CaptureFile::new(&file[..]).unwrap());
    assert_cmd_vel_writer(&events_from(&mut it), "fd00:50::66");
}

/// Evasion check: an SEDP announcement split across IP fragments (out of
/// order) is still seen.
#[test]
fn fragmented_sedp_is_reassembled() {
    let sedp = sedp_writer_datagram([0xee; 12], "rt/cmd_vel", TWIST, 2000);
    let ip = synth::ipv4_udp(ATTACKER, ROBOT, 49152, 7412, &sedp);
    let mut frags = synth::ipv4_fragment(&ip, 512);
    assert!(frags.len() >= 4);
    frags.swap(0, 2);
    let mut w = PcapWriter::new(Vec::new(), LinkType::RAW, 65535, false).unwrap();
    for f in &frags {
        w.write_packet(Duration::from_secs(5), f, f.len() as u32)
            .unwrap();
    }
    let file = w.into_inner();
    let mut it = rtps_datagrams(CaptureFile::new(&file[..]).unwrap());
    assert_cmd_vel_writer(&events_from(&mut it), "192.168.50.66");
    assert_eq!(it.stats().reassembled, 1);
    assert_eq!(it.stats().fragments as usize, frags.len());
}

/// Overlapping fragments with conflicting bytes (the classic "sensor and host
/// reassemble differently" trick) are dropped and counted, never parsed.
#[test]
fn conflicting_overlap_is_dropped_and_counted() {
    let sedp = sedp_writer_datagram([0xee; 12], "rt/cmd_vel", TWIST, 600);
    let ip = synth::ipv4_udp(ATTACKER, ROBOT, 49152, 7412, &sedp);
    let mut frags = synth::ipv4_fragment(&ip, 256);
    // A rewritten copy of fragment 1 with different payload bytes.
    let mut evil = frags[1].clone();
    let n = evil.len();
    evil[n - 1] ^= 0xff;
    frags.insert(2, evil);
    let mut w = PcapWriter::new(Vec::new(), LinkType::RAW, 65535, false).unwrap();
    for f in &frags {
        w.write_packet(Duration::ZERO, f, f.len() as u32).unwrap();
    }
    let file = w.into_inner();
    let mut it = rtps_datagrams(CaptureFile::new(&file[..]).unwrap());
    assert!(events_from(&mut it).is_empty());
    assert_eq!(it.reassembly_stats().dropped_overlap, 1);
}

#[test]
fn truncated_capture_delivers_what_it_has() {
    let sedp = sedp_writer_datagram([0xee; 12], "rt/cmd_vel", TWIST, 0);
    let frame = synth::ipv4_udp(ATTACKER, ROBOT, 49152, 7412, &sedp);
    let mut w = PcapWriter::new(Vec::new(), LinkType::RAW, 65535, false).unwrap();
    w.write_packet(Duration::ZERO, &frame, frame.len() as u32)
        .unwrap();
    w.write_packet(Duration::ZERO, &frame, frame.len() as u32)
        .unwrap();
    let mut file = w.into_inner();
    file.truncate(file.len() - 10);
    let mut it = rtps_datagrams(CaptureFile::new(&file[..]).unwrap());
    let events = events_from(&mut it);
    assert_cmd_vel_writer(&events, "192.168.50.66");
    assert!(matches!(
        it.last_error(),
        Some(robodr_capture::CaptureError::Truncated)
    ));
}
