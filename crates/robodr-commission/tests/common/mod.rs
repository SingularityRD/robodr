//! Synthetic RTPS discovery traffic for the pcap tests, built from the
//! DDSI-RTPS 2.5 layout (§8.3, §9.4, §9.6). Not captured from a real stack.
#![allow(dead_code)]

use robodr_capture::{synth, LinkType, PcapWriter};
use std::net::Ipv4Addr;
use std::time::Duration;

pub const SEDP_PUB_WRITER: [u8; 4] = [0x00, 0x00, 0x03, 0xc2];
pub const SEDP_SUB_WRITER: [u8; 4] = [0x00, 0x00, 0x04, 0xc2];
const SUBMSG_DATA: u8 = 0x15;
const SUBMSG_DATA_FRAG: u8 = 0x16;
const FLAG_E: u8 = 0x01;
const FLAG_D: u8 = 0x04;

/// A 24-hex-char GUID prefix made of one repeated byte.
pub fn prefix(b: u8) -> [u8; 12] {
    [b; 12]
}

pub fn hex(p: [u8; 12]) -> String {
    p.iter().map(|b| format!("{b:02x}")).collect()
}

fn param(pid: u16, value: &[u8]) -> Vec<u8> {
    let mut v = value.to_vec();
    while v.len() % 4 != 0 {
        v.push(0);
    }
    let mut p = pid.to_le_bytes().to_vec();
    p.extend_from_slice(&(v.len() as u16).to_le_bytes());
    p.extend_from_slice(&v);
    p
}

fn string_param(pid: u16, s: &str) -> Vec<u8> {
    let mut v = ((s.len() + 1) as u32).to_le_bytes().to_vec();
    v.extend_from_slice(s.as_bytes());
    v.push(0);
    param(pid, &v)
}

/// Serialized SEDP payload (PL_CDR_LE) for one endpoint owned by `owner`.
/// `pad` adds a vendor parameter of that many bytes, standing in for the
/// XTypes type information that makes real announcements large.
pub fn sedp_payload(
    owner: [u8; 12],
    entity: u32,
    topic: &str,
    type_name: &str,
    pad: usize,
) -> Vec<u8> {
    let mut out = vec![0x00, 0x03, 0x00, 0x00]; // PL_CDR_LE, options
    let mut guid = owner.to_vec();
    guid.extend_from_slice(&entity.to_be_bytes());
    out.extend(param(0x005a, &guid)); // PID_ENDPOINT_GUID
    if pad > 0 {
        out.extend(param(0x8001, &vec![0x5a; pad])); // vendor-specific, ignored
    }
    out.extend(string_param(0x0005, topic)); // PID_TOPIC_NAME
    out.extend(string_param(0x0007, type_name)); // PID_TYPE_NAME
    out.extend_from_slice(&[0x01, 0x00, 0x00, 0x00]); // PID_SENTINEL
    out
}

fn submsg(id: u8, flags: u8, body: &[u8]) -> Vec<u8> {
    let mut s = vec![id, flags | FLAG_E];
    s.extend_from_slice(&(body.len() as u16).to_le_bytes());
    s.extend_from_slice(body);
    s
}

/// DATA submessage carrying a whole serialized payload.
pub fn data(writer: [u8; 4], sn: u32, payload: &[u8]) -> Vec<u8> {
    let mut b = vec![0, 0];
    b.extend_from_slice(&16u16.to_le_bytes());
    b.extend_from_slice(&[0, 0, 0, 0]);
    b.extend_from_slice(&writer);
    b.extend_from_slice(&0i32.to_le_bytes());
    b.extend_from_slice(&sn.to_le_bytes());
    b.extend_from_slice(payload);
    submsg(SUBMSG_DATA, FLAG_D, &b)
}

/// The payload split into DATA_FRAG submessages of `frag_size` bytes, one
/// fragment each (as Fast DDS does for large SEDP samples).
pub fn data_frags(writer: [u8; 4], sn: u32, payload: &[u8], frag_size: u16) -> Vec<Vec<u8>> {
    payload
        .chunks(usize::from(frag_size))
        .enumerate()
        .map(|(i, chunk)| {
            let mut b = vec![0, 0];
            b.extend_from_slice(&28u16.to_le_bytes());
            b.extend_from_slice(&[0, 0, 0, 0]);
            b.extend_from_slice(&writer);
            b.extend_from_slice(&0i32.to_le_bytes());
            b.extend_from_slice(&sn.to_le_bytes());
            b.extend_from_slice(&(i as u32 + 1).to_le_bytes()); // fragmentStartingNum
            b.extend_from_slice(&1u16.to_le_bytes()); // fragmentsInSubmessage
            b.extend_from_slice(&frag_size.to_le_bytes());
            b.extend_from_slice(&(payload.len() as u32).to_le_bytes());
            b.extend_from_slice(chunk);
            submsg(SUBMSG_DATA_FRAG, 0, &b)
        })
        .collect()
}

/// RTPS message from participant `from` carrying `subs`.
pub fn rtps(from: [u8; 12], subs: &[Vec<u8>]) -> Vec<u8> {
    let mut d = b"RTPS".to_vec();
    d.extend_from_slice(&[2, 3, 0x01, 0x0f]);
    d.extend_from_slice(&from);
    for s in subs {
        d.extend_from_slice(s);
    }
    d
}

/// One endpoint announcement.
pub struct Ann<'a> {
    pub writer: bool,
    pub topic: &'a str,
}

pub fn w(topic: &str) -> Ann<'_> {
    Ann {
        writer: true,
        topic,
    }
}
pub fn r(topic: &str) -> Ann<'_> {
    Ann {
        writer: false,
        topic,
    }
}

/// A ROS 2 node's usual endpoints: /rosout, /parameter_events, the six
/// parameter services (server side) and ros_discovery_info.
pub fn ros_node(node: &str) -> Vec<String> {
    let mut v = vec![
        "W rt/rosout".to_string(),
        "W rt/parameter_events".into(),
        "R rt/parameter_events".into(),
        "W ros_discovery_info".into(),
        "R ros_discovery_info".into(),
    ];
    for s in [
        "describe_parameters",
        "get_parameter_types",
        "get_parameters",
        "list_parameters",
        "set_parameters",
        "set_parameters_atomically",
    ] {
        v.push(format!("R rq{node}/{s}Request"));
        v.push(format!("W rr{node}/{s}Reply"));
    }
    v
}

/// Datagrams: one SEDP DATA per "W topic" / "R topic" spec, from `owner`.
pub fn announce(owner: [u8; 12], specs: &[String]) -> Vec<Vec<u8>> {
    specs
        .iter()
        .enumerate()
        .map(|(i, spec)| {
            let (kind, topic) = spec.split_at(2);
            let writer = kind == "W ";
            let entity = ((i as u32 + 1) << 8) | if writer { 0x03 } else { 0x04 };
            let payload = sedp_payload(owner, entity, topic, "pkg::msg::dds_::T_", 0);
            let w = if writer {
                SEDP_PUB_WRITER
            } else {
                SEDP_SUB_WRITER
            };
            rtps(owner, &[data(w, i as u32 + 1, &payload)])
        })
        .collect()
}

pub const ROBOT: Ipv4Addr = Ipv4Addr::new(10, 42, 0, 1);

/// Wrap RTPS datagrams from `src` into Ethernet/IPv4/UDP frames to the
/// robot's metatraffic unicast port.
pub fn frames(src: Ipv4Addr, datagrams: &[Vec<u8>]) -> Vec<Vec<u8>> {
    datagrams
        .iter()
        .map(|d| synth::ethernet(0x0800, &synth::ipv4_udp(src, ROBOT, 49152, 7412, d)))
        .collect()
}

/// IPv4 fragments of one datagram, as Ethernet frames.
pub fn ip_fragmented(src: Ipv4Addr, datagram: &[u8], chunk: usize) -> Vec<Vec<u8>> {
    let ip = synth::ipv4_udp(src, ROBOT, 49152, 7412, datagram);
    synth::ipv4_fragment(&ip, chunk)
        .into_iter()
        .map(|f| synth::ethernet(0x0800, &f))
        .collect()
}

/// A classic pcap (Ethernet, microsecond timestamps) of `frames`.
pub fn pcap(frames: &[Vec<u8>]) -> Vec<u8> {
    let mut wr = PcapWriter::new(Vec::new(), LinkType::ETHERNET, 65535, false).unwrap();
    for (i, f) in frames.iter().enumerate() {
        wr.write_packet(
            Duration::new(1_760_000_000 + i as u64, 0),
            f,
            f.len() as u32,
        )
        .unwrap();
    }
    wr.into_inner()
}

/// A minimal little-endian pcapng (SHB, one Ethernet IDB, EPBs).
pub fn pcapng(frames: &[Vec<u8>]) -> Vec<u8> {
    fn block(out: &mut Vec<u8>, t: u32, body: &[u8]) {
        let mut body = body.to_vec();
        while body.len() % 4 != 0 {
            body.push(0);
        }
        let len = (12 + body.len()) as u32;
        out.extend_from_slice(&t.to_le_bytes());
        out.extend_from_slice(&len.to_le_bytes());
        out.extend_from_slice(&body);
        out.extend_from_slice(&len.to_le_bytes());
    }
    let mut out = Vec::new();
    let mut shb = 0x1a2b_3c4du32.to_le_bytes().to_vec();
    shb.extend_from_slice(&[1, 0, 0, 0]);
    shb.extend_from_slice(&[0xff; 8]);
    block(&mut out, 0x0a0d_0d0a, &shb);
    let mut idb = 1u16.to_le_bytes().to_vec(); // LINKTYPE_ETHERNET
    idb.extend_from_slice(&[0, 0]);
    idb.extend_from_slice(&0u32.to_le_bytes()); // snaplen: unlimited
    block(&mut out, 1, &idb);
    for f in frames {
        let mut epb = 0u32.to_le_bytes().to_vec(); // interface 0
        epb.extend_from_slice(&0u32.to_le_bytes());
        epb.extend_from_slice(&0u32.to_le_bytes());
        epb.extend_from_slice(&(f.len() as u32).to_le_bytes());
        epb.extend_from_slice(&(f.len() as u32).to_le_bytes());
        epb.extend_from_slice(f);
        block(&mut out, 6, &epb);
    }
    out
}

pub const TALKER: Ipv4Addr = Ipv4Addr::new(10, 42, 0, 11);
pub const LISTENER: Ipv4Addr = Ipv4Addr::new(10, 42, 0, 12);

/// A clean two-node graph (talker / listener) as frames, with the talker's
/// large `/chatter` announcement sent as DATA_FRAG (one per datagram) and
/// one ordinary announcement IP-fragmented. `drop_frag` removes one
/// DATA_FRAG to simulate a lossy capture.
pub fn talker_listener(drop_frag: bool) -> Vec<Vec<u8>> {
    let (t, l) = (prefix(0xa1), prefix(0xb2));
    let mut out = Vec::new();
    let mut tspecs = ros_node("/talker");
    tspecs.push("W rq/listener/get_parametersRequest".into()); // a client too
    tspecs.push("R rr/listener/get_parametersReply".into());
    out.extend(frames(TALKER, &announce(t, &tspecs)));
    let mut lspecs = ros_node("/listener");
    lspecs.push("R rt/chatter".into());
    lspecs.push("W rq/talker/get_parametersRequest".into());
    lspecs.push("R rr/talker/get_parametersReply".into());
    // Action: listener serves /dock.
    lspecs.push("W rr/dock/_action/send_goalReply".into());
    lspecs.push("R rq/dock/_action/send_goalRequest".into());
    lspecs.push("W rt/dock/_action/feedback".into());
    lspecs.push("W rt/dock/_action/status".into());
    let ldgrams = announce(l, &lspecs);
    let (first, rest) = ldgrams.split_first().unwrap();
    // The first listener announcement arrives IP-fragmented.
    out.extend(ip_fragmented(LISTENER, first, 64));
    out.extend(frames(LISTENER, rest));
    // The talker's /chatter writer, large enough to need DATA_FRAG.
    let big = sedp_payload(
        t,
        0x0000_ff03,
        "rt/chatter",
        "std_msgs::msg::dds_::String_",
        3000,
    );
    let mut frags = data_frags(SEDP_PUB_WRITER, 900, &big, 1024);
    assert!(frags.len() >= 3);
    if drop_frag {
        frags.remove(1);
    }
    let dgrams: Vec<Vec<u8>> = frags.into_iter().map(|f| rtps(t, &[f])).collect();
    out.extend(frames(TALKER, &dgrams));
    out
}
