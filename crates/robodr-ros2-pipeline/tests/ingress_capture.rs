//! Per-packet ingress from the capture layer, end to end: a loopback source
//! address is judged by the interface each packet was captured on, for
//! captures that mix interfaces (`tcpdump -i any` cooked captures, pcapng
//! with several Interface Description Blocks) — the cases that used to be
//! `Ingress::Unknown` and therefore accepted as same-host traffic.

mod common;

use std::net::Ipv4Addr;
use std::time::{Duration, Instant};

use common::*;
use robodr_capture::{synth, CaptureFile, LinkType, PcapWriter, RtpsFilter};
use robodr_events::Severity;
use robodr_ros2_pipeline::binding::{BindingOptions, Ingress};
use robodr_ros2_pipeline::pipeline::rules;
use robodr_ros2_pipeline::source::{CaptureDatagramSource, DatagramSource};
use robodr_ros2_pipeline::{Finding, Pipeline, PipelineOptions};

const ARPHRD_ETHER: u16 = 1;
const ARPHRD_LOOPBACK: u16 = 772;
const LO: Ipv4Addr = Ipv4Addr::LOCALHOST;

fn on_robot() -> PipelineOptions {
    PipelineOptions {
        binding: BindingOptions {
            local_addresses: vec![ROBOT_IP.into()],
            ..Default::default()
        },
        ..Default::default()
    }
}

/// LEGIT bound from the robot's address, as on a running bus.
fn bound(t: Instant) -> Pipeline {
    let mut p = Pipeline::new(robot_profile(true), on_robot());
    assert!(p
        .process_at(&spdp_datagram(LEGIT, ROBOT_IP), &ROBOT_IP.to_string(), t)
        .is_empty());
    p
}

fn mismatches(f: &[Finding]) -> Vec<&Finding> {
    f.iter()
        .filter(|x| x.deviation.rule == rules::ENDPOINT_SOURCE_MISMATCH)
        .collect()
}

/// Run every datagram of `src` through a freshly bound pipeline; returns
/// (ingress, interface, findings) per datagram.
fn judge(src: &mut dyn DatagramSource) -> Vec<(Ingress, Option<String>, Vec<Finding>)> {
    let t = Instant::now();
    let mut out = Vec::new();
    while let Some(d) = src.recv().unwrap() {
        let mut p = bound(t);
        let f = p.process_datagram(&d);
        out.push((d.ingress, d.interface.clone(), f));
    }
    out
}

fn sedp_ip() -> Vec<u8> {
    synth::ipv4_udp(LO, LO, 51000, 7413, &sedp_datagram(LEGIT, "rt/odom", ODOM))
}

/// `tcpdump -i any` (classic pcap, LINUX_SLL2): the same loopback-sourced
/// SEDP once on `lo` (accepted: same-host) and once on an Ethernet
/// interface (forged: Critical), with the default, non-strict options.
#[test]
fn sll2_any_capture_judges_loopback_source_per_interface() {
    let ip = sedp_ip();
    let mut w = PcapWriter::new(Vec::new(), LinkType::LINUX_SLL2, 65535, false).unwrap();
    for (ifindex, hatype, pkttype) in [
        (1, ARPHRD_LOOPBACK, 4), // outgoing copy on lo: skipped
        (1, ARPHRD_LOOPBACK, 0),
        (2, ARPHRD_ETHER, 0),
    ] {
        let f = synth::linux_sll2_on(ifindex, hatype, pkttype, 0x0800, &ip);
        w.write_packet(Duration::ZERO, &f, f.len() as u32).unwrap();
    }
    let bytes = w.into_inner();
    let mut src =
        CaptureDatagramSource::new(CaptureFile::new(&bytes[..]).unwrap(), RtpsFilter::default());
    let got = judge(&mut src);
    assert_eq!(got.len(), 2, "outgoing loopback copy delivered once");
    assert_eq!(src.stats().loopback_outgoing, 1);
    assert_eq!(got[0].0, Ingress::Loopback);
    assert!(mismatches(&got[0].2).is_empty(), "{:#?}", got[0].2);
    assert_eq!(got[1].0, Ingress::External);
    let m = mismatches(&got[1].2);
    assert_eq!(m.len(), 1, "{:#?}", got[1].2);
    assert_eq!(m[0].deviation.severity, Severity::Critical);
}

/// The cooked v1 header (older libpcap) has no ifindex, but its hardware
/// type still tells loopback from Ethernet.
#[test]
fn sll_v1_capture_uses_the_hardware_type() {
    let ip = sedp_ip();
    let mut w = PcapWriter::new(Vec::new(), LinkType::LINUX_SLL, 65535, false).unwrap();
    for hatype in [ARPHRD_LOOPBACK, ARPHRD_ETHER] {
        let f = synth::linux_sll_on(0, hatype, 0x0800, &ip);
        w.write_packet(Duration::ZERO, &f, f.len() as u32).unwrap();
    }
    let bytes = w.into_inner();
    let mut src =
        CaptureDatagramSource::new(CaptureFile::new(&bytes[..]).unwrap(), RtpsFilter::default());
    let got = judge(&mut src);
    let ing: Vec<Ingress> = got.iter().map(|g| g.0).collect();
    assert_eq!(ing, [Ingress::Loopback, Ingress::External]);
    assert!(mismatches(&got[0].2).is_empty());
    assert_eq!(mismatches(&got[1].2).len(), 1);
}

/// Minimal little-endian pcapng: SHB, one IDB per `(linktype, name)`, then
/// one EPB per `(interface id, frame)`.
fn pcapng(ifaces: &[(u16, &str)], packets: &[(u32, Vec<u8>)]) -> Vec<u8> {
    fn block(out: &mut Vec<u8>, btype: u32, mut body: Vec<u8>) {
        while !body.len().is_multiple_of(4) {
            body.push(0);
        }
        let len = (12 + body.len()) as u32;
        out.extend_from_slice(&btype.to_le_bytes());
        out.extend_from_slice(&len.to_le_bytes());
        out.extend_from_slice(&body);
        out.extend_from_slice(&len.to_le_bytes());
    }
    let mut out = Vec::new();
    let mut shb = 0x1a2b_3c4du32.to_le_bytes().to_vec();
    shb.extend_from_slice(&[1, 0, 0, 0]);
    shb.extend_from_slice(&[0xff; 8]);
    block(&mut out, 0x0a0d_0d0a, shb);
    for (lt, name) in ifaces {
        let mut b = lt.to_le_bytes().to_vec();
        b.extend_from_slice(&[0, 0, 0, 0, 0, 0]);
        b.extend_from_slice(&2u16.to_le_bytes());
        b.extend_from_slice(&(name.len() as u16).to_le_bytes());
        b.extend_from_slice(name.as_bytes());
        while !b.len().is_multiple_of(4) {
            b.push(0);
        }
        b.extend_from_slice(&[0; 4]);
        block(&mut out, 1, b);
    }
    for (id, data) in packets {
        let mut b = id.to_le_bytes().to_vec();
        b.extend_from_slice(&[0; 8]);
        b.extend_from_slice(&(data.len() as u32).to_le_bytes());
        b.extend_from_slice(&(data.len() as u32).to_le_bytes());
        b.extend_from_slice(data);
        block(&mut out, 6, b);
    }
    out
}

/// A Wireshark/dumpcap capture of `lo` and `eth0` together: each packet's
/// Enhanced Packet Block names its interface.
#[test]
fn multi_interface_pcapng_judges_each_packet_by_its_interface() {
    let ip = sedp_ip();
    let bytes = pcapng(
        &[(1, "lo"), (1, "eth0"), (101, "wlan0")],
        &[
            (0, synth::ethernet(0x0800, &ip)),
            (1, synth::ethernet(0x0800, &ip)),
            (2, ip.clone()),
        ],
    );
    let mut src =
        CaptureDatagramSource::new(CaptureFile::new(&bytes[..]).unwrap(), RtpsFilter::default());
    let got = judge(&mut src);
    let tags: Vec<(Ingress, Option<&str>)> = got.iter().map(|g| (g.0, g.1.as_deref())).collect();
    assert_eq!(
        tags,
        [
            (Ingress::Loopback, Some("lo")),
            (Ingress::External, Some("eth0")),
            (Ingress::External, Some("wlan0")),
        ]
    );
    assert!(mismatches(&got[0].2).is_empty());
    for g in &got[1..] {
        let m = mismatches(&g.2);
        assert_eq!(m.len(), 1, "{:#?}", g.2);
        assert_eq!(m[0].deviation.severity, Severity::Critical);
    }
}

/// A classic pcap of plain Ethernet frames says nothing about the interface:
/// still `Unknown` (the documented, non-strict default applies), unless the
/// operator names the interface the file was captured on.
#[test]
fn classic_pcap_is_unknown_unless_named() {
    let ip = sedp_ip();
    let mut w = PcapWriter::new(Vec::new(), LinkType::ETHERNET, 65535, false).unwrap();
    let f = synth::ethernet(0x0800, &ip);
    w.write_packet(Duration::ZERO, &f, f.len() as u32).unwrap();
    let bytes = w.into_inner();
    let mut src =
        CaptureDatagramSource::new(CaptureFile::new(&bytes[..]).unwrap(), RtpsFilter::default());
    let got = judge(&mut src);
    assert_eq!(got[0].0, Ingress::Unknown);
    assert!(mismatches(&got[0].2).is_empty());
    let mut src = CaptureDatagramSource::new(
        CaptureFile::new(&bytes[..])
            .unwrap()
            .with_default_interface("eth0"),
        RtpsFilter::default(),
    );
    let got = judge(&mut src);
    assert_eq!(got[0].0, Ingress::External);
    assert_eq!(mismatches(&got[0].2).len(), 1);
}
