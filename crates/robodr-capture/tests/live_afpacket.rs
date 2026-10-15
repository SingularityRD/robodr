//! Live AF_PACKET capture on loopback. Needs CAP_NET_RAW; without it the
//! tests print "SKIPPED" and pass.
//!
//! The *test* sends ordinary UDP datagrams with `std::net::UdpSocket` to
//! generate traffic on `lo`; the capture code itself never transmits.

#![cfg(target_os = "linux")]

use std::net::UdpSocket;
use std::time::{Duration, Instant};

use robodr_capture::afpacket::{AfPacketConfig, AfPacketSource};
use robodr_capture::{CaptureError, RtpsDatagrams, RtpsFilter};

fn open(cfg: AfPacketConfig) -> Option<AfPacketSource> {
    match AfPacketSource::open(&cfg) {
        Ok(s) => Some(s),
        Err(CaptureError::PermissionDenied(m)) => {
            eprintln!("SKIPPED: live capture needs CAP_NET_RAW ({m})");
            None
        }
        Err(e) => panic!("opening AF_PACKET failed: {e}"),
    }
}

/// Send `payload` to 127.0.0.1:`port` and collect matching captured payloads
/// (identified by a unique marker) for up to two seconds.
fn send_and_capture(
    src: AfPacketSource,
    sends: &[(u16, Vec<u8>)],
    marker: &[u8],
) -> Vec<(String, u16, Vec<u8>)> {
    let mut it = RtpsDatagrams::new(src, RtpsFilter::default()).with_frame_budget(64);
    let tx = UdpSocket::bind("127.0.0.1:0").unwrap();
    for (port, payload) in sends {
        tx.send_to(payload, ("127.0.0.1", *port)).unwrap();
    }
    let mut got = Vec::new();
    let deadline = Instant::now() + Duration::from_secs(2);
    while Instant::now() < deadline {
        // A busy host may never go quiet for a whole read timeout, so the
        // deadline is checked per packet too.
        while let Some(p) = it.next_packet() {
            if p.payload.windows(marker.len()).any(|w| w == marker) {
                got.push((p.src.to_string(), p.dst_port, p.payload));
            }
            if Instant::now() >= deadline {
                break;
            }
        }
        assert!(
            !it.is_finished(),
            "live source ended: {:?}",
            it.last_error()
        );
    }
    got
}

fn marker() -> Vec<u8> {
    format!("robodr-test-{}-{:?}", std::process::id(), Instant::now()).into_bytes()
}

#[test]
fn loopback_rtps_is_captured_once_and_non_rtps_is_filtered() {
    let Some(src) = open(AfPacketConfig {
        interfaces: vec!["lo".into()],
        read_timeout: Some(Duration::from_millis(50)),
        ..Default::default()
    }) else {
        return;
    };
    assert!(
        src.filter_attached(),
        "kernel rejected BPF: {:?}",
        src.filter_error()
    );
    let m = marker();
    let mut rtps = b"RTPS\x02\x03\x01\x0f".to_vec();
    rtps.extend_from_slice(&[0x11; 12]);
    rtps.extend_from_slice(&m);
    let mut not_rtps = b"XXXX".to_vec();
    not_rtps.extend_from_slice(&m);
    let got = send_and_capture(
        src,
        &[
            (7410, rtps.clone()),      // well-known port + magic
            (34567, rtps.clone()),     // magic on a non-standard port
            (34568, not_rtps.clone()), // neither: must be dropped
        ],
        &m,
    );
    let ports: Vec<u16> = got.iter().map(|g| g.1).collect();
    // Exactly once each: the loopback outgoing copy is skipped.
    assert_eq!(ports.iter().filter(|&&p| p == 7410).count(), 1, "{ports:?}");
    assert_eq!(
        ports.iter().filter(|&&p| p == 34567).count(),
        1,
        "{ports:?}"
    );
    assert!(
        !ports.contains(&34568),
        "non-RTPS leaked through: {ports:?}"
    );
    assert!(got.iter().all(|g| g.0 == "127.0.0.1" && g.2 == rtps));
}

#[test]
fn all_interfaces_without_kernel_filter_uses_userspace_filter() {
    let Some(src) = open(AfPacketConfig {
        interfaces: Vec::new(),
        kernel_filter: None,
        read_timeout: Some(Duration::from_millis(50)),
        recv_buffer: None,
    }) else {
        return;
    };
    assert!(!src.filter_attached());
    let m = marker();
    let mut rtps = b"RTPS\x02\x03\x01\x0f".to_vec();
    rtps.extend_from_slice(&[0x22; 12]);
    rtps.extend_from_slice(&m);
    let mut not_rtps = b"YYYY".to_vec();
    not_rtps.extend_from_slice(&m);
    let got = send_and_capture(src, &[(7411, rtps), (34569, not_rtps)], &m);
    let ports: Vec<u16> = got.iter().map(|g| g.1).collect();
    assert_eq!(ports, vec![7411]);
}
