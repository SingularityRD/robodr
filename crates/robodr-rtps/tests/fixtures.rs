//! Regression tests over the SYNTHETIC RTPS fixtures in `tests/fixtures/`.
//!
//! 1. `fixture_files_match_generator`: the checked-in `.bin` files (and the
//!    cargo-fuzz seed corpus) are byte-identical to what `common::all()`
//!    builds, so the byte-by-byte documentation in `common/mod.rs` cannot drift
//!    from the files. Regenerate with `ROBODR_BLESS=1 cargo test -p robodr-rtps`.
//! 2. One test per fixture asserting the parser's current events. Only the
//!    event kind, GUID prefix, topic and type name are asserted, never
//!    locators or other fields the parser may start populating.

mod common;

use common::*;
use robodr_events::RobotEvent;
use robodr_rtps::{hex12, parse_datagram};

fn load(name: &str) -> Vec<u8> {
    let path = fixtures_dir().join(format!("{name}.bin"));
    std::fs::read(&path).unwrap_or_else(|e| panic!("read {}: {e}", path.display()))
}

#[test]
fn fixture_files_match_generator() {
    let corpus = fuzz_corpus_dir();
    if bless() {
        std::fs::create_dir_all(&corpus).unwrap();
    }
    for f in all() {
        let bin = fixtures_dir().join(format!("{}.bin", f.name));
        let seed = corpus.join(format!("seed-{}.bin", f.name));
        if bless() {
            std::fs::write(&bin, &f.bytes).unwrap();
            std::fs::write(&seed, &f.bytes).unwrap();
            continue;
        }
        assert_eq!(
            std::fs::read(&bin).ok().as_deref(),
            Some(f.bytes.as_slice()),
            "{} differs from generator; run with ROBODR_BLESS=1 if intended",
            bin.display()
        );
        assert_eq!(
            std::fs::read(&seed).ok().as_deref(),
            Some(f.bytes.as_slice()),
            "fuzz seed {} differs from generator",
            seed.display()
        );
    }
}

#[test]
fn every_fixture_satisfies_invariants() {
    for f in all() {
        let events = parse_datagram(&f.bytes, SRC_IP);
        check_invariants(&f.bytes, SRC_IP, &events).unwrap_or_else(|e| panic!("{}: {e}", f.name));
    }
}

/// Assert the first event is the sending participant (from the RTPS header).
fn assert_participant(events: &[RobotEvent], prefix: &[u8; 12]) {
    match events.first() {
        Some(RobotEvent::Ros2ParticipantDiscovered(p)) => {
            assert_eq!(p.guid_prefix, hex12(prefix));
            assert_eq!(p.src_ip, SRC_IP);
        }
        other => panic!("expected participant first, got {other:?}"),
    }
}

fn endpoints(events: &[RobotEvent]) -> Vec<(&'static str, String, String, String)> {
    events
        .iter()
        .filter_map(|e| match e {
            RobotEvent::Ros2WriterDiscovered(ep) => Some(("writer", ep)),
            RobotEvent::Ros2ReaderDiscovered(ep) => Some(("reader", ep)),
            _ => None,
        })
        .map(|(k, ep)| {
            (
                k,
                ep.guid_prefix.clone(),
                ep.topic.clone(),
                ep.type_name.clone(),
            )
        })
        .collect()
}

#[test]
fn fastdds_spdp_yields_only_participant() {
    let events = parse_datagram(&load("fastdds_spdp_participant"), SRC_IP);
    assert_participant(&events, &FASTDDS_PREFIX);
    assert_eq!(hex12(&FASTDDS_PREFIX), "010f3a7c2104000001000000");
    assert!(
        endpoints(&events).is_empty(),
        "SPDP must not yield endpoints"
    );
}

#[test]
fn cyclonedds_spdp_yields_only_participant() {
    let events = parse_datagram(&load("cyclonedds_spdp_participant"), SRC_IP);
    assert_participant(&events, &CYCLONE_PREFIX);
    assert_eq!(hex12(&CYCLONE_PREFIX), "01105e2b9c41a7d38e6f1c22");
    assert!(endpoints(&events).is_empty());
}

#[test]
fn sedp_cmd_vel_publication_yields_writer() {
    let events = parse_datagram(&load("sedp_pub_cmd_vel"), SRC_IP);
    assert_participant(&events, &FASTDDS_PREFIX);
    assert_eq!(
        endpoints(&events),
        vec![(
            "writer",
            hex12(&FASTDDS_PREFIX),
            "rt/cmd_vel".to_string(),
            "geometry_msgs::msg::dds_::Twist_".to_string()
        )]
    );
}

#[test]
fn sedp_odom_subscription_with_inline_qos_yields_reader() {
    let events = parse_datagram(&load("sedp_sub_odom"), SRC_IP);
    assert_participant(&events, &CYCLONE_PREFIX);
    assert_eq!(
        endpoints(&events),
        vec![(
            "reader",
            hex12(&CYCLONE_PREFIX),
            "rt/odom".to_string(),
            "nav_msgs::msg::dds_::Odometry_".to_string()
        )]
    );
}

#[test]
fn service_request_writer_keeps_rq_mangling() {
    let events = parse_datagram(&load("sedp_pub_service_request"), SRC_IP);
    assert_participant(&events, &FASTDDS_CLIENT_PREFIX);
    assert_eq!(
        endpoints(&events),
        vec![(
            "writer",
            hex12(&FASTDDS_CLIENT_PREFIX),
            "rq/add_two_intsRequest".to_string(),
            "example_interfaces::srv::dds_::AddTwoInts_Request_".to_string()
        )]
    );
}

#[test]
fn action_datagram_yields_both_writers_in_order() {
    let events = parse_datagram(&load("sedp_pub_action_feedback"), SRC_IP);
    assert_participant(&events, &CYCLONE_PREFIX);
    let g = hex12(&CYCLONE_PREFIX);
    assert_eq!(
        endpoints(&events),
        vec![
            (
                "writer",
                g.clone(),
                "rt/fibonacci/_action/feedback".to_string(),
                "action_tutorials_interfaces::action::dds_::Fibonacci_FeedbackMessage_".to_string()
            ),
            (
                "writer",
                g,
                "rt/fibonacci/_action/status".to_string(),
                "action_msgs::msg::dds_::GoalStatusArray_".to_string()
            ),
        ]
    );
}

#[test]
fn big_endian_datagram_yields_writer() {
    let events = parse_datagram(&load("sedp_pub_big_endian"), SRC_IP);
    assert_participant(&events, &CONNEXT_PREFIX);
    assert_eq!(
        endpoints(&events),
        vec![(
            "writer",
            hex12(&CONNEXT_PREFIX),
            "rt/scan".to_string(),
            "sensor_msgs::msg::dds_::LaserScan_".to_string()
        )]
    );
}

#[test]
fn heartbeat_acknack_yields_only_participant() {
    let events = parse_datagram(&load("heartbeat_acknack_only"), SRC_IP);
    assert_participant(&events, &FASTDDS_PREFIX);
    assert!(endpoints(&events).is_empty());
}

/// Spot-check the generator against hand-written bytes so the documented
/// layout is verified independently of the builder helpers.
#[test]
fn generator_layout_spot_checks() {
    let d = sedp_pub_cmd_vel();
    // Header: magic, version 2.3, vendor 01 0f, prefix.
    assert_eq!(&d[..8], b"RTPS\x02\x03\x01\x0f");
    assert_eq!(&d[8..20], &FASTDDS_PREFIX);
    // INFO_DST: id 0x0e, flags E, length 12 LE, then the destination prefix.
    assert_eq!(&d[20..24], &[0x0e, 0x01, 12, 0]);
    assert_eq!(&d[24..36], &CYCLONE_PREFIX);
    // INFO_TS: id 0x09, flags E, length 8, seconds LE, fraction 0.
    assert_eq!(&d[36..40], &[0x09, 0x01, 8, 0]);
    assert_eq!(&d[40..44], &TS_SECONDS.to_le_bytes());
    // DATA: id 0x15, flags E|D, then body; length covers the rest exactly.
    assert_eq!(&d[48..50], &[0x15, 0x05]);
    assert_eq!(u16::from_le_bytes([d[50], d[51]]) as usize, d.len() - 52);
    // extraFlags 0, octetsToInlineQos 16, readerId 000003c7, writerId 000003c2.
    assert_eq!(&d[52..56], &[0, 0, 16, 0]);
    assert_eq!(&d[56..64], &[0, 0, 3, 0xc7, 0, 0, 3, 0xc2]);
    // writerSN = 3, then encapsulation PL_CDR_LE (00 03) + options.
    assert_eq!(&d[64..72], &[0, 0, 0, 0, 3, 0, 0, 0]);
    assert_eq!(&d[72..76], &[0x00, 0x03, 0, 0]);
    // First parameter: PID_ENDPOINT_GUID (5a 00), length 16.
    assert_eq!(&d[76..80], &[0x5a, 0x00, 16, 0]);
    // Ends with PID_SENTINEL.
    assert_eq!(&d[d.len() - 4..], &[1, 0, 0, 0]);

    // Big-endian variant: E clear, lengths BE, encapsulation 00 02.
    let be = sedp_pub_big_endian();
    assert_eq!(&be[20..24], &[0x09, 0x00, 0, 8]);
    assert_eq!(&be[32..36], &[0x15, FLAG_D, 0, (be.len() - 36) as u8]);
    assert_eq!(&be[56..60], &[0x00, 0x02, 0, 0]);
    assert_eq!(&be[be.len() - 4..], &[0, 1, 0, 0]);

    // Inline QoS fixture: flags E|Q|D and PID_KEY_HASH first in the QoS list.
    let q = sedp_sub_odom();
    assert_eq!(&q[48..50], &[0x15, 0x07]);
    assert_eq!(&q[72..76], &[0x70, 0x00, 16, 0]);

    // USER_DATA "enclave=/;" in the SPDP announcement: len 10, padded to 16.
    let spdp = fastdds_spdp_participant();
    let needle = [&[0x2c, 0x00, 16, 0, 10, 0, 0, 0][..], b"enclave=/;"].concat();
    assert!(spdp.windows(needle.len()).any(|w| w == needle.as_slice()));
}
