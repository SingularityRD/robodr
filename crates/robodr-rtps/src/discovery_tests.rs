//! Unit tests for SPDP, INFO_SRC / attribution, disposal, DATA_FRAG and
//! hostile input, plus an in-crate mutation fuzz loop.

use std::time::Duration;

use robodr_events::RobotEvent;

use crate::testutil::*;
use crate::wire::*;
use crate::*;

const S: [u8; 12] = [0x5e; 12]; // sender / header prefix
const X: [u8; 12] = [0xc1; 12]; // another participant
const PUB: [u8; 4] = ENTITYID_SEDP_PUBLICATIONS_WRITER;
const SUB: [u8; 4] = ENTITYID_SEDP_SUBSCRIPTIONS_WRITER;
const SPDP: [u8; 4] = ENTITYID_SPDP_WRITER;
const W_ENT: [u8; 4] = [0, 0, 0x12, 0x03];

fn dg(prefix: [u8; 12], subs: &[Vec<u8>]) -> Vec<u8> {
    let mut d = header(prefix);
    for s in subs {
        d.extend_from_slice(s);
    }
    d
}

fn report(d: &[u8]) -> DatagramReport {
    parse_datagram_detailed(d).expect("rtps")
}

fn participants(ev: &[RobotEvent]) -> Vec<&robodr_events::graph::Participant> {
    ev.iter()
        .filter_map(|e| match e {
            RobotEvent::Ros2ParticipantDiscovered(p) => Some(p),
            _ => None,
        })
        .collect()
}

fn endpoints(ev: &[RobotEvent]) -> usize {
    ev.iter()
        .filter(|e| {
            matches!(
                e,
                RobotEvent::Ros2WriterDiscovered(_) | RobotEvent::Ros2ReaderDiscovered(_)
            )
        })
        .count()
}

fn sedp(le: bool, writer: [u8; 4], ep: [u8; 16], topic: &str) -> Vec<u8> {
    data(
        le,
        writer,
        None,
        Payload::Data(sedp_payload(le, ep, topic, "std_msgs::msg::dds_::String_")),
    )
}

// ---------------------------------------------------------------- SPDP

#[test]
fn spdp_all_fields_all_endian_combinations() {
    for sub_le in [true, false] {
        for pl_le in [true, false] {
            let d = dg(
                S,
                &[data(
                    sub_le,
                    SPDP,
                    None,
                    Payload::Data(spdp_payload(pl_le, S)),
                )],
            );
            let r = report(&d);
            assert!(r.anomalies.is_empty(), "{:?}", r.anomalies);
            assert_eq!(r.participants.len(), 1);
            let p = &r.participants[0];
            assert_eq!(p.guid_prefix, S);
            assert_eq!(p.attribution, Attribution::ParticipantGuid);
            assert_eq!(p.participant_entity, Some(ENTITYID_PARTICIPANT));
            assert!(!p.relayed());
            assert_eq!(p.protocol_version, Some((2, 3)));
            assert_eq!(p.vendor_id, Some([0x01, 0x0f]));
            assert_eq!(p.vendor_name(), Some("eProsima Fast DDS"));
            assert_eq!(p.domain_id, Some(0));
            assert_eq!(p.entity_name.as_deref(), Some("/"));
            assert_eq!(p.enclave(), Some("/"));
            let lease = p.lease_duration.unwrap();
            assert_eq!(lease.to_std(), Some(Duration::from_millis(20_500)));
            assert_eq!(
                p.metatraffic_unicast[0].to_string(),
                "udpv4://192.168.1.20:7410"
            );
            assert_eq!(
                p.metatraffic_multicast[0].socket_string().as_deref(),
                Some("239.255.0.1:7400")
            );
            assert_eq!(p.default_multicast.len(), 1);
            assert_eq!(
                p.unicast_locator_strings(),
                vec!["192.168.1.20:7410", "192.168.1.20:7411"]
            );
        }
    }
}

#[test]
fn spdp_from_sender_merges_into_one_participant_event() {
    let d = dg(
        S,
        &[data(true, SPDP, None, Payload::Data(spdp_payload(true, S)))],
    );
    let ev = parse_datagram(&d, "192.168.1.20");
    let ps = participants(&ev);
    assert_eq!(ev.len(), 1, "header + SPDP of the same prefix = one event");
    assert_eq!(ps[0].guid_prefix, hex12(&S));
    assert_eq!(ps[0].src_ip, "192.168.1.20");
    assert_eq!(
        ps[0].locators,
        vec!["192.168.1.20:7410", "192.168.1.20:7411"]
    );
}

#[test]
fn spdp_repeated_in_one_datagram_is_one_event() {
    let s = data(true, SPDP, None, Payload::Data(spdp_payload(true, X)));
    let d = dg(S, &[s.clone(), s]);
    let ev = parse_datagram(&d, "10.0.0.1");
    let ps = participants(&ev);
    assert_eq!(ps.len(), 2, "sender + X");
    assert_eq!(ps[1].guid_prefix, hex12(&X));
    assert_eq!(ps[1].locators.len(), 2, "locators de-duplicated");
}

#[test]
fn spdp_relayed_by_discovery_server_is_attributed_to_the_client() {
    let d = dg(
        S,
        &[data(true, SPDP, None, Payload::Data(spdp_payload(true, X)))],
    );
    let r = report(&d);
    assert_eq!(r.participants[0].guid_prefix, X);
    assert_eq!(r.participants[0].source, S);
    assert!(r.participants[0].relayed());
    let ev = r.to_events("10.0.0.9");
    let ps = participants(&ev);
    assert_eq!(ps.len(), 2);
    assert_eq!(ps[0].guid_prefix, hex12(&S));
    assert!(ps[0].locators.is_empty());
    assert_eq!(ps[1].guid_prefix, hex12(&X));
    assert_eq!(ps[1].locators.len(), 2);
}

#[test]
fn spdp_ipv6_and_non_udp_locators() {
    let v6: [u8; 16] = std::net::Ipv6Addr::new(0xfd00, 0, 0, 0, 0, 0, 0, 0x20).octets();
    let pl = Pl::new(true)
        .guid(PID_PARTICIPANT_GUID, guid_of(X, ENTITYID_PARTICIPANT))
        .locator(
            PID_METATRAFFIC_UNICAST_LOCATOR,
            LOCATOR_KIND_UDPV6,
            7410,
            v6,
        )
        .locator(PID_METATRAFFIC_UNICAST_LOCATOR, 16, 1234, [7; 16]) // e.g. SHM
        .locator(PID_DEFAULT_UNICAST_LOCATOR, LOCATOR_KIND_UDPV4, 0, [0; 16]) // invalid port
        .end();
    let d = dg(
        S,
        &[data(false, SPDP, None, Payload::Data(pl_payload(true, pl)))],
    );
    let r = report(&d);
    let p = &r.participants[0];
    assert_eq!(p.metatraffic_unicast.len(), 2);
    assert_eq!(p.metatraffic_unicast[1].kind, 16);
    assert_eq!(p.metatraffic_unicast[1].kind_name(), "other");
    assert_eq!(p.unicast_locator_strings(), vec!["[fd00::20]:7410"]);
}

#[test]
fn spdp_without_participant_guid_falls_back() {
    // No PID_PARTICIPANT_GUID, no key: the source prefix (after INFO_SRC).
    let pl = Pl::new(true).u32(PID_DOMAIN_ID, 42).end();
    let d = dg(
        S,
        &[
            info_src(true, X),
            data(
                true,
                SPDP,
                None,
                Payload::Data(pl_payload(true, pl.clone())),
            ),
        ],
    );
    let r = report(&d);
    assert_eq!(r.participants[0].guid_prefix, X);
    assert_eq!(r.participants[0].attribution, Attribution::SourcePrefix);
    assert_eq!(r.participants[0].domain_id, Some(42));

    // Key hash in inline QoS is used before the source.
    let q = Pl::new(true)
        .guid(PID_KEY_HASH, guid_of([9; 12], ENTITYID_PARTICIPANT))
        .end();
    let d = dg(
        S,
        &[data(
            true,
            SPDP,
            Some(q),
            Payload::Data(pl_payload(true, pl)),
        )],
    );
    let r = report(&d);
    assert_eq!(r.participants[0].guid_prefix, [9; 12]);
    assert_eq!(r.participants[0].attribution, Attribution::KeyHash);
}

#[test]
fn spdp_unexpected_participant_entity_is_flagged() {
    let pl = Pl::new(true)
        .guid(PID_PARTICIPANT_GUID, guid_of(X, [0, 0, 3, 0xc2]))
        .end();
    let d = dg(
        S,
        &[data(true, SPDP, None, Payload::Data(pl_payload(true, pl)))],
    );
    let r = report(&d);
    assert!(r
        .anomalies
        .contains(&Anomaly::UnexpectedParticipantEntityId));
    assert_eq!(r.participants[0].guid_prefix, X);
}

#[test]
fn spdp_enclave_variants() {
    let mk = |ud: &[u8]| {
        let pl = Pl::new(true)
            .guid(PID_PARTICIPANT_GUID, guid_of(X, ENTITYID_PARTICIPANT))
            .octets(PID_USER_DATA, ud)
            .end();
        let d = dg(
            S,
            &[data(true, SPDP, None, Payload::Data(pl_payload(true, pl)))],
        );
        report(&d).participants.remove(0)
    };
    assert_eq!(mk(b"enclave=/robot/nav;").enclave(), Some("/robot/nav"));
    assert_eq!(mk(b"securitycontext=/a;").enclave(), Some("/a"));
    assert_eq!(mk(b"name=x;enclave=/b;\0").enclave(), Some("/b"));
    assert_eq!(mk(b"nothing here").enclave(), None);
    assert_eq!(mk(&[0xff, 0xfe]).enclave(), None);
    assert_eq!(mk(b"").user_data.as_deref(), Some(&b""[..]));
}

#[test]
fn spdp_bad_user_data_length_does_not_allocate() {
    let mut v = u32::MAX.to_le_bytes().to_vec();
    v.extend_from_slice(b"enclave=/;\0\0");
    let pl = Pl::new(true)
        .guid(PID_PARTICIPANT_GUID, guid_of(X, ENTITYID_PARTICIPANT))
        .raw(PID_USER_DATA, &v)
        .end();
    let d = dg(
        S,
        &[data(true, SPDP, None, Payload::Data(pl_payload(true, pl)))],
    );
    let r = report(&d);
    assert_eq!(r.participants[0].user_data, None);
    assert!(r
        .anomalies
        .contains(&Anomaly::BadParameterValue(PID_USER_DATA)));
}

#[test]
fn lease_duration_edge_cases() {
    let inf = RtpsDuration {
        seconds: i32::MAX,
        fraction: u32::MAX,
    };
    assert!(inf.is_infinite());
    assert_eq!(inf.to_std(), None);
    let neg = RtpsDuration {
        seconds: -1,
        fraction: 0,
    };
    assert_eq!(neg.to_std(), None);
    let max = RtpsDuration {
        seconds: i32::MAX,
        fraction: u32::MAX - 1,
    };
    assert!(max.to_std().unwrap().subsec_nanos() < 1_000_000_000);
}

#[test]
fn too_many_locators_are_capped() {
    let mut pl = Pl::new(true).guid(PID_PARTICIPANT_GUID, guid_of(X, ENTITYID_PARTICIPANT));
    for i in 0..40u8 {
        pl = pl.v4(PID_METATRAFFIC_UNICAST_LOCATOR, [10, 0, 0, i], 7410);
    }
    let d = dg(
        S,
        &[data(
            true,
            SPDP,
            None,
            Payload::Data(pl_payload(true, pl.end())),
        )],
    );
    let r = report(&d);
    assert_eq!(
        r.participants[0].metatraffic_unicast.len(),
        MAX_LOCATORS_PER_LIST
    );
    assert!(r.anomalies.contains(&Anomaly::TooManyLocators));
    assert!(r.anomalies.len() <= MAX_ANOMALIES);
    assert_eq!(r.stats.anomalies, 40 - MAX_LOCATORS_PER_LIST as u32);
}

// ---------------------------------------------------------------- INFO_SRC & attribution

#[test]
fn info_src_changes_source_for_following_submessages() {
    // SEDP without any GUID: falls back to the *current* source.
    let pl = Pl::new(true).string(PID_TOPIC_NAME, "rt/a").end();
    let anon = data(true, PUB, None, Payload::Data(pl_payload(true, pl)));
    for le in [true, false] {
        let d = dg(S, &[anon.clone(), info_src(le, X), anon.clone()]);
        let r = report(&d);
        assert_eq!(r.stats.info_src, 1);
        assert_eq!(r.sources, vec![S, X]);
        assert_eq!(r.endpoints[0].participant, S);
        assert_eq!(r.endpoints[1].participant, X);
        assert_eq!(r.endpoints[1].attribution, Attribution::SourcePrefix);
        assert_eq!(r.endpoints[1].source, X);
        let ev = r.to_events("10.0.0.1");
        assert_eq!(participants(&ev).len(), 2);
        assert_eq!(endpoints(&ev), 2);
    }
}

#[test]
fn info_src_unknown_prefix_is_not_a_participant() {
    let d = dg(S, &[info_src(true, GUIDPREFIX_UNKNOWN)]);
    assert_eq!(parse_datagram(&d, "x").len(), 1);
}

#[test]
fn info_src_back_to_header_prefix_dedupes() {
    let d = dg(
        S,
        &[info_src(true, X), info_src(false, S), info_src(true, X)],
    );
    let r = report(&d);
    assert_eq!(r.sources, vec![S, X]);
    assert_eq!(parse_datagram(&d, "x").len(), 2);
}

#[test]
fn truncated_info_src_keeps_old_source() {
    let pl = Pl::new(true).string(PID_TOPIC_NAME, "rt/a").end();
    let d = dg(
        S,
        &[
            submsg(SUBMSG_INFO_SRC, FLAG_E, &[0; 12]),
            data(true, PUB, None, Payload::Data(pl_payload(true, pl))),
        ],
    );
    let r = report(&d);
    assert!(r.anomalies.contains(&Anomaly::MalformedInfoSource));
    assert_eq!(r.endpoints[0].participant, S);
}

#[test]
fn relayed_sedp_is_attributed_to_endpoint_owner() {
    let ep = guid_of(X, W_ENT);
    let d = dg(S, &[sedp(true, PUB, ep, "rt/cmd_vel")]);
    let r = report(&d);
    let e = &r.endpoints[0];
    assert_eq!(e.participant, X);
    assert_eq!(e.guid, Some(ep));
    assert_eq!(e.attribution, Attribution::EndpointGuid);
    assert_eq!(e.source, S);
    assert!(e.relayed());
    match &r.to_events("x")[1] {
        RobotEvent::Ros2WriterDiscovered(w) => assert_eq!(w.guid_prefix, hex12(&X)),
        other => panic!("{other:?}"),
    }
    assert_eq!(hex_guid(&ep), format!("{}00001203", hex12(&X)));
}

#[test]
fn participant_guid_is_used_when_endpoint_guid_absent() {
    let pl = Pl::new(false)
        .guid(PID_PARTICIPANT_GUID, guid_of(X, ENTITYID_PARTICIPANT))
        .string(PID_TOPIC_NAME, "rt/odom")
        .end();
    let d = dg(
        S,
        &[data(true, SUB, None, Payload::Data(pl_payload(false, pl)))],
    );
    let r = report(&d);
    let e = &r.endpoints[0];
    assert_eq!(e.kind, EndpointKind::Reader);
    assert_eq!(e.participant, X);
    assert_eq!(e.attribution, Attribution::ParticipantGuid);
    assert_eq!(e.guid, None);
}

#[test]
fn conflicting_participant_guid_is_flagged_endpoint_guid_wins() {
    let pl = Pl::new(true)
        .guid(PID_PARTICIPANT_GUID, guid_of(S, ENTITYID_PARTICIPANT))
        .guid(PID_ENDPOINT_GUID, guid_of(X, W_ENT))
        .string(PID_TOPIC_NAME, "rt/cmd_vel")
        .end();
    let d = dg(
        S,
        &[data(true, PUB, None, Payload::Data(pl_payload(true, pl)))],
    );
    let r = report(&d);
    assert!(r.endpoints[0].guid_conflict);
    assert_eq!(r.endpoints[0].participant, X);
    assert_eq!(
        r.endpoints[0].participant_guid_param,
        Some(guid_of(S, ENTITYID_PARTICIPANT))
    );
    assert!(r.anomalies.contains(&Anomaly::EndpointParticipantMismatch));
}

#[test]
fn key_hash_is_used_when_no_guid_in_payload() {
    let q = Pl::new(true).guid(PID_KEY_HASH, guid_of(X, W_ENT)).end();
    let pl = Pl::new(true).string(PID_TOPIC_NAME, "rt/x").end();
    let d = dg(
        S,
        &[data(
            true,
            PUB,
            Some(q),
            Payload::Data(pl_payload(true, pl)),
        )],
    );
    let r = report(&d);
    assert_eq!(r.endpoints[0].participant, X);
    assert_eq!(r.endpoints[0].attribution, Attribution::KeyHash);
}

#[test]
fn key_hash_mismatch_is_flagged() {
    let q = Pl::new(true).guid(PID_KEY_HASH, guid_of(S, W_ENT)).end();
    let d = dg(
        S,
        &[data(
            true,
            PUB,
            Some(q),
            Payload::Data(sedp_payload(true, guid_of(X, W_ENT), "rt/x", "t")),
        )],
    );
    let r = report(&d);
    assert!(r.anomalies.contains(&Anomaly::KeyHashMismatch));
    assert_eq!(r.endpoints[0].participant, X);
}

#[test]
fn secure_sedp_writer_plaintext_is_decoded() {
    let d = dg(
        S,
        &[sedp(
            true,
            ENTITYID_SEDP_PUBLICATIONS_SECURE_WRITER,
            guid_of(X, W_ENT),
            "rt/x",
        )],
    );
    assert_eq!(report(&d).endpoints.len(), 1);
}

// ---------------------------------------------------------------- disposal

#[test]
fn disposed_endpoint_via_inline_qos_is_not_discovered() {
    for flags in [0x01u8, 0x02, 0x03] {
        let q = Pl::new(true)
            .guid(PID_KEY_HASH, guid_of(X, W_ENT))
            .status(flags)
            .end();
        let d = dg(S, &[data(true, PUB, Some(q), Payload::None)]);
        let r = report(&d);
        assert!(r.endpoints.is_empty());
        assert_eq!(r.removed_endpoints.len(), 1);
        let rm = &r.removed_endpoints[0];
        assert_eq!(rm.guid, Some(guid_of(X, W_ENT)));
        assert_eq!(rm.participant, X);
        assert_eq!(rm.kind, EndpointKind::Writer);
        assert_eq!(rm.status.disposed(), flags & 1 != 0);
        assert_eq!(rm.status.unregistered(), flags & 2 != 0);
        assert_eq!(endpoints(&parse_datagram(&d, "x")), 0);
    }
}

#[test]
fn disposed_with_full_data_is_still_a_removal() {
    let q = Pl::new(false).status(0x01).end();
    let d = dg(
        S,
        &[data(
            false,
            SUB,
            Some(q),
            Payload::Data(sedp_payload(false, guid_of(X, W_ENT), "rt/x", "t")),
        )],
    );
    let r = report(&d);
    assert!(r.endpoints.is_empty());
    assert_eq!(r.removed_endpoints[0].kind, EndpointKind::Reader);
    assert_eq!(
        r.removed_endpoints[0].attribution,
        Attribution::EndpointGuid
    );
}

#[test]
fn key_only_dispose_with_cdr_key() {
    for (encap, le) in [(CDR_BE, false), (CDR_LE, true)] {
        let q = Pl::new(le).status(0x02).end();
        let mut key = encap.to_be_bytes().to_vec();
        key.extend_from_slice(&[0, 0]);
        key.extend_from_slice(&guid_of(X, W_ENT));
        let d = dg(S, &[data(le, PUB, Some(q), Payload::Key(key))]);
        let r = report(&d);
        assert!(r.endpoints.is_empty());
        assert_eq!(r.removed_endpoints[0].guid, Some(guid_of(X, W_ENT)));
        assert_eq!(r.removed_endpoints[0].attribution, Attribution::KeyHash);
    }
}

#[test]
fn key_only_with_pl_cdr_key_and_no_status_is_ignored() {
    let key = pl_payload(
        true,
        Pl::new(true)
            .guid(PID_ENDPOINT_GUID, guid_of(X, W_ENT))
            .end(),
    );
    let d = dg(S, &[data(true, PUB, None, Payload::Key(key))]);
    let r = report(&d);
    assert!(r.endpoints.is_empty());
    assert!(r.removed_endpoints.is_empty());
    assert!(r.anomalies.is_empty());
}

#[test]
fn filtered_status_is_not_a_removal() {
    let q = Pl::new(true).status(0x04).end();
    let d = dg(
        S,
        &[data(
            true,
            PUB,
            Some(q),
            Payload::Data(sedp_payload(true, guid_of(X, W_ENT), "rt/x", "t")),
        )],
    );
    let r = report(&d);
    assert_eq!(r.endpoints.len(), 1);
    assert!(r.removed_endpoints.is_empty());
}

#[test]
fn spdp_dispose_of_other_participant_emits_no_discovery() {
    let q = Pl::new(true)
        .guid(PID_KEY_HASH, guid_of(X, ENTITYID_PARTICIPANT))
        .status(0x03)
        .end();
    let d = dg(S, &[data(true, SPDP, Some(q), Payload::None)]);
    let r = report(&d);
    assert!(r.participants.is_empty());
    assert_eq!(r.removed_participants[0].guid_prefix, X);
    assert_eq!(r.removed_participants[0].source, S);
    let ev = parse_datagram(&d, "x");
    assert_eq!(ev.len(), 1, "only the sender");
    assert_eq!(participants(&ev)[0].guid_prefix, hex12(&S));
}

#[test]
fn malformed_inline_qos_drops_the_sample() {
    let q = Pl::new(true).raw_len(PID_STATUS_INFO, 3, &[0, 0, 1]).end();
    let d = dg(
        S,
        &[data(
            true,
            PUB,
            Some(q),
            Payload::Data(sedp_payload(true, guid_of(X, W_ENT), "rt/x", "t")),
        )],
    );
    let r = report(&d);
    assert!(r.endpoints.is_empty());
    assert!(r.anomalies.contains(&Anomaly::MalformedParameterList));
}

// ---------------------------------------------------------------- submessage walk

#[test]
fn zero_length_info_ts_and_pad_do_not_swallow_the_rest() {
    let ep = guid_of(X, W_ENT);
    let d = dg(
        S,
        &[
            submsg(SUBMSG_INFO_TS, FLAG_E | 0x02, &[]), // I flag: no timestamp
            submsg(SUBMSG_PAD, 0, &[]),
            sedp(true, PUB, ep, "rt/cmd_vel"),
        ],
    );
    let r = report(&d);
    assert_eq!(r.stats.info_ts, 1);
    assert_eq!(r.stats.pad, 1);
    assert_eq!(r.endpoints.len(), 1);
}

#[test]
fn zero_length_last_submessage_extends_to_end() {
    let mut sub = sedp(false, PUB, guid_of(X, W_ENT), "rt/a");
    sub[2] = 0;
    sub[3] = 0;
    let d = dg(S, &[submsg(SUBMSG_INFO_DST, 0, &X), sub]);
    let r = report(&d);
    assert_eq!(r.stats.info_dst, 1);
    assert_eq!(r.endpoints.len(), 1);
}

#[test]
fn control_secure_vendor_and_unknown_submessages_are_skipped() {
    let d = dg(
        S,
        &[
            submsg(SUBMSG_HEARTBEAT, FLAG_E, &[0; 28]),
            submsg(SUBMSG_ACKNACK, 0, &[0; 24]),
            submsg(0x30, FLAG_E, &[0xaa; 40]),
            submsg(0x31, FLAG_E, &[0xaa; 8]),
            submsg(0x80, FLAG_E, &[0xbb; 12]),
            submsg(0xff, 0, &[]), // len 0, not PAD/INFO_TS: to end of message...
        ],
    );
    let r = report(&d);
    assert_eq!(r.stats.other, 2);
    assert_eq!(r.stats.secure, 2);
    assert_eq!(r.stats.vendor_specific, 2);
    assert_eq!(r.stats.submessages, 6);
    // ...and things after a vendor submessage are still parsed.
    let d = dg(
        S,
        &[
            submsg(0x80, FLAG_E, &[0xbb; 12]),
            submsg(0x42, FLAG_E, &[0; 4]),
            sedp(true, PUB, guid_of(X, W_ENT), "rt/a"),
        ],
    );
    let r = report(&d);
    assert_eq!(r.stats.unknown, 1);
    assert_eq!(r.endpoints.len(), 1);
}

#[test]
fn trailing_partial_submessage_header_is_an_anomaly() {
    let mut d = dg(S, &[sedp(true, PUB, guid_of(X, W_ENT), "rt/a")]);
    d.extend_from_slice(&[SUBMSG_DATA, 1]);
    let r = report(&d);
    assert_eq!(r.endpoints.len(), 1);
    assert_eq!(r.anomalies, vec![Anomaly::TruncatedSubmessage]);
}

#[test]
fn unsupported_major_version_reports_sender_only() {
    let mut d = header_v(S, [1, 0]);
    d.extend(sedp(true, PUB, guid_of(X, W_ENT), "rt/a"));
    let r = report(&d);
    assert!(r.endpoints.is_empty());
    assert_eq!(r.anomalies, vec![Anomaly::UnsupportedProtocolVersion(1, 0)]);
    assert_eq!(r.header.vendor_name(), Some("eProsima Fast DDS"));
    assert_eq!(parse_datagram(&d, "x").len(), 1);
}

#[test]
fn non_rtps_detailed_is_none() {
    assert!(parse_datagram_detailed(b"RTPX\x02\x03\x01\x0f000000000000").is_none());
    assert!(parse_datagram_detailed(b"").is_none());
    assert!(parse_datagram_detailed(b"RTPS\x02\x03\x01\x0f").is_none());
}

#[test]
fn octets_to_inline_qos_rules() {
    // Too small: rejected.
    let mut sub = sedp(true, PUB, guid_of(X, W_ENT), "rt/a");
    sub[6..8].copy_from_slice(&12u16.to_le_bytes());
    let r = report(&dg(S, &[sub]));
    assert!(r.endpoints.is_empty());
    assert!(r.anomalies.contains(&Anomaly::BadOctetsToInlineQos));

    // Larger than 16 (future fields): honoured.
    let mut body = vec![0, 0];
    body.extend_from_slice(&20u16.to_le_bytes());
    body.extend_from_slice(&[0; 4]);
    body.extend_from_slice(&PUB);
    body.extend_from_slice(&[0; 8]);
    body.extend_from_slice(&[0xee; 4]); // unknown extra field
    body.extend(sedp_payload(true, guid_of(X, W_ENT), "rt/b", "t"));
    let r = report(&dg(S, &[submsg(SUBMSG_DATA, FLAG_E | FLAG_D, &body)]));
    assert_eq!(r.endpoints[0].topic, "rt/b");

    // Past the end of the body.
    let mut sub = sedp(true, PUB, guid_of(X, W_ENT), "rt/a");
    sub[6..8].copy_from_slice(&u16::MAX.to_le_bytes());
    let r = report(&dg(S, &[sub]));
    assert!(r.endpoints.is_empty());
    assert!(r.anomalies.contains(&Anomaly::MalformedData));
}

#[test]
fn inline_qos_before_payload_is_skipped_correctly() {
    for le in [true, false] {
        let q = Pl::new(le)
            .raw(0x0070, &[1; 16])
            .raw(0x8001, &[0; 8]) // vendor-specific
            .end();
        let d = dg(
            S,
            &[data(
                le,
                PUB,
                Some(q),
                Payload::Data(sedp_payload(!le, guid_of(X, W_ENT), "rt/q", "t")),
            )],
        );
        let r = report(&d);
        assert_eq!(r.endpoints[0].topic, "rt/q");
        assert!(r.anomalies.contains(&Anomaly::KeyHashMismatch));
    }
}

// ---------------------------------------------------------------- parameter strictness

#[test]
fn misaligned_or_unterminated_parameter_list_is_rejected() {
    let bad = Pl::new(true)
        .guid(PID_ENDPOINT_GUID, guid_of(X, W_ENT))
        .raw_len(PID_TOPIC_NAME, 10, b"\x05\0\0\0rt/a\0\0")
        .end();
    let unterminated = Pl::new(true)
        .guid(PID_ENDPOINT_GUID, guid_of(X, W_ENT))
        .string(PID_TOPIC_NAME, "rt/a")
        .no_sentinel();
    for pl in [bad, unterminated] {
        let d = dg(
            S,
            &[data(true, PUB, None, Payload::Data(pl_payload(true, pl)))],
        );
        let r = report(&d);
        assert!(r.endpoints.is_empty());
        assert_eq!(r.anomalies, vec![Anomaly::MalformedParameterList]);
    }
}

#[test]
fn extended_pid_is_unsupported() {
    let pl = Pl::new(true)
        .raw(PID_EXTENDED, &[0; 8])
        .string(PID_TOPIC_NAME, "rt/a")
        .end();
    let r = report(&dg(
        S,
        &[data(true, PUB, None, Payload::Data(pl_payload(true, pl)))],
    ));
    assert!(r.endpoints.is_empty());
    assert_eq!(r.anomalies, vec![Anomaly::UnsupportedParameter]);
}

#[test]
fn duplicate_parameters_first_wins() {
    let pl = Pl::new(true)
        .string(PID_TOPIC_NAME, "rt/chatter")
        .string(PID_TOPIC_NAME, "rt/chatter")
        .string(PID_TOPIC_NAME, "rt/cmd_vel")
        .end();
    let r = report(&dg(
        S,
        &[data(true, PUB, None, Payload::Data(pl_payload(true, pl)))],
    ));
    assert_eq!(r.endpoints[0].topic, "rt/chatter");
    assert_eq!(
        r.anomalies,
        vec![Anomaly::ConflictingDuplicateParameter(PID_TOPIC_NAME)]
    );
}

#[test]
fn unsupported_encapsulation_is_reported() {
    for encap in [CDR_LE, 0x000b /* PL_CDR2_LE */, 0xffff] {
        let mut p = encap.to_be_bytes().to_vec();
        p.extend_from_slice(&[0, 0]);
        p.extend(Pl::new(true).string(PID_TOPIC_NAME, "rt/a").end());
        let r = report(&dg(S, &[data(true, PUB, None, Payload::Data(p))]));
        assert!(r.endpoints.is_empty());
        assert_eq!(r.anomalies, vec![Anomaly::UnsupportedEncapsulation(encap)]);
    }
    // Payload too short to hold an encapsulation id.
    let r = report(&dg(S, &[data(true, PUB, None, Payload::Data(vec![0]))]));
    assert_eq!(r.anomalies, vec![Anomaly::MalformedData]);
}

#[test]
fn announcement_without_valid_topic() {
    let pl = Pl::new(true)
        .guid(PID_ENDPOINT_GUID, guid_of(X, W_ENT))
        .raw(PID_TOPIC_NAME, b"\x04\0\0\0rt/a") // no NUL
        .raw(PID_ENDPOINT_GUID, &[1; 8]) // too short (and duplicate)
        .end();
    let r = report(&dg(
        S,
        &[data(true, PUB, None, Payload::Data(pl_payload(true, pl)))],
    ));
    assert!(r.endpoints.is_empty());
    assert_eq!(
        r.anomalies,
        vec![
            Anomaly::BadParameterValue(PID_TOPIC_NAME),
            Anomaly::BadParameterValue(PID_ENDPOINT_GUID),
            Anomaly::AnnouncementWithoutTopic
        ]
    );
}

#[test]
fn anomalies_are_capped() {
    let mut pl = Pl::new(true);
    for _ in 0..200 {
        pl = pl.raw(PID_TOPIC_NAME, &[0; 4]);
    }
    let r = report(&dg(
        S,
        &[data(
            true,
            PUB,
            None,
            Payload::Data(pl_payload(true, pl.end())),
        )],
    ));
    assert_eq!(r.anomalies.len(), MAX_ANOMALIES);
    assert_eq!(r.stats.anomalies, 201);
}

#[test]
fn events_list_participants_before_endpoints() {
    let d = dg(
        S,
        &[
            sedp(true, PUB, guid_of(S, W_ENT), "rt/a"),
            info_src(true, X),
            sedp(true, SUB, guid_of(X, W_ENT), "rt/b"),
            data(true, SPDP, None, Payload::Data(spdp_payload(true, X))),
        ],
    );
    let ev = parse_datagram(&d, "x");
    assert_eq!(ev.len(), 4);
    assert!(matches!(ev[0], RobotEvent::Ros2ParticipantDiscovered(_)));
    assert!(matches!(&ev[1], RobotEvent::Ros2ParticipantDiscovered(p) if p.locators.len() == 2));
    assert!(matches!(ev[2], RobotEvent::Ros2WriterDiscovered(_)));
    assert!(matches!(ev[3], RobotEvent::Ros2ReaderDiscovered(_)));
}

// ---------------------------------------------------------------- DATA_FRAG

fn frag_pieces(le: bool, payload: &[u8], fs: u16, writer: [u8; 4], sn: u32) -> Vec<Vec<u8>> {
    payload
        .chunks(fs as usize)
        .enumerate()
        .map(|(i, c)| {
            data_frag(
                le,
                writer,
                sn,
                i as u32 + 1,
                1,
                fs,
                payload.len() as u32,
                None,
                c,
            )
        })
        .collect()
}

#[test]
fn data_frag_is_counted_without_reassembler() {
    let payload = sedp_payload(true, guid_of(X, W_ENT), "rt/big", "T");
    let frags = frag_pieces(true, &payload, 32, PUB, 1);
    let d = dg(S, &frags);
    let r = report(&d);
    assert!(r.fragmented_discovery_seen());
    assert_eq!(r.stats.data_frag as usize, frags.len());
    assert_eq!(r.stats.discovery_data_frag as usize, frags.len());
    assert!(r.endpoints.is_empty());

    // User-data fragments are not "discovery".
    let d = dg(S, &[data_frag(true, W_ENT, 1, 1, 1, 4, 8, None, &[0; 4])]);
    let r = report(&d);
    assert_eq!(r.stats.data_frag, 1);
    assert!(!r.fragmented_discovery_seen());
}

#[test]
fn data_frag_reassembles_across_datagrams_both_endians() {
    for le in [true, false] {
        let payload = sedp_payload(
            !le,
            guid_of(X, W_ENT),
            "rt/big_topic_name",
            "pkg::msg::dds_::Big_",
        );
        let frags = frag_pieces(le, &payload, 24, PUB, 9);
        let (a, b) = frags.split_at(frags.len() / 2);
        let mut ra = FragmentReassembler::new(ReassemblyLimits::default());
        // Second half first: order does not matter.
        let r1 = ra.parse_datagram_detailed(&dg(S, b)).unwrap();
        assert!(r1.endpoints.is_empty());
        assert_eq!(ra.pending_samples(), 1);
        let ev = ra.parse_datagram(&dg(S, a), "10.0.0.3");
        assert_eq!(ra.pending_samples(), 0);
        assert_eq!(ra.completed(), 1);
        match &ev[1] {
            RobotEvent::Ros2WriterDiscovered(e) => {
                assert_eq!(e.topic, "rt/big_topic_name");
                assert_eq!(e.guid_prefix, hex12(&X));
            }
            other => panic!("{other:?}"),
        }
    }
}

#[test]
fn data_frag_spdp_and_dispose_through_reassembler() {
    let mut ra = FragmentReassembler::new(ReassemblyLimits::default());
    let payload = spdp_payload(true, X);
    let r = ra
        .parse_datagram_detailed(&dg(S, &frag_pieces(true, &payload, 64, SPDP, 1)))
        .unwrap();
    assert_eq!(r.stats.frag_completed, 1);
    assert!(r.participants[0].from_fragments);
    assert_eq!(r.participants[0].guid_prefix, X);

    // Fragmented SEDP carrying a disposed status in the first fragment's QoS.
    let payload = sedp_payload(true, guid_of(X, W_ENT), "rt/a", "t");
    let n = payload.len() as u32;
    let q = Pl::new(true).status(0x01).end();
    let f1 = data_frag(true, PUB, 2, 1, 1, 40, n, Some(q), &payload[..40]);
    let f2 = data_frag(true, PUB, 2, 2, 1, 40, n, None, &payload[40..]);
    let r = ra.parse_datagram_detailed(&dg(S, &[f1, f2])).unwrap();
    assert!(r.endpoints.is_empty());
    assert_eq!(r.removed_endpoints.len(), 1);
}

#[test]
fn data_frag_from_different_sources_do_not_mix() {
    let payload = sedp_payload(true, guid_of(X, W_ENT), "rt/a", "t");
    let frags = frag_pieces(true, &payload, 32, PUB, 1);
    let mut ra = FragmentReassembler::new(ReassemblyLimits::default());
    ra.parse_datagram(&dg(S, &frags[..1]), "x");
    // Same writer id and SN but from another source (INFO_SRC): separate sample.
    let mut subs = vec![info_src(true, X)];
    subs.extend_from_slice(&frags[1..]);
    let r = ra.parse_datagram_detailed(&dg(S, &subs)).unwrap();
    assert!(r.endpoints.is_empty());
    assert_eq!(ra.pending_samples(), 2);
}

#[test]
fn data_frag_hostile_headers() {
    let mut ra = FragmentReassembler::new(ReassemblyLimits::default());
    let cases = vec![
        data_frag(true, PUB, 1, 1, 1, 4, u32::MAX, None, &[0; 4]), // 4 GiB claim
        data_frag(true, PUB, 1, 0, 1, 4, 8, None, &[0; 4]),        // fragment 0
        data_frag(true, PUB, 1, 1, 1, 0, 8, None, &[0; 4]),        // size 0
        data_frag(true, PUB, 1, 1, 9, 4, 8, None, &[0; 4]),        // too many
        data_frag(true, PUB, 1, 1, 2, 4, 8, None, &[0; 4]),        // short data
    ];
    let r = ra.parse_datagram_detailed(&dg(S, &cases)).unwrap();
    assert_eq!(r.stats.frag_rejected, 5);
    assert_eq!(ra.pending_bytes(), 0);

    // Short DATA_FRAG body and bad octetsToInlineQos.
    let short = submsg(SUBMSG_DATA_FRAG, FLAG_E, &[0; 20]);
    let mut bad_oti = data_frag(true, PUB, 1, 1, 1, 4, 8, None, &[0; 4]);
    bad_oti[6..8].copy_from_slice(&16u16.to_le_bytes());
    let r = ra
        .parse_datagram_detailed(&dg(S, &[short, bad_oti]))
        .unwrap();
    assert_eq!(
        r.anomalies,
        vec![Anomaly::MalformedDataFrag, Anomaly::BadOctetsToInlineQos]
    );
}

#[test]
fn reassembler_memory_stays_bounded_under_flood() {
    let limits = ReassemblyLimits {
        max_sample_bytes: 8 * 1024,
        max_pending_samples: 8,
        max_total_bytes: 32 * 1024,
    };
    let mut ra = FragmentReassembler::new(limits);
    for sn in 0..500u32 {
        let d = dg(
            S,
            &[data_frag(
                true,
                PUB,
                sn,
                1,
                1,
                1024,
                8 * 1024,
                None,
                &[0xab; 1024],
            )],
        );
        ra.parse_datagram(&d, "x");
        assert!(ra.pending_bytes() <= 32 * 1024);
        assert!(ra.pending_samples() <= 8);
    }
    // User-data fragments never take memory.
    let mut ra = FragmentReassembler::new(limits);
    let d = dg(
        S,
        &[data_frag(
            true, W_ENT, 1, 1, 1, 1024, 4096, None, &[0; 1024],
        )],
    );
    ra.parse_datagram(&d, "x");
    assert_eq!(ra.pending_samples(), 0);
}

// ---------------------------------------------------------------- fuzz

/// xorshift64*: deterministic, std-only.
struct Rng(u64);

impl Rng {
    fn next(&mut self) -> u64 {
        self.0 ^= self.0 >> 12;
        self.0 ^= self.0 << 25;
        self.0 ^= self.0 >> 27;
        self.0.wrapping_mul(0x2545_f491_4f6c_dd1d)
    }
    fn below(&mut self, n: usize) -> usize {
        if n == 0 {
            0
        } else {
            (self.next() % n as u64) as usize
        }
    }
}

fn seeds() -> Vec<Vec<u8>> {
    let ep = guid_of(X, W_ENT);
    let spdp_pl = spdp_payload(true, X);
    let mut v = vec![
        dg(S, &[sedp(true, PUB, ep, "rt/cmd_vel")]),
        dg(S, &[sedp(false, SUB, ep, "rt/odom")]),
        dg(
            S,
            &[data(
                false,
                SPDP,
                None,
                Payload::Data(spdp_payload(false, S)),
            )],
        ),
        dg(
            S,
            &[
                info_src(true, X),
                data(true, SPDP, None, Payload::Data(spdp_pl.clone())),
            ],
        ),
        dg(
            S,
            &[data(
                true,
                PUB,
                Some(Pl::new(true).guid(PID_KEY_HASH, ep).status(3).end()),
                Payload::None,
            )],
        ),
        dg(
            S,
            &[
                submsg(SUBMSG_INFO_TS, FLAG_E, &[1, 2, 3, 4, 5, 6, 7, 8]),
                submsg(SUBMSG_INFO_DST, FLAG_E, &X),
                sedp(true, PUB, ep, "rt/a"),
            ],
        ),
    ];
    let frags = frag_pieces(true, &spdp_pl, 48, SPDP, 3);
    v.push(dg(S, &frags));
    v.push(dg(S, &frags[1..]));
    v
}

fn mutate(rng: &mut Rng, d: &mut Vec<u8>) {
    const INTERESTING: [u8; 8] = [0x00, 0x01, 0x03, 0x7f, 0x80, 0xc2, 0xfe, 0xff];
    for _ in 0..1 + rng.below(4) {
        match rng.below(7) {
            0 if !d.is_empty() => {
                let i = rng.below(d.len());
                d[i] ^= 1 << rng.below(8);
            }
            1 if !d.is_empty() => {
                let i = rng.below(d.len());
                d[i] = INTERESTING[rng.below(INTERESTING.len())];
            }
            2 => {
                let n = rng.below(d.len() + 1);
                d.truncate(n);
            }
            3 => {
                let i = rng.below(d.len() + 1);
                let n = rng.below(16);
                for k in 0..n {
                    d.insert(i + k, rng.next() as u8);
                }
            }
            4 if d.len() > 4 => {
                // Overwrite a 16-bit field (lengths!) with an extreme value.
                let i = rng.below(d.len() - 1);
                let v = [0u16, 1, 3, 4, 0x7fff, 0xfffc, 0xffff][rng.below(7)];
                d[i..i + 2].copy_from_slice(&v.to_le_bytes());
            }
            5 if d.len() > 8 => {
                // Duplicate a chunk (repeated submessages / parameters).
                let a = rng.below(d.len());
                let b = (a + rng.below(64)).min(d.len());
                let chunk = d[a..b].to_vec();
                let at = rng.below(d.len());
                d.splice(at..at, chunk);
            }
            _ => {
                if d.len() > 20 {
                    // Keep the header valid more often than not.
                    d[..4].copy_from_slice(b"RTPS");
                }
            }
        }
    }
}

#[test]
fn mutation_fuzz_never_panics() {
    let limits = ReassemblyLimits {
        max_sample_bytes: 4096,
        max_pending_samples: 4,
        max_total_bytes: 8192,
    };
    let mut ra = FragmentReassembler::new(limits);
    let mut rng = Rng(0x9e37_79b9_7f4a_7c15);
    let seeds = seeds();
    for iter in 0..6000 {
        let mut d = seeds[iter % seeds.len()].clone();
        mutate(&mut rng, &mut d);
        let ev = parse_datagram(&d, "10.0.0.1");
        if let Some(r) = parse_datagram_detailed(&d) {
            assert!(r.anomalies.len() <= MAX_ANOMALIES);
            assert_eq!(r.to_events("10.0.0.1"), ev);
        } else {
            assert!(ev.is_empty());
        }
        let _ = ra.parse_datagram_detailed(&d);
        assert!(ra.pending_bytes() <= limits.max_total_bytes);
        assert!(ra.pending_samples() <= limits.max_pending_samples);
    }
    // Pure random bytes behind a valid header.
    for _ in 0..2000 {
        let mut d = header(S);
        let n = rng.below(256);
        d.extend((0..n).map(|_| rng.next() as u8));
        let _ = parse_datagram(&d, "x");
        let _ = ra.parse_datagram(&d, "x");
    }
}

#[test]
fn every_truncation_of_every_seed_is_safe() {
    let mut ra = FragmentReassembler::new(ReassemblyLimits::default());
    for s in seeds() {
        for cut in 0..=s.len() {
            let _ = parse_datagram(&s[..cut], "x");
            let _ = ra.parse_datagram(&s[..cut], "x");
        }
    }
}
