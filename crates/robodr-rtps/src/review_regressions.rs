//! Regression tests for the independent parser review. Each test is the
//! reviewer's proof of concept, inverted: it asserts the *fixed* behaviour.

use std::time::{Duration, Instant};

use robodr_events::profile::{Envelope, Profile};
use robodr_events::{RobotEvent, Severity};

use crate::testutil::*;
use crate::wire::*;
use crate::*;

const ATT: [u8; 12] = [0xaa; 12]; // attacker header prefix
const LEGIT: [u8; 12] = [0x11; 12]; // profiled participant (e.g. nav2)
const PUB: [u8; 4] = ENTITYID_SEDP_PUBLICATIONS_WRITER;
const ROGUE_ENT: [u8; 4] = [0, 0, 0x77, 0x03];

fn dg(prefix: [u8; 12], subs: &[Vec<u8>]) -> Vec<u8> {
    let mut d = header(prefix);
    for s in subs {
        d.extend_from_slice(s);
    }
    d
}

fn writer_topics(ev: &[RobotEvent]) -> Vec<(String, String)> {
    ev.iter()
        .filter_map(|e| match e {
            RobotEvent::Ros2WriterDiscovered(w) => Some((w.guid_prefix.clone(), w.topic.clone())),
            _ => None,
        })
        .collect()
}

fn has_writer(ev: &[RobotEvent], prefix: [u8; 12], topic: &str) -> bool {
    writer_topics(ev).contains(&(hex12(&prefix), topic.to_string()))
}

/// F1: one DATA_FRAG carrying the whole sample is decoded by the stateless
/// parser too, and so are several fragments of one sample in one datagram.
#[test]
fn single_data_frag_writer_is_seen_stateless_and_stateful() {
    let payload = sedp_payload(
        true,
        guid_of(ATT, ROGUE_ENT),
        "rt/cmd_vel",
        "geometry_msgs::msg::dds_::Twist_",
    );
    let n = payload.len() as u32;
    let f = data_frag(true, PUB, 1, 1, 1, n as u16, n, None, &payload);
    let ev = parse_datagram(&dg(ATT, std::slice::from_ref(&f)), "10.0.0.66");
    assert!(has_writer(&ev, ATT, "rt/cmd_vel"), "{ev:?}");
    let r = parse_datagram_detailed(&dg(ATT, std::slice::from_ref(&f))).unwrap();
    assert!(r.fragmented_discovery_seen());
    assert!(r.endpoints[0].from_fragments);

    let mut ra = FragmentReassembler::new(ReassemblyLimits::default());
    let ev2 = ra.parse_datagram(&dg(ATT, &[f]), "10.0.0.66");
    assert!(has_writer(&ev2, ATT, "rt/cmd_vel"));
    assert_eq!(
        ra.pending_samples(),
        0,
        "whole samples never enter the table"
    );

    // Several DATA_FRAGs of one sample, all in one datagram, stateless.
    let fs = 24u16;
    let frags: Vec<Vec<u8>> = payload
        .chunks(fs as usize)
        .enumerate()
        .map(|(i, c)| data_frag(true, PUB, 2, i as u32 + 1, 1, fs, n, None, c))
        .collect();
    assert!(frags.len() > 2);
    let ev3 = parse_datagram(&dg(ATT, &frags), "10.0.0.66");
    assert!(has_writer(&ev3, ATT, "rt/cmd_vel"));
    // Spread over two datagrams, only the stateful reassembler gets it.
    let (a, b) = frags.split_at(1);
    assert!(writer_topics(&parse_datagram(&dg(ATT, a), "x")).is_empty());
    assert!(writer_topics(&parse_datagram(&dg(ATT, b), "x")).is_empty());
}

/// F2a: 16 junk partial samples under spoofed prefixes in the same datagram
/// do not evict the attacker's own in-progress SEDP sample.
#[test]
fn fragment_eviction_flood_in_same_datagram_does_not_hide_the_sample() {
    let payload = sedp_payload(true, guid_of(ATT, ROGUE_ENT), "rt/cmd_vel", "T");
    let half = payload.len() / 2 / 4 * 4;
    let n = payload.len() as u32;
    let fs = half as u16;
    let f1 = data_frag(true, PUB, 1, 1, 1, fs, n, None, &payload[..half]);
    let rest = &payload[half..];
    let nfr = payload.len().div_ceil(half);
    let mut subs = vec![f1];
    // More junk sources than the default table holds (256 pending).
    for i in 0..300u16 {
        let mut src = [0x11; 12];
        src[..2].copy_from_slice(&(i + 1).to_be_bytes());
        subs.push(info_src(true, src));
        subs.push(data_frag(true, PUB, 1, 1, 1, 4, 8, None, &[0; 4]));
    }
    subs.push(info_src(true, ATT));
    for k in 1..nfr {
        let lo = (k - 1) * half;
        let hi = (lo + half).min(rest.len());
        subs.push(data_frag(
            true,
            PUB,
            1,
            k as u32 + 1,
            1,
            fs,
            n,
            None,
            &rest[lo..hi],
        ));
    }
    let d = dg(ATT, &subs);
    for stateful in [true, false] {
        let mut ra = FragmentReassembler::new(ReassemblyLimits::default());
        let r = if stateful {
            ra.parse_datagram_detailed(&d).unwrap()
        } else {
            parse_datagram_detailed(&d).unwrap()
        };
        assert!(has_writer(&r.to_events("x"), ATT, "rt/cmd_vel"));
        // The junk was evicted (and reported), never the real sample.
        assert!(r.stats.frag_evicted >= 1);
        assert!(r.anomalies.contains(&Anomaly::DiscoveryFragmentEvicted));
        assert!(r
            .fragment_events
            .iter()
            .filter(|e| matches!(e.kind, FragmentEventKind::Evicted(_)))
            .all(|e| e.source != ATT));
    }
}

/// F2b: a conflicting duplicate of fragment 1 no longer drops the sample:
/// the first copy is kept (as a DDS stack does), the conflict is reported,
/// and the remaining fragments complete it.
#[test]
fn conflicting_duplicate_fragment_keeps_first_copy_and_completes() {
    let payload = sedp_payload(true, guid_of(ATT, ROGUE_ENT), "rt/cmd_vel", "T");
    let n = payload.len() as u32;
    let half = (payload.len() / 2 / 4 * 4) as u16;
    let h = half as usize;
    let f1 = data_frag(true, PUB, 1, 1, 1, half, n, None, &payload[..h]);
    let f1_bad = data_frag(true, PUB, 1, 1, 1, half, n, None, &vec![0x41; h]);
    let mut rest = vec![];
    let mut k = 1;
    let mut lo = h;
    while lo < payload.len() {
        let hi = (lo + h).min(payload.len());
        rest.push(data_frag(
            true,
            PUB,
            1,
            k + 1,
            1,
            half,
            n,
            None,
            &payload[lo..hi],
        ));
        k += 1;
        lo = hi;
    }
    let mut ra = FragmentReassembler::new(ReassemblyLimits::default());
    let r1 = ra.parse_datagram_detailed(&dg(ATT, &[f1, f1_bad])).unwrap();
    assert!(r1.endpoints.is_empty());
    assert_eq!(r1.stats.frag_conflicts, 1);
    assert!(r1
        .anomalies
        .contains(&Anomaly::ConflictingDiscoveryFragment));
    assert_eq!(
        r1.fragment_events[0].kind,
        FragmentEventKind::ConflictingOverlap
    );
    let ev = ra.parse_datagram(&dg(ATT, &rest), "x");
    assert!(has_writer(&ev, ATT, "rt/cmd_vel"), "sample completes");
    assert_eq!(ra.conflicts(), 1);
}

fn locked_profile() -> Profile {
    let mut p = Profile {
        model: "ugv".into(),
        locked: true,
        ..Default::default()
    };
    p.participants.insert(hex12(&LEGIT));
    p.writer_topics.insert("/cmd_vel".into());
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

/// F3: an SEDP announcement sent by ATT that names LEGIT's prefix in
/// `PID_ENDPOINT_GUID` is also attributed to its sender, so the profile
/// raises the Critical motion-writer deviation against ATT. Same through
/// INFO_SRC.
#[test]
fn rogue_writer_naming_a_profiled_participant_is_attributed_to_its_sender() {
    let s = data(
        true,
        PUB,
        None,
        Payload::Data(sedp_payload(
            true,
            guid_of(LEGIT, ROGUE_ENT),
            "rt/cmd_vel",
            "T",
        )),
    );
    let profile = locked_profile();
    for d in [
        dg(ATT, std::slice::from_ref(&s)),
        dg(LEGIT, &[info_src(true, ATT), s.clone()]),
    ] {
        let ev = parse_datagram(&d, "10.0.0.66");
        assert!(has_writer(&ev, LEGIT, "rt/cmd_vel"));
        assert!(has_writer(&ev, ATT, "rt/cmd_vel"));
        let devs: Vec<_> = ev.iter().filter_map(|e| profile.evaluate(e)).collect();
        assert!(devs
            .iter()
            .any(|d| d.rule == "robot.ros2.unauthorized_motion_writer"
                && d.severity == Severity::Critical));
    }
    // A participant announcing its own endpoint gets exactly one event.
    let own = data(
        true,
        PUB,
        None,
        Payload::Data(sedp_payload(
            true,
            guid_of(LEGIT, ROGUE_ENT),
            "rt/cmd_vel",
            "T",
        )),
    );
    let ev = parse_datagram(&dg(LEGIT, &[own]), "10.0.0.5");
    assert_eq!(writer_topics(&ev).len(), 1);
}

/// F3, documented limit: with the header prefix spoofed as well, the bytes
/// are identical to LEGIT's own; only the source IP differs, and it is
/// carried in the participant event for the consumer to check.
#[test]
fn fully_spoofed_prefix_is_only_distinguishable_by_source_ip() {
    let s = data(
        true,
        PUB,
        None,
        Payload::Data(sedp_payload(
            true,
            guid_of(LEGIT, ROGUE_ENT),
            "rt/cmd_vel",
            "T",
        )),
    );
    let ev = parse_datagram(&dg(LEGIT, &[s]), "10.0.0.66");
    assert_eq!(
        writer_topics(&ev),
        vec![(hex12(&LEGIT), "rt/cmd_vel".to_string())]
    );
    assert!(ev.iter().any(|e| matches!(e,
        RobotEvent::Ros2ParticipantDiscovered(p)
            if p.guid_prefix == hex12(&LEGIT) && p.src_ip == "10.0.0.66")));
}

/// F4a: a duplicated `PID_TOPIC_NAME` yields an event for every value, so
/// the topic a last-wins stack registers (`rt/cmd_vel`) is seen.
#[test]
fn duplicate_topic_yields_every_reading() {
    let pl = Pl::new(true)
        .guid(PID_ENDPOINT_GUID, guid_of(ATT, ROGUE_ENT))
        .string(PID_TOPIC_NAME, "rt/chatter")
        .string(PID_TOPIC_NAME, "rt/cmd_vel")
        .string(PID_TYPE_NAME, "T")
        .end();
    let s = data(true, PUB, None, Payload::Data(pl_payload(true, pl)));
    let d = dg(ATT, &[s]);
    let ev = parse_datagram(&d, "x");
    assert!(has_writer(&ev, ATT, "rt/chatter"));
    assert!(has_writer(&ev, ATT, "rt/cmd_vel"));
    let r = parse_datagram_detailed(&d).unwrap();
    assert!(r.endpoints[0].ambiguous());
    assert_eq!(r.endpoints[0].topics, vec!["rt/chatter", "rt/cmd_vel"]);
    assert!(r
        .anomalies
        .contains(&Anomaly::ConflictingDuplicateParameter(PID_TOPIC_NAME)));
}

/// F4b: a topic CDR string with an interior NUL is read the way a C-string
/// based stack reads it (`rt/cmd_vel`) and flagged, not dropped.
#[test]
fn topic_with_interior_nul_is_surfaced_and_flagged() {
    let mut v = 13u32.to_le_bytes().to_vec();
    v.extend_from_slice(b"rt/cmd_vel\0x\0");
    let pl = Pl::new(true)
        .guid(PID_ENDPOINT_GUID, guid_of(ATT, ROGUE_ENT))
        .raw(PID_TOPIC_NAME, &v)
        .string(PID_TYPE_NAME, "T")
        .end();
    let s = data(true, PUB, None, Payload::Data(pl_payload(true, pl)));
    let d = dg(ATT, &[s]);
    assert!(has_writer(&parse_datagram(&d, "x"), ATT, "rt/cmd_vel"));
    let r = parse_datagram_detailed(&d).unwrap();
    assert!(r
        .anomalies
        .contains(&Anomaly::NonCanonicalString(PID_TOPIC_NAME)));
    assert!(!r.anomalies.contains(&Anomaly::AnnouncementWithoutTopic));
}

/// F4c: a parameter length that is not a multiple of 4 is accepted
/// (DDSI-RTPS §9.4.2.11 is violated, but a lenient stack reads on) and
/// flagged.
#[test]
fn unaligned_parameter_length_is_accepted_and_flagged() {
    let mut v = 11u32.to_le_bytes().to_vec();
    v.extend_from_slice(b"rt/cmd_vel\0"); // 15 bytes, no padding
    let pl = Pl::new(true)
        .guid(PID_ENDPOINT_GUID, guid_of(ATT, ROGUE_ENT))
        .raw_len(PID_TOPIC_NAME, 15, &v)
        .end();
    let s = data(true, PUB, None, Payload::Data(pl_payload(true, pl)));
    let r = parse_datagram_detailed(&dg(ATT, &[s])).unwrap();
    assert_eq!(r.endpoints.len(), 1);
    assert_eq!(r.endpoints[0].topic, "rt/cmd_vel");
    assert!(r.anomalies.contains(&Anomaly::MisalignedParameterLength));
    assert!(!r.anomalies.contains(&Anomaly::MalformedParameterList));
}

/// F5: an unknown protocol major version is flagged and still parsed.
#[test]
fn unknown_major_version_is_parsed_and_flagged() {
    let s = data(
        true,
        PUB,
        None,
        Payload::Data(sedp_payload(
            true,
            guid_of(ATT, ROGUE_ENT),
            "rt/cmd_vel",
            "T",
        )),
    );
    for v in [[3, 0], [1, 0], [0xff, 0xff]] {
        let mut d = header_v(ATT, v);
        d.extend_from_slice(&s);
        assert!(has_writer(&parse_datagram(&d, "x"), ATT, "rt/cmd_vel"));
        let r = parse_datagram_detailed(&d).unwrap();
        assert!(r
            .anomalies
            .contains(&Anomaly::UnsupportedProtocolVersion(v[0], v[1])));
    }
}

/// A datagram of `n` INFO_SRC: distinct prefixes, or alternating between
/// two (same size and submessage count, nothing to index).
fn info_src_flood(n: u32, distinct: bool) -> Vec<u8> {
    let mut d = header(ATT);
    for i in 0..n {
        let i = if distinct { i } else { i % 2 };
        let mut p = [0u8; 12];
        p[..4].copy_from_slice(&i.to_be_bytes());
        p[11] = 1;
        d.extend_from_slice(&info_src(true, p));
    }
    d
}

fn best_of(rounds: usize, mut f: impl FnMut()) -> Duration {
    (0..rounds)
        .map(|_| {
            let t = Instant::now();
            f();
            t.elapsed()
        })
        .min()
        .unwrap()
}

/// F6: every distinct source is still reported (no cap that padding could
/// exploit), and the work stays linear. The reviewed code took ~190 ms for a
/// 64 KiB datagram of ~2700 distinct INFO_SRC (debug build) and scales
/// quadratically (~3 s for 4x that); this one takes ~15 ms. Two checks,
/// with wide margins for a loaded machine:
/// - walking 10 800 distinct prefixes costs a small multiple of walking the
///   same bytes with two alternating prefixes (a membership scan of a Vec
///   would make it ~100x);
/// - turning the 10 800 sources into events takes well under a second.
#[test]
fn many_sources_are_all_reported_in_linear_time() {
    let d64k = info_src_flood(2700, true);
    assert!(d64k.len() <= 65_000);
    let ev = parse_datagram(&d64k, "10.0.0.66");
    assert_eq!(ev.len(), 2701, "header + every INFO_SRC prefix");

    let n = 10_800;
    let distinct = info_src_flood(n, true);
    let repeated = info_src_flood(n, false);
    assert_eq!(distinct.len(), repeated.len());
    let t_rep = best_of(5, || {
        std::hint::black_box(parse_datagram_detailed(std::hint::black_box(&repeated)));
    });
    let t_dis = best_of(5, || {
        std::hint::black_box(parse_datagram_detailed(std::hint::black_box(&distinct)));
    });
    let ratio = t_dis.as_secs_f64() / t_rep.as_secs_f64().max(1e-9);
    let r = parse_datagram_detailed(&distinct).unwrap();
    assert_eq!(r.sources.len(), n as usize + 1);
    let t_ev = best_of(3, || {
        std::hint::black_box(r.to_events("10.0.0.66"));
    });
    eprintln!("sources: walk {t_rep:?} vs {t_dis:?} (x{ratio:.1}), events {t_ev:?}");
    assert!(ratio < 25.0, "superlinear source indexing: x{ratio:.1}");
    assert!(t_ev < Duration::from_secs(1), "to_events took {t_ev:?}");
}
