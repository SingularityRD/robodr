//! Regression tests for the third independent review (R3-R1, R3-R2). The
//! reviewer's PoCs asserted the buggy behaviour; these assert the fix.

use robodr_events::RobotEvent;

use crate::testutil::*;
use crate::wire::{PID_KEY_HASH, PID_STATUS_INFO};
use crate::*;

const ATT: [u8; 12] = [0xaa; 12];
const PUB: [u8; 4] = ENTITYID_SEDP_PUBLICATIONS_WRITER;
const ROGUE_ENT: [u8; 4] = [0, 0, 0x77, 0x03];

fn dg(prefix: [u8; 12], subs: &[Vec<u8>]) -> Vec<u8> {
    let mut d = header(prefix);
    for s in subs {
        d.extend_from_slice(s);
    }
    d
}

fn motion_writers(ev: &[RobotEvent]) -> usize {
    ev.iter()
        .filter(|e| matches!(e, RobotEvent::Ros2WriterDiscovered(w) if w.topic == "rt/cmd_vel"))
        .count()
}

fn status_conflict(r: &DatagramReport) -> bool {
    r.anomalies
        .contains(&Anomaly::ConflictingDuplicateParameter(PID_STATUS_INFO))
}

/// A rogue `rt/cmd_vel` announcement split in fragments of `half` bytes.
/// `qos[i]` is the inline QoS of fragment i+1.
fn rogue_frags(qos: &[Option<Vec<u8>>]) -> (Vec<Vec<u8>>, usize) {
    let payload = sedp_payload(true, guid_of(ATT, ROGUE_ENT), "rt/cmd_vel", "T");
    let n = payload.len() as u32;
    let half = payload.len() / 2 / 4 * 4;
    let fs = half as u16;
    let frags = payload
        .chunks(half)
        .enumerate()
        .map(|(i, c)| {
            let q = qos.get(i).cloned().flatten();
            data_frag(true, PUB, 1, i as u32 + 1, 1, fs, n, q, c)
        })
        .collect();
    (frags, half)
}

/// R3-R1: an exact byte copy of fragment 1 carrying inline
/// PID_STATUS_INFO = disposed|unregistered is a duplicate: DDS stacks drop it
/// whole, so the writer is still announced. The differing inline QoS is
/// flagged.
#[test]
fn r3_r1_status_on_duplicate_fragment_is_ignored_and_flagged() {
    let (frags, _) = rogue_frags(&[]);
    let qos = Pl::new(true).status(0x03).end();
    let (dup, _) = rogue_frags(&[Some(qos)]);

    // Control: without the duplicate the writer is seen.
    assert_eq!(motion_writers(&parse_datagram(&dg(ATT, &frags), "x")), 1);

    let mut subs = vec![frags[0].clone(), dup[0].clone()];
    subs.extend(frags[1..].iter().cloned());
    let d = dg(ATT, &subs);
    let r = parse_datagram_detailed(&d).unwrap();
    assert_eq!(motion_writers(&r.to_events("x")), 1, "writer announced");
    assert_eq!(r.endpoints.len(), 1);
    assert!(r.removed_endpoints.is_empty());
    assert!(status_conflict(&r), "conflict flagged: {:?}", r.anomalies);
    assert!(r
        .fragment_events
        .iter()
        .any(|e| e.kind == FragmentEventKind::ConflictingInlineQos(PID_STATUS_INFO)));
    assert_eq!(r.stats.frag_conflicts, 1);

    // Same with the long-lived reassembler, and with the fragments spread
    // over several datagrams.
    let mut ra = FragmentReassembler::new(ReassemblyLimits::default());
    assert_eq!(motion_writers(&ra.parse_datagram(&d, "x")), 1);
    let mut ra = FragmentReassembler::new(ReassemblyLimits::default());
    let mut found = 0;
    let mut flagged = false;
    for s in &subs {
        let r = ra
            .parse_datagram_detailed(&dg(ATT, std::slice::from_ref(s)))
            .unwrap();
        flagged |= status_conflict(&r);
        found += motion_writers(&r.to_events("x"));
        assert!(r.removed_endpoints.is_empty());
    }
    assert_eq!(found, 1);
    assert!(flagged);
}

/// A byte-identical duplicate with the *same* inline QoS (an honest
/// retransmission) raises nothing.
#[test]
fn r3_r1_honest_retransmission_is_not_flagged() {
    let qos = Pl::new(true)
        .guid(PID_KEY_HASH, guid_of(ATT, ROGUE_ENT))
        .end();
    let (frags, _) = rogue_frags(&[Some(qos.clone()), Some(qos)]);
    let mut subs = vec![frags[0].clone(), frags[0].clone()];
    subs.extend(frags[1..].iter().cloned());
    let r = parse_datagram_detailed(&dg(ATT, &subs)).unwrap();
    assert_eq!(motion_writers(&r.to_events("x")), 1);
    assert!(r.anomalies.is_empty(), "{:?}", r.anomalies);
    assert!(r.fragment_events.is_empty());
}

/// A genuine fragmented dispose (status on the first fragment, which both
/// creates the sample and is fragment 1) is still a removal.
#[test]
fn r3_r1_fragmented_dispose_is_still_a_removal() {
    let qos = Pl::new(true).status(0x01).end();
    let (frags, _) = rogue_frags(&[Some(qos.clone()), Some(qos)]);
    let r = parse_datagram_detailed(&dg(ATT, &frags)).unwrap();
    assert_eq!(motion_writers(&r.to_events("x")), 0);
    assert_eq!(r.removed_endpoints.len(), 1);
    assert!(r.removed_endpoints[0].status.disposed());
    assert!(r.anomalies.is_empty(), "{:?}", r.anomalies);
}

/// Inline QoS of a fragment that is neither the creator nor fragment 1 is
/// ignored (no stack uses it), but a differing value is flagged.
#[test]
fn r3_r1_status_on_a_later_new_fragment_is_ignored() {
    let payload = sedp_payload(true, guid_of(ATT, ROGUE_ENT), "rt/cmd_vel", "T");
    let n = payload.len() as u32;
    let third = payload.len() / 3 / 4 * 4;
    let chunks: Vec<&[u8]> = payload.chunks(third).collect();
    assert!(chunks.len() >= 3);
    let qos = Pl::new(true).status(0x03).end();
    let subs: Vec<Vec<u8>> = chunks
        .iter()
        .enumerate()
        .map(|(i, c)| {
            let q = (i == 2).then(|| qos.clone());
            data_frag(true, PUB, 1, i as u32 + 1, 1, third as u16, n, q, c)
        })
        .collect();
    let r = parse_datagram_detailed(&dg(ATT, &subs)).unwrap();
    assert_eq!(motion_writers(&r.to_events("x")), 1);
    assert!(r.removed_endpoints.is_empty());
    // Absent vs present is not a conflict of values: nothing flagged.
    assert!(!status_conflict(&r));
}

/// Out of order: fragment 2 creates the sample (alive), fragment 1 says
/// disposed. Stacks that take the creator's QoS see a writer, stacks that
/// take fragment 1's see a removal: the announcement wins (conservative).
#[test]
fn r3_r1_creator_and_head_readings_disagree_announcement_wins() {
    let qos = Pl::new(true).status(0x03).end();
    let (frags, _) = rogue_frags(&[Some(qos)]);
    let mut subs: Vec<Vec<u8>> = frags[1..].to_vec();
    subs.push(frags[0].clone());
    let r = parse_datagram_detailed(&dg(ATT, &subs)).unwrap();
    assert_eq!(motion_writers(&r.to_events("x")), 1);
    assert!(r.removed_endpoints.is_empty());

    // Creator says disposed, fragment 1 (arriving later, alive status set
    // explicitly) says alive: a conflict of values, flagged, still a writer.
    let dis = Pl::new(true).status(0x03).end();
    let alive = Pl::new(true).status(0x00).end();
    let (frags, _) = rogue_frags(&[Some(alive), Some(dis)]);
    let mut subs: Vec<Vec<u8>> = frags[1..].to_vec();
    subs.push(frags[0].clone());
    let r = parse_datagram_detailed(&dg(ATT, &subs)).unwrap();
    assert_eq!(motion_writers(&r.to_events("x")), 1);
    assert!(r.removed_endpoints.is_empty());
    assert!(status_conflict(&r));
}

/// R3-R2: duplicate PID_STATUS_INFO in one DATA's inline QoS, disposed then
/// alive. A last-wins stack registers an alive writer: the writer event is
/// emitted and the conflict flagged (PID_STATUS_INFO is an identity PID for
/// the pipeline).
#[test]
fn r3_r2_conflicting_inline_status_is_flagged_and_announced() {
    let payload = sedp_payload(true, guid_of(ATT, ROGUE_ENT), "rt/cmd_vel", "T");
    let qos = Pl::new(true).status(0x03).status(0x00).end();
    let d = dg(ATT, &[data(true, PUB, Some(qos), Payload::Data(payload))]);
    let r = parse_datagram_detailed(&d).unwrap();
    assert_eq!(motion_writers(&r.to_events("x")), 1, "writer announced");
    assert!(r.removed_endpoints.is_empty());
    assert!(status_conflict(&r), "{:?}", r.anomalies);

    // Alive first, disposed last: same outcome.
    let payload = sedp_payload(true, guid_of(ATT, ROGUE_ENT), "rt/cmd_vel", "T");
    let qos = Pl::new(true).status(0x00).status(0x02).end();
    let d = dg(ATT, &[data(true, PUB, Some(qos), Payload::Data(payload))]);
    let r = parse_datagram_detailed(&d).unwrap();
    assert_eq!(motion_writers(&r.to_events("x")), 1);
    assert!(status_conflict(&r));
}

/// Two removal readings that differ (disposed vs unregistered) are still a
/// removal (no reading is alive), flagged.
#[test]
fn r3_r2_two_removal_readings_stay_a_removal() {
    let payload = sedp_payload(true, guid_of(ATT, ROGUE_ENT), "rt/cmd_vel", "T");
    let qos = Pl::new(true).status(0x01).status(0x02).end();
    let d = dg(ATT, &[data(true, PUB, Some(qos), Payload::Data(payload))]);
    let r = parse_datagram_detailed(&d).unwrap();
    assert_eq!(motion_writers(&r.to_events("x")), 0);
    assert_eq!(r.removed_endpoints.len(), 1);
    assert!(status_conflict(&r));
}

/// Conflicting statuses on a key-only sample (nothing to announce): the
/// removal reading is recorded, and the conflict flagged.
#[test]
fn r3_r2_key_only_with_conflicting_status_is_a_removal() {
    let mut key = vec![0x00, 0x00, 0, 0];
    key.extend_from_slice(&guid_of(ATT, ROGUE_ENT));
    let qos = Pl::new(true).status(0x00).status(0x01).end();
    let d = dg(ATT, &[data(true, PUB, Some(qos), Payload::Key(key))]);
    let r = parse_datagram_detailed(&d).unwrap();
    assert_eq!(r.removed_endpoints.len(), 1);
    assert!(r.removed_endpoints[0].status.disposed());
    assert!(status_conflict(&r));
}

/// Repeating the same status (or key hash) is not a conflict; a different
/// inline key hash is; a short status is a bad value.
#[test]
fn r3_r2_inline_duplicates_same_value_and_bad_values() {
    let payload = || sedp_payload(true, guid_of(ATT, ROGUE_ENT), "rt/cmd_vel", "T");
    let g = guid_of(ATT, ROGUE_ENT);
    let qos = Pl::new(true)
        .status(0x01)
        .status(0x01)
        .guid(PID_KEY_HASH, g)
        .guid(PID_KEY_HASH, g)
        .end();
    let r = parse_datagram_detailed(&dg(
        ATT,
        &[data(true, PUB, Some(qos), Payload::Data(payload()))],
    ))
    .unwrap();
    assert!(r.anomalies.is_empty(), "{:?}", r.anomalies);
    assert_eq!(r.removed_endpoints.len(), 1);

    let qos = Pl::new(true)
        .guid(PID_KEY_HASH, g)
        .guid(PID_KEY_HASH, guid_of([0xbb; 12], ROGUE_ENT))
        .end();
    let r = parse_datagram_detailed(&dg(
        ATT,
        &[data(true, PUB, Some(qos), Payload::Data(payload()))],
    ))
    .unwrap();
    assert!(r
        .anomalies
        .contains(&Anomaly::ConflictingDuplicateParameter(PID_KEY_HASH)));
    assert_eq!(motion_writers(&r.to_events("x")), 1);

    let qos = Pl::new(true).raw_len(PID_STATUS_INFO, 0, &[]).end();
    let r = parse_datagram_detailed(&dg(
        ATT,
        &[data(true, PUB, Some(qos), Payload::Data(payload()))],
    ))
    .unwrap();
    assert!(r
        .anomalies
        .contains(&Anomaly::BadParameterValue(PID_STATUS_INFO)));
    assert_eq!(motion_writers(&r.to_events("x")), 1);
}
