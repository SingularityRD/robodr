//! Recorder behaviour: round trip, reopen, crash recovery, retention modes.

#![allow(clippy::field_reassign_with_default)]

mod common;

use common::*;
use robodr_blackbox::record::{
    RecordKind, RecoveryPayload, ResumePayload, SealPayload, SealReason, SegmentDroppedPayload,
};
use robodr_blackbox::store::{segment_file_name, CHECKPOINT_FILE, QUARANTINE_DIR};
use robodr_blackbox::verify::verify_dir;
use robodr_blackbox::*;
use robodr_events::{graph::Participant, Deviation, MotionCommand, RobotEvent, Severity};

fn verify_path(p: &std::path::Path) -> Report {
    verify_dir(p, &verifier(), &VerifyOptions::default()).unwrap()
}

#[test]
fn round_trip_events_deviations_notes_and_reopen() {
    let d = TestDir::new("roundtrip");
    let mut c = cfg(d.path(), big());
    c.fsync = FsyncPolicy::Always;
    let mut r = open(c.clone());
    let ev = RobotEvent::Ros2ParticipantDiscovered(Participant {
        guid_prefix: "0102030405060708090a0b0c".into(),
        src_ip: "10.0.0.7".into(),
        locators: vec!["10.0.0.7:7410".into()],
    });
    let s_ev = recorded(r.append_event(&ev, false).unwrap());
    let mc = RobotEvent::MotionCommand(MotionCommand {
        channel: "/cmd_vel".into(),
        source_guid: None,
        linear_speed: Some(3.5),
        joint_speed: None,
        angular_speed: None,
        ..Default::default()
    });
    recorded(r.append_event(&mc, true).unwrap());
    let dev = Deviation::new(
        "robot.ros2.unknown_participant",
        Severity::Critical,
        "participant not in profile",
    );
    let s_dev = recorded(r.append_deviation(&dev).unwrap());
    recorded(
        r.append_note(&serde_json::json!({"operator": "shift-2"}), false)
            .unwrap(),
    );
    let head = r.head().unwrap();
    let chain = r.chain_id();
    drop(r); // no close: simulate an orderly-enough stop without a seal

    let recs = all_records(d.path());
    assert_eq!(recs[0].kind, RecordKind::Genesis);
    assert_eq!(recs[0].seq, 0);
    let back: RobotEvent = recs[s_ev as usize].payload_json().unwrap();
    assert_eq!(back, ev);
    let devj: serde_json::Value = recs[s_dev as usize].payload_json().unwrap();
    assert_eq!(devj["rule"], "robot.ros2.unknown_participant");
    assert_eq!(devj["severity"], "critical");
    assert!(recs[s_dev as usize].critical);
    assert_eq!(recs[s_dev as usize].time.source, TimeSource::Gps);

    // Reopen in a new boot: chain continues, Resume is recorded.
    let mut c2 = c.clone();
    c2.boot_id = "boot-b".into();
    let mut r = open(c2);
    assert_eq!(r.chain_id(), chain);
    let resume = all_records(d.path()).pop().unwrap();
    assert_eq!(resume.kind, RecordKind::Resume);
    assert_eq!(resume.seq, head.0 + 1);
    assert_eq!(resume.prev_hash, head.1);
    let rp: ResumePayload = resume.payload_json().unwrap();
    assert_eq!(rp.boot_id, "boot-b");
    assert_eq!(rp.chain_boot_id, "boot-a");
    assert!(!rp.recovered);
    recorded(r.append_note(&note(1), false).unwrap());
    r.close().unwrap();

    let rep = verify_path(d.path());
    assert!(rep.is_clean(), "{}", dump(&rep));
    assert_eq!(rep.identity.unwrap().boot_id, "boot-a");
}

#[test]
fn reopen_with_other_key_or_device_is_refused() {
    let d = TestDir::new("refuse");
    build_log(d.path(), 3);
    let other = HmacSha256Key::new("other-key", &[1; 32]).unwrap();
    let e = Recorder::open(cfg(d.path(), big()), Box::new(other), clock()).unwrap_err();
    assert!(matches!(e, Error::KeyMismatch { .. }), "{e}");
    let mut c = cfg(d.path(), big());
    c.device_id = "ugv-02".into();
    let e = Recorder::open(c, signer(), clock()).unwrap_err();
    assert!(matches!(e, Error::DeviceMismatch { .. }), "{e}");
    // Nothing was written by the refused opens.
    assert!(verify_path(d.path()).is_clean());
}

#[test]
fn payload_limit_is_enforced() {
    let d = TestDir::new("payload");
    let mut c = cfg(d.path(), big());
    c.max_payload_bytes = 64;
    let mut r = open(c);
    let e = r
        .append(EntryKind::Note, vec![b'x'; 65], false)
        .unwrap_err();
    assert!(matches!(e, Error::PayloadTooLarge { len: 65, max: 64 }));
    recorded(r.append(EntryKind::Note, vec![b'x'; 64], false).unwrap());
}

fn crash_with_tail(tag: &str, tail: impl Fn(&[u8]) -> Vec<u8>) -> TestDir {
    let d = TestDir::new(tag);
    let mut r = open(cfg(d.path(), big()));
    for i in 0..30 {
        recorded(r.append_note(&note(i), false).unwrap());
    }
    drop(r); // crash: no seal
    let s = segs(d.path());
    let last = s.last().unwrap();
    let f = frames(&last.bytes);
    let (o, l, _) = f[f.len() - 1].clone();
    let extra = tail(&last.bytes[o..o + l]);
    let path = d.path().join(&last.name);
    let mut bytes = std::fs::read(&path).unwrap();
    bytes.extend_from_slice(&extra);
    std::fs::write(&path, bytes).unwrap();
    d
}

#[test]
fn torn_write_is_truncated_quarantined_and_recorded() {
    let d = crash_with_tail("torn", |frame| frame[..frame.len() - 7].to_vec());
    let before = segs(d.path());
    let last_name = before.last().unwrap().name.clone();
    // Unrecovered: verifier warns.
    let rep = verify_path(d.path());
    assert!(rep.is_intact() && !rep.is_clean(), "{}", dump(&rep));

    let r = open(cfg(d.path(), big()));
    let head = r.head().unwrap();
    drop(r);
    let recs = all_records(d.path());
    let rec = recs
        .iter()
        .find(|r| r.kind == RecordKind::Recovery)
        .expect("recovery record");
    assert_eq!(rec.seq, head.0);
    let rp: RecoveryPayload = rec.payload_json().unwrap();
    let qfile = d.path().join(rp.quarantine_file.as_ref().unwrap());
    let q = std::fs::read(&qfile).unwrap();
    assert_eq!(q.len() as u64, rp.discarded_bytes);
    assert_eq!(
        rp.discarded_sha256,
        robodr_blackbox::crypto::to_hex(&robodr_blackbox::crypto::sha256(&q))
    );
    assert!(rp.reason.contains("torn"), "{}", rp.reason);
    assert!(qfile.starts_with(d.path().join(QUARANTINE_DIR)));
    // Resume says so, and is written before the recovery record.
    let resume = recs
        .iter()
        .rev()
        .find(|r| r.kind == RecordKind::Resume)
        .unwrap();
    assert!(resume.payload_json::<ResumePayload>().unwrap().recovered);
    assert_eq!(resume.seq + 1, rec.seq);
    // The truncated file holds only whole frames again.
    let after = segs(d.path());
    assert_eq!(after.last().unwrap().name, last_name);
    // Recovery is intact (nothing forged) but not clean: it is a warning.
    let rep = verify_path(d.path());
    assert!(rep.is_intact(), "{}", dump(&rep));
    assert!(!rep.is_clean(), "{}", dump(&rep));
    assert!(has(&rep, |k| matches!(
        k,
        FindingKind::RecoveryRecorded { discarded_bytes, .. } if *discarded_bytes == q.len() as u64
    )));
}

#[test]
fn zero_filled_tail_is_recovered() {
    let d = crash_with_tail("zeros", |_| vec![0u8; 300]);
    let r = open(cfg(d.path(), big()));
    drop(r);
    let rp: RecoveryPayload = all_records(d.path())
        .iter()
        .find(|r| r.kind == RecordKind::Recovery)
        .unwrap()
        .payload_json()
        .unwrap();
    assert_eq!(rp.discarded_bytes, 300);
    assert!(rp.reason.contains("zero"));
    let rep = verify_path(d.path());
    assert!(rep.is_intact() && !rep.is_clean(), "{}", dump(&rep));
}

#[test]
fn corrupt_last_record_and_mid_log_corruption_refuse() {
    // A complete but modified final frame cannot be a crash artefact (the
    // hash is computed before the frame is written): refuse, touch nothing.
    let d = TestDir::new("corrupt-last");
    let mut r = open(cfg(d.path(), big()));
    for i in 0..5 {
        recorded(r.append_note(&note(i), false).unwrap());
    }
    drop(r);
    let s = segs(d.path());
    let path = d.path().join(&s[0].name);
    let mut b = std::fs::read(&path).unwrap();
    let n = b.len();
    b[n - 40] ^= 0xff; // inside the last frame's hash/sig area
    std::fs::write(&path, &b).unwrap();
    let e = Recorder::open(cfg(d.path(), big()), signer(), clock()).unwrap_err();
    assert!(matches!(e, Error::Corrupt { .. }), "{e}");
    assert_eq!(std::fs::read(&path).unwrap(), b);
    assert!(!d.path().join(QUARANTINE_DIR).exists());
    assert!(!verify_path(d.path()).is_intact());

    // Corruption followed by valid frames: refuse, do not touch the file.
    let d = TestDir::new("corrupt-mid");
    let mut r = open(cfg(d.path(), big()));
    for i in 0..5 {
        recorded(r.append_note(&note(i), false).unwrap());
    }
    drop(r);
    let s = segs(d.path());
    let (o, _, _) = frames(&s[0].bytes)[2].clone();
    let path = d.path().join(&s[0].name);
    let mut b = std::fs::read(&path).unwrap();
    b[o + 80] ^= 0x01;
    std::fs::write(&path, &b).unwrap();
    let e = Recorder::open(cfg(d.path(), big()), signer(), clock()).unwrap_err();
    assert!(matches!(e, Error::Corrupt { .. }), "{e}");
    assert_eq!(std::fs::read(&path).unwrap(), b);
    assert!(!d.path().join(QUARANTINE_DIR).exists());
}

#[test]
fn crash_after_segment_creation_resumes_cleanly() {
    let d = TestDir::new("empty-seg");
    let mut r = open(cfg(d.path(), big()));
    for i in 0..30 {
        recorded(r.append_note(&note(i), false).unwrap());
    }
    let last_idx = *r.segments().last().unwrap();
    r.close().unwrap();
    std::fs::write(d.path().join(segment_file_name(last_idx + 1)), b"").unwrap();
    let mut r = open(cfg(d.path(), big()));
    assert_eq!(*r.segments().last().unwrap(), last_idx + 1);
    recorded(r.append_note(&note(99), false).unwrap());
    drop(r);
    let s = segs(d.path());
    let first = &frames(&s.last().unwrap().bytes)[0].2;
    assert_eq!(first.kind, RecordKind::SegmentStart);
    let rep = verify_path(d.path());
    assert!(rep.is_clean(), "{}", dump(&rep));
}

#[test]
fn crash_before_genesis_starts_chain_in_place() {
    let d = TestDir::new("no-genesis");
    std::fs::write(d.path().join(segment_file_name(0)), b"RBF1\x00\x00").unwrap();
    let r = open(cfg(d.path(), big()));
    drop(r);
    let recs = all_records(d.path());
    assert_eq!(recs[0].kind, RecordKind::Genesis);
    assert_eq!(recs[1].kind, RecordKind::Recovery);
    let rep = verify_path(d.path());
    assert!(rep.is_intact() && !rep.is_clean(), "{}", dump(&rep));
}

#[test]
fn periodic_seals_and_checkpoint_file() {
    let d = TestDir::new("seals");
    let mut c = cfg(d.path(), big());
    c.seal_every_records = 5;
    let mut r = open(c);
    for i in 0..23 {
        recorded(r.append_note(&note(i), false).unwrap());
    }
    let cp = r.last_checkpoint().unwrap().clone();
    let on_disk =
        Checkpoint::from_json(&std::fs::read_to_string(d.path().join(CHECKPOINT_FILE)).unwrap())
            .unwrap();
    assert_eq!(cp, on_disk);
    assert!(cp.verify(&verifier()));
    drop(r);
    let recs = all_records(d.path());
    let seals: Vec<_> = recs.iter().filter(|r| r.kind == RecordKind::Seal).collect();
    assert!(seals.len() >= 4);
    let periodic = seals
        .iter()
        .filter(|s| s.payload_json::<SealPayload>().unwrap().reason == SealReason::Periodic)
        .count();
    assert!(periodic >= 3);
    let mut o = VerifyOptions::default();
    o.checkpoint = Some(cp);
    let rep = verify_dir(d.path(), &verifier(), &o).unwrap();
    assert!(rep.is_clean(), "{}", dump(&rep));
}

#[test]
fn cyclic_wrap_keeps_tail_verifiable() {
    let d = TestDir::new("cyclic");
    let c = cfg(d.path(), RetentionMode::Cyclic { max_segments: 3 });
    let mut r = open(c.clone());
    for i in 0..200 {
        recorded(r.append_note(&note(i), i % 17 == 0).unwrap());
    }
    assert_eq!(r.segments().len(), 3);
    assert!(r.segments()[0] > 0);
    drop(r);
    assert!(!d.path().join(segment_file_name(0)).exists());
    let rep = verify_path(d.path());
    assert!(rep.is_intact(), "{}", dump(&rep));
    assert!(rep.first_seq.unwrap() > 0);
    assert!(has(&rep, |k| matches!(
        k,
        FindingKind::HeadDropRecorded { .. }
    )));
    assert!(!has(&rep, |k| matches!(k, FindingKind::HeadMissing { .. })));
    let drops: Vec<SegmentDroppedPayload> = all_records(d.path())
        .iter()
        .filter(|r| r.kind == RecordKind::SegmentDropped)
        .map(|r| r.payload_json().unwrap())
        .collect();
    assert!(!drops.is_empty());
    assert!(drops.iter().all(|p| !p.exported && !p.missing));

    // Survives reopen and further wrapping.
    let mut r = open(c);
    for i in 0..100 {
        recorded(r.append_note(&note(i), false).unwrap());
    }
    r.close().unwrap();
    let rep = verify_path(d.path());
    assert!(rep.is_clean(), "{}", dump(&rep));

    // An attacker deleting the oldest retained segment is caught.
    let s = segs(d.path());
    std::fs::remove_file(d.path().join(&s[0].name)).unwrap();
    let rep = verify_path(d.path());
    assert!(has(&rep, |k| matches!(k, FindingKind::HeadMissing { .. })));
}

#[test]
fn segment_deleted_behind_recorder_is_reported_at_drop() {
    let d = TestDir::new("missing");
    let mut r = open(cfg(d.path(), RetentionMode::Cyclic { max_segments: 3 }));
    while r.segments().len() < 3 {
        recorded(r.append_note(&note(0), false).unwrap());
    }
    let oldest = r.segments()[0];
    std::fs::remove_file(d.path().join(segment_file_name(oldest))).unwrap();
    while r.segments()[0] == oldest {
        recorded(r.append_note(&note(1), false).unwrap());
    }
    drop(r);
    let rep = verify_path(d.path());
    assert!(
        has(
            &rep,
            |k| matches!(k, FindingKind::SegmentMissingReported { segment_index, .. } if *segment_index == oldest)
        ),
        "{}",
        dump(&rep)
    );
    assert!(!rep.is_intact());
}

#[test]
fn saturation_refuses_noncritical_keeps_critical_and_clears_after_export() {
    let d = TestDir::new("saturation");
    let mode = RetentionMode::Saturation {
        max_segments: 2,
        critical_reserve_segments: 1,
    };
    let mut r = open(cfg(d.path(), mode));
    let mut n = 0u64;
    loop {
        match r.append_note(&note(n), false).unwrap() {
            AppendOutcome::Recorded { .. } => n += 1,
            AppendOutcome::Refused(Refusal::Saturated) => break,
            other => panic!("{other:?}"),
        }
        assert!(n < 10_000);
    }
    assert!(r.is_saturated());
    assert_eq!(r.segments().len(), 3); // normal + reserve
                                       // Non-critical keeps being refused, critical is accepted.
    assert_eq!(
        r.append_note(&note(0), false).unwrap(),
        AppendOutcome::Refused(Refusal::Saturated)
    );
    let crit = Deviation::new("robot.motion.envelope", Severity::Critical, "over speed");
    recorded(r.append_deviation(&crit).unwrap());
    let low = Deviation::new("robot.ros2.new_topic", Severity::Low, "x");
    assert_eq!(
        r.append_deviation(&low).unwrap(),
        AppendOutcome::Refused(Refusal::Saturated)
    );
    // Fill the reserve until even critical records are refused.
    let mut k = 0;
    loop {
        match r.append_deviation(&crit).unwrap() {
            AppendOutcome::Recorded { .. } => k += 1,
            AppendOutcome::Refused(Refusal::Full) => break,
            other => panic!("{other:?}"),
        }
        assert!(k < 10_000);
    }
    assert_eq!(r.segments().len(), 3);
    assert_eq!(r.refused(), (3, 1));
    let rep = verify_path(d.path());
    assert!(rep.is_intact(), "{}", dump(&rep));
    assert!(has(&rep, |k| matches!(
        k,
        FindingKind::SaturationRecorded { .. }
    )));
    assert!(!d.path().join(segment_file_name(3)).exists());
    let recs = all_records(d.path());
    let sat_pos = recs
        .iter()
        .position(|r| r.kind == RecordKind::Saturation)
        .unwrap();
    assert!(recs[sat_pos + 1..]
        .iter()
        .all(|r| r.critical || r.kind.is_control()));

    // Export, prune: saturation ends and is recorded.
    let b = r.export_pending(None).unwrap().unwrap();
    r.mark_exported(&b).unwrap();
    let pruned = r.prune_exported().unwrap();
    assert!(pruned >= 2, "pruned {pruned}");
    assert!(!r.is_saturated());
    recorded(r.append_note(&note(7), false).unwrap());
    r.close().unwrap();
    let recs = all_records(d.path());
    let cleared = recs
        .iter()
        .find(|r| r.kind == RecordKind::SaturationCleared)
        .unwrap();
    let p: serde_json::Value = cleared.payload_json().unwrap();
    assert_eq!(p["refused_noncritical"], 3);
    assert_eq!(p["refused_critical"], 1);
    let rep = verify_path(d.path());
    assert!(rep.is_intact(), "{}", dump(&rep));
    assert!(has(&rep, |k| matches!(
        k,
        FindingKind::SegmentDropRecorded { exported: true, .. }
    )));
}

#[test]
fn saturation_state_survives_reopen() {
    let d = TestDir::new("sat-reopen");
    let mode = RetentionMode::Saturation {
        max_segments: 1,
        critical_reserve_segments: 2,
    };
    let mut r = open(cfg(d.path(), mode));
    while r.append_note(&note(0), false).unwrap() != AppendOutcome::Refused(Refusal::Saturated) {}
    drop(r);
    let mut r = open(cfg(d.path(), mode));
    assert!(r.is_saturated());
    assert_eq!(
        r.append_note(&note(0), false).unwrap(),
        AppendOutcome::Refused(Refusal::Saturated)
    );
    recorded(r.append_note(&note(0), true).unwrap());
    r.close().unwrap();
    assert!(verify_path(d.path()).is_intact());
}

/// Segment size: with an HMAC (or Ed25519) key, a periodic seal after the
/// last record and the rotation / shutdown seal still fit, so no segment of
/// a normally written log exceeds `max_segment_bytes` (README "Segment
/// size" lists the remaining exceptions).
#[test]
fn segments_stay_within_max_segment_bytes() {
    for seal_every in [0, 1, 3] {
        let d = TestDir::new("segsize");
        let mut c = cfg(d.path(), big());
        c.seal_every_records = seal_every;
        let max = c.max_segment_bytes;
        let mut r = open(c);
        for i in 0..200 {
            recorded(r.append_note(&note(i), i % 7 == 0).unwrap());
        }
        r.close().unwrap();
        let all = segs(d.path());
        assert!(all.len() > 3, "rotated ({} segments)", all.len());
        for s in &all {
            assert!(
                s.bytes.len() as u64 <= max,
                "seal_every {seal_every}: {} is {} bytes > {max}",
                s.name,
                s.bytes.len()
            );
        }
    }
}
