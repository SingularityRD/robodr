//! rev3 review findings, ported from the PoCs as regression tests that
//! assert the FIXED behaviour (B1 truncation evidence, B2 persisted refusal
//! counters, B3 never brick on lost write-back), plus key rotation.
mod common;
use common::*;
use robodr_blackbox::crypto::{sha256, to_hex};
use robodr_blackbox::keys::Keyring;
use robodr_blackbox::record::{
    KeyRotationPayload, RecoveryPayload, ResumePayload, SaturationClearedPayload, SealPayload,
    SegmentStartPayload, TruncationPayload,
};
use robodr_blackbox::sign::SignError;
use robodr_blackbox::store::{segment_file_name, CHECKPOINT_FILE, CURSOR_FILE, QUARANTINE_DIR};
use robodr_blackbox::verify::verify_dir;
use robodr_blackbox::*;
use robodr_events::Severity;
use std::collections::HashSet;
use std::path::Path;

fn vdir(p: &Path) -> Report {
    verify_dir(p, &verifier(), &VerifyOptions::default()).unwrap()
}

fn last_of<T: for<'de> serde::Deserialize<'de>>(dir: &Path, kind: RecordKind) -> Option<T> {
    all_records(dir)
        .iter()
        .rev()
        .find(|r| r.kind == kind)
        .and_then(|r| r.payload_json())
}

fn assert_unique_seqs(dir: &Path) {
    let mut seen = HashSet::new();
    for r in all_records(dir) {
        assert!(seen.insert(r.seq), "seq {} used twice", r.seq);
    }
}

// ---------------------------------------------------------------------------
// B1: tail truncated at a frame boundary below the local checkpoint
// ---------------------------------------------------------------------------

/// Builds the PoC situation: 3 notes, a seal (checkpoint), 2 more notes,
/// then every frame from the seal on cut away at a frame boundary.
/// Returns (config, original checkpoint, original checkpoint.json text,
/// seq of the head left in the file).
fn truncated_below_checkpoint(d: &TestDir) -> (RecorderConfig, Checkpoint, String, u64) {
    let c = cfg(d.path(), big());
    let mut r = open(c.clone());
    for i in 0..3 {
        recorded(r.append_note(&note(i), true).unwrap());
    }
    let cp = r.seal().unwrap();
    for i in 3..5 {
        recorded(r.append_note(&note(i), true).unwrap());
    }
    let seg_idx = *r.segments().last().unwrap();
    drop(r);
    let cp_text = std::fs::read_to_string(d.path().join(CHECKPOINT_FILE)).unwrap();
    let path = d.path().join(segment_file_name(seg_idx));
    let bytes = std::fs::read(&path).unwrap();
    let fr = frames(&bytes);
    let pos = fr.iter().position(|(_, _, rec)| rec.seq == cp.seq).unwrap();
    std::fs::write(&path, &bytes[..fr[pos].0]).unwrap();
    let head = fr[pos - 1].2.seq;
    (c, cp, cp_text, head)
}

#[test]
fn b1_truncation_below_checkpoint_is_recorded_and_seqs_are_not_reused() {
    let d = TestDir::new("r3-b1");
    let (c, cp, cp_text, head) = truncated_below_checkpoint(&d);
    // Before reopening, the directory's own checkpoint exposes it.
    assert!(has(&vdir(d.path()), |k| matches!(
        k,
        FindingKind::TruncatedTail { .. }
    )));

    let r = open(c.clone());
    // The next record continued *after* the checkpoint's seq: no reuse.
    assert!(r.head().unwrap().0 > cp.seq);
    r.close().unwrap();

    let rs: ResumePayload = last_of(d.path(), RecordKind::Resume).unwrap();
    assert_eq!(rs.resumed_after_seq, head);
    assert_eq!(rs.skipped_seqs, Some([head + 1, cp.seq]));
    assert!(rs
        .rejected_state
        .iter()
        .any(|s| s.contains(CHECKPOINT_FILE) && s.contains("truncated")));

    let td_rec = all_records(d.path())
        .into_iter()
        .find(|r| r.kind == RecordKind::TruncationDetected)
        .expect("TruncationDetected record");
    assert!(td_rec.critical);
    let td: TruncationPayload = td_rec.payload_json().unwrap();
    assert_eq!(td.head_seq, head);
    assert_eq!(td.skipped_seqs, [head + 1, cp.seq]);
    assert_eq!(td.severity, Severity::Critical);
    assert_eq!(td.evidence.len(), 1);
    let ev = &td.evidence[0];
    assert_eq!((ev.file.as_str(), ev.seq), (CHECKPOINT_FILE, cp.seq));
    assert_eq!(ev.hash, to_hex(&cp.hash));
    // The evidence checkpoint was preserved byte for byte before the
    // recorder's next seal replaced checkpoint.json.
    let kept = std::fs::read_to_string(d.path().join(ev.preserved_as.as_ref().unwrap())).unwrap();
    assert_eq!(kept, cp_text);
    assert_eq!(ev.sha256, to_hex(&sha256(kept.as_bytes())));
    assert_eq!(Checkpoint::from_json(&kept).unwrap(), cp);

    assert_unique_seqs(d.path());
    // The verifier reports the truncation (not a quiet, intact log), and
    // never a fork.
    let after = vdir(d.path());
    assert!(!after.is_intact(), "{}", dump(&after));
    assert!(has(&after, |k| matches!(
        k,
        FindingKind::TruncationRecorded { .. }
    )));
    assert!(has(&after, |k| *k
        == FindingKind::Deleted {
            first_missing: head + 1,
            last_missing: cp.seq
        }));
    assert!(!has(&after, |k| matches!(k, FindingKind::Fork { .. })));
    // An off-unit copy of the original checkpoint finds no mismatch.
    let ext = verify_dir(
        d.path(),
        &verifier(),
        &VerifyOptions {
            checkpoint: Some(cp.clone()),
            ..Default::default()
        },
    )
    .unwrap();
    assert!(!has(&ext, |k| matches!(
        k,
        FindingKind::CheckpointMismatch { .. }
    )));
    assert!(!ext.is_intact());

    // Reopening again works (the declared seq jump is accepted) and does
    // not report the truncation twice.
    open(c).close().unwrap();
    let n = all_records(d.path())
        .iter()
        .filter(|r| r.kind == RecordKind::TruncationDetected)
        .count();
    assert_eq!(n, 1);
    assert_unique_seqs(d.path());
}

#[test]
fn b1_cursor_beyond_head_is_truncation_evidence_too() {
    let d = TestDir::new("r3-b1-cursor");
    let c = cfg(d.path(), big());
    let mut r = open(c.clone());
    for i in 0..4 {
        recorded(r.append_note(&note(i), false).unwrap());
    }
    let b = r.export_pending(None).unwrap().unwrap();
    r.mark_exported(&b).unwrap();
    let exported_to = r.export_cursor().unwrap().seq;
    let seg_idx = *r.segments().last().unwrap();
    drop(r);
    // Remove the checkpoint so only the cursor proves the truncation.
    std::fs::remove_file(d.path().join(CHECKPOINT_FILE)).unwrap();
    let path = d.path().join(segment_file_name(seg_idx));
    let bytes = std::fs::read(&path).unwrap();
    let fr = frames(&bytes);
    std::fs::write(&path, &bytes[..fr[3].0]).unwrap(); // keep seqs 0..=2
    let r = open(c);
    assert!(r.head().unwrap().0 > exported_to);
    assert!(r.export_cursor().is_none());
    drop(r);
    let td: TruncationPayload = last_of(d.path(), RecordKind::TruncationDetected).unwrap();
    assert_eq!(td.evidence[0].file, CURSOR_FILE);
    assert_eq!(td.skipped_seqs, [3, exported_to]);
    assert_unique_seqs(d.path());
}

#[test]
fn b1_authentic_checkpoint_that_contradicts_the_log_refuses_open() {
    let d = TestDir::new("r3-b1-mismatch");
    let c = cfg(d.path(), big());
    let mut r = open(c.clone());
    for i in 0..4 {
        recorded(r.append_note(&note(i), false).unwrap());
    }
    let chain = r.chain_id();
    drop(r);
    // Signed with the chain's key, for a seq the log has, other hash: the
    // history was rewritten by a key holder (or the key leaked).
    let h = [7u8; 32];
    let forged = Checkpoint {
        chain_id: chain,
        seq: 2,
        hash: h,
        key_id: KEY_ID.into(),
        sig: Signer::sign(&verifier(), &robodr_blackbox::record::signing_message(&h)).unwrap(),
    };
    std::fs::write(d.path().join(CHECKPOINT_FILE), forged.to_json()).unwrap();
    let seg = std::fs::read(d.path().join(segment_file_name(0))).unwrap();
    match Recorder::open(c, signer(), clock()) {
        Err(Error::Untrusted(m)) => assert!(m.contains(CHECKPOINT_FILE), "{m}"),
        other => panic!("expected Untrusted, got {:?}", other.map(|_| ())),
    }
    assert_eq!(
        std::fs::read(d.path().join(segment_file_name(0))).unwrap(),
        seg
    );
}

// ---------------------------------------------------------------------------
// B2: saturation refusal counters survive restarts
// ---------------------------------------------------------------------------

fn saturated(d: &TestDir, n: u64, reserve: u32) -> (RecorderConfig, Recorder) {
    let c = cfg(
        d.path(),
        RetentionMode::Saturation {
            max_segments: 2,
            critical_reserve_segments: reserve,
        },
    );
    let mut r = open(c.clone());
    let mut refused = 0u64;
    let mut i = 0;
    while refused < n {
        match r.append_note(&note(i), false).unwrap() {
            AppendOutcome::Refused(_) => refused += 1,
            AppendOutcome::Recorded { .. } => {}
        }
        i += 1;
    }
    (c, r)
}

#[test]
fn b2_refusal_counts_survive_restart_and_reach_saturation_cleared() {
    let d = TestDir::new("r3-b2");
    let (c, r) = saturated(&d, 5, 1);
    assert_eq!(r.refused().0, 5);
    let cp = r.close().unwrap();
    // The shutdown seal carries the counters.
    let seal: SealPayload = all_records(d.path())
        .into_iter()
        .find(|x| x.seq == cp.seq)
        .unwrap()
        .payload_json()
        .unwrap();
    assert_eq!(seal.refused_noncritical, 5);

    let mut r = open(c.clone());
    assert!(r.is_saturated());
    assert_eq!(r.refused(), (5, 0), "counts restored after restart");
    let rs: ResumePayload = last_of(d.path(), RecordKind::Resume).unwrap();
    assert_eq!(rs.refused_noncritical, 5);
    // Two more after the restart: totals keep counting.
    let mut i = 1000;
    while r.refused().0 < 7 {
        r.append_note(&note(i), false).unwrap();
        i += 1;
    }
    drop(r); // crash, no close: the Resume record still holds 5
    let mut r = open(c);
    assert_eq!(
        r.refused(),
        (5, 0),
        "refusals after the last record are lost"
    );
    let b = r.export_pending(None).unwrap().unwrap();
    r.mark_exported(&b).unwrap();
    assert!(r.prune_exported().unwrap() > 0);
    assert_eq!(r.refused(), (0, 0), "reset once reported");
    r.close().unwrap();
    let cleared: Vec<SaturationClearedPayload> = all_records(d.path())
        .iter()
        .filter(|x| x.kind == RecordKind::SaturationCleared)
        .filter_map(|x| x.payload_json())
        .collect();
    assert_eq!(cleared.len(), 1);
    assert_eq!(cleared[0].refused_noncritical, 5);
    assert!(vdir(d.path()).is_intact());
}

#[test]
fn b2_counts_found_in_previous_segment_when_active_has_none() {
    // Saturation reached, then a rotation (critical record into the
    // reserve) leaves an active segment without any seal/resume of its own
    // when the process dies: the rotation seal of the previous segment has
    // the counts.
    let d = TestDir::new("r3-b2-prev");
    let (c, mut r) = saturated(&d, 3, 2);
    let segs_before = r.segments().len();
    let mut i = 0;
    while r.segments().len() == segs_before {
        recorded(r.append_note(&note(5000 + i), true).unwrap());
        i += 1;
    }
    drop(r);
    let r = open(c);
    assert_eq!(r.refused(), (3, 0));
}

// ---------------------------------------------------------------------------
// B3: lost write-back in the middle of the active segment
// ---------------------------------------------------------------------------

fn six_unsynced_notes(d: &TestDir) -> (RecorderConfig, std::path::PathBuf) {
    let c = cfg(d.path(), big());
    let mut r = open(c.clone());
    for i in 0..6 {
        recorded(r.append_note(&note(i), false).unwrap());
    }
    let seg_idx = *r.segments().last().unwrap();
    drop(r); // SealsOnly: the notes were never fsynced
    (c, d.path().join(segment_file_name(seg_idx)))
}

#[test]
fn b3_zero_hole_before_valid_frames_is_quarantined_not_bricking() {
    let d = TestDir::new("r3-b3");
    let (c, path) = six_unsynced_notes(&d);
    let mut bytes = std::fs::read(&path).unwrap();
    let fr = frames(&bytes);
    let (off, len, ref hole_rec) = fr[fr.len() - 3];
    let hole_seq = hole_rec.seq;
    let last_seq = fr.last().unwrap().2.seq;
    let original = bytes.clone();
    for b in &mut bytes[off..off + len] {
        *b = 0;
    }
    std::fs::write(&path, &bytes).unwrap();

    let r = Recorder::open(c.clone(), signer(), clock()).expect("must not brick");
    assert!(
        r.head().unwrap().0 > last_seq,
        "quarantined seqs not reused"
    );
    drop(r);
    let rp: RecoveryPayload = last_of(d.path(), RecordKind::Recovery).unwrap();
    assert_eq!(rp.offset, off as u64);
    assert_eq!(rp.discarded_records, 2);
    assert_eq!(rp.discarded_seqs, Some([hole_seq, last_seq]));
    assert!(rp.crash_plausible);
    assert_eq!(rp.severity, Some(Severity::High));
    // The damaged suffix is kept byte for byte, with its hash recorded.
    let q = std::fs::read(d.path().join(rp.quarantine_file.as_ref().unwrap())).unwrap();
    assert_eq!(q, bytes[off..]);
    assert_eq!(rp.discarded_sha256, to_hex(&sha256(&q)));
    assert_eq!(rp.discarded_bytes, (original.len() - off) as u64);
    let rs: ResumePayload = last_of(d.path(), RecordKind::Resume).unwrap();
    assert_eq!(rs.skipped_seqs, Some([hole_seq, last_seq]));

    // A crash explains it: intact, not clean, no Deleted.
    let rep = vdir(d.path());
    assert!(rep.is_intact(), "{}", dump(&rep));
    assert!(!rep.is_clean());
    assert!(has(&rep, |k| matches!(
        k,
        FindingKind::RecoveryRecorded { .. }
    )));
    assert!(!has(&rep, |k| matches!(k, FindingKind::Deleted { .. })));
    assert_unique_seqs(d.path());

    // And the recorder keeps working across further restarts.
    let mut r = open(c.clone());
    recorded(r.append_note(&note(99), false).unwrap());
    r.close().unwrap();
    assert!(vdir(d.path()).is_intact());
}

#[test]
fn b3_partial_page_loss_inside_a_frame_is_quarantined() {
    // A zeroed run inside one frame's payload (the frame still parses but
    // its hash fails) plus valid frames after it.
    let d = TestDir::new("r3-b3-partial");
    let (c, path) = six_unsynced_notes(&d);
    let mut bytes = std::fs::read(&path).unwrap();
    let fr = frames(&bytes);
    let (off, _, _) = fr[3];
    for b in &mut bytes[off + 80..off + 112] {
        *b = 0;
    }
    std::fs::write(&path, &bytes).unwrap();
    let r = Recorder::open(c, signer(), clock()).expect("must not brick");
    drop(r);
    let rp: RecoveryPayload = last_of(d.path(), RecordKind::Recovery).unwrap();
    assert_eq!(rp.offset, off as u64);
    assert!(rp.crash_plausible);
    assert!(vdir(d.path()).is_intact());
}

#[test]
fn b3_hole_before_a_synced_record_is_quarantined_but_reported_as_tamper() {
    let d = TestDir::new("r3-b3-synced");
    let c = cfg(d.path(), big());
    let mut r = open(c.clone());
    for i in 0..4 {
        recorded(r.append_note(&note(i), false).unwrap());
    }
    r.seal().unwrap(); // fsync: everything before it is durable
    recorded(r.append_note(&note(4), false).unwrap());
    drop(r);
    let path = d.path().join(segment_file_name(0));
    let mut bytes = std::fs::read(&path).unwrap();
    let (off, len, _) = frames(&bytes)[2];
    for b in &mut bytes[off..off + len] {
        *b = 0;
    }
    std::fs::write(&path, &bytes).unwrap();
    drop(Recorder::open(c, signer(), clock()).expect("must not brick"));
    let rp: RecoveryPayload = last_of(d.path(), RecordKind::Recovery).unwrap();
    assert!(!rp.crash_plausible);
    assert_eq!(rp.severity, Some(Severity::Critical));
    let rep = vdir(d.path());
    assert!(!rep.is_intact());
    assert!(has(&rep, |k| matches!(
        k,
        FindingKind::DamageQuarantined { .. }
    )));
    assert_unique_seqs(d.path());
}

#[test]
fn b3_non_zero_modification_is_still_refused() {
    // The never-brick path is for zero-filled damage only; a flipped byte
    // in a complete frame is tampering and stays Error::Corrupt.
    let d = TestDir::new("r3-b3-flip");
    let (c, path) = six_unsynced_notes(&d);
    let mut bytes = std::fs::read(&path).unwrap();
    let (off, _, _) = frames(&bytes)[3];
    bytes[off + 80] ^= 0x01;
    std::fs::write(&path, &bytes).unwrap();
    assert!(matches!(
        Recorder::open(c, signer(), clock()),
        Err(Error::Corrupt { .. })
    ));
    assert_eq!(std::fs::read(&path).unwrap(), bytes);
}

// ---------------------------------------------------------------------------
// Key rotation and keyrings
// ---------------------------------------------------------------------------

const KEY_B: [u8; 32] = [0x43; 32];

fn key_b() -> HmacSha256Key {
    HmacSha256Key::new("unit-key-2", &KEY_B).unwrap()
}

fn both_keys() -> Keyring {
    let mut k = Keyring::new();
    k.add(Box::new(verifier())).unwrap();
    k.add(Box::new(key_b())).unwrap();
    k
}

#[test]
fn rotation_keeps_the_chain_and_verifies_with_a_keyring() {
    let d = TestDir::new("rot");
    let c = cfg(d.path(), big());
    let mut r = open(c.clone());
    for i in 0..3 {
        recorded(r.append_note(&note(i), false).unwrap());
    }
    let chain = r.chain_id();
    let cp = r
        .rotate_key(Box::new(key_b()), None, "scheduled rotation")
        .unwrap();
    assert_eq!(cp.key_id, "unit-key-2");
    assert_eq!(r.key_id(), "unit-key-2");
    assert_eq!(r.chain_id(), chain);
    for i in 3..40 {
        recorded(r.append_note(&note(i), false).unwrap());
    }
    assert!(r.segments().len() > 1);
    let last = r.close().unwrap();
    assert_eq!(last.key_id, "unit-key-2");

    let rot: KeyRotationPayload = last_of(d.path(), RecordKind::KeyRotation).unwrap();
    assert_eq!(
        (rot.from.key_id.as_str(), rot.to.key_id.as_str()),
        ("unit-key", "unit-key-2")
    );
    let ss: SegmentStartPayload = last_of(d.path(), RecordKind::SegmentStart).unwrap();
    assert_eq!(ss.signing_key.unwrap().key_id, "unit-key-2");
    assert_eq!(ss.identity.key_id, "unit-key");

    let ring = both_keys();
    let rep = verify_dir(d.path(), &ring, &VerifyOptions::default()).unwrap();
    assert!(rep.is_intact() && rep.is_clean(), "{}", dump(&rep));
    assert!(has(&rep, |k| matches!(
        k,
        FindingKind::KeyRotationRecorded { .. }
    )));
    // Either key alone is not enough.
    assert!(!vdir(d.path()).is_intact());
    assert!(!verify_dir(d.path(), &key_b(), &VerifyOptions::default())
        .unwrap()
        .is_intact());
    // The external checkpoint names its key; the keyring finds it.
    let ext = verify_dir(
        d.path(),
        &ring,
        &VerifyOptions {
            checkpoint: Some(last),
            ..Default::default()
        },
    )
    .unwrap();
    assert!(ext.is_intact());

    // Reopen: the old key may no longer sign; it must not need to.
    assert!(matches!(
        Recorder::open(c.clone(), signer(), clock()),
        Err(Error::KeyMismatch { .. })
    ));
    // The new key alone cannot authenticate the retained old-key records.
    assert!(matches!(
        Recorder::open(c.clone(), Box::new(key_b()), clock()),
        Err(Error::Corrupt { .. })
    ));
    let mut prev = Keyring::new();
    prev.add(Box::new(verifier())).unwrap();
    let mut r = Recorder::open_with_keys(c, Box::new(key_b()), None, Some(Box::new(prev)), clock())
        .unwrap();
    recorded(r.append_note(&note(100), false).unwrap());
    r.close().unwrap();
    assert!(
        verify_dir(d.path(), &both_keys(), &VerifyOptions::default())
            .unwrap()
            .is_intact()
    );
}

#[test]
fn rotation_in_the_active_segment_survives_restart_and_cyclic_wrap() {
    let d = TestDir::new("rot-wrap");
    let c = cfg(d.path(), RetentionMode::Cyclic { max_segments: 2 });
    let mut r = open(c.clone());
    recorded(r.append_note(&note(0), false).unwrap());
    r.rotate_key(Box::new(key_b()), None, "t").unwrap();
    recorded(r.append_note(&note(1), false).unwrap());
    drop(r); // crash right after the rotation, same segment
    let mut prev = Keyring::new();
    prev.add(Box::new(verifier())).unwrap();
    let mut r = Recorder::open_with_keys(
        c.clone(),
        Box::new(key_b()),
        None,
        Some(Box::new(prev)),
        clock(),
    )
    .unwrap();
    // Wrap until every old-key segment is gone.
    let mut i = 10;
    while r.segments()[0] < 3 {
        recorded(r.append_note(&note(i), false).unwrap());
        i += 1;
    }
    r.close().unwrap();
    // Now the new key alone opens and verifies the retained tail.
    open_b(&c).close().unwrap();
    let rep = verify_dir(d.path(), &key_b(), &VerifyOptions::default()).unwrap();
    assert!(rep.is_intact(), "{}", dump(&rep));
}

fn open_b(c: &RecorderConfig) -> Recorder {
    Recorder::open(c.clone(), Box::new(key_b()), clock()).unwrap()
}

#[test]
fn rotate_key_rejects_bad_new_keys() {
    let d = TestDir::new("rot-bad");
    let mut r = open(cfg(d.path(), big()));
    // Same key id.
    assert!(matches!(
        r.rotate_key(signer(), None, "x"),
        Err(Error::Config(_))
    ));
    // Verifier for another key.
    assert!(matches!(
        r.rotate_key(Box::new(key_b()), Some(Box::new(verifier())), "x"),
        Err(Error::Config(_))
    ));
    // A signer that cannot self-verify and no verifier.
    struct Opaque(HmacSha256Key);
    impl Signer for Opaque {
        fn algorithm(&self) -> &str {
            Signer::algorithm(&self.0)
        }
        fn key_id(&self) -> &str {
            Signer::key_id(&self.0)
        }
        fn sign(&self, m: &[u8]) -> Result<Vec<u8>, SignError> {
            self.0.sign(m)
        }
    }
    assert!(matches!(
        r.rotate_key(Box::new(Opaque(key_b())), None, "x"),
        Err(Error::Config(_))
    ));
    // ... but with its verifier it works.
    r.rotate_key(Box::new(Opaque(key_b())), Some(Box::new(key_b())), "x")
        .unwrap();
    // Rotating back to a retired key id is refused.
    assert!(matches!(
        r.rotate_key(signer(), None, "x"),
        Err(Error::Config(_))
    ));
    r.close().unwrap();
    assert!(
        verify_dir(d.path(), &both_keys(), &VerifyOptions::default())
            .unwrap()
            .is_intact()
    );
}

#[test]
fn receiver_accepts_bundles_across_a_rotation_with_a_keyring() {
    let d = TestDir::new("rot-bundle");
    let mut r = open(cfg(d.path(), big()));
    for i in 0..3 {
        recorded(r.append_note(&note(i), false).unwrap());
    }
    let ring = both_keys();
    let mut rx = Receiver::new(Some("ugv-01".into()));
    let b1 = r.export_pending(None).unwrap().unwrap();
    assert!(rx.accept(&b1, &ring).is_intact());
    r.mark_exported(&b1).unwrap();
    r.rotate_key(Box::new(key_b()), None, "t").unwrap();
    for i in 3..6 {
        recorded(r.append_note(&note(i), false).unwrap());
    }
    let b2 = r.export_pending(None).unwrap().unwrap();
    let rep = rx.accept(&b2, &ring);
    assert!(rep.is_intact(), "{}", dump(&rep));
    assert_eq!(rx.state().unwrap().seq, b2.last().unwrap().0);
    // With only the old key, the post-rotation bundle is rejected.
    let mut old_only = Receiver::with_state(
        Some("ugv-01".into()),
        b1.last()
            .map(|(seq, hash)| Anchor {
                chain_id: r.chain_id(),
                seq,
                hash,
            })
            .unwrap(),
    );
    assert!(!old_only.accept(&b2, &verifier()).is_intact());
}

#[test]
fn quarantine_dir_holds_only_private_files() {
    // The evidence copies written by B1/B3 are private like everything else.
    let d = TestDir::new("r3-q-modes");
    let (c, _, _, _) = truncated_below_checkpoint(&d);
    drop(open(c));
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        for e in std::fs::read_dir(d.path().join(QUARANTINE_DIR)).unwrap() {
            let m = e.unwrap().metadata().unwrap().permissions().mode() & 0o777;
            assert_eq!(m, 0o600);
        }
    }
}
