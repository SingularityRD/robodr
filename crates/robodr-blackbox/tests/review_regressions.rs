//! Regressions for the independent security review of the evidence recorder.
//!
//! Each `reg_*` test is the review's proof of concept (`review_poc.rs`)
//! ported to assert the FIXED behaviour, plus edge cases around each fix.

mod common;
use common::*;
use robodr_blackbox::export::{cursor_signing_message, Ack, SignedCursor};
use robodr_blackbox::record::{ResumePayload, SegmentDroppedPayload};
use robodr_blackbox::store::{
    segment_file_name, ACK_FILE, CHECKPOINT_FILE, CURSOR_FILE, QUARANTINE_DIR,
};
use robodr_blackbox::verify::verify_dir;
use robodr_blackbox::*;
use std::path::Path;

fn vdir(p: &Path) -> Report {
    verify_dir(p, &verifier(), &VerifyOptions::default()).unwrap()
}

fn last_resume(dir: &Path) -> ResumePayload {
    all_records(dir)
        .iter()
        .rev()
        .find(|r| r.kind == RecordKind::Resume)
        .expect("resume record")
        .payload_json()
        .unwrap()
}

fn drops(dir: &Path) -> Vec<SegmentDroppedPayload> {
    all_records(dir)
        .iter()
        .filter(|r| r.kind == RecordKind::SegmentDropped)
        .filter_map(|r| r.payload_json())
        .collect()
}

// ---------------------------------------------------------------------------
// (a) cyclic anchor forgery
// ---------------------------------------------------------------------------

/// PoC A fixed: a frame planted in the segment about to be dropped no longer
/// steers the drop anchor; deleting the next segment is detected, and a
/// reopen reports it instead of laundering it.
#[test]
fn reg_a_cyclic_anchor_forgery_is_detected() {
    let d = TestDir::new("reg-a");
    let c = cfg(d.path(), RetentionMode::Cyclic { max_segments: 3 });
    let mut r = open(c.clone());
    let mut i = 0;
    while r.segments().len() < 3 {
        recorded(r.append_note(&note(i), false).unwrap());
        i += 1;
    }
    assert_eq!(r.segments(), vec![0, 1, 2]);
    let s1 = std::fs::read(d.path().join(segment_file_name(1))).unwrap();
    let f1 = frames(&s1);
    let seg1_first = f1[0].2.seq;
    let (o, l, _) = f1.last().unwrap().clone();
    let mut s0 = std::fs::read(d.path().join(segment_file_name(0))).unwrap();
    s0.extend_from_slice(&s1[o..o + l]);
    std::fs::write(d.path().join(segment_file_name(0)), &s0).unwrap();
    while r.segments()[0] == 0 {
        recorded(r.append_note(&note(i), false).unwrap());
        i += 1;
    }
    drop(r);
    // The drop anchor is the real end of segment 0, not the planted frame.
    let d0 = drops(d.path())
        .into_iter()
        .find(|x| x.segment_index == 0)
        .unwrap();
    assert_eq!(d0.last_seq, Some(seg1_first - 1));
    assert!(!d0.missing);

    std::fs::remove_file(d.path().join(segment_file_name(1))).unwrap();
    let rep = vdir(d.path());
    assert!(!rep.is_intact(), "deletion not detected:\n{}", dump(&rep));
    assert!(has(&rep, |k| matches!(k, FindingKind::HeadMissing { .. })));

    // Reopen: the recorder notices the gap and records it.
    let mut r = open(c);
    recorded(r.append_note(&note(i), false).unwrap());
    drop(r);
    assert_eq!(last_resume(d.path()).missing_segments, vec![1]);
    let rep = vdir(d.path());
    assert!(!rep.is_intact(), "{}", dump(&rep));
    assert!(has(&rep, |k| matches!(
        k,
        FindingKind::SegmentMissingReported {
            segment_index: 1,
            ..
        }
    )));
    // A second reopen does not report the same segment twice.
    drop(open(cfg(
        d.path(),
        RetentionMode::Cyclic { max_segments: 3 },
    )));
    assert!(last_resume(d.path()).missing_segments.is_empty());
    assert_eq!(
        drops(d.path())
            .iter()
            .filter(|x| x.missing && x.segment_index == 1)
            .count(),
        1
    );
}

/// Control for (a): untampered cyclic wrap across reopens stays intact.
#[test]
fn reg_a_untampered_cyclic_wrap_is_intact() {
    let d = TestDir::new("reg-a-ok");
    let c = cfg(d.path(), RetentionMode::Cyclic { max_segments: 3 });
    let mut i = 0;
    for round in 0..3 {
        let mut r = open(c.clone());
        if round > 0 {
            let rs = last_resume(d.path());
            assert!(rs.missing_segments.is_empty() && rs.rejected_state.is_empty());
        }
        for _ in 0..60 {
            recorded(r.append_note(&note(i), false).unwrap());
            i += 1;
        }
        r.close().unwrap();
    }
    let rep = vdir(d.path());
    assert!(rep.is_intact(), "{}", dump(&rep));
    assert!(!drops(d.path()).is_empty());
    assert!(drops(d.path()).iter().all(|x| !x.missing));
}

/// (a) verifier side: a drop record for some *other* segment whose anchor
/// happens to match does not cover the head.
#[test]
fn reg_a_gap_in_the_middle_is_reported_at_open() {
    let d = TestDir::new("reg-a-gap");
    let c = cfg(d.path(), big());
    let mut r = open(c.clone());
    let mut i = 0;
    while r.segments().len() < 4 {
        recorded(r.append_note(&note(i), false).unwrap());
        i += 1;
    }
    drop(r);
    std::fs::remove_file(d.path().join(segment_file_name(1))).unwrap();
    drop(open(c));
    assert_eq!(last_resume(d.path()).missing_segments, vec![1]);
    let rep = vdir(d.path());
    assert!(!rep.is_intact());
    assert!(has(&rep, |k| matches!(
        k,
        FindingKind::SegmentMissingReported {
            segment_index: 1,
            ..
        }
    )));
}

// ---------------------------------------------------------------------------
// (b) forged export cursor
// ---------------------------------------------------------------------------

fn sat() -> RetentionMode {
    RetentionMode::Saturation {
        max_segments: 50,
        critical_reserve_segments: 2,
    }
}

/// PoC B fixed: an unsigned (or wrongly signed, or out-of-chain) cursor is
/// ignored and reported; nothing unexported is pruned.
#[test]
fn reg_b_forged_export_cursor_is_rejected() {
    let d = TestDir::new("reg-b");
    let c = cfg(d.path(), sat());
    let mut r = open(c.clone());
    let mut i = 0;
    while r.segments().len() < 5 {
        recorded(r.append_note(&note(i), true).unwrap());
        i += 1;
    }
    let chain = r.chain_id();
    let (head, _) = r.head().unwrap();
    drop(r);
    let forged = Anchor {
        chain_id: chain,
        seq: 1_000_000,
        hash: [0; 32],
    };
    std::fs::write(d.path().join(CURSOR_FILE), forged.to_json()).unwrap();
    let mut r = open(c.clone());
    assert!(r.export_cursor().is_none());
    let before = r.segments();
    assert_eq!(r.prune_exported().unwrap(), 0);
    assert_eq!(r.segments(), before);
    let b = r
        .export_pending(None)
        .unwrap()
        .expect("everything is pending");
    assert!(b.anchor.is_none());
    assert!(b.last().unwrap().0 > head);
    drop(r);
    let rs = last_resume(d.path());
    assert!(
        rs.rejected_state.iter().any(|s| s.contains(CURSOR_FILE)),
        "{:?}",
        rs.rejected_state
    );
    let rep = vdir(d.path());
    assert!(rep.is_intact(), "{}", dump(&rep));
    assert!(!has(&rep, |k| matches!(
        k,
        FindingKind::SegmentDropRecorded { .. }
    )));
}

/// (b) a cursor signed with the right key but for a position that is not a
/// real record of the chain (beyond head, wrong hash) is still rejected.
#[test]
fn reg_b_signed_but_inconsistent_cursor_is_rejected() {
    let d = TestDir::new("reg-b-sig");
    let c = cfg(d.path(), sat());
    let mut r = open(c.clone());
    for i in 0..40 {
        recorded(r.append_note(&note(i), false).unwrap());
    }
    let chain = r.chain_id();
    let (head, head_hash) = r.head().unwrap();
    drop(r);
    let key = verifier();
    let sign = |a: Anchor| SignedCursor {
        sig: Signer::sign(&key, &cursor_signing_message(&a)).unwrap(),
        anchor: a,
    };
    let bad = [
        sign(Anchor {
            chain_id: chain,
            seq: head + 1_000,
            hash: head_hash,
        }),
        sign(Anchor {
            chain_id: chain,
            seq: head - 3,
            hash: [7; 32],
        }),
        sign(Anchor {
            chain_id: [9; 32],
            seq: 2,
            hash: head_hash,
        }),
        // Right position, wrong key.
        SignedCursor {
            anchor: Anchor {
                chain_id: chain,
                seq: head,
                hash: head_hash,
            },
            sig: Signer::sign(
                &HmacSha256Key::new(KEY_ID, &[1; 32]).unwrap(),
                &cursor_signing_message(&Anchor {
                    chain_id: chain,
                    seq: head,
                    hash: head_hash,
                }),
            )
            .unwrap(),
        },
    ];
    for cur in bad {
        std::fs::write(d.path().join(CURSOR_FILE), cur.to_json()).unwrap();
        let mut r = open(c.clone());
        assert!(r.export_cursor().is_none(), "accepted {cur:?}");
        assert_eq!(r.prune_exported().unwrap(), 0);
        drop(r);
        assert!(!last_resume(d.path()).rejected_state.is_empty());
    }
    // Garbage and a symlinked cursor file are rejected too, without panics.
    std::fs::write(d.path().join(CURSOR_FILE), b"\xff\x00not json").unwrap();
    assert!(open(c.clone()).export_cursor().is_none());
    std::fs::remove_file(d.path().join(CURSOR_FILE)).unwrap();
    let target = d.sub("elsewhere.json");
    std::fs::write(&target, "{}").unwrap();
    std::os::unix::fs::symlink(&target, d.path().join(CURSOR_FILE)).unwrap();
    assert!(open(c).export_cursor().is_none());
    assert_eq!(std::fs::read_to_string(&target).unwrap(), "{}");
}

/// (b) the legitimate flow still works: a cursor the recorder signed itself
/// survives reopen and bounds pruning; the verifier stays intact.
#[test]
fn reg_b_legit_cursor_survives_reopen_and_prunes() {
    let d = TestDir::new("reg-b-ok");
    let c = cfg(d.path(), sat());
    let mut r = open(c.clone());
    let mut i = 0;
    while r.segments().len() < 4 {
        recorded(r.append_note(&note(i), false).unwrap());
        i += 1;
    }
    let b = r.export_pending(None).unwrap().unwrap();
    let mut rx = Receiver::new(Some("ugv-01".into()));
    assert!(rx.accept(&b, &verifier()).is_intact());
    r.mark_exported(&b).unwrap();
    let cur = r.export_cursor().cloned().unwrap();
    drop(r);
    let mut r = open(c);
    assert_eq!(r.export_cursor(), Some(&cur));
    assert!(last_resume(d.path()).rejected_state.is_empty());
    let pruned = r.prune_exported().unwrap();
    assert_eq!(pruned, 3);
    r.close().unwrap();
    let rep = vdir(d.path());
    assert!(rep.is_intact(), "{}", dump(&rep));
    assert!(drops(d.path()).iter().all(|x| x.exported && !x.missing));
}

/// (b) ack mode: pruning follows only receiver-signed acknowledgements.
#[test]
fn reg_b_ack_mode_prunes_only_what_the_receiver_acked() {
    let d = TestDir::new("reg-b-ack");
    let c = cfg(d.path(), sat());
    let rx_key = HmacSha256Key::new("receiver", &[0x77; 32]).unwrap();
    let rx_verifier = || Box::new(HmacSha256Key::new("receiver", &[0x77; 32]).unwrap());
    let mut r = open(c.clone());
    assert_eq!(r.require_export_acks(rx_verifier()).unwrap(), None);
    let mut i = 0;
    while r.segments().len() < 4 {
        recorded(r.append_note(&note(i), false).unwrap());
        i += 1;
    }
    let b = r.export_pending(None).unwrap().unwrap();
    r.mark_exported(&b).unwrap();
    // The local cursor alone does not allow deletion in ack mode.
    assert_eq!(r.prune_exported().unwrap(), 0);
    let mut rx = Receiver::new(Some("ugv-01".into()));
    assert!(rx.accept(&b, &verifier()).is_intact());
    // An ack signed with some other key is refused.
    let wrong = HmacSha256Key::new("receiver", &[0x78; 32]).unwrap();
    let forged = rx.ack(&wrong).unwrap().unwrap();
    assert!(matches!(r.apply_ack(&forged), Err(Error::Untrusted(_))));
    assert_eq!(r.prune_exported().unwrap(), 0);
    // An ack for a position that is not in the chain is refused.
    let mut a = rx.state().unwrap().clone();
    a.seq += 10_000;
    let beyond = Ack::sign(&a, &rx_key).unwrap();
    assert!(matches!(r.apply_ack(&beyond), Err(Error::Untrusted(_))));
    // The real ack works, persists and survives reopen.
    let ack = rx.ack(&rx_key).unwrap().unwrap();
    assert!(r.apply_ack(&ack).unwrap());
    assert!(!r.apply_ack(&ack).unwrap());
    drop(r);
    let mut r = open(c.clone());
    assert_eq!(r.require_export_acks(rx_verifier()).unwrap(), None);
    assert_eq!(r.acked_position(), Some(&ack.anchor()));
    assert_eq!(r.prune_exported().unwrap(), 3);
    r.close().unwrap();
    assert!(vdir(d.path()).is_intact());
    // A tampered ack file is ignored (and said so), never trusted.
    let mut tampered = ack.clone();
    tampered.seq += 1;
    std::fs::write(d.path().join(ACK_FILE), tampered.to_json()).unwrap();
    let mut r = open(c);
    assert!(r.require_export_acks(rx_verifier()).unwrap().is_some());
    assert!(r.acked_position().is_none());
    assert_eq!(r.prune_exported().unwrap(), 0);
    // Applying an ack without ack mode is a configuration error.
    let d2 = TestDir::new("reg-b-noack");
    let mut r2 = open(cfg(d2.path(), sat()));
    assert!(matches!(r2.apply_ack(&ack), Err(Error::Config(_))));
}

// ---------------------------------------------------------------------------
// (c) tampered last record
// ---------------------------------------------------------------------------

/// PoC C fixed: a modified complete final record is refused at open (file
/// untouched, verifier still sees the tamper), not "recovered".
#[test]
fn reg_c_tampered_last_record_is_refused() {
    let d = TestDir::new("reg-c");
    let mut r = open(cfg(d.path(), big()));
    for i in 0..5 {
        recorded(r.append_note(&note(i), true).unwrap());
    }
    drop(r);
    let p = d.path().join(segment_file_name(0));
    let mut b = std::fs::read(&p).unwrap();
    let (o, _, _) = frames(&b).last().unwrap().clone();
    let pay = o + 8 + 1 + 32 + 24 + 3 + 4;
    b[pay + 3] ^= 0x01;
    std::fs::write(&p, &b).unwrap();
    assert!(!vdir(d.path()).is_intact());
    let e = Recorder::open(cfg(d.path(), big()), signer(), clock()).unwrap_err();
    assert!(matches!(e, Error::Corrupt { .. }), "{e}");
    assert_eq!(std::fs::read(&p).unwrap(), b, "file must not be touched");
    assert!(!d.path().join("quarantine").exists());
    let rep = vdir(d.path());
    assert!(!rep.is_intact());
    assert!(!has(&rep, |k| matches!(
        k,
        FindingKind::RecoveryRecorded { .. }
    )));
}

/// (c) non-zero trailing bytes that are not a torn frame are refused too.
#[test]
fn reg_c_trailing_garbage_is_refused_not_recovered() {
    let d = TestDir::new("reg-c-garbage");
    let mut r = open(cfg(d.path(), big()));
    for i in 0..3 {
        recorded(r.append_note(&note(i), false).unwrap());
    }
    drop(r);
    let p = d.path().join(segment_file_name(0));
    let mut b = std::fs::read(&p).unwrap();
    b.extend_from_slice(&[0xAB; 7]);
    std::fs::write(&p, &b).unwrap();
    let e = Recorder::open(cfg(d.path(), big()), signer(), clock()).unwrap_err();
    assert!(matches!(e, Error::Corrupt { .. }), "{e}");
    assert_eq!(std::fs::read(&p).unwrap(), b);
}

/// (c) a genuine torn write is still recovered, but it is a warning: the
/// log is intact, not clean.
#[test]
fn reg_c_genuine_torn_write_is_a_warning() {
    let d = TestDir::new("reg-c-torn");
    let mut r = open(cfg(d.path(), big()));
    for i in 0..5 {
        recorded(r.append_note(&note(i), false).unwrap());
    }
    drop(r);
    let p = d.path().join(segment_file_name(0));
    let b = std::fs::read(&p).unwrap();
    let (o, l, _) = frames(&b).last().unwrap().clone();
    std::fs::write(&p, &b[..o + l / 2]).unwrap();
    drop(open(cfg(d.path(), big())));
    let rep = vdir(d.path());
    assert!(rep.is_intact(), "{}", dump(&rep));
    assert!(!rep.is_clean());
    assert!(rep
        .findings
        .iter()
        .any(|f| matches!(f.kind, FindingKind::RecoveryRecorded { .. })
            && f.level == FindingLevel::Warning));
}

// ---------------------------------------------------------------------------
// (d) forged head
// ---------------------------------------------------------------------------

/// PoC D fixed: a record with a valid hash but a forged signature at the
/// head makes open refuse; nothing is chained onto it.
#[test]
fn reg_d_forged_head_is_refused() {
    let d = TestDir::new("reg-d");
    let mut r = open(cfg(d.path(), big()));
    for i in 0..3 {
        recorded(r.append_note(&note(i), false).unwrap());
    }
    drop(r);
    let p = d.path().join(segment_file_name(0));
    let mut b = std::fs::read(&p).unwrap();
    let (_, _, last) = frames(&b).last().unwrap().clone();
    let mut f = last.clone();
    f.seq += 1;
    f.prev_hash = last.hash;
    f.kind = RecordKind::Note;
    f.payload = br#"{"forged":"operator disabled estop"}"#.to_vec();
    f.hash = f.compute_hash();
    f.sig = vec![0u8; 32];
    b.extend_from_slice(&f.encode_frame());
    std::fs::write(&p, &b).unwrap();
    let e = Recorder::open(cfg(d.path(), big()), signer(), clock()).unwrap_err();
    assert!(matches!(e, Error::Corrupt { .. }), "{e}");
    assert!(e.to_string().contains("signature"), "{e}");
    assert_eq!(std::fs::read(&p).unwrap(), b);
    let rep = vdir(d.path());
    assert!(has(&rep, |k| matches!(k, FindingKind::BadSignature { .. })));
}

/// (d) a forged record in the *middle* of the active segment, and a forged
/// first record of an older retained segment, are refused as well.
#[test]
fn reg_d_forged_records_anywhere_we_trust_are_refused() {
    // Mid active segment.
    let d = TestDir::new("reg-d-mid");
    let mut r = open(cfg(d.path(), big()));
    for i in 0..4 {
        recorded(r.append_note(&note(i), false).unwrap());
    }
    drop(r);
    let p = d.path().join(segment_file_name(0));
    let mut b = std::fs::read(&p).unwrap();
    let (o, _, rec) = frames(&b)[2].clone();
    let mut f = rec.clone();
    f.sig = vec![0x55; rec.sig.len()];
    let enc = f.encode_frame();
    b[o..o + enc.len()].copy_from_slice(&enc);
    std::fs::write(&p, &b).unwrap();
    assert!(matches!(
        Recorder::open(cfg(d.path(), big()), signer(), clock()),
        Err(Error::Corrupt { .. })
    ));

    // First record of an older (closed) segment: the log's own key verifies
    // other records, so this is damage, not a missing key. The segment is
    // quarantined (recorded, reported as tamper) instead of bricking the
    // recorder; nothing is chained onto it.
    let d = TestDir::new("reg-d-old");
    let mut r = open(cfg(d.path(), big()));
    let mut i = 0;
    while r.segments().len() < 3 {
        recorded(r.append_note(&note(i), false).unwrap());
        i += 1;
    }
    drop(r);
    let p = d.path().join(segment_file_name(1));
    let mut b = std::fs::read(&p).unwrap();
    let (o, _, rec) = frames(&b)[0].clone();
    let mut f = rec.clone();
    f.sig = vec![0x55; rec.sig.len()];
    let enc = f.encode_frame();
    b[o..o + enc.len()].copy_from_slice(&enc);
    std::fs::write(&p, &b).unwrap();
    let r = Recorder::open(cfg(d.path(), big()), signer(), clock()).unwrap();
    assert_eq!(r.quarantined_at_open(), &[1]);
    r.close().unwrap();
    assert!(!p.exists());
    let rep = vdir(d.path());
    assert!(!rep.is_intact());
    assert!(has(&rep, |k| matches!(
        k,
        FindingKind::SegmentQuarantined {
            segment_index: 1,
            ..
        }
    )));
    // The forged bytes are kept as evidence, byte for byte.
    let kept = d
        .path()
        .join(QUARANTINE_DIR)
        .join("damaged-seg0000000000000001.rbb");
    assert_eq!(std::fs::read(kept).unwrap(), b);
}

/// (d) a signer that cannot check its own signatures must come with a
/// verifier, and the verifier must match it.
#[test]
fn reg_d_open_requires_a_way_to_authenticate() {
    struct Opaque(HmacSha256Key);
    impl Signer for Opaque {
        fn algorithm(&self) -> &str {
            Signer::algorithm(&self.0)
        }
        fn key_id(&self) -> &str {
            Signer::key_id(&self.0)
        }
        fn sign(&self, m: &[u8]) -> Result<Vec<u8>, robodr_blackbox::sign::SignError> {
            Signer::sign(&self.0, m)
        }
    }
    let d = TestDir::new("reg-d-verifier");
    let e =
        Recorder::open(cfg(d.path(), big()), Box::new(Opaque(verifier())), clock()).unwrap_err();
    assert!(matches!(e, Error::Config(_)), "{e}");
    // Wrong verifier key: self-test fails.
    let e = Recorder::open_with_verifier(
        cfg(d.path(), big()),
        Box::new(Opaque(verifier())),
        Box::new(HmacSha256Key::new(KEY_ID, &[1; 32]).unwrap()),
        clock(),
    )
    .unwrap_err();
    assert!(matches!(e, Error::Config(_)), "{e}");
    let mut r = Recorder::open_with_verifier(
        cfg(d.path(), big()),
        Box::new(Opaque(verifier())),
        Box::new(verifier()),
        clock(),
    )
    .unwrap();
    recorded(r.append_note(&note(1), false).unwrap());
    r.close().unwrap();
    let r = Recorder::open_with_verifier(
        cfg(d.path(), big()),
        Box::new(Opaque(verifier())),
        Box::new(verifier()),
        clock(),
    )
    .unwrap();
    r.close().unwrap();
    assert!(vdir(d.path()).is_clean());
}

// ---------------------------------------------------------------------------
// (e) two writers
// ---------------------------------------------------------------------------

/// PoC E fixed: a second recorder on the same directory is refused while the
/// first is alive (flock is per open file, so this holds within one process
/// as well as across processes); the lock is released on drop.
#[test]
fn reg_e_second_writer_is_locked_out() {
    let d = TestDir::new("reg-e");
    let mut a = open(cfg(d.path(), big()));
    recorded(a.append_note(&note(0), false).unwrap());
    let e = Recorder::open(cfg(d.path(), big()), signer(), clock()).unwrap_err();
    assert!(matches!(e, Error::Locked { .. }), "{e}");
    recorded(a.append_note(&note(1), false).unwrap());
    drop(a);
    let mut b = open(cfg(d.path(), big()));
    recorded(b.append_note(&note(2), false).unwrap());
    let e = Recorder::open(cfg(d.path(), big()), signer(), clock()).unwrap_err();
    assert!(matches!(e, Error::Locked { .. }), "{e}");
    b.close().unwrap();
    let rep = vdir(d.path());
    assert!(rep.is_clean(), "{}", dump(&rep));
    assert!(!has(&rep, |k| matches!(k, FindingKind::Fork { .. })));
}

/// (e) the lock also covers a brand-new directory and is held from before
/// genesis (a racing second open cannot write a second genesis).
#[test]
fn reg_e_lock_covers_fresh_directory() {
    let d = TestDir::new("reg-e-new");
    let dir = d.sub("log");
    let a = open(cfg(&dir, big()));
    assert!(matches!(
        Recorder::open(cfg(&dir, big()), signer(), clock()),
        Err(Error::Locked { .. })
    ));
    a.close().unwrap();
    assert!(vdir(&dir).is_clean());
}

// ---------------------------------------------------------------------------
// (f) symlinks and permissions
// ---------------------------------------------------------------------------

/// PoC F fixed: a symlink planted at the old predictable temp name is never
/// followed, and files/directories are private.
#[test]
fn reg_f_symlink_not_followed_and_private_modes() {
    use std::os::unix::fs::PermissionsExt;
    let d = TestDir::new("reg-f");
    let dir = d.sub("log");
    let victim = d.sub("victim.txt");
    std::fs::write(&victim, "precious").unwrap();
    let mut r = open(cfg(&dir, big()));
    std::os::unix::fs::symlink(&victim, dir.join(format!("{CHECKPOINT_FILE}.tmp"))).unwrap();
    let cp = r.seal().unwrap();
    assert_eq!(std::fs::read_to_string(&victim).unwrap(), "precious");
    let on_disk =
        Checkpoint::from_json(&std::fs::read_to_string(dir.join(CHECKPOINT_FILE)).unwrap())
            .unwrap();
    assert_eq!(on_disk, cp);
    let b = r.export_pending(None).unwrap().unwrap();
    r.mark_exported(&b).unwrap();
    drop(r);
    let mode = |p: &Path| std::fs::metadata(p).unwrap().permissions().mode() & 0o777;
    assert_eq!(mode(&dir), 0o700);
    assert_eq!(mode(&dir.join(segment_file_name(0))), 0o600);
    assert_eq!(mode(&dir.join(CHECKPOINT_FILE)), 0o600);
    assert_eq!(mode(&dir.join(CURSOR_FILE)), 0o600);
    // No temp files left behind (other than the planted symlink).
    let stray: Vec<_> = std::fs::read_dir(&dir)
        .unwrap()
        .filter_map(|e| e.ok())
        .map(|e| e.file_name().to_string_lossy().into_owned())
        .filter(|n| n.ends_with(".tmp") && n != &format!("{CHECKPOINT_FILE}.tmp"))
        .collect();
    assert!(stray.is_empty(), "{stray:?}");
}

/// (f) a symlink at a state file's final name is replaced, not written
/// through; a symlink at the next segment's name makes rotation fail
/// instead of clobbering the target.
#[test]
fn reg_f_symlinks_at_final_names_are_not_followed() {
    let d = TestDir::new("reg-f-final");
    let dir = d.sub("log");
    let victim = d.sub("victim.txt");
    std::fs::write(&victim, "precious").unwrap();
    let mut r = open(cfg(&dir, big()));
    std::os::unix::fs::symlink(&victim, dir.join(CHECKPOINT_FILE)).unwrap();
    r.seal().unwrap();
    assert_eq!(std::fs::read_to_string(&victim).unwrap(), "precious");
    assert!(!std::fs::symlink_metadata(dir.join(CHECKPOINT_FILE))
        .unwrap()
        .file_type()
        .is_symlink());

    std::os::unix::fs::symlink(&victim, dir.join(segment_file_name(1))).unwrap();
    let mut res = Ok(AppendOutcome::Refused(Refusal::Full));
    for i in 0..200 {
        res = r.append_note(&note(i), false);
        if res.is_err() {
            break;
        }
    }
    assert!(res.is_err(), "rotation onto a symlink must fail");
    assert_eq!(std::fs::read_to_string(&victim).unwrap(), "precious");
}
