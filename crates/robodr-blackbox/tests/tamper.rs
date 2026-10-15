//! Every tamper type is detected, with the right diagnosis and location.

#![allow(clippy::field_reassign_with_default)]

mod common;

use common::*;
use robodr_blackbox::record::{RecordKind, FRAME_HEADER_LEN};
use robodr_blackbox::verify::verify_dir;
use robodr_blackbox::*;

/// Byte offset of the payload inside a frame.
const PAYLOAD_AT: usize = FRAME_HEADER_LEN + 1 + 32 + 8 + 8 + 8 + 1 + 1 + 1 + 4;

fn splice(seg: &mut SegmentData, off: usize, len: usize, new: &[u8]) {
    seg.bytes.splice(off..off + len, new.iter().copied());
}

/// A pristine 3+ segment log and its final checkpoint.
fn fixture(tag: &str) -> (TestDir, Vec<SegmentData>, Checkpoint) {
    let d = TestDir::new(tag);
    let cp = build_log(d.path(), 50);
    let s = segs(d.path());
    assert!(
        s.len() >= 3,
        "fixture needs several segments, got {}",
        s.len()
    );
    (d, s, cp)
}

#[test]
fn pristine_log_is_clean() {
    let (_d, s, cp) = fixture("pristine");
    let r = verify(&s);
    assert!(r.is_clean(), "{}", dump(&r));
    assert_eq!(r.first_seq, Some(0));
    assert_eq!(r.last_seq, Some(cp.seq));
    assert_eq!(r.verified_records, r.frames);
    assert_eq!(r.identity.as_ref().unwrap().device_id, "ugv-01");
    assert_eq!(r.last_seal_seq, Some(cp.seq));
    let mut o = VerifyOptions::default();
    o.checkpoint = Some(cp);
    o.expected_device_id = Some("ugv-01".into());
    assert!(verify_with(&s, &o).is_clean());
}

#[test]
fn modified_record_is_hash_mismatch_at_exact_location() {
    let (_d, mut s, _) = fixture("modify");
    let (off, _, rec) = frames(&s[1].bytes)[3].clone();
    s[1].bytes[off + PAYLOAD_AT + 2] ^= 0x20;
    let r = verify(&s);
    assert_eq!(
        tamper_kinds(&r),
        vec![FindingKind::HashMismatch { seq: rec.seq }],
        "{}",
        dump(&r)
    );
    let loc = r.tamper().next().unwrap().location.clone().unwrap();
    assert_eq!(loc.segment, s[1].name);
    assert_eq!(loc.segment_position, 1);
    assert_eq!(loc.offset, off as u64);
    assert_eq!(loc.seq, Some(rec.seq));
}

#[test]
fn modified_and_rehashed_record_is_bad_signature() {
    let (_d, mut s, _) = fixture("rehash");
    let (off, len, mut rec) = frames(&s[1].bytes)[4].clone();
    rec.payload[5] ^= 0x01; // same length
    rec.hash = rec.compute_hash(); // attacker recomputes the hash, cannot sign
    splice(&mut s[1], off, len, &rec.encode_frame());
    let r = verify(&s);
    let first = r.tamper().next().unwrap();
    assert_eq!(
        first.kind,
        FindingKind::BadSignature { seq: rec.seq },
        "{}",
        dump(&r)
    );
    assert_eq!(first.location.as_ref().unwrap().offset, off as u64);
    assert!(!r.is_intact());
}

#[test]
fn deleted_record_is_reported_as_deletion() {
    let (_d, mut s, _) = fixture("delete");
    let (off, len, rec) = frames(&s[1].bytes)[5].clone();
    splice(&mut s[1], off, len, &[]);
    let r = verify(&s);
    assert_eq!(
        tamper_kinds(&r),
        vec![FindingKind::Deleted {
            first_missing: rec.seq,
            last_missing: rec.seq
        }],
        "{}",
        dump(&r)
    );
    assert_eq!(
        r.tamper().next().unwrap().location.as_ref().unwrap().seq,
        Some(rec.seq + 1)
    );
}

#[test]
fn deleted_run_of_records() {
    let (_d, mut s, _) = fixture("delete-run");
    let f = frames(&s[1].bytes);
    let (start, end) = (f[2].0, f[6].0); // drop frames 2..=5
    let (a, b) = (f[2].2.seq, f[5].2.seq);
    splice(&mut s[1], start, end - start, &[]);
    let r = verify(&s);
    assert_eq!(
        tamper_kinds(&r),
        vec![FindingKind::Deleted {
            first_missing: a,
            last_missing: b
        }]
    );
}

#[test]
fn reordered_records_are_reported() {
    let (_d, mut s, _) = fixture("reorder");
    let f = frames(&s[1].bytes);
    let (o1, l1, r1) = f[3].clone();
    let (o2, l2, r2) = f[4].clone();
    assert_eq!(o1 + l1, o2);
    let mut swapped = s[1].bytes[o2..o2 + l2].to_vec();
    swapped.extend_from_slice(&s[1].bytes[o1..o1 + l1]);
    splice(&mut s[1], o1, l1 + l2, &swapped);
    let r = verify(&s);
    assert_eq!(
        tamper_kinds(&r),
        vec![FindingKind::Reordered {
            seq: r1.seq,
            after_seq: r2.seq
        }],
        "{}",
        dump(&r)
    );
}

#[test]
fn reordered_segments_are_reported() {
    let (_d, mut s, _) = fixture("reorder-seg");
    s.swap(0, 1);
    let r = verify(&s);
    assert!(
        has(&r, |k| matches!(k, FindingKind::Reordered { .. })),
        "{}",
        dump(&r)
    );
}

#[test]
fn inserted_duplicate_is_replay() {
    let (_d, mut s, _) = fixture("dup");
    let f = frames(&s[0].bytes);
    let (o, l, rec) = f[2].clone();
    let copy = s[0].bytes[o..o + l].to_vec();
    let at = frames(&s[1].bytes)[3].0;
    splice(&mut s[1], at, 0, &copy);
    let r = verify(&s);
    assert_eq!(tamper_kinds(&r).len(), 1, "{}", dump(&r));
    assert!(matches!(
        tamper_kinds(&r)[0],
        FindingKind::Duplicate { seq, .. } if seq == rec.seq
    ));
}

#[test]
fn inserted_forged_record_is_bad_signature() {
    let (_d, mut s, _) = fixture("forge");
    let f = frames(&s[1].bytes);
    let (_, _, mut rec) = f[3].clone();
    // Forge "seq+1" with a different key and insert it after the original.
    rec.prev_hash = rec.hash;
    rec.seq += 1;
    rec.payload = br#"{"msg":"nothing happened"}"#.to_vec();
    rec.hash = rec.compute_hash();
    let other = HmacSha256Key::new(KEY_ID, &[0x99; 32]).unwrap();
    rec.sig = Signer::sign(&other, &robodr_blackbox::record::signing_message(&rec.hash)).unwrap();
    let at = f[4].0;
    splice(&mut s[1], at, 0, &rec.encode_frame());
    let r = verify(&s);
    let k = tamper_kinds(&r);
    assert_eq!(
        k,
        vec![FindingKind::BadSignature { seq: rec.seq }],
        "{}",
        dump(&r)
    );
}

fn other_chain(device: &str, boot: &str) -> (TestDir, Vec<SegmentData>) {
    let d = TestDir::new("other");
    let mut c = cfg(d.path(), big());
    c.device_id = device.into();
    c.boot_id = boot.into();
    let mut r = open(c);
    for i in 0..50 {
        recorded(r.append_note(&note(i), false).unwrap());
    }
    r.close().unwrap();
    let s = segs(d.path());
    (d, s)
}

#[test]
fn inserted_record_from_another_device_is_foreign() {
    let (_d, mut s, _) = fixture("foreign-rec");
    let (_od, os) = other_chain("ugv-99", "boot-z");
    let (o, l, orec) = frames(&os[1].bytes)[2].clone();
    let at = frames(&s[1].bytes)[2].0;
    let ins = os[1].bytes[o..o + l].to_vec();
    splice(&mut s[1], at, 0, &ins);
    let r = verify(&s);
    let k = tamper_kinds(&r);
    assert_eq!(k.len(), 1, "{}", dump(&r));
    match &k[0] {
        FindingKind::ForeignChain { seq, .. } => assert_eq!(*seq, orec.seq),
        other => panic!("unexpected {other:?}"),
    }
}

#[test]
fn replayed_segment_from_another_boot_is_detected() {
    let (_d, mut s, _) = fixture("replay-boot");
    // Same device, same key, different boot => different chain.
    let (_od, os) = other_chain("ugv-01", "boot-b");
    let name = s[1].name.clone();
    s[1] = os[1].clone();
    s[1].name = name;
    let r = verify(&s);
    let k = tamper_kinds(&r);
    assert!(
        k.iter().all(|k| matches!(
            k,
            FindingKind::ForeignChain { .. } | FindingKind::Deleted { .. }
        )),
        "{}",
        dump(&r)
    );
    let foreign: Vec<_> = r
        .findings
        .iter()
        .filter(|f| matches!(f.kind, FindingKind::ForeignChain { .. }))
        .collect();
    assert_eq!(foreign.len(), frames(&s[1].bytes).len());
    assert!(foreign
        .iter()
        .all(|f| f.location.as_ref().unwrap().segment_position == 1));
    assert!(has(&r, |k| matches!(k, FindingKind::Deleted { .. })));
}

#[test]
fn log_of_another_device_is_wrong_device() {
    let (_od, os) = other_chain("ugv-99", "boot-z");
    let mut o = VerifyOptions::default();
    o.expected_device_id = Some("ugv-01".into());
    let r = verify_with(&os, &o);
    assert_eq!(
        tamper_kinds(&r),
        vec![FindingKind::WrongDevice {
            expected: "ugv-01".into(),
            found: "ugv-99".into()
        }]
    );
    // Pinning the chain id of ugv-01 instead flags every record as foreign.
    let (_d, s, cp) = fixture("pin-chain");
    let mut o = VerifyOptions::default();
    o.expected_chain_id = Some(cp.chain_id);
    let r = verify_with(&os, &o);
    assert!(r
        .tamper()
        .all(|f| matches!(f.kind, FindingKind::ForeignChain { .. })));
    assert_eq!(r.verified_records, 0);
    assert!(verify_with(&s, &o).is_clean());
}

#[test]
fn wrong_key_is_a_single_key_mismatch() {
    let (_d, s, _) = fixture("wrong-key");
    let wrong = HmacSha256Key::new("fleet-key", &[0x11; 32]).unwrap();
    let r = robodr_blackbox::verify::verify_segments(&s, &wrong, &VerifyOptions::default());
    assert_eq!(
        tamper_kinds(&r),
        vec![FindingKind::KeyMismatch {
            verifier_key_id: "fleet-key".into(),
            recorded_key_id: Some(KEY_ID.into())
        }],
        "{}",
        dump(&r)
    );
}

#[test]
fn truncated_tail_is_detected_against_checkpoint() {
    let (d, s, cp) = fixture("truncate");
    // Drop the last three frames (including the final seal).
    let mut t = s.clone();
    let last = t.len() - 1;
    let f = frames(&t[last].bytes);
    let cut = f[f.len() - 3].0;
    t[last].bytes.truncate(cut);
    // Without a checkpoint the truncation is invisible (documented limit) ...
    assert!(verify(&t).is_intact());
    // ... with the external checkpoint it is caught.
    let mut o = VerifyOptions::default();
    o.checkpoint = Some(cp.clone());
    let r = verify_with(&t, &o);
    assert_eq!(
        tamper_kinds(&r),
        vec![FindingKind::TruncatedTail {
            checkpoint_seq: cp.seq,
            last_seq: Some(cp.seq - 3)
        }]
    );
    // verify_dir picks up the on-disk checkpoint by itself.
    write_segs(d.path(), &t);
    let r = verify_dir(d.path(), &verifier(), &VerifyOptions::default()).unwrap();
    assert!(has(&r, |k| matches!(k, FindingKind::TruncatedTail { .. })));
    // Deleting the whole active segment is caught the same way.
    std::fs::remove_file(d.path().join(&s[last].name)).unwrap();
    let r = verify_dir(d.path(), &verifier(), &VerifyOptions::default()).unwrap();
    assert!(has(&r, |k| matches!(k, FindingKind::TruncatedTail { .. })));
    // A checkpoint whose hash disagrees with the log is a rewrite.
    let mut fake = cp.clone();
    fake.seq = 3;
    let mut o = VerifyOptions::default();
    o.checkpoint = Some(fake);
    let r = verify_with(&s, &o);
    assert_eq!(
        tamper_kinds(&r),
        vec![FindingKind::CheckpointMismatch { checkpoint_seq: 3 }]
    );
    // A checkpoint with a bad signature is ignored with a warning.
    let mut bad = cp;
    bad.sig[0] ^= 1;
    let mut o = VerifyOptions::default();
    o.checkpoint = Some(bad);
    let r = verify_with(&s, &o);
    assert!(r.is_intact() && !r.is_clean());
}

#[test]
fn truncated_closed_segment_is_unsealed() {
    let (_d, mut s, _) = fixture("unsealed");
    let f = frames(&s[0].bytes);
    let (o, _, seal) = f.last().unwrap().clone();
    assert_eq!(seal.kind, RecordKind::Seal);
    s[0].bytes.truncate(o);
    let r = verify(&s);
    let k = tamper_kinds(&r);
    assert!(
        k.contains(&FindingKind::SegmentUnsealed {
            segment: s[0].name.clone()
        }),
        "{}",
        dump(&r)
    );
    assert!(k.contains(&FindingKind::Deleted {
        first_missing: seal.seq,
        last_missing: seal.seq
    }));
}

#[test]
fn deleted_oldest_segment_is_head_missing() {
    let (_d, s, _) = fixture("head");
    let first_seq = frames(&s[1].bytes)[0].2.seq;
    let r = verify(&s[1..]);
    assert_eq!(
        tamper_kinds(&r),
        vec![FindingKind::HeadMissing { first_seq }]
    );
}

#[test]
fn renamed_segment_is_detected() {
    let (_d, mut s, _) = fixture("rename");
    s[1].name = "seg-0000000000000042.rbb".into();
    let r = verify(&s);
    assert_eq!(
        tamper_kinds(&r),
        vec![FindingKind::SegmentIndexMismatch {
            segment: s[1].name.clone(),
            recorded_index: 1
        }]
    );
}

#[test]
fn torn_tail_without_recovery_is_a_warning() {
    let (_d, s, _) = fixture("torn");
    let last = s.len() - 1;
    let frame = frames(&s[0].bytes)[1].clone();
    let partial = s[0].bytes[frame.0..frame.0 + frame.1 / 2].to_vec();
    let mut t = s.clone();
    t[last].bytes.extend_from_slice(&partial);
    let r = verify(&t);
    assert!(r.is_intact(), "{}", dump(&r));
    assert!(!r.is_clean());
    assert!(has(&r, |k| matches!(k, FindingKind::TornTail { .. })));
    // A torn frame at the end of a *closed* segment is not excused.
    let mut c = s.clone();
    c[0].bytes.extend_from_slice(&partial);
    assert!(!verify(&c).is_intact());
    // Garbage instead of a torn frame is not excused either.
    let mut g = s.clone();
    g[last].bytes.extend_from_slice(b"\x01\x02garbage");
    let r = verify(&g);
    assert!(
        tamper_kinds(&r)
            .iter()
            .any(|k| matches!(k, FindingKind::TrailingGarbage { len: 9 })),
        "{}",
        dump(&r)
    );
}

#[test]
fn malformed_bytes_mid_segment_are_located() {
    let (_d, mut s, _) = fixture("malformed");
    let (off, _, _) = frames(&s[1].bytes)[2].clone();
    s[1].bytes[off] = b'X'; // break the magic
    let r = verify(&s);
    let first = r.tamper().next().unwrap();
    assert!(
        matches!(first.kind, FindingKind::Malformed { .. }),
        "{}",
        dump(&r)
    );
    assert_eq!(first.location.as_ref().unwrap().offset, off as u64);
    // The record behind the broken frame is not reported as deleted twice.
    assert_eq!(r.tamper().count(), 1, "{}", dump(&r));
}

#[test]
fn random_single_byte_flips_are_always_detected() {
    let (_d, s, cp) = fixture("fuzz-flip");
    let mut rng = Rng(0x5eed_1234_abcd_0001);
    let total: usize = s.iter().map(|x| x.bytes.len()).sum();
    for iter in 0..400 {
        let mut t = s.clone();
        let mut at = rng.below(total);
        let mut si = 0;
        while at >= t[si].bytes.len() {
            at -= t[si].bytes.len();
            si += 1;
        }
        let mask = (rng.below(255) + 1) as u8;
        t[si].bytes[at] ^= mask;
        let r = verify(&t);
        assert!(
            !r.is_clean(),
            "iteration {iter}: flip {mask:#04x} at {}+{at} went undetected",
            t[si].name
        );
        // With the checkpoint as well, a flip is never reported as clean either.
        let mut o = VerifyOptions::default();
        o.checkpoint = Some(cp.clone());
        assert!(!verify_with(&t, &o).is_clean());
    }
}

#[test]
fn random_truncations_are_detected_with_checkpoint() {
    let (_d, s, cp) = fixture("fuzz-trunc");
    let mut rng = Rng(0x0dd_ba11);
    let mut o = VerifyOptions::default();
    o.checkpoint = Some(cp);
    for _ in 0..100 {
        let mut t = s.clone();
        let si = rng.below(t.len());
        let len = t[si].bytes.len();
        let cut = rng.below(len);
        t[si].bytes.truncate(cut);
        let r = verify_with(&t, &o);
        assert!(
            !r.is_clean(),
            "truncation of {} at {cut} undetected",
            t[si].name
        );
    }
}

#[test]
fn hostile_segments_never_panic() {
    let mut rng = Rng(42);
    for _ in 0..200 {
        let n = rng.below(3) + 1;
        let segs: Vec<SegmentData> = (0..n)
            .map(|i| {
                let len = rng.below(600);
                let mut bytes: Vec<u8> = (0..len).map(|_| rng.next() as u8).collect();
                if len > 16 {
                    bytes[..4].copy_from_slice(b"RBF1");
                }
                SegmentData {
                    name: format!("seg-{i:016}.rbb"),
                    bytes,
                }
            })
            .collect();
        let r = verify(&segs);
        assert!(!r.is_clean());
    }
    assert!(!verify(&[]).is_clean());
}
