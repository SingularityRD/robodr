//! Review findings on in-place key rotation: a retired key (usually retired
//! because it leaked) must vouch for nothing after the `KeyRotation` that
//! retired it. Every test is attack-shaped: the attacker holds the retired
//! key `k1` and write access to the log directory, never `k2`.
mod common;
use common::*;
use robodr_blackbox::export::cursor_signing_message;
use robodr_blackbox::record::{
    signing_message, KeyRotationPayload, Record, ResumePayload, SegmentStartPayload,
};
use robodr_blackbox::store::{
    list_segments, segment_file_name, CHECKPOINT_FILE, CURSOR_FILE, HEAD_FILE,
};
use robodr_blackbox::verify::{read_segments, verify_dir, verify_segments};
use robodr_blackbox::*;
use std::path::Path;

fn k1() -> Ed25519SigningKey {
    Ed25519SigningKey::from_seed("bb-1", &[1; 32]).unwrap()
}
fn k2() -> Ed25519SigningKey {
    Ed25519SigningKey::from_seed("bb-2", &[2; 32]).unwrap()
}
/// Another key under the new key's id (a swapped `.pub`, a forged target).
fn k2_impostor() -> Ed25519SigningKey {
    Ed25519SigningKey::from_seed("bb-2", &[9; 32]).unwrap()
}

fn prev(keys: &[&Ed25519SigningKey]) -> Box<dyn Verifier> {
    let mut ring = Keyring::new();
    for k in keys {
        ring.add(Box::new(k.verifying_key())).unwrap();
    }
    Box::new(ring)
}

fn open_k2(c: &RecorderConfig) -> Result<Recorder, Error> {
    Recorder::open_with_keys(
        c.clone(),
        Box::new(k2()),
        None,
        Some(prev(&[&k1()])),
        clock(),
    )
}

/// A log under k1, rotated to k2, with k2 records after the rotation.
/// Returns the config and the rotation record's seq.
fn rotated_log(dir: &Path, after: u64) -> (RecorderConfig, u64) {
    let mut c = cfg(dir, big());
    c.max_segment_bytes = 1 << 20; // one segment
    let mut r = Recorder::open(c.clone(), Box::new(k1()), clock()).unwrap();
    for i in 0..3 {
        recorded(r.append_note(&note(i), false).unwrap());
    }
    r.rotate_key(Box::new(k2()), None, "k1 leaked").unwrap();
    for i in 3..3 + after {
        recorded(r.append_note(&note(i), false).unwrap());
    }
    r.close().unwrap();
    let rot = all_records(dir)
        .into_iter()
        .find(|r| r.kind == RecordKind::KeyRotation)
        .unwrap()
        .seq;
    (c, rot)
}

/// `rec` re-chained after `prev` (seq + 1, prev_hash), hashed and signed.
fn chain_after(prev: &Record, mut rec: Record, key: &dyn Signer) -> Record {
    rec.seq = prev.seq + 1;
    rec.prev_hash = prev.hash;
    rec.hash = rec.compute_hash();
    rec.sig = key.sign(&signing_message(&rec.hash)).unwrap();
    rec
}

fn last_segment(dir: &Path) -> std::path::PathBuf {
    list_segments(dir).unwrap().pop().unwrap().1
}

fn resume_of(dir: &Path) -> ResumePayload {
    all_records(dir)
        .iter()
        .rev()
        .find(|r| r.kind == RecordKind::Resume)
        .and_then(|r| r.payload_json())
        .unwrap()
}

// Finding 1: k1-signed events after the rotation (the log truncated right
// after the KeyRotation record, forged events appended) are not chained on.
#[test]
fn retired_key_records_after_the_rotation_are_refused() {
    let d = TestDir::new("rk-events");
    let (c, rot) = rotated_log(d.path(), 2);
    let seg = last_segment(d.path());
    let bytes = std::fs::read(&seg).unwrap();
    let fr = frames(&bytes);
    let pos = fr.iter().position(|(_, _, r)| r.seq == rot).unwrap();
    let (off, len, rot_rec) = fr[pos].clone();
    let mut out = bytes[..off + len].to_vec();
    let mut prev = rot_rec;
    for (_, _, r) in fr.iter().skip(pos + 1).take(2) {
        let mut f = r.clone();
        f.kind = RecordKind::Note;
        f.payload = serde_json::to_vec(&serde_json::json!({"forged": "by k1"})).unwrap();
        let f = chain_after(&prev, f, &k1());
        out.extend_from_slice(&f.encode_frame());
        prev = f;
    }
    std::fs::write(&seg, &out).unwrap();
    match open_k2(&c) {
        Err(Error::Corrupt { reason, .. }) => assert!(reason.contains("bb-2"), "{reason}"),
        other => panic!("retired-key records after the rotation accepted: {other:?}"),
    }
    // The independent verifier agrees.
    let ring = prev_ring();
    let rep = verify_dir(d.path(), &ring, &VerifyOptions::default()).unwrap();
    assert!(!rep.is_intact(), "{}", dump(&rep));
}

fn prev_ring() -> Keyring {
    let mut ring = Keyring::new();
    ring.add(Box::new(k1().verifying_key())).unwrap();
    ring.add(Box::new(k2().verifying_key())).unwrap();
    ring
}

// Finding 1: state files forged with k1 for positions after the rotation
// (truncated tail hidden behind k1-signed head.json / checkpoint.json; an
// export cursor claiming unexported records are exported) are rejected.
#[test]
fn retired_key_state_after_the_rotation_is_rejected() {
    let d = TestDir::new("rk-state");
    let (c, rot) = rotated_log(d.path(), 6);
    let recs = all_records(d.path());
    let chain_id = recs[0].chain_id;
    // Truncate: keep up to two records after the rotation.
    let keep = recs.iter().find(|r| r.seq == rot + 2).unwrap().clone();
    let seg = last_segment(d.path());
    let bytes = std::fs::read(&seg).unwrap();
    let fr = frames(&bytes);
    let (off, len, _) = fr
        .iter()
        .find(|(_, _, r)| r.seq == keep.seq)
        .unwrap()
        .clone();
    std::fs::write(&seg, &bytes[..off + len]).unwrap();
    // Forge the state under k1 to hide the cut.
    let cp = Checkpoint {
        chain_id,
        seq: keep.seq,
        hash: keep.hash,
        key_id: "bb-1".into(),
        sig: k1().sign(&signing_message(&keep.hash)).unwrap(),
    };
    std::fs::write(d.path().join(HEAD_FILE), cp.to_json()).unwrap();
    std::fs::write(d.path().join(CHECKPOINT_FILE), cp.to_json()).unwrap();
    let a = Anchor {
        chain_id,
        seq: keep.seq,
        hash: keep.hash,
    };
    let cur = SignedCursor {
        sig: k1().sign(&cursor_signing_message(&a)).unwrap(),
        anchor: a,
    };
    std::fs::write(d.path().join(CURSOR_FILE), cur.to_json()).unwrap();

    let r = open_k2(&c).unwrap();
    assert!(
        r.export_cursor().is_none(),
        "a k1-signed export cursor after the rotation is trusted (would prune unexported records)"
    );
    drop(r);
    let rej = resume_of(d.path()).rejected_state.join("\n");
    for f in [HEAD_FILE, CHECKPOINT_FILE, CURSOR_FILE] {
        assert!(rej.contains(f), "{f} not rejected: {rej}");
    }
}

// The rotation re-signs the export cursor under the new key, and a
// retired-key mark at or before the rotation still counts.
#[test]
fn rotation_resigns_the_cursor_and_old_positions_stay_valid() {
    let d = TestDir::new("rk-cursor");
    let c = cfg(d.path(), big());
    let mut r = Recorder::open(c.clone(), Box::new(k1()), clock()).unwrap();
    for i in 0..3 {
        recorded(r.append_note(&note(i), false).unwrap());
    }
    let b = r.export_pending(None).unwrap().unwrap();
    r.mark_exported(&b).unwrap();
    let exported = r.export_cursor().cloned().unwrap();
    r.rotate_key(Box::new(k2()), None, "t").unwrap();
    r.close().unwrap();
    let cur =
        SignedCursor::from_json(&std::fs::read_to_string(d.path().join(CURSOR_FILE)).unwrap())
            .unwrap();
    assert!(k2()
        .verify_own(&cursor_signing_message(&cur.anchor), &cur.sig)
        .unwrap());
    let r = open_k2(&c).unwrap();
    assert_eq!(r.export_cursor(), Some(&exported));
}

// Finding 1 + 3: the tail replaced by a forged k1 segment (SegmentStart
// naming the chain key k1, k1 events, and a forged KeyRotation k1 -> k2
// so the current key matches) is refused: the previous segment ended
// with k2, and a switch back to an earlier key is never a rotation.
#[test]
fn forged_tail_switching_back_to_the_retired_key_is_refused() {
    let d = TestDir::new("rk-switchback");
    let c = cfg(d.path(), big());
    let mut r = Recorder::open(c.clone(), Box::new(k1()), clock()).unwrap();
    recorded(r.append_note(&note(0), false).unwrap());
    r.rotate_key(Box::new(k2()), None, "k1 leaked").unwrap();
    let mut i = 1;
    while r.segments().len() < 4 {
        recorded(r.append_note(&note(i), false).unwrap());
        i += 1;
    }
    r.close().unwrap();
    let segs = list_segments(d.path()).unwrap();
    let (prev_idx, prev_path) = segs[segs.len() - 2].clone();
    let (last_idx, last_path) = segs[segs.len() - 1].clone();
    let prev_last = frames(&std::fs::read(&prev_path).unwrap()).pop().unwrap().2;
    let orig = frames(&std::fs::read(&last_path).unwrap());
    let ss0 = orig[0].2.clone();
    let mut ssp: SegmentStartPayload = ss0.payload_json().unwrap();
    assert_eq!(ssp.segment_index, last_idx);
    assert!(prev_idx + 1 == last_idx);
    ssp.signing_key = None; // names the chain key, k1
    ssp.signing_key_fingerprint = None;
    let mut ss = ss0.clone();
    ss.payload = serde_json::to_vec(&ssp).unwrap();
    let ss = chain_after(&prev_last, ss, &k1());
    let mut ev = orig[1].2.clone();
    ev.kind = RecordKind::Note;
    ev.payload = serde_json::to_vec(&serde_json::json!({"forged": "by k1"})).unwrap();
    let ev = chain_after(&ss, ev, &k1());
    let rot: KeyRotationPayload = all_records(d.path())
        .iter()
        .find(|r| r.kind == RecordKind::KeyRotation)
        .unwrap()
        .payload_json()
        .unwrap();
    let mut kr = orig[1].2.clone();
    kr.kind = RecordKind::KeyRotation;
    kr.payload = serde_json::to_vec(&rot).unwrap();
    let kr = chain_after(&ev, kr, &k1());
    let mut out = Vec::new();
    for f in [&ss, &ev, &kr] {
        out.extend_from_slice(&f.encode_frame());
    }
    std::fs::write(&last_path, &out).unwrap();
    // The k2-signed marks would expose the rewrite: the attacker deletes them.
    for f in [HEAD_FILE, CHECKPOINT_FILE] {
        let _ = std::fs::remove_file(d.path().join(f));
    }
    match open_k2(&c) {
        Err(Error::Corrupt { reason, .. }) => assert!(reason.contains("bb-1"), "{reason}"),
        other => panic!("forged k1 tail accepted: {other:?}"),
    }
}

// Finding 3 (verify): once the rotation segment is gone, a SegmentStart
// naming the earlier key must not reset trust to it.
#[test]
fn verifier_refuses_a_switch_back_after_the_rotation_was_pruned() {
    let d = TestDir::new("rk-verify-back");
    let c = cfg(d.path(), big());
    let mut r = Recorder::open(c, Box::new(k1()), clock()).unwrap();
    recorded(r.append_note(&note(0), false).unwrap());
    r.rotate_key(Box::new(k2()), None, "k1 leaked").unwrap();
    let mut i = 1;
    while r.segments().len() < 4 {
        recorded(r.append_note(&note(i), false).unwrap());
        i += 1;
    }
    r.close().unwrap();
    let all = read_segments(d.path()).unwrap();
    // Retained: the last two segments (the rotation is in segment 0).
    let mut kept: Vec<_> = all[all.len() - 2..].to_vec();
    let prev_last = frames(&kept[0].bytes).pop().unwrap().2;
    let orig = frames(&kept[1].bytes);
    let mut ssp: SegmentStartPayload = orig[0].2.payload_json().unwrap();
    ssp.signing_key = None;
    ssp.signing_key_fingerprint = None;
    let mut ss = orig[0].2.clone();
    ss.payload = serde_json::to_vec(&ssp).unwrap();
    let ss = chain_after(&prev_last, ss, &k1());
    let mut ev = orig[1].2.clone();
    ev.payload = serde_json::to_vec(&serde_json::json!({"forged": "by k1"})).unwrap();
    let ev = chain_after(&ss, ev, &k1());
    let mut out = ss.encode_frame();
    out.extend_from_slice(&ev.encode_frame());
    kept[1].bytes = out;
    let rep = verify_segments(&kept, &prev_ring(), &VerifyOptions::default());
    assert!(
        has(&rep, |k| matches!(k, FindingKind::KeySwitchRefused { .. })),
        "{}",
        dump(&rep)
    );
    assert!(!rep.is_intact());
}

// Finding 4: the rotation commits to the new key's public-key fingerprint.
// Records after it re-signed by another key under the new id (with that
// key's public file swapped into the verifier's keyring / given to the
// recorder) are refused.
#[test]
fn rotation_binds_the_new_key_fingerprint() {
    let d = TestDir::new("rk-fp");
    let (c, rot) = rotated_log(d.path(), 3);
    let rp: KeyRotationPayload = all_records(d.path())
        .iter()
        .find(|r| r.kind == RecordKind::KeyRotation)
        .unwrap()
        .payload_json()
        .unwrap();
    assert_eq!(
        rp.to_fingerprint,
        Some(robodr_blackbox::sign::key_fingerprint(&k2().public_key()))
    );
    // Re-sign every record after the rotation with the impostor.
    for (_, path) in list_segments(d.path()).unwrap() {
        let bytes = std::fs::read(&path).unwrap();
        let mut out = Vec::new();
        for (_, _, mut r) in frames(&bytes) {
            if r.seq > rot {
                r.sig = k2_impostor().sign(&signing_message(&r.hash)).unwrap();
            }
            out.extend_from_slice(&r.encode_frame());
        }
        std::fs::write(&path, &out).unwrap();
    }
    for f in [HEAD_FILE, CHECKPOINT_FILE] {
        let _ = std::fs::remove_file(d.path().join(f));
    }
    let mut ring = Keyring::new();
    ring.add(Box::new(k1().verifying_key())).unwrap();
    ring.add(Box::new(k2_impostor().verifying_key())).unwrap();
    let rep = verify_dir(d.path(), &ring, &VerifyOptions::default()).unwrap();
    assert!(
        has(&rep, |k| matches!(
            k,
            FindingKind::KeyFingerprintMismatch { .. }
        )),
        "{}",
        dump(&rep)
    );
    assert!(!rep.is_intact());
    let r = Recorder::open_with_keys(
        c,
        Box::new(k2_impostor()),
        None,
        Some(prev(&[&k1()])),
        clock(),
    );
    assert!(matches!(r, Err(Error::Corrupt { .. })), "{r:?}");
    // Old (v1) payloads without a fingerprint still parse.
    let v1: KeyRotationPayload = serde_json::from_str(
        r#"{"from":{"key_id":"a","algorithm":"ed25519"},"to":{"key_id":"b","algorithm":"ed25519"},"reason":"r"}"#,
    )
    .unwrap();
    assert_eq!(v1.to_fingerprint, None);
    let _ = segment_file_name(0);
}
