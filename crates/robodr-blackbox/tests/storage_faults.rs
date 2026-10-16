//! Wave 6: failing storage must not brick the recorder, and a cut tail must
//! not go unnoticed.
//!
//! (1) a damaged *closed* segment is quarantined (recorded, reported as
//!     tamper by the verifier) and recording continues, seqs never reused;
//! (2) the `head.json` high-water mark and the external `HeadAnchor` expose
//!     records cut after the newest seal;
//!
//! Crash-at-every-step tests (fault injection) live in `src/store.rs`
//! (unit tests, they need the crate-private hooks).
mod common;
use common::*;
use robodr_blackbox::crypto::{sha256, to_hex};
use robodr_blackbox::record::{
    signing_message, RecoveryPayload, ResumePayload, SegmentDroppedPayload, TruncationPayload,
};
use robodr_blackbox::store::{
    segment_file_name, CHECKPOINT_FILE, CURSOR_FILE, EXTERNAL_ANCHOR, HEAD_FILE, QUARANTINE_DIR,
};
use robodr_blackbox::verify::verify_dir;
use robodr_blackbox::*;
use robodr_events::Severity;
use std::collections::HashSet;
use std::path::Path;
use std::sync::Arc;

fn vdir(p: &Path) -> Report {
    verify_dir(p, &verifier(), &VerifyOptions::default()).unwrap()
}

fn assert_unique_seqs(dir: &Path) {
    let mut seen = HashSet::new();
    for r in all_records(dir) {
        assert!(seen.insert(r.seq), "seq {} used twice", r.seq);
    }
}

fn payloads<T: for<'de> serde::Deserialize<'de>>(dir: &Path, kind: RecordKind) -> Vec<T> {
    all_records(dir)
        .iter()
        .filter(|r| r.kind == kind)
        .filter_map(|r| r.payload_json())
        .collect()
}

fn seg_quarantines(dir: &Path) -> Vec<RecoveryPayload> {
    payloads::<RecoveryPayload>(dir, RecordKind::Recovery)
        .into_iter()
        .filter(|p| p.quarantined_segment)
        .collect()
}

/// A log with at least `n` segments (the last one active), not closed.
fn multi_segment(c: &RecorderConfig, n: usize) -> u64 {
    let mut r = open(c.clone());
    let mut i = 0;
    while r.segments().len() < n {
        recorded(r.append_note(&note(i), false).unwrap());
        i += 1;
    }
    recorded(r.append_note(&note(i), false).unwrap());
    drop(r);
    i
}

/// Flip one bit at `off` of segment `idx`; returns the new bytes.
fn flip(dir: &Path, idx: u64, off: usize, bit: u8) -> Vec<u8> {
    let p = dir.join(segment_file_name(idx));
    let mut b = std::fs::read(&p).unwrap();
    b[off] ^= 1 << bit;
    std::fs::write(&p, &b).unwrap();
    b
}

// ---------------------------------------------------------------------------
// (1) Damaged closed segments
// ---------------------------------------------------------------------------

#[test]
fn bit_flip_in_closed_segment_is_quarantined_not_bricking() {
    let d = TestDir::new("w6-flip");
    let c = cfg(d.path(), big());
    multi_segment(&c, 4);
    let before = all_records(d.path());
    let max_before = before.iter().map(|r| r.seq).max().unwrap();
    // A payload byte in the middle of segment 1.
    let s1 = std::fs::read(d.path().join(segment_file_name(1))).unwrap();
    let (o, _, rec) = frames(&s1)[3].clone();
    let damaged = flip(d.path(), 1, o + 8 + 1 + 32 + 24 + 3 + 4 + 2, 3);
    let seg1_seqs: Vec<u64> = frames(&s1).iter().map(|(_, _, r)| r.seq).collect();
    assert!(seg1_seqs.contains(&rec.seq));

    let mut r = Recorder::open(c.clone(), signer(), clock()).expect("must not brick");
    assert_eq!(r.quarantined_at_open(), &[1]);
    assert!(r.head().unwrap().0 > max_before);
    recorded(r.append_note(&note(999), false).unwrap());
    r.close().unwrap();

    // The original is gone, the bytes are kept and hashed.
    assert!(!d.path().join(segment_file_name(1)).exists());
    let q = seg_quarantines(d.path());
    assert_eq!(q.len(), 1);
    let q = &q[0];
    assert_eq!(q.segment_index, 1);
    assert!(!q.crash_plausible);
    assert_eq!(q.severity, Some(Severity::High), "hash damage = media");
    assert_eq!(q.discarded_bytes, damaged.len() as u64);
    assert_eq!(q.discarded_sha256, to_hex(&sha256(&damaged)));
    let kept = std::fs::read(d.path().join(q.quarantine_file.as_ref().unwrap())).unwrap();
    assert_eq!(kept, damaged);
    assert_eq!(
        q.discarded_seqs,
        Some([seg1_seqs[0], *seg1_seqs.last().unwrap()])
    );
    // Every frame but the flipped one still hashes.
    assert_eq!(q.discarded_records, seg1_seqs.len() as u64 - 1);

    // The verifier reports the damage and the missing seqs as tamper.
    let rep = vdir(d.path());
    assert!(!rep.is_intact());
    assert!(has(&rep, |k| matches!(
        k,
        FindingKind::SegmentQuarantined {
            segment_index: 1,
            ..
        }
    )));
    assert!(has(&rep, |k| *k
        == FindingKind::Deleted {
            first_missing: seg1_seqs[0],
            last_missing: *seg1_seqs.last().unwrap()
        }));
    assert_unique_seqs(d.path());

    // Reopening again: nothing new to report, no "missing segment" noise.
    open(c).close().unwrap();
    assert_eq!(seg_quarantines(d.path()).len(), 1);
    let missing: Vec<SegmentDroppedPayload> =
        payloads::<SegmentDroppedPayload>(d.path(), RecordKind::SegmentDropped)
            .into_iter()
            .filter(|p| p.missing)
            .collect();
    assert!(missing.is_empty(), "{missing:?}");
    let rs: Vec<ResumePayload> = payloads(d.path(), RecordKind::Resume);
    assert!(rs.last().unwrap().missing_segments.is_empty());
    assert_unique_seqs(d.path());
}

#[test]
fn every_single_bit_flip_in_closed_segments_opens_and_is_reported() {
    // Exhaustive over byte positions (one bit each, varying) of the closed
    // segments of a small log: open never refuses, never reuses a seq, and
    // the verifier always reports something.
    let d0 = TestDir::new("w6-flip-all-src");
    let c0 = cfg(d0.path(), big());
    multi_segment(&c0, 3);
    let pristine = segs(d0.path());
    let closed_len: Vec<usize> = pristine[..pristine.len() - 1]
        .iter()
        .map(|s| s.bytes.len())
        .collect();
    let mut rng = Rng(0x5eed_f00d);
    let mut tried = 0;
    for (si, len) in closed_len.iter().enumerate() {
        // Every 37th byte plus random ones keeps the run time reasonable
        // while still hitting headers, hashes, signatures and payloads.
        let mut offs: Vec<usize> = (0..*len).step_by(37).collect();
        offs.extend((0..30).map(|_| rng.below(*len)));
        for off in offs {
            let d = TestDir::new("w6-flip-all");
            write_segs(d.path(), &pristine);
            for f in [CHECKPOINT_FILE, HEAD_FILE] {
                if let Ok(b) = std::fs::read(d0.path().join(f)) {
                    std::fs::write(d.path().join(f), b).unwrap();
                }
            }
            let bit = (rng.next() % 8) as u8;
            flip(d.path(), si as u64, off, bit);
            let c = cfg(d.path(), big());
            let r = Recorder::open(c, signer(), clock())
                .unwrap_or_else(|e| panic!("flip seg {si} off {off} bit {bit} bricked: {e}"));
            r.close().unwrap();
            assert_unique_seqs(d.path());
            let rep = vdir(d.path());
            assert!(
                !rep.is_intact(),
                "flip seg {si} off {off} bit {bit} undetected:\n{}",
                dump(&rep)
            );
            tried += 1;
        }
    }
    assert!(tried > 60, "{tried}");
}

#[test]
fn damaged_newest_closed_segment_with_empty_active_continues_after_it() {
    // Crash right after the rotation created an empty segment, and the
    // just-closed segment is damaged: chain onto the one before it and
    // never reuse the damaged segment's seqs.
    let d = TestDir::new("w6-newest");
    let c = cfg(d.path(), big());
    let mut r = open(c.clone());
    let mut i = 0;
    while r.segments().len() < 3 {
        recorded(r.append_note(&note(i), false).unwrap());
        i += 1;
    }
    drop(r);
    // Make segment 2 empty again (crash right after its creation) by
    // removing it and creating an empty file.
    std::fs::write(d.path().join(segment_file_name(2)), b"").unwrap();
    let s1 = std::fs::read(d.path().join(segment_file_name(1))).unwrap();
    let s1_max = frames(&s1).last().unwrap().2.seq;
    let (o, _, _) = frames(&s1)[2];
    flip(d.path(), 1, o + 60, 0);
    // The checkpoint of seg 1's rotation seal would also expose the seqs;
    // remove the local state so only the quarantined segment does.
    std::fs::remove_file(d.path().join(CHECKPOINT_FILE)).unwrap();
    std::fs::remove_file(d.path().join(HEAD_FILE)).unwrap();

    let r = Recorder::open(c.clone(), signer(), clock()).unwrap();
    assert_eq!(r.quarantined_at_open(), &[1]);
    let seg0_last = all_records(d.path())
        .iter()
        .filter(|x| x.seq < s1_max)
        .map(|x| x.seq)
        .max()
        .unwrap();
    assert!(seg0_last < s1_max);
    assert!(r.head().unwrap().0 > s1_max, "seq floor after the damage");
    r.close().unwrap();
    assert_unique_seqs(d.path());
    let rs: Vec<ResumePayload> = payloads(d.path(), RecordKind::Resume);
    let skipped = rs.last().unwrap().skipped_seqs.unwrap();
    assert_eq!(skipped[1], s1_max);
    // rev5: the newest segment vanishing while an older one is intact is
    // not media damage: critical, and its authentic records beyond the
    // head are truncation evidence (the quarantine explains nothing).
    assert_eq!(
        seg_quarantines(d.path())[0].severity,
        Some(Severity::Critical)
    );
    let td = payloads::<TruncationPayload>(d.path(), RecordKind::TruncationDetected);
    assert_eq!(td.len(), 1);
    assert!(td[0]
        .evidence
        .iter()
        .any(|e| e.file == segment_file_name(1) && e.seq == s1_max));
    let rep = vdir(d.path());
    assert!(has(&rep, |k| matches!(
        k,
        FindingKind::SegmentQuarantined {
            segment_index: 1,
            ..
        }
    )));
    // Reopen: the declared jump and the gap are accepted.
    open(c).close().unwrap();
    assert_unique_seqs(d.path());
}

#[test]
fn damaged_oldest_segment_under_cyclic_retention() {
    let d = TestDir::new("w6-oldest");
    let c = cfg(d.path(), RetentionMode::Cyclic { max_segments: 3 });
    let mut r = open(c.clone());
    let mut i = 0;
    while r.segments()[0] < 3 {
        recorded(r.append_note(&note(i), false).unwrap());
        i += 1;
    }
    let oldest = r.segments()[0];
    drop(r);
    let b = std::fs::read(d.path().join(segment_file_name(oldest))).unwrap();
    flip(d.path(), oldest, b.len() / 2, 5);
    let mut r = Recorder::open(c.clone(), signer(), clock()).unwrap();
    assert_eq!(r.quarantined_at_open(), &[oldest]);
    for j in 0..40 {
        recorded(r.append_note(&note(1000 + j), false).unwrap());
    }
    r.close().unwrap();
    assert_unique_seqs(d.path());
    let rep = vdir(d.path());
    // Cyclic retention has since dropped what followed; the quarantine
    // record may or may not still be retained, but nothing is reused and
    // the log keeps verifying from its recorded drops.
    assert!(rep.verified_records > 0, "{}", dump(&rep));
}

#[test]
fn cross_segment_link_break_is_quarantined_as_critical() {
    // Segment 1 replaced by a *validly signed* segment that does not end
    // where segment 2 begins (an old copy with its last records removed
    // and re-sealed is not possible without the key; emulate with the
    // key): authentic-looking but inconsistent bytes are critical.
    let d = TestDir::new("w6-link");
    let c = cfg(d.path(), big());
    multi_segment(&c, 4);
    let p = d.path().join(segment_file_name(1));
    let b = std::fs::read(&p).unwrap();
    let fr = frames(&b);
    // Drop the second-to-last record and re-link + re-sign the seal.
    let (o_prev, _, prev) = fr[fr.len() - 3].clone();
    let (_, _, seal) = fr[fr.len() - 1].clone();
    let mut s2 = seal.clone();
    s2.seq = prev.seq + 1;
    s2.prev_hash = prev.hash;
    s2.hash = s2.compute_hash();
    s2.sig = verifier().sign(&signing_message(&s2.hash)).unwrap();
    let mut nb = b[..o_prev + fr[fr.len() - 3].1].to_vec();
    nb.extend_from_slice(&s2.encode_frame());
    std::fs::write(&p, &nb).unwrap();
    let r = Recorder::open(c, signer(), clock()).unwrap();
    assert_eq!(r.quarantined_at_open(), &[1]);
    r.close().unwrap();
    let q = seg_quarantines(d.path());
    assert_eq!(q[0].severity, Some(Severity::Critical));
    assert!(q[0].reason.contains("chains onto"), "{}", q[0].reason);
    assert!(!vdir(d.path()).is_intact());
}

#[test]
fn signature_flip_mid_segment_found_only_with_full_verification() {
    let d = TestDir::new("w6-sig");
    let c = cfg(d.path(), big());
    multi_segment(&c, 3);
    let p = d.path().join(segment_file_name(0));
    let b = std::fs::read(&p).unwrap();
    let (o, l, _) = frames(&b)[3];
    // The signature is the frame's last bytes; the hash does not cover it.
    flip(d.path(), 0, o + l - 5, 2);
    let snapshot = segs(d.path());

    // Default (sampled signatures): opens without quarantine; the verifier
    // still reports the bad signature.
    open(c.clone()).close().unwrap();
    assert!(seg_quarantines(d.path()).is_empty());
    assert!(has(&vdir(d.path()), |k| matches!(
        k,
        FindingKind::BadSignature { .. }
    )));

    // Full verification at open: quarantined as critical.
    let d2 = TestDir::new("w6-sig-full");
    write_segs(d2.path(), &snapshot[..snapshot.len() - 1]);
    std::fs::write(
        d2.path().join(&snapshot.last().unwrap().name),
        &snapshot.last().unwrap().bytes,
    )
    .unwrap();
    let mut c2 = cfg(d2.path(), big());
    c2.verify_closed_signatures = true;
    let r = Recorder::open(c2, signer(), clock()).unwrap();
    assert_eq!(r.quarantined_at_open(), &[0]);
    r.close().unwrap();
    assert_eq!(
        seg_quarantines(d2.path())[0].severity,
        Some(Severity::Critical)
    );
}

#[test]
fn no_intact_head_still_refuses() {
    // Active segment empty and every closed segment damaged: nothing
    // trustworthy to chain onto.
    let d = TestDir::new("w6-nohead");
    let c = cfg(d.path(), big());
    let mut r = open(c.clone());
    while r.segments().len() < 2 {
        recorded(r.append_note(&note(1), false).unwrap());
    }
    drop(r);
    std::fs::write(d.path().join(segment_file_name(1)), b"").unwrap();
    flip(d.path(), 0, 200, 1);
    let e = Recorder::open(c, signer(), clock()).unwrap_err();
    assert!(matches!(e, Error::Corrupt { .. }), "{e}");
    assert!(!d.path().join(QUARANTINE_DIR).exists(), "nothing touched");
}

#[test]
fn export_cursor_inside_a_quarantined_segment_is_kept() {
    let d = TestDir::new("w6-cursor");
    let c = cfg(d.path(), big());
    let mut r = open(c.clone());
    let mut i = 0;
    while r.segments().len() < 2 {
        recorded(r.append_note(&note(i), false).unwrap());
        i += 1;
    }
    let b = r.export_pending(None).unwrap().unwrap();
    r.mark_exported(&b).unwrap();
    let cursor = r.export_cursor().unwrap().seq;
    while r.segments().len() < 4 {
        recorded(r.append_note(&note(i), false).unwrap());
        i += 1;
    }
    drop(r);
    // The cursor's record lives in segment 1 (the export seal).
    let s1 = std::fs::read(d.path().join(segment_file_name(1))).unwrap();
    assert!(frames(&s1).iter().any(|(_, _, x)| x.seq == cursor));
    flip(d.path(), 1, 100, 4);
    let r = Recorder::open(c, signer(), clock()).unwrap();
    assert_eq!(r.export_cursor().map(|a| a.seq), Some(cursor));
    let rs: Vec<ResumePayload> = payloads(d.path(), RecordKind::Resume);
    assert!(!rs
        .last()
        .unwrap()
        .rejected_state
        .iter()
        .any(|s| s.contains(CURSOR_FILE)));
}

// ---------------------------------------------------------------------------
// (2) High-water mark and external anchor
// ---------------------------------------------------------------------------

/// `n` notes after the last seal, then the tail cut at `keep` notes.
fn cut_after_seal(d: &TestDir, c: &RecorderConfig, n: u64, keep: u64) -> (u64, u64) {
    let mut r = open(c.clone());
    let cp = r.seal().unwrap();
    for i in 0..n {
        recorded(r.append_note(&note(i), false).unwrap());
    }
    let mark = r.head_mark().unwrap();
    drop(r);
    let p = d.path().join(segment_file_name(0));
    let b = std::fs::read(&p).unwrap();
    let fr = frames(&b);
    let pos = fr
        .iter()
        .position(|(_, _, x)| x.seq == cp.seq + keep + 1)
        .unwrap_or(fr.len());
    if pos < fr.len() {
        std::fs::write(&p, &b[..fr[pos].0]).unwrap();
    }
    (cp.seq, mark)
}

#[test]
fn records_cut_after_the_newest_seal_are_detected_by_the_head_mark() {
    let d = TestDir::new("w6-mark");
    let mut c = cfg(d.path(), big());
    c.head_mark_every_records = 4;
    let (cp_seq, mark) = cut_after_seal(&d, &c, 10, 3);
    assert_eq!(mark, cp_seq + 8, "marks every 4 records");
    // The verifier sees it from head.json before any reopen.
    assert!(has(&vdir(d.path()), |k| matches!(
        k,
        FindingKind::TruncatedTail { .. }
    )));
    let r = open(c.clone());
    assert!(r.head().unwrap().0 > mark, "seq continues after the mark");
    r.close().unwrap();
    let td = payloads::<TruncationPayload>(d.path(), RecordKind::TruncationDetected);
    assert_eq!(td.len(), 1);
    assert_eq!(td[0].severity, Severity::Critical);
    assert_eq!(td[0].skipped_seqs, [cp_seq + 4, mark]);
    assert!(td[0]
        .evidence
        .iter()
        .any(|e| e.file == HEAD_FILE && e.seq == mark));
    assert_unique_seqs(d.path());
    let rep = vdir(d.path());
    assert!(has(&rep, |k| matches!(
        k,
        FindingKind::TruncationRecorded { .. }
    )));
}

#[test]
fn the_remaining_window_is_the_records_after_the_last_mark() {
    // Documented limit: a cut that only removes records written after the
    // newest mark leaves no local trace.
    let d = TestDir::new("w6-window");
    let mut c = cfg(d.path(), big());
    c.head_mark_every_records = 4;
    let (cp_seq, mark) = cut_after_seal(&d, &c, 10, 8);
    assert_eq!(mark, cp_seq + 8);
    open(c).close().unwrap();
    assert!(payloads::<TruncationPayload>(d.path(), RecordKind::TruncationDetected).is_empty());
}

#[test]
fn time_based_marks_and_mark_head() {
    let d = TestDir::new("w6-time");
    let mut c = cfg(d.path(), big());
    c.head_mark_every_records = 0;
    c.head_mark_interval_ns = 10_000;
    // 1 us per clock reading: a mark about every 10 records.
    let mut r = Recorder::open(
        c,
        signer(),
        Box::new(SteppingClock::new(1, 1_000, TimeSource::Gps)),
    )
    .unwrap();
    let first = r.head_mark().unwrap();
    for i in 0..25 {
        recorded(r.append_note(&note(i), false).unwrap());
    }
    let m = r.head_mark().unwrap();
    assert!(m > first && m < r.head().unwrap().0, "{first} {m}");
    r.mark_head().unwrap();
    assert_eq!(r.head_mark(), Some(r.head().unwrap().0));
    let on_disk =
        Checkpoint::from_json(&std::fs::read_to_string(d.path().join(HEAD_FILE)).unwrap()).unwrap();
    assert_eq!(on_disk.seq, r.head().unwrap().0);
    assert!(on_disk.verify(&verifier()));
    assert_eq!(r.mark_failures(), 0);
}

#[test]
fn forged_or_garbage_head_mark_is_rejected_not_fatal() {
    let d = TestDir::new("w6-garbage");
    let c = cfg(d.path(), big());
    let mut r = open(c.clone());
    for i in 0..3 {
        recorded(r.append_note(&note(i), false).unwrap());
    }
    let chain = r.chain_id();
    drop(r);
    // Unsigned mark far beyond the head: ignored (and reported).
    let forged = Checkpoint {
        chain_id: chain,
        seq: 1_000_000,
        hash: [7; 32],
        key_id: KEY_ID.into(),
        sig: vec![0; 32],
    };
    std::fs::write(d.path().join(HEAD_FILE), forged.to_json()).unwrap();
    let r = open(c.clone());
    assert!(r.head().unwrap().0 < 100, "a forged mark cannot burn seqs");
    drop(r);
    let rs: Vec<ResumePayload> = payloads(d.path(), RecordKind::Resume);
    assert!(rs
        .last()
        .unwrap()
        .rejected_state
        .iter()
        .any(|s| s.contains(HEAD_FILE)));
    std::fs::write(d.path().join(HEAD_FILE), b"\xff\x00not json").unwrap();
    open(c).close().unwrap();
}

#[test]
fn authentic_mark_contradicting_the_log_refuses_open() {
    let d = TestDir::new("w6-mismatch");
    let c = cfg(d.path(), big());
    let mut r = open(c.clone());
    for i in 0..3 {
        recorded(r.append_note(&note(i), false).unwrap());
    }
    let (seq, _) = r.head().unwrap();
    let chain = r.chain_id();
    drop(r);
    // Only a key holder can sign this: history rewritten under the key.
    let other = [9u8; 32];
    let m = Checkpoint {
        chain_id: chain,
        seq: seq - 1,
        hash: other,
        key_id: KEY_ID.into(),
        sig: verifier().sign(&signing_message(&other)).unwrap(),
    };
    std::fs::write(d.path().join(HEAD_FILE), m.to_json()).unwrap();
    let e = Recorder::open(c, signer(), clock()).unwrap_err();
    assert!(matches!(e, Error::Untrusted(_)), "{e}");
}

fn with_anchor(c: &RecorderConfig, a: &Arc<MemoryHeadAnchor>) -> RecorderConfig {
    let mut c = c.clone();
    c.head_anchor = Some(a.clone() as Arc<dyn HeadAnchor>);
    c
}

#[test]
fn external_anchor_catches_a_rolled_back_head_mark() {
    let d = TestDir::new("w6-anchor");
    let anchor = Arc::new(MemoryHeadAnchor::new());
    let mut c = with_anchor(&cfg(d.path(), big()), &anchor);
    c.head_mark_every_records = 4;
    let mut r = open(c.clone());
    let cp = r.seal().unwrap();
    let old_mark = std::fs::read(d.path().join(HEAD_FILE)).unwrap();
    for i in 0..10 {
        recorded(r.append_note(&note(i), false).unwrap());
    }
    let mark = r.head_mark().unwrap();
    assert_eq!(anchor.get().unwrap().seq, mark);
    assert_eq!(anchor.get().unwrap().chain_id, Some(r.chain_id()));
    drop(r);
    // The attacker cuts everything after the seal and restores the old
    // (authentic) head.json: locally consistent, the anchor knows better.
    let p = d.path().join(segment_file_name(0));
    let b = std::fs::read(&p).unwrap();
    let fr = frames(&b);
    let pos = fr.iter().position(|(_, _, x)| x.seq == cp.seq + 1).unwrap();
    std::fs::write(&p, &b[..fr[pos].0]).unwrap();
    std::fs::write(d.path().join(HEAD_FILE), old_mark).unwrap();
    let r = open(c);
    assert!(r.head().unwrap().0 > mark);
    r.close().unwrap();
    let td = payloads::<TruncationPayload>(d.path(), RecordKind::TruncationDetected);
    assert_eq!(td.len(), 1);
    assert!(td[0]
        .evidence
        .iter()
        .any(|e| e.file == EXTERNAL_ANCHOR && e.seq == mark));
    assert_unique_seqs(d.path());
}

#[test]
fn wiped_store_with_counter_anchor_is_reported_and_seqs_go_on() {
    let d = TestDir::new("w6-wipe");
    let anchor = Arc::new(MemoryHeadAnchor::counter());
    let c = with_anchor(&cfg(d.path(), big()), &anchor);
    let mut r = open(c.clone());
    for i in 0..20 {
        recorded(r.append_note(&note(i), false).unwrap());
    }
    let last = r.close().unwrap().seq;
    assert_eq!(anchor.get().unwrap().seq, last);
    assert_eq!(anchor.get().unwrap().hash, None);
    // Wipe the store completely.
    std::fs::remove_dir_all(d.path()).unwrap();
    let mut r = open(c.clone());
    let head = recorded(r.append_note(&note(99), false).unwrap());
    assert!(head > last, "never below the counter");
    r.close().unwrap();
    let td = payloads::<TruncationPayload>(d.path(), RecordKind::TruncationDetected);
    assert_eq!(td.len(), 1);
    assert_eq!(td[0].head_seq, 0);
    assert_eq!(td[0].skipped_seqs, [1, last]);
    let rep = vdir(d.path());
    assert!(!rep.is_intact());
    assert!(has(&rep, |k| matches!(
        k,
        FindingKind::TruncationRecorded { .. }
    )));
    // Reopen: the declared jump is accepted, no second report.
    open(c).close().unwrap();
    assert_eq!(
        payloads::<TruncationPayload>(d.path(), RecordKind::TruncationDetected).len(),
        1
    );
    assert_unique_seqs(d.path());
}

#[derive(Debug)]
struct Broken;
impl HeadAnchor for Broken {
    fn advance(&self, _: &Checkpoint) -> Result<(), String> {
        Err("TPM busy".into())
    }
    fn current(&self) -> Result<Option<AnchoredHead>, String> {
        Err("TPM busy".into())
    }
}

#[test]
fn failing_anchor_never_stops_recording() {
    let d = TestDir::new("w6-broken");
    let mut c = cfg(d.path(), big());
    c.head_anchor = Some(Arc::new(Broken));
    let mut r = open(c.clone());
    for i in 0..40 {
        recorded(r.append_note(&note(i), false).unwrap());
    }
    assert!(r.anchor_failures() > 0);
    assert_eq!(r.last_anchor_error(), Some("TPM busy"));
    assert_eq!(r.mark_failures(), 0, "head.json itself works");
    r.close().unwrap();
    let r = open(c);
    assert!(r.anchor_failures() > 0);
    drop(r);
    let rs: Vec<ResumePayload> = payloads(d.path(), RecordKind::Resume);
    assert!(rs
        .last()
        .unwrap()
        .rejected_state
        .iter()
        .any(|s| s.contains(EXTERNAL_ANCHOR)));
    assert!(vdir(d.path()).is_intact());
}

#[test]
fn anchor_of_another_chain_is_ignored_with_a_note() {
    let d = TestDir::new("w6-otherchain");
    let anchor = Arc::new(MemoryHeadAnchor::new());
    let c = with_anchor(&cfg(d.path(), big()), &anchor);
    open(c.clone()).close().unwrap();
    anchor.set(Some(AnchoredHead {
        chain_id: Some([1; 32]),
        seq: 1_000,
        hash: None,
    }));
    let r = open(c);
    assert!(r.head().unwrap().0 < 1_000);
    drop(r);
    let rs: Vec<ResumePayload> = payloads(d.path(), RecordKind::Resume);
    assert!(rs
        .last()
        .unwrap()
        .rejected_state
        .iter()
        .any(|s| s.contains("another chain")));
}

#[test]
fn hole_before_a_marked_record_is_not_crash_plausible() {
    // Zero-filled hole followed by records that the high-water mark proves
    // were fsynced: lost write-back cannot explain it.
    let d = TestDir::new("w6-hole-mark");
    let mut c = cfg(d.path(), big());
    c.head_mark_every_records = 3;
    let mut r = open(c.clone());
    for i in 0..7 {
        recorded(r.append_note(&note(i), false).unwrap());
    }
    let mark = r.head_mark().unwrap();
    drop(r);
    let p = d.path().join(segment_file_name(0));
    let mut b = std::fs::read(&p).unwrap();
    let fr = frames(&b);
    // Zero a frame before the mark (a non-control, non-critical note).
    let (o, l, rec) = fr
        .iter()
        .find(|(_, _, x)| x.kind == RecordKind::Note && x.seq + 2 < mark)
        .cloned()
        .unwrap();
    for x in &mut b[o + 8..o + l] {
        *x = 0;
    }
    std::fs::write(&p, &b).unwrap();
    open(c).close().unwrap();
    let rp: Vec<RecoveryPayload> = payloads(d.path(), RecordKind::Recovery);
    let rp = rp.last().unwrap();
    assert!(
        !rp.crash_plausible,
        "seq {} hole before mark {mark}",
        rec.seq
    );
    assert_eq!(rp.severity, Some(Severity::Critical));
    assert_unique_seqs(d.path());
}

#[test]
fn stale_temp_files_are_removed_at_open() {
    let d = TestDir::new("w6-tmp");
    let c = cfg(d.path(), big());
    open(c.clone()).close().unwrap();
    let stale = d.path().join(".head.json.0123456789abcdef01234567.tmp");
    std::fs::write(&stale, b"x").unwrap();
    let other = d.path().join(".unrelated.tmp");
    std::fs::write(&other, b"x").unwrap();
    open(c).close().unwrap();
    assert!(!stale.exists());
    assert!(other.exists(), "only the recorder's own temp files");
}
