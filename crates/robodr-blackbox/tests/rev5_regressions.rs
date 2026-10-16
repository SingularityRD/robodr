//! rev5 independent review: regression tests. Each one started as a
//! proof-of-concept that passed while the issue existed; they now assert the
//! fixed behaviour.
//!
//! F1 (medium): one empty `seg-<active+1>` file made open treat the live,
//!    unsealed segment as a closed segment without a seal, quarantine it as
//!    High "media damage" and let that quarantine "explain" the head.json
//!    mark (no TruncationDetected).
//! F2 (medium, DoS): every frame after a zero hole in the *active* segment
//!    was signature-checked, unbounded.
//! F3 (low): `verify_dir` ignored `recovery-pin.json` and
//!    `export-cursor.json`, which open treats as truncation proof.
mod common;
use common::*;
use robodr_blackbox::record::{RecoveryPayload, ResumePayload, TruncationPayload};
use robodr_blackbox::store::{
    segment_file_name, CHECKPOINT_FILE, CURSOR_FILE, HEAD_FILE, QUARANTINE_DIR, RECOVERY_PIN_FILE,
};
use robodr_blackbox::verify::verify_dir;
use robodr_blackbox::*;
use robodr_events::Severity;
use std::collections::HashSet;
use std::path::Path;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;

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

fn truncations(dir: &Path) -> Vec<TruncationPayload> {
    payloads(dir, RecordKind::TruncationDetected)
}

fn vdir(p: &Path) -> Report {
    verify_dir(p, &verifier(), &VerifyOptions::default()).unwrap()
}

fn assert_unique_seqs(dir: &Path) {
    let mut seen = HashSet::new();
    for r in all_records(dir) {
        assert!(seen.insert(r.seq), "seq {} used twice", r.seq);
    }
}

/// A log of 3+ segments; the active one is unsealed and holds `extra`
/// notes after the rotation, the last of them marked in head.json.
fn unsealed_active(c: &RecorderConfig, extra: u64) -> (u64, Vec<u64>) {
    let mut r = open(c.clone());
    let mut i = 0;
    while r.segments().len() < 3 {
        recorded(r.append_note(&note(i), false).unwrap());
        i += 1;
    }
    let active = *r.segments().last().unwrap();
    let mut seqs = Vec::new();
    for _ in 0..extra {
        seqs.push(recorded(r.append_note(&note(i), false).unwrap()));
        i += 1;
    }
    assert_eq!(*r.segments().last().unwrap(), active, "no rotation");
    r.mark_head().unwrap();
    assert_eq!(r.head_mark(), seqs.last().copied());
    drop(r); // killed: no seal
    (active, seqs)
}

// ---------------------------------------------------------------------------
// F1: stray segment files above the live segment
// ---------------------------------------------------------------------------

#[test]
fn f1_empty_next_segment_is_quarantined_as_tamper_and_the_live_segment_kept() {
    // Control: delete the active segment's content -> Critical truncation.
    let d0 = TestDir::new("rev5-ctl");
    let c0 = cfg(d0.path(), big());
    let (act0, _) = unsealed_active(&c0, 4);
    std::fs::write(d0.path().join(segment_file_name(act0)), b"").unwrap();
    open(c0).close().unwrap();
    let t = truncations(d0.path());
    assert_eq!(t.len(), 1);
    assert_eq!(t[0].severity, Severity::Critical);

    // Attack: leave the active segment, add an empty successor.
    let d = TestDir::new("rev5-f1");
    let c = cfg(d.path(), big());
    let (act, seqs) = unsealed_active(&c, 4);
    let stray = d.path().join(segment_file_name(act + 1));
    std::fs::write(&stray, b"").unwrap();
    let mut r = open(c.clone());
    // The stray file is what gets quarantined, not the live segment.
    assert_eq!(r.quarantined_at_open(), &[act + 1]);
    assert!(!stray.exists(), "stray file unlinked after its record");
    assert!(d.path().join(segment_file_name(act)).exists());
    assert_eq!(*r.segments().last().unwrap(), act, "still the live segment");
    let inc = r.open_incidents().to_vec();
    assert_eq!(inc.len(), 1, "{inc:?}");
    assert!(matches!(
        &inc[0],
        OpenIncident::SegmentQuarantined { segment_index, severity: Severity::Critical, .. }
            if *segment_index == act + 1
    ));
    // Recording continues in the live segment and can rotate past the
    // stray's index again.
    let mut i = 1000;
    while r.segments().len() < 5 {
        recorded(r.append_note(&note(i), false).unwrap());
        i += 1;
    }
    r.close().unwrap();
    let q = seg_quarantines(d.path());
    assert_eq!(q.len(), 1);
    assert_eq!(q[0].segment_index, act + 1);
    assert_eq!(q[0].severity, Some(Severity::Critical), "tamper, not media");
    assert!(
        q[0].reason.contains("stray segment file"),
        "{}",
        q[0].reason
    );
    // Nothing the head.json mark proves is gone, so no truncation; and the
    // records are all still in the log, even with the quarantine removed.
    assert!(truncations(d.path()).is_empty());
    std::fs::remove_dir_all(d.path().join(QUARANTINE_DIR)).unwrap();
    let left: HashSet<u64> = all_records(d.path()).iter().map(|r| r.seq).collect();
    assert!(seqs.iter().all(|s| left.contains(s)), "records kept");
    assert_unique_seqs(d.path());
    // The verifier reports the quarantine as tamper.
    let rep = vdir(d.path());
    assert!(!rep.is_intact());
    assert!(has(&rep, |k| matches!(
        k,
        FindingKind::SegmentQuarantined { segment_index, .. } if *segment_index == act + 1
    )));
    // A further open is clean.
    let r = open(c);
    assert!(r.open_incidents().is_empty(), "{:?}", r.open_incidents());
    r.close().unwrap();
}

#[test]
fn f1_garbage_and_multiple_stray_files_are_all_quarantined() {
    let d = TestDir::new("rev5-f1-garbage");
    let c = cfg(d.path(), big());
    let (act, seqs) = unsealed_active(&c, 3);
    // Non-zero garbage (used to refuse open: "corrupt active segment") and
    // an empty file with an index gap above it.
    std::fs::write(
        d.path().join(segment_file_name(act + 1)),
        b"not a frame at all",
    )
    .unwrap();
    std::fs::write(d.path().join(segment_file_name(act + 3)), b"").unwrap();
    let r = open(c.clone());
    assert_eq!(r.quarantined_at_open(), &[act + 1, act + 3]);
    assert!(r
        .open_incidents()
        .iter()
        .all(|i| i.severity() == Severity::Critical));
    assert!(r.head().unwrap().0 > *seqs.last().unwrap());
    r.close().unwrap();
    let q = seg_quarantines(d.path());
    assert_eq!(q.len(), 2);
    assert!(q.iter().all(|q| q.severity == Some(Severity::Critical)));
    let rs: Vec<ResumePayload> = payloads(d.path(), RecordKind::Resume);
    assert!(
        rs.last().unwrap().missing_segments.is_empty(),
        "no gap reported for files above the live segment"
    );
    assert!(truncations(d.path()).is_empty());
    assert_unique_seqs(d.path());
}

#[test]
fn f1_stray_above_a_live_segment_with_a_torn_tail() {
    let d = TestDir::new("rev5-f1-torn");
    let c = cfg(d.path(), big());
    let (act, _) = unsealed_active(&c, 3);
    let p = d.path().join(segment_file_name(act));
    let mut b = std::fs::read(&p).unwrap();
    let (o, l, _) = frames(&b)[1];
    let torn = b[o..o + l / 2].to_vec();
    b.extend_from_slice(&torn); // torn write of a frame
    std::fs::write(&p, &b).unwrap();
    std::fs::write(d.path().join(segment_file_name(act + 1)), b"").unwrap();
    let r = open(c);
    assert_eq!(r.quarantined_at_open(), &[act + 1]);
    assert_eq!(*r.segments().last().unwrap(), act);
    r.close().unwrap();
    // The torn tail is a routine (medium) recovery, the stray is tamper.
    let rp: Vec<RecoveryPayload> = payloads(d.path(), RecordKind::Recovery);
    assert!(rp
        .iter()
        .any(|x| !x.quarantined_segment && x.severity == Some(Severity::Medium)));
    assert_eq!(
        seg_quarantines(d.path())[0].severity,
        Some(Severity::Critical)
    );
}

#[test]
fn crash_right_after_rotation_is_not_a_stray() {
    // Sealed segment N, empty N+1 (the rotation crashed before its
    // SegmentStart): legitimate. A further empty file above that one makes
    // N+1 an empty *closed* segment: critical, never "media damage".
    let d = TestDir::new("rev5-rot");
    let c = cfg(d.path(), big());
    let mut r = open(c.clone());
    let mut i = 0;
    while r.segments().len() < 3 {
        recorded(r.append_note(&note(i), false).unwrap());
        i += 1;
    }
    let act = *r.segments().last().unwrap();
    drop(r);
    // Emulate the crash: the newest segment is empty again.
    std::fs::write(d.path().join(segment_file_name(act)), b"").unwrap();
    std::fs::remove_file(d.path().join(HEAD_FILE)).unwrap();
    std::fs::remove_file(d.path().join(CHECKPOINT_FILE)).unwrap();
    std::fs::write(d.path().join(segment_file_name(act + 1)), b"").unwrap();
    let r = open(c.clone());
    assert_eq!(r.quarantined_at_open(), &[act]);
    assert_eq!(*r.segments().last().unwrap(), act + 1);
    assert!(r
        .open_incidents()
        .iter()
        .all(|i| i.severity() == Severity::Critical));
    r.close().unwrap();
    // Without the extra file: nothing quarantined at all.
    let d2 = TestDir::new("rev5-rot2");
    let c2 = cfg(d2.path(), big());
    let mut r = open(c2.clone());
    let mut i = 0;
    while r.segments().len() < 3 {
        recorded(r.append_note(&note(i), false).unwrap());
        i += 1;
    }
    drop(r);
    std::fs::write(d2.path().join(segment_file_name(act)), b"").unwrap();
    let r = open(c2);
    assert!(r.quarantined_at_open().is_empty());
    assert!(r.open_incidents().is_empty(), "{:?}", r.open_incidents());
    r.close().unwrap();
    let r = open(c);
    assert!(r.quarantined_at_open().is_empty());
    r.close().unwrap();
    assert_unique_seqs(d.path());
}

#[test]
fn closed_segment_cut_on_a_frame_boundary_is_critical() {
    // Whole frames (the seal among them) removed from a closed segment:
    // media does not do that, so it is not "media damage".
    let d = TestDir::new("rev5-cutclosed");
    let c = cfg(d.path(), big());
    let mut r = open(c.clone());
    let mut i = 0;
    while r.segments().len() < 3 {
        recorded(r.append_note(&note(i), false).unwrap());
        i += 1;
    }
    recorded(r.append_note(&note(i), false).unwrap());
    drop(r);
    let p = d.path().join(segment_file_name(1));
    let b = std::fs::read(&p).unwrap();
    let fr = frames(&b);
    std::fs::write(&p, &b[..fr[fr.len() - 2].0]).unwrap();
    let r = open(c);
    assert_eq!(r.quarantined_at_open(), &[1]);
    r.close().unwrap();
    let q = seg_quarantines(d.path());
    assert_eq!(q[0].severity, Some(Severity::Critical));
    assert!(
        q[0].reason.contains("does not end with a seal"),
        "{}",
        q[0].reason
    );
}

#[test]
fn critical_quarantine_of_the_newest_segment_does_not_explain_the_mark() {
    // Active segment empty (rotation crashed before its SegmentStart), the
    // newest closed segment damaged. Its quarantine no longer "accounts
    // for" the head.json mark / checkpoint inside it: Critical quarantine
    // plus a Critical TruncationDetected, seqs never reused.
    let d = TestDir::new("rev5-newest");
    let c = cfg(d.path(), big());
    let mut r = open(c.clone());
    let mut i = 0;
    while r.segments().len() < 3 {
        recorded(r.append_note(&note(i), false).unwrap());
        i += 1;
    }
    let mark = r.head_mark().unwrap();
    drop(r);
    std::fs::write(d.path().join(segment_file_name(2)), b"").unwrap();
    let s1 = std::fs::read(d.path().join(segment_file_name(1))).unwrap();
    let s1_max = frames(&s1).last().unwrap().2.seq;
    assert!(mark >= s1_max, "the rotation seal was marked");
    let p = d.path().join(segment_file_name(1));
    let mut b = s1.clone();
    let (o, _, _) = frames(&b)[2];
    b[o + 60] ^= 1;
    std::fs::write(&p, &b).unwrap();
    let r = open(c);
    assert_eq!(r.quarantined_at_open(), &[1]);
    assert!(r.head().unwrap().0 > s1_max);
    let kinds: Vec<Severity> = r.open_incidents().iter().map(|i| i.severity()).collect();
    assert_eq!(kinds, vec![Severity::Critical, Severity::Critical]);
    assert!(matches!(
        r.open_incidents()[1],
        OpenIncident::TruncationDetected { .. }
    ));
    r.close().unwrap();
    let q = seg_quarantines(d.path());
    assert_eq!(q[0].severity, Some(Severity::Critical));
    assert!(
        q[0].reason.contains("newer than the newest intact"),
        "{}",
        q[0].reason
    );
    let t = truncations(d.path());
    assert_eq!(t.len(), 1);
    assert_eq!(t[0].severity, Severity::Critical);
    assert!(t[0].evidence.iter().any(|e| e.file == HEAD_FILE));
    // The quarantined records themselves are evidence too.
    assert!(t[0]
        .evidence
        .iter()
        .any(|e| e.file == segment_file_name(1) && e.seq == s1_max));
    assert_unique_seqs(d.path());
}

#[test]
fn critical_active_hole_raises_truncation() {
    // A zero hole before a record the seal synced: not a crash; the seal
    // (named by checkpoint.json and head.json) is quarantined with it.
    let d = TestDir::new("rev5-hole");
    let c = cfg(d.path(), big());
    let mut r = open(c.clone());
    for i in 0..4 {
        recorded(r.append_note(&note(i), false).unwrap());
    }
    let seal = r.seal().unwrap();
    recorded(r.append_note(&note(4), false).unwrap());
    drop(r);
    let p = d.path().join(segment_file_name(0));
    let mut b = std::fs::read(&p).unwrap();
    let (off, len, _) = frames(&b)[2];
    for x in &mut b[off..off + len] {
        *x = 0;
    }
    std::fs::write(&p, &b).unwrap();
    let r = open(c);
    assert!(r.head().unwrap().0 > seal.seq + 1);
    assert!(r.open_incidents().iter().any(|i| matches!(
        i,
        OpenIncident::DamageQuarantined {
            severity: Severity::Critical,
            crash_plausible: false,
            ..
        }
    )));
    r.close().unwrap();
    let t = truncations(d.path());
    assert_eq!(t.len(), 1);
    assert!(t[0].evidence.iter().any(|e| e.file == CHECKPOINT_FILE));
    assert_unique_seqs(d.path());
}

#[test]
fn crash_plausible_hole_is_still_explained() {
    // Unsynced notes, hole, more unsynced notes, no mark beyond the head:
    // a crash explains it (High), no truncation.
    let d = TestDir::new("rev5-plausible");
    let mut c = cfg(d.path(), big());
    c.head_mark_every_records = 0;
    c.head_mark_interval_ns = 0;
    c.fsync_critical = false;
    let mut r = open(c.clone());
    for i in 0..6 {
        recorded(r.append_note(&note(i), false).unwrap());
    }
    drop(r);
    let p = d.path().join(segment_file_name(0));
    let mut b = std::fs::read(&p).unwrap();
    let fr = frames(&b);
    let (off, len, _) = fr[fr.len() - 3];
    for x in &mut b[off..off + len] {
        *x = 0;
    }
    std::fs::write(&p, &b).unwrap();
    let r = open(c);
    assert!(r.open_incidents().iter().any(|i| matches!(
        i,
        OpenIncident::DamageQuarantined {
            severity: Severity::High,
            crash_plausible: true,
            ..
        }
    )));
    r.close().unwrap();
    assert!(truncations(d.path()).is_empty());
    assert!(vdir(d.path()).is_intact());
}

// ---------------------------------------------------------------------------
// F2: bounded signature work after a hole in the active segment
// ---------------------------------------------------------------------------

/// Counts every signature check the recorder makes at open.
#[derive(Debug)]
struct Counting(HmacSha256Key, Arc<AtomicU64>);
impl Verifier for Counting {
    fn algorithm(&self) -> &str {
        Verifier::algorithm(&self.0)
    }
    fn key_id(&self) -> &str {
        Verifier::key_id(&self.0)
    }
    fn verify(&self, m: &[u8], s: &[u8]) -> bool {
        self.1.fetch_add(1, Ordering::Relaxed);
        self.0.verify(m, s)
    }
}

#[test]
fn f2_active_hole_signature_checks_are_bounded() {
    let d = TestDir::new("rev5-f2");
    let mut c = cfg(d.path(), big());
    c.max_segment_bytes = 64 * 1024 * 1024;
    let mut r = open(c.clone());
    for i in 0..3 {
        recorded(r.append_note(&note(i), false).unwrap());
    }
    drop(r);
    let p = d.path().join(segment_file_name(0));
    let mut b = std::fs::read(&p).unwrap();
    let last = frames(&b).last().unwrap().2.clone();
    b.extend_from_slice(&[0u8; 64]); // "lost write-back"
    const N: u64 = 5_000;
    let mut prev = last.hash;
    for i in 0..N {
        let mut f = last.clone();
        f.seq = last.seq + 1 + i;
        f.prev_hash = prev;
        f.payload = b"{}".to_vec();
        f.hash = f.compute_hash();
        f.sig = vec![0u8; 32];
        prev = f.hash;
        b.extend_from_slice(&f.encode_frame());
    }
    std::fs::write(&p, &b).unwrap();
    let n = Arc::new(AtomicU64::new(0));
    let v = Counting(verifier(), n.clone());
    let r = Recorder::open_with_verifier(c, signer(), Box::new(v), clock()).unwrap();
    // Forged frames are not crash damage.
    assert!(r.open_incidents().iter().any(|i| matches!(
        i,
        OpenIncident::DamageQuarantined {
            severity: Severity::Critical,
            crash_plausible: false,
            ..
        }
    )));
    drop(r);
    let calls = n.load(Ordering::Relaxed);
    assert!(
        calls < 200,
        "{calls} signature checks for {N} forged frames"
    );
    let rp: Vec<RecoveryPayload> = payloads(d.path(), RecordKind::Recovery);
    let rp = rp.last().unwrap();
    assert_eq!(rp.discarded_records, N, "hash-valid frames are counted");
    assert!(!rp.crash_plausible);
}

#[test]
fn f2_authentic_records_after_the_hole_still_set_the_seq_floor() {
    let d = TestDir::new("rev5-f2-auth");
    let mut c = cfg(d.path(), big());
    c.max_segment_bytes = 1 << 20;
    c.head_mark_every_records = 0;
    c.head_mark_interval_ns = 0;
    c.fsync_critical = false;
    let mut r = open(c.clone());
    for i in 0..100 {
        recorded(r.append_note(&note(i), false).unwrap());
    }
    let top = r.head().unwrap().0;
    drop(r);
    let p = d.path().join(segment_file_name(0));
    let mut b = std::fs::read(&p).unwrap();
    let (off, len, _) = frames(&b)[20];
    for x in &mut b[off..off + len] {
        *x = 0;
    }
    std::fs::write(&p, &b).unwrap();
    let r = open(c);
    assert!(r.head().unwrap().0 > top, "seqs after the hole not reused");
    r.close().unwrap();
    assert_unique_seqs(d.path());
}

// ---------------------------------------------------------------------------
// F3: verify_dir sees the state files open treats as truncation proof
// ---------------------------------------------------------------------------

#[test]
fn f3_verify_dir_honours_the_recovery_pin() {
    let d = TestDir::new("rev5-f3");
    let mut c = cfg(d.path(), big());
    c.head_mark_every_records = 0;
    c.head_mark_interval_ns = 0;
    let mut r = open(c.clone());
    for i in 0..4 {
        recorded(r.append_note(&note(i), false).unwrap());
    }
    r.mark_head().unwrap();
    for i in 4..8 {
        recorded(r.append_note(&note(i), false).unwrap());
    }
    let chain = r.chain_id();
    drop(r);
    let p = d.path().join(segment_file_name(0));
    let b = std::fs::read(&p).unwrap();
    let fr = frames(&b);
    let (_, _, top) = fr.last().unwrap().clone();
    // State a crash after Recovery::quarantine's truncate leaves: pin names
    // the highest cut record; segment cut on a frame boundary.
    let pin = Checkpoint {
        chain_id: chain,
        seq: top.seq,
        hash: top.hash,
        key_id: KEY_ID.into(),
        sig: top.sig.clone(),
    };
    std::fs::write(d.path().join(RECOVERY_PIN_FILE), pin.to_json()).unwrap();
    let (cut, _, _) = fr[fr.len() - 3];
    std::fs::write(&p, &b[..cut]).unwrap();

    let rep = vdir(d.path());
    assert!(!rep.is_intact(), "offline verifier agrees with open");
    assert!(has(&rep, |k| matches!(
        k,
        FindingKind::TruncatedTail { checkpoint_seq, .. } if *checkpoint_seq == top.seq
    )));
    // A forged pin is ignored (not a finding by itself).
    let mut forged = pin.clone();
    forged.sig = vec![1; 32];
    std::fs::write(d.path().join(RECOVERY_PIN_FILE), forged.to_json()).unwrap();
    assert!(vdir(d.path()).is_intact());
    std::fs::write(d.path().join(RECOVERY_PIN_FILE), pin.to_json()).unwrap();

    open(c).close().unwrap();
    assert_eq!(truncations(d.path()).len(), 1, "open: truncation");
    assert!(!d.path().join(RECOVERY_PIN_FILE).exists());
}

#[test]
fn f3_verify_dir_honours_the_export_cursor() {
    let d = TestDir::new("rev5-f3-cursor");
    let mut c = cfg(d.path(), big());
    c.head_mark_every_records = 0;
    c.head_mark_interval_ns = 0;
    let mut r = open(c.clone());
    let cp = r.seal().unwrap();
    for i in 0..6 {
        recorded(r.append_note(&note(i), false).unwrap());
    }
    let bundle = r.export_pending(None).unwrap().unwrap();
    r.mark_exported(&bundle).unwrap();
    let cursor = r.export_cursor().unwrap().seq;
    drop(r);
    // Cut every record after the seal and roll head.json back to it.
    let p = d.path().join(segment_file_name(0));
    let b = std::fs::read(&p).unwrap();
    let fr = frames(&b);
    let pos = fr.iter().position(|(_, _, x)| x.seq == cp.seq + 1).unwrap();
    std::fs::write(&p, &b[..fr[pos].0]).unwrap();
    std::fs::write(d.path().join(HEAD_FILE), cp.to_json()).unwrap();
    assert!(d.path().join(CURSOR_FILE).exists());

    let rep = vdir(d.path());
    assert!(!rep.is_intact(), "{}", dump(&rep));
    assert!(has(&rep, |k| matches!(
        k,
        FindingKind::TruncatedTail { checkpoint_seq, .. } if *checkpoint_seq == cursor
    )));
    open(c).close().unwrap();
    let t = truncations(d.path());
    assert_eq!(t.len(), 1);
    assert!(t[0].evidence.iter().any(|e| e.file == CURSOR_FILE));
}

// ---------------------------------------------------------------------------
// FileHeadAnchor
// ---------------------------------------------------------------------------

#[test]
fn file_anchor_reports_a_wiped_store_and_never_decreases() {
    let d = TestDir::new("rev5-fanchor");
    let anchor_dir = TestDir::new("rev5-fanchor-a");
    let path = anchor_dir.path().join("head-anchor.json");
    let a = Arc::new(FileHeadAnchor::new(&path).unwrap());
    let mut c = cfg(d.path(), big());
    c.head_anchor = Some(a.clone() as Arc<dyn HeadAnchor>);
    let mut r = open(c.clone());
    for i in 0..20 {
        recorded(r.append_note(&note(i), false).unwrap());
    }
    let last = r.close().unwrap();
    let held = a.current().unwrap().unwrap();
    assert_eq!(held.seq, last.seq);
    assert_eq!(held.hash, Some(last.hash));
    assert_eq!(held.chain_id, Some(last.chain_id));
    // Never decreases.
    let mut older = last.clone();
    older.seq -= 1;
    assert!(a.advance(&older).is_err());
    assert_eq!(a.current().unwrap().unwrap().seq, last.seq);
    // Wipe the store: the new chain declares the gap.
    std::fs::remove_dir_all(d.path()).unwrap();
    let r = open(c.clone());
    assert!(r.head().unwrap().0 > last.seq);
    assert!(matches!(
        r.open_incidents(),
        [OpenIncident::TruncationDetected { .. }]
    ));
    r.close().unwrap();
    assert_eq!(truncations(d.path()).len(), 1);
    // Unparseable anchor file: counted and noted, recording goes on.
    std::fs::write(&path, b"{oops").unwrap();
    let r = open(c);
    assert!(r.anchor_failures() > 0);
    drop(r);
    // Relative paths are refused.
    assert!(FileHeadAnchor::new("relative/anchor.json").is_err());
}
