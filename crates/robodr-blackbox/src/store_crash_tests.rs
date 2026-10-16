//! Crash at every step of segment rotation, retention drops, high-water
//! marks, state-file replacement, torn-tail recovery and closed-segment
//! quarantine (fault injection through [`super::fault`]): the store must
//! always reopen, verify, never reuse a sequence number and never lose the
//! record of a quarantine.
//!
//! A crash is simulated by failing the step (the recorder is then dropped:
//! nothing after that step reaches disk, as when the process is killed). It
//! does not simulate the kernel losing unsynced pages; that is covered by
//! the zero-hole tests in `tests/rev3_regressions.rs`.

use super::*;
use crate::record::RecoveryPayload;
use crate::sign::HmacSha256Key;
use crate::time::{SteppingClock, TimeSource};
use crate::verify::{verify_dir, FindingKind, Report, VerifyOptions};
use std::collections::HashSet;
use std::sync::atomic::{AtomicU64, Ordering};

struct Dir(PathBuf);

impl Dir {
    fn new(tag: &str) -> Self {
        static N: AtomicU64 = AtomicU64::new(0);
        let p = std::env::temp_dir().join(format!(
            "robodr-bb-crash-{tag}-{}-{}",
            std::process::id(),
            N.fetch_add(1, Ordering::Relaxed)
        ));
        let _ = fs::remove_dir_all(&p);
        fs::create_dir_all(&p).unwrap();
        Dir(p)
    }
}

impl Drop for Dir {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

const KEY: [u8; 32] = [0x42; 32];

fn key() -> HmacSha256Key {
    HmacSha256Key::new("unit-key", &KEY).unwrap()
}

fn cfg(dir: &Path, mode: RetentionMode) -> RecorderConfig {
    let mut c = RecorderConfig::new(dir, "ugv-01", "boot-a");
    c.mode = mode;
    c.max_segment_bytes = 4096;
    c.fsync = FsyncPolicy::SealsOnly;
    c.seal_every_records = 7;
    c.head_mark_every_records = 4;
    c
}

fn open(c: &RecorderConfig) -> Result<Recorder, Error> {
    Recorder::open(
        c.clone(),
        Box::new(key()),
        Box::new(SteppingClock::new(1_000_000, 1_000, TimeSource::Gps)),
    )
}

fn note(i: u64) -> serde_json::Value {
    serde_json::json!({ "i": i, "msg": "evidence note with some padding to fill segments" })
}

fn records(dir: &Path) -> Vec<Record> {
    let mut v = Vec::new();
    for (_, p) in list_segments(dir).unwrap() {
        for it in scan_frames(&fs::read(p).unwrap()).items {
            if let ScanItem::Record(sr) = it {
                v.push(sr.record);
            }
        }
    }
    v
}

fn assert_unique_seqs(dir: &Path, ctx: &str) {
    let mut seen = HashSet::new();
    for r in records(dir) {
        assert!(seen.insert(r.seq), "{ctx}: seq {} used twice", r.seq);
    }
}

fn verify(dir: &Path) -> Report {
    verify_dir(dir, &key(), &VerifyOptions::default()).unwrap()
}

fn dump(r: &Report) -> String {
    r.findings
        .iter()
        .map(|f| f.to_string())
        .collect::<Vec<_>>()
        .join("\n")
}

fn stale_tmp(dir: &Path) -> Vec<String> {
    fs::read_dir(dir)
        .unwrap()
        .flatten()
        .filter_map(|e| e.file_name().to_str().map(String::from))
        .filter(|n| n.ends_with(".tmp"))
        .collect()
}

/// Every step of rotation (seal, checkpoint, new segment, segment start),
/// of cyclic drops (record, unlink), of the high-water mark and of the
/// atomic state-file replacement.
const ROTATION_POINTS: &[&str] = &[
    "rotate.after_seal",
    "rotate.after_create",
    "rotate.after_segment_start",
    "drop.after_record",
    "drop.after_unlink",
    "mark.after_sync",
    "atomic.after_tmp",
    "atomic.after_rename",
];

#[test]
fn crash_at_every_rotation_step_leaves_an_openable_verifiable_store() {
    let mut fired_points = HashSet::new();
    for mode in [
        RetentionMode::Cyclic { max_segments: 3 },
        RetentionMode::Saturation {
            max_segments: 3,
            critical_reserve_segments: 2,
        },
    ] {
        for &point in ROTATION_POINTS {
            for nth in [1u32, 2, 5] {
                let ctx = format!("{mode:?} {point} #{nth}");
                let d = Dir::new("rot");
                let c = cfg(&d.0, mode);
                let mut r = open(&c).unwrap();
                fault::arm(point, nth);
                let mut i = 0u64;
                let mut crashed = false;
                while i < 200 {
                    match r.append_note(&note(i), i.is_multiple_of(5)) {
                        Ok(_) => {}
                        Err(_) => {
                            crashed = true;
                            break;
                        }
                    }
                    i += 1;
                }
                fault::disarm();
                if !crashed {
                    continue;
                }
                assert!(fault::fired(), "{ctx}: failed without the injected fault");
                fired_points.insert(point);
                let before = records(&d.0).iter().map(|x| x.seq).max();
                drop(r); // the process dies here

                let mut r = open(&c).unwrap_or_else(|e| panic!("{ctx}: reopen failed: {e}"));
                assert!(r.head().unwrap().0 > before.unwrap_or(0), "{ctx}");
                for j in 0..30 {
                    r.append_note(&note(10_000 + j), true)
                        .unwrap_or_else(|e| panic!("{ctx}: append after reopen: {e}"));
                }
                r.close().unwrap();
                assert!(stale_tmp(&d.0).is_empty(), "{ctx}: {:?}", stale_tmp(&d.0));
                assert_unique_seqs(&d.0, &ctx);
                let rep = verify(&d.0);
                assert!(rep.is_intact(), "{ctx}:\n{}", dump(&rep));
                // And once more: a second restart is clean too.
                open(&c).unwrap().close().unwrap();
                assert!(verify(&d.0).is_intact(), "{ctx} (second reopen)");
            }
        }
    }
    for p in ROTATION_POINTS {
        assert!(fired_points.contains(p), "crash point {p} never reached");
    }
}

/// A log with closed segments 0..=2 and active 3, segment 1 damaged.
fn damaged_store(d: &Dir) -> (RecorderConfig, Vec<u8>) {
    let c = cfg(&d.0, RetentionMode::Cyclic { max_segments: 1000 });
    let mut r = open(&c).unwrap();
    let mut i = 0;
    while r.segments().len() < 4 {
        r.append_note(&note(i), false).unwrap();
        i += 1;
    }
    r.append_note(&note(i), false).unwrap();
    drop(r);
    let p = d.0.join(segment_file_name(1));
    let mut b = fs::read(&p).unwrap();
    let n = b.len();
    b[n / 2] ^= 0x10;
    fs::write(&p, &b).unwrap();
    (c, b)
}

fn seg_quarantines(dir: &Path) -> Vec<RecoveryPayload> {
    records(dir)
        .iter()
        .filter(|r| r.kind == RecordKind::Recovery)
        .filter_map(|r| r.payload_json::<RecoveryPayload>())
        .filter(|p| p.quarantined_segment)
        .collect()
}

const QUARANTINE_POINTS: &[&str] = &[
    "quarantine.after_copy",
    "quarantine.after_records",
    "quarantine.after_unlink",
    "mark.after_sync",
    "atomic.after_tmp",
    "atomic.after_rename",
];

#[test]
fn crash_at_every_quarantine_step_finishes_the_quarantine_exactly_once() {
    for &point in QUARANTINE_POINTS {
        for nth in [1u32, 2] {
            let ctx = format!("{point} #{nth}");
            let d = Dir::new("q");
            let (c, damaged) = damaged_store(&d);
            let max_before = records(&d.0).iter().map(|x| x.seq).max().unwrap();
            fault::arm(point, nth);
            let first = open(&c);
            fault::disarm();
            match first {
                // Best-effort steps (the closing high-water mark) poison the
                // recorder instead of failing open; either way it dies here.
                Ok(r) => drop(r),
                Err(e) => assert!(fault::fired(), "{ctx}: unexpected error {e}"),
            }
            let mut r = open(&c).unwrap_or_else(|e| panic!("{ctx}: reopen failed: {e}"));
            assert!(r.head().unwrap().0 > max_before, "{ctx}");
            r.append_note(&note(77), false).unwrap();
            r.close().unwrap();

            assert!(!d.0.join(segment_file_name(1)).exists(), "{ctx}");
            let q = seg_quarantines(&d.0);
            assert_eq!(q.len(), 1, "{ctx}: recorded exactly once: {q:?}");
            assert_eq!(q[0].discarded_sha256, to_hex(&sha256(&damaged)), "{ctx}");
            let kept = fs::read(d.0.join(q[0].quarantine_file.as_ref().unwrap())).unwrap();
            assert_eq!(kept, damaged, "{ctx}: the recorded copy holds the bytes");
            assert_unique_seqs(&d.0, &ctx);
            let rep = verify(&d.0);
            assert!(
                rep.findings.iter().any(|f| matches!(
                    f.kind,
                    FindingKind::SegmentQuarantined {
                        segment_index: 1,
                        ..
                    }
                )),
                "{ctx}:\n{}",
                dump(&rep)
            );
            // Nothing else but the quarantine and its gap is reported.
            for f in rep.tamper() {
                assert!(
                    matches!(
                        f.kind,
                        FindingKind::SegmentQuarantined { .. } | FindingKind::Deleted { .. }
                    ),
                    "{ctx}: unexpected {f}"
                );
            }
        }
    }
}

/// Active segment with a zero-filled hole followed by authentic records
/// (lost write-back): the cut is pinned by a high-water mark first.
fn holed_store(d: &Dir) -> (RecorderConfig, u64) {
    let mut c = cfg(&d.0, RetentionMode::Cyclic { max_segments: 1000 });
    c.head_mark_every_records = 0;
    c.head_mark_interval_ns = 0;
    c.seal_every_records = 0;
    let mut r = open(&c).unwrap();
    for i in 0..6 {
        r.append_note(&note(i), false).unwrap();
    }
    let top = r.head().unwrap().0;
    drop(r);
    let p = d.0.join(segment_file_name(0));
    let mut b = fs::read(&p).unwrap();
    let frames: Vec<(usize, usize)> = scan_frames(&b)
        .items
        .iter()
        .filter_map(|it| match it {
            ScanItem::Record(sr) => Some((sr.offset as usize, sr.frame_len as usize)),
            _ => None,
        })
        .collect();
    let (o, l) = frames[2];
    for x in &mut b[o..o + l] {
        *x = 0;
    }
    fs::write(&p, &b).unwrap();
    (c, top)
}

#[test]
fn crash_at_every_torn_tail_recovery_step_never_reuses_seqs() {
    for point in [
        "recovery.after_preserve",
        "recovery.after_mark",
        "recovery.after_truncate",
    ] {
        let d = Dir::new("rec");
        let (c, top) = holed_store(&d);
        fault::arm(point, 1);
        assert!(open(&c).is_err(), "{point}");
        assert!(fault::fired(), "{point}");
        let after_cut = point == "recovery.after_truncate";
        fault::disarm();
        let mut r = open(&c).unwrap_or_else(|e| panic!("{point}: reopen failed: {e}"));
        let next = r.append_note(&note(1), false).unwrap();
        let AppendOutcome::Recorded { seq, .. } = next else {
            panic!("{point}: refused")
        };
        assert!(seq > top, "{point}: seq {seq} reuses a lost one (<= {top})");
        r.close().unwrap();
        assert_unique_seqs(&d.0, point);
        // The loss is on record either as the recovery itself or (crash
        // after the cut) as a truncation proven by the pinned mark.
        let kinds: Vec<RecordKind> = records(&d.0).iter().map(|r| r.kind).collect();
        assert!(
            kinds.contains(&RecordKind::Recovery)
                || kinds.contains(&RecordKind::TruncationDetected),
            "{point}: {kinds:?}"
        );
        // A crash-plausible hole is a warning; a crash in the middle of its
        // recovery leaves only the pinned mark, which proves a truncation.
        let rep = verify(&d.0);
        assert!(!rep.is_clean(), "{point}: damage must show");
        assert_eq!(rep.is_intact(), !after_cut, "{point}:\n{}", dump(&rep));
    }
}

#[test]
fn fault_hooks_are_inert_unless_armed() {
    fault::disarm();
    assert!(fault("rotate.after_seal").is_ok());
    fault::arm("x", 2);
    assert!(fault("x").is_ok());
    assert!(!fault::fired());
    assert!(fault("x").is_err());
    assert!(fault::fired());
    assert!(fault("x").is_ok(), "fires once");
}
