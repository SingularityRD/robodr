//! T15: evidence that was not exported is never dropped silently by cyclic
//! retention. Pending-export protection (`unexported_reserve_segments`),
//! the retention status a host reports before a drop, and the
//! `outbox` exporter that moves records out while the recorder runs.

mod common;

use common::*;
use robodr_blackbox::export::{cursor_signing_message, SignedCursor};
use robodr_blackbox::outbox::{collect_pending, export_pending_to, PendingOptions};
use robodr_blackbox::record::{RecordKind, SegmentDroppedPayload};
use robodr_blackbox::store::CURSOR_FILE;
use robodr_blackbox::*;
use std::path::Path;

fn protected(dir: &Path, max: u32, reserve: u32) -> RecorderConfig {
    let mut c = cfg(dir, RetentionMode::Cyclic { max_segments: max });
    c.unexported_reserve_segments = reserve;
    c
}

/// Append notes until the recorder has rotated `n` more times.
fn rotations(r: &mut Recorder, n: usize, i: &mut u64) {
    let mut seen = r.segments().last().copied().unwrap_or(0);
    let target = seen + n as u64;
    while seen < target {
        recorded(r.append_note(&note(*i), false).unwrap());
        *i += 1;
        seen = r.segments().last().copied().unwrap_or(0);
    }
}

fn authentic(m: &[u8], s: &[u8]) -> bool {
    verifier().verify(m, s)
}

fn drops(dir: &Path) -> Vec<SegmentDroppedPayload> {
    all_records(dir)
        .into_iter()
        .filter(|r| r.kind == RecordKind::SegmentDropped)
        .filter_map(|r| r.payload_json::<SegmentDroppedPayload>())
        .collect()
}

#[test]
fn without_protection_cyclic_drops_unexported_segments_but_counts_them() {
    let d = TestDir::new("t15-plain");
    let mut r = open(cfg(d.path(), RetentionMode::Cyclic { max_segments: 2 }));
    let mut i = 0;
    rotations(&mut r, 4, &mut i);
    assert_eq!(r.segments().len(), 2);
    assert_eq!(r.unexported_drops(), 3);
    let st = r.retention_status();
    assert!(!st.protecting);
    assert_eq!(st.unexported_drops, 3);
    assert_eq!(st.capacity_segments, 2);
    drop(r);
    assert!(drops(d.path()).iter().all(|p| !p.exported));
}

#[test]
fn protection_keeps_unexported_segments_up_to_the_reserve_then_reports_the_drop() {
    let d = TestDir::new("t15-protect");
    let mut r = open(protected(d.path(), 2, 3));
    let mut i = 0;
    // Four rotations: five segments, all unexported, nothing dropped.
    rotations(&mut r, 4, &mut i);
    assert_eq!(r.segments(), vec![0, 1, 2, 3, 4]);
    assert_eq!(r.unexported_drops(), 0);
    let st = r.retention_status();
    assert!(st.protecting);
    assert_eq!(st.capacity_segments, 5);
    assert_eq!(st.unexported_segments, 5);
    assert_eq!(st.unexported_fill_percent(), 100);
    assert!(drops(d.path()).is_empty());
    // The reserve is used up: the next rotation drops, and says so.
    rotations(&mut r, 1, &mut i);
    assert_eq!(r.segments(), vec![1, 2, 3, 4, 5]);
    assert_eq!(r.unexported_drops(), 1);
    drop(r);
    let dr = drops(d.path());
    assert_eq!(dr.len(), 1);
    assert!(!dr[0].exported);
    assert_eq!(dr[0].segment_index, 0);
}

#[test]
fn reserve_is_cyclic_only() {
    let d = TestDir::new("t15-cfg");
    let mut c = cfg(
        d.path(),
        RetentionMode::Saturation {
            max_segments: 2,
            critical_reserve_segments: 1,
        },
    );
    c.unexported_reserve_segments = 1;
    let e = Recorder::open(c, signer(), clock()).unwrap_err();
    assert!(matches!(e, Error::Config(_)), "{e}");
}

/// The exporter runs next to a live recorder (its lock held), the recorder
/// learns of the moved cursor at its next rotation and drops what was
/// exported, and the far side accepts every bundle as one chain.
#[test]
fn exporter_beside_a_running_recorder_releases_exported_segments() {
    let d = TestDir::new("t15-outbox");
    let out = TestDir::new("t15-outbox-out");
    let mut r = open(protected(d.path(), 2, 3));
    let mut i = 0;
    rotations(&mut r, 4, &mut i);
    assert_eq!(r.segments().len(), 5);
    let mut rx = Receiver::new(Some("ugv-01".into()));

    // Export everything so far, in bundles of at most 40 records.
    let opts = PendingOptions {
        max_records: 40,
        max_bytes: 1 << 20,
    };
    let mut n = 0;
    while let Some((p, path)) =
        export_pending_to(d.path(), out.path(), &*signer(), &authentic, opts, None).unwrap()
    {
        assert!(p.gap.is_none());
        let b = Bundle::from_bytes(&std::fs::read(&path).unwrap()).unwrap();
        let rep = rx.accept(&b, &verifier());
        assert!(rep.is_intact(), "{}", dump(&rep));
        n += 1;
    }
    assert!(n >= 2, "{n} bundles");
    let head = r.head().unwrap().0;
    assert_eq!(rx.state().unwrap().seq, head);

    // The recorder picks the cursor up and returns to max_segments.
    assert_eq!(r.retention_status().unexported_segments, 5);
    assert!(r.refresh_export_state());
    assert_eq!(r.retention_status().confirmed_export_seq, Some(head));
    assert_eq!(r.retention_status().unexported_segments, 0);
    rotations(&mut r, 1, &mut i);
    assert_eq!(r.segments().len(), 2);
    assert_eq!(r.unexported_drops(), 0);
    drop(r);
    let dr = drops(d.path());
    assert_eq!(dr.len(), 4);
    assert!(dr.iter().all(|p| p.exported), "{dr:?}");

    // What came after continues the chain at the receiver.
    let r = open(protected(d.path(), 2, 3));
    drop(r);
    let (p, path) = export_pending_to(d.path(), out.path(), &*signer(), &authentic, opts, None)
        .unwrap()
        .unwrap();
    assert_eq!(p.bundle.anchor.as_ref().unwrap().seq, head);
    let b = Bundle::from_bytes(&std::fs::read(path).unwrap()).unwrap();
    assert!(rx.accept(&b, &verifier()).is_clean());
}

/// A cursor not signed by the recorder's key moves nothing: the recorder
/// keeps the segments and the exporter starts over (re-export is safe).
#[test]
fn a_forged_cursor_neither_releases_segments_nor_skips_records() {
    let d = TestDir::new("t15-forged");
    let mut r = open(protected(d.path(), 2, 3));
    let mut i = 0;
    rotations(&mut r, 3, &mut i);
    let (seq, hash) = r.head().unwrap();
    let a = Anchor {
        chain_id: r.chain_id(),
        seq,
        hash,
    };
    let other = HmacSha256Key::new("intruder", &[0x13; 32]).unwrap();
    let forged = SignedCursor {
        sig: other.sign(&cursor_signing_message(&a)).unwrap(),
        anchor: a,
    };
    std::fs::write(d.path().join(CURSOR_FILE), forged.to_json()).unwrap();
    assert!(!r.refresh_export_state());
    assert_eq!(r.retention_status().confirmed_export_seq, None);
    rotations(&mut r, 1, &mut i);
    assert_eq!(r.segments().len(), 5, "nothing released");
    let cursor_key = |m: &[u8], s: &[u8]| signer().verify_own(m, s) == Some(true);
    let p = collect_pending(d.path(), &cursor_key, &authentic, PendingOptions::default())
        .unwrap()
        .unwrap();
    assert_eq!(p.first_seq, 0);
    assert!(p.cursor_rejected.is_some());
}

/// Records dropped before they were exported are a gap the exporter names
/// and the receiver reports; the bundle is not passed off as continuous.
#[test]
fn records_lost_before_export_are_a_reported_gap() {
    let d = TestDir::new("t15-gap");
    let out = TestDir::new("t15-gap-out");
    let mut r = open(cfg(d.path(), RetentionMode::Cyclic { max_segments: 2 }));
    let mut i = 0;
    rotations(&mut r, 1, &mut i);
    let opts = PendingOptions::default();
    let (_, p1) = export_pending_to(d.path(), out.path(), &*signer(), &authentic, opts, None)
        .unwrap()
        .unwrap();
    let mut rx = Receiver::new(Some("ugv-01".into()));
    let b1 = Bundle::from_bytes(&std::fs::read(p1).unwrap()).unwrap();
    assert!(rx.accept(&b1, &verifier()).is_intact());
    // No protection: three more rotations drop exported and unexported
    // segments alike.
    rotations(&mut r, 4, &mut i);
    assert!(r.unexported_drops() > 0);
    let (p, p2) = export_pending_to(d.path(), out.path(), &*signer(), &authentic, opts, None)
        .unwrap()
        .unwrap();
    let [lo, hi] = p.gap.unwrap();
    assert_eq!(lo, b1.last().unwrap().0 + 1);
    assert_eq!(hi + 1, p.first_seq);
    assert!(p.bundle.anchor.is_none());
    let b2 = Bundle::from_bytes(&std::fs::read(p2).unwrap()).unwrap();
    // The far side sees a warning naming the lost seqs (the retained
    // records are authentic and anchored by the signed drop records).
    let rep = rx.accept(&b2, &verifier());
    assert!(!rep.is_clean(), "{}", dump(&rep));
    assert!(
        dump(&rep).contains(&format!("records {lo}..={hi} were dropped before export")),
        "{}",
        dump(&rep)
    );
}

/// The exporter refuses to export records that were rewritten after the
/// cursor was set (the cursor's hash no longer matches what follows).
#[test]
fn a_rewritten_log_after_the_cursor_is_refused() {
    let d = TestDir::new("t15-fork");
    let out = TestDir::new("t15-fork-out");
    let mut r = open(cfg(d.path(), big()));
    for i in 0..10 {
        recorded(r.append_note(&note(i), false).unwrap());
    }
    let (seq, _) = r.head().unwrap();
    let a = Anchor {
        chain_id: r.chain_id(),
        seq,
        hash: [0xAB; 32],
    };
    for i in 10..20 {
        recorded(r.append_note(&note(i), false).unwrap());
    }
    let c = SignedCursor {
        sig: signer().sign(&cursor_signing_message(&a)).unwrap(),
        anchor: a,
    };
    std::fs::write(d.path().join(CURSOR_FILE), c.to_json()).unwrap();
    let e = export_pending_to(
        d.path(),
        out.path(),
        &*signer(),
        &authentic,
        PendingOptions::default(),
        Some("ugv-01"),
    )
    .unwrap_err();
    assert!(matches!(e, Error::Untrusted(_)), "{e}");
    assert_eq!(std::fs::read_dir(out.path()).unwrap().count(), 0);
}

/// Run as root next to a recorder running as its own user, the exporter
/// leaves a cursor that user can read (owned like the directory).
#[cfg(unix)]
#[test]
fn the_cursor_is_owned_like_the_directory() {
    use std::os::unix::fs::MetadataExt;
    let d = TestDir::new("t15-owner");
    let out = TestDir::new("t15-owner-out");
    let mut r = open(cfg(d.path(), big()));
    recorded(r.append_note(&note(0), false).unwrap());
    drop(r);
    let me = std::fs::metadata(d.path()).unwrap().uid();
    if me != 0 {
        eprintln!("skipped: needs root to give the directory to another user");
        return;
    }
    std::os::unix::fs::chown(d.path(), Some(4242), Some(4243)).unwrap();
    export_pending_to(
        d.path(),
        out.path(),
        &*signer(),
        &authentic,
        PendingOptions::default(),
        Some("ugv-01"),
    )
    .unwrap()
    .unwrap();
    let m = std::fs::metadata(d.path().join(CURSOR_FILE)).unwrap();
    assert_eq!((m.uid(), m.gid()), (4242, 4243));
    assert_eq!(m.mode() & 0o777, 0o600);
}

/// The exporter streams segments one frame at a time; bytes that are not
/// a frame in the middle of a segment (damage) are resynchronised past as
/// before: the bundle stops at the break and the next one names the lost
/// record as a gap.
#[test]
fn a_damaged_frame_mid_segment_is_a_break_then_a_gap() {
    let d = TestDir::new("t15-damaged");
    let out = TestDir::new("t15-damaged-out");
    let mut r = open(cfg(d.path(), big()));
    let mut i = 0;
    rotations(&mut r, 3, &mut i);
    let head = r.head().unwrap().0;
    drop(r);
    let segs = robodr_blackbox::store::list_segments(d.path()).unwrap();
    let victim = &segs[1].1;
    let mut b = std::fs::read(victim).unwrap();
    let at = b
        .windows(4)
        .enumerate()
        .filter(|(_, w)| *w == b"RBF1")
        .map(|(i, _)| i)
        .nth(3)
        .unwrap();
    b[at] = b'X';
    std::fs::write(victim, b).unwrap();
    let opts = PendingOptions::default();
    let (p1, _) = export_pending_to(d.path(), out.path(), &*signer(), &authentic, opts, None)
        .unwrap()
        .unwrap();
    assert!(p1.gap.is_none());
    assert!(p1.last_seq < head);
    let (p2, _) = export_pending_to(d.path(), out.path(), &*signer(), &authentic, opts, None)
        .unwrap()
        .unwrap();
    assert_eq!(p2.gap, Some([p1.last_seq + 1, p1.last_seq + 1]));
    assert_eq!(p2.first_seq, p1.last_seq + 2);
    assert!(p2.last_seq <= head);
}

/// Review (WP4 phase 3): damage early in a large segment is resynchronised
/// past while streaming, not by reading the rest of the segment whole (up
/// to 256 MiB, which broke the exporter unit's `MemoryMax`). The segment
/// here carries 300 MiB of (sparse) zeros after its records: the old
/// fallback read them all into memory and then refused the segment as
/// larger than 256 MiB; the export must go on past the damage.
#[test]
fn damage_in_a_huge_segment_is_resynchronised_without_reading_it_whole() {
    let d = TestDir::new("t15-damaged-huge");
    let out = TestDir::new("t15-damaged-huge-out");
    let mut r = open(cfg(d.path(), big()));
    let mut i = 0;
    rotations(&mut r, 3, &mut i);
    let head = r.head().unwrap().0;
    drop(r);
    let segs = robodr_blackbox::store::list_segments(d.path()).unwrap();
    let victim = &segs[1].1;
    let mut b = std::fs::read(victim).unwrap();
    let at = b
        .windows(4)
        .enumerate()
        .filter(|(_, w)| *w == b"RBF1")
        .map(|(i, _)| i)
        .nth(1)
        .unwrap();
    b[at] = b'X';
    std::fs::write(victim, &b).unwrap();
    let f = std::fs::OpenOptions::new()
        .write(true)
        .open(victim)
        .unwrap();
    f.set_len(b.len() as u64 + 300 * 1024 * 1024).unwrap();
    drop(f);
    let opts = PendingOptions::default();
    let (p1, _) = export_pending_to(d.path(), out.path(), &*signer(), &authentic, opts, None)
        .unwrap()
        .unwrap();
    assert!(p1.gap.is_none());
    let (p2, _) = export_pending_to(d.path(), out.path(), &*signer(), &authentic, opts, None)
        .unwrap()
        .unwrap();
    assert_eq!(p2.gap, Some([p1.last_seq + 1, p1.last_seq + 1]));
    assert_eq!(p2.first_seq, p1.last_seq + 2);
    // Everything after the damage, the following segments included.
    let mut last = p2.last_seq;
    while last < head {
        let (p, _) = export_pending_to(d.path(), out.path(), &*signer(), &authentic, opts, None)
            .unwrap()
            .unwrap();
        assert_eq!(p.first_seq, last + 1, "{:?}", p.gap);
        last = p.last_seq;
    }
}

/// The bundle buffer never grows past `max_bytes` (a plain `Vec` doubles
/// to up to twice that).
#[test]
fn the_bundle_buffer_stays_within_max_bytes() {
    let d = TestDir::new("t15-bundle-cap");
    let mut r = open(cfg(d.path(), big()));
    for i in 0..400 {
        recorded(r.append_note(&note(i), false).unwrap());
    }
    drop(r);
    for max in [1000u64, 3000, 5000, 40_000] {
        let opts = PendingOptions {
            max_records: 100_000,
            max_bytes: max,
        };
        let cursor_key = |m: &[u8], s: &[u8]| authentic(m, s);
        let p = collect_pending(d.path(), &cursor_key, &authentic, opts)
            .unwrap()
            .unwrap();
        assert!(p.more);
        assert!(p.bundle.frames.len() as u64 <= max);
        assert!(
            p.bundle.frames.capacity() as u64 <= max,
            "max {max}: capacity {}",
            p.bundle.frames.capacity()
        );
    }
}

/// Review (WP4): a key rotation re-signs the newest export cursor on disk
/// (one an exporter beside the recorder advanced since the recorder last
/// read it), never an older copy held in memory: moving the cursor back
/// would re-export records the far side already has.
#[test]
fn rotation_never_moves_the_export_cursor_backwards() {
    let d = TestDir::new("t15-rotate-cursor");
    let out = TestDir::new("t15-rotate-cursor-out");
    let mut r = open(cfg(d.path(), big()));
    for i in 0..10 {
        recorded(r.append_note(&note(i), false).unwrap());
    }
    let opts = PendingOptions::default();
    export_pending_to(d.path(), out.path(), &*signer(), &authentic, opts, None)
        .unwrap()
        .unwrap();
    assert!(r.refresh_export_state());
    let held = r.retention_status().confirmed_export_seq.unwrap();
    for i in 10..20 {
        recorded(r.append_note(&note(i), false).unwrap());
    }
    let (p, _) = export_pending_to(d.path(), out.path(), &*signer(), &authentic, opts, None)
        .unwrap()
        .unwrap();
    assert!(p.last_seq > held);
    let k2 = Ed25519SigningKey::from_seed("bb-2", &[2; 32]).unwrap();
    let k2b = Ed25519SigningKey::from_seed("bb-2", &[2; 32]).unwrap();
    r.rotate_key(Box::new(k2b), None, "test").unwrap();
    let c = SignedCursor::from_json(&std::fs::read_to_string(d.path().join(CURSOR_FILE)).unwrap())
        .unwrap();
    assert_eq!(c.anchor.seq, p.last_seq, "cursor moved back to {held}");
    assert_eq!(
        k2.verify_own(&cursor_signing_message(&c.anchor), &c.sig),
        Some(true)
    );
    assert_eq!(r.retention_status().confirmed_export_seq, Some(p.last_seq));
}
