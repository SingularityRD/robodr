//! Store-and-forward bundles verified by an independent receiver.

mod common;

use common::*;
use robodr_blackbox::*;

fn fill(r: &mut Recorder, n: u64) {
    for i in 0..n {
        recorded(r.append_note(&note(i), false).unwrap());
    }
}

/// Bundles survive serialisation (as they would through a diode).
fn ship(b: &Bundle) -> Bundle {
    Bundle::from_bytes(&b.to_bytes()).unwrap()
}

#[test]
fn successive_bundles_verify_and_chain() {
    let d = TestDir::new("export");
    let mut r = open(cfg(d.path(), big()));
    fill(&mut r, 30);
    let mut rx = Receiver::new(Some("ugv-01".into()));

    let b1 = ship(&r.export_pending(None).unwrap().unwrap());
    assert!(b1.anchor.is_none());
    let rep = rx.accept(&b1, &verifier());
    assert!(rep.is_clean(), "{}", dump(&rep));
    assert_eq!(rep.first_seq, Some(0));
    r.mark_exported(&b1).unwrap();
    assert_eq!(rx.state().unwrap().seq, b1.last().unwrap().0);
    assert_eq!(r.export_cursor().unwrap(), rx.state().unwrap());
    assert!(r.export_pending(None).unwrap().is_none());

    fill(&mut r, 25);
    let b2 = ship(&r.export_pending(None).unwrap().unwrap());
    assert_eq!(b2.anchor.as_ref().unwrap().seq, b1.last().unwrap().0);
    let rep = rx.accept(&b2, &verifier());
    assert!(rep.is_clean(), "{}", dump(&rep));
    r.mark_exported(&b2).unwrap();

    // Limited bundles chain too.
    fill(&mut r, 10);
    let b3 = ship(&r.export_pending(Some(4)).unwrap().unwrap());
    assert_eq!(b3.records().len(), 4);
    assert!(rx.accept(&b3, &verifier()).is_intact());
    r.mark_exported(&b3).unwrap();
    let b4 = ship(&r.export_pending(None).unwrap().unwrap());
    let rep = rx.accept(&b4, &verifier());
    assert!(rep.is_clean(), "{}", dump(&rep));

    // The cursor survives reopen.
    r.mark_exported(&b4).unwrap();
    let cursor = r.export_cursor().cloned();
    drop(r);
    let r = open(cfg(d.path(), big()));
    assert_eq!(r.export_cursor().cloned(), cursor);
}

#[test]
fn receiver_detects_gap_replay_and_tamper() {
    let d = TestDir::new("export-attacks");
    let mut r = open(cfg(d.path(), big()));
    let mut bundles = Vec::new();
    for _ in 0..3 {
        fill(&mut r, 8);
        let b = ship(&r.export_pending(None).unwrap().unwrap());
        r.mark_exported(&b).unwrap();
        bundles.push(b);
    }
    let mut rx = Receiver::new(Some("ugv-01".into()));
    assert!(rx.accept(&bundles[0], &verifier()).is_clean());
    let state = rx.state().cloned();

    // Skipped bundle: gap from the receiver's anchor.
    let rep = rx.accept(&bundles[2], &verifier());
    assert!(
        tamper_kinds(&rep)
            .iter()
            .any(|k| matches!(k, FindingKind::Deleted { .. })),
        "{}",
        dump(&rep)
    );
    assert_eq!(rx.state().cloned(), state, "state must not advance");

    // In order works; then replaying an old bundle is stale.
    assert!(rx.accept(&bundles[1], &verifier()).is_clean());
    let rep = rx.accept(&bundles[0], &verifier());
    assert!(has(&rep, |k| matches!(k, FindingKind::StaleBundle { .. })));
    assert!(!rep.is_clean());

    // A modified byte in the frames.
    let mut t = bundles[2].clone();
    let n = t.frames.len();
    t.frames[n / 2] ^= 0x04;
    let rep = rx.accept(&t, &verifier());
    assert!(!rep.is_clean(), "{}", dump(&rep));
    assert!(rx.accept(&bundles[2], &verifier()).is_clean());
}

#[test]
fn bundle_from_another_device_is_rejected() {
    let da = TestDir::new("export-a");
    let db = TestDir::new("export-b");
    let mut ra = open(cfg(da.path(), big()));
    let mut cb = cfg(db.path(), big());
    cb.device_id = "ugv-99".into();
    let mut rb = open(cb);
    fill(&mut ra, 5);
    fill(&mut rb, 5);
    let ba = ship(&ra.export_pending(None).unwrap().unwrap());
    let bb = ship(&rb.export_pending(None).unwrap().unwrap());

    // First contact, pinned to ugv-01.
    let mut fresh = Receiver::new(Some("ugv-01".into()));
    let rep = fresh.accept(&bb, &verifier());
    assert!(
        tamper_kinds(&rep)
            .iter()
            .any(|k| matches!(k, FindingKind::WrongDevice { .. })),
        "{}",
        dump(&rep)
    );
    assert!(fresh.state().is_none());

    // Receiver already following ugv-01's chain.
    let mut rx = Receiver::new(Some("ugv-01".into()));
    assert!(rx.accept(&ba, &verifier()).is_clean());
    let rep = rx.accept(&bb, &verifier());
    assert!(rep
        .tamper()
        .any(|f| matches!(f.kind, FindingKind::ForeignChain { .. })));

    // Lying about the identity in the bundle header does not help.
    let mut forged = bb.clone();
    forged.identity = ba.identity.clone();
    let rep = Receiver::new(Some("ugv-01".into())).accept(&forged, &verifier());
    assert!(rep
        .tamper()
        .any(|f| matches!(f.kind, FindingKind::ForeignChain { .. })));
}

#[test]
fn cyclic_loss_before_export_is_visible_to_receiver() {
    let d = TestDir::new("export-cyclic");
    let mut r = open(cfg(d.path(), RetentionMode::Cyclic { max_segments: 2 }));
    fill(&mut r, 5);
    let b1 = ship(&r.export_pending(None).unwrap().unwrap());
    r.mark_exported(&b1).unwrap();
    let mut rx = Receiver::new(None);
    assert!(rx.accept(&b1, &verifier()).is_clean());
    fill(&mut r, 120); // wraps several times before the next export
    let b2 = ship(&r.export_pending(None).unwrap().unwrap());
    let rep = rx.accept(&b2, &verifier());
    assert!(rep.is_intact(), "{}", dump(&rep));
    assert!(has(&rep, |k| matches!(
        k,
        FindingKind::DroppedBeforeExport { .. }
    )));
    assert_eq!(rx.state().unwrap().seq, b2.last().unwrap().0);
}

#[test]
fn first_contact_mid_stream_flags_unverified_anchor() {
    let d = TestDir::new("export-mid");
    let mut r = open(cfg(d.path(), big()));
    fill(&mut r, 5);
    let b1 = r.export_pending(None).unwrap().unwrap();
    r.mark_exported(&b1).unwrap();
    fill(&mut r, 5);
    let b2 = ship(&r.export_pending(None).unwrap().unwrap());
    let rep = Receiver::new(None).accept(&b2, &verifier());
    assert!(rep.is_intact(), "{}", dump(&rep));
    assert!(has(&rep, |k| matches!(
        k,
        FindingKind::AnchorUnverified { .. }
    )));
}

#[test]
fn random_bundle_corruption_is_always_detected() {
    let d = TestDir::new("export-fuzz");
    let mut r = open(cfg(d.path(), big()));
    fill(&mut r, 20);
    let b = r.export_pending(None).unwrap().unwrap();
    let bytes = b.to_bytes();
    let mut rng = Rng(77);
    for _ in 0..300 {
        let mut t = bytes.clone();
        let at = rng.below(t.len());
        t[at] ^= (rng.below(255) + 1) as u8;
        match Bundle::from_bytes(&t) {
            Err(_) => {}
            Ok(parsed) => {
                let rep = Receiver::new(Some("ugv-01".into())).accept(&parsed, &verifier());
                assert!(!rep.is_clean(), "flip at {at} undetected: {}", dump(&rep));
            }
        }
    }
}
