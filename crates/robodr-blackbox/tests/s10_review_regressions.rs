//! S10 hardening review: regression tests.
//!
//! L3: agentd links this library and runs with `panic = "abort"`, so an
//!    invariant `expect` in `Recorder::open`'s recovery that on-disk state
//!    can reach kills the daemon (and, being on-disk state, again at every
//!    restart). An authentic record with seq `u64::MAX` after a hole in the
//!    active segment made the seq floor overflow to `None` while truncation
//!    evidence was still recorded, and `skipped.expect("evidence implies a
//!    floor")` panicked. Open must refuse the log instead (there is no seq
//!    left to continue the chain without reusing one).
mod common;
use common::*;
use robodr_blackbox::record::signing_message;
use robodr_blackbox::store::segment_file_name;
use robodr_blackbox::*;

#[test]
fn l3_authentic_max_seq_after_a_hole_is_an_error_not_a_panic() {
    let d = TestDir::new("s10-l3-maxseq");
    let mut c = cfg(d.path(), big());
    c.max_segment_bytes = 1 << 20;
    let mut r = open(c.clone());
    for i in 0..3 {
        recorded(r.append_note(&note(i), false).unwrap());
    }
    drop(r);
    let p = d.path().join(segment_file_name(0));
    let mut b = std::fs::read(&p).unwrap();
    let last = frames(&b).last().unwrap().2.clone();
    b.extend_from_slice(&[0u8; 64]); // a hole, then an authentic frame
    let mut f = last.clone();
    f.seq = u64::MAX;
    f.prev_hash = last.hash;
    f.critical = true; // synced under fsync_critical: no crash explains it
    f.payload = b"{}".to_vec();
    f.hash = f.compute_hash();
    f.sig = verifier().sign(&signing_message(&f.hash)).unwrap();
    b.extend_from_slice(&f.encode_frame());
    std::fs::write(&p, &b).unwrap();

    let res = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        Recorder::open(c.clone(), signer(), clock()).map(drop)
    }));
    let res = res.expect("open must not panic on corrupted on-disk state");
    match res {
        Err(Error::Corrupt { reason, .. }) => {
            assert!(reason.contains("sequence"), "{reason}");
        }
        Err(e) => panic!("unexpected error: {e}"),
        Ok(_) => panic!("opened a log whose seq space is exhausted"),
    }
    // Nothing was modified: the evidence is still there for a human.
    assert_eq!(std::fs::read(&p).unwrap(), b);
}
