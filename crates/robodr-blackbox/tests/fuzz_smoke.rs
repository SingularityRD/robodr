//! Std-only smoke run of the `blackbox_segments` libFuzzer target
//! (`fuzz/fuzz_targets/`): the same harness code (`fuzz/harness/*.rs`,
//! included by path) driven by the deterministic mutator in
//! `fuzz/harness/smoke.rs` over the committed seed corpus. See
//! `fuzz/README.md`. `ROBODR_FUZZ_ITERS` / `ROBODR_FUZZ_SECS` tune the run.

#[path = "../../../fuzz/harness/blackbox_segments.rs"]
mod blackbox_segments;
#[path = "../../../fuzz/harness/smoke.rs"]
mod smoke;

use robodr_blackbox::verify::{verify_segments, SegmentData, VerifyOptions};
use robodr_blackbox::Bundle;

const DIR: &str = env!("CARGO_MANIFEST_DIR");

/// The seeds are real recorder output signed with the harness key, so the
/// fuzzer starts from evidence whose records verify (not from garbage that
/// stops at the first signature check).
#[test]
fn blackbox_seed_records_verify() {
    let seeds = smoke::corpus(DIR, "blackbox_segments");
    let v = blackbox_segments::verifier();
    let mut chains = 0;
    let mut bundles = 0;
    for seed in &seeds {
        let (segs, _) = blackbox_segments::split(seed);
        if segs.len() > 1 || seed.starts_with(b"RBF1") {
            let data: Vec<SegmentData> = segs
                .into_iter()
                .enumerate()
                .map(|(i, bytes)| SegmentData {
                    name: format!("seg-{i}"),
                    bytes,
                })
                .collect();
            let r = verify_segments(&data, &v, &VerifyOptions::default());
            // Every record verifies (hash, signature, chain). The rotated
            // seed keeps only the newest segments, like a cyclic recorder
            // that dropped its oldest: that is reported as a missing head.
            assert!(
                r.frames > 0 && r.verified_records == r.frames,
                "seed does not verify: {r:?}"
            );
            chains += 1;
        }
        if let Ok(b) = Bundle::from_bytes(seed) {
            assert!(b.verify(&v, None, None).is_intact());
            bundles += 1;
        }
    }
    assert!(
        chains >= 2 && bundles >= 1,
        "chains {chains}, bundles {bundles}"
    );
}

#[test]
fn blackbox_segments_smoke() {
    let seeds = smoke::corpus(DIR, "blackbox_segments");
    smoke::run(
        "blackbox_segments",
        &seeds,
        0xbb0c_0001,
        &blackbox_segments::run,
    );
    blackbox_segments::cleanup();
}
