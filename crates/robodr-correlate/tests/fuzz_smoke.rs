//! Std-only smoke run of the `correlate_rules` libFuzzer target
//! (`fuzz/fuzz_targets/`): the same harness code
//! (`fuzz/harness/correlate_rules.rs`, included by path) driven by the
//! deterministic mutator in `fuzz/harness/smoke.rs` over the committed seed
//! corpus. See `fuzz/README.md`. `ROBODR_FUZZ_ITERS` / `ROBODR_FUZZ_SECS`
//! tune the run.
//!
//! Seeds: the shipped default rules followed by a signal stream that makes
//! them fire, built by `regenerate_seeds` (run with `--ignored`).

#[path = "../../../fuzz/harness/correlate_rules.rs"]
mod correlate_rules;
#[path = "../../../fuzz/harness/smoke.rs"]
mod smoke;

use robodr_correlate::DEFAULT_RULES_JSON;

const DIR: &str = env!("CARGO_MANIFEST_DIR");

#[test]
fn seeds_are_accepted_and_fire() {
    for seed in smoke::corpus(DIR, "correlate_rules") {
        let (accepted, findings) = correlate_rules::run_counting(&seed);
        assert!(accepted, "seed rules rejected");
        assert!(findings > 0, "seed signals never fire a rule");
    }
}

#[test]
fn correlate_rules_smoke() {
    let seeds = smoke::corpus(DIR, "correlate_rules");
    smoke::run(
        "correlate_rules",
        &seeds,
        0xc0e1_0001,
        &correlate_rules::run,
    );
}

/// Regenerates the committed seeds: default rules + the first pseudo-random
/// signal streams (deterministic) that produce findings. Run with
/// `cargo test -p robodr-correlate --test fuzz_smoke -- --ignored regenerate_seeds`.
#[test]
#[ignore = "writes into fuzz/corpus; run manually to refresh seeds"]
fn regenerate_seeds() {
    let dir = smoke::corpus_dir(DIR, "correlate_rules");
    std::fs::create_dir_all(&dir).unwrap();
    let mut rng = smoke::Rng::new(0xc0e1_5eed);
    let mut written = 0;
    for attempt in 0..10_000 {
        let mut input = DEFAULT_RULES_JSON.as_bytes().to_vec();
        input.push(0);
        input.push(0); // max_groups_per_rule = 1 + 0
        input.extend((0..4 * 200 - 1).map(|i| match i % 4 {
            // Small time steps, so windows overlap.
            3 => (rng.below(4)) as u8,
            _ => rng.byte(),
        }));
        let (accepted, findings) = correlate_rules::run_counting(&input);
        assert!(accepted);
        if findings > 0 {
            std::fs::write(dir.join(format!("seed-default-{written}.bin")), &input).unwrap();
            written += 1;
            if written == 3 {
                eprintln!("seeds found after {attempt} attempts");
                return;
            }
        }
    }
    panic!("no firing signal stream found");
}
