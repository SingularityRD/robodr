//! Std-only smoke run of the `events_profile` libFuzzer target
//! (`fuzz/fuzz_targets/`): the same harness code (`fuzz/harness/*.rs`,
//! included by path) driven by the deterministic mutator in
//! `fuzz/harness/smoke.rs` over the committed seed corpus. See
//! `fuzz/README.md`. `ROBODR_FUZZ_ITERS` / `ROBODR_FUZZ_SECS` tune the run.

#[path = "../../../fuzz/harness/events_profile.rs"]
mod events_profile;
#[path = "../../../fuzz/harness/smoke.rs"]
mod smoke;

use robodr_events::profile::Profile;

const DIR: &str = env!("CARGO_MANIFEST_DIR");

#[test]
fn profile_seeds_are_valid_and_produce_deviations() {
    for seed in smoke::corpus(DIR, "events_profile") {
        let p: Profile = serde_json::from_slice(&seed).expect("seed parses");
        assert_eq!(p.validate(), Ok(()));
        let hits = events_profile::probe_events(&p)
            .iter()
            .filter(|e| p.evaluate(e).is_some())
            .count();
        assert!(hits > 0, "probe events never deviate");
    }
}

#[test]
fn events_profile_smoke() {
    let seeds = smoke::corpus(DIR, "events_profile");
    smoke::run("events_profile", &seeds, 0xe7e0_0001, &events_profile::run);
}
