//! Std-only smoke run of the `ocsf_parse_and_validate` libFuzzer target
//! (`fuzz/fuzz_targets/`): the same harness code (`fuzz/harness/*.rs`,
//! included by path) driven by the deterministic mutator in
//! `fuzz/harness/smoke.rs` over the committed seed corpus. See
//! `fuzz/README.md`. `ROBODR_FUZZ_ITERS` / `ROBODR_FUZZ_SECS` tune the run.

#[path = "../../../fuzz/harness/ocsf_parse_and_validate.rs"]
mod ocsf_parse_and_validate;
#[path = "../../../fuzz/harness/smoke.rs"]
mod smoke;

const DIR: &str = env!("CARGO_MANIFEST_DIR");

#[test]
fn ocsf_seeds_are_valid_findings() {
    for seed in smoke::corpus(DIR, "ocsf_parse_and_validate") {
        let text = std::str::from_utf8(&seed).unwrap();
        robodr_ocsf::parse_and_validate(text).expect("seed is a valid finding");
    }
}

#[test]
fn ocsf_parse_and_validate_smoke() {
    let seeds = smoke::corpus(DIR, "ocsf_parse_and_validate");
    smoke::run(
        "ocsf_parse_and_validate",
        &seeds,
        0x0c5f_0001,
        &ocsf_parse_and_validate::run,
    );
}
