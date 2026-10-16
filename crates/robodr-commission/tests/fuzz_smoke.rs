//! Std-only smoke run of the `commission_profile_file`,
//! `commission_signoff` and `commission_jsonl` libFuzzer targets
//! (`fuzz/fuzz_targets/`): the same harness code (`fuzz/harness/*.rs`,
//! included by path) driven by the deterministic mutator in
//! `fuzz/harness/smoke.rs` over the committed seed corpora. See
//! `fuzz/README.md`. `ROBODR_FUZZ_ITERS` / `ROBODR_FUZZ_SECS` tune the run.

#[path = "../../../fuzz/harness/commission_jsonl.rs"]
mod commission_jsonl;
#[path = "../../../fuzz/harness/commission_profile_file.rs"]
mod commission_profile_file;
#[path = "../../../fuzz/harness/commission_signoff.rs"]
mod commission_signoff;
#[path = "../../../fuzz/harness/smoke.rs"]
mod smoke;

use std::io::Cursor;

use robodr_commission::input::read_all;
use robodr_commission::{lock, parse_profile_text, JsonlSource, Signoff};

const DIR: &str = env!("CARGO_MANIFEST_DIR");

#[test]
fn commission_seeds_take_the_success_paths() {
    let files = smoke::corpus(DIR, "commission_profile_file");
    let parsed: Vec<_> = files
        .iter()
        .map(|f| parse_profile_text(std::str::from_utf8(f).unwrap()).expect("seed parses"))
        .collect();
    assert!(parsed.iter().any(|p| p.locked) && parsed.iter().any(|p| !p.locked));

    let draft = commission_signoff::draft();
    let mut locked = 0;
    for f in smoke::corpus(DIR, "commission_signoff") {
        let so: Signoff = serde_json::from_slice(&f).expect("seed parses");
        locked += usize::from(lock(&draft, &so).is_ok());
    }
    assert_eq!(locked, 1, "exactly the confirmed sign-off seed locks");

    for f in smoke::corpus(DIR, "commission_jsonl") {
        let events = read_all(&mut JsonlSource::new("seed", Cursor::new(f))).expect("seed reads");
        assert!(!events.is_empty(), "JSONL seed yields no events");
    }
}

#[test]
fn commission_profile_file_smoke() {
    let seeds = smoke::corpus(DIR, "commission_profile_file");
    smoke::run(
        "commission_profile_file",
        &seeds,
        0xc0aa_0001,
        &commission_profile_file::run,
    );
}

#[test]
fn commission_signoff_smoke() {
    let seeds = smoke::corpus(DIR, "commission_signoff");
    smoke::run(
        "commission_signoff",
        &seeds,
        0xc0aa_0002,
        &commission_signoff::run,
    );
}

#[test]
fn commission_jsonl_smoke() {
    let seeds = smoke::corpus(DIR, "commission_jsonl");
    smoke::run(
        "commission_jsonl",
        &seeds,
        0xc0aa_0003,
        &commission_jsonl::run,
    );
}
