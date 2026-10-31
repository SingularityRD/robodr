//! Std-only smoke run of the `fleet_token` and `fleet_envelope` libFuzzer
//! targets (`fuzz/fuzz_targets/`): the same harness code
//! (`fuzz/harness/*.rs`, included by path) driven by the deterministic
//! mutator in `fuzz/harness/smoke.rs` over the committed seed corpora (the
//! contract vectors' tokens and bodies). See `fuzz/README.md`.
//! `ROBODR_FUZZ_ITERS` / `ROBODR_FUZZ_SECS` tune the run.

#[path = "../../../fuzz/harness/fleet_envelope.rs"]
mod fleet_envelope;
#[path = "../../../fuzz/harness/fleet_token.rs"]
mod fleet_token;
#[path = "../../../fuzz/harness/smoke.rs"]
mod smoke;

use robodr_blackbox::Ed25519SigningKey;
use robodr_fleet::wire::{self, Envelope, Token};

const DIR: &str = env!("CARGO_MANIFEST_DIR");

#[test]
fn fleet_seeds_take_the_success_paths() {
    let soc = Ed25519SigningKey::from_seed_with_derived_id(&[0x50; 32]);
    for f in smoke::corpus(DIR, "fleet_token") {
        let t = Token::parse(std::str::from_utf8(&f).unwrap()).expect("seed token parses");
        t.verify(&soc.public_key()).expect("seed token verifies");
    }
    let mut kinds = std::collections::BTreeSet::new();
    let (mut parsed, mut total) = (0, 0);
    for f in smoke::corpus(DIR, "fleet_envelope") {
        total += 1;
        let mut ok = wire::Offer::parse(&f).is_ok();
        for kind in [
            wire::T_ENROLL_REQUEST,
            wire::T_ENROLL_ANSWER,
            wire::T_ROTATE_REQUEST,
            wire::T_ROTATE_ANSWER,
            wire::T_RETIRE_REQUEST,
            wire::T_RETIRE_ANSWER,
            wire::T_CANCEL_REQUEST,
            wire::T_CANCEL_ANSWER,
            wire::T_APPROVAL,
            wire::T_RING,
            wire::T_DECOMMISSION_REQUEST,
            wire::T_DECOMMISSION_ANSWER,
        ] {
            if Envelope::parse(&f, kind).is_ok() {
                ok = true;
                kinds.insert(kind);
            }
        }
        parsed += usize::from(ok);
    }
    // The malformed-request vectors (no mac, trailing bytes) are seeds too.
    assert!(parsed + 2 >= total, "only {parsed} of {total} seeds parse");
    assert!(
        kinds.len() >= 11,
        "seeds cover too few envelope types: {kinds:?}"
    );
}

#[test]
fn fleet_token_smoke() {
    let seeds = smoke::corpus(DIR, "fleet_token");
    smoke::run("fleet_token", &seeds, 0xf1ee_0001, &fleet_token::run);
}

#[test]
fn fleet_envelope_smoke() {
    let seeds = smoke::corpus(DIR, "fleet_envelope");
    smoke::run("fleet_envelope", &seeds, 0xf1ee_0002, &fleet_envelope::run);
}
