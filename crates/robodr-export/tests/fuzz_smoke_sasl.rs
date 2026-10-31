//! Std-only smoke run of the `kafka_sasl` libFuzzer target
//! (`fuzz/fuzz_targets/kafka_sasl.rs`): the same harness code
//! (`fuzz/harness/kafka_sasl.rs`, included by path) driven by the
//! deterministic mutator in `fuzz/harness/smoke.rs` over the committed seed
//! corpus (`fuzz/corpus/kafka_sasl/`). The seeds are written by
//! `regenerate_seeds` (`--ignored`); `seeds_are_current` fails when the
//! committed files differ, `seeds_take_the_success_paths` checks they still
//! reach the accepting paths. See `fuzz/README.md`.

#[path = "../../../fuzz/harness/kafka_sasl.rs"]
mod kafka_sasl;
#[path = "../../../fuzz/harness/smoke.rs"]
mod smoke;

use robodr_export::kafka::sasl::{
    b64_decode, decode_authenticate_response, decode_handshake_response, Mechanism, ScramClient,
};

const DIR: &str = env!("CARGO_MANIFEST_DIR");
const TARGET: &str = "kafka_sasl";

#[test]
#[ignore = "writes fuzz/corpus/kafka_sasl; run after a format change"]
fn regenerate_seeds() {
    let dir = smoke::corpus_dir(DIR, TARGET);
    std::fs::create_dir_all(&dir).unwrap();
    for (name, bytes) in kafka_sasl::seeds() {
        std::fs::write(dir.join(name), bytes).unwrap();
    }
}

#[test]
fn seeds_are_current() {
    for (name, bytes) in kafka_sasl::seeds() {
        let p = smoke::corpus_dir(DIR, TARGET).join(name);
        let on_disk = std::fs::read(&p)
            .unwrap_or_else(|e| panic!("{}: {e} (run regenerate_seeds)", p.display()));
        assert!(
            on_disk == bytes,
            "{} is stale: run regenerate_seeds",
            p.display()
        );
    }
}

#[test]
fn seeds_take_the_success_paths() {
    let mut kinds = std::collections::BTreeSet::new();
    for (name, seed) in kafka_sasl::seeds() {
        let (&sel, body) = seed.split_first().unwrap();
        kinds.insert(sel % 4);
        let s = sel / 4;
        let text = std::str::from_utf8(body).unwrap_or("");
        let ok = match sel % 4 {
            0 => b64_decode(text).is_some(),
            1 => {
                let mech = if s.is_multiple_of(2) {
                    Mechanism::ScramSha256
                } else {
                    Mechanism::ScramSha512
                };
                ScramClient::with_nonce(mech, "robodr", kafka_sasl::RFC_NONCE)
                    .client_final(text, "pencil")
                    .is_ok()
            }
            // The "e=" seed must be refused: it reaches the error branch.
            2 => {
                let mut c =
                    ScramClient::with_nonce(Mechanism::ScramSha256, "user", kafka_sasl::RFC_NONCE);
                c.client_final(kafka_sasl::RFC_SERVER_FIRST, "pencil")
                    .unwrap();
                c.verify_final(text).is_ok() == text.starts_with("v=")
            }
            _ if s.is_multiple_of(2) => decode_handshake_response(body).is_ok(),
            _ => decode_authenticate_response(i16::from((s / 2) % 2), body).is_ok(),
        };
        assert!(ok, "seed {name} does not take its success path");
    }
    assert_eq!(kinds.len(), 4, "seeds cover every entry point");
}

/// Hostile server-first messages the RFC tests name, through the harness
/// (each must be refused without tripping an invariant).
#[test]
fn kafka_sasl_hostile_inputs() {
    for sf in [
        "r=rOprNGfwEbeRWgbNEkqO,s=c2FsdA==,i=4096",
        "r=rOprNGfwEbeRWgbNEkqOx,s=c2FsdA==,i=4095",
        "r=rOprNGfwEbeRWgbNEkqOx,s=c2FsdA==,i=100001",
        "r=rOprNGfwEbeRWgbNEkqOx,s=c2FsdA==,i=4294967296",
        "r=rOprNGfwEbeRWgbNEkqOx,s=,i=4096",
        "r=rOprNGfwEbeRWgbNEkqOx\u{7f},s=c2FsdA==,i=4096",
        "m=ext,r=rOprNGfwEbeRWgbNEkqOx,s=c2FsdA==,i=4096",
        "r=rOprNGfwEbeRWgbNEkqOx,s=c2FsdA==,i=4096,x=extension",
    ] {
        let mut input = vec![1u8];
        input.extend_from_slice(sf.as_bytes());
        kafka_sasl::run(&input);
    }
    for sf in [
        "v=",
        "v=AAAA",
        "e=other-error",
        "v=6rriTRBi23WpRR/wtup+mMhUZUn/dB5nLTJRsjl95G4",
    ] {
        let mut input = vec![2u8];
        input.extend_from_slice(sf.as_bytes());
        kafka_sasl::run(&input);
    }
}

#[test]
fn kafka_sasl_smoke() {
    let seeds = smoke::corpus(DIR, TARGET);
    smoke::run(TARGET, &seeds, 0x7361_736c, &kafka_sasl::run);
}
