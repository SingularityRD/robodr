//! Std-only smoke run of the `kafka_wire` libFuzzer target
//! (`fuzz/fuzz_targets/kafka_wire.rs`): the same harness code
//! (`fuzz/harness/kafka_wire.rs`, included by path) driven by the
//! deterministic mutator in `fuzz/harness/smoke.rs` over the committed seed
//! corpus (`fuzz/corpus/kafka_wire/`, one input per decoder and version
//! class, written by `fuzz/seedgen/kafka_wire.py`). See `fuzz/README.md`.
//! `ROBODR_FUZZ_ITERS` / `ROBODR_FUZZ_SECS` tune the run.

#[path = "../../../fuzz/harness/kafka_wire.rs"]
mod kafka_wire;
#[path = "../../../fuzz/harness/smoke.rs"]
mod smoke;

use robodr_export::kafka::batch::decode_batches;
use robodr_export::kafka::proto::{
    decode_api_versions, decode_init_producer_id_request, decode_init_producer_id_response,
    decode_metadata, decode_metadata_request, decode_produce_request, decode_produce_response,
    parse_request_header, API_INIT_PRODUCER_ID,
};
use robodr_export::kafka::wire::Reader;

const DIR: &str = env!("CARGO_MANIFEST_DIR");

/// Every seed takes its decoder's success path (same selector layout as the
/// harness), so a wire-format change cannot silently turn the corpus into
/// inputs that only exercise the first error branch.
#[test]
fn kafka_wire_seeds_take_the_success_paths() {
    let seeds = smoke::corpus(DIR, "kafka_wire");
    let mut selectors = std::collections::BTreeSet::new();
    let (mut init_pid_response, mut init_pid_request, mut idempotent_batch) = (false, false, false);
    for (i, f) in seeds.iter().enumerate() {
        let (&sel, body) = f.split_first().expect("seed has a selector byte");
        let s = sel / 8;
        selectors.insert(sel % 8);
        let ok = match sel % 8 {
            0 if s % 2 == 1 => {
                init_pid_response = true;
                decode_init_producer_id_response(body).is_ok()
            }
            0 => decode_api_versions(body).is_ok(),
            1 => decode_metadata(1 + i16::from(s % 8), body).is_ok(),
            2 => decode_produce_response(3 + i16::from(s % 6), body).is_ok(),
            3 | 4 => decode_batches(body).is_ok_and(|b| {
                idempotent_batch |= b.iter().any(|x| x.producer_id >= 0);
                !b.is_empty()
            }),
            5 => parse_request_header(body).is_ok_and(|(h, mut r)| {
                if h.api_key == API_INIT_PRODUCER_ID {
                    init_pid_request = true;
                    decode_init_producer_id_request(&mut r).is_ok()
                } else {
                    decode_metadata_request(&mut r).is_ok()
                }
            }),
            6 => parse_request_header(body)
                .is_ok_and(|(_, mut r)| decode_produce_request(&mut r).is_ok()),
            _ => {
                let mut r = Reader::new(body);
                r.string().is_ok()
            }
        };
        assert!(ok, "seed {i} (selector {sel}) does not decode");
    }
    assert_eq!(
        selectors.len(),
        8,
        "seeds cover too few decoders: {selectors:?}"
    );
    assert!(
        init_pid_response && init_pid_request && idempotent_batch,
        "seeds cover InitProducerId and idempotent batches"
    );
}

#[test]
fn kafka_wire_smoke() {
    let seeds = smoke::corpus(DIR, "kafka_wire");
    smoke::run("kafka_wire", &seeds, 0x6b61_6602, &kafka_wire::run);
}
