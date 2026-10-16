//! Std-only smoke run of the `pcap_reader` and `capture_reassembly`
//! libFuzzer targets (`fuzz/fuzz_targets/`): the same harness code
//! (`fuzz/harness/*.rs`, included by path) driven by the deterministic
//! mutator in `fuzz/harness/smoke.rs` over the committed seed corpus.
//! See `fuzz/README.md`. `ROBODR_FUZZ_ITERS` / `ROBODR_FUZZ_SECS` tune the
//! run (default 20 000 inputs or 8 s per target).

#[path = "../../../fuzz/harness/capture_reassembly.rs"]
mod capture_reassembly;
#[path = "../../../fuzz/harness/pcap_reader.rs"]
mod pcap_reader;
#[path = "../../../fuzz/harness/smoke.rs"]
mod smoke;

use robodr_capture::{rtps_datagrams, CaptureFile, VecSource};

const DIR: &str = env!("CARGO_MANIFEST_DIR");

#[test]
fn pcap_reader_seeds_reach_the_rtps_parser() {
    for seed in smoke::corpus(DIR, "pcap_reader") {
        let mut it = rtps_datagrams(CaptureFile::new(&seed[..]).expect("seed opens"));
        let mut events = 0;
        while let Some(p) = it.next_packet() {
            events += robodr_rtps::parse_datagram(&p.payload, &p.src.to_string()).len();
        }
        assert!(it.last_error().is_none(), "{:?}", it.last_error());
        assert!(events > 0, "seed yields no RTPS events");
    }
}

#[test]
fn capture_reassembly_seeds_reassemble() {
    let mut reassembled = 0;
    for seed in smoke::corpus(DIR, "capture_reassembly") {
        let frames = capture_reassembly::frames(&seed);
        assert!(!frames.is_empty());
        let mut it = rtps_datagrams(VecSource::new(frames))
            .with_reassembly_limits(capture_reassembly::limits());
        let mut n = 0;
        while it.next_packet().is_some() {
            n += 1;
        }
        assert!(n > 0, "seed yields no datagram");
        reassembled += it.stats().reassembled;
    }
    assert!(reassembled >= 2, "fragment seeds do not reassemble");
}

#[test]
fn pcap_reader_smoke() {
    let seeds = smoke::corpus(DIR, "pcap_reader");
    smoke::run("pcap_reader", &seeds, 0x9ca9_0001, &pcap_reader::run);
}

#[test]
fn capture_reassembly_smoke() {
    let seeds = smoke::corpus(DIR, "capture_reassembly");
    smoke::run(
        "capture_reassembly",
        &seeds,
        0x9ca9_0002,
        &capture_reassembly::run,
    );
}
