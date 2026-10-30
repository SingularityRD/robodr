//! libFuzzer target: the Go1 v3.8.6 compressed `LowCmd` (614 bytes) in
//! `robodr-cdr` (decoder) and `robodr-firewall-gw` (gateway decoder and
//! in-place writer).
//!
//! The harness (invariants) is `fuzz/harness/go1_compressed_lowcmd.rs`,
//! shared via `#[path]` with the std-only smoke test
//! `crates/robodr-firewall-gw/tests/fuzz_smoke_go1_compressed.rs`.
//!
//! Run: `cargo +nightly fuzz run go1_compressed_lowcmd` (seeds:
//! `fuzz/corpus/go1_compressed_lowcmd/`).
#![no_main]

use libfuzzer_sys::fuzz_target;

#[path = "../harness/go1_compressed_lowcmd.rs"]
mod harness;

fuzz_target!(|data: &[u8]| {
    harness::run(data);
});
