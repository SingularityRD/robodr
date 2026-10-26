//! libFuzzer target: the in-path gateway's packet path
//! (`robodr-firewall-gw`) and its NFQUEUE netlink parser.
//!
//! The harness (input format, invariants) is
//! `fuzz/harness/firewall_gw_packet.rs`, shared via `#[path]` with the
//! std-only smoke test `crates/robodr-firewall-gw/tests/fuzz_smoke.rs`, so the
//! two cannot drift.
//!
//! Run: `cargo +nightly fuzz run firewall_gw_packet` (seeds:
//! `fuzz/corpus/firewall_gw_packet/`).
#![no_main]

use libfuzzer_sys::fuzz_target;

#[path = "../harness/firewall_gw_packet.rs"]
mod harness;

fuzz_target!(|data: &[u8]| {
    harness::run(data);
});
