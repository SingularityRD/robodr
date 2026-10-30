//! libFuzzer target: the in-path gateway's ROS 2 joint-trajectory channels
//! (`robodr-firewall-gw`, `trajectory`): strict decode, probe, bound
//! check, time scaling, through `Gateway::process`.
//!
//! The harness (input format, invariants) is
//! `fuzz/harness/firewall_gw_trajectory.rs`, shared via `#[path]` with the
//! std-only smoke test
//! `crates/robodr-firewall-gw/tests/fuzz_smoke_trajectory.rs`.
//!
//! Run: `cargo +nightly fuzz run firewall_gw_trajectory` (seeds:
//! `fuzz/corpus/firewall_gw_trajectory/`).
#![no_main]

use libfuzzer_sys::fuzz_target;

#[path = "../harness/firewall_gw_trajectory.rs"]
mod harness;

fuzz_target!(|data: &[u8]| {
    harness::run(data);
});
