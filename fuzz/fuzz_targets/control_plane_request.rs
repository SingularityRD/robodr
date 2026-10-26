//! libFuzzer target: the control-plane request path of `robodr-agentd`
//! (bounded HTTP parser, credentials, signature check, routing, strict
//! action / revert / evidence-export bodies).
//!
//! The harness (input format, invariants) is `fuzz/harness/control_plane_request.rs`,
//! shared via `#[path]` with the std-only smoke test
//! `crates/robodr-agentd/tests/fuzz_smoke.rs`, so the two cannot drift.
//!
//! Run: `cargo +nightly fuzz run control_plane_request` (seeds: `fuzz/corpus/control_plane_request/`).
#![no_main]

use libfuzzer_sys::fuzz_target;

#[path = "../harness/control_plane_request.rs"]
mod harness;

fuzz_target!(|data: &[u8]| {
    harness::run(data);
});
