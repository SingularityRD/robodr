//! libFuzzer target for `robodr_rtps::parse_datagram`.
//!
//! The parser reads untrusted bytes straight off the robot's RTPS discovery
//! bus, so any input must yield events, never a panic, an over-read or an
//! unbounded allocation. On top of "no panic", this target enforces the same
//! output invariants as the deterministic `tests/mutation_fuzz.rs` (the
//! checker is shared via `#[path]`, so the two cannot drift): bounded event
//! count, 24-char lower-case hex GUID prefixes, UTF-8 topic/type names no
//! longer than the datagram, no events from non-RTPS input.
//!
//! Run: `cargo +nightly fuzz run parse_datagram fuzz/corpus/parse_datagram`
#![no_main]

use libfuzzer_sys::fuzz_target;

#[path = "../../crates/robodr-rtps/tests/common/mod.rs"]
mod common;

const SRC_IP: &str = "198.51.100.7";

fuzz_target!(|data: &[u8]| {
    let events = robodr_rtps::parse_datagram(data, SRC_IP);
    if let Err(why) = common::check_invariants(data, SRC_IP, &events) {
        panic!("invariant violated: {why}");
    }
});
