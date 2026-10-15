# Coverage-guided fuzzing for `robodr-rtps` (cargo-fuzz / libFuzzer)

`fuzz_targets/parse_datagram.rs` feeds arbitrary bytes to
`robodr_rtps::parse_datagram` and fails on a panic **or** on any violated
output invariant (bounded event count, 24-char lower-case hex GUID prefixes,
UTF-8 topic/type names no longer than the datagram, no events from non-RTPS
input). The invariant checker is the same file the deterministic test
`crates/robodr-rtps/tests/mutation_fuzz.rs` uses (`tests/common/mod.rs`,
included via `#[path]`), so the two cannot drift.

This crate is **not** part of the main workspace: `Cargo.toml` has its own
`[workspace]` table, so `cargo build --workspace` / `cargo test --workspace`
at the repo root never touch it and never need nightly or `libfuzzer-sys`.

## Status: not run in the development sandbox

`libfuzzer-sys` (crates.io) and the nightly toolchain with `cargo-fuzz` were
unreachable where this was written, so **the target has never been run under
libFuzzer**. What was verified: the target compiles and passes
`clippy -D warnings` against a local stand-in for `libfuzzer-sys` that only
provides the `fuzz_target!` macro, and it runs every seed in the corpus
without an invariant violation. The deterministic mutation fuzz
(`cargo test -p robodr-rtps --release --test mutation_fuzz -- --include-ignored`,
620k iterations) runs in normal CI.

## Running it (on a machine with network access)

```sh
rustup toolchain install nightly
cargo install cargo-fuzz
# from the repository root:
cargo +nightly fuzz run parse_datagram fuzz/corpus/parse_datagram
# time-boxed, e.g. for CI:
cargo +nightly fuzz run parse_datagram fuzz/corpus/parse_datagram -- -max_total_time=600 -max_len=4096
# reproduce a crash:
cargo +nightly fuzz run parse_datagram fuzz/artifacts/parse_datagram/crash-<hash>
# shrink the corpus after a long run:
cargo +nightly fuzz cmin parse_datagram fuzz/corpus/parse_datagram
```

`cargo fuzz` finds this directory automatically from the repo root. A crash
input should be turned into a regular unit test in `crates/robodr-rtps` before
the fix lands.

## Seed corpus

`corpus/parse_datagram/seed-*.bin` are copies of the SYNTHETIC fixtures in
`crates/robodr-rtps/tests/fixtures/` (see the README there), kept
byte-identical by `tests/fixtures.rs::fixture_files_match_generator`.
libFuzzer adds new inputs to this directory while it runs; commit only
minimised (`cmin`) additions. Real Gazebo captures (Sprint 1, E2) should be
added here as seeds once they exist.
