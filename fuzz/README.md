# Coverage-guided fuzzing for RoboDR (cargo-fuzz / libFuzzer)

Every parser that reads bytes an attacker (or a corrupted disk) can control
has a libFuzzer target here. Each target fails on a panic **or** on a
violated output invariant (documented at the top of its harness file).

| target | crate | what it feeds | smoke test |
|---|---|---|---|
| `parse_datagram` | robodr-rtps | one RTPS datagram to `parse_datagram` | `crates/robodr-rtps/tests/mutation_fuzz.rs` |
| `pcap_reader` | robodr-capture | a pcap/pcapng file to `CaptureFile` + `rtps_datagrams` + RTPS parser | `crates/robodr-capture/tests/fuzz_smoke.rs` |
| `cdr_unitree` | robodr-cdr | a selector byte + payload to the Unitree DDS decoders (`decode_unitree` / `decode_payload`), the `unitree_legacy` UDP decoders, and the bounded API-parameter JSON reader | `crates/robodr-cdr/tests/fuzz_smoke.rs` |
| `capture_reassembly` | robodr-capture | a framed train of link-layer frames to `decode_frame`, `Reassembler` (small limits) and the pipeline | same |
| `blackbox_segments` | robodr-blackbox | a flattened recorder directory to `scan_frames`, `Record::decode_body`, `verify_segments`, `verify_dir` (temp dir), `Bundle::from_bytes`, checkpoint/cursor/ack JSON | `crates/robodr-blackbox/tests/fuzz_smoke.rs` |
| `ocsf_parse_and_validate` | robodr-ocsf | a finding to `parse_and_validate`, re-encode, Kafka record | `crates/robodr-ocsf/tests/fuzz_smoke.rs` |
| `events_profile` | robodr-events | profile JSON to `Profile` + `validate` + `evaluate` (probe events derived from the profile) | `crates/robodr-events/tests/fuzz_smoke.rs` |
| `commission_profile_file` | robodr-commission | a profile file to `parse_profile_text`, seal and `lock` round trips | `crates/robodr-commission/tests/fuzz_smoke.rs` |
| `commission_signoff` | robodr-commission | sign-off JSON to `Signoff` + `ops::lock` against a fixed draft | same |
| `commission_jsonl` | robodr-commission | a JSONL recording to `JsonlSource`, `Learner`, strict re-read of the learned draft, `check_event` | same |
| `firewall_policy` | robodr-agent / robodr-firewall | `profile JSON \0 command bytes` to `strict_from_str`, `FirewallSettings::from_profile`, `Policy::compile`, `Firewall::check` | `crates/robodr-agent/tests/fuzz_smoke.rs` |
| `pipeline_config` | robodr-ros2-pipeline | sensor `Config` (JSON) to `validate_with`, a `Pipeline` over RTPS fixtures, `/proc/net/route` parsing | `crates/robodr-ros2-pipeline/tests/fuzz_smoke.rs` |

The firewall crate has no file format of its own (and no serde): its policy
is compiled from the profile JSON the agent parses, so that target and its
smoke test live with the agent. The sensor reads its config from TOML through
Pulsar; no TOML parser is available offline, so `pipeline_config` feeds JSON
to the same `serde::Deserialize` impl (struct shape, defaults and validation
are under test, not the TOML lexer).

## Layout: one harness, two drivers

`harness/<target>.rs` holds the whole harness (`pub fn run(data: &[u8])`,
input format, invariants). It is included via `#[path]` by

* `fuzz_targets/<target>.rs` (libFuzzer, coverage-guided), and
* `crates/<crate>/tests/fuzz_smoke.rs`, a std-only integration test that runs
  it in normal `cargo test` with the deterministic mutator in
  `harness/smoke.rs` (xorshift64*: bit flips, byte overwrites, truncation,
  extension, run insertion/deletion, splices between seeds, chunk
  duplication, u16/u32 length-field inflation in both byte orders, and
  JSON-aware edits: extreme numbers, structural tokens, swapped strings).

So the targets cannot drift from what CI exercises. The smoke driver runs the
committed seeds, then mutated inputs: 20 000 by default or 8 s of wall time,
whichever comes first (at least 1 000), and fails if any single input takes
more than 3 s (no hang / quadratic blow-up). On a panic it minimises the input
(greedy chunk removal) and prints it as a Rust byte-string literal ready for a
regression test. Knobs:

```sh
ROBODR_FUZZ_ITERS=1000000 ROBODR_FUZZ_SECS=120 ROBODR_FUZZ_SEED=7 \
  cargo test --release -p robodr-commission --test fuzz_smoke -- --nocapture
```

This crate is **not** part of the main workspace: `Cargo.toml` has its own
`[workspace]` table, so `cargo build --workspace` / `cargo test --workspace`
at the repo root never touch it and never need nightly or `libfuzzer-sys`.

## Status: libFuzzer not run in the development sandbox

`libfuzzer-sys` (crates.io) and the nightly toolchain with `cargo-fuzz` were
unreachable where this was written, so **no target has been run under
libFuzzer**. What was verified:

* all 11 targets compile and pass `clippy -D warnings` against a local
  stand-in for `libfuzzer-sys` that only provides the `fuzz_target!` macro
  (as a `main` that replays files), and replay their whole seed corpus
  without a panic or invariant violation;
* the smoke tests (same harness code) pass in debug in `cargo test`; two
  longer release runs (2026-10-16, PRNG seeds default and `0x5eed2`, up to
  2 M inputs or 40-60 s per target, about 26 M inputs in total:
  `blackbox_segments` 1.0 M, `commission_jsonl` and `ocsf_parse_and_validate`
  2.0 M each, the others 3 M each) found no panic and no invariant
  violation.

The deterministic mutator is not coverage-guided: it finds shallow bugs
cheaply but is no substitute for libFuzzer runs (CI's `fuzz` job runs every
target for 60 s; longer campaigns should run on a machine with network).

## Running it (on a machine with network access)

```sh
rustup toolchain install nightly
cargo install cargo-fuzz
# from the repository root:
cargo +nightly fuzz list
cargo +nightly fuzz run pcap_reader                  # uses fuzz/corpus/pcap_reader
cargo +nightly fuzz run firewall_policy -- -max_total_time=600
# reproduce a crash:
cargo +nightly fuzz run blackbox_segments fuzz/artifacts/blackbox_segments/crash-<hash>
# shrink a corpus after a long run:
cargo +nightly fuzz cmin events_profile
```

A crash input should be turned into a regular unit test in the owning crate
before the fix lands (the smoke driver's minimised literal is a good start).
`blackbox_segments` writes into a per-thread directory under `$TMPDIR`
(`robodr-fuzz-bb-<pid>-<thread>`); with libFuzzer's `-fork`/`-jobs` each
process gets its own.

## Seed corpora

All seeds are SYNTHETIC (no real robot data):

* `parse_datagram/seed-*.bin`: copies of `crates/robodr-rtps/tests/fixtures/`,
  kept byte-identical by `tests/fixtures.rs::fixture_files_match_generator`.
* `pcap_reader/`: an Ethernet pcap (SPDP + SEDP), a nanosecond Linux-SLL
  pcap of a fragmented SEDP datagram, a two-interface pcapng (EPB + SPB),
  built with `robodr_capture::synth` + `PcapWriter` from the RTPS fixtures.
* `cdr_unitree/`: a selector byte plus one synthetic payload each — a go
  `WirelessController_`, an `unitree_api` `Request_` (sport `Move`), a bare
  `SetVelocity` parameter JSON, and a legacy `HighCmd` UDP frame. Built from
  the crate's test encoder by the `regenerate_seeds` test in
  `crates/robodr-cdr/tests/fuzz_smoke.rs` (run with `--ignored` to refresh).
* `capture_reassembly/`: the harness's framed format (see its doc) with IPv4
  fragments, reversed IPv6 fragments, a QinQ frame and an SLL2 mix with a
  reassembly timeout.
* `blackbox_segments/`: real `Recorder` output (HMAC key = the harness key,
  so records verify): one segment, a rotated two-segment chain with its
  `checkpoint.json`, an export bundle, a single frame body, a checkpoint.
  The rotated chain was recorded before the recorder reserved room for its
  closing seals, so its first segment is 4291 bytes with
  `max_segment_bytes = 4096` (one seal frame over; see
  `crates/robodr-blackbox/README.md`, "Segment size"). It still verifies and
  is kept as a seed for exactly that shape.
* `ocsf_parse_and_validate/`: `docs/contracts/robot-edr-finding.example.json`
  (pretty and minified).
* `events_profile/`: `config/profile.example.json`,
  `crates/robodr-agent/examples/ugv-demo.profile.json`.
* `commission_profile_file/`, `commission_signoff/`: a draft, its sealed
  locked form, and its sign-off confirmed / unconfirmed (from the
  commissioning API).
* `commission_jsonl/`: the first 20 lines of the JSONL examples in
  `crates/robodr-commission/examples` and `crates/robodr-agent/examples`.
* `firewall_policy/`: the demo profile (locked and observe) and a joint-arm
  profile, each followed by a command stream with NaN / inf / foreign
  sources / clock steps / a fault verdict.
* `pipeline_config/`: `config/robodr.toml.example` as JSON, a capture-enabled
  and a replay config, a `/proc/net/route` table.

Each smoke test also checks its seeds take the success path (pcaps reach the
RTPS parser, fragments reassemble, chains verify, findings validate, the
confirmed sign-off locks, ...), so a format change that silently turns the
corpus into garbage fails CI. libFuzzer adds new inputs to these
directories while it runs; commit only minimised (`cmin`) additions.
