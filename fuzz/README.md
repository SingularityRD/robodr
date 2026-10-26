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
| `control_plane_request` | robodr-agentd | raw bytes from a control-plane peer (read-step byte + request) to the bounded HTTP parser (`control::http::read_request`, re-encode round trip, read sizes do not matter), `auth::credentials` + signature check, `control::route`, `api::parse_submit` / `parse_revert`, `evidence::parse_export` / `parse_link` | `crates/robodr-agentd/tests/fuzz_smoke.rs` |
| `cdr_payload` | robodr-cdr | a limits selector + one payload to every `MessageKind` decoder (ROS 2 standard kinds and Unitree), `decode_by_type_name`, the built-in `Registry`, `decode_std` (`std_msgs`), `Encapsulation::parse`, event conversion | `crates/robodr-cdr/tests/fuzz_smoke.rs` |
| `diode_manifest` | robodr-diode | `MANIFEST.json \0 MANIFEST.sig` to the manifest / signature-file parsers, `check` / `check_import`, `batch_hash`, round trips | `crates/robodr-diode/tests/fuzz_smoke.rs` |
| `diode_import` | robodr-diode | a flattened batch directory (optionally signed by the harness key) through `Importer::run`: authentication, sequence and file checks, findings / bundles, parity repair, emission | same |
| `diode_fec` | robodr-diode | Reed-Solomon parameters, data and an erasure mask: encode, erase, rebuild, all against the `reed-solomon` 0.2.1 oracle (dev-only) | same |
| `correlate_rules` | robodr-correlate | `rules JSON \0 signal records` to `RuleSet::from_json` and a `Correlator` driven by the result (finding invariants) | `crates/robodr-correlate/tests/fuzz_smoke.rs` |
| `safety_feed` | robodr-agentd | `safety_feed JSON \0 records`: safety-socket lines, RTPS datagrams (through the sensor pipeline, then `SafetyFeed::observe_datagram`), clock steps; "never less conservative than a fresh socket report" | `crates/robodr-agentd/tests/fuzz_smoke.rs` |
| `kafka_wire` | robodr-export | a selector + body to the Kafka decoders: ApiVersions / Metadata v1-8 / Produce v3-8 responses (decode-encode-decode identity), RecordBatch v2 (CRC fixed up or not), request header + Metadata / Produce requests, wire primitives | none (see below) |

`kafka_wire` has no std-only smoke test: it was added while
`crates/robodr-export` was being changed by parallel work, so nothing was
added under that crate; it runs under libFuzzer only (and in CI's fuzz job).

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

## Status

### libFuzzer runs (S10, 2026-10-26)

First runs under libFuzzer: `nightly-2026-09-01` (CI's `FUZZ_TOOLCHAIN`),
`cargo-fuzz` 0.13.1, AddressSanitizer + debug assertions (cargo-fuzz
defaults), one process per target, `-max_total_time=630 -rss_limit_mb=2560`,
seeded from `fuzz/corpus/<target>/`, three or four targets in parallel on a
4-core sandbox (exec/s are shared-CPU figures). **No crash, leak, timeout or
invariant violation** in any run:

| target | runs | exec/s | coverage (edges) | corpus at end |
|---|---:|---:|---:|---:|
| `kafka_wire` | 9 281 801 | 14 709 | 1 486 | 689 |
| `parse_datagram` | 2 599 153 | 4 119 | 1 701 | 1 004 |
| `diode_manifest` | 2 425 143 | 3 843 | 2 683 | 2 206 |
| `pcap_reader` | 1 914 399 | 3 033 | 2 136 | 627 |
| `capture_reassembly` | 1 489 440 | 2 360 | 2 680 | 1 069 |
| `safety_feed` | 166 347 | 263 | 6 889 | 1 359 |
| `cdr_payload` | 145 678 | 230 | 3 586 | 381 |
| `diode_import` | 30 704 | 48 | 7 928 | 712 |
| `diode_fec` | 28 448 | 45 | 958 | 579 |
| `correlate_rules` | 7 870 + 19 329 | 12 / 30 | 4 312 | 582 |

`correlate_rules` ran twice: the second run (after capping the signal stream
at 512 records and dropping a redundant re-validation, which doubled the
rate) started from the first run's corpus. The slow targets do real work per
input (`diode_import` writes and imports a whole batch directory;
`diode_fec` decodes every codeword through the oracle as well), so they need
longer campaigns than ten minutes: the roadmap's 1 h per target in a nightly
job and the 24 h acceptance run still stand. The other existing targets
(`cdr_unitree`, `blackbox_segments`, `ocsf_parse_and_validate`,
`events_profile`, `commission_*`, `firewall_policy`, `pipeline_config`,
and `control_plane_request`, which came with control plane v2) have not
been run under libFuzzer yet (CI's `fuzz` job runs each for 60 s).
Grown corpora were not committed (README rule: only `cmin`-minimised
additions).

### Smoke runs

* all targets except `kafka_wire` are compiled and run in `cargo test` by
  their crate's `tests/fuzz_smoke.rs` (so `clippy -D warnings` covers them);
  `kafka_wire` compiles warning-free under `cargo fuzz build`;
* the smoke tests (same harness code) pass in debug in `cargo test`; two
  longer release runs of the first 12 targets (2026-10-16, PRNG seeds
  default and `0x5eed2`, up to 2 M inputs or 40-60 s per target, about 26 M
  inputs in total: `blackbox_segments` 1.0 M, `commission_jsonl` and
  `ocsf_parse_and_validate` 2.0 M each, the others 3 M each) found no panic
  and no invariant violation;
* `control_plane_request` (added 2026-10-26 with control plane v2): about
  90 000 inputs in a 240 s debug run of the smoke driver (PRNG seed `7`), no
  panic, no invariant violation. Writing its read-size invariant exposed
  that the HTTP head bound depended on how the peer's bytes were split into
  reads (fixed before the target landed).

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
* `ocsf_parse_and_validate/`: `docs/contracts/robodr-finding.example.json`
  (pretty and minified; contract 2.0), plus the superseded contract 1.1
  example as `seed-finding-legacy-1.1.*` (parse-only path).
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
* `control_plane_request/`: signed `robodr-control-plane/v2` requests of
  every route (fixed test SOC key, timestamp and nonces; action request,
  revert, evidence inventory / exports / chunk / delete), each prefixed with
  the harness's read-step byte. Written by the `regenerate_seeds` test in
  `crates/robodr-agentd/tests/fuzz_smoke.rs` (`--ignored`); the smoke test
  fails when the committed seeds differ from it.
* `cdr_payload/`: one payload of each standard ROS 2 kind (Twist,
  TwistStamped, Odometry, Imu, JointState, JointTrajectory) in CDR LE, CDR BE
  and D_CDR2 LE, plus `std_msgs` Bool / UInt8 / String; built from the crate's
  test encoder by `regenerate_payload_seeds` in
  `crates/robodr-cdr/tests/fuzz_smoke.rs`.
* `diode_import/`, `diode_manifest/`: real `Packer` output (findings only;
  findings + bundles with two parity files; the same with a data file missing
  and the signature left to the harness), by `regenerate_seeds` in
  `crates/robodr-diode/tests/fuzz_smoke.rs`; `diode_fec/`: two codes
  (k=4/m=2 and k=31/m=10).
* `correlate_rules/`: the shipped `rules/default.json` followed by signal
  streams that make it fire (`regenerate_seeds` in
  `crates/robodr-correlate/tests/fuzz_smoke.rs`).
* `safety_feed/`: hand-built SPDP / SEDP / Bool / UInt8 / String / Odometry
  samples and socket lines, with the built-in and a custom configuration
  (`regenerate_seeds` in `crates/robodr-agentd/tests/fuzz_smoke.rs`).
* `kafka_wire/`: responses and requests (one per decoder and version class)
  written by `fuzz/seedgen/kafka_wire.py` from the layouts the encoders in
  `robodr-export` use.

Each smoke test also checks its seeds take the success path (pcaps reach the
RTPS parser, fragments reassemble, chains verify, findings validate, the
confirmed sign-off locks, ...), so a format change that silently turns the
corpus into garbage fails CI. libFuzzer adds new inputs to these
directories while it runs; commit only minimised (`cmin`) additions.
