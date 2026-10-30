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
| `kafka_wire` | robodr-export | a selector + body to the Kafka decoders: ApiVersions / Metadata v1-8 / Produce v3-8 responses (decode-encode-decode identity), RecordBatch v2 (CRC fixed up or not), request header + Metadata / Produce requests, wire primitives | `crates/robodr-export/tests/fuzz_smoke.rs` |
| `firewall_gw_packet` | robodr-firewall-gw | a flags byte + framed records (each wrapped in IPv4 / UDP) to `Gateway::process` (strict RTPS walk, SEDP learning, `LowCmd_` / sport `Request_` / Go1 decode, firewall decision, in-place rewrite), and the bytes to the NFQUEUE netlink parser | `crates/robodr-firewall-gw/tests/fuzz_smoke.rs` |
| `pkg_rpk` | robodr-pkg | `MANIFEST.json \0 MANIFEST.sig` to `parse_manifest` (canonical, every value rule), `rpk_digest`, `SignatureSet::parse`, `verify_manifest` against a fixed harness site (release quorum of the programme owning the package, policy), `verify_content` | `crates/robodr-pkg/tests/fuzz_smoke.rs` |
| `pkg_bundle` | robodr-pkg | `bundle.json \0 bundle.sig` to `parse_bundle` (path grammar, parity plan), `verify_bundle_manifest` (programme scope of signers and packages), and `check_chain` against genesis and several heads (gap / replay / equivocation / broken-link rules as invariants) | same |
| `pkg_deployment` | robodr-pkg | `deployment \0 sig` to `parse_deployment`, `verify_deployment` (depot + operator quorum; lab quorum only for units the trust file assigns to that ring), `check_seq` | same |
| `pkg_trust` | robodr-pkg | `trust \0 sig \0 next \0 next sig` to `parse_trust` (disjoint roles, expiry bounds, quorum caps, programme scopes and package ownership), `verify_trust_pinned` (pins, site, expiry) and `verify_trust_update` from the harness site (monotonic revocations, serials and floors; unexpired) | same |
| `pkg_parity` | robodr-pkg | `k`, `m`, an erasure mask and data files to `parity::layout`, `encode_group`, `rebuild_group` (`robodr-diode`'s RS code): erased members come back byte for byte | same |
| `deliverd_state` | robodr-deliverd | a selector byte + JSON to the agent's configuration (`Config::parse`: strict members, normalised and disjoint paths) and state file (`State::parse`): accepted documents re-serialise to an equal value, `raise_floor` never lowers a floor | `crates/robodr-deliverd/tests/fuzz_smoke.rs` |
| `seal_policy` | robodr-seal | a selector byte + a signed PCR policy (`policy::parse` / `verify`: canonical, version and PCR rules, approved policy a pure function of the members, verifies only for the harness authority) or a unit enrolment record (`UnitRecord::parse`: usable recipient, round trip) | `crates/robodr-seal/tests/fuzz_smoke.rs` |
| `seal_wrap` | robodr-seal | a selector byte + a key wrap (`wrap::parse` / `unwrap` with the harness X25519 and P-256 keys: context binding to unit, RPK and purpose; re-wrap round trip) or a sealed chunk (`chunk::open_chunk`: one ciphertext per plaintext and place, refused at any other place or RPK) | same |
| `deliverd_inputs` | robodr-deliverd | a selector byte + bytes to agentd's `status.json` as the safety-state gate reads it (`safety::judge`: installs allowed only for a fresh, this-boot, live-feed `idle` / `safe_state_active`), the passwd lookup of probe users, recorded safety reports and their replay schedule, and the structural check of delivered Pulsar rule files | same |

`kafka_wire` got its std-only smoke test after the fact (it was added while
`crates/robodr-export` was being changed by parallel work); it also checks
that every seed still takes its decoder's success path.

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

### libFuzzer runs (Sprint 13a, 2026-10-26)

The five `pkg_*` targets and, again, `diode_fec` (its Reed-Solomon code is
what bundle parity reuses): `nightly-2026-09-01`, `cargo-fuzz` 0.13.1,
AddressSanitizer + debug assertions, `-max_total_time=300
-rss_limit_mb=2048`, seeded from `fuzz/corpus/<target>/` (copied, so the
grown corpora stay out of the repository), three targets at a time on a
4-core sandbox that was also compiling (exec/s are shared-CPU figures).
The harnesses were those of commit `4d31dc9`; the later chain-state
change (`trust_version` / `trust_digest`) only adds two members to a
value the `pkg_bundle` harness builds itself. **No crash, leak, timeout
or invariant violation:**

| target | runs | exec/s | coverage (edges) | corpus at end |
|---|---:|---:|---:|---:|
| `pkg_bundle` | 2 895 655 | 9 620 | 5 361 | 2 623 |
| `pkg_deployment` | 2 804 612 | 9 317 | 5 082 | 2 665 |
| `pkg_rpk` | 2 052 839 | 6 820 | 6 393 | 3 444 |
| `pkg_parity` | 442 414 | 1 469 | 600 | 215 |
| `pkg_trust` | 337 370 | 1 120 | 3 770 | 1 529 |
| `diode_fec` | 57 550 | 191 | 963 | 596 |

`pkg_trust` is slow by design (every input that parses decodes up to
nine Ed25519 keys and checks signatures twice). Five minutes per target
is a first run, not an acceptance run: the 1 h nightly and 24 h
campaigns of the roadmap still apply.

### libFuzzer runs (13a review fixes, 2026-10-26)

After the fixes for the independent review of Sprint 13a changed the
trust file (site pin, `expires_at`, programme scopes, rings,
`revoked_serials`), the deployment quorum rule and the chain state, the
five `pkg_*` harnesses and seeds were updated (`seeds_are_current`
passes) and each target re-run: `nightly-2026-09-01`, `cargo-fuzz`
0.13.1, AddressSanitizer + debug assertions, `-max_total_time=150
-rss_limit_mb=2048`, seeded from `fuzz/corpus/<target>/` (copied), two
targets at a time on a 4-core sandbox. **No crash, leak, timeout or
invariant violation:**

| target | runs | exec/s | coverage (edges) | corpus at end |
|---|---:|---:|---:|---:|
| `pkg_bundle` | 1 582 320 | 10 478 | 5 695 | 2 233 |
| `pkg_deployment` | 2 203 276 | 14 591 | 5 417 | 2 460 |
| `pkg_rpk` | 1 162 425 | 7 698 | 6 619 | 2 910 |
| `pkg_parity` | 355 437 | 2 353 | 600 | 203 |
| `pkg_trust` | 176 570 | 1 169 | 4 371 | 1 198 |

### libFuzzer runs (Sprint 13b, 2026-10-26)

The two `deliverd_*` targets: `nightly-2026-09-01`, `cargo-fuzz` 0.13.1,
`-O` (release) with AddressSanitizer, **without** debug assertions (disk
space on the sandbox), `-max_total_time=150 -rss_limit_mb=2560`, one at
a time, seeded from `fuzz/corpus/<target>/` (copied). **No crash, leak,
timeout or invariant violation:**

| target | runs | corpus at end |
|---|---:|---:|
| `deliverd_state` | 3 126 173 | 3 146 |
| `deliverd_inputs` | 2 316 321 | 5 333 |

### Smoke runs

* all targets are compiled and run in `cargo test` by their crate's
  `tests/fuzz_smoke.rs` (so `clippy -D warnings` covers them);
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
* `pkg_*` (Sprint 13a): the default debug smoke run, 20 000 inputs each
  (`pkg_trust` about 1 000: each input costs about 10 ms in debug), no
  panic, no invariant violation.
* `deliverd_*` (Sprint 13b): the default debug smoke run found one
  harness bug at once (its passwd invariant assumed an `x` password
  field; fixed in the harness, the parser was right); see "libFuzzer runs
  (Sprint 13b)" for the coverage-guided runs.

* `seal_*` (Sprint 13c): the default debug smoke run and a 20 s run per
  target (`ROBODR_FUZZ_SECS=20`: `seal_policy` 11 585 inputs,
  `seal_wrap` 19 643), no panic, no invariant violation. **Not yet run
  under libFuzzer:** the coverage-guided build of the fuzz crate needs
  more disk than the shared sandbox had free (a release ASan build was
  started and aborted when the disk filled); the seeds are in
  `fuzz/corpus/seal_*/` for the first campaign.

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
* `pkg_rpk/`, `pkg_bundle/`, `pkg_deployment/`, `pkg_trust/`,
  `pkg_parity/`: built by each harness's `seeds()` and signed with the
  harness site's fixed Ed25519 keys (`fuzz/harness/pkg_common.rs`): a
  `files` RPK signed by the release quorum and a `deb` RPK with an SBOM
  signed once; a bundle with parity signed by the quorum and a chained
  bundle 2 signed once; a lab deployment with its quorum and a production
  one short of it; the harness trust file followed by a signed version-2
  update; parity file sets and a parity file name. Written by
  `regenerate_seeds` in `crates/robodr-pkg/tests/fuzz_smoke.rs`
  (`--ignored`); `seeds_are_current` fails when the committed seeds
  differ.
* `deliverd_state/`, `deliverd_inputs/`: a full configuration and a state
  with an installed, a kept and a staged version and a switch in progress;
  an agentd status claiming `idle` and one claiming `moving_slow`, a passwd
  file, a safety recording, a Pulsar rule file. Written by
  `regenerate_seeds` in `crates/robodr-deliverd/tests/fuzz_smoke.rs`.

Each smoke test also checks its seeds take the success path (pcaps reach the
RTPS parser, fragments reassemble, chains verify, findings validate, the
confirmed sign-off locks, ...), so a format change that silently turns the
corpus into garbage fails CI. libFuzzer adds new inputs to these
directories while it runs; commit only minimised (`cmin`) additions.
