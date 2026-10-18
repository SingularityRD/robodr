# Changelog

All notable changes to RoboDR are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html)
(pre-1.0: any minor or pre-release may change interfaces).
A release is cut by tagging `v<VERSION>`. `.github/workflows/release.yml`
requires a `## [<VERSION>]` section here and uses it as the release notes.

## [Unreleased]

### Added

- Remote head anchor for the black box
  (`robodr_blackbox::remote_anchor`): `RemoteHeadAnchor` on the unit sends
  every head mark, signed with the black-box key over (unit, chain id, seq,
  hash, key id), to the new std-only `robodr-anchor-receiver` daemon on a
  base station, which verifies it under the unit's public key, keeps the
  highest mark per unit durably (atomic replace + fsync before it answers)
  and refuses and alerts lower marks, forks and bad signatures
  (`alerts.jsonl`, log line, per-unit counter). At open the unit queries the
  held mark with a fresh nonce; the answer is signed by the receiver's
  Ed25519 key and the mark inside verified under the unit's own key, so a
  man-in-the-middle can neither feed a lower mark nor replay an old answer
  (dropping it is an anchor failure). Marks are delivered by a background
  thread with a coalescing one-slot queue, so `append` never waits for the
  network. `robodr-agentd` `blackbox.head_anchor` kind `remote`
  (`address`, `receiver_public_key`, `timeout_ms`; Ed25519 black-box key
  required). Detect-only mode for diode-only sites:
  `robodr-blackbox anchor-mark` + `robodr-anchor-receiver ingest`. Packaging:
  `robodr-anchor-receiver.service` (base station, disabled) and
  `robodr-anchor-receiver(8)`. Tested with a real receiver process over
  loopback, not across a real network.
- `robodr-kafka-publish` / the std-only Kafka producer run against real
  Apache Kafka brokers for the first time: `scripts/kafka-it.sh` starts a
  single-node KRaft broker in docker (`apache/kafka:3.9.1` by default,
  `KAFKA_IT_IMAGE=apache/kafka:4.1.0` also verified) and runs the new
  `#[ignore]`d `tests/kafka_real_broker.rs` (gated on
  `ROBODR_KAFKA_BROKER`). Verified against both versions: signed findings
  from a spool and through the diode path delivered exactly once with key,
  value bytes, headers (signature last, verifying) and contract §4
  partition intact; CRCs re-checked by `kafka-dump-log`; spool `acked/` and
  `progress.json` correct; crash between acknowledgement and commit re-sends
  exactly one chunk; a broker restart mid-stream loses nothing; unknown
  topic, ACL denial, oversized record, quota throttling, idle-connection
  close and SASL / TLS listeners handled; partitioner identical to the Java
  client's for 205 robot ids. Single-node only (see the crate README).
- TPM 2.0 NV counter head anchor for the black box
  (`robodr_blackbox::tpm_anchor::TpmNvCounterAnchor`): the counter counts
  head marks (one increment per mark, at most one per
  `min_increment_interval`, default 60 s), a sidecar signed with the
  recorder's key binds the count to the mark; an older restored sidecar
  yields a lower bound of the head, so a cut log tail with rolled-back
  state is reported as `TruncationDetected`. Driven through `tpm2-tools`
  with a configurable TCTI, bounded tool runs and strict parsing; indexes
  that are not counters are refused. New `robodr-blackbox tpm-anchor-init`
  / `tpm-anchor-check`; `robodr-agentd` `blackbox.head_anchor` kind
  `tpm_nv_counter`. Tested with a fake TPM and against swtpm
  (`scripts/swtpm-anchor-it.sh`, `ROBODR_SWTPM=1`); not yet on a hardware
  TPM.
- Real ROS 2 Jazzy captures (Fast DDS 2.14, Cyclone DDS 0.10) under
  `fixtures/captures/ros2-jazzy/` with the container lab that produced them
  (`tools/lab-capture/`) and end-to-end tests
  (`robodr-ros2-pipeline/tests/real_captures.rs`).
- Participant identities (`Profile::participant_identities`: source IPs,
  RTPS vendor, enclave, nodes, `max_instances`): DDS draws a new GUID prefix
  per process start, so a GUID-only profile matched none of the robot's
  participants after a restart. The pipeline resolves fresh prefixes at SPDP
  time (`robodr-ros2-pipeline::identity`, new rule
  `robot.ros2.identity_instances_exceeded`); `robodr-commission learn`
  writes identities (`--no-identities` to opt out), each one a sign-off item
  and a lock floor requirement; `check` resolves them; Motion Firewall
  `allowed_sources` and agentd `safety_feed` writers accept
  `identity:<name>`.
- `robodr-commission learn --pcap` decodes `Twist` / `TwistStamped` /
  `JointTrajectory` samples of announced writers (same decoder as the
  sensor), so a capture alone yields motion envelopes.
- `robodr-sensor-ros2`: first unit test (threat `extra` through the real
  `pulsar_core::event::Value`).
- Host-side (Pulsar) threats reach `robodr-agentd`, so the host-dependent
  correlation rules (`coordinated_intrusion`, `credential_theft`,
  `trojaned_package_key_access`, `defense_tampering`,
  `host_process_persistence`) can fire in the daemon:
  - New Pulsar module `robodr-threat-forward` (registered by
    `robodr-pulsard`, off by default, `[module.robodr-threat-forward]
    socket_path`): forwards every Pulsar threat except
    `robodr-sensor-ros2`'s own as one JSON line (rule name, source module,
    severity / category from the rule metadata, time, pid / ppid / uid /
    gid, bounded sanitised image) to a unix socket; bounded queue with
    counted drops, never blocks the bus, reconnects with backoff, heartbeat
    with its counters.
  - `robodr-agentd` `host_threats` section: binds the socket (`0600` or
    `0660`; refuses a group/world-writable or foreign-owned directory and a
    path that is not its own socket), accepts only peers with uid 0 or
    `allowed_uids` (`SO_PEERCRED`), parses lines strictly (4 KiB, no unknown
    or duplicate keys, bounded strings, no control characters; refused lines
    are `robot.agent.input_malformed`). Each threat is a
    `robot.host.pulsar_threat` finding and a `Signal::host(<rule name>)`
    with the pid as its process entity. Heartbeats are the input's
    liveness (a configured but silent host input reads `unknown`); the
    forwarder's losses are reported as queue drops. `status.json` shows
    connections, `upstream_dropped` and the host-threat counters.
  - OCSF catalog (contract 1.3, unreleased): `robot.host.pulsar_threat` with
    the new data source `host_runtime` (schema enums updated).
  - Packaging: `config/robodr.toml.example` (hence `/etc/robodr/pulsar.toml`)
    gains the disabled `[module.robodr-threat-forward]` section,
    `config/agentd.full.example.json` the `host_threats` key, and the
    drop-in example `robodr-pulsard.service.d/30-host-threats.conf.example`
    (`SupplementaryGroups=robodr`, since pulsard has no
    `CAP_DAC_OVERRIDE`).
- Wave 6 (integrated on `integrate-w6`):
  - `robodr-agentd` live safety-state feed (`safety_feed`): ROS 2 topics
    decoded passively from captured user DATA (`std_msgs` Bool / UInt8 /
    String, Odometry speed with hysteresis) and/or a `0600` unix socket of
    JSON lines from a safety-PLC gateway; stale -> unknown, conflicts -> most
    conservative; untrusted writers ignored and reported
    (`robot.safety_state.untrusted_source`). `robodr-cdr` gained bounded
    `std_msgs` decoders. Read-only; synthetic traffic only.
  - `robodr-correlate`: weak-signal correlation engine (JSON rules: sequence,
    co-occurrence, threshold, distinct sources; bounded memory, LRU eviction
    that cannot evict multi-signal state). Wired into `robodr-agentd`
    (`correlation`, on by default; optional site rule file validated with
    the shipped rules): every reported finding is a signal, correlated
    `robot.correlate.*` findings are recorded with all contributors
    (`robodr.correlated_finding` note) and stay observe-only if any input
    was; eviction pressure raises `robot.agent.correlation_pressure`.
  - Per-finding Ed25519 signatures (contract 1.2, header
    `robodr-finding-sig`); `robodr-agentd` signs with a dedicated key
    (`finding_signing.key_file`; HMAC, the black-box key and keys inside the
    spool / black box are refused; systemd drop-in example
    `20-finding-key.conf.example`). `robodr-kafka-publish --spool` forwards
    the header verbatim. Not carried across the diode (contract §8).
  - OCSF contract 1.3.0: catalog entries for `robot.correlate.*`,
    `robot.safety_state.*`, `robot.ros2.profile_state_tampered`,
    `robot.agent.evidence_quarantined`, `robot.agent.correlation_pressure`
    (data sources `robodr_correlation`, `robot_safety_state`,
    `robodr_agent`; technique T0856). The validator applies the catalog of
    each message's own minor, so 1.2 messages stay valid.
  - `robodr-export`: `robodr-spool-export` (agentd spool -> signed diode
    batches, crash-safe intent journal) and `robodr-kafka-publish` (importer
    output or a connected spool -> Kafka; std-only client, `acks=all`,
    idempotence off, no TLS/SASL; verified against Apache Kafka 3.9.1 and
    4.1.0, see the first entry). Both
    shipped in the `.deb` and required by the release workflow; man pages
    `robodr-spool-export(1)`, `robodr-kafka-publish(1)`.
  - Black box: damaged closed segments are quarantined instead of bricking
    the recorder, `head.json` high-water mark, crash-safe rotation.
    `robodr-agentd` marks the head on every tick when records were added and
    reports quarantined segments (`robot.agent.evidence_quarantined`, High,
    observe-only).
  - Profile trust: trust roots, root-signed `min_profile_version` floor,
    signed revocation lists, black box as second anti-rollback witness
    (`robot.ros2.profile_state_tampered`). `robodr-ros2-watch` gained
    `--trust-roots`, `--revocations`, `--revocations-required`.
  - Commissioning: operator-signed sign-off (`signoff --sign-key`,
    `operators`, two-person rule for motion items), discovery-server relay
    attribution, output manifest checked by `lock` / `check`.
  - Diode: single-instance lock, Reed-Solomon parity (`--parity`), `resend`.
  - Capture: per-packet ingress (interface, loopback, packet type) for
    strict loopback trust.
  - Events / CDR: holonomic per-axis motion fields and envelope limits
    (`robot.motion.angular_over_envelope`).
  - Motion monitor: hold-protected cross-sensor disagreement, opposite-
    direction escalation, full-GUID publisher keys, frozen-at-cruise fix.
  - Rules: self-protection of the installed layout and service names,
    installer coverage (uv, pipx, poetry, conda, npm, ...), CMake 3.28
    FindPython probes excluded by exact argv. `validate_rules.py` accepts an
    `argv CONTAINS` literal with spaces without a warning when the same AND
    chain pins `payload.argc == N`.

- Wave 7 (review fixes, integrated on `integrate-w6`):
  - Profile trust: with `trust_roots` configured the trust file must be
    root-signed, and a locked profile must carry a verified
    `metadata.attestation` (the exact signed sign-off and its operator
    signatures, checked against the trust file's operators and
    `motion_quorum`); a root-signed `require_attestation: false` opts out.
    The highest accepted `min_profile_version` is remembered (state file and
    black box), so an older trust file never lowers the floor.
  - Revocation lists v2 (`robodr-profile-revocations/v2`): signing keys are
    revoked by public-key fingerprint (SHA-256 of the key bytes), bound to
    one platform; `revoke --platform --revoke-key KEY.pub /
    --key-fingerprint`; `keygen` / `verify-profile` print fingerprints.
  - Safety feed: `safety_feed.topics[].writers` is required; a sample is
    used only if the binding vouches for its source (`allows_from ==
    Some(true)`); a full writer table raises
    `robot.safety_state.writer_overflow` (High) and reads at least unknown;
    socket writers are tracked per connection.
  - Binding: a profiled GUID prefix claimed by SPDP from a second host is
    **contested** (Critical `robot.ros2.participant_source_mismatch`): no
    source is trusted for it until `participant_ips` pins it.
  - Motion decode applies the same rule: a decoded sample whose writer's
    participant has no binding (or whose source IP does not parse) is
    `robot.motion.unattributed_sample` (High), a contested prefix is
    `robot.motion.sample_source_mismatch`; `MotionSample::attribution`
    carries the verdict and `robodr-agentd` drops the writer GUID of a
    refused command, so the firewall model sees an unknown source.
  - Correlation: protection tiers and reserved slots for multi-signal
    groups; evicting evidence raises the observe-only
    `robot.correlate.correlation_state_evicted`.
  - Black box: stray / cut segment files are Critical quarantines, an
    authentic cut after the newest mark is Critical
    `robot.agent.evidence_truncated`; `blackbox.head_anchor` (kind `file`,
    `FileHeadAnchor`; only as strong as its storage, a TPM or remote anchor
    is still required for deployment) and anchor status in `status.json`.
  - Export recovery: after a split pack, only records whose exact line is
    found in a committed batch (outbox or archive, checked against
    `MANIFEST.json`) are acknowledged; `Exporter::open` refuses planner
    limits that differ from the packer's (`Packer::config`, new);
    `open_checked` also checks the unit; publisher progress is per batch.
  - Commissioning: a trusted discovery server must be pinned by IP
    (`PREFIX@IP` or `IP`). The sensor pipeline's `discovery_server` was
    already IP-only (a GUID prefix is refused; regression tests added).
  - OCSF 1.3.0 catalog (still unreleased): entries for the three wave-7 ids
    and for every other `robot.*` id an in-repo detector emits (agent
    health, sensor pipeline, motion decode and monitor, firewall), which
    used to fall back to the generic entry; a test fails on an emitted id
    without one. `robodr-correlate` knows `robot.agent.evidence_truncated`
    and its drift test now checks both directions.
  - `config/agentd.example.json` passes `--check-config` as copied on a
    commissioned robot; `config/agentd.full.example.json` adds
    `trust_roots`, `revocation_list` and `finding_signing` (needs the
    `20-finding-key.conf.example` drop-in).

- Live motion path: RTPS user DATA on the profile's motion channels and on
  `motion.feedback_topics` is decoded (`robodr-cdr`) into `MotionCommand` /
  `MotionFeedback` (`robodr_ros2_pipeline::motion`,
  `Pipeline::process_datagram_with_motion`) and fed by `robodr-agentd` to
  the agent (envelope, Motion Firewall recording-only, motion monitor).
  Config sub-table `motion` / agentd `sensor.motion`. Verified on synthetic
  RTPS / CDR only.
- Ed25519 is the default key type: `robodr-blackbox-key/v2` secret (0600)
  and public `.pub` (0644) key files, `robodr-blackbox keygen --alg
  ed25519|hmac` (default ed25519) and `export-pub`. The diode packer signs
  with Ed25519; the SOC importer holds public keys only (HMAC only with
  `--allow-hmac`). `robodr-agentd` and `robodr-replay` load Ed25519 keys;
  `robodr-replay verify` accepts the `.pub`.
- `robodr-commission trust-keys --out trust.json --pub KEY.pub...` builds a
  profile trust file from Ed25519 public key files; `keygen` also writes
  `<out>.pub`.

- Signed, versioned model profiles. `robodr-commission lock` stamps
  `metadata` (schema / monotonic profile version, platform, unit,
  locked_by, locked_at, parent digest; `--parent` for lineage) and with
  `--sign-key` writes `<profile>.sig` (Ed25519 over the exact sealed bytes).
  New subcommands `keygen`, `sign`, `verify-profile`, `migrate-legacy`.
  The sensor pipeline (`profile_trust` settings, `load_profile_with_trust`),
  `robodr-agentd` (`sensor.profile_trust`), `robodr-replay`
  (`--trusted-keys`, `--profile-state`, `--allow-profile-rollback`) and
  `robodr-ros2-watch` enforce a locked profile only with a valid signature
  from a trusted key, and refuse a rollback to a lower `profile_version`
  (state file) unless the operator names the file's digest.

- Packaging and operations: systemd units for `robodr-pulsard` (root confined
  to a bounded eBPF capability set, read-only OS) and `robodr-agentd`
  (dedicated `robodr` user, `CAP_NET_RAW` only, no IP traffic, key via
  `LoadCredential=`); `tmpfiles.d` and `sysusers.d` fragments; a reproducible
  `.deb` builder; an offline install bundle with verify/install/rollback
  (`packaging/`).
- Man pages for `robodr-commission(1)`, `robodr-replay(1)`,
  `robodr-ros2-watch(1)`, `robodr-pulsard(8)`, `robodr-agentd(8)`,
  `robodr-blackbox(1)`, `robodr-diode-pack(1)` and `robodr-diode-unpack(1)`
  (`man/`).
- `config/agentd.example.json`, matching the `robodr-agentd` unit's paths.
- `robodr-agentd` accepts a `robodr-blackbox keygen` key file
  (`robodr-blackbox-key/v1`; key id taken from it) besides bare hex.
- Tag-triggered release workflow: `--locked` build, reproducibility check
  of the released binaries, CycloneDX SBOM, SHA-256 checksums, minisign
  signatures, offline bundle per architecture (amd64, arm64).
- `SECURITY.md`, this changelog, and `docs/OPERATIONS.md` (air-gapped
  install, key generation and rotation, commissioning, upgrade and rollback,
  evidence export).

### Changed

- **Security (`robodr-blackbox`)**: Ed25519 now uses the audited
  `ed25519-dalek` 2.x crate (`curve25519-dalek` 4, `zeroize`; SHA-512 from
  RustCrypto `sha2` 0.10) instead of the hand-written, unaudited field /
  curve / scalar / SHA-512 code, which is deleted. `sign_ed25519` keeps its
  public API as thin wrappers, so key files (`robodr-blackbox-key/v2` and
  `.pub`), derived key ids (`ed25519:<16 hex>`), the 64-byte `R || S`
  signature layout and the strict verification rules (`verify_strict`:
  canonical `S`, no small-order `A` / `R`, cofactorless; plus a
  canonical-encoding check on public keys) are unchanged, and the RFC 8032,
  OpenSSL cross-check and rev4 regression vectors still pass. Seeds still
  come from `getrandom(2)` (no `rand_core`). Verification is about 50x
  faster (about 25 µs instead of about 1.3 ms in release on x86-64).
  `sign_ed25519::Sha512::new` is no longer a `const fn`. New dependencies
  (BSD-3-Clause / MIT OR Apache-2.0) are allowed by `deny.toml`; all build
  on the 1.87 MSRV.

- **Breaking (`robodr-commission lock`)**: `--operators operators.json` is
  required; every sign-off must carry valid operator signatures
  (`<signoff>.sig`), and motion items need `motion_quorum` distinct
  operators. `lock` also refuses a draft without a matching output manifest
  (`--no-manifest` for older drafts). See OPERATIONS.md section 5.
- **Breaking (findings contract 1.3.0)**: findings for the newly catalogued
  rule ids (wave 6, and since wave 7 every emitted `robot.*` id) carry their
  own title / description / data source instead of the generic entry;
  consumers must run the 1.3 validator (it still accepts 1.2 messages).
- **Breaking (wave 7)**: revocation lists v1 (by key id) are refused;
  profiles loaded with `trust_roots` need an attestation; `safety_feed`
  topics without `writers` are refused; `Exporter::open` refuses
  mismatched planner limits.
- One key file format: profile signing keys are robodr-blackbox `KeyFile`s
  (`robodr-commission keygen` now writes v2 secret + `.pub`; a key from
  `robodr-blackbox keygen` signs profiles too; older v1 Ed25519 signing
  keys still load). A `.pub` given as `--sign-key` is refused.
- `robodr-sensor-ros2` loads the profile with
  `load_profile_with_trust(profile_path, profile_trust)` and logs the
  `profile_trust` warnings, so a signed profile is enforced under Pulsar
  (before, it ran observe-only). Decoded motion samples are not forwarded to
  the Pulsar bus (documented); their envelope findings are.
- Packaging: `tmpfiles.d` creates `/var/lib/robodr/profile-state`
  (`robodr:robodr`, agentd) and `/var/lib/robodr/profile-state-pulsard`
  (`root:robodr`); each unit lists its directory in `ReadWritePaths=`. The
  example sensor `state_file` moved to
  `/var/lib/robodr/profile-state-pulsard/pulsard.json`.

- **Breaking:** a locked profile without metadata and a valid signature is
  no longer enforced (observe-only + `robot.ros2.profile_refused`);
  migrate with `robodr-commission migrate-legacy` (OPERATIONS.md 5.2).
  `robodr-commission lock` requires `--platform` and `--profile-version`
  (or `--parent`). `robodr-replay --profile-version` and agentd's
  `robot.profile_version` were removed (the version comes from the signed
  metadata). The plain `robodr_ros2_pipeline::load_profile` trusts no key.

- **Breaking (`robodr-replay`)**: `--key-hex` and `--key-id` are removed (a
  key on argv is readable through `/proc`). `--key-file` now takes a
  `robodr-blackbox-key/v1` file (`robodr-blackbox keygen`), permission-checked
  by `KeyFile::load`; the key id comes from the file.
- `robodr-replay run` exits 3 (not 0, never "VERIFIED") when findings were
  lost (failed OCSF validation); `ReplaySummary::verified()` is false then,
  `evidence_verified()` / `findings_lost()` tell the cases apart.
- Every RoboDR binary reports a non-UTF-8 argument as a usage error (exit 2)
  instead of panicking.
- `robodr-ros2-pipeline`: conflicting inline QoS between the fragments of
  one discovery sample (`FragmentEventKind::ConflictingInlineQos`) is a High
  `robot.ros2.ambiguous_discovery`, read from the fragment events as well as
  the (bounded) anomaly list.
- `robodr-sensor-ros2` passes captured datagrams to the pipeline with their
  ingress (`Pipeline::process_datagram`), so loopback spoofing on an external
  interface is judged as such.
- `robodr-blackbox`: rotation keeps room for the two seals that may follow
  the last record, so segments no longer end one seal frame past
  `max_segment_bytes` (remaining exceptions documented in its README).
- `robodr-agentd.service`: `ProcSubset=pid` removed (the daemon reads
  `/proc/sys/kernel/random/boot_id` and `/proc/net/*`), no restart on exit 2,
  `RuntimeDirectory=robodr-agentd` for a unix-socket event input.

### Fixed

- `robodr-export` Kafka producer (found against a real broker): a batch
  refused with `MESSAGE_TOO_LARGE` only because of its total size (topic
  `max.message.bytes` below `max_request_bytes`) degraded the partition to
  one record per request for the rest of the call; it is now halved until it
  fits. A TLS listener's alert was reported as an absurd frame size and a
  SASL listener's close as a bare disconnect; both errors now name the
  cause. Connections closed by the broker's `connections.max.idle.ms` cost
  an I/O error, a metadata refresh and a backoff on the first send after
  each quiet period; connections idle for `connections_max_idle` (9 min) are
  now closed before use.
- Cyclone DDS's 1-byte shutdown wake-up datagram is no longer counted as
  malformed RTPS by `learn --pcap`.

- CI: first local run of every `ci.yml` job and of the `release.yml`
  build/package steps (2026-10-17, Debian 13 / WSL2; record in
  `docs/BUILD.md`, "Local CI verification"). Fixed what failed: shellcheck
  findings in `packaging/install-bundle.sh` and `packaging/make-bundle.sh`;
  `cargo deny` licenses (license clarifications for the remaining Pulsar
  crates, a scoped CC0-1.0 exception for the compile-time-only
  `tiny-keccak`), bans (every RoboDR crate is now `publish = false`; Pulsar's
  path crates are skipped for the wildcard lint) and advisories
  (RUSTSEC-2021-0139, unmaintained `ansi_term` via Pulsar, ignored with a
  documented reason and review date). No source code or `Cargo.lock` change.
- `robodr-agentd` e2e test `hostile_datagrams_and_event_lines_never_stop_the_daemon`
  could stop the daemon before housekeeping raised `robot.agent.input_malformed`;
  it now waits until both expected findings are in the spool.
- `robodr-kafka-publish` dead-lettered every signed finding ("headers
  disagree with the value"); the signature header is now carried.
- `robodr-agentd` test `queue_overflow_is_counted_and_reported` was flaky:
  it stopped the daemon before the socket reader had read every line. It
  now waits for `received == 5000` in the status file first.

## [0.1.0-alpha.1] - 2026-10-16

First integrated pre-release of the workspace. Nothing in it has run on a robot
or a live kernel yet. The verification status of each crate is in its README
and in `docs/PULSAR-INTEGRATION.md`.

### Added

- **Pulsar integration**: `robodr-sensor-ros2` aligned with the real Pulsar
  module API, and the `robodr-pulsard` daemon (Pulsar with the RoboDR modules
  registered).
- **RTPS / DDS parsing** (`robodr-rtps`): SPDP and SEDP, INFO_SRC
  attribution, disposal, DATA_FRAG, vendor ids. Split into a pure crate with
  mutation fuzzing, synthetic fixtures, a golden corpus and a cargo-fuzz
  harness.
- **Passive capture** (`robodr-capture`): pcap/pcapng decoders, read-only
  AF_PACKET with a classic BPF filter.
- **ROS 2 pipeline** (`robodr-ros2-pipeline`): a pure sensor pipeline, a
  capture source and the `robodr-ros2-watch` tool.
- **Commissioning** (`robodr-commission`): observe-mode learner,
  `learn`/`lock`/`diff`/`merge`/`check`/`signoff`. Learns services, actions,
  raw DDS topics and reader sets, takes pcap input, and validates on lock.
- **Motion**: a consistency detector for motion commands against feedback
  (`robodr-motion`) and the Motion Firewall core (pass / limit / reject,
  alloc-free hot path; `robodr-firewall`).
- **Response**: Cyber-Jidoka graded response planner (`robodr-responder`).
- **Evidence**: signed, hash-chained black-box recorder with
  store-and-forward export bundles (`robodr-blackbox`). The authenticator is
  HMAC-SHA256, a documented placeholder.
- **Findings**: OCSF Detection Finding envelope for `robot-edr.findings`
  (`robodr-ocsf`).
- **Agent**: first end-to-end decision chain, run offline, plus `robodr-replay`
  (`robodr-agent`).
- **Rules**: robot host rules rewritten for Pulsar's real rules engine, with
  an offline grammar-checked validator.
- **CI**: defence-posture CI with a `Cargo.lock` policy and `--locked`
  builds, cargo-deny, CycloneDX SBOM, reproducible-build check, air-gapped
  mirror support and fuzz smoke tests.
- Docs: roadmap and sprint plan, re-sequenced defence-first.

### Changed

- `robodr-events`: `Severity` is ordered and hashable. Motion checks fail
  closed, ROS 2 names are de-mangled, and observe mode is added. Wave 1
  adapted all crates to the events API (`Cow` rule, `MotionFeedback`).

### Security

Fixes from the wave-3 security and safety reviews:

- commission: poisoning gate, mandatory sign-off, profile seal, hard caps,
  safe file I/O (atomic, no-clobber, symlink-refusing).
- blackbox: anchor forgery, export cursor, crash recovery, forged head, lock,
  symlinks.
- rtps: fragments, attribution, leniency, CPU bounds.
- capture: passive-capture findings F7a/F7b/F7c/F8.
- ros2-pipeline: participant/source-IP binding, flood caps, ambiguity and
  not-inspected findings.
- firewall: angular bound, HoldLast, infinite envelope, observe mode,
  spoofer state.
- motion: direction, injected feedback, NaN.
- responder: bounded decoy influence on rate limiting, overflow and motion
  guard; honours `Deviation::mode`; per-(source, rule) rate limiting.
- agent: fail-safe evidence and clock handling, replay isolation, strict
  config.
- ocsf: allow-list taint neutralisation, dual rendering, flags; observe-mode
  fix.
- events: ROS names validated in profiles, malformed mangled names rejected,
  name-normalisation gaps closed.
- rules / supply chain: exec-path, fileless, Python and keystore bypasses
  closed; `--locked` CI.
- sensor-ros2: Pulsar lifecycle mismatches fixed. Status is documented as
  stub-verified.

[Unreleased]: https://github.com/SingularityRD/robodr/compare/v0.1.0-alpha.1...HEAD
[0.1.0-alpha.1]: https://github.com/SingularityRD/robodr/releases/tag/v0.1.0-alpha.1
