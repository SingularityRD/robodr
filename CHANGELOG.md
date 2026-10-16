# Changelog

All notable changes to RoboDR are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html)
(pre-1.0: any minor or pre-release may change interfaces).
A release is cut by tagging `v<VERSION>`. `.github/workflows/release.yml`
requires a `## [<VERSION>]` section here and uses it as the release notes.

## [Unreleased]

### Added

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
