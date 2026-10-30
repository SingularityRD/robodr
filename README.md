<div align="center">
  <h1>RoboDR</h1>
  <b>Robot Detection &amp; Response</b><br/>
  <i>The security layer for the next generation of industrial and physical-AI robots.</i>
</div>

---

RoboDR is a detection-and-response platform for robots: industrial arms, AMRs,
humanoids, drones and defence UGVs. It watches what a robot's software *and its
motion* are actually doing, catches deviation from a locked model profile, and
responds in a way that is aware of the robot's physical safety state — never by
blindly killing a process on a machine that is mid-motion.

It is built on [Pulsar](https://github.com/exein-io/pulsar) (eBPF runtime
security for Linux), vendored under `vendor/pulsar`. RoboDR adds the robot layer
Pulsar does not have: the ROS 2 / DDS graph, the motion envelope, device
attestation, and a safety-aware responder (*Cyber-Jidoka*).

> **Status: alpha, research codebase, not a product release.** Verified
> offline on synthetic data, on real ROS 2 Jazzy traffic from Fast DDS and
> Cyclone DDS captured in a container lab
> ([`fixtures/captures/ros2-jazzy`](fixtures/captures/ros2-jazzy/README.md)),
> and with a real Pulsar build run as root
> ([`docs/PULSAR-INTEGRATION.md`](docs/PULSAR-INTEGRATION.md) §7b). Nothing has
> run on a real robot yet. See [Status](#status) for the exact line.

## Why not just Pulsar, Exein or Alias?

Pulsar, Exein Runtime and Alias RIS all secure the robot's **Linux host** —
processes, files, network. That is necessary and RoboDR inherits it from Pulsar.
It is not sufficient: a host can look clean while an authenticated-but-spoofed
ROS 2 participant publishes a manipulated motion command, or a jailbroken LLM
planner issues a legal-looking but unsafe command. Recent work shows both are
real (see [`docs/ROADMAP.md`](docs/ROADMAP.md) §0). RoboDR's differentiators:

- **ROS 2 / DDS graph awareness** — who is on the bus, who may publish motion.
- **Motion Firewall** — every motion command checked against a physical
  envelope before it reaches the motors.
- **Cyber-Jidoka** — response graded by the robot's safety state, borrowing the
  Toyota *jidoka* idea: stop safely, surface the fault, fix it fleet-wide.
- **One core, every robot kind** — including closed controllers (via the
  agentless Sentinel Box) and air-gapped fleets.

## Repository layout

```
crates/
  robodr-events/          Pure event taxonomy (RobotEvent, Deviation, Severity),
                          DDS graph model + ROS 2 name de-mangling, model profile
                          and Profile::evaluate (the detection core). No I/O.
  robodr-rtps/            Read-only RTPS discovery parser: SPDP + SEDP, LE/BE,
                          inline QoS, bounded DATA_FRAG reassembly. No I/O.
  robodr-capture/         Passive capture: Ethernet/IP/UDP decode, IP reassembly,
                          pcap/pcapng replay, Linux AF_PACKET reader. Never sends.
  robodr-ros2-pipeline/   Pulsar-independent ROS 2 sensor pipeline: datagram
                          sources -> RTPS parse -> profile deviations -> dedup ->
                          sanitised findings. Binary: robodr-ros2-watch (lab tool).
  robodr-commission/      Observe-mode commissioning: learn a draft profile.json
                          from a clean run, diff / merge / lock / check it;
                          signed, versioned profiles (keygen / sign /
                          verify-profile / trust-keys, anti-rollback state).
                          Binary: robodr-commission.
  robodr-firewall/        Motion Firewall decision core: pass / limit / reject a
                          motion command against the locked envelope. Pure,
                          allocation-free hot path; no ROS 2 gateway yet.
  robodr-motion/          Motion/feedback consistency detector (injected or frozen
                          telemetry, uncommanded motion, GNSS vs odom vs IMU). Pure.
  robodr-responder/       Cyber-Jidoka response *planner*: graded, safety-state-aware
                          plans; executes nothing, never overrides the safety system.
                          Owns the vendor-neutral action catalog (`actions`:
                          seven actions, approval tier, reversibility, GA
                          execution) and the humanoid rule (no executable
                          safe pause / safe state: a humanoid would fall).
  robodr-blackbox/        Signed (Ed25519 by default, via the audited
                          ed25519-dalek crate; legacy HMAC-SHA256 warned),
                          hash-chained evidence recorder with append-only
                          segments and export bundles. Owns the one key file
                          format (robodr-blackbox-key/v2 secret + .pub) also
                          used for profile signing. Binary: robodr-blackbox
                          (keygen, export-pub, verify, inspect).
  robodr-ocsf/            Deviation -> OCSF Detection Finding in the vendor-neutral
                          robodr.findings contract (2.0; configurable data source
                          and topic; 1.x parse-only); Kafka key/partition helpers
                          (no Kafka client); optional detached Ed25519 per-finding
                          signatures (header robodr-finding-sig); rule catalog
                          for correlation, safety-state and agent findings.
  robodr-agent/           Offline decision chain composing the crates above
                          (event -> deviation -> plan -> evidence -> finding).
                          Binary: robodr-replay (JSONL replay). Executes nothing.
  robodr-agentd/          Live daemon (std threads, no Pulsar): capture / pcap /
                          JSONL events -> ROS 2 pipeline -> decision chain ->
                          signed black box -> OCSF findings spool, self-health;
                          passive live safety-state feed (bus topics / PLC
                          socket), correlation (robodr-correlate), optional
                          per-finding signatures, black-box head marks and
                          quarantine reports. Binary: robodr-agentd (systemd
                          unit in packaging/). Plans only; tested offline with
                          pcaps and JSONL, never run on a robot.
  robodr-correlate/       Weak-signal correlation engine: declarative JSON rules
                          (sequence, co-occurrence, threshold, distinct sources)
                          combine already-reported findings into
                          robot.correlate.* findings citing every input. Pure,
                          bounded memory. Wired into robodr-agentd; host-side
                          (Pulsar) signals do not reach it yet, and the default
                          rules are untuned engineering defaults.
  robodr-cdr/             ROS 2 CDR (XCDR1/XCDR2) decoder for motion topics
                          (Twist, TwistStamped, JointTrajectory, Odometry, Imu,
                          JointState) -> MotionCommand / MotionFeedback. Pure
                          library, used by the pipeline's live motion path.
  robodr-diode/           One-way export of findings and black-box bundles across
                          a data diode or media: signed, chained batches.
                          Binaries: robodr-diode-pack (low side),
                          robodr-diode-unpack (SOC side). No network code;
                          Ed25519 batches, the SOC holds public keys only (HMAC
                          only with --allow-hmac); Reed-Solomon parity, resend.
  robodr-export/          The hops around the diode. Binaries:
                          robodr-spool-export (robot side: agentd spool ->
                          diode outbox, crash-safe) and robodr-kafka-publish
                          (SOC side: importer output or a connected spool ->
                          Kafka; std-only client, acks=all, idempotence off, no
                          TLS/SASL). Tested against an in-process fake broker
                          in CI and against single-node Apache Kafka 3.9.1 and
                          4.1.0 brokers (scripts/kafka-it.sh, docker). And
                          robodr-uplink: the same inputs -> the AutoSecOps
                          ingest API (docs/contracts/robodr.ingest-api.md) over
                          TLS (rustls + ring, CA bundle, SPKI pins), signed
                          NDJSON batches, at-least-once and crash-safe;
                          uplink-status.json + sd_notify STATUS= show a
                          blocked queue; `reinject` re-queues dead letters
                          after a registration fix.
  robodr-pkg/             Secure delivery formats (docs/SECURE-DELIVERY.md §3):
                          pure, fuzzed parsers for RPK packages, release
                          bundles, deployments, the site trust file and quorum
                          signature sets. Sprint 13a.
  robodr-release/         Connected-side release tool: build RPKs, sign with a
                          key quorum, assemble chained bundles with parity,
                          verify anywhere, repair from parity. Binary:
                          robodr-release. Sprint 13a; sealed RPKs
                          (`build rpk --seal-to`) since 13c; no depot yet.
  robodr-seal/            Captured-unit protection (docs/SECURE-DELIVERY.md
                          §7): XChaCha20-Poly1305 sealed chunks, key wraps
                          to depots and units, a TPM-resident unit key
                          behind a signed PCR policy, a policy floor and an
                          erase epoch (tpm2-tools), the LUKS2 runtime
                          volume and the Clevis/Tang fallback. Binary:
                          robodr-seal. Sprint 13c; tested against swtpm.
  robodr-sensor-ros2/     Thin Pulsar module wrapping robodr-ros2-pipeline.
                          Pulsar-dependent: built, linted and tested against
                          vendor/pulsar in CI's `pulsar` job (needs Pulsar's
                          eBPF toolchain).
  robodr-threat-forward/  Pulsar module (no binary) forwarding every Pulsar
                          threat to robodr-agentd's host_threats socket (JSON
                          lines, bounded queue, never blocks the bus).
                          Pulsar-dependent; built and tested like the above.
  robodr-pulsard/         Pulsar daemon with the RoboDR modules registered.
                          Pulsar-dependent; built and tested in the `pulsar`
                          job; run as root with eBPF probes loaded in WSL2,
                          never on a robot (PULSAR-INTEGRATION §7b).
rules/robodr/           Robot detection rules in Pulsar rules-engine TOML format
                        (validate: scripts/validate_rules.py; see rules/README.md).
config/                 Profile, response-policy and daemon config examples.
docs/ROADMAP.md         The engineering plan: phases, components, research.
docs/SPRINTS.md         The roadmap broken into sprints, with status.
docs/SECURE-DELIVERY.md Design (not implemented): air-gapped fleet distribution,
                        staged updates, captured-unit software protection.
docs/BUILD.md           Toolchain, MSRV, Cargo.lock policy, air-gapped builds, CI.
docs/PULSAR-INTEGRATION.md  Every Pulsar item the Pulsar-bound crates use.
docs/contracts/         robodr.findings contract (v2) + JSON Schema + example,
                        robodr.control-plane contract (v2) + fixtures/
                        test vectors; legacy/ = superseded 1.x.
docs/{adr,compliance,customer}/  ADRs (D1-D9 etc.), IEC 62443/CRA/safety notes, customer drafts.
fuzz/                   cargo-fuzz targets (RTPS, capture, black box, OCSF,
                        commissioning, firewall, pipeline config, control-plane
                        requests; own workspace) + std-only smoke runs in the
                        crates' tests.
man/                    Man pages for every shipped binary.
packaging/              .deb, offline bundle, systemd units, tmpfiles, sysusers.
vendor/pulsar/          Pulsar, as a git submodule (the base we build on).
```

## Status

**Alpha (`0.1.0-alpha.1`), unreleased, not validated on a real robot.**
Everything below was verified offline: unit and integration tests, real
ROS 2 lab captures, network namespaces on a development VM, containers and
qemu. No release has been cut or signed, and GitHub CI has never run
(every CI job passed in a local run). Plan and per-sprint status:
[`docs/GA-ROADMAP.md`](docs/GA-ROADMAP.md); blunt list of limits:
[`docs/customer/known-limitations.md`](docs/customer/known-limitations.md).

**In the code (2026-10-26):**

- **Detection** in `robodr-agentd`: DDS graph against a signed, locked
  profile (participant identities survive GUID changes), RTPS user DATA →
  CDR → motion envelope, Motion Firewall decisions (recording only in the
  passive modes), motion monitor, correlation, Pulsar host threats, a
  signed and hash-chained black box. Unitree SDK2 topics and Go1 legacy
  UDP decode end to end on synthetic traffic and IDL-derived vectors
  ([`docs/UNITREE.md`](docs/UNITREE.md)).
- **Findings to a SOC**: `robodr.findings` 2.1 over `robodr-uplink`
  (signed NDJSON batches, TLS, contract
  [`robodr.ingest-api`](docs/contracts/robodr.ingest-api.md)), the diode,
  or Kafka (no TLS).
- **Control plane `robodr-control-plane/v2`** (off by default; v1 is
  removed): mutual TLS off loopback, Ed25519-signed requests and answers,
  a persistent request journal and replay store, and an evidence API that
  exports black-box records as signed, chunked bundles
  (`robodr-blackbox verify BUNDLE`)
  ([contract](docs/contracts/robodr.control-plane.md)).
- **Executor v1** (`robodr-executor`, **off by default**): reversible,
  TTL-bounded `isolate_network` and `quarantine_node` (nftables) and
  `record_evidence`, decided again on the robot against its own policy and
  the live safety state; separate process with `CAP_NET_ADMIN` only.
  `restrict_motion` is recorded only; `safe_pause`, `request_safe_state`
  and `rollback_config` are never executed
  ([crate README](crates/robodr-executor/README.md)).
- **In-path gateway** (`robodr-firewall-gw`, optional): a bridged sensor
  box that passes, limits, holds or removes Unitree and ROS 2 motion
  samples (`rt/lowcmd`, sport `Move`, loco requests, arm SDK, hands,
  `rt/cmd_vel` twists, Go1 UDP) and never originates one;
  `fail_closed` by default. It protects only what crosses its bridge
  ([crate README](crates/robodr-firewall-gw/README.md), "Known limits").
- **Fleet lifecycle, robot side** (`robodr-enroll`): enrollment with a
  single-use SOC token, uplink / finding key rotation, revocation lists,
  staged SOC profiles, ring information
  ([contract](docs/contracts/robodr.fleet-api.md), draft v1).
- **Hardening (S10)**: `sha2` (HMAC as a wiping RFC 2104 wrapper over it)
  instead of hand-written crypto,
  `forbid(unsafe_code)` where possible, panic-family calls denied in daemon
  code, 23 fuzz targets (10 run under libFuzzer for 630 s each, no crash).

**Not verified:**

- No real robot, sensor box, controller hardware or hardware TPM. No 72 h
  soak; false-positive rates and resource budgets are unmeasured. Gateway
  latency was measured only on a shared VM.
- The executor and the gateway have run only in network namespaces with
  synthetic traffic, never under a real systemd on a target, never next to
  a real Cyclone / Fast DDS stack. Unitree's `rt/lowcmd` QoS and the motor
  board's behaviour on a lost command stream are unconfirmed.
- The control plane, uplink and enroll have run against in-process clients,
  reference servers and a local test PKI, not across a real network. The
  AutoSecOps side (ingest module, control-plane v2 client, approvals, robot
  pages) is on an unreleased AutoSecOps branch and passes the shared
  contract vectors. In one container the uplink-to-case path and fleet
  enrollment ran end to end against it (`tools/e2e/RESULTS.md`), not
  across a real network.
- Zenoh is detected, not decoded; DDS-Security payloads, RTI Connext and
  arm64 hardware are untested; `robodr-pulsard` ran only under WSL2, and
  the host rules were never loaded into a running rules engine on a robot.
- Kafka and the anchor receiver have no TLS. Keys are files, not TPM-held.
  The executor verifies the SOC's signed request itself, but not the
  SOC's internal approval process.
- Reviews were done by independent AI agents, not humans; there has been no
  penetration test. RoboDR is not a safety-rated component
  ([`docs/compliance/safety-positioning.md`](docs/compliance/safety-positioning.md)).

## Build

Two paths; [`docs/BUILD.md`](docs/BUILD.md) is authoritative for both.

- **Connected lab host:** Rust toolchain from `rust-toolchain.toml`, crates
  from crates.io (or the internal mirror).
- **Air-gapped host:** no crates.io at all — crates from the internal mirror
  or a vendored tarball, `--locked --offline`, toolchain from the offline
  bundle (BUILD.md, "Air-gapped builds").

```bash
git clone --recurse-submodules https://github.com/SingularityRD/robodr.git
cd robodr
# or, if already cloned:  git submodule update --init --recursive

# Pure crates: build and test with no kernel and no robot. (Cargo still
# resolves the whole workspace, so this needs the submodule and the crates
# pinned in Cargo.lock, from crates.io or the mirror.)
cargo test --workspace --exclude robodr-sensor-ros2 --exclude robodr-pulsard \
  --exclude robodr-threat-forward
cargo test -p robodr-rtps          # RTPS discovery parser
cargo test -p robodr-ros2-pipeline # sensor pipeline (what the Pulsar module runs)

# Pulsar-bound crates link all of Pulsar (needs its eBPF build toolchain; see
# vendor/pulsar/README.md for kernel 5.5+, BTF, clang requirements):
cargo build -p robodr-sensor-ros2 -p robodr-threat-forward -p robodr-pulsard
```

## License

RoboDR is proprietary software of SingularityRD; use requires a written license
agreement. See [`LICENSE`](LICENSE). Third-party components (Pulsar: Apache-2.0
userspace, GPL-2.0 eBPF probes; Rust dependencies: see the release SBOM) keep
their own licenses.
