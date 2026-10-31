<div align="center">
  <h1>RoboDR</h1>
  <b>Robot Detection &amp; Response</b><br/>
  <i>The security layer for the next generation of industrial and physical-AI robots.</i>
</div>

---

RoboDR is a detection-and-response platform for Linux-based robots that
use ROS 2 / DDS, including Unitree quadrupeds and humanoids. It watches
what a robot's software *and its motion* are actually doing, catches
deviation from a locked model profile, and responds in a way that is aware
of the robot's physical safety state — never by blindly killing a process
on a machine that is mid-motion. What is in scope today, and how far each
part is verified, is under [Scope](#scope).

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
- **Air-gapped fleets** — findings and evidence leave through a data diode
  or on media as signed batches; releases arrive the same way.

These are design goals; the evidence for each is lab evidence, not field
evidence (see [Scope](#scope) and [Status](#status)).

## Scope

What RoboDR covers in this release line, with the verification level of
[`docs/customer/support-matrix.md`](docs/customer/support-matrix.md)
(V2 lab: real software of that kind in a lab; V1: synthetic vectors,
emulation or containers; nothing is V3 field-verified):

| In scope | Level | Where to look |
|---|---|---|
| ROS 2 / DDS robots: graph, discovery and motion-command detection (Jazzy; Fast DDS 2.14, Cyclone DDS 0.10) | V2 (lab captures) | [support matrix](docs/customer/support-matrix.md#ros-2-and-middleware) |
| ROS 2 Humble, Foxy | V1 | same |
| Unitree robots (Go2, B2, H1, G1 and others over SDK2 / DDS; Go1 legacy UDP) | V1 (synthetic traffic, IDL-derived vectors; no real Unitree capture) | [`docs/UNITREE.md`](docs/UNITREE.md) |
| Linux host runtime security (Pulsar eBPF rules through `robodr-pulsard`) | V2 under WSL2; never on a robot | [support matrix](docs/customer/support-matrix.md#kernel-and-host-monitoring-robodr-pulsard-ebpf) |
| On-robot agent, or a passive sensor box on a tap / mirror port | V2 (agent in a lab VM), V1 (sensor-box example configuration) | [`docs/customer/quick-start.md`](docs/customer/quick-start.md) |
| Inline Motion Firewall gateway on a bridged sensor box (Unitree channels, ROS 2 `cmd_vel` and joint trajectories) | V2 (network namespaces, synthetic frames) | [`crates/robodr-firewall-gw/README.md`](crates/robodr-firewall-gw/README.md) |
| Response actions through `robodr-executor` (off by default; adapters per platform, each gated by `oem_validated`) | V2 network actions and the `gateway` motion adapter; V1 the other motion adapters | [response actions](docs/customer/support-matrix.md#response-actions) |
| Findings to AutoSecOps (ingest API), Kafka, or across a diode | V2 Kafka; V1 ingest API and diode | [support matrix](docs/customer/support-matrix.md#soc-and-export-paths) |

Every rule RoboDR can report is listed in the
[detection catalog](docs/customer/detection-catalog.md); measured lab
figures are in the [performance data sheet](docs/customer/performance.md);
a POC follows the [POC guide](docs/customer/poc-guide.md).

**Roadmap, not in this release line:** drones and other MAVLink vehicles
(the executor has a PX4 hold adapter, but nothing detects on MAVLink
traffic), industrial arms behind closed controllers (KUKA, FANUC, ABB,
OPC UA) and the agentless *Sentinel Box* appliance for them, fieldbuses
(CAN, EtherCAT), defence UGV integrations, Zenoh decoding, RTOS / MCU
targets, remote attestation. See [`docs/ROADMAP.md`](docs/ROADMAP.md).

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
                          allocation-free hot path; used by agentd (recording)
                          and by robodr-firewall-gw (inline).
  robodr-motion/          Motion/feedback consistency detector (injected or frozen
                          telemetry, uncommanded motion, GNSS vs odom vs IMU). Pure.
  robodr-responder/       Cyber-Jidoka response *planner*: graded, safety-state-aware
                          plans; executes nothing, never overrides the safety system.
                          Owns the vendor-neutral action catalog (`actions`:
                          seven actions, approval tier, reversibility, GA
                          execution) and the humanoid rule (no executable
                          safe pause / safe state: a humanoid would fall).
  robodr-blackbox/        Signed (Ed25519 by default, via the audited
                          ed25519-dalek crate; legacy HMAC-SHA256 refused
                          unless allowed),
                          hash-chained evidence recorder with append-only
                          segments and export bundles. Owns the one key file
                          format (robodr-blackbox-key/v2 secret + .pub) also
                          used for profile signing. Binary: robodr-blackbox
                          (keygen, export-pub, verify, inspect).
  robodr-ocsf/            Deviation -> OCSF Detection Finding in the vendor-neutral
                          robodr.findings contract (2.5; configurable data source
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
  robodr-executor/        Executor v1 (off by default): carries out catalog
                          actions on the robot after its own precheck and a
                          live safety-state re-check. Network actions
                          (nftables, reversible, TTL) and, with a `motion`
                          section, platform motion adapters (gateway,
                          Unitree sport, Nav2, ros2_control, PX4, rollback),
                          each refused unless the site set `oem_validated`.
                          Binary: robodr-executor (CAP_NET_ADMIN only).
  robodr-firewall-gw/     Inline Motion Firewall gateway for a bridged sensor
                          box (NFQUEUE): passes, limits, holds or removes
                          motion samples; never originates one. Binary:
                          robodr-firewall-gw.
  robodr-fleet/           Robot side of the fleet API: enrollment, key
                          rotation, revocation lists, SOC profiles. Binary:
                          robodr-enroll.
  robodr-deliverd/        Secure-delivery unit agent: installs signed,
                          optionally sealed packages, health gate, rollback,
                          leases, crypto-erase. Binaries: robodr-deliverd,
                          robodr-safety-replay.
  robodr-depot/           Site depot for air-gapped delivery: bundle import
                          with entry-station report, unit enrolment, staged
                          rollouts. Binary: robodr-depot.
  robodr-correlate/       Weak-signal correlation engine: declarative JSON rules
                          (sequence, co-occurrence, threshold, distinct sources)
                          combine already-reported findings into
                          robot.correlate.* findings citing every input. Pure,
                          bounded memory. Wired into robodr-agentd; host-side
                          (Pulsar) signals reach it by rule name, and the default
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
                          Kafka; in-crate client, acks=all, idempotent producer,
                          TLS required, mutual TLS, SASL/SCRAM). Tested against
                          an in-process fake broker
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
                          (`build rpk --seal-to`) since 13c; the site depot is
                          robodr-depot (14a).
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
docs/SECURE-DELIVERY.md Air-gapped fleet distribution (13a-14b implemented, swtpm only),
                        staged updates, captured-unit software protection.
docs/BUILD.md           Toolchain, MSRV, Cargo.lock policy, air-gapped builds, CI.
docs/PULSAR-INTEGRATION.md  Every Pulsar item the Pulsar-bound crates use.
docs/contracts/         robodr.findings contract (v2) + JSON Schema + example,
                        robodr.control-plane contract (v2) + fixtures/
                        test vectors; legacy/ = superseded 1.x.
docs/{adr,compliance,customer}/  ADRs (D1-D9 etc.), IEC 62443/CRA/safety notes, customer
                        documents (support matrix, detection catalog, performance,
                        POC guide, quick start, known limitations, drafts).
fuzz/                   37 cargo-fuzz targets (RTPS, capture, black box, OCSF,
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
qemu. No release has been cut or signed. GitHub CI has run once in full
(2026-10-30) and was not green; every job had passed in a local run
([`docs/BUILD.md`](docs/BUILD.md), "Local CI verification"). Plan and per-sprint status:
[`docs/GA-ROADMAP.md`](docs/GA-ROADMAP.md); blunt list of limits:
[`docs/customer/known-limitations.md`](docs/customer/known-limitations.md).

**In the code (2026-10-30):**

- **Detection** in `robodr-agentd`: DDS graph against a signed, locked
  profile (participant identities survive GUID changes), RTPS user DATA →
  CDR → motion envelope, Motion Firewall decisions (recording only in the
  passive modes), motion monitor, correlation, Pulsar host threats, a
  signed and hash-chained black box. Unitree SDK2 topics and Go1 legacy
  UDP decode end to end on synthetic traffic and IDL-derived vectors
  ([`docs/UNITREE.md`](docs/UNITREE.md)).
- **Findings to a SOC**: `robodr.findings` 2.5 over `robodr-uplink`
  (signed NDJSON batches, TLS, contract
  [`robodr.ingest-api`](docs/contracts/robodr.ingest-api.md)), the diode,
  or Kafka (TLS, mutual TLS, SASL/SCRAM).
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
  Without a `motion` section in `executor.json`, `restrict_motion` is
  recorded only and `safe_pause`, `request_safe_state` and
  `rollback_config` are refused. With one, they run through **platform
  adapters**: `gateway` and `unitree_sport` (`restrict_motion`), `nav2`,
  `ros2_control` and `px4` (`safe_pause`, `request_safe_state`),
  `rollback` (`rollback_config`). Each adapter refuses to run until the
  site sets its `oem_validated: true`; pause, safe state and rollback need
  two distinct human approvers, and pause and safe state are never
  executed on a humanoid. Only the `gateway` adapter has run against the
  real component (lab soak); the others only against in-process simulated
  peers ([response actions](docs/customer/support-matrix.md#response-actions),
  [crate README](crates/robodr-executor/README.md)).
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
  code, 37 fuzz targets (CI runs each for 60 s; an earlier campaign ran 10
  of them for 630 s each, no crash).

**Not verified:**

- No real robot, sensor box, controller hardware or hardware TPM. No 72 h
  soak (a 2 h lab soak ran on a shared VM); false-positive rates on a real
  robot are unmeasured, and the resource and latency figures are lab
  values from a shared VM
  ([performance data sheet](docs/customer/performance.md)).
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
- Kafka and the anchor receiver use TLS (plain TCP only when explicitly
  allowed); mutual TLS authenticates hosts, not robot ids. Every TLS path
  checks CRLs (no OCSP). Keys are files, not TPM-held.
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
