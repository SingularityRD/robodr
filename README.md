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

> **Status: alpha, research codebase, not a product release.** Everything that
> is verified so far is verified *offline* on synthetic data; nothing has yet run
> against a real robot, real DDS stack or real Pulsar build. See
> [Status](#status) for the exact line.

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
  robodr-blackbox/        Signed (Ed25519 by default, unaudited std-only
                          implementation; legacy HMAC-SHA256 warned),
                          hash-chained evidence recorder with append-only
                          segments and export bundles. Owns the one key file
                          format (robodr-blackbox-key/v2 secret + .pub) also
                          used for profile signing. Binary: robodr-blackbox
                          (keygen, export-pub, verify, inspect).
  robodr-ocsf/            Deviation -> OCSF Detection Finding for the AutoSecOps
                          robot-edr.findings contract; Kafka key/partition helpers
                          (no Kafka client).
  robodr-agent/           Offline decision chain composing the crates above
                          (event -> deviation -> plan -> evidence -> finding).
                          Binary: robodr-replay (JSONL replay). Executes nothing.
  robodr-agentd/          Live daemon (std threads, no Pulsar): capture / pcap /
                          JSONL events -> ROS 2 pipeline -> decision chain ->
                          signed black box -> OCSF findings spool, self-health.
                          Binary: robodr-agentd (systemd unit in packaging/).
                          Plans only; tested offline with pcaps and JSONL, never
                          run on a robot.
  robodr-cdr/             ROS 2 CDR (XCDR1/XCDR2) decoder for motion topics
                          (Twist, TwistStamped, JointTrajectory, Odometry, Imu,
                          JointState) -> MotionCommand / MotionFeedback. Pure
                          library, used by the pipeline's live motion path.
  robodr-diode/           One-way export of findings and black-box bundles across
                          a data diode or media: signed, chained batches.
                          Binaries: robodr-diode-pack (low side),
                          robodr-diode-unpack (SOC side). No network code;
                          Ed25519 batches, the SOC holds public keys only (HMAC
                          only with --allow-hmac).
  robodr-sensor-ros2/     Thin Pulsar module wrapping robodr-ros2-pipeline.
                          Pulsar-dependent; not built or tested offline.
  robodr-pulsard/         Pulsar daemon with the RoboDR module registered.
                          Pulsar-dependent; not built or tested offline.
rules/robodr/           Robot detection rules in Pulsar rules-engine TOML format
                        (validate: scripts/validate_rules.py; see rules/README.md).
config/                 Profile, response-policy and daemon config examples.
docs/ROADMAP.md         The engineering plan: phases, components, research.
docs/SPRINTS.md         The roadmap broken into sprints, with status.
docs/BUILD.md           Toolchain, MSRV, Cargo.lock policy, air-gapped builds, CI.
docs/PULSAR-INTEGRATION.md  Every Pulsar item the Pulsar-bound crates use.
docs/contracts/         robot-edr.findings topic contract + JSON Schema.
fuzz/                   cargo-fuzz targets (RTPS, capture, black box, OCSF,
                        commissioning, firewall, pipeline config; own
                        workspace) + std-only smoke runs in the crates' tests.
man/                    Man pages for every shipped binary.
packaging/              .deb, offline bundle, systemd units, tmpfiles, sysusers.
vendor/pulsar/          Pulsar, as a git submodule (the base we build on).
```

## Status

**Verified offline** (dev sandbox: no network, Rust stable 1.97, Pulsar-bound
members dropped from the workspace, serde patched to local checkouts; no kernel
module, no robot):

- The 14 pure crates build, pass `clippy -D warnings` and pass their tests:
  1413 unit + integration tests passing, 1 long fuzz run `#[ignore]`d (at the
  wave-4 integration). The Pulsar-bound crates are only type-checked and
  linted against local stubs of the Pulsar API, not built against Pulsar.
- All inputs are **synthetic**: RTPS datagrams and pcap/pcapng files are
  generated byte by byte from the DDSI-RTPS spec by test generators
  (`crates/robodr-rtps/tests/fixtures/README.md` says so explicitly). No
  capture from a real DDS stack is checked in.
- Live `AF_PACKET` capture is exercised only on the loopback interface with
  test-generated datagrams, and only when the test has `CAP_NET_RAW` (it
  prints `SKIPPED` and passes otherwise).

**Not verified:**

- The Pulsar-bound crates (`robodr-sensor-ros2`, `robodr-pulsard`) have never
  been compiled against the real Pulsar here (they need `pulsar-core`, tokio
  and crates.io / a mirror); they were type-checked against API stubs only and
  have no tests of their own.
- No real robot, no real Fast DDS / Cyclone DDS / Connext traffic, no Gazebo
  run, no controller hardware, no TPM. False-positive rates are unmeasured.
- `rules/robodr/*.toml` are checked by `scripts/validate_rules.py` only, not
  loaded into a running Pulsar rules engine.
- The firewall, motion monitor, responder, black box and OCSF mapper run
  live in `robodr-agentd`: capture -> RTPS user DATA -> CDR ->
  `MotionCommand` / `MotionFeedback` -> agent. That path has only decoded
  hand-built RTPS / CDR in synthetic pcaps, never traffic from a real RMW;
  the Motion Firewall runs recording-only, and nothing executes a response.
  The Pulsar module (`robodr-sensor-ros2`) runs the same decode for its
  envelope check but does not forward decoded samples (see its crate docs).
- Evidence (black box, diode bundles) and profiles are signed with Ed25519
  key files (`robodr-blackbox-key/v2`; HMAC still loads, with a warning). The
  Ed25519 code is RoboDR's own std-only implementation, checked against RFC
  8032 vectors but not audited, and keys are files, not TPM-held;
  anti-rollback state is a plain file.

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
cargo test --workspace --exclude robodr-sensor-ros2 --exclude robodr-pulsard
cargo test -p robodr-rtps          # RTPS discovery parser
cargo test -p robodr-ros2-pipeline # sensor pipeline (what the Pulsar module runs)

# Pulsar-bound crates link all of Pulsar (needs its eBPF build toolchain; see
# vendor/pulsar/README.md for kernel 5.5+, BTF, clang requirements):
cargo build -p robodr-sensor-ros2 -p robodr-pulsard
```

## License

Apache-2.0 for userspace, GPL-2.0 for any eBPF probe code, matching Pulsar. See
[`LICENSE`](LICENSE).
