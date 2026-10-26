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

**Verified offline** (dev sandbox: no network, Rust stable 1.97, Pulsar-bound
members dropped from the workspace, serde patched to local checkouts; no kernel
module, no robot):

- The 16 pure crates build, pass `clippy -D warnings` and pass their tests:
  1883 unit + integration tests passing, 1 long fuzz run `#[ignore]`d (at the
  wave-7 integration, two consecutive full runs).
- Wave 7 (review fixes) is in: profile trust files must be root-signed and
  locked profiles attested when `trust_roots` is configured; revocation
  lists v2 revoke signing keys by fingerprint; `safety_feed` topics need
  commissioned `writers`, and safety and motion samples are trusted only
  when the participant binding vouches for their source (contested
  prefixes trust no source); the black box can mark its head through a
  file anchor (`blackbox.head_anchor`, kind `file`); spool export recovers
  a split pack without acknowledging unpacked records. Every emitted
  `robot.*` rule id has its own OCSF 1.3 catalog entry. The Pulsar-bound
  crates are built against the real Pulsar (commit 4796504) and were run as
  root with eBPF probes loaded (PULSAR-INTEGRATION §7b).
- Inputs: most tests use **synthetic** RTPS / pcap generated from the spec;
  four **real captures** of ROS 2 Jazzy (Fast DDS 2.14, Cyclone DDS 0.10;
  robot + teleop + a rogue `/cmd_vel` publisher) are checked in under
  `fixtures/captures/ros2-jazzy/` and exercised end to end by
  `crates/robodr-ros2-pipeline/tests/real_captures.rs`: learn from one run,
  detect the rogue in another run in which every process has a new GUID
  (participant identities, `Profile::participant_identities`).
- Live `AF_PACKET` capture is exercised only on the loopback interface with
  test-generated datagrams, and only when the test has `CAP_NET_RAW` (it
  prints `SKIPPED` and passes otherwise).

**Not verified:**

- No real robot, no RTI Connext traffic, no DDS-Security, no controller
  hardware, no TPM. False-positive rates are unmeasured beyond the lab
  captures; thresholds are still estimates.
- Gazebo: a headless Gazebo Harmonic robot (gz bridge,
  robot_state_publisher, `/clock`, `/tf`, `/joint_states`, `/odom`) was
  captured, learned and replayed against a restarted run with a rogue
  (`fixtures/captures/ros2-jazzy/`, second set): no false positive left
  after one fix (DATA before the writer's own SEDP). No rendering sensors,
  ros2_control or nav2.
- DATA_FRAG: real fragmented SEDP (Fast DDS, Cyclone) and a fragmented
  JointTrajectory are reassembled and learned (two reassembly bugs found and
  fixed). Fragmented SPDP only from Cyclone.
- Zenoh (`rmw_zenoh_cpp`) is **not decoded**: the sensor is blind to it.
  It is detected by port and reported (`robot.capture.unsupported_middleware`,
  High when no RTPS is seen; agentd health never `ok`; `learn` warns), not
  inspected.
- `robodr-pulsard` ran in WSL2 (kernel 6.18), not on a robot: the multicast
  join on the robot's interface and coexistence with each DDS vendor on the
  same host are open.
- arm64 is cross-built and tested under qemu-user only (docs/BUILD.md,
  "arm64 (cross-compiled, 2026-10-18)"). Not tested on arm64 hardware, and
  Pulsar's eBPF probes have never been loaded on an arm64 kernel.
- `rules/robodr/*.toml` are checked by `scripts/validate_rules.py` only, not
  loaded into a running Pulsar rules engine.
- The firewall, motion monitor, responder, black box and OCSF mapper run
  live in `robodr-agentd`: capture -> RTPS user DATA -> CDR ->
  `MotionCommand` / `MotionFeedback` -> agent. The XCDR1 `Twist` decode is
  confirmed on real Fast DDS and Cyclone DDS samples; XCDR2 / `D_CDR2` and
  the other message types only on hand-built vectors. The Motion Firewall
  runs recording-only, and nothing executes a response.
- The control-plane API `robodr-control-plane/v2` (`robodr-agentd`
  `control_plane`, off by default; `docs/contracts/robodr.control-plane.md`)
  serves mutual TLS (rustls) off loopback and authenticates Ed25519-signed
  SOC requests for the seven catalog actions, judges them against the live
  safety state, records them and keeps their state across restarts
  (journal, persisted replay store). It **executes nothing**
  (`recorded_not_executed`) unless executor v1 (`robodr-executor`, off by
  default) is enabled; then executor states (`verified`, `reverted`, ...)
  are signed and journalled like every other state. Its evidence API exports black-box records as
  signed, chunked bundles that `robodr-blackbox verify` checks. Exercised
  with an in-process signing client and a test PKI over loopback, not
  against a deployed SOC or across a real network.
  The Pulsar module (`robodr-sensor-ros2`) runs the same decode for its
  envelope check but does not forward decoded samples (see its crate docs).
- The black box's TPM 2.0 NV counter head anchor (`TpmNvCounterAnchor`,
  `blackbox.head_anchor` kind `tpm_nv_counter`) is tested against swtpm
  only, not a hardware TPM; it makes rollback and truncation detectable,
  not impossible (root can still use the counter; owner/lockout
  authorization must be kept off the unit). The remote head anchor
  (`RemoteHeadAnchor` + `robodr-anchor-receiver`, kind `remote`) is tested
  over loopback against a real receiver process only, not across a real
  network; it needs a reverse channel to the receiver (otherwise
  detect-only through the diode) and makes rollback detectable, not
  impossible. A contested GUID prefix fails closed (an attacker who can send
  one SPDP can make a profiled participant untrusted until it is pinned in
  `participant_ips`).
- Evidence (black box, diode bundles) and profiles are signed with Ed25519
  key files (`robodr-blackbox-key/v2`; HMAC still loads, with a warning). The
  Ed25519 arithmetic is the audited `ed25519-dalek` crate (strict
  verification, pinned to the RFC 8032 vectors), but keys are files, not TPM-held;
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
