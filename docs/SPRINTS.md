# RoboDR sprint plan

This breaks [`ROADMAP.md`](ROADMAP.md) into executable sprints: who builds what,
in what order, and what "done" looks like for each. It is the layer the roadmap
left open — task breakdown, ownership, dependencies and a per-sprint demo.

> **SOC side.** The SOC tasks below were first written against the old
> `autosecops2` integration (Kafka consumer, `core/integrations/robot_edr/`);
> that integration is cancelled. The GA SOC is SingularityRD/AutoSecOps1
> (plan: [`GA-ROADMAP.md`](GA-ROADMAP.md)). RoboDR now speaks
> vendor-neutral contracts
> ([`robodr.findings`](contracts/robodr.findings.md) 2.x,
> [`robodr.control-plane`](contracts/robodr.control-plane.md), the action
> catalog `robodr_responder::actions`) and the SOC-side work is planned
> against those. "SOC bridge" below means whatever SOC consumes them.

## Working assumptions

Change these and the plan rescales; they are stated so the plan is honest.

- **Sprint length:** 2 weeks.
- **Team of 4 engineers:**
  - **E1 — Core/eBPF:** Rust detection core, Pulsar integration, eBPF/LSM.
  - **E2 — Robotics:** ROS 2 / DDS, motion, robot lab, commissioning.
  - **E3 — Backend:** fleet control plane, SOC bridge, console.
  - **E4 — Embedded/HW:** Sentinel Box, Lite SDK (RTOS), attestation, fieldbus.
  - Security research is shared across all four, 1 day/week, feeding the eval corpus.
- **Lab start:** Gazebo simulation of a **defence ground UGV** + one real ROS 2
  companion computer; a CAN / MIL-STD-1553 lower stack and drone/RTOS hardware
  arrive at Phase 2/3.
- **Defence posture (sets the bar from Sprint 1):**
  - **Air-gapped by default.** The lab and every build run with no outbound
    connectivity; dependencies (crates, Pulsar, images, models) are mirrored
    into an internal registry, never pulled from the public internet at build.
  - **Export control decided first.** An ECCN/ITAR-vs-dual-use and Turkish
    defence-export classification of RoboDR is produced in Sprint 1, before any
    code is shared outside the team; it gates what goes in the open-core repo
    vs. the controlled defence repo.
  - **Protective scope only.** No attack tooling ships; attack reproduction lives
    only in the internal eval corpus to validate detection. RoboDR never
    overrides platform safety/command authority.
  - **Assurance:** reproducible builds, signed releases, SBOM per build, and a
    path to the assurance level the customer programme requires.
- **Team note:** personnel and facility clearances, and which engineers may touch
  the controlled repo, are a programme prerequisite — assumed in place, not
  scheduled here.
- **Definition of Done (every task):** code + unit tests + docs; CI green
  (`fmt`, `clippy -D warnings`, tests); SBOM emitted; merged to `main`; demoable.
- **Each sprint ends in a demo** — something that runs, not a status update.

The sprint count per phase firms up as the previous phase lands; Phase 1 is
planned task-by-task, later phases sprint-by-sprint with named tasks that get
split into issues at phase start.

**Status notes.** Each sprint below ends with a *Status as of 2026-10-16*
block, checked against the code in this repository on that date. Terms follow
the [roadmap legend](ROADMAP.md#2-component-map-dependency-order): **pure
logic done** = crate exists and is tested offline on synthetic inputs;
**integrated** = wired into a runnable sensor/daemon and built; **field-
verified** = shown on a real robot, real DDS traffic or real hardware.
Nothing is field-verified yet. `Cargo.lock` is committed and the CI
workflow is complete (pure crates, Pulsar-bound crates, scripts, fuzz
smoke), but it has not yet run on a hosted runner (see `docs/BUILD.md`);
every job's commands are run locally instead. The Pulsar-bound crates are
built and tested against the vendored Pulsar and `robodr-pulsard` was run
as root with eBPF probes loaded in WSL2 (`docs/PULSAR-INTEGRATION.md` §7b),
not on a robot. Status blocks dated before those facts keep their wording.
Work that happened out of order (much of Phase 2's pure logic) is recorded
under its planned sprint.

---

## Phase 1 — Detect on one defence UGV (Sprints 1–5)

Goal of the phase: on a ROS 2 UGV companion computer, catch an unknown
participant, an unauthorized motion/command publisher, and a host compromise,
visible in one console and flowing into the SOC — all air-gapped. Exit = the
Phase 1 criteria in the roadmap.

Defence note: attestation (Sprint 3 spike → brought forward from Phase 3) and
air-gapped build/packaging (Sprint 1) lead here because the captured-unit and
no-cloud threats are Phase 1 realities for a defence platform, not later ones.

### Sprint 1 — Lab up, pipeline green, air-gapped and classified

Objective: an air-gapped lab with a UGV producing real DDS traffic, the code
building and testing in CI off an internal mirror, and the export classification
decided before anything leaves the team.

Added defence tasks this sprint (on top of the general Sprint 1 work below):
- **E3:** Stand up the internal crate/image mirror; CI builds with no public
  internet; emit an SBOM per build.
- **Lead/E1:** Produce the export-control classification memo and split the repo
  into open-core vs. controlled-defence before any external sharing.

- **E2:** Stand up Gazebo + `turtlebot3` (or equivalent) on ROS 2; capture real
  SPDP/SEDP traffic to `pcap` fixtures checked into `crates/robodr-rtps/tests/fixtures/`
  (the parser moved to `robodr-rtps`; see that directory's README for the
  procedure).
- **E1:** Wire Pulsar as a submodule into CI; get `cargo test -p robodr-events`
  and `-p robodr-sensor-ros2` green on a hosted runner; publish the first
  `pulsard` build with the RoboDR module registered (behind `DEFAULT_ENABLED = false`).
- **E3:** Stand up a dev SOC instance with a findings ingest path reachable;
  document the findings contract (now `robodr.findings` 2.x).
- **E4:** Spike: pick the Sentinel Box reference hardware (fanless, ≥2 NIC) and
  the attestation stack (TPM 2.0 + Keylime) to validate in Phase 2/3; no code.
- **Demo:** a Gazebo robot runs; CI is green; a captured SPDP packet replays
  through `rtps::parse_datagram` in a test.
- **Exit:** real `pcap` fixtures exist; CI runs all current tests.

**Status as of 2026-10-17 — exit met in the lab, except CI on the hosted
runner.**
- **Real captures exist** (`fixtures/captures/ros2-jazzy/`, see its README):
  ROS 2 Jazzy in containers, Fast DDS 2.14 and Cyclone DDS 0.10, robot +
  teleop (+ a rogue `/cmd_vel` publisher), replayed through the pipeline and
  the commissioning tool in `crates/robodr-ros2-pipeline/tests/real_captures.rs`.
  They showed that DDS GUID prefixes change on every process start; the
  profile gained `participant_identities` to survive it. Not Gazebo, not a
  turtlebot: a two-node container lab (`tools/lab-capture/`).
- **Update 2026-10-18: Gazebo, DATA_FRAG, Zenoh** (same README, second
  set). A headless Gazebo Harmonic robot (ros_gz bridge,
  robot_state_publisher, live `/odom` to the operator) learned from one run
  and replayed against a restarted run with a rogue: no false positive after
  the fix for DATA arriving before its writer's SEDP (Fast DDS). Real
  DATA_FRAG (small `maxMessageSize` / `FragmentSize`) found two reassembly
  bugs (per-source quota too small for Cyclone's SEDP bursts; interleaved
  per-reader copies left never-completing partial samples), both fixed. A
  robot on `rmw_zenoh_cpp` shows no RTPS at all: that blind spot is now
  reported (`robot.capture.unsupported_middleware`), not decoded. Still no
  turtlebot, no rendering sensors, no 72-hour soak.
- `Cargo.lock` is committed; every job of `ci.yml` (and the build part of
  `release.yml`) passes when run locally on Linux (docs/BUILD.md, "Local CI
  verification"). The hosted runs do not start: GitHub Actions is blocked by
  the organisation's billing, which only the account owner can fix.
- `robodr-pulsard` is built and was run as root with the module registered
  (docs/PULSAR-INTEGRATION.md §7b).

Previous status (2026-10-16), kept for the record:
- **No real capture exists.** Every fixture is synthetic: the `.bin`
  datagrams in `crates/robodr-rtps/tests/fixtures/` are generated byte by byte
  from the DDSI-RTPS spec (their README says so), and the pcap/pcapng files
  used by `robodr-capture`, `robodr-commission` and `robodr-ros2-pipeline`
  tests are built by `robodr_capture::synth` at test time. There is no
  `crates/robodr-sensor-ros2/tests/fixtures/`. No Gazebo lab is evidenced.
- CI: `.github/workflows/ci.yml` is written (pure, Pulsar, MSRV, deny, SBOM,
  fuzz, reproducibility jobs) but has never run, and fails by design until a
  `Cargo.lock` is committed. The Pulsar submodule is wired (`.gitmodules`);
  `robodr-pulsard` registers the module but has never been built.
- Mirror / SBOM: scripts exist (`scripts/ci-setup.sh`, `scripts/sbom.sh`);
  the SBOM fallback is verified in the sandbox; the air-gapped procedure is
  documented, not rehearsed.
- Findings contract: documented (`docs/contracts/`; then `robot-edr.findings`
  1.x, now `robodr.findings` 2.x).
- Export-control memo, Sentinel Box / TPM hardware choice: nothing in this
  repository; status unknown from the code.

### Sprint 2 — See the whole graph (capture SEDP, validate on real traffic)

Objective: writer/reader detection becomes real on live traffic, not just in
unit tests.

- **Done ahead of plan:** SEDP DATA parsing in `rtps` — builtin publications/
  subscriptions writers, `PID_TOPIC_NAME` / `PID_TYPE_NAME` / `PID_ENDPOINT_GUID`,
  LE and BE encapsulation, inline-QoS skip; emits `Ros2WriterDiscovered` /
  `Ros2ReaderDiscovered`. Originally 12 parser tests; `robodr-rtps` now has
  121 `#[test]` functions (synthetic inputs) incl. an end-to-end "foreign
  `cmd_vel` writer on the wire → Critical"; a 500k-iteration mutation fuzz
  (now an `#[ignore]`d test, 20k iterations by default) with overflow checks
  on found no panics.
- **E1 + E2 (pair):** Capture-based listener. SEDP is usually *unicast* to each
  participant's metatraffic port, so the current SPDP multicast socket mostly
  never sees it. Add an AF_PACKET (or eBPF socket-filter) listener on the
  robot's interfaces + loopback for the RTPS metatraffic port range, feeding the
  same `rtps::parse_datagram`. Read-only, no injection.
- **E2:** Per-vendor validation (Fast DDS, Cyclone DDS, Connext): does local
  discovery stay on UDP or move to shared memory? Record the answer per vendor;
  if shared memory, plan the SHM-observation path.
- **E1:** Port the mutation fuzz into `cargo-fuzz` seeded with the captured
  `pcap`s, and run it in CI.
- **E2:** Extend the ROS 2 topic de-mangling (`rt`/`rq`/`rr`) and add fixtures
  for services and actions, not just topics.
- **E3:** Define the OCSF mapping for robot findings (envelope fields plus an
  OCSF Detection Finding) as a typed struct shared with the SOC bridge.
- **Demo:** on the Gazebo robot, the sensor prints the live participant/topic
  graph; a `cmd_vel` publisher shows up as a writer on `/cmd_vel`.
- **Exit:** writer/reader events carry real topics; fuzzing runs in CI.

**Status as of 2026-10-16 — exit NOT met** (no real traffic; CI never ran).
- Capture-based listener: **pure logic done.** `robodr-capture` (AF_PACKET,
  optional kernel BPF filter, pcap/pcapng, IP reassembly; never transmits)
  feeds `robodr-ros2-pipeline`, which `robodr-sensor-ros2` wraps (integration
  written, never compiled). Live AF_PACKET is tested on loopback only, with
  test-generated datagrams, when the test has `CAP_NET_RAW`.
- DATA_FRAG reassembly added (`robodr_rtps::FragmentReassembler`, bounded).
- cargo-fuzz harness: `fuzz/` exists, seeded with the **synthetic** corpus
  (no captured pcaps exist); the CI `fuzz` job is defined, never run.
- De-mangling of `rt`/`rq`/`rr` incl. actions: done in `robodr-events`
  (`graph.rs`); synthetic service and action fixtures exist.
- OCSF mapping as a typed struct: **pure logic done** as `robodr-ocsf` in this
  repo (schema-checked); the SOC-side bridge is not here.
- Per-vendor UDP-vs-shared-memory validation: not done.

### Sprint 3 — Learn and lock the profile

Objective: a robot's "normal" is captured automatically, not hand-written.

- **E2:** Commissioning tool (`robodr-commission`): runs the sensor in observe
  mode over a clean run, records participants, writer topics and observed motion
  ranges, emits `profile.json`; the OEM reviews and sets `locked: true`.
- **E1:** Observe-mode semantics in the sensor: while `locked == false`, report
  deviations but mark them observe-only; add the motion-range learning hook.
- **E3:** Profile storage and versioning in the control plane (a profile is a
  signed, versioned artifact; rollback supported).
- **E4:** Validate TPM measured-boot read on the reference board (feeds Phase 3).
- **Demo:** run commissioning on the Gazebo robot → a `profile.json` → lock it →
  re-run and get zero deviations on a clean run.
- **Exit:** a locked profile produced by the tool, not by hand.

**Status as of 2026-10-16 — met offline only** (the demo on a robot is not done).
- `robodr-commission`: **pure logic done** — `learn` / `diff` / `merge` /
  `lock` / `check` CLI over JSONL event recordings and pcap/pcapng;
  learn → lock → check over the same clean run gives zero deviations
  (property-tested on synthetic runs). Motion envelopes are learned from
  recorded motion events; a pcap alone gives discovery only.
- Observe-mode semantics: findings are stamped observe / enforce in
  `robodr-ros2-pipeline` (an unlocked or invalid profile runs observe-only).
- Control-plane profile storage, TPM measured-boot read: not done.

### Sprint 4 — Host rules + SOC bridge

Objective: host-level robot threats and graph deviations both reach the SOC.

- **E1:** Run `rules/robodr/*.toml` (offline-validated by `scripts/validate_rules.py`;
  see `rules/README.md` "Still unverified") on a real Pulsar daemon on the
  controller; tune to the robot's actual control stack to hit the false-positive bound.
- **E3:** Ship the SOC's robot source-trust map (sensor vs adversary fields,
  contract §9) and a robot-action category that is never autonomous.
- **E3:** Kafka publisher from the control plane to the findings topic;
  findings carry black-box evidence links.
- **E2:** 72-hour clean-run soak on the Gazebo robot; record the false-positive rate.
- **Demo:** a reverse shell on the controller and a rogue DDS participant both
  appear as findings in the SOC console, correctly categorised.
- **Exit:** findings flow end to end; soak FP rate under the agreed bound.

**Status as of 2026-10-16 — exit NOT met.**
- `rules/robodr/*.toml` (7 files) pass `scripts/validate_rules.py`; never
  loaded by a real Pulsar daemon.
- Findings: OCSF envelope, record key and partitioning (`robodr-ocsf`) and
  evidence links (`robodr-agent`) are **pure logic done**; the std-only
  publisher `robodr-kafka-publish` delivers them to the findings topic and
  was verified against single-node Apache Kafka 3.9.1 and 4.1.0 brokers
  (`scripts/kafka-it.sh`, 2026-10-17); not run against the SOC's cluster.
  SOC-side changes are not in this repo.
- 72-hour soak: not done.

### Sprint 5 — Phase 1 hardening + red-team gate

Objective: prove Phase 1 against real attacks; close the phase.

- **Shared:** Red-team week. Reproduce in the lab: (a) a foreign `cmd_vel`
  publisher, (b) a rogue participant, (c) the SROS 2 keystore-exfil case
  (authenticated-but-unprofiled participant). Each must be caught at the
  severity the roadmap states.
- **E1/E2:** Fix whatever the red team slips past; add each attack to the eval corpus.
- **E3:** First console view of a single robot's live posture for the design partner.
- **Demo:** design-partner OEM sees their robot's posture; a spoofed command is
  caught live.
- **Exit (phase gate):** all Phase 1 roadmap exit criteria met; corpus has the
  three attacks as regression tests.

**Status as of 2026-10-16 — not started** (needs the lab). Synthetic
regression tests for a foreign `cmd_vel` writer and a rogue participant exist
in the pure crates; they are not red-team results.

---

## Phase 2 — Respond safely, reach closed controllers (Sprints 6–11)

Goal: graded safety-aware response, the Motion Firewall, and the agentless
Sentinel Box. This is where RoboDR stops only watching and starts acting.

### Sprint 6 — Motion/feedback consistency sensor

- **E2:** `robodr-sensor-motion`: subscribe to command and feedback (odometry,
  joint state, IMU); detect sustained command↔feedback divergence (the injected-
  telemetry class). Pure detector in `robodr-events`, I/O in the sensor.
- **E1:** Extend the event model with `MotionCommand`/feedback correlation state.
- **E4:** Sentinel Box OS image: minimal, read-only root, dual-NIC, TAP/SPAN capture.
- **Demo:** injected fake odometry on the Gazebo robot raises a consistency deviation.

**Status as of 2026-10-16:** detector **pure logic done** as its own crate,
`robodr-motion` (not in `robodr-events` as planned), with synthetic scenario
tests. No sensor subscribes to topics yet; `robodr-cdr` (ROS 2 CDR motion
decoder) is in progress. Sentinel Box image: not started.

### Sprint 7 — Motion Firewall v1 (in-path gateway)

- **E2 + E1 (pair):** `robodr-firewall` as a ROS 2 command gateway: every motion
  command passes through, checked against envelope + allowed source set; passes /
  limits / rejects. Deterministic, fixed latency budget, no alloc in the hot loop.
- **E1:** Latency + jitter harness: control-loop jitter, firewall on vs off; a
  regression over budget fails the build.
- **Demo:** an over-envelope command is limited without stopping a healthy run;
  jitter within budget.

**Status as of 2026-10-16:** decision core **pure logic done**
(`robodr-firewall`: pass / limit / reject, allocation-free hot path checked by
an `alloc_free` test). No ROS 2 gateway. A latency micro-benchmark exists
(`examples/latency.rs`, run by hand); no control-loop jitter harness and no
CI gate.

### Sprint 8 — Cyber-Jidoka responder

- **E1:** `robodr-responder`: the five-step ladder (record → restrict → limit
  motion → safe pause → request safe state), chosen by severity × safety state.
  Response profiles per model, OEM-validated. Never overrides the safety system.
- **E3:** Response actions as SOC action classes (the catalog's wire names
  `robot_restrict_motion`, `robot_safe_pause`, …), all approval-gated, none
  autonomous; a SOC-side executor that sends them to the control plane.
- **Demo:** a Critical deviation on a moving robot → "request safe state", logged
  and evidenced; the safety PLC remains final authority.

**Status as of 2026-10-16:** planner **pure logic done** (`robodr-responder`,
incl. the vendor-neutral action catalog `actions`, all non-autonomous). It executes
nothing: `robodr-agent` composes it into an offline chain with no-op /
logging executors only. `robodr-agentd` (runtime daemon) is in progress.

### Sprint 9 — Signed black-box + evidence chain

- **E1:** Hash-chained, signed event recorder; cyclic + saturation modes; store-
  and-forward when disconnected.
- **E3:** Evidence links on every finding; forensic timeline in the console.
- **E4:** Sentinel Box carries the recorder for cells it watches.
- **Demo:** a tamper of the evidence log is detectable; a case opens with a
  replayable timeline.

**Status as of 2026-10-16:** recorder **pure logic done** (`robodr-blackbox`:
hash chain, cyclic / saturation retention, export bundles, tamper tests).
Signing (updated): Ed25519 by default through the audited `ed25519-dalek`
crate (`robodr-blackbox` key format v2, public `.pub` for verifiers; legacy
HMAC-SHA256 still loads with a warning). Keys are 0600 files, not yet
non-exportable (TPM-held keys are later work; a TPM NV counter head anchor
exists, tested on swtpm). Evidence links on findings: in `robodr-agent` /
`robodr-ocsf`. Console timeline, Sentinel Box: not done.

### Sprint 10 — Sentinel Box: first closed controller

- **E4 + E2:** Vendor control-API connector for one brand (ABB Robot Web Services
  or OPC UA): periodic program/config snapshot, change detection, event logs.
- **E4:** Passive network detection on the cell (reuse the core; sensors differ).
- **Demo:** an out-of-window program change on a real closed controller is caught
  via its vendor API, with no agent inside the controller.

**Status as of 2026-10-16:** not started.

### Sprint 11 — Phase 2 gate

- **Shared:** Red-team against the firewall and responder (RoboPAIR-style unsafe
  command; injected telemetry). Latency budget holds under load.
- **Exit (phase gate):** all Phase 2 roadmap criteria; Sentinel Box flags a
  closed-controller change; firewall holds budget; responder validated with the OEM.

**Status as of 2026-10-16:** not started.

---

## Phase 3 — Attestation, air-gap, second robot family (Sprints 12–17)

Goal: trust the robot's identity, run with no network, extend off Linux to
RTOS/drones.

- **Sprint 12 — Attestation:** `robodr-attest` (TPM 2.0 measured boot + IMA);
  fleet verifier (Keylime-based); trust states Verified / Deviation / Unknown;
  disconnected robots decay to Unknown. *Catches the UniPwn rooted-firmware class.*
- **Sprint 13 — Air-gap packaging:** offline install bundle (images, crates, model);
  signed, versioned, rollback-able update bundles; entry-station scan via Robot
  Analyzer; local time source for the evidence chain. Split into **13a**
  (formats + quorum release signing), **13b** (on-unit agent: install, health
  gate, rollback, floors, safety-state gate) and **13c** (TPM sealing,
  crypto-erase, no-TPM fallback); see
  [`SECURE-DELIVERY.md`](SECURE-DELIVERY.md) §10.
- **Sprint 14 — Air-gap bring-up + single-box control plane:** full isolated
  install; evidence egress via one-way export; no outbound connectivity.
  Split into **14a** (`robodr-depot`: enrolment, deployments, rings, operator
  quorum), **14b** (site lease, crypto-erase as the first executed response,
  delivery findings) and **14c** (OS A/B updates, real TPM hardware); see
  [`SECURE-DELIVERY.md`](SECURE-DELIVERY.md) §10.
- **Sprint 15 — Lite SDK (RTOS/MCU):** C agent for Zephyr/FreeRTOS/NuttX; signed
  event summaries; heavy analysis on the companion computer or Sentinel Box.
- **Sprint 16 — Bus Tap + drone family:** `robodr-sensor-bus` (CAN/EtherCAT/
  MAVLink/1553); PX4/ArduPilot module; detect an unsigned MAVLink mode change.
- **Sprint 17 — Compliance + Phase 3 gate:** IEC 62443-4-2 evidence package for
  the agent; CRA reporting workflow; ISO 10218-2:2025 / EU Machinery Reg 2023/1230
  alignment. *Exit:* tampered firmware fails attestation; full air-gapped
  detect+respond; Lite SDK catches the MAVLink case.

**Status as of 2026-10-16:** Sprints 12–17 not started, except: the black box
already tags timestamps with their time source (`robodr-blackbox` `time`
module), and `robodr-diode` (one-way export, Sprint 14) is in progress.

**Status as of 2026-10-26 — Sprint 13a: pure logic done** (formats and
release signing, [`SECURE-DELIVERY.md`](SECURE-DELIVERY.md) §3, §3.5,
§10). `robodr-pkg` (pure parsers and validators for RPK, bundle,
deployment, trust file and quorum signature sets) and `robodr-release`
(`build rpk`, `build bundle` with Reed-Solomon parity through
`robodr-diode`'s code, `sign`, `verify`, `repair`). The exit criteria are
demonstrated by tests, offline, on synthetic payloads in temporary
directories: a bundle built and signed in one tree verifies in another
that holds only the bundle, the trust file and the pinned root
fingerprints (`crates/robodr-release/tests/cross_host.rs`, through the
binary); every single-byte change of `bundle.json` and `MANIFEST.json`,
missing signatures, a wrong quorum, revoked keys, chain gaps, replays,
equivocations and the review's forgery attempts are refused
(`tests/forgery.rs`); five `pkg_*` libFuzzer targets with std-only smoke
runs (`fuzz/README.md`). Not done: 13c (sealing), the entry-station
scan, any run on a real site or robot.

**Status as of 2026-10-26 — Sprint 13b: unit agent done, offline**
([`SECURE-DELIVERY.md`](SECURE-DELIVERY.md) §10, "13b status").
`robodr-deliverd` installs `files`, `config`, `deb` and `robodr-rules` RPKs
from per-unit media packs (verified-copy import, the unit's own trust
anchor, ring and unit checks), from a content-addressed store, behind
agentd's live safety-state gate, with a health gate (probes without a
shell, as an unprivileged UID, bounded), automatic rollback,
anti-rollback floors in a crash-safe state file, black-box evidence and
the `robot.deliver.*` findings (contract 2.2) in agentd's spool;
`robodr-safety-replay` replays recorded safety reports into agentd's
socket. Exit criteria shown by tests: a bad release rolls back, a
downgrade below the floor is refused, the install waits while a real
agentd's replayed state is `moving_slow` and proceeds at `idle`, all in
the black box; plus a crash at every step and the adversarial cases.
Shipped in both packages (`robodr-deliverd.service`, installed disabled).
Not done: 13c, 14a–c, any run on a robot.

**Status as of 2026-10-30 — Sprint 13c: sealing done, against a software
TPM** ([`SECURE-DELIVERY.md`](SECURE-DELIVERY.md) §7.9, §10 "13c
status"). `robodr-seal` (library and CLI): sealed RPKs (XChaCha20-Poly1305
chunks bound to their place, key commitment, keyed file digests;
`robodr-release build rpk --seal-to`), content-key wraps release → depot →
unit, a P-256 UWK created inside the TPM and usable only under a PCR
policy signed by the policy authority, a policy floor (older signed
policies revoked in the TPM) and an erase epoch; the LUKS2 runtime volume
keyed through the UWK; the Clevis/Tang fallback. `robodr-deliverd`
installs sealed RPKs and every model only into the mounted dm-crypt
runtime volume and crypto-erases (`erase`); `robot.seal.*` findings
(contract 2.3). Exit criteria shown by tests against swtpm 0.7.3 +
tpm2-tools 5.6, a real Tang server and `cryptsetup` on image files: a
disk image of an enrolled unit yields no plaintext, a changed PCR refuses
unseal, an epoch increment kills every sealed key, a fallback unit cannot
unlock without Tang; plus policy and epoch rollback, wrong-unit and
tampered wraps, chunk reordering / truncation / swaps, nonce reuse. Not
done: the dm-crypt open path (no device-mapper in the test container;
gated test), a hardware TPM, EK / AK certification (14a), erase triggers
and lease (14b), a libFuzzer campaign of the two new targets. An
adversarial review of 13c (two high, two medium, three low findings:
floor rollback without a TPM owner authorization, a fallback erase that
destroyed nothing, an open volume left readable, session contexts on
disk) is fixed with regression tests; `robodr-seal` is packaged and the
agent's unit reaches the TPM.

**Status as of 2026-10-30 — Sprints 14a and 14b: site depot, leases and
executed erase done, against software TPMs**
([`SECURE-DELIVERY.md`](SECURE-DELIVERY.md) §10 "14a status", "14b
status"). `robodr-depot` (library, CLI and `robodr-depot.service`):
import only with a passing signed entry report, inventory, TPM enrolment
(EK certificate chain to a vendor CA listed in the trust file, AK
credential activation, AK-certified UWK and identity key, quote, two
operators), staged rollouts with per-ring quorums, soak and
halt-on-failure, per-unit re-wrapping, mutual-TLS LAN serving with the
unit's key in its TPM, media packs; TPM-enforced site leases; crypto-erase
from the platform's tamper input, planned by the responder and deferred
while the robot moves; anti-rollback floors (unit and depot) anchored in
TPM NV counters; `robot.depot.*` and `robot.seal.erase_deferred`
(contract 2.3). Exit criteria shown by tests against swtpm 0.7 +
tpm2-tools 5.6 on loopback: lab → canary → ring-1 on four units, a
failing release halts at canary, a captured unit cannot decrypt a model
assigned only to another unit; lease expiry blocks unseal after reboot;
erase from a tamper input deferred at `moving_fast` and executed at
`idle`; the full chain of findings through the diode path. An adversarial
self-review fixed a lease based on self-reported TPM time (now
AK-attested), a connection-slot exhaustion and trust-file compatibility.
Not done: 14c (OS A/B, hardware TPM, a robot), depot keys in a TPM / HSM,
a signed remote erase command, libFuzzer runs of `pkg_entry` and
`seal_attest`.

---

## Phase 4 — AI-robot security + the frontier lab (Sprints 18–21)

Goal: secure LLM/VLA robots, and turn fleet telemetry into a research and model
advantage.

- **Sprint 18 — AI Guard (AIDR):** policy over the planner's tool/task calls on
  VLA/LLM robots; the Motion Firewall is the backstop a jailbroken or backdoored
  model cannot pass. *Covers RoboPAIR, BadVLA, SilentDrift.*
- **Sprint 19 — Robot-attack benchmark (public):** reproduce RoboPAIR, SROS 2
  keystore exfil, telemetry injection, VLA backdoors as a published benchmark
  others are measured against. Owning the benchmark is how a lab leads the field.
- **Sprint 20 — Foundation model v0:** train on fleet robot-behaviour telemetry
  (graph, motion, feedback, bus); must beat the rule+profile baseline on the
  held-out corpus (injection tests placed in ROS node/topic names).
- **Sprint 21 — Agentic robot SOC + OEM edition:** robot-specific hunt/root-cause
  workflows; a confirmed root cause ships a signed rule fleet-wide (poka-yoke);
  white-label console + OEM edition. *Exit:* a jailbroken planner's unsafe command
  is blocked by the firewall and explained by the SOC; the model beats baseline.

**Status as of 2026-10-16:** not started.

---

## Rhythm and tracking

- **Cadence:** 2-week sprints; demo on the last day; one day of planning on day 1.
- **Phase gates:** a phase does not close until its roadmap exit criteria are met
  and its attacks are regression tests in the eval corpus.
- **Backlog home:** each sprint's tasks become GitHub issues at sprint planning,
  labelled by phase and owner; the eval corpus grows every red-team week.
- **Hardware long-lead items** (Sentinel Box boards, a closed controller, a drone
  flight controller, TPM dev boards) are ordered in Sprint 1 so they arrive before
  the sprint that needs them.
- **What is NOT scheduled here** and gets its own planning when the team size is
  known: hiring, sales/pilot contracts, certification lab bookings, and the legal
  review of the Pulsar GPL-2.0 eBPF components for commercial distribution.
