# RoboDR engineering roadmap

This is the build plan: what we are defending against, the architecture, the
components in dependency order, and the phases with their exit criteria. It is
written to be executed, not admired — every phase ends in something that runs on
a real robot and something a customer can see.

The guiding principle is **earn each layer**. We ship the smallest thing that
protects a real robot against a real, demonstrated attack, then widen. We do not
build the foundation model before we have the telemetry to train it, and we do
not build inline enforcement before passive detection is trusted on a line.

---

## 0. The threat landscape we are building against

Every component below traces to a demonstrated attack. This is the evidence base
that makes RoboDR a response to reality, not a feature list.

| Attack | What it showed | RoboDR answer |
|---|---|---|
| **RoboPAIR** (Robey et al., 2024) | Jailbreaking an LLM planner drove a Unitree Go2, a Clearpath Jackal and an NVIDIA self-driving stack to harmful physical actions, often at 100% success. | Motion Firewall: the planner's output is checked against a physical envelope regardless of how it was produced. |
| **UniPwn** (Makris & Finisterre, 2025) | Hardcoded BLE keys gave root on Unitree Go2/B2/G1/H1; wormable across a fleet over the air. | Attestation (catch rooted/modified firmware), network sensor (catch the BLE/Wi-Fi setup path and lateral scan). |
| **Secure ROS 2 keystore exfiltration** (Sakib et al., MILCOM 2025) | A trojaned Debian package leaked SROS 2 keystores; the attacker rejoined as an *authenticated* participant and published spoofed stop-sign and motion messages. | ROS 2 graph sensor (a key-valid but profile-unknown participant is still flagged) + Robot Analyzer (catch the trojaned package pre-deploy). |
| **"Seeing is Not Believing"** (Shen et al., 2026) | One env var loaded a hook into Secure ROS 2 that injected fabricated telemetry *and* control, fooling an AI detector 87% of the time on a real Franka arm. | Motion/feedback consistency check + attestation of the runtime, not just the host. Telemetry we verify is sensor-authored, not process-authored. |
| **BadVLA / SilentDrift** (2025–26) | Near-100% backdoors in vision-language-action models, stealthy and surviving fine-tuning; SilentDrift hides in the action-chunk approach phase. | AI Guard (AIDR) on VLA/LLM robots + Motion Firewall as the backstop the model cannot talk its way past. |

Defence-platform threats raise the same two lessons in a harder setting —
contested comms, no cloud, and an adversary who may physically hold a unit:

| Threat (defence) | What it is | RoboDR answer |
|---|---|---|
| **C2 / datalink compromise** | Spoofed or replayed command-and-control over a contested RF link; injected waypoints or mode changes. | Command source + envelope check at the robot; signed-command verification; link-integrity sensor. Enforcement is local, never cloud-dependent. |
| **GNSS / navigation spoofing** | Falsified position/time drives the platform off-mission. | GNSS-vs-inertial consistency check (sensor-authored vs claimed), flagged as a navigation deviation. |
| **Captured-unit exploitation** | An adversary physically recovers a platform and extracts keys, firmware or mission data, or re-flashes it. | Measured-boot attestation + sealed keys; tamper response; a unit that fails attestation never rejoins the fleet at trust. Software, models and mission config delivered by RoboDR are encrypted at rest under keys sealed to the unit's TPM and measured boot, with an optional site lease and cryptographic erase ([`SECURE-DELIVERY.md`](SECURE-DELIVERY.md) §7, design only). (Physical zeroization/anti-tamper remains the platform's job.) |
| **Supply-chain / sovereignty** | Trojaned package or dependency (cf. the SROS 2 keystore case) in a platform that must run with no outside connectivity and under export control. | Entry-station Analyzer scan of every offline bundle; quorum-signed, versioned, rollback-able updates with anti-rollback floors and staged fleet rollout ([`SECURE-DELIVERY.md`](SECURE-DELIVERY.md), design only); on-prem/air-gapped by default; no component phones home. |

Two lessons set the architecture:

1. **Authentication is not authorization.** SROS 2 and DDS Security verify *who*
   signed a message, not whether the message is *plausible* for this robot now.
   Every demonstrated 2025–26 attack that mattered was authenticated. RoboDR's
   job is the plausibility layer: the model profile and the motion envelope.
2. **The host can be clean while the robot is compromised.** Defence must reach
   the DDS graph, the motion path and the hardware root of trust — not stop at
   process/file/network. That is precisely the gap above Pulsar.

---

## 1. Architecture principles (the non-negotiables)

1. **Platform-shaped sensors, one brain.** Four collector forms — Full Agent
   (Linux), Lite SDK (RTOS/MCU), Sentinel Box (agentless, for closed
   controllers), Bus Tap (fieldbus) — feed one event model, one detection core,
   one console. New robot kinds are new sensors, not new products.
2. **The detection core is pure and portable.** `robodr-events` has no I/O. The
   same `Profile::evaluate` runs on the controller, in the Sentinel Box and in
   CI. Decisions are testable without a robot.
3. **Safety-aware response, never safety-replacing.** RoboDR proposes and, at
   most, requests a safe state. The functional-safety system (e-stop, safety
   PLC, per ISO 10218 / ISO 13849 / IEC 61508) is always the final authority.
   RoboDR is not a safety-rated component and never claims to be.
4. **Observe before enforce.** A fresh install reports only. Enforcement for a
   robot model is turned on by the OEM, per action class, after the profile is
   locked and false-negative bounds hold.
5. **Offline by default.** Detection and response run on the robot. The cloud is
   for visibility, policy and analysis — removable without losing protection.
6. **Deterministic on the control path.** Only the Motion Firewall sits in-path,
   with a fixed latency budget and no dynamic allocation in the hot loop.
7. **Protective scope only.** RoboDR defends a platform from compromise. It does
   not target, it does not control weapons or effects, and it never overrides a
   platform's safety or weapons-safety interlocks. It detects, refuses trust, and
   requests a safe state; the platform's own safety and command authority remain
   final. Attack reproduction lives only in the lab eval corpus, to prove our
   detection — never shipped as an operational capability.
8. **Sovereign, air-gapped, export-aware.** For defence the default deployment is
   on-prem/air-gapped with no outbound connectivity; builds are reproducible from
   source we hold (Pulsar is vendored, not pulled at build time); crypto and
   model choices allow a sovereign variant; and export-control classification is
   decided before anything ships (see §3 and SPRINTS.md).

### Defence-first sequencing

This is a defence company, so the first platform is a **defence ground UGV**
(Linux + ROS 2 companion computer over a CAN / MIL-STD-1553 lower stack), run
**air-gapped**, not an industrial AMR. That pulls three things the roadmap
otherwise placed later into the front: **attestation** (captured-unit threat),
**air-gapped packaging** (no cloud in the field), and the **Bus Tap** for the
fieldbus. Industrial/commercial robots become a later, lower-assurance
derivative of the same core — not the other way round. The phase goals below are
written for that target; the component dependency order is unchanged.

---

## 2. Component map (dependency order)

```
                 ┌──────────── robodr-events (pure core)                   [P]
                 │   RobotEvent taxonomy · Profile · Deviation · graph
                 ▼
 ┌───────────────────────────── sensors ──────────────────────────────────────┐
 │ robodr-sensor-ros2   DDS/RTPS graph        (Full Agent)   [P] [I-unbuilt]
 │   ├ robodr-rtps          SPDP/SEDP parser + DATA_FRAG                [P]
 │   ├ robodr-capture       pcap replay + AF_PACKET (passive)           [P]
 │   └ robodr-ros2-pipeline parse → profile → dedup → findings          [P]
 │ robodr-sensor-ebpf   process/file/net+LSM  (reuse Pulsar)  [~] rules only
 │ robodr-sensor-motion motion cmd + feedback (Full Agent)    [P] detector
 │   ├ robodr-motion        consistency detector                        [P]
 │   └ robodr-cdr           ROS 2 CDR motion decoder                    [~]
 │ robodr-sensor-bus    CAN/EtherCAT/MAVLink  (Bus Tap)        [ ]
 │ robodr-attest        TPM/IMA measured boot                  [ ]
 └─────────────────────────────────────────────────────────────────────────────┘
                 │ all emit RobotEvent / Pulsar threats
                 ▼
 robodr-firewall   Motion Firewall decision core              [P] (no gateway)
                 │
                 ▼
 robodr-responder  Cyber-Jidoka response planner              [P] (no executor)
 robodr-blackbox   signed, hash-chained evidence              [P] (HMAC interim)
 robodr-agent      offline chain: event→plan→evidence→finding [P]
 robodr-agentd     runtime daemon hosting the chain           [~]
                 │ signed evidence ↕ signed policy/rules
                 ▼
 robodr-diode      one-way export (air-gap)                   [~]
 robodr-fleet      control plane · attestation verifier · console [ ]
 robodr-depot      air-gap fleet delivery (SECURE-DELIVERY)   [ ]
   ├ robodr-pkg       RPK / bundle / deployment formats       [ ]
   ├ robodr-deliverd  on-unit install, rollback, safety gate  [ ]
   └ robodr-seal      TPM-sealed payload keys, crypto-erase   [ ]
                 │ OCSF findings  (robodr-ocsf mapper          [P])
                 ▼
 SOC (any; robodr.findings v2 + control plane)  triage · hunt · workflows [ ]
```

Legend (status as of 2026-10-16):

| Tag | Meaning |
|---|---|
| `[P]` | **Pure logic done**: the crate exists, is unit/integration-tested offline on synthetic inputs. No live I/O path proven. |
| `[I]` | **Integrated**: wired into a runnable sensor/daemon, built, and exercised end to end on a host. `[I-unbuilt]` = integration code written but never compiled (Pulsar-bound crates cannot be built in the offline sandbox). |
| `[F]` | **Field-verified**: shown on real robot / real DDS traffic / real hardware. **Nothing is `[F]` yet.** |
| `[~]` | In progress (crate being written). |
| `[ ]` | Planned; no code. |

---

## 3. Phases

Each phase names its deliverable, the exit criteria that let us move on, and the
customer-visible result. Durations are deliberately omitted; the exit criteria,
not a calendar, gate each phase.

### Phase 1 — Detect on one defence UGV (MVP)

**Goal:** On a ROS 2 Linux UGV companion computer (bench or Gazebo first, then a
real controller), detect an unknown DDS participant, an unauthorized motion/
command publisher, and a host compromise, and surface them in one console — with
everything running with no outbound connectivity.

- `robodr-events` pure core with model profile + envelope. **[P]**
- `robodr-sensor-ros2` passive SPDP + SEDP sensor raising profile deviations.
  **[P]** for the pipeline (`robodr-rtps`, `robodr-capture`,
  `robodr-ros2-pipeline`, incl. live AF_PACKET on loopback in tests);
  **[I-unbuilt]** for the Pulsar module (`robodr-sensor-ros2`,
  `robodr-pulsard`: written, never compiled, no tests).
- Reuse Pulsar's process/file/network + LSM probes unchanged; add `rules/robodr/*.toml` (Pulsar TOML rules, see `rules/README.md`).
  **[~]** rules written and checked by `scripts/validate_rules.py`; never
  loaded into a Pulsar rules engine.
- Observe-mode profile learning: a commissioning tool records the graph and
  envelopes over a clean run, emits a `profile.json`, the OEM locks it.
  **[P]** `robodr-commission` (`learn` / `diff` / `merge` / `lock` / `check`,
  from JSONL event recordings or pcap/pcapng); never run on a real robot.
- Bridge threats to the SOC through the vendor-neutral findings contract
  (`robodr.findings` 2.x: robot source-trust map, never-autonomous robot
  actions; see the contract's consumer checklist).
  **[P]** for the OCSF mapping and contract (`robodr-ocsf`,
  `docs/contracts/`) and the std-only publisher `robodr-kafka-publish`
  (verified against single-node Apache Kafka 3.9.1 and 4.1.0,
  `scripts/kafka-it.sh`); SOC side not done.

**Exit criteria.** On a real UGV companion computer: a foreign `cmd_vel`
publisher is flagged Critical *from live traffic* (SEDP parser done; needs the
capture listener); a rogue participant is flagged High; a reverse shell on the
controller is flagged; false positives on a 72-hour clean run are under an
agreed bound.

**Customer-visible:** a design-partner OEM sees their robot's live security
posture in the console; a red-team spoofed command is caught.

### Phase 2 — Respond safely, and reach closed controllers

**Goal:** Turn detection into graded, safety-aware response, and cover robots we
cannot put an agent inside.

- `robodr-firewall` (Motion Firewall), v1 as a ROS 2 command gateway
  (**[P]** decision core only; the gateway and CDR decoding, `robodr-cdr`
  **[~]**, are not done): every
  motion command passes through, is checked against the envelope and the allowed
  source set, and is passed / limited / rejected. Deterministic, fixed latency
  budget, fail-safe behaviour defined per model by the OEM.
- `robodr-responder` (Cyber-Jidoka): the five-step graded ladder (record →
  restrict → limit motion → safe pause → request safe state), choosing by
  deviation severity × current safety state. Response profiles validated per
  model with the OEM. **[P]** planner only; executes nothing (no executor).
- `robodr-sensor-motion`: the motion/feedback consistency check that catches the
  "Seeing is Not Believing" injected-telemetry class. **[P]** detector
  (`robodr-motion`); no topic subscription yet.
- **Sentinel Box**: agentless appliance for closed controllers (KUKA, FANUC,
  ABB, Yaskawa). Passive network + vendor control-API connectors + black-box
  recorder. Pure detection core reused unchanged; only the sensors differ.
- Signed, hash-chained black-box evidence; evidence links ride on every finding.
  **[P]** `robodr-blackbox` (HMAC-SHA256 placeholder signer) and evidence
  links in `robodr-agent` / `robodr-ocsf`.

**Exit criteria.** Motion Firewall holds its latency budget under load with
zero control-loop jitter regression (agent on vs off). A staged over-envelope
command is limited without stopping a healthy line. Sentinel Box flags an
out-of-window program change on one closed-controller brand via its vendor API.

### Phase 3 — Attestation, air-gap, and the second robot family

**Goal:** Trust the robot's identity, run with no network at all, and extend off
Linux.

- `robodr-attest`: TPM 2.0 measured boot + Linux IMA, verified by the fleet
  attestation verifier (Keylime-based). A robot with no hardware root of trust
  is never shown at the same trust level; a disconnected robot decays to
  `Unknown`. Catches the UniPwn rooted-firmware class.
- **Air-gapped deployment**: single-box control plane inside the isolated
  network; signed, versioned, rollback-able update bundles carried by data diode
  or vetted media through an entry station (every bundle scanned by Robot
  Analyzer); evidence out via diode. Local time source for the evidence chain.
  Designed in [`SECURE-DELIVERY.md`](SECURE-DELIVERY.md): fleet distribution of
  any software (`robodr-depot`, `robodr-deliverd`), staged updates gated on
  safety state, and captured-unit protection (`robodr-seal`).
- `robodr-sensor-bus` (Bus Tap) + Lite SDK (RTOS/MCU, Zephyr/FreeRTOS/NuttX,
  PX4/ArduPilot): the drone and defence-UGV family. CAN/EtherCAT/MAVLink/1553.
- **IEC 62443-4-2** evidence package for the agent itself; CRA reporting workflow
  (obligations began 11 Sep 2026; full application 11 Dec 2027) and alignment
  with ISO 10218-2:2025's new cybersecurity-relevant control-function
  requirements and the EU Machinery Regulation 2023/1230 (applies 20 Jan 2027).

**Exit criteria.** A tampered firmware image fails attestation and the robot
shows `Deviation`. A full air-gapped install detects and responds with no
outbound connectivity. The Lite SDK detects an unsigned MAVLink mode change on a
PX4 flight controller.

### Phase 4 — AI-robot security and the frontier lab

**Goal:** Secure LLM/VLA-driven robots, and turn our fleet telemetry into a
research and model advantage no one else can match.

- **AI Guard (AIDR)** on VLA/LLM robots: policy over the planner's tool calls and
  tasks; the Motion Firewall is the backstop a jailbroken or backdoored model
  cannot talk past (RoboPAIR, BadVLA, SilentDrift).
- **RoboDR foundation model**: trained on the robot-behaviour telemetry our fleet
  produces (graph, motion, feedback, bus) — a data asset that, like Exein's, is
  hard to replicate, but robot-behaviour-native rather than firmware-generic.
- **Agentic robot SOC**: robot-specific hunt/root-cause workflows in the SOC;
  a confirmed root cause ships a signed new rule to the whole fleet (poka-yoke).
- White-label console and OEM edition: the OEM ships RoboDR inside the robot and
  sells the posture to their own customers.

**Exit criteria.** A jailbroken planner's unsafe command is blocked by the
firewall and explained by the SOC. The foundation model beats the rule+profile
baseline on a held-out attack corpus (our own eval set, with injection tests
placed in ROS node and topic names, as an LLM-based SOC's eval set must be).

---

## 4. What makes this a frontier lab, not a me-too EDR

- **A public robot-attack eval corpus and benchmark.** We reproduce RoboPAIR,
  the SROS 2 keystore attack, the telemetry-injection attack and VLA backdoors
  in a lab, and publish a benchmark RoboDR and others are measured against.
  Owning the benchmark is how a lab leads a field.
- **Robot-behaviour foundation model.** Firmware-generic runtime models already
  exist. A model that knows what *this class of robot doing this task* should
  look like — and flags the subtle drift SilentDrift hides in the approach phase
  — does not. That is our moat and it compounds with every robot we protect.
- **Deterministic safety-aware response as a researched discipline.** Cyber-
  Jidoka — graded response conditioned on physical safety state, provably never
  overriding the safety system — is a publishable contribution, not just a
  feature. It is also what makes OEMs willing to let us act at all.
- **Open where it builds trust, closed where it is the moat.** Sensors and the
  event model open (community and scrutiny, like Pulsar); the foundation model,
  the fleet analytics and the response engine commercial.

## 5. Immediate next actions

1. ~~Finish the SEDP parse in `rtps`~~ — **done [P]** (topic/type/endpoint
   GUID, DATA_FRAG reassembly, tested, fuzzed). ~~Capture-based listener~~ —
   **done [P]**: `robodr-capture` (AF_PACKET + pcap, read-only) feeding
   `robodr-ros2-pipeline`; wired into the Pulsar module but **unbuilt**.
   Remaining: build the Pulsar-bound crates on a connected host and run them
   on real traffic.
2. ~~Build the observe-mode commissioning tool that emits `profile.json`~~ —
   **done [P]** (`robodr-commission`). Remaining: a commissioning run on a
   real or Gazebo robot.
3. Stand up the lab (**not started**; every test so far uses synthetic
   inputs): one ROS 2 AMR (or Gazebo + a real controller) and one
   closed-controller brand, so detection is measured against real traffic.
4. Land the SOC-side robot source-trust map and never-autonomous robot
   action category (consumer checklist, `docs/contracts/robodr.findings.md`
   §9) so Phase 1 findings flow into the SOC.
