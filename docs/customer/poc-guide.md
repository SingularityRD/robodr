# POC guide

> **Pre-release draft (2026-10-30).** How a proof of concept with RoboDR
> runs: what to check before it starts, a four-week plan, measurable exit
> criteria, how to handle the captured data, and the readout template.
> RoboDR is alpha software (`0.1.0-alpha`); everything has been verified
> in labs only ([`support-matrix.md`](support-matrix.md),
> [`known-limitations.md`](known-limitations.md)). A POC is therefore also
> the first time RoboDR meets your robot: plan it as a joint evaluation,
> observe-only, with nothing in the motion path depending on RoboDR.

## 1. Qualify first (week 0)

Answer these before anyone travels. A "no" in the right-hand column does
not end the POC, but it changes what it can show.

| Question | Why it matters | Limits if not met |
|---|---|---|
| Which middleware: ROS 2 distribution, DDS implementation and version, `RMW_IMPLEMENTATION`? | RoboDR decodes ROS 2 over DDS/RTPS (Fast DDS, Cyclone DDS; Jazzy lab-verified, Humble / Foxy synthetic) | **Zenoh** is detected but not decoded; **RTI Connext** is untested; **DDS-Security / SROS2** payloads cannot be inspected (discovery only, depending on settings) |
| Unitree robot? Which model and firmware, EDU computer image (JetPack 5 or 6)? | Model support and package choice ([`docs/UNITREE.md`](../UNITREE.md)) | No real Unitree capture has been tested; JetPack 5 gets `robodr-focal` without host rules |
| Where can RoboDR see traffic: a mirror port or tap on the robot's network, or a companion computer we may install on? | Passive sensor box or on-robot agent ([`quick-start.md`](quick-start.md) section 0) | Without a mirror, unicast between the robot's internal computers is invisible |
| Can the host monitor (eBPF) run: kernel with BTF, root, glibc 2.35+, systemd 247+? | Host detections ([platform requirements](support-matrix.md#platform-requirements)) | Network and motion detections only |
| Hardware for a sensor box: x86-64 or arm64 Linux, two NICs if it may later go inline | Runs agentd (and later the gateway) | Any Linux host that meets the requirements will do for observe-only |
| Is the robot's safety state available live (e-stop topic, PLC signal)? | Grades findings and responses by safety state | The state reads `unknown`; findings still flow |
| Where do findings go: AutoSecOps, a Kafka-based SIEM, or stay on the box? | Delivery path | AutoSecOps' RoboDR module is not released yet: use Kafka or read the local spool |
| May captures and findings leave the site? Who approves? | Section 4 | Analysis on site only |
| Which attack scenarios may be run, where, and who is the customer's safety officer? | Section 3 | Replay-only scenarios |

## 2. Plan

Effort figures are estimates for one RoboDR engineer with the customer's
robot engineer; they have not been timed on a customer site.

| Week | Steps | RoboDR effort | Customer effort | Output |
|---|---|---|---|---|
| 0 | Qualification (section 1); agree exit criteria (section 3) and data rules (section 4); sensor-box hardware ready; release media verified on the entry station ([`quick-start.md`](quick-start.md) section 1) | 1 day | 0.5 day | Signed-off POC plan |
| 1 | Install (quick-start section 2); black-box key; capture **clean runs** of every mission (at least 30 minutes of normal operation each); learn a draft profile and start the agent on it in `observe` mode (quick-start section 4a); findings delivery (Kafka or local spool) | 2–3 days | 1–2 days (robot runs, network access) | Agent running, findings flowing |
| 2 | Review every finding on clean operation with the robot engineer: explain or tune (re-learn with more runs, adjust thresholds); sign off and lock the profile (one operator is enough in a lab: `--motion-quorum 1`); measure CPU / RSS | 2 days | 1 day | Locked profile; first false-positive log |
| 3 | Attack scenarios (section 3), each with its injection time recorded; continue clean operation for the false-positive count; evidence export and verification | 2–3 days | 1 day (safety officer present for live scenarios) | Scenario results |
| 4 | Measurements summarised, readout (section 5) | 1–2 days | 0.5 day | Readout |

Keep the executor disabled (`executor.enabled: false`) and, if an inline
gateway is tried, keep it in `mode: observe` for the whole POC.

## 3. Exit criteria

Agree the thresholds in week 0; the "suggested" column is a starting
point, not a RoboDR claim.

| Criterion | How it is measured | Suggested threshold |
|---|---|---|
| Detection per scenario | The scenario's expected rule ids (table below) appear in the spool within the observation window after the recorded injection time | Every agreed scenario detected |
| False positives on clean operation | Findings on clean operation after the profile is locked, each classified with the robot engineer as true / explained / false; per robot per day | Agreed in week 0 (the GA target is < 1 false alarm per robot per day; not yet demonstrated anywhere) |
| CPU and memory | `pidstat -r -u -p $(pidof robodr-agentd) 60` (or `systemctl status`) over at least 24 h of normal operation, on the actual hardware | GA targets: < 5 % CPU, < 150 MB RSS on the robot |
| Time to detect | Recorded injection time → the finding's `first_seen_time` (and, if delivered, the time it reached the SOC) | Agreed in week 0; RoboDR has no published figure yet ([`performance.md`](performance.md)) |
| Evidence integrity | `robodr-blackbox verify` on the black box and on an export bundle, against the robot's `.pub` | `RESULT: INTACT, CLEAN` |
| Delivery | Findings spooled vs received by the SOC / Kafka | No loss |
| Stability | No restart, crash or `robot.agent.*` health finding without a known cause | None |

**Scenarios.** Run live scenarios only on an isolated network segment,
with the robot powered down, in simulation, or with the customer's
safety officer present and the robot's own safety functions active: a
foreign `/cmd_vel` publisher can move a robot. Where that is not
possible, replay a capture of the scenario into the agent instead
(`sensor.capture.pcap_replay`). There is no packaged attack simulator
yet; the scenarios are run by the RoboDR engineer with the lab tooling
in `tools/e2e/` and the lab captures in `fixtures/captures/ros2-jazzy/`.

| Scenario | Expected rule ids (lab result) |
|---|---|
| Rogue ROS 2 participant publishing on a motion topic | `robot.ros2.unknown_participant`, `robot.ros2.unauthorized_motion_writer`, `robot.firewall.rejected_unknown_source`, `robot.motion.linear_over_envelope` (if outside the envelope), `robot.correlate.motion_hijack` |
| Motion command outside the learned envelope | `robot.motion.linear_over_envelope` / `joint_over_envelope` / `angular_over_envelope` |
| GUID spray (many short-lived participants) | `robot.ros2.discovery_flood` (aggregated, not one finding per participant) |
| Malformed or truncated RTPS discovery | `robot.rtps.malformed_discovery`, `robot.rtps.discovery_not_inspected` |
| Safety-state topic published from a foreign address | `robot.safety_state.untrusted_source`, `robot.ros2.participant_source_mismatch` |
| New subscriber reading the robot's topics | `robot.ros2.unknown_reader` |
| Host: a process tripping a Pulsar rule (where `robodr-pulsard` runs) | `robot.host.pulsar_threat` |

The full list of rule ids is in the
[detection catalog](detection-catalog.md).

## 4. Captured data

Captures of the robot's network contain the robot's addresses, topic
names, motion commands and possibly application data on other topics.
Unless the customer agrees otherwise in writing:

- Captures, profiles, black boxes and findings **stay on the customer's
  site**, on the sensor box or the customer's own media. RoboDR staff
  analyse them on site.
- What may leave (for example a findings export for the readout, or a
  capture to reproduce a defect) is listed by file, approved by the
  customer's named contact, and moved on media the customer vetted.
- Capture only the robot's network segment, and only the DDS / RTPS
  traffic needed (a `udp` capture filter); stop captures when the run
  ends.
- At the end of the POC everything RoboDR created is deleted or handed
  to the customer, and the deletion is confirmed in the readout. Keys
  generated for the POC are test keys and are destroyed with it.

## 5. Readout template

1. **Scope and setup**: robot(s), middleware and versions, deployment
   (agent or sensor box), RoboDR release and its verification, dates.
2. **What was run**: missions captured, hours of clean operation,
   scenarios with injection times.
3. **Results against the exit criteria** (section 3): one row per
   criterion with the measured value and pass / fail.
4. **Findings on clean operation**: count per rule, classification, what
   was tuned.
5. **Resources**: CPU and RSS per process on the customer hardware, with
   the hardware, kernel and load.
6. **Gaps seen**: traffic RoboDR could not see or decode, scenarios not
   detected, defects found (with their tracking ids).
7. **Data handling**: what left the site, with the approval, and the
   deletion confirmation.
8. **Next steps**: what a pilot would need (executor or gateway
   enforcement only after OEM validation), open items from
   [`known-limitations.md`](known-limitations.md) that matter for this
   customer.

## 6. Tools

| Need | Tool | Note |
|---|---|---|
| Findings by rule and severity | `tools/e2e/spool-summary.py <spool dir>` | Lab script from the repository, not packaged yet |
| CPU / RSS trend over a soak | `tools/e2e/soak_report.py metrics.csv robodr-agentd` | Lab script; needs the metrics CSV of `soak2_monitor.py` |
| Evidence verification | `robodr-blackbox verify` | Shipped |
| Profile diff after re-learning | `robodr-commission diff old.json new.json` | Shipped |
| Gateway latency on the sensor box | `crates/robodr-firewall-gw/examples/gw_latency.rs --budget-p99-ns` | From source |
