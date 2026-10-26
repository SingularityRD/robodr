# Known limitations

> **Pre-release draft (2026-10-26).** This is a consolidated, deliberately
> blunt list. Each item names its source document, and its planned fix
> where one exists. Sprint numbers refer to GA-ROADMAP. The source
> documents are authoritative. If this page and a source disagree, the
> source wins, and this page should be corrected.

## Maturity

- **Alpha, unreleased.** Version `0.1.0-alpha`. No signed release has been
  cut, and the release signing workflow has never run
  ([`docs/BUILD.md`](../BUILD.md)).
- **No real robot yet.** Everything is verified offline, in container
  labs, under qemu, or with synthetic traffic ([`README.md`](../../README.md)
  "Status"). Field validation with a 72 h soak is S11.
- **False-positive rates are unmeasured** beyond lab captures and a
  benign rule corpus. Thresholds and correlation rules are untuned
  engineering defaults.
- **GitHub CI has never run.** All jobs passed in a local step-by-step
  run ([`docs/BUILD.md`](../BUILD.md), "Local CI verification").

## Response and enforcement

- **Nothing is executed.** The responder plans, agentd's executor
  records, and the control plane answers `recorded_not_executed`
  ([`docs/contracts/robodr.control-plane.md`](../contracts/robodr.control-plane.md)).
  Executing actions are S7 and S8.
- **The Motion Firewall records only.** There is no in-path gateway: a
  command outside the envelope is reported but still reaches the motors
  ([`docs/UNITREE.md`](../UNITREE.md) section 5). Gateway: S8.
- **Humanoids and other balancing robots:** RoboDR will never execute a
  pause or safe state on a humanoid, and never terminates processes on a
  balancing robot. It cannot stop such a robot. That remains the
  platform's safety function
  ([ADR-0012](../adr/0012-balancing-robot-response-rules.md)).
- **Not a safety-rated component**
  ([`docs/compliance/safety-positioning.md`](../compliance/safety-positioning.md)).
- **Judgment is only as good as its inputs.** Operational context
  (control mode, phase, connectivity) is still configuration, not a live
  input. The safety state comes from a live feed only where one is
  configured.

## Detection coverage

- **Zenoh is not decoded**: it is detected and reported, but the sensor is
  blind to its content ([`README.md`](../../README.md)).
- **DDS-Security / SROS2 payloads are not inspected.** No DDS-Security
  traffic has been tested.
- **RTI Connext traffic has not been tested.**
- **XCDR2 and most motion message types** are verified on hand-built
  vectors only.
- **Pulsar host rules** have been validated by script only, never in a
  running engine on a robot. `robodr-pulsard` ran only under WSL2. arm64
  eBPF has never been loaded.
- **No host rules on current Unitree EDU images** (JetPack 5 has no BTF;
  JetPack 6 needs a glibc 2.35 build) ([`docs/UNITREE.md`](../UNITREE.md)
  "Known limits").
- **Host-side (Pulsar) signals do not reach correlation** yet. Every host
  detection reaches the planner as `robot.host.pulsar_threat`, so a policy
  cannot single out one host rule.
- **The sensor box sees only what is mirrored to it.** It cannot see
  unicast between the robot's internal computers without a mirror, or
  traffic over Wi-Fi or cellular, or the content of the Go2 app's WebRTC
  channel.
- **Legacy Unitree UDP:** the sender identity is the IP address only,
  which can be spoofed. MAC binding can be spoofed on the same L2. Go1's
  compressed low-level frames are undecodable.
- **A contested GUID prefix fails closed.** An attacker who can send one
  SPDP message can make a profiled participant untrusted until it is
  pinned by IP ([`README.md`](../../README.md)).

## Security of RoboDR itself

- **No TLS** on the control plane, the Kafka exporter or the anchor
  receiver. Only `robodr-uplink` uses TLS. Use loopback or a unix socket,
  a TLS terminator, or an isolated segment (S5).
- **Keys are files**, not TPM-held. Distribution and rotation are manual.
  Anti-rollback state is a plain file (S9, S10).
- **The TPM head anchor is tested on swtpm only.** Head anchors make
  rollback and truncation *detectable*, not impossible
  ([`SECURITY.md`](../../SECURITY.md)).
- **Control-plane request states are in memory.** A restart forgets them;
  the black box keeps every decision.
- **The robot cannot verify SOC-side approvals.** It verifies the SOC key
  only ([ADR-0006](../adr/0006-approval-never-autonomous.md)).
- **Hand-written components remain:** SHA-256/HMAC, the agentd HTTP
  server, the Kafka client, Reed-Solomon
  ([ADR-0007](../adr/0007-audited-libraries.md)).
- **`panic = "abort"`:** any panic stops the daemon until systemd restarts
  it.
- **Legacy HMAC keys** still load, with a warning. Verifiers holding an
  HMAC key can forge.
- **No time-source authentication.** Signatures and replay windows depend
  on NTP.

## Operations

- **Install, upgrade and rollback have not been rehearsed on a target
  robot.** Whether an older recorder can append to a chain written by a
  newer one is not verified ([`docs/OPERATIONS.md`](../OPERATIONS.md)
  section 7).
- **No fleet management or console.** Updates and keys are handled per
  robot. The secure-delivery design is not implemented
  ([`docs/SECURE-DELIVERY.md`](../SECURE-DELIVERY.md)).
- **Debian 12 and Ubuntu 22.04 hosts** get the agentd-only package
  ([`support-matrix.md`](support-matrix.md)).
- **Resource budgets are unmeasured** on target hardware.
- **The Kafka exporter** is at-least-once (idempotence off), and
  multi-broker behaviour has only been tested against a fake broker.
- **The `done/` markers and dead-letter files** of the exporters must be
  pruned by the operator.
- **The AutoSecOps ingest module does not exist yet.** `robodr-uplink` has
  not been run against it.

## Commercial

- Support period, SLA and EULA are drafts
  ([`sla-support-draft.md`](sla-support-draft.md),
  [`eula-draft.md`](eula-draft.md)).
- RoboDR packages do not yet ship a third-party notices file (S12).
