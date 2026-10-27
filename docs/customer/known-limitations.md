# Known limitations

> **Pre-release draft (refreshed 2026-10-26).** This is a consolidated,
> deliberately blunt list. Each item names its source document, and its
> planned fix where one exists. Sprint numbers refer to GA-ROADMAP. The
> source documents are authoritative. If this page and a source disagree,
> the source wins, and this page should be corrected.

## Maturity

- **Alpha, unreleased.** Version `0.1.0-alpha`. No signed release has been
  cut, and the release signing workflow has never run
  ([`docs/BUILD.md`](../BUILD.md)).
- **No real robot yet.** Everything is verified offline, in container
  labs, in network namespaces, under qemu, or with synthetic traffic
  ([`README.md`](../../README.md) "Status"). Field validation with a 72 h
  soak is S11.
- **False-positive rates are unmeasured** beyond lab captures and a
  benign rule corpus. Thresholds and correlation rules are untuned
  engineering defaults.
- **GitHub CI has never run.** All jobs passed in a local step-by-step
  run ([`docs/BUILD.md`](../BUILD.md), "Local CI verification").
- **Reviews so far were done by AI agents**, not by independent human
  security reviewers, and there has been no penetration test
  ([`docs/compliance/iec-62443-4-1-sdl-evidence.md`](../compliance/iec-62443-4-1-sdl-evidence.md)).

## Response and enforcement

- **Nothing is executed by default.** The responder plans, the control
  plane answers `recorded_not_executed`, and the executor is off
  (`executor.enabled: false`)
  ([`docs/contracts/robodr.control-plane.md`](../contracts/robodr.control-plane.md)).
- **Executor v1 (opt-in) executes only reversible network actions:**
  `isolate_network` and `quarantine_node` (nftables, TTL-bounded) and the
  `record_evidence` mark. `restrict_motion` from the SOC is recorded only;
  `safe_pause`, `request_safe_state` and `rollback_config` are never
  executed ([`crates/robodr-executor/README.md`](../../crates/robodr-executor/README.md)).
  - It has run against real nftables in network namespaces only, not on a
    robot and not under a real systemd (load the nf_tables modules at boot
    on a minimal kernel).
  - A participant can be quarantined only after agentd has seen it: by
    the addresses it was seen sending from (cut whole on the robot's DDS
    ports, any source port) and its SPDP locators there, or by its GUID
    prefix alone when none can be vouched for. Cutting an address cuts
    every DDS participant on that host, a legitimate one included. RTPS
    over TCP or shared memory, a sender that changes its GUID prefix, and
    a rogue on the same host over loopback are not covered. Source
    addresses are not authenticated: a rogue that forges an unprofiled
    host's address gets that host into its own quarantine (never this
    host, an address pinned to or learned for a profiled participant, or
    a profile identity's address). A rogue on an address a profiled
    participant was learned at is cut by its own locators only (an
    attacker that announces a profiled prefix first is learned there; pin
    the profiled participants to avoid it). The SOC's answer says
    `containment: "full"` only when every address and locator is cut
    whole; otherwise `partial`, or `guid_only` for the GUID-prefix drop
    alone, which the participant can evade.
  - Upgrade the executor before agentd: an older executor drops an order
    with the newer quarantine fields unanswered (the request reads
    `failed`, nothing is applied).
  - Bridged traffic is isolated only with `br_netfilter` loaded.
  - It verifies the SOC's signed request itself (its own copy of the SOC
    keys, its own replay store) before it executes a control-plane order,
    so a compromised agentd cannot claim a human approval it does not
    hold. It cannot check the SOC's internal approval process (who
    approved, a two-person rule): that is the SOC's
    ([`crates/robodr-executor/README.md`](../../crates/robodr-executor/README.md),
    "Trust boundary").
  - A failed revert or a corrupt executor journal is reported in the
    request state, the black box and `status.json`, not yet as a finding.
- **The Motion Firewall records only in the passive modes** (tap, mirror
  port, on-robot agent): a command outside the envelope is reported but
  still reaches the motors ([`docs/UNITREE.md`](../UNITREE.md) section 5).
- **The inline gateway** (`robodr-firewall-gw`, opt-in, sensor box bridged
  into the controller cable) enforces the envelopes on Unitree
  `rt/lowcmd`, sport `Move`, loco requests, the arm SDK, Dex3 / hand SDK,
  arm action requests, ROS 2 `Twist` / `TwistStamped` on `rt/cmd_vel` and
  Go1 legacy UDP
  ([`crates/robodr-firewall-gw/README.md`](../../crates/robodr-firewall-gw/README.md),
  "Known limits"). Before relying on it, check on site:
  - **all SPDP / SEDP between controller-side participants and the robot
    crosses the bridge**: no Wi-Fi, second NIC or modem that reaches the
    controller side, or a writer the gateway never classified passes
    unchecked;
  - **the DDS ports in use are inside the queued range** (7400 + 250·d
    .. +249 per configured domain). A non-default Cyclone DDS port or
    participant-index configuration sends traffic around the queue;
  - **the controller-side segment carries only the controller.** An
    attacker on that segment who uses the controller's own IP and MAC
    cannot be told apart; the gateway bounds the effect but cannot
    prevent it. Set `allowed_src_ips` (and `allowed_src_macs`) on every
    channel;
  - **what the robot does on a lost command stream**: with `fail_closed`
    (default) a stopped gateway hands over to the robot's own command
    timeout. Unitree's motor-board behaviour and `rt/lowcmd` QoS are not
    confirmed;
  - **latency on your sensor box**: measured only on a shared development
    VM; the p99 gate must be measured on the target with the latency
    harness (`crates/robodr-firewall-gw/examples/gw_latency.rs`).
  The gateway is IPv4 only, does not decide ROS 2 `JointTrajectory`
  (the loco, arm, hand and ROS 2 twist channels were tested on synthetic
  frames only), forwards
  `led` / `fan` / `gpio` fields as sent, and writes its verdicts to a
  local events file that does not reach agentd or the SOC yet. It has not
  run on a robot, a real Cyclone DDS stack or a real sensor box. Start in
  `mode: observe`.
- **Humanoids and other balancing robots:** RoboDR never executes a pause
  or safe state on a humanoid, never terminates processes on a balancing
  robot, and never emits a damping or limp frame on a humanoid joint
  channel. The executor runs neither network action on a humanoid unless
  the OEM lists the target in `fall_safe_restrict`, and then only with a
  human's approval; the gateway refuses `bypass` for a humanoid joint
  channel. RoboDR cannot stop such a robot; that remains the platform's
  safety function ([ADR-0012](../adr/0012-balancing-robot-response-rules.md)).
- **Not a safety-rated component**
  ([`docs/compliance/safety-positioning.md`](../compliance/safety-positioning.md)).
  In inline mode the gateway is part of the command path and belongs in
  the integrator's risk assessment.
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
- **The sensor box sees only what is mirrored to it** (or, inline, what
  crosses its bridge). It cannot see unicast between the robot's internal
  computers without a mirror, or traffic over Wi-Fi or cellular, or the
  content of the Go2 app's WebRTC channel.
- **Legacy Unitree UDP:** the sender identity is the IP address only,
  which can be spoofed. MAC binding can be spoofed on the same L2. Go1's
  compressed low-level frames are undecodable.
- **A contested GUID prefix fails closed.** An attacker who can send one
  SPDP message can make a profiled participant untrusted until it is
  pinned by IP in `participant_ips` ([`docs/OPERATIONS.md`](../OPERATIONS.md)).

## Security of RoboDR itself

- **No TLS** on the Kafka exporter or the anchor receiver. The control
  plane (v2) uses mutual TLS off loopback, but it has only been tested
  against a local test PKI, not a deployed SOC; SOC client certificates
  cannot be revoked other than by removing the CA or pins and restarting.
- **Keys are files**, not TPM-held. The robot side of SOC-driven uplink
  and finding key rotation exists (`robodr-enroll`), and the SOC side is
  on an unreleased AutoSecOps branch; the black-box key is rotated by
  hand. Anti-rollback state
  is a plain file (S9, S10).
- **The TPM head anchor is tested on swtpm only.** Head anchors make
  rollback and truncation *detectable*, not impossible
  ([`SECURITY.md`](../../SECURITY.md)).
- **The control-plane journal and replay store are checksummed, not
  signed.** Someone with write access to the state directory can make the
  robot forget requests or fence; the black box keeps every decision.
- **The robot cannot verify the SOC's internal approval process** (who
  approved, a two-person rule), and SOC keys have no per-key action
  scopes. agentd and the executor each verify the SOC's signature on the
  request (and agentd the client certificate); the executor refuses a
  control-plane order without a valid SOC-signed request
  ([ADR-0006](../adr/0006-approval-never-autonomous.md)).
- **Hand-written components remain:** the agentd HTTP server (fuzzed), the
  Kafka client, Reed-Solomon (pinned to an independent oracle)
  ([ADR-0007](../adr/0007-audited-libraries.md)). SHA-256 now comes from
  the audited `sha2` crate; HMAC is the RFC 2104 construction over it (a
  few lines, so every keyed buffer can be wiped).
- **`panic = "abort"`:** a panic stops the daemon until systemd restarts
  it. Panic-family calls are denied in daemon code, but indexing can
  still panic.
- **Legacy HMAC keys** still load, with a warning. Verifiers holding an
  HMAC key can forge.
- **No time-source authentication.** Signatures and replay windows depend
  on NTP.

## Operations

- **Install, upgrade and rollback have not been rehearsed on a target
  robot.** They are tested against the real `dpkg` in a separate dpkg
  root, including the black-box format gate, downgrade refusal and the
  security floor ([`docs/OPERATIONS.md`](../OPERATIONS.md) section 7).
- **No fleet management console yet.** The robot side of the fleet
  lifecycle exists (`robodr-enroll`: enrollment, uplink / finding key
  rotation, revocation lists and SOC profiles,
  [`docs/OPERATIONS.md`](../OPERATIONS.md) section 8.6), and AutoSecOps has
  robot list and detail pages and the SOC side of the fleet API on its
  unreleased development branch (enrollment ran end to end against it in
  one container, `tools/e2e/RESULTS.md`), but there is no released fleet
  console yet, so keys and updates are still handled per robot. Update rings are information only; the secure-delivery design is
  not implemented ([`docs/SECURE-DELIVERY.md`](../SECURE-DELIVERY.md)).
- **More state to back up.** The control-plane state directory, the
  executor journal, the gateway's `rtps.state_file` and the fleet state
  join `/etc/robodr`; no backup procedure is documented yet.
- **Debian 12 and Ubuntu 22.04 hosts** get the agentd-only package
  ([`support-matrix.md`](support-matrix.md)).
- **Resource budgets are unmeasured** on target hardware.
- **The Kafka exporter** is at-least-once (idempotence off), and
  multi-broker behaviour has only been tested against a fake broker.
- **The `done/` markers and dead-letter files** of the exporters must be
  pruned by the operator.
- **`robodr-uplink` has run against the AutoSecOps ingest module only in
  one container** (TLS and loopback HTTP, `tools/e2e/RESULTS.md`), not
  across a real network; the module is on an unreleased AutoSecOps
  branch.

## Commercial

- Support period, SLA and EULA are drafts and have not been signed off by
  legal ([`sla-support-draft.md`](sla-support-draft.md),
  [`eula-draft.md`](eula-draft.md)).
- No production licence key exists on the SOC side yet.
- RoboDR packages do not yet ship a third-party notices file (S12).
