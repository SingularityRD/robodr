# Known limitations

> **Pre-release draft (refreshed 2026-10-30).** This is a consolidated,
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
- **False-positive rates are unmeasured** beyond lab captures, a benign
  rule corpus and a 2-hour lab soak on a shared VM
  ([`performance.md`](performance.md)). Thresholds and correlation rules
  are untuned engineering defaults.
- **GitHub CI is not green yet.** Its first complete run (2026-10-30)
  failed several jobs; all jobs had passed in a local step-by-step run
  ([`docs/BUILD.md`](../BUILD.md), "Local CI verification").
- **Reviews so far were done by AI agents**, not by independent human
  security reviewers, and there has been no penetration test
  ([`docs/compliance/iec-62443-4-1-sdl-evidence.md`](../compliance/iec-62443-4-1-sdl-evidence.md)).

## Response and enforcement

- **Nothing is executed by default.** The responder plans, the control
  plane answers `recorded_not_executed`, and the executor is off
  (`executor.enabled: false`)
  ([`docs/contracts/robodr.control-plane.md`](../contracts/robodr.control-plane.md)).
- **Executor v1 (opt-in)** executes the reversible network actions
  `isolate_network` and `quarantine_node` (nftables, TTL-bounded) and the
  `record_evidence` mark. Without a `motion` section in `executor.json`,
  `restrict_motion` is recorded only and `safe_pause`,
  `request_safe_state` and `rollback_config` are refused. With one, they
  run through platform adapters (`gateway`, `unitree_sport`, `nav2`,
  `ros2_control`, `px4`, `rollback`), each refused until the site sets
  its `oem_validated: true`, and pause, safe state and rollback only with
  two distinct human approvers
  ([`support-matrix.md`](support-matrix.md#response-actions),
  [`crates/robodr-executor/README.md`](../../crates/robodr-executor/README.md)).
  - Only the `gateway` adapter has run against the real component (the
    gateway binary, in a lab soak). `unitree_sport`, `nav2`,
    `ros2_control`, `px4` and `rollback` have run only against in-process
    simulated peers and test programs, never against a real Unitree
    robot, Nav2, ros2_control or PX4. Executor service requests use
    `rmw_cyclonedds` only; MAVLink signing is not supported.
  - Nav2 and PX4 pauses are not latches: a new goal or a mode change by
    someone else moves the robot again (combine with the gateway's
    restriction). Unitree `SpeedLevel` is advisory without the gateway and
    is reverted to level 0, not to the level before.
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
  The gateway is IPv4 only (it drops IPv6, VLAN-tagged and PPPoE
  traffic), its loco, arm, hand and ROS 2 channels were tested on
  synthetic frames only, and it forwards `led` / `fan` / `gpio` fields as
  sent. Its findings reach agentd (and so the SOC) through agentd's
  `gateway_feed`; that channel is trusted by uid, so a process running as
  root or as the gateway's user can claim any gateway finding. On an
  overloaded host a frame decided late gets the fail-safe verdict (seen
  on a shared VM in the lab soak); the gateway reports such frames as
  `robot.gateway.overload` (Medium, High from `overload_high_late` late or
  shed frames in one interval), at most once per `overload_interval_ms`. It
  has not run on a robot, a real Cyclone DDS stack or a
  real sensor box. Start in `mode: observe`.
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
- **Judgment is only as good as its inputs.** The safety state and the
  operational context (control mode, phase, connectivity) come from a live
  feed only where one is configured (`safety_feed`); otherwise they are
  configuration. Live sources have been tested on synthetic traffic only,
  not on a real robot, Nav2 stack or uplink.
- **A ROS 2 lifecycle (Nav2) state is held, not re-confirmed.** Lifecycle
  events come only on change, so agentd keeps the last one while the node's
  DDS participant is alive: at most one SPDP lease (10 s to 10 min) after
  the participant's last announcement or the event. A node that hangs while
  its process keeps running, or that dies while other nodes sharing its
  participant keep running, is not detected.
- **The Unitree CRC on `LowState` detects corruption only.** It is an
  unkeyed CRC32 anyone can recompute; a forged sample with a correct CRC is
  kept out only by the commissioned writer list and the IP binding.

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
- **No host rules on JetPack 5 Unitree EDU images** (no `robodr-pulsard`
  for glibc 2.31 / systemd 245, and no BTF). On JetPack 6 the regular
  package runs `robodr-pulsard` when the kernel has BTF or an external BTF
  file for the running kernel is installed; not yet tried on a Jetson
  ([`docs/UNITREE.md`](../UNITREE.md) section 3.2).
- **The RPM offline bundle** (`make-bundle.sh --rpm`, same signature,
  format, downgrade and security-floor checks as the `.deb` bundle) has
  been tested against `rpm` in a separate root only, not on a real RHEL /
  Rocky / Fedora host.
- **Secure delivery of packages is deb only.** `robodr-deliverd` installs
  package RPKs with dpkg; on an RPM-based unit (Rocky / RHEL / Fedora) a
  `deb` RPK is refused before anything is unpacked, and there is no `rpm`
  kind, so neither the unit agent nor the site depot delivers RPM
  packages. The `files`, `model`, `config` and `robodr-rules` kinds work
  there, and
  RoboDR itself is updated with the offline bundle
  ([`docs/OPERATIONS.md`](../OPERATIONS.md) sections 7 and 11.4).
- **Host-side (Pulsar) signals reach correlation** by their Pulsar rule
  name. Since contract 2.5 each Pulsar rule RoboDR ships has its own
  finding id (`robot.host.<name>`), which the response planner sees; a
  Pulsar rule RoboDR does not ship (a site's own rule, or a shipped rule
  renamed on the unit) is reported as `robot.host.pulsar_threat`, so a
  response policy cannot single it out.
- **The sensor box sees only what is mirrored to it** (or, inline, what
  crosses its bridge). It cannot see unicast between the robot's internal
  computers without a mirror, or traffic over Wi-Fi or cellular, or the
  content of the Go2 app's WebRTC channel (encrypted; the inline gateway
  detects, attributes and can quarantine such sessions, never reads them).
- **Legacy Unitree UDP:** the sender identity is the IP address only,
  which can be spoofed. MAC binding can be spoofed on the same L2. Go1's
  compressed low-level command is decoded from a layout read from the
  vendor library, not yet compared with a real capture; its compressed
  state frames are not decoded.
- **A contested GUID prefix fails closed.** An attacker who can send one
  SPDP message can make a profiled participant untrusted until it is
  pinned by IP in `participant_ips` ([`docs/OPERATIONS.md`](../OPERATIONS.md)).

## Security of RoboDR itself

- **TLS on the Kafka exporter and the anchor receiver** (mutual TLS and,
  for Kafka, SASL/SCRAM) since 2026-10-30; plain TCP only when explicitly
  allowed. Tested against a local test PKI and a single-node Apache Kafka
  3.9.1, not a deployed SOC. The control plane (v2) uses mutual TLS off
  loopback, but it has only been tested against a local test PKI, not a
  deployed SOC. Every TLS path checks CRLs (fail closed, reloaded on
  change, since 2026-10-30); there is no OCSP (by design, for air-gapped
  fleets), so revocation is only as fresh as the CRL files the operator
  installs. Early warnings before a CRL's `nextUpdate` or a certificate's
  expiry: agentd raises `robot.agent.credential_expiring` for the control
  plane's certificate and CRLs; `robodr-uplink`, `robodr-kafka-publish`,
  `robodr-anchor-receiver` and `robodr-depot` only log them, and the
  site-acceptance checks print the days left. The robot's remote head
  anchor client and `robodr-deliverd` do not warn.
- **Robot keys are files by default.** agentd's private keys can instead
  be sealed to the robot's TPM as systemd encrypted credentials (systemd
  250 or newer, not the focal package): that protects them **at rest**
  only; while the service runs the key is in its credential mount and
  memory, and the TPM does not make the signatures. agentd reports each
  key's protection in `status.json` and, with `key_protection.require:
  "tpm2"`, refuses to start on a weaker one (or when systemd did not start
  it with credentials). It cannot tell a unit that still loads the plain
  key file (`LoadCredential=`) from one that loads the sealed credential,
  when a sealed file of that name exists; check the unit after sealing.
  `robodr-executor`, the uplink, the exporters and the anchor receiver do
  not report key protection. Tested on swtpm only, not on a hardware TPM.
- **Offline signing keys in a token (PKCS#11)** are tested with SoftHSM 2
  only, not yet on YubiKey, Nitrokey or a network HSM. The signing station
  needs OpenSC 0.25 or later (Ubuntu 22.04 and Debian 12 ship older
  releases, which the adapter refuses), the token PIN comes from an
  environment variable or a PIN file (there is no terminal prompt), and
  `keygen` makes file keys only (token keys are generated with the token
  vendor's or OpenSC's tools).
- **Key rotation.** The robot side of SOC-driven uplink
  and finding key rotation exists (`robodr-enroll`), and the SOC side is
  on an unreleased AutoSecOps branch. The black-box key is rotated with
  `robodr-blackbox rotate` while agentd is stopped (retired keys in
  `blackbox.previous_keys`); rotation with a remote head anchor has no
  end-to-end test. Anti-rollback state is a plain file (S9, S10).
- **The TPM head anchor is tested on swtpm only.** Head anchors make
  rollback and truncation *detectable*, not impossible
  ([`SECURITY.md`](../../SECURITY.md)).
- **The control-plane journal and replay store are sealed** (HMAC chain
  under a key derived from the black-box key, end points in signed
  black-box notes), so an edit, deletion, truncation or rollback is
  detected, quarantined and reported. Entries written after the last
  recorded end point and lost in a crash cannot be proven missing. The
  executor seals its journal too, but has no black box to anchor to, so an
  older sealed copy put back is not detected.
- **The robot cannot verify the SOC's internal approval process** (who
  approved, a two-person rule), and SOC keys have no per-key action
  scopes. agentd and the executor each verify the SOC's signature on the
  request (and agentd the client certificate); the executor refuses a
  control-plane order without a valid SOC-signed request
  ([ADR-0006](../adr/0006-approval-never-autonomous.md)).
- **Hand-written components remain**
  ([ADR-0007](../adr/0007-audited-libraries.md)): the agentd HTTP server
  (fuzzed), the Kafka client's wire protocol (fuzzed: `kafka_wire`), the
  `robodr-uplink` HTTP/1.1 client (fuzzed: `uplink_http`), the
  SASL/SCRAM message parsing (fuzzed: `kafka_sasl`; its HMAC, SHA-256,
  PBKDF2 and base64 come from RustCrypto's `hmac`, `sha2`, `pbkdf2` and
  `base64ct`), Reed-Solomon (pinned to an independent oracle), the depot's
  X.509 DER writer (the certificates it issues go through rustls
  handshakes in its tests) and the TPM 2.0 structure parsers
  (`TPM2B_PUBLIC`, `TPMS_ATTEST`; fuzzed: `seal_attest`). SHA-256 now
  comes from the audited `sha2` crate; HMAC is the RFC 2104 construction
  over it (a few lines, so every keyed buffer can be wiped). Direct libc
  calls (`extern "C"` or the `libc` crate: signals, sockets, `flock`,
  clocks) remain in agentd, the black box, capture, deliverd, depot,
  diode, executor, export, firewall-gw, fleet and the ROS 2 pipeline.
- **`panic = "abort"`:** a panic stops the daemon until systemd restarts
  it. Panic-family calls and unchecked indexing are denied in daemon code
  and in the in-process parsers; arithmetic overflow and the remaining
  library code are left to review and fuzzing.
- **Legacy HMAC keys** are refused unless explicitly allowed
  (`blackbox.allow_hmac`, `--allow-hmac`). Where they are allowed,
  verifiers holding an HMAC key can forge. The deliverd finding key
  (`findings.finding_key`) has no HMAC check yet.
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
  console yet, so keys and updates are still handled per robot. Secure
  delivery (sprints 13a–14b: signed releases, unit agent, sealing, site
  depot, leases, crypto-erase) is implemented and tested against software
  TPMs only; OS A/B updates (14c), depot keys in a TPM / HSM and a signed
  remote erase are not done ([`docs/SECURE-DELIVERY.md`](../SECURE-DELIVERY.md) §10).
- **Backup and restore** are documented ([`docs/OPERATIONS.md`](../OPERATIONS.md)
  §14), but the restore order has not been rehearsed on a unit.
- **Ubuntu 20.04 / JetPack 5 hosts** (glibc 2.31, systemd 245) get the
  `robodr-focal` package: agentd and the tools, no `robodr-pulsard`, so
  no host rules. Debian 12 and Ubuntu 22.04 take the regular package
  (glibc 2.35+, systemd 247+;
  [platform requirements](support-matrix.md#platform-requirements)).
- **Resource budgets are unmeasured** on target hardware. The lab
  values in [`performance.md`](performance.md) come from a shared VM.
- **The Kafka exporter** is idempotent by default (exactly-once per
  partition within a producer id's lifetime), tested against an in-process
  fake broker and a single-node Apache Kafka (`scripts/kafka-it.sh`); a
  batch can still be written twice (at-least-once, never lost) after the
  broker expires the producer id (`producer.id.expiration.ms`, default
  1 day) or after a producer id reset while an acknowledgement was lost.
  A sequence error on a broker that supports KIP-360 (Kafka 2.5+) bumps
  the epoch and keeps the producer id; a fencing answer
  (`INVALID_PRODUCER_EPOCH`, `PRODUCER_FENCED`), also for a batch of an
  older epoch of the current id, resets the producer id. Multi-broker
  behaviour (leader failover) has only been tested against the fake
  broker.
- **Exporter retention** prunes `done/` markers and rotated dead-letter
  files by default. Pruning `rejected/`, finished re-injection payloads
  and the importer's `out/` is opt-in (`--rejected-max-*`,
  `--reinject-max-*`, `--out-max-*`). A pruned `out/` batch keeps a
  tombstone (its directory and `MANIFEST.json`) and its `done/` marker for
  good, a few KiB per batch that nothing removes; the reinject ledger is
  never pruned. An `out/` batch the exporter may not delete or cannot read
  is reported (`out_prune_error`) and left in place; delivery goes on.
- **`robodr-uplink` has run against the AutoSecOps ingest module only in
  one container** (TLS and loopback HTTP, `tools/e2e/RESULTS.md`), not
  across a real network; the module is on an unreleased AutoSecOps
  branch.

## Commercial

- Support period, SLA and EULA are drafts and have not been signed off by
  legal ([`sla-support-draft.md`](sla-support-draft.md),
  [`eula-draft.md`](eula-draft.md)).
- No production licence key exists on the SOC side yet.
- Third-party notices and the eBPF GPL-2.0 source offer ship in the
  packages; legal has not yet confirmed the source offer's contact wording.
- Release builds need the repository variable `ROBODR_MAINTAINER` (a real
  maintainer address); it is not set yet.
