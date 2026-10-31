# IEC 62443-4-2 gap analysis (RoboDR as a security component)

> **Status: working analysis. Verified at commit `8b2b172` (2026-10-30)**,
> after the wave-2 merges (TLS for Kafka and the anchor, motion adapters,
> JointTrajectory gateway channels, secure delivery 13a-14b, sealing) and
> the gap closures of 2026-10-30 (CRLs everywhere, sealed journals,
> black-box key rotation, HMAC refused by default, indexing lints, backup
> procedure, executor and gateway findings). This
> is an engineering self-assessment for planning, not a certification, an
> audit, or a claim of conformance. Requirement titles below are short
> paraphrases. Before any external use, check every row against the
> licensed text of IEC 62443-4-2 (and IEC 62443-3-3 for system-level
> terms). Every "Today" entry cites a file or commit you can check.
> **Nothing here was verified on a real robot**, and no row has been
> reviewed by an independent human assessor. See the repository
> [Status](../../README.md#status).

## 1. Scope and assumptions

**Component under assessment:** the RoboDR software that runs on a robot
companion computer or a sensor box:

- `robodr-agentd` (with the control plane v2 listener), `robodr-pulsard`,
  the exporters (`robodr-spool-export`, `robodr-uplink`,
  `robodr-kafka-publish`) and the diode tools;
- `robodr-executor` (executor v1, reversible network actions; off by
  default);
- `robodr-firewall-gw` (the in-path Motion Firewall gateway on a bridged
  sensor box; optional);
- `robodr-enroll` (robot side of the fleet lifecycle);
- `robodr-deliverd` and `robodr-seal` (on-unit secure delivery and
  captured-unit protection; the site depot `robodr-depot` runs on a site
  server and is assessed only where the unit depends on it);
- the offline tools (`robodr-commission`, `robodr-blackbox`);
- their packaging (`.deb`, offline bundle, systemd units).

**Component type** in 62443-4-2 terms: mainly a **software application**
(SAR variants) on a Linux **host device** that RoboDR does not supply.
`robodr-firewall-gw` turns a sensor box into a filtering bridge, so the
network-device (NDR) requirements now apply to that deployment mode; they
are flagged where relevant. The planned sensor-box reference image
(GA-ROADMAP S7) would add host-device (HDR) requirements.

**Not in scope:**

- AutoSecOps1 (the SOC), which needs its own analysis. Its RoboDR work is
  cited only where the robot side depends on it (commits on its branch
  `claude/robodr-ingest`, not merged to its `main`);
- the robot platform, its safety system, ROS 2 and the DDS vendors;
- the host OS.

Where a requirement falls to the host OS (user accounts, boot integrity),
it is marked **Host**. It is a compensating-countermeasure dependency
(CCSC 2) that must be listed in the customer documentation.

**Requirement families** are the seven foundational requirements:

| FR | Name |
|---|---|
| FR1 | identification and authentication control (IAC) |
| FR2 | use control (UC) |
| FR3 | system integrity (SI) |
| FR4 | data confidentiality (DC) |
| FR5 | restricted data flow (RDF) |
| FR6 | timely response to events (TRE) |
| FR7 | resource availability (RA) |

## 2. Proposed capability security level (SL-C) targets

| FR | GA target | Post-GA target | Rationale |
|---|---|---|---|
| FR1 IAC | SL-C 2 | SL-C 3 | Every machine-to-machine path is signed, and the control plane adds mutual TLS. SL 3 needs hardware-protected authenticators (TPM) and an authenticated Kafka path. |
| FR2 UC | SL-C 2 | SL-C 3 | Requests are authorised against the safety state, twice when the executor acts. SL 3 needs approvals and per-key scopes verifiable on the robot (CR 2.1). |
| FR3 SI | **SL-C 3** | SL-C 3 | Integrity of evidence, profiles, findings and of the commands the gateway forwards is RoboDR's core value. |
| FR4 DC | SL-C 2 | SL-C 2 | Findings are not secret by nature. Kafka and the anchor receiver use TLS by default since 2026-10-30 (plain TCP only when explicitly allowed). |
| FR5 RDF | SL-C 2 | SL-C 3 | Passive capture, no IP from agentd, per-unit allow-lists, an inline gateway for motion channels. |
| FR6 TRE | **SL-C 3** | SL-C 3 | Detection and evidence are the product's function. |
| FR7 RA | SL-C 2 | SL-C 3 | Bounded queues and cgroup caps exist but are unmeasured on targets. |

These targets are a **proposal for the product owner**. Customers in
defence and other safety-relevant settings may ask for SL 3 across the
board. The post-GA target supports the "IEC 62443-4-2 certification" item
in GA-ROADMAP §6.

## 3. Requirement mapping

Legend:

| Mark | Meaning |
|---|---|
| ✅ | addressed today, at least at the GA target, *as designed and tested offline* |
| 🟡 | partial |
| ❌ | gap |
| Host | host OS responsibility |
| N/A | not applicable to this component |

"Tested offline" means unit, integration and network-namespace tests on a
development VM, never a robot.

### FR1: Identification and authentication control

| CR | Requirement (paraphrased) | Today | Status | Gap → backlog |
|---|---|---|---|---|
| 1.1 | Human user identification and authentication | No interactive UI or login on the robot. CLI tools run as local OS users; `robodr-enroll` is root-only and refuses a token on the command line (`3083030`). Key files are root-only (`LoadCredential=`, `InaccessiblePaths=-/etc/robodr/keys` in [`packaging/systemd/robodr-agentd.service`](../../packaging/systemd/robodr-agentd.service)). | Host | Document the host account policy as a CCSC 2 dependency (GAP-01, S13). |
| 1.2 | Software process / device identification and authentication | SOC → robot: control plane v2 needs a client certificate that chains to `control_plane.tls.client_ca` (optional SPKI pins) **and** an Ed25519 request signature on every listener (`a158536`; `crates/robodr-agentd/src/control/tls.rs`, `auth.rs`). agentd → executor: HMAC-authenticated unix-socket protocol (`crates/robodr-executor/src/proto.rs`). Robot → SOC: Ed25519-signed ingest batches, diode batches, anchor marks; enrollment signed by all three unit keys and MAC'd with the token secret (`3083030`). | 🟡 | The Kafka export authenticates with mutual TLS or SASL/SCRAM when configured (GAP-03 closed in code). The executor authenticates the SOC behind a control-plane order itself (its own SOC keys and replay store, executor M1 `fcd58b2`, `6f37253`; GAP-23 closed in code). |
| 1.5 | Authenticator management | Ed25519 key files `0600`, systemd credentials. `robodr-enroll`: keys generated on the unit, uplink / finding rotation with overlap, crash-safe journal, retire and shred, `rotate --cancel` (`1de502d`, `3083030`; [`docs/OPERATIONS.md`](../OPERATIONS.md) 8.6). Revocation lists v2 for profile keys, now also distributed from the SOC (`robodr-enroll revocations`). | 🟡 | The operational keys (finding, uplink, black box) are plain files, not hardware-protected (GAP-04); the TPM is used only for the head anchor, the sealing unit key and deliverd's depot client key (swtpm-tested). The black-box key is rotated in place by `robodr-blackbox rotate` (agentd reads retired keys from `blackbox.previous_keys`), not by `robodr-enroll`. The SOC side of enrollment and rotation is in progress on the AutoSecOps branch and has never run against a robot (GAP-18). |
| 1.8 | PKI certificates | `robodr-uplink` and `robodr-enroll`: X.509 against the operator CA bundle only, optional SPKI pin, no bypass. Control plane v2: server certificate for the robot, client CA and pins for the SOC, no session resumption ([`docs/contracts/robodr.control-plane.md`](../contracts/robodr.control-plane.md) §1). Elsewhere raw Ed25519 keys. | ✅ | CRLs on every TLS path (control plane, uplink `--crl-file`, enroll `soc.crl_files`, Kafka `--tls-crl-file`, head-anchor client and receiver), fail closed on a missing issuer CRL or an expired or unusable CRL, reloaded on change without a restart; TLS clients with CRLs do not resume sessions (GAP-05 closed in code, merges `f640dfe`, `0cb1ef5`). OCSP is not supported, by design (air-gapped fleets). |
| 1.9 | Strength of public-key authentication | `ed25519-dalek` strict verification, pinned to RFC 8032 vectors; rustls + ring for TLS. Key ids derived from the key. | ✅ | SL 3 asks for hardware protection of the private keys (GAP-04). |
| 1.11 | Unsuccessful login attempts | Unauthenticated requests and failed TLS handshakes are counted (`tls_failures`) and reported (`robot.agent.control_plane_unauthenticated`, High). Per-key rate limit; the persisted nonce store fails closed. | ✅ | — |
| 1.14 | Strength of symmetric-key authentication | SHA-256 / HMAC now come from RustCrypto `sha2` / `hmac` with a constant-time compare (`86e70e7`). Legacy HMAC-SHA256 black-box keys are refused by default in `robodr-blackbox`, `robodr-agentd`, `robodr-replay`, `robodr-deliverd` and the diode; an explicit `--allow-hmac` / `blackbox.allow_hmac` opts in for migration (merges `c9a11c4`, `70d0019`). The executor protocol key is a local HMAC secret. | ✅ | GAP-06 closed in code. |
| 1.3, 1.4, 1.7, 1.10, 1.12 | Accounts, identifiers, passwords, feedback, use notification | No accounts or passwords in RoboDR. | N/A / Host | — |

### FR2: Use control

| CR | Requirement (paraphrased) | Today | Status | Gap → backlog |
|---|---|---|---|---|
| 2.1 | Authorisation enforcement | Control plane: only the seven catalog actions, `authority: request`, no motion fields, judged against the live safety state, policy ceiling and morphology (contract §4.1). Executor v1 decides again with **its own** policy and configuration and re-checks the safety state ≤ 500 ms before apply; humanoids get nothing outside `fall_safe_restrict` and nothing without approval ([`crates/robodr-executor/README.md`](../../crates/robodr-executor/README.md), "Safety argument"). Profile lock needs a quorum of operator signatures, verified on the robot. SOC side: AutoSecOps refuses to sign a robot action without platform sign-off by a requester and one approver (two for the strongest actions) (AutoSecOps `bee7e167`, `6ae14d0e`, `a9fca839`). | 🟡 | Every configured SOC key may request every action (no per-key scopes). The robot cannot verify the SOC-side approval process or two-person rule (GAP-07); the executor verifies the SOC-signed request, so a compromised agentd can no longer assert `human_approved` (executor M1, GAP-23 closed in code). |
| 2.8 | Auditable events | Signed black-box notes for every control-plane request, decision, revert, rejection and evidence export (`robodr.control_plane_start`, `robodr.control_plane_evidence_export`), executor events (`robodr.executor_event`, critical for failures and journal resets), profile acceptance, fleet lifecycle steps (fleet journal chain, `1de502d`). | ✅ | Gateway findings (`robot.gateway.*`, `robot.firewall.*`) reach agentd's pipeline and the signed black box through `gateway_feed` (catalogued ids only, `2876a46`); failed executor reverts and journal resets are High findings (contract 2.4.0). The gateway's per-sample verdicts stay a local JSON-lines file (GAP-24 closed in code). |
| 2.9 | Audit storage capacity | Segment rotation, with a signed `SegmentDropped` record ([`crates/robodr-blackbox/README.md`](../../crates/robodr-blackbox/README.md), "Storage behaviour"). Evidence exports have size, count, storage and age limits (contract §11.7). | 🟡 | No capacity alerting threshold before segments drop (GAP-08). |
| 2.10 | Response to audit-processing failures | No black-box note → the request is answered `failed` and nothing is decided. Journal begin / commit / abort around the note; a compaction whose rename may not be durable refuses further appends (`dc22a34`). Executor: a journal write that fails before apply leaves the rule set out; a revert not journalled is never reported `reverted`. | ✅ | — |
| 2.11 | Timestamps | System clock; NTP required by the control plane (±30 s) and ingest (±300 s). Executor TTLs on `CLOCK_BOOTTIME` within a boot, and a wall-clock step back never extends an action (`12931f3`). The gateway uses kernel arrival timestamps, never the sender's. | 🟡 | No authenticated time source (GAP-09). |
| 2.12 | Non-repudiation | SOC request signatures are kept in the black box and re-verify offline. Every control-plane answer to an authenticated request is signed (v2). Evidence exports carry a manifest signed with the finding key. | ✅ | — |
| 2.2, 2.4, 2.5, 2.6, 2.13 | Wireless, mobile code, session lock, remote session termination, diagnostic interfaces | RoboDR has none of these. | N/A | Platform / host. |

### FR3: System integrity

| CR | Requirement (paraphrased) | Today | Status | Gap → backlog |
|---|---|---|---|---|
| 3.1 | Communication integrity | Signed ingest, diode, fleet and control-plane messages; answers always signed (v2); TLS on uplink, enroll and control plane. The gateway recomputes and verifies the Unitree CRC on every rewrite and suppresses a sample whose rewrite fails verification. | 🟡 | Kafka has transport integrity through TLS (required unless plain TCP is explicitly allowed; GAP-03 closed in code). |
| 3.2 | Protection from malicious code (SAR/HDR) | RoboDR is itself a detection component (Pulsar rules, `rules/robodr/`). For its own processes: systemd confinement, `MemoryDenyWriteExecute=yes`, syscall filters. | 🟡 | The rules have never been loaded into a running Pulsar rules engine on a robot (GAP-10). |
| 3.3 | Security functionality verification | `--check-config` (agentd, `robodr-firewall-gw check-config`); executor read-back verification of every nft transaction; self-health in `status.json`; sd_notify watchdogs; the black box verifies itself at open. | 🟡 | No operator-run end-to-end self-test (GAP-11). |
| 3.4 | Software and information integrity | Release design: minisign over every asset; `install-bundle.sh` verifies the tarball before extracting it, installs from a private extraction and refuses a modified directory (`ace7fba`). Signed, attested, anti-rollback profiles; SOC-published profiles are staged, never enforced without an operator-run, SOC-signed approval (`1de502d`). Hash-chained black box. Air-gapped delivery: quorum-signed RPKs and deployment records, verified on the unit by `robodr-deliverd` with anti-rollback floors ([`docs/SECURE-DELIVERY.md`](../SECURE-DELIVERY.md) 13a-14b; swtpm only). | 🟡 | **Release signing has never run.** No release has been cut and no signing key is provisioned ([`docs/BUILD.md`](../BUILD.md)). No SLSA/cosign provenance (GAP-12). |
| 3.5 | Input validation | Bounded, strict parsers; `clippy::indexing_slicing` denied in the daemons and in-process parsers. **37** cargo-fuzz targets ([`fuzz/fuzz_targets/`](../../fuzz/fuzz_targets/)), among them `control_plane_request`, `kafka_wire`, `firewall_gw_packet`, `firewall_gw_trajectory`, `unitree_webrtc`, the fleet, delivery (`pkg_*`, `deliverd_*`) and sealing (`seal_*`) targets. First libFuzzer runs: 10 targets × 630 s, no crash (`f34754a`, [`fuzz/README.md`](../../fuzz/README.md)); `deliverd_state` and `deliverd_inputs` in Sprint 13b (`1531ca3`). Allow-list taint escaping (findings contract §3). | 🟡 | The other targets have std-only smoke tests and at most a short libFuzzer run; the CI fuzz smoke job failed on its first GitHub run (cause not yet known); no nightly ≥ 1 h runs, no 24 h campaign (GAP-13). |
| 3.6 | Deterministic output | In passive modes RoboDR is not in the motion path. With the inline gateway: every forwarded humanoid `LowCmd_` is an accepted frame or a hold of the last accepted one (never damping or limp); the gateway never originates a datagram or a sequence number; gateway down → `fail_closed` by default, `bypass` refused for a humanoid joint channel ([`crates/robodr-firewall-gw/README.md`](../../crates/robodr-firewall-gw/README.md), "When the gateway itself fails"). The executor fails toward "no rule set" on every error. | 🟡 | What the robot does after its own command timeout is the OEM's; Unitree's `rt/lowcmd` QoS and motor-board behaviour are unconfirmed; the p99 latency gate is unmeasured on a target box (GAP-14, GAP-25). |
| 3.7 | Error handling | Errors become findings, status and black-box notes. Panic-family calls (`unwrap`, `expect`, `panic!`, ...) are denied by clippy in non-test code of the daemon crates, the executor, the gateway and the fleet crate; a process-level abort / restart test verifies the black box across both runs (`7637f9d`, `crates/robodr-agentd/tests/abort_restart.rs`). | 🟡 | `panic = "abort"` stays; `clippy::indexing_slicing` is denied in the daemons and in-process parsers (merge `20ad170`); arithmetic lints are not denied; restart is tested by re-launching the binary, not under a real systemd on a target (GAP-15). |
| 3.8 | Session integrity | Control plane v2: nonce plus time window, persisted nonce store (fsync before the request proceeds; fences when it cannot be trusted), persistent request journal, request-id idempotency (`a158536`). Ingest: `(key, batch id)` replay table. Gateway: per-writer sequence state bound to (GUID, source, IP, MAC) (`e85471c`). | ✅ | The journal and replay store are sealed (an HMAC chain under a key derived from the black-box key, end points in signed black-box notes; an edited, truncated or rolled-back journal is quarantined, rebuilt from the black box and reported, merge `e95d9d5`). Entries after the last anchored end point and lost in a crash are not detectable (contract §13). |
| 3.9 | Protection of audit information | Ed25519-signed, hash-chained, fsynced black box. Head anchors (TPM NV counter, remote receiver) make truncation and rollback detectable, not impossible ([`SECURITY.md`](../../SECURITY.md)). | 🟡 | TPM anchor tested on swtpm only; remote anchor over loopback only (GAP-16). |
| 3.10 | Support for updates | Offline bundle: signed install from a private extraction, kept releases, `rollback <version>`, downgrade refusal, monotonic security floor, black-box format gate (`3d36c65`, `ace7fba`); tested against the real `dpkg` in a separate dpkg root ([`crates/robodr-fleet/tests/packaging.rs`](../../crates/robodr-fleet/tests/packaging.rs)). SOC update rings are information only, except that a ring's minimum version raises the floor. | 🟡 | Never rehearsed on a target robot. Staged rollouts with operator quorums and halt-on-failure exist for air-gapped sites through the site depot ([`docs/SECURE-DELIVERY.md`](../SECURE-DELIVERY.md) 14a; swtpm and loopback only); connected fleets have rings as information only (GAP-17). |
| 3.11 | Physical tamper resistance | — | N/A | Host device (sensor-box image, S7). |
| 3.12, 3.13 | Provisioning supplier and asset-owner roots of trust | Release key out of band. Asset-owner trust roots sign profile trust files and revocation lists. `robodr-enroll` binds the unit's generated keys to a SOC-signed single-use token (robot, site, workspace) (`1de502d`, `3083030`). | 🟡 | The SOC registry side of enrollment is not finished (GAP-18). |
| 3.14 | Integrity of the boot process | Not provided. | Host | Measured boot and attestation are post-GA (GA-ROADMAP §6). |

### FR4: Data confidentiality

| CR | Requirement (paraphrased) | Today | Status | Gap → backlog |
|---|---|---|---|---|
| 4.1 | Information confidentiality | In transit: TLS on `robodr-uplink` and `robodr-enroll`; mutual TLS on the control plane off loopback (plain HTTP only on loopback and the unix socket); TLS (optionally mutual, Kafka also SASL/SCRAM) on Kafka and the anchor receiver, plain TCP there only when explicitly allowed. At rest: key files root-only; evidence, spool, journals and exports are not encrypted. | 🟡 | GAP-03 (TLS for Kafka and the anchor) closed in code; field validation open. Evidence at rest relies on host full-disk encryption (document it, GAP-01). |
| 4.2 | Information persistence | Decommissioning procedure (OPERATIONS 9); package purge removes the executor journal. | 🟡 | Cryptographic erase of the sealed runtime volume and its keys exists (`robodr-seal`, `robodr-deliverd`, executed under the responder's safety grading; SECURE-DELIVERY §7.6, 14b), tested against swtpm only. Evidence, spool and keys outside the sealed volume are removed by the decommissioning procedure, not crypto-erased. |
| 4.3 | Use of cryptography | `ed25519-dalek`; `sha2` (HMAC as an RFC 2104 wrapper over it, every keyed buffer wiped) with `subtle` and `zeroize`, byte-identical to the former code by differential tests (`86e70e7`); rustls + ring; minisign for releases. Reed-Solomon (not cryptography) stays in-crate, pinned to an independent oracle (`aba80a5`). | ✅ | The hand-written HTTP/1.1 server and Kafka client remain (not cryptography; fuzzed) ([ADR-0007](../adr/0007-audited-libraries.md)). |

### FR5: Restricted data flow

| CR | Requirement (paraphrased) | Today | Status | Gap → backlog |
|---|---|---|---|---|
| 5.1 | Network segmentation | agentd captures passively (`CAP_NET_RAW` only) with `IPAddressDeny=any`. `robodr-spool-export` uses `PrivateNetwork=yes`. Uplink and Kafka drop-ins allow exactly the SOC or broker addresses. The executor has no IP sockets (`RestrictAddressFamilies=AF_UNIX AF_NETLINK`, `IPAddressDeny=any`). Sensor box: nftables example and a silent capture NIC ([`docs/UNITREE.md`](../UNITREE.md) 3.1). One-way diode path. | ✅ | `IPAddressAllow` relies on IP literals (document, GAP-01). |
| NDR 5.2 | Zone boundary protection (network-device requirement; applies only to the inline gateway mode) | `robodr-firewall-gw` bridges controller and robot sides, queues the configured DDS port range and legacy UDP ports, drops IPv4 fragments, IPv6 and other ethertypes from the controller port, and decides every motion-channel sample ([`docs/OPERATIONS.md`](../OPERATIONS.md) 6.6). | 🟡 | It is a motion-command filter, not a general firewall. It protects only traffic that crosses the bridge, only DDS ports inside the queued range, and cannot tell a sender with the controller's own IP and MAC on the controller segment from the controller (GAP-25). |

### FR6: Timely response to events

| CR | Requirement (paraphrased) | Today | Status | Gap → backlog |
|---|---|---|---|---|
| 6.1 | Audit log accessibility | `robodr-blackbox verify` / `inspect` (also `verify BUNDLE`, `5cf978e`); evidence API exports over the control plane (contract §11); diode transfer; `status.json`. SOC side: AutoSecOps downloads, verifies and stores exports (AutoSecOps `a9fca839`). | ✅ | Gateway events are a local file only (GAP-24). |
| 6.2 | Continuous monitoring | The product's function: DDS graph, motion envelope, host rules, correlation. Self-health findings when inputs go silent or are unsupported (Zenoh). | 🟡 | False-positive rate and detection latency are unmeasured on real robots. No 72 h soak (GAP-20). |

### FR7: Resource availability

| CR | Requirement (paraphrased) | Today | Status | Gap → backlog |
|---|---|---|---|---|
| 7.1 | Denial-of-service protection | Bounded parsers, queues and nonce store; per-key rate limits; control plane: connection cap, 5 s handshake and 30 s write deadlines; executor: 8 connections, 5 s per message; gateway: bounded writer tables and kernel queue, late packets get the fault verdict. A control-plane flood costs only the control plane (429/503), never detection. | 🟡 | Not tested under load on target hardware (GAP-20). A multi-source TLS slowloris can hold the control plane's pre-authentication slots (GAP-28). |
| 7.2 | Resource management | `MemoryHigh=384M` / `MemoryMax=512M` for agentd; positive `OOMScoreAdjust`. The gateway runs at FIFO priority 40. | 🟡 | Figures are estimates; the CPU budget and the gateway's real-time behaviour next to the motion stack are unmeasured (GAP-20, GAP-25). |
| 7.3 | Control-system backup | Backup and restore procedure for `/etc/robodr` and the state directories, including what must never be restored (anti-rollback, replay and TPM-bound state) ([`docs/OPERATIONS.md`](../OPERATIONS.md) §14). | 🟡 | Procedure only: no backup tool, and restore was not rehearsed on a unit (GAP-21). |
| 7.4 | Recovery and reconstitution | `Restart=` and watchdogs; crash-safe spool, uplink, diode and fleet state; black-box crash recovery; control-plane journal settles half-journaled decisions from the black box; executor reconciles after restart / reboot / crash and holds actions until a fresh safety state (`31d1aa4`). | ✅ | — |
| 7.6 | Network and security configuration settings | Strict JSON configs with unknown keys refused, `--check-config`, documented examples (`config/`). | 🟡 | No secure configuration baseline document (GAP-22). |
| 7.7 | Least functionality | Units installed disabled; executor off by default (`executor.enabled`); control plane off by default; gateway units optional; minimal capabilities; syscall filters; no listener unless configured. | ✅ | — |
| 7.8 | Component inventory | CycloneDX SBOM per build ([`docs/BUILD.md`](../BUILD.md), "SBOM"). Robot inventory at the SOC: AutoSecOps robots pages (AutoSecOps `05a431e0`). | 🟡 | The SBOM has never shipped with a release (GAP-12). |

### Common component security constraints

| CCSC | Today | Status |
|---|---|---|
| 1 Support of essential functions | Passive modes and the executor: nothing in the motion stack depends on RoboDR, and the executor never cuts the protected motion path. **Inline gateway mode is different:** the robot's motion commands cross the gateway, so its availability is part of the control system; on failure `fail_closed` hands over to the robot's own command timeout ([`safety-positioning.md`](safety-positioning.md) §2a). | 🟡 (inline mode needs OEM and integrator risk assessment; field validation S11) |
| 2 Compensating countermeasures | The Host rows above, the gateway deployment rules and the executor's kernel prerequisites must become customer documentation ([`docs/customer/known-limitations.md`](../customer/known-limitations.md) lists them as a draft). | 🟡 (GAP-01) |
| 3 Least privilege | Dedicated `robodr` user; agentd `CAP_NET_RAW` only; executor as its own user `robodr-exec` with `CAP_NET_ADMIN` only; gateway `CAP_NET_ADMIN` only; `robodr-enroll` root-only by design (key files). Only `robodr-pulsard` runs as root as a daemon. | ✅ |
| 4 Development process | See [`iec-62443-4-1-sdl-evidence.md`](iec-62443-4-1-sdl-evidence.md). | 🟡 |

## 4. Backlog

Status: **Closed in code** = implemented and tested offline, with the
commit; it still needs field validation where the row says so.
**Partial** = part implemented. **Open** = not started.

| ID | Item | Status | Sprint | Related |
|---|---|---|---|---|
| GAP-01 | Customer "secure deployment baseline": host account policy, full-disk encryption, NTP, IP-literal allow-lists, CCSC 2 dependencies, gateway deployment rules, executor kernel prerequisites | Open (drafts in `docs/customer/`) | S13 | [`docs/customer/security-whitepaper.md`](../customer/security-whitepaper.md) |
| GAP-02 | Control plane v2: mTLS, persistent nonce and request state, mandatory answer signatures | **Closed in code** (`a158536`, `5cf978e`, `dc22a34`); tested on a local test PKI only; the AutoSecOps client speaks v2 (AutoSecOps `a9fca839`) | S5 → field S11 | ADR-0004 |
| GAP-03 | Kafka export: TLS + SASL, or `rdkafka`; TLS for the anchor receiver | Closed in code 2026-10-30 (TLS, mutual TLS, SASL/SCRAM-SHA-256/512 on the in-crate client, verified against Apache Kafka 3.9.1; anchor TLS / mutual TLS); field validation open | S10 (carry-over from S5) | ADR-0007 |
| GAP-04 | Hardware-protected keys (TPM) where available; SOC-driven rotation | Partial: SOC-driven uplink / finding rotation on the robot side (`1de502d`, `3083030`); no TPM sealing | S9 (SOC side), S10 (TPM) | — |
| GAP-05 | Certificate revocation on every TLS path | **Closed in code** 2026-10-30 (CRL files, fail closed, reloaded on change; merges `f640dfe`, `0cb1ef5`); OCSP not supported by design; field validation open | S10 | contract §13 |
| GAP-06 | HMAC evidence keys off by default | **Closed in code** 2026-10-30 (refused unless opted in; merges `c9a11c4`, `70d0019`) | S10 | — |
| GAP-07 | Per-key action scopes; decide whether the robot verifies two-person approvals | Partial: SOC-side sign-off and two-person rule in AutoSecOps (`bee7e167`, `6ae14d0e`); nothing on the robot | S10 / S11 | ADR-0006 |
| GAP-08 | Black-box capacity alerting | Open | S12 | — |
| GAP-09 | Time-source integrity guidance; skew findings | Open | S10 / S13 | — |
| GAP-10 | Load the Pulsar rules into a real engine on target hardware | Open | S11 | — |
| GAP-11 | Operator self-test (synthetic deviation → finding → SOC) | Open | S12 | — |
| GAP-12 | First real signed release: minisign key ceremony, SBOM shipped, SLSA/cosign provenance, Pulsar-bound reproducibility | Open | S12 | — |
| GAP-13 | Fuzzing: missing targets; nightly ≥ 1 h per target; 24 h crash-free | Partial: targets added (`f34754a`, `5cf978e`, `a4e0b4b`, `1de502d`), 10 targets ran 630 s under libFuzzer; no nightly, no long run | S10 (remaining) | — |
| GAP-14 | Gateway fail-safe behaviour and latency gate | Partial: fail-safe built (`a4e0b4b`, `e85471c`); latency gate measured only on a shared VM, not on a target box (moves to GAP-25) | S8 → S11 | ADR-0012 |
| GAP-15 | Panic and restart behaviour test; reduce panic surface | **Closed in code** (`7637f9d`; indexing lints denied in the daemons and parsers, merge `20ad170`); residual: arithmetic lints, restart under real systemd on a target | S10 → S11 | — |
| GAP-16 | TPM anchor on hardware; remote anchor across a real network, with TLS | Open | S10, S11 | — |
| GAP-17 | Update and rollback rehearsed on target hardware; staged rollout | Partial: dpkg-tested gates and floor (`3d36c65`, `ace7fba`); depot staged rollouts for air-gapped sites (14a, swtpm); not on a target; connected-fleet rings are information only | S11 (target), post-GA (connected staged rollout) | SECURE-DELIVERY |
| GAP-18 | Enrollment: bind unit keys to the SOC registry | Partial: robot side done (`1de502d`, `3083030`; contract [`robodr.fleet-api`](../contracts/robodr.fleet-api.md) draft v1); AutoSecOps side built on its unreleased branch, enrollment end to end in one container (`tools/e2e/RESULTS.md`); not released, not across a real network | S9 (SOC side) | — |
| GAP-19 | Replace the in-house SHA-256 and HMAC with `sha2`/`hmac` | **Closed in code** (`86e70e7`; HMAC later moved off `hmac` onto a wiping RFC 2104 wrapper over `sha2`) | S10 | ADR-0007 |
| GAP-20 | 72 h soak, FP rate, CPU and memory budget on target hardware | Open | S11 | — |
| GAP-21 | Backup and restore procedure for `/etc/robodr` and the persistent state directories | Partial: procedure documented (OPERATIONS §14, merge `8f669c1`); no tool, not rehearsed on a unit | S12 | — |
| GAP-22 | Secure configuration baseline document | Open | S13 | — |
| GAP-23 | Executor verifies the SOC-signed request and its approval itself, so a compromised agentd cannot assert `human_approved` (executor review M1) | **Closed in code** (`fcd58b2`, review fixes `6f37253`); residual: the SOC's internal approval process is not verifiable on the robot (GAP-07) | S10 (carry-over from S7) | [`crates/robodr-executor/README.md`](../../crates/robodr-executor/README.md) "Trust boundary" |
| GAP-24 | Findings for executor failures (failed revert, journal reset) and gateway conditions; gateway findings into agentd and the black box | **Closed in code** (`robot.agent.executor_revert_failed` / `executor_journal_reset`, merge `e95d9d5`, contract 2.4.0; `gateway_feed`, `9ddb327`, `2876a46`); residual: per-sample gateway verdicts stay a local file (per-minute decision summaries with the configuration, firewall and profile digests are signed black-box notes since sales-readiness T19); gateway overload is reported as `robot.gateway.overload`, Medium / High, once per interval (RESULTS O1, sales-readiness T8) | S12 | — |
| GAP-25 | Gateway on a real robot and sensor box: all SPDP / SEDP through the bridge, DDS ports inside the queued range, controller segment free of other hosts, Unitree `rt/lowcmd` QoS and motor-board timeout behaviour (OEM), p99 latency on the target | Open | S11 | [`docs/UNITREE.md`](../UNITREE.md) 5.1 |
| GAP-26 | Independent review of control plane v2 and of the S10 changes (no review round is recorded in the commit history for them); external pentest | Open | S11 | [`iec-62443-4-1-sdl-evidence.md`](iec-62443-4-1-sdl-evidence.md) SVV |
| GAP-27 | Executor on a target robot under real systemd (syscall filter with `nft`, kernel modules, Cyclone / Fast DDS traffic, IPv6 traffic) | Open | S11 (Kapı 2 Q item) | OPERATIONS 6.5 |
| GAP-28 | Control-plane pre-authentication slots can be held by a slow TLS handshake from 3 or more source addresses, locking the SOC out while it lasts (red team W2-4, [`tools/e2e/RESULTS.md`](../../tools/e2e/RESULTS.md)); detection and recording continue | Open (mitigation: the documented `IPAddressAllow=` drop-in for the SOC network, OPERATIONS §6.4) | S11 | CR 7.1 |

### Remaining gaps by sprint

| Sprint | Gaps |
|---|---|
| S9 (SOC side) | GAP-04 (SOC rotation), GAP-18 |
| S10 (remaining hardening) | GAP-07 (scopes), GAP-09, GAP-13, GAP-16 (TPM) |
| S11 (field, red team) | GAP-10, GAP-14/25, GAP-15 (systemd residual), GAP-16 (network), GAP-17 (target), GAP-20, GAP-26, GAP-27, GAP-28 |
| S12 | GAP-08, GAP-11, GAP-12, GAP-21 (tool, rehearsal) |
| S13 | GAP-01, GAP-09 (guidance), GAP-22 |
