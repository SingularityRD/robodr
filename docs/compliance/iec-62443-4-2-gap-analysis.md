# IEC 62443-4-2 gap analysis (RoboDR as a security component)

> **Status: working analysis, 2026-10-26.** This is an engineering
> self-assessment for planning, not a certification, an audit, or a claim
> of conformance. Requirement titles below are short paraphrases. Before
> any external use, check every row against the licensed text of
> IEC 62443-4-2 (and IEC 62443-3-3 for system-level terms). Every "Today"
> entry cites a file you can check. Nothing here was verified on a real
> robot. See the repository [Status](../../README.md#status).

## 1. Scope and assumptions

**Component under assessment:** the RoboDR software that runs on a robot
companion computer or a passive sensor box:

- `robodr-agentd`, `robodr-pulsard`, the exporters (`robodr-spool-export`,
  `robodr-uplink`, `robodr-kafka-publish`), and the diode tools;
- the offline tools (`robodr-commission`, `robodr-blackbox`);
- their packaging (`.deb`, offline bundle, systemd units).

**Component type** in 62443-4-2 terms: mainly a **software application**
(SAR variants) on a Linux **host device** that RoboDR does not supply. The
planned sensor-box reference image (GA-ROADMAP S7) would add host-device
(HDR) requirements, which are flagged where relevant.

**Not in scope:**

- AutoSecOps1 (the SOC), which needs its own analysis;
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
| FR1 IAC | SL-C 2 | SL-C 3 | Every machine-to-machine path is signed today. SL 3 needs hardware-protected authenticators (TPM) and mutual TLS. |
| FR2 UC | SL-C 2 | SL-C 3 | Requests are authorised against the safety state. SL 3 needs approver identities verifiable on the robot (see CR 2.1). |
| FR3 SI | **SL-C 3** | SL-C 3 | Integrity of evidence, profiles and findings is RoboDR's core value. Much of it is already in place. |
| FR4 DC | SL-C 2 | SL-C 2 | Findings are not secret by nature. Confidentiality in transit is the gap. |
| FR5 RDF | SL-C 2 | SL-C 3 | Passive capture, no IP from agentd, per-unit allow-lists. |
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

### FR1: Identification and authentication control

| CR | Requirement (paraphrased) | Today | Status | Gap → backlog |
|---|---|---|---|---|
| 1.1 | Human user identification and authentication | No interactive UI or login on the robot. CLI tools run as local OS users. Key files are root-only (`packaging/systemd/robodr-agentd.service`, `LoadCredential=`, `InaccessiblePaths=-/etc/robodr/keys`). | Host | Document the host account policy as a CCSC 2 dependency (GAP-01, S13). |
| 1.2 | Software process / device identification and authentication | SOC → robot: Ed25519-signed control-plane requests bound to method, target, robot id, key id, time and nonce (`crates/robodr-agentd/src/control/auth.rs`). Robot → SOC: Ed25519-signed ingest batches (`crates/robodr-export/src/uplink/wire.rs`), diode batches (`crates/robodr-diode/`), remote anchor marks (`crates/robodr-blackbox/src/remote_anchor.rs`). | 🟡 | No mutual TLS on the control plane (GAP-02, S5, [ADR-0004](../adr/0004-control-plane-v2.md)). The Kafka export is unauthenticated (GAP-03, S5, [ADR-0007](../adr/0007-audited-libraries.md)). |
| 1.5 | Authenticator management | Ed25519 key files `0600`, handed to services as systemd credentials. Manual rotation ([`docs/OPERATIONS.md`](../OPERATIONS.md) 4.3). Revocation lists v2 for profile-signing keys (5.3). A secret key or wrong-mode file is refused at start. | 🟡 | Keys are plain files, not hardware-protected. Distribution and rotation are manual (GAP-04: TPM sealing S10, enrolment and rotation from the SOC S9). |
| 1.8 | PKI certificates | `robodr-uplink`: X.509 validation against the operator CA bundle only, optional SPKI pin, no bypass (`crates/robodr-export/src/uplink/http.rs`). Elsewhere, raw Ed25519 keys, not X.509. | 🟡 | Server-certificate revocation checking is not described in the uplink documentation: confirm or add it (GAP-05, S5). The control plane needs a certificate model for mTLS (GAP-02). |
| 1.9 | Strength of public-key authentication | `ed25519-dalek` strict verification, pinned to RFC 8032 vectors. Key ids derived from the key. Trust roots and revocation for profile keys. | ✅ | SL 3 asks for hardware protection of the private keys (GAP-04). |
| 1.11 | Unsuccessful login attempts | Unauthenticated control-plane requests are counted and reported (`robot.agent.control_plane_unauthenticated`, High). There is a per-key rate limit, and the nonce cache fails closed. | ✅ | — |
| 1.14 | Strength of symmetric-key authentication | Legacy HMAC-SHA256 black-box keys still load, with a warning, and the diode needs `--allow-hmac` (`crates/robodr-blackbox/src/crypto.rs`). | 🟡 | Remove HMAC acceptance from GA defaults, or make it an explicit lab option (GAP-06, S10). |
| 1.3, 1.4, 1.7, 1.10, 1.12 | Accounts, identifiers, passwords, feedback, use notification | No accounts or passwords in RoboDR. | N/A / Host | — |

### FR2: Use control

| CR | Requirement (paraphrased) | Today | Status | Gap → backlog |
|---|---|---|---|---|
| 2.1 | Authorisation enforcement | Control plane: only the seven catalog actions, `authority` must be `request`, and no motion, force or override fields exist. Each request is judged against the live safety state, the policy ceiling and the morphology ([`docs/contracts/robodr.control-plane.md`](../contracts/robodr.control-plane.md) §4.1). Profile lock needs a quorum of operator signatures, verified on the robot (OPERATIONS 5.4). | 🟡 | Every configured SOC key may request every action, because the contract defines no per-key scopes. The robot cannot verify SOC-side approval or the two-person rule (GAP-07, S5/S6, [ADR-0006](../adr/0006-approval-never-autonomous.md)). |
| 2.8 | Auditable events | Signed black-box notes for every control-plane request, decision, revert and rejection. Profile acceptance and anti-rollback events. Health findings. | ✅ | — |
| 2.9 | Audit storage capacity | Segment rotation, with a signed `SegmentDropped` record when segments are dropped ([`crates/robodr-blackbox/README.md`](../../crates/robodr-blackbox/README.md), "Storage behaviour"). | 🟡 | No capacity alerting threshold before segments drop. Size it per target (GAP-08, S12 observability). |
| 2.10 | Response to audit-processing failures | If the black box does not take a control-plane note, the answer is `failed` and nothing is decided. Crash recovery is never silent (a signed `Recovery` record). | ✅ | — |
| 2.11 | Timestamps | System clock. NTP is required by the control plane (±30 s) and ingest (±300 s). Black-box records carry time and are chained. | 🟡 | No authenticated time source. Clock tampering is detectable only through skew refusals (GAP-09, S10; document it in the whitepaper). |
| 2.12 | Non-repudiation | SOC request signatures are kept in the black box and re-verify offline. Findings can carry per-finding Ed25519 signatures. Evidence is signed with keys that verifiers cannot use to sign. | ✅ | — |
| 2.2, 2.4, 2.5, 2.6, 2.13 | Wireless, mobile code, session lock, remote session termination, diagnostic interfaces | RoboDR has none of these. | N/A | Platform / host. |

### FR3: System integrity

| CR | Requirement (paraphrased) | Today | Status | Gap → backlog |
|---|---|---|---|---|
| 3.1 | Communication integrity | Signed ingest batches, diode batches, control-plane requests and anchor marks. Optional per-finding signatures. TLS on `robodr-uplink`. | 🟡 | Control-plane answers are signed only when `finding_signing` is configured. Kafka has no transport integrity (GAP-02, GAP-03). |
| 3.2 | Protection from malicious code (SAR/HDR) | RoboDR is itself a detection component (Pulsar rules, `rules/robodr/`). For its own processes: systemd confinement, `MemoryDenyWriteExecute=yes` and a syscall filter. | 🟡 | The rules have never been loaded into a running Pulsar rules engine on a robot (GAP-10, S11). |
| 3.3 | Security functionality verification | `--check-config`; self-health in `status.json` and heartbeats; sd_notify watchdog; the black box verifies itself at open. | 🟡 | No operator-run end-to-end self-test (inject a synthetic deviation, see a finding) (GAP-11, S12). |
| 3.4 | Software and information integrity | Release design: minisign over every asset and `SHA256SUMS`, reproducible pure binaries, `install-bundle.sh` refuses unsigned or unlisted files (OPERATIONS 2–3). Signed, attested, anti-rollback profiles. Hash-chained black box. | 🟡 | **Release signing has never run.** No release has been cut, and no signing key is provisioned ([`docs/BUILD.md`](../BUILD.md)). No SLSA/cosign provenance. The Pulsar-bound binary is not reproducible-checked (GAP-12, S12). |
| 3.5 | Input validation | Bounded, strict parsers for RTPS, CDR, pcap, JSON configs, findings and HTTP. 12 cargo-fuzz targets ([`fuzz/fuzz_targets/`](../../fuzz/fuzz_targets/)) plus std-only fuzz smoke runs in tests. Allow-list taint escaping of attacker strings ([`docs/contracts/robodr.findings.md`](../contracts/robodr.findings.md) §3). | 🟡 | No fuzz targets yet for the diode manifest and batches, the control-plane HTTP/JSON, correlate rules, the safety feed or the Kafka wire. No long fuzz runs (GAP-13, S10). |
| 3.6 | Deterministic output | RoboDR is not in the motion path today, and the firewall records only. The humanoid joint channel never emits a zero or limp frame and holds on fault (ADR-0012). | 🟡 | The gateway's fail-safe behaviour when it dies (stop or pass-through, chosen by OEM policy) is not built (GAP-14, S8). |
| 3.7 | Error handling | Errors are reported as findings and status. `panic = "abort"` with systemd restart. | 🟡 | Every panic kills the daemon (detection gap until restart). Restart behaviour under `panic = "abort"` is to be tested (GAP-15, S10). |
| 3.8 | Session integrity | Control plane: nonce plus timestamp window, one request per connection, request id idempotency. Ingest: `(key, batch id)` replay table, `409` on body mismatch. | 🟡 | The control-plane nonce cache and request states are in memory and lost on restart (GAP-02, [ADR-0004](../adr/0004-control-plane-v2.md)). |
| 3.9 | Protection of audit information | Ed25519-signed, hash-chained, fsynced black box. Head anchors (TPM NV counter, remote receiver) make truncation and rollback detectable, not impossible ([`SECURITY.md`](../../SECURITY.md)). | 🟡 | The TPM anchor is tested on swtpm only. The remote anchor is tested only over loopback (GAP-16, S10/S11). |
| 3.10 | Support for updates | Offline bundle: signed install, kept releases, `rollback <version>` (OPERATIONS 7). | 🟡 | Never rehearsed on a target robot with dpkg (GA-ROADMAP R4). No fleet-staged update; the secure-delivery design is not implemented ([`docs/SECURE-DELIVERY.md`](../SECURE-DELIVERY.md)) (GAP-17, S9). |
| 3.11 | Physical tamper resistance | — | N/A | Host device (sensor-box image, S7). |
| 3.12, 3.13 | Provisioning supplier and asset-owner roots of trust | The release public key reaches the entry station out of band. Asset-owner trust roots sign profile trust files and revocation lists (OPERATIONS 4.1). | 🟡 | No enrolment flow binds a unit's keys to the SOC registry (GAP-18, S9). |
| 3.14 | Integrity of the boot process | Not provided. | Host | Measured boot and attestation are post-GA (GA-ROADMAP §6). |

### FR4: Data confidentiality

| CR | Requirement (paraphrased) | Today | Status | Gap → backlog |
|---|---|---|---|---|
| 4.1 | Information confidentiality | At rest: key files root-only and passed as credentials; evidence and spool are not encrypted. In transit: TLS only on `robodr-uplink`. The control plane, Kafka and the anchor receiver are plaintext. | ❌ | mTLS for the control plane, TLS for Kafka and the anchor (GAP-02, GAP-03, S5). Evidence at rest relies on host full-disk encryption (document it, GAP-01). |
| 4.2 | Information persistence | Decommissioning procedure: export, purge, `shred` keys (OPERATIONS 9). | 🟡 | Cryptographic erase is design only (SECURE-DELIVERY §7.6). |
| 4.3 | Use of cryptography | `ed25519-dalek`; rustls + ring (TLS 1.3/1.2); minisign for releases. | 🟡 | The hand-written SHA-256 and HMAC in `crates/robodr-blackbox/src/crypto.rs` should be replaced by `sha2` (GAP-19, S10, [ADR-0007](../adr/0007-audited-libraries.md)). |

### FR5: Restricted data flow

| CR | Requirement (paraphrased) | Today | Status | Gap → backlog |
|---|---|---|---|---|
| 5.1 | Network segmentation | agentd captures passively (AF_PACKET, `CAP_NET_RAW` only) with `IPAddressDeny=any`. `robodr-spool-export` uses `PrivateNetwork=yes`. Uplink and Kafka drop-ins allow exactly the SOC or broker addresses. The sensor box has an nftables example and a silent capture NIC ([`docs/UNITREE.md`](../UNITREE.md) 3.1). One-way diode path. | ✅ | The `IPAddressAllow` drop-ins rely on IP literals, so DNS changes break them. Document this (GAP-01). |

### FR6: Timely response to events

| CR | Requirement (paraphrased) | Today | Status | Gap → backlog |
|---|---|---|---|---|
| 6.1 | Audit log accessibility | `robodr-blackbox verify` / `inspect`; export bundles; diode transfer; `status.json`. | ✅ | SOC-side evidence download and verification (GA-ROADMAP S4). |
| 6.2 | Continuous monitoring | The product's function: DDS graph, motion envelope, host rules, correlation. Self-health findings when inputs go silent or are unsupported (for example Zenoh). | 🟡 | False-positive rate and detection latency are unmeasured on real robots. No 72 h soak (GAP-20, S11). |

### FR7: Resource availability

| CR | Requirement (paraphrased) | Today | Status | Gap → backlog |
|---|---|---|---|---|
| 7.1 | Denial-of-service protection | Bounded parsers, queues and nonce cache. Per-key rate limits. A control-plane flood costs only the control plane (429/503), never detection. Capture is rate-limited per source. | 🟡 | Not tested under load on target hardware (GAP-20, S11). |
| 7.2 | Resource management | `MemoryHigh=384M` and `MemoryMax=512M`; positive `OOMScoreAdjust` so the motion stack is never the OOM victim. | 🟡 | The figures are estimates, not measured. The CPU budget (< 5 % in GA-ROADMAP S11) is unmeasured (GAP-20). |
| 7.3 | Control-system backup | — | ❌ | No documented backup of `/etc/robodr` (keys, trust files, profile, anti-rollback state) (GAP-21, S12). |
| 7.4 | Recovery and reconstitution | `Restart=on-failure`, watchdog, crash-safe spool, uplink and diode state. Black-box crash recovery (`crates/robodr-blackbox/src/store_crash_tests.rs`). | ✅ | — |
| 7.6 | Network and security configuration settings | Strict JSON configs, `--check-config`, documented examples (`config/`). | 🟡 | No "secure baseline" document listing every security-relevant setting and its recommended value (GAP-22, S13). |
| 7.7 | Least functionality | Units installed disabled. Minimal capabilities. Syscall filter. No listener unless configured. | ✅ | — |
| 7.8 | Component inventory | CycloneDX SBOM per build ([`docs/BUILD.md`](../BUILD.md), "SBOM"). | 🟡 | The SBOM has never shipped with a release (GAP-12). Robot inventory at the SOC is planned (S4, S9). |

### Common component security constraints

| CCSC | Today | Status |
|---|---|---|
| 1 Support of essential functions | RoboDR is never in the motion stack's dependency chain. Detection never blocks motion ([`docs/compliance/safety-positioning.md`](safety-positioning.md)). | ✅ (by design; field validation S11) |
| 2 Compensating countermeasures | The Host rows above must become customer documentation. | 🟡 (GAP-01) |
| 3 Least privilege | Dedicated `robodr` user. Only `robodr-pulsard` runs as root, because Pulsar needs it. | ✅ |
| 4 Development process | See [`iec-62443-4-1-sdl-evidence.md`](iec-62443-4-1-sdl-evidence.md). | 🟡 |

## 4. Backlog

| ID | Item | Sprint | Related |
|---|---|---|---|
| GAP-01 | Customer "secure deployment baseline": host account policy, full-disk encryption, NTP, IP-literal allow-lists, CCSC 2 dependencies | S13 | [`docs/customer/security-whitepaper.md`](../customer/security-whitepaper.md) |
| GAP-02 | Control plane v2: mTLS, persistent nonce and request state, mandatory answer signatures | S5 | ADR-0004 |
| GAP-03 | Kafka export: TLS + SASL, or `rdkafka`; TLS for the anchor receiver | S5 | ADR-0007 |
| GAP-04 | Hardware-protected keys (TPM) where available; SOC-driven rotation | S9, S10 | — |
| GAP-05 | Server-certificate revocation behaviour of `robodr-uplink`: confirm and document | S5 | — |
| GAP-06 | HMAC keys off by default in GA builds | S10 | — |
| GAP-07 | Per-key action scopes; decide whether the robot verifies two-person approvals | S5, S6 | ADR-0006 |
| GAP-08 | Black-box capacity alerting | S12 | — |
| GAP-09 | Time-source integrity guidance; skew findings | S10 | — |
| GAP-10 | Load the Pulsar rules into a real engine on target hardware | S11 | — |
| GAP-11 | Operator self-test (synthetic deviation → finding → SOC) | S12 | — |
| GAP-12 | First real signed release: minisign key ceremony, SBOM shipped, SLSA/cosign provenance, Pulsar-bound reproducibility | S12 | — |
| GAP-13 | Missing fuzz targets; nightly fuzzing of at least 1 h per target; 24 h crash-free | S10 | — |
| GAP-14 | Firewall gateway fail-safe behaviour and latency gate | S8 | ADR-0012 |
| GAP-15 | Panic and restart behaviour test; reduce panic surface | S10 | — |
| GAP-16 | TPM anchor on hardware; remote anchor across a real network, with TLS | S10, S11 | — |
| GAP-17 | Update and rollback rehearsed on target hardware; staged rollout | S9 | SECURE-DELIVERY |
| GAP-18 | Enrolment: bind unit keys to the SOC registry | S9 | — |
| GAP-19 | Replace the in-house SHA-256 and HMAC with `sha2`/`hmac` | S10 | ADR-0007 |
| GAP-20 | 72 h soak, FP rate, CPU and memory budget on target hardware | S11 | — |
| GAP-21 | Backup and restore procedure for `/etc/robodr` | S12 | — |
| GAP-22 | Secure configuration baseline document | S13 | — |
