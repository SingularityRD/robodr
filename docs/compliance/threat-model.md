# RoboDR product threat model (IEC 62443-4-1 SR-1, SR-2)

> **Status: engineering threat model. Verified at commit `8b2b172`
> (2026-10-30).** It consolidates the per-component threat models (black
> box, executor, gateway, control plane, secure delivery) into one product
> view: security context, assets, threat agents, trust boundaries with
> data-flow diagrams, STRIDE per boundary, the mitigations with the tests
> that hold them, residual risks and the proposed capability security
> levels. Written by an AI engineering agent from the code and tests at
> that commit; **it has not been reviewed by an independent human**, and
> nothing in it has been validated on a real robot. It is reviewed and
> restamped for every release ([`docs/RELEASE.md`](../RELEASE.md) §3
> checklist; review log in §9).
>
> *Corrected at `a28163b` (2026-10-31) without re-verifying the rest of the document:* the fuzz target count (41).
>
> Companion documents: [`iec-62443-4-2-gap-analysis.md`](iec-62443-4-2-gap-analysis.md)
> (requirement mapping and backlog, GAP-nn),
> [`iec-62443-4-1-sdl-evidence.md`](iec-62443-4-1-sdl-evidence.md),
> [`safety-positioning.md`](safety-positioning.md),
> [`docs/customer/data-handling.md`](../customer/data-handling.md),
> [`docs/customer/security-whitepaper.md`](../customer/security-whitepaper.md).
> Normative behaviour is in the contracts under
> [`docs/contracts/`](../contracts/) and in [`SECURITY.md`](../../SECURITY.md).

## 1. Security context (SR-1)

**Product.** RoboDR is a detection-and-response component for robots. It
watches a robot's ROS 2 / DDS bus, its motion commands and (with Pulsar)
its Linux host, compares them with a signed, locked profile, keeps signed
evidence, and sends findings to a SOC. Optional parts act: executor v1
(reversible network containment; motion actions only through
OEM-validated platform adapters) and the inline Motion Firewall gateway
on a bridged sensor box.

**Intended environment.**

| Item | Assumption |
|---|---|
| Where it runs | A robot companion computer or a sensor box next to the robot, Linux with systemd ≥ 247 (245 for the `robodr-focal` package), amd64 or arm64 ([`docs/customer/support-matrix.md`](../customer/support-matrix.md)) |
| Who operates it | The asset owner's OT / robotics team (installation, keys, commissioning) and a SOC (findings, approved actions) |
| Network | An industrial or field network zone with the robot; a conduit to the SOC (TLS uplink, Kafka, or a one-way diode / media for air-gapped sites) |
| Robot safety | The platform has its own safety system, e-stop and command authority; RoboDR is not part of them ([`safety-positioning.md`](safety-positioning.md)) |
| Sectors | Critical infrastructure, industrial and defence-adjacent customers; air-gapped sites are a first-class case |

**Assumed host and environment controls** (compensating countermeasures,
62443-4-2 CCSC 2; they must be listed in the customer baseline, 4-2
GAP-01):

- H1. The host OS is supported and patched; root is restricted to
  administrators; no untrusted user has a shell on the host.
- H2. The robot's clock is synchronised (NTP or PTP); the control plane
  refuses requests outside ±30 s.
- H3. Full-disk encryption where the evidence or findings are sensitive
  (RoboDR does not encrypt its evidence at rest).
- H4. systemd is the service manager and the shipped unit files are not
  weakened.
- H5. The site's network separates the robot zone from the SOC conduit
  (RoboDR's `IPAddressAllow=` drop-ins rely on IP literals).
- H6. Private keys are created and kept as OPERATIONS §4 describes
  (root-only files, systemd credentials; offline stations for profile and
  trust-root keys).

**Out of scope:** the robot platform and its safety functions, ROS 2 and
the DDS vendors, the host OS and kernel, the SOC (AutoSecOps has its own
model), vendored Pulsar internals (see
[`third-party-due-diligence.md`](third-party-due-diligence.md)), physical
safety of people.

## 2. Assets

| # | Asset | Security property | Why it matters |
|---|---|---|---|
| AS1 | The robot's motion and safety behaviour | Safety: RoboDR must not cause or worsen a hazard; availability of the command path in inline mode | Physical harm; the overriding constraint ([ADR-0006](../adr/0006-approval-never-autonomous.md), [ADR-0012](../adr/0012-balancing-robot-response-rules.md)) |
| AS2 | Evidence (black box, evidence exports) | Integrity, completeness, non-repudiation | Incident reconstruction, legal and insurance use |
| AS3 | Locked profile, trust files, revocation lists | Integrity, anti-rollback | The baseline every detection is judged against |
| AS4 | Findings in transit and in the SOC | Integrity, authenticity, timeliness; confidentiality of personal data inside | Detection value; findings name hosts, processes, users and operators |
| AS5 | Private keys (black box, finding, uplink, diode, executor protocol, TLS, SOC, fleet, release, depot, seal) | Confidentiality, integrity | Every other control rests on them |
| AS6 | Control-plane authority (SOC → robot actions) | Authorisation, integrity, replay protection | A forged action could isolate or pause a robot |
| AS7 | Detection availability | Availability | A blinded sensor misses the attack |
| AS8 | Software and rules on the unit | Integrity, provenance, anti-rollback | A malicious update owns the unit |
| AS9 | Sealed content (models, RPKs) on a unit | Confidentiality against a captured unit | Customer and vendor IP on fielded robots |
| AS10 | SOC analysts' and LLM agents' judgement | Integrity of what they are shown | Prompt injection through finding contents |

## 3. Threat agents

| # | Agent | Capability assumed | In scope |
|---|---|---|---|
| TA1 | Network attacker on the robot's bus / LAN | Sends arbitrary RTPS, UDP, TCP; chooses GUIDs, names, source IPs and MACs (other than a host it does not control); floods | Yes (primary) |
| TA2 | Network attacker on the SOC conduit | Reads, drops, delays, replays and alters traffic between robot and SOC; slowloris | Yes |
| TA3 | Unprivileged local process on the robot host (for example a compromised ROS node) | Runs as a non-root, non-RoboDR user; reads world-readable files; connects to local sockets it is allowed to | Yes |
| TA4 | Root on the robot host | Anything on the host: rewrite state, keys, binaries; kill services | Partly: RoboDR makes evidence truncation and state rollback **detectable** with a head anchor, it cannot prevent them |
| TA5 | Malicious or compromised SOC user, LLM agent misled by finding text, or stolen SOC key | Signs valid requests with a configured key; misreads findings | Partly: the robot judges every request against the live safety state and its own policy; the SOC's approval process is trusted |
| TA6 | Supply-chain attacker | Tampers with a dependency, Pulsar upstream, the build, the release key or distribution media | Yes |
| TA7 | Physical attacker with a captured unit or media | Holds the disk, the media pack, can boot another OS | Partly: sealed content and keys are bound to the TPM and PCR policy (secure delivery 13c); plain evidence and keys on disk rely on H3 |

## 4. Trust boundaries and data flows (SR-2)

Boundary numbers TB1-TB11 are those of the
[security whitepaper](../customer/security-whitepaper.md) §3; TB12 and
TB13 are added here.

| # | Boundary | Data crossing | Direction |
|---|---|---|---|
| TB1 | Robot DDS bus / network → capture | RTPS discovery and user data, UDP, WebRTC signalling | in |
| TB2 | Host OS ↔ RoboDR processes | State files, keys, sockets, Pulsar eBPF events | both |
| TB3 | Robot → SOC network | Signed NDJSON batches (uplink), Kafka records, enrollment | out |
| TB4 | Data diode / media | Signed, chained, FEC-protected batches and bundles | out (one-way) |
| TB5 | SOC → robot control plane | Signed action requests, revert, evidence export requests; signed answers back | in / out |
| TB6 | Findings → SOC analysts and LLM agents | Finding text and tainted fields | out |
| TB7 | Commissioning station / offline keys → robot | Locked profile, sign-offs, trust files, revocation lists | in |
| TB8 | Release supply chain → site entry station → unit | Packages, bundles, RPKs, SBOM, signatures | in |
| TB9 | agentd → executor (local unix socket) | Orders (with the SOC's signed request), answers | local |
| TB10 | Controller segment → inline gateway → robot | Motion-command samples | in (inline) |
| TB11 | SOC fleet documents → robot | Enrollment tokens, rotation answers, revocations, staged profiles, ring info | in |
| TB12 | Site depot ↔ unit (secure delivery) | Media packs, wrapped keys, leases, attested reports (mutual TLS on the LAN, or media) | both |
| TB13 | Local feeds → agentd (`host_threats`, `gateway_feed`, safety socket) | Pulsar threats, gateway findings and heartbeats, safety state | local |

### 4.1 Detection path (TB1, TB2, TB13)

```
           TB1 (hostile)                         TB13 (local, peer-checked)
 robot bus ──────────────► capture (CAP_NET_RAW, ─┐   robodr-pulsard ──host_threats──┐
 RTPS / UDP / WebRTC        AF_PACKET, passive)   │   robodr-firewall-gw ─gateway_feed┤
                                                  ▼   safety source ──safety socket──┤
                          RTPS parse ─► CDR ─► profile / Motion Firewall /           │
                          correlation ◄──────────────────────────────────────────────┘
                                │
                                ▼
                 responder (plans) ─► black box (signed, chained; TB2 state on disk)
                                │                     │
                                ▼                     └─ head mark ─► TPM NV / remote anchor
                       OCSF findings spool (TB2)
```

### 4.2 SOC conduits (TB3, TB4, TB5, TB6, TB11)

```
 unit                                   │ TB3 / TB4 / TB5 / TB11 (untrusted network)   │ SOC
 spool ─► robodr-uplink ────────────────┼── TLS + Ed25519 batches ─────────────────────┼─► ingest ─► cases ─► analysts / LLM (TB6)
 spool ─► robodr-kafka-publish ─────────┼── TLS / mTLS / SASL ─────────────────────────┼─► Kafka ─► SIEM
 spool ─► robodr-spool-export ─► media ─┼── diode: signed, chained, FEC ──────────────►┼─► diode-unpack
 agentd control plane ◄─────────────────┼── mTLS + Ed25519 request (nonce, time, id) ──┼── approved action (human, 2 for strongest)
                      ─────────────────►┼── signed answer / signed evidence bundle ───►┼─►
 robodr-enroll ◄───────────────────────►┼── TLS + signed fleet documents ──────────────┼─► fleet API
```

### 4.3 Acting components (TB9, TB10)

```
 agentd ── TB9: HMAC unix socket, order + SOC-signed request ──► robodr-executor (CAP_NET_ADMIN only, no IP)
                                                                   ├─► nftables table inet robodr (TTL, read-back)
                                                                   └─► motion adapters (only with motion section
                                                                       and oem_validated): gateway restriction file,
                                                                       Unitree SpeedLevel, Nav2, ros2_control, PX4,
                                                                       site rollback program

 controller ── TB10 (hostile segment) ──► bridge ─► NFQUEUE ─► robodr-firewall-gw ─► robot
                                                     pass / limit / hold / remove; never originates
```

### 4.4 Supply and delivery (TB7, TB8, TB12)

```
 commissioning station (offline) ── TB7: signed profile + quorum sign-off, trust files ──► unit
 release build (CI, pinned toolchains) ─► minisign / quorum-signed RPKs ── TB8 ──► entry station ─► depot / unit
 site depot (TPM, operator quorum) ── TB12: mTLS LAN or media pack, wrapped keys, leases ──► robodr-deliverd ─► dpkg / sealed volume
```

## 5. STRIDE per boundary, with mitigations and the tests that hold them

S = spoofing, T = tampering, R = repudiation, I = information disclosure,
D = denial of service, E = elevation of privilege. "Tests" name the test
files (under `crates/`) or harnesses that fail if the mitigation breaks;
"Residual" is what remains and where it is tracked.

### TB1: robot bus → capture

| | Threat | Mitigation | Tests | Residual |
|---|---|---|---|---|
| S | Rogue participant or writer impersonates a profiled one (GUID reuse, address spoofing) | Participant identity binding (GUID prefix + locators + observed sources); contested prefixes fail closed; motion writers bound to their source | `robodr-agentd/tests/redteam_regressions.rs`, `robodr-ros2-pipeline/tests/redteam_regressions.rs`, `robodr-agentd/tests/real_captures_lab.rs` | A sender with the legitimate host's own IP and MAC on the same L2 cannot be told apart |
| T | Malformed RTPS / CDR / pcap crafted to crash or confuse parsers | Bounded, strict parsers; `clippy::indexing_slicing` and panic-family calls denied; 42 fuzz targets with smoke runs | `robodr-rtps/tests/mutation_fuzz.rs`, `robodr-capture/tests/fuzz_smoke.rs`, `robodr-cdr/tests/hostile.rs`, `fuzz/fuzz_targets/` | No long fuzz campaigns (4-2 GAP-13); the CI fuzz smoke job is red |
| I | Attacker learns detection logic from behaviour | Not mitigated (passive sensor; rules ship with the product) | — | Accepted |
| D | Discovery flood / GUID spray exhausts tables or the spool | Bounded tables; aggregated `discovery_flood` findings; spool room kept for Critical | `robodr-agentd/tests/redteam_regressions.rs` (F1); RESULTS R2 (3000 GUIDs → 8 findings) | Detection of other activity during a flood is not measured |
| E | Attacker-chosen strings reach a SOC LLM as instructions (TB6) | SR-TAINT: tainted typed fields only, allow-list escaping, `injection_hint` flags | `robodr-ocsf/tests/findings.rs` (`INJECTIONS`) | The SOC must honour the taint labels (ingest contract) |

### TB2: host OS ↔ RoboDR

| | Threat | Mitigation | Tests | Residual |
|---|---|---|---|---|
| S | A local process writes into agentd's sockets | `SO_PEERCRED` checks (root and listed uids only) on `host_threats`, `gateway_feed`, the safety socket; socket path ownership checks | `robodr-agentd/tests/host_threats.rs`, `robodr-agentd/tests/gateway_feed.rs`, `robodr-agentd/tests/safety_feed.rs`; RESULTS G1, R4b | A process running as root or as the gateway's user can claim any gateway finding (RESULTS W2-5) |
| T | TA4 truncates the black box and rolls back state files | Signed hash chain; head anchors (TPM NV counter, remote receiver) make it detectable; sealed control-plane and executor journals anchored in the black box | `robodr-blackbox/tests/tamper.rs`, `robodr-blackbox/tests/tpm_anchor.rs`, `robodr-blackbox/tests/remote_anchor_tls.rs`, `robodr-agentd/tests/remote_head_anchor.rs`, `robodr-agentd/tests/executor_link.rs` | Prevention is impossible against root; TPM anchor tested on swtpm only (GAP-16) |
| T | Profile replaced by an older or unsigned one | Signed profiles from root-signed trust files, quorum sign-off for motion items, anti-rollback state, revocation lists | `robodr-agentd/tests/profile_trust.rs`, `robodr-commission/tests/profile_signing.rs`, `robodr-commission/tests/operator_signoff.rs` | `ROBODR_ALLOW_UNSIGNED=1` exists for labs |
| R | Unit denies an action it took | Every decision is a signed black-box note; answers signed with the finding key | `robodr-agentd/tests/control_plane.rs`, `robodr-agentd/tests/rev5_evidence.rs` | — |
| I | Keys read by a non-root process | Key files `0600 root`, systemd credentials, `InaccessiblePaths=-/etc/robodr/keys` | `scripts/check-packages.py` (no private key material in packages); unit files | Keys are files, not TPM-held (GAP-04) |
| E | Escape from a RoboDR service | Per-service users, minimal capabilities, syscall filters, `MemoryDenyWriteExecute`, `IPAddressDeny=any` for agentd and executor; only `robodr-pulsard` runs as root | `scripts/check-focal-units.py`, `scripts/check-packages.py`, `packaging/systemd/` | Never run under a real systemd on a target robot (GAP-27). `robodr-pulsard` runs as root with eBPF and `CAP_SYS_PTRACE`: its compromise must be treated as a compromise of the unit's keys ([`third-party-due-diligence.md`](third-party-due-diligence.md) §2.2) |

### TB3 and TB4: robot → SOC

| | Threat | Mitigation | Tests | Residual |
|---|---|---|---|---|
| S | A forged robot sends findings | Ed25519 batch signatures per unit key; SOC key registry; optional per-finding signatures | `robodr-export/tests/ingest_vectors.rs`, `robodr-ocsf/tests/signed.rs`, `robodr-diode/tests/ed25519.rs` | Ingest red team R7 not re-run in wave 2 |
| T | Batches altered in transit or on media | TLS (rustls) with CA and optional SPKI pin; signatures over exact bytes; diode hash chain and Reed-Solomon parity | `robodr-export/tests/uplink_https.rs`, `robodr-diode/tests/diode.rs`, `robodr-diode/tests/fec_oracle.rs` | — |
| R | Duplicate or replayed batches | `(key, batch id)` replay table on the SOC; idempotent Kafka producer | `robodr-export/tests/ingest_vectors.rs`, `robodr-export/tests/kafka_fake_broker.rs` | Idempotent producer not re-tested against a real broker after the change |
| I | Findings read in transit | TLS on uplink, Kafka (plain TCP only when explicitly allowed), enroll | `robodr-export/tests/kafka_tls.rs`, `robodr-export/tests/uplink_https.rs` | Diode media are signed, not encrypted |
| D | Network attacker drops the uplink | Crash-safe, at-least-once spool; findings wait; silence is visible at the SOC only if it watches liveness | `robodr-export/tests/pipeline.rs`, `robodr-export/tests/retention.rs` | No agent health check-in in the findings contract yet (SALES-READINESS T5) |
| E | — | The exporters hold no robot authority | — | — |

### TB5: SOC → robot control plane

| | Threat | Mitigation | Tests | Residual |
|---|---|---|---|---|
| S | Unauthenticated party sends actions | Mutual TLS off loopback (client CA, optional pins, CRL); Ed25519 signature by a configured SOC key over method, target, robot id, key id, time, nonce, body hash | `robodr-agentd/tests/control_plane.rs`, `robodr-agentd/tests/control_plane_vectors.rs`, `robodr-agentd/tests/cp_review.rs`; RESULTS R5-R5f | Stolen SOC key **and** client certificate (TA5) |
| T | Request altered or re-targeted to another robot | Signature covers target and robot id; answers bound to the request signature | same | — |
| R | SOC denies having sent a request | Request, signature, body and decision kept in the black box; re-verifiable offline | `robodr-agentd/tests/rev5_evidence.rs` | — |
| I | Evidence export leaks keys or files | Exports carry only black-box frames, signed manifest; no key material | `robodr-agentd/tests/control_plane.rs`, `robodr-blackbox/tests/export.rs` | — |
| D | Slowloris / flood locks the SOC out | Per-source and pre-auth slot caps, handshake and write deadlines, per-key rate limits; flood costs only the control plane | RESULTS S1 (pass), S2 (**fail** before T39); `robodr-agentd/tests/control_plane.rs` slowloris tests | Multi-source slowloris holds the general slots; `soc_sources` keeps a reserved slot for the SOC (in process only, lab re-run open; W2-4, 4-2 GAP-28); reported as `control_plane_saturated`; mitigation `IPAddressAllow=` |
| E | A valid key asks for more than it should | Seven catalog actions only, `authority: request`, no motion fields; judged against the live safety state, policy ceiling and morphology; the executor decides again | `robodr-responder/tests/plan_matrix.rs`, `robodr-responder/tests/fall_prone_review.rs`, `robodr-agentd/tests/review_safety_regressions.rs` | Per-key action scopes (agentd `control_plane.soc_keys`, executor `soc.key_scopes`, configured separately) bound what one key may ask; two-person rule asserted by the SOC (GAP-07) |

### TB6: findings → SOC analysts and LLM agents

| | Threat | Mitigation | Tests | Residual |
|---|---|---|---|---|
| T / E | Prompt injection through node names, topics, detail | SR-TAINT (see TB1); titles and descriptions from a trusted catalog only; robot actions need human approval | `robodr-ocsf/tests/findings.rs`, `robodr-correlate/tests/catalog_drift.rs` | Depends on the SOC rendering tainted fields as data |
| R | Analyst approves a harmful action | Two-person approval for the strongest actions, signed and recorded | RESULTS A0-A13 | Names are asserted by the SOC |

### TB7: commissioning and offline keys

| | Threat | Mitigation | Tests | Residual |
|---|---|---|---|---|
| S / T | Poisoned profile (attacker traffic during learning) or forged sign-off | Observe-mode learning reviewed by operators; quorum sign-off for motion items; signatures verified on the robot | `robodr-commission/tests/operator_signoff.rs`, `robodr-commission/tests/review_regressions.rs` | An attacker present during commissioning is learned unless an operator spots it |
| E | Profile key on the robot | Profile and trust-root keys never on the robot (procedure) | — | Procedural only |

### TB8 and TB12: supply chain and delivery

| | Threat | Mitigation | Tests | Residual |
|---|---|---|---|---|
| T | Tampered package, bundle or RPK | Minisign over every asset; bundle verified before extraction, installed from a private extraction; quorum-signed RPKs; deployment records; anti-rollback floors | `robodr-release/tests/forgery.rs`, `robodr-release/tests/review_13a.rs`, `robodr-deliverd/tests/adversarial.rs`, `robodr-fleet/tests/packaging.rs` | **No release has been signed**; key ceremony not held (SALES-READINESS C1) |
| T | Malicious dependency or Pulsar change | Committed `Cargo.lock`, no git or patched sources, `cargo deny`, pinned Pulsar submodule, due-diligence review | CI `lockfile` and `cargo-deny` jobs; [`third-party-due-diligence.md`](third-party-due-diligence.md) | cargo-deny currently red (RUSTSEC-2026-0387); no SLSA provenance |
| R | Unit denies what it installed | `robot.deliver.*` findings and black-box evidence | `robodr-deliverd/tests/exit_criteria.rs` | — |
| I | Captured unit or media reveals sealed content (TA7) | XChaCha20-Poly1305 sealed chunks; unit key in the TPM behind a signed PCR policy; erase epoch; crypto-erase on tamper | `robodr-seal/tests/adversarial.rs`, `robodr-seal/tests/exit_criteria.rs`, `robodr-seal/tests/lease_14b.rs` | swtpm only; plain evidence and operational keys are not sealed |
| D | Depot or unit refuses all updates | Health gate and rollback; halt-on-failure rollouts | `robodr-depot/tests/adversarial_14a.rs`, `robodr-depot/tests/exit_14b.rs` | — |
| E | Downgrade to a vulnerable version | Downgrade refusal, monotonic security floor, TPM NV anti-rollback for delivery | `robodr-fleet/tests/packaging.rs`, `robodr-deliverd/tests/review_14b.rs` | Not rehearsed on a target (GAP-17) |

### TB9: agentd → executor

| | Threat | Mitigation | Tests | Residual |
|---|---|---|---|---|
| S / E | Compromised agentd asserts an approval or forges an order | HMAC-authenticated socket; the executor verifies the SOC-signed request itself with its own SOC keys and replay store (M1) | `robodr-executor` unit tests (`src/tests.rs`, `src/motion_tests.rs`); RESULTS R6a, R6b, R6f-R6h | The SOC's internal approval is trusted (GAP-07) |
| T | Partial rule set or a revert lost in a crash | Journal (sealed) around every apply; one atomic nft transaction; read-back; reconcile after restart; failed revert is a High finding | `robodr-executor/tests/netns.rs`, `robodr-agentd/tests/executor_link.rs` | Not run under a real systemd on a target (GAP-27) |
| D | Isolation cuts the motion path or management | Protected motion path, management, control buses and discovery accepted before any drop; humanoid `fall_safe_restrict` | `robodr-executor/tests/netns.rs`; RESULTS R6c | Correct only if the motion path is listed correctly |
| E (safety) | A motion adapter de-energises a robot that falls | Morphology gates (`fall_hazard`), two approvers, `oem_validated` per adapter, a `safe_pause` never lifted automatically | `src/motion_tests.rs`, `robodr-responder/tests/fall_prone_review.rs` | Platform behaviour is the OEM's; adapters not run against real peers |

### TB10: controller segment → inline gateway

| | Threat | Mitigation | Tests | Residual |
|---|---|---|---|---|
| S | Spoofed writer or sequence numbers | `allowed_src_ips` / `allowed_src_macs`, sequence state bound to (GUID, IP, MAC), writer-binding conflict findings | `robodr-firewall-gw/tests/gateway.rs`, `robodr-firewall-gw/tests/hardening.rs`, `robodr-firewall-gw/tests/netns_e2e.rs` | Same IP and MAC on the controller segment (GAP-25) |
| T | Out-of-envelope command | Per-channel limits, trajectory checks (splines, NaN, time), hold of the last accepted frame; never originates a datagram | `robodr-firewall-gw/tests/trajectory.rs`, `robodr-firewall-gw/tests/review_motion.rs`, `robodr-firewall/tests/joint_properties.rs` | Channel configuration file not signed (SALES-READINESS T11) |
| D | Gateway down or overloaded | `fail_closed` default, watchdog, FIFO priority; late packets get the fault verdict | `robodr-firewall-gw/tests/netns_e2e.rs`; RESULTS O1 | Overload reported as `robot.gateway.overload` (aggregated per interval, T8); p99 latency unmeasured on a target box (GAP-14, GAP-25) |

### TB11: SOC fleet documents → robot

| | Threat | Mitigation | Tests | Residual |
|---|---|---|---|---|
| S / T | Forged enrollment token, rotation answer, revocation or profile | SOC fleet-key signatures, single-use tokens, proof of possession, root-signed revocations with anti-rollback, staged profiles installed only with a separate approval key and a local operator step | `robodr-fleet/tests/lifecycle.rs`, `robodr-fleet/tests/fleet_vectors.rs`, `robodr-fleet/tests/https.rs` | SOC side unreleased (GAP-18); no decommission flow |
| I | Token on the command line | Token read from a root-only file or stdin only | `robodr-fleet/tests/https.rs` (`cli_never_takes_the_token_from_argv`) | — |

### TB13: local feeds

| | Threat | Mitigation | Tests | Residual |
|---|---|---|---|---|
| S | Unprivileged process injects threats or a false safety state | Peer credential checks; strict line parsing; only catalogued rule ids; safety state from untrusted sources ignored | `robodr-agentd/tests/gateway_feed.rs`, `robodr-agentd/tests/safety_feed.rs`, `robodr-agentd/tests/host_threats.rs` | Root or the gateway user can claim gateway findings (W2-5) |
| D | Feed floods agentd | Bounded queues, `max_connections`, counted drops | RESULTS G8-G10 | Flood folding does not cover this channel (W2-5) |

## 6. Security requirements and traceability

The requirements below are the product-level security requirements
(62443-4-1 SR-2). Each names where it is specified and what enforces it.

| ID | Requirement | Specified in | Verified by |
|---|---|---|---|
| PSR-1 | RoboDR never commands motion, overrides the safety system or originates a motion datagram | [`SECURITY.md`](../../SECURITY.md) "Scope", ADR-0006, gateway README | `robodr-firewall-gw/tests/gateway.rs`, `robodr-responder/tests/randomized_invariants.rs` |
| PSR-2 | No SOC action is executed without an authenticated, replay-protected request and the robot's own judgment against the live safety state | control-plane contract §2, §4 | `robodr-agentd/tests/control_plane.rs`, `robodr-agentd/tests/control_plane_vectors.rs` |
| PSR-3 | Strongest actions need two approvers; de-energising actions never on a humanoid | ADR-0006, ADR-0012, executor README | executor `src/motion_tests.rs`, `robodr-responder/tests/fall_prone_review.rs` |
| PSR-4 | Evidence is signed, chained, and its truncation or rollback is detectable with an anchor | black-box README "Threat model" | `robodr-blackbox/tests/tamper.rs`, `robodr-blackbox/tests/tpm_anchor.rs` |
| PSR-5 | Attacker-controlled strings never reach trusted text (SR-TAINT) | findings contract §3 | `robodr-ocsf/tests/findings.rs` |
| PSR-6 | Every network path to or from the robot is authenticated and integrity-protected; TLS paths check CRLs and fail closed | ingest, control-plane, fleet contracts | `robodr-export/tests/uplink_https.rs`, `robodr-export/tests/kafka_tls.rs`, `robodr-blackbox/tests/remote_anchor_tls.rs` |
| PSR-7 | Hostile input never crashes a daemon | BUILD.md lint policy | fuzz targets and `*/tests/fuzz_smoke*.rs`; `robodr-agentd/tests/abort_restart.rs` |
| PSR-8 | Only signed, non-rolled-back software and profiles are installed or enforced | SECURE-DELIVERY, fleet contract | `robodr-release/tests/forgery.rs`, `robodr-deliverd/tests/adversarial.rs`, `robodr-agentd/tests/profile_trust.rs` |
| PSR-9 | Least privilege per service | packaging README | `scripts/check-packages.py`, `scripts/check-focal-units.py` |
| PSR-10 | Bounded resources; a flood against one interface does not stop detection | 4-2 CR 7.1 | `robodr-agentd/tests/redteam_regressions.rs`; RESULTS R2, G8-G10 |

## 7. Proposed capability security levels (SL-C)

Taken from [`iec-62443-4-2-gap-analysis.md`](iec-62443-4-2-gap-analysis.md)
§2 (a proposal for the product owner, not a claim):

| FR | GA target | Main gap to the target |
|---|---|---|
| FR1 IAC | SL-C 2 | SL 3 needs hardware-protected keys (GAP-04) |
| FR2 UC | SL-C 2 | On-robot approval verification (GAP-07; per-key scopes closed in code) |
| FR3 SI | SL-C 3 | First signed release (GAP-12); field validation |
| FR4 DC | SL-C 2 | Evidence at rest relies on host encryption (H3) |
| FR5 RDF | SL-C 2 | Gateway coverage limits (GAP-25) |
| FR6 TRE | SL-C 3 | FP rate and latency unmeasured on robots (GAP-20) |
| FR7 RA | SL-C 2 | Slot exhaustion (GAP-28); budgets unmeasured (GAP-20) |

## 8. Top residual risks

1. **No signed release, no key ceremony** (TB8): customers cannot verify
   what they run. Owner decision and ceremony (SALES-READINESS C1).
2. **No human review and no external pentest** of any component (C8,
   GAP-26). Every review so far was by AI agents.
3. **Nothing validated on a real robot** (GAP-10, -14, -20, -25, -27):
   the acting components' safety arguments rest on namespace tests.
4. **Root on the host** (TA4) defeats prevention; only detection via
   anchors remains, and the TPM anchor is swtpm-tested only.
5. **SOC trust** (TA5): a stolen SOC key plus client certificate can
   request any catalog action the safety state allows; no per-key scopes.
6. **Control-plane slot exhaustion** by a multi-source slowloris (GAP-28): the SOC's `soc_sources` keep a reserved slot (in process only); other clients are locked out while it lasts.
7. **Personal data in findings** without a redaction option
   ([`data-handling.md`](../customer/data-handling.md)).

## 9. Review log

Each release adds a row: the commit reviewed, who reviewed, what changed
in the model, and new residual risks.

| Date | Commit | Reviewer | Result |
|---|---|---|---|
| 2026-10-30 | `8b2b172` | AI engineering agent (not independent) | First consolidated version. New boundaries TB12, TB13; residual W2-4 recorded as GAP-28. Needs a human review before external use. |
