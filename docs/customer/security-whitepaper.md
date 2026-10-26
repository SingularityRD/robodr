# RoboDR security whitepaper

> **Pre-release draft (refreshed 2026-10-26).** This describes the architecture as
> implemented in the repository at this date, and marks what is planned.
> Claims are limited to what the code and its tests show. Nothing here has
> been validated on a customer robot, and no external audit or penetration
> test has taken place. Normative details are in the contracts under
> [`docs/contracts/`](../contracts/) and in [`SECURITY.md`](../../SECURITY.md).

## 1. What RoboDR is, and what it is not

RoboDR is a detection-and-response component for robots. It watches the
ROS 2 / DDS graph, the motion commands on the bus, and (where it can run)
the Linux host. It compares them with a locked, signed model profile,
records signed evidence, and sends findings to a SOC.

It is **protective only**:

- it never commands motion;
- it never overrides the platform's safety system, e-stop or command
  authority;
- the strongest action it knows is a *request* for a safe state.

It is **not a safety-rated component**
([`docs/compliance/safety-positioning.md`](../compliance/safety-positioning.md)).
By default it **executes no response**: plans and SOC requests are
recorded, not carried out. Two opt-in components can act, within narrow,
reversible limits: executor v1 (network containment) and the inline
Motion Firewall gateway (motion-command filtering on a bridged sensor
box). Section 7 lists exactly what each does.

## 2. Architecture

```
 Robot / sensor box                                              SOC
 ┌────────────────────────────────────────────┐           ┌──────────────────────────┐
 │ robodr-pulsard (root, eBPF)  ──threats──►  │           │                          │
 │ capture (AF_PACKET, CAP_NET_RAW) ─► RTPS ─►│           │ AutoSecOps ingest API    │
 │   CDR ─► profile / Motion Firewall (rec.)  │  TLS      │  (signed batches, key    │
 │   ─► responder (plans) ─► black box (sig.) │ ────────► │   registry, dedup, case) │
 │   ─► OCSF findings spool                   │ uplink    │                          │
 │ robodr-uplink | robodr-spool-export ───────┼─diode────►│ diode-unpack ─► uplink   │
 │ control plane v2 (off by default, mTLS) ◄──┼───────────│ approved action requests,│
 │   └─(HMAC unix socket)─► robodr-executor   │ signed    │ evidence exports         │
 │      (off by default; nftables only)       │           │                          │
 │ robodr-enroll (fleet lifecycle) ───────────┼─TLS──────►│ fleet API (in progress)  │
 └────────────────────────────────────────────┘           └──────────────────────────┘

 Optional inline mode (sensor box with two bridged NICs):
   controller ──► [ bridge ─► NFQUEUE ─► robodr-firewall-gw ] ──► robot
                    pass / limit / hold / remove; never originates a datagram
```

| Process | Privilege | Network |
|---|---|---|
| `robodr-agentd` | User `robodr`, `CAP_NET_RAW` only, syscall filter, `ProtectSystem=strict`, `MemoryMax=512M` | Passive capture only. `IPAddressDeny=any`: agentd opens no IP connection. |
| `robodr-pulsard` | root. Pulsar's eBPF probes load into the kernel. Bounded capabilities. | Local only |
| `robodr-uplink` | User `robodr` | Only the SOC address in its drop-in. TLS. |
| `robodr-spool-export` | User `robodr` | None (`PrivateNetwork=yes`) |
| `robodr-kafka-publish` | User `robodr` | Only the brokers in its drop-in. **No TLS.** |
| `robodr-executor` (off by default) | User `robodr-exec`, `CAP_NET_ADMIN` only, writes only its journal directory, runs `nft` with an argument vector and an empty environment | None: `RestrictAddressFamilies=AF_UNIX AF_NETLINK`, `IPAddressDeny=any` |
| `robodr-firewall-gw` (inline mode only) | `CAP_NET_ADMIN` only (NFQUEUE), FIFO priority 40, watchdog 2 s | No IP sockets; the bridge needs no IP address |
| `robodr-enroll` | root, run by an operator (key files) | Only the SOC, over TLS, or files on media |

Unit files and the reasons behind them:
[`packaging/systemd/`](../../packaging/systemd/),
[`packaging/README.md`](../../packaging/README.md).

## 3. Trust boundaries

| # | Boundary | Treated as | Controls |
|---|---|---|---|
| TB1 | The robot's DDS bus and network | **Hostile input.** Anyone who reaches it can choose node, topic and type names, GUIDs and addresses. | Bounded, strict parsers; fuzzing; participant identity binding (contested prefixes fail closed); taint marking of every attacker-chosen string (section 6) |
| TB2 | The host OS of the robot or box | Trusted for privilege separation; not trusted to be unmodified | systemd confinement; signed and anti-rollback profile state; signed black box with optional head anchors that make rollback detectable |
| TB3 | Robot → SOC network | Untrusted | TLS (rustls) with the operator's CA and optional SPKI pin; Ed25519 batch signatures; optional per-finding signatures; server-side replay table |
| TB4 | Data diode or media | One-way, untrusted carrier | Ed25519-signed, hash-chained batches; Reed-Solomon parity; the SOC holds only public keys |
| TB5 | SOC → robot (control plane) | Untrusted network; the SOC is trusted only to sign approved requests | Mutual TLS (rustls) off loopback; Ed25519 request signatures bound to robot id, target, nonce and time, with a persisted replay store; judgment against the live safety state; every answer signed; evidence exports with signed manifests. No per-key action scopes yet. |
| TB9 | agentd → executor (local) | agentd is trusted for what it judged, including the approval flag | HMAC-authenticated unix socket; the executor re-checks its own policy, configuration and the live safety state; reversible, TTL-bounded rules only. A compromised agentd can assert an approval; verification of the SOC signature in the executor is planned. |
| TB10 | Controller segment → inline gateway | Hostile: GUIDs and sequence numbers are claims | Per-channel `allowed_src_ips` / `allowed_src_macs`; sequence state bound to (GUID, source IP, MAC); unknown writers probed and undecidable samples suppressed. **Not covered:** a sender with the controller's own IP and MAC on that segment, discovery paths that bypass the bridge, DDS ports outside the queued range. |
| TB11 | SOC fleet documents → robot | Verified data, never orders | SOC fleet-key signatures, single-use enrollment tokens, root-signed revocation lists with anti-rollback; SOC profiles staged and installed only with an approval signed by a separate SOC approval key and a local operator command. |
| TB6 | SOC analysts and LLM agents | May be misled by finding contents | Taint delimiting; actions need human approval (two people for the strongest) |
| TB7 | Commissioning station and offline keys | Trusted, offline | Profile and trust-root keys never on the robot; operator sign-off with a quorum, verified on the robot |
| TB8 | Release supply chain | Verified at the site's entry station | Minisign signatures, `SHA256SUMS`, reproducible pure binaries, SBOM. *Designed; the release workflow has never run.* |

## 4. Keys

All keys are Ed25519 (the audited `ed25519-dalek` crate, strict
verification) in the `robodr-blackbox-key/v2` file format. Secret files
are `0600 root`, and services receive them only as systemd credentials. No
tool accepts a key on its command line.

| Key | Lives | Signs |
|---|---|---|
| Black-box key | robot | the evidence chain |
| Finding key | robot (required when the control plane is enabled) | per-finding signatures; control-plane answers; evidence-export manifests |
| Control-plane TLS key and certificate | robot | the robot's TLS server identity (the SOC's client CA and optional SPKI pins configured next to it) |
| Executor protocol key | robot (agentd and executor) | HMAC over agentd ↔ executor messages |
| Uplink or relay key | robot / sensor box, or the SOC-side importer | ingest batches |
| Diode key | robot | diode batches |
| SOC key | SOC | control-plane requests (its `.pub` on each robot) |
| SOC fleet key, SOC approval key | SOC | enrollment tokens and fleet documents; profile approvals (two separate keys) |
| Profile-signing key | commissioning station, never the robot | locked profiles |
| Trust roots | offline station or token | profile trust files, revocation lists |
| Operator keys | each operator | commissioning sign-off |
| Release key | SingularityRD, offline | releases (minisign) |

Limits:

- keys are files, not TPM-held;
- rotation and distribution are manual
  ([`docs/OPERATIONS.md`](../OPERATIONS.md) section 4);
- legacy HMAC keys still load, with a warning.

Robot side available, SOC side in progress: enrolment with a single-use,
SOC-signed token (read from a root-only file or standard input, never the
command line) and rotation of the uplink and finding keys with the SOC
(`robodr-enroll`; keys are generated on the unit and never leave it; the
enrollment request is signed by all three new keys;
[`docs/OPERATIONS.md`](../OPERATIONS.md) section 8.6). Planned: TPM sealing
(S10) and the AutoSecOps side of the fleet API.

## 5. Integrity and evidence

- **Black box.** Each record is Ed25519-signed and hash-chained, and
  fsynced for critical records. The chain identity binds device, boot and
  key. Crash recovery, drops and pruning each leave a signed record.
  Verification: `robodr-blackbox verify` with the `.pub` only.
  Truncation of the newest records plus a state rollback is detectable
  only with a head anchor the attacker cannot rewind (a TPM NV counter,
  tested on swtpm only; or a remote receiver)
  ([`crates/robodr-blackbox/README.md`](../../crates/robodr-blackbox/README.md),
  "Threat model").
- **Profiles.** A locked profile is signed by a profile key from the
  root-signed trust file. It carries the operators' signed sign-off
  (motion items need a quorum), is bound to its content, and has
  anti-rollback state. Revocation lists can revoke signing keys.
- **Findings.** Optional detached per-finding signatures, carried
  unchanged through the ingest API. Ingest batches are signed over the
  exact body bytes.
- **Evidence exports.** The control plane's evidence API exports
  black-box frames exactly as stored, as `RBBXBND1` bundles with a
  manifest signed by the finding key, in signed, size-bounded, resumable
  chunks; `robodr-blackbox verify BUNDLE` checks them
  ([`docs/contracts/robodr.control-plane.md`](../contracts/robodr.control-plane.md) §11).

## 6. Attacker-controlled data and prompt injection

Strings an attacker can choose (ROS node, topic and type names, GUIDs,
source addresses, process and file names, free-text detail) can reach an
LLM-based SOC. RoboDR treats each one as a potential prompt-injection
carrier ([`docs/contracts/robodr.findings.md`](../contracts/robodr.findings.md)
§3, SR-TAINT):

- They appear only in typed, `taint: adversary` data fields. They are
  **never** interpolated into the title, description or message, which
  come from a trusted rule catalog.
- Every tainted location is listed as a JSON Pointer in
  `adversary_controlled_fields`.
- Escaping uses an **allow-list**. Each string has two renderings:
  - a lossless escaped `value`;
  - a lossy ASCII `display` with nothing a model could "decode".
- Flags mark `non_ascii`, `mixed_script` (homoglyphs) and
  `injection_hint` (role labels, "ignore", verdict words, URLs, Markdown,
  HTML, templates).
- A corpus of injections is part of the test suite (`INJECTIONS` in
  [`crates/robodr-ocsf/tests/findings.rs`](../../crates/robodr-ocsf/tests/findings.rs)).

The ingest contract requires the SOC to store these fields as data, render
them delimited, and label them untrusted in any LLM prompt. An LLM agent
can never send a robot action without human approval
([ADR-0006](../adr/0006-approval-never-autonomous.md)). On its development
branch AutoSecOps renders these fields only as neutralised, labelled
untrusted data, refuses to sign a robot action without platform sign-off
(two people for the strongest actions), and forces approval for the robot
action tools in every agent; this is not released yet.

## 7. What is and is not executed

| Item | Today |
|---|---|
| Response plans (on-robot responder) | **Recorded, not executed** by default. With executor v1 enabled (off by default), an eligible plan's network isolation / participant quarantine may be handed to `robodr-executor` (`planner_orders`); never on a humanoid, where everything needs a human. |
| SOC action requests (control plane v2) | Authenticated, judged, recorded; answered `recorded_not_executed`: **nothing reaches the robot** unless executor v1 is enabled. Then only `isolate_network` and `quarantine_node` (nftables, reversible, TTL) and `record_evidence` are executed, by the separate `robodr-executor`, after its own precheck and a safety-state re-check right before apply; states `verified` / `refused` / `failed` / `reverted` are signed and journalled. `restrict_motion` is recorded only; `safe_pause`, `request_safe_state` and `rollback_config` are never executed. |
| Motion Firewall, passive modes | Decides per command and per joint frame; **recording only**. |
| Motion Firewall, inline gateway (opt-in) | Passes, limits in place, holds (humanoid: never damping or limp) or removes motion samples that cross the bridge; never originates a datagram; `fail_closed` by default when it is down. Its limits are configuration, not SOC actions. |
| Processes RoboDR starts | None on the robot's behalf. |
| Code loaded into the kernel | Pulsar's eBPF probes (GPL-2.0), only by `robodr-pulsard`, only where enabled. |
| Network transmission from agentd | None (passive capture; IP denied). |

**Planned for GA (not implemented):** `restrict_motion` as a SOC action
through the gateway, and `safe_pause` through OEM-validated platform
adapters; verification of the SOC signature and approval inside the
executor. Every action needs SOC approval, a re-check against the live
safety state on the robot, and an automatic revert at TTL. On humanoids
the de-energising actions are never executable
([ADR-0005](../adr/0005-action-catalog.md),
[ADR-0012](../adr/0012-balancing-robot-response-rules.md)).

## 8. Availability and failure behaviour

- In the passive modes nothing in the motion stack depends on RoboDR.
  agentd is OOM-killed before the motion stack, and its loss is visible
  (watchdog, stale status, missing heartbeats).
- **Inline mode is the exception.** The robot's commands cross the
  gateway. When it is down, `fail_closed` (default) drops them and the
  robot's own command timeout applies; `bypass` forwards them unchecked
  and is refused for a humanoid joint channel. A late packet gets the
  firewall's fault verdict (hold on a humanoid). Integrators must include
  this in their risk assessment
  ([`docs/compliance/safety-positioning.md`](../compliance/safety-positioning.md)).
- The executor fails toward "no rule set": any journal, nft, read-back,
  safety-state or configuration error leaves the robot without the
  action. An operator's `nft delete table inet robodr` disables it at
  once.
- Parsers, queues, caches and rate limits are bounded. A flood against
  the control plane costs the control plane (429/503), never detection.
- Exporters are crash-safe and at-least-once. A batch the SOC keeps
  refusing blocks later findings visibly, and is never dropped.
- `panic = "abort"`: a panic stops the daemon until systemd restarts it.
  Panic-family calls are denied in the daemon crates' non-test code, and a
  process-level test checks that the black box verifies across an abort
  and restart.

## 9. Supply chain

- Committed `Cargo.lock`, `--locked` builds, and `cargo deny` for
  licences, advisories, bans and sources.
- Pure binaries are reproducible bit for bit (pinned Rust and clang).
- A CycloneDX SBOM is produced per build.
- Releases are designed to be minisign-signed, with the public key
  delivered out of band.
- **Not yet:**
  - a real release;
  - SLSA or cosign provenance;
  - a reproducibility check of the Pulsar-bound binary;
  - a third-party notices file in the packages;
  - CI runs on GitHub.

  See [`docs/BUILD.md`](../BUILD.md).

## 10. Further reading

[`known-limitations.md`](known-limitations.md) ·
[`support-matrix.md`](support-matrix.md) ·
[`docs/compliance/iec-62443-4-2-gap-analysis.md`](../compliance/iec-62443-4-2-gap-analysis.md) ·
[`psirt-process.md`](psirt-process.md)
