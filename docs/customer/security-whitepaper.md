# RoboDR security whitepaper

> **Pre-release draft (2026-10-26).** This describes the architecture as
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
In this release it **executes no response at all**: plans and SOC requests
are recorded, not carried out.

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
 │ control plane v2 (off by default, mTLS)    │ ◄──────── │ approved action requests │
 └────────────────────────────────────────────┘ signed    └──────────────────────────┘
```

| Process | Privilege | Network |
|---|---|---|
| `robodr-agentd` | User `robodr`, `CAP_NET_RAW` only, syscall filter, `ProtectSystem=strict`, `MemoryMax=512M` | Passive capture only. `IPAddressDeny=any`: agentd opens no IP connection. |
| `robodr-pulsard` | root. Pulsar's eBPF probes load into the kernel. Bounded capabilities. | Local only |
| `robodr-uplink` | User `robodr` | Only the SOC address in its drop-in. TLS. |
| `robodr-spool-export` | User `robodr` | None (`PrivateNetwork=yes`) |
| `robodr-kafka-publish` | User `robodr` | Only the brokers in its drop-in. **No TLS.** |

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
| TB5 | SOC → robot (control plane) | Untrusted network; the SOC is trusted only to sign approved requests | Ed25519 request signatures bound to robot id, nonce and time; judgment against the safety state; signed evidence; mutual TLS (rustls) off loopback and signed answers (control plane v2). |
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
| Finding key (optional) | robot | per-finding signatures; control-plane answers |
| Uplink or relay key | robot / sensor box, or the SOC-side importer | ingest batches |
| Diode key | robot | diode batches |
| SOC key | SOC | control-plane requests (its `.pub` on each robot) |
| Profile-signing key | commissioning station, never the robot | locked profiles |
| Trust roots | offline station or token | profile trust files, revocation lists |
| Operator keys | each operator | commissioning sign-off |
| Release key | SingularityRD, offline | releases (minisign) |

Limits:

- keys are files, not TPM-held;
- rotation and distribution are manual
  ([`docs/OPERATIONS.md`](../OPERATIONS.md) section 4);
- legacy HMAC keys still load, with a warning.

Planned: TPM sealing (S10) and enrolment and rotation from the SOC (S9).

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
([ADR-0006](../adr/0006-approval-never-autonomous.md)). The SOC-side
enforcement and evaluation are AutoSecOps work (S3, S6).

## 7. What is and is not executed

| Item | Today |
|---|---|
| Response plans (on-robot responder) | **Recorded, not executed** by default. With executor v1 enabled (off by default), an Eligible plan's network isolation / participant quarantine may be handed to `robodr-executor`. |
| SOC action requests (control plane v2) | Authenticated, judged, recorded; answered `recorded_not_executed`: **nothing reaches the robot** unless executor v1 is enabled. Then only `isolate_network` and `quarantine_node` (nftables, reversible, TTL) and `record_evidence` are executed, by the separate `robodr-executor` (the only `CAP_NET_ADMIN` unit). |
| Motion Firewall | Decides per command and per joint frame; **recording only**. No in-path gateway. |
| Processes RoboDR starts | None on the robot's behalf. |
| Code loaded into the kernel | Pulsar's eBPF probes (GPL-2.0), only by `robodr-pulsard`, only where enabled. |
| Network transmission from agentd | None (passive capture; IP denied). |

**Planned for GA (not implemented):** executing the reversible actions
`restrict_motion`, `quarantine_node`, `isolate_network` and
`record_evidence`, plus `safe_pause` through OEM-validated platform
adapters. Every one needs SOC approval, a re-check against the live
safety state on the robot, and an automatic revert at TTL. On humanoids
the de-energising actions are never executable
([ADR-0005](../adr/0005-action-catalog.md),
[ADR-0012](../adr/0012-balancing-robot-response-rules.md)).

## 8. Availability and failure behaviour

- Nothing in the motion stack depends on RoboDR. agentd is OOM-killed
  before the motion stack, and its loss is visible (watchdog, stale
  status, missing heartbeats).
- Parsers, queues, caches and rate limits are bounded. A flood against
  the control plane costs the control plane (429/503), never detection.
- Exporters are crash-safe and at-least-once. A batch the SOC keeps
  refusing blocks later findings visibly, and is never dropped.
- `panic = "abort"`: a panic stops the daemon until systemd restarts it.

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
