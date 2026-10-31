# RoboDR security whitepaper

> **Pre-release draft (refreshed 2026-10-31).** This describes the architecture as
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
recorded, not carried out. Three opt-in components can act:

- executor v1: network containment (reversible, TTL-bounded nftables
  rules) and, where the site configures OEM-validated platform adapters,
  motion actions; a `rollback_config` adapter runs the site's own rollback
  program, whose effect RoboDR cannot undo;
- the inline Motion Firewall gateway: motion-command filtering on a
  bridged sensor box;
- secure delivery (`robodr-deliverd`, root): it installs signed packages
  with `dpkg` (their maintainer scripts run as root; a failed health check
  rolls back to the previous version), and, with sealed delivery
  configured, **crypto-erases** the unit's sealed keys on an operator
  command or a platform tamper / attestation / authentication trigger.
  The erase is **irreversible** (recovery is re-enrolment and
  re-delivery); it also stops the services listed in `seal.stop_units`
  and closes the runtime volume once the robot is idle or in a safe
  state.

Section 7 lists what each does.

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
 │      (off by default; nftables, adapters)  │           │                          │
 │ robodr-enroll (fleet lifecycle) ───────────┼─TLS──────►│ fleet API (unreleased)   │
 └────────────────────────────────────────────┘           └──────────────────────────┘

 Optional inline mode (sensor box with two bridged NICs):
   controller ──► [ bridge ─► NFQUEUE ─► robodr-firewall-gw ] ──► robot
                    pass / limit / hold / remove; never originates a datagram
```

| Process | Privilege | Network |
|---|---|---|
| `robodr-agentd` | User `robodr-agentd`, `CAP_NET_RAW` only, syscall filter, `ProtectSystem=strict`, `MemoryMax=512M` | Passive capture. `IPAddressDeny=any`: by default agentd opens no IP connection. Opt-in, each only to the addresses of an `IPAddressAllow=` drop-in: the control plane's inbound mutual-TLS listener (`30-control-plane.conf.example`), and an outbound TLS connection to a remote head-anchor receiver (`blackbox.head_anchor` kind `remote`). |
| `robodr-pulsard` | root. Pulsar's eBPF probes load into the kernel. Bounded capabilities. | Local only |
| `robodr-uplink` | User `robodr` | Only the SOC address in its drop-in. TLS. |
| `robodr-spool-export` | User `robodr` | None (`PrivateNetwork=yes`) |
| `robodr-kafka-publish` | User `robodr` | Only the brokers in its drop-in. TLS (plain TCP only if explicitly allowed); optional mutual TLS, SASL/SCRAM. |
| `robodr-executor` (off by default) | User `robodr-exec`, `CAP_NET_ADMIN` only; changes only the nftables table `inet robodr`; writes only its journal directory (`/var/lib/robodr/executor`; the motion drop-in adds the gateway's restriction directory); runs `nft` and motion adapters with an argument vector and an empty environment | None by default: `RestrictAddressFamilies=AF_UNIX AF_NETLINK`, `IPAddressDeny=any`. Motion adapters need a drop-in (`robodr-executor.service.d/40-motion.conf.example`) that adds `AF_INET` and allows exactly their peers |
| `robodr-firewall-gw` (inline sensor box, opt-in) | User `robodr-gw`, `CAP_NET_ADMIN` only (NFQUEUE), FIFO priority 40, watchdog 2 s | `RestrictAddressFamilies=AF_UNIX AF_NETLINK`, `IPAddressDeny=any`; it never originates a datagram, and the bridge needs no IP address |
| `robodr-anchor-receiver` (off-robot) | `DynamicUser=yes`, no capabilities | Its listen address; TLS (mutual TLS optional) |
| `robodr-deliverd` (secure delivery, opt-in) | root, no ambient capabilities (it installs packages, drives the TPM and crypto-erases) | None by default (`PrivateNetwork=yes`, `IPAddressDeny=any`; releases on media). LAN delivery (`robodr-deliverd.service.d/50-depot-lan.conf.example`) opens mutual TLS to the site depot's address only |
| `robodr-depot` (site depot, off-robot) | User `robodr-depot`, no capabilities | Its LAN listen address |
| `robodr-enroll` (run by the operator) | root (`sudo`), no daemon; it reads the enrollment token only from a file closed to group and others (owned by root) or from standard input, never from the command line | Only the SOC's fleet API, TLS; air-gapped units exchange a request and an answer file on media instead |

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
| TB9 | agentd → executor (local) | agentd is trusted for what it judged, including the approval flag | HMAC-authenticated unix socket; the executor re-checks its own policy, configuration and the live safety state; reversible, TTL-bounded rules only. A control-plane order carries the SOC's signed request, which the executor verifies itself (its own SOC keys and replay store), so a compromised agentd cannot assert an approval it does not hold. |
| TB10 | Controller segment → inline gateway | Hostile: GUIDs and sequence numbers are claims | Per-channel `allowed_src_ips` / `allowed_src_macs`; sequence state bound to (GUID, source IP, MAC); unknown writers probed and undecidable samples suppressed. **Not covered:** a sender with the controller's own IP and MAC on that segment, discovery paths that bypass the bridge, DDS ports outside the queued range. |
| TB11 | SOC fleet documents → robot | Verified data, never orders | SOC fleet-key signatures, single-use enrollment tokens, root-signed revocation lists with anti-rollback; SOC profiles staged and installed only with an approval signed by a separate SOC approval key and a local operator command. |
| TB6 | SOC analysts and LLM agents | May be misled by finding contents | Taint delimiting; actions need human approval (two people for the strongest) |
| TB7 | Commissioning station and offline keys | Trusted, offline | Profile and trust-root keys never on the robot; operator sign-off with a quorum, verified on the robot |
| TB8 | Release supply chain | Verified at the site's entry station | Minisign signatures, `SHA256SUMS`, reproducible pure binaries, SBOM. *Designed; the release workflow has never run.* |

## 4. Keys

All keys are Ed25519 (the audited `ed25519-dalek` crate, strict
verification) in the `robodr-blackbox-key/v2` file format. Secret files
are `0600 root`, and services receive them as systemd credentials. No
tool accepts a key on its command line. Two exceptions: the site depot
(off the robot) reads its keys by path from `/etc/robodr-depot/keys`
(0700, owned by its user `robodr-depot`), because the operator's depot
commands load the same keys; and on `robodr-focal` (systemd 245, no
`LoadCredential=`) a root helper copies each credential to
`/run/credentials/<unit>/` on a tmpfs, which can be swapped out, unlike
systemd's credential store (encrypt swap or run without it).

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
| Release key | GitHub environment `release` of the RoboDR repository (encrypted minisign secret key and its password as environment secrets), used online by the release workflow's publish job on a GitHub-hosted runner after two required reviewers approve; an offline copy stays with the root key. Not generated yet: no release has been signed | releases (minisign) |
| Release root key | SingularityRD, offline | the statement that names the current release key |

Limits:

- keys are files by default. agentd's keys can be sealed to the TPM at
  rest (systemd encrypted credentials; decrypted into the service's memory
  at run time, the TPM does not sign; tested on swtpm only), and offline
  signing keys can live in a PKCS#11 token (tested with SoftHSM only;
  OpenSC 0.25 or later on the signing station, PIN from an environment
  variable or file). Limits in
  [`known-limitations.md`](known-limitations.md);
- rotation and distribution are manual
  ([`docs/OPERATIONS.md`](../OPERATIONS.md) section 4);
- legacy HMAC keys are refused unless explicitly allowed
  (`blackbox.allow_hmac`, `--allow-hmac`).

Robot side available, SOC side on an unreleased AutoSecOps branch
(enrollment ran end to end against it in one container,
`tools/e2e/RESULTS.md`): enrolment with a single-use,
SOC-signed token (read from a root-only file or standard input, never the
command line) and rotation of the uplink and finding keys with the SOC
(`robodr-enroll`; keys are generated on the unit and never leave it; the
enrollment request is signed by all three new keys;
[`docs/OPERATIONS.md`](../OPERATIONS.md) section 8.6). TPM use exists for the
black-box head anchor and for sealed delivery (`robodr-seal`, a TPM-resident
unit key), tested against swtpm only; the agent's own signing keys are
still files.

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
  unchanged through Kafka (`robodr-kafka-publish`) and the ingest API.
  Ingest batches are signed over the exact body bytes. Per-finding
  signatures do **not** cross the diode: there a batch is authenticated
  as a whole by its unit-bound manifest signature, which the importer
  checks, and the findings it emits carry no signature. A SOC behind a
  diode therefore runs signature checks in the optional policy, and
  whoever can produce to its findings topic (after the importer) can
  inject findings that look the same as imported ones: the produce ACL on
  that topic is the trust boundary
  ([`known-limitations.md`](known-limitations.md), "Security of RoboDR
  itself"; contract §8).
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
| SOC action requests (control plane v2) | Authenticated, judged, recorded; answered `recorded_not_executed`: **nothing reaches the robot** unless executor v1 is enabled. Then `isolate_network` and `quarantine_node` (nftables, reversible, TTL) and `record_evidence` are executed, by the separate `robodr-executor`, after its own precheck and a safety-state re-check right before apply; states `verified` / `refused` / `failed` / `reverted` are signed and journalled. `restrict_motion`, `safe_pause`, `request_safe_state` and `rollback_config` are recorded or refused unless the site configures a platform adapter for them **and** sets its `oem_validated: true` (`gateway`, `unitree_sport`, `nav2`, `ros2_control`, `px4`, `rollback`); pause, safe state and rollback then need two distinct human approvers and are never executed on a humanoid ([support matrix](support-matrix.md#response-actions)). |
| Motion Firewall, passive modes | Decides per command and per joint frame; **recording only**. |
| Motion Firewall, inline gateway (opt-in) | Passes, limits in place, holds (humanoid: never damping or limp) or removes motion samples that cross the bridge; never originates a datagram; `fail_closed` by default when it is down. Its limits are configuration, not SOC actions. |
| Processes RoboDR starts | No process of the robot's own. Its components run tools with an argument vector: the executor `nft`, the configured motion adapters and (`rollback_config`) the site's rollback program; deliverd `dpkg` / `dpkg-deb` / `dpkg-query` (package maintainer scripts run as root), `systemctl` (health checks, the erase lockdown), `mount` / `umount`, `cryptsetup`, the `tpm2-tools` and the site's configured rules reload and validator commands; agentd the `tpm2-tools` for a TPM head anchor. |
| Code loaded into the kernel | Pulsar's eBPF probes (GPL-2.0), only by `robodr-pulsard`, only where enabled. |
| Network transmission from agentd | None by default (passive capture; IP denied). Opt-in: answers on the control plane's mutual-TLS listener, and marks to a remote head-anchor receiver, each to the addresses its `IPAddressAllow=` drop-in names. |
| Secure delivery (`robodr-deliverd`, opt-in) | Installs quorum-signed packages with `dpkg` after a safety-state check, rolls back on a failed health check. Crypto-erase (sealed delivery only): destroys the unit's sealed keys at once, in every safety state, and **cannot be undone**; stopping `seal.stop_units` and closing the runtime volume wait until the robot is idle, in a safe state or e-stopped. Triggers: an operator command, or the platform's tamper / attestation / authentication input on a peer-checked socket ([OPERATIONS](../OPERATIONS.md) §12.6, §12.8). |

**Implemented, not yet validated by an OEM:** `restrict_motion` as a SOC
action through the gateway (run with the real gateway in a lab soak) and
`safe_pause` / `request_safe_state` / `rollback_config` through platform
adapters (run against in-process simulated peers only); the executor
verifies the SOC's signature itself. It cannot verify the SOC's internal
approval process. Every action needs SOC approval, a re-check against the
live safety state on the robot, and, where it is reversible, an automatic
revert at TTL; a `safe_pause` is never lifted automatically. On humanoids
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
  Panic-family calls are denied in the non-test library code of the
  daemon crates and in the entry files of agentd, the executor and the
  gateway (not yet in the entry files of the exporters, the anchor
  receiver and pulsard; [`known-limitations.md`](known-limitations.md)),
  and a process-level test checks that the black box verifies across an
  abort and restart.

## 9. Supply chain

- Committed `Cargo.lock`, `--locked` builds, and `cargo deny` for
  licences, advisories, bans and sources.
- Pure binaries are reproducible bit for bit (pinned Rust and clang).
- A CycloneDX SBOM is produced per build.
- Releases are designed to be minisign-signed, with the public key
  delivered out of band.
- **Not yet:**
  - a real release;
  - an independently produced provenance. The release workflow writes
    SLSA v1 provenance (`robodr-<ver>.intoto.jsonl`, an in-toto statement
    over every asset, minisign-signed like the assets) and a GitHub
    (Sigstore) build-provenance attestation of every asset, but both come
    from the same workflow that builds and signs, and neither has been
    produced for a real release yet; no SLSA build level is claimed;
  - a reproducibility check of the Pulsar-bound binary;
  - a green CI run on GitHub (the first complete run, 2026-10-30, failed
    several jobs).

  Third-party notices and the eBPF GPL-2.0 source offer ship in every
  package.

  See [`docs/BUILD.md`](../BUILD.md).

## 10. Further reading

[`known-limitations.md`](known-limitations.md) ·
[`support-matrix.md`](support-matrix.md) ·
[`docs/compliance/iec-62443-4-2-gap-analysis.md`](../compliance/iec-62443-4-2-gap-analysis.md) ·
[`psirt-process.md`](psirt-process.md)
