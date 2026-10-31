# RoboDR data handling and privacy

> **Pre-release document. Verified at commit `8b2b172` (2026-10-30)**
> against the code, unit files and contracts at that commit. It describes
> what data RoboDR processes, where it goes, how it is protected and how
> long it is kept, so that a customer can complete a record of processing,
> a DPIA or a vendor questionnaire. It is not legal advice and not a data
> processing agreement (DPA); the DPA is a separate contract that
> SingularityRD has not yet issued (see the end of this page).

## 1. Summary

- **RoboDR sends no data to SingularityRD.** No component has a
  SingularityRD address compiled in or configured, there is no telemetry,
  no licence check-in and no automatic update download. The only URL of
  ours in the code is the findings JSON Schema identifier
  (`https://schemas.singularityrd.com/robodr/findings/...`), which is a
  name and is never fetched. Data reaches SingularityRD only if you send
  it to us, for example with a support request.
- **Everything stays on the unit or goes where you configure it:** your
  SOC (`robodr-uplink`), your Kafka brokers (`robodr-kafka-publish`), your
  diode or media (`robodr-spool-export`), your anchor receiver, your site
  depot. You choose and operate every destination.
- **RoboDR does not record raw network traffic or sensor data in
  operation.** It parses traffic in memory and keeps findings and decision
  records, not packets, video, audio, point clouds or maps.
- **Some records can identify people** (section 3): network addresses of
  devices on the robot network, host process and user ids, the names of
  SOC operators who request and approve actions, and the names of
  commissioning operators. There is **no redaction option yet**.
- **At rest, RoboDR signs but does not encrypt** its evidence, findings
  and state (exception: content sealed by secure delivery). Use full-disk
  encryption on the unit where this matters.

## 2. Roles

For the data RoboDR processes on your robots and in your SOC, **you (the
asset owner or operator) are the controller.** SingularityRD supplies the
software and does not receive or process this data. If you send us data
for support (logs, a support bundle, black-box exports, captures),
SingularityRD processes it on your behalf for that request; the terms
belong in the DPA. Do not include live evidence, keys or captures in a
first support request or vulnerability report ([`SECURITY.md`](../../SECURITY.md)).

## 3. Data categories

| Category | Examples | Can identify a person? | Where it comes from |
|---|---|---|---|
| Robot and site identifiers | robot id, model, site, workspace, unit key ids | Indirectly (a robot assigned to a named person) | Your configuration, enrollment |
| Network identifiers on the robot network | IP and MAC addresses, DDS GUID prefixes and locators of participants, WebRTC client addresses (for example a Unitree app on a phone) | **Yes**, where a device belongs to a person (a laptop, a phone) | Observed traffic |
| ROS 2 names | node, topic and type names; free-text detail | Rarely (a name someone chose) | Observed traffic (attacker-controlled, tainted) |
| Host process data | rule name, process image path, pid, ppid, uid, gid, container flag (Pulsar threats) | **Yes**: a uid maps to a user account on the host | `robodr-pulsard` (eBPF) |
| Motion data in findings | commanded speeds and joint values that broke the envelope, channel names | No (machine data) | Observed commands |
| SOC operator identities | `requested_by`, `approved_by` on control-plane requests (user names or email-like ids), key ids | **Yes** | Your SOC |
| Commissioning operator identities | operator key ids and names in profile sign-offs | **Yes** | Your commissioning operators |
| Software inventory | package versions, agentd version, profile digest | No | The unit |
| Keys and certificates | private keys (never leave the unit or its owner), public keys, certificates | Certificates may carry names | You |

RoboDR does not process special categories of personal data (GDPR Art. 9),
biometric data, location tracks or sensor content.

## 4. Inventory per flow

"Default retention" is the shipped default; most values are configurable
(the reference is in the "Where set" column). "Encrypted in transit /
at rest" refers to RoboDR's own protection; host full-disk encryption
adds to the "at rest" column.

| # | Flow | Data | Stored where | Encrypted in transit | Encrypted at rest | Integrity | Default retention | Where set / deletion |
|---|---|---|---|---|---|---|---|---|
| F1 | Capture and parsing (`robodr-agentd`) | Packets of the robot network, in memory only | Not stored | — | — | — | Not kept | — |
| F2 | Black box | Findings, deviations, decisions, control-plane requests with signatures and operator names, executor events, profile acceptance, safety-state changes | `/var/lib/robodr/blackbox/agentd` on the unit (example configuration) | — | No | Ed25519-signed, hash-chained | Ring of 8 segments × 8 MiB (oldest dropped with a signed record) | `blackbox` section of `agentd.json`; deletion: segment rotation, or the whole store at decommissioning (OPERATIONS §9). Single records cannot be deleted without breaking the chain. |
| F3 | Findings spool | Findings (OCSF Detection Finding in the `robodr.findings` envelope) | `/var/lib/robodr/spool/agentd` | — | No | Optional per-finding signatures | Until an exporter has delivered them; `done/` markers (ids only) 30 days | `robodr-export` README "Retention"; dead-letter files are never deleted by default (they may be the only copy) |
| F4 | Uplink to your SOC (`robodr-uplink`) | Findings in signed NDJSON batches | Your SOC | TLS (rustls), your CA, optional SPKI pin, CRL | Your SOC's | Ed25519 batch signature | Your SOC's policy | [`robodr.ingest-api`](../contracts/robodr.ingest-api.md) |
| F5 | Kafka export (`robodr-kafka-publish`) | Findings | Your brokers | TLS by default (plain TCP only if explicitly allowed); optional mutual TLS, SASL/SCRAM | Your brokers' | Optional per-finding signatures | Proposed topic retention 7 days | [`robodr.findings`](../contracts/robodr.findings.md) §7 |
| F6 | Diode / media (`robodr-spool-export`) | Findings and black-box bundles | Media, then your SOC | No (signed, not encrypted): protect the media physically | No | Ed25519, hash chain, Reed-Solomon parity | Until you delete the media | OPERATIONS; diode README |
| F7 | Control plane (`robodr-agentd`, off by default) | Action requests and answers; evidence exports (black-box frames) | Request journal and replay store under `/var/lib/robodr`; exports in the evidence directory | Mutual TLS off loopback | No | Ed25519 signatures; sealed journal | Exports deleted after 24 h, at most 8 kept and 512 MiB in all | [`robodr.control-plane`](../contracts/robodr.control-plane.md) §11 |
| F8 | Executor (`robodr-executor`, off by default) | Action journal (ids, targets such as GUIDs and addresses, times) | `/var/lib/robodr/executor` | — (local socket) | No | Sealed journal | Until the action ends; purge removes it | executor README |
| F9 | Local feeds (`host_threats`, `gateway_feed`, safety socket) | Pulsar threats, gateway findings, safety state | Not stored as such; they become F2 / F3 records | — (unix sockets, peer-checked) | — | — | — | — |
| F10 | Pulsar threat log | Pulsar threats (process image, pid, uid) | The systemd journal | — | Host's | Host's | Your journald settings | `pulsar.toml` `[module.threat-logger]` |
| F11 | Status and service logs | Counters, health, refusal reasons (sanitised) | `status.json`, the systemd journal | — | Host's | — | Your journald settings | — |
| F12 | Gateway events (`robodr-firewall-gw`, inline mode) | Firewall deviations and gateway findings, writer addresses | Local JSON-lines events file (`events_path`) | — | No | No | Rotated at `events_max_bytes` (64 MiB) | gateway README |
| F13 | Fleet enrollment (`robodr-enroll`) | robot id, site, workspace, agentd version, profile digest, public keys | Your SOC; fleet state on the unit | TLS, or files on media | No | Signed by all unit keys and the SOC fleet key | Your SOC's policy | [`robodr.fleet-api`](../contracts/robodr.fleet-api.md) |
| F14 | Head anchor marks (optional) | unit id, chain id, sequence number, hash | Your anchor receiver | TLS by default | No | Ed25519 | Latest mark per unit | black-box README |
| F15 | Secure delivery (`robodr-deliverd`, `robodr-depot`, optional) | Packages, unit inventory, attested reports, leases | Your site depot; the unit | Mutual TLS on the LAN, or media | Sealed content: yes (XChaCha20-Poly1305, TPM-bound keys); the rest: no | Quorum signatures, TPM attestation | Until replaced or erased | [`docs/SECURE-DELIVERY.md`](../SECURE-DELIVERY.md) |
| F16 | Commissioning (`robodr-commission`, offline) | Captures you record for learning (pcap), the draft and locked profile, operator sign-offs | The commissioning station, then the profile on the unit | — | No | Profile signed | Your policy; the captures are yours to delete after commissioning | OPERATIONS §5 |
| F17 | Support requests to SingularityRD | Only what you choose to send | SingularityRD (terms in the DPA, not yet issued) | Agreed per request | Agreed | — | Agreed | — |

## 5. Protection measures

- **Access on the unit:** every service has its own system user and the
  minimum capabilities; key files are `0600 root` and reach services only
  as systemd credentials; state directories are not world-readable
  ([`packaging/README.md`](../../packaging/README.md)).
- **Network:** `robodr-agentd`, the executor, the gateway, deliverd and
  spool-export cannot open IP connections (`IPAddressDeny=any` or
  `PrivateNetwork=yes`); the exporters may reach only the addresses in
  their drop-ins.
- **Integrity:** evidence, findings, requests, answers and fleet documents
  are signed (Ed25519); attacker-chosen strings are marked and escaped in
  findings (SR-TAINT), so a SOC can show them safely.
- **At rest:** RoboDR does not encrypt its records (except sealed
  delivery content). Use host full-disk encryption; it is one of the host
  controls the product assumes ([`docs/compliance/threat-model.md`](../compliance/threat-model.md) §1, H3).

## 6. Data subject requests and deletion

- **Access:** findings and black-box records can be read with
  `robodr-blackbox inspect` and in your SOC.
- **Erasure of a single record** in the black box is not possible without
  breaking its signature chain, which is what makes it evidence. Options:
  wait for segment rotation, delete the whole store (an operator action
  that leaves a visible gap; see OPERATIONS §9), or rely on the
  legal-claims / legal-obligation exceptions your counsel identifies.
  Findings in your SOC, Kafka and media follow your own deletion
  processes.
- **Decommissioning:** [`DECOMMISSION.md`](../DECOMMISSION.md) (summary in OPERATIONS §9): the package never deletes evidence or keys itself; after the far side holds verified copies, the operator destroys `/var/lib/robodr` and `/etc/robodr` and sanitises the storage per NIST SP 800-88;
  sealed delivery content is crypto-erased.

## 7. International transfers

RoboDR transfers nothing across borders by itself. Where your SOC,
brokers or depot are located decides that.

## 8. Not done yet

- **No redaction option** for user ids, process paths, network addresses
  or operator names in findings (a configurable redaction or
  pseudonymisation is a candidate improvement).
- **No DPA, no privacy notice, no legal review** of this page
  (SALES-READINESS C3). The EULA draft leaves the DPA as a placeholder.
- **No retention setting for the black box by age**, only by size.
- Not validated on a customer site.
