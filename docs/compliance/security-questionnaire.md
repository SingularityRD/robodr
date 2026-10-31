# Security questionnaire answers (SIG Lite / CAIQ style)

> **Status: prepared answers. Verified at commit `8b2b172` (2026-10-30).**
> Pre-filled answers to the questions customers' security and
> procurement teams usually ask, grouped like the domains of the Shared
> Assessments SIG Lite and the CSA CAIQ. The questions are **paraphrased**,
> not quoted from those questionnaires; map them to the customer's own
> form when answering. Every answer links to evidence in this repository,
> and `scripts/check-doc-facts.py` (check `evidence-links`) fails if a
> linked file disappears. Answers are deliberately conservative: "Yes"
> means implemented **and** tested at the stamped commit; anything not
> validated on a real robot, not reviewed by a human or not yet decided by
> SingularityRD says so.
>
> *Corrected at `a28163b` (2026-10-31) without re-verifying the rest of the document:* the fuzz target count (41) and GRC-05 (now Partial).
>
> **Before sending to a customer:** re-run the check script, restamp, have
> the product owner confirm every "Organisation" answer, and remove
> anything the customer's NDA does not cover. This file is not legal
> advice and not a contractual commitment.

## How to read the answers

| Answer | Meaning |
|---|---|
| Yes | Implemented and tested at the stamped commit (offline: unit, integration, network-namespace or container tests) |
| Partial | Implemented in part, or implemented but not validated as the question implies (for example not on a robot, not by a human reviewer) |
| No | Not in place |
| Planned | Not in place; a backlog item exists (named) |
| Owner | Needs a decision or action by SingularityRD management, legal or a named person; engineering cannot answer it |
| N/A | Does not apply: RoboDR is **on-premises software**, not a hosted service; SingularityRD operates no service that holds customer data |

## 1. Product and deployment model

| ID | Question (paraphrased) | Answer | Detail | Evidence |
|---|---|---|---|---|
| PRD-01 | Is the product a hosted (SaaS) service or customer-operated software? | — | Customer-operated software on the robot or a sensor box, with an optional customer-operated SOC. No SingularityRD-hosted component. | [security whitepaper](../customer/security-whitepaper.md) §1-§2 |
| PRD-02 | Does the product send any data to the vendor (telemetry, licence check, updates)? | No | No vendor address is compiled in or configured; no telemetry; updates are installed by the customer from signed bundles. | [data-handling.md](../customer/data-handling.md) §1 |
| PRD-03 | Can it run fully air-gapped? | Yes | One-way diode / media export, offline install bundles, air-gapped secure delivery through a site depot (swtpm-tested). | `docs/OPERATIONS.md` §3, §8; [`docs/SECURE-DELIVERY.md`](../SECURE-DELIVERY.md) |
| PRD-04 | Can the product affect the physical process? | Partial | By default it only observes and records. Opt-in executor (network containment; motion actions only through OEM-validated platform adapters, two approvers for the strongest) and opt-in inline gateway (filters motion commands). Not safety-rated. | [safety-positioning.md](safety-positioning.md) |
| PRD-05 | Which platforms are supported? | — | Linux with systemd; Ubuntu 22.04/24.04, Debian 12, JetPack 6, RHEL/Rocky/Alma 9 (RPM), JetPack 5 agent-only. | [support matrix](../customer/support-matrix.md) |

## 2. Governance, risk and compliance (organisation)

| ID | Question (paraphrased) | Answer | Detail | Evidence |
|---|---|---|---|---|
| GRC-01 | Is there a documented information security policy and programme with a named owner? | Owner | No written security management plan, role list or named security owner yet (62443-4-1 SM gap; SALES-READINESS C18). | [SDL evidence](iec-62443-4-1-sdl-evidence.md) "SM" |
| GRC-02 | Is the organisation certified (ISO/IEC 27001, SOC 2, IEC 62443-4-1)? | No | No certification. IEC 62443-4-1 / 4-2 self-assessments exist; certification is a post-GA goal. | [4-1 evidence](iec-62443-4-1-sdl-evidence.md), [4-2 gap analysis](iec-62443-4-2-gap-analysis.md) |
| GRC-03 | Is there a product risk assessment / threat model, reviewed regularly? | Partial | Consolidated threat model with STRIDE per trust boundary, residual risks and SL-C targets; reviewed per release (checklist). Not yet reviewed by an independent human. | [threat-model.md](threat-model.md) |
| GRC-04 | How do you track regulatory obligations (EU CRA, NIS2 customers)? | Partial | CRA readiness check with open actions; product category and conformity route await legal (CRA-1). | [cra-readiness.md](cra-readiness.md) |
| GRC-05 | Are security documents kept current? | Partial | Compliance documents carry a "Verified at commit" stamp; a script checks stamps, counts, the action catalog, the unsafe-code lints and evidence links against the code. The script still reports drift in other documents (README, BUILD, fuzz and executor READMEs) and does not run in CI yet, so nothing stops a merge that makes a document stale; a stamp is a manual re-verification, not a guarantee. | `scripts/check-doc-facts.py` |
| GRC-06 | Is there a functional-safety position? | Yes | RoboDR is a cybersecurity component, not safety-rated; integrator obligations listed. | [safety-positioning.md](safety-positioning.md) |

## 3. Human resources and awareness (organisation)

| ID | Question (paraphrased) | Answer | Detail | Evidence |
|---|---|---|---|---|
| HRS-01 | Background checks for staff with access to source and signing keys? | Owner | Not documented. | — |
| HRS-02 | Secure-development training for developers, with records? | No | No training records (62443-4-1 SM gap). | [SDL evidence](iec-62443-4-1-sdl-evidence.md) "SM" |
| HRS-03 | Are AI coding agents used, and how are they controlled? | Yes | Implementation and review rounds were done by AI coding agents under written binding rules (never autonomous actions, no own crypto, no skipped tests, claims only what was verified). Human security review has **not** taken place. | [`docs/GA-AGENT-PROMPT.md`](../GA-AGENT-PROMPT.md); [SDL evidence](iec-62443-4-1-sdl-evidence.md) "Independent review rounds" |

## 4. Secure development lifecycle and application security

| ID | Question (paraphrased) | Answer | Detail | Evidence |
|---|---|---|---|---|
| AIS-01 | Is a secure development lifecycle followed? | Partial | Evidence per 62443-4-1 practice; gaps listed (plan, training, human review). | [SDL evidence](iec-62443-4-1-sdl-evidence.md) |
| AIS-02 | Memory-safe language? | Yes | Rust; `forbid(unsafe_code)` where possible, reviewed FFI elsewhere; eBPF probes (Pulsar) in C, kernel-verified. | [SDL evidence](iec-62443-4-1-sdl-evidence.md) "SI" |
| AIS-03 | Static analysis and lint gates? | Yes | `clippy -D warnings`, panic-family calls and `clippy::indexing_slicing` denied in the daemons and parsers, `cargo fmt --check`. | [`docs/BUILD.md`](../BUILD.md) "CI jobs" |
| AIS-04 | Dependency vulnerability scanning (SCA)? | Partial | `cargo deny` (advisories, licences, bans, sources) in CI; currently **failing** on RUSTSEC-2026-0387 (fix in progress). No scan of released tags yet. | [`deny.toml`](../../deny.toml); [third-party due diligence](third-party-due-diligence.md) §3 |
| AIS-05 | Fuzzing? | Partial | 41 cargo-fuzz targets with smoke runs in the tests; 10 ran 630 s under libFuzzer without findings; no long campaigns; CI fuzz smoke job red on its first run. | [`fuzz/README.md`](../../fuzz/README.md); [4-2 gap analysis](iec-62443-4-2-gap-analysis.md) CR 3.5 |
| AIS-06 | Independent penetration test? | No | None yet (SALES-READINESS C8). An end-to-end red team by an AI agent (2026-10-30) is recorded. | [`tools/e2e/RESULTS.md`](../../tools/e2e/RESULTS.md) "Wave-2 soak and red team" |
| AIS-07 | Is CI enforced on every change? | Partial | CI exists and ran on GitHub for the first time on 2026-10-30: **red** (4 jobs); fixes in progress. | [SDL evidence](iec-62443-4-1-sdl-evidence.md) "Honest limits" |
| AIS-08 | Input validation and protection against injection? | Yes | Bounded strict parsers; attacker-controlled strings tainted and escaped for LLM-based SOCs (SR-TAINT) with an injection corpus in the tests. | [`docs/contracts/robodr.findings.md`](../contracts/robodr.findings.md) §3; `crates/robodr-ocsf/tests/findings.rs` |
| AIS-09 | Are security requirements traced to tests? | Yes | Product security requirements PSR-1..10 with the tests that hold them. | [threat-model.md](threat-model.md) §6 |
| AIS-10 | Coding standard? | No | Lint policy only; no written coding standard. | [SDL evidence](iec-62443-4-1-sdl-evidence.md) "SI" |

## 5. Identity, authentication and access control

| ID | Question (paraphrased) | Answer | Detail | Evidence |
|---|---|---|---|---|
| IAM-01 | How do remote systems authenticate to the product? | Yes | Control plane: mutual TLS plus an Ed25519 signature per request, bound to robot id, target, time and nonce, persisted replay store. | [`docs/contracts/robodr.control-plane.md`](../contracts/robodr.control-plane.md) §1-§2; `crates/robodr-agentd/tests/control_plane.rs` |
| IAM-02 | How does the product authenticate to remote systems? | Yes | Signed batches (Ed25519) over TLS to the SOC; TLS / mutual TLS / SASL-SCRAM to Kafka; CRLs checked, fail closed. | [`docs/contracts/robodr.ingest-api.md`](../contracts/robodr.ingest-api.md); `crates/robodr-export/tests/kafka_tls.rs` |
| IAM-03 | Are there user accounts, passwords or default credentials? | N/A | No interactive accounts or passwords in the product; no default credentials. Keys are generated per unit. | [4-2 gap analysis](iec-62443-4-2-gap-analysis.md) CR 1.1 |
| IAM-04 | Least privilege for services? | Yes | Per-service users, minimal capabilities, syscall filters; only `robodr-pulsard` runs as root (bounded capabilities). | [`packaging/README.md`](../../packaging/README.md); `packaging/systemd/` |
| IAM-05 | Fine-grained authorisation of remote actions? | Partial | Seven catalog actions only, judged against the live safety state and policy, two approvers for the strongest. **No per-key action scopes**; the SOC's approval process is trusted. | [4-2 gap analysis](iec-62443-4-2-gap-analysis.md) CR 2.1, GAP-07 |
| IAM-06 | Brute-force and abuse protection? | Partial | Failed handshakes and unauthenticated requests counted and reported; rate limits. A multi-source TLS slowloris can lock the SOC out of the control plane (open, GAP-28). | [4-2 gap analysis](iec-62443-4-2-gap-analysis.md) CR 1.11, CR 7.1 |

## 6. Cryptography and key management

| ID | Question (paraphrased) | Answer | Detail | Evidence |
|---|---|---|---|---|
| CEK-01 | Which algorithms and libraries? | Yes | Ed25519 (`ed25519-dalek`, strict), SHA-256 / HMAC (RustCrypto `sha2`), TLS 1.2/1.3 (`rustls` + `ring`), XChaCha20-Poly1305 for sealed delivery, minisign for releases. No home-grown cryptography. | [ADR-0007](../adr/0007-audited-libraries.md); [4-2 gap analysis](iec-62443-4-2-gap-analysis.md) CR 4.3 |
| CEK-02 | Encryption in transit? | Yes | TLS on every network path (Kafka and anchor plain TCP only when explicitly allowed); diode media are signed, not encrypted. | [data-handling.md](../customer/data-handling.md) §4 |
| CEK-03 | Encryption at rest? | Partial | Only secure-delivery content is encrypted (sealed, TPM-bound). Evidence, findings and state are signed but rely on host full-disk encryption. | [data-handling.md](../customer/data-handling.md) §5 |
| CEK-04 | Key storage and hardware protection? | Partial | Root-only key files delivered as systemd credentials; TPM used for the head anchor, sealing and the depot client key (swtpm-tested). Operational signing keys are files, not TPM-held (GAP-04). | [4-2 gap analysis](iec-62443-4-2-gap-analysis.md) CR 1.5 |
| CEK-05 | Key rotation and revocation? | Partial | Uplink and finding key rotation with the SOC (`robodr-enroll`), black-box key rotation, revocation lists, CRLs on TLS paths. SOC side unreleased. | `docs/OPERATIONS.md` §4, §8.6 |
| CEK-06 | Release signing key custody? | Owner | Key ceremony designed (offline root, two people) but **not held**; no release signed yet (SALES-READINESS C1). | [`docs/RELEASE.md`](../RELEASE.md) §2 |

## 7. Logging, monitoring and evidence

| ID | Question (paraphrased) | Answer | Detail | Evidence |
|---|---|---|---|---|
| LOG-01 | Are security-relevant events logged? | Yes | Signed, hash-chained black box: findings, decisions, control-plane requests and answers, executor events, profile changes. | [`crates/robodr-blackbox/README.md`](../../crates/robodr-blackbox/README.md) |
| LOG-02 | Are logs tamper-evident? | Yes | Ed25519 signatures, hash chain; truncation plus rollback detectable with a head anchor (TPM NV counter or remote receiver; TPM on swtpm only). | [threat-model.md](threat-model.md) TB2; `crates/robodr-blackbox/tests/tamper.rs` |
| LOG-03 | Can logs be exported to a SIEM? | Yes | OCSF 1.1 Detection Findings over HTTPS, Kafka or diode; evidence bundles verifiable offline. | [`docs/contracts/robodr.findings.md`](../contracts/robodr.findings.md) |
| LOG-04 | Is the agent's own health visible to the SOC? | Partial | Silent inputs and failures become findings; there is no periodic health check-in in the findings contract yet. | [4-2 gap analysis](iec-62443-4-2-gap-analysis.md) CR 6.2 |
| LOG-05 | Time synchronisation? | Partial | Depends on host NTP; requests outside ±30 s refused; no authenticated time source (GAP-09). | [4-2 gap analysis](iec-62443-4-2-gap-analysis.md) CR 2.11 |

## 8. Vulnerability management and incident response

| ID | Question (paraphrased) | Answer | Detail | Evidence |
|---|---|---|---|---|
| TVM-01 | Is there a vulnerability disclosure policy? | Yes | Coordinated disclosure, safe harbour for good-faith research, target times. | [`SECURITY.md`](../../SECURITY.md) |
| TVM-02 | Is there a working channel to report vulnerabilities? | No | The documented channel (GitHub private vulnerability reporting) is **disabled** on the repository; a fallback is described; mailbox and `security.txt` planned (CRA-3, CRA-8). | [cra-readiness.md](cra-readiness.md) §3 |
| TVM-03 | PSIRT with defined roles, severity scoring and advisories? | Partial | Process drafted; never exercised; no CNA; severity scoring not defined beyond Critical/High. | [`docs/customer/psirt-process.md`](../customer/psirt-process.md) |
| TVM-04 | Patch timelines for critical vulnerabilities? | Partial | Acknowledge in 3 working days, assess in 10; fix "as fast as practical". No contractual SLA (draft only). | [`SECURITY.md`](../../SECURITY.md); [`docs/customer/sla-support-draft.md`](../customer/sla-support-draft.md) |
| TVM-05 | EU CRA reporting of actively exploited vulnerabilities (24 h / 72 h)? | No | No procedure or owner yet; the obligation applies from the first EU sale (C6). | [cra-readiness.md](cra-readiness.md) §4 |
| TVM-06 | Customer notification of vulnerabilities in third-party components? | Partial | Pulsar issues reported upstream and tracked; no advisory channel to customers yet. | [third-party due diligence](third-party-due-diligence.md) §2.3 |
| SEF-01 | Does the product support the customer's incident response? | Yes | Evidence exports with signed manifests, offline verification, approved containment actions (opt-in). | [`docs/contracts/robodr.control-plane.md`](../contracts/robodr.control-plane.md) §11 |

## 9. Change, release and supply chain

| ID | Question (paraphrased) | Answer | Detail | Evidence |
|---|---|---|---|---|
| STA-01 | SBOM per release? | Partial | CycloneDX SBOM generated per build (CI job green); no release has shipped one; eBPF objects, Rust std and musl not yet in it. | [cra-readiness.md](cra-readiness.md) §3 |
| STA-02 | Signed releases and integrity verification? | Partial | Minisign over every asset, verified before extraction; quorum-signed RPKs for air-gapped delivery. **No release has been signed yet.** | [`docs/RELEASE.md`](../RELEASE.md); `docs/OPERATIONS.md` §2 |
| STA-03 | Build provenance (SLSA) and reproducible builds? | Partial | Pure binaries reproducible bit for bit (CI job green); no SLSA/in-toto provenance. | [`docs/BUILD.md`](../BUILD.md) "Reproducible builds" |
| STA-04 | Third-party component due diligence? | Partial | Pulsar record with risk table and per-release review; lockfile policy and `cargo deny` for crates.io dependencies. | [third-party due diligence](third-party-due-diligence.md) |
| STA-05 | Open-source licence compliance? | Yes | Licence policy in `deny.toml`; `THIRD_PARTY_NOTICES` and GPL-2.0 source offer ship in packages (offer wording awaits legal approval). | [`deny.toml`](../../deny.toml); `scripts/third_party_notices.py` |
| CCC-01 | Change control for releases (review, approval)? | Partial | Release environment needs a second maintainer's approval; tag must be on `main`; never exercised. | [`docs/RELEASE.md`](../RELEASE.md) §3 |
| CCC-02 | Safe updates and rollback, downgrade protection? | Yes | Offline bundle with kept releases, rollback, downgrade refusal, security floor, format gate (tested with real `dpkg`, not on a robot). | `docs/OPERATIONS.md` §7; `crates/robodr-fleet/tests/packaging.rs` |
| CCC-03 | Support period / end of life? | Owner | Pre-1.0: latest release line only; a support period suitable for robots (CRA: at least 5 years) is not set (C5). | [`SECURITY.md`](../../SECURITY.md) "Supported versions" |

## 10. Data security and privacy

| ID | Question (paraphrased) | Answer | Detail | Evidence |
|---|---|---|---|---|
| DSP-01 | Data inventory and classification? | Yes | 17 flows with storage place, protection and retention; categories that identify people marked. | [data-handling.md](../customer/data-handling.md) |
| DSP-02 | Does the vendor process customer personal data? | No | Only what a customer sends for support. | [data-handling.md](../customer/data-handling.md) §2 |
| DSP-03 | Data minimisation and redaction? | Partial | Findings carry detections and evidence references, not raw telemetry; no option to redact user ids, process paths, addresses or operator names yet. | [data-handling.md](../customer/data-handling.md) §8 |
| DSP-04 | Retention and secure deletion? | Partial | Size-bounded black box and export limits; decommissioning procedure; crypto-erase for sealed content only. | [data-handling.md](../customer/data-handling.md) §4, §6 |
| DSP-05 | DPA available? | Owner | Not issued (C3). | — |

## 11. Resilience and availability

| ID | Question (paraphrased) | Answer | Detail | Evidence |
|---|---|---|---|---|
| BCR-01 | What happens when the product fails? | Yes | Passive modes: nothing depends on RoboDR. Executor fails toward "no rule set". Inline gateway: `fail_closed` hands over to the robot's own command timeout. | [safety-positioning.md](safety-positioning.md) §2a |
| BCR-02 | Backup and restore? | Partial | Procedure including what must never be restored (anti-rollback state); no tool; not rehearsed on a unit (GAP-21). | `docs/OPERATIONS.md` §14 |
| BCR-03 | Resource limits and DoS resistance? | Partial | Bounded parsers and queues, cgroup limits, rate limits; 2 h soak on a shared VM; no 72 h soak, no target hardware measurement (GAP-20). | [`tools/e2e/RESULTS.md`](../../tools/e2e/RESULTS.md) |

## 12. Physical, infrastructure and hosted-service questions

| ID | Question (paraphrased) | Answer | Detail |
|---|---|---|---|
| DCS-01 | Data-centre physical security, cloud tenancy, hosting certifications | N/A | No hosted service. The customer operates every component. |
| IVS-01 | Network security of the vendor's production environment | N/A | As above. The source repository and CI run on GitHub. |
| UEM-01 | Endpoint security of developer machines | Owner | Not documented. |

## 13. Trust bundle (shared under NDA)

To assemble per customer, from the stamped commit:

| Item | Status |
|---|---|
| This questionnaire, [threat-model.md](threat-model.md), [4-2 gap analysis](iec-62443-4-2-gap-analysis.md), [4-1 evidence](iec-62443-4-1-sdl-evidence.md), [CRA readiness](cra-readiness.md), [safety positioning](safety-positioning.md), [data handling](../customer/data-handling.md), [third-party due diligence](third-party-due-diligence.md) | Available (engineering self-assessment) |
| SBOM (CycloneDX) of the delivered build | Generated per build; no release yet |
| Release signature verification instructions and the release public key | Waiting for the key ceremony (C1) |
| Red-team and soak results | [`tools/e2e/RESULTS.md`](../../tools/e2e/RESULTS.md) (AI-run, lab only) |
| External penetration test report or attestation letter | Not available (C8) |
| Certifications (ISO 27001, IEC 62443) | None |
| Insurance certificate, financial statements, company policies | Owner |

## Review log

| Date | Commit | Reviewer | Result |
|---|---|---|---|
| 2026-10-30 | `8b2b172` | AI engineering agent | First version. Organisation answers ("Owner") need the product owner. |
