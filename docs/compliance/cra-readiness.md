# EU Cyber Resilience Act (CRA) readiness

> **Status: engineering readiness check, refreshed 2026-10-26 (branch head
> `332d88f`). Not legal advice.**
> The Regulation is (EU) 2024/2847. Its classification, dates and
> obligations must be confirmed by SingularityRD legal against the
> Regulation text and its implementing acts. This page records what the
> RoboDR repository does today against the obligations engineering can
> act on.

## 1. Applicability: questions for legal

| Question | Engineering view | Owner |
|---|---|---|
| Is RoboDR a "product with digital elements" placed on the EU market? | Yes for any commercial EU sale. RoboDR is software that connects to networks (ingest API, fleet API, Kafka, control plane). | Legal |
| Defence carve-out | The CRA does not apply to products developed exclusively for national security or defence. RoboDR is sold to civil industry as well, so assume the CRA applies to the product line. | Legal |
| Product category | RoboDR detects intrusions and anomalies on robots, records and forwards security findings, and (opt-in) filters motion commands inline (`robodr-firewall-gw`) and applies reversible network containment (`robodr-executor`). The inline gateway strengthens the case for a firewall-like category. It may fall under the Regulation's lists of **important products** (candidates: intrusion detection and prevention systems; firewalls; security information and event management; software that detects malicious software). The category decides whether conformity can be self-assessed or needs a third party. **Unresolved. This is the most important open question.** | Legal |
| Dates | Reporting obligations (actively exploited vulnerabilities, severe incidents) apply from **11 September 2026**, which has already passed. The main obligations apply from **11 December 2027**. RoboDR has not been placed on the market yet (no release). GA is planned for about 30 weeks after Sprint 0 (GA-ROADMAP), so the reporting duty applies from the first sale. | Legal to confirm |

## 2. Annex I, Part I: product security requirements (status)

| Requirement (paraphrased) | Status | Evidence / gap |
|---|---|---|
| No known exploitable vulnerabilities at release | 🟡 | `cargo deny` advisories (passed locally on 2026-10-26). No release yet. No pentest (S11). |
| Secure by default configuration | 🟡 | Units are installed disabled. No listener unless configured. The control plane and executor v1 are off by default (`executor.enabled`); the gateway starts in the configured `mode` and should be run `observe` first; `fail_closed` is its default. Least privilege ([`packaging/systemd/`](../../packaging/systemd/)). Gaps: legacy HMAC keys still load (with a warning); `ROBODR_ALLOW_UNSIGNED=1` exists for labs; the gateway's `bypass` mode exists (refused for a humanoid joint channel). Document all three as non-default. |
| Security updates (automatic where appropriate, with opt-out) | 🟡 | Offline bundle and rollback ([`docs/OPERATIONS.md`](../OPERATIONS.md) section 7), installed from a verified private extraction of the signed tarball (`ace7fba`). Downgrade refusal, a per-unit security floor and a black-box format gate on install and rollback (`3d36c65`, `ace7fba`; tested against a real `dpkg`, not on a target robot). No fleet update mechanism yet: SOC update rings are information only (`robodr-enroll ring`, OPERATIONS 8.6; [`docs/SECURE-DELIVERY.md`](../SECURE-DELIVERY.md) is a design only). Air-gapped customers cannot receive automatic updates, which should be documented as the justified exception. |
| Protection from unauthorised access | 🟡 | Signed requests and batches. Control plane v2: mutual TLS plus signed requests and answers (`a158536`), tested on a local test PKI only. Executor orders over an HMAC-authenticated local socket. Gaps: no per-key action scopes; the executor trusts agentd's approval flag (4-2 GAP-07, GAP-23); no revocation for SOC client certificates (GAP-05). |
| Confidentiality of data (state of the art encryption) | 🟡 | TLS on `robodr-uplink` and `robodr-enroll`, mutual TLS on the control plane off loopback (4-2 GAP-02 closed in code). Kafka and the anchor receiver are plaintext (GAP-03). No encryption at rest beyond the host's. |
| Integrity of data, commands, programs and configuration | ✅ / 🟡 | Signed black box, profiles, batches, requests and answers; SOC profiles staged, never enforced without a signed approval and a local operator step; the gateway verifies the CRC of every rewritten frame. Release signing designed but never exercised. |
| Data minimisation | ✅ | Findings carry correlated detections and evidence links, not raw telemetry ([`docs/contracts/robodr.findings.md`](../contracts/robodr.findings.md) §1). |
| Availability of essential functions, resilience against DoS | 🟡 | Bounded queues, connection caps and deadlines, cgroup caps. Unmeasured on targets (S11). In inline mode the robot's motion commands depend on the gateway's availability (`fail_closed` → the robot's own command timeout). |
| Minimise negative impact on other devices and networks | 🟡 | Passive capture; agentd opens no IP connection. Two opt-in components now act: the executor (reversible, TTL-bounded nftables rules in its own table that never cut the protected motion path or management) and the inline gateway (passes, limits, holds or removes motion samples; never originates one). Both are tested in network namespaces only, not on a robot ([`safety-positioning.md`](safety-positioning.md)). |
| Limit attack surfaces | ✅ / 🟡 | Minimal capabilities and syscall filters; `CAP_NET_ADMIN` only in the separate executor and gateway processes. A hand-written HTTP server remains in agentd (fuzzed, `control_plane_request`; ADR-0007). |
| Exploitation mitigation | 🟡 | Rust, bounds everywhere, `forbid(unsafe_code)` where possible and reviewed FFI elsewhere (`c2800c8`), `MemoryDenyWriteExecute`. The arm64 static `robodr-focal` binaries are non-PIE (no ASLR of the image; [`docs/UNITREE.md`](../UNITREE.md) "Known limits"). |
| Record and monitor relevant internal activity | ✅ / 🟡 | Signed black box (also control-plane, evidence-export and executor events), fleet journal, `status.json`, health findings. Gateway verdicts are an unsigned local events file, not yet in the black box (4-2 GAP-24). |
| Secure removal of data and settings | 🟡 | A decommissioning procedure exists (OPERATIONS section 9). Crypto erase is design only. |

## 3. Annex I, Part II: vulnerability handling (status)

| Requirement (paraphrased) | Status | Evidence / gap |
|---|---|---|
| Identify and document components, including an SBOM | 🟡 | CycloneDX generator and verification ([`docs/BUILD.md`](../BUILD.md) "SBOM"). **No SBOM has shipped**, because no release has been cut. The SBOM does not yet cover the eBPF objects or the clang toolchain. |
| Address and remediate vulnerabilities without delay, with separate security updates where feasible | 🟡 | `SECURITY.md` timelines. Untested. No release branches yet. |
| Regular security testing and review | 🟡 | Tests, 23 fuzz targets (10 run under libFuzzer for 630 s), nine AI-agent review rounds ([`iec-62443-4-1-sdl-evidence.md`](iec-62443-4-1-sdl-evidence.md)). CI has never run on GitHub. No external pentest. Control plane v2 has no recorded review. |
| Publicly disclose fixed vulnerabilities (advisories) | ❌ | Process drafted ([`docs/customer/psirt-process.md`](../customer/psirt-process.md)). Never exercised. The repository is private, so the advisory channel must be decided. |
| Coordinated vulnerability disclosure policy | ✅ | [`SECURITY.md`](../../SECURITY.md) |
| Contact address for reporting | 🟡 | GitHub private reporting on a **private** repository. External researchers cannot reach it. A public contact (for example a security mailbox and `security.txt`) is needed. |
| Secure distribution of updates | 🟡 | Minisign-signed bundles; the release key travels out of band. Never exercised. |
| Security updates free of charge, with advisory information | ❌ | Commercial terms not yet set ([`docs/customer/sla-support-draft.md`](../customer/sla-support-draft.md) leaves this open). |

## 4. Other obligations

| Obligation (paraphrased) | Status |
|---|---|
| **Support period** reflecting the expected time of use (at least 5 years, unless the product's expected use is shorter), stated at purchase | ❌ [`SECURITY.md`](../../SECURITY.md) says "from 1.0, the latest minor, and the previous one for 6 months". Robots are used for 5 to 15 years. The product owner must set a support period. |
| Reporting of actively exploited vulnerabilities and severe incidents to the designated CSIRT / ENISA single platform (early warning within 24 h, notification within 72 h, final report later) | ❌ No procedure, no owner. Added as a stage to [`psirt-process.md`](../customer/psirt-process.md). Owner to be named. |
| Technical documentation (design, risk assessment, SBOM, test reports) | 🟡 The ADRs, contracts, threat models and this compliance set are inputs. No consolidated technical file exists. |
| User information and instructions (Annex II) | 🟡 [`docs/customer/`](../customer/quick-start.md) drafts. The support period, contact, and secure use and decommissioning instructions must be completed. |
| Conformity assessment, EU declaration of conformity, CE marking | ❌ Depends on the category (§1). |
| Due diligence on third-party components (including open source) | 🟡 `cargo deny`, lockfile policy, pinned Pulsar submodule. No documented due-diligence record for Pulsar as a whole (its eBPF code runs in the kernel). |

## 5. Actions

| # | Action | Sprint | Owner |
|---|---|---|---|
| CRA-1 | Legal: product category, conformity route, defence carve-out position | S0/S13 | Legal |
| CRA-2 | Set and publish the support period; align `SECURITY.md` and the SLA | S13 | Product |
| CRA-3 | Public vulnerability contact (mailbox, `security.txt`) and advisory channel | S13 | Product/PSIRT |
| CRA-4 | CRA reporting procedure (24 h / 72 h) with a named owner; rehearse it | S13 | PSIRT |
| CRA-5 | First signed release with SBOM; include eBPF objects in the SBOM | S12 | DevOps |
| CRA-6 | Close the confidentiality gaps: control-plane mTLS done in code (`a158536`); Kafka and anchor-receiver TLS open | S10 | R |
| CRA-7 | Technical file index linking ADRs, threat models, test and pentest reports | S13–S14 | Product |
