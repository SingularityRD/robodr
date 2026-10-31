# EU Cyber Resilience Act (CRA) readiness

> **Status: engineering readiness check. Verified at commit `8b2b172`
> (2026-10-30). Not legal advice.** Every "today" statement below was
> checked against the code and the CI record at that commit;
> `scripts/check-doc-facts.py` checks the stamp and the counts.
> The Regulation is (EU) 2024/2847. Its classification, dates and
> obligations must be confirmed by SingularityRD legal against the
> Regulation text and its implementing acts. This page records what the
> RoboDR repository does today against the obligations engineering can
> act on.
>
> *Corrected at `a28163b` (2026-10-31) without re-verifying the rest of the document:* the fuzz target count (41).

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
| No known exploitable vulnerabilities at release | 🟡 | `cargo deny` runs in CI. Its first GitHub run (run 41136491301, 2026-10-30) **failed** on RUSTSEC-2026-0387 (`crypto-bigint` 0.5.5 through `p256` 0.13; the fix, an upgrade to `p256` 0.14, is in progress). No release yet. No external pentest. |
| Secure by default configuration | 🟡 | Units are installed disabled. No listener unless configured. The control plane and executor v1 are off by default (`executor.enabled`); the gateway starts in the configured `mode` and should be run `observe` first; `fail_closed` is its default. Least privilege ([`packaging/systemd/`](../../packaging/systemd/)). Legacy HMAC black-box keys are refused by default since 2026-10-30 (opt in with `--allow-hmac` / `blackbox.allow_hmac`). Gaps: `ROBODR_ALLOW_UNSIGNED=1` exists for labs; the gateway's `bypass` mode exists (refused for a humanoid joint channel); the HMAC opt-in exists for migration. Document all three as non-default. |
| Security updates (automatic where appropriate, with opt-out) | 🟡 | Offline bundle and rollback ([`docs/OPERATIONS.md`](../OPERATIONS.md) section 7), installed from a verified private extraction of the signed tarball (`ace7fba`). Downgrade refusal, a per-unit security floor and a black-box format gate on install and rollback (`3d36c65`, `ace7fba`; tested against a real `dpkg`, not on a target robot). No fleet update mechanism yet: SOC update rings are information only (`robodr-enroll ring`, OPERATIONS 8.6). Air-gapped delivery of signed packs through a site depot ([`docs/SECURE-DELIVERY.md`](../SECURE-DELIVERY.md), Sprints 13a-14b) is implemented and tested against swtpm only; staged rollout is not. Air-gapped customers cannot receive automatic updates, which should be documented as the justified exception. |
| Protection from unauthorised access | 🟡 | Signed requests and batches. Control plane v2: mutual TLS plus signed requests and answers (`a158536`), tested on a local test PKI only. Executor orders over an HMAC-authenticated local socket. The executor verifies the SOC-signed request itself (4-2 GAP-23 closed in code). CRLs on every TLS path, fail closed (GAP-05 closed in code; no OCSP, by design). Gap: no per-key action scopes, and the robot cannot verify the SOC's internal two-person approval (GAP-07). |
| Confidentiality of data (state of the art encryption) | 🟡 | TLS on `robodr-uplink` and `robodr-enroll`, mutual TLS on the control plane off loopback (4-2 GAP-02 closed in code). Kafka and the anchor receiver use TLS by default (mutual TLS optional; GAP-03 closed in code 2026-10-30, plain TCP only when explicitly allowed). No encryption at rest beyond the host's. |
| Integrity of data, commands, programs and configuration | ✅ / 🟡 | Signed black box, profiles, batches, requests and answers; sealed (HMAC-chained, anchored in the black box) control-plane and executor journals; SOC profiles staged, never enforced without a signed approval and a local operator step; the gateway verifies the CRC of every rewritten frame. Secure-delivery formats (RPK, quorum-signed releases, sealed packs) are implemented and tested against swtpm. Release signing designed but never exercised (no tag, no key ceremony). The gateway's channel configuration file is not signed yet. |
| Data minimisation | ✅ / 🟡 | Findings carry correlated detections and evidence links, not raw telemetry ([`docs/contracts/robodr.findings.md`](../contracts/robodr.findings.md) §1). Findings can carry host names, process command lines, user names and SOC operator names; there is no redaction option yet. Inventory: [`docs/customer/data-handling.md`](../customer/data-handling.md). |
| Availability of essential functions, resilience against DoS | 🟡 | Bounded queues, connection caps and deadlines, cgroup caps. Unmeasured on targets (S11). In inline mode the robot's motion commands depend on the gateway's availability (`fail_closed` → the robot's own command timeout). |
| Minimise negative impact on other devices and networks | 🟡 | Passive capture; agentd opens no IP connection. Two opt-in components now act: the executor (reversible, TTL-bounded nftables rules in its own table that never cut the protected motion path or management) and the inline gateway (passes, limits, holds or removes motion samples; never originates one). Both are tested in network namespaces only, not on a robot ([`safety-positioning.md`](safety-positioning.md)). |
| Limit attack surfaces | ✅ / 🟡 | Minimal capabilities and syscall filters; `CAP_NET_ADMIN` only in the separate executor and gateway processes. A hand-written HTTP server remains in agentd (fuzzed, `control_plane_request`; ADR-0007). |
| Exploitation mitigation | 🟡 | Rust, bounds everywhere, `forbid(unsafe_code)` where possible and reviewed FFI elsewhere (`c2800c8`), panic-family calls and `clippy::indexing_slicing` denied in the daemons and in-process parsers, `MemoryDenyWriteExecute`. Every packaged program is position-independent (ET_DYN: PIE, static-pie for both `robodr-focal` architectures, so the image is address-randomised); `scripts/build-static.sh` and `scripts/check-packages.py` refuse a non-PIE program ([`docs/UNITREE.md`](../UNITREE.md) "Static binaries"). |
| Record and monitor relevant internal activity | ✅ / 🟡 | Signed black box (also control-plane, evidence-export and executor events), fleet journal, `status.json`, health findings. Gateway findings (`robot.gateway.*`, `robot.firewall.*`) reach agentd's pipeline and black box through `gateway_feed`; failed executor reverts and journal resets are High findings (4-2 GAP-24 closed in code). The gateway's per-sample verdicts stay a local events file. |
| Secure removal of data and settings | 🟡 | A decommissioning procedure exists (OPERATIONS section 9). Cryptographic erase of the sealed runtime volume and its keys exists for secure delivery (`robodr-seal`, `robodr-deliverd`; tested against swtpm only). The fleet API has no signed decommission flow yet. |

## 3. Annex I, Part II: vulnerability handling (status)

| Requirement (paraphrased) | Status | Evidence / gap |
|---|---|---|
| Identify and document components, including an SBOM | 🟡 | CycloneDX generator and verification ([`docs/BUILD.md`](../BUILD.md) "SBOM"); the CI `SBOM` job passed in run 41136491301. `THIRD_PARTY_NOTICES` and the GPL-2.0 source offer ship in the packages. **No SBOM has shipped**, because no release has been cut. The SBOM does not yet cover the eBPF objects, the Rust standard library, musl or the clang toolchain. Pulsar due diligence: [`third-party-due-diligence.md`](third-party-due-diligence.md). |
| Address and remediate vulnerabilities without delay, with separate security updates where feasible | 🟡 | `SECURITY.md` timelines. Untested. No release branches yet. |
| Regular security testing and review | 🟡 | Tests, 41 fuzz targets (std-only smoke runs in the crates' tests; libFuzzer runs of 630 s for 10 of them), AI-agent review rounds, and a 2 h soak with an end-to-end red team ([`iec-62443-4-1-sdl-evidence.md`](iec-62443-4-1-sdl-evidence.md)). CI ran on GitHub for the first time on 2026-10-30 (run 41136491301) and is **red** (pure-crate tests, Rocky 9 RPM builds, cargo-deny, fuzz smoke). No external pentest; no human security review. |
| Publicly disclose fixed vulnerabilities (advisories) | ❌ | Process drafted ([`docs/customer/psirt-process.md`](../customer/psirt-process.md)). Never exercised. The repository is **public** (verified 2026-10-30), so GitHub security advisories could carry them; whether the source stays public is an open owner decision. |
| Coordinated vulnerability disclosure policy | ✅ | [`SECURITY.md`](../../SECURITY.md) |
| Contact address for reporting | ❌ | [`SECURITY.md`](../../SECURITY.md) points to GitHub private vulnerability reporting, but that feature is **disabled** on the repository (GitHub API, 2026-10-30): the documented channel does not accept reports. Enable it, and add a security mailbox and `security.txt`. |
| Secure distribution of updates | 🟡 | Minisign-signed bundles; the release key travels out of band; quorum-signed RPK delivery for air-gapped fleets (`robodr-release`, `robodr-deliverd`, `robodr-depot`; swtpm only). Never exercised with a real key. |
| Security updates free of charge, with advisory information | ❌ | Commercial terms not yet set ([`docs/customer/sla-support-draft.md`](../customer/sla-support-draft.md) leaves this open). |

## 4. Other obligations

| Obligation (paraphrased) | Status |
|---|---|
| **Support period** reflecting the expected time of use (at least 5 years, unless the product's expected use is shorter), stated at purchase | ❌ [`SECURITY.md`](../../SECURITY.md) says "from 1.0, the latest minor, and the previous one for 6 months". Robots are used for 5 to 15 years. The product owner must set a support period. |
| Reporting of actively exploited vulnerabilities and severe incidents to the designated CSIRT / ENISA single platform (early warning within 24 h, notification within 72 h, final report later) | ❌ No procedure, no owner. Added as a stage to [`psirt-process.md`](../customer/psirt-process.md). Owner to be named. |
| Technical documentation (design, risk assessment, SBOM, test reports) | 🟡 The ADRs, contracts, the consolidated [`threat-model.md`](threat-model.md) and this compliance set are inputs. No technical file index exists. |
| User information and instructions (Annex II) | 🟡 [`docs/customer/`](../customer/quick-start.md) drafts. The support period, contact, and secure use and decommissioning instructions must be completed. |
| Conformity assessment, EU declaration of conformity, CE marking | ❌ Depends on the category (§1). |
| Due diligence on third-party components (including open source) | 🟡 `cargo deny`, lockfile policy, pinned Pulsar submodule. Pulsar due-diligence record: [`third-party-due-diligence.md`](third-party-due-diligence.md), reviewed per release. The other Rust dependencies have `cargo deny` and the lockfile policy only. |

## 5. Actions

| # | Action | Sprint | Owner |
|---|---|---|---|
| CRA-1 | Legal: product category, conformity route, defence carve-out position | S0/S13 | Legal |
| CRA-2 | Set and publish the support period; align `SECURITY.md` and the SLA | S13 | Product |
| CRA-3 | Public vulnerability contact (mailbox, `security.txt`) and advisory channel | S13 | Product/PSIRT |
| CRA-4 | CRA reporting procedure (24 h / 72 h) with a named owner; rehearse it | S13 | PSIRT |
| CRA-5 | First signed release with SBOM; include eBPF objects in the SBOM | S12 | DevOps |
| CRA-6 | Confidentiality: control-plane mTLS (`a158536`), Kafka and anchor-receiver TLS, and CRLs on every TLS path are done in code; field validation open | S11 | R |
| CRA-7 | Technical file index linking ADRs, threat models, test and pentest reports | S13–S14 | Product |
| CRA-8 | Enable GitHub private vulnerability reporting (a repository setting; disabled today) | now | Repository admin |
| CRA-9 | Review [`third-party-due-diligence.md`](third-party-due-diligence.md) and [`threat-model.md`](threat-model.md) for every release and restamp them | every release | R |
