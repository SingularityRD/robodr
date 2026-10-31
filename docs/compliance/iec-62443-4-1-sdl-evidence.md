# IEC 62443-4-1 secure development lifecycle: evidence inventory

> **Status: inventory. Verified at commit `8b2b172` (2026-10-30).** This
> lists what evidence for a secure development lifecycle exists in this
> repository today, and what is missing. It is not an assessment of
> process maturity and not a certification claim. The practice names
> follow the eight practices of IEC 62443-4-1, paraphrased:
>
> | Practice | Name |
> |---|---|
> | SM | security management |
> | SR | security requirements |
> | SD | secure by design |
> | SI | secure implementation |
> | SVV | security verification and validation testing |
> | DM | management of security-related issues |
> | SUM | security update management |
> | SG | security guidelines |
>
> Check against the licensed standard text before external use. Companion
> document: [`iec-62443-4-2-gap-analysis.md`](iec-62443-4-2-gap-analysis.md).

## Summary

| Practice | Evidence today | Main gaps |
|---|---|---|
| SM | Roadmap with acceptance criteria per sprint; ADRs; written agent rules; dependency policy; pinned C toolchain for ring; Pulsar due-diligence record | No written security management plan, role list or training records; release-key custody not set up |
| SR | Consolidated product threat model with security context, SL-C targets and requirement-to-test traceability ([`threat-model.md`](threat-model.md)); per-component threat models and "what is claimed" sections; contract-level security requirements (SR-TAINT) | Threat model not yet reviewed by a human; SL-C targets are a proposal |
| SD | Defence-in-depth invariants in code (decided twice before the executor acts); data-flow diagrams per trust boundary ([`threat-model.md`](threat-model.md) §4); design docs; ADRs | Threat-model review is a release-checklist item but has never been done for a release |
| SI | Lints as errors; `forbid(unsafe_code)` where possible and `deny` + SAFETY comments elsewhere; panic-family calls and `clippy::indexing_slicing` denied in the daemons and in-process parsers; audited `sha2` (HMAC as RFC 2104 over it); `cargo deny` | Hand-written HTTP server and Kafka client remain (fuzzed); no written coding standard |
| SVV | Unit, integration and network-namespace tests; 41 fuzz targets with std-only smoke runs (10 also run under libFuzzer for 630 s); review regression suites from AI-agent review rounds; contract vectors shared with the SOC; a 2 h soak and an end-to-end red team through the release binaries (2026-10-30) | **CI is red** on its first GitHub run (run 41136491301); no pentest; reviews were by AI agents, not independent humans; no dedicated review round of the control plane v2 core |
| DM | `SECURITY.md` intake and timelines | The documented intake (GitHub private vulnerability reporting) is **disabled** on the repository; no tracker records, advisory process or CVE assignment path exercised |
| SUM | Signed offline bundle installed from a verified private extraction; downgrade refusal, security floor, format gate (tested with the real `dpkg`); quorum-signed air-gapped delivery (swtpm); SBOM generator | **No release has ever been cut or signed**; support period not CRA-ready |
| SG | Operations, Unitree and packaging guides (executor 6.5, gateway 6.6, fleet 8.6); systemd hardening rationale | No secure configuration baseline; customer docs are drafts |

## SM: security management

| Evidence | Where |
|---|---|
| Product plan with acceptance criteria per sprint and GA exit criteria | [`docs/GA-ROADMAP.md`](../GA-ROADMAP.md) §3, §4 |
| Binding rules for every implementation session: never autonomous, never bypass safety, TLS + Ed25519 on network paths, taint, no own crypto, no skipped tests, claims only what was verified | [`docs/GA-AGENT-PROMPT.md`](../GA-AGENT-PROMPT.md) |
| Architecture decisions | [`docs/adr/`](../adr/README.md) |
| Third-party components: committed `Cargo.lock` with no patched, git or unknown sources (CI `lockfile` job); `cargo deny` for licences, advisories, bans and sources; Pulsar pinned as a submodule, with a due-diligence record | [`docs/BUILD.md`](../BUILD.md) "Cargo.lock policy", "CI jobs"; [`deny.toml`](../../deny.toml); [`third-party-due-diligence.md`](third-party-due-diligence.md) |
| Advisory exceptions carry a reason and a review date (for example RUSTSEC-2021-0139, review 2027-04-17) | [`deny.toml`](../../deny.toml) |
| Toolchain pins: `rust-toolchain.toml`; clang 18.1.3 for ring, enforced in release and repro builds (`38ac3a7`) | [`rust-toolchain.toml`](../../rust-toolchain.toml), [`docs/BUILD.md`](../BUILD.md) "C toolchain" |
| New dependencies are named with their licence and reason in the commit (for example `hmac` 0.12.1 in `86e70e7`; `reed-solomon` 0.2.1 as a dev-only oracle in `aba80a5`) | commit history |

**Missing:**

- a security management plan (roles, a named security owner,
  responsibilities, process scope);
- records of developers' security training;
- private-key controls for the release signing key. The minisign key is
  not provisioned, and an offline root plus release key is planned for
  GA-ROADMAP S12;
- a process-verification and improvement cycle (periodic SDL audit).

## SR: security requirements

| Evidence | Where |
|---|---|
| Product security context (intended environment, assumed host controls), assets, attacker model, trust boundaries, STRIDE per boundary, mitigations linked to tests, SL-C targets | [`threat-model.md`](threat-model.md) |
| Data inventory per flow (what leaves the robot, where it is stored, for how long) | [`docs/customer/data-handling.md`](../customer/data-handling.md) |
| SR-TAINT: attacker-controlled strings, allow-list escaping, never interpolated into trusted text | [`docs/contracts/robodr.findings.md`](../contracts/robodr.findings.md) §3 |
| Claims and non-claims for the control plane and the head anchors | [`SECURITY.md`](../../SECURITY.md); [`docs/contracts/robodr.control-plane.md`](../contracts/robodr.control-plane.md) §13 |
| Black-box threat model | [`crates/robodr-blackbox/README.md`](../../crates/robodr-blackbox/README.md) "Threat model" |
| Secure-delivery threat model (adversaries, assets, claims) | [`docs/SECURE-DELIVERY.md`](../SECURE-DELIVERY.md) §1 |
| Responder invariants (safety-related security requirements) | [`crates/robodr-responder/README.md`](../../crates/robodr-responder/README.md) "Invariants" |
| Executor safety argument and trust boundary (what a compromised agentd can and cannot obtain) | [`crates/robodr-executor/README.md`](../../crates/robodr-executor/README.md) "Safety argument", "Trust boundary" |
| Gateway safety argument ("what hold means on the wire"), writer binding, failure behaviour, deployment rules | [`crates/robodr-firewall-gw/README.md`](../../crates/robodr-firewall-gw/README.md) |
| Fleet lifecycle security requirements (single-use token, proof of possession, overlap rotation, staged profiles, approval keys) | [`docs/contracts/robodr.fleet-api.md`](../contracts/robodr.fleet-api.md) |

**Missing:** a human review of the threat model, and acceptance of the
SL-C targets by the product owner.

## SD: secure by design

| Evidence | Where |
|---|---|
| Protective-only scope: the control plane has no motion fields; nothing in the motion stack depends on RoboDR except in the opt-in inline gateway mode, whose failure behaviour is configured and documented | [`SECURITY.md`](../../SECURITY.md) "Scope"; [`docs/contracts/robodr.control-plane.md`](../contracts/robodr.control-plane.md) §4; [`safety-positioning.md`](safety-positioning.md) |
| Defence in depth: policy validation, plan-time invariants, agentd's judgment, then the executor's own precheck and a safety re-check right before apply | [`crates/robodr-responder/README.md`](../../crates/robodr-responder/README.md), [`crates/robodr-executor/README.md`](../../crates/robodr-executor/README.md) |
| Privilege separation: the only `CAP_NET_ADMIN` in the agent path is a separate executor process with no IP sockets; agentd keeps `CAP_NET_RAW` only | [`packaging/systemd/robodr-executor.service`](../../packaging/systemd/robodr-executor.service), [`packaging/systemd/robodr-agentd.service`](../../packaging/systemd/robodr-agentd.service) |
| Least privilege per service (capabilities, `IPAddressDeny`, syscall filters, credentials) with the reasons documented | [`packaging/README.md`](../../packaging/README.md), [`packaging/systemd/`](../../packaging/systemd/) |
| Decision records | [`docs/adr/`](../adr/README.md) |

**Missing:** a recorded threat-model review for a release. The review is
now an item of the release checklist ([`docs/RELEASE.md`](../RELEASE.md)
§3), but no release has been cut.

## SI: secure implementation

| Evidence | Where |
|---|---|
| `cargo clippy -D warnings`, `cargo fmt --check` in CI (pure and Pulsar jobs) | [`docs/BUILD.md`](../BUILD.md) "CI jobs" |
| `#![forbid(unsafe_code)]` on 9 library crates and every binary root; `deny(unsafe_code)` + `unsafe_op_in_unsafe_fn` + a SAFETY comment on every remaining FFI block elsewhere; executor forbids it; gateway and fleet deny it with local allows | `c2800c8`, `2b8ab65`, `a4e0b4b`, `1de502d` |
| Panic-family calls (`unwrap`, `expect`, `panic!`, `unreachable!`, `todo!`, `unimplemented!`) denied by clippy in non-test code of the daemon crates, executor, gateway and fleet | `7637f9d`, `2b8ab65`, `a4e0b4b`, `1de502d` |
| `clippy::indexing_slicing` denied in non-test code of `robodr-agentd`, `-executor`, `-export`, `-firewall-gw`, `-deliverd` and the parsers they run on untrusted input (`-rtps`, `-capture`, `-cdr`, `-pkg`, `-ros2-pipeline`); about 530 sites rewritten to checked access | merge `20ad170` |
| Audited crypto: `ed25519-dalek` (strict), rustls + ring, `sha2` (HMAC as RFC 2104 over it) with `subtle` and `zeroize`, proven byte-identical to the replaced code by differential tests | [ADR-0007](../adr/0007-audited-libraries.md); `86e70e7`; `crates/robodr-blackbox/tests/crypto_differential.rs` |
| In-crate Reed-Solomon kept (its parity is part of the signed wire format) and pinned to an independent oracle | `aba80a5`; `crates/robodr-diode/tests/fec_oracle.rs` |
| Memory and resource bounds stated per parser and queue | crate READMEs |

**Missing:**

- a written coding standard;
- `arithmetic_side_effects` is not denied (release builds do not enable
  `overflow-checks`), and `indexing_slicing` is not denied in the crates
  outside the list above (for example `robodr-blackbox`, `-diode`,
  `-seal`, `-depot`, `-fleet`);
- the hand-written HTTP/1.1 server (agentd control plane, now fuzzed) and
  Kafka client remain (ADR-0007).

## SVV: security verification and validation testing

| Evidence | Where |
|---|---|
| Unit and integration tests. GA-ROADMAP §3a recorded "2196+ tests, 0 failures" on 2026-10-26, before executor v1, control plane v2, the gateway, the fleet crate and S10 were merged. No workspace-wide count after those merges is recorded; this inventory did not re-run or re-count the tests. The first GitHub CI run (run 41136491301, 2026-10-30) failed the pure-crate tests: the `robodr-deliverd` adversarial suite fails without root because its test passwd file lacks the agentd user (a test-fixture defect; fix in progress). | [`docs/GA-ROADMAP.md`](../GA-ROADMAP.md) |
| Real-traffic tests: ROS 2 Jazzy captures (Fast DDS 2.14, Cyclone DDS 0.10, Gazebo); pcap replays judged on their packet timeline (`398a0d5`) | [`fixtures/captures/ros2-jazzy/`](../../fixtures/captures/ros2-jazzy/README.md) |
| Real kernels in network namespaces: executor nftables with UDP traffic between veth peers; gateway through a bridge with br_netfilter and NFQUEUE, including an attacker namespace | `crates/robodr-executor/tests/netns.rs`, `crates/robodr-firewall-gw/tests/netns_e2e.rs` |
| Real `dpkg`: install → upgrade → rollback, format gate, downgrade and floor | `crates/robodr-fleet/tests/packaging.rs` |
| Fuzzing: 41 cargo-fuzz targets with std-only smoke tests. First libFuzzer runs (S10): 10 targets × 630 s, about 18 M executions, no crash, leak, timeout or invariant violation; Sprint 13b ran `deliverd_state` and `deliverd_inputs` (`1531ca3`). The CI `Fuzz smoke` job (60 s per target) **failed** on its first GitHub run (run 41136491301); the cause is not yet known. | [`fuzz/fuzz_targets/`](../../fuzz/fuzz_targets/), [`fuzz/README.md`](../../fuzz/README.md), `f34754a` |
| Contract test vectors shared with the SOC implementation (ingest, control plane v2, fleet); AutoSecOps reproduces the ingest and control-plane vectors (AutoSecOps `68e3d2d5`, `a9fca839`) | [`docs/contracts/fixtures/`](../contracts/fixtures/) |
| Rule validation and a benign corpus (86 rules, 659 fixtures, 0 false positives on that corpus, `efdac01`) | `scripts/validate_rules.py`, `scripts/rules_benign_corpus.json` |
| Real Kafka brokers (3.9.1, 4.1.0); swtpm for the TPM anchor, sealing and the depot | `scripts/kafka-it.sh`, `scripts/swtpm-anchor-it.sh`, `crates/robodr-seal/tests/`, `crates/robodr-depot/tests/` |
| Wave-2 soak (7201 s, release binaries, Kafka with mutual TLS) and an end-to-end red team through the binaries: rogue participant, GUID spray, malformed RTPS, safety-feed spoofing, control-plane replay and forgery, executor forgery, gateway feed abuse, Go2 WebRTC, two-person approval evasion, TLS slowloris, erase-trigger spoofing. 3 defects fixed during the run; W2-4 (control-plane slot exhaustion by a multi-source slowloris) documented, not fixed | [`tools/e2e/RESULTS.md`](../../tools/e2e/RESULTS.md) "Wave-2 soak and red team" |
| Independent review rounds (below), each finding fixed with a regression test that failed first | commit history; `crates/*/tests/` |

### Independent review rounds

Each round was done by an AI agent that did not write the code under
review. Finding counts are taken from the fix commits' messages (H = high,
M = medium, L = low, F = numbered finding without a class).

| Component | Reviewed | Findings fixed | Open | Fix commits |
|---|---|---|---|---|
| Motion Firewall low-level joint path | `77bb77f` | 9 (F1–F6, F8–F10) | — | `8b93df1` |
| Unitree decoders | `958a2ae` | 11 items (unnumbered) | — | `85c0223` |
| Responder rules, findings contract 2.x, legacy upgrade path | `ed4f1ac`, `dae7993` | 13 (H1–H2, M1–M6, L1–L5) | — | `f134cc0`, `4c455cf`, `bf93713`, `25fa90d` |
| Unitree live integration | `871d06b`, `76d6253` | 7 numbered (H1–H2, M1–M4, M6) plus low items | — | `fe9acb7` |
| Ingest API and `robodr-uplink` | `fa3f3dc`, `cf2f857` | 8 (F1–F8) | — | `b5a9c7c`, `30e8a7d`, `4f4dfbf`, `8f22bac`, `38ac3a7`, `b6cc96d` |
| Executor v1 | `0499a47`..`356224f` | 15 (H1–H3, M2–M6, L1–L7) plus the journal-reset notice | M1 (trust boundary: agentd can assert `human_approved`) | `31d1aa4`, `7573721`, `ea44192` |
| In-path gateway | `a4e0b4b` | 3 (F1 critical, F2 high, F3 medium) | residual risks documented (L2 spoofing, discovery differential, non-motor fields) | `e85471c` |
| Fleet lifecycle and install bundle | `1de502d`, `3d36c65` | 13 (H1, M1–M4, L1–L8) plus info items | — | `ace7fba`, `3083030`, `6c19e73` |
| Unitree host rules and focal packaging | rules and packaging (GA-ROADMAP §3a) | not numbered | — | `efdac01`, `da81991`, `23ce654` |
| Secure delivery 13a (formats, quorum release signing) | `6e0409e`..`4d31dc9` | 9 numbered (findings 1-9) | — | `f8d67f3`, `8e1db5d`, `ccd5f70` |
| Secure delivery 13b (`robodr-deliverd`), three rounds | `0d03a0d`, then each fix head | H1, H2, M1, M2, M4, L1-L4, I1; round 2 H-A, M-A, M-B, L-A..L-F; round 3 (unnumbered) | — | `6cd7f8b`, `4d41ecc`, `bd701c7`, `e94689e` |
| Sealing 13c (`robodr-seal`) | `0406ca8` | H1, H2, M1, M2, L1-L3 | — | `3f93db5` |
| Red-team fixes (GUID spray, quarantine locators), two review rounds | `b63a509`, `47ba6c7` | H1-H4, M5-M7, L9, L10; R2-1..R2-6; R3-1, R3-2, R3-6 | — | `2a0e232`, `1395edd`, `ac71f3d`, `d2aca58`, `08494ba`, `0049a18` |
| Executor motion adapters and gateway channels (wave 2) | `f557b2f`, `f996920` | unnumbered review items; motion-safety findings 1-4, 7, 8 | — | `ec98227`, `2f9d5fd`, `d9ec8f3`, `e0ae2d8`, merge `6975f72` |
| Gap-closure changes of 2026-10-30 (TLS / CRL, sealed journals, parsers, exporters, retired keys, secure delivery, packaging) | the merges listed under "Fix commits" | per merge message | — | merges `0cb1ef5`, `49dad02`, `3b29bc5`, `477a626`, `9e4a75d`, `4a0df5d`, `f84bfc1` |

**Not reviewed** (no review round in the commit history): the control
plane v2 core (`a158536`, `5cf978e`, `dc22a34`; its sealed journal was
reviewed in merge `49dad02`, and the red team of 2026-10-30 attacked it
end to end) and the S10 hardening commits (`86e70e7`, `c2800c8`,
`7637f9d`, `aba80a5`, `f34754a`).

**Honest limits:**

- **GitHub Actions ran for the first time on 2026-10-30** (run
  41136491301, branch `claude/modest-cray-drpwy7`) and **failed**: pure
  crates (the deliverd test fixture), both Rocky Linux 9 RPM jobs (PATH
  in the container), cargo-deny (RUSTSEC-2026-0387) and fuzz smoke
  (cause not yet known); package install smoke was skipped. The other 11
  jobs passed, including the Pulsar-bound crates, SBOM, reproducible
  build, static musl builds and the Ubuntu 22.04 `.deb` builds on amd64
  and arm64. Earlier runs on `main` failed within seconds (no runner).
- The review rounds above were done by **separate AI coding agents**, not
  by independent human security reviewers. They are useful, but they do
  not meet a requirement for independent human review.
- No penetration test, no human red team (the red team of 2026-10-30
  was scripted by an AI agent), no fuzzing campaign longer than 630 s
  per target, no soak longer than 2 h, and no testing on a real robot.

## DM: management of security-related issues

| Evidence | Where |
|---|---|
| Intake policy: GitHub private vulnerability reporting (**disabled** on the repository as of 2026-10-30; see below), an offline path for air-gapped finders, target times (acknowledge in 3 working days, assess in 10) and coordinated disclosure | [`SECURITY.md`](../../SECURITY.md) |
| PSIRT process draft | [`docs/customer/psirt-process.md`](../customer/psirt-process.md) |

**Missing:**

- a working intake channel: GitHub private vulnerability reporting must
  be enabled (repository setting), and a security mailbox and
  `security.txt` added (CRA-3, CRA-8);
- the process has never been exercised: no issue records, no published
  advisory, no CVE assignment path (CNA or MITRE request) decided;
- severity scoring is not defined beyond "Critical/High";
- no process yet for EU CRA reporting
  ([`cra-readiness.md`](cra-readiness.md)).

## SUM: security update management

| Evidence | Where |
|---|---|
| Offline bundle: tarball verified before extraction, install from a private extraction, kept releases, rollback, downgrade refusal, monotonic security floor, black-box format gate | [`docs/OPERATIONS.md`](../OPERATIONS.md) sections 2, 3, 7; `3d36c65`, `ace7fba` |
| Air-gapped secure delivery: quorum-signed RPKs, deployment records, on-unit `robodr-deliverd` with anti-rollback high-water marks, site depot with leases, sealed packs bound to a TPM key (all tested against swtpm only) | [`docs/SECURE-DELIVERY.md`](../SECURE-DELIVERY.md); OPERATIONS §11-§13 |
| Backup and restore, including what must never be restored (anti-rollback, replay and TPM-bound state) | OPERATIONS §14 |
| SBOM per build (CycloneDX), deterministic fallback generator, verification procedure | [`docs/BUILD.md`](../BUILD.md) "SBOM" |
| Reproducible pure binaries (CI `reproducible` and `static` jobs), pinned C compiler for ring | [`docs/BUILD.md`](../BUILD.md) "Reproducible builds", "C toolchain" |
| SOC ring information with a minimum version that raises the unit's floor | [`docs/contracts/robodr.fleet-api.md`](../contracts/robodr.fleet-api.md); OPERATIONS 8.6 |
| Supported-version policy | [`SECURITY.md`](../../SECURITY.md) "Supported versions" |

**Missing:**

- **no release has been cut**, so no signature, SBOM or advisory has
  ever reached a customer;
- no SLSA or cosign provenance;
- no reproducibility check for the Pulsar-bound binary;
- the support period ("latest minor, plus the previous for 6 months")
  is short for robots and for the CRA.

## SG: security guidelines

| Evidence | Where |
|---|---|
| Installation, keys, commissioning, executor (6.5), inline gateway (6.6), upgrade, ingest (8.5), fleet lifecycle (8.6), decommissioning | [`docs/OPERATIONS.md`](../OPERATIONS.md) |
| Unitree deployment, sensor-box hardening checklist, gateway mode, executor on Unitree | [`docs/UNITREE.md`](../UNITREE.md) |
| Hardening rationale for the units | [`packaging/README.md`](../../packaging/README.md) |
| Customer drafts | [`docs/customer/`](../customer/quick-start.md) |

**Missing:** a secure configuration baseline (GAP-22 in the 4-2 analysis),
and documentation of the host responsibilities (GAP-01).
