# IEC 62443-4-1 secure development lifecycle: evidence inventory

> **Status: inventory, 2026-10-26.** This lists what evidence for a secure
> development lifecycle exists in this repository today, and what is
> missing. It is not an assessment of process maturity and not a
> certification claim. The practice names follow the eight practices of
> IEC 62443-4-1, paraphrased:
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
| SM | Roadmap with acceptance criteria per sprint; ADRs; written agent rules; dependency policy | No written security management plan, role list or training records; release-key custody not set up |
| SR | Per-component threat models and "what is claimed" sections; contract-level security requirements (SR-TAINT) | No single product security context and requirements document |
| SD | Defence-in-depth invariants in code; design docs; ADRs | Threat models not reviewed per release |
| SI | Lints as errors; formatting; Cargo.lock policy; `cargo deny` | No `forbid(unsafe_code)` sweep; hand-written crypto and HTTP remain |
| SVV | ~2200 tests (as recorded in GA-ROADMAP §3a); 12 fuzz targets; review regression suites; contract vectors | **CI has never run on GitHub**; no pentest; no red team; reviews were by AI agents, not independent humans |
| DM | `SECURITY.md` intake and timelines | No tracker records, advisory process or CVE assignment path exercised |
| SUM | Signed offline bundle and rollback design; SBOM generator | **No release has ever been cut or signed**; support period not CRA-ready |
| SG | Operations, Unitree and packaging guides; systemd hardening rationale | No secure configuration baseline; customer docs are first drafts |

## SM: security management

| Evidence | Where |
|---|---|
| Product plan with acceptance criteria per sprint and GA exit criteria | [`docs/GA-ROADMAP.md`](../GA-ROADMAP.md) §3, §4 |
| Binding rules for every implementation session: never autonomous, never bypass safety, TLS + Ed25519 on network paths, taint, no own crypto, no skipped tests, claims only what was verified | [`docs/GA-AGENT-PROMPT.md`](../GA-AGENT-PROMPT.md) |
| Architecture decisions | [`docs/adr/`](../adr/README.md) |
| Third-party components: committed `Cargo.lock` with no patched, git or unknown sources (CI `lockfile` job); `cargo deny` for licences, advisories, bans and sources; Pulsar pinned as a submodule | [`docs/BUILD.md`](../BUILD.md) "Cargo.lock policy", "CI jobs"; [`deny.toml`](../../deny.toml) |
| Advisory exceptions carry a reason and a review date (for example RUSTSEC-2021-0139, review 2027-04-17) | [`deny.toml`](../../deny.toml) |
| Toolchain pins: `rust-toolchain.toml`; clang 18.1.3 for ring, enforced in release and repro builds (`38ac3a7`) | [`rust-toolchain.toml`](../../rust-toolchain.toml), [`docs/BUILD.md`](../BUILD.md) "C toolchain" |

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
| SR-TAINT: attacker-controlled strings, allow-list escaping, never interpolated into trusted text | [`docs/contracts/robodr.findings.md`](../contracts/robodr.findings.md) §3 |
| Claims and non-claims for the control plane and the head anchors | [`SECURITY.md`](../../SECURITY.md) |
| Black-box threat model | [`crates/robodr-blackbox/README.md`](../../crates/robodr-blackbox/README.md) "Threat model" |
| Secure-delivery threat model (adversaries, assets, claims) | [`docs/SECURE-DELIVERY.md`](../SECURE-DELIVERY.md) §1 |
| Responder invariants (safety-related security requirements) | [`crates/robodr-responder/README.md`](../../crates/robodr-responder/README.md) "Invariants" |

**Missing:** one product security context document (intended
environment, assumed host controls, SL-C targets) with traceability from
requirements to tests. The 4-2 gap analysis is a first step.

## SD: secure by design

| Evidence | Where |
|---|---|
| Protective-only scope: nothing in the motion stack depends on RoboDR; the control plane has no motion fields | [`SECURITY.md`](../../SECURITY.md) "Scope"; [`docs/contracts/robodr.control-plane.md`](../contracts/robodr.control-plane.md) §4 |
| Defence in depth in the responder: policy validation, plan-time invariants, a re-check by the executor | [`crates/robodr-responder/README.md`](../../crates/robodr-responder/README.md) |
| Least privilege per service (capabilities, `IPAddressDeny`, syscall filters, credentials) with the reasons documented | [`packaging/README.md`](../../packaging/README.md), [`packaging/systemd/`](../../packaging/systemd/) |
| Decision records | [`docs/adr/`](../adr/README.md) |

**Missing:** threat-model review as a release gate. A data-flow diagram
per trust boundary exists only in prose
([`docs/customer/security-whitepaper.md`](../customer/security-whitepaper.md)).

## SI: secure implementation

| Evidence | Where |
|---|---|
| `cargo clippy -D warnings`, `cargo fmt --check` in CI (pure and Pulsar jobs) | [`docs/BUILD.md`](../BUILD.md) "CI jobs" |
| Audited crypto for signatures (`ed25519-dalek`, strict) and TLS (rustls + ring) | [ADR-0007](../adr/0007-audited-libraries.md) |
| Memory and resource bounds stated per parser and queue | crate READMEs |

**Missing:**

- a written coding standard;
- `#![forbid(unsafe_code)]` where possible, and a review of the remaining
  `unsafe` (GA-ROADMAP S10). `unsafe` appears in, among others,
  `crates/robodr-blackbox/src/crypto.rs`, `crates/robodr-agentd/src/signal.rs`
  and `crates/robodr-ros2-pipeline/src/socket.rs`;
- the hand-written SHA-256, HMAC, HTTP server and Kafka client are still
  in place (ADR-0007).

## SVV: security verification and validation testing

| Evidence | Where |
|---|---|
| Unit and integration tests. GA-ROADMAP §3a records "2196+ tests, 0 failures" (2026-10-26) and §3 Sprint 1 records all workspace tests green locally. This inventory did not re-run them. | [`docs/GA-ROADMAP.md`](../GA-ROADMAP.md) |
| Real-traffic tests: ROS 2 Jazzy captures (Fast DDS 2.14, Cyclone DDS 0.10, Gazebo) | [`fixtures/captures/ros2-jazzy/`](../../fixtures/captures/ros2-jazzy/README.md) |
| Fuzzing: 12 cargo-fuzz targets; std-only fuzz smoke runs in the crate tests. The local CI run of 2026-10-17 ran the then-11 targets for 60 s each without a crash. | [`fuzz/fuzz_targets/`](../../fuzz/fuzz_targets/), [`docs/BUILD.md`](../BUILD.md) "Local CI verification" |
| Regression suites for review findings (for example `review_regressions.rs`, `review_safety_regressions.rs`, `rev3_regressions.rs` in several crates) | `crates/*/tests/` |
| Contract test vectors shared with the SOC implementation | [`docs/contracts/fixtures/ingest/`](../contracts/fixtures/ingest/) |
| Rule validation and a benign corpus (0 false positives on that corpus, as recorded in GA-ROADMAP §3a) | `scripts/validate_rules.py`, `scripts/rules_benign_corpus.json` |
| Real Kafka brokers (3.9.1, 4.1.0); swtpm for the TPM anchor | `scripts/kafka-it.sh`, `scripts/swtpm-anchor-it.sh` |
| Review rounds by a reviewer that did not write the code (GA-ROADMAP §3a: firewall `8b93df1`, decoders `85c0223`, responder `f134cc0`, contracts `4c455cf`, `bf93713`, live integration `fe9acb7`, ingest `8f22bac`) | commit history |

**Honest limits:**

- **GitHub Actions has never run** for this repository (organisation
  billing, GA-ROADMAP R6). Every CI job passed in a local step-by-step
  run on 2026-10-17. `cargo deny` passed locally on 2026-10-26.
- The review rounds above were done by **separate AI coding agents**, not
  by independent human security reviewers. They are useful, but they do
  not meet a requirement for independent human review.
- No penetration test, no red-team exercise, no long fuzzing campaign
  (planned S10, S11), and no testing on a real robot.

## DM: management of security-related issues

| Evidence | Where |
|---|---|
| Private intake through GitHub private vulnerability reporting, an offline path for air-gapped finders, target times (acknowledge in 3 working days, assess in 10) and coordinated disclosure | [`SECURITY.md`](../../SECURITY.md) |
| PSIRT process draft | [`docs/customer/psirt-process.md`](../customer/psirt-process.md) |

**Missing:**

- the process has never been exercised: no issue records, no published
  advisory, no CVE assignment path (CNA or MITRE request) decided;
- severity scoring is not defined beyond "Critical/High";
- no process yet for EU CRA reporting
  ([`cra-readiness.md`](cra-readiness.md)).

## SUM: security update management

| Evidence | Where |
|---|---|
| Offline bundle: minisign-verified install, `SHA256SUMS`, kept releases, rollback | [`docs/OPERATIONS.md`](../OPERATIONS.md) sections 2, 3, 7 |
| SBOM per build (CycloneDX), deterministic fallback generator, verification procedure | [`docs/BUILD.md`](../BUILD.md) "SBOM" |
| Reproducible pure binaries (CI `reproducible` and `static` jobs) | [`docs/BUILD.md`](../BUILD.md) "Reproducible builds" |
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
| Installation, keys, commissioning, upgrade, decommissioning | [`docs/OPERATIONS.md`](../OPERATIONS.md) |
| Unitree deployment and sensor-box hardening checklist | [`docs/UNITREE.md`](../UNITREE.md) |
| Hardening rationale for the units | [`packaging/README.md`](../../packaging/README.md) |
| Customer drafts | [`docs/customer/`](../customer/quick-start.md) |

**Missing:** a secure configuration baseline (GAP-22 in the 4-2 analysis),
and documentation of the host responsibilities (GAP-01).
