# Third-party component due diligence

> **Status: due-diligence record. Verified at commit `8b2b172`
> (2026-10-30).** It records what SingularityRD checked about the
> third-party components RoboDR ships, starting with the one that matters
> most: Pulsar, whose eBPF probes run inside the robot's kernel. It
> answers the CRA's due-diligence obligation for integrated components
> ([`cra-readiness.md`](cra-readiness.md) §4) and the "supplier" questions
> of a security questionnaire. Not legal advice. It is reviewed for every
> release and on every Pulsar bump (review log, §5); a Pulsar bump without
> a new row in that log is a release blocker ([`docs/RELEASE.md`](../RELEASE.md)
> §3 checklist).

## 1. Components and how they are controlled

| Component | How it enters the product | Control in this repository |
|---|---|---|
| **Pulsar** (Exein) | Git submodule `vendor/pulsar`, path dependency of `robodr-pulsard`, `robodr-sensor-ros2` and `robodr-threat-forward`; eBPF probes compiled at build time | This record (§2); pinned commit; its Rust dependencies are in our `Cargo.lock` and checked by `cargo deny` |
| Rust crates from crates.io (about all other code we do not write) | `Cargo.lock`, committed | CI `lockfile` job (no git, patched or unknown sources), `cargo deny` (advisories, licences, bans, sources), new dependencies named with licence and reason in the commit ([`docs/BUILD.md`](../BUILD.md) "Cargo.lock policy") |
| Rust toolchain, clang (for `ring` and the eBPF probes), musl, glibc | Rust: exact version in `rust-toolchain.toml`, installed from hash-pinned artifacts in the independent rebuilds. clang for `ring`: exact package version per build userland (`scripts/c-toolchain.sh`). clang for the eBPF probes: **not hash-pinned**; the `.deb` build takes apt.llvm.org's current clang 20 (archive key pinned, major version enforced), the `.rpm` build exactly clang 21.1.8-2.el9 (one major ahead of Pulsar's 20); `scripts/release-toolchain-inputs.lock` is empty until a hash-pinned package mirror exists | [`docs/BUILD.md`](../BUILD.md) "C toolchain" and "Reproducible builds"; the release's independent rebuild must embed the same eBPF objects in `robodr-pulsard` ([`docs/RELEASE.md`](../RELEASE.md) sections 1 and 11; [`known-limitations.md`](../customer/known-limitations.md)) |
| System libraries linked by `robodr-pulsard` (for example SQLite, unless vendored) | `.deb` / `.rpm` `Depends:` from `dpkg-shlibdeps` and a soname table | `scripts/check-glibc-floor.sh`, `scripts/check-packages.py` |

Notices for all of them ship as `THIRD_PARTY_NOTICES` and
`GPL-2.0-SOURCE-OFFER` in every package (`scripts/third_party_notices.py`,
checked against `deny.toml` in CI).

## 2. Pulsar

### 2.1 Identity

| Item | Value (checked at `8b2b172`) |
|---|---|
| Upstream | <https://github.com/exein-io/pulsar> (`.gitmodules`) |
| Maintainer | Exein SpA ("Copyright 2022 Exein, SpA" in `vendor/pulsar/LICENSE`) |
| Pinned commit | `4796504895ce42f95ffc1e414be19a5d7f40fc0a` (2026-10-12, "chore(github): Update PR template"), `git describe`: `v0.10.0-52-g4796504`, contained in upstream `main` (no RoboDR patches on top) |
| Version in its manifest | `0.11.0-alpha.1` (an unreleased development version; the latest upstream tags are `v0.10.0`, 2026-09-18, and `v0.10.1`, 2026-09-30) |
| Licence | Userspace Apache-2.0; eBPF probes GPL-2.0 (`vendor/pulsar/LICENSES/`). Legal clearance: [ADR-0010](../adr/0010-legal-clearance.md); GPL-2.0 written source offer ships in the packages |
| Size | about 17,600 lines of Rust; three kernel probe files (`process-monitor`, `network-monitor`, `file-system-monitor`, about 1,560 lines of C) |
| Upstream activity | 741 commits since 2022-06-18; 64 in the year before the pinned commit, by 7 authors (52 by one maintainer) |

### 2.2 What RoboDR uses, and what runs where

- `robodr-pulsard` is upstream `pulsard` with two RoboDR modules registered
  (`robodr-sensor-ros2`, `robodr-threat-forward`) and only the core module
  set: process, network and file-system monitors, threat logger, rules
  engine. The **SMTP and desktop notifiers are not built** (feature
  `pulsar-core-modules`; `crates/robodr-pulsard/Cargo.toml`), so Pulsar has
  no outbound notification path and no OpenSSL dependency.
- It runs as **root** and loads eBPF programs into the kernel
  ([`packaging/systemd/robodr-pulsard.service`](../../packaging/systemd/robodr-pulsard.service)).
  It is the only RoboDR daemon that runs as root.
- Its threats reach `robodr-agentd` only through the peer-checked
  `host_threats` socket as strictly parsed JSON lines; agentd never links
  Pulsar. The unit is root with a bounded capability set
  (`CAP_BPF CAP_PERFMON CAP_SYS_RESOURCE CAP_IPC_LOCK CAP_NET_RAW
  CAP_SYS_PTRACE CAP_DAC_READ_SEARCH CAP_MAC_ADMIN`), `ProtectSystem=strict`
  and `InaccessiblePaths=-/etc/robodr/keys`, so it cannot open the key
  files. It can still inject host findings, and with `CAP_SYS_PTRACE` and
  its eBPF capabilities it could read other processes' memory: **treat a
  compromise of `robodr-pulsard` as a compromise of the unit's keys.**
- Every Pulsar API item RoboDR calls was read and checked one by one
  ([`docs/PULSAR-INTEGRATION.md`](../PULSAR-INTEGRATION.md) §2), and the
  build was smoke-tested as root on one kernel (§7b there).

### 2.3 Risk assessment

| Risk | Assessment | Mitigation in RoboDR | Residual |
|---|---|---|---|
| Kernel-side bug in a probe (verifier-accepted but wrong, or a kernel-version-specific behaviour) | eBPF programs are checked by the kernel verifier, which bounds memory access and termination; logic bugs remain possible | Probes load only where `robodr-pulsard` is enabled; BTF guard refuses a BTF file of another kernel (`robodr-btf-check`) | No independent review of the probe C code by SingularityRD; run on one kernel (WSL2 6.18) only, never on a robot kernel or Jetson L4T |
| Root userspace daemon parsing kernel events | A memory-safety bug is unlikely in Rust (80 `unsafe` occurrences in the tree, mostly BPF and FFI glue); a logic bug could blind host detection | systemd confinement of the unit (capability bounding, protected paths); agentd reports a silent `host_threats` input | Runs as root; a compromise is a host compromise |
| Supply chain (malicious upstream commit) | Upstream is a single company's open-source project with a public history | Pinned to an exact commit on upstream `main`; bumps are manual commits reviewed against this record; Pulsar's crates.io dependencies are in our `Cargo.lock` under `cargo deny` | No signed upstream commits or releases are verified; no SLSA provenance from upstream |
| Unmaintained transitive dependency | RUSTSEC-2021-0139 (`ansi_term`, unmaintained, informational) via `bpf-common` → `nut` | Accepted with a reason and review date in `deny.toml` (review by 2027-04-17 or the next Pulsar bump) | Cannot be replaced without patching the submodule |
| Unreleased upstream version | The pin is 52 commits after `v0.10.0`, version `0.11.0-alpha.1` | Pinned for the toolchain and API RoboDR was verified against | Upstream fixes after 2026-10-12 are not in; no upstream security advisory process was found in the tree (no `SECURITY.md`) |
| Vulnerability disclosure | Vulnerabilities in Pulsar that do not depend on RoboDR are reported upstream ([`SECURITY.md`](../../SECURITY.md) "Out of scope"); we track the fix | Bump procedure below | No agreement with Exein; response times unknown |
| Licence (GPL-2.0 kernel code) | The probes are GPL-2.0, loaded into the kernel; userspace is Apache-2.0 | GPL-2.0 source offer and notices in every package; `deny.toml` licence policy for userspace | Wording of the source offer awaits legal approval (SALES-READINESS C20) |
| Availability on target kernels | Needs kernel ≥ 5.5 with BPF and BTF (or an external BTF file) | Support matrix; BTF guard; `robodr-focal` (JetPack 5) ships without `robodr-pulsard` | Not run on a robot kernel |

### 2.4 Bump procedure (each Pulsar update)

1. Read the upstream changes between the old and the new commit, with
   extra attention to `crates/modules/*/probes.bpf.c`, `bpf-common`,
   `pulsar-core` and new dependencies.
2. Re-check every Pulsar API item in
   [`docs/PULSAR-INTEGRATION.md`](../PULSAR-INTEGRATION.md) §2.
3. Update `Cargo.lock` with `--locked` builds, run `cargo deny`, and
   review every new advisory exception.
4. Rebuild, run the Pulsar-bound CI job and the root smoke test.
5. Regenerate `THIRD_PARTY_NOTICES`; update §2.1 and add a row to §5.

## 3. Other dependencies

The crates.io dependencies are governed by policy rather than by a
per-crate record: committed lockfile, `cargo deny` on every CI run,
audited cryptography only ([ADR-0007](../adr/0007-audited-libraries.md):
`ed25519-dalek`, RustCrypto `sha2`, `rustls` + `ring`), and a reason and
licence named for every new dependency. Open item at this commit:
**RUSTSEC-2026-0387** (`crypto-bigint` 0.5.5 through `p256` 0.13) fails
`cargo deny` in CI; the upgrade to `p256` 0.14 is in progress.

## 4. Not done

- No independent review of the Pulsar eBPF probe code.
- No check of upstream's GitHub security advisories or maintainer
  security contact from this environment (no access); check them at the
  next review.
- No supplier agreement with Exein (support, disclosure).
- No per-crate due-diligence records for the crates.io dependencies
  beyond the policy above.

## 5. Review log

| Date | RoboDR commit | Pulsar commit | Reviewer | Result |
|---|---|---|---|---|
| 2026-10-30 | `8b2b172` | `4796504` | AI engineering agent (not independent) | First record. Pin on upstream `main`, no local patches, notifiers not built, one accepted advisory (RUSTSEC-2021-0139). Needs a human review. |
