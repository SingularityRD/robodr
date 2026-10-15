# Building RoboDR

How RoboDR is built, in the lab and air-gapped; how the SBOM is produced and
verified; how a release is reproduced; and what of all this has actually been
verified so far. CI is `.github/workflows/ci.yml`; every procedure below is a
script that CI runs, so the lab and CI cannot drift apart.

Contents: [Toolchain](#toolchain) · [Developer build](#developer-build) ·
[Pulsar / eBPF prerequisites](#pulsar--ebpf-prerequisites) ·
[Cargo.lock policy](#cargolock-policy) · [Air-gapped builds](#air-gapped-builds) ·
[SBOM](#sbom) · [Reproducible builds](#reproducible-builds) ·
[Licensing](#licensing) · [CI jobs](#ci-jobs) ·
[Verification status](#verification-status)

---

## Toolchain

| What | Value | Where |
|---|---|---|
| Release toolchain | Rust **1.98.1** (same pin as Pulsar) | `rust-toolchain.toml` |
| MSRV | **1.85** (Pulsar's floor: edition 2024) | `[workspace.package] rust-version` |
| Edition (RoboDR crates) | 2021 | `[workspace.package]` |
| Targets | `x86_64-unknown-linux-gnu`, `aarch64-unknown-linux-gnu` | `rust-toolchain.toml` |

`pulsar-core` is compiled *inside* this workspace (path dependency on the
`vendor/pulsar` submodule), so RoboDR pins exactly the compiler Pulsar is tested
with. A fixed compiler is also a precondition for reproducible builds.

The MSRV applies to crates that opt in with `rust-version.workspace = true`
(none do yet; see [Verification status](#verification-status)). The `msrv` CI
job checks the pure crates with 1.85.

A host that does not have 1.98.1 (for example the dev sandbox, which only has
a newer stable and no network) can override **for local work only**:

```bash
RUSTUP_TOOLCHAIN=stable cargo test --workspace --exclude robodr-sensor-ros2
```

Release artefacts must be built with the pinned toolchain.

## Developer build

```bash
git clone --recurse-submodules https://github.com/SingularityRD/robodr.git
cd robodr

# Pure crates: no kernel, no robot, no Pulsar toolchain needed.
cargo fmt --all -- --check
cargo clippy --workspace --exclude robodr-sensor-ros2 --all-targets -- -D warnings
cargo test   --workspace --exclude robodr-sensor-ros2

# Pulsar-bound crates (need the packages listed in the next section).
cargo build -p robodr-sensor-ros2
cargo test  -p robodr-sensor-ros2
```

The submodule must be checked out even for the pure crates: cargo loads the
whole workspace manifest, and `pulsar-core` is a path dependency.

`scripts/ci-pure-excludes.py` prints the exact `--exclude` list CI uses: every
member that is named Pulsar-bound (`robodr-sensor-ros2`, `robodr-pulsard`),
depends on `pulsar-core` / `bpf-common`, or depends on such a member. It only
names members that exist, because older cargo rejects (and current cargo warns
about) `--exclude` of an unknown package.

## Pulsar / eBPF prerequisites

From `vendor/pulsar/README.md` and Pulsar's own CI (`vendor/pulsar/Cross.toml`,
`.github/workflows/*.yaml`):

**To build** (any Linux host, no special kernel):

- Rust 1.98.1 (above).
- `clang-20`, `lld-20`, `llvm-20` with `clang` and `llvm-strip` on `PATH`
  (Pulsar's `bpf-builder` invokes `clang -target bpf` and `llvm-strip`; override
  the compiler with `CLANG=`). Pulsar's build containers symlink
  `/usr/bin/clang-20 -> clang` and `llvm-strip-20 -> llvm-strip`.
- `libssl-dev` (smtp-notifier with `tls-openssl`) and `libsqlite3-dev`
  (`rusqlite` in `bpf-common`), unless built with Pulsar's `all-vendored`
  feature. `pkg-config`.
- Ubuntu 24.04:
  `sudo apt-get install clang-20 lld-20 llvm-20 libssl-dev libsqlite3-dev pkg-config`.

**To run** (`pulsard` with RoboDR modules on the robot companion computer):

- Linux kernel **5.5 or newer** with BPF and **BTF** enabled
  (`CONFIG_BPF=y`, `CONFIG_BPF_SYSCALL=y`, `CONFIG_DEBUG_INFO_BTF=y`; check that
  `/sys/kernel/btf/vmlinux` exists). Full list:
  <https://pulsar.sh/docs/faq/kernel-requirements/>.
- Root (or the equivalent capabilities) for the daemon.
- Pulsar's integration CI exercises kernels 5.13 to 6.12 on amd64/arm64; the
  RoboDR module has not been run on a kernel yet (see verification status).

## Cargo.lock policy

RoboDR ships binaries, so **`Cargo.lock` is committed** and every release and
CI build uses `--locked`.

- The lock must be generated on a machine that resolves against **crates.io or
  the internal mirror**: `cargo generate-lockfile` (or any normal `cargo build`).
  With source replacement the lock still records crates.io as the source, so a
  lock made through the mirror and one made against crates.io are identical.
- A lock generated with `[patch.crates-io]` pointing at local paths (as the dev
  sandbox's `offline-cargo.sh` does) records registry crates with no source and
  no checksum. **It must never be committed.** `scripts/ci-check-lockfile.py`
  fails CI if a non-local package has no source, any source is `path+`/`git+`
  or an unknown registry, or a registry package lacks a checksum.
- Until the first real lock is committed, the CI `lockfile` job generates one,
  validates it, uploads it as the `Cargo.lock-generated` artifact and raises a
  warning. A maintainer reviews that file and commits it; from then on every
  job runs with `--locked` automatically (`scripts/ci-setup.sh`).
- `.gitattributes` marks `Cargo.lock merge=binary`: resolve lock conflicts by
  regenerating, never by hand-merging.

## Air-gapped builds

Defence posture (docs/SPRINTS.md): the lab and every build run with no
outbound connectivity. Two supported ways, both driven by
`.cargo/config.toml.example`.

### A. Internal registry mirror (inside the lab network)

1. The mirror serves a sparse index at
   `sparse+https://crates.mirror.internal/index/` (replace with the real host).
   It is populated on the connected side and transferred through the entry
   station; its content is whatever `Cargo.lock` needs, nothing fetched live.
2. On each build host: `cp .cargo/config.toml.example ~/.cargo/config.toml`
   (or `.cargo/config.toml` in the repo, which is git-ignored). Keep Option A,
   set the mirror URL, and the private CA under `[http] cainfo` if needed.
3. `cargo build --locked`. Cargo verifies every crate against the checksum in
   `Cargo.lock`, so a tampered mirror is detected.
4. CI on a self-hosted runner: set the repository variable
   `ROBODR_CRATES_MIRROR` to the sparse index URL and change `runs-on` to the
   self-hosted label; `scripts/ci-setup.sh` writes the same source replacement
   into `CARGO_HOME`.

### B. Vendored tarball through the entry station (no network at all)

On the **connected** side, at the commit to be built:

```bash
git clone --recurse-submodules https://github.com/SingularityRD/robodr.git
cd robodr && git checkout <tag>
# Cargo.lock must be the committed one; do not regenerate here.
cargo vendor --locked --versioned-dirs third_party/cargo-vendor > /dev/null
# NOT `vendor/`: that directory is the Pulsar submodule.
cd .. && tar --sort=name --mtime="@$(git -C robodr log -1 --format=%ct)" \
             --owner=0 --group=0 --numeric-owner -cJf robodr-<tag>-src+vendor.tar.xz robodr
sha256sum robodr-<tag>-src+vendor.tar.xz > robodr-<tag>-src+vendor.tar.xz.sha256
```

Also carry, as separate verified items:

- the Rust **1.98.1** toolchain: the `rust-1.98.1-<target>.tar.xz` standalone
  installers from `static.rust-lang.org`, each checked against its `.asc`
  signature with the Rust release key before transfer (or the internal rustup
  mirror via `RUSTUP_DIST_SERVER`);
- the CI tools as vendored sources (`cargo-deny`, `cargo-cyclonedx`), built
  inside with the same toolchain;
- a snapshot of the RustSec advisory DB (git bundle of
  `rustsec/advisory-db`) for `cargo deny check advisories --disable-fetch`.

At the **entry station**: verify the SHA-256 (and the signature, per the
programme's signing scheme), scan per site policy, log the transfer.

On the **air-gapped** build host:

```bash
tar xJf robodr-<tag>-src+vendor.tar.xz && cd robodr
mkdir -p .cargo && cp .cargo/config.toml.example .cargo/config.toml
# In .cargo/config.toml: comment out Option A, enable Option B (vendored-sources, net.offline = true).
cargo build --release --locked --offline
scripts/sbom.sh dist/sbom          # falls back to the std-only generator if cargo-cyclonedx is absent
scripts/ci-repro.sh dist/repro     # optional: prove the build reproduces on this host
```

`cargo vendor` vendors every registry crate in the lock, including the
dependencies of `pulsar-core`; Pulsar's own crates come from the submodule in
the tarball.

## SBOM

One SBOM per build, CycloneDX JSON.

```bash
scripts/sbom.sh dist/sbom
```

- **With `cargo-cyclonedx`** (CI installs 0.5.9): one `<crate>.cdx.json` per
  workspace crate, collected into `dist/sbom/`.
- **Without it** (air-gapped host, dev sandbox): `cargo metadata` piped through
  `scripts/metadata_to_cyclonedx.py` (Python 3.11+ std-lib only) into one
  `robodr.cdx.json` covering the workspace. It records name, version, purl,
  license (SPDX expression, or the raw string as a named license when it is not
  valid SPDX, e.g. Pulsar's), SHA-256 from `Cargo.lock`, source kind,
  repository, and the resolved dependency graph. Dev-only dependencies are
  omitted (`--include-dev` keeps them); build-dependencies are kept. Output is
  deterministic: no timestamp unless `SOURCE_DATE_EPOCH` is set, content-derived
  serial number, sorted, no absolute build paths.
- Force a generator with `SBOM_TOOL=cyclonedx|metadata`. CI runs both and
  uploads `dist/sbom/` as the `sbom-<sha>` artifact (kept 90 days).

**Verifying an SBOM** (yours or one received with a release):

```bash
# 1. Integrity of the delivered files.
(cd dist/sbom/metadata && sha256sum -c SHA256SUMS)
# 2. Structure, and every component's name/version/SHA-256 against Cargo.lock.
python3 scripts/metadata_to_cyclonedx.py --check dist/sbom/metadata/robodr.cdx.json --lockfile Cargo.lock
# 3. Regenerate from the same commit and compare (fallback generator is deterministic).
SOURCE_DATE_EPOCH=$(git log -1 --format=%ct) SBOM_TOOL=metadata CARGO_METADATA_ARGS=--locked scripts/sbom.sh /tmp/sbom-check
cmp /tmp/sbom-check/robodr.cdx.json dist/sbom/metadata/robodr.cdx.json
```

`--check` is a structural check (format, spec version, unique bom-refs,
dependency references, hash syntax) plus the lock cross-check. It is not a full
CycloneDX JSON-schema validation; use the CycloneDX CLI
(`cyclonedx validate`) where it is available.

## Reproducible builds

```bash
scripts/ci-repro.sh dist/repro
```

builds the pure workspace twice in release mode, from two copies of the tree at
paths of different length, and requires every executable
`target/release/robodr-*` to be bit-identical. It writes the hashes to
`dist/repro/SHA256SUMS` (CI uploads it as `release-sha256-<sha>`). Controlled:

| Source of drift | Control |
|---|---|
| Compiler | `rust-toolchain.toml` pin |
| Dependency versions | committed `Cargo.lock`, `--locked` (one shared resolution if none is committed yet) |
| Absolute paths (checkout, `CARGO_HOME`) | `--remap-path-prefix` to `/build/robodr` and `/cargo` |
| Timestamps | `SOURCE_DATE_EPOCH` = HEAD commit time |
| Codegen non-determinism | `codegen-units = 1`, `incremental = false`, `CARGO_INCREMENTAL=0` |
| Debug info / symbols | `debug = false`, `strip = true` (`[profile.release]`) |

To verify a published release independently: check out the tag with
submodules, install Rust 1.98.1, run `scripts/ci-repro.sh`, and compare its
`SHA256SUMS` with the one published for the release. Signing the release (the
other half of the Sprint 1 assurance item) is not implemented yet.

The Pulsar-bound binary (`pulsard` with RoboDR modules, embedding eBPF objects
built by clang) is **not** covered yet: clang/LLVM output must be pinned and
checked separately.

## Licensing

- Rust crates: `license = "Apache-2.0"` (`[workspace.package]`), a valid SPDX
  expression for cargo, cargo-deny and the SBOM.
- eBPF probe C sources (`*.bpf.c`): GPL-2.0-only, declared per file with an
  `SPDX-License-Identifier` header. They are separate kernel programs, not Rust
  crates. See `LICENSE` and `LICENSES/`.
- Pulsar uses the free-text string "Apache-2.0 WITH BPF probes exception under
  GPL-2.0", which is not SPDX; `deny.toml` clarifies Pulsar's Rust crates as
  Apache-2.0 so cargo-deny can evaluate them, and the fallback SBOM records the
  raw string as a named license.
- `deny.toml` allows only permissive licenses for userspace crates; any
  GPL/LGPL/AGPL (and MPL-2.0 without a reviewed exception) fails CI.

## CI jobs

| Job | Required | What |
|---|---|---|
| `lockfile` | yes | Committed `Cargo.lock` has no local/patched/git/unknown sources; if none is committed, generate + upload one (warning) |
| `scripts` | yes | Python self-tests of the CI scripts, `shellcheck scripts/*.sh` |
| `pure` | yes | `fmt --check`, `clippy -D warnings`, `test` for every member except Pulsar-bound ones |
| `pulsar` | yes | Installs Pulsar's build packages, then `build` / `clippy -D warnings` / `test` of every Pulsar-bound member (`robodr-sensor-ros2`, later `robodr-pulsard`). No kernel load |
| `msrv` | informational | `cargo +1.85.0 check` of the pure crates |
| `deny` | yes | `cargo deny check advisories bans licenses sources` (`deny.toml`) |
| `sbom` | yes | CycloneDX via cargo-cyclonedx **and** the std-only fallback; uploaded as artifact |
| `fuzz` | yes | If `fuzz/` exists: every `cargo fuzz` target for 60 s on a pinned nightly; crashes uploaded |
| `reproducible` | yes | `scripts/ci-repro.sh`; hashes uploaded |

All third-party actions are pinned by full commit SHA (resolved with
`git ls-remote --tags` from the upstream repositories), with the tag in a
comment. Workflow token permissions are `contents: read`.

## Verification status

Be precise about what has and has not been exercised. Last updated with the CI
rewrite (feat/ci).

**Verified in the dev sandbox** (no network, Rust 1.97.0 stable, no
cargo-cyclonedx / cargo-deny / shellcheck installed):

- `scripts/metadata_to_cyclonedx.py`, `scripts/ci-check-lockfile.py`,
  `scripts/ci-pure-excludes.py`: self-tests pass.
- `scripts/sbom.sh` fallback path on real `cargo metadata` output of the pure
  workspace: produces a CycloneDX 1.5 SBOM (19 components) that passes `--check`
  and the `Cargo.lock` cross-check; two runs are byte-identical.
- `scripts/ci-check-lockfile.py` rejects the sandbox's patched lock
  (10 registry crates without source) and accepts well-formed ones (self-test).
- `scripts/ci-repro.sh` on the pure workspace with a temporary
  `robodr-commission` binary: two builds from different paths produced
  identical SHA-256.
- `scripts/ci-setup.sh`: exclude list (`--exclude robodr-sensor-ros2`), mirror
  config generation, rejection of a non-sparse mirror URL.
- cargo 1.97 only *warns* on `--exclude` of a nonexistent package (we avoid
  passing one anyway).
- Workflow YAML parses (PyYAML); every `uses:` is a 40-hex SHA. Scripts pass
  `bash -n`.

**Not verified** (needs network, the pinned toolchain or a kernel):

- No CI run has happened yet. In particular unverified: that `clang-20` /
  `llvm-20` install from the ubuntu-24.04 runner's apt sources (the job falls
  back to the distribution clang with a warning), that the Pulsar-bound build
  passes, cargo-cyclonedx 0.5.9 flags/output names, the cargo-deny 0.20.2
  config keys (`[[licenses.clarify]]` with empty `license-files` for path
  crates, `sparse+` entries in `allow-registry`), which licenses the full
  dependency graph actually carries (the allow-list may need additions after
  the first run), that the pinned nightly `nightly-2026-09-01` and
  cargo-fuzz 0.13.1 work together, and that 1.85 really builds the pure crates.
- `shellcheck` was not available in the sandbox; CI runs it.
- No `Cargo.lock` is committed yet (none could be generated here without
  crates.io); builds are not reproducible across machines until it is.
- No crate inherits `rust-version.workspace = true` yet, so the MSRV is
  declared but not enforced by cargo.
- The air-gapped procedures (mirror, vendored tarball, offline toolchain,
  advisory-DB snapshot) are documented, not yet rehearsed in the lab.
- Release signing is not implemented. Reproducibility of the Pulsar-bound
  binary (eBPF objects from clang) is not checked.
