# Building RoboDR

How RoboDR is built, in the lab and air-gapped; how the SBOM is produced and
verified; how a release is reproduced; and what of all this has actually been
verified so far. CI is `.github/workflows/ci.yml`; every procedure below is a
script that CI runs, so the lab and CI cannot drift apart.

Contents: [Toolchain](#toolchain) · [Developer build](#developer-build) ·
[C toolchain](#c-toolchain) ·
[Pulsar / eBPF prerequisites](#pulsar--ebpf-prerequisites) ·
[Cargo.lock policy](#cargolock-policy) · [Air-gapped builds](#air-gapped-builds) ·
[SBOM](#sbom) · [Reproducible builds](#reproducible-builds) ·
[Static (musl) build](#static-musl-build) ·
[Licensing](#licensing) · [CI jobs](#ci-jobs) ·
[Local CI verification](#local-ci-verification) ·
[Verification status](#verification-status)

---

## Toolchain

| What | Value | Where |
|---|---|---|
| Release toolchain | Rust **1.98.1** (same pin as Pulsar) | `rust-toolchain.toml` |
| MSRV | **1.87** (`u*::is_multiple_of`; Pulsar's own floor is 1.85, edition 2024) | `[workspace.package] rust-version`, `MSRV` in `.github/workflows/ci.yml` |
| Edition (RoboDR crates) | 2021 | `[workspace.package]` |
| Targets | `x86_64-unknown-linux-gnu`, `aarch64-unknown-linux-gnu` | `rust-toolchain.toml` |
| Static targets (`robodr-focal`) | `x86_64-unknown-linux-musl`, `aarch64-unknown-linux-musl` (`rustup target add`; not in `rust-toolchain.toml`) | `scripts/build-static.sh` |

`pulsar-core` is compiled *inside* this workspace (path dependency on the
`vendor/pulsar` submodule), so RoboDR pins exactly the compiler Pulsar is tested
with. A fixed compiler is also a precondition for reproducible builds.

Every workspace crate inherits the MSRV with `rust-version.workspace = true`
(all 13 members; the separate `fuzz/` workspace does not, it needs nightly).
Why 1.87: `u*::is_multiple_of` is used in library code of `robodr-capture`,
`-rtps`, `-blackbox` and `-commission` (and in tests/examples of
`-firewall`, `-motion`, `-ros2-pipeline`). Because the crates declare it,
clippy's `incompatible_msrv` lint (on by default, an error under
`-D warnings`) rejects any std API newer than 1.87. The `msrv` CI job
compiles the pure crates with 1.87 itself; it is still marked informational
in `ci.yml` (see [Verification status](#verification-status)).

A host that does not have 1.98.1 (for example the dev sandbox, which only has
a newer stable and no network) can override **for local work only**:

```bash
RUSTUP_TOOLCHAIN=stable cargo test --workspace --exclude robodr-sensor-ros2 --exclude robodr-pulsard
```

Release artefacts must be built with the pinned toolchain.

## Developer build

```bash
git clone --recurse-submodules https://github.com/SingularityRD/robodr.git
cd robodr

# Pure crates: no kernel, no robot, no Pulsar toolchain needed.
cargo fmt --all -- --check
cargo clippy --workspace --exclude robodr-sensor-ros2 --exclude robodr-pulsard --all-targets -- -D warnings
cargo test   --workspace --exclude robodr-sensor-ros2 --exclude robodr-pulsard

# Pulsar-bound crates (need the packages listed in the next section).
cargo build -p robodr-sensor-ros2 -p robodr-pulsard
cargo test  -p robodr-sensor-ros2 -p robodr-pulsard
```

The pure set is every other member: `robodr-agent`, `-agentd`, `-blackbox`,
`-capture`, `-cdr`, `-commission`, `-diode`, `-events`, `-firewall`,
`-motion`, `-ocsf`, `-responder`, `-ros2-pipeline`, `-rtps`. CI covers them
workspace-wide (no list to maintain).

Binaries built from the pure set (all shipped in the `.deb`, all checked by
`scripts/ci-repro.sh`): `robodr-replay`, `robodr-agentd`, `robodr-blackbox`,
`robodr-commission`, `robodr-diode-pack`, `robodr-diode-unpack`,
`robodr-ros2-watch`, `robodr-spool-export`, `robodr-kafka-publish`,
`robodr-uplink`, `robodr-anchor-receiver`. Pulsar-bound: `robodr-pulsard`.

C in the pure set: only `ring` (the crypto provider of rustls, linked into
`robodr-uplink` for TLS) compiles C and assembly through the `cc` crate,
so a C compiler is needed. A developer build uses whatever `cc` is
installed; **release and reproducibility builds use the pinned clang**
for every target ([C toolchain](#c-toolchain)). Everything else is pure
Rust.

## C toolchain

ring's C and assembly objects end up in the shipped `robodr-uplink`, so
the release bytes depend on the C compiler, not only on the Rust
toolchain. The C toolchain is therefore pinned like Rust is
(`scripts/c-toolchain.sh` is the single source; this table repeats it):

| Tool | Pin | Used for | Enforced |
|---|---|---|---|
| clang | **`clang-18` 18.1.3**, Ubuntu 24.04 package `clang-18=1:18.1.3-1ubuntu1` (release pocket: amd64 and arm64) | ring, every target: `x86_64`/`aarch64` `-linux-gnu` and `-linux-musl` (`CC_<triple>`) | yes: `scripts/ci-repro.sh`, `scripts/build-static.sh` and `release.yml` fail (exit 1) when `clang-18` is missing or reports another version; a `CC_<triple>` you set is checked the same way. No fallback to `cc`. |
| gcc | 13.3.0 (Ubuntu 24.04 `gcc-13`) | the link driver of the `-linux-gnu` builds (`cc`) | documented, recorded |
| binutils | 2.42 (Ubuntu 24.04) | GNU `ld` behind gcc (`-linux-gnu`); `ar` archives ring's objects before rustc reads them | documented, recorded |
| rust-lld | from the Rust 1.98.1 toolchain | the linker of the musl builds | with the Rust pin |

CI and release jobs install the pin with `scripts/ci-install-clang.sh`
(`apt-get install clang-18=1:18.1.3-1ubuntu1`, `apt-mark hold`, then the
version check). Each build writes the versions it actually used to
`TOOLCHAIN.txt` next to its `SHA256SUMS` (`dist/repro/`,
`dist/static/<triple>/`). `ROBODR_ALLOW_UNPINNED_CC=1` accepts another
clang for local experiments only: the scripts then say "NOT a release
build", and the hashes are not expected to match a release. The
Pulsar-bound `robodr-pulsard` keeps its own clang-20 (eBPF) and is built
without the ring pin; its reproducibility is not claimed.

Changing a pin is a release-visible change: edit `scripts/c-toolchain.sh`,
this table and the verification notes in one commit.

**Air-gapped build hosts.** Besides the Rust toolchain and the vendored
crates ([Air-gapped builds](#air-gapped-builds)), bring the C toolchain
from a connected Ubuntu 24.04 host of the same architecture:

```bash
# On a connected noble host (amd64 or arm64, as the build host):
apt-get download clang-18=1:18.1.3-1ubuntu1 \
  $(apt-cache depends --recurse --no-recommends --no-suggests --no-conflicts \
      --no-breaks --no-replaces --no-enhances clang-18=1:18.1.3-1ubuntu1 | grep '^\w' | sort -u)
sha256sum ./*.deb > SHA256SUMS      # carry both through the entry station
# On the build host (Ubuntu 24.04, same arch):
sha256sum -c SHA256SUMS && sudo apt-get install ./*.deb   # or dpkg -i
sudo apt-mark hold clang-18
clang-18 --version | head -n1       # Ubuntu clang version 18.1.3 (1ubuntu1)
```

The `.deb` files are signed through Ubuntu's archive (`Release.gpg` →
`Packages` → per-package SHA-256): verify them on the connected host
(`apt-get download` does) before carrying them over. gcc 13 and binutils
2.42 are part of a standard Ubuntu 24.04 build host (`build-essential`).

**Independent verification of a release** (what a third party, or the
air-gapped site, does to confirm the published binaries come from the
tagged source):

1. Ubuntu 24.04 (amd64, or arm64 for the arm64 assets), clean user, the
   pinned C toolchain above, `rustup` with the toolchain of
   `rust-toolchain.toml` (1.98.1) and, for `robodr-focal`, the musl
   targets.
2. `git clone --recurse-submodules` the repository and check out the
   release tag; do **not** regenerate `Cargo.lock`.
3. `scripts/ci-repro.sh dist/repro` (glibc binaries of the main `.deb`) and,
   for `robodr-focal`, `CARGO_BUILD_TARGET=<triple>
   CARGO_TARGET_<TRIPLE>_LINKER=rust-lld scripts/ci-repro.sh
   dist/repro-static` or `scripts/build-static.sh <triple>`.
4. Compare `dist/repro*/SHA256SUMS` with the release's `SHA256SUMS-<arch>`
   (and the binaries extracted from the `.deb` with `dpkg-deb -x`); check
   `TOOLCHAIN.txt` names the pinned versions. Verify the release's minisign
   signatures as described below.

A mismatch with every pin in place is a finding: report it (do not
install).

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
- A committed `Cargo.lock` is **required**. `scripts/ci-setup.sh` makes every
  CI job fail if it is missing and passes `--locked` to every cargo command
  (`CARGO_LOCKED`), so a stale lock fails the build instead of being
  rewritten. The only exception is the `lockfile` job
  (`ROBODR_ALLOW_MISSING_LOCK=1`): when no lock is committed it generates one,
  validates it with `scripts/ci-check-lockfile.py`, uploads it as the
  `Cargo.lock-generated` artifact and then **fails**. Bootstrap: download that
  artifact, check its `sha256sum` against the job log, review it, commit it.
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
`dist/repro/SHA256SUMS` (CI uploads it as `release-sha256-<sha>`). For a
cross build, set `CARGO_BUILD_TARGET` (e.g. `aarch64-unknown-linux-gnu`); the
script then compares `target/<triple>/release/robodr-*`. Controlled:

| Source of drift | Control |
|---|---|
| Compiler | `rust-toolchain.toml` pin |
| C compiler (ring) | pinned clang 18.1.3 for every target, enforced ([C toolchain](#c-toolchain)) |
| Dependency versions | committed `Cargo.lock` (required), `--locked` |
| Absolute paths (checkout, `CARGO_HOME`) | `--remap-path-prefix` to `/build/robodr` and `/cargo` |
| Timestamps | `SOURCE_DATE_EPOCH` = HEAD commit time |
| Codegen non-determinism | `codegen-units = 1`, `incremental = false`, `CARGO_INCREMENTAL=0` |
| Debug info / symbols | `debug = false`, `strip = true` (`[profile.release]`) |

To verify a published release independently: follow
[C toolchain](#c-toolchain), "Independent verification of a release"
(the tag with submodules, Rust 1.98.1, the pinned clang,
`scripts/ci-repro.sh`, compare its `SHA256SUMS` with the release's). Signing (the other
half of the Sprint 1 assurance item) is implemented in `release.yml`'s
`publish` job: `SHA256SUMS` plus a minisign signature (`*.minisig`) for every
asset, verifiable offline with the public key in the repository variable
`ROBODR_MINISIGN_PUBKEY`. It has never run: the `MINISIGN_SECRET_KEY` /
`MINISIGN_PASSWORD` secrets are not provisioned and no release has been cut.
cosign / SLSA provenance is a TODO in the workflow.

The Pulsar-bound binary (`pulsard` with RoboDR modules, embedding eBPF objects
built by clang) is **not** covered yet: clang/LLVM output must be pinned and
checked separately.

## Static (musl) build

**Why.** The release `.deb` is built on Ubuntu 24.04 and its binaries need
glibc 2.39 (see [arm64](#arm64-cross-compiled-2026-10-18)); its units need
systemd 247. Robot computers on older images cannot run it: NVIDIA JetPack 5
(Ubuntu 20.04: glibc 2.31, systemd 245), the image of current Unitree EDU
computers, and JetPack 6 / Ubuntu 22.04 (glibc 2.35). For them the pure
binaries are built as **static musl executables** and shipped in the
`robodr-focal` package (packaging/README.md), with systemd 245 units.
`robodr-pulsard` is not built this way (it links libsqlite3/OpenSSL, embeds
clang-built eBPF objects, and needs a BTF kernel that JetPack 5 lacks).

```bash
rustup target add x86_64-unknown-linux-musl aarch64-unknown-linux-musl
scripts/build-static.sh x86_64-unknown-linux-musl     # -> dist/static/x86_64-unknown-linux-musl/
scripts/build-static.sh aarch64-unknown-linux-musl    # cross, from any x86-64 host
packaging/build-deb.sh --variant focal --bin-dir dist/static/aarch64-unknown-linux-musl --arch arm64 --out dist
```

`scripts/build-static.sh` builds exactly the set `ci-repro.sh` builds (the
pure workspace) for the musl target with the release flags (`--locked`,
`SOURCE_DATE_EPOCH`, `--remap-path-prefix`), links with **rust-lld** from
the Rust toolchain for both targets (self-contained musl CRT and libc from
the target's rust-std; no `musl-gcc`), compiles the one piece of C,
`ring`'s C and assembly (rustls' crypto provider, `robodr-uplink`), with
the **pinned clang** for both triples (`CC_<triple>` = `clang-18` 18.1.3,
[C toolchain](#c-toolchain): missing or another version fails the build;
ring needs no libc headers beyond what clang finds, verified 2026-10-26
with clang 18 for both triples), then **refuses** any `robodr-*` binary
that is not an ELF for the target machine, has a `PT_INTERP` program
header or a `DT_NEEDED` entry, and writes the binaries and `SHA256SUMS`
to `dist/static/<triple>/`. `build-deb.sh --variant focal` repeats the
static check, so a dynamic binary can never reach `robodr-focal`, whose
only dependency is `systemd (>= 245)`.

| | x86_64-unknown-linux-musl | aarch64-unknown-linux-musl |
|---|---|---|
| Linker | rust-lld | rust-lld (cross) |
| Layout | static-pie (ASLR of the image) | static, **not PIE**: the Rust target has no static-pie support, so the executable image is at a fixed address (stack, heap and mappings are still randomised) |
| C compiler (ring) | pinned `clang-18` 18.1.3 | pinned `clang-18` 18.1.3 (cross, `--target` added by the `cc` crate) |
| Reproducible | yes (`CARGO_BUILD_TARGET=<triple>` + `CARGO_TARGET_<TRIPLE>_LINKER=rust-lld` with `scripts/ci-repro.sh`, which pins `CC_<triple>` like `build-static.sh`) | same |

Runtime differences from the glibc build to keep in mind: the musl resolver
reads `/etc/hosts` and `/etc/resolv.conf` but not `nsswitch.conf` (give
`robodr-kafka-publish` IP literals, and map `robodr-uplink`'s host name in
`/etc/hosts`); musl's allocator is slower than glibc's
under contention (agentd's hot path is single-threaded; not measured on a
robot).

**Verified on 2026-10-26** (Ubuntu 24.04 container, x86-64, Rust 1.98.1):

- Both targets built with `scripts/build-static.sh` (10 binaries each,
  every check passed). `file`: `ELF 64-bit LSB pie executable, x86-64,
  static-pie linked, stripped` and `ELF 64-bit LSB executable, ARM aarch64,
  statically linked, stripped`; `ldd`: `statically linked`; no `INTERP`, no
  `NEEDED`.
- `scripts/ci-repro.sh` with `CARGO_BUILD_TARGET=x86_64-unknown-linux-musl`:
  10 binaries bit-identical across the two paths, and identical to
  `build-static.sh`'s output from the same commit.
- Smoke runs, amd64 natively and arm64 under `qemu-aarch64-static` 8.2:
  `--version` of agentd / commission / ros2-watch; `robodr-blackbox keygen`;
  `robodr-agentd --check-config` on `agentd.unitree-edu.example.json` (paths
  pointed at the G1 example profile, policy and firewall); a 5 s agentd run
  capturing on `lo`, then `robodr-blackbox verify`: `INTACT, CLEAN`.
- `robodr-focal` `.deb` for both arches (`Depends: systemd (>= 245)`), built
  twice with the same `SOURCE_DATE_EPOCH`: identical. Installed with dpkg in
  the container; its units pass `systemd-analyze verify`; the credential
  start sequence and agentd / spool-export as user `robodr` were run
  without systemd (packaging/README.md, "Not verified").
- Not done: the musl test suite (`cargo test --target ...-musl`; no disk
  space in the sandbox), any run on a Jetson or under systemd 245.

**Re-verified on 2026-10-26 with `robodr-uplink`** (rustls + ring, the first
C in the pure set; Ubuntu 24.04 container, Rust 1.98.1, clang 18.1.3):
`scripts/build-static.sh x86_64-unknown-linux-musl`: 11 binaries, all
static-pie, no `INTERP`, no `NEEDED`; `scripts/ci-repro.sh` with
`CARGO_BUILD_TARGET=x86_64-unknown-linux-musl`: 11 binaries bit-identical
across the two paths (ring's C objects included); the aarch64 musl build of
`robodr-uplink` links (clang cross-compiling ring), not run (no qemu in the
container). The static `robodr-uplink --once` delivered a spool to an
OpenSSL-based (Python `ssl`) HTTPS server through the test CA, a host name
and an SPKI pin. `cargo +1.87.0 check -p robodr-export --all-targets`
passes (MSRV).

## Licensing

- RoboDR crates: `license = "LicenseRef-Proprietary"` (`[workspace.package]`;
  `LICENSE` is the SingularityRD proprietary license). Every crate is
  `publish = false`, so cargo-deny ignores our own crates
  (`[licenses.private]`) and checks only third-party ones.
- eBPF probe C sources (`*.bpf.c`, all from Pulsar): GPL-2.0-only, declared per
  file with an `SPDX-License-Identifier` header. They are separate kernel
  programs, not Rust crates; the corresponding source is offered with every
  release (`LICENSE`, `LICENSES/`).
- Pulsar uses the free-text string "Apache-2.0 WITH BPF probes exception under
  GPL-2.0", which is not SPDX; `deny.toml` clarifies Pulsar's Rust crates as
  Apache-2.0 so cargo-deny can evaluate them, and the fallback SBOM records the
  raw string as a named license.
- `deny.toml` allows only permissive licenses for third-party userspace
  crates; any GPL/LGPL/AGPL (and MPL-2.0 without a reviewed exception) fails
  CI, which keeps proprietary distribution of the linked binaries possible.

## CI jobs

| Job | Required | What |
|---|---|---|
| `lockfile` | yes | Committed `Cargo.lock` has no local/patched/git/unknown sources; if none is committed, generate + upload the bootstrap lock and **fail** (every other job also fails without it) |
| `scripts` | yes | Python self-tests of the CI scripts, Pulsar rule validation, `scripts/check-focal-units.py` (systemd 245 unit variants in step), `shellcheck` of `scripts/*.sh`, `packaging/*.sh`, the maintainer scripts and the focal credential helper |
| `pure` | yes | `fmt --check`, `clippy -D warnings`, `test` for every member except Pulsar-bound ones |
| `pulsar` | yes | Installs Pulsar's build packages, then `build` / `clippy -D warnings` / `test` of every Pulsar-bound member (`robodr-sensor-ros2`, `robodr-pulsard`). No kernel load |
| `msrv` | informational | `cargo +1.87.0 check` of the pure crates |
| `deny` | yes | `cargo deny check advisories bans licenses sources` (`deny.toml`) |
| `sbom` | yes | CycloneDX via cargo-cyclonedx **and** the std-only fallback; uploaded as artifact |
| `fuzz` | yes | If `fuzz/` exists: every `cargo fuzz` target for 60 s on a pinned nightly; crashes uploaded |
| `reproducible` | yes | `scripts/ci-repro.sh`; hashes uploaded |
| `static` | yes | Per musl target: `ci-repro.sh` for the target, `scripts/build-static.sh`, built == reproduced, smoke run (arm64 under qemu-user), `robodr-focal` `.deb` (`Depends: systemd (>= 245)`, helper present, no `robodr-pulsard`); hashes uploaded. `release.yml`'s `build-static` job does the same and publishes `robodr-focal` debs and bundles with `SHA256SUMS-focal-<arch>` |

All third-party actions are pinned by full commit SHA (resolved with
`git ls-remote --tags` from the upstream repositories), with the tag in a
comment. Workflow token permissions are `contents: read`.

## Local CI verification

GitHub Actions has not run for this repository yet (the organisation's
Actions are blocked by billing). On **2026-10-17** every job of `ci.yml`, and
the build/package part of `release.yml`, was run locally, step by step with
the workflow's own commands and environment (`CARGO_INCREMENTAL=0`,
`scripts/ci-setup.sh` exports applied as `$GITHUB_ENV` would), on the commit
that introduced this section.

Host: Debian 13.5 (trixie) under WSL2 (kernel 6.18.33.2-microsoft-standard-WSL2),
x86_64, 8 vCPU, crates.io reachable (no mirror). Toolchains: Rust 1.98.1
(`rust-toolchain.toml`), 1.87.0 (MSRV), `nightly-2026-09-01`
(1.100.0-nightly 0dfb098f3). Tools: cargo-deny 0.20.2, cargo-cyclonedx 0.5.9,
cargo-fuzz 0.13.1 (each `cargo install --locked --version` as in `ci.yml`),
shellcheck 0.10.0, Python 3.13.5, clang/lld/llvm 19.1.7.

| Job | Result | Notes |
|---|---|---|
| `lockfile` | pass | Cargo.lock committed; `ci-check-lockfile.py`: OK (363 packages) |
| `scripts` | pass after fix | Self-tests 18 + 13 + 5 OK; `validate_rules.py --strict`: 62 rules, 429 fixtures, 0 errors/warnings; shellcheck failed on 4 info-level findings (SC2015 in `install-bundle.sh`, SC2094 in `make-bundle.sh`), fixed |
| `pure` | pass | `fmt --check`, `clippy -D warnings`, `test` (1883 passed, 0 failed, 1 ignored); no tracked file modified |
| `pulsar` | pass | `robodr-pulsard`, `robodr-sensor-ros2`: build, clippy `-D warnings`, test. Only a deprecation warning inside vendored `bpf-common` (tokio `AsyncFd::with_interest`), not a workspace lint |
| `msrv` | pass | `cargo +1.87.0 check` of the pure crates is clean |
| `deny` | pass after fix | Initially advisories, bans and licenses failed (see below); `Cargo.lock` unchanged |
| `sbom` | pass | 18 cargo-cyclonedx SBOMs + the fallback `robodr.cdx.json` (304 components), all pass `--check` against Cargo.lock; Cargo.lock unchanged |
| `fuzz` | pass | All 11 targets, 60 s each, no crash (0.3 M to 9.3 M executions per target) |
| `reproducible` | pass | 9 pure `robodr-*` binaries bit-identical across the two paths |
| release `build` (amd64, no upload) | pass | repro proof; release build; released pure binaries == reproduced hashes; Cargo.lock unchanged; SBOM; `.deb` with every `ROBODR_DEB_REQUIRE` binary; offline bundle (`install-bundle.sh verify` OK on the extracted bundle, rejects an unlisted file); SBOM tarball; `SHA256SUMS-amd64` |

Fixes made by that run:

- `packaging/install-bundle.sh`, `packaging/make-bundle.sh`: shellcheck
  SC2015 (`A && B || die` rewritten as `if`) and SC2094 (SHA256SUMS is
  now written outside the tree being hashed, then moved in).
- `cargo deny`, licenses: the Pulsar crates of the daemon library
  (`pulsar`, `engine-api`, `bpf-builder`, `bpf-filtering`, the three
  monitors, `rules-engine`, `threat-logger`) were unlicensed (non-SPDX
  string) and got the same `[[licenses.clarify]]` as the others;
  `tiny-keccak` (CC0-1.0, compile-time only, via a proc-macro) got a
  per-crate exception.
- `cargo deny`, bans: `allow-wildcard-paths` only applies to
  `publish = false` crates, so every RoboDR crate now declares
  `publish = false`; Pulsar's path crates (not editable) are listed under
  `[bans] skip` with the reason in `deny.toml`.
- `cargo deny`, advisories: RUSTSEC-2021-0139 (`ansi_term` unmaintained, no
  fix; only via Pulsar `bpf-common` -> `nut`) ignored with a reason and a
  review date (2027-04-17) in `deny.toml`.

Differences from the ubuntu-24.04 runner, not reflected in the workflow:

- Debian 13 has no `clang-20`/`lld-20`/`llvm-20` in its default archive, so
  the run used the workflow's fallback path (distribution clang/lld/llvm 19).
  Whether the runner gets clang-20 from its apt sources is still unverified.
- arm64 was not built on 2026-10-17; it was cross-built on 2026-10-18 (next
  section), not on the `ubuntu-24.04-arm` runner. The `prepare` (tag/draft
  release) and `publish` (minisign, upload) jobs need GitHub and secrets and
  were not run; nor were the `upload-artifact` steps.
- The fuzz job writes newly found inputs into the tracked `fuzz/corpus/`
  directories; harmless on a runner, but clean them up after a local run.

### arm64 (cross-compiled, 2026-10-18)

First arm64 build of any kind. No arm64 machine was available, so the
`release.yml` build job was replayed **cross-compiled** on the x86_64 host
above, and the tests ran under **qemu-user**. Commit: the merge `afdc880`
(main `fc1066e` plus the two fixes below); `SOURCE_DATE_EPOCH` = its commit
time.

Host additions: `rustup target add aarch64-unknown-linux-gnu` (1.98.1),
`gcc-aarch64-linux-gnu` / `g++-aarch64-linux-gnu` 14.2.0,
`libc6-dev-arm64-cross`, multiarch `libsqlite3-dev:arm64` 3.46.1 and
`libssl-dev:arm64` 3.5.7 (`dpkg --add-architecture arm64`), `qemu-user`
10.0.11 + `qemu-user-binfmt`; eBPF still with clang 19 (eBPF bytecode is
arch-independent; `bpf-builder` picks `include/aarch64/vmlinux.h` and
`-D__TARGET_ARCH_arm64` from `CARGO_CFG_TARGET_ARCH`, as in Pulsar's own
`Cross.toml` builds). Environment:

```bash
export CARGO_BUILD_TARGET=aarch64-unknown-linux-gnu
export CARGO_TARGET_AARCH64_UNKNOWN_LINUX_GNU_LINKER=aarch64-linux-gnu-gcc
export CARGO_TARGET_AARCH64_UNKNOWN_LINUX_GNU_RUNNER="qemu-aarch64 -L /usr/aarch64-linux-gnu"
export CC_aarch64_unknown_linux_gnu=aarch64-linux-gnu-gcc
export PKG_CONFIG_ALLOW_CROSS=1
export PKG_CONFIG_LIBDIR_aarch64_unknown_linux_gnu=/usr/lib/aarch64-linux-gnu/pkgconfig:/usr/share/pkgconfig
```

The release steps were then run with the workflow's own commands; the only
differences are `CARGO_BUILD_TARGET` and `--bin-dir
target/aarch64-unknown-linux-gnu/release` for `build-deb.sh`.

| Step | Result | Notes |
|---|---|---|
| `cargo build --workspace --all-targets --target aarch64-...` | pass | Every member, `robodr-pulsard` with its eBPF probes included; no source change was needed |
| `cargo test --workspace --no-fail-fast` under qemu | 1946 passed, 3 failed, 14 ignored | Same 1949 tests and 14 ignored as amd64. The 3 failures come from qemu, not arm64 (below) |
| repro (`scripts/ci-repro.sh`, `REPRO_REQUIRE_BINARIES=1`) | pass | 10 pure `robodr-*` binaries bit-identical across the two paths |
| release build (two invocations, remap flags) | pass | |
| released pure binaries == reproduced | pass | `sha256sum --strict -c` in `target/aarch64-unknown-linux-gnu/release` |
| Cargo.lock unchanged | pass | |
| SBOM (`SBOM_TOOL=cyclonedx`) | pass | 19 SBOMs, all pass `--check` |
| `.deb` (`ROBODR_DEB_REQUIRE` as in the workflow) | pass after fix | `Architecture: arm64`; every binary ELF AArch64; `Depends: libc6 (>= 2.39), ...` (was 2.35, wrong: see fixes) |
| offline bundle, SBOM tarball, `SHA256SUMS-arm64` | pass | `install-bundle.sh verify` on the extracted bundle: checksums OK |
| `file` on the 11 binaries | pass | `ELF 64-bit LSB pie executable, ARM aarch64`, interpreter `/lib/ld-linux-aarch64.so.1`, stripped |
| qemu smoke runs | pass | `robodr-pulsard --version`: `robodr-pulsard 0.1.0-alpha.1` / `pulsar: 0.11.0-alpha.1 (commit 4796504...)`; `robodr-agentd --version` and `robodr-commission --version` print `0.1.0-alpha.1` |
| second, independent run from a fresh clone at another path | pure binaries identical | Same 10 pure-binary hashes in all four builds (two repro copies and one release build per run). `robodr-pulsard` and the three packaged artefacts differ between the two checkouts (below) |

The three test failures, each checked:

- `robodr-capture` `afpacket::tests::open_or_skip_without_privileges`: the
  AF_PACKET socket opened and the filter attached (the WSL root user has
  `CAP_NET_RAW`), but qemu-user does not translate
  `getsockopt(SOL_PACKET, PACKET_STATISTICS)` and returns `EOPNOTSUPP`
  (seen with `QEMU_STRACE=1`). Every live AF_PACKET test in
  `tests/live_afpacket.rs` passed under qemu. Nothing was skipped.
- `robodr-blackbox` `tpm_anchor::tests::real_runner_kills_a_hanging_tool_and_reads_output`:
  asserts that running a missing tool fails. qemu-user runs glibc's
  `posix_spawn` (`clone(CLONE_VM|CLONE_VFORK)`) in a way that cannot report
  the child's exec error, so `Command::output()` of a missing program
  returns `Ok` with exit status 127. A 3-line program shows it (`spawn Ok,
  status 127` under qemu, `No such file or directory` natively).
- `robodr-threat-forward` `tests::offer_never_blocks_on_a_stalled_peer`:
  a 2 s bound on 20 000 offers; the debug build under qemu takes 2.1 to
  2.2 s (amd64 debug: 0.16 s). The arm64 release build under qemu passes
  (0.13 s).

Reproducibility beyond the pure binaries (the same holds for amd64; nothing
here is arm64-specific):

- `robodr-pulsard` is **not** reproducible across checkout paths: the eBPF
  objects that clang builds carry absolute source paths
  (`<checkout>/vendor/pulsar/crates/bpf-builder/include/*.bpf.h`, ~100
  strings), which `--remap-path-prefix` does not reach. A possible fix that
  does not touch Pulsar: point `CLANG` at a wrapper that adds
  `-ffile-prefix-map=$PWD=/build/robodr`. Not done.
- The cargo-cyclonedx SBOMs carry `path+file://<checkout>/crates/...`
  bom-refs. They are byte-identical when regenerated at the same path, not
  across paths.
- So the `.deb`, the bundle and the SBOM tarball are reproducible only from
  the same checkout path.

Run 1 (`/root/wt-arm64`), `SHA256SUMS-arm64`:

```text
4398340d8b334114441bf1c3b5cd46a06aedf45df2e4cf62161acb865f478093  robodr_0.1.0~alpha.1-1_arm64.deb
4b31ece83e42fc7ac01eb051c7a6a3036b66efedcb1cb9aa1affab7c00eada9f  robodr-0.1.0-alpha.1-arm64-offline.tar.gz
1c28dc181c8ccfb90b8d4dc111f39c4bc87338dcf1a3efb724b4ae9f98d16a2a  robodr-0.1.0-alpha.1-arm64-sbom.tar.gz
```

Pure binaries (`dist/repro/SHA256SUMS`, identical in both runs):

```text
a1da04575841d4b443715feb41cec67fdc3ec3498b8d26e820e8305607cac1af  robodr-agentd
63405ad05a6e94953266128124bb77e21f68e838dc90c5a3c079cb533cf99944  robodr-anchor-receiver
e755064661bc9e64e06948bb33efe45344d25a09707c67958a4f77835fb7586b  robodr-blackbox
e95fce5d8289430da5ae53c3081cd0f1396e4a3225ce2f99f57fad504a76ed3a  robodr-commission
96e54e1fbd8462abebda14cc01eb8055bb91b08d05bdb46431543b1f7352e436  robodr-diode-pack
6d5d6261260ad8989777e9d65f85d881e3067a56a1b43bd5f9b26adf3222894f  robodr-diode-unpack
1802add2b3e83b6f33812378a8e494e1394f64d6eff67aa4946c6f2cc6c70a6c  robodr-kafka-publish
cef67368e2c4664206adab1ca3d5e9db987386ac7697f75b8adf957f98c6e219  robodr-replay
f6f302bd517c7dfbb5fbdfd65723d65bd30501ef04f67f24f36584c602f4db03  robodr-ros2-watch
68b54c28e9142e01521eafed18dfd3867882db69b20c246b9fe4ee5eee60c04c  robodr-spool-export
```

These are cross-built with Debian 13's toolchain and glibc 2.41 headers. A
native `ubuntu-24.04-arm` build links a different C runtime (`crt*.o`,
`libgcc`), so its hashes are not expected to match these.

Fixes made by the arm64 run:

- `packaging/build-deb.sh`: the hard-coded `libc6 (>= 2.35)` was wrong.
  `robodr-agentd` and `robodr-blackbox` (both arches, built on any glibc 2.39
  host: Debian 13, ubuntu-24.04 and its arm runner) need `GLIBC_2.39`.
  Rust std references `pidfd_spawnp` / `pidfd_getpid` weakly, but the
  version need is not marked weak (`readelf -V`: `Flags: none`), so ld.so
  would refuse to start them on Ubuntu 22.04 (2.35) or Debian 12 (2.36),
  which dpkg would have accepted. The floor is now the newest `GLIBC_x.y`
  the packaged binaries need (at least 2.35), read with `readelf -V`.
  Supporting glibc < 2.39 robots needs a build on an older runner
  (ubuntu-22.04); that is a release decision, not made here.
- `packaging/build-deb.sh`: checks every binary's ELF `e_machine` against
  `--arch` (62 x86-64, 183 AArch64), so an amd64 `target/release` cannot be
  packaged as arm64 by mistake.
- `scripts/ci-repro.sh`: honours `CARGO_BUILD_TARGET` (binaries under
  `target/<triple>/release`). Unset, as on both workflow runners, nothing
  changes.

`release.yml` is unchanged: its arm64 leg builds natively on
`ubuntu-24.04-arm`, and the scripts above work for that leg as is.

Not checked on arm64:

- eBPF probes loading and running on an arm64 kernel. qemu-user has no BPF
  and the probes were only compiled. Pulsar's own CI loads them on arm64
  kernels; RoboDR's `robodr-pulsard` has never run on one.
- Any run on real arm64 hardware (a robot companion computer), including
  timing-sensitive code at native speed and AF_PACKET `PACKET_STATISTICS`.
- The native `ubuntu-24.04-arm` runner: clang-20 from its apt sources, the
  native build and its hashes.
- That ld.so really refuses the binaries on glibc < 2.39. This follows from
  the `readelf -V` output above and was not run on an old system.

## Verification status

Be precise about what has and has not been exercised. Last updated with the CI
rewrite (feat/ci); MSRV entry updated 2026-10-16 (w3-docs).

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

- No GitHub Actions run has happened yet. Since 2026-10-17 every job has
  passed locally ([Local CI verification](#local-ci-verification)): the
  Pulsar-bound build, cargo-cyclonedx 0.5.9, the cargo-deny 0.20.2 config,
  the full graph's licenses, `nightly-2026-09-01` + cargo-fuzz 0.13.1,
  shellcheck, and a real 1.87 build of the pure crates. Still unverified:
  that `clang-20` / `llvm-20` install from the ubuntu-24.04 runner's apt
  sources (the local run used the fallback, clang 19), and the arm64 runner
  (arm64 was only cross-built and tested under qemu-user, see
  [arm64](#arm64-cross-compiled-2026-10-18)).
- `Cargo.lock` is committed (2026-10-17); the bootstrap path of the
  `lockfile` job is therefore no longer exercised.
- MSRV: passed `cargo +1.87.0 check` locally on 2026-10-17; the job is still
  `continue-on-error` until it has passed on the runners. Earlier note
  (2026-10-16): all crates now inherit `rust-version.workspace = true`.
  In the sandbox (Rust 1.97 only) `clippy -D warnings` of the pure crates is
  clean at `rust-version = "1.87"`, and fails at `"1.86"` on
  `is_multiple_of` (first hit `robodr-capture/src/ports.rs`) — so 1.87 is the
  floor *for std APIs*. Language features are not covered by that lint, and no
  1.87 compiler was available, so an actual 1.87 build is unverified until the
  `msrv` CI job runs. Once it has passed, flip its `continue-on-error` off in
  `ci.yml` (its comment says to do so when every crate opts in, which is now
  the case). The Pulsar-bound crates were not checked at all.
- The air-gapped procedures (mirror, vendored tarball, offline toolchain,
  advisory-DB snapshot) are documented, not yet rehearsed in the lab.
- Release signing (minisign in `release.yml`'s `publish` job) is written but
  has never run: no signing key is provisioned and no release was cut.
  Reproducibility of the Pulsar-bound binary (eBPF objects from clang) is not
  checked.
