# Releasing RoboDR

Maintainer procedure for cutting a release with
`.github/workflows/release.yml`, the signing-key ceremony, and what the
local dry run (`scripts/release-dry-run.sh`) proves and does not prove.
For the operator side (verifying a release on the entry station, the
offline bundle) see `docs/OPERATIONS.md` sections 2 and 3; for the build
pins and reproducibility see `docs/BUILD.md`.

## 1. What a release is

Pushing a tag `v<VERSION>` runs `release.yml`:

| Job | Runner | Does |
|---|---|---|
| `prepare` | ubuntu-24.04 | tag == `v` + `VERSION`; `Cargo.toml` workspace (and every member) version == `VERSION`; `CHANGELOG.md` has `## [<VERSION>]`; `Cargo.lock` committed. Creates a **draft** GitHub release (prerelease when the version has a `-`), notes = that CHANGELOG section |
| `build` (amd64, arm64) | ubuntu-24.04, ubuntu-24.04-arm (native), in an **Ubuntu 22.04 container** (digest-pinned) | pinned clang-14 for ring, clang-20 (apt.llvm.org, key fingerprint pinned) for Pulsar's eBPF, `scripts/ci-repro.sh` (two builds, two paths, must be bit-identical), release build (`scripts/ci-release-build.sh`: pure workspace, then the Pulsar-bound members incl. `robodr-pulsard`), released == reproduced, `Cargo.lock` unchanged, CycloneDX SBOM, `robodr_<debver>_<arch>.deb` (`Depends:` from `dpkg-shlibdeps`, libc6 floor <= 2.35 checked), offline bundle, SBOM tarball, `SHA256SUMS-<arch>` |
| `build-rpm` (amd64, arm64) | the same runners, in a **Rocky Linux 9 container** (digest-pinned) | pinned AppStream clang for ring and eBPF, `ci-repro.sh`, release build, released == reproduced, `robodr-<rpmver>-1.<x86_64\|aarch64>.rpm` (`packaging/build-rpm.sh`; generated GLIBC requirement <= 2.34 checked), `SHA256SUMS-rpm-<arch>` |
| `build-static` (amd64, arm64) | ubuntu-24.04 (both cross-linked with rust-lld) | musl repro + `scripts/build-static.sh`, built == reproduced, smoke run (qemu for arm64), SBOM, `robodr-focal_<debver>_<arch>.deb` + bundle, `SHA256SUMS-focal-<arch>` |
| `smoke` (amd64, arm64) | ubuntu-24.04, ubuntu-24.04-arm | `scripts/check-packages.py` on the three packages of the architecture, then `scripts/pkg-smoke-matrix.sh`: each package installed with apt / dnf in Debian 12, Ubuntu 20.04 / 22.04 / 24.04, Rocky Linux 9 and Fedora 42 containers |
| `publish` | ubuntu-24.04, environment `release` | downloads the build jobs' workflow artifacts, re-checks every `SHA256SUMS-*`, writes `SHA256SUMS`, signs every asset with minisign, self-verifies with the public key variable, uploads assets, sums and signatures to the draft, publishes it |

The build jobs have `contents: read` only and hand their assets over as
workflow artifacts; only `prepare` (creates the draft) and `publish`
(behind the `release` environment) can write the release. Nothing is
signed before `smoke` passed.

21 assets + 21 `.minisig` per release (amd64 and arm64 each: `.deb`,
offline bundle, SBOM tarball, `.rpm`, RPM offline bundle
(`robodr-<ver>-<arch>-rpm-offline.tar.gz`, the same `install-bundle.sh`
driving `rpm -U`), focal `.deb`, focal bundle, three per-arch hash files;
plus `SHA256SUMS`). The RPM has no SBOM tarball of its own (same
`Cargo.lock` and crates as the `.deb`'s). Every package and bundle carries
`THIRD_PARTY_NOTICES` and `GPL-2.0-SOURCE-OFFER`
(`scripts/third_party_notices.py`, committed; CI job `deny` fails when they
no longer match `Cargo.lock` or the Pulsar commit).

## 2. Signing keys: ceremony and where secrets live

minisign has no certificate chains, so the hierarchy is procedural:

- **Offline root key** (`robodr-root`). Generated on an air-gapped,
  freshly installed machine that never connects to a network, by two
  maintainers together. Password-protected (`minisign -G`, no `-W`); the
  secret key file and its password are stored separately (e.g. key on two
  encrypted USB media in two safes, password split between the two
  custodians). It signs only **release-key statements**, never a release.
  Its public key is the trust anchor customers pin on their entry stations
  (delivered out of band: signed letter, in-person handover, customer PKI;
  `OPERATIONS.md` section 2).
- **Release key** (`robodr-release-<year>`). Generated in the same
  ceremony, password-protected. The root signs a statement for it:

  ```sh
  minisign -G -p robodr-release-2026.pub -s robodr-release-2026.key
  minisign -S -s robodr-root.key -m robodr-release-2026.pub \
      -t "robodr release key 2026, valid 2026-11-01..2027-12-31, serial 1"
  ```

  `robodr-release-2026.pub` + `.minisig` are published (repository and
  release notes); an entry station verifies the statement with the pinned
  root key (`minisign -V -p robodr-root.pub -m robodr-release-2026.pub`)
  before it pins the release key for `install-bundle.sh --pubkey`.
  `install-bundle.sh` takes the release key only; the root check is the
  operator's step.
- **Where the release key lives.** In the GitHub environment `release`
  only (Settings > Environments > release):
  - secret `MINISIGN_SECRET_KEY`: the full contents of the encrypted
    secret-key file (both lines);
  - secret `MINISIGN_PASSWORD`: its password;
  - repository variable `ROBODR_MINISIGN_PUBKEY`: the `RW...` line of the
    public key (used to self-verify before publishing).
- **Package maintainer.** Repository variable `ROBODR_MAINTAINER`:
  `Name <address>` for the `.deb` `Maintainer:` and the RPM `Packager:`.
  The build jobs run with `ROBODR_RELEASE=1`, so an unset value or a
  placeholder (`robodr-maintainers@invalid`, the development default, or
  any `.invalid` / `example.*` / `localhost` address) fails the release
  build (`packaging/release-maintainer.sh`); development builds keep the
  placeholder.
  No other job references the environment, so no build step can read the
  key. The offline copy of the release key stays with the root material.
- **Environment protection** (`release`): required reviewers = at least two
  maintainers, "prevent self-review" on; deployment restricted to tags
  matching `v*`; no admin bypass. Protect `v*` tags with a ruleset (only
  maintainers create them, no deletion or update). The publish job waits
  for approval, so a reviewer checks the draft (asset list, per-arch hashes,
  the reproducibility lines in the build logs) before anything is signed.
- **Rotation / compromise.** Yearly, or immediately on suspicion: new
  release key in a ceremony, root-signed statement, replace the two secrets
  and the variable, announce. On compromise also publish a root-signed
  revocation statement naming the old key id and the last good release,
  and raise `packaging/security-floor` if a signed malicious release is
  possible. A lost root means re-pinning at every customer: keep two
  copies.

Do not commit any key material. `scripts/release-dry-run.sh` uses a
throwaway key (section 4) and refuses a work directory inside the
repository.

## 3. Procedure (maintainer)

1. Main is green in CI (`ci.yml`, including `pulsar`, `static`,
   `reproducible`).
2. Release commit on main (via a reviewed PR):
   - `VERSION` = the new version (`0.1.0-alpha.2`, `0.1.0-rc.1`, `0.1.0`);
   - `Cargo.toml` `[workspace.package] version` = the same, then
     `cargo update --workspace --offline` (only the workspace members'
     lines in `Cargo.lock` change; review that diff);
   - `CHANGELOG.md`: insert `## [<version>] - <date>` under
     `## [Unreleased]`, so the unreleased entries become the release's;
   - if the release fixes a vulnerability that must never come back,
     raise `min_version` in `packaging/security-floor`;
   - `packaging/formats` must match what the release writes/reads (tests
     enforce it).
3. Optional but recommended: `scripts/release-dry-run.sh --tag v<version>`
   on that commit (it then skips its own release commit).
4. Tag and push: `git tag -s v<version> -m "RoboDR <version>"` then
   `git push origin v<version>`.
5. Watch `prepare`, `build` x2, `build-rpm` x2, `build-static` x2,
   `smoke` x2. Check in the logs: `repro: N binary(ies) reproducible` for
   each target, the `sha256sum -c` of released vs reproduced, the
   `check-glibc-floor` lines (`.deb` `Depends:`, RPM `GLIBC_` requirement),
   and the `pkg-smoke-matrix` summary (every row `ok`).
6. Approve the `release` environment for `publish` (second maintainer).
7. After publish: download the release on a clean machine, verify with the
   pinned release key as in `OPERATIONS.md` section 2, and run
   `scripts/deb-install-smoke.sh` on the four `.deb`s (systemd >= 250 for
   its `verify --root`).
8. If a job fails after the draft exists: fix on main, delete the draft
   release and the tag, re-tag the fixed commit. Never re-tag a version
   that was **published**: bump instead.

### Checklist

- [ ] CI green on the release commit
- [ ] `VERSION`, `Cargo.toml`, `Cargo.lock`, `CHANGELOG.md` agree
- [ ] security floor / formats reviewed
- [ ] dry run passed on the release commit (optional)
- [ ] signed tag pushed
- [ ] reproducibility lines present in all six build jobs
- [ ] `smoke` green on both architectures
- [ ] 19 assets + `.minisig` each in the published release, per-arch `SHA256SUMS-*`
- [ ] `release` environment approved by a second maintainer
- [ ] published release verified offline with the pinned key
- [ ] `deb-install-smoke.sh` on the published `.deb`s
- [ ] release-key statement and root public key unchanged (or rotation announced)

### RPM signatures

The `.rpm` is signed like every other asset: a minisign signature and its
line in `SHA256SUMS`, verified on the entry station before
`dnf install ./robodr-*.rpm` (dnf does not check signatures of a local
file by default on RHEL 9). An OpenPGP signature inside the RPM
(`rpmsign --addsign`), needed for a dnf repository with `gpgcheck=1`, is
**not** produced: it needs an OpenPGP release key, its own ceremony
(section 2) and a secret in the `release` environment. Hook for it: after
`build-rpm` and before `publish` hashes the assets (an `rpmsign` step in
`publish`, before "Check per-arch hashes", re-hashing the RPMs into
`SHA256SUMS-rpm-<arch>`).

## 4. Dry run

**Not updated for the 2026-10-30 release workflow.**
`scripts/gha-local-run.py` refuses `container:` jobs and
`actions/download-artifact`, which `build`, `build-rpm`, `smoke` and
`publish` now use; the dry run below describes the previous workflow.
Extending it (run container jobs with `docker run`, emulate the artifact
hand-over with a local directory) is open work.

`scripts/release-dry-run.sh [--tag v0.1.0-rc.0-dryrun] [--out DIR]`
replays `release.yml` on one Ubuntu 24.04 amd64 host without GitHub:

- `scripts/gha-local-run.py` runs each job's `run:` scripts **as written**
  in the workflow (same shell flags, `env:`, `$GITHUB_ENV`,
  `$GITHUB_OUTPUT`, `${{ }}` context references); `gh release` is
  `scripts/gh-release-shim.sh` (a local draft-release directory).
- The tree is a snapshot of HEAD (+ submodules); a release commit for the
  simulated tag is made in a private repository under the work directory.
  **No git tag is created.**
- Guard tests: `prepare` must refuse a wrong tag and a commit whose
  `Cargo.toml` version is not `VERSION`.
- Signing uses a **throwaway, test-only** minisign key generated in the
  work directory (password-protected, so the workflow's password branch
  runs) and shredded at the end; only its public key is kept next to the
  report (`TEST-ONLY-dry-run-minisign.pub`).
- After `publish`: asset set complete, every signature verifies with the
  public key file, `SHA256SUMS` covers every asset, `install-bundle.sh
  verify --pubkey --tarball` passes for each bundle and refuses a tampered
  one or a foreign key, and `scripts/deb-install-smoke.sh` on every `.deb`
  (throwaway dpkg root, `--version`/`--help` of every binary,
  `systemd-analyze verify` of every unit).

Host prerequisites are listed in the script header (cross toolchain
`gcc-aarch64-linux-gnu`, `libc6-dev-arm64-cross`, multiarch
`libssl-dev:arm64`/`libsqlite3-dev:arm64`, `qemu-user-static`, the musl
targets, `minisign`, PyYAML). The workflow's `apt-get install` steps run
for real (`clang-20`, `lld-20`, `llvm-20`, `minisign`, ...); its
`ln -sf ... /usr/local/bin/` lines are redirected into the dry run's own
`bin/` so the host's `clang` is not changed.

### What the dry run proves

- Every `run:` script of `release.yml` executes successfully, in order,
  with the real scripts (`ci-setup.sh`, `ci-repro.sh`, `build-static.sh`,
  `sbom.sh`, `build-deb.sh`, `make-bundle.sh`) on the release commit.
- The tag/version/CHANGELOG/Cargo guards work (positively and negatively).
- Reproducibility of the pure binaries for all four targets (two paths
  each), and released == reproduced.
- `robodr-pulsard` builds with `--locked` in the release configuration
  (clang-20 for eBPF, as on the runner), amd64 natively and arm64
  cross-compiled, and ships in both regular `.deb`s.
- The minisign signing step, with a password-protected key passed exactly
  as the secrets are, and the self-verification with the `RW...` string.
- The published set is what `OPERATIONS.md` tells operators to verify, and
  the entry-station procedure (`install-bundle.sh verify`) works on it.
- The packages unpack, every binary starts (`--version`, `--help`), the
  sysusers/tmpfiles files apply, and every unit passes
  `systemd-analyze verify` (systemd 255).

### What only a real CI run can prove

- **Runner differences.** The real `build` arm64 job runs natively on
  `ubuntu-24.04-arm`: native rustc/cc/ld, native `robodr-pulsard` with
  native libssl/libsqlite3 and native SBOM generation. The dry run
  cross-compiles arm64 (`aarch64-linux-gnu-gcc` 13.3 as linker, clang-18
  for ring, multiarch libraries, the arm64 SBOMs generated on the amd64
  host); its arm64 pure-binary hashes are only
  expected to match the runner's if the cross and native toolchains emit
  identical code, which is not established. The availability of
  `ubuntu-24.04-arm` for this (private) repository and its apt mirror's
  clang-20 are unverified.
- Exact runner images (preinstalled packages, `rustup`, `gh`, python
  versions), the `actions/checkout` submodule fetch, `actions/upload-artifact`.
- `gh release create/upload/download/edit` against the real API
  (permissions of `GITHUB_TOKEN`, `--verify-tag` on a pushed tag, asset
  name clashes, draft download), and the `release` environment's
  reviewers and secret scoping.
- That the real secrets are formatted as expected (the full key file in
  `MINISIGN_SECRET_KEY`, the matching `ROBODR_MINISIGN_PUBKEY`).
- Reproducibility of `robodr-pulsard` (not claimed anywhere; its eBPF
  objects carry absolute paths, `docs/BUILD.md`), and of the `.deb`,
  bundles and SBOMs across checkout paths (they embed the checkout path
  via the SBOMs' bom-refs).
- Running the daemons on a real robot kernel (BTF, eBPF load) or on
  systemd 245 (focal units are only checked statically and with systemd
  255's verifier).

## 5. Dry-run record

2026-10-26, source `04663a0`, tag `v0.1.0-rc.0-dryrun` (simulated): every
job and acceptance check passed; it found and fixed three defects
(`prepare` did not compare the `Cargo.toml` version with `VERSION`;
`ROBODR_DEB_REQUIRE` lacked three daemons; `ci-repro.sh` leaked its scratch
directory). The package smoke test reports eight binaries without a working
`--version` (and two whose `--help` exits 2): crate code, not yet fixed.
Details, adaptations and the artefact hashes: `docs/BUILD.md`, "Release
dry run (2026-10-26)".

Usage notes: allow about 75 minutes on 4 cores and 6 GB of free disk; the
report, logs and the test-only public key land in `--out`
(default `dist/release-dry-run/`, git-ignored), the published set in
`--out`/assets (about 50 MB; delete it after inspection).
