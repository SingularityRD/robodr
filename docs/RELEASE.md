# Releasing RoboDR

Maintainer procedure for cutting a release with
`.github/workflows/release.yml`, the signing-key ceremony, long-term-support
lines, the secure-delivery RPK ceremony, the package repositories, the
vulnerability monitoring of published releases, and what the dry runs (the
workflow's own `workflow_dispatch` run and the local
`scripts/release-dry-run.sh`) prove and do not prove. For the operator side
(verifying a release on the entry station, the offline bundle) see
`docs/OPERATIONS.md` sections 2 and 3; for the build pins and
reproducibility see `docs/BUILD.md`.

## 1. What a release is

Pushing a tag `v<VERSION>` on `main` or on a `release/X.Y` branch runs
`release.yml`. Running it by hand (`workflow_dispatch`, any branch) is the
**dry run** (section 4): the same jobs, then `publish-dry-run` instead of
`publish`.

| Job | Runner | Does |
|---|---|---|
| `prepare` | ubuntu-24.04 | tag == `v` + `VERSION`; `Cargo.toml` workspace (and every member) version == `VERSION`; `CHANGELOG.md` has `## [<VERSION>]`; `Cargo.lock` committed. **Release line** (`scripts/release-gate.py line`): the commit is on `main` (the release will be "Latest", unless the version is a pre-release: GitHub never makes a pre-release "Latest", so it is published with `--latest=false`) or on `release/X.Y` for version `X.Y.*` (an LTS line, never "Latest", section 6); anything else is refused. **CI gate** (`release-gate.py ci`): `ci.yml` has a completed, successful `push` / `workflow_dispatch` / `schedule` run for exactly this commit (a running one is waited for, up to 2 h; a `pull_request` run tested a merge commit and does not count). Creates a **draft** GitHub release (prerelease when the version has a `-`), notes = that CHANGELOG section |
| `build` (amd64, arm64) | ubuntu-24.04, ubuntu-24.04-arm (native), in an **Ubuntu 22.04 container** (digest-pinned) | pinned clang-14 for ring, clang-20 (apt.llvm.org, key fingerprint pinned) for Pulsar's eBPF; toolchain inputs recorded (section 11); `scripts/ci-repro.sh` (two builds, two paths, must be bit-identical), release build (`scripts/ci-release-build.sh`), released == reproduced, `--version` names this commit, `SOURCE_DATE_EPOCH` and target, `Cargo.lock` unchanged, CycloneDX 1.5 SBOMs completed by `scripts/release-sbom-augment.sh` (Rust std/core/alloc, robodr-pulsard's eBPF objects with hashes, toolchain formulation; section 9), `robodr_<debver>_<arch>.deb` (`Depends:` from `dpkg-shlibdeps`, libc6 floor <= 2.35 checked), offline bundle, SBOM archive, `SHA256SUMS-<arch>` |
| `build-rpm` (amd64, arm64) | the same runners, in a **Rocky Linux 9 container** (digest-pinned) | as `build` with the AppStream clang: `robodr-<rpmver>-1.<x86_64\|aarch64>.rpm` (generated GLIBC requirement <= 2.34 checked), RPM offline bundle, its own SBOM archive `robodr-<ver>-rpm-<arch>-sbom.tar.gz`, `SHA256SUMS-rpm-<arch>` |
| `build-static` (amd64, arm64) | ubuntu-24.04 (both cross-linked with rust-lld; arm64 through `scripts/static-pie-ld`, whose test runs first) | musl repro + `scripts/build-static.sh` (every binary static-pie: ET_DYN, no interpreter, no `NEEDED`, no text relocations), built == reproduced, smoke run naming the build (qemu for arm64), SBOMs (+ musl and libunwind with archive hashes), `robodr-focal_<debver>_<arch>.deb` (its programs re-checked), bundle, SBOM archive, `SHA256SUMS-focal-<arch>` |
| `smoke` (amd64, arm64) | ubuntu-24.04, ubuntu-24.04-arm | `scripts/check-packages.py` on the three packages of the architecture, then `scripts/pkg-smoke-matrix.sh`: each package installed with apt / dnf in Debian 12, Ubuntu 20.04 / 22.04 / 24.04, Rocky Linux 9 and Fedora 42 containers |
| `rebuild-deb`, `rebuild-rpm` (amd64, arm64) | ubuntu-22.04, ubuntu-22.04-arm, in the same digest-pinned containers | independent rebuild: Rust from hash-pinned artifacts (`scripts/ci-install-pinned-toolchain.sh`, no rustup), fresh `CARGO_HOME`, every program incl. `robodr-pulsard`, package and bundle (`scripts/ci-rebuild.sh`); its toolchain inputs recorded |
| `rebuild-static` (amd64, arm64) | a fresh ubuntu-24.04 VM | the same for `robodr-focal` (same static-pie linker) |
| `delivery` | ubuntu-24.04 | this commit's `robodr-release` builds **unsigned** secure-delivery RPKs of the `robodr` and `robodr-focal` `.deb` (both arches) and of `rules/robodr` (`scripts/release-rpk.py`, each built twice, digests must agree) plus `DELIVERY-MANIFEST.json`: the asset `robodr-<ver>-rpk.tar.gz` for the offline 2-of-N ceremony (section 7) |
| `publish` (tag push only) | ubuntu-24.04, environment `release` | release line and CI gate again; `scripts/release-finalize.sh`: rebuild comparison (`scripts/compare-rebuild.py`: packages and programs identical, bundles except their SBOM; `robodr-pulsard` recorded) into the signed `REPRODUCIBILITY-<version>.txt` with every job's toolchain inputs appended, **SBOM gate** (all six SBOM archives; the `robodr` and `.rpm` ones must contain a `robodr-pulsard` SBOM, the `robodr-focal` ones must not; every file complete per `metadata_to_cyclonedx.py --check --require-complete`, which requires the eBPF objects in a `robodr-pulsard` SBOM, and valid per the official `cyclonedx validate` 1.5, pinned by SHA-256), `robodr-<ver>.openvex.json` (section 10), `robodr-<ver>.intoto.jsonl` (SLSA v1 provenance of every asset, section 9), per-arch sums re-checked, `SHA256SUMS`; `scripts/release-sign.sh` (minisign, self-verified with the public key variable); provenance verified against the signed set; `actions/attest-build-provenance` (pinned by SHA) attests every asset in `SHA256SUMS`; uploads; publishes with `--latest` from the release line |
| `publish-dry-run` (`workflow_dispatch` only) | ubuntu-24.04, no environment | the same `release-finalize.sh`, signed with a **throwaway** key generated in the job, verified; the set and `TEST-ONLY-dry-run-minisign.pub` uploaded as the workflow artifact `release-dry-run-<sha>`; nothing published, no secret, no attestation |

The build jobs have `contents: read` only and hand their assets over as
workflow artifacts; only `prepare` (creates the draft) and `publish`
(behind the `release` environment) can write the release. Nothing is
signed before `smoke`, the rebuilds and the SBOM gate passed.

29 assets + 29 `.minisig` per release. Per architecture (amd64, arm64):
`.deb`, offline bundle, SBOM archive, `SHA256SUMS-<arch>`; `.rpm`, RPM
offline bundle (`robodr-<ver>-<arch>-rpm-offline.tar.gz`, the same
`install-bundle.sh` driving `rpm -U`), RPM SBOM archive,
`SHA256SUMS-rpm-<arch>`; focal `.deb`, focal bundle, focal SBOM archive,
`SHA256SUMS-focal-<arch>`. Once: `robodr-<ver>-rpk.tar.gz`,
`REPRODUCIBILITY-<ver>.txt`, `robodr-<ver>.openvex.json`,
`robodr-<ver>.intoto.jsonl`, `SHA256SUMS`. Every package and bundle
carries `THIRD_PARTY_NOTICES` and `GPL-2.0-SOURCE-OFFER`
(`scripts/third_party_notices.py`, committed; CI job `deny` fails when they
no longer match `Cargo.lock` or the Pulsar commit).

Every binary's `--version` names its build (`crates/robodr-buildinfo`):
`robodr-agentd 0.1.0 (commit <sha>, source-date-epoch <s>, target
<triple>)`, taken from `ROBODR_BUILD_COMMIT`, else `GITHUB_SHA`, and
`SOURCE_DATE_EPOCH`; never from `git` at build time, so the
reproducibility copies (no `.git`) still equal the release. A support case
quotes that line; with `SHA256SUMS` and the reproducibility record it names
the exact source and build inputs. (`robodr-firewall-gw` follows after the
gateway merge.)

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

Do not commit any key material. The dry runs use throwaway keys
(section 4); `scripts/release-dry-run.sh` refuses a work directory inside
the repository.


## 3. Procedure (maintainer)

1. CI must be green on the commit: `prepare` refuses to start otherwise
   (`release-gate.py ci`; it waits up to 2 h for a running CI). Required
   repository settings: branch protection of `main` and `release/*` with
   `ci.yml`'s jobs as required status checks and required reviews; a tag
   ruleset for `v*` (only maintainers create, no update or deletion).
   `ci.yml` runs on pushes to `main`; for an LTS line it must also run on
   pushes to `release/**` (one trigger line in `ci.yml`).
2. Release commit on main (or on `release/X.Y`, section 6) via a reviewed PR:
   - `VERSION` = the new version (`0.1.0-alpha.2`, `0.1.0-rc.1`, `0.1.0`);
   - `Cargo.toml` `[workspace.package] version` = the same, then
     `cargo update --workspace --offline` (only the workspace members'
     lines in `Cargo.lock` change; review that diff);
   - `CHANGELOG.md`: insert `## [<version>] - <date>` under
     `## [Unreleased]`, so the unreleased entries become the release's;
   - if the release fixes a vulnerability that must never come back,
     raise `min_version` in `packaging/security-floor`;
   - `packaging/formats` must match what the release writes/reads (tests
     enforce it);
   - `security/vex/statements.json` has a statement for every advisory the
     release's `Cargo.lock` is known to carry (section 10).
3. Recommended: run `release.yml` with **workflow_dispatch** on that branch
   (section 4) and download `release-dry-run-<sha>`.
4. Tag and push: `git tag -s v<version> -m "RoboDR <version>"` then
   `git push origin v<version>`.
5. Watch `prepare`, `build` x2, `build-rpm` x2, `build-static` x2,
   `smoke` x2, `rebuild-*` x6, `delivery`. Check in the logs: `repro: N
   binary(ies) reproducible` for each target, the `sha256sum -c` of released
   vs reproduced, the `--version` lines, the `check-glibc-floor` lines, the
   `pkg-smoke-matrix` summary (every row `ok`), the toolchain-input records,
   and `DELIVERY-MANIFEST.json`.
6. Approve the `release` environment for `publish` (second maintainer).
   It refuses to sign when a rebuild differs, an SBOM is incomplete or
   invalid, or the provenance does not match; read
   `REPRODUCIBILITY-<version>.txt` in its log.
7. After publish: download the release on a clean machine, verify with the
   pinned release key as in `OPERATIONS.md` section 2, check the
   provenance (section 9), and run `scripts/deb-install-smoke.sh` on the
   four `.deb`s (systemd >= 250 for its `verify --root`). Then the delivery
   ceremony (section 7) and the package repositories (section 8).
8. If a job fails after the draft exists: fix, delete the draft release and
   the tag, re-tag the fixed commit. Never re-tag a version that was
   **published**: bump instead.

### Checklist

- [ ] CI green on the release commit (enforced by `prepare`)
- [ ] `VERSION`, `Cargo.toml`, `Cargo.lock`, `CHANGELOG.md` agree
- [ ] security floor / formats / VEX statements reviewed
- [ ] `docs/compliance/threat-model.md`, `third-party-due-diligence.md` (Pulsar) and the other compliance documents reviewed against the release commit, findings recorded in their review logs, and restamped ("Verified at commit")
- [ ] customer documents (`docs/customer/`, `SECURITY.md`, `docs/customer/data-handling.md`) refreshed for what changed since the last release
- [ ] `python3 scripts/check-doc-facts.py` passes on the release commit
- [ ] workflow_dispatch dry run passed on the release commit
- [ ] signed tag pushed (on `main`, or on `release/X.Y` for an LTS patch)
- [ ] reproducibility lines present in all six build jobs
- [ ] `smoke` green on both architectures
- [ ] 29 assets + `.minisig` each in the published release (section 1), per-arch `SHA256SUMS-*`
- [ ] `release` environment approved by a second maintainer
- [ ] published release verified offline with the pinned key; provenance verified
- [ ] `deb-install-smoke.sh` on the published `.deb`s
- [ ] RPKs signed by the release quorum, bundle built and signed (section 7)
- [ ] package repositories built (section 8)
- [ ] release-key statement and root public key unchanged (or rotation announced)

### RPM signatures

The `.rpm` release asset is signed like every other asset: a minisign
signature and its line in `SHA256SUMS`, verified on the entry station before
`dnf install ./robodr-*.rpm`. The OpenPGP signature inside the RPM
(`rpmsign --addsign`) that a dnf repository with `gpgcheck=1` needs is added
by the package-repository workflow (section 8) to the repository's copies;
the release assets stay unsigned inside, so their minisign signatures and
the reproducibility comparison stay valid.

## 4. Dry run

### On GitHub (the complete dry run)

Actions > Release > Run workflow, on any branch. Every job of the release
runs on the real runners and containers; `prepare` runs the tag-independent
checks (the release line and CI gate only warn: a feature branch can be
dry-run), creates no draft; `publish-dry-run` runs `release-finalize.sh`
(rebuild comparison, SBOM gate with `cyclonedx validate`, VEX, provenance),
signs with a throwaway key generated in the job and verifies. Download the
artifact `release-dry-run-<sha>` and check it like a release, with
`TEST-ONLY-dry-run-minisign.pub` as the key. No secret, environment, release
or attestation is touched.

### Locally

`scripts/release-dry-run.sh [--tag v0.1.0-rc.0-dryrun] [--out DIR]
[--jobs "..."]` replays `release.yml` without GitHub:

- `scripts/gha-local-run.py` runs each job's `run:` scripts **as written**
  (same shell flags, `env:`, `$GITHUB_ENV`, `$GITHUB_PATH`,
  `$GITHUB_OUTPUT`, `${{ }}` context references, `if:` comparisons),
  `container:` jobs inside their digest-pinned image (docker), with a local
  artifact store for `upload-artifact` / `download-artifact`; `gh` is
  `scripts/gh-release-shim.sh` (a local draft-release directory, and the
  CI gate's `gh api` call).
- The tree is a snapshot of HEAD (+ submodules); a release commit for the
  simulated tag is made in a private repository under the work directory.
  **No git tag is created.** Uncommitted changes are not part of it.
- Guard tests: `prepare` must refuse a wrong tag, a commit whose
  `Cargo.toml` version is not `VERSION`, a commit on neither `main` nor
  `release/X.Y`, and a commit whose CI run failed; each refusal must be
  for that reason (its log is checked).
- Signing uses a **throwaway, test-only** minisign key generated in the
  work directory and shredded at the end.
- After `publish`: asset set complete, every signature verifies with the
  public key file, `SHA256SUMS` covers every asset, the release is
  "Latest" (for a pre-release version, such as the default dry-run tag,
  `--latest=false` was requested instead), the SLSA provenance verifies against the assets,
  `install-bundle.sh verify --pubkey --tarball` passes for each bundle and
  refuses a tampered one or a foreign key, and
  `scripts/deb-install-smoke.sh` on every `.deb`.
- On a non-arm64 host the jobs GitHub runs on native arm64 runners (`build`,
  `build-rpm`, `smoke`, `rebuild-deb`, `rebuild-rpm` arm64), and therefore
  `delivery` and `publish`, are reported as skipped: the complete run is
  the workflow_dispatch one above, or the script on an aarch64 host.

### What the dry runs prove

- Every `run:` script of `release.yml` executes successfully, in order,
  with the real scripts, in the real job containers.
- The tag/version/CHANGELOG/Cargo guards, the release-line gate and the CI
  gate work (positively and negatively).
- Reproducibility of the pure binaries for all four targets (two paths
  each), released == reproduced, and the independent rebuilds (GitHub).
- The SBOM gate, the RPK build, VEX and provenance generation, and the
  minisign signing and self-verification as the secrets are passed.

### What only a real release can prove

- `gh release create/upload/edit` against the real API (permissions of
  `GITHUB_TOKEN`, `--verify-tag` on a pushed tag, `--latest`), the
  `release` environment's reviewers and secret scoping, and that the real
  secrets are formatted as expected.
- `actions/attest-build-provenance` (OIDC, the attestation store) and
  `gh attestation verify` of the published assets.
- Reproducibility of `robodr-pulsard` (not claimed; recorded) and running
  the daemons on a real robot kernel or on systemd 245.

## 5. Dry-run record

2026-10-31 (local, `scripts/release-dry-run.sh --jobs prepare` on the
workflow with the gates): `prepare` and the four guard tests (wrong tag,
Cargo version, release line, red CI) passed. The earlier record below
is of the previous workflow.

2026-10-26, source `04663a0`, tag `v0.1.0-rc.0-dryrun` (simulated): every
job and acceptance check passed; it found and fixed three defects
(`prepare` did not compare the `Cargo.toml` version with `VERSION`;
`ROBODR_DEB_REQUIRE` lacked three daemons; `ci-repro.sh` leaked its scratch
directory). The package smoke test reported eight binaries without a working
`--version` (and two whose `--help` exits 2); fixed in the crates after
the run, and the dry run now runs the smoke test with `--strict`.
Details, adaptations and the artefact hashes: `docs/BUILD.md`, "Release
dry run (2026-10-26)".

Usage notes: allow about 75 minutes on 4 cores and 6 GB of free disk; the
report, logs and the test-only public key land in `--out`
(default `dist/release-dry-run/`, git-ignored), the published set in
`--out`/assets (about 50 MB; delete it after inspection).

## 6. Long-term-support lines (`release/X.Y`)

A patch for an older line (e.g. `0.1.4` while `main` is at `0.2.x`) is
released from a protected branch `release/0.1`:

1. Create `release/0.1` from the last `v0.1.*` tag; protect it like `main`
   (required reviews, `ci.yml` jobs as required checks, no force push).
   `ci.yml` must run on pushes to `release/**`.
2. Cherry-pick or backport the fix with a reviewed PR into `release/0.1`;
   release commit as in section 3 (version `0.1.4`).
3. Tag `v0.1.4` on that branch. `prepare` accepts it only because the commit
   is on `origin/release/0.1` and the version is `0.1.*`
   (`scripts/release-gate.py line`); a `v0.2.*` tag there, or any tag on an
   unprotected branch, is refused, before anything is built and again
   before signing.
4. The release is published with `--latest=false`: the repository's
   "Latest" stays the newest `main` release.

The scheduled vulnerability scan (section 10) covers every `X.Y` line
automatically.

## 7. Secure delivery: RPKs and the 2-of-N signing ceremony

`robodr-<ver>-rpk.tar.gz` contains, built by the `delivery` job with this
release's own `robodr-release` (`docs/SECURE-DELIVERY.md`):

- `rpk_robodr_<serial>_{amd64,arm64}/`, `rpk_robodr-focal_<serial>_{amd64,arm64}/`
  (kind `deb`, the release's `.deb` as `<name>_<arch>.deb`, one merged
  CycloneDX SBOM `sbom.cdx.json`, health check `robodr-agentd.service`,
  maintainer scripts allowed), `rpk_robodr-rules_<serial>_all/` (kind
  `robodr-rules`, `rules/robodr/*.toml` of the tagged commit);
- `DELIVERY-MANIFEST.json`: every RPK's directory, digest, serial, payload
  hashes and the release asset it was made from.

The serial orders releases: `((X*1000+Y)*1000+Z)*1000 + p` with `p` =
100+N (alpha.N), 400+N (beta.N), 700+N (rc.N), 999 (final)
(`scripts/release-rpk.py`). The RPKs are **unsigned**; no delivery key is
ever in CI. The ceremony, on the offline signing station
(`crates/robodr-release/README.md`), with the delivery roots' trust file:

1. Copy the tarball (after `minisign -V` with the release key) to the
   station; optionally rebuild the RPKs there from the `.deb`s with
   `scripts/release-rpk.py` and compare the digests with the manifest
   (the build is deterministic).
2. Two holders of the programme's release keys each run
   `robodr-release sign --key REL_KEY --target rpk_... TRUST` for every RPK
   (`sign` re-checks manifest, file set, chunks, site policy and the
   signatures already present).
3. `robodr-release build bundle --programme P --seq N --prev-bundle DIR
   --rpk rpk_... TRUST --parity M --out bundle-N`, then two holders sign
   the bundle (`sign --target bundle-N`).
4. `robodr-release verify bundle --dir bundle-N TRUST --state chain-P.json`
   before it leaves the station; the bundle, `trust.json` and its signature
   cross the gap.

The delivery roots (root quorum of the trust file) and release keys are
generated and held as in section 2's ceremony (SALES-READINESS C1);
hardware-backed keys are T36.

## 8. Package repositories (apt / dnf)

`.github/workflows/pkg-repo.yml` runs when a release is published (or by
hand for a tag). It downloads the release's packages, **verifies each one
with the release minisign key and trusted comment first**, and builds with
`scripts/build-pkg-repo.sh`:

- apt: suites `stable` (`robodr`, Ubuntu 22.04 / 24.04, Debian 12+) and
  `focal` (`robodr-focal`), `Packages`, `Release`, clear-signed `InRelease`
  and `Release.gpg` (SHA-512);
- dnf: `rpm/{x86_64,aarch64}/` with `rpmsign`-signed RPMs, `createrepo_c`
  metadata and `repomd.xml.asc`, and `robodr.repo` (`gpgcheck=1`,
  `repo_gpgcheck=1`);
- `robodr-archive-keyring.gpg` / `.asc`, `KEY-FINGERPRINT`,
  `REPO-SHA256SUMS`;

and verifies all of it with only the exported public key (`gpgv`,
`rpm -K`) before handing the tree over as the artifact
`robodr-pkg-repo-<tag>`. Configuration: environment `package-repo` (required
reviewers) with secrets `REPO_GPG_PRIVATE_KEY` (ASCII-armoured) and
`REPO_GPG_PASSPHRASE`, variable `ROBODR_REPO_GPG_FINGERPRINT`. The OpenPGP
repository key is generated in the key ceremony (section 2; RSA 4096 or
Ed25519 per the customers' RHEL crypto policy) and its fingerprint is given
to customers with the root key. `dry_run: true` signs with a throwaway key.

Customer side (apt): `deb [signed-by=/usr/share/keyrings/robodr-archive-keyring.gpg]
<url>/apt stable main`; (dnf): `robodr.repo` with `gpgkey=` the `.asc`.
`--valid-days N` adds `Valid-Until` (apt refuses a stale, replayed
repository; then re-run the workflow before it expires). Where the tree is
served (authenticated portal or registry) is the delivery-channel decision
(SALES-READINESS C14); the workflow ends at the signed, verified tree.

## 9. SBOMs and provenance

Every SBOM archive holds cargo-cyclonedx's per-crate CycloneDX 1.5 SBOMs,
completed by `scripts/release-sbom-augment.sh`
(`scripts/metadata_to_cyclonedx.py --augment`) with what cargo does not
see: Rust `std`/`core`/`alloc` of the pinned toolchain; for the musl builds
`musl` (version read from rust-std's `libc.a`) and `libunwind` with the
SHA-256 of the archives linked; for `robodr-pulsard` every embedded eBPF
object (`*.bpf.o`, SHA-256, `GPL-2.0-only`): only the build-script outputs
whose bytes occur in the built `robodr-pulsard` are listed (stale or
duplicate build directories, and objects built only for Pulsar's tests,
are left out), and an eBPF ELF object in the program that no `*.bpf.o`
accounts for fails the build; and a `formulation` naming
rustc (release, commit, LLVM), cargo, cargo-cyclonedx and the C compilers.
`robodr-focal` does not ship `robodr-pulsard`, so its archives leave out
that crate's SBOM. `publish` refuses to sign unless all six archives are
present, the `robodr` and `.rpm` archives contain a `robodr-pulsard` SBOM
(with its eBPF objects) and the `robodr-focal` ones do not, and every
file passes `metadata_to_cyclonedx.py --check --require-complete` and
`cyclonedx validate --input-version v1_5 --fail-on-errors`. The delivery
RPKs carry one merged SBOM per package. (Installing the SBOM into
`/usr/share/doc/robodr/` is packaging work, `packaging/build-deb.sh`.)

Provenance, two independent forms:

- `robodr-<ver>.intoto.jsonl`: an in-toto Statement v1 with an SLSA
  provenance v1 predicate (`scripts/slsa-provenance.py`): every asset with
  its SHA-256 as a subject; the source commit, the submodule commits, the
  container images by digest and the Rust channel as resolved
  dependencies; the workflow, tag and run as builder and invocation. It is
  minisign-signed like every asset, so it verifies **offline**:
  ```sh
  minisign -V -p robodr-release.pub -m robodr-<ver>.intoto.jsonl
  python3 scripts/slsa-provenance.py verify --provenance robodr-<ver>.intoto.jsonl \
      --assets . --commit <sha> --repo SingularityRD/robodr --tag v<ver>
  ```
- GitHub's Sigstore attestation of the same subjects
  (`actions/attest-build-provenance`), online:
  `gh attestation verify robodr_<debver>_amd64.deb -R SingularityRD/robodr`.

## 10. Vulnerability monitoring and VEX

`security/vex/statements.json` is the curated exploitability record
(`scripts/vex.py check` validates it): per advisory, the component (purl),
products, versions and status (`not_affected` with one of OpenVEX's five
justifications and an impact statement; `affected` with an action;
`fixed`; `under_investigation`). Each release publishes
`robodr-<ver>.openvex.json` generated from it.

`.github/workflows/vuln-scan.yml` runs daily, for every `X.Y` line, on its
newest final release and, when one is newer, its newest pre-release
(`scripts/vuln-scan-tags.py`: semantic-version precedence, so `v0.2.0`
ranks above `v0.2.0-rc.1`; `sort -V` would not): cargo-deny with an
**empty** configuration (no waiver of the tag's `deny.toml` can hide an
advisory) and osv-scanner (pinned by SHA-256) on the tag's `Cargo.lock`. Every advisory found must have an applicable
statement in the current `statements.json` (`scripts/vex.py coverage`), or
the workflow fails: assess the advisory, add the statement on `main`, and
if the release is affected, patch it (section 6 for an older line). Each run
uploads OpenVEX and CSAF 2.0 (`csaf_vex`) documents per release (artifact
`vex-<tag>`) for customers and the advisory page (SALES-READINESS C14).

## 11. Release toolchain inputs

Every build and rebuild job records what it took from outside the
repository (`scripts/release-toolchain-inputs.sh`): the container image
digest, `rustc -vV`, a hash of the target's rust-std, and every C / eBPF
toolchain package with its version and a fingerprint (rpm's
`SHA256HEADER`; for dpkg the SHA-256 of the package's file list with
contents digests). `publish` appends all records to
`REPRODUCIBILITY-<version>.txt`, so drift between the build and the
independent rebuild, or between two releases, is visible and signed.

`scripts/release-toolchain-inputs.lock` turns records into enforced pins:
for a job label with lines there, any other version or fingerprint fails
the build. It is empty on purpose: apt.llvm.org (the eBPF clang of the
`.deb` build) and Rocky's AppStream do not keep superseded builds, so a pin
only holds once those packages come from a **hash-pinned mirror** under our
control (an apt/dnf snapshot repository; hosting is an infrastructure
decision). Then point `scripts/ci-install-ebpf-toolchain.sh` /
`ci-install-clang.sh` at the mirror and copy the recorded lines into the
lock in a reviewed commit.
