#!/usr/bin/env bash
# Release dry run: replay .github/workflows/release.yml end to end on this
# machine, without GitHub and without the real release secrets
# (docs/RELEASE.md "Dry run").
#
#   scripts/release-dry-run.sh [--tag v0.1.0-rc.99] [--out DIR]
#       [--work DIR] [--jobs "prepare build:amd64 ..."] [--keep-work]
#
# What it does, in order:
#  1. Source: `git archive` of HEAD plus every submodule at its recorded
#     commit (uncommitted changes are NOT included; a dirty tree is
#     reported), committed into a private git repository under the work dir.
#  2. Release commit (only when the tag's version differs from VERSION):
#     VERSION, [workspace.package] version in Cargo.toml, the workspace
#     members' entries of Cargo.lock (cargo update --workspace --offline)
#     and CHANGELOG.md (the [Unreleased] heading gets a "## [<version>]"
#     heading below it, as a maintainer cuts a release) - exactly the
#     commit a maintainer tags (docs/RELEASE.md). NO git tag is created,
#     not even in the private repository; the tag name only reaches the jobs
#     as GITHUB_REF_NAME.
#  3. Guard tests: the prepare job must REFUSE a tag that does not match
#     VERSION, a commit whose Cargo.toml version disagrees with VERSION, a
#     version without a secure-delivery serial, a commit that is on neither
#     main nor release/X.Y, a line whose branch is not protected, and a
#     commit whose newest CI run (the shim's `gh api`) did not pass.
#  4. The jobs of release.yml, through scripts/gha-local-run.py, which runs
#     each step's `run:` script as written, `container:` jobs inside their
#     pinned image (docker), with a local artifact store between jobs:
#     prepare, build, build-rpm, build-static, smoke, rebuild-deb,
#     rebuild-rpm, rebuild-static, delivery, rebuild-delivery, finalize,
#     publish (with finalize's set digest). Each job starts from a
#     fresh clone (a fresh runner: no target/, no dist/) that is deleted
#     after the job. `gh release ...` / the CI `gh api` call are
#     scripts/gh-release-shim.sh (a local draft release directory).
#     Adaptations, all printed in the log:
#       * the arm64 jobs that GitHub runs on native arm64 runners (build,
#         build-rpm, smoke, rebuild-deb, rebuild-rpm) run only on an
#         aarch64 host; elsewhere they, delivery, rebuild-delivery,
#         finalize and publish are SKIPPED
#         (reported, RESULT stays PASS for what ran). build-static and
#         rebuild-static arm64 run anywhere (cross-linked, as on GitHub).
#         The complete dry run on real runners is the workflow itself:
#         run release.yml with workflow_dispatch (job publish-dry-run,
#         throwaway key, nothing published; docs/RELEASE.md "Dry run").
#       * `ln -sf ... /usr/local/bin/X` writes into the dry run's own bin
#         directory (first on PATH) instead of the host's /usr/local/bin;
#       * actions/attest-build-provenance is skipped (needs GitHub OIDC).
#     `sudo apt-get install` steps run for real (they install the same
#     packages the runner gets).
#  5. Signing with a THROWAWAY minisign key, generated in the work dir for
#     this run only (password-protected, so the workflow's password branch
#     runs), passed to the publish job as its MINISIGN_SECRET_KEY /
#     MINISIGN_PASSWORD secrets and ROBODR_MINISIGN_PUBKEY variable. The
#     secret key is shredded at the end; it is TEST-ONLY and never leaves
#     the work dir (which must be outside the repository).
#  6. Acceptance beyond the workflow: the published set is complete and
#     signed (minisign -V with the public key FILE, SHA256SUMS covers every
#     asset), the SLSA provenance verifies against the published assets
#     (scripts/slsa-provenance.py verify), the release is marked Latest
#     (explicitly not Latest for a pre-release version such as the default),
#     every offline bundle passes `install-bundle.sh verify --pubkey
#     --tarball` (trusted copy from the release commit) and is refused when
#     tampered with or checked with another key, and every .deb passes
#     scripts/deb-install-smoke.sh --strict (throwaway dpkg root, --version
#     and --help of every binary must exit 0, systemd-analyze verify of
#     every unit).
#  7. Report: OUT/REPORT.txt (steps, adaptations, artefacts with sizes and
#     SHA-256), OUT/logs/, and the published assets in OUT/assets/ together
#     with the TEST-ONLY public key (OUT/TEST-ONLY-dry-run-minisign.pub).
#
# Host prerequisites (checked first): python3 with PyYAML, git, docker (the
# container jobs), cargo/rustup (rust-toolchain.toml) with the musl targets,
# clang-18 (scripts/c-toolchain.sh), qemu-aarch64-static, minisign, rpm,
# dpkg-deb, systemd-analyze. About 20 GB of free disk; network for images,
# apt/dnf and crates. --jobs "..." runs a subset (e.g. --jobs prepare).
#
# Exit: 0 every job and check that ran passed, 1 something failed (see the
# report), 2 usage or missing prerequisite.
set -euo pipefail

here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
root="$(cd "$here/.." && pwd)"
# The default simulated tag: a pre-release with a secure-delivery serial
# (prepare refuses any other, scripts/release-rpk.py --serial). No git tag
# is created.
tag="v0.1.0-rc.99"
out="$root/dist/release-dry-run"
work=""
keep=0
jobs_all="prepare build:amd64 build:arm64 build-rpm:amd64 build-rpm:arm64 build-static:amd64 build-static:arm64
smoke:amd64 smoke:arm64 rebuild-deb:amd64 rebuild-deb:arm64 rebuild-rpm:amd64 rebuild-rpm:arm64
rebuild-static:amd64 rebuild-static:arm64 delivery rebuild-delivery finalize publish"
# Jobs GitHub runs on native arm64 runners; without them delivery,
# rebuild-delivery, finalize and publish have nothing to work on.
native_arm64=" build:arm64 build-rpm:arm64 smoke:arm64 rebuild-deb:arm64 rebuild-rpm:arm64 "
jobs="$(tr '\n' ' ' <<<"$jobs_all")"
while [[ $# -gt 0 ]]; do
    case "$1" in
    --tag) tag="$2"; shift 2 ;;
    --out) out="$2"; shift 2 ;;
    --work) work="$2"; shift 2 ;;
    --jobs) jobs="$2"; shift 2 ;;
    --keep-work) keep=1; shift ;;
    -h | --help) sed -n '2,/^set -euo/p' "$0" | sed '$d'; exit 0 ;;
    *) echo "release-dry-run: unknown argument $1" >&2; exit 2 ;;
    esac
done
case "$tag" in v[0-9]*) ;; *) echo "release-dry-run: --tag must look like v<version>" >&2; exit 2 ;; esac
version="${tag#v}"
# A pre-release (a '-' before any '+build') is never "Latest"
# (scripts/release-gate.py line).
want_latest=true
case "${version%%+*}" in *-*) want_latest=false ;; esac
workflow_rel=.github/workflows/release.yml

# ---------------------------------------------------------------- preflight
missing=()
need() { command -v "$1" >/dev/null 2>&1 || missing+=("$1 ($2)"); }
need git git; need python3 python3; need cargo rustup; need rustup rustup; need docker docker
need clang-18 "clang-18=1:18.1.3-1ubuntu1, scripts/ci-install-clang.sh"
need qemu-aarch64-static qemu-user-static; need rpm rpm
need minisign minisign; need dpkg-deb dpkg; need systemd-analyze systemd; need shred coreutils
python3 -c 'import yaml' 2>/dev/null || missing+=("PyYAML (python3-yaml)")
for t in x86_64-unknown-linux-musl aarch64-unknown-linux-musl; do
    (cd "$root" && rustup target list --installed 2>/dev/null) | grep -qx "$t" || missing+=("rust target $t")
done
if [[ ${#missing[@]} -gt 0 ]]; then
    printf 'release-dry-run: missing prerequisite: %s\n' "${missing[@]}" >&2
    exit 2
fi

if [[ -z "$work" ]]; then
    work="$(mktemp -d "${TMPDIR:-/tmp}/robodr-release-dry-run.XXXXXX")"
fi
mkdir -p "$work"
work="$(cd "$work" && pwd)"
case "$work/" in "$root"/*)
    echo "release-dry-run: --work must be outside the repository (the throwaway key lives there)" >&2
    exit 2
    ;;
esac
mkdir -p "$out"
out="$(cd "$out" && pwd)"
rm -rf "$out/logs" "$out/assets" "$out/REPORT.txt" "$out"/TEST-ONLY-*
mkdir -p "$out/logs"
report="$out/REPORT.txt"
keydir="$work/TEST-ONLY-minisign-key"
# shellcheck disable=SC2317 # invoked by the EXIT trap
cleanup() {
    if [[ -d "$keydir" ]]; then
        find "$keydir" -type f -exec shred -u {} + 2>/dev/null || true
        rm -rf "$keydir"
    fi
    if [[ $keep == 0 ]]; then rm -rf "$work"; fi
}
trap cleanup EXIT

say() { echo "release-dry-run: $*" | tee -a "$report" >&2; }
rc_all=0
result() { # status text
    printf '%-5s %s\n' "$1" "$2" | tee -a "$report" >&2
    [[ "$1" == PASS || "$1" == INFO ]] || rc_all=1
}
free_gb() { df -Pk "$work" | awk 'NR==2 { printf "%d", $4 / 1048576 }'; }

{
    echo "RoboDR release dry run (scripts/release-dry-run.sh)"
    echo "Date: $(date -u +%Y-%m-%dT%H:%M:%SZ)  Host: $(uname -srm)  $(sed -n 's/^PRETTY_NAME=//p' /etc/os-release | tr -d '"')"
    echo "Source: $(git -C "$root" rev-parse HEAD) ($(git -C "$root" rev-parse --abbrev-ref HEAD))"
    echo "Tag (simulated, not created): $tag"
    echo "Signing key: THROWAWAY, generated for this run, TEST ONLY"
    echo
} >"$report"
if [[ -n "$(git -C "$root" status --porcelain --untracked-files=no)" ]]; then
    say "WARNING: uncommitted changes in $root are NOT part of the dry run (it builds HEAD)"
fi

# ------------------------------------------------------- 1. source snapshot
repo="$work/repo"
rm -rf "$repo"
mkdir -p "$repo"
git -C "$root" archive --format=tar HEAD | tar -xf - -C "$repo"
while read -r line; do
    [[ -n "$line" ]] || continue
    case "$line" in
    [-+U]*) echo "release-dry-run: submodule not at its recorded commit: $line" >&2; exit 1 ;;
    esac
    sha="$(awk '{ print $1 }' <<<"$line")"
    path="$(awk '{ print $2 }' <<<"$line")"
    mkdir -p "$repo/$path"
    git -C "$root/$path" archive --format=tar "$sha" | tar -xf - -C "$repo/$path"
done < <(git -C "$root" submodule status --recursive)
commit_date="$(git -C "$root" log -1 --format=%cI HEAD)"
export GIT_AUTHOR_NAME="RoboDR release dry run" GIT_AUTHOR_EMAIL="dry-run@invalid"
export GIT_COMMITTER_NAME="$GIT_AUTHOR_NAME" GIT_COMMITTER_EMAIL="$GIT_AUTHOR_EMAIL"
export GIT_AUTHOR_DATE="$commit_date" GIT_COMMITTER_DATE="$commit_date"
git -C "$repo" init -q -b main
git -C "$repo" config commit.gpgsign false
git -C "$repo" add -A -f
git -C "$repo" commit -q -m "snapshot of $(git -C "$root" rev-parse HEAD) (submodules inlined)"
say "source: HEAD $(git -C "$root" rev-parse --short HEAD) + submodules -> $repo"

# ------------------------------------------------------- 2. release commit
set_version() { # dir version [cargo]
    local d="$1" v="$2" cargo="${3:-1}"
    printf '%s\n' "$v" >"$d/VERSION"
    if [[ "$cargo" == 1 ]]; then
        python3 - "$d/Cargo.toml" "$v" <<'PY'
import re, sys
p, v = sys.argv[1], sys.argv[2]
s = open(p, encoding="utf-8").read()
m = re.search(r'(?ms)^\[workspace\.package\]\n(.*?)(?=^\[)', s)
assert m, "no [workspace.package] in Cargo.toml"
body, n = re.subn(r'(?m)^version = "[^"]*"', f'version = "{v}"', m.group(1), count=1)
assert n == 1, "no version in [workspace.package]"
open(p, "w", encoding="utf-8").write(s[: m.start(1)] + body + s[m.end(1):])
PY
        (cd "$d" && cargo update --workspace --offline --quiet)
    fi
    python3 - "$d/CHANGELOG.md" "$v" "$(date -u -d "$commit_date" +%Y-%m-%d)" <<'PY'
import sys
p, v, day = sys.argv[1:4]
s = open(p, encoding="utf-8").read()
head = "## [Unreleased]\n"
assert head in s, "CHANGELOG.md has no '## [Unreleased]' heading"
s = s.replace(head, f"{head}\n## [{v}] - {day}\n\nRelease dry run only (scripts/release-dry-run.sh): never published.\n", 1)
open(p, "w", encoding="utf-8").write(s)
PY
}
current="$(tr -d '[:space:]' <"$repo/VERSION")"
if [[ "$current" != "$version" ]]; then
    set_version "$repo" "$version"
    git -C "$repo" add -A
    git -C "$repo" commit -q -m "release: $version (dry run)"
    say "release commit: VERSION $current -> $version; Cargo.toml, Cargo.lock ($(git -C "$repo" diff --numstat HEAD~1 -- Cargo.lock | awk '{ print "+" $1 "/-" $2 }') lines), CHANGELOG.md"
fi
sha="$(git -C "$repo" rev-parse HEAD)"
say "release commit $sha, SOURCE_DATE_EPOCH $(git -C "$repo" log -1 --format=%ct)"

# ------------------------------------------------------- shims and secrets
bin="$work/bin"
mkdir -p "$bin"
install -m 0755 "$here/gh-release-shim.sh" "$bin/gh"
export PATH="$bin:$PATH"
export GH_SHIM_GIT="$repo"

mkdir -p "$keydir"
chmod 0700 "$keydir"
pw="$(head -c 24 /dev/urandom | base64)"
printf '%s\n%s\n' "$pw" "$pw" | minisign -G -p "$keydir/TEST-ONLY.pub" -s "$keydir/TEST-ONLY.key" >/dev/null 2>&1
pubkey="$(sed -n 2p "$keydir/TEST-ONLY.pub")"
cp "$keydir/TEST-ONLY.pub" "$out/TEST-ONLY-dry-run-minisign.pub"
say "throwaway minisign key generated (TEST ONLY): public key $pubkey"

runner() { # name logfile shim-root [gha-local-run args...]
    local name="$1" log="$2" shimroot="$3"
    shift 3
    local rdir="$work/runner/$name"
    rm -rf "$rdir"
    mkdir -p "$rdir"
    GH_SHIM_ROOT="$shimroot" python3 "$here/gha-local-run.py" \
        --workflow "$repo/$workflow_rel" --repo "$repo" \
        --workspace "$rdir/robodr" --runner-temp "$rdir/temp" \
        --artifacts "$work/artifacts" --event push \
        --subst "/usr/local/bin/=>$bin/" --log "$log" "$@"
}

# ------------------------------------------------------- 3. guard tests
guard_root="$work/gh-guard"
mkdir -p "$guard_root"
guard() { # name expect-in-log description args...
    local gname="$1" want="$2" what="$3"
    shift 3
    local glog="$out/logs/guard-$gname.log"
    if runner "guard-$gname" "$glog" "$guard_root" --job prepare "$@" >/dev/null 2>&1; then
        result FAIL "guard: prepare accepted $what"
    elif grep -q -- "$want" "$glog"; then
        result PASS "guard: prepare refuses $what"
    else
        result FAIL "guard: prepare failed for another reason than $what (logs/guard-$gname.log)"
    fi
    rm -rf "$work/runner/guard-$gname"
}
guard wrong-tag "does not match VERSION" "a tag that does not match VERSION" \
    --sha "$sha" --ref-name "v0.0.0-not-$version"
git -C "$repo" checkout -q -b guard-cargo-version "$sha"
set_version "$repo" "$version-guard" 0
git -C "$repo" commit -q -am "guard: VERSION without Cargo.toml"
guard_sha="$(git -C "$repo" rev-parse HEAD)"
git -C "$repo" checkout -q -b guard-feature "$sha"
git -C "$repo" commit -q --allow-empty -m "guard: an unreviewed commit on a feature branch"
feature_sha="$(git -C "$repo" rev-parse HEAD)"
git -C "$repo" checkout -q main
git -C "$repo" checkout -q -b guard-serial "$sha"
set_version "$repo" "${version%%-*}-dev.1"
git -C "$repo" commit -q -am "guard: a version without an RPK serial"
serial_sha="$(git -C "$repo" rev-parse HEAD)"
git -C "$repo" checkout -q main
guard cargo-version "Cargo.toml" "a commit whose Cargo.toml version is not VERSION" \
    --sha "$guard_sha" --ref-name "v$version-guard"
guard rpk-serial "has no secure-delivery serial" "a version without a secure-delivery serial" \
    --sha "$serial_sha" --ref-name "v${version%%-*}-dev.1"
guard release-line "neither on main nor on release/" "a commit on neither main nor release/X.Y" \
    --sha "$feature_sha" --ref-name "$tag"
GH_SHIM_UNPROTECTED=1 guard unprotected "is not protected" "a release line whose branch is not protected" \
    --sha "$sha" --ref-name "$tag"
GH_SHIM_CI_CONCLUSION=failure guard ci-red "did not pass" "a commit whose newest CI run failed" \
    --sha "$sha" --ref-name "$tag"
git -C "$repo" branch -q -D guard-cargo-version guard-feature guard-serial

# ------------------------------------------------------- 4. the jobs
shim="$work/gh-releases"
mkdir -p "$shim" "$work/artifacts"
outputs="$work/prepare-outputs.json"
foutputs="$work/finalize-outputs.json"
vout=""
set_sha=""
skipped=()
publish_ran=0
for j in $jobs; do
    job="${j%%:*}"
    arch=""
    [[ "$j" == *:* ]] && arch="${j#*:}"
    name="$job${arch:+-$arch}"
    log="$out/logs/$name.log"
    if [[ "$(uname -m)" != aarch64 && "$native_arm64" == *" $j "* ]]; then
        skipped+=("$j")
        result INFO "job $name: SKIPPED (a native arm64 runner on GitHub; this host is $(uname -m))"
        continue
    fi
    if [[ ("$job" == delivery || "$job" == rebuild-delivery || "$job" == finalize || "$job" == publish) && ${#skipped[@]} -gt 0 ]]; then
        result INFO "job $name: SKIPPED (needs ${skipped[*]}); run release.yml with workflow_dispatch for the complete dry run"
        continue
    fi
    args=(--job "$job" --sha "$sha" --ref-name "$tag")
    [[ -n "$arch" ]] && args+=(--matrix "arch=$arch")
    [[ -n "$vout" ]] && args+=(--needs "prepare.version=$vout" --needs "prepare.latest=$want_latest" --needs "prepare.dry_run=false")
    [[ "$job" == prepare ]] && args+=(--outputs-file "$outputs")
    [[ "$job" == finalize ]] && args+=(--outputs-file "$foutputs")
    [[ "$job" == publish ]] && args+=(--needs "finalize.set_sha256=$set_sha")
    # The build jobs run with ROBODR_RELEASE=1, which refuses a placeholder
    # maintainer; the dry run's own (reserved .test domain) stands in for
    # the repository variable ROBODR_MAINTAINER.
    secrets=("DRYRUN_VAR_ROBODR_MAINTAINER=RoboDR release dry run <dry-run@robodr.test>")
    if [[ "$job" == publish ]]; then
        secrets=(
            "DRYRUN_SECRET_MINISIGN_SECRET_KEY=$(cat "$keydir/TEST-ONLY.key")"
            "DRYRUN_SECRET_MINISIGN_PASSWORD=$pw"
            "DRYRUN_VAR_ROBODR_MINISIGN_PUBKEY=$pubkey"
        )
    fi
    if [[ "$(free_gb)" -lt 4 ]]; then
        result FAIL "job $name: not started, only $(free_gb) GB free in $work"
        break
    fi
    t0=$(date +%s)
    say "job $name: started ($(free_gb) GB free), log $log"
    set +e
    (
        [[ ${#secrets[@]} -gt 0 ]] && export "${secrets[@]}"
        runner "$name" "$log" "$shim" "${args[@]}" </dev/null
    ) 2>&1 | grep --line-buffered -E '^(===|---|!!!|\[dry-run\]|gha-local-run)' >&2
    rc="${PIPESTATUS[0]}"
    set -e
    secs=$(($(date +%s) - t0))
    rm -rf "$work/runner/$name"
    if [[ "$rc" == 0 ]]; then
        result PASS "job $name ($((secs / 60)) min $((secs % 60)) s)"
        [[ "$job" == publish ]] && publish_ran=1
    else
        result FAIL "job $name (exit $rc after $((secs / 60)) min; see logs/$name.log)"
        break
    fi
    if [[ "$job" == finalize ]]; then
        set_sha="$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1]))["set_sha256"])' "$foutputs")"
        [[ "$set_sha" =~ ^[0-9a-f]{64}$ ]] || { result FAIL "finalize: no set digest output"; break; }
        result INFO "finalize: set digest $set_sha (what the release reviewers approve)"
    fi
    if [[ "$job" == prepare ]]; then
        vout="$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1]))["version"])' "$outputs")"
        [[ "$vout" == "$version" ]] || { result FAIL "prepare output version '$vout' != $version"; break; }
        lout="$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1]))["latest"])' "$outputs")"
        [[ "$lout" == "$want_latest" ]] || { result FAIL "prepare: latest=$lout, want $want_latest (a commit on main becomes Latest unless $version is a pre-release)"; break; }
    fi
done
grep -h '^\[dry-run\] .*adaptation' "$out"/logs/*.log 2>/dev/null | sort | uniq -c |
    sed 's/^ */INFO  adaptation x/' | tee -a "$report" >&2 || true

# ------------------------------------------------------- 6. acceptance
rel="$shim/$tag"
if [[ $rc_all == 0 && $publish_ran == 1 ]]; then
    assets="$rel/assets"
    if grep -qx 'draft=0' "$rel/meta"; then
        result PASS "release published (draft=false)"
    else
        result FAIL "release still a draft"
    fi
    if [[ "$want_latest" == true ]]; then
        if grep -qx 'latest=1' "$rel/meta"; then
            result PASS "marked Latest (a final release from main)"
        else
            result FAIL "a final release from main is not marked Latest"
        fi
    elif grep -qx 'latest=0' "$rel/meta"; then
        result PASS "not marked Latest (pre-release $version)"
    else
        result FAIL "pre-release $version: --latest=false was not requested"
    fi
    case "$version" in
    *-*)
        if grep -qx 'prerelease=1' "$rel/meta"; then
            result PASS "marked prerelease ($version)"
        else
            result FAIL "pre-release version not marked prerelease"
        fi
        ;;
    esac
    # Expected asset set (release.yml header).
    debver="${version/-/\~}-1"
    want=()
    rpmver="${version/-/\~}"
    declare -A rpmarch=([amd64]=x86_64 [arm64]=aarch64)
    for a in amd64 arm64; do
        want+=("robodr_${debver}_$a.deb" "robodr-$version-$a-offline.tar.gz"
            "robodr-$version-$a-sbom.tar.gz" "SHA256SUMS-$a"
            "robodr-$rpmver-1.${rpmarch[$a]}.rpm" "robodr-$version-$a-rpm-offline.tar.gz"
            "robodr-$version-rpm-$a-sbom.tar.gz" "SHA256SUMS-rpm-$a"
            "robodr-focal_${debver}_$a.deb" "robodr-focal-$version-$a-offline.tar.gz"
            "robodr-focal-$version-$a-sbom.tar.gz" "SHA256SUMS-focal-$a")
    done
    want+=("robodr-$version-rpk.tar.gz" "REPRODUCIBILITY-$version.txt" "robodr-$version.openvex.json"
        "robodr-$version.intoto.jsonl" SHA256SUMS)
    have="$(cd "$assets" && find . -maxdepth 1 -type f ! -name '*.minisig' -printf '%P\n' | LC_ALL=C sort)"
    wantl="$(printf '%s\n' "${want[@]}" | LC_ALL=C sort)"
    if [[ "$have" == "$wantl" ]]; then
        result PASS "asset set complete (${#want[@]} assets + ${#want[@]} signatures)"
    else
        result FAIL "asset set differs: $(diff <(echo "$wantl") <(echo "$have") | grep '^[<>]' | tr '\n' ' ')"
    fi
    sigok=1
    for f in $have; do
        minisign -V -q -p "$out/TEST-ONLY-dry-run-minisign.pub" -m "$assets/$f" >/dev/null 2>&1 || { sigok=0; say "bad signature: $f"; }
        grep -q "trusted comment: robodr $version $f\$" "$assets/$f.minisig" || { sigok=0; say "trusted comment of $f.minisig"; }
    done
    if [[ $sigok == 1 ]]; then
        result PASS "every asset verifies (minisign -V -p <pubkey file>), trusted comment 'robodr $version <file>'"
    else
        result FAIL "signature check"
    fi
    listed="$(awk '{ print $2 }' "$assets/SHA256SUMS" | LC_ALL=C sort)"
    if [[ "$listed" == "$(grep -vx 'SHA256SUMS.*' <<<"$have" | LC_ALL=C sort)" ]] &&
        (cd "$assets" && sha256sum --strict --quiet -c SHA256SUMS); then
        result PASS "SHA256SUMS covers every asset (per-arch SHA256SUMS-* files are signed, not listed) and matches"
    else
        result FAIL "SHA256SUMS incomplete or mismatching"
    fi
    if python3 "$here/slsa-provenance.py" verify --provenance "$assets/robodr-$version.intoto.jsonl" \
        --assets "$assets" --commit "$sha" --tag "$tag" >"$out/logs/provenance.log" 2>&1; then
        result PASS "SLSA provenance names every published asset with its SHA-256, the commit and the tag"
    else
        result FAIL "SLSA provenance (logs/provenance.log)"
    fi
    # Offline bundles: the documented entry-station check, with a trusted
    # copy of the installer (the release commit's), never the bundle's.
    trusted="$work/trusted-install-bundle.sh"
    git -C "$repo" show "$sha:packaging/install-bundle.sh" >"$trusted"
    other="$work/other-key"
    mkdir -p "$other"
    minisign -G -W -p "$other/other.pub" -s "$other/other.key" </dev/null >/dev/null 2>&1
    for t in "$assets"/*-offline.tar.gz; do
        b="$(basename "$t")"
        if o="$(sh "$trusted" verify --pubkey "$out/TEST-ONLY-dry-run-minisign.pub" --tarball "$t" 2>&1)"; then
            result PASS "install-bundle.sh verify $b: $(grep -c 'signature OK' <<<"$o") signature(s) OK"
        else
            result FAIL "install-bundle.sh verify $b: $o"
        fi
        if sh "$trusted" verify --pubkey "$other/other.pub" --tarball "$t" >/dev/null 2>&1; then
            result FAIL "install-bundle.sh verify $b accepted ANOTHER key"
        fi
        tam="$work/tamper"
        rm -rf "$tam"
        mkdir -p "$tam"
        cp "$t" "$t.minisig" "$tam/"
        printf 'x' >>"$tam/$b"
        if sh "$trusted" verify --pubkey "$out/TEST-ONLY-dry-run-minisign.pub" --tarball "$tam/$b" >/dev/null 2>&1; then
            result FAIL "install-bundle.sh verify accepted a tampered $b"
        fi
        rm -rf "$tam"
    done
    result PASS "tampered bundles and a foreign key are refused (any acceptance is listed as FAIL above)"
    # Install smoke test of every package.
    # --strict: a binary whose --version / --help does not exit 0 (naming
    # the release version) fails the run instead of being a finding.
    if "$here/deb-install-smoke.sh" --strict "$assets"/*.deb >"$out/logs/deb-install-smoke.log" 2>&1; then
        result PASS "deb-install-smoke: every .deb unpacks in a throwaway dpkg root, every binary starts, sysusers/tmpfiles apply, units verify"
    else
        result FAIL "deb-install-smoke (logs/deb-install-smoke.log)"
    fi
    grep -E '^(== |   )' "$out/logs/deb-install-smoke.log" | sed 's/^/INFO  /' | tee -a "$report" >&2 || true
    grep 'FINDING' "$out/logs/deb-install-smoke.log" | sed 's/^deb-install-smoke: /INFO  /' | tee -a "$report" >&2 || true
    cp -a "$assets" "$out/assets"
    cp "$rel/notes.md" "$out/assets/RELEASE-NOTES.md"
fi

# ------------------------------------------------------- 7. report
{
    echo
    echo "Artefacts (published set, signed with the TEST-ONLY key):"
    if [[ -d "$out/assets" ]]; then
        (cd "$out/assets" && for f in $(find . -maxdepth 1 -type f ! -name '*.minisig' ! -name RELEASE-NOTES.md -printf '%P\n' | LC_ALL=C sort); do
            printf '%10s  %s  %s\n' "$(stat -c %s "$f")" "$(sha256sum "$f" | cut -d' ' -f1)" "$f"
        done)
    fi
    echo
    if [[ $rc_all == 0 ]]; then echo "RESULT: PASS"; else echo "RESULT: FAIL"; fi
} >>"$report"
tail -n 40 "$report" >&2
exit "$rc_all"
