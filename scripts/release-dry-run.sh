#!/usr/bin/env bash
# Release dry run: replay .github/workflows/release.yml end to end on this
# machine, without GitHub and without the real release secrets
# (docs/RELEASE.md "Dry run").
#
#   scripts/release-dry-run.sh [--tag v0.1.0-rc.0-dryrun] [--out DIR]
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
#     VERSION and a commit whose Cargo.toml version disagrees with VERSION.
#  4. The jobs of release.yml, through scripts/gha-local-run.py, which runs
#     each step's `run:` script as written: prepare, build (amd64, arm64),
#     build-static (amd64, arm64), publish. Each job starts from a fresh
#     clone (a fresh runner: no target/, no dist/) that is deleted after
#     the job. `gh release ...` is scripts/gh-release-shim.sh (a local
#     draft release directory). Adaptations, all printed in the log:
#       * build arm64 runs on a native arm64 runner on GitHub; here it is
#         cross-compiled (aarch64-linux-gnu-gcc links, ring's C still with
#         the pinned clang-18, robodr-pulsard against multiarch arm64
#         libssl/libsqlite3), so target/release reads
#         target/aarch64-unknown-linux-gnu/release and the host triple
#         reads aarch64-unknown-linux-gnu in its step scripts;
#       * `ln -sf ... /usr/local/bin/X` writes into the dry run's own bin
#         directory (first on PATH) instead of the host's /usr/local/bin.
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
#     asset), every offline bundle passes `install-bundle.sh verify --pubkey
#     --tarball` (trusted copy from the release commit) and is refused when
#     tampered with or checked with another key, and every .deb passes
#     scripts/deb-install-smoke.sh --strict (throwaway dpkg root, --version
#     and --help of every binary must exit 0, systemd-analyze verify of
#     every unit).
#  7. Report: OUT/REPORT.txt (steps, adaptations, artefacts with sizes and
#     SHA-256), OUT/logs/, and the published assets in OUT/assets/ together
#     with the TEST-ONLY public key (OUT/TEST-ONLY-dry-run-minisign.pub).
#
# Host prerequisites (checked first): python3 with PyYAML, git, cargo/rustup
# (rust-toolchain.toml), the musl and aarch64-unknown-linux-gnu targets,
# clang-18 (scripts/c-toolchain.sh), gcc-aarch64-linux-gnu +
# libc6-dev-arm64-cross, libssl-dev:arm64 + libsqlite3-dev:arm64
# (dpkg --add-architecture arm64), qemu-aarch64-static, minisign, dpkg-deb,
# systemd-analyze. About 6 GB of free disk; network for apt and crates.
#
# Exit: 0 every job and check passed, 1 something failed (see the report),
# 2 usage or missing prerequisite.
set -euo pipefail

here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
root="$(cd "$here/.." && pwd)"
tag="v0.1.0-rc.0-dryrun"
out="$root/dist/release-dry-run"
work=""
keep=0
jobs_all="prepare build:amd64 build:arm64 build-static:amd64 build-static:arm64 publish"
jobs="$jobs_all"
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
workflow_rel=.github/workflows/release.yml
cross_triple=aarch64-unknown-linux-gnu

# ---------------------------------------------------------------- preflight
missing=()
need() { command -v "$1" >/dev/null 2>&1 || missing+=("$1 ($2)"); }
need git git; need python3 python3; need cargo rustup; need rustup rustup
need clang-18 "clang-18=1:18.1.3-1ubuntu1, scripts/ci-install-clang.sh"
need aarch64-linux-gnu-gcc gcc-aarch64-linux-gnu; need qemu-aarch64-static qemu-user-static
need minisign minisign; need dpkg-deb dpkg; need systemd-analyze systemd; need shred coreutils
python3 -c 'import yaml' 2>/dev/null || missing+=("PyYAML (python3-yaml)")
[[ -e /usr/aarch64-linux-gnu/lib/libc.so.6 ]] || missing+=("arm64 glibc sysroot (libc6-dev-arm64-cross)")
for p in libssl-dev:arm64 libsqlite3-dev:arm64; do
    dpkg-query -W -f='${Status}' "$p" 2>/dev/null | grep -q 'install ok installed' ||
        missing+=("$p (dpkg --add-architecture arm64; robodr-pulsard cross build)")
done
for t in x86_64-unknown-linux-musl aarch64-unknown-linux-musl "$cross_triple"; do
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
        --subst "/usr/local/bin/=>$bin/" --log "$log" "$@"
}

# ------------------------------------------------------- 3. guard tests
guard_root="$work/gh-guard"
mkdir -p "$guard_root"
if runner guard-tag "$out/logs/guard-wrong-tag.log" "$guard_root" --job prepare \
    --sha "$sha" --ref-name "v0.0.0-not-$version" >/dev/null 2>&1; then
    result FAIL "guard: prepare accepted tag v0.0.0-not-$version for VERSION $version"
else
    result PASS "guard: prepare refuses a tag that does not match VERSION"
fi
git -C "$repo" checkout -q -b guard-cargo-version "$sha"
set_version "$repo" "$version-guard" 0
git -C "$repo" commit -q -am "guard: VERSION without Cargo.toml"
guard_sha="$(git -C "$repo" rev-parse HEAD)"
git -C "$repo" checkout -q main
if runner guard-cargo "$out/logs/guard-cargo-version.log" "$guard_root" --job prepare \
    --sha "$guard_sha" --ref-name "v$version-guard" >/dev/null 2>&1; then
    result FAIL "guard: prepare accepted a commit whose Cargo.toml version is not VERSION ($version-guard)"
else
    result PASS "guard: prepare refuses a commit whose Cargo.toml version is not VERSION"
fi
rm -rf "$work/runner/guard-tag" "$work/runner/guard-cargo"

# ------------------------------------------------------- 4. the jobs
shim="$work/gh-releases"
mkdir -p "$shim"
outputs="$work/prepare-outputs.json"
vout=""
for j in $jobs; do
    job="${j%%:*}"
    arch=""
    [[ "$j" == *:* ]] && arch="${j#*:}"
    name="$job${arch:+-$arch}"
    log="$out/logs/$name.log"
    args=(--job "$job" --sha "$sha" --ref-name "$tag")
    [[ -n "$arch" ]] && args+=(--matrix "arch=$arch")
    [[ -n "$vout" ]] && args+=(--needs "prepare.version=$vout")
    [[ "$job" == prepare ]] && args+=(--outputs-file "$outputs")
    if [[ "$job" == build && "$arch" == arm64 && "$(uname -m)" != aarch64 ]]; then
        args+=(
            --env "CARGO_BUILD_TARGET=$cross_triple"
            --env "CARGO_TARGET_AARCH64_UNKNOWN_LINUX_GNU_LINKER=aarch64-linux-gnu-gcc"
            --env "PKG_CONFIG_ALLOW_CROSS=1"
            --env "PKG_CONFIG_LIBDIR_aarch64_unknown_linux_gnu=/usr/lib/aarch64-linux-gnu/pkgconfig:/usr/share/pkgconfig"
            --subst "target/release=>target/$cross_triple/release"
            --subst "rustc -vV | sed -n 's/^host: //p'=>echo $cross_triple"
            # A host tool, not a release binary: CARGO_BUILD_TARGET would
            # make `cargo install` put an aarch64 cargo-cyclonedx into
            # ~/.cargo/bin (the first dry run did exactly that).
            --subst "cargo install =>env -u CARGO_BUILD_TARGET cargo install "
        )
    fi
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
    else
        result FAIL "job $name (exit $rc after $((secs / 60)) min; see logs/$name.log)"
        break
    fi
    if [[ "$job" == prepare ]]; then
        vout="$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1]))["version"])' "$outputs")"
        [[ "$vout" == "$version" ]] || { result FAIL "prepare output version '$vout' != $version"; break; }
    fi
done
grep -h '^\[dry-run\] .*adaptation' "$out"/logs/*.log 2>/dev/null | sort | uniq -c |
    sed 's/^ */INFO  adaptation x/' | tee -a "$report" >&2 || true

# ------------------------------------------------------- 6. acceptance
rel="$shim/$tag"
if [[ $rc_all == 0 && " $jobs " == *" publish "* ]]; then
    assets="$rel/assets"
    if grep -qx 'draft=0' "$rel/meta"; then
        result PASS "release published (draft=false)"
    else
        result FAIL "release still a draft"
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
    for a in amd64 arm64; do
        want+=("robodr_${debver}_$a.deb" "robodr-$version-$a-offline.tar.gz"
            "robodr-$version-$a-sbom.tar.gz" "SHA256SUMS-$a"
            "robodr-focal_${debver}_$a.deb" "robodr-focal-$version-$a-offline.tar.gz"
            "SHA256SUMS-focal-$a")
    done
    want+=(SHA256SUMS)
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
