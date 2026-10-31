#!/usr/bin/env bash
# Record (and optionally enforce) the toolchain inputs of a release build:
# what came from outside the repository and could drift between two
# builds of the same commit (SALES-READINESS T74; docs/BUILD.md "C
# toolchain", "Release toolchain inputs").
#
#   scripts/release-toolchain-inputs.sh LABEL [--lock FILE] > TOOLCHAIN-INPUTS-LABEL.txt
#   scripts/release-toolchain-inputs.sh --self-test
#
# One "key value" line per input, sorted:
#   image <ROBODR_BUILD_IMAGE>          the container image (by digest), if set
#   rustc <rustc -vV, one line>          release, commit, host, LLVM
#   rust-sysroot-sha256 <hash>           of the sorted file list + contents of the
#                                        target's rust-std (what is linked)
#   pkg:<name> <version> <fingerprint>   every C/eBPF toolchain package of
#                                        the userland: the pinned clang and its
#                                        LLVM libraries (scripts/c-toolchain.sh),
#                                        the eBPF clang/lld/llvm (apt.llvm.org on
#                                        jammy, AppStream on Rocky), libssl and
#                                        libsqlite3 headers. The fingerprint is
#                                        rpm's SHA256HEADER (signed header incl.
#                                        the payload digest) or, for dpkg, the
#                                        SHA-256 of the package's md5sums list
#                                        (its installed file contents).
# The record is appended to the signed REPRODUCIBILITY-<version>.txt by
# release.yml, for the build and for the independent rebuild, so drift
# between the two (or between releases) is visible.
#
# --lock FILE enforces: every "LABEL key value" line of FILE whose LABEL
# matches must equal the recorded line (a missing package, another version
# or fingerprint FAILS, exit 1). Lines for other labels are ignored; with no
# line for LABEL nothing is enforced (a WARNING says so): upstream archives
# such as apt.llvm.org do not keep old builds, so a version pin only holds
# with a hash-pinned mirror of those packages (docs/RELEASE.md); commit the
# recorded lines to the lock once that mirror serves them.
set -euo pipefail
here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

if [[ "${1:-}" == --self-test ]]; then
    t="$(mktemp -d)"
    trap 'rm -rf "$t"' EXIT
    printf 'rustc a\npkg:x 1 f\n' >"$t/rec"
    printf 'other pkg:x 9 z\nL rustc a\nL pkg:x 1 f\n' >"$t/lock"
    n=0
    compare_lock() { "$here/release-toolchain-inputs.sh" --compare "$1" "$2" "$3" >/dev/null 2>&1; }
    compare_lock L "$t/rec" "$t/lock" && n=$((n + 1)) || echo "self-test FAIL: matching lock refused" >&2
    printf 'L pkg:x 2 f\n' >"$t/lock2"
    compare_lock L "$t/rec" "$t/lock2" && echo "self-test FAIL: other version accepted" >&2 || n=$((n + 1))
    printf 'L pkg:y 1 f\n' >"$t/lock3"
    compare_lock L "$t/rec" "$t/lock3" && echo "self-test FAIL: missing package accepted" >&2 || n=$((n + 1))
    compare_lock M "$t/rec" "$t/lock2" && n=$((n + 1)) || echo "self-test FAIL: other label enforced" >&2
    echo "self-test: $n/4 passed"
    [[ $n == 4 ]]
    exit
fi

if [[ "${1:-}" == --compare ]]; then # LABEL RECORD LOCK (internal; tested by --self-test)
    label="$2" rec="$3" lock="$4" rc=0 seen=0
    while read -r l k v; do
        [[ "$l" == "$label" ]] || continue
        seen=1
        got="$(awk -v k="$k" '$1 == k { $1 = ""; sub(/^ /, ""); print; exit }' "$rec")"
        if [[ "$got" != "$v" ]]; then
            echo "toolchain-inputs: FAIL $label $k: recorded '${got:-(absent)}', locked '$v'" >&2
            rc=1
        fi
    done < <(grep -v '^\s*#' "$lock" | grep -v '^\s*$' || true)
    [[ $seen == 1 ]] || echo "toolchain-inputs: WARNING: no lock lines for $label in $lock; recorded only" >&2
    exit "$rc"
fi

label="${1:?usage: release-toolchain-inputs.sh LABEL [--lock FILE]}"
lock=""
[[ "${2:-}" == --lock ]] && lock="${3:?--lock needs a file}"
[[ "$label" =~ ^[a-z0-9-]+$ ]] || { echo "toolchain-inputs: bad label $label" >&2; exit 2; }

# shellcheck source=scripts/c-toolchain.sh disable=SC1091
. "$here/c-toolchain.sh"
rec="$(mktemp)"
trap 'rm -f "$rec"' EXIT
{
    [[ -n "${ROBODR_BUILD_IMAGE:-}" ]] && echo "image $ROBODR_BUILD_IMAGE"
    echo "rustc $(rustc -vV | tr '\n' ' ' | sed 's/ $//')"
    # The musl jobs name their triple in TARGET (release.yml build-static).
    target="${CARGO_BUILD_TARGET:-${TARGET:-$(rustc -vV | sed -n 's/^host: //p')}}"
    std="$(rustc --print sysroot)/lib/rustlib/$target/lib"
    if [[ -d "$std" ]]; then
        echo "rust-sysroot-sha256 $(cd "$std" && find . -type f -print0 | LC_ALL=C sort -z | xargs -0 sha256sum | sha256sum | cut -d' ' -f1) $target"
    fi
    echo "userland $(robodr_build_userland)"
    read -r -a also <<<"${ROBODR_CLANG_APT_ALSO:-}"
    pkgs=("$ROBODR_CLANG_APT_PACKAGE" "${also[@]}")
    if command -v dpkg-query >/dev/null 2>&1; then
        pkgs+=(clang-20 lld-20 llvm-20 libllvm20 libclang-cpp20 libclang1-20 libssl-dev libsqlite3-dev)
        for p in "${pkgs[@]}"; do
            v="$(dpkg-query -W -f='${Version} ${Architecture}' "$p" 2>/dev/null || true)"
            [[ -n "$v" ]] || continue
            m="/var/lib/dpkg/info/$p.md5sums"
            [[ -f "$m" ]] || m="/var/lib/dpkg/info/$p:$(dpkg --print-architecture).md5sums"
            fp="$(sha256sum "$m" 2>/dev/null | cut -d' ' -f1 || true)"
            echo "pkg:$p $v ${fp:-no-md5sums}"
        done
    else
        pkgs+=(clang lld llvm llvm-libs clang-libs lld-libs openssl-devel sqlite-devel)
        for p in $(printf '%s\n' "${pkgs[@]}" | LC_ALL=C sort -u); do
            rpm -q "$p" >/dev/null 2>&1 || continue
            echo "pkg:$p $(rpm -q --qf '%{VERSION}-%{RELEASE} %{ARCH} %{SHA256HEADER}' "$p")"
        done
    fi
} | LC_ALL=C sort -u >"$rec"
sed "s/^/$label /" "$rec"
if [[ -n "$lock" ]]; then
    "$0" --compare "$label" "$rec" "$lock"
fi
