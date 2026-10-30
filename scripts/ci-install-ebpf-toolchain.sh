#!/usr/bin/env bash
# Install Pulsar's build toolchain for robodr-pulsard (docs/BUILD.md
# "Pulsar / eBPF prerequisites"): clang-20, lld-20, llvm-20 with `clang`
# and `llvm-strip` on PATH (Pulsar's bpf-builder runs `clang -target bpf`
# and `llvm-strip`), plus libssl-dev, libsqlite3-dev and pkg-config.
#
#   scripts/ci-install-ebpf-toolchain.sh
#   scripts/ci-install-ebpf-toolchain.sh --self-test   (key pinning checks)
#
# Ubuntu 24.04 (the CI runner): from the distribution; when its apt sources
# lack clang-20, the distribution clang/llvm with a warning (as before).
# Ubuntu 22.04 (the release container; the distribution has no clang-20):
# from apt.llvm.org (llvm-toolchain-jammy-20), whose archive key is checked
# against the pinned fingerprint below before apt trusts it, and only for
# that one source (signed-by): the keyring holds exactly that key
# (pinned_keyring), and apt preferences keep every other package of that
# archive at priority -1. No fallback there: the release must embed
# eBPF objects built with Pulsar's pinned major version.
#
# Rocky Linux 9 (the RPM build container): clang, lld, llvm from AppStream,
# whatever major version it carries (21 in 2026-10, one ahead of Pulsar's
# pin; a warning says so), plus sqlite-devel, openssl-devel, pkgconf.
#
# The eBPF objects' reproducibility is not claimed (docs/BUILD.md); the
# version used is printed for the build log.
# Runs apt through sudo, or directly as root (container jobs).
# Exit: 0 installed, 1 failed.
set -euo pipefail

LLVM_MAJOR=20
# apt.llvm.org archive key (Sylvestre Ledru - Debian LLVM packages),
# primary key fingerprint, checked 2026-10-30.
LLVM_APT_KEY_FPR=6084F3CF814B57C1CF12EFD515CF4D18AF4F7421
LLVM_APT_KEY_URL=https://apt.llvm.org/llvm-snapshot.gpg.key

as_root=()
[[ "$(id -u)" -eq 0 ]] || as_root=(sudo)
apt_install() {
    "${as_root[@]}" env DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends "$@"
}
# pinned_keyring IN.asc FPR OUT.gpg: OUT gets exactly one OpenPGP key, the
# one whose primary fingerprint is FPR, exported minimal from a throwaway
# GNUPGHOME. Fails when IN holds no key, more than one primary key, or
# another one: a second key in the downloaded file must never end up in
# the signed-by keyring (dearmoring the whole file would trust it).
pinned_keyring() {
    local in="$1" want="$2" out="$3" g n fpr
    g="$(mktemp -d)"
    if ! GNUPGHOME="$g" gpg --batch --quiet --import "$in" 2>/dev/null; then
        rm -rf "$g"
        echo "ci-install-ebpf-toolchain: FAIL: $in is not an OpenPGP key file" >&2
        return 1
    fi
    n="$(GNUPGHOME="$g" gpg --batch --with-colons --list-keys | awk -F: '$1 == "pub"' | wc -l)"
    fpr="$(GNUPGHOME="$g" gpg --batch --with-colons --list-keys |
        awk -F: '$1 == "pub" { p = 1; next } p && $1 == "fpr" { print $10; exit }')"
    if [[ "$n" -ne 1 || "$fpr" != "$want" ]]; then
        GNUPGHOME="$g" gpgconf --kill all 2>/dev/null || true
        rm -rf "$g"
        echo "ci-install-ebpf-toolchain: FAIL: $in holds $n primary key(s) (first $fpr), want exactly $want" >&2
        return 1
    fi
    GNUPGHOME="$g" gpg --batch --export --export-options export-minimal "$want" >"$out"
    GNUPGHOME="$g" gpgconf --kill all 2>/dev/null || true
    rm -rf "$g"
    [[ "$(gpg --batch --show-keys --with-colons "$out" | awk -F: '$1 == "pub"' | wc -l)" -eq 1 ]]
}

# apt preferences: apt.llvm.org at -1 except Pulsar's toolchain packages.
llvm_apt_preferences() {
    local m="$LLVM_MAJOR"
    cat <<PREF
# scripts/ci-install-ebpf-toolchain.sh: only the eBPF toolchain from apt.llvm.org.
Package: *
Pin: origin apt.llvm.org
Pin-Priority: -1

Package: clang-$m lld-$m llvm-$m llvm-$m-runtime llvm-$m-linker-tools llvm-$m-tools libllvm$m libclang-cpp$m libclang-common-$m-dev libclang1-$m liblld-$m
Pin: origin apt.llvm.org
Pin-Priority: 500
PREF
}

self_test() {
    local t g ok=0
    t="$(mktemp -d)"
    for n in pinned other; do
        g="$t/gpg-$n"
        mkdir -m 0700 "$g"
        GNUPGHOME="$g" gpg --batch --quiet --pinentry-mode loopback --passphrase '' \
            --quick-gen-key "$n <$n@example.invalid>" ed25519 sign never 2>/dev/null
        GNUPGHOME="$g" gpg --batch --armor --export >"$t/$n.asc"
        GNUPGHOME="$g" gpgconf --kill all 2>/dev/null || true
    done
    local pin other
    pin="$(gpg --batch --show-keys --with-colons "$t/pinned.asc" | awk -F: '$1 == "fpr" { print $10; exit }')"
    other="$(gpg --batch --show-keys --with-colons "$t/other.asc" | awk -F: '$1 == "fpr" { print $10; exit }')"
    cat "$t/pinned.asc" "$t/other.asc" >"$t/both.asc"
    cat "$t/other.asc" "$t/pinned.asc" >"$t/both2.asc"
    check() { # name expect(0 ok/1 refused) file fpr
        if pinned_keyring "$3" "$4" "$t/out.gpg" 2>/dev/null; then r=0; else r=1; fi
        if [[ "$r" == "$2" ]]; then ok=$((ok + 1)); else echo "self-test FAIL: $1" >&2; fi
    }
    check "the pinned key alone" 0 "$t/pinned.asc" "$pin"
    check "pinned + a second key" 1 "$t/both.asc" "$pin"
    check "a second key first" 1 "$t/both2.asc" "$pin"
    check "another key" 1 "$t/other.asc" "$pin"
    check "not a key" 1 /etc/hostname "$pin"
    pinned_keyring "$t/pinned.asc" "$pin" "$t/out.gpg"
    if gpg --batch --show-keys --with-colons "$t/out.gpg" | grep -q "$other"; then
        echo "self-test FAIL: keyring holds the other key" >&2
    else
        ok=$((ok + 1))
    fi
    LLVM_MAJOR=20 llvm_apt_preferences | grep -q '^Pin-Priority: -1$' && ok=$((ok + 1))
    rm -rf "$t"
    echo "self-test: $ok/7 passed"
    [[ $ok -eq 7 ]]
}
if [[ "${1:-}" == --self-test ]]; then
    self_test
    exit
fi

# shellcheck source=/dev/null
codename="$(. /etc/os-release && printf '%s' "${VERSION_CODENAME:-}")"

if ! command -v apt-get >/dev/null 2>&1; then
    "${as_root[@]}" dnf install -y --setopt=install_weak_deps=False clang lld llvm \
        sqlite-devel openssl-devel pkgconf-pkg-config
    major="$(clang --version | sed -n 's/.*clang version \([0-9]*\)\..*/\1/p' | head -n1)"
    if [[ "$major" != "$LLVM_MAJOR" ]]; then
        echo "::warning::eBPF objects built with clang $major from the distribution; Pulsar pins $LLVM_MAJOR"
    fi
    clang --version | head -n1
    llvm-strip --version | head -n2 | tail -n1
    exit 0
fi

"${as_root[@]}" apt-get update
case "$codename" in
jammy | bookworm)
    apt_install ca-certificates curl gnupg
    tmp="$(mktemp -d)"
    trap 'rm -rf "$tmp"' EXIT
    curl -fsSL --proto '=https' --tlsv1.2 -o "$tmp/key.asc" "$LLVM_APT_KEY_URL"
    pinned_keyring "$tmp/key.asc" "$LLVM_APT_KEY_FPR" "$tmp/llvm.gpg"
    "${as_root[@]}" install -D -m 0644 "$tmp/llvm.gpg" /usr/share/keyrings/robodr-apt-llvm.gpg
    echo "deb [signed-by=/usr/share/keyrings/robodr-apt-llvm.gpg] https://apt.llvm.org/$codename/ llvm-toolchain-$codename-$LLVM_MAJOR main" |
        "${as_root[@]}" tee /etc/apt/sources.list.d/robodr-apt-llvm.list >/dev/null
    # Only the toolchain packages may come from apt.llvm.org: everything
    # else from it is pinned to -1 (never installed or upgraded from there).
    llvm_apt_preferences | "${as_root[@]}" tee /etc/apt/preferences.d/robodr-apt-llvm >/dev/null
    "${as_root[@]}" apt-get update
    apt_install "clang-$LLVM_MAJOR" "lld-$LLVM_MAJOR" "llvm-$LLVM_MAJOR"
    ;;
*)
    if ! apt_install "clang-$LLVM_MAJOR" "lld-$LLVM_MAJOR" "llvm-$LLVM_MAJOR"; then
        echo "::warning::clang-$LLVM_MAJOR not available from the runner's apt sources; using the distribution clang/llvm (Pulsar pins $LLVM_MAJOR)"
        apt_install clang lld llvm
        LLVM_MAJOR=""
    fi
    ;;
esac
if [[ -n "$LLVM_MAJOR" ]]; then
    "${as_root[@]}" ln -sf "/usr/bin/clang-$LLVM_MAJOR" /usr/local/bin/clang
    "${as_root[@]}" ln -sf "/usr/bin/llvm-strip-$LLVM_MAJOR" /usr/local/bin/llvm-strip
fi
apt_install libssl-dev libsqlite3-dev pkg-config
clang --version | head -n1
llvm-strip --version | head -n2 | tail -n1
