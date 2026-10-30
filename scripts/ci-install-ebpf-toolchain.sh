#!/usr/bin/env bash
# Install Pulsar's build toolchain for robodr-pulsard (docs/BUILD.md
# "Pulsar / eBPF prerequisites"): clang-20, lld-20, llvm-20 with `clang`
# and `llvm-strip` on PATH (Pulsar's bpf-builder runs `clang -target bpf`
# and `llvm-strip`), plus libssl-dev, libsqlite3-dev and pkg-config.
#
#   scripts/ci-install-ebpf-toolchain.sh
#
# Ubuntu 24.04 (the CI runner): from the distribution; when its apt sources
# lack clang-20, the distribution clang/llvm with a warning (as before).
# Ubuntu 22.04 (the release container; the distribution has no clang-20):
# from apt.llvm.org (llvm-toolchain-jammy-20), whose archive key is checked
# against the pinned fingerprint below before apt trusts it, and only for
# that one source (signed-by). No fallback there: the release must embed
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
    fpr="$(gpg --batch --show-keys --with-colons "$tmp/key.asc" | awk -F: '$1 == "fpr" { print $10; exit }')"
    if [[ "$fpr" != "$LLVM_APT_KEY_FPR" ]]; then
        echo "ci-install-ebpf-toolchain: FAIL: apt.llvm.org key fingerprint $fpr, pinned $LLVM_APT_KEY_FPR" >&2
        exit 1
    fi
    gpg --batch --dearmor -o "$tmp/llvm.gpg" "$tmp/key.asc"
    "${as_root[@]}" install -D -m 0644 "$tmp/llvm.gpg" /usr/share/keyrings/robodr-apt-llvm.gpg
    echo "deb [signed-by=/usr/share/keyrings/robodr-apt-llvm.gpg] https://apt.llvm.org/$codename/ llvm-toolchain-$codename-$LLVM_MAJOR main" |
        "${as_root[@]}" tee /etc/apt/sources.list.d/robodr-apt-llvm.list >/dev/null
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
