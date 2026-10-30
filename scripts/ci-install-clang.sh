#!/usr/bin/env bash
# Install the pinned clang (scripts/c-toolchain.sh) of this build userland
# (Ubuntu 24.04 runner, the Ubuntu 22.04 or Rocky Linux 9 release
# container) with an exact apt / dnf version, together with the LLVM libraries that hold its code
# generator, hold them, and check them. CI and release jobs call this; it
# fails rather than install anything else.
#
#   scripts/ci-install-clang.sh
#
# Runs apt / dnf through sudo, or directly as root (container jobs have no sudo).
# Exit: 0 installed and checked, 1 failed.
set -euo pipefail
here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=scripts/c-toolchain.sh disable=SC1091
. "$here/c-toolchain.sh"

as_root=()
[[ "$(id -u)" -eq 0 ]] || as_root=(sudo)
pkgs=("$ROBODR_CLANG_APT_PACKAGE")
read -r -a also <<<"${ROBODR_CLANG_APT_ALSO:-}"
pkgs+=("${also[@]}")

if command -v dpkg-query >/dev/null 2>&1; then
    pkg_version() { dpkg-query -W -f='${Version}' "$1" 2>/dev/null || true; }
else
    # RPM userland (rocky9): ROBODR_CLANG_APT_VERSION is a version-release.
    pkg_version() { rpm -q --qf '%{VERSION}-%{RELEASE}' "$1" 2>/dev/null || true; }
fi

pinned_ok() {
    local p
    for p in "${pkgs[@]}"; do
        [[ "$(pkg_version "$p")" == "$ROBODR_CLANG_APT_VERSION" ]] || return 1
    done
}

if ! pinned_ok; then
    spec=()
    if command -v apt-get >/dev/null 2>&1; then
        "${as_root[@]}" apt-get update
        # Exact versions (a newer stable update is replaced by the pin:
        # --allow-downgrades). Packages that depend on the driver with "="
        # follow.
        for p in "${pkgs[@]}"; do spec+=("$p=$ROBODR_CLANG_APT_VERSION"); done
        "${as_root[@]}" env DEBIAN_FRONTEND=noninteractive apt-get install -y \
            --no-install-recommends --allow-downgrades "${spec[@]}"
    else
        for p in "${pkgs[@]}"; do spec+=("$p-$ROBODR_CLANG_APT_VERSION"); done
        "${as_root[@]}" dnf install -y --setopt=install_weak_deps=False "${spec[@]}"
    fi
fi
if command -v apt-mark >/dev/null 2>&1; then
    "${as_root[@]}" apt-mark hold "${pkgs[@]}" >/dev/null
fi
for p in "${pkgs[@]}"; do
    installed="$(pkg_version "$p")"
    if [[ "$installed" != "$ROBODR_CLANG_APT_VERSION" ]]; then
        echo "ci-install-clang: FAIL: $p ${installed:-(none)} installed, pinned $ROBODR_CLANG_APT_VERSION ($(robodr_build_userland))" >&2
        exit 1
    fi
done
if ! robodr_clang_ok "$ROBODR_CLANG"; then
    echo "ci-install-clang: FAIL: $ROBODR_CLANG --version: $("$ROBODR_CLANG" --version | head -n1)" >&2
    exit 1
fi
echo "ci-install-clang: $(robodr_build_userland): ${pkgs[*]} = $ROBODR_CLANG_APT_VERSION"
"$ROBODR_CLANG" --version | head -n1
