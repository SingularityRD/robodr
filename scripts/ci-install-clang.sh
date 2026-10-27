#!/usr/bin/env bash
# Install the pinned clang (scripts/c-toolchain.sh) from the Ubuntu 24.04
# archive with an exact apt version, hold it, and check it. CI and release
# jobs call this; it fails rather than install anything else.
#
#   scripts/ci-install-clang.sh
#
# Exit: 0 installed and checked, 1 failed.
set -euo pipefail
here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=scripts/c-toolchain.sh disable=SC1091
. "$here/c-toolchain.sh"

current="$(dpkg-query -W -f='${Version}' "$ROBODR_CLANG_APT_PACKAGE" 2>/dev/null || true)"
if [[ "$current" != "$ROBODR_CLANG_APT_VERSION" ]]; then
    sudo apt-get update
    # Exact version (a newer stable update of the package is replaced by
    # the pin: --allow-downgrades).
    sudo apt-get install -y --no-install-recommends --allow-downgrades \
        "$ROBODR_CLANG_APT_PACKAGE=$ROBODR_CLANG_APT_VERSION"
fi
sudo apt-mark hold "$ROBODR_CLANG_APT_PACKAGE" >/dev/null
installed="$(dpkg-query -W -f='${Version}' "$ROBODR_CLANG_APT_PACKAGE")"
if [[ "$installed" != "$ROBODR_CLANG_APT_VERSION" ]]; then
    echo "ci-install-clang: FAIL: $ROBODR_CLANG_APT_PACKAGE $installed installed, pinned $ROBODR_CLANG_APT_VERSION" >&2
    exit 1
fi
if ! robodr_clang_ok "$ROBODR_CLANG"; then
    echo "ci-install-clang: FAIL: $ROBODR_CLANG --version: $("$ROBODR_CLANG" --version | head -n1)" >&2
    exit 1
fi
"$ROBODR_CLANG" --version | head -n1
