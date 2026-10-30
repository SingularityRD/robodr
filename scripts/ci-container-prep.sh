#!/usr/bin/env bash
# Base packages of the release build containers (release.yml / ci.yml
# `container:` jobs), installed as root after actions/checkout:
#
#   scripts/ci-container-prep.sh
#
# Ubuntu 22.04 (robodr .deb): C toolchain and linker driver (gcc,
# binutils; ring's C goes through the pinned clang, ci-install-clang.sh),
# dpkg-dev (dpkg-shlibdeps for the Depends of the .deb), systemd (for
# scripts/deb-install-smoke.sh: systemd-analyze, -sysusers, -tmpfiles),
# python3, xz, file.
# Rocky Linux 9 (robodr .rpm): gcc, binutils, rpm-build (rpmbuild and
# rpm2archive), python3, xz, file.
# Both: git (already there for checkout), curl, ca-certificates, and the
# repository marked safe for git (the workspace belongs to the runner's
# uid, the container runs as root).
#
# Exit: 0 done, 1 failed.
set -euo pipefail
[[ "$(id -u)" -eq 0 ]] || { echo "ci-container-prep: run as root (container job)" >&2; exit 1; }

if command -v apt-get >/dev/null 2>&1; then
    export DEBIAN_FRONTEND=noninteractive
    apt-get update
    apt-get install -y --no-install-recommends ca-certificates curl git gnupg \
        build-essential binutils pkg-config dpkg-dev systemd python3 xz-utils file
elif command -v dnf >/dev/null 2>&1; then
    # /usr/bin/curl: curl-minimal of the image satisfies it (curl conflicts).
    dnf install -y --setopt=install_weak_deps=False ca-certificates /usr/bin/curl git \
        gcc binutils rpm-build python3 xz file findutils diffutils gzip which tar
else
    echo "ci-container-prep: neither apt-get nor dnf found" >&2
    exit 1
fi
if [[ -n "${GITHUB_WORKSPACE:-}" ]]; then
    git -C / config --global --add safe.directory "$GITHUB_WORKSPACE"
    git -C / config --global --add safe.directory "$GITHUB_WORKSPACE/vendor/pulsar"
fi
# shellcheck source=/dev/null
. /etc/os-release
echo "ci-container-prep: $PRETTY_NAME, $(ldd --version 2>&1 | head -n1)"
