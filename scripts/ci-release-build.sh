#!/usr/bin/env bash
# The release build of every packaged binary into target/release, exactly
# as release.yml does it (and the ci.yml package jobs, which build what
# the release builds): run after scripts/ci-setup.sh in the build userland
# (Ubuntu 22.04 for the .deb, Rocky Linux 9 for the .rpm).
#
#   scripts/ci-release-build.sh
#
#  * SOURCE_DATE_EPOCH = HEAD's commit time, --remap-path-prefix for the
#    checkout and CARGO_HOME, --locked (CARGO_LOCKED from ci-setup.sh).
#  * The pure workspace first, with ring compiled by the pinned clang of
#    this userland (scripts/c-toolchain.sh; fails if it is missing or
#    another version), in its own cargo invocation so feature unification
#    is exactly the one scripts/ci-repro.sh built: those binaries must equal
#    the reproduced ones.
#  * Then each Pulsar-bound member (robodr-pulsard and the crates it
#    links; PURE_EXCLUDES) without the ring pin: Pulsar's own clang builds
#    its eBPF objects (scripts/ci-install-ebpf-toolchain.sh); its
#    reproducibility is not claimed.
#
# Exit: 0 built, non-zero failed.
set -euo pipefail
here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$here/.."

export SOURCE_DATE_EPOCH="${SOURCE_DATE_EPOCH:-$(git log -1 --format=%ct)}"
export RUSTFLAGS="--remap-path-prefix=$PWD=/build/robodr --remap-path-prefix=${CARGO_HOME:-$HOME/.cargo}=/cargo"
# shellcheck source=scripts/c-toolchain.sh disable=SC1091
. scripts/c-toolchain.sh
host="$(rustc -vV | sed -n 's/^host: //p')"
robodr_pin_cc "$host" release
robodr_toolchain_report >&2
# Word lists exported by ci-setup.sh.
read -r -a excludes <<<"${PURE_EXCLUDES:-}"
read -r -a locked <<<"${CARGO_LOCKED:---locked}"
cargo build --release --workspace "${excludes[@]}" "${locked[@]}"
unset "CC_$(printf '%s' "$host" | tr '-' '_')"
pkgs=()
for w in "${excludes[@]}"; do
    [[ "$w" == --exclude ]] || pkgs+=("$w")
done
if [[ ${#pkgs[@]} -eq 0 ]]; then
    echo "ci-release-build: no Pulsar-bound members in PURE_EXCLUDES (run scripts/ci-setup.sh first)" >&2
    exit 1
fi
for p in "${pkgs[@]}"; do
    cargo build --release -p "$p" "${locked[@]}"
done
for b in target/release/robodr-*; do
    if [[ -f "$b" && -x "$b" ]]; then echo "ci-release-build: $b" >&2; fi
done
