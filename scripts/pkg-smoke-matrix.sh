#!/usr/bin/env bash
# Install-smoke every package of one architecture in every target
# distribution it is for, each in a fresh container
# (scripts/pkg-install-smoke.sh does the checks inside; docs/BUILD.md
# "Package matrix"). Runs on the CI runner (docker), native architecture:
# the arm64 run is on the arm64 runner.
#
#   scripts/pkg-smoke-matrix.sh DIR
#
# DIR holds the packages of the runner's architecture:
#   robodr_<debver>_<arch>.deb        -> Debian 12, Ubuntu 22.04, Ubuntu 24.04
#   robodr-focal_<debver>_<arch>.deb  -> Ubuntu 20.04, Ubuntu 22.04
#   robodr-<ver>-1.<rpmarch>.rpm      -> Rocky Linux 9, Fedora 42
# A package type that is missing from DIR fails the run (no silent skip).
# Images are pinned by multi-arch index digest (resolved 2026-10-30 with
# `docker buildx imagetools inspect`); bump them deliberately.
#
# Environment (all optional; CI sets none):
#   ROBODR_SMOKE_REGISTRY_MIRROR  e.g. mirror.gcr.io/library: put in front of
#                     the Docker Hub images instead of docker.io/library (an
#                     air-gapped runner's registry or a pull-through cache);
#                     the digests are the same.
#   ROBODR_SMOKE_DOCKER_ARGS      extra `docker run` arguments (split on white
#                     space), e.g. "--network host -e https_proxy=..." for a
#                     host whose package mirrors are behind a proxy.
#   ROBODR_SMOKE_SETUP            a shell snippet sourced in each container
#                     before the smoke test (proxy / CA / mirror setup of the
#                     distribution's package manager), mounted read-only.
# Exit: 0 every combination passed, 1 one failed, 2 usage.
set -euo pipefail

here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
dir="${1:-}"
[[ -d "$dir" ]] || { echo "usage: pkg-smoke-matrix.sh DIR" >&2; exit 2; }
dir="$(cd "$dir" && pwd)"
command -v docker >/dev/null || { echo "pkg-smoke-matrix: docker not found" >&2; exit 2; }

hub="${ROBODR_SMOKE_REGISTRY_MIRROR:-docker.io/library}"
DEBIAN_12="$hub/debian:12@sha256:d74df7598108a173a621eda4d58a2adbf850b2d9a9d81bc2cca1a6c21174a880"
UBUNTU_2004="$hub/ubuntu:20.04@sha256:8feb4d8ca5354def3d8fce243717141ce31e2c428701f6682bd2fafe15388214"
UBUNTU_2204="$hub/ubuntu:22.04@sha256:076e7bf82319619f28dd0aa9c02ab34b055ad37100395b4f49a2ffba04fb5e11"
UBUNTU_2404="$hub/ubuntu:24.04@sha256:fe81560990fae86dc4743202b2cb4d3df98d0bcf949173cecef15ce1127ef852"
FEDORA_42="$hub/fedora:42@sha256:99e203b80b1c3d8f7e161ec10a68fd02b081ef83a3963553e513c82846b97814"
ROCKY_9="quay.io/rockylinux/rockylinux:9@sha256:8101994123cf3d0a8fee517bee7f39e555c7d92bd2d9eb3303cc988a0eeed00f"

one() { # pattern -> the single file in DIR
    local m=()
    mapfile -t m < <(cd "$dir" && { compgen -G "$1" || true; })
    if [[ ${#m[@]} -ne 1 ]]; then
        echo "pkg-smoke-matrix: expected exactly one $1 in $dir, found ${#m[@]}" >&2
        exit 1
    fi
    printf '%s\n' "${m[0]}"
}
deb="$(one 'robodr_*.deb')"
focal="$(one 'robodr-focal_*.deb')"
rpm="$(one 'robodr-*.rpm')"

# image | package | extra arguments
matrix=(
    "$DEBIAN_12|$deb|--pulsard"
    "$UBUNTU_2204|$deb|--pulsard"
    "$UBUNTU_2404|$deb|--pulsard"
    "$UBUNTU_2004|$focal|"
    "$UBUNTU_2204|$focal|"
    "$ROCKY_9|$rpm|--pulsard"
    "$FEDORA_42|$rpm|--pulsard"
)
read -r -a docker_args <<<"${ROBODR_SMOKE_DOCKER_ARGS:-}"
setup_mount=()
setup_cmd=""
if [[ -n "${ROBODR_SMOKE_SETUP:-}" ]]; then
    [[ -f "$ROBODR_SMOKE_SETUP" ]] || { echo "pkg-smoke-matrix: ROBODR_SMOKE_SETUP $ROBODR_SMOKE_SETUP is not a file" >&2; exit 2; }
    setup_mount=(-v "$(cd "$(dirname "$ROBODR_SMOKE_SETUP")" && pwd)/$(basename "$ROBODR_SMOKE_SETUP"):/smoke-setup.sh:ro")
    setup_cmd='. /smoke-setup.sh && '
fi
fail=0
summary=()
for row in "${matrix[@]}"; do
    IFS='|' read -r image pkg extra <<<"$row"
    name="${image##*/}"
    name="${name%%@*}"
    echo "::group::$name: $pkg"
    # Read-only mounts: the packages and the smoke script; the container is
    # thrown away (--rm), nothing is written back to the runner.
    # shellcheck disable=SC2086 # $extra is empty or one flag
    if docker run --rm --pull=missing "${docker_args[@]}" \
        -v "$dir:/pkgs:ro" -v "$here/pkg-install-smoke.sh:/pkg-install-smoke.sh:ro" \
        "${setup_mount[@]}" \
        "$image" bash -c "$setup_cmd"'bash /pkg-install-smoke.sh "$@"' smoke $extra "/pkgs/$pkg"; then
        summary+=("ok    $name  $pkg")
    else
        summary+=("FAIL  $name  $pkg")
        fail=1
    fi
    echo "::endgroup::"
done
printf '%s\n' "${summary[@]}"
exit "$fail"
