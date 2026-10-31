#!/usr/bin/env bash
# Run scripts/systemd-lifecycle.sh (install, enable --now, heartbeat,
# upgrade N-1 -> N, rollback, purge) in a container per distribution in
# which systemd is PID 1 (T10 of docs/SALES-READINESS.md). Runs on the CI
# runner (docker, privileged containers), native architecture.
#
#   scripts/systemd-lifecycle-matrix.sh OLD_DIR NEW_DIR
#
# OLD_DIR holds the N-1 packages, NEW_DIR the candidate's, each with
# robodr_<ver>_<arch>.deb and robodr-<ver>.<arch>.rpm:
#   .deb -> Debian 12, Ubuntu 22.04, Ubuntu 24.04
#   .rpm -> Rocky Linux 9
# Each base image (pinned by digest, the same as scripts/pkg-smoke-matrix.sh)
# gets systemd, python3 and procps installed and boots /sbin/init in a
# --privileged container with its own cgroup namespace. SELinux cannot be
# enforcing in a container: the AVC check of systemd-lifecycle.sh only runs
# in a Rocky / RHEL VM (docs/BUILD.md "Extended CI").
#
#   relabel-deb PKG VERSION OUT_DIR
#       write a copy of the .deb PKG with Version: VERSION (the N-1 stand-in
#       while no earlier release exists: same files, lower version, so the
#       maintainer scripts' upgrade and downgrade paths still run)
#
# Environment: ROBODR_SMOKE_REGISTRY_MIRROR, ROBODR_SMOKE_DOCKER_ARGS (as
# scripts/pkg-smoke-matrix.sh); ROBODR_LIFECYCLE_ONLY=<substring> runs only
# the matching rows; ROBODR_LIFECYCLE_NO_RPM_PREV=1 (set by the workflow
# only while no release exists) reports the Rocky row as NOT RUN, with a
# warning, when OLD_DIR has no .rpm. Exit: 0 every row passed, 1 one failed, 2 usage.
set -euo pipefail

here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

if [[ "${1:-}" == relabel-deb ]]; then
    pkg="${2:?relabel-deb PKG VERSION OUT_DIR}"
    ver="${3:?relabel-deb PKG VERSION OUT_DIR}"
    outdir="${4:?relabel-deb PKG VERSION OUT_DIR}"
    tmp="$(mktemp -d)"
    trap 'rm -rf "$tmp"' EXIT
    dpkg-deb -R "$pkg" "$tmp/root"
    sed -i "s/^Version: .*/Version: $ver/" "$tmp/root/DEBIAN/control"
    mkdir -p "$outdir"
    name="$(dpkg-deb -f "$pkg" Package)"
    arch="$(dpkg-deb -f "$pkg" Architecture)"
    dpkg-deb --root-owner-group -b "$tmp/root" "$outdir/${name}_${ver}_${arch}.deb" >/dev/null
    echo "$outdir/${name}_${ver}_${arch}.deb"
    exit 0
fi

olddir="${1:-}"
newdir="${2:-}"
[[ -d "$olddir" && -d "$newdir" ]] || { echo "usage: systemd-lifecycle-matrix.sh OLD_DIR NEW_DIR" >&2; exit 2; }
olddir="$(cd "$olddir" && pwd)"
newdir="$(cd "$newdir" && pwd)"
command -v docker >/dev/null || { echo "systemd-lifecycle-matrix: docker not found" >&2; exit 2; }

hub="${ROBODR_SMOKE_REGISTRY_MIRROR:-docker.io/library}"
DEBIAN_12="$hub/debian:12@sha256:d74df7598108a173a621eda4d58a2adbf850b2d9a9d81bc2cca1a6c21174a880"
UBUNTU_2204="$hub/ubuntu:22.04@sha256:076e7bf82319619f28dd0aa9c02ab34b055ad37100395b4f49a2ffba04fb5e11"
UBUNTU_2404="$hub/ubuntu:24.04@sha256:fe81560990fae86dc4743202b2cb4d3df98d0bcf949173cecef15ce1127ef852"
ROCKY_9="quay.io/rockylinux/rockylinux:9@sha256:8101994123cf3d0a8fee517bee7f39e555c7d92bd2d9eb3303cc988a0eeed00f"

one() { # dir pattern -> the single file
    local m=()
    mapfile -t m < <(cd "$1" && { compgen -G "$2" || true; })
    if [[ ${#m[@]} -ne 1 ]]; then
        echo "systemd-lifecycle-matrix: expected exactly one $2 in $1, found ${#m[@]}" >&2
        exit 1
    fi
    printf '%s\n' "${m[0]}"
}

# tag | base image | package pattern
matrix=(
    "debian12|$DEBIAN_12|robodr_*.deb"
    "ubuntu2204|$UBUNTU_2204|robodr_*.deb"
    "ubuntu2404|$UBUNTU_2404|robodr_*.deb"
    "rocky9|$ROCKY_9|robodr-[0-9]*.rpm"
)
read -r -a docker_args <<<"${ROBODR_SMOKE_DOCKER_ARGS:-}"
fail=0
summary=()
for row in "${matrix[@]}"; do
    IFS='|' read -r tag image pattern <<<"$row"
    if [[ -n "${ROBODR_LIFECYCLE_ONLY:-}" && "$tag" != *"$ROBODR_LIFECYCLE_ONLY"* ]]; then
        continue
    fi
    if [[ "$pattern" == *.rpm && "${ROBODR_LIFECYCLE_NO_RPM_PREV:-0}" == 1 ]] &&
        ! compgen -G "$olddir/$pattern" >/dev/null; then
        # No earlier release yet and no way to relabel an .rpm here: said
        # loudly, never silently (the workflow sets this only then).
        echo "::warning::systemd lifecycle: no N-1 .rpm (no earlier release): $tag not run"
        summary+=("NOT RUN $tag (no N-1 .rpm)")
        continue
    fi
    old="$(one "$olddir" "$pattern")"
    new="$(one "$newdir" "$pattern")"
    echo "::group::$tag: $old -> $new"
    img="robodr-lifecycle-$tag:local"
    ctx="$(mktemp -d)"
    case "$pattern" in
    *.deb)
        printf 'FROM %s\nRUN apt-get update && DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends systemd systemd-sysv dbus python3 procps util-linux ca-certificates && rm -f /etc/dpkg/dpkg.cfg.d/excludes\nSTOPSIGNAL SIGRTMIN+3\nCMD ["/sbin/init"]\n' "$image" >"$ctx/Dockerfile"
        ;;
    *)
        printf 'FROM %s\nRUN dnf install -y --setopt=install_weak_deps=False systemd python3 procps-ng util-linux && sed -i "/^tsflags=/d" /etc/dnf/dnf.conf\nSTOPSIGNAL SIGRTMIN+3\nCMD ["/sbin/init"]\n' "$image" >"$ctx/Dockerfile"
        ;;
    esac
    status=0
    docker build -q -t "$img" "$ctx" >/dev/null || status=1
    rm -rf "$ctx"
    name="robodr-lifecycle-$tag-$$"
    if [[ $status == 0 ]]; then
        docker run -d --name "$name" --privileged --cgroupns=private \
            --tmpfs /run --tmpfs /run/lock --tmpfs /tmp \
            "${docker_args[@]}" \
            -v "$here:/robodr-scripts:ro" -v "$olddir:/pkgs-old:ro" -v "$newdir:/pkgs-new:ro" \
            "$img" >/dev/null || status=1
    fi
    if [[ $status == 0 ]]; then
        # PID 1 up before the script asks for the boot state.
        for _ in $(seq 60); do
            docker exec "$name" test -d /run/systemd/system 2>/dev/null && break
            sleep 1
        done
        # Docker hands PID 1 a private root mount; on a booted host / is
        # shared, and systemd >= 254 moves each service's credentials
        # mount (LoadCredential=) out of a child namespace into
        # /run/credentials, which needs that propagation.
        docker exec "$name" mount --make-rshared / || status=1
        docker exec "$name" bash /robodr-scripts/systemd-lifecycle.sh "/pkgs-old/$old" "/pkgs-new/$new" || status=1
        if [[ $status != 0 ]]; then
            docker exec "$name" journalctl --no-pager -n 120 2>/dev/null || true
        fi
    fi
    docker rm -f "$name" >/dev/null 2>&1 || true
    echo "::endgroup::"
    if [[ $status == 0 ]]; then
        summary+=("PASS $tag")
    else
        summary+=("FAIL $tag")
        echo "::error::systemd lifecycle failed on $tag"
        fail=1
    fi
done
printf '%s\n' "${summary[@]}"
[[ ${#summary[@]} -gt 0 ]] || { echo "systemd-lifecycle-matrix: no row selected" >&2; exit 1; }
exit "$fail"
