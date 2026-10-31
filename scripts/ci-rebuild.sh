#!/usr/bin/env bash
# Independent rebuild of one release build job (release.yml, jobs rebuild-*),
# for `publish` to compare with the release before anything is signed.
#
#   scripts/ci-rebuild.sh deb|rpm|focal ARCH OUT [RELEASE_DIR]
#
# Run after scripts/ci-setup.sh, with the toolchain of
# scripts/ci-install-pinned-toolchain.sh on PATH (not the release job's
# rustup installation) and cargo-cyclonedx installed for deb / focal (their
# bundles carry the SBOM). Builds from the checkout exactly as the release
# job does (ci-release-build.sh or build-static.sh, build-deb.sh /
# build-rpm.sh, make-bundle.sh; SOURCE_DATE_EPOCH = the commit time) and
# writes into OUT:
#   the package and its offline bundle, named as the release job names them;
#   BINARIES-<kind>-<arch>.sha256  every robodr-* program this rebuild built,
#                                  robodr-pulsard included (deb, rpm);
#   PACKAGES-<kind>-<arch>.sha256  the package and the bundle.
#
# robodr-pulsard (Pulsar-bound, clang-built eBPF objects) is not proven to
# be reproducible: the .deb / .rpm are therefore packaged with the RELEASE
# job's robodr-pulsard, taken from its package in RELEASE_DIR, so every other
# byte of the packages is compared, while the rebuilt robodr-pulsard's own
# hash is in BINARIES-* and publish records in the signed
# REPRODUCIBILITY-<version>.txt whether it matched.
#
# Exit: 0 built, 1 build failed, 2 usage.
set -euo pipefail

[[ $# -ge 3 ]] || { echo "usage: $0 deb|rpm|focal ARCH OUT [RELEASE_DIR]" >&2; exit 2; }
kind="$1"
arch="$2"
out="$3"
rel="${4:-}"
here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$here/.."
case "$arch" in
amd64) gnu=x86_64; musl=x86_64-unknown-linux-musl; rpmarch=x86_64 ;;
arm64) gnu=aarch64; musl=aarch64-unknown-linux-musl; rpmarch=aarch64 ;;
*) echo "ci-rebuild: unknown arch $arch" >&2; exit 2 ;;
esac
: "$gnu"
export SOURCE_DATE_EPOCH="${SOURCE_DATE_EPOCH:-$(git log -1 --format=%ct)}"
mkdir -p "$out"
out="$(cd "$out" && pwd)"
tmp="$(mktemp -d)"
trap 'rm -rf "$tmp"' EXIT

case "$kind" in
deb | rpm)
    [[ -n "$rel" ]] || { echo "ci-rebuild: $kind needs RELEASE_DIR (for the release's robodr-pulsard)" >&2; exit 2; }
    scripts/ci-release-build.sh
    bins=target/release
    ;;
focal)
    scripts/build-static.sh "$musl" --out "dist/static/$musl"
    bins="dist/static/$musl"
    ;;
*) echo "ci-rebuild: unknown kind $kind" >&2; exit 2 ;;
esac

# What this rebuild built (pulsard included).
(cd "$bins" && find . -maxdepth 1 -type f -name 'robodr-*' -perm -u+x ! -name '*.d' -printf '%P\n' |
    LC_ALL=C sort | xargs -r -d '\n' sha256sum) >"$out/BINARIES-$kind-$arch.sha256"
test -s "$out/BINARIES-$kind-$arch.sha256"

# The programs to package: the rebuilt ones, robodr-pulsard from the release.
stage="$tmp/bin"
mkdir -p "$stage"
cp -p "$bins"/robodr-* "$stage/"
case "$kind" in
deb)
    relpkg="$(find "$rel" -maxdepth 1 -name "robodr_*_$arch.deb" | head -n1)"
    [[ -n "$relpkg" ]] || { echo "ci-rebuild: no release robodr_*_$arch.deb in $rel" >&2; exit 1; }
    dpkg-deb --fsys-tarfile "$relpkg" | tar -xOf - ./usr/sbin/robodr-pulsard >"$stage/robodr-pulsard"
    ;;
rpm)
    relpkg="$(find "$rel" -maxdepth 1 -name "robodr-*.$rpmarch.rpm" | head -n1)"
    [[ -n "$relpkg" ]] || { echo "ci-rebuild: no release robodr-*.$rpmarch.rpm in $rel" >&2; exit 1; }
    rpm2archive - <"$relpkg" | tar -xzOf - ./usr/sbin/robodr-pulsard >"$stage/robodr-pulsard"
    ;;
esac
chmod 0755 "$stage"/robodr-*

case "$kind" in
deb)
    SBOM_TOOL=cyclonedx scripts/sbom.sh dist/sbom
    deb="$(packaging/build-deb.sh --bin-dir "$stage" --arch "$arch" --out "$out")"
    packaging/make-bundle.sh --deb "$deb" --sbom-dir dist/sbom --out "$out" >/dev/null
    (cd "$out" && sha256sum robodr_*.deb robodr-*-offline.tar.gz) >"$out/PACKAGES-$kind-$arch.sha256"
    ;;
rpm)
    rpm="$(packaging/build-rpm.sh --bin-dir "$stage" --arch "$arch" --out "$out")"
    packaging/make-bundle.sh --rpm "$rpm" --out "$out" >/dev/null
    (cd "$out" && sha256sum robodr-*.rpm robodr-*-rpm-offline.tar.gz) >"$out/PACKAGES-$kind-$arch.sha256"
    ;;
focal)
    SBOM_TOOL=cyclonedx scripts/sbom.sh dist/sbom
    # As release.yml's robodr-focal job: robodr-focal does not ship
    # robodr-pulsard, so its SBOM is not in the bundle (the rebuild
    # comparison fails on a member present in one bundle only).
    rm -f dist/sbom/*robodr-pulsard*.cdx.json
    deb="$(packaging/build-deb.sh --variant focal --bin-dir "$stage" --arch "$arch" --out "$out")"
    packaging/make-bundle.sh --deb "$deb" --sbom-dir dist/sbom --out "$out" >/dev/null
    (cd "$out" && sha256sum robodr-focal*) >"$out/PACKAGES-$kind-$arch.sha256"
    ;;
esac
cat "$out/BINARIES-$kind-$arch.sha256" "$out/PACKAGES-$kind-$arch.sha256"
