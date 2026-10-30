#!/usr/bin/env bash
# Build the offline (air-gapped) install bundle for one architecture.
#
#   packaging/make-bundle.sh --deb dist/<package>_<v>_<arch>.deb \
#       [--sbom-dir dist/sbom] [--out dist]
#   packaging/make-bundle.sh --rpm dist/robodr-<v>-1.<x86_64|aarch64>.rpm \
#       [--sbom-dir dist/sbom] [--out dist]
#
# <package> is robodr, or robodr-focal for the static systemd-245 variant
# (packaging/build-deb.sh --variant focal), read from the .deb itself.
# Produces <package>-<version>-<arch>-offline.tar.gz containing:
#   <package>-<version>-<arch>/
#     <package>_<debver>_<arch>.deb
#     install-bundle.sh            (verify + install + rollback, POSIX sh)
#     security-floor               (min_version=<debver>: no install or
#                                   rollback below it, packaging/security-floor)
#     sbom/*.cdx.json              (CycloneDX, when --sbom-dir is given)
#     doc/OPERATIONS.md UNITREE.md SECURITY.md CHANGELOG.md
#         THIRD_PARTY_NOTICES GPL-2.0-SOURCE-OFFER licenses/*
#     SHA256SUMS                   (every file above, relative paths)
# With --rpm (RHEL / Rocky / Alma 9, Fedora; packaging/build-rpm.sh) the
# bundle is robodr-<version>-<arch>-rpm-offline.tar.gz (<arch> amd64 /
# arm64 as for the .deb, from the RPM's x86_64 / aarch64), with the .rpm in
# place of the .deb and the same install-bundle.sh, which installs it with
# rpm (signature check, downgrade refusal, security floor, black-box format
# gate and rollback exactly as for the .deb).
# The release workflow signs the tarball and SHA256SUMS separately
# (minisign); the bundle never carries the public key it is verified with:
# that key reaches the entry station out of band (OPERATIONS.md).
#
# Deterministic: sorted entries, root:root numeric owners, mtimes =
# SOURCE_DATE_EPOCH, no atime/ctime in PAX headers, gzip -n.
set -euo pipefail
# Directories and the SHA256SUMS file take their mode from the umask: a
# build under umask 000 (seen in containers) must not produce a
# world-writable bundle, and the tarball's bytes must not depend on it.
umask 022

here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
root="$(cd "$here/.." && pwd)"

deb=""
rpm_file=""
sbom_dir=""
out="dist"
while [[ $# -gt 0 ]]; do
    case "$1" in
    --deb) deb="$2"; shift 2 ;;
    --rpm) rpm_file="$2"; shift 2 ;;
    --sbom-dir) sbom_dir="$2"; shift 2 ;;
    --out) out="$2"; shift 2 ;;
    -h | --help) sed -n '2,/^set -euo/p' "$0" | sed '$d'; exit 0 ;;
    *) echo "make-bundle: unknown argument $1" >&2; exit 2 ;;
    esac
done
version="$(tr -d '[:space:]' <"$root/VERSION")"
if [[ -n "$deb" && -z "$rpm_file" ]]; then
    [[ -f "$deb" ]] || { echo "make-bundle: $deb not found" >&2; exit 2; }
    pkg_file="$deb"
    arch="$(dpkg-deb -f "$deb" Architecture)"
    package="$(dpkg-deb -f "$deb" Package)"
    case "$package" in robodr | robodr-focal) ;; *) echo "make-bundle: unexpected package $package" >&2; exit 2 ;; esac
    suffix=""
elif [[ -n "$rpm_file" && -z "$deb" ]]; then
    [[ -f "$rpm_file" ]] || { echo "make-bundle: $rpm_file not found" >&2; exit 2; }
    command -v rpm >/dev/null || { echo "make-bundle: rpm not found (needed to read $rpm_file)" >&2; exit 2; }
    pkg_file="$rpm_file"
    package="$(rpm -qp --nosignature --qf '%{NAME}' "$rpm_file")"
    [[ "$package" == robodr ]] || { echo "make-bundle: unexpected package $package" >&2; exit 2; }
    [[ "$(rpm -qp --nosignature --qf '%{EPOCHNUM}' "$rpm_file")" == 0 ]] ||
        { echo "make-bundle: $rpm_file has an RPM epoch; install-bundle.sh refuses it" >&2; exit 2; }
    case "$(rpm -qp --nosignature --qf '%{ARCH}' "$rpm_file")" in
    x86_64) arch=amd64 ;;
    aarch64) arch=arm64 ;;
    noarch) arch=all ;;
    *) echo "make-bundle: unsupported RPM architecture in $rpm_file" >&2; exit 2 ;;
    esac
    case "$(basename "$rpm_file")" in
    robodr-[0-9]*.rpm) ;;
    *)
        echo "make-bundle: the RPM must be named robodr-<version>-<release>.<arch>.rpm (install-bundle.sh looks for robodr-[0-9]*.rpm)" >&2
        exit 2
        ;;
    esac
    suffix="-rpm"
else
    echo "make-bundle: exactly one of --deb <file.deb> or --rpm <file.rpm> is required" >&2
    exit 2
fi
if [[ -z "${SOURCE_DATE_EPOCH:-}" ]]; then
    SOURCE_DATE_EPOCH="$(git -C "$root" log -1 --format=%ct 2>/dev/null || echo 0)"
fi

mkdir -p "$out"
out="$(cd "$out" && pwd)"
stage="$(mktemp -d)"
trap 'rm -rf "$stage"' EXIT
name="$package-$version-$arch$suffix"
b="$stage/$name"
mkdir -p "$b/doc"

install -m 0644 "$pkg_file" "$b/"
install -m 0755 "$here/install-bundle.sh" "$b/install-bundle.sh"
install -m 0644 "$here/security-floor" "$b/security-floor"
for f in docs/OPERATIONS.md docs/UNITREE.md SECURITY.md CHANGELOG.md; do
    [[ -f "$root/$f" ]] && install -m 0644 "$root/$f" "$b/doc/"
done
# Licences: the third-party notices, the eBPF source offer and the licence
# texts they refer to (scripts/third_party_notices.py; required, as in the
# package).
for f in THIRD_PARTY_NOTICES GPL-2.0-SOURCE-OFFER; do
    [[ -s "$root/$f" ]] || { echo "make-bundle: $f missing (python3 scripts/third_party_notices.py)" >&2; exit 1; }
    install -m 0644 "$root/$f" "$b/doc/"
done
mkdir -p "$b/doc/licenses"
install -m 0644 "$root"/LICENSES/* "$b/doc/licenses/"
if [[ -n "$sbom_dir" ]]; then
    mkdir -p "$b/sbom"
    find "$sbom_dir" -maxdepth 1 -type f -name '*.cdx.json' -exec install -m 0644 {} "$b/sbom/" \;
fi

# Hash into a file outside the tree being hashed, then move it in.
(cd "$b" && find . -type f -printf '%P\n' | LC_ALL=C sort |
    xargs -r -d '\n' sha256sum >"$stage/SHA256SUMS")
mv "$stage/SHA256SUMS" "$b/SHA256SUMS"

find "$b" -exec touch -h -d "@$SOURCE_DATE_EPOCH" {} +
tarball="$out/$name-offline.tar.gz"
tar --sort=name --owner=0 --group=0 --numeric-owner \
    --mtime="@$SOURCE_DATE_EPOCH" \
    --pax-option=exthdr.name=%d/PaxHeaders/%f,delete=atime,delete=ctime \
    -C "$stage" -cf - "$name" | gzip -9 -n >"$tarball"
echo "$tarball"
