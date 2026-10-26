#!/usr/bin/env bash
# Build the offline (air-gapped) install bundle for one architecture.
#
#   packaging/make-bundle.sh --deb dist/<package>_<v>_<arch>.deb \
#       [--sbom-dir dist/sbom] [--out dist]
#
# <package> is robodr, or robodr-focal for the static systemd-245 variant
# (packaging/build-deb.sh --variant focal), read from the .deb itself.
# Produces <package>-<version>-<arch>-offline.tar.gz containing:
#   <package>-<version>-<arch>/
#     <package>_<debver>_<arch>.deb
#     install-bundle.sh            (verify + install + rollback, POSIX sh)
#     sbom/*.cdx.json              (CycloneDX, when --sbom-dir is given)
#     doc/OPERATIONS.md UNITREE.md SECURITY.md CHANGELOG.md
#     SHA256SUMS                   (every file above, relative paths)
# The release workflow signs the tarball and SHA256SUMS separately
# (minisign); the bundle never carries the public key it is verified with:
# that key reaches the entry station out of band (OPERATIONS.md).
#
# Deterministic: sorted entries, root:root numeric owners, mtimes =
# SOURCE_DATE_EPOCH, no atime/ctime in PAX headers, gzip -n.
set -euo pipefail

here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
root="$(cd "$here/.." && pwd)"

deb=""
sbom_dir=""
out="dist"
while [[ $# -gt 0 ]]; do
    case "$1" in
    --deb) deb="$2"; shift 2 ;;
    --sbom-dir) sbom_dir="$2"; shift 2 ;;
    --out) out="$2"; shift 2 ;;
    -h | --help) sed -n '2,/^set -euo/p' "$0" | sed '$d'; exit 0 ;;
    *) echo "make-bundle: unknown argument $1" >&2; exit 2 ;;
    esac
done
[[ -f "$deb" ]] || { echo "make-bundle: --deb <file.deb> is required" >&2; exit 2; }

version="$(tr -d '[:space:]' <"$root/VERSION")"
arch="$(dpkg-deb -f "$deb" Architecture)"
package="$(dpkg-deb -f "$deb" Package)"
case "$package" in robodr | robodr-focal) ;; *) echo "make-bundle: unexpected package $package" >&2; exit 2 ;; esac
if [[ -z "${SOURCE_DATE_EPOCH:-}" ]]; then
    SOURCE_DATE_EPOCH="$(git -C "$root" log -1 --format=%ct 2>/dev/null || echo 0)"
fi

mkdir -p "$out"
out="$(cd "$out" && pwd)"
stage="$(mktemp -d)"
trap 'rm -rf "$stage"' EXIT
name="$package-$version-$arch"
b="$stage/$name"
mkdir -p "$b/doc"

install -m 0644 "$deb" "$b/"
install -m 0755 "$here/install-bundle.sh" "$b/install-bundle.sh"
for f in docs/OPERATIONS.md docs/UNITREE.md SECURITY.md CHANGELOG.md; do
    [[ -f "$root/$f" ]] && install -m 0644 "$root/$f" "$b/doc/"
done
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
