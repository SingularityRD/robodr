#!/bin/sh
# Build the RoboDR sensor box disk image from a SIGNED offline bundle.
#
#   packaging/sensor-box/image/build-image.sh \
#       --bundle robodr-<V>-<arch>-offline.tar.gz \
#       --pubkey /etc/robodr-trust/robodr-release.pub \
#       [--expect-version V] [--out DIR] [--mkosi PATH]
#
# 1. Verifies the bundle with minisign against --pubkey (the release key you
#    received out of band; never one from the bundle or its download
#    location), BEFORE anything in it is extracted or read. There is no
#    "unsigned" switch. The signature's trusted comment (signed too) must
#    name the bundle's file name, as release.yml signs it ("robodr
#    <version> <file>", or minisign's default "file:<file>"), so a signed
#    older bundle renamed to look like a newer one is refused. With
#    --expect-version V it must be exactly "robodr V <file>": the release
#    you meant to build, not an older correctly signed one (downgrade).
#    The trusted comment is printed either way.
# 2. Extracts it into a private directory, checks its SHA256SUMS, and takes
#    exactly one robodr_<ver>_<arch>.deb (the standard package; this image
#    is Ubuntu 24.04).
# 3. Runs mkosi with that .deb (and its digest) as an extra tree; the
#    recipe's postinst checks the digest again and installs it.
#
# Needs: minisign, tar, sha256sum, mkosi >= 24 (and what mkosi needs to
# build an Ubuntu image: root or user namespaces, network access to an
# Ubuntu mirror or a local one). Exit 0 built, 1 failed, 2 usage.
set -eu
PATH=/usr/sbin:/usr/bin:/sbin:/bin:/usr/local/bin
export PATH
umask 077

here="$(cd "$(dirname "$0")" && pwd)"
bundle="" pubkey="" out="$PWD/dist/sensor-box" mkosi=mkosi version=""
while [ $# -gt 0 ]; do
    case "$1" in
    --bundle) bundle="$2"; shift 2 ;;
    --pubkey) pubkey="$2"; shift 2 ;;
    --expect-version) version="$2"; shift 2 ;;
    --out) out="$2"; shift 2 ;;
    --mkosi) mkosi="$2"; shift 2 ;;
    -h | --help) sed -n '2,/^set -eu/p' "$0" | sed '$d'; exit 0 ;;
    *) echo "build-image: unknown argument $1" >&2; exit 2 ;;
    esac
done
[ -n "$bundle" ] && [ -n "$pubkey" ] || { echo "build-image: --bundle and --pubkey are required" >&2; exit 2; }
[ -f "$bundle" ] || { echo "build-image: $bundle: no such file" >&2; exit 2; }
[ -f "$pubkey" ] || { echo "build-image: $pubkey: no such file" >&2; exit 2; }
[ -f "$bundle.minisig" ] || { echo "build-image: $bundle.minisig missing: only signed bundles are accepted" >&2; exit 1; }
# The trust anchor must not travel with what it verifies.
bdir="$(cd "$(dirname "$bundle")" && pwd)"
kdir="$(cd "$(dirname "$pubkey")" && pwd)"
if [ "$bdir" = "$kdir" ]; then
    echo "build-image: --pubkey sits next to the bundle; use the release key you hold out of band" >&2
    exit 1
fi
command -v minisign >/dev/null || { echo "build-image: minisign not found" >&2; exit 1; }
case "$version" in
*[!A-Za-z0-9.+~_-]*) echo "build-image: --expect-version $version: not a version" >&2; exit 2 ;;
esac

# 1. Signature (and its signed trusted comment), before anything is
# extracted.
name="$(basename "$bundle")"
tc="$(minisign -VQ -p "$pubkey" -m "$bundle")" || { echo "build-image: signature check FAILED for $bundle" >&2; exit 1; }
tc="$(printf '%s\n' "$tc" | head -n 1)"
named=0
set -f
for w in $(printf '%s' "$tc" | tr '\t' ' '); do
    case "$w" in "$name" | "file:$name") named=1 ;; esac
done
set +f
[ "$named" -eq 1 ] || { echo "build-image: REFUSED: the signature of $name is valid but its trusted comment ('$tc') names another file" >&2; exit 1; }
if [ -n "$version" ] && [ "$tc" != "robodr $version $name" ]; then
    echo "build-image: REFUSED: trusted comment '$tc' is not 'robodr $version $name' (--expect-version): another release than the one expected" >&2
    exit 1
fi
echo "build-image: signature OK ($name; trusted comment: $tc)"

# 2. Private extraction and checksums.
work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT INT TERM
tar --no-same-owner --no-same-permissions -xzf "$bundle" -C "$work"
set -- "$work"/*/
[ "$#" -eq 1 ] && [ -d "$1" ] || { echo "build-image: unexpected bundle layout" >&2; exit 1; }
top="${1%/}"
(cd "$top" && sha256sum -c --quiet SHA256SUMS) || { echo "build-image: SHA256SUMS check FAILED" >&2; exit 1; }
set -- "$top"/robodr_*.deb
[ "$#" -eq 1 ] && [ -f "$1" ] || { echo "build-image: expected exactly one robodr_*.deb (the standard package) in the bundle" >&2; exit 1; }
deb="$1"
case "$(basename "$deb")" in
*_amd64.deb) arch=x86-64 ;;
*_arm64.deb) arch=arm64 ;;
*) echo "build-image: unsupported architecture in $(basename "$deb")" >&2; exit 1 ;;
esac

# 3. The verified package as an extra tree, with its digest.
extra="$work/extra"
mkdir -p "$extra/var/cache/robodr-image" "$extra/usr/share/doc/robodr/sensor-box-image"
cp "$deb" "$extra/var/cache/robodr-image/"
(cd "$extra/var/cache/robodr-image" && sha256sum "$(basename "$deb")" >robodr.deb.sha256)
cp "$here/README.md" "$extra/usr/share/doc/robodr/sensor-box-image/README.md"
chmod -R u=rwX,go=rX "$extra"
mkdir -p "$out"
"$mkosi" -C "$here" --architecture="$arch" --extra-tree="$extra" --output-dir="$out" build
echo "build-image: built $(ls "$out"/robodr-sensor-box* | head -n 1) from $(basename "$deb")"
