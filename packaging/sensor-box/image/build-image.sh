#!/bin/sh
# Build the RoboDR sensor box disk image from a SIGNED offline bundle.
#
#   packaging/sensor-box/image/build-image.sh \
#       --bundle robodr-<V>-<arch>-offline.tar.gz \
#       --pubkey /etc/robodr-trust/robodr-release.pub \
#       [--out DIR] [--mkosi PATH]
#
# 1. Verifies the bundle with minisign against --pubkey (the release key you
#    received out of band; never one from the bundle or its download
#    location), BEFORE anything in it is extracted or read. There is no
#    "unsigned" switch.
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
bundle="" pubkey="" out="$PWD/dist/sensor-box" mkosi=mkosi
while [ $# -gt 0 ]; do
    case "$1" in
    --bundle) bundle="$2"; shift 2 ;;
    --pubkey) pubkey="$2"; shift 2 ;;
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

# 1. Signature, before anything is extracted.
minisign -Vq -p "$pubkey" -m "$bundle" || { echo "build-image: signature check FAILED for $bundle" >&2; exit 1; }

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
