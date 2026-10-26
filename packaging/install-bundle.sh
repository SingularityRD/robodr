#!/bin/sh
# RoboDR offline install bundle: verify, install, upgrade, roll back.
# POSIX sh; needs only coreutils (sha256sum), dpkg and, for signature
# checks, minisign. Runs on the air-gapped robot (or its entry station).
#
#   ./install-bundle.sh verify  [--pubkey robodr-release.pub] [--tarball T]
#   ./install-bundle.sh install [--pubkey robodr-release.pub] [--tarball T]
#   ./install-bundle.sh list                 (releases kept for rollback)
#   ./install-bundle.sh rollback <version>   (reinstall a kept release)
#
# verify   checks SHA256SUMS of the extracted bundle. With --pubkey and
#          --tarball it first checks the tarball's minisign signature
#          (<tarball>.minisig) against the pinned release key. The public key
#          must come from your own trusted store, NEVER from the bundle.
# install  verify, then `dpkg -i` the .deb, and keep a copy of it under
#          /var/lib/robodr/releases/<version>/ for rollback. Services are not
#          enabled; on upgrade the running ones are restarted by dpkg.
#          Refuses to run without a signature check unless
#          ROBODR_ALLOW_UNSIGNED=1 (lab only).
# rollback reinstall a kept release (dpkg downgrade). Config files (conffiles)
#          and evidence are untouched; see OPERATIONS.md "Rollback".
#
# Exit: 0 ok, 1 verification failed, 2 usage or environment error.
set -eu

here=$(cd "$(dirname "$0")" && pwd)
releases=/var/lib/robodr/releases

die() { echo "install-bundle: $2" >&2; exit "$1"; }

need_root() {
    [ "$(id -u)" -eq 0 ] || die 2 "must run as root"
}

verify_sig() { # pubkey tarball
    command -v minisign >/dev/null 2>&1 || die 2 "minisign not installed; cannot check the signature"
    [ -f "$1" ] || die 2 "public key $1 not found"
    [ -f "$2" ] || die 2 "tarball $2 not found"
    [ -f "$2.minisig" ] || die 1 "signature $2.minisig not found"
    minisign -V -q -p "$1" -m "$2" || die 1 "SIGNATURE CHECK FAILED for $2"
    echo "install-bundle: signature OK ($2)"
}

verify_sums() {
    [ -f "$here/SHA256SUMS" ] || die 1 "SHA256SUMS missing in $here"
    (cd "$here" && sha256sum --strict --quiet -c SHA256SUMS) || die 1 "CHECKSUM MISMATCH in $here"
    # Every file in the bundle must be listed (nothing smuggled in).
    extra=$(cd "$here" && find . -type f ! -name SHA256SUMS | sed 's|^\./||' | LC_ALL=C sort |
        while IFS= read -r f; do
            awk -v f="$f" '{ sub(/^[0-9a-f]+  /, "") } $0 == f { found = 1 } END { exit !found }' \
                SHA256SUMS || echo "$f"
        done)
    [ -z "$extra" ] || die 1 "files not covered by SHA256SUMS: $extra"
    echo "install-bundle: checksums OK"
}

# The bundle holds one package: robodr, or robodr-focal (static build for
# systemd 245 hosts). The two conflict; dpkg replaces one with the other.
find_deb() {
    n=0
    for d in "$here"/robodr_*.deb "$here"/robodr-focal_*.deb; do
        [ -f "$d" ] || continue
        deb=$d
        n=$((n + 1))
    done
    [ "$n" -eq 1 ] || die 1 "expected exactly one robodr_*.deb or robodr-focal_*.deb in $here, found $n"
    pkg=$(dpkg-deb -f "$deb" Package)
    case "$pkg" in robodr | robodr-focal) ;; *) die 1 "unexpected package $pkg in $deb" ;; esac
}

pubkey=""
tarball=""
cmd=${1:-}
[ -n "$cmd" ] || die 2 "usage: $0 verify|install|list|rollback ..."
shift
version_arg=""
while [ $# -gt 0 ]; do
    case "$1" in
    --pubkey) [ $# -ge 2 ] || die 2 "--pubkey needs a value"; pubkey=$2; shift 2 ;;
    --tarball) [ $# -ge 2 ] || die 2 "--tarball needs a value"; tarball=$2; shift 2 ;;
    -*) die 2 "unknown option $1" ;;
    *) version_arg=$1; shift ;;
    esac
done

do_verify() {
    if [ -n "$pubkey" ] || [ -n "$tarball" ]; then
        if [ -z "$pubkey" ] || [ -z "$tarball" ]; then
            die 2 "--pubkey and --tarball go together"
        fi
        verify_sig "$pubkey" "$tarball"
        signed=1
    else
        signed=0
    fi
    verify_sums
}

case "$cmd" in
verify)
    do_verify
    [ "$signed" -eq 1 ] || echo "install-bundle: WARNING: signature not checked (give --pubkey and --tarball)"
    ;;
install)
    need_root
    do_verify
    if [ "$signed" -ne 1 ] && [ "${ROBODR_ALLOW_UNSIGNED:-0}" != 1 ]; then
        die 1 "refusing to install without a signature check (--pubkey/--tarball); ROBODR_ALLOW_UNSIGNED=1 for lab use"
    fi
    find_deb
    ver=$(dpkg-deb -f "$deb" Version)
    prev=""
    for p in robodr robodr-focal; do
        v=$(dpkg-query -W -f '${db:Status-Abbrev} ${Version}' "$p" 2>/dev/null || true)
        case "$v" in ii*) prev="$prev $p ${v##* }" ;; esac
    done
    echo "install-bundle: installing $pkg $ver (currently installed:${prev:- none})"
    dpkg -i "$deb"
    install -d -m 0750 "$releases/$ver"
    # One package per kept version: the variant installed last (robodr and
    # robodr-focal share version numbers).
    rm -f "$releases/$ver"/robodr_*.deb "$releases/$ver"/robodr-focal_*.deb
    install -m 0644 "$deb" "$releases/$ver/"
    (cd "$here" && install -m 0644 SHA256SUMS "$releases/$ver/SHA256SUMS")
    echo "install-bundle: kept $releases/$ver for rollback"
    ;;
list)
    [ -d "$releases" ] || die 1 "no releases kept in $releases"
    ls -1 "$releases"
    ;;
rollback)
    need_root
    [ -n "$version_arg" ] || die 2 "rollback needs a version (see: $0 list)"
    dir="$releases/$version_arg"
    [ -d "$dir" ] || die 1 "release $version_arg not kept in $releases"
    (cd "$dir" && sha256sum --strict --quiet --ignore-missing -c SHA256SUMS) ||
        die 1 "kept release $version_arg fails its checksums"
    n=0
    for d in "$dir"/robodr_*.deb "$dir"/robodr-focal_*.deb; do
        [ -f "$d" ] || continue
        deb=$d
        n=$((n + 1))
    done
    [ "$n" -eq 1 ] || die 1 "expected exactly one .deb in $dir, found $n"
    echo "install-bundle: rolling back to $(dpkg-deb -f "$deb" Package) $version_arg"
    dpkg -i "$deb"
    ;;
*)
    die 2 "unknown command $cmd (verify|install|list|rollback)"
    ;;
esac
