#!/bin/sh
# RoboDR offline install bundle: verify, install, upgrade, roll back.
# POSIX sh; needs only coreutils (sha256sum), dpkg and, for signature
# checks, minisign. Runs on the air-gapped robot (or its entry station).
#
#   ./install-bundle.sh verify  [--pubkey robodr-release.pub] [--tarball T]
#   ./install-bundle.sh install [--pubkey robodr-release.pub] [--tarball T]
#   ./install-bundle.sh list                 (releases kept for rollback)
#   ./install-bundle.sh rollback <version>   (reinstall a kept release)
#   ./install-bundle.sh ring                 (SOC update-ring information)
#
# Options of install / rollback: --blackbox-dir DIR (repeatable; default
# /var/lib/robodr/blackbox and /var/lib/robodr/fleet/journal), the
# black-box directories whose segment format the release must read.
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
# Black-box format gate (install and rollback): every package states the
# black-box segment formats it writes and reads (/usr/share/robodr/formats,
# e.g. blackbox_read=RBF1:1; a release without the file is a legacy release
# that reads RBF1:1 only). Before dpkg runs, the first frame of every
# segment file in the black-box directories is read (magic + record format
# version); a release that cannot read one of them is REFUSED with the
# segment named: it could neither verify nor extend that evidence. Export
# and archive the chain first (OPERATIONS.md 7), or install a release that
# reads it. There is no override.
#
# Ring information (Sprint 9): if robodr-enroll recorded the SOC's
# update-ring information (/var/lib/robodr/fleet/ring.env), install and
# ring print it. It is information only: nothing here is triggered by it.
#
# ROBODR_ROOT=DIR (staging and the packaging test only) prefixes every
# path and runs dpkg with --root=DIR (its own dpkg database under DIR).
#
# Exit: 0 ok, 1 verification failed or refused, 2 usage or environment error.
set -eu

here=$(cd "$(dirname "$0")" && pwd)
root=${ROBODR_ROOT:-}
releases=$root/var/lib/robodr/releases
ring_env=$root/var/lib/robodr/fleet/ring.env
# Formats of a release without /usr/share/robodr/formats (every release
# before the file existed wrote and read record format 1 only).
legacy_read="RBF1:1"

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

dpkg_() {
    if [ -n "$root" ]; then dpkg --root="$root" "$@"; else dpkg "$@"; fi
}

dpkg_query() {
    if [ -n "$root" ]; then dpkg-query --admindir="$root/var/lib/dpkg" "$@"; else dpkg-query "$@"; fi
}

# The formats file of a .deb on stdout (empty for a legacy release).
deb_formats() { # deb
    dpkg-deb --fsys-tarfile "$1" | tar -xOf - ./usr/share/robodr/formats 2>/dev/null || true
}

# The black-box formats a formats file says it reads.
reads_of() { # formats-file
    r=$(sed -n 's/^blackbox_read=//p' "$1" | tr ',' ' ')
    [ -n "$r" ] || r=$legacy_read
    echo "$r"
}

# "<format> <segment>" for the first frame of every segment file: RBF1:<v>,
# or unknown:<hex of the first 4 bytes> for another frame magic.
ondisk_formats() {
    for d in $bb_dirs; do
        [ -d "$d" ] || continue
        find "$d" -type f -name 'seg-*.rbb' -size +8c | LC_ALL=C sort | while IFS= read -r f; do
            h=$(od -An -tx1 -N9 "$f" | tr -d ' \n')
            case "$h" in
            52424631????????*) echo "RBF1:$(printf '%d' "0x${h#????????????????}") $f" ;;
            *) echo "unknown:$(printf '%s' "$h" | cut -c1-8) $f" ;;
            esac
        done
    done
}

# Refuse a release that cannot read the black box on this unit.
check_formats() { # formats-file version
    reads=$(reads_of "$1")
    bad=$(ondisk_formats | while read -r fmt seg; do
        case " $reads " in *" $fmt "*) ;; *) echo "$fmt $seg" ;; esac
    done)
    if [ -n "$bad" ]; then
        first=$(echo "$bad" | head -n1)
        echo "install-bundle: REFUSED: release $2 reads black-box formats [$reads], but ${first#* } is ${first%% *} (written by a newer release; $(echo "$bad" | wc -l) segment(s) affected). $2 could neither verify nor extend this evidence. Export and archive the chain first (robodr-blackbox export; move the directory aside, OPERATIONS.md section 7), or install a release that reads ${first%% *}." >&2
        return 1
    fi
    echo "install-bundle: black-box formats OK for $2 (reads: $reads)"
}

# Print the SOC ring information recorded by robodr-enroll (information only).
ring_note() { # [deb-version]
    [ -r "$ring_env" ] || return 0
    rv=$(sed -n 's/^ring=//p' "$ring_env")
    tv=$(sed -n 's/^target_version=//p' "$ring_env")
    st=$(sed -n 's/^stale=//p' "$ring_env")
    echo "install-bundle: SOC ring information (information only): ring ${rv:-?}, target ${tv:--}${st:+, expired=$st}"
    if [ -n "${1:-}" ] && [ -n "$tv" ]; then
        up=${1%-*}
        if [ "$up" = "$(echo "$tv" | sed 's/-/~/')" ]; then
            echo "install-bundle: this release matches the ring target"
        else
            echo "install-bundle: note: installing $1, the ring target is $tv (information only; installation proceeds)"
        fi
    fi
    bs=$(sed -n 's/^bundle_sha256=//p' "$ring_env")
    if [ -n "${tarball:-}" ] && [ -n "$bs" ] && [ -f "$tarball" ]; then
        if [ "$(sha256sum "$tarball" | cut -d' ' -f1)" = "$bs" ]; then
            echo "install-bundle: the tarball is the ring's bundle ($bs)"
        else
            echo "install-bundle: note: the tarball is not the ring's bundle $bs (information only)"
        fi
    fi
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
bb_dirs=""
cmd=${1:-}
[ -n "$cmd" ] || die 2 "usage: $0 verify|install|list|rollback|ring ..."
shift
version_arg=""
while [ $# -gt 0 ]; do
    case "$1" in
    --pubkey) [ $# -ge 2 ] || die 2 "--pubkey needs a value"; pubkey=$2; shift 2 ;;
    --tarball) [ $# -ge 2 ] || die 2 "--tarball needs a value"; tarball=$2; shift 2 ;;
    --blackbox-dir)
        [ $# -ge 2 ] || die 2 "--blackbox-dir needs a value"
        case "$2" in *[[:space:]]*) die 2 "--blackbox-dir must not contain white space" ;; esac
        bb_dirs="$bb_dirs $2"
        shift 2
        ;;
    -*) die 2 "unknown option $1" ;;
    *) version_arg=$1; shift ;;
    esac
done
[ -n "$bb_dirs" ] || bb_dirs="$root/var/lib/robodr/blackbox $root/var/lib/robodr/fleet/journal"

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
        # shellcheck disable=SC2016 # dpkg-query format, not a shell expansion
        v=$(dpkg_query -W -f '${db:Status-Abbrev} ${Version}' "$p" 2>/dev/null || true)
        case "$v" in ii*) prev="$prev $p ${v##* }" ;; esac
    done
    echo "install-bundle: installing $pkg $ver (currently installed:${prev:- none})"
    ring_note "$ver"
    fmt=$(mktemp)
    deb_formats "$deb" >"$fmt"
    check_formats "$fmt" "$ver" || { rm -f "$fmt"; exit 1; }
    dpkg_ -i "$deb"
    install -d -m 0750 "$releases/$ver"
    # One package per kept version: the variant installed last (robodr and
    # robodr-focal share version numbers).
    rm -f "$releases/$ver"/robodr_*.deb "$releases/$ver"/robodr-focal_*.deb
    install -m 0644 "$deb" "$releases/$ver/"
    (cd "$here" && install -m 0644 SHA256SUMS "$releases/$ver/SHA256SUMS")
    if [ -s "$fmt" ]; then install -m 0644 "$fmt" "$releases/$ver/formats"; fi
    rm -f "$fmt"
    echo "install-bundle: kept $releases/$ver for rollback"
    ;;
list)
    [ -d "$releases" ] || die 1 "no releases kept in $releases"
    for d in "$releases"/*/; do
        [ -d "$d" ] || continue
        v=$(basename "$d")
        if [ -f "$d/formats" ]; then r=$(reads_of "$d/formats"); else r="$legacy_read (legacy)"; fi
        echo "$v  black-box formats read: $r"
    done
    ;;
ring)
    [ -r "$ring_env" ] || die 1 "no ring information recorded ($ring_env; robodr-enroll ring)"
    ring_note ""
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
    fmt=$(mktemp)
    if [ -f "$dir/formats" ]; then cp "$dir/formats" "$fmt"; else deb_formats "$deb" >"$fmt"; fi
    check_formats "$fmt" "$version_arg" || { rm -f "$fmt"; exit 1; }
    rm -f "$fmt"
    echo "install-bundle: rolling back to $(dpkg-deb -f "$deb" Package) $version_arg"
    dpkg_ -i "$deb"
    ;;
*)
    die 2 "unknown command $cmd (verify|install|list|rollback|ring)"
    ;;
esac
