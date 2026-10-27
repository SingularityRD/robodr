#!/bin/sh
# RoboDR offline install bundle: verify, install, upgrade, roll back.
# POSIX sh; needs only coreutils (sha256sum), tar, gzip, dpkg and, for
# signature checks, minisign. Runs on the air-gapped robot (or its entry
# station).
#
#   install-bundle.sh verify  [--pubkey robodr-release.pub --tarball T]
#   install-bundle.sh install [--pubkey robodr-release.pub --tarball T]
#                             [--allow-downgrade] [--accept-unreadable SEG]...
#   install-bundle.sh list                 (releases kept for rollback)
#   install-bundle.sh rollback <version>   (reinstall a kept release)
#   install-bundle.sh ring                 (SOC update-ring information)
#
# Options of install / rollback: --blackbox-dir DIR (repeatable; default
# /var/lib/robodr/blackbox and /var/lib/robodr/fleet/journal), the
# black-box directories whose segment format the release must read;
# --accept-unreadable SEG (repeatable), see the format gate below.
#
# Signed installation (--pubkey and --tarball). The tarball's minisign
# signature (<tarball>.minisig) is checked against the pinned release key;
# when the release's SHA256SUMS and SHA256SUMS.minisig lie next to the
# tarball, that signature is checked too and the tarball must be listed in
# it with its hash. The verified tarball is then extracted into a private
# directory (mktemp -d, 0700) and everything is checked and installed FROM
# THERE: nothing is taken from an already extracted directory. If this
# script itself runs from an extracted bundle directory, that directory
# must be identical to the signed tarball's content, otherwise it was
# modified after extraction and the run is REFUSED. The public key must
# come from your own trusted store, NEVER from the bundle, and this script
# must be a trusted copy: one extracted from a tarball whose signature you
# checked BEFORE extracting it (minisign -V), or the copy an earlier
# verified release installed as /usr/lib/robodr/install-bundle.sh
# (OPERATIONS.md section 3).
#
# verify   the signed checks above (with --pubkey and --tarball), or only
#          the SHA256SUMS of the directory this script runs from (a
#          warning says the signature was not checked).
# install  verify, then `dpkg -i` the .deb, and keep a copy of it under
#          /var/lib/robodr/releases/<version>/ for rollback. Services are not
#          enabled; on upgrade the running ones are restarted by dpkg.
#          Refuses to run without a signature check unless
#          ROBODR_ALLOW_UNSIGNED=1 (lab only; the bundle is then the
#          directory this script runs from).
# rollback reinstall a kept release (dpkg downgrade). Config files (conffiles)
#          and evidence are untouched; see OPERATIONS.md "Rollback".
#
# Downgrades and the security floor. `install` of a release older than the
# installed one is a downgrade and is REFUSED unless --allow-downgrade
# (rollback to a kept release is the usual way back). No install and no
# rollback ever goes below the unit's security floor
# (/var/lib/robodr/releases/security-floor): the highest minimum version
# ever seen in an installed bundle's `security-floor` file (inside the
# signed tarball) or in the SOC's signed ring information that
# robodr-enroll recorded (ring.env min_version). The floor only rises.
#
# Black-box format gate (install and rollback): every package states the
# black-box segment formats it writes and reads (/usr/share/robodr/formats,
# e.g. blackbox_read=RBF1:1; a release without the file is a legacy release
# that reads RBF1:1 only). Before dpkg runs, the first frame of every
# segment file in the black-box directories is read (magic + record format
# version). A segment in a recognised format (RBF1:<v>) the release cannot
# read REFUSES the release, with the segment named: it could neither verify
# nor extend that evidence. Export and archive the chain first
# (OPERATIONS.md 7), or install a release that reads it, or accept that
# exact segment with --accept-unreadable SEG. A file that does not start
# with a RoboDR frame (damaged, or not RoboDR's) is reported and does not
# block. Only segment files (seg-*.rbb) are judged: the other state
# journals on the unit (robodr-executor-journal/v1 under
# /var/lib/robodr/executor, robodr-cp-journal/v1 and the RBBXBND1 evidence
# exports under /var/lib/robodr/control-plane, the gateway's and
# robodr-enroll's JSON state, quarantined damaged-seg*.rbb copies) are not
# black-box chains and are neither gated nor reported; each daemon checks
# its own journal's format when it opens it.
#
# Ring information (Sprint 9): if robodr-enroll recorded the SOC's
# update-ring information (/var/lib/robodr/fleet/ring.env), install and
# ring print it. Apart from its minimum version (the security floor) it is
# information only: nothing here is triggered by it.
#
# ROBODR_ROOT=DIR (staging and the packaging test only) prefixes every
# path and runs dpkg with --root=DIR (its own dpkg database under DIR).
#
# Exit: 0 ok, 1 verification failed or refused, 2 usage or environment error.
set -eu

here=$(cd "$(dirname "$0")" && pwd)
root=${ROBODR_ROOT:-}
releases=$root/var/lib/robodr/releases
floor_file=$releases/security-floor
ring_env=$root/var/lib/robodr/fleet/ring.env
# Formats of a release without /usr/share/robodr/formats (every release
# before the file existed wrote and read record format 1 only).
legacy_read="RBF1:1"
nl='
'
stage=""
# Temporary formats file of install / rollback (removed on every exit path).
fmt=""

die() { echo "install-bundle: $2" >&2; exit "$1"; }

cleanup() {
    if [ -n "$stage" ]; then rm -rf "$stage"; fi
    if [ -n "$fmt" ]; then rm -f "$fmt"; fi
}
trap cleanup EXIT
trap 'exit 130' INT TERM

need_root() {
    [ "$(id -u)" -eq 0 ] || die 2 "must run as root"
}

# A Debian or upstream version: 1-64 of [0-9A-Za-z.+~-], starting with a
# digit (never a path, never a pattern).
valid_version() {
    case "$1" in '' | *[!0-9A-Za-z.+~-]*) return 1 ;; [0-9]*) ;; *) return 1 ;; esac
    [ "${#1}" -le 64 ]
}

# A plain absolute or relative path without white space or glob characters.
valid_path() {
    case "$1" in '' | *[[:space:]]* | *[*?[]*) return 1 ;; esac
}

verify_sig() { # pubkey file
    command -v minisign >/dev/null 2>&1 || die 2 "minisign not installed; cannot check the signature"
    [ -f "$1" ] || die 2 "public key $1 not found"
    [ -f "$2" ] || die 2 "$2 not found"
    [ -f "$2.minisig" ] || die 1 "signature $2.minisig not found"
    minisign -V -q -p "$1" -m "$2" || die 1 "SIGNATURE CHECK FAILED for $2"
    echo "install-bundle: signature OK ($2)"
}

# The release's SHA256SUMS next to the tarball, if it is shipped signed.
verify_release_sums() { # pubkey tarball
    s=$(dirname "$2")/SHA256SUMS
    if [ -f "$s.minisig" ]; then
        [ -f "$s" ] || die 1 "$s.minisig without $s"
        verify_sig "$1" "$s"
        want=$(awk -v f="$(basename "$2")" '{ h = $1; sub(/^[0-9a-f]+ [ *]/, "") } $0 == f { print h; exit }' "$s")
        [ -n "$want" ] || die 1 "$(basename "$2") is not listed in the signed $s"
        [ "$(sha256sum "$2" | cut -d' ' -f1)" = "$want" ] ||
            die 1 "CHECKSUM MISMATCH: $2 is not the tarball the signed $s lists"
        echo "install-bundle: the tarball is listed in the signed release SHA256SUMS"
    elif [ -f "$s" ]; then
        echo "install-bundle: note: $s has no SHA256SUMS.minisig next to it; not used"
    fi
}

# Whether every file of DIR is listed in DIR/SHA256SUMS with its hash and
# nothing else is there. Prints what is wrong.
sums_ok() { # dir
    [ -f "$1/SHA256SUMS" ] || { echo "SHA256SUMS missing in $1"; return 1; }
    (cd "$1" && sha256sum --strict --quiet -c SHA256SUMS >/dev/null 2>&1) ||
        { echo "CHECKSUM MISMATCH in $1"; return 1; }
    extra=$(cd "$1" && find . ! -type d ! -name SHA256SUMS | sed 's|^\./||' | LC_ALL=C sort |
        while IFS= read -r f; do
            awk -v f="$f" '{ sub(/^[0-9a-f]+ [ *]/, "") } $0 == f { found = 1 } END { exit !found }' \
                SHA256SUMS || echo "$f"
        done)
    [ -z "$extra" ] || { echo "files not covered by SHA256SUMS in $1: $extra"; return 1; }
}

verify_sums() { # dir
    why=$(sums_ok "$1") || die 1 "$why"
    echo "install-bundle: checksums OK"
}

# Extract the verified tarball into a private directory; sets $bundle.
stage_tarball() { # tarball
    stage=$(mktemp -d "${TMPDIR:-/tmp}/robodr-bundle.XXXXXXXX") || die 2 "mktemp failed"
    chmod 0700 "$stage"
    tops=$(tar -tzf "$1" | sed 's|^\./||; s|/.*||' | LC_ALL=C sort -u) ||
        die 1 "$1 is not a readable tar.gz"
    case "$tops" in
    *"$nl"* | '' | . | .. | *[!A-Za-z0-9._+~-]*)
        die 1 "$1 must hold exactly one top-level directory (found: $(echo "$tops" | tr '\n' ' '))"
        ;;
    esac
    tar -xzf "$1" -C "$stage" --no-same-owner || die 1 "extracting $1 failed"
    bundle=$stage/$tops
    if [ ! -d "$bundle" ] || [ -L "$bundle" ]; then die 1 "$1: $tops is not a directory"; fi
}

# The directory this script runs from, if it claims to be a bundle, must be
# the signed one (a trusted copy outside any bundle has no SHA256SUMS).
check_running_copy() { # bundle tarball
    [ -f "$here/SHA256SUMS" ] || return 0
    if ! cmp -s "$here/SHA256SUMS" "$1/SHA256SUMS" || ! sums_ok "$here" >/dev/null; then
        die 1 "REFUSED: $here (the directory this script runs from) differs from the signed tarball $2: it was modified after extraction. Extract the verified tarball again, or run a trusted copy of install-bundle.sh (OPERATIONS.md section 3)."
    fi
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
    printf '%s\n' "$bb_dirs" | while IFS= read -r d; do
        if [ -z "$d" ] || [ ! -d "$d" ]; then continue; fi
        find "$d" -type f -name 'seg-*.rbb' -size +8c | LC_ALL=C sort | while IFS= read -r f; do
            h=$(od -An -tx1 -N9 "$f" | tr -d ' \n')
            case "$h" in
            52424631????????*) echo "RBF1:$(printf '%d' "0x${h#????????????????}") $f" ;;
            *) echo "unknown:$(printf '%s' "$h" | cut -c1-8) $f" ;;
            esac
        done
    done
}

# Whether SEG was named by --accept-unreadable.
accepted() { # segment
    a=$(readlink -f "$1" 2>/dev/null || echo "$1")
    printf '%s\n' "$accept_unreadable" | while IFS= read -r x; do
        [ -n "$x" ] || continue
        if [ "$(readlink -f "$x" 2>/dev/null || echo "$x")" = "$a" ]; then
            echo yes
            break
        fi
    done
}

# Refuse a release that cannot read the black box on this unit.
check_formats() { # formats-file version
    reads=$(reads_of "$1")
    maxv=0
    set -f
    for r in $reads; do
        case "$r" in RBF1:*) v=${r#RBF1:}; [ "$v" -gt "$maxv" ] 2>/dev/null && maxv=$v ;; esac
    done
    set +f
    report=$(ondisk_formats | while read -r fmt seg; do
        case " $reads " in *" $fmt "*) continue ;; esac
        case "$fmt" in
        RBF1:*)
            if [ -n "$(accepted "$seg")" ]; then echo "ACCEPTED $fmt $seg"; else echo "BAD $fmt $seg"; fi
            ;;
        *) echo "UNKNOWN $fmt $seg" ;;
        esac
    done)
    printf '%s\n' "$report" | while read -r kind fmt seg; do
        case "$kind" in
        UNKNOWN) echo "install-bundle: WARNING: $seg is not a RoboDR black-box frame ($fmt): damaged, or not a RoboDR segment; the format gate cannot judge it and it does not block. Check it: robodr-blackbox verify $(dirname "$seg")" ;;
        ACCEPTED) echo "install-bundle: WARNING: $seg is $fmt, which $2 does not read; accepted by --accept-unreadable: $2 will neither verify nor extend it" ;;
        esac
    done
    bad=$(printf '%s\n' "$report" | sed -n 's/^BAD //p')
    if [ -n "$bad" ]; then
        first=$(echo "$bad" | head -n1)
        # (not $fmt: that is the caller's temporary formats file)
        badfmt=${first%% *}
        v=${badfmt#RBF1:}
        if [ "$v" -gt "$maxv" ] 2>/dev/null; then why="written by a newer release"; else why="a format this release does not read"; fi
        echo "install-bundle: REFUSED: release $2 reads black-box formats [$reads], but ${first#* } is $badfmt ($why; $(echo "$bad" | wc -l) segment(s) affected). $2 could neither verify nor extend this evidence. Export and archive the chain first (robodr-blackbox export; move the directory aside, OPERATIONS.md section 7), install a release that reads $badfmt, or accept that segment explicitly with --accept-unreadable PATH." >&2
        return 1
    fi
    echo "install-bundle: black-box formats OK for $2 (reads: $reads)"
}

# An upstream version (ring information) as a Debian version: a pre-release
# "-" sorts before the release with "~" (build-deb.sh).
deb_of() { echo "$1" | sed 's/-/~/'; }

# The recorded security floor (empty if none).
floor_now() {
    [ -f "$floor_file" ] || return 0
    f=$(sed -n 's/^min_version=//p' "$floor_file" | head -n1)
    valid_version "$f" || die 1 "$floor_file is malformed (min_version=$f); refusing to guess the security floor"
    echo "$f"
}

# Raise the recorded floor to VERSION if it is higher (never lowers it).
raise_floor() { # version source
    valid_version "$1" || die 1 "$2 names a malformed minimum version ($1)"
    cur=$(floor_now)
    if [ -z "$cur" ] || dpkg --compare-versions "$1" gt "$cur"; then
        install -d -m 0750 "$releases"
        printf 'min_version=%s\nsource=%s\n' "$1" "$2" >"$floor_file.tmp"
        mv "$floor_file.tmp" "$floor_file"
        echo "install-bundle: security floor raised to $1 ($2)"
    fi
}

# The ring information's minimum version raises the floor.
floor_from_ring() {
    [ -r "$ring_env" ] || return 0
    m=$(sed -n 's/^min_version=//p' "$ring_env")
    [ -z "$m" ] || raise_floor "$(deb_of "$m")" "SOC ring information (robodr-enroll)"
}

check_floor() { # version
    f=$(floor_now)
    if [ -n "$f" ] && dpkg --compare-versions "$1" lt "$f"; then
        die 1 "REFUSED: $1 is below this unit's security floor $f ($(sed -n 's/^source=//p' "$floor_file")): releases below it are known to be vulnerable. There is no override."
    fi
    echo "install-bundle: security floor ${f:-none}: $1 is allowed"
}

# Print the SOC ring information recorded by robodr-enroll (information only).
ring_note() { # [deb-version]
    [ -r "$ring_env" ] || return 0
    rv=$(sed -n 's/^ring=//p' "$ring_env")
    tv=$(sed -n 's/^target_version=//p' "$ring_env")
    mv_=$(sed -n 's/^min_version=//p' "$ring_env")
    st=$(sed -n 's/^stale=//p' "$ring_env")
    echo "install-bundle: SOC ring information (information only): ring ${rv:-?}, target ${tv:--}${mv_:+, minimum $mv_}${st:+, expired=$st}"
    if [ -n "${1:-}" ] && [ -n "$tv" ]; then
        up=${1%-*}
        if [ "$up" = "$(deb_of "$tv")" ]; then
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
find_deb() { # dir
    n=0
    for d in "$1"/robodr_*.deb "$1"/robodr-focal_*.deb; do
        [ -f "$d" ] || continue
        deb=$d
        n=$((n + 1))
    done
    [ "$n" -eq 1 ] || die 1 "expected exactly one robodr_*.deb or robodr-focal_*.deb in $1, found $n"
    pkg=$(dpkg-deb -f "$deb" Package)
    case "$pkg" in robodr | robodr-focal) ;; *) die 1 "unexpected package $pkg in $deb" ;; esac
}

pubkey=""
tarball=""
bb_dirs=""
accept_unreadable=""
allow_downgrade=0
cmd=${1:-}
[ -n "$cmd" ] || die 2 "usage: $0 verify|install|list|rollback|ring ..."
shift
version_arg=""
have_version=0
while [ $# -gt 0 ]; do
    case "$1" in
    --pubkey) [ $# -ge 2 ] || die 2 "--pubkey needs a value"; pubkey=$2; shift 2 ;;
    --tarball) [ $# -ge 2 ] || die 2 "--tarball needs a value"; tarball=$2; shift 2 ;;
    --blackbox-dir)
        [ $# -ge 2 ] || die 2 "--blackbox-dir needs a value"
        valid_path "$2" || die 2 "--blackbox-dir must be a directory without white space or glob characters"
        bb_dirs="$bb_dirs$nl$2"
        shift 2
        ;;
    --accept-unreadable)
        [ $# -ge 2 ] || die 2 "--accept-unreadable needs a segment path"
        valid_path "$2" || die 2 "--accept-unreadable must be a segment path without white space or glob characters"
        accept_unreadable="$accept_unreadable$nl$2"
        shift 2
        ;;
    --allow-downgrade) allow_downgrade=1; shift ;;
    -*) die 2 "unknown option $1" ;;
    *)
        [ "$have_version" -eq 0 ] || die 2 "unexpected argument $1"
        version_arg=$1
        have_version=1
        shift
        ;;
    esac
done
[ -n "$bb_dirs" ] || bb_dirs="$root/var/lib/robodr/blackbox$nl$root/var/lib/robodr/fleet/journal"

# Verify; sets $signed and $bundle (the directory to install from).
do_verify() {
    if [ -n "$pubkey" ] || [ -n "$tarball" ]; then
        if [ -z "$pubkey" ] || [ -z "$tarball" ]; then
            die 2 "--pubkey and --tarball go together"
        fi
        verify_sig "$pubkey" "$tarball"
        verify_release_sums "$pubkey" "$tarball"
        stage_tarball "$tarball"
        verify_sums "$bundle"
        check_running_copy "$bundle" "$tarball"
        signed=1
    else
        bundle=$here
        verify_sums "$bundle"
        signed=0
    fi
}

case "$cmd" in
verify)
    [ "$have_version" -eq 0 ] || die 2 "verify takes no version"
    do_verify
    [ "$signed" -eq 1 ] || echo "install-bundle: WARNING: signature not checked (give --pubkey and --tarball)"
    ;;
install)
    [ "$have_version" -eq 0 ] || die 2 "install takes no version"
    need_root
    do_verify
    if [ "$signed" -ne 1 ] && [ "${ROBODR_ALLOW_UNSIGNED:-0}" != 1 ]; then
        die 1 "refusing to install without a signature check (--pubkey/--tarball); ROBODR_ALLOW_UNSIGNED=1 for lab use"
    fi
    find_deb "$bundle"
    ver=$(dpkg-deb -f "$deb" Version)
    valid_version "$ver" || die 1 "the package version $ver is malformed"
    prev=""
    cur=""
    for p in robodr robodr-focal; do
        # shellcheck disable=SC2016 # dpkg-query format, not a shell expansion
        v=$(dpkg_query -W -f '${db:Status-Abbrev} ${Version}' "$p" 2>/dev/null || true)
        case "$v" in ii*) prev="$prev $p ${v##* }"; cur=${v##* } ;; esac
    done
    echo "install-bundle: installing $pkg $ver (currently installed:${prev:- none})"
    if [ -n "$cur" ] && dpkg --compare-versions "$ver" lt "$cur"; then
        if [ "$allow_downgrade" -ne 1 ]; then
            die 1 "REFUSED: $ver is older than the installed $cur: a downgrade (it may bring back fixed vulnerabilities). Roll back to a kept release (rollback), or pass --allow-downgrade if this downgrade is deliberate; neither goes below the security floor."
        fi
        echo "install-bundle: WARNING: downgrading from $cur to $ver (--allow-downgrade)"
    fi
    ring_note "$ver"
    floor_from_ring
    if [ -f "$bundle/security-floor" ]; then
        bf=$(sed -n 's/^min_version=//p' "$bundle/security-floor" | head -n1)
        [ -z "$bf" ] || raise_floor "$bf" "security-floor of the $ver bundle"
    fi
    check_floor "$ver"
    fmt=$(mktemp)
    deb_formats "$deb" >"$fmt"
    check_formats "$fmt" "$ver" || { rm -f "$fmt"; exit 1; }
    dpkg_ -i "$deb"
    install -d -m 0750 "$releases/$ver"
    # One package per kept version: the variant installed last (robodr and
    # robodr-focal share version numbers).
    rm -f "$releases/$ver"/robodr_*.deb "$releases/$ver"/robodr-focal_*.deb
    install -m 0644 "$deb" "$releases/$ver/"
    (cd "$bundle" && install -m 0644 SHA256SUMS "$releases/$ver/SHA256SUMS")
    if [ -s "$fmt" ]; then install -m 0644 "$fmt" "$releases/$ver/formats"; fi
    rm -f "$fmt"
    echo "install-bundle: kept $releases/$ver for rollback"
    ;;
list)
    [ -d "$releases" ] || die 1 "no releases kept in $releases"
    f=$(floor_now)
    echo "security floor: ${f:-none}"
    for d in "$releases"/*/; do
        [ -d "$d" ] || continue
        v=$(basename "$d")
        valid_version "$v" || continue
        if [ -f "$d/formats" ]; then r=$(reads_of "$d/formats"); else r="$legacy_read (legacy)"; fi
        below=""
        if [ -n "$f" ] && dpkg --compare-versions "$v" lt "$f"; then below="  (below the security floor)"; fi
        echo "$v  black-box formats read: $r$below"
    done
    ;;
ring)
    [ -r "$ring_env" ] || die 1 "no ring information recorded ($ring_env; robodr-enroll ring)"
    ring_note ""
    ;;
rollback)
    need_root
    [ "$have_version" -eq 1 ] || die 2 "rollback needs a version (see: $0 list)"
    valid_version "$version_arg" ||
        die 2 "rollback: $version_arg is not a version (1-64 of [0-9A-Za-z.+~-], starting with a digit; see: $0 list)"
    dir="$releases/$version_arg"
    if [ ! -d "$dir" ] || [ -L "$dir" ]; then die 1 "release $version_arg not kept in $releases"; fi
    (cd "$dir" && sha256sum --strict --quiet --ignore-missing -c SHA256SUMS) ||
        die 1 "kept release $version_arg fails its checksums"
    n=0
    for d in "$dir"/robodr_*.deb "$dir"/robodr-focal_*.deb; do
        [ -f "$d" ] || continue
        deb=$d
        n=$((n + 1))
    done
    [ "$n" -eq 1 ] || die 1 "expected exactly one .deb in $dir, found $n"
    [ "$(dpkg-deb -f "$deb" Version)" = "$version_arg" ] ||
        die 1 "the kept .deb in $dir is not version $version_arg"
    floor_from_ring
    check_floor "$version_arg"
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
