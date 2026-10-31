#!/bin/sh
# RoboDR offline install bundle: verify, install, upgrade, roll back.
# POSIX sh; needs only coreutils (sha256sum), tar, gzip, the package
# manager (dpkg for a .deb bundle; rpm, and rpm2archive or rpm2cpio + cpio,
# for an RPM bundle) and, for signature checks, RoboDR's built-in verifier
# (robodr-deliverd verify-minisign, installed by every release since
# WP8a) or, before the first such release is installed, minisign. Runs on
# the air-gapped robot (or its entry station).
#
# Package formats: a bundle holds exactly one package, robodr_*.deb or
# robodr-focal_*.deb (Debian / Ubuntu / JetPack: dpkg) or robodr-*.rpm (RHEL /
# Rocky / Alma 9, Fedora: rpm -U, see "RPM hosts" below). Every check below
# (signature, private extraction, checksums, downgrade refusal, security
# floor, black-box format gate, kept releases, rollback) is the same for both.
#
#   install-bundle.sh verify  [--pubkey robodr-release.pub --tarball T]
#   install-bundle.sh install [--pubkey robodr-release.pub --tarball T]
#                             [--allow-downgrade] [--allow-variant-switch]
#                             [--accept-unreadable SEG]...
#                             [--allow-gateway-restart | --defer-restart]
#                             [--health-timeout SECS] [--no-auto-rollback]
#                             [--keep N]
#   install-bundle.sh list                 (releases kept for rollback)
#   install-bundle.sh rollback <version> [--allow-variant-switch]
#                             [--allow-gateway-restart | --defer-restart]
#                             [--health-timeout SECS]
#                                          (reinstall a kept release)
#   install-bundle.sh restart-pending [--allow-gateway-restart]
#                             [--health-timeout SECS]
#                                          (deferred gateway / executor restart)
#   install-bundle.sh prune --keep N       (drop older kept releases)
#   install-bundle.sh ring                 (SOC update-ring information)
#
# Options of install / rollback: --blackbox-dir DIR (repeatable; default
# /var/lib/robodr/blackbox and /var/lib/robodr/fleet/journal), the
# black-box directories whose segment format the release must read;
# --accept-unreadable SEG (repeatable), see the format gate below.
#
# Signature verifier (T51). When the installed release carries the
# built-in verifier (/usr/sbin/robodr-deliverd verify-minisign: RoboDR's
# own minisign implementation, robodr-pkg::minisign, installed from a
# release whose signature was checked), every signature is checked with
# it, after its known-answer self-test; otherwise with the minisign
# program. Once such a release is installed, ROBODR_ALLOW_UNSIGNED is
# REFUSED: the unit can check signatures, so it must. Sign lab builds
# with a lab key instead (minisign -G; --pubkey lab.pub).
#
# Signed installation (--pubkey and --tarball). The tarball's minisign
# signature (<tarball>.minisig) is checked against the pinned release key;
# when the release's SHA256SUMS and SHA256SUMS.minisig lie next to the
# tarball, that signature is checked too and the tarball must be listed in
# it with its hash. The tarball must be a regular file (no symlink, FIFO
# or device). It is COPIED ONCE, with its signature and the release's
# SHA256SUMS(.minisig), into a private directory (mktemp -d, 0700), and
# every check (signature, trusted comment, checksum, listing) and the
# extraction run on that private copy only: the file named by --tarball is
# never read again, so swapping it after the check (another process of the
# same user, removable media) cannot change what is installed. The
# signature's trusted comment must name the tarball's file name (release.yml
# signs with "robodr <version> <file>"; minisign's default comment
# "file:<file>" is accepted too): a signed bundle renamed to look like
# another one is refused. Everything is installed FROM THE PRIVATE
# EXTRACTION: nothing is taken from an already extracted directory. If this
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
# install  verify, then `dpkg -i` the .deb (`rpm -U` the .rpm), check the
#          unit's health and keep a copy of the package under
#          /var/lib/robodr/releases/<version>/ for rollback. Then runs
#          the installed release's host preflight (robodr-setup preflight:
#          BTF, bpffs, nf_tables, systemd, clock, disk, key directory) and
#          prints it. Advisory: a FAIL there is a warning, never a failed
#          install (the package is installed and healthy either way; the
#          host lacks something RoboDR's daemons need before they run).
#          Services are not enabled; on upgrade the running ones are restarted
#          by the package's maintainer scripts / scriptlets, except the
#          gateway and the executor (see "Safety-state gate").
#          Refuses to run without a signature check unless
#          ROBODR_ALLOW_UNSIGNED=1 (lab only, and only on a unit without
#          the built-in verifier; the bundle is then the directory this
#          script runs from).
# rollback reinstall a kept release (a dpkg downgrade, or `rpm -U
#          --oldpackage`). Config files (conffiles, %config(noreplace)) and
#          evidence are untouched; see OPERATIONS.md "Rollback".
#
# Safety-state gate (T9). Restarting robodr-firewall-gw drops the motion
# commands queued in it (fail_closed: the bridge refuses motion while it
# is down) and restarting robodr-executor drops its pending actions, so a
# package upgrade never restarts them unguarded: the maintainer scripts
# leave them running the old binaries and record them in
# /var/lib/robodr/pending-restart. install, rollback and restart-pending
# restart them only while the live safety state (agentd's status,
# `robodr-deliverd safety-state`, the same peer-checked read deliverd's
# own installs use) is idle or safe_state_active. If one of them is
# running and the state is anything else (moving, a human nearby, e-stop,
# unknown, no live safety feed configured), install and rollback are
# REFUSED before anything changes, unless:
#   --defer-restart          install now; the two keep running the old
#                            binaries until `restart-pending` (gated) or
#                            the next reboot;
#   --allow-gateway-restart  restart them anyway (deliberate: motion
#                            through the gateway is interrupted).
# The gate is decided before anything on the unit changes (before the
# security floor is raised, before dpkg / rpm). The state is checked again
# right before the restart (the upgrade takes time); if it closed meanwhile
# the restart is deferred. Not deferrable: a one-time migration that must
# stop the gateway (the gateway user split, upgrading from 0.1.0-alpha.1),
# and installing or rolling back to a package whose post-install script
# predates the gate (no gated_restart block: 0.1.0-alpha.1), which
# try-restarts the two itself; with the gate closed both are REFUSED
# unless --allow-gateway-restart, and with it open the state is read once
# more right before dpkg / rpm (refused if it closed meanwhile). A release
# below the security floor is refused before the gate is read. When the
# installed robodr-deliverd has no safety-state command (0.1.0-alpha.1),
# install reads the state with the robodr-deliverd of the package being
# installed, run as root from a copy in the private staging directory,
# after the checksum check and (with --pubkey) the signature check but
# before the floor and format gates; under ROBODR_ALLOW_UNSIGNED nothing
# was signature-checked. While the units wait, robodr-agentd reports
# robot.agent.restart_pending to the SOC from the pending-restart file.
#
# Health check and automatic rollback (T50). After install and rollback,
# every RoboDR unit that was active before must be active again (on two
# consecutive checks one second apart) and, if robodr-agentd was active,
# its heartbeat must be fresh, within --health-timeout seconds (default
# 120). If not, install reinstalls the release that was installed before
# (when it is kept under /var/lib/robodr/releases and allowed by the
# security floor and the format gate, and, for a release from before the
# gate, while the safety state allows its unconditional restart), checks
# health again, and exits 1; the failed release is not kept.
# --no-auto-rollback only reports. restart-pending checks health the same
# way after its restarts and exits 1 when unhealthy (no automatic
# rollback). `list` shows the units still waiting for a restart.
#
# Kept releases (T50). --keep N (install) or `prune --keep N` keeps the N
# newest kept releases and always the installed one; prune is REFUSED when
# neither dpkg nor rpm reports the installed version. The formats file of
# a pruned release is archived under releases/formats-archive, so the
# black-box format gate still knows what that release wrote.
#
# RPM hosts. The .rpm is installed with `rpm -U` (with --oldpackage and
# --replacepkgs: whether a downgrade or reinstall is allowed is decided
# here, by the same rules as for a .deb, before rpm runs), not with dnf: an
# air-gapped host has no repository to resolve from, and the package's
# dependencies (systemd, glibc, openssl-libs, sqlite-libs) are part of
# every supported base system. dnf notes the change in its history on its
# next run. Versions are compared with rpm's own algorithm (rpm.vercmp);
# the release and floor versions have the same form for both formats
# (<upstream with "-" as "~">-1). A package with an RPM epoch is refused
# (versions would no longer compare as written). A bundle of one format is
# refused on a host where robodr is installed through the other one.
#
# Variants. robodr and robodr-focal (.deb) conflict: installing one removes
# the other (robodr-focal has no robodr-pulsard). A signed bundle must hold
# the variant its signed file name names (robodr-focal-* holds
# robodr-focal, robodr-* holds robodr), and install / rollback REFUSE to
# replace the installed variant with the other one unless
# --allow-variant-switch is given.
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
# version). The segment files are writable by robodr-agentd, so a first
# frame is only a claim: it blocks only when it is VERIFIED, i.e. its
# format is one that a release installed on this unit writes, by records
# root keeps and agentd cannot write (blackbox_write= of the installed
# package's /usr/share/robodr/formats and of every kept release's formats
# file under /var/lib/robodr/releases; RBF1:1, the legacy format, always).
# A verified segment in a format the release cannot read REFUSES the
# release, with the segment named: it could neither verify nor extend that
# evidence. Export and archive the chain first (OPERATIONS.md 7), or
# install a release that reads it, or accept that exact segment with
# --accept-unreadable SEG. A segment claiming a format no release here
# ever wrote (forged, damaged, or carried over from another unit) is
# reported as UNKNOWN and does not block, nor does a file that does not
# start with a RoboDR frame: a compromised agentd cannot block updates by
# writing such a file. Only segment files (seg-*.rbb) are judged: the other state
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
# path and runs dpkg with --root=DIR (its own dpkg database under DIR), or
# rpm with --root DIR (its own rpm database under DIR, `rpm --root DIR
# --initdb` first).
#
# ROBODR_ROOT also prefixes /run/systemd/system: services are only
# looked at (systemctl from PATH) when DIR/run/systemd/system exists.
#
# Exit: 0 ok, 1 verification failed, refused or unhealthy (rolled back),
# 2 usage or environment error.
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
# The private copy of the signed tarball (set by stage_inputs).
tarcopy=""
# Temporary formats file of install / rollback (removed on every exit path).
fmt=""
# The built-in verifier and safety-state gate (robodr-deliverd of the
# installed release, root-owned, from a verified package).
deliverd_bin=$root/usr/sbin/robodr-deliverd
deliverd_cfg=$root/etc/robodr/deliverd.json
pending_file=$root/var/lib/robodr/pending-restart
# Every RoboDR unit the maintainer scripts restart, and the two of them a
# package upgrade restarts only through the safety-state gate.
all_units="robodr-pulsard.service robodr-agentd.service robodr-anchor-receiver.service
robodr-spool-export.service robodr-kafka-publish.service robodr-uplink.service
robodr-executor.service robodr-firewall-gw.service robodr-deliverd.service
robodr-depot.service"
gated_units="robodr-executor.service robodr-firewall-gw.service"

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

# Whether PATH is a regular file (not a symlink, FIFO, device or directory).
regular_file() { # path
    [ -f "$1" ] && [ ! -L "$1" ]
}

# Copy SRC once into the private staging directory as NAME; the copy must be
# a regular file (cp -RP copies a symlink or FIFO swapped in after the check
# as what it is, never through it, and the check below refuses it).
stage_copy() { # src name
    regular_file "$1" || die 1 "REFUSED: $1 is not a regular file (symlink, FIFO, device or directory)"
    cp -RP -- "$1" "$stage/in/$2" 2>/dev/null || die 1 "cannot copy $1"
    regular_file "$stage/in/$2" || die 1 "REFUSED: $1 changed while it was copied (no longer a regular file)"
    chmod 0600 "$stage/in/$2"
}

# The private staging directory (0700): in/ the copied inputs, x/ the
# extraction. Sets $stage.
make_stage() {
    stage=$(mktemp -d "${TMPDIR:-/tmp}/robodr-bundle.XXXXXXXX") || die 2 "mktemp failed"
    chmod 0700 "$stage"
    mkdir -m 0700 "$stage/in" "$stage/x"
}

# Copy the tarball, its signature and (if shipped signed) the release's
# SHA256SUMS next to it into the private directory, each read exactly once.
# Every later check reads the copies only. Sets $tname, $tarcopy and
# $sumscopy.
stage_inputs() { # tarball
    tname=$(basename "$1")
    case "$tname" in
    '' | . | .. | SHA256SUMS* | *[!A-Za-z0-9._+~-]*) die 1 "REFUSED: unexpected tarball file name '$tname'" ;;
    esac
    make_stage
    stage_copy "$1" "$tname"
    tarcopy=$stage/in/$tname
    if [ -e "$1.minisig" ] || [ -L "$1.minisig" ]; then
        stage_copy "$1.minisig" "$tname.minisig"
    fi
    sumscopy=""
    s=$(dirname "$1")/SHA256SUMS
    if [ -e "$s.minisig" ] || [ -L "$s.minisig" ]; then
        if [ ! -e "$s" ] && [ ! -L "$s" ]; then die 1 "$s.minisig without $s"; fi
        stage_copy "$s" SHA256SUMS
        stage_copy "$s.minisig" SHA256SUMS.minisig
        sumscopy=$stage/in/SHA256SUMS
    elif [ -e "$s" ]; then
        echo "install-bundle: note: $s has no SHA256SUMS.minisig next to it; not used"
    fi
}

# Check FILE (a private copy) against FILE.minisig with the pinned key, and
# that the signature's trusted comment names NAME: "robodr <version> NAME"
# (release.yml) or minisign's default "...file:NAME...". The comment is
# signed too (minisign -V checks the global signature over it), so a
# signed file renamed to pass for another one is refused.
verify_sig() { # pubkey file name
    [ -f "$1" ] || die 2 "public key $1 not found"
    [ -f "$2" ] || die 2 "$3 not found"
    [ -f "$2.minisig" ] || die 1 "signature $3.minisig not found"
    if builtin_verifier; then
        if [ "$selftest_done" -eq 0 ]; then
            "$deliverd_bin" verify-minisign --self-test >/dev/null 2>&1 ||
                die 2 "the built-in verifier ($deliverd_bin verify-minisign) fails its self-test; refusing to trust it"
            selftest_done=1
        fi
        tc=$("$deliverd_bin" verify-minisign --pubkey "$1" --file "$2" --sig "$2.minisig") ||
            die 1 "SIGNATURE CHECK FAILED for $3 (built-in verifier)"
        echo "install-bundle: verifier: built-in ($deliverd_bin verify-minisign)"
    else
        command -v minisign >/dev/null 2>&1 ||
            die 2 "no signature verifier: neither the built-in one ($deliverd_bin, installed with a release) nor minisign is available"
        tc=$(minisign -V -Q -p "$1" -m "$2" -x "$2.minisig") || die 1 "SIGNATURE CHECK FAILED for $3"
    fi
    ok_name=0
    set -f
    for w in $(printf '%s
' "$tc" | head -n1 | tr '	' ' '); do
        case "$w" in "$3" | "file:$3") ok_name=1 ;; esac
    done
    set +f
    [ "$ok_name" -eq 1 ] ||
        die 1 "REFUSED: the signature of $3 is valid but its trusted comment ('$tc') names another file: a signed file renamed to pass for $3"
    echo "install-bundle: signature OK ($3; trusted comment: $tc)"
}

# Whether the installed release carries the built-in verifier (a regular,
# root-owned executable that lists verify-minisign in its usage).
selftest_done=0
builtin_verifier() {
    regular_file "$deliverd_bin" && [ -x "$deliverd_bin" ] || return 1
    [ "$(stat -c %u "$deliverd_bin")" = 0 ] || return 1
    "$deliverd_bin" --help 2>/dev/null | grep -q 'verify-minisign'
}

# The release's SHA256SUMS next to the tarball, if it is shipped signed
# (both read from the private copies).
verify_release_sums() { # pubkey
    [ -n "$sumscopy" ] || return 0
    verify_sig "$1" "$sumscopy" SHA256SUMS
    want=$(awk -v f="$tname" '{ h = $1; sub(/^[0-9a-f]+ [ *]/, "") } $0 == f { print h; exit }' "$sumscopy")
    [ -n "$want" ] || die 1 "$tname is not listed in the signed release SHA256SUMS"
    [ "$(sha256sum "$tarcopy" | cut -d' ' -f1)" = "$want" ] ||
        die 1 "CHECKSUM MISMATCH: $tname is not the tarball the signed release SHA256SUMS lists"
    echo "install-bundle: the tarball is listed in the signed release SHA256SUMS"
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

# Extract the verified private copy into the private directory; sets $bundle.
stage_tarball() { # copy name
    tops=$(tar -tzf "$1" | sed 's|^\./||; s|/.*||' | LC_ALL=C sort -u) ||
        die 1 "$2 is not a readable tar.gz"
    case "$tops" in
    *"$nl"* | '' | . | .. | *[!A-Za-z0-9._+~-]*)
        die 1 "$2 must hold exactly one top-level directory (found: $(echo "$tops" | tr '\n' ' '))"
        ;;
    esac
    tar -xzf "$1" -C "$stage/x" --no-same-owner || die 1 "extracting $2 failed"
    bundle=$stage/x/$tops
    if [ ! -d "$bundle" ] || [ -L "$bundle" ]; then die 1 "$2: $tops is not a directory"; fi
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

rpm_() {
    if [ -n "$root" ]; then rpm --root "$root" "$@"; else rpm "$@"; fi
}

# Package format of a package file: deb or rpm (by its name, as find_pkg
# selected it).
format_of() { # file
    case "$1" in *.rpm) echo rpm ;; *) echo deb ;; esac
}

need_tool() { # format
    case "$1" in
    deb)
        if ! command -v dpkg >/dev/null 2>&1 || ! command -v dpkg-deb >/dev/null 2>&1; then
            die 2 "dpkg not found: a .deb bundle installs on Debian / Ubuntu hosts (RPM hosts take the robodr-<version>-<arch>-rpm-offline bundle)"
        fi
        ;;
    rpm)
        command -v rpm >/dev/null 2>&1 ||
            die 2 "rpm not found: an RPM bundle installs on RHEL / Rocky / Alma / Fedora hosts (Debian / Ubuntu hosts take the .deb bundle)"
        ;;
    esac
}

# Package name / version of a package file (Debian version form for both:
# <version>-<release> for an RPM, which has no epoch).
pkg_name() { # file
    case "$(format_of "$1")" in
    deb) dpkg-deb -f "$1" Package ;;
    rpm) rpm -qp --nosignature --qf '%{NAME}' "$1" 2>/dev/null ;;
    esac
}

pkg_version() { # file
    case "$(format_of "$1")" in
    deb) dpkg-deb -f "$1" Version ;;
    rpm)
        e=$(rpm -qp --nosignature --qf '%{EPOCHNUM}' "$1" 2>/dev/null) || die 1 "$1 is not a readable RPM"
        [ "$e" = 0 ] || die 1 "$1 carries RPM epoch $e; RoboDR packages have none (refused: versions would not compare as written)"
        rpm -qp --nosignature --qf '%{VERSION}-%{RELEASE}' "$1" 2>/dev/null
        ;;
    esac
}

# Whether version A is lower than B, by the package manager of $pkgfmt
# (dpkg on a .deb host, rpm.vercmp on an RPM host; both are validated
# versions, never shell text).
ver_lt() { # a b
    if [ "${pkgfmt:-deb}" = rpm ]; then
        [ "$(rpm --eval "%{lua: print(rpm.vercmp('$1', '$2'))}")" = -1 ]
    else
        dpkg --compare-versions "$1" lt "$2"
    fi
}

# The installed robodr packages: "<name> <version>" lines (none, or one).
# A package counts as installed in every dpkg state but not-installed and
# config-files: half-installed, unpacked, half-configured and
# triggers-awaiting/pending packages too (a failed or interrupted upgrade
# must not let the next install pass as a first install, skipping the
# downgrade and variant checks).
installed_pkgs() { # format
    case "$1" in
    deb)
        command -v dpkg-query >/dev/null 2>&1 || return 0
        for p in robodr robodr-focal; do
            # shellcheck disable=SC2016 # dpkg-query format, not a shell expansion
            v=$(dpkg_query -W -f '${db:Status-Abbrev} ${Version}' "$p" 2>/dev/null || true)
            case "$v" in
            '' | ?n* | ?c*) ;;
            *) echo "$p ${v##* }" ;;
            esac
        done
        ;;
    rpm)
        command -v rpm >/dev/null 2>&1 || return 0
        v=$(rpm_ -q --qf '%{VERSION}-%{RELEASE}\n' robodr 2>/dev/null) || return 0
        printf '%s\n' "$v" | sed -n '$s/^/robodr /p'
        ;;
    esac
}

# The installed robodr version on this host, whichever package manager
# holds it. Sets $inst (empty if none can be found) and $pkgfmt: the format
# of the manager that holds it (versions then compare by it), or, with
# nothing found, rpm on a host with rpm and no dpkg.
host_installed() {
    inst=""
    for hf in deb rpm; do
        inst=$(installed_pkgs "$hf" | sed -n '1s/^[^ ]* //p')
        if [ -n "$inst" ]; then
            pkgfmt=$hf
            return 0
        fi
    done
    if ! command -v dpkg >/dev/null 2>&1 && command -v rpm >/dev/null 2>&1; then pkgfmt=rpm; fi
}

# Refuse a package of one format where robodr is installed through the other.
check_other_format() { # format
    case "$1" in deb) o=rpm ;; *) o=deb ;; esac
    other=$(installed_pkgs "$o")
    [ -z "$other" ] || die 1 "REFUSED: robodr is installed here as an $o package ($(echo "$other" | tr '\n' ' ')); this bundle holds a $1 package. Use the $o bundle."
}

# The content of the file PATH (absolute) of a package file on stdout;
# returns 1 when the package does not carry it.
pkg_cat() { # file path
    case "$(format_of "$1")" in
    deb) dpkg-deb --fsys-tarfile "$1" | tar -xOf - ".$2" 2>/dev/null ;;
    rpm)
        rpm -qpl --nosignature "$1" 2>/dev/null | grep -qx "$2" || return 1
        if command -v rpm2archive >/dev/null 2>&1; then
            rpm2archive - <"$1" | tar -xzOf - ".$2" ||
                die 1 "cannot read $2 from $1"
        elif command -v rpm2cpio >/dev/null 2>&1 && command -v cpio >/dev/null 2>&1; then
            rpm2cpio "$1" | cpio --quiet -i --to-stdout ".$2" ||
                die 1 "cannot read $2 from $1"
        else
            die 2 "rpm2archive (or rpm2cpio and cpio) needed to read $2 from $1"
        fi
        ;;
    esac
}

# The formats file of a package on stdout (empty for a legacy release).
pkg_formats() { # file
    pkg_cat "$1" /usr/share/robodr/formats || true
}

# A package's post-install script (rpm: all its scriptlets) on stdout;
# fails when it cannot be read (an unreadable control archive, a failing
# dpkg-deb / rpm, no post-install script).
pkg_postinst() { # file
    case "$(format_of "$1")" in
    deb)
        pp_t=$(mktemp) || return 1
        if ! dpkg-deb --ctrl-tarfile "$1" >"$pp_t" 2>/dev/null; then
            rm -f "$pp_t"
            return 1
        fi
        pp_rc=0
        tar -xOf "$pp_t" ./postinst 2>/dev/null || pp_rc=$?
        rm -f "$pp_t"
        return "$pp_rc"
        ;;
    rpm) rpm -qp --nosignature --scripts "$1" 2>/dev/null ;;
    *) return 1 ;;
    esac
}

# Whether a package's post-install script leaves the gateway and the
# executor to the safety-state gate (its gated_restart block defines
# mark_pending_restart). The post-install script of a release from before
# the gate (0.1.0-alpha.1) try-restarts both unconditionally. A script that
# cannot be read counts as from before the gate (the safe side for every
# gating decision).
pkg_gate_aware() { # file
    pg_s=$(pkg_postinst "$1") || return 1
    printf '%s\n' "$pg_s" | grep -q '^mark_pending_restart()'
}

# Whether a package's post-install script was read and has no
# gated_restart block (a release from before the gate, for certain).
pkg_pre_gate() { # file
    pg_s=$(pkg_postinst "$1") || return 1
    ! printf '%s\n' "$pg_s" | grep -q '^mark_pending_restart()'
}

# Install a package file (policy already checked).
pkg_install() { # file
    case "$(format_of "$1")" in
    deb) dpkg_ -i "$1" ;;
    rpm) rpm_ -U --oldpackage --replacepkgs "$1" ;;
    esac
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

# The formats releases installed on this unit write (one per line): the
# installed package's formats file and every kept release's, both written
# by root only, plus the legacy format. A segment may block only in one of
# these (see "Black-box format gate" above).
written_formats() {
    echo "$legacy_read"
    for f in "$root/usr/share/robodr/formats" "$releases"/*/formats "$releases"/formats-archive/*.formats; do
        if [ -f "$f" ] && [ ! -L "$f" ]; then
            sed -n 's/^blackbox_write=//p' "$f" | tr ',' '\n'
        fi
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
    written=" $(written_formats | tr '\n' ' ') "
    report=$(ondisk_formats | while read -r fmt seg; do
        case " $reads " in *" $fmt "*) continue ;; esac
        case "$fmt" in
        RBF1:*)
            if [ -n "$(accepted "$seg")" ]; then
                echo "ACCEPTED $fmt $seg"
            else
                case "$written" in
                *" $fmt "*) echo "BAD $fmt $seg" ;;
                *) echo "UNVERIFIED $fmt $seg" ;;
                esac
            fi
            ;;
        *) echo "UNKNOWN $fmt $seg" ;;
        esac
    done)
    printf '%s\n' "$report" | while read -r kind fmt seg; do
        case "$kind" in
        UNKNOWN) echo "install-bundle: WARNING: $seg is not a RoboDR black-box frame ($fmt): damaged, or not a RoboDR segment; the format gate cannot judge it and it does not block. Check it: robodr-blackbox verify $(dirname "$seg")" ;;
        UNVERIFIED) echo "install-bundle: WARNING: UNKNOWN: $seg claims $fmt, which no release installed on this unit writes (installed and kept releases write: $(written_formats | LC_ALL=C sort -u | tr '\n' ' ')): forged, damaged or from another unit; the claim cannot be verified and does not block. Check it: robodr-blackbox verify $(dirname "$seg")" ;;
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
# (POSIX sh has no local variables: rf_old is used nowhere else; install's
# $prev_ver, the release it replaces, is the automatic rollback target.)
raise_floor() { # version source
    valid_version "$1" || die 1 "$2 names a malformed minimum version ($1)"
    rf_old=$(floor_now)
    if [ -z "$rf_old" ] || ver_lt "$rf_old" "$1"; then
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
    if [ -n "$f" ] && ver_lt "$1" "$f"; then
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
    if [ -n "$tarcopy" ] && [ -n "$bs" ] && [ -f "$tarcopy" ]; then
        if [ "$(sha256sum "$tarcopy" | cut -d' ' -f1)" = "$bs" ]; then
            echo "install-bundle: the tarball is the ring's bundle ($bs)"
        else
            echo "install-bundle: note: the tarball is not the ring's bundle $bs (information only)"
        fi
    fi
}

# The bundle (or a kept release) holds one package: the robodr .deb, or
# robodr-focal (static build for systemd 245 hosts; the two conflict and
# dpkg replaces one with the other), or the robodr .rpm. Sets $pkgfile,
# $pkgfmt and $pkg.
find_pkg() { # dir
    n=0
    for d in "$1"/robodr_*.deb "$1"/robodr-focal_*.deb "$1"/robodr-[0-9]*.rpm; do
        [ -f "$d" ] || continue
        pkgfile=$d
        n=$((n + 1))
    done
    [ "$n" -eq 1 ] || die 1 "expected exactly one robodr_*.deb, robodr-focal_*.deb or robodr-*.rpm in $1, found $n"
    pkgfmt=$(format_of "$pkgfile")
    need_tool "$pkgfmt"
    pkg=$(pkg_name "$pkgfile") || die 1 "$pkgfile is not a readable package"
    case "$pkgfmt:$pkg" in deb:robodr | deb:robodr-focal | rpm:robodr) ;; *) die 1 "unexpected package $pkg in $pkgfile" ;; esac
}

# The variant a signed tarball's name names: robodr-focal-* holds
# robodr-focal, any other robodr-* holds robodr.
variant_of_name() { # tarball file name
    case "$1" in robodr-focal-*) echo robodr-focal ;; *) echo robodr ;; esac
}

# Refuse to replace the installed variant (robodr / robodr-focal) with the
# other one unless --allow-variant-switch: robodr-focal has no
# robodr-pulsard, so a switch silently removes a detection layer.
check_variant() { # package installed-lines
    others=$(printf '%s\n' "$2" | awk -v p="$1" 'NF && $1 != p { print $1 }')
    [ -n "$others" ] || return 0
    o=$(echo "$others" | head -n1)
    if [ "$allow_variant_switch" -ne 1 ]; then
        die 1 "REFUSED: $o is installed and this release is $1: installing it REPLACES $o (dpkg removes it; robodr-focal has no robodr-pulsard). Pass --allow-variant-switch if this switch is deliberate."
    fi
    echo "install-bundle: WARNING: switching from $o to $1 (--allow-variant-switch)"
}

# ------------------------------------------------------------- services
# Whether systemd runs here (the unit tests run without: ROBODR_ROOT).
have_systemd() { [ -d "$root/run/systemd/system" ]; }

# The RoboDR units active now (one per line).
active_units() {
    have_systemd || return 0
    for u in $all_units; do
        if systemctl is-active --quiet "$u" 2>/dev/null; then echo "$u"; fi
    done
}

# Whether a robodr-deliverd binary has the safety-state command (every
# release since WP8a; not 0.1.0-alpha.1).
has_safety_state() { # binary
    regular_file "$1" && [ -x "$1" ] && "$1" --help 2>/dev/null | grep -q 'safety-state'
}

# The safety-state reader of the package being installed, when the
# installed release has none (an upgrade from 0.1.0-alpha.1): the
# package's own robodr-deliverd, verified with the package above, copied
# into the private staging directory. Sets $bundle_reader (or leaves it
# empty).
bundle_reader=""
pick_bundle_reader() { # package file
    bundle_reader=""
    ! has_safety_state "$deliverd_bin" || return 0
    [ -n "$stage" ] || make_stage
    [ -d "$stage/gate" ] || mkdir -m 0700 "$stage/gate"
    br=$stage/gate/robodr-deliverd
    if pkg_cat "$1" /usr/sbin/robodr-deliverd >"$br" 2>/dev/null; then
        chmod 0700 "$br"
        if has_safety_state "$br"; then
            bundle_reader=$br
            echo "install-bundle: the installed robodr-deliverd cannot read the safety state; reading it with the new package's robodr-deliverd"
        fi
    fi
}

# Whether the gate is open now: robodr-deliverd safety-state says idle or
# safe_state_active. The reader is the installed release's robodr-deliverd
# or, while that one has no safety-state command, the new package's
# (pick_bundle_reader). Sets $gate_why and $gate_out.
gate_open() {
    rd=$deliverd_bin
    if [ -n "$bundle_reader" ] && ! has_safety_state "$rd"; then rd=$bundle_reader; fi
    gate_out=""
    gate_why="no safety-state reader ($deliverd_bin)"
    [ -x "$rd" ] || return 1
    gate_rc=0
    if [ -f "$deliverd_cfg" ]; then
        gate_out=$("$rd" safety-state --config "$deliverd_cfg" 2>&1) || gate_rc=$?
    else
        gate_out=$("$rd" safety-state 2>&1) || gate_rc=$?
    fi
    gate_why=$(printf '%s\n' "$gate_out" | tr -d '\n' | tr -s ' ' | cut -c1-300)
    [ "$gate_rc" -eq 0 ]
}

# Decide, before any change, what happens to the running gated units.
# Sets $gate (none: none running; open; override; defer) or refuses.
decide_gate() { # active-units what package-file
    gated_active=""
    for u in $gated_units; do
        case "$nl$1$nl" in *"$nl$u$nl"*) gated_active="$gated_active $u" ;; esac
    done
    gate=none
    [ -n "$gated_active" ] || return 0
    if [ "$allow_gateway_restart" -eq 1 ]; then
        gate=override
        echo "install-bundle: WARNING: restarting$gated_active without the safety-state gate (--allow-gateway-restart)"
    elif gate_open; then
        gate=open
        echo "install-bundle: safety-state gate open:$gated_active will be restarted ($gate_why)"
    elif [ "$defer_restart" -eq 1 ]; then
        gate=defer
        echo "install-bundle: safety-state gate closed ($gate_why): the restart of$gated_active is deferred (--defer-restart); run '$0 restart-pending' when the robot is idle or in its safe state"
    else
        die 1 "REFUSED: $2 would restart$gated_active, and the live safety state does not allow it ($gate_why). Wait until the robot is idle or in its safe state, or pass --defer-restart (install now, restart later with '$0 restart-pending'), or --allow-gateway-restart (deliberate: motion through the gateway is interrupted). OPERATIONS.md section 7."
    fi
    # The one-time gateway user migration (upgrade from 0.1.0-alpha.1)
    # stops the gateway inside the maintainer script: never deferred.
    if [ "$gate" = defer ] && [ ! -e "$root/var/lib/robodr/.exporter-users-migrated" ]; then
        case " $gated_active " in *" robodr-firewall-gw.service "*)
            die 1 "REFUSED: this upgrade must stop robodr-firewall-gw once to move its state to its own user (upgrade from 0.1.0-alpha.1); that cannot be deferred. Run it when the robot is idle or in its safe state, or with --allow-gateway-restart." ;;
        esac
    fi
    # A package from before the gate restarts the two itself,
    # unconditionally, from its post-install script: never deferred.
    if [ "$gate" = defer ] && ! pkg_gate_aware "$3"; then
        die 1 "REFUSED: $2: that release's maintainer scripts predate the safety-state gate and restart$gated_active unconditionally, so the restart cannot be deferred. Run it when the robot is idle or in its safe state, or with --allow-gateway-restart."
    fi
}

# Install a package file with the gate's decision handed to the
# maintainer scripts (ROBODR_GATED_RESTART=allow lets the one-time
# gateway migration stop the gateway; nothing else reads it).
pkg_install_gated() { # file
    if [ "$gate" = open ] || [ "$gate" = override ]; then
        ROBODR_GATED_RESTART=allow pkg_install "$1"
    else
        pkg_install "$1"
    fi
    # A package from before the gate has just try-restarted the running
    # gated units itself: nothing is pending any more. Only when its
    # post-install script was read: a package whose script could not be
    # read may well have left them pending (and the file is then the
    # record agentd reports to the SOC).
    if pkg_pre_gate "$1"; then rm -f "$pending_file"; fi
}

# Right before installing a package whose post-install script predates
# the gate (it restarts the running gated units unconditionally), with the
# gate decided open: the state must still allow it now (the security
# floor, the format gate and the package reads took time).
recheck_pre_gate() { # what package-file
    [ "$gate" = open ] || return 0
    ! pkg_gate_aware "$2" || return 0
    if ! gate_open; then
        die 1 "REFUSED: $1: that release's maintainer scripts predate the safety-state gate and restart$gated_active unconditionally, and the live safety state no longer allows it ($gate_why). Nothing was installed. Run it again when the robot is idle or in its safe state, or with --allow-gateway-restart."
    fi
}

# The security floor this install or rollback would end at (the recorded
# floor, the ring information's minimum and, for an install, the bundle's
# own), checked without recording anything: a release below it is refused
# before the safety-state gate is asked (the floor has no override, so
# waiting for the robot to be idle would not help).
precheck_floor() { # version [bundle-floor]
    pf=$(floor_now)
    if [ -r "$ring_env" ]; then
        pm=$(sed -n 's/^min_version=//p' "$ring_env")
        if [ -n "$pm" ]; then
            pm=$(deb_of "$pm")
            if [ -z "$pf" ] || ver_lt "$pf" "$pm"; then pf=$pm; fi
        fi
    fi
    if [ -n "${2:-}" ] && { [ -z "$pf" ] || ver_lt "$pf" "$2"; }; then pf=$2; fi
    if [ -n "$pf" ] && ver_lt "$1" "$pf"; then
        die 1 "REFUSED: $1 is below this unit's security floor $pf (recorded floor, SOC ring information or the bundle's security-floor): releases below it are known to be vulnerable. There is no override."
    fi
}

# Restart what the maintainer scripts left in the pending-restart file,
# through the gate (checked again now) unless overridden. Returns 0 when
# nothing is pending afterwards.
restart_pending() { # gate-decision
    regular_file "$pending_file" || return 0
    if ! have_systemd; then return 0; fi
    units=$(LC_ALL=C sort -u "$pending_file")
    want=""
    for u in $units; do
        case " $gated_units " in
        *" $u "*) want="$want $u" ;;
        *) echo "install-bundle: WARNING: ignoring '$u' in $pending_file (not a gated unit)" ;;
        esac
    done
    if [ -z "$want" ]; then rm -f "$pending_file"; return 0; fi
    case "$1" in
    override) ;;
    open | check)
        if ! gate_open; then
            echo "install-bundle: WARNING: the safety state no longer allows restarting$want ($gate_why): deferred; run '$0 restart-pending' when the robot is idle or in its safe state"
            return 1
        fi
        ;;
    *)
        echo "install-bundle: restart of$want deferred ($pending_file); run '$0 restart-pending' when the robot is idle or in its safe state"
        return 1
        ;;
    esac
    for u in $want; do
        echo "install-bundle: restarting $u on the new binaries"
        systemctl try-restart "$u" || echo "install-bundle: WARNING: restarting $u failed"
    done
    rm -f "$pending_file"
}

# Whether the unit is healthy now: every unit in ACTIVE is active, and
# agentd's heartbeat is fresh if agentd is among them. Sets $health_why.
healthy_now() { # active-units
    health_why=""
    for u in $1; do
        systemctl is-active --quiet "$u" 2>/dev/null || health_why="$health_why $u not active;"
    done
    case "$nl$1$nl" in
    *"${nl}robodr-agentd.service$nl"*)
        # A release without `safety-state` (before WP8a) cannot report
        # the heartbeat: only the units are checked then.
        if ! "$deliverd_bin" --help 2>/dev/null | grep -q 'safety-state'; then
            agentd_note=" (agentd heartbeat not checked: this release's robodr-deliverd has no safety-state)"
            [ -z "$health_why" ]
            return
        fi
        agentd_note=", agentd heartbeat fresh"
        gate_open || true
        # The JSON field, pretty-printed or compact (install_gate.rs
        # checks the real binary's output against this expression).
        if ! printf '%s\n' "$gate_out" | grep -Eq '"agentd_fresh"[[:space:]]*:[[:space:]]*true'; then
            health_why="$health_why agentd heartbeat not fresh;"
        fi
        ;;
    esac
    [ -z "$health_why" ]
}

# Wait up to --health-timeout for two consecutive healthy checks.
health_check() { # active-units
    have_systemd || return 0
    [ -n "$1" ] || { echo "install-bundle: health: no RoboDR unit was running; nothing to check"; return 0; }
    waited=0
    good=0
    while :; do
        if healthy_now "$1"; then
            good=$((good + 1))
            if [ "$good" -ge 2 ]; then
                echo "install-bundle: health OK: $(echo "$1" | tr '\n' ' ')active again${agentd_note:-}"
                return 0
            fi
        else
            good=0
        fi
        [ "$waited" -lt "$health_timeout" ] || break
        sleep 1
        waited=$((waited + 1))
    done
    echo "install-bundle: HEALTH CHECK FAILED after ${health_timeout}s:$health_why" >&2
    return 1
}

# The host preflight of the release just installed (robodr-setup, T68).
# Advisory only: it reads the host and writes nothing.
host_preflight() {
    setup_bin=$root/usr/sbin/robodr-setup
    if [ ! -x "$setup_bin" ]; then
        echo "install-bundle: host preflight skipped: this release has no robodr-setup"
        return 0
    fi
    echo "install-bundle: host preflight (robodr-setup preflight):"
    if [ -n "$root" ]; then set -- --root "$root"; else set --; fi
    if ! "$setup_bin" preflight "$@"; then
        echo "install-bundle: WARNING: the host preflight reports FAIL lines (above): fix them before enabling RoboDR's services; a new unit is set up with 'robodr-setup init' (OPERATIONS.md)" >&2
    fi
    return 0
}

# Keep the N newest kept releases and the installed one; archive the
# formats file of every pruned release (the format gate's record).
prune_releases() { # n installed-version
    [ -d "$releases" ] || return 0
    vs=""
    for d in "$releases"/*/; do
        [ -d "$d" ] || continue
        v=$(basename "$d")
        valid_version "$v" || continue
        [ ! -L "${d%/}" ] || continue
        vs="$vs$v$nl"
    done
    # Newest first, by the package manager's comparison (insertion sort:
    # a handful of versions).
    sorted=""
    for v in $vs; do
        out=""
        placed=0
        for w in $sorted; do
            if [ "$placed" -eq 0 ] && ver_lt "$w" "$v"; then out="$out$v$nl"; placed=1; fi
            out="$out$w$nl"
        done
        [ "$placed" -eq 1 ] || out="$out$v$nl"
        sorted=$out
    done
    i=0
    for v in $sorted; do
        i=$((i + 1))
        if [ "$i" -le "$1" ] || [ "$v" = "$2" ]; then continue; fi
        if [ -f "$releases/$v/formats" ]; then
            install -d -m 0750 "$releases/formats-archive"
            install -m 0644 "$releases/$v/formats" "$releases/formats-archive/$v.formats"
        fi
        rm -rf -- "${releases:?}/$v"
        echo "install-bundle: pruned kept release $v (--keep $1)"
    done
}

pubkey=""
tarball=""
bb_dirs=""
accept_unreadable=""
allow_downgrade=0
allow_variant_switch=0
allow_gateway_restart=0
defer_restart=0
auto_rollback=1
health_timeout=120
keep=""
cmd=${1:-}
[ -n "$cmd" ] || die 2 "usage: $0 verify|install|list|rollback|restart-pending|prune|ring ..."
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
    --allow-variant-switch) allow_variant_switch=1; shift ;;
    --allow-gateway-restart) allow_gateway_restart=1; shift ;;
    --defer-restart) defer_restart=1; shift ;;
    --no-auto-rollback) auto_rollback=0; shift ;;
    --health-timeout)
        [ $# -ge 2 ] || die 2 "--health-timeout needs a value"
        case "$2" in '' | *[!0-9]*) die 2 "--health-timeout: seconds (0-3600)" ;; esac
        if [ "${#2}" -gt 4 ] || [ "$2" -gt 3600 ]; then die 2 "--health-timeout: seconds (0-3600)"; fi
        health_timeout=$2
        shift 2
        ;;
    --keep)
        [ $# -ge 2 ] || die 2 "--keep needs a value"
        case "$2" in '' | *[!0-9]*) die 2 "--keep: a number of releases (1-99)" ;; esac
        if [ "${#2}" -gt 2 ] || [ "$2" -lt 1 ]; then die 2 "--keep: a number of releases (1-99)"; fi
        keep=$2
        shift 2
        ;;
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
if [ "$allow_gateway_restart" -eq 1 ] && [ "$defer_restart" -eq 1 ]; then
    die 2 "--allow-gateway-restart and --defer-restart exclude each other"
fi

# Verify; sets $signed and $bundle (the directory to install from).
do_verify() {
    if [ -n "$pubkey" ] || [ -n "$tarball" ]; then
        if [ -z "$pubkey" ] || [ -z "$tarball" ]; then
            die 2 "--pubkey and --tarball go together"
        fi
        stage_inputs "$tarball"
        verify_sig "$pubkey" "$tarcopy" "$tname"
        verify_release_sums "$pubkey"
        stage_tarball "$tarcopy" "$tname"
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
    if [ "$signed" -ne 1 ]; then
        if builtin_verifier; then
            die 1 "REFUSED: refusing to install without a signature check (--pubkey/--tarball): this unit has the built-in verifier ($deliverd_bin), so ROBODR_ALLOW_UNSIGNED is not accepted. Sign lab builds with a lab key (minisign -G) and pass --pubkey."
        fi
        if [ "${ROBODR_ALLOW_UNSIGNED:-0}" != 1 ]; then
            die 1 "refusing to install without a signature check (--pubkey/--tarball); ROBODR_ALLOW_UNSIGNED=1 for lab use (only on a unit without the built-in verifier)"
        fi
        echo "install-bundle: UNSIGNED install (ROBODR_ALLOW_UNSIGNED=1, lab only): no signature was checked"
    fi
    find_pkg "$bundle"
    if [ "$signed" -eq 1 ] && [ "$pkgfmt" = deb ] && [ "$pkg" != "$(variant_of_name "$tname")" ]; then
        die 1 "REFUSED: the signed tarball $tname names the $(variant_of_name "$tname") variant but holds $pkg"
    fi
    ver=$(pkg_version "$pkgfile")
    valid_version "$ver" || die 1 "the package version $ver is malformed"
    check_other_format "$pkgfmt"
    have=$(installed_pkgs "$pkgfmt")
    check_variant "$pkg" "$have"
    prev=""
    prev_ver=""
    while read -r p v; do
        [ -n "$p" ] || continue
        prev="$prev $p $v"
        prev_ver=$v
    done <<EOF
$have
EOF
    echo "install-bundle: installing $pkg $ver ($pkgfmt; currently installed:${prev:- none})"
    if [ -n "$prev_ver" ] && ver_lt "$ver" "$prev_ver"; then
        if [ "$allow_downgrade" -ne 1 ]; then
            die 1 "REFUSED: $ver is older than the installed $prev_ver: a downgrade (it may bring back fixed vulnerabilities). Roll back to a kept release (rollback), or pass --allow-downgrade if this downgrade is deliberate; neither goes below the security floor."
        fi
        echo "install-bundle: WARNING: downgrading from $prev_ver to $ver (--allow-downgrade)"
    fi
    bf=""
    if [ -f "$bundle/security-floor" ]; then
        bf=$(sed -n 's/^min_version=//p' "$bundle/security-floor" | head -n1)
    fi
    precheck_floor "$ver" "$bf"
    # The safety-state gate, before anything on the unit changes.
    before=$(active_units)
    pick_bundle_reader "$pkgfile"
    decide_gate "$before" "installing $ver" "$pkgfile"
    ring_note "$ver"
    floor_from_ring
    if [ -f "$bundle/security-floor" ]; then
        bf=$(sed -n 's/^min_version=//p' "$bundle/security-floor" | head -n1)
        [ -z "$bf" ] || raise_floor "$bf" "security-floor of the $ver bundle"
    fi
    check_floor "$ver"
    fmt=$(mktemp)
    pkg_formats "$pkgfile" >"$fmt"
    check_formats "$fmt" "$ver" || { rm -f "$fmt"; exit 1; }
    new_pkg=$pkg
    recheck_pre_gate "installing $ver" "$pkgfile"
    pkg_install_gated "$pkgfile"
    restart_pending "$gate" || true
    if ! health_check "$before"; then
        if [ "$auto_rollback" -ne 1 ]; then
            die 1 "$new_pkg $ver is installed but the unit is not healthy (--no-auto-rollback): check the units, then '$0 rollback <version>'"
        fi
        if [ -z "$prev_ver" ] || [ "$prev_ver" = "$ver" ]; then
            die 1 "$new_pkg $ver is installed but the unit is not healthy, and there is no earlier release to roll back to"
        fi
        prevdir=$releases/$prev_ver
        if [ ! -d "$prevdir" ] || [ -L "$prevdir" ]; then
            die 1 "$new_pkg $ver is installed but the unit is not healthy, and the release it replaced ($prev_ver) is not kept in $releases: roll back by hand"
        fi
        echo "install-bundle: AUTOMATIC ROLLBACK to $prev_ver"
        (cd "$prevdir" && sha256sum --strict --quiet --ignore-missing -c SHA256SUMS) ||
            die 1 "automatic rollback impossible: the kept release $prev_ver fails its checksums"
        find_pkg "$prevdir"
        [ "$(pkg_version "$pkgfile")" = "$prev_ver" ] ||
            die 1 "automatic rollback impossible: the kept package in $prevdir is not version $prev_ver"
        f=$(floor_now)
        if [ -n "$f" ] && ver_lt "$prev_ver" "$f"; then
            die 1 "automatic rollback impossible: $prev_ver is below the security floor $f; $new_pkg $ver stays installed, unhealthy"
        fi
        pfmt=$(mktemp)
        if [ -f "$prevdir/formats" ]; then cp "$prevdir/formats" "$pfmt"; else pkg_formats "$pkgfile" >"$pfmt"; fi
        if ! check_formats "$pfmt" "$prev_ver"; then
            rm -f "$pfmt"
            die 1 "automatic rollback impossible (format gate); $ver stays installed, unhealthy"
        fi
        rm -f "$pfmt"
        # A release from before the gate restarts the gateway and the
        # executor itself, unconditionally: only while the safety state
        # allows that now.
        case "$gate" in
        open | defer)
            if ! pkg_gate_aware "$pkgfile"; then
                if ! gate_open; then
                    die 1 "automatic rollback impossible: the maintainer scripts of $prev_ver predate the safety-state gate and would restart$gated_active unconditionally, and the safety state does not allow that now ($gate_why); $new_pkg $ver stays installed, unhealthy. Roll back with '$0 rollback $prev_ver' when the robot is idle or in its safe state."
                fi
                gate=open
            fi
            ;;
        esac
        pkg_install_gated "$pkgfile"
        restart_pending "$gate" || true
        if health_check "$before"; then
            echo "install-bundle: rolled back to $prev_ver; it is healthy" >&2
        else
            echo "install-bundle: rolled back to $prev_ver, which is NOT healthy either: check the units" >&2
        fi
        die 1 "$new_pkg $ver failed its post-install health check and was rolled back to $prev_ver (the failed release is not kept)"
    fi
    install -d -m 0750 "$releases/$ver"
    # One package per kept version: the variant installed last (robodr and
    # robodr-focal share version numbers).
    rm -f "$releases/$ver"/robodr_*.deb "$releases/$ver"/robodr-focal_*.deb "$releases/$ver"/robodr-[0-9]*.rpm
    install -m 0644 "$pkgfile" "$releases/$ver/"
    (cd "$bundle" && install -m 0644 SHA256SUMS "$releases/$ver/SHA256SUMS")
    if [ -s "$fmt" ]; then install -m 0644 "$fmt" "$releases/$ver/formats"; fi
    rm -f "$fmt"
    echo "install-bundle: kept $releases/$ver for rollback"
    if [ -n "$keep" ]; then prune_releases "$keep" "$ver"; fi
    host_preflight
    ;;
restart-pending)
    [ "$have_version" -eq 0 ] || die 2 "restart-pending takes no version"
    need_root
    if [ "$allow_gateway_restart" -eq 1 ]; then g=override; else g=check; fi
    # What runs now must run again afterwards (the health check below).
    before=$(active_units)
    configured=0
    # A package whose configuration was deferred by its maintainer script
    # (the one-time gateway migration with the gate closed): configure it
    # now, through the gate.
    if command -v dpkg >/dev/null 2>&1; then
        for p in robodr robodr-focal; do
            # shellcheck disable=SC2016 # dpkg-query format
            st=$(dpkg_query -W -f '${db:Status-Abbrev}' "$p" 2>/dev/null || true)
            case "$st" in
            ?[FU]*)
                if [ "$g" = check ] && ! gate_open; then
                    die 1 "$p is not configured and the safety state does not allow restarting the gateway ($gate_why); try again when idle or in the safe state, or with --allow-gateway-restart"
                fi
                echo "install-bundle: configuring $p (deferred configuration)"
                ROBODR_GATED_RESTART=allow dpkg_ --configure "$p"
                configured=1
                ;;
            esac
        done
    fi
    if ! regular_file "$pending_file"; then
        echo "install-bundle: nothing pending"
        if [ "$configured" -eq 1 ]; then
            health_check "$before" || die 1 "the unit is not healthy after the deferred configuration: check the units"
        fi
        exit 0
    fi
    restart_pending "$g" || exit 1
    echo "install-bundle: pending restarts done"
    # No automatic rollback here (the package was installed earlier and
    # passed its own check); an unhealthy restart is reported, exit 1.
    health_check "$before" ||
        die 1 "the restarted units are not healthy: check them; '$0 rollback <version>' goes back to a kept release"
    ;;
prune)
    [ "$have_version" -eq 0 ] || die 2 "prune takes no version"
    need_root
    [ -n "$keep" ] || die 2 "prune needs --keep N"
    host_installed
    # Without the installed version it could not be protected.
    [ -n "$inst" ] ||
        die 1 "REFUSED: cannot determine the installed robodr version (neither dpkg nor rpm reports one); nothing pruned"
    prune_releases "$keep" "$inst"
    ;;
list)
    [ -d "$releases" ] || die 1 "no releases kept in $releases"
    # Versions compare by the package manager that holds robodr.
    host_installed
    f=$(floor_now)
    echo "installed: ${inst:-unknown}"
    echo "security floor: ${f:-none}"
    if regular_file "$pending_file"; then
        echo "pending restart (still on the previous binaries; restart-pending): $(LC_ALL=C sort -u "$pending_file" | tr '\n' ' ')"
    fi
    for d in "$releases"/*/; do
        [ -d "$d" ] || continue
        v=$(basename "$d")
        valid_version "$v" || continue
        if [ -f "$d/formats" ]; then r=$(reads_of "$d/formats"); else r="$legacy_read (legacy)"; fi
        below=""
        if [ -n "$f" ] && ver_lt "$v" "$f"; then below="  (below the security floor)"; fi
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
    find_pkg "$dir"
    [ "$(pkg_version "$pkgfile")" = "$version_arg" ] ||
        die 1 "the kept package in $dir is not version $version_arg"
    check_other_format "$pkgfmt"
    check_variant "$pkg" "$(installed_pkgs "$pkgfmt")"
    precheck_floor "$version_arg"
    # The safety-state gate, before anything on the unit changes.
    before=$(active_units)
    decide_gate "$before" "rolling back to $version_arg" "$pkgfile"
    floor_from_ring
    check_floor "$version_arg"
    fmt=$(mktemp)
    if [ -f "$dir/formats" ]; then cp "$dir/formats" "$fmt"; else pkg_formats "$pkgfile" >"$fmt"; fi
    check_formats "$fmt" "$version_arg" || { rm -f "$fmt"; exit 1; }
    rm -f "$fmt"
    echo "install-bundle: rolling back to $pkg $version_arg ($pkgfmt)"
    recheck_pre_gate "rolling back to $version_arg" "$pkgfile"
    pkg_install_gated "$pkgfile"
    restart_pending "$gate" || true
    health_check "$before" || die 1 "rolled back to $version_arg, but the unit is not healthy: check the units"
    ;;
*)
    die 2 "unknown command $cmd (verify|install|list|rollback|restart-pending|prune|ring)"
    ;;
esac
