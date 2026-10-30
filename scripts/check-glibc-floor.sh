#!/usr/bin/env bash
# Fail when a robodr package needs a newer glibc than its oldest supported
# userland has (docs/BUILD.md "Release build userlands"):
#
#   scripts/check-glibc-floor.sh PACKAGE.deb|PACKAGE.rpm
#
#   robodr .deb   Depends: libc6 (>= X) with X <= 2.35 (Ubuntu 22.04 /
#                 JetPack 6; Debian 12 has 2.36)
#   robodr .rpm   every generated libc.so.6(GLIBC_X) requirement X <= 2.34
#                 (RHEL / Rocky / Alma 9)
#   robodr-focal  no libc6 dependency at all (static)
# Also prints the dependency line, for the build log.
#
# Exit: 0 within the floor, 1 above it, 2 usage.
set -euo pipefail
DEB_FLOOR=2.35
RPM_FLOOR=2.34

f="${1:-}"
[[ -f "$f" ]] || { echo "usage: check-glibc-floor.sh PACKAGE.deb|PACKAGE.rpm" >&2; exit 2; }
le() { [[ "$(printf '%s\n%s\n' "$1" "$2" | sort -V | tail -n1)" == "$2" ]]; }

case "$f" in
*.deb)
    pkg="$(dpkg-deb -f "$f" Package)"
    dep="$(dpkg-deb -f "$f" Depends)"
    echo "check-glibc-floor: $pkg Depends: $dep"
    v="$(printf '%s\n' "$dep" | tr ',' '\n' | sed -n 's/^ *libc6 (>= \([^)]*\)).*$/\1/p')"
    if [[ "$pkg" == robodr-focal ]]; then
        [[ -z "$v" ]] || { echo "check-glibc-floor: FAIL: robodr-focal depends on libc6" >&2; exit 1; }
        exit 0
    fi
    [[ -n "$v" ]] || { echo "check-glibc-floor: FAIL: no versioned libc6 dependency" >&2; exit 1; }
    # A Debian version (2.35, or 2.35-0ubuntu3): compare its upstream part.
    if ! le "${v%%-*}" "$DEB_FLOOR"; then
        echo "check-glibc-floor: FAIL: libc6 (>= $v) is above $DEB_FLOOR: the package would not install on Ubuntu 22.04 / JetPack 6" >&2
        exit 1
    fi
    echo "check-glibc-floor: libc6 >= $v, within $DEB_FLOOR"
    ;;
*.rpm)
    reqs="$(rpm -qp --requires "$f")"
    printf '%s\n' "$reqs" | sed 's/^/check-glibc-floor: requires /'
    v="$(printf '%s\n' "$reqs" | sed -n 's/^libc\.so\.6(GLIBC_\([0-9.]*\)).*/\1/p' | sort -V | tail -n1)"
    [[ -n "$v" ]] || { echo "check-glibc-floor: FAIL: no generated GLIBC requirement (AutoReq off?)" >&2; exit 1; }
    if ! le "$v" "$RPM_FLOOR"; then
        echo "check-glibc-floor: FAIL: needs GLIBC_$v, above $RPM_FLOOR: the package would not install on RHEL 9" >&2
        exit 1
    fi
    echo "check-glibc-floor: GLIBC_$v, within $RPM_FLOOR"
    ;;
*) echo "check-glibc-floor: $f is neither .deb nor .rpm" >&2; exit 2 ;;
esac
