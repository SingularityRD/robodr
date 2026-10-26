#!/usr/bin/env bash
# Install a built robodr / robodr-focal .deb into a THROWAWAY dpkg root and
# smoke-test what it ships (release acceptance; scripts/release-dry-run.sh
# runs it on every released .deb, docs/RELEASE.md).
#
#   scripts/deb-install-smoke.sh [--keep] DEB...
#
# Per package, in a fresh root (mktemp -d, own dpkg database, as the fleet
# packaging test does):
#   1. dpkg --root=R --unpack DEB, then dpkg --verify (md5sums) and the
#      maintainer scripts parsed with `sh -n`. Not --configure: dpkg would
#      run postinst chrooted into R, which has no shell. Instead the two
#      things postinst does to the file system are replayed against R:
#      systemd-sysusers --root=R and systemd-tmpfiles --root=R --create with
#      the shipped sysusers.d / tmpfiles.d files (they must apply cleanly).
#   2. Every ELF executable in usr/bin, usr/sbin and usr/lib/robodr is run
#      with --version and with --help (arm64 under qemu-aarch64-static; a
#      dynamically linked arm64 binary with -L /usr/aarch64-linux-gnu). Both
#      must exit 0 and print something; --version must print the package's
#      upstream version.
#   3. `systemd-analyze verify --root=R` on every shipped unit (the units
#      reference the binaries and the users inside R).
# The host is never modified: no maintainer script runs, nothing outside R
# is written.
#
# Exit: 0 all checks passed, 1 a check failed, 2 usage / missing tool.
set -euo pipefail

keep=0
debs=()
while [[ $# -gt 0 ]]; do
    case "$1" in
    --keep) keep=1; shift ;;
    -h | --help) sed -n '2,/^set -euo/p' "$0" | sed '$d'; exit 0 ;;
    -*) echo "deb-install-smoke: unknown option $1" >&2; exit 2 ;;
    *) debs+=("$1"); shift ;;
    esac
done
[[ ${#debs[@]} -gt 0 ]] || { echo "deb-install-smoke: no .deb given" >&2; exit 2; }
for t in dpkg dpkg-deb systemd-analyze systemd-sysusers systemd-tmpfiles readelf timeout; do
    command -v "$t" >/dev/null || { echo "deb-install-smoke: $t not found" >&2; exit 2; }
done

fail=0
bad() { echo "deb-install-smoke: FAIL: $*" >&2; fail=1; }

smoke_one() {
    local deb="$1" pkg ver arch upstream r run f b o rc units
    pkg="$(dpkg-deb -f "$deb" Package)"
    ver="$(dpkg-deb -f "$deb" Version)"
    arch="$(dpkg-deb -f "$deb" Architecture)"
    upstream="${ver%-*}"
    upstream="${upstream/\~/-}"
    echo "== $pkg $ver ($arch): $(basename "$deb")"
    r="$(mktemp -d)"
    mkdir -p "$r/var/lib/dpkg/info" "$r/var/lib/dpkg/updates" "$r/var/lib/dpkg/triggers"
    : >"$r/var/lib/dpkg/status"
    : >"$r/var/lib/dpkg/available"

    # 1. unpack, verify, maintainer scripts, sysusers/tmpfiles replay.
    if ! dpkg --root="$r" --force-architecture --unpack "$deb" >"$r.unpack.log" 2>&1; then
        bad "$pkg: dpkg --unpack failed:"; cat "$r.unpack.log" >&2
        rm -rf "$r" "$r.unpack.log"; return
    fi
    rm -f "$r.unpack.log"
    st="$(dpkg-query --admindir="$r/var/lib/dpkg" -W -f='${Status} ${Version}' "$pkg")"
    [[ "$st" == "install ok unpacked $ver" ]] || bad "$pkg: dpkg status '$st'"
    if o="$(dpkg --root="$r" --verify "$pkg" 2>&1)" && [[ -z "$o" ]]; then
        echo "   dpkg --verify: OK ($(dpkg-query --admindir="$r/var/lib/dpkg" -L "$pkg" | wc -l) paths)"
    else
        bad "$pkg: dpkg --verify: $o"
    fi
    for s in preinst postinst prerm postrm; do
        f="$r/var/lib/dpkg/info/$pkg.$s"
        [[ -e "$f" ]] || continue
        sh -n "$f" || bad "$pkg: $s does not parse"
    done
    if [[ -f "$r/usr/lib/sysusers.d/robodr.conf" ]]; then
        systemd-sysusers --root="$r" "$r/usr/lib/sysusers.d/robodr.conf" >/dev/null 2>&1 ||
            bad "$pkg: systemd-sysusers --root failed"
        echo "   sysusers: $(cut -d: -f1 "$r/etc/passwd" 2>/dev/null | grep robodr | tr '\n' ' ')"
    else
        bad "$pkg: no usr/lib/sysusers.d/robodr.conf"
    fi
    if [[ -f "$r/usr/lib/tmpfiles.d/robodr.conf" ]]; then
        o="$(systemd-tmpfiles --root="$r" --create "$r/usr/lib/tmpfiles.d/robodr.conf" 2>&1)" ||
            bad "$pkg: systemd-tmpfiles --root --create failed: $o"
    else
        bad "$pkg: no usr/lib/tmpfiles.d/robodr.conf"
    fi

    # 2. every ELF executable: --version and --help.
    run=()
    case "$arch" in
    amd64) [[ "$(uname -m)" == x86_64 ]] || run=(qemu-x86_64-static) ;;
    arm64)
        if [[ "$(uname -m)" != aarch64 ]]; then
            command -v qemu-aarch64-static >/dev/null || { bad "$pkg: qemu-aarch64-static needed for arm64"; rm -rf "$r"; return; }
            run=(qemu-aarch64-static -L /usr/aarch64-linux-gnu)
        fi
        ;;
    esac
    local n=0
    while IFS= read -r f; do
        [[ "$(head -c4 "$f" | od -An -tx1 | tr -d '[:space:]')" == 7f454c46 ]] || continue
        b="${f#"$r"}"
        n=$((n + 1))
        for flag in --version --help; do
            rc=0
            o="$(timeout 30 "${run[@]}" "$f" "$flag" 2>&1)" || rc=$?
            if [[ $rc -ne 0 || -z "$o" ]]; then
                bad "$pkg: $b $flag: exit $rc: $(printf '%s' "$o" | head -n3)"
            elif [[ "$flag" == --version && "$o" != *"$upstream"* ]]; then
                bad "$pkg: $b --version does not name $upstream: $(printf '%s' "$o" | head -n1)"
            elif [[ "$flag" == --version ]]; then
                echo "   $b: $(printf '%s' "$o" | head -n1 | cut -c1-100)"
            fi
        done
    done < <(find "$r/usr/bin" "$r/usr/sbin" "$r/usr/lib/robodr" -maxdepth 1 -type f -perm -u+x 2>/dev/null | LC_ALL=C sort)
    [[ $n -gt 0 ]] || bad "$pkg: no executables found"
    echo "   $n executable(s): --version and --help run"

    # 3. systemd-analyze verify on the shipped units.
    mapfile -t units < <(find "$r/usr/lib/systemd/system" -maxdepth 1 -type f -name '*.service' 2>/dev/null | LC_ALL=C sort)
    if [[ ${#units[@]} -eq 0 ]]; then
        bad "$pkg: no systemd units shipped"
    else
        # Relative to R: --root resolves unit paths and ExecStart= under it.
        rel=()
        for u in "${units[@]}"; do rel+=("${u#"$r"}"); done
        if o="$(cd / && SYSTEMD_LOG_LEVEL=notice systemd-analyze verify --man=no --root="$r" "${rel[@]}" 2>&1)" && [[ -z "$o" ]]; then
            echo "   systemd-analyze verify: OK (${#units[@]} units: $(printf '%s\n' "${rel[@]##*/}" | tr '\n' ' '))"
        else
            bad "$pkg: systemd-analyze verify:"; printf '%s\n' "$o" >&2
        fi
    fi
    if [[ $keep == 1 ]]; then echo "   root kept: $r"; else rm -rf "$r"; fi
}

for d in "${debs[@]}"; do
    [[ -f "$d" ]] || { bad "$d not found"; continue; }
    smoke_one "$d"
done
if [[ $fail -ne 0 ]]; then
    echo "deb-install-smoke: FAILED" >&2
    exit 1
fi
echo "deb-install-smoke: all ${#debs[@]} package(s) passed"
