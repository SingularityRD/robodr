#!/usr/bin/env bash
# Install a robodr / robodr-focal .deb or a robodr .rpm into a REAL target
# userland and check it (run as root inside a throwaway container of the
# target distribution; CI runs it in debian:12, ubuntu:20.04/22.04/24.04,
# rockylinux:9 and fedora containers, docs/BUILD.md "Package matrix").
#
#   scripts/pkg-install-smoke.sh [--pulsard] PACKAGE
#
# Where scripts/deb-install-smoke.sh unpacks into a separate dpkg root and
# never runs a maintainer script, this script uses the distribution's own
# package manager, so it proves what that cannot:
#   1. the package INSTALLS there: apt-get / dnf resolves its Depends /
#      Requires against the distribution (libc6 floor, libssl3, libsqlite3,
#      systemd version, rpm's generated GLIBC_x.y requirements), and the
#      maintainer scripts / scriptlets run (sysusers, tmpfiles; no systemd
#      is running in the container, so nothing is started);
#   2. dpkg --verify / rpm -V are clean;
#   3. the users, groups and the directory modes/owners tmpfiles sets;
#   4. every shipped ELF program STARTS on that glibc: --version exits 0
#      and the loader reports no missing library or symbol version;
#   5. no setuid/setgid or group/other-writable file, everything root-owned;
#   6. systemd-analyze verify of every shipped unit (the distribution's own
#      systemd, so a directive it does not know fails);
#   7. reinstall (the upgrade branch of the scripts), removal and, for a
#      .deb, purge: evidence (/var/lib/robodr) and keys stay, the executor
#      journal goes on purge, units are gone.
# --pulsard: robodr-pulsard must be in the package (the release builds).
#
# The container is modified (that is the point); never run this on a host.
# Exit: 0 all checks passed, 1 a check failed, 2 usage.
set -euo pipefail

want_pulsard=0
pkgfile=""
while [[ $# -gt 0 ]]; do
    case "$1" in
    --pulsard) want_pulsard=1; shift ;;
    -h | --help) sed -n '2,/^set -euo/p' "$0" | sed '$d'; exit 0 ;;
    -*) echo "pkg-install-smoke: unknown option $1" >&2; exit 2 ;;
    *) pkgfile="$1"; shift ;;
    esac
done
[[ -f "$pkgfile" ]] || { echo "pkg-install-smoke: no package file given" >&2; exit 2; }
[[ "$(id -u)" -eq 0 ]] || { echo "pkg-install-smoke: run as root in a throwaway container" >&2; exit 2; }
if [[ -d /run/systemd/system ]]; then
    echo "pkg-install-smoke: systemd is running here: this script is for throwaway containers only" >&2
    exit 2
fi
pkgfile="$(cd "$(dirname "$pkgfile")" && pwd)/$(basename "$pkgfile")"

fail=0
bad() { echo "pkg-install-smoke: FAIL: $*" >&2; fail=1; }
step() { echo "pkg-install-smoke: --- $*" >&2; }
# shellcheck source=/dev/null
os="$(. /etc/os-release && printf '%s %s' "${ID:-?}" "${VERSION_ID:-?}")"

case "$pkgfile" in
*.deb) kind=deb ;;
*.rpm) kind=rpm ;;
*) echo "pkg-install-smoke: $pkgfile is neither .deb nor .rpm" >&2; exit 2 ;;
esac

step "$os: install $(basename "$pkgfile")"
if [[ $kind == deb ]]; then
    export DEBIAN_FRONTEND=noninteractive
    # Minimised container images drop docs and man pages at unpack
    # (dpkg path-exclude); a real host keeps them, and dpkg --verify below
    # would report them missing.
    rm -f /etc/dpkg/dpkg.cfg.d/excludes
    apt-get update -qq
    # binutils: readelf for the ELF checks below (not a package dependency).
    apt-get install -y -qq --no-install-recommends binutils >/dev/null
    apt-get install -y --no-install-recommends "$pkgfile"
    name="$(dpkg-deb -f "$pkgfile" Package)"
    dpkg -s "$name" | grep -E '^(Package|Version|Depends|Status):' >&2
    files() { dpkg -L "$name"; }
    step "dpkg --verify"
    out="$(dpkg --verify "$name" 2>&1 || true)"
    [[ -z "$out" ]] || bad "dpkg --verify: $out"
else
    # Container images set tsflags=nodocs (docs not installed); a real host
    # installs them, and %license files must be there either way.
    sed -i '/^tsflags=/d' /etc/dnf/dnf.conf 2>/dev/null || true
    dnf install -y -q --setopt=install_weak_deps=False binutils >/dev/null
    dnf install -y --setopt=install_weak_deps=False "$pkgfile"
    name="$(rpm -qp --qf '%{NAME}' "$pkgfile")"
    rpm -q --requires "$name" | sed 's/^/requires: /' >&2
    files() { rpm -ql "$name"; }
    step "rpm -V"
    out="$(rpm -V "$name" 2>&1 || true)"
    [[ -z "$out" ]] || bad "rpm -V: $out"
fi

step "users and groups"
for u in robodr robodr-agentd robodr-exec; do
    getent passwd "$u" >/dev/null || bad "user $u missing"
done
getent group robodr-safety >/dev/null || bad "group robodr-safety missing"
id -nG robodr-agentd 2>/dev/null | tr ' ' '\n' | grep -x robodr >/dev/null || bad "robodr-agentd is not in group robodr"
for u in robodr robodr-agentd robodr-exec; do
    sh_="$(getent passwd "$u" | cut -d: -f7)"
    case "$sh_" in */nologin | */false) ;; *) bad "user $u has login shell $sh_" ;; esac
done

step "directories (tmpfiles)"
check_dir() { # path mode owner group
    local got
    got="$(stat -c '%a %U %G' "$1" 2>/dev/null || echo missing)"
    [[ "$got" == "$2 $3 $4" ]] || bad "$1: $got, want $2 $3 $4"
}
check_dir /etc/robodr 750 root robodr
check_dir /etc/robodr/keys 700 root root
check_dir /var/lib/robodr 750 root robodr
check_dir /var/lib/robodr/blackbox/agentd 750 robodr-agentd robodr
check_dir /var/lib/robodr/spool/agentd 2750 robodr-agentd robodr
check_dir /var/lib/robodr/spool/agentd/ready 2770 robodr-agentd robodr
check_dir /var/lib/robodr/executor 700 robodr-exec robodr
check_dir /var/lib/robodr/fleet 700 root root
check_dir /var/lib/robodr/deliverd 700 root root
check_dir /var/lib/robodr/releases 750 root root

step "programs start on $os ($(ldd --version 2>&1 | head -n1))"
nprog=0
while IFS= read -r f; do
    [[ -f "$f" && ! -L "$f" ]] || continue
    [[ "$(head -c4 "$f" | od -An -tx1 | tr -d '[:space:]')" == 7f454c46 ]] || continue
    nprog=$((nprog + 1))
    set +e
    o="$(timeout 20 "$f" --version 2>&1)"
    rc=$?
    set -e
    if [[ $rc -ne 0 ]] || grep -qiE 'error while loading shared libraries|GLIBC_[0-9.]+. not found|version .* not found|No such file or directory' <<<"$o"; then
        bad "$f --version: exit $rc: $(head -n3 <<<"$o")"
    else
        echo "  $(basename "$f"): $(head -n1 <<<"$o")" >&2
    fi
done < <(files | grep -E '^/usr/s?bin/robodr-' | LC_ALL=C sort)
[[ $nprog -gt 0 ]] || bad "no programs in the package"
if [[ $want_pulsard == 1 ]]; then
    files | grep -x /usr/sbin/robodr-pulsard >/dev/null || bad "robodr-pulsard is not in the package"
    [[ -f /etc/robodr/pulsar.toml ]] || bad "/etc/robodr/pulsar.toml missing"
fi

step "file modes and owners"
while IFS= read -r f; do
    [[ -e "$f" && ! -L "$f" ]] || continue
    [[ -d "$f" ]] && continue
    m="$(stat -c '%a %U %G' "$f")"
    read -r mode user group <<<"$m"
    [[ "$user $group" == "root root" ]] || bad "$f owned by $user:$group"
    (( (8#$mode & 8#6022) == 0 )) || bad "$f has mode $mode (setuid/setgid or group/other-writable)"
done < <(files)

step "systemd-analyze verify (systemd $(systemctl --version 2>/dev/null | head -n1 | awk '{print $2}'))"
units=()
while IFS= read -r u; do units+=("$u"); done < <(files | grep -E '^/usr/lib/systemd/system/robodr-.*\.service$' | LC_ALL=C sort)
[[ ${#units[@]} -gt 0 ]] || bad "no units in the package"
for u in "${units[@]}"; do
    # --man=no: Documentation=man:... needs man(1), not part of the check.
    out="$(SYSTEMD_LOG_LEVEL=warning systemd-analyze verify --man=no "$u" 2>&1 || true)"
    # Without a running systemd, verify cannot read the boot's state:
    # those lines are noise. Anything about the unit's own content is not.
    out="$(grep -vE 'Failed to (connect|initialize|create)|Ignoring|/proc/|D-Bus|cgroup|Running in chroot|System has not been booted' <<<"$out" || true)"
    if [[ -n "$out" ]]; then
        bad "systemd-analyze verify $(basename "$u"): $out"
    fi
done

step "reinstall (upgrade path of the scripts)"
mkdir -p /var/lib/robodr/blackbox/agentd
echo evidence >/var/lib/robodr/blackbox/agentd/smoke-segment
echo journal >/var/lib/robodr/executor/journal.json
if [[ $kind == deb ]]; then
    apt-get install -y --reinstall --no-install-recommends "$pkgfile" >/dev/null
else
    rpm -U --replacepkgs "$pkgfile"
fi

# An operator enabled a service (offline enable: symlinks only). After the
# package is gone (rpm erase, deb purge) nothing may stay enabled: a later
# reinstall must not start an uncommissioned service at the next boot.
step "enable robodr-agentd (as an operator would)"
systemctl enable robodr-agentd.service >/dev/null 2>&1 || bad "systemctl enable robodr-agentd failed"
wants() { find -P /etc/systemd/system -mindepth 2 -maxdepth 2 -name 'robodr-*.service' -type l 2>/dev/null; }
[[ -n "$(wants)" ]] || bad "systemctl enable created no wants link"

step "remove"
if [[ $kind == deb ]]; then
    apt-get remove -y "$name" >/dev/null
else
    dnf remove -y "$name" >/dev/null
    [[ -z "$(wants)" ]] || bad "rpm erase left the service enabled: $(wants | tr '\n' ' ')"
fi
[[ ! -e /usr/lib/systemd/system/robodr-agentd.service ]] || bad "robodr-agentd.service still installed after removal"
[[ -f /var/lib/robodr/blackbox/agentd/smoke-segment ]] || bad "removal deleted evidence"
[[ -d /etc/robodr/keys ]] || bad "removal deleted /etc/robodr/keys"
if [[ $kind == deb ]]; then
    step "purge"
    apt-get purge -y "$name" >/dev/null
    [[ -f /var/lib/robodr/blackbox/agentd/smoke-segment ]] || bad "purge deleted evidence"
    [[ -d /etc/robodr/keys ]] || bad "purge deleted /etc/robodr/keys"
    [[ ! -e /var/lib/robodr/executor/journal.json ]] || bad "purge kept the executor journal"
    [[ -z "$(wants)" ]] || bad "purge left the service enabled: $(wants | tr '\n' ' ')"
fi

if [[ $fail -ne 0 ]]; then
    echo "pkg-install-smoke: $os: FAILED ($(basename "$pkgfile"))" >&2
    exit 1
fi
echo "pkg-install-smoke: $os: OK ($(basename "$pkgfile"), $nprog programs)"
