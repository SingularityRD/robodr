#!/usr/bin/env bash
# Install -> enable --now -> heartbeat -> upgrade N-1 -> N -> rollback ->
# purge of a robodr .deb / .rpm on a host where systemd is PID 1 (T10 of
# docs/SALES-READINESS.md). scripts/pkg-install-smoke.sh checks a package in
# a container WITHOUT systemd (nothing started); this script starts the
# daemon under the real unit (credentials, sandboxing, sd_notify, watchdog)
# and checks that state survives the package manager's upgrade and
# downgrade paths. Run as root in a throwaway systemd container or VM
# (scripts/systemd-lifecycle-matrix.sh starts one per distribution).
#
#   scripts/systemd-lifecycle.sh OLD_PACKAGE NEW_PACKAGE
#
# OLD_PACKAGE is the previous release (N-1), NEW_PACKAGE the candidate (N);
# both .deb or both .rpm, same package name. Steps:
#   1. install N-1 with apt-get / dnf; commission a minimal agentd (black-box
#      key under /etc/robodr/keys, agentd.json, the example profile and
#      policy); systemctl enable --now robodr-agentd;
#   2. heartbeat: the unit is active, status.json (spool) is rewritten and
#      its heartbeat counter advances, the black box verifies INTACT with
#      the key's .pub;
#   3. upgrade to N: the version changed; the key, agentd.json and every
#      black-box segment written before are unchanged (hashed in full; the
#      newest one, which may still grow, on its first 4 KiB, see
#      scripts/lifecycle-state.sh); the daemon is (still
#      or again) active and heartbeating; the black box verifies INTACT
#      across the upgrade (one chain, no gap);
#   3b. key credentials on N: prints the form LoadCredential= hands over
#      (ls -ln as the service user) and requires the ACL form (0440 root,
#      "+") where systemd >= 254 and the kernel >= 6.4 (E2E finding F1:
#      the daemons refused it); starts robodr-spool-export under its shipped
#      unit with its own credential (diode.key) and requires it active, not
#      restarted and without a key error;
#   4. rollback to N-1 (apt-get --allow-downgrades / dnf downgrade): the
#      same checks;
#   5. purge (deb) / remove (rpm): units gone, nothing robodr running, the
#      evidence (/var/lib/robodr) and the keys stay.
# With SELinux enforcing (Rocky / RHEL VM), no AVC denial for robodr may be
# logged during the run (ausearch).
#
# Exit: 0 all checks passed, 1 a check failed, 2 usage.
set -euo pipefail

old="${1:-}"
new="${2:-}"
[[ -f "$old" && -f "$new" ]] || { echo "usage: systemd-lifecycle.sh OLD_PACKAGE NEW_PACKAGE" >&2; exit 2; }
[[ "$(id -u)" == 0 ]] || { echo "systemd-lifecycle: run as root" >&2; exit 2; }
[[ -d /run/systemd/system ]] || { echo "systemd-lifecycle: systemd is not PID 1 here" >&2; exit 2; }
old="$(cd "$(dirname "$old")" && pwd)/$(basename "$old")"
new="$(cd "$(dirname "$new")" && pwd)/$(basename "$new")"
case "$old/$new" in
*.deb/*.deb) kind=deb ;;
*.rpm/*.rpm) kind=rpm ;;
*) echo "systemd-lifecycle: both packages must be .deb or both .rpm" >&2; exit 2 ;;
esac

fail=0
bad() { echo "systemd-lifecycle: FAIL: $*" >&2; fail=1; }
step() { echo "systemd-lifecycle: --- $*" >&2; }
die() { echo "systemd-lifecycle: FATAL: $*" >&2; journalctl -u robodr-agentd --no-pager -n 80 >&2 || true; exit 1; }

# Wait for boot; "degraded" (some unrelated unit failed in a container) is fine.
systemctl is-system-running --wait >/dev/null 2>&1 || true
# shellcheck source=/dev/null
os="$(. /etc/os-release && printf '%s %s' "${ID:-?}" "${VERSION_ID:-?}")"
step "$os, systemd $(systemctl --version | head -n1 | awk '{print $2}')"

pkgver() {
    if [[ $kind == deb ]]; then dpkg-deb -f "$1" Version; else rpm -qp --qf '%{VERSION}-%{RELEASE}' "$1"; fi
}
pkgname() {
    if [[ $kind == deb ]]; then dpkg-deb -f "$1" Package; else rpm -qp --qf '%{NAME}' "$1"; fi
}
installed_ver() {
    if [[ $kind == deb ]]; then dpkg-query -W -f '${Version}' "$name"; else rpm -q --qf '%{VERSION}-%{RELEASE}' "$name"; fi
}
name="$(pkgname "$new")"
[[ "$(pkgname "$old")" == "$name" ]] || { echo "systemd-lifecycle: the packages are not the same package" >&2; exit 2; }
v_old="$(pkgver "$old")"
v_new="$(pkgver "$new")"
step "$name: $v_old (N-1) -> $v_new (N)"
[[ "$v_old" != "$v_new" ]] || { echo "systemd-lifecycle: N-1 and N have the same version" >&2; exit 2; }

install_pkg() { # file [downgrade]
    if [[ $kind == deb ]]; then
        export DEBIAN_FRONTEND=noninteractive
        apt-get install -y --no-install-recommends ${2:+--allow-downgrades} \
            -o Dpkg::Options::=--force-confold "$1"
    elif [[ -n "${2:-}" ]]; then
        dnf downgrade -y --setopt=install_weak_deps=False "$1"
    else
        dnf install -y --setopt=install_weak_deps=False "$1"
    fi
}

if [[ $kind == deb ]]; then
    export DEBIAN_FRONTEND=noninteractive
    apt-get update -qq
fi

step "1. install N-1 ($v_old)"
install_pkg "$old" || die "installing N-1 failed"
[[ "$(installed_ver)" == "$v_old" ]] || bad "installed version $(installed_ver), want $v_old"

step "commission a minimal agentd"
ex=/usr/share/doc/robodr/examples
key=/etc/robodr/keys/agentd-blackbox.key
robodr-blackbox keygen --out "$key" --key-id lifecycle-bb >/dev/null
chmod 600 "$key"
install -m 0640 -g robodr "$ex/profile.example.json" /etc/robodr/profile.json
install -m 0640 -g robodr "$ex/response-policy.example.json" /etc/robodr/response-policy.json
umask 027
cat >/etc/robodr/agentd.json <<'EOF'
{
  "robot": { "id": "lifecycle-1", "site": "ci" },
  "sensor": { "profile_path": "/etc/robodr/profile.json", "listen_spdp": false,
              "capture": { "enabled": false } },
  "policy_path": "/etc/robodr/response-policy.json",
  "blackbox": { "dir": "/var/lib/robodr/blackbox/agentd",
                "key_file": "/run/credentials/robodr-agentd.service/blackbox.key" },
  "spool": { "dir": "/var/lib/robodr/spool/agentd",
             "status_socket": "/run/robodr-agentd/status.sock" },
  "event_inputs": [ { "kind": "unix_socket", "path": "/run/robodr-agentd/events.sock" } ],
  "daemon": { "tick_ms": 500, "heartbeat_ms": 1000, "silence_ms": 30000 }
}
EOF
umask 022
chgrp robodr /etc/robodr/agentd.json
# The key reaches the daemon only through the unit's LoadCredential=, so
# the unit itself is the configuration check.
systemctl enable --now robodr-agentd.service || die "systemctl enable --now robodr-agentd failed"

status=/var/lib/robodr/spool/agentd/status.json
heartbeats() { python3 - "$status" <<'PY' 2>/dev/null || echo -1
import json, sys
print(json.load(open(sys.argv[1]))["daemon"]["heartbeats"])
PY
}
heartbeat() { # label
    local t0 h0 h1
    for _ in $(seq 60); do
        systemctl is-active --quiet robodr-agentd && [[ -s "$status" ]] && break
        sleep 0.5
    done
    systemctl is-active --quiet robodr-agentd || { bad "$1: robodr-agentd is not active"; return; }
    h0="$(heartbeats)"
    t0="$(stat -c %Y "$status")"
    sleep 4
    h1="$(heartbeats)"
    [[ "$h1" -gt "$h0" ]] || bad "$1: no heartbeat (status.json heartbeats $h0 -> $h1)"
    [[ "$(stat -c %Y "$status")" -ge "$t0" ]] || bad "$1: status.json not rewritten"
    [[ "$(systemctl show -p NRestarts --value robodr-agentd)" == 0 ]] ||
        bad "$1: robodr-agentd restarted $(systemctl show -p NRestarts --value robodr-agentd) time(s)"
    echo "systemd-lifecycle: $1: active, heartbeats $h0 -> $h1" >&2
}
verify_bb() { # label
    local out
    if ! out="$(robodr-blackbox verify /var/lib/robodr/blackbox/agentd --keyring "$key.pub" 2>&1)"; then
        bad "$1: black box does not verify: $(tail -n 3 <<<"$out")"
    elif ! grep -q 'RESULT: INTACT' <<<"$out"; then
        bad "$1: black box: $(tail -n 1 <<<"$out")"
    else
        echo "systemd-lifecycle: $1: $(grep -E '^frames' <<<"$out")" >&2
    fi
}
# seg_hash, state_snapshot, state_changed (tested by
# scripts/test-lifecycle-state.sh).
# shellcheck source=scripts/lifecycle-state.sh
. "$(dirname "$0")/lifecycle-state.sh"
snapshot() { # -> stdout: the key, config and every black-box segment
    state_snapshot /var/lib/robodr/blackbox/agentd "$key" "$key.pub" /etc/robodr/agentd.json
}
same_state() { # label before-file
    local changed
    changed="$(state_changed "$2")"
    [[ -z "$changed" ]] || bad "$1: state changed or lost:$changed"
}

step "2. heartbeat on N-1"
heartbeat "N-1"
systemctl stop robodr-agentd # seal the black box for a stable snapshot
verify_bb "N-1"
snapshot >/var/tmp/lifecycle.before
systemctl start robodr-agentd

step "3. upgrade to N ($v_new)"
install_pkg "$new" || die "upgrade to N failed"
[[ "$(installed_ver)" == "$v_new" ]] || bad "after upgrade: version $(installed_ver), want $v_new"
# The package may leave the daemon to the operator (pending restart): start
# it if it is not running, then require it healthy.
systemctl is-active --quiet robodr-agentd || systemctl start robodr-agentd || die "agentd does not start on N"
systemctl reset-failed robodr-agentd 2>/dev/null || true
heartbeat "N"
same_state "upgrade" /var/tmp/lifecycle.before
systemctl stop robodr-agentd
verify_bb "N"
snapshot >/var/tmp/lifecycle.after-upgrade
systemctl start robodr-agentd

step "3b. key credentials on N: the form systemd hands over, spool-export under its unit"
# E2E finding F1: systemd >= 254 on kernel >= 6.4 hands a LoadCredential=
# file over as 0440 root:root with a POSIX ACL for User= (ls: -r--r-----+).
# Every daemon must accept exactly that. Say which form this host produces,
# and require the ACL form where systemd and the kernel are new enough, so
# the Ubuntu 24.04 row cannot silently test only the old 0400 form.
sd_ver="$(systemctl --version | head -n1 | awk '{print $2}')"
k_ver="$(uname -r | awk -F. '{printf "%d%03d", $1, $2}')"
probe_unit="robodr-lifecycle-probe-$$.service"
form="$(systemd-run --quiet --wait --pipe --collect --unit="$probe_unit" -p User=robodr-agentd \
    -p LoadCredential=probe:"$key" /bin/ls -ln "/run/credentials/$probe_unit/probe" 2>&1 || true)"
echo "systemd-lifecycle: credential form (systemd $sd_ver, kernel $(uname -r)): $form" >&2
if [[ "${sd_ver%%[!0-9]*}" -ge 254 && "$k_ver" -ge 6004 && "$form" != *+* ]]; then
    bad "systemd $sd_ver on kernel $(uname -r) should hand credentials over with an ACL (got: $form)"
fi
# agentd's heartbeat above already proves its black-box credential loads;
# spool-export loads its own (diode.key) under its shipped unit and must
# stay active without a restart (a key it refuses is exit 2: failed).
if [[ -f /usr/lib/systemd/system/robodr-spool-export.service ]]; then
    robodr-blackbox keygen --out /etc/robodr/keys/diode.key --key-id lifecycle-diode >/dev/null
    chmod 600 /etc/robodr/keys/diode.key
    [[ -f /etc/robodr/spool-export.env ]] || printf 'ROBODR_UNIT_ID=lifecycle-1\nROBODR_SPOOL_EXPORT_ARGS=\n' >/etc/robodr/spool-export.env
    systemctl start robodr-spool-export.service || bad "robodr-spool-export does not start on N"
    sleep 3
    if ! systemctl is-active --quiet robodr-spool-export ||
        [[ "$(systemctl show -p NRestarts --value robodr-spool-export)" != 0 ]]; then
        bad "robodr-spool-export is not running with its credential: $(journalctl -u robodr-spool-export --no-pager -n 5 | tr '\n' ' ')"
    elif journalctl -u robodr-spool-export --no-pager | grep -q 'key file\|secret file\|credential directory'; then
        bad "robodr-spool-export logged a key error: $(journalctl -u robodr-spool-export --no-pager -n 5 | tr '\n' ' ')"
    else
        echo "systemd-lifecycle: N: robodr-spool-export active with its credential" >&2
    fi
    systemctl stop robodr-spool-export.service || true
fi

step "4. rollback to N-1 ($v_old)"
install_pkg "$old" downgrade || die "rollback to N-1 failed"
[[ "$(installed_ver)" == "$v_old" ]] || bad "after rollback: version $(installed_ver), want $v_old"
systemctl is-active --quiet robodr-agentd || systemctl start robodr-agentd || die "agentd does not start after the rollback"
heartbeat "rollback"
same_state "rollback" /var/tmp/lifecycle.after-upgrade
systemctl stop robodr-agentd
verify_bb "rollback"

step "5. purge"
if [[ $kind == deb ]]; then
    apt-get purge -y "$name" >/dev/null
else
    dnf remove -y "$name" >/dev/null
fi
systemctl daemon-reload
[[ ! -e /usr/lib/systemd/system/robodr-agentd.service ]] || bad "robodr-agentd.service still installed"
if pgrep -f '/usr/s?bin/robodr-' >/dev/null; then
    bad "robodr processes still running: $(pgrep -af '/usr/s?bin/robodr-' | tr '\n' ' ')"
fi
[[ -n "$(find /var/lib/robodr/blackbox/agentd -name 'seg-*.rbb' 2>/dev/null)" ]] || bad "purge deleted the evidence"
[[ -f "$key" ]] || bad "purge deleted the black-box key"
if [[ -n "$(find -P /etc/systemd/system -name 'robodr-*' 2>/dev/null)" ]]; then
    bad "units still enabled after purge: $(find -P /etc/systemd/system -name 'robodr-*' | tr '\n' ' ')"
fi

if command -v getenforce >/dev/null && [[ "$(getenforce)" == Enforcing ]]; then
    step "SELinux AVC denials"
    avc="$(ausearch -m avc -ts boot 2>/dev/null | grep -i robodr || true)"
    [[ -z "$avc" ]] || bad "SELinux AVC denials: $(head -n 5 <<<"$avc")"
fi

if [[ $fail != 0 ]]; then
    journalctl -u robodr-agentd --no-pager -n 60 >&2 || true
    echo "systemd-lifecycle: FAILED ($os)" >&2
    exit 1
fi
echo "systemd-lifecycle: OK ($os, $name $v_old -> $v_new -> $v_old -> purged)"
