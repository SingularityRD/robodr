# Shared by the RoboDR sensor box image scripts (POSIX sh, sourced).
#
# R: file-system prefix. Empty on the box; the tests
# (crates/robodr-ops/tests/sensor_box_image.rs) run the scripts against a
# temporary tree with ROBODR_IMAGE_ROOT set, and only then may put stub
# commands first in PATH (ROBODR_IMAGE_TEST_PATH).
R="${ROBODR_IMAGE_ROOT:-}"
PATH=/usr/sbin:/usr/bin:/sbin:/bin
if [ -n "$R" ] && [ -n "${ROBODR_IMAGE_TEST_PATH:-}" ]; then
    PATH="$ROBODR_IMAGE_TEST_PATH:$PATH"
fi
export PATH
umask 027

STATE="$R/var/lib/robodr-image"
PROVISION="$R/etc/robodr/provision.env"

log() { echo "robodr-image: $*" >&2; }
die() { log "$*"; exit 1; }

# valid KIND VALUE: the provisioning values end up in file names, unit
# configuration and command arguments; only these shapes are accepted.
valid() {
    case "$1" in
    unit_id | site)
        printf '%s' "$2" | grep -Eq '^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$' ;;
    iface)
        printf '%s' "$2" | grep -Eq '^[A-Za-z0-9][A-Za-z0-9._@-]{0,14}$' ;;
    ntp)
        # An IP address only (v4 dotted quad, or v6 hex and colons): the
        # strict default firewall lets no DNS out, so a host name would
        # never resolve and the clock would never be set.
        printf '%s' "$2" | grep -Eq '^(([0-9]{1,3}\.){3}[0-9]{1,3}|[0-9A-Fa-f]{0,4}(:[0-9A-Fa-f]{0,4}){2,7})$' ;;
    role)
        case "$2" in robot | unitree-sensor-box) return 0 ;; *) return 1 ;; esac ;;
    exporter)
        case "$2" in none | uplink | kafka-publish | spool-export) return 0 ;; *) return 1 ;; esac ;;
    *) return 1 ;;
    esac
}

# The provisioning file holds KEY=VALUE lines only; it is parsed, never
# sourced (no shell expansion of what an integrator or a USB stick wrote).
# get KEY -> value or empty.
get() {
    [ -f "$PROVISION" ] || return 0
    sed -n "s/^$1=\\(.*\\)\$/\\1/p" "$PROVISION" | tail -n 1
}
