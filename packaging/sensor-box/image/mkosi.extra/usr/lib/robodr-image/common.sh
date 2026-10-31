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
        # An IP address only: the strict default firewall lets no DNS out,
        # so a host name would never resolve and the clock would never be
        # set. A malformed address would never sync either.
        valid_ipv4 "$2" || valid_ipv6 "$2" ;;
    role)
        case "$2" in robot | unitree-sensor-box) return 0 ;; *) return 1 ;; esac ;;
    exporter)
        case "$2" in none | uplink | kafka-publish | spool-export) return 0 ;; *) return 1 ;; esac ;;
    *) return 1 ;;
    esac
}

# valid_ipv4 A: a dotted quad, every octet 0-255 (no leading zeros, which
# some resolvers read as octal).
valid_ipv4() {
    printf '%s' "$1" | grep -Eq '^(25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9]?[0-9])(\.(25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9]?[0-9])){3}$'
}

# valid_ipv6 A: RFC 4291 text form: eight groups of 1-4 hex digits, or
# fewer with exactly one "::"; the last two groups may be a dotted quad
# (::ffff:192.0.2.1). No zone index (fe80::1%eth0).
valid_ipv6() {
    v6_a=$1
    case "$v6_a" in *:*) ;; *) return 1 ;; esac
    printf '%s' "$v6_a" | grep -Eq '^[0-9A-Fa-f:.]{2,45}$' || return 1
    case "$v6_a" in
    *.*)
        v6_v4=${v6_a##*:}
        valid_ipv4 "$v6_v4" || return 1
        v6_a="${v6_a%"$v6_v4"}0:0" ;;
    esac
    case "$v6_a" in *:::* | *::*::* | :[!:]* | *[!:]:) return 1 ;; esac
    v6_n=0
    v6_rest=$v6_a
    while [ -n "$v6_rest" ]; do
        v6_g=${v6_rest%%:*}
        [ ${#v6_g} -le 4 ] || return 1
        [ -z "$v6_g" ] || v6_n=$((v6_n + 1))
        case "$v6_rest" in *:*) v6_rest=${v6_rest#*:} ;; *) v6_rest= ;; esac
    done
    case "$v6_a" in
    *::*) [ "$v6_n" -le 7 ] ;;
    *) [ "$v6_n" -eq 8 ] ;;
    esac
}

# The provisioning file holds KEY=VALUE lines only; it is parsed, never
# sourced (no shell expansion of what an integrator or a USB stick wrote).
# get KEY -> value or empty.
get() {
    [ -f "$PROVISION" ] || return 0
    sed -n "s/^$1=\\(.*\\)\$/\\1/p" "$PROVISION" | tail -n 1
}
