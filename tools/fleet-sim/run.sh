#!/usr/bin/env bash
# Fleet capacity simulator (sales-readiness T71): N simulated units run the
# real robodr-enroll binary through the whole fleet lifecycle against the
# reference SOC (crates/robodr-fleet/examples/fleet_sim_soc.rs) over TLS:
#
#   enroll -> rotate uplink (overlap, swap) -> rotate --finish (retire)
#          -> check -> decommission (every key retired at the SOC)
#
# then checks the SOC's invariants (every unit enrolled and decommissioned,
# no key registered twice, no key left active, no rotation left open) and
# prints per-step latency percentiles.
#
# usage: tools/fleet-sim/run.sh [--units N] [--parallel P] [--netns] [--keep]
#                               [--bin-dir DIR] [--out DIR]
#
#   --units N      simulated units (default 50; 500 for the capacity run)
#   --parallel P   units running at once (default 16)
#   --netns        every unit in its own network namespace behind a bridge
#                  (root; ip, veth, bridge): real per-unit network stacks.
#                  Default: every unit on 127.0.0.1 (no root needed).
#   --bin-dir DIR  where robodr-enroll and fleet_sim_soc are (default: build
#                  them with cargo into target/debug)
#   --out DIR      work directory (default: a new mktemp dir; kept with --keep)
#
# Exit 0 when every unit finished every step and the invariants hold.
# Test keys and a throw-away PKI only. See tools/fleet-sim/README.md.
set -euo pipefail

UNITS=50
PARALLEL=16
NETNS=0
KEEP=0
BIN_DIR=""
OUT=""
while [[ $# -gt 0 ]]; do
    case "$1" in
    --units) UNITS="$2"; shift 2 ;;
    --parallel) PARALLEL="$2"; shift 2 ;;
    --netns) NETNS=1; shift ;;
    --keep) KEEP=1; shift ;;
    --bin-dir) BIN_DIR="$2"; shift 2 ;;
    --out) OUT="$2"; shift 2 ;;
    -h | --help) sed -n '2,27p' "$0"; exit 0 ;;
    *) echo "run.sh: unknown argument $1" >&2; exit 2 ;;
    esac
done
[[ "$UNITS" =~ ^[0-9]+$ && "$UNITS" -ge 1 && "$UNITS" -le 5000 ]] || { echo "--units 1..5000" >&2; exit 2; }
[[ "$PARALLEL" =~ ^[0-9]+$ && "$PARALLEL" -ge 1 ]] || { echo "--parallel >= 1" >&2; exit 2; }
if [[ $NETNS == 1 && $(id -u) != 0 ]]; then
    echo "run.sh: --netns needs root" >&2
    exit 2
fi

root="$(cd "$(dirname "$0")/../.." && pwd)"
if [[ -z "$BIN_DIR" ]]; then
    (cd "$root" && cargo build -q -p robodr-fleet --bin robodr-enroll --example fleet_sim_soc)
    BIN_DIR="${CARGO_TARGET_DIR:-$root/target}/debug"
    SOC_BIN="$BIN_DIR/examples/fleet_sim_soc"
else
    SOC_BIN="$BIN_DIR/fleet_sim_soc"
    [[ -x "$SOC_BIN" ]] || SOC_BIN="$BIN_DIR/examples/fleet_sim_soc"
fi
ENROLL="$BIN_DIR/robodr-enroll"
[[ -x "$ENROLL" && -x "$SOC_BIN" ]] || { echo "run.sh: binaries not found in $BIN_DIR" >&2; exit 2; }

[[ -n "$OUT" ]] || OUT="$(mktemp -d /tmp/robodr-fleet-sim.XXXXXX)"
mkdir -p "$OUT"
chmod 0755 "$OUT"
BR=br-rdfsim
NS_PREFIX=rdfsim
SOC_PID=""

cleanup() {
    [[ -n "$SOC_PID" ]] && kill "$SOC_PID" 2>/dev/null || true
    if [[ $NETNS == 1 ]]; then
        for ((i = 1; i <= UNITS; i++)); do
            ip netns del "$NS_PREFIX$i" 2>/dev/null || true
        done
        ip link del "$BR" 2>/dev/null || true
    fi
    [[ $KEEP == 1 ]] || rm -rf "$OUT"
}
trap cleanup EXIT

# Addresses: the SOC on 10.77.0.1 (netns) or 127.0.0.1; unit i on
# 10.77.<i/250>.<i%250+2>/16.
if [[ $NETNS == 1 ]]; then
    SOC_IP=10.77.0.1
    ip link add "$BR" type bridge
    ip addr add "$SOC_IP/16" dev "$BR"
    ip link set "$BR" up
else
    SOC_IP=127.0.0.1
fi
PORT=$((20000 + RANDOM % 20000))
URL="https://$SOC_IP:$PORT/api"

# Throw-away PKI: a CA and a server certificate for the SOC address.
pki="$OUT/pki"
mkdir -p "$pki"
openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes -days 2 \
    -subj "/CN=robodr-fleet-sim-ca" -keyout "$pki/ca.key" -out "$pki/ca.pem" 2>/dev/null
openssl req -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes \
    -subj "/CN=robodr-fleet-sim-soc" -keyout "$pki/server.key" -out "$pki/server.csr" 2>/dev/null
printf 'subjectAltName=IP:%s,DNS:localhost\nextendedKeyUsage=serverAuth\nbasicConstraints=CA:FALSE\n' \
    "$SOC_IP" >"$pki/ext.cnf"
openssl x509 -req -in "$pki/server.csr" -CA "$pki/ca.pem" -CAkey "$pki/ca.key" -CAcreateserial \
    -days 2 -extfile "$pki/ext.cnf" -out "$pki/server.pem" 2>/dev/null

if [[ $NETNS == 1 ]]; then
    echo "creating $UNITS network namespaces ..."
    for ((i = 1; i <= UNITS; i++)); do
        ns="$NS_PREFIX$i"
        ip netns add "$ns"
        ip link add "vh$i" type veth peer name "vn$i"
        ip link set "vh$i" master "$BR" up
        ip link set "vn$i" netns "$ns"
        ip -n "$ns" addr add "10.77.$((i / 250)).$((i % 250 + 2))/16" dev "vn$i"
        ip -n "$ns" link set "vn$i" up
        ip -n "$ns" link set lo up
    done
fi

"$SOC_BIN" --units "$UNITS" --dir "$OUT" --listen "$SOC_IP:$PORT" --url "$URL" \
    --cert "$pki/server.pem" --key "$pki/server.key" --ca "$pki/ca.pem" \
    >"$OUT/soc.out" 2>"$OUT/soc.err" &
SOC_PID=$!
for _ in $(seq 1 600); do
    grep -q '^ready' "$OUT/soc.out" 2>/dev/null && break
    kill -0 "$SOC_PID" 2>/dev/null || { cat "$OUT/soc.err" >&2; exit 1; }
    sleep 0.1
done
grep -q '^ready' "$OUT/soc.out" || { echo "SOC did not start" >&2; exit 1; }

# One unit: every step timed (ms); one line per step in results/<robot>.
unit() {
    local i="$1" robot cfg tok res ns=() rc t0 t1
    robot=$(printf 'ugv-%04d' "$i")
    cfg="$OUT/units/$robot/etc/fleet.json"
    tok="$OUT/units/$robot/token.txt"
    res="$OUT/results/$robot"
    [[ $NETNS == 1 ]] && ns=(ip netns exec "$NS_PREFIX$i")
    : >"$res"
    step() {
        local name="$1"
        shift
        t0=$(date +%s%N)
        if "${ns[@]}" "$ENROLL" "$@" --config "$cfg" >>"$OUT/logs/$robot.log" 2>&1; then rc=0; else rc=$?; fi
        t1=$(date +%s%N)
        echo "$name $rc $(((t1 - t0) / 1000000))" >>"$res"
        return "$rc"
    }
    step enroll --token-file "$tok" &&
        step rotate rotate --role uplink &&
        step retire rotate --role uplink --finish &&
        step check check &&
        step decommission decommission --reason end_of_life
}
export -f unit
export OUT ENROLL NETNS NS_PREFIX
mkdir -p "$OUT/results" "$OUT/logs"

echo "running $UNITS units ($PARALLEL at a time, $([[ $NETNS == 1 ]] && echo "one netns each" || echo "loopback")) against $URL ..."
start=$(date +%s%N)
seq 1 "$UNITS" | xargs -P "$PARALLEL" -I{} bash -c 'unit {}' || true
wall=$((($(date +%s%N) - start) / 1000000))

stats=$(curl -s --cacert "$pki/ca.pem" "https://$SOC_IP:$PORT/_sim/stats" ||
    { [[ $NETNS == 1 ]] && curl -s --cacert "$pki/ca.pem" --resolve "x:$PORT:$SOC_IP" "https://$SOC_IP:$PORT/_sim/stats"; })
echo "SOC: $stats"

summary() {
    cat "$OUT"/results/* | awk -v units="$UNITS" -v wall="$wall" '
    { n[$1]++; if ($2 != 0) fail[$1]++; v[$1, n[$1]] = $3 }
    END {
        split("enroll rotate retire check decommission", order, " ")
        printf "%-13s %6s %6s %8s %8s %8s\n", "step", "ok", "fail", "p50 ms", "p95 ms", "max ms"
        for (k = 1; k <= 5; k++) {
            s = order[k]; m = n[s]
            for (i = 1; i <= m; i++) a[i] = v[s, i]
            # insertion sort (m <= 5000)
            for (i = 2; i <= m; i++) { x = a[i]; j = i - 1; while (j > 0 && a[j] > x) { a[j + 1] = a[j]; j-- } a[j + 1] = x }
            p50 = m ? a[int((m - 1) * 0.50) + 1] : 0
            p95 = m ? a[int((m - 1) * 0.95) + 1] : 0
            mx = m ? a[m] : 0
            printf "%-13s %6d %6d %8d %8d %8d\n", s, m - fail[s], fail[s] + 0, p50, p95, mx
            delete a
        }
        printf "wall %d ms for %d units\n", wall, units
    }'
}
summary | tee "$OUT/summary.txt"

# Invariants.
ok=1
want_steps=$((UNITS * 5))
done_steps=$(cat "$OUT"/results/* | awk '$2 == 0' | wc -l)
[[ "$done_steps" == "$want_steps" ]] || { echo "FAIL: $done_steps of $want_steps steps succeeded (logs: $OUT/logs)"; ok=0; }
field() { sed -n "s/.*\"$1\":\([0-9]*\).*/\1/p" <<<"$stats"; }
[[ "$(field units_enrolled)" == "$UNITS" ]] || { echo "FAIL: units_enrolled != $UNITS"; ok=0; }
[[ "$(field decommissioned)" == "$UNITS" ]] || { echo "FAIL: decommissioned != $UNITS"; ok=0; }
[[ "$(field keys_active)" == 0 ]] || { echo "FAIL: keys left active"; ok=0; }
[[ "$(field rotations_open)" == 0 ]] || { echo "FAIL: rotations left open"; ok=0; }
# 3 keys per enrollment + 1 per uplink rotation, all distinct.
[[ "$(field keys_registered)" == $((UNITS * 4)) && "$(field keys_distinct_fingerprints)" == $((UNITS * 4)) ]] ||
    { echo "FAIL: expected $((UNITS * 4)) distinct registered keys"; ok=0; }
if [[ $ok == 1 ]]; then
    echo "PASS: $UNITS units enrolled, rotated, checked and decommissioned; invariants hold"
    exit 0
fi
KEEP=1
echo "work directory kept: $OUT"
exit 1
