#!/usr/bin/env bash
# Nightly, unattended run of the network-side red team (REDTEAM.md R1-R4)
# against a real robodr-agentd capturing live in a network namespace, with
# pass/fail assertions and a results file (T80 of docs/SALES-READINESS.md;
# .github/workflows/nightly.yml). Root only (namespaces, AF_PACKET). Test
# keys only, all generated fresh.
#
#   ROBODR_BIN=target/release tools/e2e/nightly-redteam.sh OUT_DIR
#
# Steps: netns.sh up -> commission.sh (the real CLI flow: learn, sign-off,
# two operator signatures, lock, trust file) on the Gazebo baseline capture
# -> agentd (live capture on rob-rt, signed profile enforced, live safety
# feed on /odom + a 0600 PLC socket) -> redteam_net.py rogue spray malformed
# safety -> SIGTERM -> robodr-blackbox verify.
#
# Asserted (a regression in any fails the run):
#   R1 rogue      robot.ros2.unknown_participant and
#                 robot.ros2.unauthorized_motion_writer raised;
#   R2 spray      agentd alive, detected (discovery_flood or
#                 unknown_participant), fewer than 300 findings for 3000
#                 GUIDs (REDTEAM.md F1 amplification), RSS bounded;
#   R3 malformed  agentd alive, RSS bounded;
#   R4 safety     robot.safety_state.untrusted_source raised; the safety
#                 state never taken from the spoof (status.json reads
#                 "unknown" once the feed is stale, not "idle"); the
#                 unprivileged write to the PLC socket refused;
#   end           agentd exits 0 on SIGTERM, black box RESULT: INTACT.
# OUT_DIR gets commission.log, agentd.log, steps.jsonl, verify.txt and
# results.json. Not covered here (they need AutoSecOps, REDTEAM.md R5-R7):
# the control-plane, executor and ingest attacks.
#
# Environment: ROBODR_BIN (release binaries: robodr-agentd, robodr-blackbox,
# robodr-commission), ROBODR_RSS_LIMIT_KIB (default 65536).
# Exit: 0 all assertions passed, 1 one failed, 2 usage.
set -euo pipefail

H="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
root="$(cd "$H/../.." && pwd)"
out="${1:-}"
[[ -n "$out" ]] || { echo "usage: nightly-redteam.sh OUT_DIR" >&2; exit 2; }
[[ "$(id -u)" == 0 ]] || { echo "nightly-redteam: run as root" >&2; exit 2; }
B="$(cd "${ROBODR_BIN:?set ROBODR_BIN to the release binaries}" && pwd)"
for b in robodr-agentd robodr-blackbox robodr-commission; do
    [[ -x "$B/$b" ]] || { echo "nightly-redteam: $B/$b missing" >&2; exit 2; }
done
export ROBODR_BIN="$B" ROBODR_REPO="$root"
mkdir -p "$out"
out="$(cd "$out" && pwd)"
w="$(mktemp -d /var/tmp/rdr-nightly.XXXXXX)"
pid=""
cleanup() {
    if [[ -n "$pid" ]] && kill -0 "$pid" 2>/dev/null; then
        kill -KILL "$pid" 2>/dev/null || true
    fi
    "$H/netns.sh" down || true
    rm -rf "$w"
}
trap cleanup EXIT

"$H/netns.sh" down
"$H/netns.sh" up

echo "nightly-redteam: commissioning the lab profile"
"$H/commission.sh" "$w/prof" "$root/fixtures/captures/ros2-jazzy/fastrtps_gz_baseline.pcap" \
    >"$out/commission.log" 2>&1 || { tail -n 30 "$out/commission.log"; exit 1; }

rt="$w/rt"
mkdir -p "$rt"
cp "$w/prof/locked.json" "$w/prof/locked.json.sig" "$w/prof/profile-trust.json" "$rt/"
"$H/agentd-config.py" "$rt" rt-ugv-001 --iface rob-rt >/dev/null
python3 - "$rt" <<'PY'
import json, sys
rt = sys.argv[1]
p = f"{rt}/agentd.json"
c = json.load(open(p))
c["context"] = {"safety_state": "unknown"}
c["safety_feed"] = {
    "stale_after_ms": 1000,
    "topics": [{"topic": "/odom", "type": "nav_msgs/msg/Odometry",
                "motion": {"moving_above": 0.05, "fast_above": 1.0, "hysteresis": 0.02},
                "writers": ["identity:gz_bridge"]}],
    "socket": {"path": f"{rt}/safety.sock", "max_connections": 2},
}
json.dump(c, open(p, "w"), indent=2)
PY
ip netns exec rdr-rob "$B/robodr-agentd" --config "$rt/agentd.json" --check-config >"$out/check-config.txt" 2>&1 ||
    { cat "$out/check-config.txt"; exit 1; }

echo "nightly-redteam: starting agentd in rdr-rob"
ip netns exec rdr-rob "$B/robodr-agentd" --config "$rt/agentd.json" >"$out/agentd.log" 2>&1 &
pid=$!
for i in $(seq 100); do
    [[ -s "$rt/spool/status.json" ]] && break
    if ! kill -0 "$pid" 2>/dev/null || [[ "$i" == 100 ]]; then
        tail -n 40 "$out/agentd.log"
        echo "nightly-redteam: agentd did not come up" >&2
        exit 1
    fi
    sleep 0.2
done

echo "nightly-redteam: red team (rogue spray malformed safety)"
python3 "$H/redteam_net.py" "$rt" "$pid" rogue spray malformed safety | tee "$out/steps.jsonl"

kill -TERM "$pid"
rc=0
wait "$pid" || rc=$?
pid=""
verify_rc=0
"$B/robodr-blackbox" verify "$rt/blackbox" --keyring "$rt/blackbox.key.pub" >"$out/verify.txt" 2>&1 || verify_rc=$?

# The assertions (tested by tools/e2e/test_nightly_redteam_checks.py).
python3 "$H/nightly_redteam_checks.py" "$out" "$rc" "$verify_rc" "${ROBODR_RSS_LIMIT_KIB:-65536}"
