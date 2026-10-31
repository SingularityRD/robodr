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
#                 state never taken from the spoof (not "idle"); the
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

python3 - "$out" "$rc" "$verify_rc" "${ROBODR_RSS_LIMIT_KIB:-65536}" <<'PY'
import json, sys
out, agentd_rc, verify_rc, rss_limit = sys.argv[1], int(sys.argv[2]), int(sys.argv[3]), int(sys.argv[4])
steps = {}
for line in open(f"{out}/steps.jsonl"):
    line = line.strip()
    if line.startswith("{"):
        s = json.loads(line)
        steps[s["step"]] = s
checks = []
def check(name, ok, detail):
    checks.append({"check": name, "pass": bool(ok), "detail": detail})
def found(step, uid):
    return steps.get(step, {}).get("new_findings", {}).get(uid, 0)
for st in ("rogue", "spray", "malformed", "safety"):
    check(f"{st}: step ran", st in steps, list(steps))
    s = steps.get(st, {})
    check(f"{st}: agentd alive", s.get("agentd_alive"), s.get("agentd_alive"))
    rss = s.get("rss_kib_after") or 0
    check(f"{st}: RSS under {rss_limit} KiB", 0 < rss < rss_limit, rss)
check("R1 rogue: unknown_participant", found("rogue", "robot.ros2.unknown_participant") > 0,
      steps.get("rogue", {}).get("new_findings"))
check("R1 rogue: unauthorized_motion_writer",
      found("rogue", "robot.ros2.unauthorized_motion_writer") > 0, steps.get("rogue", {}).get("new_findings"))
spray = steps.get("spray", {}).get("new_findings", {})
check("R2 spray: detected (discovery_flood or unknown_participant)",
      found("spray", "robot.ros2.discovery_flood") + found("spray", "robot.ros2.unknown_participant") > 0, spray)
# REDTEAM.md F1: 3000 sprayed GUIDs once made about 5000 findings; they are
# aggregated now. A tenth of the packets is the regression bound.
check("R2 spray: no finding amplification (< 300 findings for 3000 GUIDs)",
      sum(spray.values()) < 300, sum(spray.values()))
check("R4 safety: untrusted_source", found("safety", "robot.safety_state.untrusted_source") > 0,
      steps.get("safety", {}).get("new_findings"))
check("R4 safety: state not taken from the spoof",
      steps.get("safety", {}).get("safety_state") not in ("idle",), steps.get("safety", {}).get("safety_state"))
unpriv = steps.get("safety", {}).get("info", {}).get("unprivileged_socket", "")
check("R4 safety: unprivileged PLC socket write refused", "Permission" in unpriv or "denied" in unpriv, unpriv)
check("agentd exit 0 on SIGTERM", agentd_rc == 0, agentd_rc)
verify = open(f"{out}/verify.txt").read()
check("black box INTACT", verify_rc == 0 and "RESULT: INTACT" in verify, verify.strip().splitlines()[-1:] )
json.dump({"checks": checks, "steps": steps}, open(f"{out}/results.json", "w"), indent=1)
bad = [c for c in checks if not c["pass"]]
for c in checks:
    print(f"nightly-redteam: {'PASS' if c['pass'] else 'FAIL'} {c['check']}: {c['detail']}")
if bad:
    for c in bad:
        print(f"::error::nightly red team: {c['check']}: {c['detail']}")
    sys.exit(1)
print(f"nightly-redteam: all {len(checks)} checks passed")
PY
