#!/usr/bin/env bash
# Inline gateway topology for the soak / red team (as tests/netns_e2e.rs):
#   $PFX-ctrl (controller 192.168.123.164, c0)
#     <-veth-> $PFX-gw (bridge br0: gc0 + gr0, robodr-firewall-gw on NFQUEUE)
#     <-veth-> $PFX-rob (robot 192.168.123.161, r0)
#   $PFX-atk: macvlan on the controller link (attacker 192.168.123.99).
# Writes GW_DIR/{profile.json(+.sig),firewall.json,gateway.json,
# profile-trust.json} (Go2 LowCmd + sport + ROS 2 JointTrajectory channels,
# test keys only) and installs the gateway's ruleset in $PFX-gw.
# usage: gw-setup.sh up GW_DIR FINDINGS_SOCKET RESTRICTION_PATH
#        gw-setup.sh down
# Environment: PFX (namespace prefix, default sk), QNUM (NFQUEUE number,
# default 11), WEBRTC=1 (adds a Go2 `webrtc` section: controller
# 192.168.123.164 MAC-bound, action block_unlisted, max_sessions 1).
set -euo pipefail
B=${ROBODR_BIN:-/home/user/wt/target-soak/release}
PFX=${PFX:-sk}; QNUM=${QNUM:-11}; WEBRTC=${WEBRTC:-0}
if [ "$1" = down ]; then
  for ns in ctrl gw rob atk; do ip netns del "$PFX-$ns" 2>/dev/null || true; done
  exit 0
fi
gw=$2; feed=$3; restr=$4
mkdir -p "$gw"; cd "$gw"
"$B/examples/soak_traffic" setup . >/dev/null
python3 - <<'PY'
import hashlib
body = open("profile.json").read()
d = hashlib.sha256(body.encode()).hexdigest()
open("profile.json", "w").write('{\n  "seal": "sha256:%s",\n%s' % (d, body[2:]))
PY
[ -f prof.key ] || "$B/robodr-blackbox" keygen --out prof.key --key-id soak-profile >/dev/null
"$B/robodr-commission" sign --profile profile.json --sign-key prof.key --allow-unattested --force 2>/dev/null
"$B/robodr-commission" trust-keys --out profile-trust.json --pub prof.key.pub --force >/dev/null 2>&1
mkdir -p state "$(dirname "$restr")"
python3 - "$gw" "$feed" "$restr" "$QNUM" "$WEBRTC" <<'PY'
import json, sys
gw, feed, restr, qnum, webrtc = sys.argv[1:]
ctrl = "192.168.123.164"
joints = [{"name": n, "min_position": -2.0, "max_position": 2.0, "max_velocity": 1.5,
           "max_acceleration": 4.0, "max_effort": 20.0}
          for n in ("shoulder_pan_joint", "shoulder_lift_joint", "elbow_joint")]
cfg = {
  "mode": "enforce",
  "profile": f"{gw}/profile.json",
  "profile_trust": {"trusted_keys": f"{gw}/profile-trust.json"},
  "firewall": f"{gw}/firewall.json",
  "queue": {"num": int(qnum), "on_gateway_down": "fail_closed", "max_len": 1024,
            "controller_port": "gc0", "robot_port": "gr0"},
  "rtps": {"domain_ids": [0], "malformed_datagram": "drop", "unknown_writers": "probe",
           "state_file": f"{gw}/state/writers.json"},
  "channels": [
    {"firewall_channel": "/lowcmd", "codec": "unitree_go_lowcmd", "allowed_src_ips": [ctrl]},
    {"firewall_channel": "/api/sport/request", "codec": "unitree_sport_request",
     "allowed_src_ips": [ctrl], "allowed_api_ids": [1003, 1008, 1001, 1004, 1015]},
    {"firewall_channel": "/arm_trajectory", "codec": "ros2_joint_trajectory",
     "topic": "rt/arm_controller/joint_trajectory", "allowed_src_ips": [ctrl],
     "trajectory": {"joints": joints, "max_points": 64, "max_duration_s": 20.0}},
  ],
  "max_queue_delay_ns": 5000000,
  "events_path": f"{gw}/events.jsonl",
  "status_path": f"{gw}/status.json",
  "housekeeping_ms": 100,
  "findings_socket": feed,
  "restriction_path": restr,
}
if webrtc == "1":
    cfg["webrtc"] = {"action": "block_unlisted", "robot_addresses": ["192.168.123.161"],
                     "controllers": [{"ip": ctrl, "mac": "02:00:00:00:01:64", "label": "controller"}],
                     "max_sessions": 1}
json.dump(cfg, open(f"{gw}/gateway.json", "w"), indent=2)
PY
"$B/robodr-firewall-gw" check-config --config gateway.json
for ns in ctrl gw rob atk; do ip netns add "$PFX-$ns"; done
ip link add c0 netns $PFX-ctrl type veth peer name gc0 netns $PFX-gw
ip link add r0 netns $PFX-rob type veth peer name gr0 netns $PFX-gw
ip -n $PFX-gw link add br0 type bridge
ip -n $PFX-gw link set gc0 master br0; ip -n $PFX-gw link set gr0 master br0
for l in gc0 gr0 br0 lo; do ip -n $PFX-gw link set "$l" up; done
ip -n $PFX-ctrl link set c0 address 02:00:00:00:01:64; ip -n $PFX-ctrl addr add 192.168.123.164/24 dev c0; ip -n $PFX-ctrl link set c0 up; ip -n $PFX-ctrl link set lo up
ip -n $PFX-rob addr add 192.168.123.161/24 dev r0; ip -n $PFX-rob link set r0 up; ip -n $PFX-rob link set lo up
ip -n $PFX-ctrl link add link c0 name m0 type macvlan mode bridge
ip -n $PFX-ctrl link set m0 netns $PFX-atk
ip -n $PFX-atk addr add 192.168.123.99/24 dev m0; ip -n $PFX-atk link set m0 up; ip -n $PFX-atk link set lo up
"$B/robodr-firewall-gw" ruleset --config gateway.json > ruleset.sh
ip netns exec $PFX-gw sh ruleset.sh
echo "gateway topology $PFX up; ruleset installed in $PFX-gw"
