#!/usr/bin/env bash
# Red-team robot "rt-ugv-001" in netns rdr-rob: agentd (capture rob-rt,
# control plane v2 over mutual TLS on 127.0.0.1:8787 inside the netns + unix
# socket, live safety feed, executor v1 enabled) and robodr-executor (real
# nftables, inside rdr-rob only). TEST KEYS ONLY.
# usage: redteam-setup.sh RT_DIR PROFILE_DIR CP_TLS_DIR SOC_PUB
set -euo pipefail
rt=$1; prof=$2; tls=$3; socpub=$4
B=${ROBODR_BIN:-/home/user/robodr/target/release}
H=$(dirname "$(readlink -f "$0")")
mkdir -p "$rt"; cd "$rt"
cp "$prof"/locked.json "$prof"/locked.json.sig "$prof"/profile-trust.json .
[ -f executor.key ] || "$B/robodr-executor" keygen --out executor.key >/dev/null
mkdir -p -m 700 exec-state
"$H/agentd-config.py" . rt-ugv-001 --iface rob-rt --control --soc-key "$socpub" \
  --cp-tls "$tls" --cp-listen 127.0.0.1:8787 >/dev/null
python3 - "$rt" <<'PY'
import json, sys
rt = sys.argv[1]
c = json.load(open(f"{rt}/agentd.json"))
c["context"] = {"safety_state": "unknown"}
c["safety_feed"] = {
    "stale_after_ms": 1000,
    "topics": [{"topic": "/odom", "type": "nav_msgs/msg/Odometry",
                "motion": {"moving_above": 0.05, "fast_above": 1.0, "hysteresis": 0.02},
                "writers": ["identity:gz_bridge"]}],
    "socket": {"path": f"{rt}/safety.sock", "max_connections": 2},
}
c["executor"] = {"enabled": True, "socket": f"{rt}/executor.sock",
                 "key_file": f"{rt}/executor.key", "planner_orders": False}
json.dump(c, open(f"{rt}/agentd.json", "w"), indent=2)
e = {
  "schema": "robodr-executor-config/v1", "robot_id": "rt-ugv-001",
  "socket": f"{rt}/executor.sock", "socket_mode": "0600",
  "key_file": f"{rt}/executor.key", "state_dir": f"{rt}/exec-state",
  "policy_path": f"{rt}/policy.json", "nft": "/usr/sbin/nft",
  "network": {
    "management": [{"cidr": "10.99.3.0/24", "proto": "tcp", "port": 22}],
    "uplink": [{"cidr": "127.0.0.1", "proto": "tcp", "port": 8000}],
    "control_buses": {"exempt": True, "entries": [{"interface": "rob-go2"}]},
    "motion_control_path": [{"cidr": "10.77.10.10", "udp_ports": [7400, 7600]}],
    "discovery": {"multicast_groups": ["239.255.0.1"], "domains": [0]},
    "quarantine": {"cidrs": ["10.77.10.0/24"]},
  },
  "ttl": {"default_s": 900, "max_s": 86400},
  "max_safety_age_ms": 500, "verify_interval_s": 10,
  "soc": {"keys": [sys.argv[0] and None] if False else [], "max_clock_skew_s": 30,
          "robot_keys": [f"{rt}/blackbox.key.pub", f"{rt}/finding.key.pub"]},
  "require_approval_for_all_containment": False,
}
json.dump(e, open(f"{rt}/executor.json", "w"), indent=2)
PY
python3 - "$rt/executor.json" "$socpub" <<'PY'
import json, sys
p, soc = sys.argv[1:]
e = json.load(open(p)); e["soc"]["keys"] = [soc]; json.dump(e, open(p, "w"), indent=2)
PY
ip netns exec rdr-rob "$B/robodr-executor" --config executor.json --check-config
ip netns exec rdr-rob "$B/robodr-agentd" --config agentd.json --check-config 2>&1 | tail -1
