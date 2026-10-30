#!/usr/bin/env bash
# Wave-2 soak robot "soak-ugv-001" (TEST KEYS ONLY), all real binaries:
#   netns rdr-rob: robodr-agentd (live capture on rob-ugv; control plane v2
#     on mutual TLS 127.0.0.1:8787 + unix socket; live safety feed; executor
#     link; gateway_feed from robodr-firewall-gw; remote head anchor over
#     mutual TLS to robodr-anchor-receiver 127.0.0.1:7461; status socket),
#     robodr-executor (nftables inside rdr-rob, motion adapters: `gateway`
#     for restrict_motion, `nav2` for safe_pause with no peer),
#     robodr-anchor-receiver.
#   root ns: Apache Kafka (local distribution, mutual-TLS listener
#     localhost:19096) and robodr-kafka-publish draining agentd's spool.
#   sk-* namespaces: the inline gateway (gw-setup.sh).
# usage: soak2-setup.sh RUN_DIR KAFKA_HOME
# Environment (red-team instance): RID (robot id, default soak-ugv-001),
# SUB (robot directory under RUN_DIR, default ugv), IFACE (capture,
# default rob-ugv), CPPORT (8787), APORT (anchor receiver, 7461),
# NOKAFKA=1 (no broker).
set -euo pipefail
run=$1; kafka_home=$2
RID=${RID:-soak-ugv-001}; SUB=${SUB:-ugv}; IFACE=${IFACE:-rob-ugv}
CPPORT=${CPPORT:-8787}; APORT=${APORT:-7461}; NOKAFKA=${NOKAFKA:-0}
B=${ROBODR_BIN:-/home/user/wt/target-soak/release}
H=$(dirname "$(readlink -f "$0")")
REPO=$(cd "$H/../.." && pwd)
export ROBODR_BIN=$B ROBODR_REPO=$REPO
F=$REPO/fixtures/captures/ros2-jazzy
ugv=$run/$SUB; mkdir -p "$ugv" "$run/tls" "$run/restrict"
chmod 700 "$run/restrict"

# --- PKI (test fixtures; private keys copied 0600) -------------------------
cp "$REPO"/crates/robodr-agentd/tests/data/control-tls/{robot.pem,robot.key,soc-ca.pem,soc.pem,soc.key,robot-ca.pem} "$run/tls/"
mkdir -p "$run/tls/anchor"
cp "$REPO"/fixtures/tls/{ca.pem,server.pem,server.key,client.pem,client.key} "$run/tls/anchor/"
chmod 600 "$run"/tls/*.key "$run"/tls/anchor/*.key
[ -f "$run/soc.key" ] || "$B/robodr-blackbox" keygen --out "$run/soc.key" --key-id soc:soak:1 >/dev/null

# --- profile (real commissioning CLI flow on the Gazebo baseline) ----------
[ -f "$run/profile/locked.json" ] || "$H/commission.sh" "$run/profile" "$F/fastrtps_gz_baseline.pcap" >/dev/null
cp "$run/profile"/{locked.json,locked.json.sig,profile-trust.json} "$ugv/"
[ -f "$ugv/executor.key" ] || "$B/robodr-executor" keygen --out "$ugv/executor.key" >/dev/null
mkdir -p -m 700 "$ugv/exec-state" "$ugv/cp-state" "$run/anchor-rx"
"$H/agentd-config.py" "$ugv" "$RID" --iface "$IFACE" --control --soc-key "$run/soc.key.pub" \
  --cp-tls "$run/tls" --cp-listen "127.0.0.1:$CPPORT" >/dev/null
[ -f "$run/anchor-rx/receiver.key" ] || "$B/robodr-blackbox" keygen --out "$run/anchor-rx/receiver.key" --key-id anchor-rx-soak >/dev/null
# The remote anchor needs an Ed25519 black-box key whose .pub the receiver holds.
python3 - "$run" "$ugv" "$RID" "$APORT" <<'PY'
import json, sys
run, ugv, rid, aport = sys.argv[1:]
# The capture link's /24 is quarantinable; management is the other link.
net, mgmt = ("10.99.3", "10.99.1") if rid.startswith("rt-") else ("10.99.1", "10.99.3")
c = json.load(open(f"{ugv}/agentd.json"))
c["context"] = {"safety_state": "unknown"}
c["safety_feed"] = {
    "stale_after_ms": 1000,
    "topics": [{"topic": "/odom", "type": "nav_msgs/msg/Odometry",
                "motion": {"moving_above": 0.05, "fast_above": 1.0, "hysteresis": 0.02},
                "writers": ["identity:gz_bridge"]}],
    "socket": {"path": f"{ugv}/safety.sock", "max_connections": 2},
}
c["executor"] = {"enabled": True, "socket": f"{ugv}/executor.sock",
                 "key_file": f"{ugv}/executor.key", "planner_orders": False}
c["gateway_feed"] = {"socket_path": f"{run}/gateway-feed.sock", "allowed_uids": [0]}
c["spool"]["status_socket"] = f"{ugv}/status.sock"
c["blackbox"]["head_anchor"] = {
    "kind": "remote", "address": f"127.0.0.1:{aport}",
    "receiver_public_key": f"{run}/anchor-rx/receiver.key.pub", "timeout_ms": 2000,
    "tls": {"ca_file": f"{run}/tls/anchor/ca.pem", "cert_chain": f"{run}/tls/anchor/client.pem",
            "key_file": f"{run}/tls/anchor/client.key"}}
json.dump(c, open(f"{ugv}/agentd.json", "w"), indent=2)
e = {
  "schema": "robodr-executor-config/v1", "robot_id": rid,
  "socket": f"{ugv}/executor.sock", "socket_mode": "0600",
  "key_file": f"{ugv}/executor.key", "state_dir": f"{ugv}/exec-state",
  "policy_path": f"{ugv}/policy.json", "nft": "/usr/sbin/nft",
  "network": {
    "management": [{"cidr": f"{mgmt}.0/24", "proto": "tcp", "port": 22}],
    "uplink": [{"cidr": "127.0.0.1", "proto": "tcp", "port": int(aport)}],
    "control_buses": {"exempt": True, "entries": [{"interface": "rob-go2"}]},
    "motion_control_path": [{"cidr": "10.77.10.10", "udp_ports": [7400, 7600]}],
    "discovery": {"multicast_groups": ["239.255.0.1"], "domains": [0]},
    "quarantine": {"cidrs": [f"{net}.0/24"]},
  },
  "ttl": {"default_s": 900, "max_s": 86400},
  "max_safety_age_ms": 500, "verify_interval_s": 10,
  "soc": {"keys": [f"{run}/soc.key.pub"], "max_clock_skew_s": 30,
          "robot_keys": [f"{ugv}/blackbox.key.pub", f"{ugv}/finding.key.pub"]},
  "require_approval_for_all_containment": False,
  "motion": {
    "restrict_motion": ["gateway"], "safe_pause": "nav2", "request_safe_state": "nav2",
    "safe_pause_ttl_s": 600,
    "gateway": {"oem_validated": True, "restriction_path": f"{run}/restrict/restriction.json",
                "status_path": f"{run}/gw/status.json", "verify_timeout_ms": 3000},
    "nav2": {"oem_validated": True,
             "ros2": {"domain_id": 0, "peer_ip": f"{net}.1", "peer_participant_id": 0,
                      "local_ip": f"{net}.2", "participant_prefix": "01104242424242420a000001",
                      "rmw": "cyclonedds", "timeout_ms": 1500, "resend_ms": 200},
             "actions": ["/navigate_to_pose"], "cmd_vel_topic": "/cmd_vel",
             "zero_twists": 10, "zero_twist_interval_ms": 50,
             "allowed_states": ["idle", "moving_slow"]},
  },
}
json.dump(e, open(f"{ugv}/executor.json", "w"), indent=2)
r = {"listen": f"127.0.0.1:{aport}", "state_dir": f"{run}/anchor-rx/state",
     "key_file": f"{run}/anchor-rx/receiver.key",
     "units": [{"unit": rid, "public_key": f"{ugv}/blackbox.key.pub"}],
     "max_connections": 64, "max_connections_per_source": 8, "io_timeout_ms": 5000,
     "tls": {"cert_chain": f"{run}/tls/anchor/server.pem", "key_file": f"{run}/tls/anchor/server.key",
             "client_ca": f"{run}/tls/anchor/ca.pem"}}
json.dump(r, open(f"{run}/anchor-rx/receiver.json", "w"), indent=2)
PY
mkdir -p -m 700 "$run/anchor-rx/state"

# --- Kafka (mutual TLS listener; the fixture server cert names localhost) --
k=$run/kafka
if [ "$NOKAFKA" != 1 ] && [ ! -f "$k/server.properties" ]; then
  mkdir -p "$k"
  openssl pkcs12 -export -in "$REPO/fixtures/tls/server.pem" -inkey "$REPO/fixtures/tls/server.key" \
    -certfile "$REPO/fixtures/tls/ca.pem" -name broker -passout pass:soak-it -out "$k/broker.p12"
  keytool -importcert -noprompt -alias ca -file "$REPO/fixtures/tls/ca.pem" -keystore "$k/trust.p12" \
    -storetype PKCS12 -storepass soak-it >/dev/null 2>&1
  cat >"$k/server.properties" <<EOF
process.roles=broker,controller
node.id=1
controller.quorum.voters=1@localhost:29193
listeners=MTLS://localhost:19096,INTERNAL://localhost:29192,CONTROLLER://localhost:29193
advertised.listeners=MTLS://localhost:19096,INTERNAL://localhost:29192
listener.security.protocol.map=CONTROLLER:PLAINTEXT,INTERNAL:PLAINTEXT,MTLS:SSL
controller.listener.names=CONTROLLER
inter.broker.listener.name=INTERNAL
log.dirs=$k/data
num.partitions=1
offsets.topic.replication.factor=1
transaction.state.log.replication.factor=1
transaction.state.log.min.isr=1
auto.create.topics.enable=false
ssl.keystore.location=$k/broker.p12
ssl.keystore.type=PKCS12
ssl.keystore.password=soak-it
ssl.key.password=soak-it
ssl.truststore.location=$k/trust.p12
ssl.truststore.type=PKCS12
ssl.truststore.password=soak-it
listener.name.mtls.ssl.client.auth=required
EOF
  "$kafka_home/bin/kafka-storage.sh" format -t "$("$kafka_home/bin/kafka-storage.sh" random-uuid)" \
    -c "$k/server.properties" >/dev/null
fi

ip netns exec rdr-rob "$B/robodr-executor" --config "$ugv/executor.json" --check-config
ip netns exec rdr-rob "$B/robodr-agentd" --config "$ugv/agentd.json" --check-config 2>&1 | tail -3
echo "soak robot configured in $ugv"
