#!/usr/bin/env bash
# Reduced red-team target for the TLS slowloris scenarios S2 / S3
# (redteam2_tls.py; W2-4): the parts those scenarios exercise, without the
# network namespaces, the inline gateway, the executor or Kafka. TEST KEYS
# ONLY. In the root namespace on loopback:
#   robodr-agentd  rt-ugv-001: pcap replay of the Gazebo baseline (kept
#                  running), control plane v2 on mutual TLS 127.0.0.1:8788,
#                  remote head anchor over mutual TLS to
#   robodr-anchor-receiver  127.0.0.1:7462 (max_connections 64, 8 per
#                  source, io_timeout 5 s, as in soak2-setup.sh).
# The run directory has the layout redteam2_tls.py and soclib.py expect
# (RUN/soc.key, RUN/tls, RUN/rt, RUN/anchor-rx).
#
# usage: redteam2-slowloris.sh setup|start|stop RUN_DIR
# Environment: ROBODR_BIN (release binaries), CP_EXTRA (JSON merged into
# agentd's control_plane, e.g. '{"priority_sources":["127.0.0.1/32"]}'),
# RX_EXTRA (JSON merged into receiver.json).
#
# Then (AutoSecOps venv python for the SOC client):
#   redteam2_tls.py RUN cp 8 2 40; redteam2_tls.py RUN cp 32 2 40
#   redteam2_tls.py RUN anchor 10 8 40
set -euo pipefail
cmd=$1; run=$2
B=${ROBODR_BIN:-/home/user/wt/target-soak/release}
H=$(dirname "$(readlink -f "$0")")
REPO=$(cd "$H/../.." && pwd)
export ROBODR_BIN=$B ROBODR_REPO=$REPO
P=$run/pids
kill_pf() { local p; p=$(cat "$P/$1.pid" 2>/dev/null) && kill -TERM "$p" 2>/dev/null || true; }
case $cmd in
stop)
  kill_pf agentd; sleep 3; kill_pf anchor-rx
  exit 0 ;;
start)
  mkdir -p "$P" "$run/logs"
  nohup "$B/robodr-anchor-receiver" serve --config "$run/anchor-rx/receiver.json" \
    >"$run/logs/anchor-rx.log" 2>&1 & echo $! >"$P/anchor-rx.pid"
  sleep 1
  nohup "$B/robodr-agentd" --config "$run/rt/agentd.json" >"$run/logs/agentd.log" 2>&1 &
  echo $! >"$P/agentd.pid"
  for _ in $(seq 1 30); do [ -e "$run/rt/spool/status.json" ] && break; sleep 1; done
  echo "slowloris target up in $run"
  exit 0 ;;
setup) ;;
*) echo "usage: $0 setup|start|stop RUN_DIR" >&2; exit 2 ;;
esac

F=$REPO/fixtures/captures/ros2-jazzy
rt=$run/rt; mkdir -p "$rt" "$run/tls/anchor" "$run/anchor-rx"
cp "$REPO"/crates/robodr-agentd/tests/data/control-tls/{robot.pem,robot.key,soc-ca.pem,soc.pem,soc.key,robot-ca.pem} "$run/tls/"
cp "$REPO"/fixtures/tls/{ca.pem,server.pem,server.key,client.pem,client.key} "$run/tls/anchor/"
chmod 600 "$run"/tls/*.key "$run"/tls/anchor/*.key
[ -f "$run/soc.key" ] || "$B/robodr-blackbox" keygen --out "$run/soc.key" --key-id soc:rt:1 >/dev/null
[ -f "$run/profile/locked.json" ] || "$H/commission.sh" "$run/profile" "$F/fastrtps_gz_baseline.pcap" >/dev/null
cp "$run/profile"/{locked.json,locked.json.sig,profile-trust.json} "$rt/"
"$H/agentd-config.py" "$rt" rt-ugv-001 --pcap "$F/fastrtps_gz_baseline.pcap" --no-exit --control \
  --soc-key "$run/soc.key.pub" --cp-tls "$run/tls" --cp-listen 127.0.0.1:8788 >/dev/null
[ -f "$run/anchor-rx/receiver.key" ] || "$B/robodr-blackbox" keygen --out "$run/anchor-rx/receiver.key" --key-id anchor-rx-rt >/dev/null
mkdir -p -m 700 "$run/anchor-rx/state"
cpx=${CP_EXTRA:-'{}'}; rxx=${RX_EXTRA:-'{}'}
python3 - "$run" "$rt" "$cpx" "$rxx" <<'PY'
import json, sys
run, rt, cp_extra, rx_extra = sys.argv[1:]
c = json.load(open(f"{rt}/agentd.json"))
# 2 s probes for 40 s plus baselines: above the default 30/min key limit.
c["control_plane"].update({"rate_per_minute": 120, "burst": 20})
c["control_plane"].update(json.loads(cp_extra))
c["blackbox"]["head_anchor"] = {
    "kind": "remote", "address": "127.0.0.1:7462",
    "receiver_public_key": f"{run}/anchor-rx/receiver.key.pub", "timeout_ms": 2000,
    "tls": {"ca_file": f"{run}/tls/anchor/ca.pem", "cert_chain": f"{run}/tls/anchor/client.pem",
            "key_file": f"{run}/tls/anchor/client.key"}}
json.dump(c, open(f"{rt}/agentd.json", "w"), indent=2)
r = {"listen": "127.0.0.1:7462", "state_dir": f"{run}/anchor-rx/state",
     "key_file": f"{run}/anchor-rx/receiver.key",
     "units": [{"unit": "rt-ugv-001", "public_key": f"{rt}/blackbox.key.pub"}],
     "max_connections": 64, "max_connections_per_source": 8, "io_timeout_ms": 5000,
     "tls": {"cert_chain": f"{run}/tls/anchor/server.pem", "key_file": f"{run}/tls/anchor/server.key",
             "client_ca": f"{run}/tls/anchor/ca.pem"}}
r.update(json.loads(rx_extra))
json.dump(r, open(f"{run}/anchor-rx/receiver.json", "w"), indent=2)
PY
"$B/robodr-agentd" --config "$rt/agentd.json" --check-config 2>&1 | tail -1
echo "set up in $run"
