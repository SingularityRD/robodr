#!/usr/bin/env bash
# Start the S11-lite soak: agentd x2 (live capture in netns rdr-rob), uplink x2
# (root ns, plain HTTP to the loopback API), generators (netns rdr-gen),
# per-minute monitor. PIDs go to $RUN/pids.
# usage: soak.sh start RUN_DIR UGV_DIR GO2_DIR [INJECT_EVERY_S]
#        soak.sh stop RUN_DIR
set -euo pipefail
B=${ROBODR_BIN:-/home/user/robodr/target/release}
H=$(dirname "$(readlink -f "$0")")
F=${FIXTURES:-/home/user/robodr/fixtures/captures/ros2-jazzy}
API=${API:-http://127.0.0.1:8000/api}
cmd=$1; run=$2
if [ "$cmd" = stop ]; then
  # generators first, then agentd (SIGTERM seals the black box), uplink last
  # so it can drain; the monitor exits once every agentd is gone.
  for n in gen-ugv gen-go2; do kill "$(cat "$run/$n.pid")" 2>/dev/null || true; done
  sleep 3
  for n in agentd-ugv agentd-go2; do kill -TERM "$(cat "$run/$n.pid")" 2>/dev/null || true; done
  sleep 15
  for n in uplink-ugv uplink-go2 monitor; do kill -TERM "$(cat "$run/$n.pid")" 2>/dev/null || true; done
  exit 0
fi
ugv=$3; go2=$4; every=${5:-600}
mkdir -p "$run"
start() { # name, then the command
  local n=$1; shift
  nohup "$@" >"$run/$n.log" 2>&1 &
  echo $! >"$run/$n.pid"
}
start agentd-ugv ip netns exec rdr-rob "$B/robodr-agentd" --config "$ugv/agentd.json"
start agentd-go2 ip netns exec rdr-rob "$B/robodr-agentd" --config "$go2/agentd.json"
sleep 2
for r in ugv go2; do
  d=$ugv; key=$ugv/keys/uplink.key
  [ $r = go2 ] && d=$go2 && key=$go2/uplink.key
  mkdir -p -m 700 "$d/uplink-state"
  start "uplink-$r" "$B/robodr-uplink" --url "$API" --key-file "$key" \
    --state-dir "$d/uplink-state" --spool "$d/spool" --interval-ms 2000
done
start gen-ugv ip netns exec rdr-gen python3 "$H/replay.py" gen-ugv \
  --base "$F/fastrtps_gz_baseline.pcap" --inject "$F/fastrtps_gz_rogue_cmd_vel.pcap" \
  --every "$every" --log "$run/gen-ugv.events"
start gen-go2 ip netns exec rdr-gen python3 "$H/replay.py" gen-go2 \
  --base "$go2/capture.pcap" --gap 0.002 --log "$run/gen-go2.events"
sleep 1
# `ip netns exec` execs the target, so the PID is agentd's own.
start monitor python3 "$H/soak_monitor.py" "$run/metrics.csv" 60 \
  "ugv=soak-ugv-001:$(cat "$run/agentd-ugv.pid"):$ugv/spool:$ugv/blackbox:$ugv/uplink-state:$(cat "$run/uplink-ugv.pid")" \
  "go2=soak-go2-001:$(cat "$run/agentd-go2.pid"):$go2/spool:$go2/blackbox:$go2/uplink-state:$(cat "$run/uplink-go2.pid")"
echo "soak started in $run"
