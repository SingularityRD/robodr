#!/usr/bin/env bash
# Wave-2 red-team target rt-ugv-001 (after `RID=rt-ugv-001 SUB=rt
# IFACE=rob-rt CPPORT=8788 APORT=7462 NOKAFKA=1 soak2-setup.sh RUN none`
# and `PFX=rk QNUM=12 WEBRTC=1 gw-setup.sh up RUN/gw RUN/gateway-feed.sock
# RUN/restrict/restriction.json`): anchor receiver, executor and agentd in
# netns rdr-rob (capture rob-rt, control plane 127.0.0.1:8788), the inline
# gateway in rk-gw, a PLC-role safety feeder ("idle" every 200 ms).
# usage: redteam2.sh start|stop RUN_DIR
set -euo pipefail
B=${ROBODR_BIN:-/home/user/wt/target-soak/release}
cmd=$1; run=$2; P=$run/pids; NS=${NS:-rt-rob}
kill_pf() { local p; p=$(cat "$P/$1.pid" 2>/dev/null) && kill -TERM "$p" 2>/dev/null || true; }
if [ "$cmd" = stop ]; then
  kill_pf safety; kill_pf agentd; kill_pf gateway; sleep 8
  kill_pf executor; kill_pf anchor-rx
  exit 0
fi
mkdir -p "$P" "$run/logs"
start() { local n=$1; shift; nohup "$@" >"$run/logs/$n.log" 2>&1 & echo $! >"$P/$n.pid"; }
wait_for() { for _ in $(seq 1 "$2"); do [ -e "$1" ] && return 0; sleep 1; done; echo "timeout: $1" >&2; return 1; }
start anchor-rx ip netns exec "$NS" "$B/robodr-anchor-receiver" serve --config "$run/anchor-rx/receiver.json"
start executor ip netns exec "$NS" "$B/robodr-executor" --config "$run/rt/executor.json"
wait_for "$run/rt/executor.sock" 20
start agentd ip netns exec "$NS" "$B/robodr-agentd" --config "$run/rt/agentd.json"
wait_for "$run/rt/safety.sock" 30; wait_for "$run/gateway-feed.sock" 30
start gateway ip netns exec rk-gw chrt -f 40 "$B/robodr-firewall-gw" run --config "$run/gw/gateway.json"
start safety python3 -c "
import socket, time, sys
c = socket.socket(socket.AF_UNIX); c.connect(sys.argv[1])
while True:
    c.sendall(b'{\"state\":\"idle\"}\n'); time.sleep(0.2)
" "$run/rt/safety.sock"
echo "red-team target up in $run"
