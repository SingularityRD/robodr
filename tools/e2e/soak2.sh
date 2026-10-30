#!/usr/bin/env bash
# Wave-2 soak (after soak2-setup.sh and gw-setup.sh). PIDs in RUN/pids/.
# usage: soak2.sh start RUN_DIR KAFKA_HOME SECONDS [INJECT_EVERY_S]
#        soak2.sh stop RUN_DIR KAFKA_HOME
set -euo pipefail
B=${ROBODR_BIN:-/home/user/wt/target-soak/release}
H=$(dirname "$(readlink -f "$0")")
REPO=$(cd "$H/../.." && pwd)
F=$REPO/fixtures/captures/ros2-jazzy
ASO_PY=${ASO_PY:-/home/user/autosecops1/.venv/bin/python}
cmd=$1; run=$2; kh=$3
P=$run/pids
kill_pf() { local p; p=$(cat "$P/$1.pid" 2>/dev/null) && kill -"${2:-TERM}" "$p" 2>/dev/null || true; }
if [ "$cmd" = stop ]; then
  for n in soc gen-gw gen-ugv safety; do kill_pf "$n"; done
  sleep 3
  kill_pf agentd; kill_pf gateway
  sleep 10
  for n in kpub executor anchor-rx monitor; do kill_pf "$n"; done
  "$kh/bin/kafka-server-stop.sh" >/dev/null 2>&1 || true
  exit 0
fi
secs=$4; every=${5:-600}
mkdir -p "$P" "$run/logs" "$run/kpub-state"; chmod 700 "$run/kpub-state"
start() { # name, then the command
  local n=$1; shift
  nohup "$@" >"$run/logs/$n.log" 2>&1 &
  echo $! >"$P/$n.pid"
}
wait_for() { for _ in $(seq 1 "$2"); do [ -e "$1" ] && return 0; sleep 1; done; echo "timeout waiting for $1" >&2; return 1; }

# Kafka (root ns, mutual TLS on localhost:19096).
export KAFKA_HEAP_OPTS="-Xmx512m -Xms256m" LOG_DIR=$run/kafka/logs
start kafka "$kh/bin/kafka-server-start.sh" "$run/kafka/server.properties"
for _ in $(seq 1 60); do
  "$kh/bin/kafka-topics.sh" --bootstrap-server localhost:29192 --list >/dev/null 2>&1 && break; sleep 1
done
"$kh/bin/kafka-topics.sh" --bootstrap-server localhost:29192 --create --if-not-exists \
  --topic robodr.findings --partitions 3 --replication-factor 1 >/dev/null 2>&1

start anchor-rx ip netns exec rdr-rob "$B/robodr-anchor-receiver" serve --config "$run/anchor-rx/receiver.json"
start executor ip netns exec rdr-rob "$B/robodr-executor" --config "$run/ugv/executor.json"
wait_for "$run/ugv/executor.sock" 20
start agentd ip netns exec rdr-rob "$B/robodr-agentd" --config "$run/ugv/agentd.json"
wait_for "$run/ugv/safety.sock" 30; wait_for "$run/gateway-feed.sock" 30
# The gateway at the unit's real-time priority (robodr-firewall-gw.service:
# CPUSchedulingPolicy=fifo, priority 40).
start gateway ip netns exec sk-gw chrt -f 40 "$B/robodr-firewall-gw" run --config "$run/gw/gateway.json"
# The PLC gateway's role: a fresh state every 200 ms (root, 0600 socket).
start safety python3 -c "
import socket, time, sys
c = socket.socket(socket.AF_UNIX); c.connect(sys.argv[1])
while True:
    c.sendall(b'{\"state\":\"idle\"}\n'); time.sleep(0.2)
" "$run/ugv/safety.sock"
start kpub "$B/robodr-kafka-publish" --bootstrap localhost:19096 --state-dir "$run/kpub-state" \
  --spool "$run/ugv/spool" --tls-ca "$run/tls/anchor/ca.pem" --tls-cert "$run/tls/anchor/client.pem" \
  --tls-key "$run/tls/anchor/client.key" --interval-ms 2000
start gen-ugv ip netns exec rdr-gen python3 "$H/replay.py" gen-ugv \
  --base "$F/fastrtps_gz_baseline.pcap" --inject "$F/fastrtps_gz_rogue_cmd_vel.pcap" \
  --every "$every" --duration "$secs" --log "$run/logs/gen-ugv.events"
start gen-gw chrt -f 30 "$B/examples/soak_traffic" soak sk-ctrl sk-rob "$secs" "$run/logs/gw-traffic.jsonl" "$every"
start soc ip netns exec rdr-rob "$ASO_PY" "$H/soak_soc.py" "$run" "$run/logs/soc.jsonl" "$secs" 900
start monitor python3 "$H/soak2_monitor.py" "$run" "$run/logs/metrics.jsonl" 60 \
  agentd="$P/agentd.pid" gateway="$P/gateway.pid" executor="$P/executor.pid" anchor-rx="$P/anchor-rx.pid" \
  kpub="$P/kpub.pid" kafka="$P/kafka.pid"
echo "soak started in $run for $secs s"
