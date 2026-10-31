#!/bin/sh
# Live attacker: sends the rogue-participant and guid-spray scenarios to the
# live robot (guarded: --i-understand, the demo subnet only), then scores the
# robot's spool with the injection time: time to detect per rule (T64).
set -eu
B=/opt/robodr/bin
S=/demo/state
F=/demo/fixtures
TARGET=172.30.77.20
say() { printf '[attacker] %s\n' "$*"; }

# Wait for the live robot to be up (its spool directory exists).
i=0
until [ -d "$S/spool-live/ready" ] || [ $i -ge 60 ]; do i=$((i + 1)); sleep 1; done
sleep 2

for sc in rogue-participant guid-spray; do
  out=$("$B/robodr-attack-sim" send --scenario "$sc" --carrier "$F/fastrtps_baseline.pcap" \
    --count 300 --target "$TARGET" --allow 172.30.77.0/24 --i-understand)
  say "$out"
  t=$(printf '%s' "$out" | sed -n 's/.*"first_send_unix_ms":\([0-9]*\).*/\1/p')
  # Score until every expected rule is in the spool (or 30 s).
  i=0
  until "$B/robodr-attack-sim" score --scenario "$sc" --findings "$S/spool-live" \
      --injected-at-ms "$t" > "$S/live-score-$sc.json" 2>/dev/null || [ $i -ge 30 ]; do
    i=$((i + 1)); sleep 1
  done
  say "$sc: $(tr -d '\n ' < "$S/live-score-$sc.json" | sed 's/"other_rule_ids".*//')"
  sleep 3
done
say "time to detect: demo/state/live-score-*.json; time to SOC: http://127.0.0.1:${DEMO_SOC_PORT:-8080}/api/metrics"
