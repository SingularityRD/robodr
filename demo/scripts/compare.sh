#!/bin/sh
# RoboDR side of the Pulsar-only comparison (T65): every attack-sim scenario,
# from two attacker placements, replayed through robodr-agentd with the demo
# profile, scored. tools/e2e/compare_pulsar_only.py builds the table.
#   foreign   the attacker is a new host on the robot network (10.77.10.66)
#   insider   the attacker runs on the operator's own host (10.77.10.21),
#             e.g. a compromised teleop laptop: same address as legit traffic
set -eu
B=/opt/robodr/bin
S=/demo/state
F=/demo/fixtures
[ -f "$S/robot.done" ] || { echo "run demo/run.sh first (it commissions the profile)"; exit 1; }
out="$S/compare"
rm -rf "$out"
mkdir -p "$out"
for placement in foreign:10.77.10.66 insider:10.77.10.21; do
  name=${placement%%:*}
  ip=${placement#*:}
  "$B/robodr-attack-sim" pcap --scenario all --carrier "$F/fastrtps_baseline.pcap" \
    --attacker-ip "$ip" --count 600 --out "$out/$name.pcap" > "$out/$name-plan.json"
  sed -e "s|@ROBOT@@SUFFIX@|demo-ugv-01|" -e "s|@SUFFIX@|-cmp-$name|g" \
    -e "s|@CAPTURE@|\"pcap_replay\": \"$out/$name.pcap\"|" -e "s|@EXIT@|true|" \
    -e "s|/demo/state/keys/blackbox-cmp-$name.key|/demo/state/keys/blackbox.key|" \
    -e "s|/demo/state/keys/finding-cmp-$name.key|/demo/state/keys/finding.key|" \
    /demo/config/agentd.json.in > "$out/agentd-$name.json"
  rm -rf "$S/spool-cmp-$name" "$S/blackbox-cmp-$name" "$S/profile-state-cmp-$name.json"
  "$B/robodr-agentd" --config "$out/agentd-$name.json" > "$out/agentd-$name.log" 2>&1
  "$B/robodr-attack-sim" score --scenario all --findings "$S/spool-cmp-$name" \
    > "$out/$name-score.json" || true
  echo "[compare] $name: $(grep -c '"pass": true' "$out/$name-score.json") scenario lines passed"
done
