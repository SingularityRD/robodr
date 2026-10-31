#!/bin/sh
# RoboDR side of the Pulsar-only comparison (T65): every attack-sim scenario,
# from two attacker placements, each scenario ALONE in its own capture,
# replayed through its own robodr-agentd run with the demo profile and
# scored on its own spool, so no scenario is credited with findings another
# one raised. tools/e2e/compare_pulsar_only.py builds the table.
#   foreign   the attacker is a new host on the robot network (10.77.10.66)
#   insider   the attacker runs on the operator's own host (10.77.10.21),
#             e.g. a compromised teleop laptop: same address as legit traffic
set -eu
B=/opt/robodr/bin
S=/demo/state
F=/demo/fixtures
SCENARIOS="rogue-participant guid-spray malformed-rtps cmd-vel-envelope lowcmd-torque"
[ -f "$S/robot.done" ] || { echo "run demo/run.sh first (it commissions the profile)"; exit 1; }
out="$S/compare"
rm -rf "$out"
mkdir -p "$out"
for placement in foreign:10.77.10.66 insider:10.77.10.21; do
  name=${placement%%:*}
  ip=${placement#*:}
  for sc in $SCENARIOS; do
    run="$name-$sc"
    "$B/robodr-attack-sim" pcap --scenario "$sc" --carrier "$F/fastrtps_baseline.pcap" \
      --attacker-ip "$ip" --count 600 --out "$out/$run.pcap" > "$out/$run-plan.json"
    sed -e "s|@ROBOT@@SUFFIX@|demo-ugv-01|" -e "s|@SUFFIX@|-cmp-$run|g" \
      -e "s|@CAPTURE@|\"pcap_replay\": \"$out/$run.pcap\"|" -e "s|@EXIT@|true|" \
      -e "s|/demo/state/keys/blackbox-cmp-$run.key|/demo/state/keys/blackbox.key|" \
      -e "s|/demo/state/keys/finding-cmp-$run.key|/demo/state/keys/finding.key|" \
      /demo/config/agentd.json.in > "$out/agentd-$run.json"
    rm -rf "$S/spool-cmp-$run" "$S/blackbox-cmp-$run" "$S/profile-state-cmp-$run.json"
    "$B/robodr-agentd" --config "$out/agentd-$run.json" > "$out/agentd-$run.log" 2>&1
    # score exits 1 when the scenario's own expected id is missing; from the
    # insider placement that is expected for lowcmd-torque (the operator's
    # host is the configured legacy sender). The table credits each scenario
    # by its evidence ids (compare_pulsar_only.py, EVIDENCE) and says which.
    st=0
    "$B/robodr-attack-sim" score --scenario "$sc" --findings "$S/spool-cmp-$run" \
      > "$out/$run-score.json" || st=$?
    [ "$st" -le 1 ] || { echo "[compare] $run: score failed ($st)"; exit 1; }
    echo "[compare] $run: expected ids $( [ "$st" -eq 0 ] && echo present || echo MISSING )"
  done
done
