#!/bin/sh
# Demo robot: commission a locked, signed profile from the real ROS 2 Jazzy
# baseline capture (the CLI flow of docs/OPERATIONS.md "Commissioning", as
# tools/e2e/commission.sh), generate every key the demo needs, merge the
# attack scenarios into the capture with robodr-attack-sim, and replay it
# through robodr-agentd. DEMO KEYS ONLY: all generated fresh in demo/state.
set -eu
B=/opt/robodr/bin
S=/demo/state
F=/demo/fixtures
ROBOT=demo-ugv-01
umask 077

say() { printf '[robot] %s\n' "$*"; }

if [ -f "$S/robot.done" ]; then
  say "already ran (rm -rf demo/state to start over)"
  exit 0
fi
rm -rf "$S/commission" "$S/keys" "$S/spool" "$S/spool-siem" "$S/blackbox"
mkdir -p "$S/commission" "$S/keys" "$S/spool" "$S/spool-siem/ready" "$S/spool-siem/acked" "$S/blackbox"

say "1/5 learn the model profile from the baseline capture"
cd "$S/commission"
"$B/robodr-commission" learn --pcap "$F/fastrtps_baseline.pcap" --model lab-ugv \
  --out draft.json --report report.json --quiet --force

say "2/5 two operators sign off, the OEM key locks and signs the profile"
for op in alice bob; do
  "$B/robodr-blackbox" keygen --out "op-$op.key" --key-id "op-$op" >/dev/null
done
"$B/robodr-commission" operators --out operators.json \
  --operator Alice=op-alice.key.pub --operator Bob=op-bob.key.pub --motion-quorum 2
# The demo stands in for the operators' review: confirm every item.
sed -i -e 's/"confirmed": *false/"confirmed": true/g' \
  -e 's/"operator": *""/"operator": "Alice"/' draft.json.signoff.json
for op in alice bob; do
  "$B/robodr-commission" signoff --signoff draft.json.signoff.json \
    --sign-key "op-$op.key" --in draft.json --operators operators.json
done
"$B/robodr-blackbox" keygen --out oem-profile.key --key-id oem-profile >/dev/null
"$B/robodr-commission" lock --in draft.json --signoff draft.json.signoff.json \
  --operators operators.json --out locked.json --platform lab-ugv \
  --profile-version 1 --sign-key oem-profile.key
"$B/robodr-commission" trust-keys --out profile-trust.json --pub oem-profile.key.pub \
  --operators operators.json --force
"$B/robodr-commission" verify-profile --profile locked.json \
  --trusted-keys profile-trust.json --expect-platform lab-ugv

say "3/5 keys: black box, finding signatures, uplinks"
cd "$S/keys"
"$B/robodr-blackbox" keygen --out blackbox.key --key-id "blackbox:$ROBOT" --device "$ROBOT" >/dev/null
"$B/robodr-blackbox" keygen --out finding.key --key-id "finding:$ROBOT:1" >/dev/null
"$B/robodr-blackbox" keygen --out finding-live.key --key-id "finding:$ROBOT-live:1" >/dev/null
"$B/robodr-blackbox" keygen --out blackbox-live.key --key-id "blackbox:$ROBOT-live" --device "$ROBOT-live" >/dev/null
"$B/robodr-blackbox" keygen --out uplink.key >/dev/null
"$B/robodr-blackbox" keygen --out uplink-live.key >/dev/null
chmod 0644 ./*.pub

cat > "$S/soc.json" <<EOF
{"robots": [{"id": "$ROBOT", "site": "demo-lab", "require_finding_signature": true},
            {"id": "$ROBOT-live", "site": "demo-lab", "require_finding_signature": true}],
 "keys": [{"role": "uplink", "robot": "$ROBOT", "pub": "$S/keys/uplink.key.pub"},
          {"role": "finding", "robot": "$ROBOT", "pub": "$S/keys/finding.key.pub"},
          {"role": "uplink", "robot": "$ROBOT-live", "pub": "$S/keys/uplink-live.key.pub"},
          {"role": "finding", "robot": "$ROBOT-live", "pub": "$S/keys/finding-live.key.pub"}]}
EOF

say "4/5 attack capture: every robodr-attack-sim scenario on the baseline"
"$B/robodr-attack-sim" pcap --scenario all --carrier "$F/fastrtps_baseline.pcap" \
  --out "$S/attack.pcap" --count 600 > "$S/attack-plan.json"

say "5/5 replay through robodr-agentd"
sed -e "s|@ROBOT@|$ROBOT|g" -e "s|@CAPTURE@|\"pcap_replay\": \"$S/attack.pcap\"|" \
  -e "s|@SUFFIX@||g" -e "s|@EXIT@|true|" /demo/config/agentd.json.in > "$S/agentd.json"
"$B/robodr-agentd" --config "$S/agentd.json" --check-config
"$B/robodr-agentd" --config "$S/agentd.json"

# Demo-only fan-out: the SIEM path (Kafka) gets its own copy of the spool,
# since each exporter consumes the spool it reads (ready/ -> acked/).
cp -p "$S/spool/ready/"* "$S/spool-siem/ready/" 2>/dev/null || true
n=$(ls "$S/spool/ready" | wc -l)
say "done: $n findings spooled; the SOC viewer is on http://127.0.0.1:${DEMO_SOC_PORT:-8080}/"
"$B/robodr-attack-sim" score --scenario all --findings "$S/spool" > "$S/score.json" || true
touch "$S/robot.done"
