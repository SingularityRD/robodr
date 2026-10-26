#!/usr/bin/env bash
# Commission a locked, signed lab profile from a baseline capture with the
# real CLI flow (docs/OPERATIONS.md "Commissioning"): learn -> confirm the
# sign-off list -> two operator signatures -> lock --sign-key -> trust file.
# usage: commission.sh OUT_DIR BASELINE.pcap [learn args...]
# TEST KEYS ONLY: every key is generated fresh in OUT_DIR.
set -euo pipefail
out=$1; pcap=$2; shift 2
B=${ROBODR_BIN:-/home/user/robodr/target/release}
mkdir -p "$out"; cd "$out"
"$B/robodr-commission" learn --pcap "$pcap" --model lab-ugv --out draft.json \
  --report report.json --quiet --force "$@"
for op in alice bob; do
  "$B/robodr-blackbox" keygen --out "op-$op.key" --key-id "op-$op" >/dev/null
done
"$B/robodr-commission" operators --out operators.json \
  --operator Alice=op-alice.key.pub --operator Bob=op-bob.key.pub --motion-quorum 2
python3 - <<'PY'
import json
p = "draft.json.signoff.json"
d = json.load(open(p))
d["operator"] = "Alice"
for item in d["items"]:
    item["confirmed"] = True
json.dump(d, open(p, "w"), indent=2)
PY
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
