#!/bin/sh
# check-score.sh SCORE.json: exit 0 when the `robodr-attack-sim score` report
# says every scenario raised its expected rule ids, else name the scenarios
# that did not and exit 1. demo/run.sh uses it so a scenario regression fails
# the demo run instead of only showing in demo/state/score.json.
set -eu
f=${1:?usage: check-score.sh SCORE.json}
[ -s "$f" ] || { echo "no scenario score in $f" >&2; exit 1; }
# The report is pretty-printed with sorted keys: the overall verdict is the
# only "pass" indented by two spaces; each scenario's "pass" is followed by
# its "scenario" line.
if grep -q '^  "pass": true,$' "$f"; then
  exit 0
fi
failed=$(grep -A1 '^      "pass": false,$' "$f" | sed -n 's/^ *"scenario": "\(.*\)"$/\1/p' | tr '\n' ' ' | sed 's/ $//')
echo "scenario score FAILED (${failed:-unreadable report}): see $f" >&2
exit 1
