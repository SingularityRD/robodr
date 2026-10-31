#!/bin/sh
# check-score.sh SCORE.json: exit 0 when `robodr-attack-sim score` exited 0
# for this report (every scenario raised its expected rule ids), else name the
# scenarios that did not and exit 1. demo/run.sh uses it so a scenario
# regression fails the demo run instead of only showing in
# demo/state/score.json.
#
# The verdict is score's exit status, which robot.sh writes next to the
# report as SCORE.rc ("0" pass, "1" a scenario missed, "2" usage or input
# error); the report's layout never decides. A missing or unreadable status
# fails.
set -eu
f=${1:?usage: check-score.sh SCORE.json}
rc_file="${f%.json}.rc"
[ -s "$f" ] || { echo "no scenario score in $f" >&2; exit 1; }
[ -r "$rc_file" ] || { echo "no score exit status in $rc_file" >&2; exit 1; }
rc=$(tr -d ' \n' < "$rc_file")
if [ "$rc" = 0 ]; then
  exit 0
fi
# Names for the message only, from either compact or pretty-printed JSON:
# each scenario object is {"expected": [...], "pass": ..., "scenario": "..."}
# (sorted keys), so a failed one has "pass": false right before its name.
failed=$(tr -d '\n' < "$f" | grep -o '"pass": *false, *"scenario": *"[^"]*"' |
  sed 's/.*"scenario": *"\([^"]*\)"/\1/' | tr '\n' ' ' | sed 's/ $//' || true)
echo "scenario score FAILED (exit $rc; ${failed:-see the report}): see $f" >&2
exit 1
