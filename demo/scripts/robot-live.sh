#!/bin/sh
# Live demo robot: the same locked profile, capturing live on eth0 (no
# replay), so the attacker's datagrams are judged as they arrive and the
# time to detect is measured on the wall clock.
set -eu
B=/opt/robodr/bin
S=/demo/state
umask 077
rm -rf "$S/spool-live" "$S/blackbox-live" "$S/profile-state-live.json"
sed -e "s|@ROBOT@|demo-ugv-01|g" -e "s|@SUFFIX@|-live|g" \
  -e 's|@CAPTURE@|"interfaces": ["eth0"]|' -e "s|@EXIT@|false|" \
  /demo/config/agentd.json.in > "$S/agentd-live.json"
"$B/robodr-agentd" --config "$S/agentd-live.json" --check-config
echo "[robot-live] capturing on eth0 ($(hostname -i 2>/dev/null || echo 172.30.77.20))"
exec "$B/robodr-agentd" --config "$S/agentd-live.json"
