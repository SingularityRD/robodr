#!/usr/bin/env bash
# Soak / red-team network: two namespaces joined by veth pairs.
#   rdr-gen  (traffic generators, attackers)  <-veth->  rdr-rob (agentd capture)
#   gen-ugv <-> rob-ugv   ROS 2 / RTPS lab traffic
#   gen-go2 <-> rob-go2   Unitree SDK2 LowCmd (500 Hz)
#   gen-rt  <-> rob-rt    red-team target
# usage: netns.sh up|down
set -euo pipefail
pairs="ugv go2 rt"
case "${1:-}" in
up)
  ip netns add rdr-gen; ip netns add rdr-rob
  i=1
  for p in $pairs; do
    ip link add "gen-$p" type veth peer name "rob-$p"
    ip link set "gen-$p" netns rdr-gen; ip link set "rob-$p" netns rdr-rob
    ip -n rdr-gen addr add "10.99.$i.1/24" dev "gen-$p"
    ip -n rdr-rob addr add "10.99.$i.2/24" dev "rob-$p"
    ip -n rdr-gen link set "gen-$p" up; ip -n rdr-rob link set "rob-$p" up
    i=$((i+1))
  done
  ip -n rdr-gen link set lo up; ip -n rdr-rob link set lo up ;;
down)
  ip netns del rdr-gen 2>/dev/null || true; ip netns del rdr-rob 2>/dev/null || true ;;
*) echo "usage: $0 up|down" >&2; exit 2 ;;
esac
