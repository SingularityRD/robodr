#!/bin/sh
# usage: capture.sh <rmw> <scenario: baseline|rogue> <out.pcap>
set -e
RMW=$1; SC=$2; OUT=$3; NET=robodr-lab
docker network inspect $NET >/dev/null 2>&1 || docker network create --subnet 10.77.10.0/24 $NET >/dev/null
ENV="-e RMW_IMPLEMENTATION=$RMW -e ROS_DOMAIN_ID=0 -e FASTDDS_BUILTIN_TRANSPORTS=UDPv4 -e CYCLONEDDS_URI=<CycloneDDS><Domain><General><Interfaces><NetworkInterface\ name=\"eth0\"/></Interfaces></General></Domain></CycloneDDS>"
D="$(cd "$(dirname "$0")" && pwd -W 2>/dev/null || pwd)"
run() { n=$1; ip=$2; shift 2; docker run -d --rm --name $n --network $NET --ip $ip -e RMW_IMPLEMENTATION=$RMW -e ROS_DOMAIN_ID=0 -e FASTDDS_BUILTIN_TRANSPORTS=UDPv4 -v "$D:/cap" robodr-cap:jazzy bash -c "source /opt/ros/jazzy/setup.bash && $*" >/dev/null; }
docker rm -f robot tcpd teleop rogue >/dev/null 2>&1 || true
run robot 10.77.10.10 "sleep 1; python3 /cap/robot.py"
docker run -d --rm --name tcpd --network container:robot -v "$D:/cap" robodr-cap:jazzy tcpdump -i eth0 -U -s 0 -w /cap/$OUT udp >/dev/null
sleep 0.5
run teleop 10.77.10.21 "sleep 1.5; python3 /cap/teleop.py teleop_twist 0.3 0.1"
if [ "$SC" = rogue ]; then sleep 6; run rogue 10.77.10.66 "python3 /cap/teleop.py debug_tool 3.0 0.0"; sleep 8; else sleep 14; fi
docker stop -t 1 teleop rogue >/dev/null 2>&1 || true
sleep 1; docker stop -t 2 tcpd robot >/dev/null 2>&1 || true
ls -la "$D/$OUT"
