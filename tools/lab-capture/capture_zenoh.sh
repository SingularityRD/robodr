#!/bin/sh
# usage: capture_zenoh.sh <scenario: baseline|rogue> <out.pcap>
# The same robot / teleop (/ rogue) as capture.sh, but on rmw_zenoh_cpp: a
# Zenoh router (rmw_zenohd) on the robot host, every node a Zenoh peer that
# connects to its local router; the teleop / rogue hosts run their own router
# connected to the robot's (the multi-host setup the rmw_zenoh docs
# recommend). No RTPS at all on the wire.
set -e
SC=$1; OUT=$2; NET=robodr-lab
IMG=${IMG:-robodr-gz:jazzy}
docker network inspect $NET >/dev/null 2>&1 || docker network create --subnet 10.77.10.0/24 $NET >/dev/null
D="$(cd "$(dirname "$0")" && pwd -W 2>/dev/null || pwd)"
ROUTER='connect/endpoints=["tcp/10.77.10.10:7447"]'
run() { n=$1; ip=$2; shift 2; docker run -d --rm --name $n --network $NET --ip $ip -e RMW_IMPLEMENTATION=rmw_zenoh_cpp -e ROS_DOMAIN_ID=0 -v "$D:/cap" $IMG bash -c "source /opt/ros/jazzy/setup.bash && (ZENOH_CONFIG_OVERRIDE='$ROUTER' ros2 run rmw_zenoh_cpp rmw_zenohd &) && sleep 2 && $*" >/dev/null; }
docker rm -f robodr-lab-robot robodr-lab-tcpd robodr-lab-teleop robodr-lab-rogue >/dev/null 2>&1 || true
while docker ps -a --format '{{.Names}}' | grep -q '^robodr-lab-'; do sleep 0.5; done
docker run -d --rm --name robodr-lab-robot --network $NET --ip 10.77.10.10 -e RMW_IMPLEMENTATION=rmw_zenoh_cpp -v "$D:/cap" $IMG bash -c "source /opt/ros/jazzy/setup.bash && (ros2 run rmw_zenoh_cpp rmw_zenohd &) && sleep 2 && python3 /cap/robot.py" >/dev/null
docker run -d --rm --name robodr-lab-tcpd --network container:robodr-lab-robot -v "$D:/cap" $IMG tcpdump -i eth0 -U -s 0 -w /cap/$OUT >/dev/null
sleep 0.5
run robodr-lab-teleop 10.77.10.21 "sleep 3; python3 /cap/teleop.py teleop_twist 0.3 0.1"
if [ "$SC" = rogue ]; then sleep 8; run robodr-lab-rogue 10.77.10.66 "python3 /cap/teleop.py debug_tool 3.0 0.0"; sleep 8; else sleep 14; fi
docker stop -t 1 robodr-lab-teleop robodr-lab-rogue >/dev/null 2>&1 || true
sleep 1; docker stop -t 2 robodr-lab-tcpd robodr-lab-robot >/dev/null 2>&1 || true
ls -la "$D/$OUT"
