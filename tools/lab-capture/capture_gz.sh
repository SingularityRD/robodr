#!/bin/sh
# usage: capture_gz.sh <rmw> <scenario: baseline|rogue> <out.pcap>
# Robot host: headless Gazebo (gz sim server) + ros_gz_bridge +
# robot_state_publisher (gz_robot.launch.py). Operator station (station.py)
# drives /cmd_vel and watches /odom; in "rogue" a third host joins and
# publishes /cmd_vel at 3.0 m/s. Gazebo's own transport is kept on loopback
# (GZ_IP=127.0.0.1) and is not DDS; only UDP is captured.
set -e
RMW=$1; SC=$2; OUT=$3; NET=robodr-lab
IMG=${IMG:-robodr-gz:jazzy}
docker network inspect $NET >/dev/null 2>&1 || docker network create --subnet 10.77.10.0/24 $NET >/dev/null
D="$(cd "$(dirname "$0")" && pwd -W 2>/dev/null || pwd)"
E="-e RMW_IMPLEMENTATION=$RMW -e ROS_DOMAIN_ID=0 -e FASTDDS_BUILTIN_TRANSPORTS=UDPv4 ${XENV:-}"
run() { n=$1; ip=$2; shift 2; docker run -d --rm --name $n --network $NET --ip $ip $E -v "$D:/cap" $IMG bash -c "source /opt/ros/jazzy/setup.bash && $*" >/dev/null; }
docker rm -f robodr-lab-robot robodr-lab-tcpd robodr-lab-teleop robodr-lab-rogue >/dev/null 2>&1 || true
while docker ps -a --format '{{.Names}}' | grep -q '^robodr-lab-'; do sleep 0.5; done
run robodr-lab-robot 10.77.10.10 "export GZ_IP=127.0.0.1 GZ_SIM_RESOURCE_PATH=/opt/ros/jazzy/share; sleep 1; ros2 launch /cap/gz_robot.launch.py"
docker run -d --rm --name robodr-lab-tcpd --network container:robodr-lab-robot -v "$D:/cap" $IMG tcpdump -i eth0 -U -s 0 -w /cap/$OUT udp and not port 5353 >/dev/null
sleep 0.5
run robodr-lab-teleop 10.77.10.21 "sleep 4; python3 /cap/station.py teleop_twist 0.3 0.1"
if [ "$SC" = rogue ]; then sleep 9; run robodr-lab-rogue 10.77.10.66 "python3 /cap/teleop.py debug_tool 3.0 0.0"; sleep 7; else sleep 16; fi
docker stop -t 1 robodr-lab-teleop robodr-lab-rogue >/dev/null 2>&1 || true
sleep 1; docker stop -t 3 robodr-lab-tcpd robodr-lab-robot >/dev/null 2>&1 || true
ls -la "$D/$OUT"
