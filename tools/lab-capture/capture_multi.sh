#!/bin/sh
# usage: capture_multi.sh <rmw> <order: a|b> <out.pcap>
# Robot host runs three processes (base_controller, add_two_ints_server,
# fibonacci action server); order b starts them in reverse.
set -e
RMW=$1; ORD=$2; OUT=$3; NET=robodr-lab
docker network inspect $NET >/dev/null 2>&1 || docker network create --subnet 10.77.10.0/24 $NET >/dev/null
D="$(cd "$(dirname "$0")" && pwd -W 2>/dev/null || pwd)"
E="-e RMW_IMPLEMENTATION=$RMW -e ROS_DOMAIN_ID=0 -e FASTDDS_BUILTIN_TRANSPORTS=UDPv4"
docker rm -f robot tcpd teleop >/dev/null 2>&1 || true
if [ "$ORD" = a ]; then
  START="python3 /cap/robot.py & sleep 1; ros2 run demo_nodes_cpp add_two_ints_server & sleep 1; ros2 run action_tutorials_cpp fibonacci_action_server & wait"
else
  START="ros2 run action_tutorials_cpp fibonacci_action_server & sleep 1; ros2 run demo_nodes_cpp add_two_ints_server & sleep 1; python3 /cap/robot.py & wait"
fi
docker run -d --rm --name robot --network $NET --ip 10.77.10.10 $E -v "$D:/cap" robodr-cap:jazzy bash -c "source /opt/ros/jazzy/setup.bash && sleep 1 && $START" >/dev/null
docker run -d --rm --name tcpd --network container:robot -v "$D:/cap" robodr-cap:jazzy tcpdump -i eth0 -U -s 0 -w /cap/$OUT udp >/dev/null
docker run -d --rm --name teleop --network $NET --ip 10.77.10.21 $E -v "$D:/cap" robodr-cap:jazzy bash -c "source /opt/ros/jazzy/setup.bash && sleep 2 && python3 /cap/teleop.py teleop_twist 0.3 0.1" >/dev/null
sleep 16
docker stop -t 1 teleop >/dev/null 2>&1 || true
sleep 1; docker stop -t 2 tcpd robot >/dev/null 2>&1 || true
ls -la "$D/$OUT"
