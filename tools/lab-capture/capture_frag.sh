#!/bin/sh
# usage: capture_frag.sh <rmw> <out.pcap>
# DATA_FRAG on a real stack: every participant runs with a small maximum
# message size (Fast DDS: fastdds_frag.xml, UDPv4 maxMessageSize 640;
# Cyclone DDS: MaxMessageSize 800 B / FragmentSize 256 B), so discovery
# announcements and large samples are split into DATA_FRAG. Robot host:
# robot.py (/cmd_vel -> /odom) + arm.py sub (/arm_controller/joint_trajectory);
# operator host: teleop.py (/cmd_vel 10 Hz) + arm.py pub (a 40-point
# JointTrajectory, ~5 kB, at 2 Hz).
set -e
RMW=$1; OUT=$2; NET=robodr-lab
IMG=${IMG:-robodr-gz:jazzy}
docker network inspect $NET >/dev/null 2>&1 || docker network create --subnet 10.77.10.0/24 $NET >/dev/null
D="$(cd "$(dirname "$0")" && pwd -W 2>/dev/null || pwd)"
CYC='<CycloneDDS><Domain><General><MaxMessageSize>800B</MaxMessageSize><FragmentSize>256B</FragmentSize></General></Domain></CycloneDDS>'
E="-e RMW_IMPLEMENTATION=$RMW -e ROS_DOMAIN_ID=0 -e FASTRTPS_DEFAULT_PROFILES_FILE=/cap/${FRAG_XML:-fastdds_frag.xml}"
run() { n=$1; ip=$2; shift 2; docker run -d --rm --name $n --network $NET --ip $ip $E -e "CYCLONEDDS_URI=$CYC" -v "$D:/cap" $IMG bash -c "source /opt/ros/jazzy/setup.bash && $*" >/dev/null; }
docker rm -f robodr-lab-robot robodr-lab-tcpd robodr-lab-teleop >/dev/null 2>&1 || true
while docker ps -a --format '{{.Names}}' | grep -q '^robodr-lab-'; do sleep 0.5; done
run robodr-lab-robot 10.77.10.10 "sleep 1; python3 /cap/arm.py sub arm_driver & python3 /cap/robot.py"
docker run -d --rm --name robodr-lab-tcpd --network container:robodr-lab-robot -v "$D:/cap" $IMG tcpdump -i eth0 -U -s 0 -w /cap/$OUT udp >/dev/null
sleep 0.5
run robodr-lab-teleop 10.77.10.21 "sleep 2; python3 /cap/arm.py pub arm_teleop 40 0.2 & python3 /cap/teleop.py teleop_twist 0.3 0.1"
sleep 12
docker stop -t 1 robodr-lab-teleop >/dev/null 2>&1 || true
sleep 1; docker stop -t 2 robodr-lab-tcpd robodr-lab-robot >/dev/null 2>&1 || true
ls -la "$D/$OUT"
