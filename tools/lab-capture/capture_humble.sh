#!/bin/sh
# usage: capture_humble.sh <scenario> <out.pcap>
#
# ROS 2 Humble (Fast DDS 2.6, rmw_fastrtps_cpp) captures for
# fixtures/captures/ros2-humble. Same Docker bridge, addresses, nodes and
# capture point (the robot container's eth0) as the Jazzy captures of
# capture.sh / capture_multi.sh / capture_frag.sh.
#
# Scenarios:
#   baseline     robot + teleop, UDPv4 only (fastdds_udp_only.xml)
#   rogue        as baseline, a rogue /cmd_vel publisher joins at ~6 s
#   multi-a      robot host runs base_controller + two service nodes, + teleop
#   multi-b      the same, robot-host processes started in reverse order
#   frag         small maxMessageSize (fastdds_frag.xml): DATA_FRAG
#   shm          Fast DDS DEFAULT transports (UDPv4 + shared memory, what a
#                Humble robot runs out of the box): the robot host runs
#                base_controller and a local planner that publishes /cmd_vel
#                over shared memory, invisible on the wire; teleop remote
#   sros2        SROS 2 (DDS-Security, ROS_SECURITY_STRATEGY=Enforce), robot +
#                teleop with enclaves from one keystore (sros2-keystore.sh)
#   sros2-rogue  as sros2, + an unsecured rogue /cmd_vel publisher and a
#                secured rogue whose certificate is from ANOTHER keystore
#
# Image: IMG (default ros:humble-ros-base, which has Fast DDS, rclpy, the
# message packages and sros2). tcpdump: from the image if it has one,
# otherwise set HOST_TCPDUMP=1 to run the host's tcpdump inside the robot
# container's network namespace (nsenter; needs root), the same capture point.
set -e
SC=$1; OUT=$2; NET=robodr-lab
DISTRO=${DISTRO:-humble}
IMG=${IMG:-ros:$DISTRO-ros-base}
docker network inspect $NET >/dev/null 2>&1 || docker network create --subnet 10.77.10.0/24 $NET >/dev/null
D="$(cd "$(dirname "$0")" && pwd -W 2>/dev/null || pwd)"
KS=${KEYSTORE:-$D/.sros2}
case "$SC" in
  frag) XML=/cap/${FRAG_XML:-fastdds_frag.xml} ;;
  shm|sros2*) XML= ;;
  *) XML=/cap/fastdds_udp_only.xml ;;
esac
E="-e RMW_IMPLEMENTATION=rmw_fastrtps_cpp -e ROS_DOMAIN_ID=0"
[ -n "$XML" ] && E="$E -e FASTRTPS_DEFAULT_PROFILES_FILE=$XML"
SEC=""
case "$SC" in
  sros2*) SEC="-e ROS_SECURITY_KEYSTORE=/keystore -e ROS_SECURITY_ENABLE=true -e ROS_SECURITY_STRATEGY=Enforce -v $KS:/keystore:ro" ;;
esac
# run <name> <ip> <enclave|-> <command>
run() {
  n=$1; ip=$2; enc=$3; shift 3
  ex=""; [ "$enc" != - ] && ex="$SEC -e ROS_SECURITY_ENCLAVE_OVERRIDE=$enc"
  docker run -d --rm --name $n --network $NET --ip $ip $E $ex -v "$D:/cap:ro" $IMG \
    bash -c ". /opt/ros/$DISTRO/setup.bash && $*" >/dev/null
}
start_capture() {
  if [ "${HOST_TCPDUMP:-0}" = 1 ]; then
    pid=$(docker inspect -f '{{.State.Pid}}' robodr-lab-robot)
    nsenter -t "$pid" -n tcpdump -Z root -i eth0 -U -s 0 -w "$D/$OUT" udp >/dev/null 2>&1 &
    echo $! > "$D/.tcpdump.pid"
  else
    docker run -d --rm --name robodr-lab-tcpd --network container:robodr-lab-robot -v "$D:/cap" $IMG \
      tcpdump -i eth0 -U -s 0 -w /cap/$OUT udp >/dev/null
  fi
}
stop_capture() {
  if [ -f "$D/.tcpdump.pid" ]; then kill "$(cat "$D/.tcpdump.pid")" 2>/dev/null || true; rm -f "$D/.tcpdump.pid"; sleep 0.5
  else docker stop -t 2 robodr-lab-tcpd >/dev/null 2>&1 || true; fi
}
docker rm -f robodr-lab-robot robodr-lab-tcpd robodr-lab-teleop robodr-lab-rogue robodr-lab-rogue2 >/dev/null 2>&1 || true
while docker ps -a --format '{{.Names}}' | grep -q '^robodr-lab-'; do sleep 0.5; done

ROBOT="sleep 1; python3 /cap/robot.py"
ROBOT_ENC=-; TELEOP_ENC=-
case "$SC" in
  multi-a) ROBOT="sleep 1; python3 /cap/robot.py & sleep 1; python3 /cap/service_node.py add_two_ints_server & sleep 1; python3 /cap/service_node.py fibonacci_action_server & wait" ;;
  multi-b) ROBOT="sleep 1; python3 /cap/service_node.py fibonacci_action_server & sleep 1; python3 /cap/service_node.py add_two_ints_server & sleep 1; python3 /cap/robot.py & wait" ;;
  frag) ROBOT="sleep 1; python3 /cap/arm.py sub arm_driver & python3 /cap/robot.py" ;;
  shm) ROBOT="sleep 1; python3 /cap/robot.py & sleep 2; python3 /cap/teleop.py local_planner 0.2 0.0 & wait" ;;
  sros2*) ROBOT_ENC=/lab/base_controller; TELEOP_ENC=/lab/teleop_twist ;;
esac
run robodr-lab-robot 10.77.10.10 $ROBOT_ENC "$ROBOT"
start_capture
sleep 0.5
case "$SC" in
  frag) run robodr-lab-teleop 10.77.10.21 - "sleep 2; python3 /cap/arm.py pub arm_teleop 40 0.2 & python3 /cap/teleop.py teleop_twist 0.3 0.1" ;;
  multi-*) run robodr-lab-teleop 10.77.10.21 - "sleep 2; python3 /cap/teleop.py teleop_twist 0.3 0.1" ;;
  *) run robodr-lab-teleop 10.77.10.21 $TELEOP_ENC "sleep 1.5; python3 /cap/teleop.py teleop_twist 0.3 0.1" ;;
esac
case "$SC" in
  rogue) sleep 6; run robodr-lab-rogue 10.77.10.66 - "python3 /cap/teleop.py debug_tool 3.0 0.0"; sleep 8 ;;
  sros2-rogue)
    sleep 6
    # Unsecured: the secured robot must ignore it (no matching).
    run robodr-lab-rogue 10.77.10.66 - "python3 /cap/teleop.py debug_tool 3.0 0.0"
    # Secured with a certificate from a foreign CA: authentication fails.
    docker run -d --rm --name robodr-lab-rogue2 --network $NET --ip 10.77.10.67 $E \
      -e ROS_SECURITY_KEYSTORE=/keystore -e ROS_SECURITY_ENABLE=true -e ROS_SECURITY_STRATEGY=Enforce \
      -e ROS_SECURITY_ENCLAVE_OVERRIDE=/lab/teleop_twist -v "$KS-foreign:/keystore:ro" -v "$D:/cap:ro" $IMG \
      bash -c ". /opt/ros/$DISTRO/setup.bash && python3 /cap/teleop.py teleop_twist 3.0 0.0" >/dev/null
    sleep 8 ;;
  multi-*) sleep 16 ;;
  frag) sleep 12 ;;
  *) sleep 14 ;;
esac
docker stop -t 1 robodr-lab-teleop robodr-lab-rogue robodr-lab-rogue2 >/dev/null 2>&1 || true
sleep 1; stop_capture; docker stop -t 2 robodr-lab-robot >/dev/null 2>&1 || true
ls -la "$D/$OUT"
