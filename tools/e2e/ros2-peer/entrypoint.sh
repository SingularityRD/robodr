#!/bin/bash
# Container entry point: source ROS 2 and run the peer (peer.py) with the
# RMW the container was started with (RMW_IMPLEMENTATION).
source /opt/ros/"${ROS_DISTRO}"/setup.bash
exec python3 -u /peer/peer.py
