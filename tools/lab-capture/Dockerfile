# Base lab image, one per ROS 2 distribution:
#   docker build --build-arg DISTRO=jazzy  -t robodr-cap:jazzy  tools/lab-capture
#   docker build --build-arg DISTRO=humble -t robodr-cap:humble tools/lab-capture
# sros2 (`ros2 security`) and the demo nodes are used by capture_sros2.sh.
ARG DISTRO=jazzy
FROM ros:${DISTRO}-ros-base
ARG DISTRO
RUN apt-get update && apt-get install -y --no-install-recommends ros-${DISTRO}-rmw-cyclonedds-cpp tcpdump ros-${DISTRO}-demo-nodes-cpp ros-${DISTRO}-demo-nodes-py ros-${DISTRO}-action-tutorials-cpp ros-${DISTRO}-sros2 && rm -rf /var/lib/apt/lists/*
