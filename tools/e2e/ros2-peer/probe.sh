#!/bin/bash
# What the ROS 2 image offers (interfaces and RMWs); run inside the image.

source /opt/ros/"${ROS_DISTRO}"/setup.bash
ls /opt/ros/"${ROS_DISTRO}"/share | grep -E "example_interfaces|action_msgs|geometry_msgs|rmw_|controller_manager|std_srvs|action_tutorials"
echo "RMW_IMPLEMENTATION=${RMW_IMPLEMENTATION:-<default>}"
