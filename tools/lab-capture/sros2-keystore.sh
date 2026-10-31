#!/bin/sh
# usage: sros2-keystore.sh
# Creates the lab SROS 2 keystores used by `capture_humble.sh sros2*`:
#   .sros2          CA + enclaves /lab/base_controller, /lab/teleop_twist
#                   (sros2's default governance and permissions)
#   .sros2-foreign  a second, unrelated CA with an enclave of the same name
#                   (/lab/teleop_twist): a "stolen name, wrong CA" rogue
# Both stay in tools/lab-capture/ and are git-ignored (private keys). The
# public parts used by the tests (governance.xml, permissions.xml, the
# identity certificates) are copied to fixtures/captures/ros2-humble/sros2/.
set -e
DISTRO=${DISTRO:-humble}
IMG=${IMG:-ros:$DISTRO-ros-base}
D="$(cd "$(dirname "$0")" && pwd -W 2>/dev/null || pwd)"
rm -rf "$D/.sros2" "$D/.sros2-foreign"
docker run --rm -v "$D:/cap" $IMG bash -c ". /opt/ros/$DISTRO/setup.bash && \
  ros2 security create_keystore /cap/.sros2 && \
  ros2 security create_enclave /cap/.sros2 /lab/base_controller && \
  ros2 security create_enclave /cap/.sros2 /lab/teleop_twist && \
  ros2 security create_keystore /cap/.sros2-foreign && \
  ros2 security create_enclave /cap/.sros2-foreign /lab/teleop_twist && \
  chmod -R a+rX /cap/.sros2 /cap/.sros2-foreign"
ls "$D/.sros2/enclaves/lab"
