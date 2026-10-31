#!/bin/bash
# Run the executor's ROS 2 adapters against a real DDS peer in a container
# (sales-readiness T18) and the ignored test
# `motion_tests::t18_real_ros2_peer` against it.
#
#   tools/e2e/ros2-peer/run.sh <mode> [image]
#
# mode:
#   fastrtps      peer.py (rclpy) on rmw_fastrtps_cpp, the stock image
#                 (default mirror.gcr.io/library/ros:humble-ros-core; any
#                 ros:<distro>-ros-core works)
#   cyclonedds    peer.py on rmw_cyclonedds_cpp: an image with
#                 ros-<distro>-rmw-cyclonedds-cpp (`docker build -t
#                 robodr-ros2-cyclone -f tools/e2e/ros2-peer/Dockerfile.cyclone
#                 tools/e2e/ros2-peer`, then pass robodr-ros2-cyclone)
#   cyclonedds-py peer_cyclone.py: Cyclone DDS 0.10 (Python binding) speaking
#                 the rmw_cyclonedds wire format, on the stock image; the
#                 wheel comes from $ROBODR_CYCLONEDDS_WHEELS (a directory
#                 with cyclonedds-0.10.5-cp310-...whl) or PyPI
#
# Needs docker; the peer is reached on the docker bridge (no host network).
# Cyclone peers run with participant index 0 (well-known ports).
set -euo pipefail
mode="${1:-fastrtps}"
here="$(cd "$(dirname "$0")" && pwd)"
root="$(cd "$here/../../.." && pwd)"
stock=mirror.gcr.io/library/ros:humble-ros-core
cyclone_uri='<CycloneDDS><Domain><Discovery><ParticipantIndex>0</ParticipantIndex></Discovery></Domain></CycloneDDS>'
extra=()
case "$mode" in
  fastrtps)
    image="${2:-$stock}"; rmw=fastrtps; entry=/peer/entrypoint.sh
    extra+=(-e RMW_IMPLEMENTATION=rmw_fastrtps_cpp) ;;
  cyclonedds)
    image="${2:-robodr-ros2-cyclone}"; rmw=cyclonedds; entry=/peer/entrypoint.sh
    extra+=(-e RMW_IMPLEMENTATION=rmw_cyclonedds_cpp -e "CYCLONEDDS_URI=$cyclone_uri") ;;
  cyclonedds-py)
    image="${2:-$stock}"; rmw=cyclonedds; entry=/peer/entrypoint_cyclone.sh
    if [ -n "${ROBODR_CYCLONEDDS_WHEELS:-}" ]; then
      extra+=(-v "$ROBODR_CYCLONEDDS_WHEELS":/wheels:ro)
    fi ;;
  *) echo "mode: fastrtps, cyclonedds or cyclonedds-py" >&2; exit 2 ;;
esac
out="$(mktemp -d)"
chmod 0777 "$out"
name="robodr-ros2-peer-$$"
cleanup() { docker rm -f "$name" >/dev/null 2>&1 || true; rm -rf "$out"; }
trap cleanup EXIT
docker run -d --name "$name" -e ROS_DOMAIN_ID=0 -e ROS_LOCALHOST_ONLY=0 "${extra[@]}" \
  -v "$here":/peer:ro -v "$out":/out "$image" "$entry" >/dev/null
for _ in $(seq 1 150); do
  [ -s "$out/peer.json" ] && break
  sleep 0.2
done
[ -s "$out/peer.json" ] || { docker logs "$name"; echo "peer did not start" >&2; exit 1; }
peer_ip="$(docker inspect -f '{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}' "$name")"
local_ip="$(docker network inspect bridge -f '{{(index .IPAM.Config 0).Gateway}}')"
echo "peer $peer_ip ($mode, $image), local $local_ip"
cd "$root"
ROBODR_ROS2_PEER_IP="$peer_ip" ROBODR_ROS2_LOCAL_IP="$local_ip" \
ROBODR_ROS2_RMW="$rmw" ROBODR_ROS2_PEER_OUT="$out/peer.json" \
  cargo test -p robodr-executor --lib t18_real_ros2_peer -- --ignored --nocapture
docker logs "$name" | tail -n 3
