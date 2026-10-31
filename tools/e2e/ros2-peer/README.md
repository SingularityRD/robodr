# ROS 2 peer containers (sales-readiness T18)

Runs the executor's `nav2` adapter (the `CancelGoal` service call, the
zero-twist burst and the T42 pause latch) against a real DDS stack in a
container, through the ignored test `motion_tests::t18_real_ros2_peer`.

```sh
tools/e2e/ros2-peer/run.sh fastrtps         # rclpy on rmw_fastrtps_cpp (stock ros:humble-ros-core)
tools/e2e/ros2-peer/run.sh cyclonedds-py    # Cyclone DDS 0.10.5 (Python binding), rmw_cyclonedds wire format
tools/e2e/ros2-peer/run.sh cyclonedds IMG   # rclpy on rmw_cyclonedds_cpp (image from Dockerfile.cyclone)
```

| File | What |
|---|---|
| `peer.py` | rclpy node: `/navigate_to_pose/_action/cancel_goal` (`action_msgs/srv/CancelGoal`) answering a scripted goal count (1, 0, 2, then 0) and a `/cmd_vel` subscriber; writes `/out/peer.json` |
| `peer_cyclone.py` | the same on the Cyclone DDS Python binding, with the `rmw_cyclonedds` request header and DDS type names by construction |
| `entrypoint*.sh` | container entry points |
| `Dockerfile.cyclone` | the stock image plus `ros-<distro>-rmw-cyclonedds-cpp` (needs the ROS apt repository) |
| `probe.sh` | lists the interfaces and RMWs an image has |

Results (2026-10-31, ROS 2 Humble image `mirror.gcr.io/library/ros:humble-ros-core`):

| Mode | Result |
|---|---|
| `fastrtps` | PASS: pause `verified` ("1 goal(s) cancelling"), zero twists received by the reliable subscriber, latch: nothing found, then "2 navigation goal(s)" → `overridden` |
| `cyclonedds-py` | PASS after two fixes this run found (below) |
| `cyclonedds` (`rmw_cyclonedds_cpp`) | not run: the ROS apt repository is not reachable from the build host |

Found by these runs and fixed:

* Fast DDS never delivered a request whose first sequence number was
  large (2^31 - 16 and above failed, 100000 passed; the first draft of the
  `fastrtps` mode drew it from 2^47): now 2..=65537, still random.
* A peer that receives our endpoint announcement before it has processed
  our participant announcement drops it; the zero twists were announced
  once, so Cyclone DDS never matched the writer and dropped every twist.
  Each twist now re-announces the writer (regression test
  `t18_zero_twists_reach_a_peer_that_missed_the_first_announcement`).

Not covered here: a real Nav2 (behaviour tree, goal states), ros2_control
(`controller_manager_msgs` is not in the image), Unitree, PX4 SITL, ROS 2
Jazzy.
