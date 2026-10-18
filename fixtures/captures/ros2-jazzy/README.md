# Real ROS 2 captures (ROS 2 Jazzy, Fast DDS and Cyclone DDS)

These are the first **real** DDS captures in the repository: traffic from
actual ROS 2 processes, not bytes generated from the specification. They
were recorded on 2026-10-17 with the tooling in
[`tools/lab-capture/`](../../../tools/lab-capture/) and are used by
`crates/robodr-ros2-pipeline/tests/real_captures.rs`.

## Setup

| | |
|---|---|
| Image | `ros:jazzy-ros-base` (`sha256:066420e07f60aa18262f2479981def87ebcfcec42eefb0c0c57c4a46098348ca`) + `ros-jazzy-rmw-cyclonedds-cpp` + `tcpdump` (+ `ros-jazzy-demo-nodes-cpp`, `ros-jazzy-action-tutorials-cpp` for the `multi` runs) |
| Fast DDS | `ros-jazzy-fastrtps` 2.14.6, `rmw_fastrtps_cpp` 8.4.4, `FASTDDS_BUILTIN_TRANSPORTS=UDPv4` (no shared memory, so all traffic is on the wire) |
| Cyclone DDS | `ros-jazzy-cyclonedds` 0.10.5, `rmw_cyclonedds_cpp` 2.2.4 |
| rclpy | 7.1.12 |
| Network | one Docker bridge, `10.77.10.0/24`, `ROS_DOMAIN_ID=0` |
| Capture | `tcpdump -i eth0 -U -s 0 udp` in the robot container's network namespace (Ethernet link type, classic pcap) |

Nodes (`tools/lab-capture/robot.py`, `teleop.py`):

| Host | Node | Role |
|---|---|---|
| `10.77.10.10` | `/base_controller` | the robot: subscribes `/cmd_vel` (`geometry_msgs/Twist`), publishes `/odom` (`nav_msgs/Odometry`) at 5 Hz |
| `10.77.10.21` | `/teleop_twist` | legitimate operator: publishes `/cmd_vel` at 10 Hz, `linear.x = 0.3`, `angular.z = 0.1` |
| `10.77.10.66` | `/debug_tool` | **rogue** (only in `*_rogue_cmd_vel.pcap`): joins after ~6 s and publishes `/cmd_vel` at 10 Hz, `linear.x = 3.0` |

## Files

| File | Packets | What |
|---|---|---|
| `fastrtps_baseline.pcap` | 289 | robot + teleop, ~15 s, then teleop stops (dispose) |
| `fastrtps_rogue_cmd_vel.pcap` | 521 | as above, rogue joins at ~6 s |
| `cyclonedds_baseline.pcap` | 353 | robot + teleop |
| `cyclonedds_rogue_cmd_vel.pcap` | 633 | robot + teleop + rogue |
| `fastrtps_multi_run1.pcap` | 603 | robot host runs **three processes** (`/base_controller` (rclpy), `/add_two_ints_server`, `/fibonacci_action_server` (rclcpp)), started in that order, + teleop (`tools/lab-capture/capture_multi.sh ... a`) |
| `fastrtps_multi_run2.pcap` | 615 | the same, processes started in **reverse** order (`... b`) |
| `cyclonedds_multi_run1.pcap` | 590 | as `fastrtps_multi_run1` |
| `cyclonedds_multi_run2.pcap` | 598 | as `fastrtps_multi_run2` |

SHA-256:

```
9701d5a28b3ddc9f304820395bd87f0c8806d60b8f9081e1e6fe57ef6b44fb66  fastrtps_baseline.pcap
f28ab76aae669d221b7cf01dcdbf57c7d69b617b13d0b3c453d56718c7a77786  fastrtps_rogue_cmd_vel.pcap
0b445c6c0a93c03878b157510be9842ec0d205e8058249fc8a27e71c39294485  cyclonedds_baseline.pcap
259837677a903e56e06c4141823c4fcb8af14d4ba7de53ed46ec3eb35f480c2d  cyclonedds_rogue_cmd_vel.pcap
35aaa6d08ba0ef5525f6ddd2dfd275370992f8dba2cbf44de3d602968bcab2d6  fastrtps_multi_run1.pcap
07b70c1a4b19ff68509bcb8ff010449338c0bce98aa71b9a4b9c05f0eea4e1ee  fastrtps_multi_run2.pcap
1f83e1bafbfe6d65887211cefce5f720828ee1e0380879ed953e253c8ac13271  cyclonedds_multi_run1.pcap
2c44a667954c67762ed179a862954babd52e16fabcaa41f033e540f745ddce32  cyclonedds_multi_run2.pcap
```

Each file is a **separate run**: every process has a different GUID prefix
in each file.

## What they showed (and what was changed because of it)

1. **GUID prefixes change on every process start** (Fast DDS: host id +
   PID; Cyclone DDS: random). A profile learned from one run matched none of
   the next run's participants: the robot's own controller was an "unknown
   participant". Fixed with `participant_identities` (source IPs + RTPS
   vendor + nodes), resolved at run time by
   `robodr-ros2-pipeline::identity`, learned by `robodr-commission learn`.
2. SEDP goes **unicast** to the peer's metatraffic port (7410/7411 +
   offsets), as the hand-over notes warned; the passive capture path sees it.
3. The XCDR1 (`CDR_LE`) `Twist` decoder of `robodr-cdr` decodes both
   vendors' samples correctly (0.3 m/s legit, 3.0 m/s rogue).
4. `learn --pcap` now decodes those samples, so a capture alone yields a
   `/cmd_vel` envelope.
5. Cyclone DDS sends a **1-byte datagram** to its own multicast port when a
   node stops (thread wake-up); it is no longer counted as malformed RTPS.
6. Three processes on one host (one IP, one vendor) are indistinguishable at
   SPDP time; in the `multi` runs, started in reverse order, each new prefix
   first takes a slot provisionally and is then confirmed (or moved) by its
   node's `get_parameters` reply writer, so every identity ends up on the
   right process.
7. After a self-dispose, the departing process's last datagrams still carry
   its prefix in the RTPS header; a released identity keeps its prefix
   profiled for 10 s so those are not "unknown participants".

## Not covered

- RTI Connext, Zenoh (`rmw_zenoh`), DDS-Security (SROS 2), discovery server.
- Real robot hardware, Gazebo, large SEDP (DATA_FRAG), IPv6.
- Same-host traffic over loopback / shared memory.
