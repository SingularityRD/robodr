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

- RTI Connext, DDS-Security (SROS 2), discovery server (Zenoh, Gazebo and
  DATA_FRAG: see the second set below).
- Real robot hardware, IPv6.
- Same-host traffic over loopback / shared memory.

# Second set (2026-10-18): Gazebo, DATA_FRAG, Zenoh

Recorded with `tools/lab-capture/capture_gz.sh`, `capture_frag.sh` and
`capture_zenoh.sh` on the image built from `tools/lab-capture/Dockerfile.gz`
(tag `robodr-gz:jazzy` = the image above + `ros-jazzy-ros-gz-sim-demos`,
`ros-jazzy-ros-gz-bridge`, `ros-jazzy-ros-gz-sim` 1.0.24 (Gazebo Harmonic,
gz-sim 8 via `gz_sim_vendor`), `ros-jazzy-robot-state-publisher` 3.3.4,
`ros-jazzy-rmw-zenoh-cpp` 0.2.11, `ros-jazzy-trajectory-msgs`; apt snapshot
of 2026-10-06). Same Docker bridge, addresses and capture point (the robot
container's `eth0`) as above. Tested by
`crates/robodr-ros2-pipeline/tests/real_captures_lab.rs`,
`crates/robodr-agentd/tests/real_captures_lab.rs` and
`crates/robodr-commission/tests/cli.rs`.

## Gazebo (headless)

Gazebo **does** run headless here: `gz sim -s -r` (server only, no
rendering sensors), Gazebo transport kept on loopback (`GZ_IP=127.0.0.1`;
it is not DDS and is not captured). `gz_robot.launch.py` starts the
`ros_gz_sim_demos` "vehicle" world (diff drive + JointStatePublisher +
PosePublisher + OdometryPublisher), `ros_gz_bridge` (`/clock`,
`/joint_states`, `/tf`, `/tf_static`, `/cmd_vel` ROS to GZ, `/odom`) and
`robot_state_publisher` (URDF from the model SDF via `sdformat_urdf`, which
also publishes `/robot_description`). The operator host runs `station.py`:
`/cmd_vel` at 10 Hz (0.3 m/s) **and a subscriber of `/odom`**, so the
simulated odometry (50 Hz) crosses the wire. Rogue as before (3.0 m/s from
10.77.10.66, joins about 9 s in).

| File | Packets | Bytes | What |
|---|---|---|---|
| `fastrtps_gz_baseline.pcap` | 1171 | 775038 | sim + station, about 16 s |
| `fastrtps_gz_rogue_cmd_vel.pcap` | 2071 | 1315398 | sim (restarted) + station + rogue |
| `cyclonedds_gz_baseline.pcap` | 1633 | 1014527 | as `fastrtps_gz_baseline` |
| `cyclonedds_gz_rogue_cmd_vel.pcap` | 1567 | 860712 | as `fastrtps_gz_rogue_cmd_vel` |
| `fastrtps_gz_dual_odom.pcap` | 1119 | 736330 | the first Fast DDS baseline, on the **unmodified** upstream world (see 3. below) |

## DATA_FRAG

Every participant runs with a small maximum message size: Fast DDS through
`FASTRTPS_DEFAULT_PROFILES_FILE=tools/lab-capture/fastdds_frag.xml` (a
UDPv4 user transport with `maxMessageSize` 640, builtin transports off;
with 512 the participants never match), Cyclone DDS through `CYCLONEDDS_URI`
`<General><MaxMessageSize>800B</MaxMessageSize><FragmentSize>256B</FragmentSize>`.
Robot host: `robot.py` + `arm.py sub` (`/arm_controller/joint_trajectory`);
operator host: `teleop.py` + `arm.py pub` (a 40-point, 6-joint
`trajectory_msgs/JointTrajectory`, 5220 bytes serialized, at 2 Hz: user
DATA_FRAG on a motion topic).

| File | Packets | Bytes | Discovery DATA_FRAG | rebuilt |
|---|---|---|---|---|
| `fastrtps_frag_run1.pcap` | 870 | 378720 | 288 | 72 |
| `fastrtps_frag_run2.pcap` | 1010 | 409600 | 288 | 72 |
| `cyclonedds_frag_run1.pcap` | 828 | 292352 | 235 | 74 |
| `cyclonedds_frag_run2.pcap` | 850 | 292448 | 226 | 74 |

Fast DDS fragments SEDP (its SPDP, 464 bytes, still fits); Cyclone with a
256-byte fragment size fragments SPDP and SEDP.

## Zenoh

`capture_zenoh.sh`: the robot / teleop / rogue of `capture.sh` with
`RMW_IMPLEMENTATION=rmw_zenoh_cpp`. Each host runs a Zenoh router
(`ros2 run rmw_zenoh_cpp rmw_zenohd`); the teleop and rogue routers connect
to the robot's (`ZENOH_CONFIG_OVERRIDE='connect/endpoints=["tcp/10.77.10.10:7447"]'`)
and nodes talk to their local router (the multi-host setup the rmw_zenoh
docs describe). Pointing only the operator's *node* at the robot's router
did not work: the router gossiped the robot nodes' `tcp/[::1]:<port>`
listen locators and no data flowed. Captured **unfiltered** (`tcpdump -i
eth0`, all protocols). rmw_zenoh 0.2.11 disables multicast scouting by
default, so the wire shows only TCP 7447 sessions (plus ARP and ICMPv6
MLD), no UDP 7446.

| File | Packets | Bytes | What |
|---|---|---|---|
| `zenoh_baseline.pcap` | 282 | 43677 | robot + teleop |
| `zenoh_rogue_cmd_vel.pcap` | 557 | 95000 | robot + teleop + rogue |

SHA-256:

```
313eebd0e71f5ee42608568cfaffc8ae930359490d4c8ad29a472e376c137b92  fastrtps_gz_baseline.pcap
59bfd237c02c2d4d9cfd4a695c254cd4aae9b203416f73214975f0358fdfdc51  fastrtps_gz_rogue_cmd_vel.pcap
4f85b6b71be3bbb6462a5bee8daa5a09e48d3604d49bf837803b27beb96dead3  cyclonedds_gz_baseline.pcap
881dfa05c62e6facc4fc06042afe879b97df27ea420733126ca123c2b4cc3dea  cyclonedds_gz_rogue_cmd_vel.pcap
1bae4d195ab1871171fbb44b4fa60ae901e68debea7f19ccfd7bd1b6f7485de8  fastrtps_gz_dual_odom.pcap
91325ff5eca677bced19da60c780231068a0dcfbecac78751cffd5d1e1f51798  fastrtps_frag_run1.pcap
9d3156389f17727a22e9f69e7da866b3248430ee7e7ed306cc932e321831fbdb  fastrtps_frag_run2.pcap
e1820ad488b040e4ac238f5b87a79353419de5e05be26d6ec732281ef6ed5ade  cyclonedds_frag_run1.pcap
eaf6b2621d88fe3e51db074697bfb810801793605eeeef205e74f10f0f7d0e76  cyclonedds_frag_run2.pcap
4c0a9b58699b0ee8534f5b711b940ef6559b841b2e514ec8640267a89239230b  zenoh_baseline.pcap
886f64d79ea2148642eff73919da87598ff5789542f62e47989375753edfad6d  zenoh_rogue_cmd_vel.pcap
```

## What they showed (second set)

1. **Gazebo, learn one run and replay a restarted one: no false positive
   on the discovery side.** The profile holds three identities
   (`gz_bridge`, `robot_state_publisher` on the robot host, `teleop_twist`)
   and the sim graph (`/clock`, `/tf`, `/tf_static`, `/joint_states`,
   `/odom`, `/robot_description`). The restarted bridge and
   robot_state_publisher start together on one host, take each other's
   slot provisionally and are moved by node evidence. Only the rogue is
   reported (unknown participant, Critical motion writer, over-envelope),
   and in `robodr-agentd` the firewall rejects exactly the rogue's
   commands.
2. **False positive, fixed: data before discovery.** Fast DDS sent three
   `/odom` samples to the station's reader 47 ms *before* the bridge's own
   SEDP publication reached it (a writer matches on the reader's SEDP).
   With `/odom` as a feedback topic that was a High
   `robot.motion.unattributed_sample` on the legitimate robot. An
   unannounced writer is now only noted and reported if it is still
   unannounced `MotionOptions::unattributed_grace` (2 s) later, or at
   `finish` (`robodr-ros2-pipeline::motion`, "Data before discovery is
   normal").
3. **The upstream demo world publishes two odometry streams onto one
   topic** (DiffDrive at 1 Hz with child frame `vehicle/chassis`,
   OdometryPublisher at 50 Hz with child `vehicle`; the bridge merges them
   into one writer). The motion monitor reported it: duplicate stamps once
   a second (`robot.motion.frozen_feedback`, Medium; kept as evidence in
   `fastrtps_gz_dual_odom.pcap`) and, under the rogue's interleaved
   commands, `robot.motion.inconsistent_feedback_stream` (High). Both are
   true observations of that data, so the lab world moves the DiffDrive
   odometry to an unbridged topic rather than the monitor being changed.
4. **Bug, fixed: Cyclone SEDP bursts were evicted.** Cyclone sends the
   first fragment of every SEDP sample of a participant (25 here) before
   any second fragment; the reassembler's quota of 4 partial samples per
   source (16 in all) evicted each before it could complete (140
   evictions; half of the robot's endpoints and services missing from the
   learned profile; `robot.rtps.discovery_fragment_evicted` in replay).
   Defaults are now 64 per source, 256 in all, 1 MiB
   (`robodr-rtps::ReassemblyLimits`).
5. **Bug, fixed: interleaved copies of one sample.** A writer sends one
   copy per matched reader, and the copies' fragments interleave (copy 1
   frag 1, copy 2 frag 1, copy 1 frag 2 completes, copy 2 frag 2). That
   last fragment started a new partial sample that could never complete:
   half of Fast DDS's fragmented SEDP samples ended "incomplete" (learner
   warning `fragmented_discovery_unreassembled`) and would later age out
   as evictions. The reassembler now remembers recently completed samples
   (256 samples / 256 KiB) and treats such fragments as late copies,
   compared byte for byte (differences are reported as conflicts).
6. With both fixes every fragmented announcement is rebuilt (0 rejected,
   0 evicted, 0 incomplete); learning from run 1 and replaying run 2 is
   clean apart from the designed `robot.rtps.fragmented_discovery` (Low,
   one per host), and the JointTrajectory commands are decoded from user
   DATA_FRAG.
7. **Zenoh is invisible to RTPS, and is now reported.** Replaying a Zenoh
   capture used to give no participant and no finding: a clean, quiet bus.
   `robodr-capture::middleware` recognises Zenoh by port (TCP 7447; UDP
   7446/7447 without the RTPS magic), the pipeline raises
   `robot.capture.unsupported_middleware` (High while no RTPS was seen,
   Medium otherwise), agentd health is never `ok` (unknown without RTPS,
   degraded with both), and `robodr-commission learn` warns
   (`unsupported_middleware`, also on stderr).
8. Worth knowing: under the rogue the simulated robot really moved faster
   (OdometryPublisher reported about 0.57 m/s against the authorised 0.3),
   but slower than the interleaved 3.0 m/s commands imply. On the
   captures' own timelines the motion monitor (both writers' commands,
   untuned tolerances) reports that once in the Fast DDS run (Medium
   `robot.motion.feedback_divergence`, "robot moving less than commanded":
   0.41 m/s against a band starting at 0.43) and not in the Cyclone DDS
   run. An earlier version of this note said "no divergence": `robodr-agentd`
   then stamped replayed packets with the time it handled them, so the
   whole replay was squeezed into however long the host took to read it
   and the result depended on host load (the Cyclone run raised it under
   load). Replays are now judged on their packet timestamps. The rogue is
   also caught by the discovery and envelope rules.

## Not covered (second set)

- Gazebo rendering sensors (camera, GPU lidar: they need a GPU / EGL),
  ros2_control / `gz_ros2_control`, nav2.
- Zenoh: decoding it (it is only detected), multicast scouting on the
  wire, Zenoh on non-default ports, over QUIC / TLS / serial, and a Zenoh
  session that started before the sensor and never reconnects (a live
  capture only passes TCP SYN / FIN / RST of port 7447 to user space).
- Fragmented SPDP from Fast DDS (it does not run below the SPDP size),
  IP-fragmented RTPS from a real stack.
