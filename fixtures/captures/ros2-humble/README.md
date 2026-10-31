# Real ROS 2 Humble captures (Fast DDS 2.6)

Traffic from actual ROS 2 Humble processes, recorded on 2026-10-31 with
[`tools/lab-capture/capture_humble.sh`](../../../tools/lab-capture/capture_humble.sh)
and used by `crates/robodr-ros2-pipeline/tests/real_captures_humble.rs`
(SALES-READINESS T33, T14, T78). Same Docker bridge, addresses, nodes and
capture point as the Jazzy set ([`../ros2-jazzy/`](../ros2-jazzy/README.md)).

## Setup

| | |
|---|---|
| Image | `ros:humble-ros-base` (`sha256:d9bcf2e6f72df127fdee07048c2e87b1b4b9a59a74af0592f4489fc2844aa855`), unmodified |
| Fast DDS | `ros-humble-fastrtps` 2.6.12, `rmw_fastrtps_cpp` 6.2.10 |
| rclpy | 3.3.22 |
| SROS 2 | `ros-humble-sros2` 0.10.9 (`ros2 security`), OpenSSL 3.0.2 |
| Network | one Docker bridge, `10.77.10.0/24`, `ROS_DOMAIN_ID=0` |
| Capture | host `tcpdump` 4.99.4 in the robot container's network namespace (`HOST_TCPDUMP=1`: `nsenter -n`, `-i eth0 -U -s 0 udp`), classic pcap, Ethernet |

The base image has no tcpdump and the lab image
([`tools/lab-capture/Dockerfile`](../../../tools/lab-capture/Dockerfile),
`--build-arg DISTRO=humble`) could not be built here: `packages.ros.org` was
not reachable from this environment. For the same reason there is **no
Cyclone DDS** Humble capture (`ros-humble-rmw-cyclonedds-cpp` is not in
`ros-base`); building the lab image where the ROS apt repository is
reachable and running the Jazzy scripts with `DISTRO=humble` /
`IMG=robodr-cap:humble` is what remains (see "Not covered").

Nodes are the Jazzy ones (`robot.py`, `teleop.py`, `arm.py`), plus
`service_node.py` (a `std_srvs/Trigger` server) for the extra processes of
the `multi` runs, because `ros-base` has no `demo_nodes_cpp` /
`action_tutorials_cpp`. The node names are kept
(`add_two_ints_server`, `fibonacci_action_server`).

Transports: Fast DDS 2.6 does not know `FASTDDS_BUILTIN_TRANSPORTS`, so the
UDP-only runs use
[`fastdds_udp_only.xml`](../../../tools/lab-capture/fastdds_udp_only.xml)
(builtin transports off, one UDPv4 transport). The `shm` and `sros2*` runs
use the **default** transports (UDPv4 + shared memory), which is what a
Humble robot runs out of the box.

## Files

| File | Packets | Bytes | What |
|---|---|---|---|
| `fastrtps_baseline.pcap` | 283 | 68694 | robot (`/base_controller`) + teleop (`/cmd_vel` 10 Hz, 0.3 m/s), UDP only |
| `fastrtps_rogue_cmd_vel.pcap` | 525 | 127082 | as above, rogue `/debug_tool` from `10.77.10.66` joins at ~6 s (3.0 m/s) |
| `fastrtps_multi_run1.pcap` | 595 | 157362 | robot host: `base_controller`, `add_two_ints_server`, `fibonacci_action_server`, + teleop |
| `fastrtps_multi_run2.pcap` | 615 | 161706 | the same, robot-host processes started in reverse order |
| `fastrtps_frag_run1.pcap` | 1233 | 362590 | `maxMessageSize` 400 ([`fastdds_frag_400.xml`](../../../tools/lab-capture/fastdds_frag_400.xml)): SEDP and a 40-point JointTrajectory as DATA_FRAG |
| `fastrtps_frag_run2.pcap` | 1198 | 361244 | second run of the same |
| `fastrtps_shm_default.pcap` | 423 | 111106 | default transports; on the robot host a `local_planner` publishes `/cmd_vel` (0.2 m/s) to the controller over **shared memory**; teleop remote |
| `fastrtps_sros2_baseline.pcap` | 307 | 168190 | SROS 2, `ROS_SECURITY_STRATEGY=Enforce`: robot (enclave `/lab/base_controller`) + teleop (`/lab/teleop_twist`) |
| `fastrtps_sros2_rogue.pcap` | 527 | 398286 | as above + an **unsecured** rogue from `10.77.10.66` and a rogue from `10.77.10.67` with an enclave of the **same name** from a **foreign keystore** |

`sros2/`: the public part of the lab keystore of the `sros2*` runs
(`governance.xml`, both enclaves' `permissions.xml` and `cert.pem`, the CA
certificate). Private keys stay in the git-ignored `tools/lab-capture/.sros2*`.

SHA-256:

```
5da40ddd6b484d278a43ca7ad2206549ba4e852ccf301faa8f71175a94bebb20  fastrtps_baseline.pcap
10844a912077774aca6df8e4c0b147fd0b0ea249383fb169308e31572e9424e5  fastrtps_frag_run1.pcap
35f18626a73226986132cda0cd90fd821975c58dc4628e780454868f17a3da6c  fastrtps_frag_run2.pcap
239428f56e7a349c783a43b86036fae887f599faa67643e2070b9ee7a0024945  fastrtps_multi_run1.pcap
4b20c482e54af7a6079c0877c186d742d4fd0c00ef31f38d173d29fb19bd81c6  fastrtps_multi_run2.pcap
5648bb037c56a346245790a3590c554cc7131128df4a10f5a86d9d8c2e8ca170  fastrtps_rogue_cmd_vel.pcap
80e673f63c8ca6663fb73136fc1bd74ebd267c02239da02d4b8a8b4ed4d0fca2  fastrtps_shm_default.pcap
59f22f2b4df6212f53250ee9eab38f9641ee2d8b30fb56b9d556bcae0912c6e5  fastrtps_sros2_baseline.pcap
3d6ca29c939b9aed43d2788ada20c59ccea0135da05b1fd4e088d0bad03a7e3b  fastrtps_sros2_rogue.pcap
```

## What they showed

1. **Humble behaves like Jazzy for everything the Jazzy captures tested.**
   Learning from one run and replaying another (new GUID prefixes) is clean
   apart from the teleop leaving; the rogue is reported (unknown
   participant, Critical motion writer, over-envelope), and only the rogue
   is Critical; the three same-host processes started in reverse order end
   on their own identities; fragmented SEDP is rebuilt without loss and
   the JointTrajectory commands are decoded from user DATA_FRAG.
2. **Fast DDS 2.6 sends no type information in SEDP**, so its
   announcements fit the 640-byte maximum that fragments Jazzy's; the
   Humble frag runs use 400 bytes.
3. **Shared memory is on by default and invisible (T14).** With default
   transports every participant's SPDP advertises a shared-memory locator
   (kind 16) next to its UDP ones, and the `local_planner`'s `/cmd_vel`
   to the controller on the same host never appears on the wire: only the
   remote teleop's commands are decoded. This is now reported once per
   host as `robot.capture.unsupported_transport` (Medium); the UDP-only
   runs do not raise it. The matching host-side evidence is the Fast DDS
   segments in `/dev/shm` (`fastrtps_port<N>`, `fastrtps_<hex>`,
   `sem.fastrtps_port<N>_mutex`), which `robodr-ros2-watch --check-config`
   reports.
4. **SROS 2 hides every topic (T78).** With sros2's default governance
   (discovery and data `ENCRYPT`, RTPS `SIGN`) SEDP and user data are
   encrypted: `learn` finds the two participants and no topic, no envelope
   (`protected_discovery` warning). The SPDP stays in clear and carries the
   identity token: `dds.cert.sn` `/CN=\/lab\/base_controller` (OpenSSL
   one-line form; the permissions file says `CN=/lab/base_controller`),
   `dds.ca.sn` `/CN=sros2CA`. The permissions document and the presented
   certificate cross the wire in clear in the authentication handshake
   (not parsed yet).
5. **Bug, fixed: a restarted SROS 2 robot was an unknown participant.**
   DDS-Security derives a secured participant's GUID prefix from its
   certificate subject (`af0c854b646f...` for the controller in both runs),
   so `learn`'s prefix-derived `vendor` holds subject-hash bytes, not
   `010f`, and identity resolution never matched. The resolver now accepts
   those bytes for participants that announce a DDS-Security identity.
6. **What the keystore adds.** With `sros2_keystore` set, the unsecured
   rogue (no identity on a domain that requires authentication) is
   `robot.ros2.untrusted_security_identity` Medium, and a subject the
   keystore does not grant is High. The foreign-keystore rogue claims the
   teleop's subject (and the same default CA name `sros2CA`), so its SPDP
   looks legitimate: only its address gives it away (unknown participant).
   Telling it apart by its certificate needs the handshake (not inspected).

## Not covered

- **Cyclone DDS on Humble** (`rmw_cyclonedds_cpp`, Cyclone 0.10.x): the
  package could not be installed here. Run `capture.sh`,
  `capture_multi.sh` and `capture_frag.sh` with `DISTRO=humble
  IMG=robodr-cap:humble` after building the lab image for Humble.
- Gazebo on Humble (Fortress via `ros_gz`), Zenoh on Humble.
- Cyclone DDS iceoryx shared memory, Connext SHMEM (kinds recognised, not
  captured).
- SROS 2 with a governance that leaves discovery in clear (topic checks
  against the permissions), Cyclone DDS with DDS-Security, and parsing of
  the authentication handshake (presented certificate vs keystore).
