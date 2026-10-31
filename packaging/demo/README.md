# RoboDR demo captures

Two small, real ROS 2 captures to see RoboDR detect a rogue command source
without a robot, on any host where the package is installed. Installed with
the package in `/usr/share/doc/robodr/demo/`. Nothing here touches the
network or any RoboDR service: both tools only read the files.

| File | What |
|---|---|
| `fastrtps_baseline.pcap` | a robot (`/base_controller`, 10.77.10.10) and its legitimate teleop (`/teleop_twist`, 10.77.10.21, `/cmd_vel` at 0.3 m/s), about 15 s, then the teleop stops |
| `fastrtps_rogue_cmd_vel.pcap` | the same robot and teleop; after about 6 s a rogue node (`/debug_tool`, 10.77.10.66) joins and publishes `/cmd_vel` at 3.0 m/s |

ROS 2 Jazzy, Fast DDS 2.14.6 over UDPv4, recorded in a container lab on
2026-10-17 (source: `fixtures/captures/ros2-jazzy/` in the RoboDR source
tree, whose README has the full set-up). Check the files against
`SHA256SUMS` in this directory.

## 1. Learn a profile from the clean run

```sh
cp /usr/share/doc/robodr/demo/*.pcap /tmp/ && cd /tmp
robodr-commission learn --pcap fastrtps_baseline.pcap --out demo-profile.json
```

This writes an **unlocked draft** profile (2 participants, the `/cmd_vel`
motion channel and its learned speed envelope) and a sign-off list of four
items. On a real robot every item is reviewed and signed before the profile
is locked (`robodr-commission(1)`, OPERATIONS.md section 5); the demo skips
that, so everything below runs observe-only.

## 2. Replay the clean run

```sh
robodr-ros2-watch --profile demo-profile.json --pcap fastrtps_baseline.pcap
```

Only bookkeeping at the end of the capture, when the teleop stops: one
`robot.ros2.participant_removed` (medium) and low-severity
`robot.rtps.discovery_removal` lines. No unknown participant, no motion
finding.

## 3. Replay the attack

```sh
robodr-ros2-watch --profile demo-profile.json --pcap fastrtps_rogue_cmd_vel.pcap
```

Among the findings (one JSON line each, `"mode": "observe"`):

* `robot.ros2.unknown_participant` (high): a DDS participant from
  10.77.10.66 joined the robot graph;
* `robot.ros2.unauthorized_motion_writer`: it publishes on `/cmd_vel`;
* `robot.motion.linear_over_envelope`: its 3.0 m/s command is outside the
  learned envelope;
* `robot.ros2.unknown_reader` / `robot.ros2.unknown_service`: the rogue
  node's own ROS 2 discovery endpoints.

The warnings on stderr (no trusted keys, profile not locked) are expected:
they are what an uncommissioned installation says.

## What the demo does not show

The full agent (`robodr-agentd`): signed black-box evidence, OCSF findings
in the spool, delivery to the SOC and response planning. Those need a
commissioned, signed profile and keys (`robodr-setup init`, then the quick
start in `/usr/share/doc/robodr/customer/quick-start.md`).
