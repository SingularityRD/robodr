# robodr-cdr

Pure, no-panic, allocation-light decoder for the **user DATA** of ROS 2 motion
topics: XCDR1 / XCDR2 serialized payloads of

| DDS type name (SEDP `PID_TYPE_NAME`) | ROS type | maps to |
|---|---|---|
| `geometry_msgs::msg::dds_::Twist_` | `geometry_msgs/msg/Twist` | `MotionCommand` (`linear_speed = linear.x`, `angular_speed = angular.z`, plus `linear_y`, `linear_z`, `angular_x`, `angular_y`; all signed, per axis) |
| `geometry_msgs::msg::dds_::TwistStamped_` | `geometry_msgs/msg/TwistStamped` | same as Twist (header stamp is **not** trusted as time) |
| `trajectory_msgs::msg::dds_::JointTrajectory_` | `trajectory_msgs/msg/JointTrajectory` | `MotionCommand` (`joint_speed` = max \|velocity\| over all points) |
| `nav_msgs::msg::dds_::Odometry_` | `nav_msgs/msg/Odometry` | `MotionFeedback` (`linear_velocity = twist.linear.x`, `angular_velocity = twist.angular.z`, plus `linear_velocity_y/_z`, `angular_velocity_x/_y`; `measured_linear_speed = ‖twist.linear‖`) |
| `sensor_msgs::msg::dds_::Imu_` | `sensor_msgs/msg/Imu` | `MotionFeedback` (`angular_velocity = angular_velocity.z`, `angular_velocity_x/_y = angular_velocity.x/.y`) |
| `sensor_msgs::msg::dds_::JointState_` | `sensor_msgs/msg/JointState` | `MotionFeedback` (`measured_joint_speed` = max \|velocity\|) |

Dependencies: `std` and `robodr-events` only. Read-only: nothing is encoded or
sent.

## Unitree

RoboDR reads the motion content of every Unitree robot generation. The
`unitree` module decodes the DDS (`unitree_sdk2`) message types, and
`unitree_legacy` decodes the raw UDP frames of the Go1 generation
(`unitree_legged_sdk`). The DDS motion types are also `MessageKind`s
(`MessageKind::Unitree*`), registered in `Registry::with_builtin` under
their DDS and ROS names, so `decode_by_type_name` / `Registry::decode`
resolve them and `MotionMessage::to_event` produces the pipeline
`MotionCommand` / `MotionFeedback`.

| DDS type name | role | mapped to |
|---|---|---|
| `unitree_go::msg::dds_::LowCmd_` (MotorCmd_[20], BmsCmd_) | command | `joint_speed` = max \|dq\| over enabled motors with `kd != 0`; full per-motor q/dq/tau/kp/kd in `JointCommandFrame`; `crc_ok` |
| `unitree_go::msg::dds_::LowState_` (IMUState_, MotorState_[20], BmsState_) | feedback | `measured_joint_speed` = max \|dq\|; IMU gyro → angular rates; `crc_ok` |
| `unitree_go::msg::dds_::SportModeState_` | feedback | body `velocity` / `yaw_speed` → linear / angular velocity feedback |
| `unitree_hg::msg::dds_::LowCmd_` (MotorCmd_[35], mode_pr, mode_machine) | command | as go `LowCmd_`; `crc_ok` |
| `unitree_hg::msg::dds_::LowState_` | feedback | as go `LowState_`; `crc_ok` |
| `unitree_hg::msg::dds_::HandCmd_` / `HandState_` (Dex3) | command / feedback | joint speed of the (bounded) hand motor sequence |
| `unitree_hg::msg::dds_::IMUState_`, `unitree_hg_doubleimu::msg::dds_::doubleIMUState_` | feedback | gyroscope → angular rates (`doubleIMUState_` adds a trailing `tick`) |
| `unitree_api::msg::dds_::Request_` | command | header `api_id` + JSON `parameter` → typed `ApiCall`; `Move` / `SetVelocity` / `StopMove` → twist |
| `unitree_api::msg::dds_::Response_`, `unitree_go::msg::dds_::WirelessController_` | (not motion) | `decode_unitree` only |

`hg_doubleimu` differs from `hg`'s `IMUState_` only by the trailing
`uint32 tick`; everything else is identical (both have an `int16`
temperature, unlike `go`'s `int8`).

**Unitree CRC.** `unitree::crc::crc32_core` is the SDK's `crc32_core`
(CRC-32, polynomial `0x04C11DB7`, init `0xFFFFFFFF`, MSB-first, no final
XOR) over the struct's C++ in-memory image as `uint32` words, excluding the
`crc` field. `LowCmd_` / `LowState_` (go and hg) expose `crc_ok()` so a
firewall can require a valid CRC; `computed_crc()` recomputes it. Tested
against vectors from an independent re-implementation of the SDK algorithm
(see `src/unitree/crc.rs`).

**API interpretation.** `ApiRequest::call(service, model)` maps a request to
a typed `ApiCall` (`Move`, `SetVelocity`, `StopMove`, `Euler`, `SetFsmId`,
`SetTargetPosition`, a classified `Other`, or `Unknown { api_id }` — unknown
ids are never an error). The service comes from the topic
(`rt/api/<svc>/request`), because api ids are reused across services and
models (e.g. `1003` is sport `StopMove` but motion-switcher `ReleaseMode`;
`7106` is loco `SetArmTask` but arm `ExecuteAction`). api ids and JSON keys
are taken from the per-model SDK headers, each table citing its source. The
`parameter` JSON is parsed by a bounded, allocation-free reader (16 KiB /
depth 8 / 32 members caps, duplicate and escaped top-level keys rejected).

### Model matrix

`UnitreeModel` is derived from the SDK directories, not invented; every
entry carries its `source`. `ModelInfo` records generation, IDL family,
morphology, motor slots, actuated motor count (where the SDK examples say),
topics and API services.

| model | generation | IDL | morphology | actuated motors | source |
|---|---|---|---|---|---|
| Go2 | SDK2 DDS | go (20) | quadruped | 12 | `example/go2/go2_stand_example.cpp` |
| Go2-W | SDK2 DDS | go (20) | wheeled quadruped | 16 (12 legs + 4 wheels) | `example/go2w/` |
| B2 | SDK2 DDS | go (20) | quadruped | 12 | `example/b2/b2_stand_example.cpp` |
| B2-W | SDK2 DDS | go (20) | wheeled quadruped | 16 | `example/b2w/` |
| A2 | SDK2 DDS | — (no low-level example) | quadruped | ? | `example/a2/sport/`, `robot/a2/sport` |
| AS2 | SDK2 DDS | — (no low-level example) | quadruped | ? | `example/as2/sport/`, `robot/as2/sport` |
| H1 | SDK2 DDS | go (20) | humanoid | ? | `example/h1/low_level/humanoid.hpp` (unitree_go, loco service) |
| H1-2 | SDK2 DDS | hg (35) | humanoid | 27 | `example/h1/low_level/h1_27dof_example.cpp` |
| H2 | SDK2 DDS | hg (35) | humanoid | 31 | `example/h2/low_level/`, `robot/h2/{loco,arm}` |
| G1 | SDK2 DDS | hg (35) | humanoid | 29 | `example/g1/low_level/`, Dex3, `robot/g1/{loco,arm}` |
| R1 | SDK2 DDS | hg (35) | humanoid | 26 | `example/r1/low_level/` |
| Go1 | legacy UDP | comm.h (20) | quadruped | 12 | `unitree_legged_sdk` v3.8.6 |
| A1, Aliengo, B1 | legacy UDP | — | quadruped | 12 (nominal) | `quadruped.h` `LeggedType`; frame layout only in release v3.3.1 (not in these sources) |

**Uncertainties (not guessed):**

- A2 / AS2 ship no low-level example, so their motor count and IDL family
  are unknown; only the sport-state (`unitree_go::SportModeState_`) and
  sport client are confirmed.
- H1 is listed by the SDK with a `unitree_go` low-level interface over an
  array of 20 slots; its actuated motor count is not stated in the example.
- A1 / Aliengo / B1 appear in `unitree_legged_sdk`'s `LeggedType` enum, but
  v3.8.6 supports only Go1; their exact UDP frame layouts live in the older
  v3.3.1 release, which is not in these sources. The legacy decoders target
  the v3.8.6 `comm.h` layout.
- v3.8.6 sends `LowCmd` / `LowState` in a "compressed" wire form
  (`LOW_CMD_LENGTH = 614`, `LOW_STATE_LENGTH = 807`) whose layout is not in
  the public headers; `unitree_legacy` decodes the declared `comm.h`
  (uncompressed) layout and `LegacyKind::for_len` flags a 614/807-byte
  frame as the undecodable compressed form. `HighCmd` / `HighState`
  (129 / 1087 bytes) are not compressed and decode directly.
- XCDR2: the SDK's own traffic is Cyclone DDS XCDR1 (`CDR_LE`); XCDR2
  support (and the `D_CDR2` nesting choice, `Limits::d_cdr2_nesting`) is
  spec-derived, as for the ROS types.

### Status

Decoded from Unitree's published IDL / msg definitions and hand-built
vectors; **not yet verified against traffic captured from a real robot.**

Separately (not motion messages, not in `MessageKind` / `Registry`):
`std_msgs::msg::dds_::Bool_`, `UInt8_` and `String_` (`std_msgs` module,
`decode_std` / `decode_std_by_type_name` -> `StdValue`), for robots that
publish an e-stop flag or an operating mode. A boolean octet other than 0
or 1 is rejected (`StdDecodeError::InvalidBool`); strings obey
`Limits::max_string_len`. `robodr-agentd`'s safety-state feed uses them.

## API

```rust
use robodr_cdr::{Registry, Limits, EventContext};

let registry = Registry::with_builtin();          // DDS + ROS names → decoder
let decoded = registry.decode(type_name, serialized_payload, &Limits::default())?;
let event = decoded.message.to_event(&EventContext {
    channel: "/cmd_vel",                           // de-mangled topic from SEDP
    writer_guid: Some(&writer_guid_hex),           // RTPS writer of the DATA
    timestamp_ns: observed_mono_ns,                // capture clock, not the payload
});
```

* `decode_payload(kind, payload, &limits)` / `decode_by_type_name(..)` —
  stateless entry points. `payload` is the RTPS `serializedPayload`
  **including** its 4-byte encapsulation header.
* `Decoded { encapsulation, message, consumed, trailing_bytes }`.
  `MotionMessage` borrows from the payload: strings are `CdrStr` (raw bytes,
  UTF-8 not required), `float64[]` is `F64Seq`, `string[]` is `StringSeq`
  (zero-copy views). The only heap allocation is `JointTrajectory::points`,
  capped by `Limits::max_trajectory_points`.
* `MotionMessage::{to_command, to_feedback, to_event, role}`.
* `Registry::{new, with_builtin, register, kind, decoder, decode}` —
  `register` lets an integrator map a vendor-renamed type onto a built-in
  decoder (`registry::builtin_decoder(kind)`).
* `Limits` (defaults): payload 256 KiB, string 256 bytes, sequence 1024
  elements, trajectory 1024 points.

## Wire rules implemented

* Encapsulation header (DDSI-RTPS 2.5 §10, XTypes 1.3 §7.6.3.1.2): big-endian
  identifier + options. `CDR_BE/LE` (0x0000/1), `CDR2_BE/LE` (0x0010/11),
  `D_CDR2_BE/LE` (0x0014/15) decode; `PL_CDR*` (0x0002/3, 0x0012/13) and XML
  (0x0004) are `UnsupportedRepresentation` (ROS motion types are never
  mutable — a parameter-list payload on a motion topic deserves a look);
  anything else is `UnknownRepresentation`. The options' 2 low bits (end
  padding) are exposed, never relied on.
* Alignment origin = first octet after the encapsulation header. XCDR1 aligns
  primitives to `min(size, 8)`; XCDR2 to `min(size, 4)`. No padding is
  inserted for an empty `float64[]` (padding precedes a serialized element).
* XCDR2: a sequence of non-primitive elements (`string[]`,
  `JointTrajectoryPoint[]`) is preceded by a DHEADER. Under `D_CDR2_*` every
  struct, top-level and nested, also has a DHEADER (ROS IDL types are
  `@appendable` by default); members beyond what we know are skipped by the
  DHEADER (forward-compatible). Under plain `CDR2_*` no struct has one.
* Strings: `uint32` length incl. NUL, bytes, NUL. Length 0 is accepted as
  empty; a non-empty string without trailing NUL is rejected. Embedded NULs /
  invalid UTF-8 are kept as bytes.
* NaN / ±inf are decoded and exposed unchanged. Aggregates propagate them
  (`F64Seq::max_abs` returns NaN if any element is NaN — `f64::max` would
  silently skip it). The firewall / `Profile::evaluate` already treat a
  non-finite command as Critical; the motion monitor decides for feedback.

## Hostile input

No `unsafe`, no direct indexing, checked arithmetic, no `unwrap`/`panic` in
library code (enforced by clippy `deny` lints). Every length is checked
against its cap **and** against the bytes actually left before iterating or
reserving; DHEADERs are checked against their container and decoding never
reads past them. Tests: all strict prefixes of valid payloads in all six
encodings, `u32::MAX` string / sequence / DHEADER lengths, undersized
DHEADERs, a wrong decoder for every sample, and two xorshift fuzz loops
(~20k random payloads + ~144k mutated valid payloads under tight and
unbounded limits) asserting no panic and `consumed + trailing == body`.

## What is and is not verified

Verified (in this crate's tests):

* Hand-derived byte vectors — Twist (CDR_LE, CDR_BE, D_CDR2_LE, D_CDR2_BE),
  TwistStamped (CDR_LE vs CDR2_LE vs D_CDR2_LE, showing the 8- vs 4-byte
  alignment difference after `frame_id`), JointState (CDR_LE, CDR_BE,
  CDR2_LE incl. the `string[]` DHEADER). Every offset is commented in
  `tests/vectors.rs`. A separate test-only encoder reproduces each hand
  vector byte for byte and is then used for Odometry / Imu /
  JointTrajectory round trips in all six encodings.

**Not verified:**

* No capture from **Fast DDS**, **Cyclone DDS** or **Connext** was available
  here; the layouts come from reading the specs. Before relying on this in
  enforce mode, decode a pcap of `ros2 topic pub /cmd_vel ...`, `/odom`,
  `/joint_states` from each RMW used on the platform and compare.
* XCDR2 in particular: which identifier an RMW uses for ROS types (`CDR2` vs
  `D_CDR2`) and whether it nests DHEADERs exactly as XTypes 1.3 says is
  unconfirmed. Default ROS 2 RMWs (Humble–Jazzy) send XCDR1 `CDR_LE`; treat
  XCDR2 support as spec-derived.
* The encapsulation identifier is trusted: XCDR1 bytes labelled `CDR2` decode
  to wrong values rather than an error (there is no way to tell from the
  bytes alone). `trailing_bytes != padding` is a useful hint.
* Message definitions are those of ROS 2 Humble through Kilted (unchanged
  since Foxy). A distro that changes them needs a new decoder.

## Wiring into the pipeline (done, synthetic traffic only)

`robodr-rtps` has a user-DATA walker (`UserDataWalker`) and
`robodr-ros2-pipeline`'s `motion` module wires this crate in: writer GUID →
(topic, type name) from SEDP, decode by the announced type name with
`Registry::decode`, `to_event` with an `EventContext` built from the
transport (channel = de-mangled topic, writer GUID, capture time), findings
`robot.motion.undecodable_sample` (Medium, rate limited),
`robot.motion.unattributed_sample` (High) and
`robot.motion.sample_source_mismatch` (Critical / High), and
`Profile::evaluate` on decoded commands. `robodr-agentd` hands the decoded
events to `Agent::handle` (firewall recording-only, motion monitor). See
those crates' READMEs.

Still true: only hand-built payloads have gone through it (see "What is and
is not verified" above), and SROS 2 / DDS-Security protected payloads cannot
be decoded passively (they are reported as undecodable).
