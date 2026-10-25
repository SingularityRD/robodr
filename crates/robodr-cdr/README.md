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

The `unitree` module decodes the DDS (`unitree_sdk2`) message types, and
`unitree_legacy` decodes the raw UDP frames of the Go1 generation
(`unitree_legged_sdk` v3.8.6). The DDS motion types are also `MessageKind`s
(`MessageKind::Unitree*`), registered in `Registry::with_builtin` under
their DDS and ROS names, so `decode_by_type_name` / `Registry::decode`
resolve them and `MotionMessage::to_event` produces the pipeline
`MotionCommand` / `MotionFeedback`. Coverage is exactly the matrix below;
see "Status" for what that does and does not mean.

| DDS type name | topic(s) | role | mapped to |
|---|---|---|---|
| `unitree_go::msg::dds_::LowCmd_` (MotorCmd_[20], BmsCmd_) | `rt/lowcmd`; `rt/arm_sdk` (H1) | command | `joint_speed` / `joint_torque` / `joint_kp` over all 20 slots (below); `crc_ok` (advisory) |
| `unitree_go::msg::dds_::LowState_` | `rt/lowstate`, `rt/lf/lowstate` | feedback | `measured_joint_speed` = max \|dq\|; IMU gyro → angular rates; `crc_ok` |
| `unitree_go::msg::dds_::SportModeState_` | `rt/sportmodestate`, `rt/lf/sportmodestate` | feedback | body `velocity` / `yaw_speed` |
| `unitree_go::msg::dds_::MotorCmds_` (sequence of MotorCmd_) | `rt/hand_sdk` (G1 hand SDK; weight × 100 in `cmds[0].mode`) | command | as `LowCmd_` over the sequence (≤ 35) |
| `unitree_hg::msg::dds_::LowCmd_` (MotorCmd_[35]) | `rt/lowcmd`, `rt/arm_sdk`, `rt/user_lowcmd` | command | as go `LowCmd_`, all 35 slots |
| `unitree_hg::msg::dds_::LowState_` | `rt/lowstate` | feedback | as go `LowState_` |
| `unitree_hg::msg::dds_::HandCmd_` / `HandState_` (Dex3) | `rt/dex3/{left,right}/cmd`, `.../state`, `rt/lf/dex3/.../state` | command / feedback | as `LowCmd_` over the (≤ 16) motors; mode octet = `Dex3Mode` bitfield `id \| status << 4 \| timeout << 7` (informational) |
| `unitree_hg::msg::dds_::MotorCmd_` / `MotorState_` (standalone) | `rt/waistpitchcmd` / `rt/waistpitchstate` (G1-D waist) | command / feedback | one-joint frame |
| `unitree_hg::msg::dds_::IMUState_`, `unitree_hg_doubleimu::msg::dds_::doubleIMUState_` | `rt/secondary_imu` | feedback | gyroscope → angular rates |
| `unitree_api::msg::dds_::Request_` | `rt/api/<service>/request` | command | `ApiCall` (below); velocity calls → twist; every call's `ApiClass` → `command_class` |
| `unitree_api::msg::dds_::Response_`, `unitree_go::msg::dds_::WirelessController_` | `rt/api/<service>/response`, `rt/wirelesscontroller` | (not motion) | `decode_unitree` only |

**Joint commands: every slot, the mode never gates a check.** Unitree's
motor controller applies `T = kp·(q − q_measured) + kd·(dq − dq_measured) +
tau`. A command frame maps to `joint_speed` = max \|dq\| over slots with
`kd != 0`, `joint_torque` = max \|tau\| and `joint_kp` = max \|kp\|, over
**all** slots on the wire (not only `ModelInfo::actuated_motors`: the
arm-SDK weight is `motor_cmd[29].q` on G1, `[9]` on H1, `[27]` on H1-2,
`[31]` on H2, see `ModelInfo::arm_sdk_weight_slot`; R1 uses `mode_pr`).
`rt/arm_sdk` frames always carry `mode = 0` and still move the arms, so the
mode octet is informational only; a non-finite value in **any** field of
**any** slot makes all three NaN (Critical in `Profile::evaluate`). The
ROS 2 pipeline adds `joint_position_step` (max \|Δq\| of an acting position
target against the previous frame on the channel). The profile envelope
bounds them with `max_joint_torque`, `max_joint_kp` and
`max_joint_position_step`; on an envelope without them a command that uses
torque or position gain is `robot.motion.unverifiable_command` (Medium),
never silently "speed 0".

**API interpretation.** `ApiRequest::call(service, model)` maps a request to
a typed `ApiCall` (`Move`, `SetVelocity`, `StopMove`, `Euler`, `SetFsmId`,
`SetTargetPosition`, a classified `Other`, `Unknown { api_id }` or
`Malformed`). The service comes from the topic (`rt/api/<svc>/request`),
because api ids are reused across services and models. The wire `api_id` is
`int64` but the SDK server dispatches on its **low 32 bits**
(`robot/server/server.hpp`): lookups use `api_id as i32`, and an id outside
the `int32` range is `DecodeAnomaly::ApiIdOutOfRange` (pipeline:
`robot.motion.api_id_out_of_range`, High). Each call's `ApiClass` is carried
into the event as `MotionCommand::command_class`; `Profile::evaluate`
reports `Trick` (High), `Trajectory` (Medium), `Unknown` / `Malformed` on a
motion service (High) as `robot.motion.unverifiable_command`, and
`ControlHandover` as `robot.motion.control_handover` (High). The event path
does not know the model, so a model-specific id (G1 `SwitchToUserCtrl`, Go2
`FrontFlip`, ...) is `Unknown` there (High) and fully classified when a
model is given. The `parameter` JSON is read by a bounded, allocation-free
reader (16 KiB / depth 8 / 32 members, duplicate and escaped top-level keys
rejected); top-level arrays are accepted where the SDK sends them (B2
`TrajectoryFollow`, ≈ 3 KB). `Request_::parameter` / `Response_::data` are
capped at that 16 KiB (`MAX_JSON_LEN`), not at `Limits::max_string_len`.

Motion-relevant services, from every `*_api.hpp` under
`unitree_sdk2/include/unitree/robot/**` and every client in
`unitree_sdk2_python/unitree_sdk2py/**`:

| service | models | interpreted |
|---|---|---|
| `sport` | Go2 / Go2-W / B2 / B2-W / A2 / AS2 (1001..2058), G1 / H2 / R1 loco (7001..7111; R1 `SetArmTask` 7106 and G1 / R1 FSM ids 701 / 702 / 706 from the Python SDK) | every id of the headers |
| `loco` | H1 (8001..8204) | every id |
| `arm` | G1 / H2 arm actions | every id |
| `motion_switcher` | B2 / G1 (and every model using it) | every id (`SelectMode` / `ReleaseMode`: control handover) |
| `obstacles_avoid` | Go2 | `Move` 1003 `{"x","y","yaw","mode"}`: mode 0 velocity, 1 / 2 position (trajectory); `UseRemoteCommandFromApi` handover |
| `agv` | G1-D | `Move` 1001 `{"vx","vy","vyaw"}` velocity; `HeightAdjust` (normalised column speed, posture) |
| `robot_state` | Go2 / B2 | `ServiceSwitch` (starts / stops services, the sport service included: handover) |
| `uwbswitch` | Go2 (UWB tracking) | `SwitchSet` (robot follows the UWB remote: handover) |

Not motion (never interpreted, `ApiService::Other`): `vui`, `voice`
(audio), `videohub`, `front_videohub`, `back_videohub`, `config`. The SDK's
`SportModeCmd_` IDL type is not published on any SDK topic.

**Unitree CRC (advisory).** `unitree::crc::crc32_core` is the SDK's
`crc32_core` (CRC-32, polynomial `0x04C11DB7`, init `0xFFFFFFFF`, MSB-first,
no final XOR) over the struct's C++ image as `uint32` words, excluding the
`crc` field, with **zeroed** padding. The SDK hashes the in-memory struct,
whose padding bytes C++ leaves indeterminate on some builds (go `LowCmd_`
22-23 and 803; go `LowState_` 22-23, 77-79, 1145-1147, 1154-1155; hg
`LowCmd_` 2-3; hg `LowState_` 10-11, 70-71), so `crc_ok() == false` may be a
padding artefact of the sender's build rather than a forged frame. It must
be validated against captured traffic; nothing here or in the ROS 2
pipeline changes a severity because of it (the Motion Firewall decides on
its own). Tested against independent vectors (`tests/unitree_vectors.rs`,
`tests/data/unitree/`: CRCs `0xe571104a`, `0x73b6f94c`, `0x533c453a`,
`0xe09ebd5e` and every field value, in CDR_LE, CDR_BE and CDR2_LE).

**XCDR2.** Every Unitree IDL type is `@final` (the generated TypeObjects
carry `IS_FINAL`; the Python IDL is `@annotate.final`). Under XCDR2 no
struct carries a DHEADER, only arrays / sequences of structs do; a `D_CDR2`
encapsulation header is read the same way (Cyclone DDS takes the
extensibility from the type), and `Limits::d_cdr2_nesting` does not apply.

**Legacy UDP.** `LegacyHighCmd::to_motion_command` maps mode 2 (target
velocity walking) to the body velocity and every mode to a class (posture,
trajectory for position walking, trick for backflip / jumpYaw /
straightHand, unknown); `LegacyLowCmd::to_motion_command` is the joint
command as for DDS. The v3.8.6 library also has an unpublished `encryptCRC`
mode: with it, plain CRC verification is expected to fail;
`crc_check(.., LegacyCrcMode::EncryptCrc)` reports `None` (not checkable).

### Model matrix

`UnitreeModel` is derived from the SDK directories, not invented; every
entry carries its `source`.

| model | generation | IDL | morphology | actuated motors | arm-SDK weight | topics / services covered |
|---|---|---|---|---|---|---|
| Go2 | SDK2 DDS | go (20) | quadruped | 12 | — | low cmd/state, `rt/lf/lowstate`, sport state; `sport`, `obstacles_avoid`, `robot_state`, `uwbswitch` |
| Go2-W | SDK2 DDS | go (20) | wheeled quadruped | 16 | — | low cmd/state, `rt/lf/sportmodestate`; `sport` |
| B2 | SDK2 DDS | go (20) | quadruped | 12 | — | low cmd/state; `sport`, `motion_switcher`, `robot_state` |
| B2-W | SDK2 DDS | go (20) | wheeled quadruped | 16 | — | low cmd/state; `sport` |
| A2 | SDK2 DDS | — (no low-level example) | quadruped | ? | — | `rt/lf/sportmodestate`; `sport` |
| AS2 | SDK2 DDS | — (no low-level example) | quadruped | ? | — | `rt/lf/sportmodestate`; `sport` |
| H1 | SDK2 DDS | go (20) | humanoid | ? | slot 9 | low cmd/state, `rt/arm_sdk`; `loco` |
| H1-2 | SDK2 DDS | hg (35) | humanoid | 27 | slot 27 | low cmd/state, `rt/arm_sdk` |
| H2 | SDK2 DDS | hg (35) | humanoid | 31 | slot 31 | low cmd/state, `rt/arm_sdk`, IMU; `sport`, `arm` |
| G1 | SDK2 DDS | hg (35) | humanoid | 29 | slot 29 | low cmd/state, `rt/arm_sdk`, `rt/user_lowcmd`, `rt/hand_sdk`, Dex3, `rt/waistpitch*`, IMU; `sport`, `arm`, `agv`, `motion_switcher` |
| R1 | SDK2 DDS | hg (35) | humanoid | 26 | `mode_pr` × 100 | low cmd/state, `rt/arm_sdk`, IMU; `sport` |
| Go1 | legacy UDP | comm.h (20) | quadruped | 12 | — | `HighCmd` / `HighState` (129 / 1087 B), `LowCmd` / `LowState` declared layout only |
| A1, Aliengo, B1 | legacy UDP | — | quadruped | 12 (nominal) | — | none: frame layout only in release v3.3.1 (not in these sources) |

Topics found in `unitree_sdk2/example`, `include/unitree/dds_wrapper` and
`unitree_sdk2_python` that carry **no command** and are not decoded:
`rt/hispeed_state` (`geometry_msgs` `Point32_`, G1-D height),
`rt/inspire/state` (Inspire hand state), `rt/audio_msg` (audio),
`rt/utlidar/switch` (`std_msgs` `String_` lidar on/off).

**Uncertainties (not guessed):**

- A2 / AS2 ship no low-level example, so their motor count and IDL family
  are unknown; only the sport-state and sport client are confirmed.
- H1's actuated motor count is not stated in its example.
- A1 / Aliengo / B1 frame layouts are only in release v3.3.1, not in these
  sources; the legacy decoders target the v3.8.6 `comm.h` layout.
- v3.8.6 sends `LowCmd` / `LowState` in a "compressed" wire form (614 / 807
  bytes) whose layout is not published; `LegacyKind::for_len` flags it as
  undecodable.
- The model-specific API tables apply only when the caller passes the
  model; the pipeline does not know it (see "API interpretation").

### Status

Decoded from Unitree's published IDL / msg definitions, checked against
hand-built vectors and against independent reviewer vectors (random field
values, CDR_LE / CDR_BE / CDR2_LE, CRCs); **not yet verified on traffic
captured from a real robot.** In particular the CRC padding behaviour, the
`encryptCRC` mode and whether any robot sends XCDR2 must be confirmed on a
capture.

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
* `Limits` (defaults): payload 256 KiB, string 256 bytes (the Unitree API
  `parameter` / `data` strings use the 16 KiB JSON cap instead), sequence
  1024 elements, trajectory 1024 points.

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
