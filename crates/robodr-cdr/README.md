# robodr-cdr

Pure, no-panic, allocation-light decoder for the **user DATA** of ROS 2 motion
topics: XCDR1 / XCDR2 serialized payloads of

| DDS type name (SEDP `PID_TYPE_NAME`) | ROS type | maps to |
|---|---|---|
| `geometry_msgs::msg::dds_::Twist_` | `geometry_msgs/msg/Twist` | `MotionCommand` (`linear_speed = linear.x`, `angular_speed = angular.z`, signed) |
| `geometry_msgs::msg::dds_::TwistStamped_` | `geometry_msgs/msg/TwistStamped` | same as Twist (header stamp is **not** trusted as time) |
| `trajectory_msgs::msg::dds_::JointTrajectory_` | `trajectory_msgs/msg/JointTrajectory` | `MotionCommand` (`joint_speed` = max \|velocity\| over all points) |
| `nav_msgs::msg::dds_::Odometry_` | `nav_msgs/msg/Odometry` | `MotionFeedback` (`linear_velocity = twist.linear.x`, `angular_velocity = twist.angular.z`, `measured_linear_speed = ‖twist.linear‖`) |
| `sensor_msgs::msg::dds_::Imu_` | `sensor_msgs/msg/Imu` | `MotionFeedback` (`angular_velocity = angular_velocity.z`) |
| `sensor_msgs::msg::dds_::JointState_` | `sensor_msgs/msg/JointState` | `MotionFeedback` (`measured_joint_speed` = max \|velocity\|) |

Dependencies: `std` and `robodr-events` only. Read-only: nothing is encoded or
sent.

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
