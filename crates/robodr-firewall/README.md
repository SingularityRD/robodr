# robodr-firewall — Motion Firewall core

The Motion Firewall is the only RoboDR component in the robot's control path.
Every motion command goes through `Firewall::check(&mut self, cmd, now) -> Verdict`
and comes out as one of three verdicts:

- **Passed**: the original command, unchanged down to the bit.
- **Limited**: the same command with its motion reduced.
- **Rejected**: the command is not forwarded. A safe substitute is emitted in its place, or nothing at all.

The command is checked against the locked model envelope and the set of sources
allowed on its channel.

This crate is only the **pure decision core**. It does no I/O, starts no threads and
has no clock of its own. The in-path gateway for Unitree low-level and sport
channels is `robodr-firewall-gw`; a ROS 2 (`/cmd_vel`, `JointTrajectory`)
gateway is a later step (see "Integration" below).

> **Not a safety-rated component.** This is a cyber-security control. It does not
> implement and does not replace any safety function under ISO 10218, ISO 13849 or
> IEC 61508. The platform's safety PLC and e-stop remain the final authority. The
> firewall can only pass, reduce, refuse, zero or briefly hold commands. It never
> originates motion and never overrides the safety system, which keeps it within
> RoboDR's protective scope.

## Design

```
 Profile (locked)  ─┐
 ChannelSpec map   ─┼─ Policy::compile ─► Policy ─► Firewall::new        (validates, interns, allocates — once)
 PlatformConfig    ─┘
 Command{SourceId, ChannelId, stamp_ns, Motion} ─► check(cmd, now) ─► Verdict   (no alloc, no panic, bounded)
                                                      └─► FirewallEvent → fixed buffer ─► drain_deviations()
```

- **Own command type.** A `Command` holds either a `Twist` (linear and angular
  `Vec3`) or `JointVelocities`, a fixed `[f64; 32]` plus a length. It contains no
  `Vec` and no `String`, and it is `Copy`. Low-level joint frames have their own
  `Copy` type, `JointCommand` / `JointFrame` (up to 35 motor slots inline), and
  their own entry point, `check_joint` (see "Low-level joint frames" below).
- **Interned identity.** Endpoint GUIDs and channel names are turned into
  `SourceId(u16)` and `ChannelId(u16)` when the policy is compiled. The hot path
  only compares integers and tests a 256-bit allow-set per channel. Each allowed
  GUID must belong to a participant in the profile; otherwise compilation fails.
- **Policy compilation fails closed.** Compilation stops with an error in any of
  these cases:
  - a profiled motion channel has no spec, or a spec names a channel the profile doesn't have;
  - a limit is NaN or negative;
  - a hard factor is below 1 or not finite;
  - a channel has no allowed source;
  - a GUID is malformed or not in the profile;
  - a rate limit is zero.

  Limits in the per-channel spec can only **tighten** the envelope. The angular
  limit comes only from the spec, because `Envelope` has no angular field.
- **Events without allocation.** `Deviation` holds a `String`, so `check` never
  builds one. Instead it writes a `Copy` `FirewallEvent` into a fixed-capacity
  buffer. The caller drains the buffer outside the control loop.
  `drain_deviations()` calls `Deviation::new` there, and if any events were lost
  it adds a `robot.firewall.events_dropped` deviation whose severity is at least
  Medium and as high as the worst event lost.
- **Flood-resistant event retention.** A spoofer can cause one event per packet, so
  the buffer (rev3 finding 4):
  - **coalesces** identical events (same rule, channel, source, action) into one
    record with a `count`, first/last time and the worst value;
  - **reserves capacity by source class**: events whose source is not authorised
    on the channel (`authorised == false`) may fill at most half the buffer;
  - when full, **evicts by priority** (severity, then authorised over not), the
    oldest of the lowest first, and only for a strictly higher-priority event.
    A pending Critical from an authorised source is therefore never evicted, and
    never in favour of an unknown-source event.

  All of this is allocation-free and bounded: one scan of the buffer per event,
  so `event_capacity` should stay in the hundreds.

## Decision semantics

The stages run in order and the first rejection wins. All rules are prefixed `robot.firewall.`.

| # | Stage | Condition | Enforcing verdict | Rule (severity) |
|---|---|---|---|---|
| 0 | clock | `now` < previous `now` | Reject | `rejected_clock_regression` (High) |
| 1 | channel | unknown id | Reject, **no substitute** | `rejected_unknown_channel` (High) |
| 2 | source | unknown / `SourceId::UNKNOWN` | Reject | `rejected_unknown_source` (Critical) |
| 2 | source | known, not allowed on channel | Reject | `rejected_unauthorized_source` (Critical) |
| 3 | rate | token bucket per (channel, source) empty | Reject | `rejected_rate_limited` (High) |
| 4 | kind | twist↔joints or wrong joint count | Reject | `rejected_kind_mismatch` (High) |
| 5 | values | NaN / ±inf anywhere | Reject | `rejected_non_finite` (Critical) |
| 6 | time | `stamp > now + max_future` (10 ms) | Reject | `rejected_future_timestamp` (High) |
| 6 | time | `now − stamp > max_age` (200 ms) | Reject | `rejected_stale` (Medium) |
| 6 | time | `stamp ≤` last stamp of (channel, source) | Reject | `rejected_out_of_order` (High) |
| 7 | hard | speed `> hard_factor × limit` (2×) | Reject | `rejected_over_hard_limit` (Critical) |
| 8a | speed | speed `> limit` | Limit: uniform scale | `limited_speed` (High) |
| 8b | accel | `‖Δv‖ > a_max·dt` | Limit: rate-limit | `limited_acceleration` (Medium) |
| 8b | jerk | `‖Δv‖/dt > ‖a_prev‖ + j_max·dt` | Limit: rate-limit | `limited_jerk` (Medium) |
| 9 | post | output non-finite / over limit (a bug) | per `FaultPolicy` | `internal_fault` (Critical) |

How speed is measured:

- **Twist commands:** two groups, linear (Euclidean norm) and angular (Euclidean norm).
- **Joint commands:** one group, the maximum absolute joint speed.

The limiting rules:

- **Speed (8a).** The whole command is multiplied by one factor, `min(limit/‖g‖)`
  over the groups. This keeps the direction. For a twist it also keeps v/ω, so a
  turning UGV keeps its turning radius. All joints scale together, so joint-space
  direction is kept too. A margin of a few ulps makes `‖out‖ ≤ limit` hold exactly
  despite rounding.
- **Acceleration and jerk (8b).** The output is `prev + λ·(target − prev)`, with
  `λ ∈ [0,1]`. Here `prev` is what was last emitted on the channel and `target` is
  the speed-limited command. As a result, the output lies on a segment between two
  in-envelope points: it stays inside the envelope and is never motion nobody asked for.
- **Clock for `dt`.** `dt` is measured on the gateway's clock and capped at
  `dynamics_dt_cap` (100 ms). The source's stamp is never used for this, because an
  attacker controls it. After `state_reset_after` (500 ms) with no output, the
  firewall assumes the platform is at rest.
- **Jerk is simplified.** "Jerk" here limits how fast the acceleration
  *magnitude* may grow. It does not limit changes in the direction of acceleration.
- **Stops are never delayed.** A command that moves every component toward zero
  without crossing it skips 8b, unless `limit_deceleration` is set. A reversal is
  not counted as a deceleration.

Rejection substitutes, set per platform by `FailBehaviour`:

- **`ZeroVelocity`** (default): emit an all-zero command of the channel's kind.
- **`HoldLast { max_hold_ns }`**: re-emit the last **accepted** output while it is
  younger than `max_hold_ns`, then emit zero. The age is measured from when that
  output was accepted, so a run of rejections cannot stretch the hold. The hold is
  only granted if it is a component-wise deceleration of the rejected command
  (own source, readable content), and it is **never more than what was last
  emitted downstream** (rev3 finding 2): the accepted output is scaled down to a
  deceleration of the last emission, so after a zero substitute every further
  hold is zero and the output can only rise again through accepted, acceleration
  limited commands. No hold is granted if the last emission is older than the
  channel's `state_reset_after_ns`, nor under a gateway clock regression (rev3
  finding 3: the hold age cannot be measured then), so zero is emitted.
- **`PassThroughObserveOnly`**: no enforcement on this platform. It behaves exactly
  like observe mode. Limiting is switched off as well, so a 1.5× command is never
  treated more strictly than a 3× one.

A substitute always carries `source = SourceId::FIREWALL` and `stamp = now`.
**A rejected command's values are never forwarded.**

`ForeignSourceAction` controls what happens when the source is unknown or not authorised:

- **`Drop`** (default) emits nothing. The legitimate stream keeps control and the attempt is still recorded.
- **`Substitute`** emits the substitute, at most once per
  `foreign_substitute_min_interval_ns` per channel. This favours the safe state, but
  it means a spoofer can stop the robot (denial of service).

**Observe mode.** Observe mode applies when the profile is not locked, or when the
platform is set to pass-through. Every verdict is then
`Passed { cmd: original, would_have }`, where `would_have` is the limit or reject
that enforcement would have produced. Events are recorded with `EventAction::ObservedOnly`.

**When the firewall itself fails (`FaultPolicy`).** The right default when the
Motion Firewall fails is a safety-case decision that belongs to the OEM, per robot
model, so it is configuration here and we do not decide it silently. For a
humanoid joint channel the configuration refuses any policy that would zero or
damp the motors or forward an unchecked frame, and a fault always holds (see
the low-level joint section).

- **Default: `FailSafe`.** Reject and emit **zero**. The firewall never holds in
  this case, because its state may be bad.
- **`FailOpen`.** Forward the original command and record the fault. This is meant
  for platforms whose safety case says an unexpected stop is the greater hazard.

Inside the library, a fault means the post-condition check failed. The gateway
should call `Firewall::fault_verdict` when it cannot run `check` before its
deadline; `Firewall::late_verdict` (and `joint_late_verdict`) give the same
verdict, substitute and `faults` count without recording an
`internal_fault` event, for a gateway that reports its own overload
(`robodr-firewall-gw` does, as `robot.gateway.overload`). If the gateway **crashes**, the decision is outside this crate and the
platform's own command timeout (for example a `cmd_vel` watchdog) applies. The
gateway must be deployed so that this timeout exists.

Two calls keep the twist state honest when a request is not a velocity:
`Firewall::check_access` checks a request that commands no motion (a
query, an allowlisted non-velocity call) for its source, rate and
timestamps only, leaving the channel's motion state (last output,
acceleration, hold value) as it was; `Firewall::twist_at_rest` records that
the platform stopped on its own (a velocity command whose duration ended),
so the next command is ramped from zero and a hold cannot hold the earlier
velocity. Both were added for the gateway's loco channel (review finding
F10 a / b).

## Low-level joint frames (Unitree `LowCmd`)

**Status: decision core, run live in recording mode.** `check_joint` decides on
decoded frames. `robodr-agentd` feeds it every decoded Unitree low-level command
of a configured joint channel (`firewall.joint_config`, e.g.
`config/firewall.unitree-g1.example.json`): the frame from `robodr-cdr`
(`JointCommandFrame` -> `JointFrame`, every slot, `MotorMode::from_u8`, the
decoder's `crc_ok`, the hg `mode_pr` / `mode_machine`), stamped with the
capture time, through `robodr-agent`'s joint verdict record
(`robodr.firewall_joint_verdict`). The daemon is a passive observer, so the
firewall runs `PassThroughObserveOnly`: verdicts are recorded would-haves,
nothing is forwarded or substituted. The **in-path** use is
`robodr-firewall-gw` (an inline bridge with NFQUEUE that calls
`check_joint` per frame and rewrites the datagram; see "Integration").
Nothing here has been run against a robot; both paths have only seen
synthetic traffic.

Unitree's low-level interface sends one frame per control tick (500 Hz to 1 kHz)
with, for every motor slot, a position target `q`, a velocity target `dq`, a
feed-forward torque `tau`, the gains `kp` / `kd` and an enable `mode`; the motor
driver computes `τ = kp·(q − q_meas) + kd·(dq − dq_meas) + tau`. Layouts covered by
`MAX_MOTORS = 35`:

| Platform | Message | Slots | Actuated |
|---|---|---|---|
| Go1, A1 (legacy) | `unitree_legged_sdk` `LowCmd` | 20 on the wire (or 12 if the decoder passes only the used ones) | 12 |
| Go2, B2 | `go` `LowCmd` | 20 | 12 |
| H1 | `go` `LowCmd` | 20 | 19 |
| G1, H1-2 (and H2-style `hg`) | `hg` `LowCmd` | 35 | up to 29 (G1) |

**API.** `JointCommand { source, channel, stamp_ns, frame: JointFrame }`, where
`JointFrame` holds up to 35 `MotorCmd { mode, q, dq, tau, kp, kd }` inline plus
`crc_ok: Option<bool>` (the decoder's CRC verdict: valid, invalid, not checked)
and the frame-level `mode_pr` / `mode_machine: Option<u8>` of the `hg`
`LowCmd` (`None` for layouts without them). Decode a slot's mode octet with
`MotorMode::from_u8` / `MotorMode::from(u8)`: `0x00` is `Disabled`, **every
other value is `Enabled`** (Unitree uses `0x01` and also `0x0A`, e.g. B2 and
the H1 strong motors; `robodr-cdr` treats any non-zero mode as enabled), so no
mode octet the motor executes can skip the checks.
`Firewall::check_joint(&cmd, now) -> JointVerdict` (`Passed` / `Limited` /
`Rejected { reason, substitute }`, same meaning as `Verdict`), and
`Firewall::joint_fault_verdict` for a deadline miss. Twist and joint-velocity
channels and `check` are unchanged.

**Configuration.** A `JointChannelSpec` per channel, compiled by
`Policy::compile_with_joints(profile, platform, specs, joint_specs)`
(`Policy::compile` is that with no joint channel), or a JSON `FirewallConfig`
(`FirewallConfig::from_json`, unknown fields refused):

- `motors`: one `MotorLimits` per slot (the slot count every frame must carry):
  `enabled`, `q_min`/`q_max`, `dq_max` (tightened by the profile envelope's
  `max_joint_speed`), `tau_max`, `kp_min`/`kp_max`, `kd_min`/`kd_max`. An enabled
  slot has no "unconstrained": every bound is required, finite, `>= 0`, ranges
  ordered. Unused slots stay `enabled: false`. Optional per slot:
  - `max_dq_step` (rad, finite, > 0): bound on `|q − q_prev|` per accepted
    frame, where `q_prev` is the slot's position target in the last accepted
    output. **Required on every enabled slot of a humanoid.**
  - `tau_pd_max` (N·m, finite, > 0): bound on `kp·|q − q_prev|`, the
    proportional torque a new target asks for over the previous one (the
    firewall has no measured joint state, so the previous accepted target
    stands in for `q_meas`; the real tracking torque can be larger).
  - `allow_limp` (default `false`): humanoid only, see below.

  `q_prev` is the target of the last accepted frame in which the slot held
  a position. A frame in which it holds none (`kp = 0` or mode off) keeps
  it: it expires by **time**, `step_reference_ttl_ns` (default 500 ms, at
  most 10 s) after that frame, not by frame (gateway review, finding 5:
  alternating `kp = 0` frames used to clear it, lifting the step bound on
  every other frame). There is no `q_prev` on the first frame, after a
  damping substitute (the motors were released) or once it expired; then
  only the absolute range applies. Like `q` itself, the step bounds act
  only while `kp > 0`.
- `require_crc` (default `true`), `rate { expected_hz, min_interval_ns,
  max_interval_ns }` (**required**; `0 < min ≤ period ≤ max`; `min_interval_ns`
  also bounds how often substitutes are emitted), `max_age_ns` (staleness
  deadline, default 20 ms, in `1..=10 s`), `max_future_ns` (2 ms, at most
  10 s; `MAX_TIME_WINDOW_NS`: a window of seconds is a unit typo and would let
  replayed or pre-dated frames through), `hard_reject_factor` (2.0),
  `damping_kd` (0).
- `pinned_mode_pr` / `pinned_mode_machine` (optional `u8`): every frame must
  carry exactly this `mode_pr` / `mode_machine` (a missing one is rejected
  too). On G1 / H1-2, `mode_pr` switches the ankles between series
  pitch / roll (`0`, PR) and parallel A / B (`1`) control, which changes what
  the envelope's ankle `q` bounds mean; `mode_machine` names the robot
  variant. **The gateway must pass both through from the decoded frame**
  (`JointFrame::mode_pr` / `mode_machine`).
- `PlatformConfig::morphology`: `humanoid`, `quadruped`, `wheeled`, `arm` or
  `other` (default; existing configs keep their behaviour).
- `FaultPolicy::FailHold` (new): on a fault, hold the last accepted joint frame.

Examples: `config/firewall.unitree-g1.example.json` (humanoid, 35 slots, 29
enabled) and `config/firewall.unitree-go2.example.json` (quadruped, 20 slots, 12
enabled). Their joint limits are illustrative values in the shape of the public
URDFs, and the allowed source is a synthetic GUID: take the limits, gains and
writer identity from the OEM data for the exact hardware revision. The G1
example gives every enabled slot non-zero gain minimums (legs and waist
`kp_min` 5–10, `kd_min` 0.2–0.5; arms `kp_min` 5, `kd_min` 0.2; wrists
`kp_min` 2, `kd_min` 0.1) rather than `allow_limp`, the conservative choice:
no single joint can be commanded limp. It pins `mode_pr` to `0` (PR, the mode
its ankle limits are written for) and leaves `mode_machine` unpinned (it
differs per unit; pin it to the value your robot reports). Both examples set
`max_dq_step` (G1 0.15 rad, Go2 0.2 rad per frame) and `tau_pd_max` equal to
`tau_max`; tune `max_dq_step` against the largest per-tick target change your
controller really sends (a 50 Hz policy behind a 500 Hz loop jumps at policy
ticks), or legitimate frames are stepped (within `f × max_dq_step`) or
rejected (beyond).

**Decision table** (`check_joint`; stages in order, first rejection wins; `f` =
`hard_reject_factor`):

| # | Stage | Condition | Verdict | Rule (severity) |
|---|---|---|---|---|
| 0 | clock | `now` < previous `now` | Reject | `rejected_clock_regression` (High) |
| 1 | channel | unknown, or not a joint channel | Reject, **no substitute** | `rejected_unknown_channel` / `rejected_kind_mismatch` |
| 2 | source | unknown / not allowed | Reject (per `ForeignSourceAction`) | `rejected_unknown_source` / `rejected_unauthorized_source` (Critical) |
| 3 | rate | `now −` last accepted `< min_interval_ns` | Reject, **no substitute** | `rejected_rate_limited` (High) |
| 4 | crc | `crc_ok == Some(false)`, or `None` with `require_crc` | Reject | `crc_invalid` (High) |
| 5 | shape | slot count ≠ configured | Reject | `rejected_kind_mismatch` (High) |
| 5 | mode | `mode_pr` / `mode_machine` ≠ its pin (if pinned) | Reject | `joint_mode_pin_mismatch` (Critical) |
| 6 | values | NaN / ±inf in any slot | Reject | `rejected_non_finite` (Critical) |
| 7 | time | future / older than `max_age_ns` / replay | Reject | `rejected_future_timestamp` / `rejected_stale` / `rejected_out_of_order` |
| 8 | slot | mode off (`0x00`) but `kp`, `kd` or `tau` ≠ 0 (any slot) | Reject | `joint_mode_inconsistent` (Critical) |
| 8 | slot | unused slot energised (mode on and `kp`, `kd` or `tau` ≠ 0) | Reject | `disabled_motor_energised` (Critical) |
| 8 | slot | gain < min (motor off = zero gains) | Reject | `joint_gain_below_minimum` (Critical) |
| 8 | slot | gain > `f`·max | Reject | `joint_gain_out_of_envelope` (Critical) |
| 8 | slot | `\|tau\|` > `f`·`tau_max` | Reject | `joint_torque_out_of_envelope` (Critical) |
| 8 | slot | `kd > 0` and `\|dq\|` > `f`·`dq_max` | Reject | `joint_velocity_out_of_envelope` (Critical) |
| 8 | slot | `kp > 0` and `q` outside the range by > `(f−1)·(q_max−q_min)` | Reject | `joint_position_out_of_envelope` (Critical) |
| 8 | slot | `kp > 0`, `q_prev` known, `\|q − q_prev\|` > `f`·`max_dq_step` | Reject | `joint_step_out_of_envelope` (Critical) |
| 8 | slot | `kp > 0`, `q_prev` known, `kp·\|q − q_prev\|` > `f`·`tau_pd_max` | Reject | `joint_pd_torque_out_of_envelope` (Critical) |
| 9 | clamp | gain > max; `\|tau\|`, `\|dq\|` > max; `q` outside range | Limit: clamp that field | `joint_{gain,torque,velocity,position}_out_of_envelope`, action `Limited` (High) |
| 9 | clamp | `\|q − q_prev\|` > `max_dq_step`, or `kp·\|q − q_prev\|` > `tau_pd_max` | Limit: move `q` from `q_prev` toward the (range-projected) target by the allowed amount | `joint_step_out_of_envelope` / `joint_pd_torque_out_of_envelope`, action `Limited` (High) |
| 10 | limp | humanoid, `balance_critical` channel (default): every enabled slot limp (`kp = kd = 0`, or mode off) | Reject | `joint_limp_frame` (Critical) |
| 11 | post | output outside the envelope (a bug) | per `FaultPolicy` (humanoid: always hold) | `internal_fault` (Critical) |
| — | gap | accepted `> max_interval_ns` after the previous accepted frame | (frame decided normally) | `joint_rate_violation` (Medium, recorded only) |
| — | hold | humanoid: hold older than `max_hold_ns` | keep holding, `tau := 0` in the held frame | `joint_hold_exceeded` (Critical, once per hold episode) |

Notes:

- **A target only constrains while its gain acts.** `q` is not checked when
  `kp == 0`, `dq` not when `kd == 0`: the Unitree SDK parks idle slots at
  `PosStopF = 2.146e9` / `VelStopF = 16000` with zero gains, and those frames pass.
- **Clamping never makes a command stronger.** `|dq|`, `|tau|`, `kp`, `kd` are
  only ever lowered (sign kept), `q` is projected onto `[q_min, q_max]` and then,
  if the step bounds require it, moved toward `q_prev` (it always lies between
  the two), and a gain below its minimum is rejected rather than raised.
  Clamps use `min` / `max`, never `f64::clamp` (which panics on inverted or NaN
  bounds; compiled bounds are ordered anyway). Events carry the motor `slot`.
- **Mode off must mean inert.** A slot whose mode octet is `0x00` but which
  carries a non-zero `kp`, `kd` or `tau` is rejected (`joint_mode_inconsistent`)
  on every slot, used or not: what a driver does with such a slot depends on
  firmware, and its values would otherwise leave the firewall unchecked.
- **Too-early frames emit nothing.** The previous frame, sent less than
  `min_interval_ns` ago, is still in force. **Substitutes obey the same
  interval:** no substitute is emitted while the last emitted frame (accepted or
  substitute) on the channel is younger than `min_interval_ns` (nothing is
  emitted; the previous emission is still in force), so a flood of bad frames
  yields at most one substitute per interval. (Under a gateway clock regression
  that age cannot be measured, and the substitute is emitted.) A late frame is
  still decided (refusing it would widen the gap); the gap is recorded.
- **Future stamps cannot lock out on-time frames.** An accepted frame stamped
  up to `max_future_ns` ahead advances the per-source out-of-order watermark
  only to `min(stamp, now)`. Trade-off: a replay of that future-stamped frame
  within the window is not caught as out of order (it is still subject to the
  staleness, rate and step checks).
- **Coalesced events keep the worst value**: the largest, except
  `joint_gain_below_minimum`, which keeps the smallest gain.
- **The gateway must recompute the CRC** of a `Limited` frame and of every
  substitute (they carry `crc_ok: Some(true)` as a marker, not a checksum), must
  pass the decoded `mode_pr` / `mode_machine` through into the `JointFrame` (and
  re-encode the output's values; a substitute carries the held frame's values,
  or the channel's pins for a damping frame), and must carry the remaining
  non-motor fields (flags, reserved words) itself.

**Substitutes, and the humanoid rule.** A zero-torque, damping or limp frame
makes a standing humanoid fall, so on a `humanoid` platform's joint channel
**nothing of the kind is ever emitted, from any path**:

- **Substitutes.** A rejection or a fault holds the last accepted frame with
  every `dq` set to 0 (`HoldLast`), also under a clock regression and whatever
  the fault policy; if no frame was accepted yet, nothing is emitted (the robot
  keeps its own last command / timeout behaviour). `Policy::compile_with_joints`
  refuses `fail_behaviour: zero_velocity`, `fault_policy: fail_safe` and
  `fault_policy: fail_open` (which would forward the raw, unchecked frame on a
  fault) for a humanoid with a joint channel (`ConfigError::UnsafeSubstitute`,
  the message says why and to use `hold_last` / `fail_hold`), and the engine
  applies the rule again regardless of the configuration. Observe mode
  (unlocked profile or `pass_through_observe_only`) never enforces anything and
  is the only path that forwards a frame unchecked.
- **Hold time limit: escalation, not release.** On a humanoid
  `HoldLast { max_hold_ns }` never ends the hold (releasing would mean falling).
  Once the held frame is older than `max_hold_ns` the firewall (a) raises a
  Critical `joint_hold_exceeded` event once per hold episode (value: hold age,
  limit: `max_hold_ns`), and (b) zeroes the held frame's feed-forward `tau`,
  keeping its `kp`, `kd` and `q`. Trade-off: the feed-forward torque was
  computed for a posture and gait phase that are no longer current, and
  replaying it indefinitely pushes the robot somewhere stale; stiffness and
  damping around the last valid target do not depend on that phase. The robot
  may sag slightly without the gravity feed-forward, but it does not go limp.
  What happens next (a controlled stop by the platform's safety controller,
  operator alert) is the responder's decision. `Stats` exposes
  `joint_hold_episodes`, `joint_holds_exceeded` and the gauge
  `joint_hold_age_ns` (age of the most recent hold; 0 once a frame is accepted).
- **No limp frames.** Every enabled slot must have `kp_min > 0` or
  `kd_min > 0`, unless it sets `allow_limp: true` (compile error otherwise,
  naming the slot): a limp leg or waist makes the robot fall, so a compromised
  source must not be able to command one. `allow_limp` is an explicit,
  reviewable opt-out for joints that may genuinely go slack. Independently, a
  frame in which **every** enabled slot is limp (`kp = kd = 0`, or mode off) is
  rejected (`joint_limp_frame`) and the last frame held, on every joint
  channel whose `balance_critical` is `true` (the default). A channel whose
  joints are not in the balance loop (a hand: the SDK releases it with
  `kp = kd = 0`) sets `balance_critical: false`, which lifts only this rule;
  the gateway accepts that flag on its hand codecs only.
- **Bounded steps.** Every enabled slot needs `max_dq_step`.
- A humanoid's twist channel (a request to its own balance controller) keeps
  the normal substitutes.
- `quadruped` / `wheeled` / `arm` / `other`: `ZeroVelocity` emits the **damping
  frame** (every enabled slot `kp = 0, dq = 0, tau = 0, kd = min(damping_kd,
  kd_max)`; unused slots off); `HoldLast { max_hold_ns }` holds the last accepted
  frame (`dq = 0`) while it is younger than `max_hold_ns` (not under a clock
  regression, not for a foreign source), then damps. Faults: `FailSafe` damps,
  `FailHold` holds, `FailOpen` forwards. **Trade-off on a quadruped:** damping
  folds the robot onto its belly (low height, usually recoverable, but it abandons
  stairs or a payload mid-step); holding keeps it standing stiffly in the last
  posture for `max_hold_ns`. An arm sags under damping: prefer `HoldLast`.

**Rule ids** (all prefixed `robot.firewall.`). Joint-frame specific:
`joint_position_out_of_envelope`, `joint_velocity_out_of_envelope`,
`joint_torque_out_of_envelope`, `joint_gain_out_of_envelope` (over the
maximum), `joint_gain_below_minimum`, `joint_step_out_of_envelope`,
`joint_pd_torque_out_of_envelope`, `joint_mode_inconsistent`,
`joint_mode_pin_mismatch`, `joint_limp_frame`, `joint_hold_exceeded`,
`disabled_motor_energised`, `crc_invalid`, `joint_rate_violation`. Reused where
the meaning is the same: `rejected_rate_limited` (too early), `rejected_stale`
(staleness deadline), `rejected_future_timestamp`, `rejected_out_of_order`,
`rejected_non_finite`, `rejected_kind_mismatch` (slot count / wrong entry
point), the source and channel ids, `internal_fault`. Every id is in the
correlation catalog (`robodr-correlate::catalog::NETWORK_AND_AGENT_RULES`) and
the OCSF rule catalog (`robodr-ocsf`).

## Invariants (and where they are verified)

| Invariant | Verified by |
|---|---|
| Emitted output is always finite and within every speed limit (independent naive norm) | `tests/properties.rs` (24 random configs × 20 000 commands, NaN/inf/`f64::MAX`/subnormals/replays/stale/future/foreign sources) |
| `Passed` (enforcing) is bit-exact and has no `would_have` | properties, decision table |
| A rejection never forwards the rejected values: the substitute is zero or exactly the last accepted output | properties |
| A hold never exceeds the last emitted output, so the emitted stream never steps up past the acceleration limit; no hold under clock regression | properties, `tests/rev3_regressions.rs` |
| A foreign-source flood cannot evict an authorised source's Critical event; floods coalesce; drop reports carry the worst lost severity | `tests/rev3_regressions.rs`, `events::tests` |
| Unknown source, non-finite, stale or future commands never pass or get limited | properties, decision table |
| The output stays inside the hull of {previous output, 0, input}, so it is never motion nobody asked for | properties |
| The acceleration bound holds for every accepted step except pure decelerations | properties (a mutation that loosens λ fails the test) |
| Speed scaling is one common factor and keeps direction and curvature | `randomized_scaling_preserves_direction`, `joints_scaled_together` |
| Observe mode always forwards the input bit-exact (including NaN payloads) | `randomized_observe_mode_always_passes_input` |
| Every row of the decision table, the boundaries (`=` vs `+1`) and the stage order | `tests/decision_table.rs` (47 tests) |
| Exact token-bucket, acceleration-ramp and jerk-ramp maths | decision table |
| Fail-safe and fail-open fault handling (via injected faults) | `src/tests.rs` |
| **No heap allocation in `check`, `fault_verdict` or `drain_events`** after construction, across all paths, all fail behaviours, observe mode and a full event buffer | `tests/alloc_free.rs`: a counting `GlobalAlloc` with a thread-local counter, plus a check that the counter does see real allocations |
| No `unwrap`/`expect`/`panic!`/slice indexing/unchecked integer arithmetic in hot-path modules | `#![deny(clippy::{unwrap_used, expect_used, panic, indexing_slicing, arithmetic_side_effects})]` on `engine`, `command`, `events`, `verdict`; confirmed to fire on a deliberate probe |
| Policy compilation rejects every class of malformed config | `config::tests` |
| Joint frames: every decision-table row, each clamp with its rule id and slot, hard rejections, gain minimums, unused-slot energising, CRC, rate window, staleness, observe mode, all three fault policies, the shipped G1 / Go2 configs, JSON strictness, and the unchanged legacy API | `tests/joint_frames.rs` (25 tests) |
| Joint frames: forwarded output always inside the envelope and the step / PD bounds against an independently modelled `q_prev` (independent check); `Passed` bit-exact; `Limited` never raises a magnitude or gain, keeps `q` between its projection and `q_prev`, and is idempotent; a mode-off slot carrying gains is never forwarded; a substitute is the held last accepted frame (`dq = 0`, and `tau = 0` on a humanoid past `max_hold_ns`) or the damping frame, **never damping and never a limp frame on a humanoid** | `tests/joint_properties.rs` (24 random envelopes of 1–35 slots × 4 000 frames, with random step / PD bounds, plus an exhaustive edge grid) |
| Review findings F1–F10 on the joint path (mode octet decoding and mode-off slots, humanoid limp slots and frames, step / PD bounds, substitute flood, humanoid hold escalation, no fail-open on a humanoid, `mode_pr` / `mode_machine` pins, future-stamp watermark, time-window bounds, below-minimum coalescing) | `tests/joint_review_regressions.rs` (17 tests), `src/tests.rs` (humanoid fault holds whatever the fault policy) |
| **No heap allocation in `check_joint` / `joint_fault_verdict`** (35, 20 and 12 slots; humanoid, quadruped, fail-open quadruped, observe; tight and wide step bounds; every path incl. step / PD clamps and rejections, limp and pinned-mode rejections, holds and their suppression inside the emission interval, a humanoid hold past `max_hold_ns`, damping, a full buffer). The test also asserts that each of these rows is actually reached | `tests/alloc_free.rs` (`check_joint_never_allocates`, hard failure) |

Total: 150 tests (100 for twist / joint-velocity channels, 50 for low-level
joint frames). Every loop in `check` runs over at most `MAX_JOINTS` (32)
elements or a constant 4 rounds. There is no recursion and no search over sources.

## Latency and jitter harness

`examples/latency.rs` is a std-only harness (`Instant`, no external crates):

    cargo run --release -p robodr-firewall --example latency -- [N] \
        [--budget-p50-ns X] [--budget-p99-ns X] [--budget-max-ns X] [--budget-jitter-ns X]

Budgets can also come from `ROBODR_FW_BUDGET_{P50,P99,MAX,JITTER}_NS` (flags win).
It times N (default 10⁶) pre-generated commands one by one and prints p50, p99,
p99.9, max, mean, jitter (p99 − p50), the `Instant` overhead and a log2 histogram,
then one `BUDGET:` line per configured budget. **Exit code 1 if any configured
budget is exceeded**, 2 on a usage error, 0 otherwise.

**Gate status: report-only.** Until the harness runs on the target controller (RT
kernel, pinned core, frequency fixed) the numbers below are not a budget, and CI
must not fail on them: run it without budgets (pure report), or with budgets and
treat a non-zero exit as a warning. Once target hardware exists, set the budgets
from the OEM's control-path latency allowance and make the exit code blocking.

The command mix:

- a 1 kHz ±50 µs stream, two thirds of it twists on a channel with accel, jerk and rate limits;
- one third joint commands for a 6-joint arm;
- smooth random-walk targets with rare jumps, plus about 7 % rejections (unknown source, NaN, stale, over-hard);
- `HoldLast` fail behaviour, 1024-entry event buffer drained every 512 commands.

The resulting verdicts: about 3 % passed, 91 % limited and 7 % rejected (the
tight angular/jerk limits make most random-walk steps limited, which exercises
the slowest accept path).

Measured 2026-10-16 in the development sandbox: a 2-vCPU VM on an Intel Xeon @ 2.80 GHz, release profile:

| p50 | p99 | p99.9 | max | jitter (p99 − p50) | Timer overhead (`Instant` pair) |
|---|---|---|---|---|---|
| 180–200 ns | 470–550 ns | 0.8–3.5 µs | 12–20 ms (preemption) | 290–350 ns | 19 ns (p50) |

**Machine caveat.** These numbers come from a shared, non-isolated VM with no RT
kernel, no CPU pinning and no frequency control.

- **The tail is the environment, not the algorithm.** The µs–ms outliers
  (fewer than 0.1 % in typical runs) are preemption, page faults and timer interrupts. `check`
  itself has no data-dependent unbounded work.
- **The numbers are not a latency budget for the robot.** The budget (the design
  doc's target is < 1 ms added in the control path) must be measured on the target
  controller, with the gateway, under load, with the firewall on and off. That is
  the Sprint 7 jitter harness; this example is its library-level half (the
  gateway-in-the-loop measurement is still to do).

### Low-level joint frames: `examples/joint_latency.rs`

    cargo run --release -p robodr-firewall --example joint_latency -- [SECONDS] [--fast] \
        [--budget-p50-ns X] [--budget-p99-ns X] [--budget-max-ns X] [--budget-jitter-ns X]

It drives four scenarios for `SECONDS` each (default 2): a 35-slot humanoid frame
(29 actuated, G1 / H1-2 layout) and a 12-slot quadruped frame (Go1 / A1 layout),
each at 1 kHz and at 500 Hz. By default the frames are **paced in real time** at
the scenario's rate (±2 % period jitter), so each decision sees the caches a real
control loop sees between ticks; `--fast` feeds the same stream back to back. The
mix: smooth sinusoidal trajectories, about 3 % frames with a position target
nudged past `max_dq_step` and a torque past `tau_max` (both limited; the frame
after a stepped one is sometimes stepped too), about 1.5 % rejected (CRC
invalid, NaN, unused slot energised, torque past the hard bound; each rejection
holds the last valid frame). A counting global allocator
reports heap allocations on the timed thread. **Exit code 1 if any allocation
happens in a timed loop** (a hard check, like `tests/alloc_free.rs`) or if a
configured budget (`ROBODR_FW_JOINT_BUDGET_{P50,P99,MAX,JITTER}_NS` or the flags) is
exceeded; 2 on a usage error. The latency budgets follow the report-only policy
above.

`tests/joint_latency.rs` is the test-level gate: it prints p50 / p99 / max for
20 000 frames of each size, is report-only in debug builds (what `cargo test` and CI
run) and, under `cargo test --release`, fails only if p99 reaches 50 µs (about 30x
the slowest p99 measured below), which only a pathological regression (an
allocation, an unbounded loop) can trip.

Measured 2026-10-25 in the development sandbox: a 4-vCPU VM on an Intel Xeon @
2.10 GHz, release profile, 10 s per scenario, two runs each, while other work
ran on the same VM; times include the `Instant` pair (about 30 ns); 0 allocations
in every run. This is the version with the step / PD-torque bounds, the
mode-consistency and limp checks (the mix: about 4.6 % of frames limited, 1.5 %
rejected):

| Scenario | Mode | p50 | p99 | p99.9 | max |
|---|---|---|---|---|---|
| 35 slots @ 1 kHz | paced | 3.2–3.4 µs | 7.2–9.1 µs | 39–74 µs | 0.85–2.2 ms |
| 35 slots @ 500 Hz | paced | 4.1–4.2 µs | 8.8–10.3 µs | 39–43 µs | 0.26–0.27 ms |
| 12 slots @ 1 kHz | paced | 2.4–2.5 µs | 6.0–6.1 µs | 41–42 µs | 0.18–0.40 ms |
| 12 slots @ 500 Hz | paced | 3.1–3.2 µs | 7.6–8.3 µs | 34–44 µs | 85–434 µs |
| 35 slots | back to back | 1.0–1.6 µs | 1.7–2.6 µs | 20–35 µs | 62–523 µs |
| 12 slots | back to back | 0.54–0.66 µs | 0.96–1.17 µs | 7–16 µs | 29–159 µs |

The previous version (without those checks), run in the same session on the
same VM for comparison, measured 35 slots paced @ 1 kHz p50 2.8 µs / p99
5.3–8.4 µs and back to back p50 0.75–0.92 µs: the extra per-slot checks cost
roughly 10–30 % at the median. (An earlier, quieter session measured the
previous version at about half these paced figures; compare numbers from one
session only.)

At 1 kHz the control period is 1 000 µs, so the decision p99 is below 1 % of it on
this machine. The paced numbers are higher than back to back because the caches
and branch predictors go cold between ticks (and the core may clock down while the
loop sleeps); 500 Hz is colder than 1 kHz for the same reason.

**Hardware caveat.** Same as above, and more so: not measured on a robot, a Jetson
or any Unitree controller, not under an RT kernel, not pinned, on a shared VM. The
µs-to-ms tail is scheduling, not the algorithm (`check_joint` is `O(slots)` with no
allocation and no data-dependent loop). The number that matters — added latency on
the robot's own compute, gateway in the loop, under load — is still to be measured.

## Integration

- **Low-level joint gateway (Unitree): done in `robodr-firewall-gw`.** The
  in-path inline-bridge gateway (NFQUEUE) decodes `unitree_go` / `unitree_hg`
  `LowCmd_` strictly, passes the decoded `crc_ok`, `mode_pr` /
  `mode_machine` into the `JointFrame`, resolves the writer to a
  `SourceId`, calls `check_joint` per frame (and `joint_late_verdict` for a
  packet read too late), re-encodes a `Limited` frame or a substitute in
  place with a freshly computed CRC and the remaining non-motor fields, and
  removes the sample when the verdict emits nothing. See
  [`crates/robodr-firewall-gw/README.md`](../robodr-firewall-gw/README.md).
  `robodr-agentd` keeps the recording-mode decode for passive deployments.

- **ROS 2 gateway.** It has to:
  - subscribe on a shadow topic and republish verdict outputs;
  - map RTPS writer GUIDs to `SourceId` once per discovered endpoint, using `SourceId::UNKNOWN` when there is no match;
  - convert header stamps into the same monotonic domain as `now`;
  - call `fault_verdict` on a deadline miss;
  - drain events off the control thread.
- **Platform watchdog.** Make sure a gateway crash leads to the platform's own
  command timeout. This is the fail-safe that sits outside the library.
- **OEM decisions per model.** Choose `FailBehaviour`, `FaultPolicy`,
  `ForeignSourceAction` and the limits per model, and validate them with the OEM.
- **Not verified here.** Behaviour on real hardware, behaviour with a real DDS
  stack, and worst-case latency on the target controller.
