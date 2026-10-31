# Safety positioning

> **Status: position statement. Verified at commit `8b2b172`
> (2026-10-30)**, after executor v1, its motion adapters (Sprint 8) and
> the in-path gateway's ROS 2 channels were merged. It describes RoboDR's intended
> relation to functional safety. It is not a safety case and not legal
> advice. The standards named here are context. RoboDR has not been
> assessed against any of them, and **neither component that acts has run
> on a real robot**.

## 1. RoboDR is not a safety-rated component

RoboDR is a **cybersecurity** component. It is not a safety function,
not a safety-related part of a control system, and not developed to a
safety integrity level (SIL) or performance level (PL). In particular:

- It has **no** SIL under IEC 61508 or IEC 62061, and **no** PL under
  ISO 13849-1.
- It must **not** be used to implement, replace or reduce the
  requirements on any safety function: e-stop, protective stop, speed and
  separation monitoring, power and force limiting, safe torque off, fall
  protection, or geofencing for safety.
- In its passive modes nothing in the robot's motion stack or safety
  system may depend on a RoboDR service being up
  ([`docs/OPERATIONS.md`](../OPERATIONS.md), "Scope";
  [`SECURITY.md`](../../SECURITY.md), "Scope"). The opt-in inline gateway
  is the one exception, and section 2a states what that means.

## 2. Design rules that keep it that way

| Rule | Where it is enforced |
|---|---|
| RoboDR never overrides the safety system, the e-stop or command authority. The strongest action is a *request* for a safe state, which the platform's safety controller decides on. | [`crates/robodr-responder/README.md`](../../crates/robodr-responder/README.md), invariant 1; [`docs/contracts/robodr.control-plane.md`](../contracts/robodr.control-plane.md) §4 |
| While the e-stop or a safe state is active, RoboDR sends nothing that competes with it (`record` only; control-plane `safety_system_engaged`; the executor refuses with `safety_system_engaged`). | Responder invariant 2; control plane §4.1, §6a |
| No action vocabulary for actuation, motor or power cut, IEC 60204-1 stop category 0, e-stop reset, or "kill process mid-motion". | Responder invariant 1 |
| No robot action is autonomous from the SOC. The strongest actions need two people. | [ADR-0006](../adr/0006-approval-never-autonomous.md) |
| An unknown safety state, a human in command, or a transient phase means motion-affecting steps need human approval. The executor refuses an `unknown` state outright. | Responder invariant 3; executor review L6 (`31d1aa4`) |
| Nothing acts until the profile is locked and the response policy is **OEM-validated** (`oem_validated`). Until then, everything is recorded only. | Responder invariant 4 |
| Agentd is sized and confined so that it is OOM-killed before the motion stack, and its loss is visible. | [`packaging/systemd/robodr-agentd.service`](../../packaging/systemd/robodr-agentd.service) |
| **Both acting components are opt-in.** Executor v1 runs only with `executor.enabled: true` (off by default); its motion adapters run only with a `motion` section in `executor.json` **and** `oem_validated: true` on each adapter; the gateway runs only where a sensor box is bridged into the controller cable, and should start in `mode: observe`. | [`crates/robodr-executor/README.md`](../../crates/robodr-executor/README.md) "Motion adapters"; [`docs/OPERATIONS.md`](../OPERATIONS.md) 6.5, 6.6 |

## 2a. The components that act, and their limits

Since executor v1 (`0499a47`, review fixes `31d1aa4`), its motion
adapters (`f557b2f`, review fixes `ec98227`, `e0ae2d8`) and the in-path
gateway (`a4e0b4b`, review fixes `e85471c`), RoboDR can change what
reaches the robot, and, through the motion adapters, ask the platform to
pause or restrict it. All of them are cybersecurity controls with a
stated safety argument, not safety functions.

### Executor v1 (`robodr-executor`)

**What it does:**

- always (when enabled): reversible network containment in one nftables
  table, `inet robodr`: `isolate_network`, `quarantine_node` (RTPS by
  GUID prefix, UDP by SPDP locator), and the `record_evidence` mark;
- only with a `motion` section and an adapter the site marked
  `oem_validated` (Sprint 8): `restrict_motion` through the gateway's
  restriction file or Unitree sport `SpeedLevel`; `safe_pause` through
  Nav2 (cancel goals, zero twists), ros2_control (switch to a hold
  controller) or PX4 (AUTO.LOITER); `request_safe_state` through the
  same adapters (hold, or return to launch when the policy says so);
  `rollback_config` (`config: program`) through the site's own validated
  rollback program. Every one of these asks the **platform's own**
  interface; none drives an actuator, cuts power or touches the e-stop.
  `safe_pause`, `request_safe_state` and `rollback_config` need two
  approvers named in the SOC-signed request (neither the requester), and
  are refused on a robot whose morphology forbids them (`fall_hazard`).

**Safety argument** ([`crates/robodr-executor/README.md`](../../crates/robodr-executor/README.md),
"Safety argument"):

- it has no code path to actuators, the e-stop or power; without a
  `motion` section `safe_pause`, `request_safe_state` and
  `rollback_config` are refused and `restrict_motion` is recorded only;
  with one, the motion actions go only through the platform's own
  pause, hold, mode and speed-level interfaces named above;
- a `safe_pause` is never lifted automatically (not at its TTL, a
  restart or an emergency disable): only by the SOC's two-person signed
  revert, with the safety state re-checked, because lifting it may set
  the robot moving;
- its network actions can only remove traffic, never open anything
  another table drops;
- the protected motion control path, management, control buses and DDS
  discovery stay open, and their accepts precede every drop;
- it decides twice: agentd judges the request, then the executor checks
  its own policy and configuration and the safety state milliseconds
  before applying;
- every action has a TTL that survives restarts and that a clock step
  back cannot extend;
- every error leaves the robot without the rule set, never with half of
  it; an operator's `nft delete table inet robodr` disables it at once.

**Limits:**

- Network isolation of a robot is still a disturbance: on a robot whose
  balance or motion loop crosses the network, cutting the wrong flow can
  make the motor controllers time out. That is why the motion path must be
  listed correctly, and why on humanoids nothing outside the OEM's
  `fall_safe_restrict` list is executed, and nothing without a human
  ([ADR-0012](../adr/0012-balancing-robot-response-rules.md)).
- The executor verifies the SOC-signed request itself (its own SOC keys
  and replay store), so a compromised agentd cannot assert a human
  approval (executor review M1, 4-2 GAP-23 closed in code). It cannot
  verify that the named approvers really approved: the two-person rule
  is as strong as the SOC's own approval workflow (4-2 GAP-07).
- A failed or stuck revert is a High finding
  (`robot.agent.executor_revert_failed`); a journal reset is
  `robot.agent.executor_journal_reset`.
- What a platform does on a pause, hold or mode change is the OEM's
  behaviour; the adapters were exercised against test peers and, in the
  red team of 2026-10-30, up to the adapter only (no Nav2, ros2_control,
  PX4 or Unitree sport peer answered). `restrict_motion` through the
  gateway was exercised end to end.
- `SpeedLevel` is a firmware speed range, not a cap: without the gateway
  in the path anyone on the bus can set another level.
- Not run on a robot or under a real systemd; network actions tested with
  real nftables in network namespaces only.

### Inline gateway (`robodr-firewall-gw`)

**What it does:** on a sensor box bridged into the controller cable, it
decides every motion-channel sample from the controller side (Unitree
`rt/lowcmd`, sport `Move`, loco requests, arm SDK, hands, Go1 legacy and
compressed UDP; ROS 2 `cmd_vel` twists and `JointTrajectory` /
`FollowJointTrajectory` goals) and passes it unchanged, limits it in
place, replaces it with a hold, or removes it. It also enforces the
executor's `restrict_motion` restriction file.

**Safety argument** ([`crates/robodr-firewall-gw/README.md`](../../crates/robodr-firewall-gw/README.md),
"What hold means on the wire", "When the gateway itself fails"):

- it never originates a datagram or a sequence number, so it cannot
  create a command the controller did not send;
- on a humanoid joint channel every forwarded frame is an accepted
  (passed or limited) frame or a hold of the last accepted one, never a
  damping or limp frame;
- a sample with nothing safe to emit is removed as if lost in transit;
  persistent silence is covered by the robot's own command timeout, as
  for a controller failure;
- when the gateway process is down the kernel drops the queued commands
  (`fail_closed`, default); `bypass` is refused for a humanoid joint
  channel;
- sequence-number state is bound to the authorised writer's source IP and
  MAC, so a spoofed far-future sequence number no longer suppresses the
  real stream (review F1, `e85471c`).

**Limits:**

- **In inline mode RoboDR is in the motion path.** Its availability and
  latency become part of the control system, and the integrator's risk
  assessment must include it. What the robot does after its own command
  timeout (for Unitree, the motor board's behaviour on a lost
  `rt/lowcmd` stream) is the OEM's safety case and has not been confirmed.
- It protects only what crosses the bridge, and only DDS traffic inside
  the queued port range. All SPDP / SEDP between controller-side
  participants and the robot must cross the bridge; a non-default DDS port
  configuration bypasses the queue; an attacker with the controller's own
  IP and MAC on the controller segment cannot be told apart.
- Unitree's `rt/lowcmd` QoS (best-effort or reliable) is not confirmed;
  both are handled, the reliable path by analysis only.
- Latency was measured on a shared development VM only (median added
  ≈ 20–70 µs); the p99 < 1 ms acceptance gate must be measured on the
  target sensor box.
- Under CPU pressure a late sample gets the fault verdict (1,364 in a 2 h
  soak on a shared VM, [`tools/e2e/RESULTS.md`](../../tools/e2e/RESULTS.md)
  O1). It is reported as `robot.gateway.overload` (Medium, High from
  `overload_high_late`), at most once per `overload_interval_ms`; a fault
  the firewall raises itself stays a Critical
  `robot.firewall.internal_fault`.
- The channel configuration (limits, allowed sources) is a plain file,
  not signed or anti-rollback protected like the profile.
- Not run on a real robot, a real Cyclone DDS stack or a real sensor box.

## 3. Relation to robot safety standards

| Standard | Relation |
|---|---|
| **ISO 10218-1 / -2** (industrial robots and robot systems) | The integrator's risk assessment and the robot's safety functions stay governed by ISO 10218. RoboDR adds no safety function. When the inline gateway is placed between a controller and the robot, the integrator must treat it as part of the control system: its failure behaviour (`fail_closed` or `bypass`) and its latency must be part of their risk assessment, and the OEM must validate it. Recent editions of ISO 10218 also expect cybersecurity to be considered; RoboDR can be one measure for that, not a substitute for the safety design. |
| **IEC 61508 / IEC 62061 / ISO 13849-1** (functional safety, SIL/PL) | Not claimed. RoboDR is not developed under these lifecycles. Where its outputs reach a safety-related system, they must be treated as **non-safety inputs**: requests that the safety system may refuse. The gateway's limits are not safety-rated limits. |
| **IEC 60204-1** (stop categories) | RoboDR never issues category 0 or 1 stops. The responder's platform-specific "safe behaviours" (for example `protective_stop_category2` for arms) are *requests* to the platform. The executor carries one out only through an OEM-validated adapter (for example a ros2_control switch to a hold controller for a category 2 stop) with two approvers; the stop itself is the platform's. |
| **ISO 3691-4** (driverless industrial trucks / AMRs), **ISO 13482** (personal care robots), **ISO/TS 15066** (collaborative operation) | Same position: platform safety functions remain the platform's. The gateway's speed and joint limits can only lower commands within the commissioned envelope, never raise them, and are never a safety-rated speed limit. `restrict_motion` from the SOC is executed only through the gateway's restriction (which lowers limits further, never below the floor for a balancing robot) or a Unitree speed level, under an OEM-validated adapter; neither is a safety-rated speed limit. |
| **IEC 62443** and the safety/security interplay (for example IEC TR 63069) | RoboDR's security functions are designed not to degrade safety: they only request or reduce, they defer to the safety system, and they fail toward "record only" (executor) or toward the robot's own command timeout (gateway). See [`iec-62443-4-2-gap-analysis.md`](iec-62443-4-2-gap-analysis.md). |

## 4. Humanoid and balancing robots

There is no established safety standard yet for actively balancing
(legged or humanoid) industrial robots that matches ISO 10218 for arms.
Standardisation work is in progress. RoboDR therefore takes the most
conservative position it can enforce in code
([ADR-0012](../adr/0012-balancing-robot-response-rules.md)):

- **No de-energising action is ever executable on a humanoid.**
  `safe_pause` and `request_safe_state` are advisory only, because a
  humanoid that is damped or loses power falls.
- **No process termination and no controller restart on any balancing
  robot** (humanoid or quadruped). A process quarantine always needs
  approval.
- **Substitute containment** (motion limits, and network measures only if
  the OEM lists them as balance-safe in `fall_safe_restrict`) **always
  needs a human**, and never goes below a minimum motion factor. The
  executor applies the same rule with its own copy of the policy; with an
  empty list (the shipped Unitree G1 example) it executes neither network
  action on a humanoid (`fall_hazard`).
- On a humanoid joint channel, the Motion Firewall and the gateway never
  emit a zero-torque, damping or limp frame. On a fault they hold the last
  good frame; past `max_hold_ns` the hold escalates (Critical finding,
  feed-forward torque zeroed) but is never released into a limp frame.
- The gateway refuses `bypass` for a humanoid joint channel.
- An **unspecified morphology is treated as a humanoid**.

These rules **reduce** the hazards that RoboDR itself could create. They
do **not** make a balancing robot safe against a cyber attack. If an
attacker commands motion through a channel RoboDR only observes, or one
that does not cross the gateway, RoboDR can detect it, record it and
request containment. Stopping the robot safely remains the platform's
function. Automatic safe posture on a humanoid is out of GA scope.

## 5. What integrators must do

1. Keep RoboDR outside the safety-related parts of the control system. Do
   not wire its outputs into safety PLC logic as a safety input.
2. Include RoboDR's possible actions in the machine risk assessment as
   non-safety, potentially failing functions: the executor's network
   isolation and quarantine, and, in inline mode, the gateway as part of
   the command path (its latency, `fail_closed` behaviour and the robot's
   own command timeout).
3. Validate the response policy with the OEM's safety data before setting
   `oem_validated: true`, including `morphology`, `min_motion_factor` and
   `fall_safe_restrict`, and list the robot's motion control path in the
   executor configuration.
4. For the inline gateway: make sure every SPDP / SEDP path between the
   controller side and the robot crosses the bridge, the DDS ports in use
   are inside the queued range, and the controller-side segment carries
   only the controller; confirm with the OEM what the robot does on a lost
   command stream.
5. Run the first field period observe-only (executor disabled, gateway in
   `mode: observe`).
6. Do field tests of any executing action in an environment with an
   e-stop, as GA-ROADMAP §5 requires.
