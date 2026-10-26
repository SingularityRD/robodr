# Safety positioning

> **Status: position statement, 2026-10-26.** It describes RoboDR's
> intended relation to functional safety. It is not a safety case and not
> legal advice. The standards named here are context. RoboDR has not been
> assessed against any of them.

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
- Nothing in the robot's motion stack or safety system may depend on a
  RoboDR service being up ([`docs/OPERATIONS.md`](../OPERATIONS.md),
  "Scope"; [`SECURITY.md`](../../SECURITY.md), "Scope").

## 2. Design rules that keep it that way

| Rule | Where it is enforced |
|---|---|
| RoboDR never overrides the safety system, the e-stop or command authority. The strongest action is a *request* for a safe state, which the platform's safety controller decides on. | [`crates/robodr-responder/README.md`](../../crates/robodr-responder/README.md), invariant 1; [`docs/contracts/robodr.control-plane.md`](../contracts/robodr.control-plane.md) §4 |
| While the e-stop or a safe state is active, RoboDR sends nothing that competes with it (`record` only; control-plane `safety_system_engaged`). | Responder invariant 2; control plane §4.1 |
| No action vocabulary for actuation, motor or power cut, IEC 60204-1 stop category 0, e-stop reset, or "kill process mid-motion". | Responder invariant 1 |
| No robot action is autonomous from the SOC. The strongest actions need two people. | [ADR-0006](../adr/0006-approval-never-autonomous.md) |
| An unknown safety state, a human in command, or a transient phase means motion-affecting steps need human approval. | Responder invariant 3 |
| Nothing acts until the profile is locked and the response policy is **OEM-validated** (`oem_validated`). Until then, everything is recorded only. | Responder invariant 4 |
| Agentd is sized and confined so that it is OOM-killed before the motion stack, and its loss is visible. | [`packaging/systemd/robodr-agentd.service`](../../packaging/systemd/robodr-agentd.service) |
| **Today nothing is executed at all.** The Motion Firewall records only, has no in-path gateway, and agentd's only executor records. | [`README.md`](../../README.md) "Status" |

## 3. Relation to robot safety standards

| Standard | Relation |
|---|---|
| **ISO 10218-1 / -2** (industrial robots and robot systems) | The integrator's risk assessment and the robot's safety functions stay governed by ISO 10218. RoboDR adds no safety function. If a future in-path Motion Firewall gateway (GA-ROADMAP S8) is placed between a controller and the drives, the integrator must treat it as part of the control system. Its failure behaviour ("stop" or "pass-through") must then be part of their risk assessment, and the OEM must validate it. Recent editions of ISO 10218 also expect cybersecurity to be considered; RoboDR can be one measure for that, not a substitute for the safety design. |
| **IEC 61508 / IEC 62061 / ISO 13849-1** (functional safety, SIL/PL) | Not claimed. RoboDR is not developed under these lifecycles. Where its outputs reach a safety-related system, they must be treated as **non-safety inputs**: requests that the safety system may refuse. |
| **IEC 60204-1** (stop categories) | RoboDR never issues category 0 or 1 stops. The responder's platform-specific "safe behaviours" (for example `protective_stop_category2` for arms) are *requests* to the platform. |
| **ISO 3691-4** (driverless industrial trucks / AMRs), **ISO 13482** (personal care robots), **ISO/TS 15066** (collaborative operation) | Same position: platform safety functions remain the platform's. RoboDR's `restrict_motion` caps (when executed, after GA-ROADMAP S8) can only lower speeds within the commissioned envelope, never raise them, and never act as a safety-rated speed limit. |
| **IEC 62443** and the safety/security interplay (for example IEC TR 63069) | RoboDR's security functions are designed not to degrade safety: they only request, they defer to the safety system, and they fail toward "record only". See [`iec-62443-4-2-gap-analysis.md`](iec-62443-4-2-gap-analysis.md). |

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
  the OEM lists them as balance-safe) **always needs a human**, and never
  goes below a minimum motion factor.
- On a humanoid joint channel, the Motion Firewall never emits a
  zero-torque, damping or limp frame. On a fault it holds the last good
  frame.
- An **unspecified morphology is treated as a humanoid**.

These rules **reduce** the hazards that RoboDR itself could create. They
do **not** make a balancing robot safe against a cyber attack. If an
attacker commands motion through a channel RoboDR only observes, RoboDR
can detect it, record it and request containment. Stopping the robot
safely remains the platform's function. Automatic safe posture on a
humanoid is out of GA scope.

## 5. What integrators must do

1. Keep RoboDR outside the safety-related parts of the control system. Do
   not wire its outputs into safety PLC logic as a safety input.
2. Include RoboDR's possible actions (when execution exists) in the
   machine risk assessment as non-safety, potentially failing functions.
3. Validate the response policy with the OEM's safety data before setting
   `oem_validated: true`, including `morphology`, `min_motion_factor` and
   `fall_safe_restrict`.
4. Run the first field period observe-only.
5. Do field tests of any executing action in an environment with an
   e-stop, as GA-ROADMAP §5 requires.
