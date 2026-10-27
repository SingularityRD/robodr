# ADR-0012: Response rules for humanoid and other balancing robots

| | |
|---|---|
| Status | Accepted in implementation; ratification pending. The values must also be validated with each OEM's safety data before any policy is marked `oem_validated`. |
| Date | 2026-10-25: humanoid rule in the catalog (`ed4f1ac`) and the firewall's humanoid no-zero rule (`77bb77f`, hardened `8b93df1`). 2026-10-26: balancing-robot rules after review (`f134cc0`), Unitree live integration (`871d06b`, `fe9acb7`). |
| Related | [ADR-0005](0005-action-catalog.md), [ADR-0006](0006-approval-never-autonomous.md), [`docs/compliance/safety-positioning.md`](../compliance/safety-positioning.md) |

## Context

The usual "stop" responses are a pause, a safe state, a protective stop or
a controller restart. On most platforms these damp the joints, cut motor
power or drop the controller. A humanoid stays upright only while its
joint controllers actively balance it, so these responses make it **fall**:
tens of kilograms from standing height, next to people. A quadruped also
balances while standing, and collapses onto its belly if its controller
stops. RoboDR cannot know how a given platform implements a pause. GA-ROADMAP
§3a adds Unitree G1 (humanoid) and Go2 (quadruped) as design-partner
platforms. On Unitree, the low-level balance loop is a DDS writer of
`rt/lowcmd`.

## Decision

These rules are enforced **in code, whatever the policy says**:

1. **Morphology is required and fails safe.** A response policy declares
   `humanoid`, `quadruped`, `wheeled_mobile`, `arm`, `aerial` or `other`.
   The declaration is required when the policy is OEM-validated or the
   platform is `other`. Where it is omitted, it reads as `unspecified` and
   gets the humanoid treatment. RoboDR never assumes a robot stands on its
   own.
2. **Humanoid (and unspecified): no executable de-energising action.**
   `safe_pause` and `request_safe_state` go only to `advisory`, for the
   operator and the platform's own safety function. The executable plan
   stops at `limit_motion`. The control plane refuses them (`fall_hazard`)
   and does not advertise them.
3. **Substitute containment always waits for a human.** On a humanoid this
   is `limit_motion`, plus only the restrict targets the OEM lists in
   `fall_safe_restrict`. Network isolation and participant quarantine are
   balance-safe only when the balance loop is not networked. On Unitree it
   is networked, so the G1 example lists none. `process` is never allowed
   there.
4. **Active balance (humanoid, quadruped, unspecified).** No process
   termination, even when idle. A process quarantine always needs approval.
   `limit_motion` never goes below `min_motion_factor` (hard floor 0.05).
   `rollback_config` is refused, because it is a controller restart.
5. **Motion Firewall on a humanoid joint channel.** A zero-torque, damping
   or limp frame is never emitted on any path. Rejections hold the last
   accepted frame with `dq = 0`. A hold is never released by timeout; it
   escalates (Critical `joint_hold_exceeded`). Configurations that could
   emit such a frame are refused at compile time.
6. **The executor re-checks** the plan against its *own* configured
   morphology (`check_invariants`), and never trusts a plan's label alone.

## Consequences

- On a humanoid, RoboDR can contain an attack only by approved motion
  limits (and approved network measures, if the OEM marks them
  balance-safe). It cannot "stop" the robot. That is the platform's own
  safety function. Customers must be told this
  ([`docs/customer/known-limitations.md`](../customer/known-limitations.md)).
- Automatic safe posture on a humanoid is out of GA scope (GA-ROADMAP §3a).
- The Unitree example policies are `oem_validated: false`, so every
  response is recorded, not acted on, until a policy is validated.
- Nothing is executed today in any case ([ADR-0005](0005-action-catalog.md)).
  The firewall runs recording-only, with no in-path gateway.

## Implementation and evidence

- Planner and invariants: [`crates/robodr-responder/src/`](../../crates/robodr-responder/src/)
  (`actions.rs`, `planner.rs`, `policy.rs`). Tests in
  [`crates/robodr-responder/tests/fall_prone_review.rs`](../../crates/robodr-responder/tests/fall_prone_review.rs),
  `randomized_invariants.rs` and `plan_matrix.rs`. Description:
  [`crates/robodr-responder/README.md`](../../crates/robodr-responder/README.md),
  "Invariants" and "Morphology".
- Firewall joint rules: [`crates/robodr-firewall/README.md`](../../crates/robodr-firewall/README.md),
  "Low-level joint frames (Unitree `LowCmd`)"; tests in
  [`crates/robodr-firewall/tests/joint_frames.rs`](../../crates/robodr-firewall/tests/joint_frames.rs).
- Control-plane judgment (`fall_hazard`, `morphology_mismatch`):
  [`docs/contracts/robodr.control-plane.md`](../contracts/robodr.control-plane.md) §4.1.
- Examples: [`config/response-policy.unitree-g1.example.json`](../../config/response-policy.unitree-g1.example.json),
  [`config/response-policy.unitree-go2.example.json`](../../config/response-policy.unitree-go2.example.json),
  [`config/firewall.unitree-g1.example.json`](../../config/firewall.unitree-g1.example.json).
- Operator view: [`docs/UNITREE.md`](../UNITREE.md) section 6.

## Open items

- Validate `min_motion_factor` (0.3 in the G1 example, 0.2 in Go2) and
  `fall_safe_restrict` with OEM safety data. The example values are
  illustrative.
- None of this has run on a real Unitree robot (GA-ROADMAP §3a,
  "Remaining").
