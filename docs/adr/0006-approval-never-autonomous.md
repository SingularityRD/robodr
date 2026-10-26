# ADR-0006: Robot actions are never autonomous; two-person rule for the strongest

| | |
|---|---|
| Status | Accepted in implementation (robot side); ratification pending. The SOC side is not implemented. |
| Proposed | 2026-10-25, GA-ROADMAP §2.1 D6 (commit `a5c5afd`) |
| Implemented | Robot side, 2026-10-25: catalog approval tiers (`ed4f1ac`). SOC side: AutoSecOps1, Sprint 6. |
| Related | [ADR-0005](0005-action-catalog.md), [ADR-0012](0012-balancing-robot-response-rules.md) |

## Context

A containment action on a robot has physical consequences. An LLM-based
SOC agent can be steered by attacker-controlled strings in findings, such
as ROS node names
([`robodr.findings`](../contracts/robodr.findings.md) §3). The approval
model that AutoSecOps1 has today is weak (GA-ROADMAP §1.2 A4). It is gated
only by a scope, with no approver role and no two-person rule.

## Decision

- **No robot action is ever autonomous.** Every robot action tool in the
  SOC is `requires_approval=True`.
- `safe_pause`, `request_safe_state` and `rollback_config` need **two
  different approvers**, and neither may be the requester. The catalog
  marks them `two-person`. The roadmap text names `safe_pause` and
  `rollback_config`, and the catalog also includes `request_safe_state`.
- The on-robot responder may still *plan* automatically, up to its
  policy's `auto_max_step`. That plan is a request to on-robot enforcement
  points, not a SOC action.

## Consequences

- An LLM agent can propose robot actions but cannot send one. A
  prompt-injection test corpus (`INJECTIONS` in
  [`crates/robodr-ocsf/tests/findings.rs`](../../crates/robodr-ocsf/tests/findings.rs))
  is meant to become an AutoSecOps1 evaluation (GA-ROADMAP S3, S6).
- AutoSecOps1 must add an approver role, the two-person rule, approval
  expiry and an audit trail (Sprint 6).
- The robot cannot verify that approval happened. It verifies only the
  SOC key's signature. Approval is a SOC-side control, and the robot's
  defence is its own safety-state judgment (control plane §4.1).

## Implementation and evidence

- The catalog's `Approval` tier, and the rule that `autonomous` is false
  for every entry and cannot be expressed otherwise:
  [`crates/robodr-responder/src/actions.rs`](../../crates/robodr-responder/src/actions.rs).
- The client requirement "approval first":
  [`docs/contracts/robodr.control-plane.md`](../contracts/robodr.control-plane.md) §9.
- A related but separate control: the two-person rule for **profile
  lock** on the robot (operator attestation, `motion_quorum`),
  [`docs/OPERATIONS.md`](../OPERATIONS.md) section 5.4.

## Open items

- A design choice for the SOC side: should the robot verify approver
  signatures (more than one SOC key over the same request) for two-person
  actions, rather than trust the SOC alone? This would be a control-plane
  v2 change ([ADR-0004](0004-control-plane-v2.md)).
