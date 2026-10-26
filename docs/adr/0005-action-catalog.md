# ADR-0005: One vendor-neutral action catalog, with what GA executes

| | |
|---|---|
| Status | Accepted in implementation; ratification pending |
| Proposed | 2026-10-25, GA-ROADMAP §2.1 D5 (commit `a5c5afd`) |
| Implemented | 2026-10-25: catalog `robodr_responder::actions` (`ed4f1ac`). 2026-10-26: review fixes for morphology and balancing robots (`f134cc0`). Execution is not implemented. |
| Related | [ADR-0004](0004-control-plane-v2.md), [ADR-0006](0006-approval-never-autonomous.md), [ADR-0012](0012-balancing-robot-response-rules.md) |

## Context

Before Sprint 1 there were two contradictory action lists. The responder's
integration module had `record_evidence` and no `rollback_config`; the
control plane had the reverse (GA-ROADMAP §1.1 R9). Neither list said
which actions would actually run at GA.

## Decision

There is one catalog, in `robodr-responder::actions`, and it is
vendor-neutral. The control plane's `ActionKind` re-exports it, and a test
asserts that the parser accepts exactly the catalog. Each entry states its
step, whether it is reversible, its approval tier, whether it runs at GA,
and whether it may de-energise actuators.

| Action | GA plan |
|---|---|
| `restrict_motion` | executed (firewall gateway), time-limited |
| `quarantine_node` | executed (DDS participant ingress/egress drop, nftables) |
| `isolate_network` | executed (nftables, management channel exempt), time-limited |
| `record_evidence` | executed (evidence only; nothing is sent to the platform) |
| `safe_pause` | only through a platform adapter (Nav2, ros2_control, PX4), and only under an OEM-validated policy |
| `request_safe_state` | plan only at GA |
| `rollback_config` | plan only at GA |

Reasoning: the robot's safety system is never bypassed, and irreversible
actions wait until after GA.

## Consequences

- SOC integrations register the actions under their wire names
  (`robot_<name>`, unchanged from the earlier integration) and send the
  plain names to the control plane.
- The GA column is a plan. **Today nothing is executed**: agentd's only
  executor records, and `robodr-agent::executor` has `NoopExecutor` and a
  logging executor ([`crates/robodr-agent/src/executor.rs`](../../crates/robodr-agent/src/executor.rs)).
  The executor is Sprint 7. The firewall gateway and the `safe_pause`
  adapters are Sprint 8.
- Morphology narrows the catalog per robot
  ([ADR-0012](0012-balancing-robot-response-rules.md)). A humanoid never
  gets an executable `safe_pause` or `request_safe_state`.

## Implementation and evidence

- [`crates/robodr-responder/src/actions.rs`](../../crates/robodr-responder/src/actions.rs)
  (catalog table and rules in the module docs).
- [`crates/robodr-responder/README.md`](../../crates/robodr-responder/README.md),
  "Action catalog" and "Invariants".
- Control-plane table: [`docs/contracts/robodr.control-plane.md`](../contracts/robodr.control-plane.md) §4.

## Open items

- The adapter interface (`precheck`, `apply`, `verify`, `revert`, TTL
  auto-revert) and the CAP_NET_ADMIN process split are Sprint 7 design
  work. They need their own ADR when they are designed.
