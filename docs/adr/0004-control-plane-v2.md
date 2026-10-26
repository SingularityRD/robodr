# ADR-0004: Control plane v2: mTLS, signed requests, persistent state, real outcomes

| | |
|---|---|
| Status | Proposed |
| Proposed | 2026-10-25, GA-ROADMAP §2.1 D4 (commit `a5c5afd`); scheduled for Sprint 5 |
| Implemented | Not yet. v1 exists: `6c3287d` (control-plane action API), with the shared action catalog from `ed4f1ac`. |
| Related | [ADR-0005](0005-action-catalog.md), [ADR-0006](0006-approval-never-autonomous.md), [ADR-0007](0007-audited-libraries.md) |

## Context

`robodr-control-plane/v1`
([`docs/contracts/robodr.control-plane.md`](../contracts/robodr.control-plane.md))
lets a SOC request one of the seven catalog actions. v1 does the following:

- It authenticates Ed25519-signed requests, bound to method, target,
  robot id, key id, timestamp, nonce and body hash.
- It judges each request against the live safety state and records it in
  the black box.
- It runs plain HTTP/1.1 with no TLS. Remote SOCs need a TLS terminator
  in front.
- It keeps request states in memory, so a restart forgets them. The black
  box keeps every decision.
- It **executes nothing**. Every accepted request is
  `recorded_not_executed`.
- Its HTTP server is hand-written ([ADR-0007](0007-audited-libraries.md)).

Executing containment at GA (GA-ROADMAP §4) needs a confidential,
mutually authenticated channel and durable request state.

## Decision (as proposed)

- `robodr-control-plane/v2` uses **mTLS (rustls)**: a SOC client
  certificate, plus the Ed25519 request-body signature v1 already has.
- Request state is persistent: a black box plus a sqlite or file journal.
  A status query after an agentd restart must be consistent.
- The outcomes are real: `executed`, `refused`, `reverted`. The statuses
  `pending` and `applied` are already reserved in v1.
- Other Sprint 5 items: a replay window and nonce store that survive a
  restart, mandatory answer signatures, a fuzz target for the HTTP layer,
  and a fix for the bind→chmod race.

## Consequences

- The robot's agent gains its first network-facing TLS listener. It must
  stay off the detection loop's critical path; v1 already bounds the queue
  to the main loop.
- Executing actions makes the executor and its safety re-check
  ([ADR-0005](0005-action-catalog.md)) safety-relevant code. Its scope is
  set by [ADR-0012](0012-balancing-robot-response-rules.md) and
  [`docs/compliance/safety-positioning.md`](../compliance/safety-positioning.md).
- SOC integrations must handle the v2 statuses. v1 clients must not report
  `recorded_not_executed` as success (v1 §9).

## Implementation and evidence

- v1 only: [`crates/robodr-agentd/src/control/`](../../crates/robodr-agentd/src/control/)
  (`http.rs`, `auth.rs`, `api.rs`, `mod.rs`) and the end-to-end test
  [`crates/robodr-agentd/tests/control_plane.rs`](../../crates/robodr-agentd/tests/control_plane.rs).
- The claims and non-claims are in [`SECURITY.md`](../../SECURITY.md),
  "Control-plane action API: what is claimed".

## Open items

- The choice of journal (sqlite or file) and the client-certificate
  provisioning flow (onboarding, GA-ROADMAP S9).
