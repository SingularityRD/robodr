# ADR-0002: MVP bridge: webhook + workflow + deduplicate before the native module

| | |
|---|---|
| Status | Proposed |
| Proposed | 2026-10-25, GA-ROADMAP §2.1 D2 (commit `a5c5afd`) |
| Implemented | Not in this repository. The bridge would live in AutoSecOps1 (Sprint 2). |
| Related | [ADR-0001](0001-findings-transport-native-ingest.md), [ADR-0011](0011-ingest-api-v1.md) |

## Context

The native ingest module ([ADR-0001](0001-findings-transport-native-ingest.md))
is Sprint 3 work in AutoSecOps1. A working end-to-end demo was wanted
sooner, so that a robot finding appears as a case in AutoSecOps1 while the
native module is still being built.

## Decision (as proposed)

- In Sprints 2 and 3, AutoSecOps1 accepts RoboDR findings through an
  existing **workflow webhook**, with an API key and an IP allowlist. The
  workflow verifies the per-finding Ed25519 signature (`pynacl`), parses
  the 2.x finding, deduplicates on `external_id` with
  `core.transform.deduplicate` (persisted), and creates or updates a case.
- From Sprint 4 the native module replaces the bridge.

## Consequences

- An early demo needs only registry and workflow work in AutoSecOps1.
- The bridge has no batch signature, no robot key registry and no replay
  table. It is a demo path and must never become a supported customer
  path.
- **Divergence to resolve.** The RoboDR producer went straight to the
  native contract. `robodr-uplink` speaks only `robodr.ingest` v1: signed
  batches with `X-RoboDR-*` headers to `/robot-edr/v2/ingest`. It has no
  webhook mode (no match for "webhook" in
  [`crates/robodr-export/`](../../crates/robodr-export/)). For the bridge
  to receive findings from a real producer, one of the following is
  needed:
  1. the webhook accepts the ingest request format,
  2. a webhook mode is added to `robodr-uplink`, or
  3. the demo feeds the webhook by hand or by script.

## Implementation and evidence

None in this repository. GA-ROADMAP Sprint 2 lists the AutoSecOps1 items:
`templates/tools/robodr/`, `integrations/robodr.py` and the "RoboDR
finding ingest" workflow template.

## Open items

- Product owner: is the webhook bridge still needed now that the native
  contract and its producer exist? If not, this ADR should be marked
  rejected and Sprint 2 updated.
