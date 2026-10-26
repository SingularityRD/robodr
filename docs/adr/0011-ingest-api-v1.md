# ADR-0011: The `robodr.ingest` HTTP API, contract v1

| | |
|---|---|
| Status | Accepted in implementation; ratification pending. The contract text calls itself "draft v1". |
| Date | 2026-10-26: contract `cf2f857`; decisions `c7d5025`; independent review `8f22bac` |
| Implements | [ADR-0001](0001-findings-transport-native-ingest.md) (D1) |
| Contract | [`docs/contracts/robodr.ingest-api.md`](../contracts/robodr.ingest-api.md). That file is normative. This ADR records the reasoning behind its main choices. |

## Context

[ADR-0001](0001-findings-transport-native-ingest.md) makes a native HTTPS
API the primary findings path. The producer (`robodr-uplink`, this
repository) and the consumer (`robot_edr` in AutoSecOps1) are built by
different teams, in different languages, at different times. They need one
precise text, plus test vectors both sides run.

## Decision

Main choices of contract v1:

1. **Batch, not per-finding, requests.** NDJSON with up to 1000 lines or
   4 MiB per batch. Each line is `{"value": <finding as a JSON string,
   verbatim>, "sig": null | {...}}`. The finding bytes are never
   re-serialised, so per-finding signatures still verify.
2. **The batch is authenticated by an Ed25519 signature** over a
   length-framed message with its own domain string
   (`"robodr-ingest/batch/v1"`). The message covers key id, batch id,
   timestamp and SHA-256 of the raw body. Verification is strict
   (RFC 8032), and the server verifies before it parses the body. The
   allowed clock skew is ±300 s.
3. **Senders are keys with roles**, registered per workspace:
   - `uplink`: bound to one robot;
   - `relay`: workspace-wide, or scoped to one site; may be marked
     `vouches_origin` (only the SOC-side diode importer, which has
     already verified the diode batch);
   - `finding`: verifies per-finding signatures and never authenticates
     a batch.

   Keys overlap during rotation. A revoked key authenticates nothing.
4. **Idempotency is in the protocol.**
   - The server stores `(key, batch id)` for 7 days, and a retry with the
     same body gets the stored response.
   - A known batch id with a different body is `409`.
   - The producer derives batch ids from input positions and the body, so
     a crash-restart re-sends the same batch under the same id.
5. **Line-level outcomes.** One bad line never fails the batch. Every
   line is accounted for exactly once in a `200`. The producer
   acknowledges records only from such a `200`, and dead-letters the
   rejected lines with the server's code.
6. **Deduplication** on `(workspace, external_id)`, with event identity
   `ocsf.metadata.uid`. Severity only rises. Out-of-order events never
   move `last_seen` backwards.
7. **Taint survives ingest.** Adversary-controlled fields are stored as
   data, rendered delimited, and labelled untrusted wherever they reach an
   LLM prompt.
8. **TLS is mandatory** off loopback. The producer has no
   verification-bypass option; it trusts only the operator's CA bundle,
   plus optional SPKI pins.
9. **Versioning.** The path carries the API major (`v2`), aligned with the
   findings contract major. New response fields and new codes are minor.
   A new line key or header is major. Test vectors are only ever added.

## Consequences

- Both sides test against the same 26 generated cases in
  [`docs/contracts/fixtures/ingest/`](../contracts/fixtures/ingest/). The
  RoboDR suite fails if the committed vectors drift from the generator.
- A sender whose key is not registered is blocked rather than dropped.
  The batch stays queued, delivery is in order, and a status file and the
  service status show the blockage. Operators need the "blocked queue"
  procedure in [`docs/OPERATIONS.md`](../OPERATIONS.md) section 8.5.
- Every `401` writes a server audit-log entry. That is why the producer
  retries such refusals on a long backoff (cap 15 min).
- Rate limit: 120 batches per minute per key (burst 30). At 1000 lines a
  batch, that is well above the Gate 1 target of 10k findings per hour.
  The target is not measured.

## Implementation and evidence

- Producer: [`crates/robodr-export/src/uplink/`](../../crates/robodr-export/src/uplink/)
  (`fa3f3dc`, review fixes `30e8a7d`, `4f4dfbf`, `b5a9c7c`, `a7cd9e9`).
- Reference consumer, test only: `crates/robodr-export/tests/common/ingest.rs`.
  Vector test: [`crates/robodr-export/tests/ingest_vectors.rs`](../../crates/robodr-export/tests/ingest_vectors.rs).
- The vectors' signatures were also checked independently with Python
  `cryptography` (contract §2.2).

## Open items

- No consumer exists yet (AutoSecOps1, Sprint 3). The contract stays
  "draft v1" until both sides pass the vectors. The product owner should
  then mark it final.
- The contract's header names the consumer module
  `autosecops/robot_edr/`, while GA-ROADMAP Sprint 3 says
  `tracecat/robot_edr/`. Align the two.
