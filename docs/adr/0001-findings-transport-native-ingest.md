# ADR-0001: Findings reach the SOC through a native HTTPS ingest API; Kafka is optional

| | |
|---|---|
| Status | Accepted in implementation; ratification pending. Producer `robodr-uplink` (`fa3f3dc`); the AutoSecOps consumer exists on its development branch (AutoSecOps `918363d2`), not released |
| Proposed | 2026-10-25, GA-ROADMAP §2.1 D1 (commit `a5c5afd`) |
| Implemented | 2026-10-26: producer side (`cf2f857`, `fa3f3dc`, `c7d5025`, `8f22bac`, `b5a9c7c`) |
| Related | [ADR-0002](0002-mvp-bridge-webhook-workflow.md) (MVP bridge), [ADR-0003](0003-findings-contract-v2.md) (payload), [ADR-0011](0011-ingest-api-v1.md) (the API contract), [ADR-0007](0007-audited-libraries.md) (Kafka client) |

## Context

RoboDR produces OCSF Detection Findings in the `robodr.findings` contract
([ADR-0003](0003-findings-contract-v2.md)). Before GA it delivered them in
two ways: on a Kafka topic (`robodr-kafka-publish`), or as signed batches
across a data diode (`robodr-diode`). The SOC product, AutoSecOps1, has no
Kafka consumer. Its workflow webhooks accept NDJSON, but they start one
workflow per line. That is slow, and it has no deduplication, no robot key
registry and no signature check. A native module can do all four in one
place: verify signatures, check the robot registry, deduplicate, and upsert
cases.

## Decision

- The primary path from RoboDR to AutoSecOps1 is a **native HTTPS ingest
  API**, `POST {base}/robot-edr/v2/ingest`. It carries signed NDJSON
  batches of `robodr.findings` 2.x values. The contract is
  [ADR-0011](0011-ingest-api-v1.md) and
  [`docs/contracts/robodr.ingest-api.md`](../contracts/robodr.ingest-api.md).
- **Kafka** stays as an **optional, generic SIEM export**
  (`robodr-kafka-publish`). It is not the SOC path.
- Air-gapped sites keep the diode. On the SOC (high) side,
  `robodr-uplink` sends the output of `robodr-diode-unpack` to the same
  API under a `relay` key.

## Consequences

- One producer, `robodr-uplink`, for the connected path and for the SOC
  side of a diode. It is crash-safe and at-least-once, and it derives batch
  ids from the input positions and the body, so the server's replay table
  makes retries idempotent.
- The SOC holds a per-workspace registry of robot keys (`uplink`, `relay`,
  `finding`). Robot onboarding (GA-ROADMAP S9) must populate it.
- The optional Kafka exporter keeps its present limits (no TLS, no SASL,
  idempotence off). They matter only to customers who enable it. Whether
  to fix it in place or move to `rdkafka` is decided under
  [ADR-0007](0007-audited-libraries.md).
- Three spool consumers now exist (`robodr-spool-export`,
  `robodr-kafka-publish`, `robodr-uplink`). Their units conflict, and
  exactly one runs per spool.

## Implementation and evidence

- Contract:
  [`docs/contracts/robodr.ingest-api.md`](../contracts/robodr.ingest-api.md)
  (`cf2f857`; decisions `c7d5025`; review `8f22bac`). Its first section
  cites D1.
- Producer: [`crates/robodr-export/src/uplink/`](../../crates/robodr-export/src/uplink/)
  (`fa3f3dc`; review fixes `30e8a7d`, `4f4dfbf`, `b5a9c7c`, `a7cd9e9`).
- Shared test vectors: [`docs/contracts/fixtures/ingest/`](../contracts/fixtures/ingest/)
  (26 cases), run through a reference consumer in
  [`crates/robodr-export/tests/ingest_vectors.rs`](../../crates/robodr-export/tests/ingest_vectors.rs).
- Unit: [`packaging/systemd/robodr-uplink.service`](../../packaging/systemd/robodr-uplink.service);
  operations: [`docs/OPERATIONS.md`](../OPERATIONS.md) section 8.5.

## Open items

- The consumer, `robot_edr` in AutoSecOps1, is Sprint 3 work in the other
  repository. `robodr-uplink` has not run against AutoSecOps
  ([`crates/robodr-export/README.md`](../../crates/robodr-export/README.md),
  "Limits (honest)").
- Gate 1 acceptance (GA-ROADMAP S3: 10k findings/hour, p95 < 2 s, no loss,
  no duplicate cases) is not measured.
