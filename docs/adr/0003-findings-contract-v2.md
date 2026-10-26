# ADR-0003: Findings contract `robodr.findings/2.x`: vendor-neutral envelope, OCSF 1.1 body

| | |
|---|---|
| Status | Accepted in implementation; ratification pending |
| Proposed | 2026-10-25, GA-ROADMAP §2.1 D3 (commit `a5c5afd`) |
| Implemented | 2026-10-25: 2.0 (`dae7993`). 2026-10-26: 2.1.0 rule catalog per contract minor (`4c455cf`), upgrade path for 1.x findings in flight (`bf93713`). |
| Related | [ADR-0001](0001-findings-transport-native-ingest.md), [ADR-0011](0011-ingest-api-v1.md) |

## Context

Contract 1.x (`robot-edr.findings`) was written for a cancelled integration.
It carried that integration's constants: a fixed `data_source`, a fixed
Kafka topic, and an envelope described as that SOC's ingestion format. A
product sold to customers with different SOCs and SIEMs needs an envelope
that any consumer can read, and a body in a standard schema.

## Decision

- The contract is `robodr.findings/2.x`. It is **2.1.0** today; 2.1 only
  added rule-catalog entries.
- The envelope is vendor-neutral. `data_source` defaults to `"robodr"` and
  is configurable, and so is the topic.
- The body is an **OCSF 1.1.0 Detection Finding** (class 2004,
  `metadata.version` 1.1.0) and is carried unchanged.
- Provenance and taint markings are kept
  ([`robodr.findings`](../contracts/robodr.findings.md) §3, SR-TAINT).
- The envelope field names (`finding_id`, `external_id`, `title`,
  `severity`, `entity_context`, `adversary_controlled_fields`, ...) are
  **kept on purpose**. Only the vendor-specific constant values changed.
  The identity derivation (`rf1-` / `re1-`) is unchanged, so an upgraded
  finding deduplicates with an earlier copy.
- 1.x is **parse-only**. Unsigned 1.x findings still in flight are upgraded
  to 2.0. Signed 1.x findings cannot be upgraded off the robot: they are
  kept for forensics and not delivered.

## Consequences

- Any OCSF-capable SIEM or SOAR can consume the findings. AutoSecOps1 is
  one consumer.
- `data_source` is unauthenticated: it is not bound to any key. Consumers
  deduplicate on `external_id` and authenticate by key, never by label.
- A consumer must accept contract 2.1 to validate the 2.1 rule entries.
- Upgrading a fleet from 1.x needs the drain procedure in
  [`docs/OPERATIONS.md`](../OPERATIONS.md) section 7.

## Implementation and evidence

- Contract: [`docs/contracts/robodr.findings.md`](../contracts/robodr.findings.md),
  schema [`docs/contracts/robodr-finding.schema.json`](../contracts/robodr-finding.schema.json),
  golden example [`docs/contracts/robodr-finding.example.json`](../contracts/robodr-finding.example.json).
  The `robodr-ocsf` tests fail when the builder's output differs from the
  example by a single byte.
- Superseded 1.x texts: [`docs/contracts/legacy/`](../contracts/legacy/).
- Reference implementation: [`crates/robodr-ocsf/`](../../crates/robodr-ocsf/)
  (`builder.rs`, `validate.rs`, `taint.rs`, `upgrade.rs`, `sig.rs`).
- Exporters and the diode carry the contract version and no longer require
  a fixed topic (`dae7993`, `bf93713`).

## Open items

- The JSON Schema `$id` names `schemas.singularityrd.com`. Whether that
  host will serve the schema publicly is a product decision.
- Section 7 of the contract (retention) is still marked "proposal,
  integrator to confirm".
