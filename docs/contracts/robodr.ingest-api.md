# `robodr.ingest` HTTP API — contract v1

| | |
| --- | --- |
| Status | **draft v1** (Sprint 2–3, GA-ROADMAP §3); the producer and the consumer are built against this text |
| Producer | `robodr-uplink` (crate `robodr-export`): on a robot / sensor box (connected sites) or on the SOC side behind `robodr-diode-unpack` (air-gapped sites) |
| Consumer | AutoSecOps (`SingularityRD/AutoSecOps1`), module `autosecops/robot_edr/` |
| Payload | `robodr.findings` 2.x values ([`robodr.findings.md`](robodr.findings.md)), carried verbatim |

The ingest API replaces Kafka as the primary path from RoboDR to the SOC
(decision D1). Kafka stays an optional export to third-party SIEMs.

## 1. Endpoint

```
POST {base}/robot-edr/v2/ingest
```

`{base}` is the AutoSecOps API root. Behind the stock Caddy front end this is
`https://<host>/api/robot-edr/v2/ingest`. TLS is mandatory on any network
path; plain HTTP is accepted by the server only from loopback (tests).

The workspace is the one the sender's key is registered in (§3); the request
carries no workspace id.

## 2. Request

### 2.1 Headers

| Header | Value |
| --- | --- |
| `Content-Type` | `application/x-ndjson` (exactly; parameters are refused) |
| `X-RoboDR-Key-Id` | the sender key id, `ed25519:<16 lower-case hex>` (RoboDR key-file format, `robodr_blackbox::sign_ed25519::derive_key_id`) |
| `X-RoboDR-Batch-Id` | 1–64 chars of `[A-Za-z0-9._:-]`, unique per sender; the retry/idempotency key |
| `X-RoboDR-Timestamp` | Unix time of signing, milliseconds, decimal ASCII, no sign, no leading zeros |
| `X-RoboDR-Signature` | the batch signature, 128 lower-case hex (64-byte Ed25519 signature) |

Header names are case-insensitive (HTTP); values are exact.

### 2.2 Batch signature

The sender signs, with its Ed25519 key, this length-framed message:

```text
message = "robodr-ingest/batch/v1" 0x00
          u32be(len(key_id))   key_id     (ASCII, as sent in X-RoboDR-Key-Id)
          u32be(len(batch_id)) batch_id   (ASCII, as sent in X-RoboDR-Batch-Id)
          u64be(timestamp_ms)             (the X-RoboDR-Timestamp value)
          sha256(body)                    (32 bytes, over the raw request body)
```

The server verifies over the raw body bytes it received, before parsing them.
Ed25519 verification is strict (RFC 8032, no malleable signatures,
`verify_strict` semantics).

### 2.3 Body

NDJSON: UTF-8, one JSON object per line, lines separated by a single LF
(`0x0A`); a final LF is optional; empty lines and CR are refused. Each line
is an object with exactly these keys:

```json
{"value":"<a robodr.findings 2.x record value, verbatim, as a JSON string>","sig":null}
{"value":"…","sig":{"alg":"ed25519","key_id":"ed25519:…","sig":"<128 hex>"}}
```

* `value` — the exact bytes the RoboDR producer emitted (what Kafka would
  carry as the record value), JSON-string-encoded. The consumer decodes the
  string and works on those bytes; it never re-serialises them.
* `sig` — `null`, or the per-finding signature object exactly as the
  `robodr-finding-sig` Kafka header defines it ([`robodr.findings.md`]
  §2a, `robodr_ocsf::sig`): signed bytes = the decoded `value` bytes.

### 2.4 Limits

| Limit | Value | Over the limit |
| --- | --- | --- |
| body | 4 MiB | `413`, nothing processed |
| lines per batch | 1000 | `413` |
| decoded `value` | 256 KiB | line rejected (`too_large`) |
| clock skew | ±300 s against the server clock | `401` (`stale_timestamp`) |
| batch rate | 120 batches / minute / sender key (burst 30) | `429` with `Retry-After` |

## 3. Senders and keys

AutoSecOps keeps, per workspace, a registry of robots and of their Ed25519
public keys. A key has a **role**:

| Role | Bound to | May send findings for |
| --- | --- | --- |
| `uplink` | one robot | that robot only (`entity_context.robot.id` must equal it) |
| `relay` | the workspace (e.g. the SOC-side diode importer) | any robot registered in the workspace |
| `finding` | one robot | — (verifies per-finding `sig`, never authenticates a batch) |

A revoked or expired key authenticates nothing from its revocation time on.
Key ids are unique per workspace.

## 4. Processing (consumer)

In this order:

1. Content type and size limits (`415`, `413`).
2. Key lookup by `X-RoboDR-Key-Id`; unknown, revoked or wrong-role key →
   `401` (`unknown_key`). Timestamp skew → `401` (`stale_timestamp`).
   Signature → `401` (`bad_signature`). Every `401` writes an audit-log entry
   (key id, source address, reason); the body is not logged.
3. Replay / retry: a `(sender key, batch id)` seen within the last 7 days
   returns the **stored** response of the first processing with
   `"replayed": true` and changes nothing.
4. Rate limit per sender key → `429`.
5. Each line independently:
   1. parse the line object (`invalid_line`);
   2. decode and validate `value` against `robodr.findings` 2.x
      (`invalid_finding`, `unsupported_contract` for any other major);
   3. robot binding: `uplink` key → the finding's robot must be the key's
      robot (`robot_mismatch`); `relay` key → the robot must be registered in
      the workspace (`unknown_robot`);
   4. per-finding signature: a present `sig` must verify with a `finding`
      key registered for that robot (`bad_finding_signature`); if the robot
      is marked `require_finding_signature`, a missing `sig` is refused
      (`missing_finding_signature`);
   5. dedup and upsert (§5).
6. Lines that fail are reported, never retried by the server; the batch
   still succeeds for the other lines.

## 5. Dedup and cases

* Identity: `(workspace, external_id)`; `external_id` is
  `<robot_id>:<finding_id>` (contract §2), checked by the validator.
* Event identity: `ocsf.metadata.uid`.
* New `external_id` → a new robot finding and a new case (`created`).
* Known `external_id`, new event uid → the finding's `last_seen`,
  `occurrence_count` and payload are updated, severity only ever rises, and
  the case gets an event (`updated`).
* Known `external_id`, known event uid → nothing changes (`duplicate`).
* Severity: OCSF `severity_id` 0–6 / 99 maps one-to-one onto the case
  severity (unknown, informational, low, medium, high, critical, fatal,
  other); priority follows severity.
* Adversary-controlled fields (the finding's `adversary_controlled_fields`
  pointers) are stored as data, rendered delimited, and labelled untrusted
  wherever they reach an LLM prompt; they never become instructions.

## 6. Response

`200` with:

```json
{"batch_id":"…","replayed":false,"accepted":3,"created":1,"updated":1,"duplicates":1,
 "rejected":[{"line":4,"code":"robot_mismatch","detail":"finding names robot r2, key is bound to r1"}]}
```

`line` is 1-based. `accepted` = `created` + `updated` + `duplicates`.
Error responses carry `{"code":"…","detail":"…"}`.

## 7. Producer obligations (`robodr-uplink`)

* At-least-once: a record leaves the local queue only after a `200` naming
  it accepted or rejected; rejected lines go to a dead-letter file with the
  server's code.
* Retries (network error, `5xx`, `429`) resend the **same** batch with the
  same batch id, timestamp re-signed (new timestamp, same body).
* Exponential backoff with jitter; honours `Retry-After`.
* TLS with a configured CA bundle and optional SHA-256 SPKI pin; no
  certificate-verification bypass exists.

## 8. Versioning

The path carries the API major (`v2`, aligned with the findings contract
major it carries). Additive response fields are minor changes; consumers of
the response ignore unknown fields. A new line key or header is a major
change.
