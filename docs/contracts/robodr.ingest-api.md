# `robodr.ingest` HTTP API — contract v1

| | |
| --- | --- |
| Status | **draft v1** (Sprint 2–3, GA-ROADMAP §3); the producer and the consumer are built against this text; changes in §10 |
| Producer | `robodr-uplink` (crate `robodr-export`): on a robot / sensor box (connected sites) or on the SOC side behind `robodr-diode-unpack` (air-gapped sites) |
| Consumer | AutoSecOps (`SingularityRD/AutoSecOps1`), module `autosecops/robot_edr/` |
| Payload | `robodr.findings` 2.x values ([`robodr.findings.md`](robodr.findings.md)), carried verbatim |
| Test vectors | [`fixtures/ingest/`](fixtures/ingest/) (§9), shared by both sides |

The ingest API replaces Kafka as the primary path from RoboDR to the SOC
(decision D1). Kafka stays an optional export to third-party SIEMs.

## 1. Endpoint

```
POST {base}/robot-edr/v2/ingest
```

`{base}` is the AutoSecOps API root. Behind the stock Caddy front end this is
`https://<host>/api/robot-edr/v2/ingest`. TLS is mandatory on any network
path; plain HTTP is accepted by the server only from loopback (tests, a
local TLS-terminating proxy).

The workspace is the one the sender's key is registered in (§3); the request
carries no workspace id.

## 2. Request

### 2.1 Headers

| Header | Value |
| --- | --- |
| `Content-Type` | the media type `application/x-ndjson`, **without parameters** (type and subtype compare case-insensitively, RFC 9110 §8.3.1; the producer sends exactly `application/x-ndjson`) |
| `X-RoboDR-Key-Id` | the sender key id, `ed25519:<16 lower-case hex>` (RoboDR key-file format, `robodr_blackbox::sign_ed25519::derive_key_id`) |
| `X-RoboDR-Batch-Id` | 1–64 chars of `[A-Za-z0-9._:-]`, unique per sender; the retry/idempotency key |
| `X-RoboDR-Timestamp` | Unix time of signing, milliseconds, decimal ASCII, no sign, no leading zeros (`0` itself is well formed), at most 20 digits and ≤ 2^64−1 |
| `X-RoboDR-Signature` | the batch signature, 128 lower-case hex (64-byte Ed25519 signature) |

Header names are case-insensitive (HTTP); values are exact. Each of the four
`X-RoboDR-*` headers must appear exactly once: a header field repeated (even
with the same value) is repeated. A missing, repeated or malformed
`X-RoboDR-*` header is `400` (`bad_header`, §6.2) — a syntax error, before
any key lookup; a well-formed key id that is not registered is `401`
(`unknown_key`). A timestamp above 2^64−1 (18446744073709551615) is
malformed (`400`); one within the bound but far from the server clock is
`401` (`stale_timestamp`). A missing `Content-Type` is `415` like a wrong
one (§4 step 1.1).

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
`verify_strict` semantics). The vectors (§9) contain signatures to check an
implementation against (they were also verified independently with Python
`cryptography`).

### 2.3 Body

NDJSON, UTF-8. The body is split into **lines** at every LF (`0x0A`); a
final LF is optional (`A\nB\n` and `A\nB` are both two lines; `A\n\nB\n` is
three lines, the second empty). Lines are numbered from 1 in that split.
Each line must be a JSON **object** with exactly these two keys, in any
order:

```json
{"value":"<a robodr.findings 2.x record value, verbatim, as a JSON string>","sig":null}
{"value":"…","sig":{"alg":"ed25519","key_id":"ed25519:…","sig":"<128 hex>"}}
```

* `value` — the exact bytes the RoboDR producer emitted (what Kafka would
  carry as the record value), JSON-string-encoded. The consumer decodes the
  string and works on those bytes; it never re-serialises them.
* `sig` — `null`, or the per-finding signature object exactly as the
  `robodr-finding-sig` Kafka header defines it ([`robodr.findings`]
  §2a, `robodr_ocsf::sig`): exactly `alg` (`ed25519`), `key_id` (1–128
  bytes of ASCII 0x21–0x7E: printable, **no space**; `robodr_ocsf::sig`
  `check_key_id`) and `sig` (128 lower-case hex), each once. The signature
  is over **the framed message of `robodr.findings` §2a** (domain
  `"robodr-ocsf/finding-sig/v1"` 0x00, then length-prefixed `alg`,
  `key_id` and value) built over the decoded `value` bytes — not over the
  raw value bytes alone. The producer sends `null` for findings that
  crossed a diode (the diode does not carry per-finding signatures,
  `robodr.findings` §8; such findings come from a `relay` key).

A line is refused as `invalid_line` (§4 step 5.1) when it is empty,
contains a CR (`0x0D`) anywhere, is not valid UTF-8, is not a JSON object
(an array is not accepted even if a parser could map it onto the two
fields), lacks `value` or `sig`, has any other key, has a key twice, has a
`value` that is not a string, has a `value` whose decoded string is not
valid Unicode (a `\uD800`–`\uDFFF` escape that is not part of a
high-low surrogate pair: the decoded value must be valid UTF-8), or has a
`sig` that is neither `null` nor a well-formed signature object (a key
twice inside `sig` included). Such a line is reported, the other lines are
processed; the batch is never refused because of a line.

### 2.4 Limits

| Limit | Value | Over the limit |
| --- | --- | --- |
| body | 4 MiB (4 194 304 bytes) | `413` (`body_too_large`), nothing processed |
| lines per batch | 1000 (counted as in §2.3) | `413` (`too_many_lines`), nothing processed |
| empty body (0 bytes) | — | `400` (`empty_batch`) |
| decoded `value` | 256 KiB (262 144 bytes) | line rejected (`too_large`), checked before validation. Note: a valid finding is ≤ 64 KiB (`robodr.findings` §6), so a value of 64 KiB + 1 … 256 KiB is `invalid_finding`; the 256 KiB bound only spares the validator large inputs |
| clock skew | \|server time − timestamp\| ≤ 300 000 ms (inclusive) | `401` (`stale_timestamp`) |
| batch rate | 120 batches / minute / sender key (burst 30) | `429` (`rate_limited`) with `Retry-After` |

`Retry-After` is sent as delay-seconds (a non-negative integer, RFC 9110
§10.2.3), never as an HTTP-date.

## 3. Senders and keys

AutoSecOps keeps, per workspace, a registry of robots and of their Ed25519
public keys. A key has a **role**:

| Role | Bound to | May send findings for |
| --- | --- | --- |
| `uplink` | one robot | that robot only (`entity_context.robot.id` must equal it) |
| `relay` | the workspace (e.g. the SOC-side diode importer) | any robot registered in the workspace |
| `finding` | one robot | — (verifies per-finding `sig`, never authenticates a batch) |

A revoked or expired key authenticates nothing from its revocation time on.
Key ids are unique per workspace. A robot may be marked
`require_finding_signature` (§4 step 5.4).

Registry fields (explicit; the vectors' `manifest.json` lists them):

| Entry | Field | Meaning |
| --- | --- | --- |
| robot | `require_finding_signature` | §4 step 5.4 |
| robot | `site` | the site it is registered with (optional) |
| key | `role`, `robot` | as above (`robot` for `uplink` and `finding`) |
| key (`relay`) | `site` | optional site scope, `null` = whole workspace |
| key (`relay`) | `vouches_origin` | `true` / `false` (default `false`) |

* **Site scope (relay).** A `relay` key may carry an optional `site`: it then
  may send findings only for robots registered with that site (a sensor box
  watching several robots of one site gets a site-scoped relay key, not an
  `uplink` key); another robot of the workspace is `site_mismatch` (§4 step
  5.3). Without `site` it covers the whole workspace.
* **Origin-vouching relay.** A `relay` key may be marked `vouches_origin`.
  Only the SOC-side diode importer gets this flag: it has already verified
  the robot's Ed25519-signed diode batch, so findings it relays satisfy
  `require_finding_signature` without a per-finding `sig` (the diode format
  carries none). Any other relay is held to the per-finding rule (§4 step
  5.4). The flag never registers a robot and never excuses a `sig` that is
  present but does not verify.
* **Rotation.** A robot may have more than one active key per role at a
  time (overlap during rotation); each authenticates independently until
  revoked.

## 4. Processing (consumer)

In this order; the first step that fails decides the response:

1. Syntax, before any lookup:
   1. `Content-Type` (§2.1) → `415` (`unsupported_media_type`);
   2. body size, then line count (§2.4) → `413` (`body_too_large`,
      `too_many_lines`);
   3. `X-RoboDR-*` headers (§2.1) → `400` (`bad_header`); empty body →
      `400` (`empty_batch`).
2. Key lookup by `X-RoboDR-Key-Id`; unknown, revoked or wrong-role
   (`finding`) key → `401` (`unknown_key`). Timestamp skew → `401`
   (`stale_timestamp`). Signature → `401` (`bad_signature`). Every `401`
   writes an audit-log entry (key id, source address, reason); the body is
   not logged.
3. Replay / retry: a `(sender key, batch id)` seen within the last 7 days
   returns the **stored** response of the first processing with
   `"replayed": true` and changes nothing — **if the body's SHA-256 equals
   the stored one**. A known batch id with a different body is `409`
   (`batch_id_reuse`) and changes nothing: the stored response numbers the
   lines of the first body, and the producer acknowledges its records by
   those numbers. The stored response is recorded atomically with the
   batch's effects; a batch whose processing failed (`5xx`) is not stored,
   so its retry is processed afresh (§5 makes that safe).
4. Rate limit per sender key → `429` (`rate_limited`).
5. Each line independently, **in line order** (a later line sees the effect
   of an earlier line of the same batch, e.g. line 3 repeating line 1 is a
   `duplicate`):
   1. the line object (§2.3) → `invalid_line`;
   2. the decoded `value`: longer than 256 KiB → `too_large`; a JSON object
      whose `contract_version` is a **well-formed** version with
      `MAJOR` ≠ 2 → `unsupported_contract` (the producer upgrades unsigned
      1.x findings to 2.0 before sending and never sends signed 1.x ones,
      `robodr.findings` §5); otherwise validate against `robodr.findings`
      2.x → `invalid_finding`.
      *Well-formed* (the Rust validator's rule,
      `robodr_ocsf::validate::contract_major`): exactly three parts
      separated by `.`, each 1–9 ASCII decimal digits; leading zeros are
      allowed and `MAJOR` is compared **as a number** (`02.1.0` is major 2,
      `1.03.0` major 1). Anything else (`2.1`, a 10-digit part, a sign, a
      suffix such as `-rc1`, a non-string) is not a version at all: the
      value is validated and fails (`invalid_finding`).
      Only `MAJOR` 2 reaches validation, and validation is the 2.x *emit*
      rule (`robodr_ocsf::validate_for_emit`): a consumer whose validator
      also parses 1.x findings (replay of old diode batches) must still
      refuse anything that is not 2.x here, as `unsupported_contract`;
   3. robot binding: `uplink` key → the finding's robot must be the key's
      robot (`robot_mismatch`); `relay` key → the robot must be registered
      in the workspace (`unknown_robot`), and, for a **site-scoped** relay
      (§3), registered with the key's site (`site_mismatch`; checked after
      `unknown_robot`);
   4. per-finding signature: a present `sig` must verify with a `finding`
      key registered for **that** robot, named by `sig.key_id`
      (`bad_finding_signature`; also when the key id is unknown, revoked or
      bound to another robot) — for every sender, origin-vouching relays
      included; if the robot is marked `require_finding_signature`, a
      missing (`null`) `sig` is refused (`missing_finding_signature`)
      **unless the sender is a `relay` key marked `vouches_origin`** (§3),
      which satisfies the requirement for the findings it relays;
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
* Out-of-order events: `last_seen` only moves forward (`max`), the stored
  payload is the one with the latest `last_seen_time`, `occurrence_count`
  is the largest seen; an older event is still recorded as a case event.
* Severity: OCSF `severity_id` 0–6 / 99 maps one-to-one onto the case
  severity (unknown, informational, low, medium, high, critical, fatal,
  other); priority follows severity.
* Adversary-controlled fields (the finding's `adversary_controlled_fields`
  pointers) are stored as data, rendered delimited, and labelled untrusted
  wherever they reach an LLM prompt; they never become instructions.

## 6. Response

### 6.1 `200`

```json
{"batch_id":"…","replayed":false,"accepted":3,"created":1,"updated":1,"duplicates":1,
 "rejected":[{"line":4,"code":"robot_mismatch","detail":"finding names robot r2, key is bound to r1"}]}
```

`line` is 1-based (§2.3). `accepted` = `created` + `updated` + `duplicates`,
and `accepted` + the number of `rejected` entries = the number of lines;
every line is named at most once. `detail` is free text for humans
(producers must not parse it). Line codes:

| Code | Step |
| --- | --- |
| `invalid_line` | 5.1 |
| `too_large` | 5.2 |
| `unsupported_contract` | 5.2 |
| `invalid_finding` | 5.2 |
| `robot_mismatch` | 5.3 |
| `unknown_robot` | 5.3 |
| `site_mismatch` | 5.3 |
| `bad_finding_signature` | 5.4 |
| `missing_finding_signature` | 5.4 |

### 6.2 Errors

Error responses carry `{"code":"…","detail":"…"}`:

| Status | `code` | Retry by the producer |
| --- | --- | --- |
| `400` | `bad_header`, `empty_batch` | no (a producer bug) |
| `401` | `unknown_key`, `stale_timestamp`, `bad_signature` | not immediately (registration or clock must be fixed); the batch stays queued |
| `409` | `batch_id_reuse` | no (a producer bug) |
| `413` | `body_too_large`, `too_many_lines` | with a smaller batch (a new batch id) |
| `415` | `unsupported_media_type` | no (a producer bug) |
| `429` | `rate_limited` | yes, same batch, after `Retry-After` |
| `5xx` | any | yes, same batch |

New codes may be added (minor change); a producer treats an unknown code by
its status.

## 7. Producer obligations (`robodr-uplink`)

* At-least-once: a record leaves the local queue only after a `200` naming
  it accepted or rejected; rejected lines go to a dead-letter file with the
  server's code. A `200` that does not account for every line exactly once,
  or names another batch id, acknowledges nothing.
* Retries (network error, `408`, `5xx`, `429`) resend the **same** batch
  with the same batch id, timestamp re-signed (new timestamp, same body).
* Exponential backoff with jitter; honours `Retry-After` (never retries
  sooner), also when it came with the last attempt of a run (the next run
  waits for it). **Producer bound:** a `Retry-After` is honoured in full up
  to 24 hours; a larger value (or one too large to parse as a 64-bit
  number) is treated as 24 hours, so an absurd value cannot park a robot's
  uplink indefinitely. No other cap shortens it.
* Refusals that need a fix (`400`, `401`, `409`, `415`, a single-line `413`,
  a `200` that does not account for the batch) are retried on a long
  backoff (default cap 15 minutes), not every minute: each `401` is an
  audit-log entry on the server (§4 step 2). The batch stays queued and
  blocks the later ones (delivery is in order); the producer makes that
  visible (status file, service status) instead of retrying silently.
* Dead-lettered lines can be re-injected by the operator after a fix
  (`robodr-uplink reinject`): they are sent again **under new batch ids**,
  never under the id whose stored response rejected them.
* Batch ids are derived from the input position and the body
  (`rdu1-` + 128 bits of SHA-256 over the input stream name, the input
  positions of the lines and SHA-256(body); `robodr_export::uplink::wire::batch_id`),
  and the batch in flight is persisted before it is sent: after a crash the
  same records are re-sent as the same body under the same batch id, so the
  server answers from §4 step 3 instead of processing them again; a body
  can never be sent under another body's id.
* A `413` is answered with smaller batches (new ids), never by dropping
  records.
* TLS with a configured CA bundle and optional SHA-256 SPKI pin; no
  certificate-verification bypass exists. Plain HTTP only to a loopback IP
  literal.

## 8. Versioning

The path carries the API major (`v2`, aligned with the findings contract
major it carries). Additive response fields and new error/line codes are
minor changes; consumers of the response ignore unknown fields. A new line
key or header is a major change.

## 9. Contract test vectors

[`fixtures/ingest/`](fixtures/ingest/) holds requests and the responses this
text requires, for both implementations to test against:

* `manifest.json` — how to run them (each case starts from an empty
  workspace holding the listed robots and keys; requests in order; server
  clock set per request), the comparison rule (status; `200` bodies field by
  field without `detail`; error bodies by `code`), the keys and the cases.
* `keys/` — fixed-seed **test** key files (`robodr-blackbox-key/v2`, secret
  and `.pub`) for the roles `uplink` (robot `ugv-001`), `relay`, `finding`
  (`ugv-001`, `ugv-002`) and one unregistered key. Never register them
  anywhere real.
* `cases/<name>/<n>.request.json` (headers, server time, body SHA-256),
  `<n>.body` (raw bytes) and `<n>.response.json` (expected status and body):
  valid single and multi-line batches with per-finding signatures,
  created/updated/duplicate within one batch, wrong robot, relay with
  unknown robot and a missing required signature, bad per-finding
  signatures, malformed line objects, invalid finding, contract 3.0 and
  1.x, oversize values (256 KiB + 1 and exactly 256 KiB), empty line, CRLF,
  no final LF, replay, batch-id reuse, every `401`, `415`, `413`, every
  `400`; and (cases 20–26) origin-vouching vs plain relay, site-scoped
  relay (own site, other site, unregistered robot), the `contract_version`
  syntax rule, lone surrogates, a key twice inside `sig`, a `sig.key_id`
  with a space, a repeated `X-RoboDR-*` header, timestamps 2^64 and
  2^64−1, no `Content-Type`, a body of 4 MiB + 1.

Cases are only ever **added** (new directories, new `manifest.json`
entries and fields); an existing case changes only with a contract change
recorded in §10.

They are generated deterministically by
`cargo run -p robodr-export --example ingest_vectors`; the RoboDR test
suite fails when the committed files differ from the generator, and runs
every request through a reference consumer of this text
(`crates/robodr-export/tests/common/ingest.rs`).

## 10. Changelog

* **v1 draft, 2026-10-26, review** (independent review of the producer and
  of the decisions entry below). Clarifications and one new line code; no
  change to the wire format of a valid request.
  - §3: the registry fields are explicit (robot `site`; relay `site` and
    `vouches_origin`).
  - §4 step 5.3: new line code **`site_mismatch`** (minor change, §8): a
    site-scoped relay sending a robot of another site (or of no site);
    checked after `unknown_robot`.
  - §4 step 5.4: the `vouches_origin` exception to
    `require_finding_signature` is now in the processing rule (it was only
    in §3); a present `sig` is verified for every sender.
  - §4 step 5.2: the `contract_version` rule is the Rust validator's
    (three parts of 1–9 digits, leading zeros allowed, `MAJOR` compared as
    a number; malformed → validated → `invalid_finding`) and the 2.x-only
    validation is stated.
  - §2.3: lone surrogate escapes in `value` → `invalid_line`; a key twice
    inside `sig` → `invalid_line`; `sig.key_id` is ASCII 0x21–0x7E (no
    space); the per-finding signature is over the §2a framed message of the
    decoded value, not the value alone.
  - §2.1: repeated header fields, the timestamp bound and a missing
    `Content-Type` spelled out.
  - §7: `Retry-After` honoured in full up to a documented 24 h producer
    bound, also after a run's last attempt; long backoff for refusals;
    re-injection under new batch ids.
  - §9: vectors 20–26 added (existing vectors unchanged; `manifest.json`
    gains the robot `site`, the key `site` / `vouches_origin` fields, the
    keys `relay-diode` and `relay-site-test-range` and robot `ugv-003`).

* **v1 draft, 2026-10-26, decisions** (coordinator, after the first
  producer's open questions): site-scoped and origin-vouching `relay` keys,
  overlapping keys for rotation (§3); out-of-order events and `last_seen`
  (§5); the consumer commits each batch's effects and its stored response
  in one database transaction, so a `5xx` means nothing was stored (§4).
  Re-injecting dead-lettered lines (new batch id) is producer tooling, not
  a contract change.
* **v1 draft, 2026-10-26** (with the first producer, `robodr-uplink`):
  clarifications found while implementing it, no change to the wire format
  of a valid request.
  - Error codes for every non-`200` status (§6.2), and `400` for missing,
    repeated or malformed `X-RoboDR-*` headers and for an empty body (the
    first draft named no status for them).
  - Processing order of the syntax checks (`415`, `413`, `400`) made
    explicit (§4 step 1).
  - `409 batch_id_reuse`: a known batch id with a different body no longer
    returns the stored response (the producer would acknowledge records by
    line numbers of another body).
  - `Content-Type`: media type compared case-insensitively, parameters
    refused (was "exactly").
  - Line splitting and numbering, empty lines / CR / invalid UTF-8 /
    non-object / duplicate-key lines (`invalid_line`), `sig` required
    (`null` allowed), key order free (§2.3).
  - `too_large` checked before validation, and its relation to the 64 KiB
    finding limit; `unsupported_contract` defined on the `contract_version`
    major; lines processed in order (§4 step 5).
  - Clock skew bound inclusive; `Retry-After` as delay-seconds; the stored
    response is recorded atomically with the batch's effects.
  - Producer notes: batch-id derivation, `413` handling, `200`
    consistency checks (§7); test vectors (§9).
