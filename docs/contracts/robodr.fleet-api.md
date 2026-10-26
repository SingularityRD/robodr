# `robodr.fleet` HTTP API — contract v1

| | |
| --- | --- |
| Status | **draft v1** (Sprint 9, GA-ROADMAP §3); the robot side is built against this text (`robodr-enroll`, crate `robodr-fleet`); the SOC side is not implemented yet; changes in §11 |
| Robot side | `robodr-enroll` (crate `robodr-fleet`), on the unit or its companion computer |
| SOC side | AutoSecOps (`SingularityRD/AutoSecOps1`), module `autosecops/robot_edr/` (to implement: §3–§8) |
| Related | [`robodr.ingest-api.md`](robodr.ingest-api.md) (the keys registered here authenticate ingest), `robodr-commission` (profile signatures, trust roots, revocation lists, anti-rollback), [`../SECURE-DELIVERY.md`](../SECURE-DELIVERY.md) (13a scope: ring information only) |
| Test vectors | [`fixtures/fleet/`](fixtures/fleet/) (§10), shared by both sides |

The fleet API is the SOC side of the robot lifecycle: one-time
**enrollment** with a single-use token, **key rotation** with overlap and
retirement, distribution of the root-signed **revocation list**, the
**profile** lifecycle (draft review, signed profile offer, operator approval
of the observe → enforce transition) and **update-ring information**. The
robot never receives orders through it: every document the SOC sends is
verified data, and nothing is installed or enforced without a local step.

## 1. Endpoints

`{base}` is the AutoSecOps API root (`https://<host>/api` behind the stock
Caddy front end), the same root as the ingest API. TLS is mandatory on any
network path (plain HTTP only from loopback, as ingest §1). The robot's
client is robodr-uplink's: the operator's CA bundle is the only trust
anchor, optional SHA-256 SPKI pins, no redirects, no proxies, response
head ≤ 32 KiB, body ≤ 1 MiB.

| Method | Path below `{base}` | Auth | Request body | `200` body |
| --- | --- | --- | --- | --- |
| `POST` | `/robot-edr/v2/fleet/enroll` | token MAC + uplink signature (§3) | `enroll-request` envelope | `enroll-answer` envelope |
| `POST` | `/robot-edr/v2/fleet/keys/rotate` | request auth (§2.5) | `rotate-request` envelope | `rotate-answer` envelope |
| `POST` | `/robot-edr/v2/fleet/keys/retire` | request auth | `retire-request` envelope | `retire-answer` envelope |
| `GET` | `/robot-edr/v2/fleet/revocations/{platform}` | request auth | — | the `robodr-profile-revocations/v2` file, verbatim |
| `POST` | `/robot-edr/v2/fleet/profiles/drafts` | request auth | a draft profile file, verbatim | `{"digest":"sha256:…","status":"received"}` |
| `GET` | `/robot-edr/v2/fleet/profiles/current` | request auth | — | profile offer (§6.2) |
| `GET` | `/robot-edr/v2/fleet/profiles/approvals/{64 hex}` | request auth | — | `profile-approval` envelope |
| `GET` | `/robot-edr/v2/fleet/ring` | request auth | — | `ring-info` envelope |

`{platform}` is `[A-Za-z0-9._-]{1,64}`; `{64 hex}` is the lower-case hex of
a profile digest (without `sha256:`). Request bodies of `POST` carry
`Content-Type: application/json` (compared case-insensitively, no
parameters; otherwise `415 unsupported_media_type`). `GET` has an empty
body. The robot of an authenticated request is the robot its key is
registered to (§2.5); no path carries a robot or workspace id.

## 2. Common formats

### 2.1 Identifiers

| Name | Syntax |
| --- | --- |
| key id | `ed25519:` + 16 lower-case hex: the RoboDR derived id (`robodr_blackbox::sign_ed25519::derive_key_id`, as in ingest §2.1) |
| fingerprint | `sha256:` + 64 lower-case hex of the 32 raw Ed25519 public-key bytes (the same as `robodr-commission` `key_fingerprint`) |
| digest | `sha256:` + 64 lower-case hex of the bytes named |
| robot id, site, platform | `[A-Za-z0-9._-]{1,64}` (the profile label rule) |
| workspace, token id, approval id, operator | `[A-Za-z0-9._:-]{1,64}` |
| request id | `rfe1-` + 32 lower-case hex (random, chosen by the robot) |
| rotation id | `rfr1-` + 32 lower-case hex (random, chosen by the robot) |
| times | Unix milliseconds, JSON integers (`*_ms`) |

### 2.2 Envelope

Every signed document (except the compact token, §3.1) is an envelope:

```json
{"format":"robodr-fleet-envelope/v1","type":"enroll-answer","payload":"<base64url>","sigs":[{"alg":"ed25519","key_id":"ed25519:…","sig":"<128 hex>"}]}
```

* `payload`: base64url **without padding** (RFC 4648 §5) of the exact
  payload bytes. Decoding is strict: URL-safe alphabet only, no `=`, no
  white space, length ≠ 1 mod 4, unused low bits of the last character zero
  (one encoding per byte string). Decoded payload ≤ 32 KiB.
* `sigs`: 1–4 signature objects, each exactly `alg` (`"ed25519"`), `key_id`
  (§2.1) and `sig` (128 lower-case hex); a key id at most once.
* `mac`: present **only** on an `enroll-request` (and required there):
  exactly `alg` (`"hmac-sha256"`), `token_id`, `mac` (64 lower-case hex).
* `type`: one of `enroll-request`, `enroll-answer`, `rotate-request`,
  `rotate-answer`, `retire-request`, `retire-answer`, `profile-approval`,
  `ring-info` (and `enroll-token`, used only in signatures of §3.1). A
  reader expects one type per place and refuses any other.
* Exactly these keys (`format`, `type`, `payload`, `sigs`, plus `mac` on a
  request), no duplicate key at any depth, at most one final LF and no other
  white space around the object, ≤ 64 KiB in total. The writer emits
  compact JSON in this key order plus one LF.

### 2.3 Signatures

Ed25519 (RFC 8032), strict verification (`verify_strict` semantics: no
malleable signatures, no small-order keys), over this length-framed
message:

```text
message = "robodr-fleet/sig/v1" 0x00
          u32be(len(type))   type     (ASCII, the envelope's type)
          u32be(len(key_id)) key_id   (ASCII, the sig's key_id)
          sha256(payload)              (32 bytes, over the decoded payload bytes)
```

The signer names its key by id; the verifier looks the id up among the keys
it trusts **for that type** and never verifies under a key the id does not
name. Ed25519 is deterministic: a document signed twice is byte-identical.

### 2.4 Payloads

Payloads are JSON objects with **exactly** the keys listed for their
format (each once, none missing, none extra; `null` only where stated),
UTF-8. Writers emit compact JSON in the listed key order (the vectors'
bytes depend on it; readers do not). Every payload carries its own
`format` string; a payload whose `format` is not the one its envelope type
requires is refused.

### 2.5 Request authentication

Every endpoint but `enroll` requires these headers, each exactly once:

| Header | Value |
| --- | --- |
| `X-RoboDR-Key-Id` | key id of an **active `uplink` key** of an enrolled robot |
| `X-RoboDR-Timestamp` | Unix ms, decimal ASCII, no sign, no leading zeros, ≤ 20 digits and ≤ 2^64−1 |
| `X-RoboDR-Signature` | 128 lower-case hex: Ed25519 over the message below |

```text
message = "robodr-fleet/request/v1" 0x00
          u32be(len(method)) method   ("GET" / "POST")
          u32be(len(target)) target   (the origin-form request target as sent,
                                       base path included: "/api/robot-edr/v2/fleet/ring")
          u32be(len(key_id)) key_id
          u64be(timestamp_ms)
          sha256(body)                (32 bytes; of the empty string for GET)
```

Processing, first failure decides: a missing, repeated or malformed header
→ `400 bad_header`; key unknown, retired or not of role `uplink` → `401
unknown_key`; |server time − timestamp| > 300 000 ms → `401
stale_timestamp`; signature → `401 bad_signature`. During a rotation
overlap (§5) both uplink keys are active and either authenticates. Every
`401` is an audit-log entry (key id, source address, reason).

### 2.6 Errors

Non-`200` responses carry `{"code":"…","detail":"…"}`. `detail` is free
text for humans; the robot shows it (control characters removed, at most
200 characters) and never parses it. New codes may be added (minor change);
a robot treats an unknown code by its status.

| Status | Codes | Robot behaviour |
| --- | --- | --- |
| `400` | `bad_request`, `bad_header`, `invalid_profile` | refused (exit 1); a robot bug or a tampered file |
| `401` | `bad_token`, `bad_signature`, `unknown_key`, `stale_timestamp` | refused; fix the token, registration or clock |
| `403` | `workspace_mismatch`, `robot_mismatch` | refused |
| `404` | `no_list`, `no_profile`, `no_approval`, `no_ring`, `unknown_rotation`, `not_found` | nothing published yet |
| `409` | `token_used`, `key_conflict`, `rotation_in_progress`, `rotation_id_reuse`, `stale_key`, `already_retired` | refused; see the step |
| `410` | `token_expired` | refused; a new token is needed |
| `413` | `too_large` | refused |
| `415` | `unsupported_media_type` | refused (a robot bug) |
| `429`, `5xx`, no response | any | retry later with the **same** stored request (exit 3 = SOC not reachable) |

## 3. Enrollment

### 3.1 Token (SOC → operator → robot)

The SOC issues a token when an operator adds a robot (UI: robot id,
optional site, validity). It is a single line:

```text
rdet1.<base64url(payload)>.<base64url(64-byte Ed25519 signature)>
```

Payload (`robodr-fleet-enroll-token/v1`), keys in this order:

| Key | Value |
| --- | --- |
| `format` | `"robodr-fleet-enroll-token/v1"` |
| `token_id` | identifier, unique in the workspace |
| `workspace` | the workspace the robot joins |
| `robot_id` | the robot it is for |
| `site` | the robot's site, or `null` |
| `soc_key_id` | key id of the SOC **fleet key** that signs it |
| `issued_at_ms`, `expires_at_ms` | validity; `0 < expires − issued ≤ 7 days` |
| `nonce` | 64 lower-case hex: 32 random bytes from a CSPRNG, not all zero: the **token secret** |

The signature is §2.3 with `type = "enroll-token"` and `key_id =
soc_key_id`, by the SOC fleet key. The token is a bearer credential until
consumed: show it once, store only what §3.3 needs (the nonce, to check
MACs), never log it. The robot trims surrounding spaces, tabs, CR and LF;
anything else (a second `.`, padding, another prefix) is refused. The token
is ≤ 4 KiB.

The robot checks before generating any key: the signature under a
**configured** SOC fleet key (`fleet.json` `soc.keys`, installed out of
band like the CA bundle: never taken from the token); `expires_at_ms ≥
now` and `issued_at_ms ≤ now + 300 000` on its own clock; the workspace
equals the unit's configured `workspace` (if set); `robot_id` and `site`
equal agentd's `robot.id` / `robot.site` (if set); the token id was not used
on this unit before.

### 3.2 Request (robot → SOC)

The robot generates its keys on the unit (§4), then builds the payload
(`robodr-fleet-enroll-request/v1`):

| Key | Value |
| --- | --- |
| `format` | `"robodr-fleet-enroll-request/v1"` |
| `request_id` | `rfe1-…` |
| `token_id`, `workspace`, `robot_id`, `site` | copied from the token |
| `created_at_ms` | robot clock |
| `agentd_version` | the RoboDR release (`[0-9][0-9A-Za-z.+~-]{0,63}`) |
| `profile_digest` | digest of agentd's current profile file, or `null` |
| `keys` | exactly three objects `{"role","key_id","public_hex","fingerprint"}` in the order `uplink`, `finding`, `blackbox`; `public_hex` 64 lower-case hex; `key_id` and `fingerprint` must be the ones derived from `public_hex`; the three keys distinct |

The envelope (`type = "enroll-request"`) is signed by the new **uplink**
key only (proof of possession) and carries the token MAC:

```text
mac_key = SHA-256("robodr-fleet/token-mac-key/v1" 0x00 || nonce)       (nonce: the 32 bytes)
mac     = HMAC-SHA256(mac_key, "robodr-fleet/token-mac/v1" 0x00
                               u32be(len(token_id)) token_id
                               sha256(payload))
```

The request never contains the nonce or the token: a copy of the request
(a log, the media of the air-gapped flow) cannot be replayed with other
keys, and cannot enroll anything after the token is consumed.

### 3.3 Processing (SOC)

First failure decides:

1. `Content-Type` → `415`; body > 64 KiB → `413 too_large`.
2. Envelope (§2.2) and payload (§3.2) syntax → `400 bad_request`;
   `mac.token_id` ≠ `token_id` → `400 bad_request`.
3. Token lookup by `token_id` (unknown → `401 bad_token`); MAC (constant
   time) → `401 bad_token`.
4. The envelope must be signed by exactly the request's uplink key and
   verify → `401 bad_signature`.
5. Replay: a consumed token whose stored request digest (digest of the
   payload bytes) equals this one → `200` with the **stored** answer, byte
   for byte (a robot whose answer was lost resends the same bytes); any
   other request with a consumed token → `409 token_used`.
6. Server time > `expires_at_ms` → `410 token_expired` (the air-gapped flow
   must reach the SOC within the token's validity: issue a longer one, ≤ 7
   days).
7. `workspace` ≠ the token's → `403 workspace_mismatch`; `robot_id` or
   `site` ≠ the token's → `403 robot_mismatch`.
8. Any key id or fingerprint already registered in the workspace → `409
   key_conflict`.
9. Effects, atomically with consuming the token and storing the answer:
   every key previously registered for the robot is retired (a
   re-enrollment replaces them), the three keys are registered active with
   their roles, the robot is registered with its site.

Answer (`robodr-fleet-enroll-answer/v1`, envelope `enroll-answer` signed by
a SOC fleet key):

| Key | Value |
| --- | --- |
| `format` | `"robodr-fleet-enroll-answer/v1"` |
| `request_id` | the request's |
| `request_digest` | digest of the request payload bytes |
| `token_id`, `workspace`, `robot_id`, `site` | as registered |
| `keys` | `{"role","key_id","fingerprint"}` for the three keys, request order |
| `enrolled_at_ms` | server time |

The robot accepts an answer only if it is signed by a configured SOC fleet
key and every field equals its pending request (request id and digest,
token, workspace, robot, site, keys); otherwise it keeps the request
pending. It then writes `enrollment.json` and the fleet journal record.

### 3.4 Air-gapped enrollment

The same bytes travel as files on vetted media: `robodr-enroll request
--token … --out request.json` writes the request envelope (no secret in
it); the SOC imports it with exactly the §3.3 processing (its import time is
"server time") and exports the answer envelope; `robodr-enroll accept
--answer answer.json` verifies it. Nothing else differs.

## 4. Keys

| Role | Signs | Registered by |
| --- | --- | --- |
| `uplink` | ingest batches (ingest §2.2) and fleet requests (§2.5) | enrollment, rotation |
| `finding` | per-finding signatures (findings contract §2a) | enrollment, rotation |
| `blackbox` | black-box records and evidence bundles; verifies the unit's chain off-unit | enrollment (not rotated by this API: agentd would need the old key to keep verifying its chain) |

* Keys are generated **on the unit** from the kernel CSPRNG and never leave
  it: robodr-blackbox key files (`robodr-blackbox-key/v2`, Ed25519, derived
  key id), created exclusively with mode 0600 in a directory not writable
  by group or others, the public half next to it (`.pub`, 0644). An
  existing key file is registered only with `--reuse-existing-keys` (e.g.
  the black-box key of an agentd that already runs).
* A `blackbox` key authenticates nothing at the ingest API (it is to be
  treated like a wrong-role key there: `401 unknown_key`); a `finding` key
  authenticates no batch and no fleet request.
* Key ids are unique per workspace; fingerprints too.

### 4.1 Revocation list (`GET …/revocations/{platform}`)

The body is the `robodr-profile-revocations/v2` file for the platform
(`robodr-commission` format: monotonic `serial`, revoked profile digests and
signing-key fingerprints, signed by a **trust root**), served verbatim.
The SOC holds the list (it is signed offline by the trust-root holders) and
only distributes it. The robot verifies it with robodr-commission against
agentd's `trust_roots`, requires `platform` to be the unit's, and refuses
a rollback: the serial must be ≥ the highest of the last list it installed,
the list currently installed (if it verifies) and agentd's accepted
`revocation_serial`; an equal serial must have the same digest
(equivocation otherwise). It then installs the file atomically at agentd's
`revocation_list` path (keeping its owner and mode) and warns when agentd
would refuse the active profile with the new list.

## 5. Key rotation

### 5.1 Rotate request

Payload `robodr-fleet-rotate-request/v1`: `format`, `rotation_id`,
`workspace`, `robot_id`, `role` (`uplink` | `finding`), `old_key_id`,
`old_fingerprint`, `new_key_id`, `new_public_hex`, `new_fingerprint`,
`created_at_ms`. Envelope `rotate-request` signed by the **old** key, then
the **new** key (two signatures, in that order): possession of both. The
HTTP request is authenticated (§2.5) by an active uplink key of the robot
(for `role = uplink`: the old key).

Processing (after §2.5): envelope / payload syntax → `400 bad_request`;
`workspace` or `robot_id` not the authenticated robot's → `403
robot_mismatch`; replay: a known `rotation_id` with the same payload digest
→ the stored answer, with another digest → `409 rotation_id_reuse`; old key
not an active key of that robot and role with that fingerprint → `409
stale_key`; signatures → `401 bad_signature`; another open rotation of the
same robot and role → `409 rotation_in_progress`; new key id or
fingerprint already registered → `409 key_conflict`. Effects: the new key is
registered **active** — both keys are now valid (overlap) — and the answer
is stored with the rotation.

Answer `rotate-answer` (payload `robodr-fleet-rotate-answer/v1`):
`format`, `rotation_id`, `request_digest`, `workspace`, `robot_id`, `role`,
`old_key_id`, `new_key_id`, `status` = `"overlap"`, `at_ms`.

### 5.2 Robot phases

```text
prepared   new key at <key>.next (0600, exclusive), request stored byte-exact
registered the SOC answered "overlap": both keys valid
swapped    old key copied to <keydir>/retired/, <key>.next rename(2)d over <key>,
           .pub rewritten, handover recorded (§5.4)
done       the SOC answered "retired": old key shredded, enrollment updated
```

Each phase is persisted before the next step; requests are resent
unchanged after a crash (the SOC answers from the stored rotation); every
step is idempotent. A `prepared` rotation can be aborted locally (the new
key is shredded) only while the SOC has not registered it; if the request
may have reached the SOC, finish it instead. Services read keys at start:
after the swap the operator restarts `robodr-uplink` (role `uplink`) or
`robodr-agentd` (role `finding`) and retires the old key only once the
service runs with the new key — for `finding`, also once the findings
already signed with the old key have been delivered (the SOC verifies them
with the old key until it is retired).

### 5.3 Retire

Payload `robodr-fleet-retire-request/v1`: `format`, `rotation_id`,
`workspace`, `robot_id`, `role`, `old_key_id`, `new_key_id`,
`created_at_ms`; envelope `retire-request` signed by the **new** key only;
the HTTP request is authenticated by an active uplink key (for `role =
uplink`: the new one). Processing: syntax → `400`; unknown rotation → `404
unknown_rotation`; another robot's → `403 robot_mismatch`; fields not the
rotation's → `400 bad_request`; signature → `401 bad_signature`; already
retired with the same request digest → stored answer, with another → `409
already_retired`. Effects: the old key is retired (authenticates nothing
from now on, ingest included). Answer `retire-answer` (payload
`robodr-fleet-retire-answer/v1`, same keys as the rotate answer) with
`status` = `"retired"`.

### 5.4 Black-box continuity

The robot records every phase in its **fleet journal**, a robodr-blackbox
recorder (`/var/lib/robodr/fleet/journal`, signed with the unit's black-box
key; separate from agentd's chain because the recorder is single-writer).
The swap writes a `robodr.fleet.key_handover` note carrying two signatures
over

```text
"robodr-fleet/key-handover/v1" 0x00
u32be-framed: rotation_id, role, old_fingerprint, new_fingerprint, journal_head
```

(`journal_head`: hex of the hash of the journal record the note follows,
or `genesis`), one by the old key and one by the new key, followed by a
seal. The journal therefore proves which key handed over to which, at which
point of the chain; it verifies with `robodr-blackbox verify` and the
black-box public key.

## 6. Profiles

### 6.1 Draft publish

`POST …/profiles/drafts` with a draft profile file (`locked: false`, as
written by `robodr-commission learn`), verbatim, ≤ 8 MiB. The SOC parses it
strictly (robodr-commission rules) and refuses a locked profile (`400
invalid_profile`); it answers `{"digest":"<digest of the body>",
"status":"received"}` and queues it for review. Locking (sign-off,
attestation, signature with a profile key) happens with
`robodr-commission` by the OEM / SOC operators, never on the unit.

### 6.2 Offer

`GET …/profiles/current` answers the profile assigned to the robot:

```json
{"format":"robodr-fleet-profile-offer/v1","profile_version":4,"digest":"sha256:…","profile":"<base64url of the exact profile file>","sig":"<base64url of the exact .sig file>"}
```

The wrapper is not signed (the profile and its `.sig` are, by
robodr-commission's trust chain); `digest` must be the digest of the
decoded `profile`. The robot **stages** it: it verifies it with exactly
agentd's trust inputs (`sensor.profile_trust`: trusted keys, trust roots and
signed floor, revocation list and policy, platform / unit expectations) and
agentd's anti-rollback state (read-only), refuses a draft and a profile for
another unit, and keeps it under `/var/lib/robodr/fleet/profile/`. A staged
profile is **not** enforced.

### 6.3 Approval (observe → enforce)

`GET …/profiles/approvals/{hex}` answers the approval envelope
(`profile-approval`, signed by a SOC fleet key) for that digest; the same
envelope can travel as a file. Payload `robodr-fleet-profile-approval/v1`:

| Key | Value |
| --- | --- |
| `format`, `approval_id` | |
| `workspace`, `robot_id` | the robot it is for |
| `platform`, `profile_digest`, `profile_version` | the exact profile |
| `transition` | `"enforce"` |
| `approved_by` | 1–8 distinct operator ids (the SOC enforces its own approval policy, e.g. two-person, before signing) |
| `issued_at_ms`, `expires_at_ms` | validity window |

The robot installs only when the operator runs `robodr-enroll profile
approve` with it, and only if: signed by a configured SOC fleet key;
workspace and robot are the unit's enrollment; digest, version and platform
equal the staged profile; not expired (robot clock; `issued_at_ms ≤ now +
300 000`); the approval id was not used on the unit; and the staged profile
verifies again **at that moment**. Install: previous profile and `.sig`
backed up, `.sig` then profile written atomically at agentd's
`profile_path` (owner and mode kept). agentd enforces it only after its
next start, where it verifies it once more. Nothing in this API makes a
robot enforce anything by itself.

## 7. Update-ring information

`GET …/ring` answers a `ring-info` envelope (SOC fleet key), payload
`robodr-fleet-ring/v1`: `format`, `serial` (≥ 1, monotonic per robot),
`workspace`, `robot_id`, `ring` (0 canary, 1 early, 2 broad), `target_version`
(version or `null`), `bundle_sha256` (64 hex of the offline bundle tarball, or
`null`), `issued_at_ms`, `expires_at_ms`.

**Information only** (SECURE-DELIVERY 13a scope): the robot verifies it,
refuses a lower serial or the same serial with other content, records it,
and tells the operator whether the target differs from the installed
release and whether the information has expired (withholding becomes
visible). It never downloads or installs anything; installation stays
`install-bundle.sh install` with its signature check, run locally.

## 8. Limits

| Limit | Value |
| --- | --- |
| envelope / enroll body | 64 KiB (`413 too_large`) |
| decoded payload | 32 KiB |
| token | 4 KiB; validity ≤ 7 days |
| draft profile body | 8 MiB |
| profile offer | 2 MiB (robot side) |
| clock skew (§2.5, token / approval issue time) | 300 000 ms, inclusive |
| signatures per envelope | 4 |

## 9. Versioning

The path carries the API major (`v2`, the robot-edr API family of ingest).
New error codes, new optional response members of non-envelope bodies and
new endpoints are minor changes. Any change to a payload's keys, to a
signed message or to an envelope is a new `format` / domain version (`/v2`)
and a major change.

## 10. Contract test vectors

[`fixtures/fleet/`](fixtures/fleet/) holds requests and the responses this
text requires:

* `manifest.json` — how to run them (each case starts from an empty
  workspace with the SOC fleet key `keys/soc.key`; register the case's
  setup tokens, serve its setup publications verbatim; requests in order,
  server clock per request), the comparison rule (status; error bodies by
  `code`; envelopes by type, signer list and decoded payload; other `200`
  bodies byte-exact), the keys, tokens and cases.
* `keys/` — fixed-seed **test** key files (secret and `.pub`): the SOC
  fleet key, robots `ugv-001` / `ugv-002` (`uplink`, `finding`, `blackbox`,
  and `ugv-001`'s next uplink key), a profile signer and a trust root.
  Never register them anywhere real.
* `tokens/` — the cases' tokens (their nonces are also in the manifest).
* `cases/<name>/<n>.request.json` (method, target with base path, headers,
  server time, body SHA-256), `<n>.body`, `<n>.response.json` and, for a
  `200`, `<n>.response.body`: enrollment (valid, retry with the stored
  answer, token reuse, bad MAC, unknown token, expired, workspace / robot /
  site binding, wrong signer, missing MAC, wrong media type, trailing bytes,
  key conflict, null site), rotation and retirement with overlap, rotate
  refusals (missing new-key signature, replay, rotation in progress, stale
  old key), request authentication (valid, stale timestamp, signature for
  another path, finding key, repeated header, no headers) and distribution
  (revocation list, offer, approval, ring, draft publish).

They are generated deterministically by `cargo run -p robodr-fleet
--example fleet_vectors`; the RoboDR test suite fails when the committed
files differ from the generator and replays every committed request through
a reference SOC of this text (`crates/robodr-fleet/tests/common/soc.rs`).
Cases are only ever added.

## 11. Changelog

* **v1 draft, 2026-10-26** (Sprint 9, robot side): first text, written with
  `robodr-enroll`. Not yet implemented on the SOC side; the vectors are
  what an AutoSecOps implementation must reproduce.
