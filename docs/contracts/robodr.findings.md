# Contract: `robodr.findings` (findings, v2)

| | |
| --- | --- |
| Contract | `robodr.findings`, version **2.5.0** (`contract_version` field, `robodr-contract-version` header); changes in §10 |
| Producer | `robodr-agentd` (findings spool; since 2.2 also `robodr-deliverd`, the on-unit delivery agent, which writes its `robot.deliver.*` findings, and since 2.3 its `robot.seal.*` findings, into the same spool; since 2.3 the in-path gateway `robodr-firewall-gw` reports its `robot.gateway.*` findings through agentd's `gateway_feed` socket), `robodr-diode` importer (air-gapped sites), `robodr-kafka-publish` |
| Consumer | Any SOC, SIEM or SOAR: the envelope is vendor-neutral and the body is a standard OCSF Detection Finding |
| Value schema | [`robodr-finding.schema.json`](robodr-finding.schema.json) (JSON Schema 2020-12, `$id` `https://schemas.singularityrd.com/robodr/findings/2.5.0`; it also describes 2.0.x – 2.4.x messages, whose only difference is the rule catalog the validator applies, §3, and, since 2.5, the optional `entity_context.agent_health` record of §3g) |
| Golden example | [`robodr-finding.example.json`](robodr-finding.example.json) |
| Reference implementation | `crates/robodr-ocsf` (`FindingBuilder`, `validate`, `kafka::record`, `sig`) |
| Superseded | Contract 1.x (`robot-edr.findings`): [`legacy/robot-edr.findings.md`](legacy/robot-edr.findings.md); parse-only (§5) |

The example and the schema are not hand-maintained prose: the `robodr-ocsf`
test suite fails if the builder's output differs from the example by a single
byte, if a produced finding is missing any key the schema marks `required`, or
if it has a key the schema does not declare.

## 1. Scope

What a robot sends a SOC is **correlated findings with links to black-box
evidence**, not raw telemetry. Each message is a vendor-neutral envelope
around a full **OCSF 1.1 Detection Finding** (`class_uid` 2004,
`category_uid` 2 *Findings*), so the same object can be ingested by a SOC
case system, forwarded to an OCSF-capable SIEM, or written to syslog
unchanged. Fields we are not certain of in the OCSF spec are listed in
`crates/robodr-ocsf/README.md` (*OCSF-UNCERTAIN*).

A finding never carries an action. A SOC never sends a motion command to a
robot: actions go through the control plane
([`robodr.control-plane.md`](robodr.control-plane.md)), are drawn from the
action catalog (`robodr_responder::actions`), and the on-robot agent judges
each one against the robot's current safety state and may refuse it.

**Transports.** The value is the same on every path:

| Path | Unit of transfer |
| --- | --- |
| Kafka (optional SIEM export) | one record per finding, §2 |
| HTTPS ingest (SOC native, planned) | NDJSON: one compact value per line, signed batch |
| Air-gapped diode | `findings.jsonl` in a signed batch, §8 |

**Envelope fields** (top level; all required unless marked):

| Field | Meaning |
| --- | --- |
| `contract_version` | `2.y.z` |
| `finding_id` | `ocsf.finding_info.uid`; deterministic (§2 *Identity*) |
| `external_id` | `<robot_id>:<finding_id>`; with `data_source` the consumer's dedup key |
| `data_source` | producer label, default `robodr`, configurable per deployment: `[a-z0-9][a-z0-9._-]{0,63}`. **Unauthenticated**: not bound to any key (see *Identity* below) |
| `title`, `description` | trusted catalog text + sensor-authored facts (never tainted text) |
| `severity` | `low` \| `medium` \| `high` \| `critical` |
| `timestamp` | RFC 3339 UTC, ms (= `ocsf.time`) |
| `entity_context` | robot, profile, rule id, mode, safety state, attestation, ROS/DDS identifiers (tainted), command and envelope, bus message id, occurrence count, detail (tainted); since 2.5 `agent_health` on `robot.agent.health` findings only (§3g) |
| `mitre_predictions` | ATT&CK for ICS techniques from RoboDR's own rule catalog (`provenance: sensor`) |
| `evidence_links` | `robodr-blackbox://<robot>/<segment>/<seq>?sha256=<hex>` |
| `anomaly_score` | *optional*, in [0, 1] |
| `adversary_controlled_fields` | JSON Pointers of every attacker-controlled value (§3) |
| `ocsf` | the OCSF Detection Finding; `ocsf.unmapped.robodr` = `entity_context` |

## 2. Record layout

| Part | Value |
| --- | --- |
| Topic | configured per deployment, default `robodr.findings`; the value names it in `ocsf.metadata.log_name` |
| Key | `finding_id` (UTF-8, `rf1-` + 32 lower-case hex) |
| Value | compact JSON `FindingEnvelope`, UTF-8, ≤ 64 KiB |
| Partition | chosen **explicitly** by the producer from the **robot id** (§4), not from the key |

### Headers (all values UTF-8, fixed order)

| Header | Value |
| --- | --- |
| `content-type` | `application/json` |
| `robodr-contract-version` | the value's own `contract_version` (`2.5.0` from this producer; a forwarded or replayed 2.0 – 2.4 message keeps its version) |
| `ocsf-version` | `1.1.0` |
| `data-source` | the value's `data_source` (default `robodr`) |
| `robot-id` | robot id (`[A-Za-z0-9._-]{1,64}`) |
| `severity` | `low` \| `medium` \| `high` \| `critical` |
| `event-uid` | `ocsf.metadata.uid` (per-emission id, `re1-` + 32 hex) |
| `robodr-finding-sig` | *optional, always last:* detached Ed25519 signature (§2a) |

Headers are a routing convenience; the value is authoritative. A consumer must
not trust a header that disagrees with the value.

### Value (abridged; full example in the JSON file)

```json
{
  "contract_version": "2.5.0",
  "finding_id": "rf1-0d7e79aac05cfd23bcfbdd38ef617eba",
  "external_id": "ugv-007:rf1-0d7e79aac05cfd23bcfbdd38ef617eba",
  "data_source": "robodr",
  "title": "Unauthorized publisher on a motion topic",
  "description": "A participant that is not in the locked model profile announced a writer on a motion/control topic. Robot ugv-007 (model ugv-tracked-v1, site range-north, firmware 2.4.1); profile version 7; mode enforce; safety state: motion moving, human proximity not detected; attestation verified; occurrences 3.",
  "severity": "critical",
  "timestamp": "2026-09-21T14:13:24.250Z",
  "entity_context": {
    "robot": { "id": "ugv-007", "model": "ugv-tracked-v1", "platform_family": "linux_ros2",
               "site": "range-north", "firmware": { "version": "2.4.1", "sha256": "1f1f…" } },
    "profile": { "version": "7", "sha256": "c0c0…" },
    "rule_id": "robot.ros2.unauthorized_motion_writer",
    "mode": "enforce",
    "safety_state": { "motion": "moving", "human_proximity": "not_detected" },
    "attestation": "verified",
    "ros": {
      "participant_guid": { "value": "0102030405060708090a0b0c", "display": "0102030405060708090a0b0c",
                            "taint": "adversary", "escaped": false, "truncated": false,
                            "non_ascii": false, "mixed_script": false, "injection_hint": false,
                            "suspicious": false, "original_len": 24, "original_sha256": "a703…" },
      "topic":            { "value": "rt/cmd_vel", "display": "rt/cmd_vel", "taint": "adversary", "…": "…" }
    },
    "occurrence_count": 3,
    "detail": { "value": "participant 0102… not in profile publishes to motion topic /cmd_vel", "taint": "adversary", "escaped": false, "…": "…" }
  },
  "mitre_predictions": [ { "technique_id": "T0855", "technique_name": "Unauthorized Command Message",
                           "framework": "attack_ics", "provenance": "sensor" } ],
  "evidence_links": [ "robodr-blackbox://ugv-007/12/40117?sha256=8d8d…", "robodr-blackbox://ugv-007/12/40118?sha256=9e9e…" ],
  "adversary_controlled_fields": [ "/entity_context/detail", "/entity_context/ros/participant_guid", "…" ],
  "ocsf": {
    "activity_id": 2, "activity_name": "Update", "category_uid": 2, "category_name": "Findings",
    "class_uid": 2004, "class_name": "Detection Finding", "type_uid": 200402,
    "severity_id": 5, "severity": "Critical", "status_id": 1, "status": "New",
    "time": 1790000004250, "count": 3,
    "metadata": { "version": "1.1.0", "product": { "name": "RoboDR", "vendor_name": "Singularity RD", "version": "0.1.0-alpha.1" },
                  "uid": "re1-e10d71877f52e563b8482d1359871bb1", "log_name": "robodr.findings" },
    "finding_info": { "uid": "rf1-0d7e…", "title": "…", "desc": "…", "types": ["robot_deviation", "ros2_dds_discovery"],
                      "first_seen_time": 1790000000000, "last_seen_time": 1790000004250,
                      "analytic": { "uid": "robot.ros2.unauthorized_motion_writer", "type_id": 1, "type": "Rule", "…": "…" },
                      "attacks": [ { "technique": { "uid": "T0855", "name": "Unauthorized Command Message" } } ] },
    "device": { "uid": "ugv-007", "name": "ugv-007", "type_id": 99, "type": "Robot", "model": "ugv-tracked-v1" },
    "evidences": [ { "data": { "kind": "robodr.blackbox", "segment": 12, "seq": 40117, "sha256": "8d8d…", "uri": "…" } } ],
    "resources": [ { "type": "ros2.participant", "uid": "0102030405060708090a0b0c", "labels": ["taint:adversary"] },
                   { "type": "ros2.topic", "name": "rt/cmd_vel", "labels": ["taint:adversary"] } ],
    "unmapped": { "robodr": { "…": "identical to entity_context" } }
  }
}
```

## 2a. Finding signature (optional; since 1.2)

**Why.** The validator proves a finding is well formed, not who wrote it. On
a connected (non-diode) path, anyone able to produce to the topic can forge a
finding that matches the rule catalog exactly. A producer may sign
each finding with a per-unit Ed25519 *finding key*; a consumer in **strict**
mode requires the signature.

**Signed bytes = the record value, verbatim.** The message is the exact UTF-8
bytes of the Kafka value as the producer emitted it (`robodr_ocsf::to_json`:
compact, deterministic). There is no canonical form and no re-serialisation:
the consumer verifies over the raw bytes it received, before trusting the
parse. Any hop that re-formats the value (pretty-print, key reordering,
re-escaping, re-serialising a parsed object) breaks the signature — on
purpose; forwarders must carry values verbatim.

```text
ed25519_sign(finding_key,
    "robodr-ocsf/finding-sig/v1" 0x00
    || u32be(len(alg))    || alg        -- "ed25519"
    || u32be(len(key_id)) || key_id     -- printable ASCII, 1..128 bytes
    || u64be(len(value))  || value)     -- record value bytes
```

The domain string keeps finding signatures distinct from black-box record or
diode manifest signatures; `alg` and `key_id` are inside the signed message,
so a signature cannot be relabelled to another key.

**Carrier: Kafka header `robodr-finding-sig`** (not a value field: a field
inside the value would make the signed bytes depend on the signature, and the
value stays byte-identical to an unsigned value). Header value, compact
JSON, exactly these fields in this order, ≤ 512 bytes
(`$defs/FindingSignatureHeader` in the schema):

```json
{"alg":"ed25519","key_id":"finding:ugv-007:1","sig":"<128 lower-case hex digits>"}
```

**Verification** (`robodr_ocsf::parse_and_validate_signed(raw, header, keys,
policy)` / `verify_record`):

1. Exactly one `robodr-finding-sig` header (name case-insensitive), else
   reject (`Duplicate`). Parse it strictly: unknown/duplicate fields,
   `alg` ≠ `ed25519` (HMAC is never accepted: a symmetric key lets every
   verifier forge), bad key id or non-lower-case hex → reject.
2. Validate the value with the strict validator (unchanged).
3. Look up the verifier for the unit **the finding itself names**,
   `entity_context.robot.id` (already bound by the validator to
   `external_id`, `ocsf.device.uid` and `finding_id`). No key for that unit
   → reject. If the keyring binds the named key to a device, it must be that
   unit. A key of unit B therefore never vouches for a finding naming unit A.
4. Verify the Ed25519 signature over the raw value bytes under the key named
   by `key_id` (a unit's keyring may hold current and previous keys).

| Policy | No header | Header present |
| --- | --- | --- |
| `Strict` | reject (`Missing`) | must verify |
| `Optional` (migration) | accept, status `Unsigned` | must verify |

**Replay is the consumer's job.** A signature proves origin, not freshness;
a captured signed record re-sent verbatim verifies again. Consumers already
drop exact duplicates on `event-uid` (§2 *Identity*); `VerifiedFinding::
replay_key()` returns `(robot id, finding_id, event uid, ocsf.time, count)`
for that dedup, and `ocsf.time` can feed a freshness window. The library
keeps no state.

**Keys.** One finding key per unit, distinct from its black-box key;
consumers hold public keys only (a map `robot id → Verifier`, e.g. a
`robodr_blackbox::Keyring`). Distribution of those public keys is the
commissioning / fleet registry's job and outside this contract. The Ed25519
implementation is `robodr-blackbox`'s wrapper over the audited
`ed25519-dalek` crate (strict verification, RFC 8032 vectors).

**Producer.** `robodr_ocsf::record_signed` / `sign_record`; the agent signs
when configured with `Agent::with_finding_signer` (Ed25519 only; if signing a
finding fails at run time it is emitted unsigned with an error, which strict
consumers drop — the black box still holds the evidence).

### Severity mapping

| RoboDR `Severity` | `severity` | `ocsf.severity_id` | `ocsf.severity` |
| --- | --- | --- | --- |
| Low | `low` | 2 | Low |
| Medium | `medium` | 3 | Medium |
| High | `high` | 4 | High |
| Critical | `critical` | 5 | Critical |

OCSF `severity_id` enum: 0 Unknown, 1 Informational, 2 Low, 3 Medium, 4 High,
5 Critical, 6 Fatal, 99 Other. RoboDR never emits 0, 1, 6 or 99.

### Identity, lifecycle, deduplication

* `finding_id` is **deterministic**: `rf1-` + first 128 bits of SHA-256 over a
  length-framed `(robot id, rule id, subject)`, the subject being the raw
  participant GUID / node / topic / type name / source IP. Same deviation, same
  robot, same subject ⇒ same `finding_id`, across restarts and producers.
* First occurrence: `ocsf.activity_id` 1 *Create*, `count` 1. Repeats: activity
  2 *Update* with the same `finding_id`, higher `count`, later `last_seen_time`.
  A consumer upserts on (`data_source`, `external_id`). With several
  RoboDR deployments feeding one SOC, give each its own `data_source`
  (e.g. `site-a.robodr`) or rely on the globally unique robot id inside
  `external_id`.
* **`data_source` is an unauthenticated label.** It is whatever the
  producing deployment was configured to write. It is inside the signed
  value when a finding is signed (§2a), but no key is bound to a
  `data_source`: the finding key is registered for a robot id, and any
  holder of any robot's key — or anyone at all on a path where signatures
  are optional — can write any well-formed label. A consumer **must not**
  route tenants, pick a trust level or choose a keyring by `data_source`
  (nor by the topic or the `data-source` header, which follow it). Route by
  the authenticated identity instead: the key that verified the finding
  (or the diode batch) → the robot id it is registered for → the tenant /
  site that robot is enrolled in. A consumer that wants the label to mean
  something should keep, per registered key or per robot, the set of
  `data_source` labels that producer may use and reject (or quarantine)
  findings outside it; neither the reference keyring nor the diode
  importer does this today.
* `ocsf.metadata.uid` (`event-uid` header) identifies one *emission*
  (hash of finding id, `last_seen_time`, `count`). Re-delivery of the same
  emission (producer retry, diode re-send) carries the same `event-uid`;
  consumers may drop exact duplicates on it.
* `status_id` is always 1 *New* from RoboDR; triage status belongs to the SOC.

## 3. Security requirement SR-TAINT: attacker-controlled strings

**Requirement.** ROS 2 node names, topic names, type names, DDS GUID prefixes,
source addresses and the deviation's free-text `detail` (which interpolates
them) are chosen by whoever can reach the robot's DDS bus. They may flow into
an **LLM-based SOC** (triage agents, summarisers), so every one of them is a
potential prompt-injection carrier: an instruction written into a ROS node
name is the canonical test case (`crates/robodr-ocsf/tests/findings.rs`,
`INJECTIONS`). The provenance rule this contract encodes: **ROS node and
topic names, process and file names, host names and command lines are
adversary-authored** — anyone with access to the robot can choose them, so a
triage model must never close a finding by trusting them.

**Producer obligations (enforced by `robodr-ocsf`, checked by its validator):**

1. Attacker-controlled strings appear **only** in typed data fields: `Tainted`
   objects (`entity_context.ros.*`, `entity_context.command.channel`,
   `entity_context.detail`, and their copies under `ocsf.unmapped.robodr`) or
   OCSF `resources[]` entries labelled `taint:adversary`. They are **never**
   interpolated into `title`, `description`, `ocsf.message` or
   `ocsf.finding_info.desc`; those are built from a trusted rule catalog and
   sensor-authored config only.
2. Every `Tainted` object carries `"taint": "adversary"`; every such location is
   listed (JSON Pointer) in `adversary_controlled_fields`.
3. Neutralisation is by **allow-list**, not deny-list (a deny-list of Unicode
   "invisible" characters cannot be complete without Unicode tables: Arabic
   number signs U+0600–0605, musical/Egyptian format controls, Mongolian
   variation selectors, braille blank U+2800, NBSP and other exotic spaces,
   private-use, unassigned code points, combining marks and Cyrillic
   homoglyphs all slipped through 1.0). Two charsets:

   | Charset | Fields | Copied raw | Everything else |
   | --- | --- | --- | --- |
   | ROS name | `entity_context.ros.*`, `entity_context.command.channel`, tainted `resources[].{uid,name}` | `A-Z a-z 0-9 _ / . : -` | escaped |
   | Text | `entity_context.detail` | printable ASCII U+0020–U+007E except ``! " # & ' ( ) * < > [ \ ] ` { \| } ~`` | escaped |

   **Escaping scheme** (unchanged syntax since 1.0): a backslash becomes `\\`;
   any other character outside the raw set becomes `\u{H}` with `H` its code
   point in upper-case hex, zero-padded to at least 4 digits (no further
   padding). Since a backslash is never raw, it always starts an escape, so
   decoding is unambiguous and exact (`robodr_ocsf::taint::unescape`); since
   escapes of raw characters and non-canonical forms are rejected, every
   input has exactly one encoding. Every encoded value is printable ASCII.
   Examples: `/cmd_v\u{0435}l` (Cyrillic `е`), `/x\u{0020}\u{0021}\u{005B}s\u{005D}…`
   (a Markdown image), `/cmd\u{0600}vel`.
   Schema patterns: ROS name `^[A-Za-z0-9_/.:{}\\-]*$`, text
   `^[ $%+,./0-9:;=?@A-Z^_a-z{}\\-]*$` (they admit `\ { }` only because escapes
   use them; well-formedness/canonicality of escapes is checked by the
   reference validator, not by the schema).

   **Two renderings** (contract 1.1). `value` is the **lossless escaped
   original** described above. `display` is an **ASCII-safe rendering** of
   the same characters: allow-listed characters kept, every other character
   (backslash included) replaced by `?` — e.g. `/cmd_v?l`,
   `/x?SYSTEM:?severity?low…`. It is lossy on purpose (no escapes a model
   could "decode"); schema patterns `^[A-Za-z0-9_/.:?-]*$` (name) and
   `^[ $%+,./0-9:;=?@A-Z^_a-z-]*$` (text). The reference validator decodes
   `value` and requires `display` to be exactly its rendering.

   **Flags** (contract 1.1, always emitted by 1.1 producers):
   `escaped` — at least one character was escaped; `truncated`;
   `non_ascii` — the raw original had a non-ASCII character (legitimate ROS
   names never do); `mixed_script` — letters from more than one script
   (coarse code-point-range heuristic; homoglyph hint); `injection_hint` —
   prompt-injection-looking content (ASCII case-insensitive keywords after
   dropping non-ASCII/control characters: role labels `system:`/`assistant:`/
   `user:`, `ignore`/`disregard`/`instruction`/`prompt`, verdict and field
   words `benign`/`severity`/`status=`/`resolved`/`verdict`, URLs `://`,
   Markdown `](`/`![`, HTML entities `&#`/`&lt`, `</`, `{{ }}`, JSON `":`;
   any line break); `suspicious` — the OR of all of the above, i.e. the value
   was altered on the way out or looks hostile. The hint flags are signals
   only: the allow-list applies whether or not they fire.
4. Length caps are in **characters of the raw input** (= bytes of `display`):
   topic/node/type name/channel 256, GUID 64, IP 64, detail 400. `value` is at
   most 10 bytes per kept character (longest escape `\u{10FFFF}`), i.e. 2560 /
   640 / 4000 B. Within the cap `value` is lossless and the reference
   validator checks that it decodes to `original_len` bytes hashing to
   `original_sha256`. Beyond it, `truncated: true`, both renderings keep the
   first *cap* characters, and the raw `original_len` and `original_sha256`
   are kept for black-box correlation.
5. **No string anywhere in the message** (keys included, trusted fields
   included) contains anything but printable ASCII U+0020–U+007E, nor `<` `>`
   `` ` ``, nor exceeds 4096 B; the whole value is ≤ 64 KiB. Every string in the
   JSON Schema has a `pattern` expressing this (or something stricter), so a
   schema-only consumer rejects raw bidi/format/newline characters and, in
   tainted fields, Markdown/HTML markup.
6. Natural-language instructions ("ignore previous instructions…") are *not*
   filtered (that is undecidable); they survive as inert, tainted data
   (verbatim in `detail`; with spaces and punctuation escaped in ROS-name
   fields, where they cannot be legitimate).

**Consumer obligations:**

* Put tainted values into prompts only inside clearly delimited data blocks,
  never as instructions: prefer `Tainted.display`; use `value` (or tainted
  `resources[]`) when exact identity matters, keeping it escaped (decode only
  for display to a human, never into a prompt). Never render tainted values
  as Markdown/HTML. Treat `suspicious` (and the individual flags) as a
  hostile-name signal; never let a tainted field be the sole basis for a
  *benign* verdict (a verdict with no sensor-field support degrades to
  *uncertain*).
* Map fields per the trust map in §9; in particular a field the map does
  not list is treated as adversary.

**Consumer parsing rules (normative).** A consumer that does
not run `robodr_ocsf::parse_and_validate` must enforce at least these:

* **Reject duplicate object keys** at any depth (including escape-equivalent
  spellings such as `"a"` / `"\u0061"`). JSON parsers disagree on duplicates
  (last-wins, first-wins, error), so a duplicated `title` or `display` could
  show one value to the validator and another to the consumer or to the
  LLM. The reference validator rejects such messages; a consumer must not
  "repair" them.
* **Prompts use `display`, never a re-rendering of `value`.** `display` is
  validated as the exact ASCII-safe rendering of the decoded `value`; feed
  that, delimited as data, to an LLM.
* **Contract 1.0 messages** (legacy, parse-only, §5) carry no `display` and no flags. The reference
  validator rejects any 1.0 message that carries one of the 1.1 tainted-value
  fields (`display`, `non_ascii`, `mixed_script`, `injection_hint`,
  `suspicious`) — present at all, even at a default value — because 1.0 has
  no checks for them and a downgraded `contract_version` would otherwise
  smuggle a forged `display` or a cleared `suspicious`. For an accepted 1.0
  message, treat every tainted value as `suspicious: true` and render it from
  `value` (kept escaped) only. Producers never emit 1.x
  (`robodr_ocsf::validate_for_emit` / `to_json` refuse it).
* **Catalog constants are exact.** `title`, the leading catalog sentence of
  `description`, `finding_info.types` (`["robot_deviation", <data source>]`),
  `finding_info.data_sources` (`[<data source>]`), the ATT&CK lists
  (`mitre_predictions[].technique_id/technique_name`, `attacks[].technique`)
  must be exactly what the rule catalog (`robodr_ocsf::rule_info(rule_id)`)
  gives for `entity_context.rule_id`, and `resources[].labels` must be exactly
  `["taint:adversary"]`. A message with anything else (e.g. prose in
  `types`) is rejected, so these sensor-provenance fields cannot carry
  free text. Data sources: `ros2_dds_discovery`, `ros2_motion_commands`,
  `robodr` (rule not in the catalog), and since 1.3 `robodr_correlation`
  (`robot.correlate.*`), `robot_safety_state` (`robot.safety_state.*`) and
  `robodr_agent` (`robot.agent.*`, `robot.ros2.profile_state_tampered`,
  `robot.ros2.profile_refused`) and `host_runtime`
  (`robot.host.pulsar_threat`: a Pulsar host rule forwarded to agentd; the
  Pulsar rule name is in the detail, since it is not a rule id; since 2.5
  each Pulsar rule RoboDR ships has its own `robot.host.<rule>` id and
  `robot.host.pulsar_threat` is the fallback for any other rule, §3g), and
  since 2.2 `robodr_delivery` (`robot.deliver.*`, the on-unit delivery agent
  `robodr-deliverd`, `docs/SECURE-DELIVERY.md` §9; for these findings
  `entity_context.profile` names the delivery trust file they were judged
  under, version `delivery-trust-<n>` and its digest, not a model profile,
  and the subject is empty: the package and reason are in the tainted
  detail). Since 1.3 every `robot.*` id an in-repo
  detector emits has its own entry (sensor discovery, capture and source
  binding ids under `ros2_dds_discovery`; motion decode, motion monitor and
  firewall ids under `ros2_motion_commands`); `robodr` is left for ids a
  deployment adds. The `catalog_1_3` test of `robodr-ocsf` scans the crate
  sources and fails on an emitted id without an entry.
  Techniques: T0848 Rogue Master, T0855 Unauthorized Command Message, T0801
  Monitor Process State, T0831 Manipulation of Control, and since 1.3 T0856
  Spoof Reporting Message (untrusted safety-state writer). Adding a catalog
  entry is a contract minor bump and needs the validator updated on both
  sides of the diode in step. The validator applies the catalog **of the
  message's own `contract_version`** (`robodr_ocsf::rule_info_for_contract`):

  | `contract_version` | catalog applied |
  | --- | --- |
  | 1.0 – 1.2 | base catalog |
  | 1.3 – 1.x, 2.0 | base + the 1.3 entries, exactly as 1.3.0 shipped (2.0 did not change the catalog) |
  | 2.1 | + the 2.1 entries: the low-level joint-frame firewall ids (`robot.firewall.joint_*`, `disabled_motor_energised`, `crc_invalid`), `robot.motion.api_id_out_of_range`, `robot.motion.control_handover`, `robot.motion.command_type_mismatch` and the Unitree legacy-UDP ids `robot.unitree.legacy_unknown_sender`, `legacy_sender_flood`, `legacy_sender_mac_mismatch`, `legacy_port_rtps`, and agentd's discovery-flood aggregate `robot.ros2.discovery_flood` (§10, 2.1.0) |
  | 2.2 | everything of 2.1 (`robot.ros2.discovery_flood` included, unchanged) + the 2.2 entries: the secure-delivery ids `robot.deliver.installed` (Low: the contract has no informational severity), `deferred_safety` (Low, Medium when repeated), `health_failed` (High), `rollback_blocked_floor` (Critical), `refused` (High), `stale` (Medium, High after the grace period), `chain_gap` (High), data source `robodr_delivery`, no techniques; titles and catalog sentences in §3a |
  | 2.5 and later | everything of 2.4, unchanged (`robot.host.pulsar_threat` included) + the 2.5 entries of §3g: `robot.agent.health` (Low), `robot.agent.credential_expiring` (Medium / High), `robot.agent.clock_unsynced` (Medium), `robot.agent.clock_jump` (High), `robot.agent.disk_low` (Medium / High), `robot.agent.executor_unreachable` (High), `robot.agent.restart_pending` (Medium), `robot.agent.executor_pause_overridden` (High), `robot.agent.evidence_retention_pressure` (Medium / High), `robot.agent.evidence_unexported_dropped` (Medium / High), `robot.agent.control_plane_request_fenced` (Low), `robot.agent.control_plane_saturated` (Medium), `robot.agent.selftest` (Low), `robot.agent.config_unattested` (High), data source `robodr_agent`; `robot.capture.unsupported_transport` (Medium), `robot.ros2.untrusted_security_identity` (Medium / High), data source `ros2_dds_discovery`; `robot.gateway.overload` (Medium / High), data source `ros2_motion_commands`; one `robot.host.<rule>` per shipped Pulsar rule, data source `host_runtime`; no techniques |
  | 2.4 | everything of 2.3, unchanged + the 2.4 agentd entries `robot.agent.control_plane_state_untrusted` (High / Critical), `robot.agent.executor_revert_failed` (High), `robot.agent.executor_journal_reset` (High), data source `robodr_agent`, no techniques (§3f) |
  | 2.3 | everything of 2.2, unchanged + the 2.3 in-path gateway entries (`robot.gateway.*`, data source `ros2_motion_commands`, no techniques; §3b) and the sealing entries `robot.seal.unseal_failed` (High), `robot.seal.lease_expired` (Medium), `robot.seal.erased` (Critical), `robot.seal.tamper` (Critical), data source `robodr_delivery`, no techniques (§3c), and the Unitree WebRTC entries `robot.unitree.webrtc_*`, data source `ros2_motion_commands`, no techniques (§3d), and the depot entries `robot.depot.import_refused` (High), `robot.depot.enrolment_refused` (High), `robot.depot.unit_enrolled` (Low), `robot.depot.rollout_halted` (High), `robot.depot.locked` (Critical) and `robot.seal.erase_deferred` (Medium), data source `robodr_delivery`, no techniques (§3e) |

  A finding of an older minor for a rule that only gained an entry in a
  later minor carries the generic entry and stays valid; a finding of that
  later minor must carry the new entry, and relabelling either way is
  rejected.
  Any `robot.correlate.*` id without its own entry (a deployment's custom
  correlation rule) gets the generic correlation entry.

## 3a. Rule catalog 2.2: secure delivery (`robot.deliver.*`)

The complete 2.2 addition, as `robodr_ocsf::rule_info_for_contract` applies
it to a message whose `contract_version` is 2.2.x (or later 2.x). Every
entry has:

* **data source** `robodr_delivery`: `finding_info.data_sources` is
  exactly `["robodr_delivery"]`, `finding_info.types` exactly
  `["robot_deviation", "robodr_delivery"]`;
* **techniques: none.** `mitre_predictions` and `attacks` are empty
  lists (a delivery event is evidence of what changed on the unit, not
  an attributed ATT&CK technique); a message that lists any technique
  for these ids is rejected;
* **producer** `robodr-deliverd` only (agentd's spool, §1);
* **profile** (`entity_context.profile`): the delivery trust file the
  finding was judged under, `version` `delivery-trust-<n>` and its
  `sha256` digest (`delivery-trust-none` and 64 zeros before any trust
  file was accepted), not a model profile;
* **subject**: empty; the package, serial and reason travel only in the
  tainted `detail` (SR-TAINT, §3), never in the title or the catalog
  sentence of `description`.

| Rule id | `title` (exact) | Severity emitted |
| --- | --- | --- |
| `robot.deliver.installed` | Delivered package installed | Low (catalogue meaning: informational; the contract has no informational severity) |
| `robot.deliver.deferred_safety` | Delivery deferred by the robot's safety state | Low; Medium from the `findings.deferral_medium_after`-th deferral of one item (default 10) and for a deferred rollback |
| `robot.deliver.health_failed` | Delivered package failed its health gate; rolled back | High |
| `robot.deliver.rollback_blocked_floor` | Failed package cannot be rolled back | Critical |
| `robot.deliver.refused` | Delivery refused | High |
| `robot.deliver.stale` | No fresh deployment or trust file | Medium; High after `findings.stale_grace_s` (default 86400 s) |
| `robot.deliver.chain_gap` | Release bundle chain gap or equivocation | High |

Catalog sentence (the leading sentence of `description`, exact):

* `robot.deliver.installed`: The unit's delivery agent installed a release-signed package that a depot and operator quorum assigned to it, and the package passed its health gate. Informational: the evidence trail of what runs on the unit.
* `robot.deliver.deferred_safety`: The unit's delivery agent deferred an install or rollback because the robot's live safety state was not idle or safe-state (moving, human nearby, e-stop or unknown); downloading and staging continue and the install waits for a safe window. Repeated deferrals mean the unit never reaches one.
* `robot.deliver.health_failed`: A package installed by the unit's delivery agent failed its health checks; the agent rolled back automatically to the previous version at or above the anti-rollback floor.
* `robot.deliver.rollback_blocked_floor`: A package installed by the unit's delivery agent failed its health checks and there is no earlier version at or above the anti-rollback floor (or the rollback itself failed); the unit stays on the failing version until an operator acts.
* `robot.deliver.refused`: The unit's delivery agent refused a media pack, deployment or package: a signature, quorum, revocation, floor, scope (unit, ring, site), platform or hash check failed, or its state had to be restored. Nothing was installed from it.
* `robot.deliver.stale`: The unit's newest deployment or its site trust file expired without a fresh one arriving: updates or revocations may be withheld from the unit.
* `robot.deliver.chain_gap`: The unit's delivery agent saw a release bundle that skips bundles it never received, or two different bundles with the same sequence number, or one that does not follow the accepted bundle.

Reasons a `robot.deliver.refused` finding names in its detail (the code
before the first `:`; informational for the SOC, not validated): the
import and item codes of `robodr_pkg::Code` (`bad_signature`,
`quorum_not_met`, `revoked_key`, `revoked_rpk`, `below_floor`,
`wrong_scope`, `expired`, `digest_mismatch`, `file_mismatch`,
`unexpected_file`, `missing_file`, `invalid`, `unsupported`, ...), and
the agent's own: `equivocation` (a serial already on the unit with other
content), `state_restored` (the state file was missing or behind and was
restored from the signed high-water record), `state_lost` (it could not
be restored completely: the unit refuses imports and installs until it is
re-anchored), `highwater_invalid` (the high-water record did not verify).

## 3b. Rule catalog 2.3: in-path gateway (`robot.gateway.*`)

<!-- 2.3 gateway block: keep separate from other 2.3 additions (e.g. robot.seal.*). -->

Added in 2.3 for the in-path Motion Firewall gateway `robodr-firewall-gw`
(Sprint 8). The gateway counts its own decisions per (rule, channel) and
reports one aggregated deviation per housekeeping period (detail: `channel
<name>: <n> time(s) since the last report; first: <reason> (<what>),
value <v>, limit <l>`) to agentd's `gateway_feed` socket; agentd turns
each line into a finding of its normal pipeline (black box, spool,
responder, correlation). The Motion Firewall's own deviations from the
gateway keep their `robot.firewall.*` ids (2.0 / 2.1 entries). Every entry
has data source `ros2_motion_commands` and no techniques.

| Id | Title | Severity |
| --- | --- | --- |
| `robot.gateway.trajectory_rejected` | Joint trajectory blocked by the in-path gateway | High |
| `robot.gateway.trajectory_time_scaled` | Joint trajectory slowed down by the in-path gateway | Medium |
| `robot.gateway.undecodable_command` | Undecodable motion command blocked by the in-path gateway | High |
| `robot.gateway.fragmented_command` | Fragmented motion command blocked by the in-path gateway | Medium |
| `robot.gateway.writer_binding_conflict` | Authorised motion writer seen from another address | High |
| `robot.gateway.sequence_jump` | Motion command sequence jump held back | Medium |
| `robot.gateway.port_bypass_risk` | Motion traffic may bypass the in-path gateway | High |
| `robot.gateway.restriction_changed` | Motion restriction changed on the in-path gateway | Low (informational) |
| `robot.gateway.findings_dropped` | In-path gateway findings lost | Medium |

Catalog sentences (`description`):

* `robot.gateway.trajectory_rejected`: The in-path motion gateway suppressed a ROS 2 joint trajectory or FollowJointTrajectory goal that was outside the channel's bounds: an unknown or repeated joint name, a non-finite value, time not increasing, too many points or too long, or a position, velocity, acceleration or effort beyond its joint limit. It never reached the robot.
* `robot.gateway.trajectory_time_scaled`: The in-path motion gateway forwarded a ROS 2 joint trajectory slowed down in place, because its velocities or accelerations exceeded the channel's limits; the path is unchanged.
* `robot.gateway.undecodable_command`: The in-path motion gateway could not decode a sample of an enforced motion channel strictly (truncated, non-canonical or unsupported encoding) and decided it as an integrity failure: it was suppressed or replaced by the firewall's substitute.
* `robot.gateway.fragmented_command`: The in-path motion gateway suppressed a fragmented, key-only or non-standard RTPS sample of an enforced motion channel, or of a writer it could not classify or knew only as writing another topic; such a sample cannot be decided in place.
* `robot.gateway.writer_binding_conflict`: The in-path motion gateway received samples under an authorised writer's GUID from another source address or MAC than the one the writer's stream is bound to, while the bound side was live: a spoofing attempt, suppressed.
* `robot.gateway.sequence_jump`: The in-path motion gateway held back a sample whose RTPS sequence number jumped far past the writer's stream until the writer confirmed it: a forged high sequence number could otherwise make the robot drop the genuine commands.
* `robot.gateway.port_bypass_risk`: DDS discovery announced a locator on a UDP port the in-path motion gateway does not inspect: commands sent there would reach the robot unchecked until the gateway's port ranges are fixed.
* `robot.gateway.restriction_changed`: A restrict_motion restriction was applied, changed, lifted or expired on the in-path motion gateway. Informational: the evidence trail of the robot's effective motion limits.
* `robot.gateway.findings_dropped`: The in-path motion gateway had more distinct findings in one reporting period than it can hold; some were counted but not reported individually.

Reasons a `robot.gateway.trajectory_rejected` finding names (`first:`):
`unknown_joint`, `duplicate_joint`, `too_many_points`, `no_joints`,
`point_shape`, `non_finite`, `negative_time`, `time_not_increasing`,
`too_long`, `position`, `velocity`, `acceleration`, `effort`,
`tolerance`, `time_scale_failed`.

<!-- end of the 2.3 gateway block -->
## 3c. Rule catalog 2.3: sealing (`robot.seal.*`)

The 2.3 addition for captured-unit software protection
(`docs/SECURE-DELIVERY.md` §7, §9; Sprint 13c), as
`robodr_ocsf::rule_info_for_contract` applies it to a message whose
`contract_version` is 2.3.x (or later 2.x). Like §3a: data source
`robodr_delivery` (`finding_info.data_sources` exactly
`["robodr_delivery"]`, `types` exactly `["robot_deviation",
"robodr_delivery"]`), no techniques, producer `robodr-deliverd`. Other
2.3 additions are documented in their own section (§3b).

| Rule id | Title | Severity emitted |
| --- | --- | --- |
| `robot.seal.unseal_failed` | Unit could not unseal delivered software | High |
| `robot.seal.lease_expired` | Site lease expired | Medium (catalogued; emitted from Sprint 14b, which adds the lease) |
| `robot.seal.erased` | Crypto-erase of delivered software executed | Critical |
| `robot.seal.tamper` | Enclosure tamper or erase trigger fired | Critical |

Catalog sentences (`finding_info.desc`):

* `robot.seal.unseal_failed`: The unit's TPM refused to release the key of a sealed (encrypted) delivered package: the boot measurements do not match the signed PCR policy, the policy was revoked, or the unit's sealing keys were crypto-erased. The package stays unreadable on the unit; RoboDR detection keeps running.
* `robot.seal.lease_expired`: The unit's site lease for unsealing delivered software expired: sealed packages become unavailable after its next reboot until a fresh lease is issued.
* `robot.seal.erased`: The unit's sealing keys were cryptographically erased (the TPM erase epoch moved on, or the fallback key and volume keyslots were destroyed), with the trigger named in the finding. Every sealed package on the unit is permanently unreadable; recovery is re-enrolment and re-delivery.
* `robot.seal.tamper`: An enclosure tamper input or another crypto-erase trigger fired on the unit; a crypto-erase of its sealing keys follows.

The detail of `robot.seal.unseal_failed` starts with the reason
(`policy_refused` or `erased`, before the first `:`); that of
`robot.seal.erased` names the trigger (`operator`, `tamper`, ...). A wrap
that does not authenticate (tampered, or another unit's) is not a sealing
finding but a `robot.deliver.refused` with reason `unauthentic_key`.

## 3d. Rule catalog 2.3: Unitree WebRTC sessions (`robot.unitree.webrtc_*`)

<!-- 2.3 Unitree block: keep separate from the other 2.3 blocks (§3b, §3c). -->

The 2.3 addition for Go2 WebRTC control sessions
(`robodr-ros2-pipeline::webrtc`; reported by the in-path gateway's
`webrtc` section through agentd's `gateway_feed`, channel `webrtc`), as
`robodr_ocsf::rule_info_for_contract` applies it to a message whose
`contract_version` is 2.3.x (or later 2.x). Data source
`ros2_motion_commands`, no techniques. The session content is DTLS-SRTP
encrypted and never inspected: these findings say who holds a WebRTC
session with the robot and when, not what it commands. Details name the
peer and its flows (`peer ip:port <-> robot ip:port`).

| Rule id | Title | Severity emitted |
| --- | --- | --- |
| `robot.unitree.webrtc_unknown_controller` | WebRTC control session from an unlisted host | High (attempt), Critical (established) |
| `robot.unitree.webrtc_new_peer` | New WebRTC peer of the robot | Medium |
| `robot.unitree.webrtc_controller_mac_mismatch` | Listed WebRTC controller seen with another link-layer address | High |
| `robot.unitree.webrtc_session_in_denied_window` | WebRTC control session during a denied window | High |
| `robot.unitree.webrtc_concurrent_sessions` | More concurrent WebRTC control sessions than allowed | High |
| `robot.unitree.webrtc_relayed_session` | Remote WebRTC session through a relay | Medium |
| `robot.unitree.webrtc_media_without_signalling` | WebRTC session without observed signalling | Medium |

Catalog sentences (`finding_info.desc`): see
`catalog_2_3_unitree` in `crates/robodr-ocsf/src/builder.rs` (one per id,
in the same order as the table).

<!-- end of the 2.3 Unitree block -->

## 3e. Rule catalog 2.3: site depot and executed erase (`robot.depot.*`)

The 2.3 addition of the site depot and the executed crypto-erase
(`docs/SECURE-DELIVERY.md` §5, §7.6, §8, §9; Sprints 14a / 14b), in a
block of its own (`catalog_2_3_depot` in `robodr-ocsf`), as
`robodr_ocsf::rule_info_for_contract` applies it to a message whose
`contract_version` is 2.3.x (or later 2.x); a 2.2 validator, and a 2.3
validator given a 2.2 message, apply the generic entry. Like §3a: data
source `robodr_delivery` (`finding_info.data_sources` exactly
`["robodr_delivery"]`, `types` exactly `["robot_deviation",
"robodr_delivery"]`), no techniques. Producers: `robodr-depot` for
`robot.depot.*` (its `robot` is the depot's `depot_id`; written into the
agentd spool of the depot box with `robodr-deliverd`'s writer) and
`robodr-deliverd` for `robot.seal.erase_deferred`.

| Rule id | Title | Severity emitted |
| --- | --- | --- |
| `robot.depot.import_refused` | Depot refused a release bundle | High |
| `robot.depot.enrolment_refused` | Depot refused a unit enrolment | High |
| `robot.depot.unit_enrolled` | Unit enrolled at the depot | Low |
| `robot.depot.rollout_halted` | Staged rollout halted | High |
| `robot.depot.locked` | Depot database failed its anti-rollback check | Critical |
| `robot.seal.erase_deferred` | Crypto-erase deferred by the safety state | Medium |

Catalog sentences (`finding_info.desc`):

* `robot.depot.import_refused`: The site depot refused to import a release bundle: no passing entry-station report for exactly that bundle, a signature, quorum, chain, revocation, floor or hash check failed. Nothing of the bundle can be deployed.
* `robot.depot.enrolment_refused`: The site depot refused to enrol a unit: its EK certificate does not chain to a TPM vendor CA the site trusts, the attestation key or a certified key is not resident in that TPM, the unit's keys are not bound to the site's policy, its boot measurements do not match the signed policy, or the credential challenge was not answered by the unit's TPM. No key is wrapped for it.
* `robot.depot.unit_enrolled`: A unit was enrolled at the site depot after TPM credential activation and the operator quorum; the depot may now deliver and wrap keys for it.
* `robot.depot.rollout_halted`: A unit of the current ring reported a failed health gate or a refusal beyond the rollout's failure threshold; the site depot halted the rollout and serves nothing more of it until operators resume it.
* `robot.depot.locked`: The site depot's database is older than its TPM anti-rollback counter says, or the counter was recreated: the database was restored or replaced. The depot signs, serves and imports nothing until operators re-anchor it.
* `robot.seal.erase_deferred`: A crypto-erase trigger fired, and the responder deferred the erase because the robot is moving (or its safety state is unknown); it runs as soon as the robot is idle or its safety system holds it.

`robot.seal.lease_expired` (§3c) is emitted from Sprint 14b: Medium, once
per reason, while a sealed item waits for a site lease. The executed erase
reports `robot.seal.tamper` and `robot.seal.erased` as in §3c, with
`robot.seal.erase_deferred` between them when the robot was moving.

## 3f. Rule catalog 2.4: control-plane state and executor (`robot.agent.*`)

The 2.4 addition (`catalog_2_4` in `robodr-ocsf`), as
`robodr_ocsf::rule_info_for_contract` applies it to a message whose
`contract_version` is 2.4.x (or later 2.x); a 2.3 validator, and a 2.4
validator given a 2.3 message, apply the generic entry. Data source
`robodr_agent` (`finding_info.data_sources` exactly `["robodr_agent"]`),
no techniques, producer `robodr-agentd` (self-health, observe-only: these
never feed a response).

| Rule id | Title | Severity emitted |
| --- | --- | --- |
| `robot.agent.control_plane_state_untrusted` | Control-plane state failed its integrity check | High (damaged, edited, another key); Critical (rolled back against the black box's signed head, or an unsealed v1 file after sealing started) |
| `robot.agent.executor_revert_failed` | Containment action could not be reverted | High |
| `robot.agent.executor_journal_reset` | Executor journal untrusted and reset | High |
| `robot.agent.executor_pause_overridden` | Robot set moving while paused (added in **2.5**, listed here with its executor siblings; a 2.4 validator applies the generic entry) | High |

Catalog sentences (`finding_info.desc`):

* `robot.agent.control_plane_state_untrusted`: At start the control plane's sealed request journal or replay store was damaged, edited, sealed under another key, or older than the head the black box recorded for it. The robot failed safe: the damaged copy was quarantined, requests were reconciled with the black box and the replay store was fenced; nothing was reset silently.
* `robot.agent.executor_revert_failed`: The robot's executor could not revert a containment action: its transaction or read-back failed, so the action's rules may still be in force after its time limit or revert request. The executor retries every tick; the detail names the action, request, time limit and error.
* `robot.agent.executor_journal_reset`: The robot's executor found its journal unreadable or failing its seal and started empty: every action it held was lifted and its history lost. It refuses new orders until an operator re-arms it.
* `robot.agent.executor_pause_overridden`: While a safe_pause the SOC approved was in force, someone set the robot moving again: a navigation goal was sent or the vehicle's flight mode was changed. The executor's latch cancelled the goal or set hold again (a pilot's manual mode is left to the pilot); the pause stays in force until the SOC's two-person signed revert. The detail names the request and what was found.

`robot.agent.control_plane_state_untrusted` is raised once per agentd start;
`robot.agent.executor_revert_failed` once per request until a revert of it
succeeds (the executor reports every retry as a black-box note); the
detail of each names what failed. Each is also in the black box (the
finding record, and the `robodr.executor_event` or
`robodr.control_plane_start` note).

## 3g. Contract 2.5: agent health record, early warnings, commissioning binding, DDS transports and SROS 2 identities, per-rule host ids

The 2.5 addition (`catalog_2_5` in `robodr-ocsf`), applied as in §3 to a
message whose `contract_version` is 2.5.x or a later 2.x. A 2.4 validator,
and a 2.5 validator given a 2.4 message, apply the generic entry to these
ids. No techniques. Producer `robodr-agentd` unless noted; every
`robot.agent.*` finding is self-health and observe-only (never feeds a
response).

| Rule id | Title | Severity emitted | Raised |
| --- | --- | --- | --- |
| `robot.agent.health` | Agent health record | Low | every `daemon.self_health.health_record_ms` (default 60 s), carries `entity_context.agent_health` |
| `robot.agent.credential_expiring` | Agent credential expires soon | Medium (≤ `credential_warn_days`, default 14); High (≤ `credential_critical_days`, default 3, or expired) | per credential on each escalation, then at most daily |
| `robot.agent.clock_unsynced` | Robot clock not synchronised | Medium | once per episode, after the kernel has reported the clock unsynchronised for `clock_unsynced_grace_ms` (default 5 min); never where `adjtimex(2)` is refused, as under the shipped systemd unit (`clock.adjtimex_errno`, `docs/TIME-SYNC.md`) |
| `robot.agent.clock_jump` | Robot wall clock jumped | High | per wall-clock jump against the monotonic clock (> 1 s), at most every `health_report_ms` |
| `robot.agent.disk_low` | Agent storage running out of space | Medium (free < `disk_warn_percent`, default 10 %); High (free < `disk_critical_percent`, default 3 %) | per filesystem on each escalation |
| `robot.agent.executor_unreachable` | Response executor unreachable | High | once per outage, after `executor_unreachable_ms` (default 30 s) without an answer |
| `robot.agent.evidence_retention_pressure` | Unexported black-box evidence filling the retention | Medium; High from 95 % | once per episode when unexported segments reach `blackbox.retention.warn_percent` of the capacity (pending-export reserve or saturation mode); formerly `robot.agent.evidence_degraded` with detail `retention pressure:` |
| `robot.agent.evidence_unexported_dropped` | Unexported black-box evidence dropped | High (the pending-export reserve was used up); Medium (plain cyclic retention, `blackbox.retention.export` `expected`, or `auto` once an export cursor exists) | High on every new drop; Medium at most once a day with the count since the last report; formerly `robot.agent.evidence_degraded` with detail `unexported evidence dropped:` |
| `robot.agent.control_plane_request_fenced` | Control-plane request refused by the replay fence | Low | when correctly signed control-plane requests were refused by the replay fence (not counted as authentication failures), at most every `health_report_ms` |
| `robot.agent.control_plane_saturated` | Control-plane connections refused or cut before authentication | Medium | when control-plane connections were refused at accept or cut before they authenticated (`connections_rejected`, `connections_evicted`), at most every `health_report_ms` |
| `robot.agent.restart_pending` | Upgraded components still on the previous binaries | Medium | once `/var/lib/robodr/pending-restart` (written by the package's maintainer scripts, removed by `install-bundle.sh` after the gated restart) names `robodr-firewall-gw` or `robodr-executor` and is `restart_pending_grace_ms` old (default 15 min), again when the units it names change, then at most daily while it stays; also when the file exists but cannot be read |
| `robot.agent.selftest` | Agent field acceptance self-test | Low | `robodr-agentd`: once per operator request (`robodr-agentd selftest`, at most one per second); the detail carries the request's nonce |
| `robot.gateway.overload` | In-path gateway overloaded | Medium; High from the gateway's `overload_high_late` late or shed packets in one interval (default 1000) | `robodr-firewall-gw`: at most once per `overload_interval_ms` (default 60 s) while packets are read later than `max_queue_delay_ns` or are shed (gaps in the NFQUEUE packet ids: queued by the kernel, never delivered to the gateway); the gateway no longer reports late packets as `robot.firewall.internal_fault` |
| `robot.agent.config_unattested` | Safety configuration not bound to the commissioning | High | once per file at agentd start (response policy, Motion Firewall joint configuration claiming more than the signed commissioning); with the executor link, once per robodr-executor `commissioning` event (the executor journals its commissioning notes at start and whenever they change) that reports a flag it does not honour or its `commissioning` section removed or changed at runtime, and for its UNSIGNED-flags note when the trusted profile binds `response_policy` or `executor_motion` |
| `robot.capture.unsupported_transport` | DDS transport not inspected (shared memory, TCP) | Medium | producer `robodr-ros2-pipeline`, data source `ros2_dds_discovery`; one per host and transport set, rate limited like every `robot.capture.*` rule |
| `robot.ros2.untrusted_security_identity` | Participant outside the robot's SROS 2 keystore | Medium (unauthenticated where the governance requires authentication); High (certificate subject named by no grant) | producer `robodr-ros2-pipeline` with an SROS 2 policy, data source `ros2_dds_discovery` |
| `robot.host.<rule>` | the Pulsar rule's name without its `RoboDR: ` prefix | the Pulsar rule's | per Pulsar threat (data source `host_runtime`) |

Catalog sentences (`finding_info.desc`):

* `robot.agent.health`: Periodic health and liveness record of the robot's RoboDR agent: monitoring state, component versions, input freshness, counters, black-box state, reachability of the executor, gateway and host sensor, credential expiry, clock synchronisation and free disk space. A robot whose newest record is older than a few record periods is silent.
* `robot.agent.credential_expiring`: A certificate or certificate revocation list the robot's agent depends on expires or reaches its next-update time soon (or already has): renew it before the control plane refuses every SOC client.
* `robot.agent.clock_unsynced`: The robot's kernel reports its wall clock unsynchronised (no NTP, NTS or PTP lock) or with a large error estimate: finding and evidence times may be wrong.
* `robot.agent.clock_jump`: The robot's wall clock moved away from what its monotonic clock says elapsed (a time step, an RTC reset or a spoofed time source). Durations are unaffected; finding and evidence times around the jump may be wrong.
* `robot.agent.disk_low`: A filesystem the robot's agent writes evidence, findings or control-plane state to is nearly full: free space before recording stops.
* `robot.agent.executor_unreachable`: The robot's agent cannot reach its response executor: containment actions cannot be applied, verified or reverted, and actions in force are not watched, until it answers again.
* `robot.agent.evidence_retention_pressure`: Black-box evidence that no export has confirmed yet fills most of the retention the robot's agent was configured with (pending-export reserve or saturation mode): run or repair the export (diode, media) before the oldest unexported evidence is dropped or new records are refused.
* `robot.agent.evidence_unexported_dropped`: Cyclic retention dropped black-box segments holding records that no export had confirmed (each drop is a signed SegmentDropped record): that evidence is no longer on the robot. Recording itself works; check the export path and the retention sizing.
* `robot.agent.restart_pending`: A package upgrade left the robot's in-path motion gateway or response executor running the binaries of the release before it (their restart waits for the safety-state gate): the installed release and its security floor are not what runs until they are restarted. The detail names the units and how long they have been pending.
* `robot.agent.control_plane_request_fenced`: A correctly signed control-plane request was refused because it was signed at or before the replay fence the agent set after a restart or a state repair; it was not judged or executed. The SOC should re-sign and resend it.
* `robot.agent.control_plane_saturated`: The robot's control-plane listener refused or cut connections before they authenticated because every slot they could use was busy: a TLS handshake flood or slowloris against the API, or more legitimate clients than its connection limit. SOC requests may fail until it ends; nothing was judged or executed.
* `robot.agent.selftest`: A marked self-test finding the robot's agent produced on an operator's request to prove the path from the agent to the SOC end to end; it reports no detection.
* `robot.gateway.overload`: The in-path motion gateway could not process every command in time over the last interval (late or shed packets, aggregated): commands were delayed or dropped by its fail behaviour. Not a gateway fault.
* `robot.agent.config_unattested`: A safety configuration file the robot's agent or executor loaded (response policy, Motion Firewall joint configuration, the executor's motion section) claims more than the signed commissioning attested. Either it is not bound to the trusted locked profile, so it is treated as not validated and stays observe-only for what it governs; or the executor's commissioning settings were removed or changed while it ran (it keeps verifying against the ones it started with until a restart); or, on a unit whose profile binds the executor's files, the executor runs without commissioning settings and honours its validation flags unsigned. The detail names the file or setting and why.
* `robot.capture.unsupported_transport`: Participants on a host advertise a DDS transport the capture cannot inspect (shared memory such as Fast DDS SHM or Cyclone Iceoryx, TCP, or an unknown locator kind): traffic between same-host processes over it never reaches a network interface, so motion commands there may be invisible. Commission the robot with UDP-only transports.
* `robot.ros2.untrusted_security_identity`: A DDS participant's security identity does not fit the robot's SROS 2 keystore: it is unauthenticated while the governance requires authentication, or its certificate subject is named by no grant of the keystore (a participant from another keystore or CA).
* every `robot.host.<rule>`: A RoboDR runtime-security rule fired on the robot controller (process, file or network activity of the host operating system, seen by Pulsar); the finding's rule id names the rule, the detail names the process.

**Per-rule host ids.** The table is `robodr_ocsf::HOST_RULES` (Pulsar
rule name → id), checked against `rules/robodr/*.toml` in both directions
by the `host_rules` test of `robodr-ocsf`. The match is exact on the rule
name; a Pulsar rule RoboDR does not ship (a deployment's own) keeps
`robot.host.pulsar_threat`. An id is never renamed or reused: a renamed
Pulsar rule keeps its id. Because the id differs, a 2.5 finding for a host
rule has a different `finding_id` than the 2.4 `robot.host.pulsar_threat`
finding for the same process: a SOC that grouped on that id should group
on `data_source = host_runtime` instead. A response policy's
`rule_overrides[]` can now name one host rule.

**`entity_context.agent_health`** (and its copy under
`ocsf.unmapped.robodr`) is present exactly on a 2.5+ `robot.agent.health`
finding; the validator refuses it on any other rule or minor and refuses a
2.5 health finding without it. Every value is sensor-authored (agentd's own
counters and configuration), printable ASCII, never tainted. Lists hold at
most 16 entries, reasons at most 256 bytes, names and versions 1 – 128
bytes (`robodr_ocsf::health_limits`):

| Field | Meaning |
| --- | --- |
| `state` | `ok` \| `degraded` \| `unknown`, as in agentd's `status.json` (`unknown`: the agent is blind) |
| `reasons[]` | why the state is not `ok` |
| `interval_ms` | the record period: a SOC alerts when the newest record (`ocsf.time`) is older than about three periods |
| `uptime_ms`, `seq` | since agentd started; `seq` counts records from 1, so a restart is visible |
| `versions[]` | `{component, version}`: `robodr-agentd` and the contract it emits |
| `inputs[]` | `{name, last_rx_age_ms?, received, dropped, malformed, ended}` per input |
| `counters` | `findings_spooled`, `finding_errors`, `health_findings`, `spool_dropped`, `spool_write_errors`, `note_errors` |
| `blackbox` | `{degraded, anchored, anchor_failures}` |
| `reachability[]` | `{component, state, last_ok_age_ms?}` for `executor`, `gateway` (the in-path gateway's feed) and `pulsard` (the host-threat forwarder): `reachable` \| `unreachable` \| `unknown` (configured, not heard yet) \| `not_configured`; a component fed by several inputs reports its worst input, and `last_ok_age_ms` is that input's |
| `credentials[]` | `{name, expires_ms, days_to_expiry}`: the control plane's server certificate (`control_plane.server_cert`) and each CRL's `nextUpdate` (`control_plane.crl:<issuer>`) |
| `clock` | `{synchronized?, max_error_ms?, source?, adjtimex_errno?, timesync_age_ms?, wall_jumps}`: `synchronized` / `max_error_ms` from `adjtimex(2)` (`source` `adjtimex`); where that call fails, `adjtimex_errno` (1 = `EPERM`, the shipped unit's `@clock` seccomp filter) and, if systemd-timesyncd touched `/run/systemd/timesync/synchronized` within 4 096 s, `synchronized: true` with `source` `timesyncd` (no error estimate; an older or absent marker leaves `synchronized` out); `timesync_age_ms` is that marker's age; `wall_jumps` from agentd's time guard |
| `disks[]` | `{name, free_bytes, total_bytes}` for `blackbox`, `spool` and `control_plane` |

The profile digest and the safety state are the finding's own
`entity_context.profile` and `entity_context.safety_state`. The record is
one finding per robot (fixed subject): each period is an *Update* of the
same `finding_id` with a higher `count`, so a SOC upserts it and reads
`last_seen_time` as the robot's last sign of life. Like every finding it is
signed when `finding_signing` is configured (§2a), recorded in the black
box, and exported on every path (Kafka, HTTPS uplink, diode) unchanged.

## 4. Ordering and partitioning

* Partition = `toPositive(murmur2(utf8(robot_id))) % partitions` — Kafka's
  default-partitioner hash, but applied to the **robot id**, not to the record
  key, and set explicitly on the record (`robodr_ocsf::partition_for`).
  All findings of one robot are therefore totally ordered on one partition,
  while the key stays the `finding_id` for compaction-style tooling and lookups.
* Producer settings: `acks=all`, `enable.idempotence=true`,
  `max.in.flight.requests.per.connection ≤ 5` (ordering-safe with idempotence).
* Changing the partition count re-maps robots; do it only with consumers
  drained, or accept a one-off reordering window per robot.
* Ordering across robots is not guaranteed and not needed: cross-robot
  correlation uses `ocsf.time`.

## 5. Versioning and compatibility

* `contract_version` is semver; the major version is in the schema `$id`
  (`https://schemas.singularityrd.com/robodr/findings/<version>`).
* **Minor** (2.x): add *optional* fields or catalog entries only; never
  change meaning, type or enum values of an existing field; never make a
  field required. Consumers must ignore unknown fields (the reference
  validator does, but still applies the SR-TAINT string rules to them).
  The validator applies the rule catalog of the message's own minor (§3).
* **Major** (3.0): anything else — removing/renaming fields, new required
  fields, changing id derivation (`rf1-`/`re1-` prefixes encode the
  derivation version), changing the OCSF class. Produce a new major in
  parallel (e.g. a new topic) until consumers migrate.
* `ocsf.metadata.version` moves independently; upgrading the OCSF version
  inside the envelope is a minor change only if it is additive for consumers.
* **2.0 vs 2.1 vs 2.2 vs 2.3 vs 2.4 vs 2.5.** 2.1 – 2.4 only added
  rule-catalog entries (§3; 2.2 also the data source `robodr_delivery` they
  use); 2.5 added entries and the optional `entity_context.agent_health`
  object (§3g). A 2.5 validator accepts 2.0 – 2.4 messages with their own catalogs; an older
  validator accepts a newer message for every rule both catalogs share and
  rejects one for a rule only the newer minor catalogues (title / data
  source differ): upgrade consumers (and both sides of a diode) before
  producers. Sites that run `robodr-deliverd` need 2.2 validators on the
  SOC side before its findings are exported, and 2.3 validators once it
  installs sealed RPKs (`robot.seal.*`). An agentd that emits 2.4
  (`robot.agent.control_plane_state_untrusted`, `executor_revert_failed`,
  `executor_journal_reset`) needs 2.4 validators on the SOC side, and one
  that emits 2.5 (the health record, the early warnings and the per-rule
  host ids) 2.5 validators: an older validator rejects those findings (their
  catalog entry differs), so upgrade the SOC side and both sides of a diode
  first.
* **Producer cap** (`findings.max_contract_minor` in `robodr-agentd`'s
  configuration, `RobotContext::max_contract_minor` in `robodr-ocsf`): a
  robot whose SOC still validates an older minor `m` (0 ≤ `m` ≤ the
  current minor) builds every finding in the wire format of contract
  `2.m.0`, which a validator of that minor accepts: `contract_version` is
  `2.m.0`; the catalog of minor `m` applies, so an id catalogued later
  carries the generic entry (title "RoboDR model-profile deviation", data
  source `robodr`, no techniques) under its own rule id; below 2.5 a
  per-rule host id is sent as `robot.host.pulsar_threat` (with that id's
  finding identity; the detail still names the Pulsar rule) and
  `entity_context.agent_health` is left out. This is not what a producer
  of minor `m` sent: such a producer never emitted the ids catalogued
  after `m`, while a capped agentd still sends them (for example
  `robot.agent.disk_low` or `robot.agent.clock_jump` below 2.5), under
  the generic title, so a SOC rule must match them by `rule_id`, not by
  title. The one exception is the periodic `robot.agent.health` record:
  below 2.5 agentd does not send it (`daemon.self_health.health_record_ms`
  is treated as 0, the start-up log says so and `status.json` shows
  `health_record_ms` 0), because it would be a Low finding every period
  titled as a deviation that reports none. A cap above this build's minor
  is refused at load. `robodr-deliverd` has the same setting
  (`findings.max_contract_minor` in its configuration, same bounds);
  give it the same value as agentd's, since both write into the same
  spool. Its `robot.deliver.*` and `robot.seal.*` entries are 2.2 / 2.3
  ones, so a cap below 2 (or below 3 for `robot.seal.*`) sends them
  under the generic entry.
* **What 2.0 changed from 1.3** (`robot-edr.findings`): `data_source` is no
  longer the constant `robot_edr` but a deployment label (default
  `robodr`); the topic is no longer fixed to `robot-edr.findings` but
  configured (default `robodr.findings`) and named in
  `ocsf.metadata.log_name`; the `data-source` header follows the value. The
  field set, identity derivation, SR-TAINT rules, signature scheme and the
  OCSF body are unchanged. The dedup key changes with `data_source`, hence
  the major bump.
* **1.x is parse-only, and upgraded where that is safe.** The reference
  validator accepts `1.y.z` messages with their fixed 1.x constants
  (`data_source` `robot_edr`, `log_name` `robot-edr.findings`) and the 1.x
  rules of their minor, so stored 1.x findings can still be read and
  verified; `to_json` and `record` never emit them. Findings in flight
  during an upgrade are **upgraded** to contract **2.0.0**
  (`robodr_ocsf::upgrade_legacy`): `contract_version`, `data_source` and
  `ocsf.metadata.log_name` are relabelled and nothing else changes — none
  of the three is an input of `finding_id` (`rf1-`: robot id, rule id,
  subject) or `ocsf.metadata.uid` (`re1-`: finding id, `last_seen_time`,
  `count`), so identity and dedup are preserved — and the result must
  validate in full as 2.0 (the 2.0 catalog is exactly the 1.3 one), else
  it is refused. A **signed** 1.x record is never upgraded (the signature
  covers the exact 1.x bytes): the spool exporter and the publisher keep it
  with the reason "legacy 1.x signed record: re-sign required". The diode
  importer upgrades the findings of a 1.x batch (batch-signed, no
  per-finding signature); an intact 1.x batch that cannot be upgraded is
  quarantined and the unit's chain advances past it (§8). Upgrade
  procedure: `docs/OPERATIONS.md` §7. Any other major is rejected. The 1.x schema is kept at
  [`legacy/robot-edr-finding.schema.json`](legacy/robot-edr-finding.schema.json).

## 6. Size limits

| Limit | Value |
| --- | --- |
| Whole value | 64 KiB (well under Kafka's 1 MiB default `max.message.bytes`) |
| Any string | 4096 B |
| `title` / `description` | 256 B / 2048 B |
| Tainted fields | see SR-TAINT (256 / 64 / 400 characters; `value` ≤ 10 B per character) |
| `evidences` / `evidence_links` | ≤ 64 |
| `mitre_predictions` | ≤ 16 |
| `resources` | ≤ 8 |
| Times | 2000-01-01 ≤ t < 2100-01-01 (rejects unset clocks) |

## 7. Retention (proposal — integrator to confirm)

* `cleanup.policy=delete`, `retention.ms=604800000` (7 days). The topic is a
  transport, not the system of record: findings live in the SOC's cases and
  the control plane; evidence lives in the signed black box (months).
* Partitions: 12 for a fleet deployment; replication 3 (1 on a single-box
  air-gapped install).

## 8. Air-gapped transport (diode export batches)

Defence sites run the console air-gapped; findings may have to cross a
one-way data diode (or controlled removable media) to reach the SOC. **Implemented in `crates/robodr-diode`** (`Packer` / `Importer`,
CLIs `robodr-diode-pack` / `robodr-diode-unpack`; format and limits in that
crate's README). Moving files across the diode and producing the emitted
records to Kafka are outside the crate (no network code).

* **Batch = one directory** `rdd_<unit_id>_<batch_seq, 16 digits>/` holding
  `findings.jsonl` (each value compact JSON, one per `\n`-terminated line,
  validated with `robodr_ocsf::to_json` before packing), optional black-box
  export bundles `bundle-NNNN.rbbx`, optional Reed-Solomon parity files
  `parity-NN.rbpar`, `MANIFEST.json` and `MANIFEST.sig`.
  `unit_id` is the exporting robot or site console (`[A-Za-z0-9._-]{1,64}`).
* **Manifest** (`deny_unknown_fields`, ≤ 128 KiB, ≤ 256 files):
  `{format: "robodr-diode/1", contract_version (`2.y.z`; the importer also
  takes a `1.y.z` batch published before an upgrade and upgrades its
  findings, §5), unit_id, batch_seq (1-based),
  prev_batch_hash, created_at (RFC 3339 ms), created_at_ms, key_id, algorithm,
  finding_count, first_time, last_time, files: [{name, kind, size, sha256}],
  parity?}` (`kind`: `findings` | `blackbox_bundle` | `parity`; `parity`
  only in parity batches, absent otherwise, so batches without parity keep
  the original byte format).
  `first_time`/`last_time` are min/max `ocsf.time`. File names are
  allow-listed (`findings.jsonl`, `bundle-NNNN.rbbx`, `parity-NN.rbpar`); anything with a path
  separator, `..`, a leading dot or upper case is rejected.
* **Signature**: the raw manifest bytes are signed through the black-box
  crate's `Signer` over `"robodr-diode/manifest/v1\0" || manifest`;
  `MANIFEST.sig` = `{format, algorithm, key_id, sig (hex)}`. Batch hash =
  SHA-256(`"robodr-diode/batch-hash/v1\0" || manifest`); each manifest carries
  the previous batch's hash, so batches form a per-unit hash chain. The
  binaries sign with Ed25519 (`ed25519-dalek`, via `robodr-blackbox`)
  and the SOC holds public keys only; legacy HMAC-SHA256 needs an explicit
  `--allow-hmac`. `batch_seq` ≤ 9 999 999 999 999 999 (16 digits).
* **Size bounds**: data bytes per batch (packer default 16 MiB, range
  64 KiB + 1 … 256 MiB) and findings per batch (default 10 000); larger
  inputs are split into several consecutive batches. The importer rejects
  batches above its `max_batch_bytes` (default 256 MiB = the packer's
  ceiling); keep the packer setting ≤ the importer's.
* **Forward error correction (optional, `--parity M`)**: the batch's data
  files (manifest order) and `M ≤ 32` parity files are the shards of a
  systematic Reed-Solomon code over GF(2^8) (`0x11D`, `α = 2`, generator
  roots `α^0…α^(M-1)`, `k + M ≤ 255`; scheme `rs-gf256-0x11d/1`, the QR-code
  RS code, implemented in std). Byte `o` of every file is one codeword; data
  files are zero-padded to the parity length = largest data file rounded up
  to `parity.shard_size`. Parity files are listed and hashed in the signed
  manifest and count against the batch size limit. The importer treats every
  missing / wrong-size / wrong-SHA-256 file as an erasure, rebuilds up to
  `M` of them, installs a rebuilt file only if its size and SHA-256 equal
  the manifest's, and then verifies the batch exactly as an undamaged one
  (report: `accepted[].repaired`). More than `M` damaged files →
  `fec_unrecoverable`; a rebuild missing the manifest hash → `fec_failed`.
* **Low side (export)**: stage in `outbox/.tmp-<batch>/`, `fsync`, commit
  (`next_seq`, chain head) to the packer state file atomically, then `rename`
  into the outbox. The transfer agent must ignore dot-entries. A crash
  between commit and rename is finished on the next start; sequence numbers
  are never reused for different visible content. Each batch is also
  archived (before commit) in `<state>.archive/` (newest 64 by default);
  `robodr-diode-pack resend --seq N` re-emits an archived batch byte for
  byte for manual retransmission, after checking the archive chains to the
  packer state; resending is idempotent.
* **Single instance**: packer and importer each hold an exclusive `flock`
  on `<state>.lock` while running; a second instance on the same state file
  fails with a clear error (exit 1).
* **High side (import)**: authenticate the manifest bytes with the keyring
  key named in `MANIFEST.sig` *before* parsing them; the key must belong to the
  manifest's unit and the directory name must match. Then, per unit:
  `seq = last+1` with the right `prev_batch_hash` → verify every file
  (regular file, no symlink, exact size and SHA-256, no unlisted entries),
  run `robodr_ocsf::parse_and_validate` on every line, parse (and, with a
  black-box key bound to this unit configured, verify) every bundle, and emit
  `out/<batch>/records.jsonl` — one Kafka record per line with the **same**
  topic (the value's `log_name`), key, partition rule and headers as §2/§4 (`{topic, partition, key, headers,
  value, diode: {unit_id, batch_seq, batch_hash, line}}`). If `out/<batch>/`
  already holds a *different* batch's output (after an operator state
  reset), the batch is emitted as `out/<batch>.<hash16>/`; an accepted batch
  is never reported without its own records on disk.
* **Unit binding**: every finding's `entity_context.robot.id` and every
  bundle's `device_id` must be the batch's `unit_id` or on that unit's
  allow-list (keyring line `robots: <unit_id> <robot_id>...`); a bundle
  signed with a black-box key registered for another unit is quarantined.
  A unit's key therefore cannot emit findings or evidence for robots it was
  not authorised to report on.
* **Ordering**: batches are processed in `batch_seq` order. A gap is
  **reported and the later batches held** in the inbox until the missing ones
  arrive (reordering heals itself) or an operator explicitly accepts that gap
  (`--accept-gap unit:seq`, at most `--max-accept-gap` batches, default
  100 000, recorded in the importer state); never silently skipped. Held
  batches older than 30 days and dot-entries older than 24 h (both
  configurable) are quarantined (`held_expired`, `stale_in_transit`). An identical re-send (same batch hash) is a duplicate: verified,
  filed under `processed/`, nothing re-emitted. A different batch for an
  already-used `seq` (conflict), an old `seq` outside the remembered window
  or inside an accepted gap (replay), or a wrong `prev_batch_hash` (chain
  break) is quarantined.
* **Quarantine**: any failed check moves the entry to its own directory
  `quarantine/<unique>/entry` with `quarantine/<unique>/reason.json`
  (`reason.code`, e.g. `bad_signature`, `hash_mismatch`, `size_mismatch`,
  `invalid_finding`, `robot_not_allowed`, `manifest_invalid`, `symlink`,
  `conflict`, `unreadable`, `fec_unrecoverable`, `fec_failed`); importer state does not advance, so an intact
  re-send of the same batch is accepted later (parity repair within a
  batch, then whole-batch retransmission via `resend`, is the forward-error
  strategy). The one exception is `legacy_not_convertible`: an authentic,
  chain-linked (in sequence with the right `prev_batch_hash`, or an
  operator-accepted gap) and intact contract 1.x batch whose findings have
  no valid 2.0 form. A re-send cannot change its content, so the importer
  records its hash as the unit's chain head before quarantining it; the
  next batch must still link to that hash, so the chain's integrity
  (nothing inserted, removed or reordered without the unit's key) is
  unchanged — only that batch's findings are not emitted.
  A failure on one inbox entry (I/O, permissions) is reported per entry and
  never stops the other entries or units from being imported.
* Because `finding_id` and `event-uid` are deterministic, re-publishing an
  already-imported finding remains idempotent for the consumer.
* **Finding signatures (§2a) and the diode — not carried (open item).**
  agentd spools each signed finding with its `robodr-finding-sig` header
  (the spool record *is* the Kafka record), and on a **connected** path
  `robodr-kafka-publish --spool` forwards that header verbatim as the last
  header (shape-checked; a malformed or misplaced signature header is
  dead-lettered). Across the **diode** the signature is dropped:
  `robodr-spool-export` packs the validated values, `findings.jsonl` carries
  values only and the importer re-serialises the parsed value
  (`robodr_ocsf::record`). There the batch is authenticated by
  `MANIFEST.sig` (unit-bound diode key) instead, so SOC consumers behind a
  diode must run the §2a check in `Optional` mode or rely on the importer's
  batch verification. `robodr-uplink --diode-out` (ingest API,
  [`robodr.ingest-api.md`](robodr.ingest-api.md)) therefore sends these
  findings with `"sig":null` under a `relay` key. Carrying it would need a signed per-finding sidecar
  (e.g. `finding-sigs.jsonl` listed and hashed in the manifest) and an
  importer that emits the original value bytes verbatim with the header
  (re-serialisation is byte-identical for builder output today — tested —
  but that is not a contract guarantee); not done in this release.

### 8.1 Exporters (`crates/robodr-export`)

The two hops around the diode are implemented in `crates/robodr-export`
(details and limits in its README):

* **`robodr-spool-export`** (robot side) takes agentd's spool
  `ready/<seq>.json` records in order, re-validates them, packs them with
  `robodr_diode::Packer` (one diode batch per step) and renames them into
  `acked/` only after the batch is committed and renamed into the outbox. An
  intent journal (`{batch_seq, spool_seqs}`) makes a crash at any point
  recoverable without loss; on recovery a record is acknowledged only if it
  is proven to be in a committed batch (its packed line read back from the
  outbox or the packer archive and checked against the manifest), so a
  `pack` that the packer split and that failed half-way never acknowledges
  unpacked records (unprovable ones are packed again: a duplicate, never a
  loss). The binary refuses exporter planner limits that differ from the
  packer's. Records leave `ready/` only by rename (to `acked/`, or to
  `rejected/` if invalid), never by deletion.
* **`robodr-kafka-publish`** (SOC side) publishes the importer's
  `out/<batch>/records.jsonl` (or a connected site's spool) to its
  configured topic (`--topic`, default `robodr.findings`; a record whose
  value names another topic is published there anyway and counted as
  `topic_overridden`, a record whose `topic` disagrees with its own value is
  dead-lettered) with the §2 key and headers (re-derived from the validated value and
  required to match the input; an optional `robodr-finding-sig` header is
  carried verbatim as the last header, §2a) and the §4 partition rule,
  computed with the
  topic's current partition count. CreateTime is the publish time (the
  finding time is `ocsf.time`). Progress is a committed line count kept per
  batch (a bounded map, so interleaved batches never reset each other's
  offsets) replaced atomically after each acknowledged chunk, plus a done
  marker per batch; invalid or broker-rejected records go to a dead-letter
  file, deduplicated on (batch, line) across crashes.
* **`robodr-uplink`** (connected robot / sensor box with `--spool`, or SOC
  side behind the importer with `--diode-out`) sends the same records,
  re-validated the same way, to the AutoSecOps ingest API
  ([`robodr.ingest-api.md`](robodr.ingest-api.md)): signed NDJSON batches
  over TLS, the value verbatim and the `robodr-finding-sig` header as the
  line's `sig`, acknowledged only after a `200` names every line; batch ids
  are derived from the input position and the body, so a crash-restart
  re-sends the same batch under the same id.
* **Producer settings actually used** (std-only client; verified against
  single-node Apache Kafka 3.9.1 and 4.1.0 with `scripts/kafka-it.sh`,
  including the §4 partition against the Java client's partitioner):
  `acks=all`, **idempotence off**, one request in flight, no compression, TLS (required unless plain TCP is
  explicitly allowed), optional mutual TLS and SASL/SCRAM-SHA-256/512; a per-request deadline covering writes and reads that exceeds the
  broker-side produce timeout; host names resolved with a timeout (IP
  literals recommended). This deviates from §4's `enable.idempotence=true`: delivery is
  at-least-once and consumers must drop duplicates on `event-uid`.
  Per-partition order is preserved.

## 9. Consumer integration checklist

What a SOC (or any consumer) needs to implement to ingest this contract
safely. Nothing here is specific to one product.

**Trust map** (field provenance):

- `entity_context.mode` is the stricter of the robot's profile mode and the
  deviation's own mode: `observe` if either says observe (report only; never
  act on it).
- **sensor** (RoboDR's own measurements and catalog): `finding_id`,
  `external_id`, `severity`, `timestamp`,
  `entity_context.{robot, profile, rule_id, mode, safety_state, attestation,
  bus_message_id, occurrence_count}`,
  `entity_context.command.{linear_speed, joint_speed, envelope_max_*}`,
  `mitre_predictions` (written by RoboDR's rule catalog, *not* a third
  party), `evidence_links`, `anomaly_score`, all `ocsf.*` except below;
- **adversary**: every pointer in `adversary_controlled_fields`
  (`entity_context.ros.*`, `entity_context.command.channel`,
  `entity_context.detail`, `ocsf.resources[*]`, and the
  `ocsf.unmapped.robodr` copies). **Participant GUID and source IP** are
  adversary too (the participant chooses its GUID; UDP source addresses are
  spoofable).
- A consumer that cannot apply the map treats the whole message as
  adversary-authored: safe, but it loses the sensor fields.

**Checks:**

- [ ] Validate every message (`robodr_ocsf::parse_and_validate`, or the
      schema plus the §3 parsing rules); reject duplicate keys.
- [ ] Verify `robodr-finding-sig` over the raw value bytes with the key
      registered for `entity_context.robot.id` (§2a); strict mode on
      connected paths once all producers sign; behind a diode rely on the
      importer's batch verification.
- [ ] `finding_id` present and used with `data_source` + `external_id` for
      dedup/upsert; drop exact re-deliveries on `event-uid` (signatures do
      not stop replay).
- [ ] Read `data_source` from the message; never default it from the topic.
- [ ] Tainted fields rendered as delimited data (`display`), never as
      instructions or Markdown/HTML; never the sole support for a benign
      verdict.
- [ ] Robot findings are never auto-remediated: any response is a request
      from the action catalog through the control plane, approved by a
      person (two people for `safe_pause`, `request_safe_state`,
      `rollback_config`), and judged again on the robot.
- [ ] `evidence_links` resolved through the robot's evidence export (not
      fetched directly from robots).
- [ ] ATT&CK for ICS techniques used by the catalog: T0848 Rogue Master,
      T0855 Unauthorized Command Message, T0801 Monitor Process State, T0831
      Manipulation of Control, T0856 Spoof Reporting Message.
- [ ] A hostile-name eval corpus: `crates/robodr-ocsf/tests/findings.rs`
      (`INJECTIONS`) holds a starting set; the produced findings are valid
      eval inputs.

## 10. Changelog

* **2.5.0** — rule-catalog entries and one optional field (minor),
  sales-readiness WP2:
  - New optional `entity_context.agent_health` (and its copy under
    `ocsf.unmapped.robodr`), only on `robot.agent.health` findings (§3g);
    schema `$defs/AgentHealth`.
  - New entries, data source `robodr_agent`: `robot.agent.health`,
    `robot.agent.credential_expiring`, `robot.agent.clock_unsynced`,
    `robot.agent.clock_jump`, `robot.agent.disk_low`,
    `robot.agent.executor_unreachable`,
    `robot.agent.control_plane_request_fenced`,
    `robot.agent.control_plane_saturated` (emitted by `robodr-agentd`) and
    `robot.agent.selftest` (reserved for its producer); data source
    `ros2_motion_commands`:
    `robot.gateway.overload` (reserved for `robodr-firewall-gw`); data
    source `host_runtime`: one `robot.host.<rule>` per shipped Pulsar rule
    (`robodr_ocsf::HOST_RULES`), `robot.host.pulsar_threat` kept as the
    fallback (§3g); `robot.agent.config_unattested` (data source
    `robodr_agent`, emitted by `robodr-agentd` at start),
    `robot.ros2.untrusted_security_identity` and
    `robot.capture.unsupported_transport` (data source `ros2_dds_discovery`):
    ids their producers already emitted without an entry (so with the
    generic one), now catalogued (§3g).
  - `robot.agent.restart_pending` (data source `robodr_agent`, emitted by
    `robodr-agentd`): the gateway or executor still runs the binaries from
    before a package upgrade (sales-readiness WP8a, §3g).
  - Schema `$id` `https://schemas.singularityrd.com/robodr/findings/2.5.0`.

* **2.4.0** — rule-catalog entries only (minor): agentd's sealed
  control-plane state and the executor (GA-ROADMAP S5):
  - New entries (data source `robodr_agent`, already in the schema's
    enums): `robot.agent.control_plane_state_untrusted`,
    `robot.agent.executor_revert_failed`,
    `robot.agent.executor_journal_reset` (§3f), emitted by `robodr-agentd`.
  - Schema `$id` `https://schemas.singularityrd.com/robodr/findings/2.4.0`.

<!-- 2.3 gateway block (merge with other 2.3 entries, e.g. robot.seal.*). -->
* **2.3.0** — rule-catalog entries only (minor), Sprint 8:
  - New entries (data source `ros2_motion_commands`, already in the
    schema's enums): `robot.gateway.trajectory_rejected`,
    `robot.gateway.trajectory_time_scaled`,
    `robot.gateway.undecodable_command`,
    `robot.gateway.fragmented_command`,
    `robot.gateway.writer_binding_conflict`,
    `robot.gateway.sequence_jump`, `robot.gateway.port_bypass_risk`,
    `robot.gateway.restriction_changed`,
    `robot.gateway.findings_dropped` (§3b), emitted by
    `robodr-firewall-gw` and reported by agentd (`gateway_feed`).
  - Schema `$id` `https://schemas.singularityrd.com/robodr/findings/2.3.0`.
<!-- end of the 2.3 gateway block -->
* **2.3.0** — rule-catalog entries only (minor). Sealing block, Sprint 13c
  (other 2.3 additions are listed as their own items):
  - New entries (data source `robodr_delivery`, already in the schema's
    enums since 2.2): `robot.seal.unseal_failed`, `robot.seal.lease_expired`,
    `robot.seal.erased`, `robot.seal.tamper` (`docs/SECURE-DELIVERY.md`
    §9), emitted by `robodr-deliverd` (`lease_expired` from 14b). §3c.
  - Schema `$id` `https://schemas.singularityrd.com/robodr/findings/2.3.0`.

<!-- 2.3 Unitree block -->
* **2.3.0** — rule-catalog entries only (minor). Unitree block (other 2.3
  additions are listed as their own items):
  - New entries (data source `ros2_motion_commands`, already in the
    schema's enums): `robot.unitree.webrtc_unknown_controller`,
    `webrtc_new_peer`, `webrtc_controller_mac_mismatch`,
    `webrtc_session_in_denied_window`, `webrtc_concurrent_sessions`,
    `webrtc_relayed_session`, `webrtc_media_without_signalling` (§3d),
    emitted by `robodr-firewall-gw` (`webrtc` section) and reported by
    agentd (`gateway_feed`, which now accepts the `robot.unitree.webrtc_*`
    ids besides `robot.gateway.*` / `robot.firewall.*`).
<!-- end of the 2.3 Unitree block -->

* **2.3.0** — rule-catalog entries only (minor). Depot block, Sprints
  14a / 14b (other 2.3 additions are listed as their own items):
  - New entries (data source `robodr_delivery`): `robot.depot.import_refused`,
    `robot.depot.enrolment_refused`, `robot.depot.unit_enrolled`,
    `robot.depot.rollout_halted`, `robot.depot.locked` (emitted by
    `robodr-depot`) and `robot.seal.erase_deferred` (emitted by
    `robodr-deliverd`). §3e. `robot.seal.lease_expired` is now emitted.
  - Schema `$id` unchanged (`.../findings/2.3.0`).

* **2.2.0** — rule-catalog entries only (minor), Sprint 13b:
  - New entries (data source `robodr_delivery`, added to the schema's
    `types` / `data_sources` enums): `robot.deliver.installed`,
    `robot.deliver.deferred_safety`, `robot.deliver.health_failed`,
    `robot.deliver.rollback_blocked_floor`, `robot.deliver.refused`,
    `robot.deliver.stale`, `robot.deliver.chain_gap`
    (`docs/SECURE-DELIVERY.md` §9), emitted by `robodr-deliverd`.
  - A second producer on the agentd spool: `robodr-deliverd` claims record
    names with no-replace links, as agentd does since this release
    (`robodr.spool/v1` unchanged; names and `seq` stay equal).
  - Schema `$id` `https://schemas.singularityrd.com/robodr/findings/2.2.0`.
  - The `robot.seal.*` ids of §9 have no entry yet (nothing emits them
    before Sprint 13c / 14b).
  - The complete 2.2 catalog (ids, exact titles and catalog sentences,
    data source, severities, techniques) is §3a; documented after the
    13b review, the entries themselves are unchanged.
* **2.1.0** — rule-catalog entries only (minor):
  - New entries: the low-level joint-frame firewall ids
    (`robot.firewall.joint_position_out_of_envelope`,
    `joint_velocity_out_of_envelope`, `joint_torque_out_of_envelope`,
    `joint_gain_out_of_envelope`, `joint_gain_below_minimum`,
    `joint_step_out_of_envelope`, `joint_pd_torque_out_of_envelope`,
    `joint_mode_inconsistent`, `joint_mode_pin_mismatch`,
    `joint_limp_frame`, `joint_hold_exceeded`, `joint_rate_violation`,
    `disabled_motor_energised`, `crc_invalid`) and
    `robot.motion.api_id_out_of_range`, `robot.motion.control_handover`.
    They had been added to the 1.3 catalog by mistake after 1.3.0 and 2.0.0
    were cut; the 1.3 / 2.0 catalogs are restored to exactly what 1.3.0
    shipped and these entries apply from 2.1 on.
  - `robot.unitree.legacy_unknown_sender` (Unitree legacy UDP, Go1
    generation: a command or state frame from a host the sensor
    configuration does not list). Added while 2.1.0 was still unreleased;
    a producer of an earlier 2.1 build reported it with the generic entry.
  - Also added while 2.1.0 was unreleased (same caveat):
    `robot.unitree.legacy_sender_flood` (unknown legacy senders aggregated
    after 16 distinct sources per class), `robot.unitree.legacy_sender_mac_mismatch`
    (a listed sender IP seen with another MAC), `robot.unitree.legacy_port_rtps`
    (an RTPS-looking datagram on a configured legacy port) and
    `robot.motion.command_type_mismatch` (a changed, unknown or feedback type
    announced on a profiled command channel).
  - Also added while 2.1.0 was unreleased (same caveat):
    `robot.ros2.discovery_flood` (agentd's aggregate of the per-participant
    and per-endpoint discovery findings of one flooding source and class).
    Catalog entry (title, description, technique T0848, data source
    `ros2_dds_discovery`) as first published; consumers that mirror the
    catalog (e.g. AutoSecOps' validator) need the entry, or they reject
    these findings for a title mismatch. Rule semantics (final for 2.1.0,
    after the review of the F1 fix):
    - **Severity**: `critical` for the aggregate of a source's Critical
      findings (e.g. sprayed `unauthorized_motion_writer`), else the most
      severe folded severity, at least `medium`. A source's Critical and
      lesser findings are two separate aggregates.
    - **Subject**: `src_ip` = the flooding source (absent for the "many
      sources" aggregate) and `node` = a synthetic, sensor-authored name
      `discovery_flood/<critical|other>/<episode start, RFC 3339 UTC ms>`,
      or `discovery_flood/protected-<critical|other>/<24 hex GUID
      prefix>/<episode start>` for findings about one of the robot's own
      participants (it is not a ROS node). Every report of one flood
      episode therefore has one `finding_id` (one case, updated with
      `count` / `last_seen_time`), and a flood after the previous one
      ended (a full 60 s quiet) has a new `finding_id`.
    - **Detail** (tainted, at most 400 characters, never cut mid-text):
      the folded count per rule, first and last seen, up to 4 sample GUID
      prefixes taken from the parsed announcements (never from text), and
      for the "many sources" aggregate up to 4 sample source addresses
      (the **latest** ones, and the latest sample prefixes, motion writers
      kept first: "latest sample sources: ...", "latest sample GUID
      prefixes: ..."). An aggregate of findings about one of the robot's
      own (profiled or pinned) participants names that participant as its
      subject ("about the robot's own participant <prefix> (profiled or
      pinned)") and lists **no** sample GUID prefixes: a SOC must not take
      that prefix as a quarantine target from this finding (it is the
      impersonated one).
    - Findings about a profiled or pinned participant (review R2-1 of the
      redfix) are folded only past 4 High / Critical ones per
      (participant, source, rule) and 60 s window, or 64 per participant
      (below High: 256 / 1024); their aggregate is `critical` for the High
      / Critical ones. Never folded: findings that are not about one
      participant, and a Critical finding from a source first seen after
      128 sources in the window, up to 2 per such source and at most 128
      such sources per window (review R2-2; charged per source since
      review R3-2, so one address cannot spend the budget).
    - Accepted limits (reviews R3-3, R3-4, R3-5 of the redfix; a SOC
      should know them): a spoofed-source spray of about 6.4 packets/s
      from 256 or more addresses can still fold a genuine rogue's Critical
      finding into the "many sources" aggregate (named while among the
      latest samples; always in the robot's black box). Without a
      draining exporter, distinct spoofed sources can fill the spool's
      reserve for new Critical sources one record each (R3-4). A spray
      with one spoofed source per prefix can evict a departed,
      Critical-ranked rogue from the robot's quarantine memory unless the
      SOC already named it in a `quarantine_node` (R3-5). A decoy whose
      discovery is spoofed to another host's address makes a quarantine
      of the decoy cut that host (R3-3; control-plane contract §6a,
      shared hosts). Source IPs in findings are adversary-controlled
      (§9, trust map).
    - The catalog title ("... unknown participants aggregated") predates
      these per-endpoint and protected-participant aggregates; it is frozen
      and mirrored, so it stays (the detail says which rules were folded).
    - No new field.
  - Schema `$id` `https://schemas.singularityrd.com/robodr/findings/2.1.0`;
    `contract_version` parts at most 9 digits and `ocsf.metadata.log_name`
    not `.` / `..` (as the validator always required).
  - `robodr-contract-version` / `ocsf-version` headers: the value's own
    versions.
  - `data_source` documented as an unauthenticated label (§2, *Identity*).
  - Upgrade path for 1.x findings in flight (§5): unsigned 1.x findings are
    upgraded to 2.0.0 by the spool exporter, the diode importer and the
    publisher; signed ones are kept with "legacy 1.x signed record: re-sign
    required"; a 1.x diode batch no longer stalls its unit's chain.
* **2.0.0** — vendor-neutral contract `robodr.findings` (supersedes
  `robot-edr.findings` 1.3.0, see
  [`legacy/robot-edr.findings.md`](legacy/robot-edr.findings.md) for the
  1.x history):
  - `data_source`: deployment label, default `robodr` (was the constant
    `robot_edr`); `data-source` header = the value's `data_source`.
  - Topic: configured, default `robodr.findings` (was fixed
    `robot-edr.findings`); `ocsf.metadata.log_name` names it and the
    record topic is derived from it.
  - Schema `$id` `https://schemas.singularityrd.com/robodr/findings/2.0.0`.
  - 1.x messages: parse-only (validated with their 1.x constants and
    rules, never emitted or forwarded).
  - Unchanged: field set, OCSF 1.1 Detection Finding body, identity
    (`rf1-`/`re1-`), SR-TAINT, signatures (§2a), rule catalog (= 1.3).
