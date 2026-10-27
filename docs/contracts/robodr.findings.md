# Contract: `robodr.findings` (findings, v2)

| | |
| --- | --- |
| Contract | `robodr.findings`, version **2.1.0** (`contract_version` field, `robodr-contract-version` header); changes in §10 |
| Producer | `robodr-agentd` (findings spool), `robodr-diode` importer (air-gapped sites), `robodr-kafka-publish` |
| Consumer | Any SOC, SIEM or SOAR: the envelope is vendor-neutral and the body is a standard OCSF Detection Finding |
| Value schema | [`robodr-finding.schema.json`](robodr-finding.schema.json) (JSON Schema 2020-12, `$id` `https://schemas.singularityrd.com/robodr/findings/2.1.0`; it also describes 2.0.x messages, whose only difference is the rule catalog the validator applies, §3) |
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
| `entity_context` | robot, profile, rule id, mode, safety state, attestation, ROS/DDS identifiers (tainted), command and envelope, bus message id, occurrence count, detail (tainted) |
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
| `robodr-contract-version` | the value's own `contract_version` (`2.1.0` from this producer; a forwarded or replayed 2.0 message keeps `2.0.0`) |
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
  "contract_version": "2.1.0",
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
  Pulsar rule name is in the description, since it is not a rule id). Since 1.3 every `robot.*` id an in-repo
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
  | 2.1 and later | + the 2.1 entries: the low-level joint-frame firewall ids (`robot.firewall.joint_*`, `disabled_motor_energised`, `crc_invalid`), `robot.motion.api_id_out_of_range`, `robot.motion.control_handover`, `robot.motion.command_type_mismatch` and the Unitree legacy-UDP ids `robot.unitree.legacy_unknown_sender`, `legacy_sender_flood`, `legacy_sender_mac_mismatch`, `legacy_port_rtps` |

  A finding of an older minor for a rule that only gained an entry in a
  later minor carries the generic entry and stays valid; a finding of that
  later minor must carry the new entry, and relabelling either way is
  rejected.
  Any `robot.correlate.*` id without its own entry (a deployment's custom
  correlation rule) gets the generic correlation entry.

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
* **2.0 vs 2.1.** 2.1 only added rule-catalog entries (§3). A 2.1
  validator accepts 2.0 messages with the 2.0 catalog; a 2.0 validator
  accepts a 2.1 message for every rule both catalogs share and rejects one
  for a rule that only 2.1 catalogues (title / data source differ): upgrade
  consumers (and both sides of a diode) before producers.
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
  `acks=all`, **idempotence off**, one request in flight, no compression, **no TLS/SASL** (isolated network or local TLS
  proxy); a per-request deadline covering writes and reads that exceeds the
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
