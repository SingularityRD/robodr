# Topic contract: `robot-edr.findings`

| | |
| --- | --- |
| Contract version | **1.1.0** (`contract_version` field, `robodr-contract-version` header); changes in §10 |
| Producer | RoboDR control plane (Kafka publisher, Sprint 4); diode importer on air-gapped sites |
| Consumer | AutoSecOps `core/ingestion/kafka_consumer_service.py` |
| Value schema | [`robot-edr-finding.schema.json`](robot-edr-finding.schema.json) (JSON Schema 2020-12) |
| Golden example | [`robot-edr-finding.example.json`](robot-edr-finding.example.json) |
| Reference implementation | `crates/robodr-ocsf` (`FindingBuilder`, `validate`, `kafka::record`) |

The example and the schema are not hand-maintained prose: the `robodr-ocsf`
test suite fails if the builder's output differs from the example by a single
byte, if a produced finding is missing any key the schema marks `required`, or
if it has a key the schema does not declare.

## 1. What the design doc specifies (quoted)

From `2-tasarim/tasarim-dokumani.md`, section *AI SOC entegrasyonu (AutoSecOps)*.
English glosses are ours.

> AI SOC'a ham telemetri değil, kontrol düzleminde korele edilmiş bulgular ve
> kara kutu kanıtına bağlantılar gider.

*Not raw telemetry: correlated findings plus links to black-box evidence.*

> AI SOC robota hiçbir zaman doğrudan hareket komutu göndermez: onaylanan
> aksiyon kontrol düzlemine gider, son kontrolü robot üzerindeki ajan yapar.

*The SOC never sends a motion command to a robot; approved actions go to the
control plane and the on-robot agent has the final check.*

**Veri akışı** (data flow):

| Yol | AutoSecOps'ta nerede | Ne zaman |
| --- | --- | --- |
| Kafka topic (`robot-edr.findings`) | `core/ingestion/kafka_consumer_service.py`: her mesajda `finding_id` zorunlu; `data_source` verilmezse `kafka:<topic>` olur | İlk sürüm, en hızlı yol |

*`finding_id` is mandatory on every message; if `data_source` is absent it
defaults to `kafka:<topic>`.* We therefore always send `data_source`.

**Bulgu şeması** (finding schema) and where each row lands in this contract:

| Robot EDR alanı (design doc) | AutoSecOps alanı (design doc) | This contract |
| --- | --- | --- |
| Olay kimliği | `finding_id` | `finding_id` = `ocsf.finding_info.uid` |
| Robot kimliği + olay kimliği | `external_id` (`data_source` ile birlikte tekilleştirme anahtarı) | `external_id` = `<robot_id>:<finding_id>`; dedup key = (`data_source`, `external_id`) |
| Sabit `robot_edr` | `data_source` | `data_source: "robot_edr"` |
| Kural adı, açıklama, önem, zaman | `title`, `description`, `severity`, `timestamp` | same names; `severity` ∈ `low/medium/high/critical`; `timestamp` RFC 3339 UTC ms |
| Robot kimliği, model, firmware sürümü ve hash'i, saha, attestation durumu, güvenlik durumu, ROS node ve topic, veri yolu mesaj kimliği, komut değeri ve izinli zarf | `entity_context` | `entity_context.{robot{id,model,site,firmware{version,sha256}}, attestation, safety_state, ros{node,topic,…}, bus_message_id, command{…, envelope_max_*}}` + `profile`, `mode`, `rule_id` |
| ATT&CK for ICS teknikleri | `mitre_predictions` | `mitre_predictions[]` (`technique_id`, `technique_name`, `framework: attack_ics`, `provenance: sensor`) |
| Kara kutu kanıtı | `evidence_links` | `evidence_links[]` = `robodr-blackbox://<robot>/<segment>/<seq>?sha256=<hex>` |
| Anomali modeli skoru | `anomaly_score` | `anomaly_score` ∈ [0,1], omitted when no model was involved |

The design doc also says the event model is "OCSF tabanlı" (OCSF-based) and the
SOC receives an "OCSF olay akışı". The design doc is **silent on the OCSF class**;
we use **OCSF 1.1 Detection Finding** (`class_uid` 2004, `category_uid` 2
*Findings*) and embed it whole under `ocsf`, so the same object can go to an
external SIEM/SOAR unchanged. Fields we are not certain of in the OCSF spec are
listed in `crates/robodr-ocsf/README.md` (*OCSF-UNCERTAIN*).

## 2. Record layout

| Part | Value |
| --- | --- |
| Topic | `robot-edr.findings` |
| Key | `finding_id` (UTF-8, `rf1-` + 32 lower-case hex) |
| Value | compact JSON `FindingEnvelope`, UTF-8, ≤ 64 KiB |
| Partition | chosen **explicitly** by the producer from the **robot id** (§4), not from the key |

### Headers (all values UTF-8, fixed order)

| Header | Value |
| --- | --- |
| `content-type` | `application/json` |
| `robodr-contract-version` | `1.1.0` |
| `ocsf-version` | `1.1.0` |
| `data-source` | `robot_edr` |
| `robot-id` | robot id (`[A-Za-z0-9._-]{1,64}`) |
| `severity` | `low` \| `medium` \| `high` \| `critical` |
| `event-uid` | `ocsf.metadata.uid` (per-emission id, `re1-` + 32 hex) |

Headers are a routing convenience; the value is authoritative. A consumer must
not trust a header that disagrees with the value.

### Value (abridged; full example in the JSON file)

```json
{
  "contract_version": "1.1.0",
  "finding_id": "rf1-0d7e79aac05cfd23bcfbdd38ef617eba",
  "external_id": "ugv-007:rf1-0d7e79aac05cfd23bcfbdd38ef617eba",
  "data_source": "robot_edr",
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
                  "uid": "re1-e10d71877f52e563b8482d1359871bb1", "log_name": "robot-edr.findings" },
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
  A consumer upserts on (`data_source`, `external_id`).
* `ocsf.metadata.uid` (`event-uid` header) identifies one *emission*
  (hash of finding id, `last_seen_time`, `count`). Re-delivery of the same
  emission (producer retry, diode re-send) carries the same `event-uid`;
  consumers may drop exact duplicates on it.
* `status_id` is always 1 *New* from RoboDR; triage status belongs to the SOC.

## 3. Security requirement SR-TAINT: attacker-controlled strings

**Requirement.** ROS 2 node names, topic names, type names, DDS GUID prefixes,
source addresses and the deviation's free-text `detail` (which interpolates
them) are chosen by whoever can reach the robot's DDS bus. They flow into an
**LLM-based SOC**. The roadmap requires our eval set to carry "injection tests
placed in ROS node and topic names, mirroring AutoSecOps' eval discipline", and
the design doc lists "`eval/` derlemine robot bulgu örnekleri ve enjeksiyon
testleri (ROS node adına yazılmış talimat gibi)" — *injection tests such as an
instruction written into a ROS node name*. The design doc's source-trust section
classifies exactly these as adversary-authored:

> **Saldırgan:** ROS node ve topic adları, süreç ve dosya adları, hostname,
> komut satırı. Bunları robota erişen biri seçebilir; triyaj modeli bunlara
> güvenerek bulguyu kapatamamalı.

*Adversary: ROS node and topic names, process and file names, hostname, command
line. Anyone with access to the robot can choose them; the triage model must not
close a finding by trusting them.*

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

**Consumer obligations (AutoSecOps side):**

* Put tainted values into prompts only inside clearly delimited data blocks,
  never as instructions: prefer `Tainted.display`; use `value` (or tainted
  `resources[]`) when exact identity matters, keeping it escaped (decode only
  for display to a human, never into a prompt). Never render tainted values
  as Markdown/HTML. Treat `suspicious` (and the individual flags) as a
  hostile-name signal; never let a tainted field be the sole basis for a
  *benign* verdict (the design doc's provenance rule: a verdict with no
  sensor-field support degrades to *uncertain*).
* Map `robot_edr` fields per the trust map below; in particular a field the map
  does not list is treated as adversary.

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
* **Contract 1.0 messages** carry no `display` and no flags. The reference
  validator rejects any 1.0 message that carries one of the 1.1 tainted-value
  fields (`display`, `non_ascii`, `mixed_script`, `injection_hint`,
  `suspicious`) — present at all, even at a default value — because 1.0 has
  no checks for them and a downgraded `contract_version` would otherwise
  smuggle a forged `display` or a cleared `suspicious`. For an accepted 1.0
  message, treat every tainted value as `suspicious: true` and render it from
  `value` (kept escaped) only. Producers never emit 1.0
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
  `robodr` (rule not in the catalog). Techniques: T0848 Rogue Master, T0855
  Unauthorized Command Message, T0801 Monitor Process State, T0831
  Manipulation of Control. Adding a catalog entry is a contract minor bump
  and needs the validator updated on both sides of the diode in step.

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

* `contract_version` is semver; the major version is in the schema `$id`.
* **Minor** (1.x): add *optional* fields only; never change meaning, type or
  enum values of an existing field; never make a field required. Consumers
  must ignore unknown fields (the reference validator does, but still applies
  the SR-TAINT string rules to them).
* **Major** (2.0): anything else — removing/renaming fields, new required
  fields, changing id derivation (`rf1-`/`re1-` prefixes encode the derivation
  version), changing the OCSF class. A major bump goes to a **new topic**
  `robot-edr.findings.v2`, produced in parallel until AutoSecOps migrates.
* `ocsf.metadata.version` moves independently; upgrading the OCSF version
  inside the envelope is a minor change only if it is additive for consumers.
* The reference validator accepts any `1.y.z` and rejects other majors.

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
  transport, not the system of record: findings live in AutoSecOps cases and
  the control plane; evidence lives in the signed black box (months).
* Partitions: 12 for a fleet deployment; replication 3 (1 on a single-box
  air-gapped install).

## 8. Air-gapped transport (diode export batches)

Defence sites run the console air-gapped; findings may have to cross a
one-way data diode (or controlled removable media) to reach an AutoSecOps
instance. **Implemented in `crates/robodr-diode`** (`Packer` / `Importer`,
CLIs `robodr-diode-pack` / `robodr-diode-unpack`; format and limits in that
crate's README). Moving files across the diode and producing the emitted
records to Kafka are outside the crate (no network code).

* **Batch = one directory** `rdd_<unit_id>_<batch_seq, 16 digits>/` holding
  `findings.jsonl` (each value compact JSON, one per `\n`-terminated line,
  validated with `robodr_ocsf::to_json` before packing), optional black-box
  export bundles `bundle-NNNN.rbbx`, `MANIFEST.json` and `MANIFEST.sig`.
  `unit_id` is the exporting robot or site console (`[A-Za-z0-9._-]{1,64}`).
* **Manifest** (`deny_unknown_fields`, ≤ 128 KiB, ≤ 256 files):
  `{format: "robodr-diode/1", contract_version, unit_id, batch_seq (1-based),
  prev_batch_hash, created_at (RFC 3339 ms), created_at_ms, key_id, algorithm,
  finding_count, first_time, last_time, files: [{name, kind, size, sha256}]}`.
  `first_time`/`last_time` are min/max `ocsf.time`. File names are
  allow-listed (`findings.jsonl`, `bundle-NNNN.rbbx`); anything with a path
  separator, `..`, a leading dot or upper case is rejected.
* **Signature**: the raw manifest bytes are signed through the black-box
  crate's `Signer` over `"robodr-diode/manifest/v1\0" || manifest`;
  `MANIFEST.sig` = `{format, algorithm, key_id, sig (hex)}`. Batch hash =
  SHA-256(`"robodr-diode/batch-hash/v1\0" || manifest`); each manifest carries
  the previous batch's hash, so batches form a per-unit hash chain.
  **Interim:** the only signer available offline is HMAC-SHA256 (symmetric:
  the SOC holding the key could forge batches). Production needs an
  asymmetric signer behind the same trait.
* **Size bounds**: data bytes per batch (default 16 MiB, ≥ 64 KiB + 1) and
  findings per batch (default 10 000); larger inputs are split into several
  consecutive batches.
* **Low side (export)**: stage in `outbox/.tmp-<batch>/`, `fsync`, commit
  (`next_seq`, chain head) to the packer state file atomically, then `rename`
  into the outbox. The transfer agent must ignore dot-entries. A crash
  between commit and rename is finished on the next start; sequence numbers
  are never reused for different visible content.
* **High side (import)**: authenticate the manifest bytes with the keyring
  key named in `MANIFEST.sig` *before* parsing them; the key must belong to the
  manifest's unit and the directory name must match. Then, per unit:
  `seq = last+1` with the right `prev_batch_hash` → verify every file
  (regular file, no symlink, exact size and SHA-256, no unlisted entries),
  run `robodr_ocsf::parse_and_validate` on every line, parse (and, with a
  black-box verifier configured, verify) every bundle, and emit
  `out/<batch>/records.jsonl` — one Kafka record per line with the **same**
  key, partition rule and headers as §2/§4 (`{topic, partition, key, headers,
  value, diode: {unit_id, batch_seq, batch_hash, line}}`).
* **Ordering**: batches are processed in `batch_seq` order. A gap is
  **reported and the later batches held** in the inbox until the missing ones
  arrive (reordering heals itself) or an operator explicitly accepts that gap
  (`--accept-gap unit:seq`, recorded in the importer state); never silently
  skipped. An identical re-send (same batch hash) is a duplicate: verified,
  filed under `processed/`, nothing re-emitted. A different batch for an
  already-used `seq` (conflict), an old `seq` outside the remembered window
  or inside an accepted gap (replay), or a wrong `prev_batch_hash` (chain
  break) is quarantined.
* **Quarantine**: any failed check moves the batch to `quarantine/` with a
  `<name>.reason.json` (`reason.code`, e.g. `bad_signature`, `hash_mismatch`,
  `size_mismatch`, `invalid_finding`, `manifest_invalid`, `symlink`,
  `conflict`); importer state does not advance, so an intact re-send of the
  same batch is accepted later (whole-file / whole-batch retransmission is the
  forward-error strategy; no application-level FEC).
* Because `finding_id` and `event-uid` are deterministic, re-publishing an
  already-imported finding remains idempotent for the consumer.

## 9. AutoSecOps-side checklist (from the design doc)

Quoted from *Yapılacak işler* (to-do), with what this contract needs from each:

- [ ] *"Robot EDR kontrol düzleminden `robot-edr.findings` topic'ine bulgu yayını ve şema"* — schema: **this document**; publisher: Sprint 4 (E3).
- [ ] *"`core/federation/provenance.py`: `robot_edr` kaynak güveni haritası"* — the trust map. Design doc: **sensor** = robot id, attestation status, firmware hash, safety state, bus message id, command value, permitted envelope, severity, time; **adversary** = ROS node and topic names, process and file names, hostname, command line. In this contract:
  - `entity_context.mode` is the stricter of the robot's profile mode and the deviation's own mode: `observe` if either says observe (report only; never act on it).
  - sensor: `finding_id`, `external_id`, `severity`, `timestamp`, `entity_context.{robot, profile, rule_id, mode, safety_state, attestation, bus_message_id, occurrence_count}`, `entity_context.command.{linear_speed, joint_speed, envelope_max_*}`, `mitre_predictions` (written by RoboDR's rule catalog, *not* third-party — note the generic Kafka map would wrongly treat MITRE as third-party), `evidence_links`, `anomaly_score`, all `ocsf.*` except below;
  - adversary: every pointer in `adversary_controlled_fields` (`entity_context.ros.*`, `entity_context.command.channel`, `entity_context.detail`, `ocsf.resources[*]`, and the `ocsf.unmapped.robodr` copies). We also classify **participant GUID and source IP** as adversary (the participant chooses its GUID; UDP source addresses are spoofable) — stricter than the design doc's list, deliberately.
  - Until this map ships, the generic Kafka map applies ("ham olay saldırgan yazımı sayılır" — the raw event counts as adversary-authored), which is safe but loses the sensor fields.
- [ ] *"`core/contracts/verdict.py` ve `core/autonomy/tiers.py`: `robotics` kategorisi, hiç otonom olmayanlar listesinde"* — the `robotics` category, **never autonomous** ("o da hiçbir zaman otonom olmamalı").
- [ ] *"`core/autonomy/categories.py`: ATT&CK for ICS eşlemesi ve `robot_edr` kaynağının kategorisi"* — the design doc names T0855, T0831, T0836, T0843, T0889, T0856 as the robotics techniques. **Gap:** RoboDR's catalog also emits **T0848 Rogue Master** (unknown DDS participant) and **T0801 Monitor Process State** (unknown reader), which are not in that list; either add them to the robotics mapping or those findings fall to `other` (still never autonomous). Decision needed.
- [ ] *"`core/response/approval_service.py` ve `core/autonomy/tiers.py`: robot aksiyon sınıfları"* — action classes, none in `AUTONOMOUS_ELIGIBLE`: `robot_restrict_motion` (approval), `robot_quarantine_node` (approval), `robot_isolate_network` (approval), `robot_safe_pause` (approval, two-person), `robot_request_safe_state` (approval, two-person; not reversible), `robot_rollback_config` (approval, two-person; not reversible). A finding never carries an action; actions go SOC → control plane → on-robot agent, which may refuse in the current safety state.
- [ ] *"`core/response/executors/`: `robot_edr` yürütücüsü"*.
- [ ] *"`core/integrations/robot_edr/`: vendor slice ve MCP araçları"*.
- [ ] *"`core/workflows/definitions/robot-incident-response/WORKFLOW.md`"*.
- [ ] *"Otonomi kademeleri tablosu için yeni veritabanı init dosyası"*.
- [ ] *"`eval/` derlemine robot bulgu örnekleri ve enjeksiyon testleri (ROS node adına yazılmış talimat gibi)"* — `crates/robodr-ocsf/tests/findings.rs` (`INJECTIONS`) holds a starting corpus of hostile names; the produced findings are valid eval inputs.

Consumer acceptance checks for this contract:

- [ ] `finding_id` present (consumer requires it) and used with `data_source` + `external_id` for dedup/upsert.
- [ ] `data_source` read from the message (`robot_edr`), not defaulted to `kafka:robot-edr.findings`.
- [ ] `robotics` category assigned from `mitre_predictions`; never autonomous.
- [ ] Tainted fields rendered as delimited data; never sole support for a benign verdict.
- [ ] `evidence_links` resolved through the control plane's black-box API (not fetched directly from robots).

## 10. Changelog

* **1.1.0, rev3 tightening** (validator and contract text only; the wire
  format and `contract_version: "1.1.0"` are unchanged — every message the
  builder ever produced still validates):
  - Duplicate object keys are rejected at any depth.
  - Contract 1.0 messages carrying any 1.1 tainted-value field are rejected
    (previously the 1.1 checks were skipped while the fields were still
    parsed and carried); 1.0 is parse-only and never emitted.
  - `title`, `description` prefix, `finding_info.types`/`data_sources`,
    ATT&CK technique ids/names and `resources[].labels` must match the rule
    catalog exactly; the JSON Schema now uses `enum`/`const` for them.

* **1.1.0** — SR-TAINT hardening and safety fix after independent review.
  - Neutralisation moved from a deny-list to the allow-lists in §3; more
    characters are escaped, with the same escape syntax (1.0 decoders still
    decode correctly). Free text (`detail`) now also escapes Markdown/HTML/
    template metacharacters.
  - New optional `Tainted` fields (always emitted by 1.1 producers): the
    ASCII-safe rendering `display`, and the flags `non_ascii`,
    `mixed_script`, `injection_hint`, `suspicious`. `value` is now documented
    and checked as the lossless escaped original (hash-verified while not
    truncated).
  - Caps are now in raw characters (256 / 64 / 400) instead of escaped
    bytes, so an all-non-ASCII name of legal length is no longer cut to a few
    characters; `value` may be up to 10 B per character. `_` is now raw in
    the text charset (readability of ROS names in `detail`).
  - Every schema string has a `pattern`; trusted strings must be printable
    ASCII. `Tainted` split into `TaintedName` / `TaintedText` in the schema.
  - `entity_context.mode`: an observe-only deviation is now published as
    `observe` even when the robot profile is locked (1.0 reported `enforce`).
  - Compatibility: the reference validator still accepts `1.y.z`; for
    `1.0.z` messages it skips the checks of fields 1.0 did not have. A 1.0
    message whose tainted values or trusted strings contain characters that
    1.1 escapes/forbids is rejected on replay. Consumers that read 1.0
    `value` strings keep working (same escape syntax, stricter raw set).
* **1.0.0** — initial contract.
