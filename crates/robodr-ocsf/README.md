# robodr-ocsf

Turns a RoboDR `Deviation` into a **finding** for the AutoSecOps AI SOC: an
OCSF 1.1 **Detection Finding** (`class_uid` 2004, `category_uid` 2 *Findings*)
wrapped in the AutoSecOps ingestion envelope, ready for the
`robot-edr.findings` Kafka topic.

Contract: [`docs/contracts/robot-edr.findings.md`](../../docs/contracts/robot-edr.findings.md) ·
Schema: [`robot-edr-finding.schema.json`](../../docs/contracts/robot-edr-finding.schema.json) ·
Example: [`robot-edr-finding.example.json`](../../docs/contracts/robot-edr-finding.example.json)

Pure crate: std + serde + `robodr-events`. No I/O, no clock, no Kafka client.

## Usage

```rust
let ctx = RobotContext::new(robot_info, profile_ref, Mode::Enforce);
let finding = FindingBuilder::from_deviation(&deviation, &ctx)
    .event(&triggering_event)          // subject: GUID / topic / IP, motion values
    .seen(first_ms, last_ms)           // explicit times; nothing reads a clock
    .occurrences(n)                    // 1 => OCSF Create, >1 => Update
    .safety_state(state)
    .attestation(AttestationStatus::Verified)
    .evidence(BlackBoxRef { segment, seq, sha256 })
    .build()?;                         // validated, or every problem listed
let rec = robodr_ocsf::record(&finding, Some(partitions))?; // key, partition, headers, JSON
```

## Modules

| Module | What |
| --- | --- |
| `model` | Typed serde structs: `FindingEnvelope`, `EntityContext`, `DetectionFinding`, … |
| `builder` | `FindingBuilder`, `RobotContext`, `Subject`, trusted rule catalog, severity map, uid derivation, RFC 3339 |
| `taint` | SR-TAINT: neutralising attacker-controlled ROS/DDS strings (`Tainted`) |
| `validate` | Strict validator (`validate`, `parse_and_validate`) |
| `kafka` | Record key, headers, partition-by-robot-id, `to_json` |
| `hash` | std-only SHA-256 (FIPS 180-4 vectors) and Kafka murmur2 (Kafka `UtilsTest` vectors) |

## Design decisions

* **Envelope + embedded OCSF.** The design doc's *Bulgu şeması* names
  AutoSecOps fields (`finding_id`, `external_id`, `data_source`, `title`,
  `description`, `severity`, `timestamp`, `entity_context`,
  `mitre_predictions`, `evidence_links`, `anomaly_score`); these are the top
  level. The full OCSF object is under `ocsf` so it can be forwarded to an
  external SIEM verbatim. Robot-specific data with no OCSF attribute lives in
  `ocsf.unmapped.robodr` (identical to `entity_context`; validator-enforced).
* **Deterministic identity.** `finding_id` = `rf1-` + 128-bit SHA-256 prefix of
  length-framed `(robot id, rule id, raw subject)`; `metadata.uid` = `re1-` +
  hash of `(finding id, last_seen, count)`. Same inputs ⇒ byte-identical JSON
  (tested), evidence is sorted/deduplicated so call order does not matter.
* **Trusted narrative only.** `title`/`description`/`message` come from the rule
  catalog in `builder.rs` and sensor-authored config. `Deviation::detail` is
  *not* used for narrative because the detection core interpolates attacker
  names into it; it is carried as `Tainted` data.
* **SR-TAINT** (security requirement). ROS node/topic/type names, GUIDs, source
  IPs and `detail` are attacker-controlled and reach an LLM-based SOC. They are
  placed only in typed `Tainted` fields (`taint: "adversary"`) or OCSF resources
  labelled `taint:adversary`, listed in `adversary_controlled_fields`, have
  control / Unicode-format / markup (`<>` and backtick) characters rewritten as
  visible `\u{XXXX}` escapes (backslash doubled, so it is injective), and are
  length-capped with the raw length and SHA-256 kept. Injected natural-language
  instructions are **not** filtered (undecidable) — they remain inert, clearly
  tainted data. The validator rejects any raw control/format/markup character
  in *any* string of the message, including unknown fields on parse.
* **Trusted config is rejected, not escaped.** A robot id, model, site, rule id
  or hash that fails its charset/format is a configuration bug; `build()` fails.
* **Partitioning** by robot id with Kafka's murmur2, key = finding id.

## Rule catalog → ATT&CK for ICS

| Rule id | Title | Technique |
| --- | --- | --- |
| `robot.ros2.unknown_participant` | Unknown DDS participant joined the robot graph | T0848 Rogue Master ¹ |
| `robot.ros2.unauthorized_motion_writer` | Unauthorized publisher on a motion topic | T0855 Unauthorized Command Message |
| `robot.ros2.unknown_writer_topic` | Writer on a topic outside the model profile | T0855 |
| `robot.ros2.unknown_reader` | Unknown subscriber in the robot graph | T0801 Monitor Process State ¹ |
| `robot.motion.unprofiled_channel` | Motion command on an unprofiled channel | T0855 |
| `robot.motion.linear_over_envelope` | Linear speed command exceeds the motion envelope | T0831 Manipulation of Control |
| `robot.motion.joint_over_envelope` | Joint speed command exceeds the motion envelope | T0831 |
| anything else | RoboDR model-profile deviation | — |

¹ Not in the design doc's robotics technique list (T0855, T0831, T0836, T0843,
T0889, T0856). Our mapping choice; AutoSecOps `categories.py` must add them or
these findings land in `other` (still never autonomous). Technique names are
from memory of ATT&CK for ICS — verify against the current matrix.

## OCSF-UNCERTAIN

Written from knowledge of OCSF 1.x without access to the schema server.
Confident: class 2004 / category 2 and their captions, `activity_id` 1/2/3,
`type_uid = class_uid*100 + activity_id`, `severity_id` 0–6/99 (Low=2,
Medium=3, High=4, Critical=5), `time` in ms, `metadata.{version, product{name,
vendor_name, version}, uid, log_name}`, `finding_info.{uid, title, desc, types,
first_seen_time, last_seen_time, analytic, data_sources}`, `analytic.type_id`
1 = Rule, `device.{uid, name, type_id, type}` with 99 = Other, `count`,
`message`, `unmapped`.

**Not certain** (confirm before putting a strict OCSF validator in the path):

* `status_id` enum for Detection Finding (we use 1 = New; assumed 0 Unknown,
  1 New, 2 In Progress, 3 Suppressed, 4 Resolved, 99 Other).
* `device.model` attribute name / availability in 1.1.
* `evidences[]` object shape — we only use its free-form `data` attribute.
* `resources[]` (`resource_details`) having `labels`; `type` values are ours.
* `finding_info.attacks[]` being populated with ATT&CK **for ICS** ids (the
  object is modelled on Enterprise ATT&CK; we fill only `technique.{uid,name}`).
* Whether Detection Finding 1.1 lists `device` and `resources` directly on the
  class (vs. only via profiles).

## Verified vs. not verified

* Verified (unit/integration tests): severity mapping, determinism, dedup-key
  stability, uid sensitivity, hostile-string neutralisation (control chars,
  bidi, zero-width, tag chars, markup, 1 MB names), validator rejection of 27
  tampering cases, round-trip, schema required/undeclared keys, golden example,
  SHA-256 and murmur2 against published vectors.
* **Not** verified: against the real OCSF schema/validator, against a running
  AutoSecOps `kafka_consumer_service.py`, against a Kafka broker, or the exact
  AutoSecOps expectations for `severity`/`timestamp`/`mitre_predictions` value
  formats (assumed: lower-case string, RFC 3339 string, list of objects).
  The JSON Schema's `pattern` keywords are not evaluated by the in-repo test
  checker (no regex engine); the Rust validator enforces those formats.
* Diode export/import is specified in the contract but not implemented.
