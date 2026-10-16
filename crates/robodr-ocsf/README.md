# robodr-ocsf

Turns a RoboDR `Deviation` into a **finding** for the AutoSecOps AI SOC: an
OCSF 1.1 **Detection Finding** (`class_uid` 2004, `category_uid` 2 *Findings*)
wrapped in the AutoSecOps ingestion envelope, ready for the
`robot-edr.findings` Kafka topic.

Contract: [`docs/contracts/robot-edr.findings.md`](../../docs/contracts/robot-edr.findings.md) ·
Schema: [`robot-edr-finding.schema.json`](../../docs/contracts/robot-edr-finding.schema.json) ·
Example: [`robot-edr-finding.example.json`](../../docs/contracts/robot-edr-finding.example.json)

Pure crate: std + serde + `robodr-events` + `robodr-blackbox` (for the
`Signer`/`Verifier` traits and Ed25519). No I/O, no clock, no Kafka client.

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
// Contract 1.2: optionally sign (Ed25519 finding key; header robodr-finding-sig)
let rec = robodr_ocsf::record_signed(&finding, Some(partitions), &finding_key)?;

// Consumer: raw value bytes + header, keys = robot id -> Verifier (e.g. a Keyring)
let sig = robodr_ocsf::signature_header(&headers)?;
let v = robodr_ocsf::parse_and_validate_signed(raw, sig, &keys, SignaturePolicy::Strict)?;
dedup.insert(v.replay_key());   // replay detection is the consumer's job
```

## Modules

| Module | What |
| --- | --- |
| `model` | Typed serde structs: `FindingEnvelope`, `EntityContext`, `DetectionFinding`, … |
| `builder` | `FindingBuilder`, `RobotContext`, `Subject`, trusted rule catalog, severity map, uid derivation, RFC 3339 |
| `taint` | SR-TAINT: neutralising attacker-controlled ROS/DDS strings (`Tainted`) |
| `validate` | Strict validator (`validate`, `parse_and_validate`) |
| `kafka` | Record key, headers, partition-by-robot-id, `to_json` |
| `sig` | Detached per-finding Ed25519 signature: `record_signed`, `parse_and_validate_signed`, `verify_record`, `ReplayKey` (contract §2a) |
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
  labelled `taint:adversary`, listed in `adversary_controlled_fields`, and
  neutralised by **allow-list**: ROS/DDS identifiers keep only
  `[A-Za-z0-9_/.:-]` raw, the free-text `detail` keeps printable ASCII minus
  Markdown/HTML/template metacharacters; everything else (all non-ASCII, all
  control/format characters, homoglyphs, markup) becomes a visible canonical
  `\u{XXXX}` escape (backslash as `\\`), which is unambiguous and reversible
  (`taint::unescape`). Each tainted value carries two renderings: `value`,
  the **lossless escaped original** (hash-verified by the validator while not
  truncated), and `display`, an **ASCII-safe rendering** (allow-listed chars
  kept, everything else `?`). Flags `escaped`, `truncated`, `non_ascii`,
  `mixed_script` (homoglyph hint), `injection_hint` (keyword heuristic:
  `SYSTEM:`, "ignore…", verdict words, URLs, Markdown/HTML/JSON syntax) and
  their OR `suspicious` mark anything altered or suspicious. Values are
  capped by raw characters (256 / 64 / 400) with the raw length and SHA-256
  kept. Injected
  natural-language instructions are **not** filtered (undecidable) — they
  remain inert, clearly tainted data. The validator re-checks canonical
  encoding per charset and requires *every* string of the message (unknown
  fields on parse included) to be printable ASCII without `<>` or backtick;
  the JSON Schema carries the same rules as `pattern`s.
* **Mode.** `entity_context.mode` is `observe` if the robot context *or* the
  deviation says observe (`effective_mode`); an observe-only deviation is
  never published as `enforce`.
* **Trusted config is rejected, not escaped.** A robot id, model, site, rule id
  or hash that fails its charset/format is a configuration bug; `build()` fails.
* **Partitioning** by robot id with Kafka's murmur2, key = finding id.

## Finding signatures (contract 1.2)

* **What is signed:** the record value bytes exactly as emitted by
  `to_json` — no canonicalisation; the verifier works on the raw received
  bytes and never re-serialises. Domain-separated, length-framed message
  (`robodr-ocsf/finding-sig/v1\0`, `alg`, `key_id`, value).
* **Where:** Kafka header `robodr-finding-sig` =
  `{"alg":"ed25519","key_id":…,"sig":<128 hex>}`, appended after the 1.1
  headers. The value (and the golden example) is unchanged by signing.
* **Binding:** the verifier is chosen by the finding's own
  `entity_context.robot.id`; a keyring's device binding is enforced too.
* **Policies:** `Strict` requires a signature; `Optional` accepts unsigned
  findings (`SignatureStatus::Unsigned`) but never a bad signature.
* **Not provided:** freshness / replay protection (dedup on
  `ReplayKey`/`event-uid` in the consumer), key distribution, carrying the
  signature across the diode (see contract §8).

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
  bidi, zero-width, tag chars, markup, 1 MB names, and every bypass from the
  wave-2 review: Arabic/musical/Egyptian format chars, Mongolian FVS, braille
  blank, exotic spaces, private-use, unassigned, combining marks, Cyrillic
  homoglyphs, Markdown image links, HTML entities, JSON quote/brace and
  fake-field text; `tests/review_regressions.rs` pins value, display and
  every flag per case), escape round-trip and canonicality, display/flag/hash
  consistency, worst-case size (every tainted field at max escape length),
  validator rejection of 27 + 17 tampering cases, observe-mode propagation, round-trip, schema
  required/undeclared keys **and every `pattern`** (hand-written matcher for
  the regex subset the schema uses), golden example,
  SHA-256 and murmur2 against published vectors, finding signatures
  (round trip, every single-byte tamper of the value and every signature
  digit, key relabelling, wrong-unit key, keyring device binding,
  strict/optional policy, duplicate headers, HMAC refusal, replay key;
  `tests/signed.rs`).
* **Not** verified: against the real OCSF schema/validator, against a running
  AutoSecOps `kafka_consumer_service.py`, against a Kafka broker, or the exact
  AutoSecOps expectations for `severity`/`timestamp`/`mitre_predictions` value
  formats (assumed: lower-case string, RFC 3339 string, list of objects).
  The schema `pattern`s are evaluated with an in-repo matcher, not a real
  ECMA-262 engine; they were written in a portable subset (anchors, classes,
  groups, simple quantifiers) but not run through a third-party JSON Schema
  validator. `injection_hint` is a fixed keyword heuristic (false positives
  and negatives expected; protection does not depend on it).
  `mixed_script` is a code-point-range heuristic, not Unicode
  script detection (no Unicode tables offline).
* Diode export/import lives in `crates/robodr-diode`; it does not yet carry
  per-finding signatures (contract §8, integrator TODO).
* Ed25519 comes from `robodr-blackbox`'s in-crate RFC 8032 implementation
  (vector-tested, not audited); not tested against an external verifier.
