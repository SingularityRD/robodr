# robodr-ocsf

Turns a RoboDR `Deviation` into a **finding** for any SOC or SIEM: an OCSF
1.1 **Detection Finding** (`class_uid` 2004, `category_uid` 2 *Findings*)
wrapped in the vendor-neutral `robodr.findings` envelope (contract **2.1**;
the rule catalog is versioned per minor and a 2.0 message validates with the
2.0 catalog),
ready for a Kafka topic (default `robodr.findings`), an NDJSON ingest API or
a diode batch. `data_source` (default `robodr`) and the topic are deployment
configuration (`RobotContext::{data_source, topic}`). Contract 1.x
(`robot-edr.findings`) messages are still parsed and validated with their
fixed 1.x constants, never emitted; `upgrade::upgrade_legacy` relabels an
unsigned 1.x finding still in flight as contract 2.0.0 (same identity, full
2.0 validation; signed ones are never upgraded).

Contract: [`docs/contracts/robodr.findings.md`](../../docs/contracts/robodr.findings.md) ·
Schema: [`robodr-finding.schema.json`](../../docs/contracts/robodr-finding.schema.json) ·
Example: [`robodr-finding.example.json`](../../docs/contracts/robodr-finding.example.json) ·
Superseded 1.x: [`legacy/`](../../docs/contracts/legacy/)

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
// Optionally sign (Ed25519 finding key; header robodr-finding-sig)
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

* **Envelope + embedded OCSF.** The top level is a vendor-neutral envelope
  with what a SOC needs to ingest, deduplicate and triage (`finding_id`,
  `external_id`, `data_source`, `title`, `description`, `severity`,
  `timestamp`, `entity_context`, `mitre_predictions`, `evidence_links`,
  `anomaly_score`, `adversary_controlled_fields`). The full OCSF object is
  under `ocsf` so it can be forwarded to any SIEM verbatim. Robot-specific data with no OCSF attribute lives in
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
  IPs and `detail` are attacker-controlled and may reach an LLM-based SOC. They are
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

## Finding signatures (since contract 1.2)

* **What is signed:** the record value bytes exactly as emitted by
  `to_json` — no canonicalisation; the verifier works on the raw received
  bytes and never re-serialises. Domain-separated, length-framed message
  (`robodr-ocsf/finding-sig/v1\0`, `alg`, `key_id`, value).
* **Where:** Kafka header `robodr-finding-sig` =
  `{"alg":"ed25519","key_id":…,"sig":<128 hex>}`, appended after the
  other headers. The value (and the golden example) is unchanged by signing.
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
| `robot.motion.angular_over_envelope` | Roll/pitch rate command exceeds the motion envelope | T0831 |
| `robot.motion.joint_over_envelope` | Joint speed command exceeds the motion envelope | T0831 |
| *since contract 1.3:* | | |
| `robot.correlate.coordinated_intrusion` | Correlated intrusion: unknown participant, foreign motion writer and host anomaly | T0848, T0855 |
| `robot.correlate.credential_theft` | Correlated credential theft: SROS 2 key read, then a foreign participant | T0848 |
| `robot.correlate.spoofed_motion_source` | Correlated spoofed motion source from one address | T0855 |
| `robot.correlate.motion_hijack` | Correlated motion hijack: foreign motion source, then unexpected motion | T0855, T0831 |
| `robot.correlate.discovery_flood` | Correlated discovery flood: unknown participants from many addresses | T0848 |
| `robot.correlate.{sensor_evasion, trojaned_package_key_access, defense_tampering, host_process_persistence}` | (own titles, data source `robodr_correlation`) | — |
| any other `robot.correlate.*` | Correlated RoboDR detection | — |
| `robot.safety_state.untrusted_source` | Safety-state sample from an untrusted writer | T0856 Spoof Reporting Message |
| `robot.safety_state.{undecodable_sample, unmapped_value}` | (own titles, data source `robot_safety_state`) | — |
| `robot.ros2.profile_state_tampered` | Profile anti-rollback state missing or behind the black box | — |
| `robot.agent.{evidence_quarantined, correlation_pressure}` | (own titles, data source `robodr_agent`) | — |
| `robot.host.pulsar_threat` | Host runtime-security detection (Pulsar rule), data source `host_runtime`; the Pulsar rule name and process are in the detail | — |
| *since contract 2.1 (among others):* | | |
| `robot.ros2.discovery_flood` | Discovery flood: unknown participants aggregated (agentd folds a flooding source's per-participant discovery findings into it) | T0848 |
| *since contract 2.5:* | | |
| `robot.agent.health` | Agent health record; the only rule that carries `entity_context.agent_health` (`AgentHealth`, `FindingBuilder::agent_health`) | — |
| `robot.agent.{credential_expiring, clock_unsynced, clock_jump, disk_low, executor_unreachable, restart_pending, control_plane_request_fenced, control_plane_saturated, control_plane_replay_unavailable, selftest}` | (own titles, data source `robodr_agent`) | — |
| `robot.gateway.overload` | In-path gateway overloaded (data source `ros2_motion_commands`) | — |
| `robot.host.<rule>` | one per shipped Pulsar rule (`HOST_RULES`, `host_rule_id`; title = the rule name), data source `host_runtime`; `robot.host.pulsar_threat` stays the fallback | — |
| anything else | RoboDR model-profile deviation | — |

The validator applies the catalog of the message's own `contract_version`
(`rule_info_for_contract`): a 1.2 finding for an id that only gained an
entry in 1.3 keeps the generic entry and stays valid; every 2.x finding has
the full catalog.

¹ Our mapping choice, outside the commonly cited robotics technique set
(T0855, T0831, T0836, T0843, T0889, T0856): a consumer that maps techniques
to a robot category must include T0848 and T0801 or these findings land in
its generic bucket (robot findings are never autonomous either way).
Technique names are from memory of ATT&CK for ICS — verify against the
current matrix.

## OCSF-UNCERTAIN

> **Checked (T61).** Produced findings are now validated against the official
> OCSF 1.1.0 schema (compiled from `ocsf/ocsf-schema` v1.1.0 by the OCSF
> compiler) and the contract schema with the `jsonschema` package
> (`tests/external_validator.rs`, `integrations/schemas/README.md`). Only
> `device.model` is not OCSF 1.1.0; every other item below holds. ATT&CK for
> ICS ids are checked against MITRE's v20 data (`tests/attack_ics.rs`): T0855
> and T0856 were revoked (now T1692.001 / T1692.002). The list below is kept
> as written for history.

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
* **Not** verified: against the real OCSF schema/validator or against a
  running SOC consumer. (Delivery to real Kafka brokers is verified in
  `robodr-export`, `scripts/kafka-it.sh`.)
  The schema `pattern`s are evaluated with an in-repo matcher, not a real
  ECMA-262 engine; they were written in a portable subset (anchors, classes,
  groups, simple quantifiers) but not run through a third-party JSON Schema
  validator. `injection_hint` is a fixed keyword heuristic (false positives
  and negatives expected; protection does not depend on it).
  `mixed_script` is a code-point-range heuristic, not Unicode
  script detection (no Unicode tables offline).
* Diode export/import lives in `crates/robodr-diode`; it does not yet carry
  per-finding signatures (contract §8, integrator TODO).
* Ed25519 comes from `robodr-blackbox` (a wrapper over the audited
  `ed25519-dalek` crate, vector-tested); finding signatures were not tested
  against an external verifier.
