# SIEM and SOC integrations

Content for getting RoboDR findings into a SIEM and acting on them (gap T62).
Everything here consumes the `robodr.findings` contract
(`docs/contracts/robodr.findings.md`, JSON Schema
`docs/contracts/robodr-finding.schema.json`); nothing here talks to a robot.

| Directory | What | For |
|---|---|---|
| `schemas/` | contract + strict OCSF 1.1.0 schemas, `validate_findings.py`, ATT&CK for ICS table | any consumer (T61) |
| `verify/` | `robodr_verify.py`: per-finding Ed25519 signature check, for pipelines that cannot run the Rust verifier | the Logstash path (`logstash/`); any forwarder you build around it |
| `splunk/TA-robodr/` | Splunk add-on: sourcetype, CIM (Intrusion Detection) aliases, event types, alert searches | Splunk Enterprise / Cloud |
| `elastic/` | ingest pipeline (ECS mapping), index template, detection rules | Elastic Security 8.x |
| `logstash/` | Kafka -> verify -> Elasticsearch pipeline | Elastic, or any Logstash output |
| `sentinel/` | custom table, data collection rule, parser function, analytics rules | Microsoft Sentinel |

`integrations/check_content.py` checks every file here against the contract:
JSON/YAML well-formed, every finding field the content reads exists in the
schema, every rule id it names is in the detection catalog
(`docs/customer/detection-catalog.md`), the Elastic pipeline produces the
expected ECS document from real findings, the Elastic index template does
not index any of their attacker-controlled locations, every shared detection
carries the verification filter below, and the Sentinel DCR's columns match
its table. `crates/robodr-ocsf/tests/integrations_content.rs` runs it.

**What is and is not verified.** The checks above run in RoboDR's tests.
None of this content has been loaded into a running Splunk, Elastic or
Sentinel instance yet; doing that with a design partner's SIEM is the
remaining step (no licence or tenant was available). The Elastic check
evaluates the pipeline with an in-repo evaluator of the processors it uses,
not Elasticsearch itself.

## How findings reach a SIEM

1. **Kafka** (`robodr-kafka-publish`, topic `robodr.findings` by default):
   the record value is the finding JSON, the key the finding id, the header
   `robodr-finding-sig` its Ed25519 signature. Use Splunk Connect for Kafka,
   Logstash's `kafka` input (`logstash/`), or Azure Event Hubs' Kafka
   endpoint for Sentinel. Only the Logstash path has a signature check
   (below); the other two deliver findings unverified.
2. **AutoSecOps ingest API** (`robodr-uplink`, `docs/contracts/robodr.ingest-api.md`):
   batches of NDJSON signed per batch and per finding; AutoSecOps forwards
   to the SIEM.
3. **Files**: NDJSON (one finding per line) from `robodr-spool-export` or a
   diode import, for air-gapped sites.

## Verify signatures before you trust a finding

A finding is evidence only if its signature verifies under the key
registered for the robot the finding names. Verify **before** indexing,
over the record value bytes exactly as received (never a re-serialised
object: any re-formatting breaks the signature on purpose).

* Rust consumers: `robodr_ocsf::parse_and_validate_signed` (strict policy).
* Pipelines: `verify/robodr_verify.py` reads NDJSON lines
  `{"value": "<raw value string>", "headers": [["robodr-finding-sig", "<header>"]]}`
  (what the ruby filter in `logstash/robodr-kafka.conf` writes from
  Logstash's Kafka input with `decorate_events => "extended"`), checks the
  header, the finding's identity fields (robot, `external_id`,
  `finding_id`) and the signature (with the strict-verification checks:
  no weak or non-canonical keys or R), and emits the finding with a
  `robodr_verification` object (`status`: `verified` or, under
  `--policy optional`, `unsigned`; `key_id`). Records that fail are written
  to the reject file with the reason and never forwarded. It does **not**
  run the strict content validator (contract §2a step 2): run
  `schemas/validate_findings.py` as well (schema-level only). On the
  Logstash path a duplicated `robodr-finding-sig` header is collapsed to one
  by Logstash before the script sees it, so the contract's duplicate-header
  rejection cannot fire there (the remaining header must still verify).

**Which delivery paths verify.** Only the Logstash path ships a verifier,
and it is a file spool (`/var/spool/robodr-verify/`) plus a run of
`robodr_verify.py` that you schedule; its output feeds Elasticsearch.
Splunk Connect for Kafka and the Event Hubs / data collection rule path for
Sentinel have no verification step: findings arrive without
`robodr_verification`, anyone able to produce to the topic can forge them,
and nothing here wires a verifier into those paths. To verify for Splunk or
Sentinel, run `robodr_verify.py` on your own Kafka consumer and send its
output by HEC or the Logs Ingestion API; that is not shipped or tested.

**How the detections use the status.** Each of the five shared detections
(below) drops findings whose `robodr_verification.status` is present and not
`verified` (Splunk: `NOT robodr_verification.status=* OR
robodr_verification.status="verified"`; Elastic: `robodr.verification.status`;
Sentinel: `VerificationStatus`). Findings with no status, i.e. every finding
on a path without a verifier, still raise them. A sixth, low-severity
detection, **Unverified findings**, reports every finding that is not
verified, including those with no status, so an unverified path shows up in
each SIEM. An unverified finding must not trigger an automated response.

Keyring for `robodr_verify.py`: JSON `{"<robot id>": {"<key id>": "<64 hex public key>"}}`,
built from the finding keys registered at commissioning (one per robot,
previous keys kept during rotation).

## Field mapping

Map on the stable fields; never key detections on `title` or
`description` (they are catalog text and change between versions) and never
render a tainted `value` (attacker-controlled DDS names) where a person or an
LLM reads it: use its `display` form (ASCII-escaped, contract §3, SR-TAINT).

| Contract field | Splunk (CIM IDS) | Elastic (ECS) | Sentinel column |
|---|---|---|---|
| `finding_id` | `id` | `robodr.finding_id` (group repeats on it) | `FindingId` |
| `ocsf.metadata.uid` (unique per emission) | `robodr_event_uid` | `event.id` | `EventUid` |
| `timestamp` | `_time` | `@timestamp` | `TimeGenerated` |
| `entity_context.rule_id` | `signature_id` | `rule.id` | `RuleId` |
| `title` | `signature` | `rule.name` | `Title` |
| `severity` | `severity` | `event.severity` (from `ocsf.severity_id`), `log.level` | `Severity` |
| `entity_context.robot.id` | `dest` | `host.id`, `host.name` | `RobotId` |
| `entity_context.robot.site` | `dest_location` | `observer.geo.name` | `Site` |
| `entity_context.mode` | `robodr_mode` | `robodr.mode` | `Mode` |
| `entity_context.safety_state.motion` | `robodr_motion` | `robodr.safety_state.motion` | `MotionState` |
| `mitre_predictions{}.technique_id` | `mitre_technique_id` | `threat.technique.id` | `Techniques` |
| `ocsf.finding_info.data_sources{}` | `category` | `event.dataset` suffix, `robodr.data_source` | `DataSources` |
| `entity_context.ros.topic.display` | `robodr_topic` | `robodr.ros.topic` | `RosTopic` |
| `entity_context.ros.participant_guid.display` | `robodr_participant` | `robodr.ros.participant` | `Participant` |
| `entity_context.ros.src_ip.display` | `src_ip` | `source.ip` | `SourceIp` |
| `evidence_links{}` | `robodr_evidence` | `robodr.evidence_links` | `EvidenceLinks` |
| `external_id` | `robodr_external_id` | `robodr.external_id` | `ExternalId` |

Repeats of one finding (same `finding_id`) are updates
(`ocsf.activity_id` 2, `ocsf.count` grows); `ocsf.metadata.uid` is unique
per emission. Deduplicate on `ocsf.metadata.uid`, group on `finding_id`.

## Detections shipped

Each SIEM gets the same five, keyed on rule ids from the catalog, plus
"Unverified findings" (above):

| Detection | Rule ids | Why |
|---|---|---|
| Unauthorised motion source | `robot.ros2.unauthorized_motion_writer`, `robot.firewall.rejected_unknown_source`, `robot.unitree.legacy_unknown_sender`, `robot.unitree.webrtc_unknown_controller` | something that is not the robot's operator is commanding it |
| Motion outside the envelope | `robot.motion.linear_over_envelope`, `robot.motion.angular_over_envelope`, `robot.motion.joint_over_envelope`, `robot.firewall.joint_torque_out_of_envelope` | commanded motion beyond the locked profile |
| Correlated intrusion | `robot.correlate.*` | several independent sensors agree |
| Sensor blind or tampered | `robot.agent.input_silent`, `robot.agent.input_ended`, `robot.agent.queue_overflow`, `robot.agent.evidence_truncated`, `robot.rtps.discovery_not_inspected` | the robot cannot see; treat its silence as unknown, not safe |
| Unknown participant burst | `robot.ros2.unknown_participant`, `robot.ros2.discovery_flood` | reconnaissance or a rogue node on the robot network |

All five are in observe-only form: they alert, they do not respond. A SOC
never sends a motion command to a robot; response goes through the control
plane and the on-robot agent decides (`docs/contracts/robodr.control-plane.md`).
