# RoboDR -> AutoSecOps end-to-end results (task #7)

Run on 2026-10-26 in one container, with real processes only (no mocks):

- robodr at `682461b` (release build). The executor and agentd used for the
  red team were rebuilt at `0a1b040`, after executor M1 merged.
- autosecops1 `claude/robodr-ingest` at `7990c9a1`, with its app code
  unmodified.

Every key, certificate and password below is a throwaway test value.

**Verdict:** the robot to case path works end to end, over TLS and over
loopback, with both registration paths: fleet enrollment and manual keys.
Every ingest assertion passes. The evidence download works only after an
in-process scope patch. As shipped, AutoSecOps refuses it with 403 (defect
D1 below).

## Setup (what was actually run)

| Piece | How |
|---|---|
| Database | Fresh database `robodr_e2e` in `aso-test-pg`, then `TRACECAT__DB_URI=postgresql+psycopg://postgres:postgres@localhost:5432/robodr_e2e uv run alembic upgrade head`. Result: `alembic_version` = `b8d2f4a61c37` (head) |
| API | `start-aso-api.sh ENV LOG 8000` (uvicorn `autosecops.api.app:app`, no Caddy), plus a second instance with `--ssl-keyfile/--ssl-certfile` on 8443 using a throwaway CA (`mkca.sh`). `TRACECAT__API_ROOT_PATH=/api`; do not also pass uvicorn `--root-path`, because the prefix then doubles (`/api/api/health`). Redis uses db 7 (`redis://localhost:6379/7`) because db 0 holds stale case-duration events from the test suite. MinIO is `aso-test-minio` (`minio`/`password`) |
| Temporal | **Not needed.** The API starts without it and logs nothing fatal. Ingest, fleet, cases and the action gateway all work without Temporal |
| Tenant | `aso_setup.py`, through the API only. It registers the superadmin and gets the default org from `GET /admin/organizations`. It grants `robot_edr` with `PATCH /admin/tiers/organizations/{org}` `{"entitlement_overrides":{"robot_edr":true}}` (multi-tenant tier mechanism, `TRACECAT__EE_MULTI_TENANT=true`, no license key). It then invites an operator as organization owner, who registers, logs in and accepts |
| Robot 1 (`lab-ugv-001`) | **Fleet enrollment** (`register.py ... fleet`): `POST /robot-edr/robots`, then `POST /robot-edr/fleet/soc-keys {"kind":"fleet"}` (active at once), then `POST /robot-edr/robots/{id}/fleet/tokens`, then `robodr-enroll --config fleet.json --token-file token.txt` |
| Robots 2 and 3 (`lab-ugv-002`, `go2-e2e-001`) | Manual: `POST /robot-edr/keys` with roles `uplink` and `finding` (`require_finding_signature: true` for the Go2) |
| Profile | `commission.sh` runs the real CLI flow on the baseline capture: learn, confirm sign-off, Alice and Bob each sign, `lock --sign-key`, `trust-keys`, `verify-profile`. Output: `TRUSTED locked.json ... profile_version 1` |
| Audit sink | `audit_sink.py` on 127.0.0.1:8790, configured as both the org (`PATCH /settings/audit`) and platform (`PATCH /admin/settings/audit`) audit webhook |

Enrollment output:

```
key uplink: ed25519:accbcf135d45087c (generated), sha256:ac04a3f9...
key finding: ed25519:b6204e43b7853c29 (generated), sha256:2d1e89c6...
key blackbox: ed25519:fe0a89fcb66c01d3 (generated), sha256:e33eea84...
enrolled: robot lab-ugv-001 in workspace c427505f-... (site lab), answer signed by ed25519:6b255c59ea4b07e9
```

## Robot 1: ROS 2 rogue scenario (pcap replay)

`robodr-agentd --config agentd.json` with `sensor.capture.pcap_replay =
fixtures/captures/ros2-jazzy/fastrtps_rogue_cmd_vel.pcap`, using the
enrolled finding and black-box keys:

```
robodr-agentd: stopped: 508 datagrams, 0 events, 192 findings spooled, black box sealed at seq 545
ready=192 acked=0
   77  critical robot.motion.linear_over_envelope
   77  critical robot.firewall.rejected_unknown_source
   20  low      robot.rtps.discovery_removal
    8  medium   robot.ros2.unknown_reader
    7  high     robot.ros2.unknown_service
    1  high     robot.ros2.unknown_participant
    1  critical robot.ros2.unauthorized_motion_writer
    1  medium   robot.ros2.participant_removed
$ robodr-blackbox verify blackbox --keyring keys/blackbox.key.pub --checkpoint spool/checkpoint.json
RESULT: INTACT, CLEAN
```

Uplink over TLS with the test CA:

```
$ robodr-uplink --url https://127.0.0.1:8443/api --key-file keys/uplink.key --ca-bundle tls/ca.pem \
    --state-dir uplink-state --spool spool --once
robodr-uplink: https://127.0.0.1:8443/api/robot-edr/v2/ingest as ed25519:accbcf135d45087c (CA bundle)
{"batches":1,"lines_sent":192,"accepted":192,"created":9,"updated":183,"duplicates":0,"rejected":0,"replayed":0,...}
```

The database after delivery shows 9 findings, 9 cases and 9 `robodr` tags:

```
 rule_id                                | sev_id | occ | signature_key_id         | case | severity
 robot.ros2.unknown_participant         |      4 |   1 | ed25519:b6204e43b7853c29 |    1 | HIGH
 robot.ros2.unknown_reader              |      3 |   8 | ...                      |    2 | MEDIUM
 robot.ros2.unknown_service             |      4 |   7 |                          |    3 | HIGH
 robot.ros2.unauthorized_motion_writer  |      5 |   1 |                          |    4 | CRITICAL
 robot.motion.linear_over_envelope      |      5 |  77 |                          |    5 | CRITICAL
 robot.firewall.rejected_unknown_source |      5 |  77 |                          |    6 | CRITICAL
 robot.rtps.discovery_removal (x2 ids)  |      2 |14+6 |                          |  7,8 | LOW
 robot.ros2.participant_removed         |      3 |   1 |                          |    9 | MEDIUM
```

## Assertions (`e2e_checks.py`, against the TLS API)

```
PASS  A1 one case per distinct finding, all tagged robodr  -- spool=192 lines, 9 distinct findings; cases=9, robodr-tagged=9
PASS  A2 case severity/priority = finding severity; robot_id, site, rule_id fields  -- 9 cases checked
PASS  A3 re-sent findings are duplicates, no new case  -- HTTP 200 accepted=100 created=0 updated=0 duplicates=100; cases 9->9
PASS  A4 same batch id + body -> replayed:true, same counts  -- 1st replayed=False 2nd HTTP 200 replayed=True
PASS  A5 same batch id, other body -> 409 batch_id_reuse
PASS  A6 batch signed by an unregistered key -> 401 unknown_key
PASS  A7 batch claiming the uplink key id, signed by another key -> 401 bad_signature
PASS  A8 both 401s audited (actor ROBOT, status FAILURE, reason, client IP)
      -- /platform: actor=ROBOT action=ingest status=FAILURE ip=127.0.0.1 data={'sender_key_id': 'ed25519:9cdc06ce017b8bce', 'batch_id': 'e2e-rogue-...', 'failure_reason': 'unknown_key'}
      ;  /org:      actor=ROBOT action=ingest status=FAILURE ip=127.0.0.1 data={'sender_key_id': 'ed25519:accbcf135d45087c', 'batch_id': 'e2e-forged-...', 'failure_reason': 'bad_signature'}
PASS  A9 robot-2 finding in robot-1's uplink batch -> line rejected robot_mismatch, rest accepted
      -- rejected=[{'line': 1, 'code': 'robot_mismatch', 'detail': 'finding names robot lab-ugv-002, key is bound to lab-ugv-001'}] accepted=1
PASS  A10 finding bytes altered after signing (content-equal) -> bad_finding_signature
0 failure(s)
```

The first version of A10 changed the title. The validator then refused the
line as `invalid_finding` (inconsistent title), before checking the
signature. A content-equal byte change exercises the signature itself.

**Re-sending the same spool with `robodr-uplink`** (fresh state directory,
plain HTTP to 127.0.0.1:8000): the uplink derives batch ids from the input
position and the body, so the same spool produces the same batch id. The
server answered from the stored response (`"replayed":1`, the original
`created:9, updated:183` counts) and created no case. The case count stayed
at 9.

```
{"batches":1,"lines_sent":192,"accepted":192,"created":9,"updated":183,"duplicates":0,"rejected":0,"replayed":1,...}
```

`--url http://localhost:8000/api` is refused as usage (loopback must be an IP
literal). This matches the documented behavior.

## Robot 3: Unitree Go2 synthetic scenario

There is no Unitree pcap fixture in the repository. The capture comes from
the `crates/robodr-agentd/tests/unitree_live.rs` timeline:
`cargo test -p robodr-agentd --test unitree_live go2_end_to_end` leaves
`capture.pcap`, `profile.json` and `firewall.json` in its temporary
directory. The release `robodr-agentd` was then re-run on it under a new
robot id with a fresh finding key (manual registration,
`require_finding_signature: true`):

```
robodr-agentd: stopped: 57 datagrams, 0 events, 14 findings spooled, black box sealed at seq 44
RESULT: INTACT, CLEAN
{"batches":1,"lines_sent":14,"accepted":14,"created":10,"updated":4,"duplicates":0,"rejected":0,...}
 case | severity | rule_id                                     | occ | signature_key_id
   10 | CRITICAL | robot.motion.joint_over_envelope            |   4 | finding-go2-e2e-001
   11 | CRITICAL | robot.firewall.joint_torque_out_of_envelope |   1 |
   12 | CRITICAL | robot.firewall.joint_gain_out_of_envelope   |   1 |
   13 | CRITICAL | robot.firewall.joint_step_out_of_envelope   |   1 |
   14 | HIGH     | robot.motion.api_id_out_of_range            |   1 |
   15 | CRITICAL | robot.motion.linear_over_envelope           |   1 |
   16 | CRITICAL | robot.firewall.rejected_over_hard_limit     |   1 |
   17 | CRITICAL | robot.ros2.unauthorized_motion_writer       |   2 |
   18 | HIGH     | robot.ros2.unknown_participant              |   1 |
   19 | CRITICAL | robot.firewall.rejected_unknown_source      |   1 |
```

## Evidence: control plane v2 to a verified report on the case

Setup:

- Robot 1's agentd was restarted on the same black box (`agentd-cp.json`),
  with `control_plane` on mutual TLS at 127.0.0.1:8787. It used the test
  PKI in `crates/robodr-agentd/tests/data/control-tls` and a fresh SOC
  signing key.
- The AutoSecOps action gateway ran on a unix socket (`start-gateway.sh`).
- `evidence_e2e.py` called the shipped registry actions
  `tools.robodr.get_robot`, `list_evidence`, `create_evidence_export` and
  `download_evidence_export`. It used an executor JWT minted with the same
  service key, carrying the operator's user id, which is what a workflow
  run carries.
- The `blackbox_public_keys` input was omitted, so the action fetched the
  black-box key that robot 1 registered at fleet enrollment.

**As shipped: FAIL.** The robot side works: signed snapshot, inventory, and
an export with a verified manifest signature. AutoSecOps then refuses its
own internal calls:

```
POST /internal/robot-edr/evidence/access -> 403 insufficient_scope missing_scopes ['robot:read']
GET  /internal/robot-edr/robots/lab-ugv-001/blackbox-keys -> 403 (same)
EvidenceError: no black-box public keys given and none registered for the robot (TracecatAuthError); pass blackbox_public_keys
```

`list_evidence` also returned `"audit_logged": false` without raising an
error: the evidence-access audit write fails silently (defect D1b).

**With `robot:read` added in process (`gateway_scope_patch.py`, no change to
the repository): PASS.**

```
create_evidence_export: {"export_id": "e2e-51636dc77f53", "created": true, "answer_signature_verified": true, "manifest_signature_verified": true, ...}
download_evidence_export: verified = True stored = {"attachment_id": "87b0a04b-...", "attachment_name": "robodr-evidence-2143c6a30b9f6ad0.txt",
   "storage_key": "robot-edr/evidence/<ws>/<manifest sha>/<uuid>/bundle.rbbx", "bundle_sha256": "2143c6a3...", ...}
verification: {"verified": true, "steps": ["answer_signatures", "manifest_signature", "chunk_hashes", "bundle", "manifest_consistency"],
   "bundle_bytes": 22762, "intact": true, "problems": [], "device_id": "lab-ugv-001", "first_seq": 19, "last_seq": 52, "verified_records": 34, ...}
robot_evidence_export: e2e-51636dc77f53 | lab-ugv-001 | 2143c6a3... | 22762 | case 3fb2dca9-... (CASE-0004)
GET /cases/3fb2dca9-.../attachments -> [('robodr-evidence-2143c6a30b9f6ad0.txt', 1458)]
```

## Pass/fail summary

| # | Assertion | Result |
|---|---|---|
| 1 | Fleet enrollment (token, robodr-enroll, three keys registered, signed answer) | PASS |
| 2 | Cases created, tagged `robodr`, severity/priority and fields correct (ROS 2 + Unitree) | PASS |
| 3 | Dedup: same findings again, all `duplicates`, no new case | PASS |
| 4 | Replay: same batch id, `replayed:true` (also via `robodr-uplink` re-send) | PASS |
| 5 | Same batch id, other body: 409 `batch_id_reuse` | PASS |
| 6 | Wrong key: 401 + audit row (platform sink for unknown key, org sink for bad signature) | PASS |
| 7 | Finding for another robot: `robot_mismatch` line | PASS |
| 8 | Tampered finding: `bad_finding_signature` | PASS |
| 9 | TLS (CA bundle) and loopback plain HTTP both accepted | PASS |
| 10 | Evidence export verified and stored on the case | **FAIL as shipped (D1)**; PASS with the one-scope in-process patch |

## Defects found

- **D1 (AutoSecOps, High).** `autosecops/authz/scopes.py:437`
  `WORKSPACE_OPERATIONAL_SCOPES`, the scope set of every executor service
  principal, has no `robot:read`. Every route in
  `autosecops/robot_edr/evidence_router.py` (`:32` `case:update`+`robot:read`,
  `:51`, `:63`) requires it. As a result, `tools.robodr.download_evidence_export`
  can never store evidence from a workflow, and the registered-key lookup
  always fails.
  - The unit tests mock this path.
  - Fix: add `robot:read` to `WORKSPACE_OPERATIONAL_SCOPES`, or give the
    internal router an executor-specific check, and add an action-gateway
    test that uses a real executor token.
- **D1b (AutoSecOps, Medium).**
  `packages/autosecops-registry/autosecops_registry/integrations/robodr_control_plane.py:2104`
  `_record_access` swallows every exception and returns `False`. A 403 on
  the evidence-access audit is therefore invisible. Evidence reads happen
  unaudited on the platform side, with only `audit_logged:false` in the
  result.
- **D2 (robodr, Low).** `crates/robodr-export/src/bin/robodr-uplink.rs:334-342`
  prints `(CA bundle)` for a plain-HTTP loopback URL that has no CA bundle.
- **D3 (robodr docs, Low).** `docs/OPERATIONS.md:2189` says the AutoSecOps
  side of the fleet API "is not built yet". It is built, and enrollment
  works end to end as shown above.
- **Note.** `robodr-uplink` refuses a key file whose `key_id` is not the
  derived `ed25519:<16 hex>` id. Keys made with `robodr-blackbox keygen
  --key-id X` cannot be uplink keys, and the error message says so.
