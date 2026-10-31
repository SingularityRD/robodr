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
  **Fixed:** it prints `plain HTTP to loopback, no TLS`.
- **D3 (robodr docs, Low).** `docs/OPERATIONS.md:2189` says the AutoSecOps
  side of the fleet API "is not built yet". It is built, and enrollment
  works end to end as shown above. **Fixed** there and in the customer
  docs, README and GA roadmap.
- **Note.** `robodr-uplink` refuses a key file whose `key_id` is not the
  derived `ed25519:<16 hex>` id. Keys made with `robodr-blackbox keygen
  --key-id X` cannot be uplink keys, and the error message says so.

## Wave-2 soak and red team (2026-10-30)

Run on 2026-10-30, 13:12 to 15:15 UTC, on the wave-2 integration head
`1356263` (branch `wt/soak`), release build (rustc 1.98.1), real binaries
only. The defects found were fixed on the branch during the run
(`2876a46`, `8d26c63`, `2c43433`); the fixed binaries were re-tested end to
end (marked "after the fix" below). Every key and certificate is a
throwaway test value (`fixtures/tls`, `crates/robodr-agentd/tests/data/control-tls`,
keys generated at run time).

**Environment and limits (read this first).**

- One VM (kernel 6.18.44-fc), 4 vCPU, 16 GB RAM, no real-time
  kernel, **shared with another agent's CPU-heavy workload** (pytest
  workers, a type checker): CPU pressure (`/proc/pressure/cpu`, "some",
  avg60) mean 9.3 %, max 61 %, with hypervisor steal time. This run's
  builds and the red team ran in the same VM during the soak (13:28 to
  14:45, short bursts).
  Latency and "late" numbers below are those of this host, not of a
  sensor box.
- No robot, no sensor box, no hardware TPM (swtpm), no real Go2, Nav2,
  PX4 or Unitree sport peer. The ROS 2 traffic is the Gazebo lab capture
  replayed at 1x on veth pairs; the Unitree / trajectory traffic is
  synthetic (`robodr-firewall-gw` testkit frames, example
  `soak_traffic`).
- AutoSecOps was not running (its database and API are not up in this
  VM): `robodr-uplink` and the ingest red team (R7) were **not** re-run.
  Findings left the robot through `robodr-kafka-publish` to a real Kafka
  broker instead.
- About 2 hours of soak, not 72 hours.

### Soak topology (`soak2-setup.sh`, `gw-setup.sh`, `soak2.sh`)

| Piece | How |
|---|---|
| `robodr-agentd` `soak-ugv-001` | netns `rdr-rob`, live AF_PACKET capture on `rob-ugv`; profile commissioned with the real CLI flow (`commission.sh`, two operators, signed); control plane v2 on mutual TLS 127.0.0.1:8787 + unix socket; live safety feed (`/odom` of `gz_bridge` + a 0600 PLC socket fed `idle` every 200 ms); executor link; `gateway_feed`; remote head anchor over **mutual TLS** to `robodr-anchor-receiver`; status socket |
| `robodr-executor` | netns `rdr-rob`, real nftables; motion adapters: `gateway` for `restrict_motion` (OEM-validated in the lab config), `nav2` for `safe_pause` (no Nav2 peer: see A0) |
| `robodr-firewall-gw` | netns `sk-gw`, Linux bridge between controller (`sk-ctrl`) and robot (`sk-rob`) namespaces with `br_netfilter`, its own ruleset, NFQUEUE 11, `fail_closed`, `chrt -f 40` like the unit; channels Go2 `LowCmd` (500 Hz), sport `Move`, ROS 2 `JointTrajectory` (3 joints); signed profile; findings to agentd's `gateway_feed`; restriction file shared with the executor |
| Traffic | Gazebo baseline capture looped at 1x on `rob-ugv`; every 600 s the lab rogue capture (foreign participant, `/cmd_vel` 3 m/s). Through the bridge (`soak_traffic`, `chrt -f 30`): LowCmd 500 Hz, sport Move 0.3 m/s every 500 ms, a smooth trajectory every second, SEDP every 5 s; every 600 s one injection round (LowCmd torque over `tau_max`, an overshooting trajectory, a foreign writer's LowCmd) |
| Export | Apache Kafka 3.9.1 (local distribution, KRaft, **mutual-TLS listener**), `robodr-kafka-publish --spool` with CA, client cert and key |
| SOC | `soak_soc.py` with AutoSecOps's own SOC client code: a robot snapshot every 60 s, an evidence inventory every 4 min, a `restrict_motion` (max 0.2 m/s, TTL 180 s) every 15 min |
| Monitor | `soak2_monitor.py` every 60 s: RSS / CPU / fds / threads per process, spool, black box, gateway counters, anchor receiver, Kafka, PSI |

### Soak results (7201 s, 120 one-minute samples)

**Verdict:** no crash, no restart, no panic or abort in any log; every
process alive in all 120 samples and stopped cleanly. No leak visible in
2 hours. No data loss on the evidence and export paths: every finding
agentd spooled reached Kafka over mutual TLS, the black box verifies, the
remote anchor holds its last record. The false-positive picture is
dominated by this host (O1) and by one defect fixed during the run
(W2-3).

| Process | RSS first → last (max) | Slope, 2nd hour | CPU mean (max) | fds |
|---|---|---|---|---|
| robodr-agentd | 11.0 → 11.9 MiB (22.8 MiB) | +1.3 MiB/h, sawtooth: see O2 | 1.9 % (2.6 %) | 15 → 15 |
| robodr-firewall-gw | 4.1 → 4.2 MiB (4.2) | +0.04 MiB/h | 4.7 % (6.3 %) | 7 → 7 |
| robodr-executor | 4.0 → 4.3 MiB (4.3) | +0.1 MiB/h | 0.3 % | 4 → 4 |
| robodr-anchor-receiver | 3.9 → 3.9 MiB | 0 | 0.4 % | 5 → 5 |
| robodr-kafka-publish | 5.8 → 6.0 MiB | +0.1 MiB/h | 0.04 % | 5 → 4 |
| Kafka broker (JVM, reference) | 342 → 478 MiB | | 1.4 % | 190 → 186 |

agentd's baseline (between evidence inventories) stayed at 11.6-11.9 MiB
for the whole run; its maximum follows the evidence inventory (O2).

| Path | Numbers |
|---|---|
| ROS 2 capture | 377,993 datagrams inspected live, 249,503 motion events, no input drops; max queue age 3.3 s (host stalls: 3 `pipeline_lag`) |
| Rogue injections (11, every ~10 min) | each detected: `correlate.motion_hijack` 11/11, `rejected_unknown_source` and `linear_over_envelope` 374 each, `unauthorized_motion_writer` 1 (later ones counted as occurrences), discovery findings folded (`discovery_flood` 12) |
| Spool | 2,946 findings, 20.4 MB, max 5 waiting; 0 write errors, 0 dropped |
| Kafka (mutual TLS) | `published_total` 2,946 = spooled, 0 dead-lettered, one partition (keyed by robot) |
| Black box | 8,408 records, 9.4 MB, `robodr-blackbox verify`: `RESULT: INTACT, CLEAN` |
| Remote anchor (mutual TLS) | 1,453 head marks, 0 errors, 0 anchor failures; receiver `held_seq` 8407 = the last record, 0 alerts |
| Inline gateway | 3,623,018 packets; recv → verdict p50 53 µs, p99 129 µs, max 133 ms; `rewrite_failed` 0, `undecidable` 0, `sn_jumps` 0, `replays` 0; `late` 16,573 (O1) |
| LowCmd 500 Hz through the bridge | 3,600,001 sent, 3,599,989 received (12 lost, 0.0003 %), 3,583,504 byte-identical; 16,485 modified: 11 injected torque frames limited, the rest late-packet substitutions (O1). Send → receive latency p50 166 µs, p99 1.7 ms, p99.9 135 ms, max 1.18 s; per-minute p99 median 1.07 ms, above 5 ms in 5 of 120 minutes (host stalls) |
| Sport Move | 14,368 sent, 14,367 received; 1,853 modified: 1,792 capped to 0.2 m/s while a SOC restriction was in force (`restriction_capped`), the rest late-packet zero-velocity substitutions |
| JointTrajectory | 7,203 sent, 7,154 byte-identical; 49 not forwarded: the 11 injected overshoots (refused) and 38 decided late (fault verdict) |
| Foreign LowCmd writer (11 injections) | 11 datagrams reached the robot with the sample removed; never a foreign LowCmd |
| SOC (mutual TLS) | 120 snapshots: 119 OK, p50 32 ms, max 77 ms; 1 refused at start (O3). 30 evidence inventories OK |
| SOC `restrict_motion` (8, every 15 min) | 5 verified (the gateway showed the restriction within 5 s) and reverted at their TTL (adapter undo verified, file removed); 3 refused `safety_state_unavailable`, judged while the replayed `/odom` was stale (the safety state was `unknown` in 49 of 120 snapshots: gaps of the looped capture). nftables empty at the end |
| CPU pressure (PSI some, avg60) | mean 9.3 %, max 61 %, above 20 % in 5 minutes |

**Findings by cause (2,946):**

| Cause | Count | Severity |
|---|---|---|
| Rogue injections (inside a 120 s window after each) | 830 | as designed |
| Gateway injections (torque limited, overshoot refused, foreign writer) | 33 | as designed (11 rounds x 3) |
| SOC restriction applied / lifted on the gateway (informational) | 10 | Low |
| Gateway late-packet fault verdicts and rate-window violations on clean traffic (O1: this host) | 2,031 | 1,364 Critical `internal_fault`, 658 Medium `joint_rate_violation`, 9 High `rejected_rate_limited` |
| `input_silent` for the gateway feed (W2-3, fixed) | 16 | High |
| End of the looped Gazebo capture: a profiled participant disposes (first loop) | 21 | 20 Low, 1 Medium |
| Host stalls: `pipeline_lag` x3, `uncommanded_motion` x1 (odometry inspected 2 s late, during a lag) | 4 | Medium / High |
| SOC request in the start-up fence (O3) | 1 | High |

So on clean traffic agentd's own detectors raised nothing that the
replay loop or a host stall does not explain; the clean-traffic rate the
SOC would have seen here (858 findings per hour) is almost entirely the
gateway's late-packet faults of this host plus W2-3, and does not
measure the FP target of Kapı 3 (< 1 false alarm per robot per day),
which needs a real robot on a real-time host.

### Secure delivery through the agent binary (swtpm)

`crates/robodr-depot/tests/soak_binaries.rs` (`ROBODR_SWTPM=1
ROBODR_SOAK_ROLLOUTS=12`, ignored by default): one lease-gated unit
(swtpm, real `tpm2-tools`), the depot's LAN server
(`robodr_depot::serve::serve`, the function `robodr-depot serve` runs, in
the test process) and the **shipped `robodr-deliverd run` binary** as the
unit agent. 12 releases, each a new bundle chained to the previous one,
imported with its entry report, rolled out and approved; every third also
a sealed model.

| Measured | Result |
|---|---|
| Releases installed | 12 / 12 (16 installs: 12 files RPKs + 4 sealed models), none rolled back |
| Time to installed | 2.3 s for the first, then 58-62 s (the agent pulls once a minute) |
| Agent RSS | 7.9 MB → 8.0 MB over 11 min |
| Leases | renewed with each report (lease 17 in force at the end); the first sealed model waited for the first lease (`robot.seal.lease_expired` x1, then installed) |
| Erase-trigger spoofing | `robodr-deliverd tamper` as uid 65534 (socket made 0666 on purpose), `operator` and `signed_command` triggers, another format version, an unknown key, garbage, a spooled finding named `robot.seal.tamper`: **no erase**, the unit still unseals |
| Tamper input while `moving_fast` | deferred (`robot.seal.erase_deferred`), nothing erased |
| Then `idle` | erased 0.35 s later (`robot.seal.erased`, the TPM refuses every unseal: `Erased`) |
| Lease replay after the erase | `robodr-deliverd lease` with lease 2: refused "lease 2 is older than the lease 17 in force (replay)"; still erased |

The swtpm-gated suites of the three crates were also run in release
(`ROBODR_SWTPM=1`): robodr-depot (incl. `exit_14a`, `exit_14b`,
`adversarial_14a`) and robodr-deliverd all pass; robodr-seal passes
(65 tests) on one of three runs, the other two each had one or two tests
fail in the harness with "swtpm did not start" / "Could not load tcti"
(the software TPM never came up on this loaded host; a different test
each time, never an assertion of the product).

### Red team (wave 2), end to end through the binaries

Target `rt-ugv-001`: its own agentd, executor, anchor receiver
(namespace `rt-rob`, attacker namespace `rt-gen`), and a second inline
gateway (`PFX=rk`, NFQUEUE 12, Go2 `webrtc` section with the controller
MAC-bound, `block_unlisted`). Scripts: `redteam2.sh`,
`redteam2_cp.py`, `redteam2_feed.py`, `redteam2_tls.py`,
`redteam2_webrtc.py`, `redteam_net.py`, `soak_traffic attack`.

**Previous scenarios (REDTEAM.md), re-run on the wave-2 head**

| # | Attack | Observed | Verdict |
|---|---|---|---|
| R1 | Rogue DDS participant (lab rogue capture, live, 1x) | `unknown_participant` x3, `unauthorized_motion_writer` x1, `rejected_unknown_source` x34, `linear_over_envelope` x34, `correlate.motion_hijack` x1, `discovery_flood` x9 | PASS |
| R2 | GUID spray, 3000 random prefixes at 873 pps | **8** findings (`discovery_flood`) instead of ~5000 on 2026-10-26 (F1 fix holds through the binary); agentd alive, RSS +0 | PASS |
| R3 | Malformed / truncated / mutated / 60 KiB fragmented RTPS, 64 KiB non-RTPS | `malformed_discovery` x4, `discovery_not_inspected` x20; alive, RSS +0.2 MB | PASS |
| R4a | `/odom` of `gz_bridge` replayed from a foreign IP | `safety_state.untrusted_source` x1, `participant_source_mismatch` x4, `sample_source_mismatch` x2; feed `untrusted: 1514` vs `applied: 1317`; state never taken from the spoof | PASS |
| R4b / R4c | Safety socket as uid 65534; malformed and unknown states as root | `Permission denied`; `malformed: 3`, nothing applied | PASS |
| R5-R5f | CP replay, foreign signature, unknown key, altered body, timestamp ±1 h, other robot id | `401 replayed_nonce`, `401 bad_signature`, `401 unknown_key`, `401 bad_signature`, `401 stale_timestamp` (both), `404 unknown_robot` | PASS |
| R6a / R6b | Executor: wrong HMAC; HMAC-valid order claiming SOC approval without the signed request | closed unanswered; `refused soc_signature_invalid` | PASS |
| R6c | `isolate_network` (TTL 45 s), SOC-signed | `verified`; management, uplink and motion path kept; reverted at the TTL, table gone | PASS |
| R6e | `quarantine_node` of the live rogue | **now executed**: `verified`, `containment: guid_only` (the rogue shares 10.77.10.10 with the robot's own profiled participants, so its locators and address are excluded and listed with the reason); reverted on request. On 2026-10-26: refused `locators_required` | PASS (GUID-prefix only, visible to the SOC) |
| R7 | Forged / replayed ingest batches | not re-run (AutoSecOps not running) | NOT RUN |

**New scenarios for wave-2 features**

| # | Attack | Observed | Verdict |
|---|---|---|---|
| T0-T16 | JointTrajectory through the real bridge: point 0.01 rad past `max_position`; points in bounds whose spline overshoots (2.145 > 2.0); velocity 3 rad/s; a 1.5 rad jump in 0.1 s; time not increasing; NaN; duplicate joint name; permuted joint order; 300 points; 30 s duration; replay of a forwarded sample (same sn); future (+1 h) and past (-10 s) `header.stamp`; stamp nanosec ≥ 1e9; a future stamp on an overshooting trajectory | every violation suppressed (DATA removed; `trajectory_rejected` / `undecodable_command` / `replays`); both stamp tricks forwarded with the stamp zeroed (`trajectory_stamp_zeroed`); the stamp does not hide an overshoot; valid trajectories (also big-endian CDR) byte-identical | PASS |
| G1 | Gateway feed: connect as uid 65534 | `rejected_connections`, no finding from it | PASS |
| G2 | Feed line naming another detector's rule (`robot.ros2.*`) | malformed | PASS |
| G3 | Feed line naming `robot.firewall.` / a made-up `robot.gateway.*` id | **accepted and spooled** as a finding with that id → fixed (`2876a46`): malformed after the fix | FIXED |
| G4 / G5 | Unknown key, other format, bad severity; 64 KiB detail; 2 MiB line without newline | malformed, RSS +0.1 MB | PASS |
| G6 | ANSI escapes / CR LF in a detail | accepted as data, escaped in the finding and the log | PASS |
| G7 | A Critical firewall rule claimed `low` | accepted with the gateway's severity (the feed is a trusted, root/gateway-uid channel) | NOTE |
| G8 / G9 | 20000 valid lines, then 5000 Critical lines, as fast as possible (as root) | input queue bounded (15891 / 895 dropped, `queue_overflow`), 3636 + 3432 findings spooled, RSS +2.2 MB, alive; one finding per line (no aggregation in agentd for this trusted channel) | NOTE (W2-5) |
| G10 | 20 idle connections | 18-19 refused (`max_connections`), the gateway reconnects | PASS |
| W0 / W5 | Listed controller: `POST /offer`, STUN, DTLS | answered, no finding; still served after the floods | PASS |
| W1 | Unlisted host: `POST /offer`, STUN, DTLS | signalling SYN dropped (`block_unlisted`), `webrtc_unknown_controller` (High); its STUN / DTLS UDP still reaches the robot (by design: only signalling is blocked; a session is cut with `webrtc-block`) | PASS (as designed) |
| W2 | Controller's IP from the attacker's MAC | dropped, `webrtc_controller_mac_mismatch`: the bridge delivers `NFULA_HWADDR` for bridged copies and bridge-family `log group` drops (open item of the gateway README, now exercised on a real bridge in a netns) | PASS |
| W3 / W4 | 20000 STUN requests, then 20000 SYNs to 8081, from ~1100 spoofed sources (80-145 kpps) | 30 findings (rate limit 32/min), gateway RSS +0.1 MB, motion path unaffected; **the "N further suppressed" aggregate was only reported with the next packet (2.5 min later, "in the last 60 s")** → fixed (`8d26c63`): after the fix it arrives 12 s after the window ends, with no further traffic ("43383 further ...") | FIXED |
| A0 | `safe_pause` approved by two distinct people (positive control) | passes the two-person gate, reaches the nav2 adapter, `failed` "cancel_goal: no answer from the peer" (no Nav2 here), undone | PASS (gate) |
| A1-A5, A10 | Same person in another case; requester as approver (also in another case, also padded with spaces); exact duplicate; a single approver | `refused approval_missing` "names 1 usable" | PASS |
| A6-A9, A11, A13 | Cyrillic homoglyph, zero-width space, leading space, 5 approvers, empty name, fullwidth Latin | `400 invalid_field` | PASS |
| A12 | `bob+1@soc` and `bob+2@soc` (one mailbox) | passes the gate | NOTE (documented: names are asserted by the SOC) |
| M0 | `restrict_motion` through the gateway adapter | `verified`, the gateway's status shows the restriction | PASS |
| M1 | Restriction file deleted behind the executor | re-applied by the executor's verification (file back, gateway shows it) | PASS |
| M2 / M3 | World-writable restriction file; a symlink | ignored, `restriction_error` names why | PASS |
| R6f-R6h | Executor socket: forged `safe_pause` with approvers, forged `restrict_motion` naming the gateway, replayed envelope (same nonce) | closed unanswered / `refused soc_signature_invalid` / second refused; nothing applied | PASS |
| S1 | TLS slowloris on the control plane, 1 source x 8 connections, 1 byte/s, 40 s | per-source cap holds: SOC 20/20 requests OK | PASS |
| S2 | Same from 8 / 32 loopback sources x 2 | **SOC locked out**: 3/20 and 1/20 requests OK during the attack (ConnectionReset), all OK at once afterwards | ISSUE (W2-4) |
| S3 | TLS slowloris on the anchor receiver, 10 sources x 8 (fills `max_connections` 64) | receiver logs "64 connections open; closing new ones"; agentd counts `anchor_failures: 2`, recording continues, held seq still advances | PASS (as designed) |
| D1-D3 | Erase-trigger spoofing, deferred / executed erase, lease replay (delivery section above) | as above | PASS |

### Defects and issues

- **W2-1 (Low, fixed `2876a46`).** agentd's `gateway_feed` checked only the
  rule id's prefix: `robot.firewall.` or any made-up id in the two
  namespaces became a finding with the generic catalog entry. Only
  catalogued ids pass now (`robodr_ocsf::builder::rule_known`); the
  regression also guards every id the gateway and the firewall emit.
- **W2-2 (Low, fixed `8d26c63`).** The Go2 WebRTC monitor reported a
  flood's aggregate only with the next packet; a flood followed by
  silence reached the SOC as its first 32 findings. The gateway's
  housekeeping now rolls the window (`WebRtcMonitor::tick`).
- **W2-3 (Medium, fixed `2c43433`).** The gateway feed carried findings
  only, so a quiet, healthy gateway made agentd report
  `robot.agent.input_silent` (High, "the agent is blind on it", state
  `unknown`) after every `silence_ms`: 16 times in the soak, and
  within 30 s on the red-team target whose gateway had nothing to
  report. An idle gateway now writes a heartbeat line every 5 s; a
  gateway that stops writing is still reported. Verified after the fix:
  70 s of an idle gateway, 14 heartbeats, no `input_silent` for it.
  Upgrade agentd before the gateway (an older agentd counts the
  heartbeat as malformed).
- **W2-4 (Medium, not fixed, documented).** Control-plane connection
  slots: 4 pre-authentication slots, 2 per source, a 5 s handshake / read
  deadline. An unauthenticated peer with 3 or more source addresses that
  reopens TLS handshakes trickling a byte a second keeps every slot busy
  and the SOC cannot reach the robot while it lasts (S2). The robot keeps
  detecting and recording; the mitigation today is the documented
  `IPAddressAllow=` drop-in for the SOC network (OPERATIONS §6.4), so the
  attacker must be on an allowed address. A product fix (evicting the
  oldest pre-authentication connection when a new one arrives, or a
  reserved slot for allow-listed client addresses) was not attempted.
  **Update (T39, `8e51ad9`):** both are in agentd now
  (`pre_auth_evict_after_ms`, `soc_sources` / `reserved_connections`,
  contract §1); the in-process regression
  `slowloris_cannot_lock_the_listed_soc_out` gets 20/20 SOC requests
  through an 8-connection trickling attacker (0/20 without the fix). The
  netns re-run of S2 with the release binaries is still to do.
- **W2-5 (Low, design note).** The gateway feed is trusted by uid: a
  process running as root or as the gateway's user can claim any
  catalogued gateway / firewall finding and its severity (G7) and can
  flood agentd's spool with one finding per line (G8 / G9); agentd's
  flood folding covers discovery findings, not this channel.
- **O1 (environment, product question).** On this host the gateway read
  0.46 % (16,573 of 3,623,018 packets) of the soak's LowCmd frames more than `max_queue_delay_ns` (5 ms)
  after their arrival, even at FIFO priority: each got the fault verdict
  (a damping frame substituted, `robot.firewall.internal_fault`
  Critical, aggregated per burst), 1,364 Critical findings in the
  soak. That is the documented fail-safe behaviour of an overloaded box;
  on a real sensor box with an RT kernel it must be re-measured. The rule
  name says "internal fault" for what is an overload: a distinct rule or
  an aggregate per minute would help a SOC.
- **O2.** `GET .../evidence` (inventory) indexes the whole retained black
  box: agentd's RSS rose by about the size of the open segment for a few
  minutes after each call (11.6 MiB → up to 22.8 MiB with a 9.0 MiB
  black box) and came back. Bounded by the 8 x 8 MiB default retention
  (segment buffer plus per-record metadata), not a leak.
- **O3.** After an agentd start with a new replay store the control plane
  refuses requests signed in the first `max_clock_skew_s` (documented
  fence, contract §2); the refused SOC request raises
  `robot.agent.control_plane_unauthenticated` (High) worded as if someone
  without a key tried: one false alarm per such start.

### What was not covered (still unverified)

- A real robot, a sensor box, a real-time kernel, arm64 hardware; a
  hardware TPM (only swtpm); 72 hours (2 hours here); the FP target of
  Kapı 3.
- Nav2, ros2_control, PX4 and Unitree sport peers: no simulated peer
  was built for the binaries, so `safe_pause` was exercised up to the
  adapter (the approval gate and the "no answer" undo), not to a peer's
  reply. The `gateway` adapter was exercised end to end.
- `robodr-uplink` and the AutoSecOps ingest (R7), the evidence export to
  a case, fleet enrollment (AutoSecOps not running in this VM).
- The depot as the `robodr-depot serve` **binary** (its serve function
  ran in the test process), depot TLS slowloris, a media pack carried
  by hand; `robodr-pulsard` / eBPF and host-threat forwarding.
- Kafka SASL / SCRAM and broker restarts during the soak (mutual TLS
  only); the Kafka TLS listener was not attacked.
- The NFQUEUE "late" behaviour on real hardware (O1), and whether the
  gateway's real-time priority prevents it there.

### Re-running

```sh
export CARGO_TARGET_DIR=/path/to/target ROBODR_BIN=$CARGO_TARGET_DIR/release
cargo build --release -p robodr-agentd -p robodr-firewall-gw -p robodr-executor \
  -p robodr-blackbox -p robodr-export -p robodr-commission
cargo build --release -p robodr-firewall-gw --example soak_traffic
tools/e2e/netns.sh up
tools/e2e/gw-setup.sh up RUN/gw RUN/gateway-feed.sock RUN/restrict/restriction.json
tools/e2e/soak2-setup.sh RUN KAFKA_HOME        # KAFKA_HOME: an Apache Kafka 3.9 distribution
tools/e2e/soak2.sh start RUN KAFKA_HOME 7200 600
tools/e2e/soak2.sh stop RUN KAFKA_HOME; tools/e2e/soak2_report.py RUN
# delivery through the agent binary (swtpm + tpm2-tools)
ROBODR_SWTPM=1 ROBODR_SOAK_ROLLOUTS=12 cargo test --release -p robodr-depot \
  --test soak_binaries -- --ignored --nocapture
```

The red-team target is the same setup with `RID=rt-ugv-001 SUB=rt
IFACE=rob-rt CPPORT=8788 APORT=7462 NOKAFKA=1` and `PFX=rk QNUM=12
WEBRTC=1`, started with `redteam2.sh start RUN` (namespaces `rt-rob` /
`rt-gen` hold the `rob-rt` / `gen-rt` link; see the scripts' headers).
