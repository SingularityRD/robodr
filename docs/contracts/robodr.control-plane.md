# Contract: `robodr.control-plane` (robot action requests)

| | |
| --- | --- |
| API version | `robodr-control-plane/v1` |
| Producer of answers | `robodr-agentd` (`crates/robodr-agentd/src/control/`), config key `control_plane` |
| Consumer | any SOC integration that sends approved robot actions (requirements in §9) |
| Action catalog | `robodr_responder::actions` (one list shared with the planner; §4) |
| Superseded | the first draft, written for a cancelled integration: [`legacy/robot-edr.control-plane.md`](legacy/robot-edr.control-plane.md) |
| Status | **Experimental.** Off by default. **Nothing is executed** in this release |
| Reference tests | `crates/robodr-agentd/tests/control_plane.rs` (end to end, real daemon), unit tests in `src/control/{http,auth,api,mod}.rs` |

A SOC asks the robot for one of the seven catalog actions. The on-robot agent
checks the request against the robot's **current** safety state, operational
context and response policy (Cyber-Jidoka), records request and decision in
its signed black box and answers. The SOC never commands motion and never
overrides the platform's safety authority: the strongest action is a
*request* for a safe state, which the platform's safety controller decides on.

In this release agentd has no executor that acts on the robot. The only
executor is the recording one: an accepted request is answered
**`recorded_not_executed`** ("accepted and recorded as a plan, not
executed"), with `"executed": false`. A consumer must report that as "not
applied", never as success.

## 1. Transport

* HTTP/1.1, one request per connection (`Connection: close`), JSON bodies,
  no chunked encoding, no keep-alive. Limits: head 8 KiB, 32 header lines,
  target 1 KiB of `[A-Za-z0-9-._~%/:]` (no query string), body 16 KiB with an
  exact `Content-Length`; the request must arrive within 5 s.
* Listeners (at least one): `listen_tcp` (loopback unless `allow_remote:
  true`) and / or `unix_socket` (mode `0600` or `0660`, private directory).
* **No TLS** (agentd is std-only). Requests are authenticated (§2) but not
  confidential. For a remote SOC terminate TLS in front of the loopback
  listener (the signature covers the exact target and body, so the proxy
  must forward both unchanged). `Authorization` headers are ignored.

## 2. Authentication

Every request, reads included, carries:

| Header | Value |
| --- | --- |
| `X-RoboDR-Key-Id` | the SOC key id (one of `control_plane.soc_keys`) |
| `X-RoboDR-Timestamp` | Unix seconds, decimal |
| `X-RoboDR-Nonce` | 16..128 characters of `[A-Za-z0-9_-]`, never reused |
| `X-RoboDR-Signature` | Ed25519 signature, 128 hex characters |

The signature is over these lines joined by `\n` (no trailing newline):

```text
robodr-control-plane/v1
<METHOD>
<request target exactly as sent, e.g. /api/v1/robots/ugv-007/action-requests/robot_safe_pause%3Augv-007>
<robot id>
<key id>
<timestamp>
<nonce>
<lower-case hex SHA-256 of the body bytes (of the empty string for a GET)>
```

The robot id is the one agentd is configured with: a request signed for
another robot never verifies. agentd then requires
|robot clock − timestamp| ≤ `max_clock_skew_s` (default 30 s; both sides need
NTP) and a (key, nonce) pair it has not seen while that timestamp is in the
window (cache of 8192 live entries; refused with 503 `replay_cache_full`
when full, never accepted unchecked). Authenticated requests are rate-limited
per key (`rate_per_minute`, default 30, `burst` 10; 429 with `Retry-After`).

SOC keys are `robodr-blackbox keygen` public key files (`algorithm:
ed25519`, `key_id`, `public_hex`, optional `device_id` which must then be
this robot). A secret key file, a group/other-writable file, a symlink, or a
key id equal to the robot's black-box or finding key is refused at start.

**Answer signature.** With `finding_signing` configured, every answer to an
authenticated request carries
`X-RoboDR-Answer-Signature: ed25519;key_id=<finding key id>;sig=<128 hex>`
over

```text
robodr-control-plane/v1 answer
<the request's X-RoboDR-Signature, lower-case hex>
<HTTP status>
<lower-case hex SHA-256 of the answer body bytes>
```

verifiable with the robot's finding public key (the key the SOC already holds
for `robodr-finding-sig`). Binding to the request signature (and so to its
nonce) stops a replay of an old answer. Answers to unauthenticated requests
are never signed.

## 3. Calls

Paths under `/api/v1`. `{robot_id}` must be this robot (else 404
`unknown_robot`); `{request_id}` is percent-decoded and must match
`[A-Za-z0-9._:-]{1,128}`.

| Call | Body | Answer |
| --- | --- | --- |
| `GET /robots/{robot_id}` | — | robot snapshot (§3.1) |
| `POST /robots/{robot_id}/action-requests` | action request (§4) | request state (§5) |
| `GET /robots/{robot_id}/action-requests/{request_id}` | — | request state |
| `POST /robots/{robot_id}/action-requests/{request_id}/revert` | `{"reason"?, "requested_by"}` | request state with the revert result (§6) |

### 3.1 Robot snapshot

```json
{"robot_id": "ugv-007", "online": true, "api": "robodr-control-plane/v1",
 "safety_state": {"state": "moving_slow", "source": "safety_feed", "safety_system_engaged": false},
 "mode": "enforce", "health": "ok", "executor": "recording", "executes_actions": false,
 "morphology": "wheeled_mobile",
 "actions": ["restrict_motion", "quarantine_node", "isolate_network", "record_evidence",
             "safe_pause", "request_safe_state", "rollback_config"]}
```

`morphology` is the response policy's (`unspecified` when it declares
none). `actions` lists only what this robot may be asked for: an action
refused for its morphology (`fall_hazard`, §4.1) is not advertised — a
humanoid lists neither `safe_pause`, `request_safe_state` nor
`rollback_config`; a quadruped not `rollback_config`.

`safety_state.state` is the state requests are judged by right now (live feed
or configuration, `source`). `mode` is `observe` when the profile is not
locked and enforced or the policy is not OEM-validated (every request is then
refused). `health` is the daemon's self-health (`ok`, `degraded`,
`unknown`).

## 4. Action request

```json
{"request_id": "robot_restrict_motion:ugv-007:3f2a9c0d11e45b6a",
 "action": "restrict_motion",
 "parameters": {"max_linear_speed": 0.5},
 "ttl_seconds": 600,
 "reason": "rogue /cmd_vel writer",
 "requested_by": "analyst@soc",
 "source": "soc-a",
 "authority": "request"}
```

Strict: unknown or duplicate keys at any level refuse the body; the body must
be an object and `parameters` an object (or absent / null = `{}`).

`action` is the catalog name (`robodr_responder::actions`; the control
plane's `ActionKind` *is* the catalog's `ActionId`, and a test asserts the
parser accepts exactly the catalog). A SOC may register the actions under
their wire names (`robot_<name>`); it sends the plain name here.

| `action` | Wire name | Parameters (only these) | `ttl_seconds` | Reversible | Ladder step | SOC approval | GA |
| --- | --- | --- | --- | --- | --- | --- | --- |
| `restrict_motion` | `robot_restrict_motion` | at least one of `max_linear_speed`, `max_joint_speed` (in (0, 10]; 0 is a stop: use `safe_pause`), `workspace_zone` (`[A-Za-z0-9._-]{1,64}`) | required, 1..=86400 | yes | `limit_motion` | single | executed |
| `quarantine_node` | `robot_quarantine_node` | exactly one of `participant_guid` (24 or 32 lower-case hex), `node` (plain ROS 2 name) | not allowed | yes | `restrict` (participant) | single | executed |
| `isolate_network` | `robot_isolate_network` | none | required, 1..=86400 | yes | `restrict` (network) | single | executed |
| `record_evidence` | `robot_record_evidence` | none | not allowed | not applicable: evidence is never reverted (a revert answers `not_reversible`) | `record` | single | executed; accepted in every safety state and in observe mode |
| `safe_pause` | `robot_safe_pause` | none | not allowed | yes | `safe_pause` | two-person | platform adapter only (OEM-validated policy); never on a humanoid |
| `request_safe_state` | `robot_request_safe_state` | none | not allowed | no (an operator restarts) | `request_safe_state` | two-person | plan only; never on a humanoid |
| `rollback_config` | `robot_rollback_config` | `config` (`profile` default, or `program`), `to_version` (`[A-Za-z0-9._-]{1,64}`) | not allowed | no | `restrict` (needs `idle`) | two-person | plan only; never on a humanoid or quadruped (a controller restart) |

No action is ever autonomous: the SOC sends one only after the approval
above. The "GA" column is the catalog's plan for the first executing
release; in this release nothing is executed (§5).

`authority` must be `"request"`. `reason` ≤ 500 characters (may be empty),
`requested_by` 1..=100 characters, neither with control characters;
`source` `[a-z0-9_-]{1,32}`. No field can carry a motion command, a force or
an override.

Body errors are answered with an HTTP error (§7) and recorded
(`robodr.control_plane_rejected`), never judged: `unknown_action`,
`unknown_field`, `duplicate_field`, `parameter_not_allowed`,
`invalid_parameter`, `ttl_required`, `ttl_out_of_range`, `ttl_not_allowed`,
`authority_not_allowed`, `invalid_request_id`, `invalid_field`,
`invalid_request`.

### 4.1 Judgment (Cyber-Jidoka)

`record_evidence` is judged first and always accepted: it is evidence
capture only and sends nothing to the platform, so it is allowed in observe
mode and while the safety system is engaged. Every other action: in order,
the first rule that applies refuses (`refusal.code`):

| Code | When |
| --- | --- |
| `safety_system_engaged` | the safety state is `estop_active` or `safe_state_active` (every action, including `request_safe_state`): the safety system has authority and gets no competing request |
| `observe_mode` | the profile is not locked and enforced, or the response policy is not OEM-validated |
| `morphology_mismatch` | the robot context's `morphology` differs from the response policy's |
| `human_in_command` | a motion-affecting step (`limit_motion` and up) while `context.control` is `teleop` or `manual` |
| `transient_phase` | a motion-affecting step during take-off / landing |
| `fall_hazard` | `safe_pause` or `request_safe_state` while the response policy's `morphology` is `humanoid` (or unspecified): those may damp or de-energise the joints and a humanoid would fall (advisory only); `rollback_config` while it is `humanoid` or `quadruped` (or unspecified): a controller restart collapses a robot that balances actively — also when `idle`, since a legged robot balances while idle; a `restrict_motion` cap that scales the profile envelope below the policy's `min_motion_factor` (default 0.2), or a cap with no profile envelope to judge it against, on a humanoid or quadruped (a near-stop envelope also stops the balance corrections) |
| `requires_idle` | `rollback_config` while the safety state is not `idle` |
| `above_policy` | the action's ladder step is above the highest step the policy's matrix allows in the current state for any severity |
| `not_a_restriction` | a `restrict_motion` cap above the profile's smallest envelope for that quantity |
| `invariant_violation` | the plan the request stands for fails `robodr_responder::check_invariants` (as a human-approved plan) |

`isolate_network` and `quarantine_node` are accepted on a humanoid, but a
SOC should send them only when the robot's balance loop is not networked:
where the low-level loop is a DDS writer (Unitree `rt/lowcmd`), cutting that
writer trips the motor watchdog and the robot falls (the on-robot planner
only plans them for a humanoid when the OEM listed them as balance-safe in
the policy's `fall_safe_restrict`).

An `unknown` safety state does not refuse by itself: the planner needs a
human's approval there, and the SOC's (approved) request stands for it; the
answer's `state.notes` says so. A refusal is final: agentd never retries it
and a consumer must not either.

## 5. Request state

```json
{"request_id": "robot_restrict_motion:ugv-007:3f2a9c0d11e45b6a",
 "status": "recorded_not_executed",
 "executed": false,
 "duplicate": true,
 "refusal": {"code": "safety_system_engaged", "reason": "...", "safety_state": "estop_active"},
 "state": {"robot_id": "ugv-007", "action": "restrict_motion", "parameters": {...},
           "ttl_seconds": 600, "requested_by": "analyst@soc",
           "received_at_ms": 1792357324051, "expires_at_ms": 1792357924051, "expired": false,
           "decision": "accepted", "safety_state": "moving_slow",
           "ladder_step": "limit_motion",
           "plan_actions": [{"step": "record"}, {"step": "limit_motion", "factor": 0.5}],
           "notes": ["..."],
           "executor": "recording", "executed": false,
           "note": "accepted and recorded in the signed black box as a plan; this agentd has no executor and sent nothing to the robot",
           "evidence": "robodr-blackbox://ugv-007/0/9?sha256=...",
           "revert": {...}}}
```

`duplicate` only on a resubmission, `refusal` only when refused.

| `status` | Meaning | Terminal |
| --- | --- | --- |
| `recorded_not_executed` | accepted against the current safety state and recorded as a plan in the black box; **nothing was sent to the robot** | yes |
| `refused` | judged unsafe or not allowed now (§4.1), recorded | yes |
| `failed` | the black box did not take the request (`state.error.code: evidence_unavailable`); nothing was decided or stored, a retry is judged anew | yes |
| `pending`, `applied` | reserved for an executor that acts; none exists in this repository | — |

`request_id` is the idempotency key: the same id with the same action,
parameters and ttl returns the stored state with `"duplicate": true` (not
judged or recorded again); the same id for anything else is 409
`request_id_conflict`. The store keeps the newest `max_requests` (default
1024) requests in memory; older ones and everything before a restart answer
404 (the black box keeps every decision).

## 6. Revert

| Stored request | Revert answer `status` |
| --- | --- |
| `request_safe_state`, `rollback_config` | `refused`, `refusal.code: not_reversible` (an operator restores the robot) |
| `recorded_not_executed`, `refused`, `failed` | `not_applied`: it never took effect; recorded (`robodr.control_plane_revert`), `state.revert` filled |

The revert answer carries the request's state with `status` replaced by the
revert's result and `revert_evidence` (the note's black-box reference).

## 7. HTTP errors

`{"error": {"code": "...", "message": "..."}}` with 400 (body errors §4,
malformed requests), 401 (`missing_credentials`, `malformed_credentials`,
`unknown_key`, `bad_signature`, `stale_timestamp`, `replayed_nonce`), 404
(`not_found`, `unknown_robot`, `unknown_request`), 405
(`method_not_allowed`), 408 (`timeout`), 409 (`request_id_conflict`), 413
(`body_too_large`), 429 (`rate_limited`), 431 (`head_too_large`,
`too_many_headers`), 503 (`busy`: the main loop did not take or answer in
`answer_timeout_ms`, or the daemon is stopping; `replay_cache_full`;
`clock_unavailable`), 505. A 503 `busy` after the request was handed over
may still have been recorded: read it back with GET.

## 8. Evidence and findings

Black-box notes (signed, hash-chained, fsynced):

* `robodr.control_plane_request`: the request, `auth` (key id, nonce,
  timestamp, signature, method, target, the exact body, peer: the SOC
  signature re-verifies offline from the note alone), safety state and its
  source, operational context, policy validation, decision, refusal or plan
  (ladder step, plan actions, notes), executor, `executed: false`, status;
* `robodr.control_plane_revert`: the revert, its result;
* `robodr.control_plane_rejected`: an authenticated request refused as
  invalid, with the error and `auth`.

Findings (OCSF, [`robodr.findings`](robodr.findings.md) 2.0, observe-only
self-health, rate limited by `daemon.health_report_ms`):

* `robot.agent.control_plane_unauthenticated` (High): requests that failed
  authentication since the last report (count, last reason and peer);
* `robot.agent.control_plane_invalid` (Medium): authenticated requests
  refused as invalid.

`status.json` and every heartbeat carry `control_plane`: `listening`,
`executor`, `executes_actions`, connection, authentication, rate-limit and
busy counters, `last_auth_failure`, and the engine's `submitted`,
`recorded_not_executed`, `refused`, `duplicates`, `conflicts`, `reverts`,
`invalid`, `record_failures`, `evicted`, `stored`.

## 9. Client requirements

What a SOC integration must do to use this API correctly:

* **Approval first.** Send a request only after the catalog's approval
  (§4): one person, or two different people (neither the requester) for
  `safe_pause`, `request_safe_state` and `rollback_config`. No robot action
  is autonomous.
* **Sign every request** (§2) with a SOC Ed25519 key whose `.pub` is
  installed on the robot (`control_plane.soc_keys`, e.g.
  `/etc/robodr/soc/soc.pub`, key id such as `soc:<id>:1`); keep `https`
  through a TLS terminator in front of agentd, or talk to loopback / the
  unix socket. `Authorization` headers are not used.
* **Statuses.** Know every status of §5. `recorded_not_executed` is
  **terminal** and means "accepted and recorded as a plan, not executed":
  report it as not applied, never as success, and never poll it. Report
  `verified` only for `applied` with `executed: true` (no such answer
  exists in this release).
* **Refusals are final** (§4.1): show `refusal.code`, `refusal.reason` and
  `refusal.safety_state` (a state name) to the person; do not retry.
* **Parameters.** `restrict_motion` caps are in (0, 10]: 0 is a stop and is
  refused (400 `invalid_parameter`); use `safe_pause` for a stop.
* **Idempotency.** Reuse `request_id` only to resubmit the identical
  request (`duplicate: true`); a revert of a never-applied request answers
  `not_applied`.
* **Answer signature** (optional): verify `X-RoboDR-Answer-Signature` with
  the robot's finding public key (the key used for `robodr-finding-sig`).

## 10. Limits

* Nothing is executed; a future executor must follow
  `robodr_agent::executor`'s contract (re-check against the current safety
  state, only request, never block) and would report `pending` / `applied`.
* The judgment is only as right as the safety state source (live feed or
  static configuration) and the response policy; `control`, `phase` and
  `connectivity` are still configuration.
* Request states live in memory (bounded); a restart forgets them (the
  black box does not).
* Answers are unauthenticated without `finding_signing`; there is no
  confidentiality without a TLS terminator; a network attacker can drop or
  delay requests and answers.
* Tested with synthetic traffic and an in-process signing client
  (`crates/robodr-agentd/tests/control_plane.rs`), not against a deployed
  SOC or across a network.
