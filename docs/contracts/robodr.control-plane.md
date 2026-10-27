# Contract: `robodr.control-plane` (robot action requests and evidence)

| | |
| --- | --- |
| API version | `robodr-control-plane/v2` (v1 is removed, §14) |
| Producer of answers | `robodr-agentd` (`crates/robodr-agentd/src/control/`), config key `control_plane` |
| Consumer | any SOC integration that sends approved robot actions or collects evidence (requirements in §10) |
| Action catalog | `robodr_responder::actions` (one list shared with the planner; §4) |
| Superseded | v1 (this file's history); the first draft, written for a cancelled integration: [`legacy/robot-edr.control-plane.md`](legacy/robot-edr.control-plane.md) |
| Status | **Experimental.** Off by default. **Nothing is executed** unless executor v1 is enabled (§6a, off by default) |
| Reference tests | `crates/robodr-agentd/tests/control_plane.rs` (end to end, real daemon: mTLS, restart, evidence), `tests/executor_link.rs` (executor v1 on v2: signed `pending` / `verified` / `refused` / `reverted` answers over the unix socket and mTLS, executor states across restarts), `tests/control_plane_vectors.rs` (§12), `tests/fuzz_smoke.rs`, `tests/cp_review.rs` (review regressions), unit tests in `src/control/{http,auth,api,journal,state,evidence,tls,mod}.rs` |
| Test vectors | [`fixtures/control-plane-v2/`](fixtures/control-plane-v2/) (§12) |

A SOC asks the robot for one of the seven catalog actions. The on-robot agent
checks the request against the robot's **current** safety state, operational
context and response policy (Cyber-Jidoka), records request and decision in
its signed black box and in a persistent request journal, and answers. The
SOC never commands motion and never overrides the platform's safety
authority: the strongest action is a *request* for a safe state, which the
platform's safety controller decides on. With the evidence API (§11) the SOC
also exports black-box evidence (a finding's records, a sequence or time
range) in signed, resumable chunks and verifies it with the robot's public
keys.

Unless executor v1 is enabled (§6a; off by default) agentd has no executor
that acts on the robot. The executor is then the recording one: an accepted
request is answered **`recorded_not_executed`** ("accepted and recorded as
a plan, not executed"), with `"executed": false`. A consumer must report
that as "not applied", never as success.

## 1. Transport

* HTTP/1.1, one request per connection (`Connection: close`), no chunked
  encoding, no keep-alive, no pipelining. Limits: the request head is at
  most 8 KiB before its blank line, 32 header lines, a target of at most
  1 KiB of `[A-Za-z0-9-._~%/:]` (no query string), a body of at most
  16 KiB with an exact `Content-Length` (none on `GET` / `DELETE`). The
  request must arrive within 5 s (after the TLS handshake, which has its own
  5 s); the answer is written within 30 s (a slower reader is cut off).
  These are deadlines on the whole exchange, not idle timeouts: the time
  left bounds every socket read, inside the TLS handshake and record layer
  too, so a peer that sends one byte at a time cannot stretch them.
* **Connections.** The unix socket has its own slots (2), never shared with
  TCP. On TCP, up to `max_connections` (default 4, 1..=16) connections may
  be in the TLS handshake or before their request authenticated, and
  another `max_connections` authenticated ones; one source address holds at
  most `max_connections_per_source` (default 2, 1..=16) of all of them.
  Over a cap the connection is closed at accept (no answer;
  `connections_rejected`); an authenticated request that finds no
  authenticated slot is answered 503 `busy` (signed).
* Answers are JSON (`Content-Type: application/json`) except evidence chunks
  (`application/octet-stream`, §11.5). `Cache-Control: no-store`.
* **Listeners** (at least one):

  | Listener | Config | Security of the channel |
  | --- | --- | --- |
  | TCP, any address | `listen_tcp` + `tls` | **mutual TLS** (below) |
  | TCP, loopback only | `listen_tcp` without `tls` | none (local tests, a local proxy) |
  | unix socket | `unix_socket` (mode `0600` or `0660`, private directory) | file permissions |

  A non-loopback `listen_tcp` without `tls` is refused at start (there is no
  plain-HTTP remote mode any more). The socket file is created with its
  final mode (bound in a private `0700` directory, `chmod`ed, then
  hard-linked into place): it is never connectable with looser permissions.
* **Mutual TLS** (rustls, ring provider; TLS 1.3 and 1.2 with rustls' safe
  defaults: AEAD suites, ECDHE only):
  * The robot presents `tls.cert_chain` (end entity first). The SOC verifies
    it against the CA it uses for robots and the address or name it
    connects to; it may also pin the robot's SPKI SHA-256
    (`status.json` → `control_plane.tls.server_spki_sha256`).
  * The SOC **must** present a client certificate that chains to one of the
    CA certificates in `tls.client_ca` (nothing else is trusted), is within
    its validity period and permits `clientAuth` (when it has an extended
    key usage). If `tls.client_spki_sha256` lists pins, the SHA-256 of the
    client end-entity certificate's DER `SubjectPublicKeyInfo` must be one
    of them **in addition**. Several CA certificates and pins may be listed
    for a rotation (§10).
  * Optional `tls.client_crl` (PEM, X.509 v2 CRLs): the client certificate
    chain is also checked for revocation. A certificate whose issuer has no
    CRL in the file is refused (unknown status fails closed), so give a
    current CRL of every CA in `tls.client_ca` that issues SOC client
    certificates. Loaded at start (a new CRL takes a restart); its
    `nextUpdate` is not enforced.
  * No session resumption (no tickets, no session cache): every connection
    presents and checks the client certificate.
  * A failed handshake (no certificate, unknown CA, expired, pin mismatch,
    plain HTTP to the TLS port) gets no HTTP answer; it is counted as a
    failed authentication (`tls_failures`, `last_auth_failure`, finding
    `robot.agent.control_plane_unauthenticated`).
* mTLS authenticates the channel. **Every request must still carry a valid
  Ed25519 SOC signature (§2)** on every listener: a stolen client
  certificate cannot sign, a stolen SOC signing key cannot connect from the
  network. `Authorization` headers are ignored.

## 2. Authentication

Every request, reads included, carries:

| Header | Value |
| --- | --- |
| `X-RoboDR-Key-Id` | the SOC key id (one of `control_plane.soc_keys`) |
| `X-RoboDR-Timestamp` | Unix seconds, decimal |
| `X-RoboDR-Nonce` | 16..128 characters of `[A-Za-z0-9_-]`, never reused |
| `X-RoboDR-Signature` | Ed25519 signature, 128 hex characters |

Each header exactly once. The signature is over these lines joined by `\n`
(no trailing newline):

```text
robodr-control-plane/v2
<METHOD>
<request target exactly as sent, e.g. /api/v2/robots/ugv-007/action-requests/robot_safe_pause%3Augv-007>
<robot id>
<key id>
<timestamp>
<nonce>
<lower-case hex SHA-256 of the body bytes (of the empty string for a GET / DELETE)>
```

The robot id is the one agentd is configured with: a request signed for
another robot never verifies. agentd then requires
|robot clock − timestamp| ≤ `max_clock_skew_s` (default 30 s; both sides need
NTP) and a (key, nonce) pair it has not seen while that timestamp is in the
window.

**Replay store.** The (key, nonce) pairs are persisted
(`<state_dir>/nonces.journal`): a pair is made durable (fsync) **before** the
request goes further, so a request accepted before a restart is still a
replay after it while its timestamp is in the window. At most 8192 live
pairs (503 `replay_cache_full` when full of live ones, never accepted
unchecked); a pair that cannot be made durable refuses the request (503
`replay_store_unavailable`). If the store may be missing pairs, agentd
**fences**: every request whose timestamp is not later than the fence is
refused (`stale_timestamp`); sign again. It fences when, at start,

* the store had to be created: a first install and a removed or wiped state
  directory look the same, so **the first start refuses requests for
  `max_clock_skew_s` seconds**;
* the store is damaged (§9);
* the wall clock reads below the store's persisted high-water mark (the
  latest second at which it dropped expired pairs, a `clock` entry); and,
  while running, when the clock steps back below that mark.

The fence is `max(now, high-water mark) + max_clock_skew_s`: a request
accepted before may carry a timestamp up to the skew ahead of the clock
that accepted it. (`status.json`: `control_plane.replay_fence`;
`state.replay.high_water`, `state.replay.clock_went_back`.)

Authenticated requests are rate-limited per key (`rate_per_minute`, default
30, `burst` 10; evidence chunk downloads have their own bucket, §11.7; 429
with `Retry-After`).

SOC keys are `robodr-blackbox keygen` public key files (`algorithm:
ed25519`, `key_id`, `public_hex`, optional `device_id` which must then be
this robot). A secret key file, a group/other-writable file, a symlink, or a
key id equal to the robot's black-box or finding key is refused at start.

**Answer signature (mandatory).** Every answer to an authenticated request
— any status, chunks included — carries

```text
X-RoboDR-Answer-Signature: ed25519;key_id=<finding key id>;sig=<128 hex>
```

over

```text
robodr-control-plane/v2 answer
<the request's X-RoboDR-Signature, lower-case hex>
<HTTP status, decimal>
<lower-case hex SHA-256 of the answer body bytes>
```

verifiable with the robot's finding public key (the key the SOC already
holds for `robodr-finding-sig`; `finding_signing` is required with
`control_plane`). Binding to the request signature (and so to its nonce)
stops the replay of an old answer.

**What the answer signature covers:** the HTTP status, the SHA-256 of the
body bytes and the request's signature, nothing else. Headers are **not**
covered: not `Content-Type`, not `Retry-After` (429), not
`X-RoboDR-Manifest-Signature` (that one is its own signature, §11.4).
A SOC takes every decision from the signed status and body; it may use
`Retry-After` only as a scheduling hint (a forged one can only delay a
retry, which the 429 body's own `retry after N s` text, signed, bounds). Answers to requests that did not
authenticate (400 before the credentials were read, 401, 503
`replay_cache_full` / `replay_store_unavailable` / `clock_unavailable`) are
never signed: there is nothing to bind them to. If the robot cannot sign, it
answers 500 `answer_signing_failed`, unsigned. **A SOC must treat any answer
without a valid signature as not coming from the robot** (it may still show
an unsigned 4xx/5xx reason to a person, never act on it).

## 3. Calls

Paths under `/api/v2/robots/{robot_id}`. `{robot_id}` must be this robot
(else 404 `unknown_robot`); `{request_id}` and `{export_id}` are
percent-decoded and must match `[A-Za-z0-9._:-]{1,128}`.

| Call | Body | Answer |
| --- | --- | --- |
| `GET /api/v2/robots/{robot_id}` | — | robot snapshot (§3.1) |
| `POST .../action-requests` | action request (§4) | request state (§5) |
| `GET .../action-requests/{request_id}` | — | request state |
| `POST .../action-requests/{request_id}/revert` | `{"reason"?, "requested_by"}` | request state with the revert result (§6) |
| `GET .../evidence` | — | evidence inventory (§11.2) |
| `POST .../evidence/exports` | export request (§11.3) | 201 manifest (§11.4); 200 for the same export again |
| `GET .../evidence/exports/{export_id}` | — | manifest |
| `GET .../evidence/exports/{export_id}/chunks/{index}` | — | chunk bytes (§11.5) |
| `DELETE .../evidence/exports/{export_id}` | — | `{"export_id", "deleted": true}` |

A method a path does not take is 405 `method_not_allowed`; an unknown path
404 `not_found`.

### 3.1 Robot snapshot

```json
{"robot_id": "ugv-007", "online": true, "api": "robodr-control-plane/v2",
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
 "in_force": false,
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

`in_force` (every request-state answer, revert answers included) says
whether the action is **being enforced on the robot now**: `true` only for
`verified` (or `applied`) when the executor does not hold it (§6a, reboot);
`false` for every other status. `executed` stays "it took effect at some
point" (`true` for `reverted` too). `state.executor_state: "held"` appears
only on a `verified` request whose action the executor holds (§6a).
`containment` (top level) and `state.quarantine` say how far a
`quarantine_node` reaches (§6a, "Quarantine scope"); `in_force` does not.

| `status` | Meaning | Terminal |
| --- | --- | --- |
| `recorded_not_executed` | accepted against the current safety state and recorded as a plan in the black box; **nothing was sent to the robot** | yes |
| `refused` | judged unsafe or not allowed now (§4.1), recorded | yes |
| `failed` | not taken: `state.error.code` is `evidence_unavailable` (the black box did not take it) or `state_unavailable` (the request journal did not take it, §9); nothing was decided or stored, **nothing was handed to an executor**, a retry is judged anew | yes |
| `pending`, `verified`, `reverted` | executor v1 only (§6a); `refused` and `failed` are also what the executor answers for its own checks and faults | see §6a |
| `applied` | reserved; no executor in this repository reports it | — |

`request_id` is the idempotency key: the same id with the same action,
parameters and ttl returns the stored state with `"duplicate": true` (not
judged or recorded again); the same id for anything else is 409
`request_id_conflict`. The store keeps the newest `max_requests` (default
1024) requests and **survives a restart** (§9), executor states (§6a)
included: a status query after a restart answers exactly as before it; older requests answer 404
`unknown_request` (the black box keeps every decision; §11 exports it).
After journal damage the requests are rebuilt from the black box (§9); a
request id the robot cannot reconcile is answered 503 `state_unavailable`
(signed) instead of being judged again.

## 6. Revert

| Stored request | Revert answer `status` |
| --- | --- |
| `request_safe_state`, `rollback_config`, `record_evidence` | `refused`, `refusal.code: not_reversible` (an operator restores the robot; evidence is never reverted) |
| `recorded_not_executed`, `refused`, `failed` | `not_applied`: it never took effect; recorded (`robodr.control_plane_revert`), `state.revert` filled (the first revert is kept, also across restarts) |
| `pending`, `verified`, `reverted` (executor v1) | `pending` or `reverted`, see §6a |

The revert answer carries the request's state with `status` replaced by the
revert's result and `revert_evidence` (the note's black-box reference).

## 6a. Executor v1 (`executor.enabled`)

> Additive subsection for executor v1 (`crates/robodr-executor`). It only
> applies when agentd's `executor.enabled` is `true`. Off by default:
> without it, everything above holds unchanged (`recorded_not_executed`).

With the executor enabled, the robot snapshot reports
`"executor": "robodr-executor"` and `"executes_actions": true`. An accepted
request (§4.1) is recorded first, then handed to the separate
`robodr-executor` process. That process checks it again against its own
policy and configuration and against the safety state **at the moment of
apply**. `executed` is `true` for `applied`, `verified` and `reverted`.

| `status` | Meaning | Terminal |
| --- | --- | --- |
| `pending` | accepted, recorded, handed to the executor; read the state again with GET | no |
| `verified` | the executor applied it and the read-back of its nftables rules matched; it stays in force until revert or TTL (`state.expires_at_ms`) | no |
| `reverted` | removed again: revert request, TTL expiry, restart reconciliation, or an operator's emergency disable (`nft delete table inet robodr`) | yes |
| `refused` | the executor's own check refused it; nothing was applied; `state.decision` then reads `refused`. `refusal.code` is one of `not_executor_action` (`safe_pause`, `request_safe_state`, `rollback_config`: never executed), `fall_hazard`, `needs_approval`, `motion_path`, `locators_required` (agentd has not seen the participant's SPDP locators), `no_management_channel`, `unsupported_target` (a `node` target, or a process), `safety_state_changed`, `safety_state_stale`, `safety_state_unavailable` (also: judged or current state `unknown`), `safety_system_engaged`, `morphology_mismatch`, `observe_mode`, `operator_disabled` (an operator removed the executor's table: nothing is executed until it is re-armed on the robot), `config_unavailable`, `already_active`, `ttl_out_of_range`, `replay`, `invalid_order`, `id_conflict`, `evidence_elsewhere`, the trust-boundary codes `soc_signature_invalid`, `soc_request_stale`, `soc_nonce_replayed`, `soc_replay_store_unavailable`, `order_mismatch`, `approval_missing`, `soc_keys_unavailable`, `approval_key_removed` (below), `locator_out_of_scope` (a participant locator outside the executor's `network.quarantine` scope), or `executor_refused` for a code this agentd does not know | yes |
| `failed` | the executor was unreachable, its queue was full, or the apply did not verify and was rolled back (`state.error`); nothing is in force | yes |
| `recorded_not_executed` | `restrict_motion` (advisory in v1: the executor does not drive the separate motion firewall gateway, `robodr-firewall-gw`) | yes |

* **Statuses by action.**
  * `isolate_network` and `quarantine_node` (by `participant_guid`) can
    reach `verified`. agentd hands a `quarantine_node` order the
    participant's SPDP unicast locators it has seen (from the pipeline's
    binding table: the prefix's own last trusted announcement, also after
    the participant left or was evicted, for 24 h, only on addresses it
    was seen sending from, minus any locator a profiled participant
    announces, any port on a profiled participant's host (for another
    prefix) and any pinned address, none for a contested or pinned prefix;
    from `ros2_participant_discovered` events
    only for a prefix the binding table does not know, through the same
    filters). With no locator left, agentd vouches for a GUID-prefix-only
    quarantine of a participant it saw that is not one of the robot's own
    (profiled, pinned, contested); otherwise the executor refuses it
    (`locators_required`). The executor leaves out (never refuses for) a
    locator outside its quarantine scope or on the motion control path,
    and refuses an order whose every locator is on the motion control path
    (`motion_path`). How far a verified quarantine reaches is in the
    answer (below, "Quarantine scope").
  * `record_evidence` becomes `verified` once a signed
    `robodr.evidence_mark` note naming the request's evidence is in the
    black box. It is never reverted.
  * An action the executor never carries out is `refused`.
* **Trust boundary (executor M1).** agentd forwards the SOC's request
  with the order exactly as it was signed (method, target, the four
  credentials of §2, body). The executor verifies it itself, with its own
  copy of the SOC public keys (`soc.keys` in `executor.json`), before it
  accepts the approval, and refuses:

  | `refusal.code` | When |
  | --- | --- |
  | `soc_signature_invalid` | no signed request with the order, a key id the executor does not hold (or none configured), a malformed request, or an Ed25519 signature that does not verify over the §2 signing message with the executor's own robot id |
  | `soc_request_stale` | the timestamp is outside the executor's window (`soc.max_clock_skew_s`, default 30 s), or inside the executor's replay fence: signed before an executor start that found its replay store missing or damaged, or while the executor's clock reads below its store's high-water mark (sign again) |
  | `soc_nonce_replayed` | the (key, nonce) pair was already presented to the executor while its timestamp is in the window (persisted across restarts) |
  | `soc_replay_store_unavailable` | the executor's replay store is full of live pairs or could not record the pair |
  | `order_mismatch` | the signed request is not `POST /api/v2/robots/{robot_id}/action-requests` for this robot, or the order's `request_id`, `action`, `ttl_seconds`, target (`participant_guid` / `node`), key id or `requested_by` differ from the signed body |
  | `approval_missing` | the signed body lacks the approval evidence §4 requires (`authority: "request"`, `requested_by`, `source`, `reason` within its limits), or an order of the on-robot planner claims a human approval |
  | `soc_keys_unavailable` | the executor's SOC key configuration cannot be trusted: a key file unreadable or refused, or a SOC key equal to one of the robot's own keys (`soc.robot_keys`); every control-plane order is refused until it is fixed |
  | `approval_key_removed` | (after a robot reboot) the key that approved a held action is no longer configured: it is not re-armed and turns `reverted` |

  The replay fence of a store found missing or damaged at start is the
  start time **plus** `soc.max_clock_skew_s`: a request signed up to the
  skew ahead of the clock may have been presented before; the SOC signs
  again after the fence. Like agentd's (§2), the executor's store also
  fences when the clock goes back below the latest time it dropped dead
  pairs (up to that time plus the skew). A site may set
  `require_approval_for_all_containment` in `executor.json`: then the
  on-robot planner's containment orders are refused (`needs_approval`) on
  every morphology.

  Nothing changes for a SOC that follows §2 and §10: the executor checks
  the same signature agentd checks. A SOC request is executed at most
  once, also when agentd is compromised.
* **Revert.** A revert of a `pending` or `verified` request answers
  `pending` (`state.revert.result: "pending"`), and GET then shows
  `reverted`. A revert of a `reverted` request answers `reverted`. The
  revert is recorded (`robodr.control_plane_revert`) and journalled
  (`revert_begin` / `revert_commit`, §9) **before** agentd sends it to the
  executor; one that is not recorded is never sent. The other rows of §6
  are unchanged.
* **Signed reverts (executor review F3).** agentd forwards the SOC's
  revert request (`POST .../action-requests/{request_id}/revert`) exactly
  as it was signed, like a submit. The executor lifts an action the SOC
  approved **only** with it, verified like the submit (its own keys, its
  own robot id, the timestamp window, its own replay store) plus: the
  target is the revert of that `request_id`, and the body is the strict
  revert body (`requested_by` 1..=100 characters, optional `reason` ≤ 500
  characters, no other field). A revert that fails these checks is
  refused by the executor: the action stays in force (GET keeps reading
  `verified`; `state.revert.result` stays `pending`) and the executor
  records a `refused` event. Nothing changes for a SOC that follows §2:
  every revert it sends is signed. Unsigned reverts remain only for the
  on-robot planner's own actions, TTL expiry, restart reconciliation and
  the operator's `revert-all` on the robot.
* **Signed and persistent (v2).** Every answer carrying these statuses is
  signed with the finding key (§2, `X-RoboDR-Answer-Signature`) like any
  other answer. Each state the executor reports is journalled (§9,
  `executor` entry, fsynced) before agentd answers it, and agentd journals
  outcomes as they arrive, not only when the SOC asks: a request that read
  `verified` reads `verified` after an agentd restart, and a `reverted` one
  stays `reverted`. If the journal does not take a new state, the request
  keeps answering its previous state until it does (never a state the
  robot could forget). At start agentd asks the executor once about the
  restored requests that are still `pending` or `verified`.
* **TTL.** Every executed action has a TTL: the request's `ttl_seconds`,
  or the executor's `ttl.default_s` when the request names none. The
  executor lifts the action at `expires_at_ms` without further requests.
* **Quarantine scope** (review R2-3 of the red-team fixes; R3-1). A
  `quarantine_node` is enforced as three kinds of drop:

  1. **address drops** (review R3-1): every UDP datagram from a source
     address the participant was seen sending from to one of the robot's
     DDS ports, and every UDP datagram to that address on one of those
     ports, **whatever the source port** (not over loopback). The DDS
     ports are the executor's `network.quarantine.udp_ports`, default the
     RTPS port ranges `7400 + 250 d ..= 7400 + 250 d + 249` of its
     discovery domains (domain 0: 7400-7649);
  2. **locator drops**: UDP from an announced unicast locator's ip **and
     port**, and to that ip:port. A DDS stack that sends from ephemeral
     ports (Fast DDS, the ROS 2 default) is not matched inbound by these;
  3. the **GUID-prefix drop**: RTPS whose header carries the
     participant's GUID prefix, from anywhere. Alone it is weak: a sender
     can re-attribute its submessages with `INFO_SRC` or restart under a
     new prefix.

  An address or locator is cut only after every exclusion (not loopback,
  not the robot's own host as agentd knows it: this host, a pinned
  address, a profile identity's address, an address a profiled
  participant was seen at; not on the motion control path; inside the
  executor's `network.quarantine.cidrs`; outside the management / uplink
  entries; one address family). **Shared hosts:** an address drop cuts
  every DDS participant on that host, including a legitimate process that
  is not in the profile; source addresses are not authenticated, so a
  decoy whose SPDP is spoofed to such a host's address gets it cut when
  the decoy is quarantined. So every answer of a `quarantine_node` request
  says what is cut:

  | Field | Where | Present | Value |
  | --- | --- | --- | --- |
  | `containment` | top level, next to `in_force` | on a `quarantine_node` request whose `status` is `verified` or `applied` (held or not); absent otherwise | `"full"`, `"partial"`, `"guid_only"` (definition below); `"unknown"`: the executor did not report the scope (an executor older than revision R2-3) |
  | `state.quarantine` | `state` | once the executor reported the scope (kept after a revert; journalled, survives a restart) | object, below |
  | `state.quarantine.addresses` | | always in the object (may be empty; empty in a scope journalled before revision R3-1) | array (0..=16) of IP address strings: the source addresses cut whole (address drops, above) |
  | `state.quarantine.excluded_addresses` | | always in the object (may be empty) | array (0..=32) of `{"address": "ip", "reason": string}` (reason as for `excluded`): observed source addresses agentd or the executor did **not** cut whole, e.g. "address a profiled participant was learned at (not commissioned): never cut whole; pin it (participant_ips) or commission the identity's ips", "this host's own address (the computer RoboDR runs on)", "executor: outside every network.quarantine.cidrs entry" |
  | `state.quarantine.evidence_truncated` | | always in the object | `true` when agentd forgot an observed source address or announced locator of the participant (it keeps 8 addresses and 32 locators per participant) or a list above was cut to its bound |
  | `state.quarantine.locators` | | always in the object | array (0..=16) of `"ip:port"` strings (IPv6 as `"[addr]:port"`): the UDP endpoints the executor cuts |
  | `state.quarantine.excluded` | | always in the object (may be empty) | array (0..=64) of `{"locator": "ip:port", "reason": string}` (reason ≤ 200 characters, no control characters, tainted text: display only): announced locators agentd or the executor left out, e.g. "the participant was never seen sending from this address (announced only)", "address of a profiled participant's host (the robot's own computer)", "over the order's locator limit (16): not acted on", "outside every network.quarantine.cidrs entry" |

  **`containment`** is derived from `state.quarantine` (one definition,
  `robodr_executor::decision::containment_of`, used by the executor and
  agentd):

  * `"full"`: **every** source address the participant was seen sending
    from and **every** unicast locator it announced is covered by an
    address drop, plus the GUID-prefix drop. Precisely: `addresses` is
    not empty, `excluded_addresses` and `excluded` are empty,
    `evidence_truncated` is `false`, and the address of every entry of
    `locators` is in `addresses`.
  * `"guid_only"`: `addresses` and `locators` are both empty: only the
    GUID-prefix drop is in force (not IP-contained).
  * `"partial"`: anything else: some address or locator drop is in force,
    but at least one observed address or announced locator is not covered
    by an address drop (left out, forgotten, or only its announced ip:port
    is cut, which a sender using ephemeral ports evades inbound).

  A scope journalled before revision R3-1 (no `addresses`) reads
  `partial` when it cut locators: those rules matched the announced ports
  only. The fields are additive: a client that ignores them keeps
  working, and answers without them (any other action, any other status,
  an older agentd) are unchanged. The fields are inside the signed body
  (§2).
* **Client requirements.** Report "in force" exactly when `in_force` is
  `true` (a `verified` request the executor does not hold); a `verified`
  request with `in_force: false` and `state.executor_state: "held"` is
  "held after a reboot, not enforced" (keep polling GET). For a
  `quarantine_node` in force, show the containment: `full` as contained
  (and list `state.quarantine.addresses`: an address drop cuts every DDS
  participant on that host); `partial` as "partially contained" with the
  left-out addresses and locators and their reasons (from a left-out
  address the participant still reaches the robot from any port it did
  not announce, and by `INFO_SRC` re-attribution); `guid_only` as
  "partially contained: GUID-prefix drop only, not IP-contained" (the
  participant can evade it; consider `isolate_network` or on-site
  action); `unknown` as "in force, scope not reported". Never show
  `guid_only`, `partial` or `unknown` as fully contained. Treat
  `refused` and `failed` as "not applied" and show `refusal.code`,
  `refusal.reason` and `state.error`. Poll GET for a `pending` request.
* **Evidence.** Each executor event (`applied`, `verified`, `refused`,
  `failed`, `reverted`, `expired`, `revert_failed`, `drift`,
  `removed_externally`, `reconciled`, `journal_reset`, `held`, `rearmed`,
  `journal_error`) is a `robodr.executor_event` note. `revert_failed`,
  `drift`, `removed_externally` and `journal_reset` are critical
  (fsynced). `status.json` carries `executor` counters.
* **Reboot.** After a reboot of the robot an action in force is held
  (not installed) until the executor re-validated it and agentd supplied
  a fresh safety state; it turns `reverted` if it is not re-armed before
  its TTL. A held action is not a new state: nothing is journalled for it
  and the request keeps its journalled `status` (`verified`), but while
  held every answer says so: `"in_force": false` and
  `"state": {"executor_state": "held", ...}`. Once re-armed, `in_force` is
  `true` again and `executor_state` is gone. (agentd learns of the hold
  from the executor's word on the request; after an agentd restart, from
  its resync.)
* **Orders follow the record.** An order is handed to the executor only
  after the request's black-box note and journal commit (or, for a revert,
  its note) exist, and only if the stored request is still `pending` and is
  the one the order was made for (action, TTL, SOC key). A request answered
  `failed` (or 503) leaves nothing behind for the executor: a retry with
  the same `request_id` can never release an order of the failed attempt.

## 7. HTTP errors

`{"error": {"code": "...", "message": "..."}}` with

* 400: body errors (§4, §11.3) and malformed requests (`bad_request_line`,
  `bad_target`, `bad_header`, `bad_head`, `content_length`,
  `transfer_encoding`, `body_not_allowed`, `truncated`, `io`);
* 401: `missing_credentials`, `malformed_credentials`, `unknown_key`,
  `bad_signature`, `stale_timestamp` (also: the replay fence, §2),
  `replayed_nonce`;
* 404: `not_found`, `unknown_robot`, `unknown_request`, `unknown_export`,
  `unknown_chunk`, `evidence_disabled`, `no_records`,
  `evidence_not_retained`;
* 405 `method_not_allowed`; 408 `timeout`;
* 409: `request_id_conflict`, `export_id_conflict`, `export_limit`,
  `evidence_mismatch`, `evidence_gap`;
* 413: `body_too_large`, `export_too_large`; 416 `out_of_range`;
* 429 `rate_limited` (with `Retry-After`);
* 431: `head_too_large`, `too_many_headers`;
* 500: `export_corrupt` (the stored export no longer matches its manifest;
  it was deleted: create it again), `answer_signing_failed` (unsigned);
* 503: `busy` (below), `replay_cache_full`,
  `replay_store_unavailable`, `clock_unavailable`, `state_unavailable`
  (also: a request id the damaged journal could not reconcile, §9),
  `evidence_busy` (another evidence index / export runs: retry shortly),
  `evidence_timeout` (an export took longer than 60 s, or the daemon is
  stopping: select fewer records), `evidence_unavailable`;
* 505 `bad_version`; 507 `storage_full`.

**503 `busy`** (signed: the request authenticated) means one of: every
authenticated TCP connection slot is taken (§1; nothing was done), the
queue to the main loop is full or the daemon is stopping (nothing was
done), or the main loop did not answer within `answer_timeout_ms` (the
request **may still have been recorded**). A SOC retries a `busy`
submission with the **same** `request_id` and body (a fresh nonce): it is
then either judged for the first time or answered as a duplicate, never
judged twice. GET is always safe to retry.

## 8. Evidence of the control plane and findings

Black-box notes (signed, hash-chained, fsynced):

* `robodr.control_plane_request`: `decision_id` (§9), the request, `auth`
  (key id, nonce, timestamp, signature, method, target, the exact body,
  peer — on mTLS `mtls:<addr>;client_spki_sha256=<hex>`: the SOC signature
  re-verifies offline from the note alone), safety state and its source,
  operational context, policy validation, decision, refusal or plan (ladder
  step, plan actions, notes), executor, `executed: false`, status;
* `robodr.control_plane_revert`: the revert, its result, `decision_id`
  (when it changed the state);
* `robodr.control_plane_rejected`: an authenticated request refused as
  invalid, with the error and `auth`;
* `robodr.control_plane_evidence_export`: an export (§11): id, selector,
  who asked (`auth`), chain id, records, anchor, bundle size / SHA-256 /
  chunk count;
* `robodr.control_plane_start`: at every start: listeners, TLS identity,
  whether the evidence API is on, and the persistent state found (§9:
  restored requests, settled decisions, journal damage, replay fence).

Findings (OCSF, [`robodr.findings`](robodr.findings.md) 2.x, observe-only
self-health, rate limited by `daemon.health_report_ms`):

* `robot.agent.control_plane_unauthenticated` (High): requests that failed
  authentication since the last report, TLS handshakes included (count,
  last reason and peer);
* `robot.agent.control_plane_invalid` (Medium): authenticated requests
  refused as invalid.

`status.json` and every heartbeat carry `control_plane`: `api`, `listening`
(`mtls:<addr>`, `tcp:<addr>`, `unix:<path>`), `executor`,
`executes_actions`, connection, authentication (`tls_failures` included),
rate-limit and busy counters, `answers_signed`, `answer_sign_failures`,
`last_auth_failure`, `tls` (`server_spki_sha256`, `client_cas`,
`client_pins`, `client_crls`), `replay_entries`, `replay_store_errors`,
`replay_fence`,
`state` (what §9 found at start, including `rebuilt_from_blackbox`,
`rebuilt_reverts`, `lost_request_ids`, `refusing_new_request_ids` and the
replay store's `replay.high_water` / `replay.clock_went_back` / `fence`),
`evidence` (exports, bytes, created,
deleted, expired, chunks served, corrupt) and the engine's `submitted`,
`recorded_not_executed`, `refused`, `duplicates`, `conflicts`, `reverts`,
`invalid`, `record_failures`, `evicted`, `stored`, `restored`,
`resolved_committed`, `resolved_aborted`, `journal_damaged`,
`journal_errors`, `journal_refusals`, `evidence_exports`.

## 9. Persistent state (`control_plane.state_dir`)

A private directory (mode `0700`, owned by the daemon's user; agentd refuses
to start otherwise; not inside the black box or spool):

| Path | What |
| --- | --- |
| `requests.journal` | the request journal |
| `nonces.journal` | the replay store (§2) |
| `exports/<sha256(export id)[..32]>/` | evidence exports: `bundle.rbbx`, `manifest.json`, `manifest.sig` |
| `quarantine/` | copies of damaged journals |

**Journal format** (`robodr-cp-journal/v1`): one entry per line,
`<64 hex: SHA-256 of the JSON bytes> <JSON object>\n`, the first line a
header `{"t":"header","format":"robodr-cp-journal/v1","kind":...}`. Each
append is one write followed by `fdatasync`; a failed append is rolled back
(the file is cut to its previous length) or, if even that fails, the journal
refuses further appends until restart. Compaction writes the live state to a
temp file, fsyncs it, renames it over the journal and fsyncs the directory;
if that last fsync fails, the journal also refuses appends until restart
(fail closed: requests are answered `failed` / `state_unavailable`, or 503
`replay_store_unavailable`), since the rename might not survive a power
loss.
At open, **one** bad line after the last good one (unterminated or not) is a
torn append (cut): every append is a single synced write, so a crash leaves
at most that one line. Anything more is **damage**: a bad line followed by
good ones, or two or more bad lines at the end. Damaged lines are counted,
the file is copied to `quarantine/` and rewritten from the good entries.
The journal is operational state, not evidence: it is checksummed, not
signed; the black box stays the record.

**After damage** agentd falls back to the record:

* replay store: it fences (§2);
* request journal: it is **rebuilt from the black box**: every
  `robodr.control_plane_request` note of this robot whose request the
  journal lost is restored (its decision-time state; `received_at_ms` is
  the note's record time; an executor request then takes the executor's
  word on resync), and every `robodr.control_plane_revert` note restores
  the revert record it proves. A note that does not convert back makes its
  `request_id` refused (503 `state_unavailable`) rather than judged again.
  If the black box cannot be read, **every new `request_id` is refused**
  (503 `state_unavailable`; stored requests still answer) until a restart
  reconciles the journal. Requests older than the black box's retention
  are gone either way (as after eviction).

**Decisions** are journaled around the black-box note:

```text
judge -> journal "begin" {decision_id, state} (fsync) -> black-box note with decision_id
      -> journal "commit" {decision_id, evidence} (fsync)  -> answer
      (black box failed -> journal "abort" -> answer failed / evidence_unavailable)
```

A crash between `begin` and `commit` leaves a dangling decision; at the next
start agentd looks for a black-box note carrying that `decision_id`: found,
the decision is committed with that note's reference (the SOC may have seen
it); not found, it is aborted (nothing was recorded, nothing decided: a
resubmission is judged anew). A journal that cannot take the `begin`
refuses the request before anything is judged into evidence (`failed`,
`state_unavailable`). Reverts that change a request's state (the first
revert record, or an executor revert that reports `reverted`) follow the
same steps (`revert_begin` / `revert_commit` / `revert_abort`). The newest
`max_requests` requests are kept.

**Replay store entries** are `{"t":"nonce","key_id":...,"nonce":...,
"dead_after":<unix s>}`, plus one `{"t":"clock","key_id":"","nonce":"",
"dead_after":<unix s>}` written with every compaction: the high-water mark
of §2 (the latest second at which expired pairs were dropped). An agentd
older than this revision reads a `clock` entry as damage and fences once.

**Executor states** (executor v1, §6a) are one entry each,
`{"t":"executor","request_id":...,"status":...,"error":...,"refusal":...}`
plus, for a verified quarantine whose scope the executor reported,
`"quarantine": {"locators": [...], "excluded": [...], "addresses": [...],
"excluded_addresses": [...], "evidence_truncated": false}` (§6a; the last
three since revision R3-1, read as empty / `false` when absent; absent
otherwise, and in the `stored` snapshot likewise), appended (fsync) before
the new state is answered. An agentd older than that revision (R2-3, or
R3-1 for the three newer fields) reads such an entry as damage and
rebuilds from the black box (§9, "After damage"; the scope is then asked
from the executor again on resync). They are the executor's
word, not a decision of agentd (the executor and agentd's
`robodr.executor_event` notes are their evidence), so they have no
begin / commit pair. An entry for a request whose decision is still
dangling is carried into it and settled with it.

## 10. Client requirements

What a SOC integration must do to use this API correctly:

* **Approval first.** Send a request only after the catalog's approval
  (§4): one person, or two different people (neither the requester) for
  `safe_pause`, `request_safe_state` and `rollback_config`. No robot action
  is autonomous.
* **Channel.** Connect over mutual TLS (§1) with the SOC client certificate
  the robot's `tls.client_ca` trusts (and, if pinned, whose SPKI is
  pinned); verify the robot's server certificate against the robot CA and
  the robot's address (optionally its SPKI pin). Over loopback or the unix
  socket (a local relay on the robot) TLS does not apply.
* **Sign every request** (§2) with a SOC Ed25519 key whose `.pub` is
  installed on the robot (`control_plane.soc_keys`, e.g.
  `/etc/robodr/soc/soc.pub`, key id such as `soc:<id>:1`), with a fresh
  nonce and an NTP-synced clock. On `stale_timestamp` right after a robot
  restart, sign again (the replay fence, §2).
* **Verify every answer** (§2) with the robot's finding public key before
  using it; drop answers without a valid signature.
* **Statuses.** Know every status of §5. `recorded_not_executed` is
  **terminal** and means "accepted and recorded as a plan, not executed":
  report it as not applied, never as success, and never poll it. Report an
  action as in force only when the answer says `"in_force": true`
  (`verified` and not held, §6a); `verified` with `in_force: false` and
  `state.executor_state: "held"` is "held, not enforced". A
  `quarantine_node` in force is fully contained only with
  `"containment": "full"`: every source address the participant was seen
  sending from and every locator it announced is cut whole (any source
  port, to and from the robot's DDS ports), plus the GUID-prefix drop
  (§6a, "Quarantine scope"). Show `partial` and `guid_only` as partially
  contained, never as contained; show `state.quarantine.addresses` with
  `full` too (an address drop also cuts any other DDS process on that
  host).
* **Retries.** On 503 `busy` or a lost answer, resubmit with the same
  `request_id` and body and a fresh nonce (§7); never a new `request_id`
  for the same intent unless the first answer was a final `failed`.
* **Refusals are final** (§4.1): show `refusal.code`, `refusal.reason` and
  `refusal.safety_state` (a state name) to the person; do not retry.
* **Parameters.** `restrict_motion` caps are in (0, 10]: 0 is a stop and is
  refused (400 `invalid_parameter`); use `safe_pause` for a stop.
* **Idempotency.** Reuse `request_id` only to resubmit the identical
  request (`duplicate: true`, also after a robot restart); a revert of a
  never-applied request answers `not_applied`.
* **Evidence.** Verify every export as §11.6 says before showing it as
  verified; keep the manifest, its signature and the bundle together.
* **Rotation.** Robot side: list the old and new SOC CA certificates in
  `tls.client_ca` (and both pins) and both SOC keys in `soc_keys` while
  the SOC switches, then remove the old ones; the robot's own TLS key and
  certificate are replaced by files and a restart (state survives it).
  With `tls.client_crl`, ship a current CRL of every client CA and restart
  agentd when it changes.

## 11. Evidence API (`control_plane.evidence`)

Off unless `control_plane.evidence` is configured (then
`evidence_disabled` is gone). Same transport, authentication and answer
signatures as every other call.

### 11.1 What an export is

An export is an `RBBXBND1` black-box bundle (`robodr_blackbox::Bundle`):

```text
"RBBXBND1" | u32_be id_len | identity JSON (ChainIdentity) | u8 has_anchor |
[chain_id 32 | u64_be seq | hash 32]? | u64_be frames_len | frames
```

`frames` are the selected records **exactly as stored** in the black box
(`"RBF1" | u32_be body_len | body` each: hashed fields, hash, signature;
`crates/robodr-blackbox/src/record.rs`): a contiguous run of sequence
numbers of the current chain. The anchor names the record just before the
first one (absent when the first is seq 0). Records are signed by the
robot's **black-box key**; nothing else (no key material, no file, nothing
outside the black box's segment files) is ever exported.

### 11.2 Inventory: `GET .../evidence`

```json
{"robot_id": "ugv-007", "api": "robodr-control-plane/v2",
 "chain": {"chain_id": "<hex>", "identity": {"device_id": "ugv-007", "boot_id": "...",
           "key_id": "bb:ugv-007:1", "algorithm": "ed25519", "created_wall_ns": 0},
           "signing_key": {"key_id": "bb:ugv-007:1", "algorithm": "ed25519"}},
 "retained": {"first_seq": 0, "last_seq": 4711, "first_wall_ms": 0, "last_wall_ms": 0,
              "records": 4712, "gaps": [{"after_seq": 99, "next_seq": 250}],
              "segments": [{"segment": 0, "first_seq": 0, "last_seq": 811,
                            "first_wall_ms": 0, "last_wall_ms": 0, "records": 812, "bytes": 8388608}]},
 "head": {"seq": 4711, "sha256": "<hex>"},
 "exports": [{"export_id": "...", "created_at_ms": 0, "expires_at_ms": 0, "first_seq": 0,
              "last_seq": 0, "bytes": 0, "chunks": 0, "manifest_sha256": "<hex>"}],
 "limits": {"max_export_bytes": 67108864, "chunk_bytes": 1048576, "max_exports": 8,
            "max_storage_bytes": 536870912, "export_ttl_s": 86400}}
```

`gaps` are seqs not retained between retained ones (dropped or quarantined
segments): an export cannot span one.

### 11.3 Create: `POST .../evidence/exports`

```json
{"export_id": "case-42:ev-1",
 "selector": {"finding": {"finding_id": "rf1-0011223344556677",
                          "evidence": ["robodr-blackbox://ugv-007/0/9?sha256=<64 hex>"],
                          "context_records": 16}},
 "requested_by": "analyst@soc",
 "reason": "case 42"}
```

Strict (unknown or duplicate keys refuse it). `export_id`
`[A-Za-z0-9._:-]{1,128}` is the idempotency key: the same id with the same
selector answers the existing manifest (200, byte-identical); another
selector is 409 `export_id_conflict`. `requested_by` / `reason` as in §4.
`selector` has **exactly one** of:

| Selector | Fields | The export covers |
| --- | --- | --- |
| `seq_range` | `from_seq` ≤ `to_seq` | exactly those seqs (all must be retained: else 416 `out_of_range`) |
| `time_range` | `from_ms` ≤ `to_ms`, at most 7 days apart | from the first to the last retained record whose wall time (ms) is in the range (404 `no_records` if none); records in between are included whatever their time |
| `finding` | `finding_id` (1..=256 bytes), `evidence`: 1..=64 `robodr-blackbox://` links of **this robot** (a finding's `evidence_links`), `context_records` 0..=1024 (default 16) | from `context_records` before the lowest linked seq to as many after the highest, as far as the seqs are contiguous; each link must name a retained record (404 `evidence_not_retained`) in that segment with that SHA-256 (409 `evidence_mismatch`) |

Selector errors: 400 `invalid_selector`. Then: a span with a gap is 409
`evidence_gap`; frames over `max_export_bytes` are 413 `export_too_large`;
more than `max_exports` kept exports is 409 `export_limit`; more than
`max_storage_bytes` in kept bundles, or an export that would leave less
than 64 MiB free on the state directory's filesystem, is 507
`storage_full`; a build that takes longer than 60 s (or meets a daemon
shutdown) is abandoned with 503 `evidence_timeout`; a concurrent
index / export is 503 `evidence_busy`; a black box that cannot be read, or
that changed under the export (retention), or that did not take the export's
note, is 503 `evidence_unavailable` (nothing was exported). Every created
export is a `robodr.control_plane_evidence_export` black-box note. Invalid
bodies are recorded like any authenticated invalid request.

### 11.4 Manifest

The answer body of a create (201, or 200 for the same export again) and of
`GET .../evidence/exports/{export_id}` is the manifest, **byte-identical
every time** (store and hash these bytes; do not re-serialize):

```json
{"kind": "robodr.evidence_manifest", "version": 1, "api": "robodr-control-plane/v2",
 "robot_id": "ugv-007", "export_id": "case-42:ev-1",
 "created_at_ms": 1800000000000, "expires_at_ms": 1800086400000,
 "requested_by": "analyst@soc", "reason": "case 42", "key_id": "soc:soc-a:1",
 "selector": {"finding": {"finding_id": "...", "evidence": [{"segment": 0, "seq": 10, "sha256": "<hex>"}],
                          "context_records": 3}},
 "chain": {"chain_id": "<hex>", "identity": {...ChainIdentity...},
           "signing_key": {"key_id": "bb:ugv-007:1", "algorithm": "ed25519"}},
 "records": {"first_seq": 7, "last_seq": 15, "count": 9, "first_wall_ms": 0, "last_wall_ms": 0,
             "last_sha256": "<hex>"},
 "anchor": {"seq": 6, "sha256": "<hex>"},
 "referenced": [{"segment": 0, "seq": 10, "sha256": "<hex>"}],
 "bundle": {"format": "RBBXBND1", "bytes": 3337, "sha256": "<hex>", "chunk_bytes": 1048576,
            "chunks": [{"index": 0, "offset": 0, "bytes": 3337, "sha256": "<hex>"}]},
 "evidence": "robodr-blackbox://ugv-007/3/4712?sha256=<hex>"}
```

`selector` is the normalized selection (links parsed, sorted, deduplicated);
`key_id` the SOC key that asked; `chain.signing_key` the black-box key that
signs the **first** exported record (different from `identity.key_id` after
a key rotation); `referenced` the linked records (finding selector);
`evidence` the export's own black-box note.

Besides the answer signature, the manifest carries a **detached signature**
that does not depend on the request, for storage with the evidence:

```text
X-RoboDR-Manifest-Signature: ed25519;key_id=<finding key id>;sig=<128 hex>
```

over the bytes

```text
robodr-evidence-manifest/v1
<lower-case hex SHA-256 of the manifest bytes>
```

(no trailing newline), with the robot's finding key.

### 11.5 Chunks: `GET .../evidence/exports/{export_id}/chunks/{index}`

`index` is decimal without leading zeros, `0 .. len(bundle.chunks)-1` (else
404 `unknown_chunk`). The answer body is `bundle.chunks[index].bytes` bytes
of the bundle from `offset` (`application/octet-stream`), signed like every
answer. Chunks are immutable and independent: a download is **resumable**
by fetching only the chunks still missing, in any order, also after a
disconnect or a robot restart (exports survive restarts until they expire).
The robot re-checks each chunk against its manifest before sending it; a
stored export that no longer matches is deleted and answered 500
`export_corrupt`.

### 11.6 Verification (what the SOC must do)

1. Verify `X-RoboDR-Answer-Signature` of every answer (§2).
2. Verify `X-RoboDR-Manifest-Signature` over the manifest bytes with the
   robot's finding public key; check `kind`, `version`, `robot_id`,
   `export_id` and that `selector` is what was asked.
3. For every chunk: `len == bytes` and SHA-256 == `sha256`; concatenate in
   `index` order; the result's length and SHA-256 must equal
   `bundle.bytes` / `bundle.sha256`.
4. Verify the bundle with the robot's **black-box public key** (the
   `.pub` of `blackbox.key_file`; a keyring holding every key named by
   the chain across rotations), exactly as `robodr-blackbox` does:
   * `robodr-blackbox verify bundle.rbbx --keyring blackbox.pub --device <robot id>
     [--signing-key <manifest chain.signing_key.key_id>]` (exit 0 =
     intact), or
   * the library: `Bundle::from_bytes(b)?.verify_with_key(&keyring, None,
     Some(robot_id), Some(&manifest.chain.signing_key))` and require
     `is_intact()`.

   This checks every record's hash, signature (under the key the chain
   names, rotations included), chain id (identity), linkage from the anchor
   through the last record, and the device. The anchor is reported as
   unverified (info) unless the SOC holds that position from an earlier
   export or checkpoint: compare it then (a match proves continuity).
5. Check the report against the manifest: `first_seq` / `last_seq` /
   `verified_records` / `last_hash` equal `records.*`, `chain_id` equals
   `chain.chain_id`, and every `referenced` record is in the bundle with
   that SHA-256 (the finding's evidence links resolve inside it).

Any failure: the evidence is not verified (a tamper finding of the verifier
is an incident). A "verified" badge must mean exactly steps 1–5 passed.

### 11.7 Limits and retention

| Setting (`control_plane.evidence`) | Default | Range |
| --- | --- | --- |
| `max_export_bytes` | 64 MiB | 64 KiB ..= 256 MiB |
| `chunk_bytes` | 1 MiB | 16 KiB ..= 4 MiB; at most 4096 chunks per export |
| `max_exports` (kept at once) | 8 | 1 ..= 64 |
| `max_storage_bytes` (all kept bundles) | 512 MiB | `max_export_bytes` ..= 16 GiB |
| `export_ttl_s` (deleted after) | 86400 | 600 ..= 604800 |
| `chunk_rate_per_minute` / `chunk_burst` (per key, own bucket) | 600 / 60 | 1..=6000 / 1..=600 |

One evidence index or export runs at a time (503 `evidence_busy`). An
export reads one black-box segment at a time (at most 256 MiB each) and
streams the bundle into its temp file as it goes (per-chunk and whole
SHA-256 computed on the way): the bundle is never held in memory. Before
building, the export must fit `max_storage_bytes` and leave 64 MiB free on
the state directory's filesystem (the request and nonce journals live
there; 507 `storage_full`); the build is abandoned after 60 s or at
shutdown (503 `evidence_timeout`, nothing kept). Delete exports when
downloaded (`DELETE`) to free the quota; expired ones are deleted at the
next evidence call or start. A chunk download that finds its export
corrupt deletes it only if it is still the export it read (a delete and
re-create of the same `export_id` in between keeps the new one).

## 12. Test vectors (`fixtures/control-plane-v2/`)

Generated deterministically by
`cargo run -p robodr-agentd --example control_plane_vectors` (generator
`crates/robodr-agentd/tests/common/cp_vectors.rs`); the test
`tests/control_plane_vectors.rs` fails when the committed files differ from
it and checks every vector against the implementation. **The keys are test
keys; their secret files are published on purpose.**

| Path | Content |
| --- | --- |
| `manifest.json` | index: keys, cases, chunk size |
| `keys/{soc,finding,blackbox}.key[.pub]` | `robodr-blackbox` key files (Ed25519) |
| `requests/NN-*.http` | the exact request bytes (CRLF) |
| `requests/NN-*.json` | method, target, timestamp, nonce, body SHA-256, the signing message, the signature, the expected outcome (`route`, or `401` + code), and for a sample answer: status, content type, body file, the answer message, `X-RoboDR-Answer-Signature` (and `X-RoboDR-Manifest-Signature`) |
| `answers/NN-*.body.{json,bin}` | sample answer bodies |
| `evidence/blackbox/seg-0000000000000000.rbb` | the synthetic black box (a `Genesis` and 23 notes) |
| `evidence/bundle.rbbx`, `evidence/chunks/NNNN.bin` | the export of case 06 (finding: seqs 10 and 12, 3 context records each side; 1 KiB chunks) |
| `evidence/manifest.json`, `manifest.sig`, `manifest.message` | its manifest bytes, signature header value, signed message |
| `evidence/expected.json` | the verification result (intact; seqs, hashes, anchor) |
| `evidence/tampered/bundle-flipped-byte.rbbx` | one payload byte of seq 10 flipped: tamper |

Negative request vectors: 11 (signature over another body), 12 (signed for
another robot), 13 (signed in the removed v1 domain); all 401
`bad_signature`, unsigned.

## 13. Limits of this release

* Nothing is executed unless executor v1 is enabled (§6a); it carries out
  `isolate_network`, `quarantine_node` (participant GUID) and
  `record_evidence` only, re-checks the safety state at apply time and
  reports `pending` / `verified` / `reverted`. A participant is
  quarantined only once agentd has seen it: by its SPDP unicast locators,
  or by its GUID prefix alone when none can be vouched for and it is not
  one of the robot's own (`locators_required` otherwise). A `pending` request whose
  order was staged but not yet sent when agentd stopped stays `pending`
  (the order is dropped, never sent late); the SOC resubmits under a new
  `request_id`.
* The judgment is only as right as the safety state source (live feed or
  static configuration) and the response policy; `control`, `phase` and
  `connectivity` are still configuration.
* TLS material is loaded at start: a rotation of the robot's certificate or
  of the trusted SOC CAs / pins / CRLs takes a restart (the state survives
  it). Revocation is by CRL file only (`tls.client_crl`, its `nextUpdate`
  not enforced); there is no OCSP.
* The request journal and replay store are checksummed, not signed: a
  person with write access to the state directory can make the robot fence,
  or remove whole valid lines, which no checksum detects: those requests
  are forgotten (a resubmission is judged anew and recorded again; the
  black box keeps both). Such a person cannot forge a decision (the black
  box holds every decision, signed). Damage the checksums do detect is
  rebuilt from the black box (§9).
* The first start on an empty state directory (and any start after the
  replay store was removed) refuses requests for `max_clock_skew_s`
  seconds (the fence, §2).
* The evidence API reads the black box while it is written: a record past
  the last complete frame is not exported yet; an export that races with
  cyclic retention is refused (retry).
* A network attacker without the client certificate can still make the TLS
  listener spend handshakes (bounded by `max_connections`, the per-source
  cap and the 5 s deadline, which a byte-at-a-time peer cannot stretch) and
  drop or delay requests and answers; from several source addresses it can
  keep every TCP pre-authentication slot busy (never the unix socket's).
* Tested with synthetic traffic, an in-process signing client and an
  OpenSSL-made test PKI (`crates/robodr-agentd/tests/data/control-tls/`),
  not against a deployed SOC or across a real network.

## 14. Changes from v1

* **v1 is removed**, on every listener (decision for GA sprint 5): the SOC
  side is being built against v2 only, so there is no deployed v1 client
  to stay compatible with, and keeping a second signing domain and
  unsigned answers on loopback would leave a weaker path in the code that
  every review must reason about. A v1 request (paths `/api/v1/...`, the
  `robodr-control-plane/v1` signing domain) is refused (404 / 401).
* Mutual TLS on TCP (any address); `allow_remote` is gone.
* Answer signatures are mandatory (`finding_signing` is required).
* Request state and replay store persist across restarts (`state_dir`).
* The evidence API (§11).
* DELETE is a method of the API (exports).
* Executor v1's statuses (§6a) are answered and persisted the v2 way:
  signed answers, journalled states (every executor refusal code of §6a
  survives a restart; a held action journals nothing new).

### Revision: control plane v2 review (2026-10)

Wire changes a SOC client must follow (the API version stays
`robodr-control-plane/v2`):

* **New answer field `in_force`** (boolean, top level) in every
  request-state answer (submit, GET, revert); `state.executor_state:
  "held"` while the executor holds a `verified` action after a reboot
  (§5, §6a). Vectors `02-submit` and `03-get-request` changed accordingly
  (body, body SHA-256, answer message and answer signature).
* **Replay fence** (§2): `now + max_clock_skew_s` (was `now`); always when
  the replay store is created (a first start refuses requests for the
  skew); also when the wall clock goes back below the store's high-water
  mark. Wire code unchanged (`stale_timestamp`).
* **New error codes**: 503 `evidence_timeout` (§11.3); 503
  `state_unavailable` also for a request id a damaged journal could not
  reconcile (§9); 507 `storage_full` also for the free-space headroom.
* **503 `busy`** semantics and retry rule documented (§7); it is also
  answered when every authenticated TCP slot is taken (§1).
* **Answer-signature coverage** documented (§2): status, body hash, request
  signature; not `Content-Type` / `Retry-After`.

Robot-side changes (no wire format change): per-listener connection slots,
handshakes counted apart from authenticated connections, a per-source cap
(`max_connections_per_source`, §1); deadlines bound every socket read (§1);
optional `tls.client_crl` (§1); journal tail damage beyond one line is
damage, the request journal is rebuilt from the black box (§9); orders reach
the executor only for recorded, matching requests (§6a); evidence exports
streamed, `max_export_bytes` at most 256 MiB, free-space headroom, build
deadline (§11.7); a corrupt-chunk delete never removes a re-created export;
`%XX` in a path takes two hex digits only (a sign is refused).

### Revision: executor trust boundary (executor M1, 2026-10)

No wire format change (the API version stays `robodr-control-plane/v2`);
it applies only with `executor.enabled` (§6a). What a SOC client sees:

* **New `refusal.code` values** on `refused` answers (§6a): the
  trust-boundary codes `soc_signature_invalid`, `soc_request_stale`,
  `soc_nonce_replayed`, `soc_replay_store_unavailable`, `order_mismatch`,
  `approval_missing`, `soc_keys_unavailable`, `approval_key_removed`, and
  `locator_out_of_scope` (quarantine). A client that does not know a code
  shows it as "not applied" (§6a, client requirements); agentd still
  answers `executor_refused` for a code it does not know.
* **Every control-plane order is refused** until the robot's
  `executor.json` lists the SOC public keys (`soc.keys`,
  `soc_signature_invalid`); one unreadable or refused key file refuses
  every order (`soc_keys_unavailable`, was `config_unavailable`).
* **Every quarantine is refused** until `executor.json` names
  `network.quarantine.cidrs` (`locator_out_of_scope`).
* **Reverts of SOC-approved actions need the SOC's signed revert** (§6a,
  "Signed reverts"): a SOC that signs every revert (§2) sees no change;
  a revert the executor refuses leaves the action `verified` with
  `state.revert.result: "pending"` until TTL.
* **After a robot reboot**, a held action whose approving SOC key was
  removed from `soc.keys` is not re-armed and turns `reverted`
  (`approval_key_removed`); rotate keys with both listed until the held
  actions expired.
* A SOC request that agentd accepted can still be refused by the executor
  as `soc_request_stale` (the executor's own window and fence) or
  `soc_nonce_replayed`: sign again with a fresh timestamp and nonce. A
  resubmission with the same `request_id` answers the stored state
  (§5): use a new `request_id`.
* `require_approval_for_all_containment` (site option): planner orders are
  refused, SOC requests unaffected.

### Revision: quarantine scope (red-team fix review R2-3, 2026-10)

Additive, no version change (`robodr-control-plane/v2`); it applies only
with `executor.enabled` (§6a). What a SOC client sees:

* **New top-level answer field `containment`** (string: `"full"`,
  `"partial"`, `"guid_only"` or `"unknown"`) on every answer of a
  `quarantine_node` request whose `status` is `verified` or `applied`
  (submit, GET, revert answers; also while held). Before this revision a
  quarantine that cut no locator (the participant announced its locators
  only on addresses it never sends from, or every locator was left out)
  read `verified` / `in_force: true` like a full one.
* **New `state.quarantine`** object `{"locators": ["ip:port", ...],
  "excluded": [{"locator": "ip:port", "reason": "..."}]}` once the
  executor reported the scope (§6a table: at most 16 locators, 64
  left-out entries, reasons ≤ 200 characters).
* `in_force`, `status`, `executed` and every other field keep their
  meaning; vectors (§12) are unchanged (none is a verified quarantine).
* Client requirement (§6a, §10): show `guid_only` as "partially
  contained: GUID-prefix drop only, not IP-contained", `partial` as
  "partially contained" with the left-out locators, `unknown` as "scope
  not reported"; only `full` is contained.
* Robot side: the executor's state answer to agentd carries
  `quarantine: {locators, excluded}` (`robodr_executor::engine::Outcome`;
  an older agentd ignores it). agentd lists locators beyond the order's 16
  in `excluded` ("over the order's locator limit (16): not acted on")
  instead of dropping them silently (review R2-6).
* **Upgrade order** (review R2-7): upgrade `robodr-executor` **before**
  `robodr-agentd`. An order carrying `guid_only` or `excluded` (since the
  previous redfix revision) is not understood by an older executor, which
  drops the message unanswered (its order format is strict); agentd then
  answers the request `failed` ("executor unreachable") and nothing is
  applied. agentd does not retry such an order in the older format: an
  unanswered order cannot be told apart from an executor that applied it
  and lost the answer, and resending a changed order under the same
  `request_id` could be answered `id_conflict` for an action in force.

### Revision: address-level quarantine (red-team fix review R3-1, 2026-10)

Additive, no version change (`robodr-control-plane/v2`); with
`executor.enabled` only.

* **`containment: "full"` changed meaning.** It meant "every announced
  locator has a rule", but a locator rule matches only traffic **from the
  announced port**, and Fast DDS (the ROS 2 default) sends from ephemeral
  ports, so such a participant was held back inbound only by the
  evadable GUID-prefix drop. A quarantine now also cuts the source
  addresses the participant was seen sending from, whole (any source
  port, to and from the robot's DDS ports), and `full` means every
  observed source address and every announced locator is covered by such
  an address drop (§6a definition). A quarantine that cut the same
  locators as before but cannot cut the address now reads `partial`; a
  scope journalled before this revision reads `partial` too.
* **New in `state.quarantine`:** `addresses`, `excluded_addresses`
  (`{"address", "reason"}`), `evidence_truncated` (§6a table).
* **Shared-host caveat** (§6a): an address drop cuts every DDS
  participant on that host, a legitimate unprofiled process included.
* Robot side: the order to the executor carries `addresses`,
  `excluded_addresses` and `evidence_truncated`; the executor's state
  answer carries them back with `containment`. **Upgrade the executor
  first** (as for R2-7): an older executor does not understand an order
  with these fields, and agentd answers the request `failed`.
