# robodr-responder — Cyber-Jidoka response planner

A **pure planning library**: given a `Deviation` (from `robodr-events`), the
robot's current safety state and its operational context, it decides a graded,
safety-aware `ResponsePlan`. It performs no I/O and executes nothing. Every
action in a plan is a *request* to another component (black box, DDS/host
enforcement, Motion Firewall, mission executive, autopilot, safety controller).
The platform's functional-safety system (e-stop, safety PLC/controller) is always
the final authority; RoboDR is not a safety-rated component.

## The ladder

Plans are cumulative: a plan at step N contains every step up to N, in order.

| # | Step | Action | Requested from | Catalog action |
|---|------|--------|----------------|----------------|
| 1 | `record` | Evidence to black box, alert to console | black box / console | `record_evidence` |
| 2 | `restrict` | Deny network link / DDS participant / process | host & DDS enforcement | `isolate_network` (network), `quarantine_node` (participant, process) |
| 3 | `limit_motion` | Scale speed/workspace envelope by `factor` ∈ (0, 1] | Motion Firewall | `restrict_motion` |
| 4 | `safe_pause` | Pause at a safe point, platform's safe behaviour | mission executive / autopilot | `safe_pause` (two-person) |
| 5 | `request_safe_state` | Ask for the protective safe state; it decides | safety controller | `request_safe_state` (two-person) |

## Action catalog (`actions`)

`robodr_responder::actions` is the **single, vendor-neutral list** of robot
containment actions. The agentd control plane accepts exactly these
(`ActionKind` is a re-export of `ActionId`; a test asserts they match), and a
SOC integration registers them under their wire names.

| Action | Wire name | Step | Reversible | Approval | GA execution | May de-energise |
|---|---|---|---|---|---|---|
| `restrict_motion` | `robot_restrict_motion` | `limit_motion` | yes, TTL | single | executor (firewall gateway) | no |
| `quarantine_node` | `robot_quarantine_node` | `restrict` | yes | single | executor (DDS / nftables) | process target only |
| `isolate_network` | `robot_isolate_network` | `restrict` | yes, TTL | single | executor (nftables, management channel exempt) | no |
| `record_evidence` | `robot_record_evidence` | `record` | not applicable (`reversible: false`, `has_effect: false`: evidence is never "reverted") | single | executor (black box) | no |
| `safe_pause` | `robot_safe_pause` | `safe_pause` | yes | two-person | platform adapter only, OEM-validated policy | yes |
| `request_safe_state` | `robot_request_safe_state` | `request_safe_state` | no | two-person | plan only | yes |
| `rollback_config` | `robot_rollback_config` | `restrict` | no | two-person | plan only | yes (controller restart) |

Every action is **never autonomous** (`autonomous = false`): a SOC must
have a human approve it. `executable_in_ga` is `false` for the plan-only
pair; GA executes only reversible actions and `record_evidence` (which has
no effect on the robot, and is accepted by the control plane in observe
mode and while the safety system is engaged). The wire names keep the
`robot_<name>` strings used so far, so existing registrations stay valid.
`Approval::Single` is written `single`; the earlier name `analyst` is still
read (serde alias). `safe_pause`, `request_safe_state` and
`rollback_config` are flagged `may_de_energise`, and `quarantine_node` on
a process target `process_target_may_de_energise`: see *Morphology* below.
(Nothing in this crate executes; GA execution is the executor's and the
platform adapters' job.)

## Invariants (in code, regardless of policy; tested exhaustively)

1. **Nothing beyond `request_safe_state` exists.** The action vocabulary has no
   actuation, motor/power cut, IEC 60204-1 stop category 0, e-stop reset or
   "kill process mid-motion". A process may be *terminated* only while
   `Idle`, only if the policy sets `allow_terminate_when_idle`, and never on a
   morphology that needs active balance; otherwise it is quarantined.
2. **`estop_active` / `safe_state_active` → `record` only.** The safety system
   already has authority; RoboDR sends it no competing requests.
3. **`unknown` safety state → motion-affecting steps (3–5) require human
   approval.** Same for a human in command (teleop/manual) and transient phases
   (take-off/landing).
4. **Observe mode → `record` only**, with `would_have` holding the enforcement
   plan. Observe mode applies when the deviation itself is in
   `Mode::Observe` (`Deviation::is_observe_only`), when the model profile is not
   locked, *or* when the policy is not `oem_validated`. The deviation's mode is
   honoured even if the caller passes a locked context.
5. **Platform-appropriate safe behaviours** (data, validated per family):
   UGV/AMR `controlled_stop`; drone `hold` or `return_to_launch` (requested to the
   autopilot — never "stop" a drone in flight); arm `protective_stop_category2`;
   all may use `platform_defined`; `other` may use only `platform_defined`.
6. **Approval contract:** if `requires_human_approval`, only `record` may run
   before a human approves. Steps above the policy's `auto_max_step` always need
   approval.
7. **Policy mismatch** (context platform or morphology ≠ the policy's) →
   `record` + approval. The context's morphology is the caller's own
   configuration, and `check_invariants` refuses an acting plan whose
   `morphology` differs from the context's (`Violation::MorphologyMismatch`),
   so a plan's own label is never trusted alone.
8. **Fall-prone (humanoid, unspecified): no executable de-energising
   action.** `safe_pause` and `request_safe_state` never appear in a plan's
   `actions`; they go to `advisory` (never executed). The substitute
   containment — `limit_motion` plus only the restrict targets in the
   policy's `fall_safe_restrict` — **always requires human approval**
   (`Reason::DeEnergisingAdvisoryOnly`,
   `Violation::DeEnergisingOnFallProneMorphology`,
   `Violation::SubstituteWithoutApproval`).
9. **Needs active balance (humanoid, quadruped, unspecified).** No process
   termination (`allow_terminate_when_idle` is rejected; `idle` is not a
   gate — the robot balances while idle), a process quarantine always needs
   approval (it may be the balance controller), `limit_motion` never below
   `min_motion_factor` (and never below the hard floor 0.05 in
   `check_invariants`), and the control plane refuses `rollback_config`
   (a controller restart) with `fall_hazard`.

## Morphology (`morphology`)

The response policy carries the robot's body plan, `morphology`:
`humanoid`, `quadruped`, `wheeled_mobile`, `arm`, `aerial` or `other`
(declared statically stable). It is **required** when `oem_validated` is
true or `platform` is `other` (the family that covers humanoids and legged
robots): `validate` rejects such a policy without it
(`PolicyError::MorphologyRequired`). Where it may still be omitted (a
not-yet-validated policy of another family, which runs observe-only) it
reads as `unspecified`, which gets the humanoid treatment. RoboDR never
assumes a robot stands on its own; `conservative_default` leaves it
unspecified for every family.

A humanoid stays upright only while its joint controllers actively balance
it. The usual implementation of "pause", "safe state" or "protective stop"
on such a platform is a damping / zero-torque mode or a motor power cut, and
the robot then **falls** — tens of kilograms from standing height, next to
the people and equipment it works with. That is a worse hazard than most
cyber events it would answer, and RoboDR cannot know how a given platform
implements those requests. So, for `humanoid` (and `unspecified`):

* the planner moves `safe_pause` / `request_safe_state` into
  `ResponsePlan::advisory` (a recommendation for the operator and the
  platform's own safety function, which may have a validated sit-down or
  crouch sequence) and caps the executable plan at `limit_motion`;
* the substitute containment always waits for a human. It adds only the
  restrict targets the OEM listed in `fall_safe_restrict` (default empty:
  `limit_motion` alone). **`isolate_network` and `quarantine_node` are
  balance-safe only when the balance loop is not networked.** On Unitree
  G1/H1 the low-level loop is a DDS writer of `rt/lowcmd`; cutting that
  writer (network isolation, participant quarantine) trips the motor
  watchdog, the joints damp and the robot falls. `process` is never
  accepted in `fall_safe_restrict`;
* `check_invariants` rejects any plan (by the plan's *or* the checker's
  morphology) whose actions contain either step, any advisory entry that is
  not one of them, and any substitute plan without approval;
* the agentd control plane refuses SOC requests for `safe_pause` /
  `request_safe_state` / `rollback_config` on a humanoid (`fall_hazard`) and
  does not advertise them in the robot snapshot.

A **quadruped** also balances actively while standing: if its controller
process dies or restarts it drops onto its belly (~15-50 kg from
~0.3-0.5 m — less dangerous than a biped falling, but a real hazard next to
people). So the *active balance* rules (invariant 9) apply to quadrupeds
too: no process termination, process quarantine only with approval, no
`rollback_config`, a `min_motion_factor` floor. A quadruped keeps an
executable `safe_pause` / `request_safe_state` under an OEM-validated
`platform_defined` behaviour (e.g. a controlled stand-down); one whose
damping mode collapses the body without a safe sequence should be declared
`humanoid`. Wheeled platforms, arms and aerial vehicles keep the full
ladder unchanged.

Examples: [`config/response-policy.unitree-g1.example.json`](../../config/response-policy.unitree-g1.example.json)
(humanoid) and [`config/response-policy.unitree-go2.example.json`](../../config/response-policy.unitree-go2.example.json)
(quadruped); both are not OEM-validated and validated by
`tests/fall_prone_review.rs`.

Defence in depth: `ResponsePolicy::validate` rejects policies that try to break
2/5 (and malformed ones); the planner enforces all invariants again at plan time;
`check_invariants_for_deviation` is run on every plan and a violating plan is
replaced by `record` + approval. Both are public so an executor can re-check a
plan it receives before acting: `check_invariants(plan, state, ctx)` checks
everything that does not need the deviation; `check_invariants_for_deviation(plan,
deviation, state, ctx)` additionally rejects any plan for an observe-mode
deviation that is not `observe_only` and `record`-only
(`Violation::ObserveOnlyDeviationActed`). Prefer the latter when the deviation
is at hand.

## Escalation, hysteresis, rate limiting (`Responder`)

- **Escalation:** `threshold` deviations from the same source within `window_ms`
  raise that source one rung (counter restarts), at most
  `max_escalation_steps` (≤ 2) rungs, never above `escalation.ceiling` or the
  rule override's `max_step`.
- **Hysteresis:** a source's step is held (never automatically lowered). It resets
  only on `Responder::acknowledge` (operator) or after `quiet_period_ms` without
  deviations from that source. The hold survives an e-stop cycle.
- **Observe-mode deviations** are informational for the stateful responder
  too: planned from the source's current state (so `would_have` is accurate),
  but they create no source entry, add no escalation hit, raise no hold and
  touch no rate-limit memory.
- **Rate limit, per (source, rule):** only *auto-executable* plans (above
  `record`, no approval needed, not observe-only) are remembered. A later
  auto-executable plan for the same source key **and** rule, not higher than
  the remembered step, within `min_reissue_interval_ms`, is reduced to `record`
  (`suppressed = true`). Escalations are never delayed. Plans awaiting approval
  are never suppressed and never count, and another source's activity never
  sets `suppressed`.
- **Robot-wide motion guard (anti-oscillation):** an auto-executable
  motion-affecting plan whose step *and* severity are both not higher than the
  motion-affecting auto step already issued robot-wide within
  `min(min_reissue_interval_ms, 5 s)` (`MAX_MOTION_GUARD_MS`) has only its
  motion-affecting actions dropped
  (`MotionAlreadyRequested`) — that step is already requested and plans never
  relax. Its `record`/`restrict` actions (which concern its own source) are
  kept, so it is not `suppressed`. A higher-severity or higher-step plan always
  passes and becomes the new reference. The guard is forgotten on any
  `acknowledge` and whenever a plan is made while the e-stop / safe state is
  engaged (that also lowers remembered motion-affecting rate-limit entries to
  `restrict`): after a safe state + restart, or an operator lifting a limit,
  an earlier request is no longer in force and must not drop a new one.
- **Decoy floods** (arbitrary fresh source ids): cannot mute or downgrade
  another source's response (see the above), cannot stop a real source being
  restricted, and cannot downgrade a higher-severity plan. They *can* flood the
  console with approval requests (not deduplicated here; the console should
  aggregate) and push new real sources into the shared overflow escalation
  bucket (more active, never less automatic: if the bucket's shared
  escalation/hold would make a plan await approval while a fresh source's plan
  would be auto-executable, the fresh-source plan is used,
  `OverflowStateNotApplied`). Review finding 2 (wave 2) was exactly
  such a flood muting real responses under the old robot-wide limiter; see
  `tests/review_poc.rs`.
- Plans never relax anything; lifting applied restrictions is an operator
  action outside this crate. `acknowledge(Some(src))` also clears that
  source's rate-limit memory; `acknowledge(None)` clears everything.
- **Bounded memory:** ≤ 64 sources, ≤ 64 timestamps each, keys ≤ 128 bytes
  (a longer key is identified by a prefix plus a SipHash of the whole key under
  a per-responder random key, so two long keys sharing their first 128 bytes
  never share state; `plan.source` still shows the plain 128-byte truncation). When full, new sources share an overflow bucket (escalates like a
  source), so flooding fresh ids cannot evict real offenders or grow memory.
  Rate-limit memory: ≤ 256 (source, rule) entries keyed by the real source
  identity, expiring after `min_reissue_interval_ms`; when full the oldest is
  evicted, which can only cause a redundant re-issue, never a suppression.
- Time is the caller's monotonic ms clock; a backwards step counts as no time
  elapsed.

## Policy format

`schema` must be `robodr.response-policy/v1`. Example:
[`config/response-policy.example.json`](../../config/response-policy.example.json).

| Field | Meaning |
|---|---|
| `model`, `platform` | Robot model and family (`ugv`, `amr`, `drone`, `arm`, `other`) |
| `morphology` | `humanoid`, `quadruped`, `wheeled_mobile`, `arm`, `aerial`, `other`. Required when `oem_validated` or `platform: other`; otherwise absent = `unspecified` (treated as humanoid). See *Morphology* |
| `oem_validated` | `true` only after OEM sign-off; otherwise observe-only |
| `matrix.<state>.<severity>` | Max step. States: `idle`, `moving_slow`, `moving_fast`, `collaborative_human_nearby`, `estop_active`, `safe_state_active`, `unknown`. All states/severities required; e-stop/safe-state rows must be `record` |
| `rule_overrides[]` | `{rule, min_step?, max_step?, restrict?}` — clamps the matrix step for one rule id; ≤ 256, unique, `[A-Za-z0-9._-]{1,128}` |
| `auto_max_step` | Highest step executable without approval |
| `limit_motion_factor` | Envelope scale for step 3, finite, in (0, 1]; ≥ `min_motion_factor` on humanoid / quadruped |
| `min_motion_factor` | Default `0.2`, in [0.05, 1]: lowest envelope scale (planner and control-plane `restrict_motion` caps) on a robot that needs active balance |
| `fall_safe_restrict` | Default `[]`: restrict targets (`network`, `participant`; never `process`) the OEM validated as balance-safe on a humanoid; humanoid only |
| `safe_pause`, `safe_state` | Safe behaviour for steps 4/5, must suit `platform` |
| `default_restrict` | Restrict targets (`network`, `participant`, `process`), non-empty |
| `allow_terminate_when_idle` | Default `false`; rejected on humanoid / quadruped / unspecified |
| `escalation` | `window_ms`, `threshold` (2–64), `max_escalation_steps` (≤ 2), `ceiling`, `quiet_period_ms` (≥ window), `min_reissue_interval_ms` (≤ quiet) |

### Default policy (`ResponsePolicy::conservative_default`)

| state \ severity | low | medium | high | critical |
|---|---|---|---|---|
| idle | record | restrict | restrict | safe_pause |
| moving_slow / moving_fast | record | record | limit_motion | request_safe_state |
| collaborative_human_nearby | record | limit_motion | safe_pause | request_safe_state |
| estop_active / safe_state_active | record | record | record | record |
| unknown | record | record | restrict | request_safe_state *(approval)* |

Reasoning: false positives that stop production are the main operational risk,
so medium deviations on a moving robot only record; restricting comms while
moving can itself trip watchdogs, so it is not used below high there. With a
human nearby, slowing down is cheap relative to the hazard, so it starts at
medium. `auto_max_step = limit_motion`: pause and safe-state requests wait for a
human (matching their two-person approval tier in the action catalog); an OEM
may raise this.
Escalation: 3 in 60 s → +1 rung, max +1, never above `limit_motion`; 5 min
quiet resets; 5 s re-issue interval. The default is **not** `oem_validated`, so
out of the box it is observe-only.

## What is not verified

- **No OEM has validated any policy**, including the default and the example.
  The matrix values are engineering judgement, not a hazard analysis.
- **No real platform safe-state interface** has been exercised. The mapping of
  `controlled_stop`, `hold`, `return_to_launch`, `protective_stop_category2` to
  actual autopilot (e.g. PX4/ArduPilot modes), Nav2/UGV controllers or arm
  controllers (protective stop) is the executor's job and does not exist yet.
- **Safety state and context are trusted inputs.** Where they come from (safety
  PLC status, mission executive, teleop link) and how authentic they are is not
  addressed here; a spoofed `idle` could enable process termination if the
  policy allows it (hence default `false`).
- The SOC-side registration of the catalog (approval workflow, two-person
  rule) and the on-robot executor are not built here.
- Known limit: deviations that are observe-only only because of the *context*
  (`profile_locked = false`) or an unvalidated policy still update escalation
  and hold (shadow evaluation), and that state carries over if the profile is
  locked within `quiet_period_ms`. The agent sets `profile_locked = false` and
  passes `Mode::Observe` deviations together, so on that path no state is kept.
- Timing (latency of planning) is not benchmarked; planning is O(policy
  overrides + tracked sources) with small fixed caps.

## Integration (not done in this crate)

The sensor/glue must supply a stable source key per deviation (participant
GUID, process identity, link), a monotonic clock, the safety state and
`OperationalContext` (with `profile_locked` from `Profile::locked`), then hand
plans to an executor that honours `observe_only`, `requires_human_approval`,
`suppressed`, and re-checks with `check_invariants_for_deviation` (or
`check_invariants` when only the plan is available). The executor is assumed
to carry out auto-executable plans it receives: the motion guard treats an
issued auto motion request as in force for the re-issue interval.
