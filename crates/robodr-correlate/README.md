# robodr-correlate: correlation engine

Combines individually weak detections into stronger findings. The design
document lists correlation as part of the detection engine ("new process +
new ROS node + the velocity command's source changed = high severity"). This
crate implements that part. It is pure, deterministic and bounded in memory.
It does no I/O, has no clock of its own and never panics.

```text
Deviation (ROS 2 pipeline, agent)  ─┐
Pulsar threat (host rule name)     ─┼─► Signal ─► Correlator::observe ─► CorrelatedFinding
agentd self-health                 ─┘                                       │ .to_deviation()
                                                                            ▼
                                                 Agent::handle_external (robodr-agent)
```

## Signals

A `Signal` is a detection that has already been reported on its own. It has:

- **`rule`**: a `robot.*` deviation id, or a Pulsar rule name such as
  `RoboDR: Interactive shell started on robot controller`.
- **`severity`** and **`mode`**: observe or enforce.
- **`domain`**: `network`, `motion`, `host`, `agent` or `other`. Inferred
  from the rule id. `Signal::host` sets it explicitly for Pulsar threats.
- **`entities`**: `participant` (GUID prefix), `ip`, `process` or `unit`.
- **`t_ns`**: monotonic time.
- **`evidence_ref`** (optional): for example, a black-box record reference.

The vocabulary the rules are checked against is `src/catalog.rs`. It holds
every `robot.*` id that the in-repo detectors raise and every rule name in
`rules/robodr/*.toml`. The `catalog_drift` test keeps the catalog in sync
with both.

## Rules (JSON)

Each rule has an `id` (`robot.correlate.<name>`), `title`, `description`,
`severity`, `escalate_by` (0–3), `window_secs`, `cooldown_secs` (defaults to
the window), `group_by` (an entity kind, or `null` for the whole unit) and a
`pattern`. There are four pattern kinds:

| kind | fires when |
| --- | --- |
| `sequence` | `steps[0]`, then `steps[1]`, … arrive in that order, all within the window of the first step, in one group |
| `co_occurrence` | every slot in `all_of` is matched (`count` times each, default 1) within the window, in any order. With slot `domain`s this means "host-side and network-side evidence together" |
| `threshold` | `count` signals matching `match` arrive within the window |
| `distinct_sources` | signals matching `match` arrive from `count` distinct values of `distinct_by` within the window |

A matcher accepts a signal when all of its set fields agree:

- `rules`: an exact id.
- `prefixes`: an id prefix.
- `domain`: the signal's domain.
- `min_severity`: the lowest severity accepted.

At least one of `rules`, `prefixes` or `domain` is required.

**Severity.** The output severity is `max(severity, max input raised by
escalate_by)`, capped at Critical. A finding is never less severe than any
of its inputs and never above Critical.

**Mode.** The output is `observe` if *any* input was observe-only.
Observe-only inputs include an unlocked profile and agent self-health. A
correlation therefore cannot turn them into an actionable finding.

**Validation** reports every problem at once. These are errors:

- unknown fields or pattern kinds
- a window that is non-finite, ≤ 0 or longer than one day
- a negative or non-finite cooldown
- a count outside its allowed range: 2–64 for `threshold` and
  `distinct_sources`, 1–64 for a `co_occurrence` slot
- a count on a sequence step or on a `threshold` / `distinct_sources` match
- more than 64 signals needed to fire
- fewer than 2 or more than 8 steps or slots
- a malformed or duplicate id
- a matcher that references `robot.correlate.*` (no feedback loops)
- `distinct_by == group_by`
- more than 64 rules
- a file over 1 MiB

These are warnings:

- an id or prefix that is not in the catalog (a custom rule, or a typo that
  would silently disable the rule)
- an id whose inferred domain contradicts the matcher's `domain`

## Default rules (`rules/default.json`)

| id | pattern | severity |
| --- | --- | --- |
| `coordinated_intrusion` | co-occurrence within 60 s: `robot.ros2.unknown_participant` + `robot.ros2.unauthorized_motion_writer` + a host process anomaly (shell, temp-dir exec, injected library, tracer, …) | Critical |
| `sensor_evasion` | co-occurrence within 120 s: 3× capture / fragment refusals or evictions + `robot.rtps.discovery_not_inspected` | High |
| `credential_theft` | sequence within 600 s: SROS 2 private key read (Pulsar) → unknown or source-mismatched participant | Critical |
| `trojaned_package_key_access` | sequence within 600 s: package install or maintainer script → SROS 2 key read | Critical |
| `spoofed_motion_source` | sequence within 30 s, **per IP**: participant or endpoint source mismatch → unauthorized motion writer | Critical |
| `motion_hijack` | sequence within 30 s: foreign motion writer or firewall source rejection → uncommanded motion, feedback divergence or a second feedback publisher | Critical |
| `defense_tampering` | co-occurrence within 120 s: RoboDR / Pulsar config change or service stop + `robot.agent.input_silent` or `input_ended` (observe-only by construction) | High |
| `discovery_flood` | unknown participants from 8 distinct IPs within 60 s | High |
| `host_process_persistence` | 3 host detections from **one process** within 300 s, escalated one level | ≥ Medium |

## Time, memory, fairness

- **Time.** The engine uses the largest timestamp it has seen. An older
  timestamp is processed at that time and counted in `clock_regressions`, so
  windows never grow and nothing panics. Each cited input keeps both its own
  time (`t_ns`) and the time it was processed at (`at_ns`). A bogus forward
  jump only expires pending state, and those inputs were already reported on
  their own. Windows are inclusive: exactly `window` apart correlates,
  `window + 1 ns` apart does not.
- **Memory.** The limits are:
  - Per group:
    - a sequence keeps at most `steps − 1` partial matches
    - a co-occurrence or threshold keeps at most `count` signals per slot
    - distinct sources keeps fewer than `count` values
  - Per rule: `max_groups_per_rule` groups (default 256).
  - Per signal: at most 8 entities, and at most 256 bytes for each value and
    for the evidence reference.

  Contributions are shared across rules through `Arc`.
- **Eviction.** This happens when a rule's table is full and a new group is
  needed:
  1. Expired state is swept first.
  2. The group with the least progress is considered, least recently used
     first.
  3. That group is evicted only if it holds at most one signal. Otherwise
     the newcomer is refused.

  A flood of fresh entities (GUIDs, spoofed IPs) therefore only churns
  single-signal groups. A group holding two or more signals can only be
  removed by expiry or by firing. Evicting a particular single-signal group
  costs an attacker at least `max_groups_per_rule` new-entity signals within
  the window, and each eviction is counted. Every rule has its own table, so
  a flood on one rule cannot touch another rule's state.
- **Cooldown.** After a group fires, its state is cleared and matching
  signals are ignored for `cooldown_secs`. If a group in cooldown is
  evicted, the result can only be an extra finding, never a missed one.

## Integration (agentd)

`robodr-agentd` runs the engine (`correlation` section of its configuration;
on by default with the shipped rules, plus an optional rule file validated
together with them as one set; see `docs/OPERATIONS.md`):

1. **Construct.** `Correlator::new(rules, Limits::default())` from
   `RuleSet::from_file` over the shipped rules and/or `correlation.rules_path`.
   A rule file that does not load refuses the configuration; load warnings
   are logged at start.
2. **Feed.** Every outcome the daemon reports goes in as
   `Signal::from_deviation(mono_ns, &outcome.deviation)` (the deviation's mode
   is already the stricter of profile and deviation), with
   `EntityKind::Ip` for `src:<ip>` sources (pipeline and safety-feed
   findings), `EntityKind::Participant` for `participant:<guid prefix>`
   sources (the agent's profile / firewall / motion-monitor deviations), and
   the deviation's black-box record URI as `evidence_ref`. Self-health issues
   (observe-only) go in without an entity. Correlated findings and the
   engine's own health finding are not fed back.
3. **Host side.** Not yet: nothing delivers Pulsar threats to agentd, so the
   host-dependent default rules (`coordinated_intrusion`,
   `credential_theft`, `trojaned_package_key_access`, `defense_tampering`,
   `host_process_persistence`) cannot fire in the daemon today.
4. **Emit.** Each `CorrelatedFinding` is recorded in full (every
   contributor) as a `robodr.correlated_finding` black-box note, then handed
   to `Agent::handle_external(now, Detector::Sensor, "correlate:<rule>[:<group>]",
   subject, f.to_deviation(), safety)`; observe-only stays observe-only.
5. **Ticks and health.** `tick(mono_ns)` on every housekeeping tick;
   `Stats` in `status.json` and the heartbeat; a rising
   `groups_evicted + groups_refused` raises the observe-only self-health
   finding `robot.agent.correlation_pressure` (rate-limited by
   `daemon.health_report_ms`).
6. **OCSF catalog.** `robot.correlate.*` entries are in the `robodr-ocsf`
   catalog since contract 1.3 (a custom rule id gets the generic
   "Correlated RoboDR detection" entry).

## Not verified

- The rules and windows are engineering defaults. They have not been tuned
  on fleet data, and false-positive rates are unknown. Run them in observe
  mode during commissioning.
- Unit-scoped rules (`group_by: null`) join host and network signals that
  share no entity. RoboDR has no process↔socket attribution yet, so on a
  busy unit two unrelated events inside a window will correlate.
- Host signals are synthetic in the engine's tests, because nothing delivers
  Pulsar threats to agentd yet; the daemon tests exercise network-only rules
  (discovery flood, a per-IP sequence) on synthetic captures. Throughput was not benchmarked. The cost per signal
  is O(rules × groups-per-signal × steps), plus an O(groups) sweep whenever
  a rule's table is full.
