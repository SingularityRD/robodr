# robodr-agent: the RoboDR decision chain, offline

This crate wires the pure RoboDR crates into one chain and runs it without
hardware. It is the Phase 1/2 demo in software.

```
RobotEvent
  -> Profile::evaluate            (robodr-events)  ┐
  -> Firewall::check              (robodr-firewall, MotionCommand only, optional)
  -> ConsistencyMonitor           (robodr-motion, commands + feedback, optional)
  -> Deviation, stamped with the profile's observe/enforce mode
  -> Responder::plan              (robodr-responder: SafetyState, OperationalContext, ResponsePolicy)
  -> backstop: check_invariants + observe-only guard -> ResponsePlan + Disposition
  -> Recorder                     (robodr-blackbox: event, firewall verdict, deviation, plan note)
  -> FindingBuilder               (robodr-ocsf, evidence links = the black-box seq/hash)
  -> validated robot-edr.findings record (Kafka key + JSON value)
  -> Executor::submit             (no-op or dry-run log: the agent executes nothing)
```

Dependencies: std, serde/serde_json and workspace crates. `robodr-commission` is
used for its JSONL reader, so `robodr-replay` reads exactly the commissioning
input format.

## API

```rust
let mut agent = Agent::new(AgentConfig { firewall: Some(..), monitor: Some(..), ..cfg },
                           Box::new(signer), Box::new(clock))?;
let outcomes: Vec<Outcome> = agent.handle(now, &event, SafetyState::MovingSlow);
// or agent.tick(&event, state) to read the injected clock
let finished = agent.finish()?;            // seals the black box; keep finished.checkpoint off-unit
let report = verify_blackbox(dir, &verifier, Some(finished.checkpoint), Some("ugv-007"))?;
let links  = resolve_links(dir, &verifier, &finding_refs(&envelope))?;
```

Each deviation produces one `Outcome`: detector, escalation source, deviation,
plan, `Disposition`, black-box `EvidenceLinks`, firewall verdict (if any), and
the validated finding (`FindingOutput { key, partition, value, headers }`).

| Disposition | Meaning |
|---|---|
| `observe_only` | Profile unlocked, deviation observe-only, or policy not OEM-validated. `Record` only; `plan.would_have` shows what enforcement would have done. |
| `suppressed` | The responder's rate limiter reduced the plan to `Record`. |
| `record_only` | The plan is `Record` (for example while the e-stop is engaged). |
| `awaiting_human_approval` | Steps above `Record` need a human first. |
| `eligible` | An executor may request the steps without a human, after it re-runs `check_invariants`. |

## Invariants

- **Observe mode covers every detector.** Every deviation, including those
  from the firewall and the motion monitor, carries the profile's mode. The
  responder gets `profile_locked = profile.locked && !deviation.is_observe_only()`.
  The agent then checks the result again and replaces any action plan for an
  observe-only deviation with `Record` + approval. `guard_violation` reports
  this replacement. Tests show it never happens with the real responder.
- **Every plan is re-checked** with `robodr_responder::check_invariants` before
  it is used.
- **Nothing is executed.** `Executor` is the seam. `NoopExecutor` and
  `LoggingExecutor` act on nothing. A real executor must re-run
  `check_invariants` (`ExecutionRequest::recheck`). It must also honour the
  disposition, and must not act while the safety system is engaged. See
  `src/executor.rs`.
- **Detections survive storage failure.** If the black box refuses a record
  (saturation) or an append fails, the outcome and the finding are still
  produced. The missing link is listed in `evidence.errors`.
- **Deterministic.** Time comes only from the injected `Clock` (`ReplayClock`
  for replays), and all state is ordered (`BTreeMap`). The same inputs with the
  same clock and key give byte-identical findings, outcomes and black-box
  segments. This is tested.

## Demo (`robodr-replay`)

The scenario files are synthetic and live in `examples/`:

| File | What |
|---|---|
| `ugv-demo.profile.json` | Locked profile: 3 participants, `/cmd_vel` envelope 0.5 m/s |
| `policy-oem-validated.json` | `config/response-policy.example.json` with `oem_validated: true` (**simulated sign-off, demo only**) |
| `rogue-ugv.jsonl` | Clean graph, then a rogue participant, its `/cmd_vel` writer and command, then a legitimate 0.8 m/s command |
| `motion-injection.jsonl` | `/cmd_vel` 0.4 m/s with honest `/odom`, then fabricated 1.2 m/s odometry from t=4.0 s to t=5.5 s |

```sh
KEY=$(printf '42%.0s' $(seq 32))        # demo key only; 32-byte HMAC key in hex
E=crates/robodr-agent/examples

# 1. Rogue participant + foreign cmd_vel writer + over-envelope command
cargo run -p robodr-agent --bin robodr-replay -- \
  --events $E/rogue-ugv.jsonl --profile $E/ugv-demo.profile.json \
  --policy $E/policy-oem-validated.json --blackbox /tmp/bb --key-hex $KEY \
  --robot-id ugv-007 --safety-state moving_slow --firewall \
  --out /tmp/findings.jsonl --outcomes /tmp/outcomes.jsonl --log-plans

# 2. Verify on its own (as a receiving side would), then tamper and verify again
cargo run -p robodr-agent --bin robodr-replay -- verify --blackbox /tmp/bb \
  --key-hex $KEY --robot-id ugv-007 --findings /tmp/findings.jsonl
printf '\xff' | dd of=/tmp/bb/seg-0000000000000000.rbb bs=1 seek=4700 conv=notrunc
cargo run -p robodr-agent --bin robodr-replay -- verify --blackbox /tmp/bb \
  --key-hex $KEY --robot-id ugv-007 --findings /tmp/findings.jsonl   # exit 1

# 3. Injected telemetry caught by the motion monitor
cargo run -p robodr-agent --bin robodr-replay -- \
  --events $E/motion-injection.jsonl --profile $E/ugv-demo.profile.json \
  --policy $E/policy-oem-validated.json --blackbox /tmp/bb-motion --key-hex $KEY \
  --robot-id ugv-007 --safety-state moving_slow --step-ms 20 \
  --monitor --feedback-source /odom=wheel_odometry --firewall

# 4. Same scenario as 1 with the repository's (not OEM-validated) policy: observe only
cargo run -p robodr-agent --bin robodr-replay -- \
  --events $E/rogue-ugv.jsonl --profile $E/ugv-demo.profile.json \
  --policy config/response-policy.example.json --blackbox /tmp/bb-observe \
  --key-hex $KEY --robot-id ugv-007 --firewall --log-plans
```

Output of run 1 on stderr (findings go to `--out` or stdout):

```
[executor:dry-run] rule=robot.ros2.unknown_participant severity=High ... would request [Restrict, LimitMotion] (no approval needed); invariants ok
[executor:dry-run] rule=robot.ros2.unauthorized_motion_writer severity=Critical ... awaiting human approval for steps [Record, Restrict, LimitMotion, SafePause, RequestSafeState]; invariants ok
[executor:dry-run] rule=robot.firewall.rejected_unknown_source severity=Critical ... rate-limited: record only; invariants ok
[executor:dry-run] rule=robot.motion.linear_over_envelope severity=Critical ... rate-limited: record only; invariants ok
[executor:dry-run] rule=robot.firewall.limited_speed severity=High ... rate-limited: record only; invariants ok
replay: 16 events, 5 deviations {"critical": 3, "high": 2}, 5 findings written (0 failed), dispositions {"AwaitingHumanApproval": 1, "Eligible": 1, "Suppressed": 3}
evidence: 16 black-box records appended, 0 append errors, 0 guard violations
black box: 18 frames, 18 records verified, seq 0..17, last seal seq 17, CLEAN
evidence links: 17/17 resolve to intact signed records
VERIFIED: evidence chain intact end to end
```

After a flipped byte, `verify` prints `TAMPERED`, the hash mismatch with its
seq and byte offset, `16/17` links resolving with the bad one named, and it
exits 1.

The three later plans are `suppressed` because the replay steps 20 ms per
event. They all fall inside the responder's 5 s re-issue interval and do not
rank above the request already issued. This is the responder's designed rate
limiting. Use `--step-ms 6000` to see each one graded on its own.

### Replay time and options

- Wall time starts at `--start-ms` (default 2026-01-01T00:00:00Z) and
  monotonic time starts at 0. Event *k* (1-based, comment lines not counted)
  is observed at `k * --step-ms` (default 20 ms).
  `MotionFeedback.timestamp_ns` must use this monotonic base, or the
  monitor's stamp checks will fire.
- `--firewall` builds one spec per envelope channel with default limits.
  Without `--firewall-allow CHANNEL=GUID,...`, it allows **every profile
  participant** on the channel. This is a permissive demo default; in
  production, list the real writer GUIDs. A listed participant prefix
  authorises all of that participant's endpoints.
- `--monitor` uses `MonitorConfig::ugv` on the profile's motion channels.
  `--monitor-config FILE` loads a JSON `MonitorConfig` instead. Feedback
  channels not mapped with `--feedback-source` count as `other`, which is not
  compared against commands.
- By default, events are recorded only when they caused a deviation or a
  non-pass verdict. `--record-all-events` records every event.
- Exit codes: 0 verified, 1 verification failed, 2 usage, input or I/O error.
  A malformed JSONL line aborts the run with exit 2. The black box is still
  sealed and verifiable.

## Mapping notes

- `MotionCommand` has magnitudes only and no source stamp. The firewall sees
  a twist `(|v|, 0, 0)` or a joint vector filled with the max joint speed. Its
  stamp is the observation time, so stale and future checks cannot fire
  through this path.
- In the finding, commanded speeds are reported as `|v|`. A non-finite value
  is omitted, because the contract accepts only finite, non-negative numbers.
  The raw value stays in the tainted detail and in the black-box event record,
  so a NaN command still yields a valid Critical finding.
- The finding's profile hash is the SHA-256 of the parsed profile's canonical
  JSON (`profile_sha256`), not of the file's bytes.
- Escalation source is `participant:<24-hex prefix>` for graph events and
  commands with a `source_guid`, otherwise `channel:<name>`.

## Verified vs. not verified

**Verified** by `cargo test -p robodr-agent` (34 tests). All inputs are
synthetic.

- (a) A locked profile gives a High finding for the rogue participant and a
  Critical finding for the foreign `cmd_vel` writer. The plans match the
  policy matrix, the overrides and `auto_max_step`. The findings pass the OCSF
  validator. Every evidence link resolves to a record whose hash recomputes
  and whose signature verifies, and that record holds that event, deviation
  and plan.
- (b) An unlocked profile, or a policy that is not OEM-validated, gives
  observe-only, `Record`-only plans for every detector.
- (c) An over-envelope command gives firewall `Limited` (output ≤ envelope),
  a firewall deviation and a profile deviation, and a finding with 4 links.
  Hard-limit, foreign-source and NaN/±inf commands are rejected and reported.
- (d) Injected odometry produces exactly one High `feedback_divergence`
  finding. Honest feedback produces none.
- (e) A flipped byte or a deleted segment after the run is reported by the
  verifier and by link resolution. The wrong key fails verification.
- (f) Two runs give byte-identical findings, outcomes and segments. A
  different key changes the findings.

Also tested: hostile names (control, bidi and markup characters, 100 kB
strings, non-ASCII GUIDs, NaN, `u64::MAX` stamps) under every safety state
never panic and always give valid findings. Saturation refusals keep the
findings. Clock regressions are clamped. E-stop gives `Record` only. Repeats
become OCSF updates with a count. Invalid configurations are refused. The CLI
is tested end to end.

**Not verified:**

- No real robot, ROS 2 graph, DDS capture or sensor feeds this agent.
  `robodr-sensor-ros2` and the Pulsar glue do not call it yet.
- Policy matrix, monitor thresholds and firewall limits are unvalidated
  defaults. `policy-oem-validated.json` is a simulated sign-off for the demo.
- The black box uses HMAC (a shared key, so the verifier can forge). It is a
  placeholder for an asymmetric TPM-held key. No external checkpoint store
  exists. The replay verifies against the checkpoint it just produced.
- Findings were not checked against an OCSF schema server, a Kafka broker or
  AutoSecOps. Nothing is published to Kafka.
- No executor exists. Nothing is requested from DDS, the host, the Motion
  Firewall gateway, the mission executive or the safety controller.
- Performance was not measured. The agent allocates per deviation, so it
  belongs off the control loop. The firewall's hot path stays allocation-free
  inside `robodr-firewall`, but this agent's wrapper around it is not.
