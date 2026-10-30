# robodr-agent: the RoboDR decision chain, offline

This crate wires the pure RoboDR crates into one chain and runs it without
hardware. It is the Phase 1/2 demo in software.

```
RobotEvent
  -> Profile::evaluate            (robodr-events)  ┐
  -> Firewall::check              (robodr-firewall, MotionCommand only, optional)
     or Firewall::check_joint     (low-level joint channel + decoded frame, handle_with_joint)
  -> ConsistencyMonitor           (robodr-motion, commands + feedback, optional)
  -> Deviation, stamped with the profile's observe/enforce mode
  -> Responder::plan              (robodr-responder: SafetyState, OperationalContext, ResponsePolicy)
  -> backstop: check_invariants + observe-only guard -> ResponsePlan + Disposition
  -> Recorder                     (robodr-blackbox: event, firewall verdict, deviation, plan note)
  -> FindingBuilder               (robodr-ocsf, evidence links = the black-box seq/hash)
  -> validated robodr.findings record (Kafka key + JSON value)
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
  produced and the plan is unchanged. The missing link is listed in
  `evidence.errors`.
- **Deterministic.** Time comes only from the injected `Clock` (`ReplayClock`
  for replays), and all state is ordered (`BTreeMap`). The same inputs with the
  same clock and key give byte-identical findings, outcomes and black-box
  segments. This is tested.

## Failure handling

Every agent-internal failure becomes an `AgentFault` (`Agent::faults()`,
bounded to the newest 256) and, when the black box can take it, a signed
critical `robodr.agent_fault` note. Faults never reach the responder: an
internal problem cannot by itself cause a motion request.

| Failure | Behaviour |
|---|---|
| Black-box I/O failure (recorder poisoned, rotation fails) | Drop the recorder, reopen the directory (resume + quarantine of a torn tail, signed `Resume`), retry once; at most one reopen per second of monotonic time. Detections, plans and findings continue without links meanwhile. `evidence_recovered` note with the number of lost appends when it works again. The reopen authenticates the chain tail and the signed export-cursor / checkpoint files with the agent's key (`Signer::verify_own`, or the verifier given to `Agent::new_with_verifier` for a signer that cannot verify); a tail that is not a crash artefact (complete frame with a bad hash or signature) is refused (`Corrupt`), and the agent stays degraded (`evidence_recovery_failed`). A recovered torn tail is a verifier **Warning**: the report is intact but not clean. |
| Signer failure | Nothing written; same outage accounting, no reopen. |
| Monotonic clock goes backwards | Held at the last value (`TimeGuard`); `clock_regression` fault. |
| Wall time disagrees with monotonic progress by > `clock_jump_tolerance_ns` (default 1 s) | Wall time kept as reported (evidence), `wall_clock_jump` fault. Rate limits and escalation windows use monotonic time only, so a wall jump cannot shorten them (tested). |
| Responder plan violates an invariant | Replaced by `Record` + approval; the rejected plan is kept in the black-box plan note. |
| Configuration that would weaken detection | Refused at start: unknown fields in profile / monitor files, `+inf` or NaN firewall limits, a firewall Twist channel without an explicit `max_angular_speed`, `kafka_partitions = 0`, labels that cannot form a valid finding (probed at start). |

The release profile uses `panic = "abort"`; a panic cannot be caught, so the
chain is written and tested not to panic on hostile input. The platform's
safety system never depends on this process.

## Executor contract

The agent only hands plans to `Executor::submit`. Every step is a *request*
to another component through an abstract interface; nothing in this crate
actuates, commands motion, resets an e-stop or overrides command authority.
`ExecutionRequest::steps_without_approval_at(current_state)` is what a real
executor may request without a human. It is empty unless the request is not
a replay, the disposition (given and re-derived from the plan) is
`eligible`, the invariants hold, the current safety state equals the one the
plan was made for, and the safety system is not engaged. Executors run
synchronously; a real one must hand off to its own bounded queue.

## Demo (`robodr-replay`)

The scenario files are synthetic and live in `examples/`:

| File | What |
|---|---|
| `ugv-demo.profile.json` | Locked, versioned (metadata `profile_version` 1) and sealed profile: 3 participants, `/cmd_vel` envelope 0.5 m/s |
| `ugv-demo.profile.json.sig` | Its detached Ed25519 signature by the **demo** profile key (public seed, see `tests/demo_profile.rs`; never trust it in the field) |
| `ugv-demo.trust.json` | Trust file with the demo key's public half (`--trusted-keys`); without it the replay is observe-only and its first finding is `robot.ros2.profile_refused` |
| `policy-oem-validated.json` | `config/response-policy.example.json` with `oem_validated: true` (**simulated sign-off, demo only**) |
| `rogue-ugv.jsonl` | Clean graph, then a rogue participant, its `/cmd_vel` writer and command, then a legitimate 0.8 m/s command |
| `motion-injection.jsonl` | `/cmd_vel` 0.4 m/s with honest `/odom`, then fabricated 1.2 m/s odometry from t=4.0 s to t=5.5 s |

```sh
# A fresh Ed25519 key file (robodr-blackbox-key/v2, mode 0600) plus
# /tmp/demo.key.pub. Keys are never passed on the command line (argv is
# readable through /proc).
cargo run -p robodr-blackbox --bin robodr-blackbox -- keygen --out /tmp/demo.key --key-id demo-key
KEY=/tmp/demo.key
E=crates/robodr-agent/examples

# 1. Rogue participant + foreign cmd_vel writer + over-envelope command
cargo run -p robodr-agent --bin robodr-replay -- \
  --events $E/rogue-ugv.jsonl --profile $E/ugv-demo.profile.json \
  --trusted-keys $E/ugv-demo.trust.json \
  --policy $E/policy-oem-validated.json --blackbox /tmp/bb --key-file $KEY \
  --robot-id ugv-007 --safety-state moving_slow \
  --firewall --firewall-max-angular /cmd_vel=1.0 \
  --out /tmp/findings.jsonl --outcomes /tmp/outcomes.jsonl --log-plans

# 2. Verify on its own (as a receiving side would), then tamper and verify again
# (the receiving side needs only the public key: --key-file $KEY.pub)
cargo run -p robodr-agent --bin robodr-replay -- verify --blackbox /tmp/bb \
  --key-file $KEY.pub --robot-id ugv-007 --findings /tmp/findings.jsonl
printf '\xff' | dd of=/tmp/bb/seg-0000000000000000.rbb bs=1 seek=4700 conv=notrunc
cargo run -p robodr-agent --bin robodr-replay -- verify --blackbox /tmp/bb \
  --key-file $KEY --robot-id ugv-007 --findings /tmp/findings.jsonl   # exit 1

# 3. Injected telemetry caught by the motion monitor
cargo run -p robodr-agent --bin robodr-replay -- \
  --events $E/motion-injection.jsonl --profile $E/ugv-demo.profile.json \
  --trusted-keys $E/ugv-demo.trust.json \
  --policy $E/policy-oem-validated.json --blackbox /tmp/bb-motion --key-file $KEY \
  --robot-id ugv-007 --safety-state moving_slow --step-ms 20 \
  --monitor --feedback-source /odom=wheel_odometry \
  --firewall --firewall-max-angular /cmd_vel=1.0

# 4. Same scenario as 1 with the repository's (not OEM-validated) policy: observe only
cargo run -p robodr-agent --bin robodr-replay -- \
  --events $E/rogue-ugv.jsonl --profile $E/ugv-demo.profile.json \
  --trusted-keys $E/ugv-demo.trust.json \
  --policy config/response-policy.example.json --blackbox /tmp/bb-observe \
  --key-file $KEY --robot-id ugv-007 --log-plans \
  --firewall --firewall-max-angular /cmd_vel=1.0
```

Output of run 1 on stderr (findings go to `--out` or stdout):

```
[executor:dry-run replay] rule=robot.ros2.unknown_participant severity=High ... would request [Restrict, LimitMotion] (no approval needed); invariants ok
[executor:dry-run replay] rule=robot.ros2.unauthorized_motion_writer severity=Critical ... awaiting human approval for steps [Record, Restrict, LimitMotion, SafePause, RequestSafeState]; invariants ok
[executor:dry-run replay] rule=robot.firewall.rejected_unknown_source severity=Critical ... rate-limited: record only; invariants ok
[executor:dry-run replay] rule=robot.motion.linear_over_envelope severity=Critical ... rate-limited: record only; invariants ok
[executor:dry-run replay] rule=robot.firewall.limited_speed severity=High ... rate-limited: record only; invariants ok
replay: 16 events, 5 deviations {"critical": 3, "high": 2}, 5 findings written (0 failed), dispositions {"awaiting_human_approval": 1, "eligible": 1, "suppressed": 3}
evidence: 16 black-box records appended, 0 append errors, 0 guard violations
black box: 18 frames, 18 records verified, seq 0..17, last seal seq 17, CLEAN
evidence links: 16/16 resolve to intact signed records
VERIFIED: evidence chain intact end to end
```

The run counts distinct links (the event record is shared by two findings);
`verify --findings` checks every link of every line (17).

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
  Twist channels need an explicit angular bound from the operator,
  `--firewall-max-angular CHANNEL=RAD_PER_S` (the OEM's value; the profile
  envelope has no angular field and a missing bound would mean unlimited):
  without it the replay refuses to start, naming the channel.
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
- `--blackbox` must be absent or empty: a replay always starts a fresh chain,
  so its output is reproducible and it never appends to real evidence.
- A replay cannot act. Its requests are marked `replay`, and `--log-plans`
  only prints what a live executor would have been offered.
- `--monitor-config` and `--profile` are parsed strictly (unknown fields are
  errors). At most 10 000 outcomes are kept in memory; all are counted.
- Keys: `--key-file FILE` only, a robodr-blackbox key file
  (`robodr-blackbox keygen --out FILE [--key-id ID]`: Ed25519 secret `FILE`,
  `robodr-blackbox-key/v2`, plus public `FILE.pub`; legacy HMAC v1 files
  are refused unless `--allow-hmac`, then load with a warning). `run` needs the secret file
  (`KeyFile::load_secret`: a symlink, a non-regular file or a mode with
  group/other bits is refused); `verify` also accepts `FILE.pub` at any mode.
  The key id is the file's. `--key-hex` and `--key-id`
  were removed (argv is readable by every process through `/proc`); giving
  them is a usage error that says so.
- Exit codes: 0 verified, 1 verification failed, 2 usage, input or I/O error
  (also an argument that is not valid UTF-8), 3 (`run` only) the evidence
  that was written verifies but findings were lost: they failed OCSF
  validation (for example a replay clock past what a finding can carry) and
  were not written, so the findings output is incomplete. The summary then
  says `NOT VERIFIED: evidence chain intact, but N finding(s) were lost`.
  1 takes precedence over 3. `ReplaySummary::verified()` is false in both
  cases; `evidence_verified()` and `findings_lost()` tell them apart.
  A malformed JSONL line aborts the run with exit 2. The black box is still
  sealed and verifiable.

## Mapping notes

- `MotionCommand` has signed per-axis values and no source stamp. The
  firewall sees a twist `(linear_speed, linear_y, linear_z)` /
  `(angular_x, angular_y, angular_speed)` (absent axes are 0) or a joint
  vector filled with the max joint speed. Its
  stamp is the observation time, so stale and future checks cannot fire
  through this path.
- Low-level joint channels (`FirewallSettings::joint_channels`, Unitree
  `LowCmd`) are checked by a separate joint-frame firewall instance:
  `Agent::handle_with_joint(now, event, Some(&JointInput { frame,
  stamp_ns }), safety)` runs `Firewall::check_joint` on the decoded frame
  (every slot, CRC verdict, `mode_pr` / `mode_machine`) with the frame's
  observation time as its clock (non-decreasing; an older stamp is
  clamped and counted, never a clock regression), and records
  `robodr.firewall_joint_verdict` (limit reasons `position` / `velocity`
  / `torque` / `gain` / `step` / `pd_torque`, substitute `hold_last` /
  `zero`, the frame's slot count, `crc_ok` and modes). A command on a
  joint channel without its frame is not checked by the firewall
  (`AgentStats::joint_frames_missing`); the profile still evaluates it.
  `FirewallSettings::from_profile_and_joints` builds both kinds.
- Channel kind (`robodr_agent::channel_kind`): the profile's recorded
  command type (`Profile::motion_types`, written by `robodr-commission
  learn`: `geometry_msgs` `Twist` / `TwistStamped`, Unitree API requests and
  the legacy `HighCmd` are twist channels; `JointTrajectory`, Unitree
  `LowCmd_` / `HandCmd_` / `MotorCmds_` / `MotorCmd_` and the legacy
  `LowCmd` joint channels) decides; without it an unambiguous envelope
  does (no `max_joint_speed` = twist, `max_joint_speed` without
  `max_linear_speed` = joint, a positive `max_linear_speed` = twist). The
  learner writes 0 for a dimension it never saw, so `max_linear_speed: 0`
  with a `max_joint_speed` (a twist channel that only turned in place
  looks like a joint channel) is ambiguous: refused with a configuration
  error when no type is recorded, and a warning
  (`FirewallSettings::warnings`) when the type had to decide. Inferring
  `Joints` there used to turn every twist command into a
  `rejected_kind_mismatch`.
- In the finding, commanded speeds are reported as `|v|` of `linear_speed`
  (the forward component) and `joint_speed`; the lateral / vertical /
  roll-pitch axes are not in the findings contract yet (the deviation detail
  names the axis that was over). A non-finite value
  is omitted, because the contract accepts only finite, non-negative numbers.
  The raw value stays in the tainted detail and in the black-box event record,
  so a NaN command still yields a valid Critical finding.
- The finding's profile hash is the SHA-256 of the parsed profile's canonical
  JSON (`profile_sha256`), not of the file's bytes.
- Escalation source is `participant:<24-hex prefix>` for graph events and
  commands with a `source_guid`, otherwise `channel:<name>`.

## Verified vs. not verified

**Verified** by `cargo test -p robodr-agent` (53 tests). All inputs are
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

Fail-safe (`tests/failsafe.rs`): a signer outage leaves plans and
dispositions identical to a healthy run, findings still validate, one fault
per outage, and a signed `evidence_recovered` note when it ends; a black-box
directory removed mid-run is recovered by reopening and the new chain
verifies; clock regressions and wall jumps are signed faults and a wall jump
does not reset rate limiting; the fault log is bounded; replays mark every
request and offer nothing, refuse a used directory and bound retained
outcomes; strict parsing refuses unknown fields and `1e400`; infinite
firewall limits, zero partitions and unusable labels are refused.

**Not verified:**

- No real robot, ROS 2 graph or real DDS capture has fed this agent. Its
  live caller is `robodr-agentd`, which feeds it RobotEvents from the sensor
  pipeline (discovery and, through the live motion path, `MotionCommand` /
  `MotionFeedback` decoded from RTPS user DATA), but only synthetic pcaps
  have been run through it. The Pulsar module (`robodr-sensor-ros2`) does
  not call the agent: it only raises Pulsar threats.
- Policy matrix, monitor thresholds and firewall limits are unvalidated
  defaults. `policy-oem-validated.json` is a simulated sign-off for the demo.
- The black box signs with an Ed25519 key file (`robodr-blackbox keygen`,
  default) or, legacy, HMAC (a shared key, so the verifier can forge; only with
  `--allow-hmac`, warned).
  The Ed25519 seed is a file, not a TPM-held key (the arithmetic is the
  audited `ed25519-dalek` crate). No external checkpoint store exists. The replay verifies against the checkpoint it just produced.
- Findings were not checked against an OCSF schema server or a running SOC
  consumer. The agent publishes nothing itself (agentd spools records;
  `robodr-export` delivers them).
- No executor exists. Nothing is requested from DDS, the host, the Motion
  Firewall gateway, the mission executive or the safety controller.
- Black-box recovery was exercised with simulated failures only (failing
  signer, directory removed). Real ENOSPC/EIO, power loss and fsync failure
  on target storage were not tested.
- Agent faults are not yet turned into OCSF findings or a health channel;
  the integrator must forward `Agent::take_faults()`.
- Performance was not measured. The agent allocates per deviation, so it
  belongs off the control loop. The firewall's hot path stays allocation-free
  inside `robodr-firewall`, but this agent's wrapper around it is not.
