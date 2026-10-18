# robodr-agentd: the RoboDR decision chain as a live daemon

`robodr-replay` runs the decision chain offline over a JSONL file. This crate
runs the same chain as a long-running process on the robot controller. It
uses std threads and `std::sync::mpsc` only: no async runtime, no Pulsar.

```
 AF_PACKET capture ┐                                 ┌ Pipeline (robodr-ros2-pipeline)
 pcap replay ──────┤ Datagram                        │   tick() every tick_ms (1 Hz), capture_findings(health)
 SPDP socket ──────┤───────┐  one bounded queue      │   Finding ─► Agent::handle_external(Sensor)
                   │       │                         │   decoded MotionCommand / MotionFeedback ─► Agent::handle
                   │       ├► try_send; when full ─► main thread ┤
 JSONL stdin ──────┤ Robot │  the item is dropped    │   RobotEvent ─► Agent::handle
 JSONL unix socket ┘ Event │  and counted            │     (profile + Motion Firewall + motion monitor)
 host_threats ──── Pulsar ─┘  (robodr-threat-forward)│   host threat ─► Agent::handle_external(Sensor) + Signal::host
                   threats                           │   Outcome ─► black box (signed, hash-chained)
                                                     │           ─► spool/ready/<seq>.json (validated OCSF)
                                                     └ self-health ─► Agent::handle_external(SelfHealth)
                                                       status.json, heartbeat notes in the black box
```

```
robodr-agentd --config /etc/robodr/agentd.json [--check-config]
```

Exit codes: `0` clean stop (SIGTERM/SIGINT, or every input ended when
`exit_when_inputs_end` is set); `1` runtime failure; `2` usage or
configuration error (nothing started).

## Configuration

There is one JSON file. See `examples/agentd.example.json` (every key, lab
paths) and `src/config.rs`. For the installed unit, `config/agentd.example.json`
is the runnable baseline (passes `--check-config` as copied on a
commissioned robot) and `config/agentd.full.example.json` adds the keys that
need extra files (`trust_roots`, `revocation_list`, `finding_signing` with
the `20-finding-key.conf.example` drop-in; `host_threats` with the
`30-host-threats.conf.example` drop-in for `robodr-pulsard`). Unknown keys are refused at every
level, and every path must be absolute.

| Key | Meaning |
|---|---|
| `robot` | `id` (also the black-box device id), `site`, optional `model`, `kafka_partitions` (`profile_version` was removed: the version in findings is the signed profile's `metadata.profile_version`) |
| `sensor` | The ROS 2 sensor's own `[module.robodr-sensor-ros2]` section in JSON form, validated by `robodr_ros2_pipeline::Config::validate`. It sets the profile path, capture (live interfaces or `pcap_replay`), the SPDP socket (`listen_spdp`, default **true**) and the binding settings. Its profile is used by the pipeline and by the agent. |
| `policy_path` | Response policy (`robodr.response-policy/v1`) |
| `blackbox` | `dir`, `key_file`, optional `key_id`, optional `boot_id` (default `/proc/sys/kernel/random/boot_id`) |
| `spool` | `dir`, `max_bytes` (default 64 MiB), `max_files` (default 10000) |
| `event_inputs` | `[{"kind":"stdin"}]` and/or `[{"kind":"unix_socket","path":...,"max_connections":4}]` |
| `context` | `safety_state` (default `unknown`; must stay `unknown` when `safety_feed` is set), `control`, `phase`, `connectivity`, `operator_present` |
| `safety_feed` | Optional. The live safety-state feed (see below): `stale_after_ms` (default 1000), `topics` (ROS topics decoded from the captured bus) and/or `socket` (a local safety-PLC gateway socket). |
| `firewall` | Optional. `max_angular` (rad/s for every profiled Twist channel) and `allow` (writer GUIDs per channel). Runs **recording-only** (see below). |
| `motion_monitor` | Optional. `config_path` (strict `MonitorConfig`; default: the UGV defaults on the profile's motion channels) and `feedback_sources`. Feedback sources that are ROS topic names (`/odom`) are also decoded from the bus. |
| `sensor.motion` | Optional. The live motion decode path: `enabled` (default true), `feedback_topics` (e.g. `["/odom"]`), `max_writers`, `max_samples_per_datagram` (`evaluate_commands` is accepted but the daemon always lets the agent evaluate). Unknown keys are refused. |
| `host_threats` | Optional. `socket_path` (the socket `robodr-threat-forward` writes Pulsar threats to), `socket_mode` (`"0600"` default or `"0660"`), `allowed_uids` (peers besides uid 0), `max_connections` (default 2, max 8). See "Host threats" below. |
| `control_plane` | Optional, off when absent. The SOC action-request API: `listen_tcp` (loopback unless `allow_remote`), `unix_socket` (`socket_mode` `"0600"`/`"0660"`), `soc_keys` (Ed25519 public key files), `max_clock_skew_s` 30, `rate_per_minute` 30, `burst` 10, `max_connections` 4, `max_requests` 1024, `answer_timeout_ms` 5000. Requests are judged and recorded, **never executed**. See "Control plane" below. |
| `daemon` | `queue_capacity` 4096 (max 65536), `queue_bytes` 33554432 (32 MiB; 1 MiB..=256 MiB), `tick_ms` 1000, `heartbeat_ms` 10000, `silence_ms` 30000, `lag_ms` 2000, `health_report_ms` 10000, `exit_when_inputs_end` false |

**Key.** Keys are never accepted on the command line. `blackbox.key_file`
is either a secret key file as written by `robodr-blackbox keygen --out FILE`
(Ed25519 by default, `robodr-blackbox-key/v2`; a legacy HMAC-SHA256 v1 file
still loads with a start-up warning; its `key_id` is used unless
`blackbox.key_id` is set, and a `blackbox.key_id` that differs from it is a
configuration error), or, as in 0.1.0-alpha.1, a bare hex HMAC key of at
least 32 bytes (key id from `blackbox.key_id`, else derived from the key;
also warned about). With Ed25519 the evidence is verified with `FILE.pub`
alone (`robodr-blackbox verify --keyring FILE.pub`), so a verifier cannot
forge it. The daemon refuses the file if it is a public key file (`.pub`),
is a symlink, is not a regular file, is accessible by group or others (it
must be `chmod 600`), is owned by a uid other than the daemon's or root, or
is larger than 4 KiB. The checks run on the opened descriptor, and that
descriptor is matched against the path.

**Profile trust.** The pipeline decides the mode, and the agent follows it.
A sealed, locked profile with metadata and a valid detached signature
(`<profile_path>.sig`) from a key in `sensor.profile_trust.trusted_keys`
enforces; with `sensor.profile_trust.state_file`, a `profile_version` lower
than the last accepted one (or the same version with other bytes, or a draft
replacing a locked profile) is refused unless `allow_rollback` names its
exact digest. `--check-config` makes the decision but never writes the state;
the daemon writes it atomically at start, and if it cannot, it does not
enforce. The shipped unit can write `/var/lib/robodr/profile-state/` (created
by `packaging/tmpfiles.d`, owner `robodr`), where `config/agentd.example.json`
puts `agentd.json`. An unlocked profile observes. A locked profile that fails the
commissioning file check (`robodr-commission lock` seal) or the trust check
runs observe-only. A profile that fails validation is replaced in the
agent by an empty, unlocked profile: everything is reported, nothing is acted
on, and the Motion Firewall is off. In that case the pipeline's
`robot.ros2.profile_refused` finding is the first one in the spool.

## Live motion data

Captured datagrams carry more than discovery: the pipeline decodes RTPS
user DATA on the profile's motion channels (`motion_envelopes`) and on the
feedback topics into `MotionCommand` / `MotionFeedback`
(`robodr_ros2_pipeline::motion`). The daemon stamps them with its own
monotonic clock when it handles the datagram and passes each one to
`Agent::handle`, like a JSONL event: profile envelope, Motion Firewall,
motion monitor (commands and per-publisher feedback), black box, spool.
The pipeline's own envelope evaluation is off in the daemon, so an
over-envelope command is reported once, by the agent, with the event as
evidence. The pipeline still reports undecodable, unattributed and
source-mismatched samples (as sensor findings).

**The firewall only records.** The daemon reads a copy of the traffic; it
is not on the command path and cannot pass, limit or drop anything. It
therefore runs the firewall with `FailBehaviour::PassThroughObserveOnly`:
each verdict is a recorded *would-have* (`"enforcing": false` in the
black-box verdict note), never an output. Plans are still produced and
recorded (never executed, as before).

`status.json` and the heartbeat carry `daemon.motion_events` and
`pipeline.motion` counters (decoded commands / feedback, undecodable,
unattributed, known writers, ...).

## Live safety state

Every plan is graded by the robot's safety state (`idle`, `moving_slow`,
`moving_fast`, `collaborative_human_nearby`, `estop_active`,
`safe_state_active`, `unknown`). Without `safety_feed` it is the static
`context.safety_state`. With it, `src/safety.rs` reads it live and **only
reads**: nothing is published, subscribed or sent to the robot or its
safety system.

```json
"safety_feed": {
  "stale_after_ms": 1000,
  "topics": [
    { "topic": "/estop", "type": "std_msgs/msg/Bool",
      "values": { "true": "estop_active", "false": "none" } },
    { "topic": "/robot_mode", "type": "std_msgs/msg/UInt8",
      "values": { "0": "idle", "1": "moving_slow", "4": "safe_state_active" } },
    { "topic": "/mode_name", "type": "std_msgs/msg/String",
      "values": { "AUTO": "none", "PROTECTIVE_STOP": "safe_state_active" } },
    { "topic": "/odom", "type": "nav_msgs/msg/Odometry",
      "motion": { "moving_above": 0.05, "fast_above": 1.0, "hysteresis": 0.02 } }
  ],
  "socket": { "path": "/run/robodr/safety.sock", "max_connections": 2 }
}
```

- **Topics** are decoded from RTPS user DATA in the captured traffic
  (needs `sensor.capture`), by the type SEDP announced, with
  `robodr-cdr`'s `std_msgs` decoders (`Bool`, `UInt8`, `String` bounded to
  256 bytes) or its `Odometry` decoder. A value maps to a state or to
  `none` ("says nothing", e.g. e-stop released). A value the mapping does
  not list reads `unknown` (`robot.safety_state.unmapped_value`, Low).
  Odometry gives `idle` / `moving_slow` / `moving_fast` from
  `‖twist.linear‖` (and optionally `angular_moving_above`), with
  hysteresis; a non-finite speed reads `unknown`.
- **Socket**: JSON lines `{"state":"estop_active"}` (strict) from a local
  gateway; created mode 0600 like the event socket. Malformed lines are
  counted as malformed input, never applied.
- **Freshness**: a source with no reading younger than its
  `stale_after_ms` reads `unknown`. Publishers must publish periodically; a
  latched, publish-on-change topic reads `unknown` between changes.
- **Conflicts**: the most conservative claim of all sources (and of all
  writers of one source) wins: `estop_active` > `safe_state_active` >
  `unknown` > `collaborative_human_nearby` > `moving_fast` > `moving_slow`
  > `idle`. The planner caps plans at Record while the safety system is
  engaged and gates every motion-affecting step on human approval when
  `unknown`, so no source, and no stale source, can make RoboDR act more
  than the others allow. If nothing claims a state the result is `unknown`.
- **Spoofing**: a bus sample is used only if its writer was announced via
  SEDP unambiguously with the configured type, its participant is in the
  profile, the topic is a profiled writer topic, it matches the optional
  `writers` allowlist, and its datagram's IP is not outside the
  participant's binding. Otherwise it is ignored and reported once per
  writer and reason (`robot.safety_state.untrusted_source`, High). An
  ignored sample never refreshes a source, so a spoofer can at most make
  it go stale (`unknown`). An undecodable trusted sample reads `unknown`
  (`robot.safety_state.undecodable_sample`, Medium).
- **Recording**: each change of the combined state is a
  `robodr.safety_state_transition` note in the black box (from, to,
  whether fresh sources disagreed, each source's claim, freshness and
  age); `status.json` carries `safety_state` and `safety_feed`.

## Host threats (Pulsar)

With `host_threats`, the Pulsar module `robodr-threat-forward` (registered
by `robodr-pulsard`, `DEFAULT_ENABLED = false`, configured in
`[module.robodr-threat-forward]`) writes every Pulsar threat except the ROS
2 sensor's own to a unix stream socket the daemon binds (`src/host.rs`),
one JSON object per line:

```json
{"kind":"threat","v":1,"rule":"RoboDR: Interactive shell started on robot controller","source":"rules-engine","severity":"medium","category":"execution","ts_ms":1790000000000,"pid":4242,"ppid":1,"uid":0,"gid":0,"image":"/usr/bin/bash","container":false}
{"kind":"heartbeat","v":1,"sent":17,"dropped":0,"skipped_own":3}
```

- **What a threat becomes.** A `robot.host.pulsar_threat` finding
  (`Detector::Sensor`, source `host:<module>`, the rule's severity, Medium
  if none; OCSF data source `host_runtime`; the Pulsar rule name, pid,
  image and uid in the detail) and a correlation signal
  `Signal::host(<Pulsar rule name>)` with the process entity
  (the pid: an `execve` or Pulsar's tracker lag can change the image of one
  process) and the finding's black-box record as evidence. So the
  host-dependent correlation rules (`coordinated_intrusion`,
  `credential_theft`, `trojaned_package_key_access`, `defense_tampering`,
  `host_process_persistence`) fire. A threat from `robodr-sensor-ros2` is
  dropped and counted (`daemon.host_threats_own_skipped`): the daemon has
  it from its own pipeline.
- **Peers.** The socket's directory must be owned by root or the daemon's
  user and not writable by group or others; an existing path must be a
  socket owned by the daemon's user. The socket is created `0600` or `0660`.
  Every connection's peer uid (`SO_PEERCRED`) must be 0 or in
  `allowed_uids`; others are closed, counted (`rejected_connections`) and
  reported as malformed input.
- **Lines.** At most 4 KiB; unknown or duplicate keys, a wrong `v`, missing
  `rule` / `source` / `pid`, over-long strings (rule and image 256 bytes,
  source and category 64) or control characters refuse the line (counted
  as malformed, `robot.agent.input_malformed`, rate-limited; never
  activity).
- **Liveness.** The forwarder writes a heartbeat at connect and every
  `heartbeat_ms` (5 s) when idle. A configured host input with no forwarder
  reads "no data yet" or silent, so the state is `unknown`, never `ok`
  (`robot.agent.input_silent`). The heartbeat's `dropped` (threats the
  forwarder lost, e.g. its queue filled while the daemon was down) is
  added to the input's `upstream_dropped` and reported like queue drops.
- **Status.** The input `host:<path>` shows `received`, `malformed`,
  `rejected_connections`, `connections`, `upstream_dropped`;
  `daemon.host_threats`, `host_heartbeats`, `host_threats_own_skipped`.

## Control plane (SOC action requests)

With `control_plane` (contract `docs/contracts/robot-edr.control-plane.md`)
a SOC such as AutoSecOps may *request* one of six actions
(`restrict_motion`, `quarantine_node`, `isolate_network`, `safe_pause`,
`request_safe_state`, `rollback_config`) over a small std-only HTTP/1.1 API
(`src/control/`). The answer is truthful about what happens: **nothing is
executed.** The only executor is the recording one, so an accepted request
is `recorded_not_executed` (`"executed": false`), "accepted and recorded as
a plan".

```json
"control_plane": {
  "unix_socket": "/run/robodr-agentd/control.sock",
  "listen_tcp": "127.0.0.1:8787",
  "soc_keys": ["/etc/robodr/soc/autosecops.pub"]
}
```

- **Authentication.** Each request is signed with a configured SOC Ed25519
  key over method, exact target, this robot's id, key id, timestamp, nonce
  and body hash; ±`max_clock_skew_s` and a nonce cache stop replays (full
  cache: refused, never unchecked); per-key token bucket. With
  `finding_signing` every answer to an authenticated request is signed with
  the finding key, bound to the request signature.
- **Allow-list.** Six classes, each with its own parameters (speed caps in
  (0, 10], a zone, a GUID or node name, a profile/program rollback); the
  time-limited classes need `ttl_seconds` 1..=86400, the others refuse one;
  no motion command, force or override field exists and `authority` must be
  `request`. Unknown or duplicate keys refuse the body.
- **Judgment.** Against the safety state *now* (live feed re-evaluated),
  the operational context and the response policy: refused while the
  e-stop / safe state is active (also `request_safe_state`: the safety
  system has authority), in observe mode, for motion-affecting steps while a
  person commands motion or during take-off / landing, `rollback_config`
  unless `idle`, anything above the policy matrix's ceiling for the state, a
  speed cap above the profile envelope, and any plan that fails
  `check_invariants`. A refusal is final.
- **Evidence.** Request (with its signature and exact body: it re-verifies
  offline), state, context and decision are one fsynced
  `robodr.control_plane_request` note; reverts and authenticated invalid
  requests are notes too. No black box, no claim: the answer is then
  `failed` and nothing is stored.
- **Abuse.** Bounded parsing (8 KiB head, 16 KiB body, 5 s), at most
  `max_connections`, a bounded queue to the main loop (full: 503). Failed
  authentications raise `robot.agent.control_plane_unauthenticated` (High),
  authenticated invalid requests `robot.agent.control_plane_invalid`
  (Medium); both observe-only self-health, rate-limited by
  `health_report_ms`. The API is not an input: a quiet SOC never makes the
  state `unknown`.
- **Transport.** No TLS in agentd: listen on the unix socket or loopback
  and put a TLS terminator in front for a remote SOC (`allow_remote` exists
  for networks you otherwise protect). The shipped unit has
  `IPAddressDeny=any`: TCP on loopback needs a drop-in with
  `IPAddressAllow=localhost`.
- **Status.** `status.json` and heartbeats carry `control_plane` (listeners,
  executor, counters, `last_auth_failure`).

## Outputs

- **Black box** (`blackbox.dir`). It holds every deviation, plan note,
  firewall verdict and triggering event, as the agent records them. It also
  holds `robodr.agentd_start`, `robodr.agentd_heartbeat` (every
  `heartbeat_ms`: state, reasons, per-input counters, pipeline, agent and
  spool counters), `robodr.agentd_recovery` and a final `robodr.agentd_stop`
  note. A restart resumes the chain; the recorder signs a `Resume` record.
- **Spool** (`spool.dir`):
  - `ready/<seq:020>.json` holds one validated `robot-edr.findings` record
    per file: `{schema, seq, topic, key, partition, headers, value}`. `value`
    contains the exact validated bytes. Each file is written under `tmp/`,
    fsynced, renamed, and then its directory is fsynced.
  - **Exporter contract:** read `ready/` in name order, deliver, then
    acknowledge by renaming the file into `acked/`.
  - When the spool would exceed `max_bytes` or `max_files`, the daemon
    deletes **acknowledged** files, oldest first. It never deletes from
    `ready/`. If acknowledged files cannot free enough space, the new record
    is not spooled: it is counted, it stays in the black box, and the daemon
    raises a `robot.agent.spool_full` finding. Health findings can use a
    small reserve.
  - `status.json` is rewritten every tick. It carries `updated_mono_ms`
    (`CLOCK_MONOTONIC`, ms), `boot_id` and `stale_after_ms` (2 x `tick_ms`
    + `lag_ms`). **A consumer must show `unknown`** when `running` is false,
    the boot id is not the current one, or the status is older than
    `stale_after_ms` (a stalled main loop leaves its last `ok` behind);
    `robodr_agentd::effective_state` implements that rule.
    `checkpoint.json` is the final
    black-box seal, written at shutdown so the exporter can take it
    off-unit.

## Self-health ("never OK when blind")

The robot's state in `status.json` and in the heartbeat is one of three
values:

- `ok`: every input delivered **valid** data within `silence_ms`, nothing
  was dropped, no lag, and the profile is enforced. Malformed lines are
  counted (`input_malformed`) but are not data: an input that sends only
  junk goes silent (`input_silent`, `unknown`).
- `degraded`: queue drops, a profile that is not enforced, spool trouble, or
  black-box trouble.
- `unknown`: an input is silent, ended, or has sent **no data yet**, every
  input has ended (live mode: the daemon keeps running, idle, and says so),
  or the pipeline lags.

The state is never `ok` before data has arrived.

Issues become findings under the rules `robot.agent.input_silent` (High,
once per silence episode), `input_ended` (High), `queue_overflow` (Medium,
deltas), `input_malformed` (Low, deltas), `pipeline_lag` (Medium, with
hysteresis), `spool_full` (High) and `evidence_degraded` (High). Recurring
counter findings are rate-limited by `health_report_ms`.

Health findings are handed to the agent as `Detector::SelfHealth` and are
**always observe-only**. A health problem, including an attacker starving or
flooding an input, is recorded and reported but never feeds a motion
request.

## Robustness

- **Bounded memory.** The queue holds at most `queue_capacity` items **and**
  at most `queue_bytes` bytes (payloads plus per-item overhead, one budget
  shared by all inputs). When either is exhausted, the item is dropped and
  counted (`dropped`, and `budget_drops` for the byte bound); a capture
  thread is never blocked. The systemd unit adds `MemoryMax=` and a
  positive `OOMScoreAdjust=` so agentd, not the motion stack, is the one
  that goes under memory pressure.
- **No busy loop.** When every input has ended in live mode, the loop
  sleeps to its next deadline instead of polling the disconnected queue.
- **Watchdog.** `READY=1`, `WATCHDOG=1` (from the main loop, every <= 1 s),
  `STATUS=` and `STOPPING=1` go to `NOTIFY_SOCKET` (std `UnixDatagram`,
  path or abstract); the unit is `Type=notify` with `WatchdogSec=60s`.
- **JSON line limits.** Lines are capped at 64 KiB, and an overlong line is
  skipped without being buffered. Non-UTF-8 or non-`RobotEvent` lines are
  counted and skipped. A stream does not end on bad data.
- **Socket limits.** Unix-socket connections are capped. The socket is
  created with mode 0600. A socket at the path that still accepts
  connections belongs to a live instance and is refused (never unlinked);
  only a stale one (connection refused) is replaced. At exit the file is
  removed only if it is still the inode this process created.
- **Directory aliasing.** `spool.dir` and `blackbox.dir` may not overlap and
  the profile state file may not live in either, compared after resolving
  symlinks and `..` (at configuration time and again on the created
  directories).
- **Datagrams** go through the pipeline, which never panics and bounds its
  own memory and output.
- **Housekeeping under load.** The main loop handles at most 256 items, and
  never past the next tick, before doing housekeeping.
- **Shutdown.** SIGTERM or SIGINT (handled through `extern "C" signal` and
  an `AtomicBool`) stops the inputs, drains the queue, reports held SEDP
  announcements (`Pipeline::finish`), writes the stop note, seals the black
  box and copies the seal to the spool.

## Tests

| Test | What it shows |
|---|---|
| `tests/e2e.rs` | A synthetic pcap (the pipeline's own builders) yields the rogue participant and rogue `cmd_vel` writer findings in the spool, validated, with a black box that verifies against the final seal and evidence links that resolve. Resume across two runs. Unlocked and invalid profiles never enforce. A truncated pcap raises `input_ended`. The agent's rogue-UGV JSONL scenario runs over a unix socket through profile, firewall and monitor. Queue overflow is counted exactly (`received = processed + dropped`). Fuzzed datagrams and event lines do not stop the daemon. |
| `tests/health.rs` | A silent input reads `unknown` (never `ok`) with an observe-only High finding. Live data turns the state `ok`. Silence again raises a new finding with the same id and a higher count. |
| `tests/binary.rs` | The real binary: exit code 2 on usage and configuration errors, on a 0644 key file and on an unknown key. SIGTERM and SIGINT give exit 0, a sealed black box that verifies with the spool's `checkpoint.json`, and a stop note. |
| `tests/motion_live.rs` | A synthetic pcap with SEDP plus CDR `Twist` on `rt/cmd_vel` (0.4 m/s, then 2.5 m/s against a 1.0 m/s envelope) and CDR `Odometry` on `rt/odom`: three motion events reach the agent, exactly one Critical `robot.motion.linear_over_envelope` finding is spooled, the black box holds the decoded command (with its writer GUID) and a firewall verdict with `enforcing: false`, and verifies. A garbage payload on `rt/cmd_vel` yields one Medium `robot.motion.undecodable_sample` and the next good command still flows. `sensor.motion` keys are strict. |
| `tests/review_regressions.rs` | Fourth-review fixes: no busy loop once every input ended (thread CPU < 25% of wall, state `unknown`); a malformed-only stream is never `ok` (`input_silent` + `input_malformed`); `..` and a late symlink cannot alias spool and black box; a live event socket is not stolen and cleanup checks the inode; the queue's byte budget; `READY`/`WATCHDOG`/`STATUS`/`STOPPING` over a notify socket and stale or other-boot `status.json` read as `unknown`; hostile event lines do not panic. |
| `tests/host_threats.rs` | The host-threat socket, with the test playing `robodr-threat-forward`: a synthetic capture (rogue participant and `cmd_vel` writer) plus a Pulsar shell threat fire `coordinated_intrusion` (Critical, enforce); three host rules from one process fire `host_process_persistence`; the sensor's own threat is not counted twice; junk lines and the forwarder's reported losses are health findings; a host input with no forwarder reads `unknown` and goes silent, and a Pulsar service-stop threat with that silence is the observe-only `defense_tampering`; config and socket-directory checks. |
| `tests/control_plane.rs` | The control-plane API on the real daemon with a test SOC key, over the unix socket and TCP: the robot snapshot; `restrict_motion` accepted and answered `recorded_not_executed` (`executed: false`, ladder step, evidence link), an idempotent resubmission, a GET with a percent-encoded id; a replay, a tampered body, an unknown key, a stale timestamp, a request signed for another robot and one without credentials refused (401); an unknown action, a missing ttl and a motion field refused (400) and recorded; under e-stop (PLC socket feed) `request_safe_state` refused `safety_system_engaged`; revert `not_applied`, an irreversible revert refused; answers signed with the finding key; the observe-only findings; the black box verifies and the recorded SOC signature re-verifies offline. Off by default; strict config. |
| `tests/agent_api.rs` | `Agent::handle_external`: sensor deviations get real plans when enforcing. Self-health and observe-mode deviations never get an action plan. |
| `tests/safety_feed.rs` | The live safety feed: Bool / UInt8 / String / Odometry mappings (with hysteresis, non-finite speed), staleness to `unknown`, conflicts to the most conservative state, unprofiled / IP-spoofed / wrong-type / non-allowlisted writers ignored with a High finding, undecodable and unmapped values read `unknown`. End to end through the daemon: an e-stop on the bus turns the plan for a Critical over-envelope command into Record (`request_safe_state` with the e-stop released); a rogue writer's "release" is reported and ignored; the PLC socket feed grades plans, goes stale to `unknown` (approval-gated plan) and every transition is in the black box. |
| unit tests | Config strictness and key file checks, spool atomicity and bounds, the line reader (CRLF, overlong lines, timeouts, a full queue), the unix socket, the peer-uid policy, the host-threat line parser and socket permission checks, and the health state machine. |

## Limits (honest)

- **Not run on a robot.** All inputs in the tests are synthetic: generated
  pcaps, the agent's demo JSONL. Nothing was exercised with real DDS stacks.
  The live motion path in particular has only decoded hand-built RTPS / CDR
  (no `ros2 topic pub /cmd_vel` capture from a real RMW).
- **Motion decode needs SEDP.** A writer announced before the daemon
  started is unknown until it is re-announced; its commands are not decoded
  meanwhile (samples to a known motion reader raise
  `robot.motion.unattributed_sample`).
- **Live capture and the SPDP socket are untested here.** Live `AF_PACKET`
  capture (needs `CAP_NET_RAW`) and the SPDP multicast socket are wired
  through the pipeline's own openers, but no test here exercises them.
  Throughput at line rate is not measured.
- **Critical evidence is slow to write.** Critical records are fsynced
  (black-box default), so a flood of critical deviations is limited by
  storage latency. Under such a flood the queue drops items (counted and
  reported) instead of growing.
- **Safety state: live feed only on synthetic traffic.** The feed was run
  against hand-built RTPS / CDR and a local socket, not a real RMW, safety
  PLC or e-stop. Its discovery of safety writers is parsed a second time
  (own reassembler and user-DATA walker), because the pipeline's motion
  path keeps only motion / feedback topics. A safety writer announced
  before the daemon started is unknown until it re-announces, so its
  source reads `unknown`. The rest of the operational context (`control`,
  `phase`, `connectivity`, `operator_present`) is still configuration.
  The new rule ids are not in `robodr-ocsf`'s rule catalog yet (generic
  title / description in findings).
- **Host threats: end to end only with a real Pulsar.** The daemon tests
  play the forwarder over the real socket; `robodr-threat-forward`'s own
  tests cover its format, queue and reconnects with a local listener. A
  real rule hit through `robodr-pulsard` needs eBPF on the target kernel.
  There is no process-to-socket attribution, so unit-scoped rules
  (`coordinated_intrusion`, `defense_tampering`) join host and network
  evidence by time window only.
- **Plans are never executed.** The agent's executor is `NoopExecutor`.
  Dispositions are recorded and reported only. Control-plane requests are
  judged and recorded the same way (`recorded_not_executed`); there is no
  executor that reaches the robot.
- **Control plane: no TLS, no persistence.** Requests are signed and
  replay-protected but travel in clear text unless a TLS terminator sits in
  front; answers are signed only with `finding_signing`. Request states live
  in memory (bounded) and are forgotten at restart (the black box keeps
  every decision). The replay window needs NTP on robot and SOC. Tested
  with synthetic traffic and AutoSecOps' client in-process, not against a
  deployed SOC.
- **No exporter is included.** The rename-to-`acked/` acknowledgement is the
  whole contract, and it has not been run against a real Kafka producer.
- **The key is a file, not a TPM.** The Ed25519 seed sits in a 0600 file
  (handed over by systemd `LoadCredential=`); root on the unit can read it
  and sign as the unit. The Ed25519 implementation is the audited
  `ed25519-dalek` crate (RFC 8032 vectors pinned). HMAC keys still load (warned: the
  verifier can forge). Wall time is recorded with `TimeSource::Unknown`.
- **A dead daemon reports nothing.** If the process dies, nothing inside it
  can report that. A console must treat a missing or stale `status.json` or
  heartbeat as `unknown`. The systemd watchdog restarts a hung loop; the
  watchdog itself is untested under real systemd here (the protocol is
  tested against a local datagram socket).
- **Stdin can block shutdown's join.** The stdin reader blocks in `read` and
  is not joined at shutdown. Socket and capture readers poll with timeouts
  (at most about 0.5 s).
- **Socket permissions race.** There is a short window between `bind` and
  `chmod 0600` of the event socket, so put the socket in a private
  directory.
- **Pipeline findings share a subject.** The finding subject of a pipeline
  finding is its source IP (the pipeline's `Finding` carries no structured
  GUID), so the finding id groups by (rule, source IP). Occurrence counts
  restart with the process.
- **The `sensor` key list is duplicated.** The list in `config.rs`
  (`SENSOR_KEYS`) mirrors `robodr_ros2_pipeline::Config`'s fields and must
  be kept in sync with it. That config only ignores unknown keys, because it
  is shared with Pulsar.
