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
 JSONL unix socket ┘ Event ┘  and counted            │     (profile + Motion Firewall + motion monitor)
                                                     │   Outcome ─► black box (signed, hash-chained)
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

There is one JSON file. See `examples/agentd.example.json` and
`src/config.rs`. Unknown keys are refused at every level, and every path
must be absolute.

| Key | Meaning |
|---|---|
| `robot` | `id` (also the black-box device id), `site`, optional `model`, `kafka_partitions` (`profile_version` was removed: the version in findings is the signed profile's `metadata.profile_version`) |
| `sensor` | The ROS 2 sensor's own `[module.robodr-sensor-ros2]` section in JSON form, validated by `robodr_ros2_pipeline::Config::validate`. It sets the profile path, capture (live interfaces or `pcap_replay`), the SPDP socket (`listen_spdp`, default **true**) and the binding settings. Its profile is used by the pipeline and by the agent. |
| `policy_path` | Response policy (`robodr.response-policy/v1`) |
| `blackbox` | `dir`, `key_file`, optional `key_id`, optional `boot_id` (default `/proc/sys/kernel/random/boot_id`) |
| `spool` | `dir`, `max_bytes` (default 64 MiB), `max_files` (default 10000) |
| `event_inputs` | `[{"kind":"stdin"}]` and/or `[{"kind":"unix_socket","path":...,"max_connections":4}]` |
| `context` | `safety_state` (default `unknown`), `control`, `phase`, `connectivity`, `operator_present` |
| `firewall` | Optional. `max_angular` (rad/s for every profiled Twist channel) and `allow` (writer GUIDs per channel). Runs **recording-only** (see below). |
| `motion_monitor` | Optional. `config_path` (strict `MonitorConfig`; default: the UGV defaults on the profile's motion channels) and `feedback_sources`. Feedback sources that are ROS topic names (`/odom`) are also decoded from the bus. |
| `sensor.motion` | Optional. The live motion decode path: `enabled` (default true), `feedback_topics` (e.g. `["/odom"]`), `max_writers`, `max_samples_per_datagram` (`evaluate_commands` is accepted but the daemon always lets the agent evaluate). Unknown keys are refused. |
| `daemon` | `queue_capacity` 4096, `tick_ms` 1000, `heartbeat_ms` 10000, `silence_ms` 30000, `lag_ms` 2000, `health_report_ms` 10000, `exit_when_inputs_end` false |

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
  - `status.json` is rewritten every tick. `checkpoint.json` is the final
    black-box seal, written at shutdown so the exporter can take it
    off-unit.

## Self-health ("never OK when blind")

The robot's state in `status.json` and in the heartbeat is one of three
values:

- `ok`: every input delivered data within `silence_ms`, nothing was dropped,
  no lag, and the profile is enforced.
- `degraded`: queue drops, a profile that is not enforced, spool trouble, or
  black-box trouble.
- `unknown`: an input is silent, ended, or has sent **no data yet**, or the
  pipeline lags.

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

- **Bounded memory.** The queue holds at most `queue_capacity` items. When
  it is full, the item is dropped and counted; a capture thread is never
  blocked.
- **JSON line limits.** Lines are capped at 64 KiB, and an overlong line is
  skipped without being buffered. Non-UTF-8 or non-`RobotEvent` lines are
  counted and skipped. A stream does not end on bad data.
- **Socket limits.** Unix-socket connections are capped. The socket is
  created with mode 0600.
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
| `tests/agent_api.rs` | `Agent::handle_external`: sensor deviations get real plans when enforcing. Self-health and observe-mode deviations never get an action plan. |
| unit tests | Config strictness and key file checks, spool atomicity and bounds, the line reader (CRLF, overlong lines, timeouts, a full queue), the unix socket, and the health state machine. |

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
- **Safety state is static.** It is configuration; there is no live feed
  from the platform yet, so plans use the configured value (default
  `unknown`).
- **Plans are never executed.** The agent's executor is `NoopExecutor`.
  Dispositions are recorded and reported only.
- **No exporter is included.** The rename-to-`acked/` acknowledgement is the
  whole contract, and it has not been run against a real Kafka producer.
- **The key is a file, not a TPM.** The Ed25519 seed sits in a 0600 file
  (handed over by systemd `LoadCredential=`); root on the unit can read it
  and sign as the unit. The Ed25519 implementation is RoboDR's own std-only
  one (RFC 8032 vectors, not audited). HMAC keys still load (warned: the
  verifier can forge). Wall time is recorded with `TimeSource::Unknown`.
- **A dead daemon reports nothing.** If the process dies, nothing inside it
  can report that. A console must treat a missing or stale `status.json` or
  heartbeat as `unknown`. There is no systemd watchdog integration yet.
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
