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
| `robot` | `id` (also the black-box device id), `site`, optional `model`, `kafka_partitions` (`profile_version` was removed: the version in findings is the signed profile's `metadata.profile_version`), optional `robot_model` (a Unitree model, see "Unitree" below) |
| `sensor` | The ROS 2 sensor's own `[module.robodr-sensor-ros2]` section in JSON form, validated by `robodr_ros2_pipeline::Config::validate`. It sets the profile path, capture (live interfaces or `pcap_replay`), the SPDP socket (`listen_spdp`, default **true**) and the binding settings. Its profile is used by the pipeline and by the agent. |
| `policy_path` | Response policy (`robodr.response-policy/v1`; its `morphology` — required once OEM-validated or for platform `other`, e.g. `humanoid` — makes safe pause / safe state advisory only and sets the balancing-robot rules, see `robodr-responder`) |
| `blackbox` | `dir`, `key_file`, optional `key_id`, optional `boot_id` (default `/proc/sys/kernel/random/boot_id`) |
| `spool` | `dir`, `max_bytes` (default 64 MiB), `max_files` (default 10000) |
| `findings` | Optional. `topic` (default `robodr.findings`) and `data_source` (default `robodr`): the deployment labels every finding carries (`robodr.findings` contract 2.x) |
| `event_inputs` | `[{"kind":"stdin"}]` and/or `[{"kind":"unix_socket","path":...,"max_connections":4}]` |
| `context` | `safety_state` (default `unknown`; must stay `unknown` when `safety_feed` is set), `control`, `phase`, `connectivity`, `operator_present` |
| `safety_feed` | Optional. The live safety-state feed (see below): `stale_after_ms` (default 1000), `topics` (ROS topics decoded from the captured bus) and/or `socket` (a local safety-PLC gateway socket). |
| `firewall` | Optional. `max_angular` (rad/s for every profiled Twist channel), `allow` (writer GUIDs per channel) and `joint_config` (a Motion Firewall JSON file whose `joint_channels` / `platform` check Unitree low-level joint frames, e.g. `config/firewall.unitree-g1.example.json`). Runs **recording-only** (see below). |
| `motion_monitor` | Optional. `config_path` (strict `MonitorConfig`; default: the UGV defaults on the profile's motion channels) and `feedback_sources`. Feedback sources that are ROS topic names (`/odom`) are also decoded from the bus. |
| `sensor.motion` | Optional. The live motion decode path: `enabled` (default true), `feedback_topics` (e.g. `["/odom"]`), `max_writers`, `max_samples_per_datagram` (`evaluate_commands` is accepted but the daemon always lets the agent evaluate). Unknown keys are refused. |
| `sensor.unitree_legacy` | Optional, off by default. Unitree legacy UDP (Go1 generation): `enabled`, `ports` (default `[8007, 8080, 8082, 8090]`), `command_senders` (IPs allowed to send `HighCmd` / `LowCmd`, or tables `{"ip", "mac"?, "label"?}`; `mac` binds the sender to its link-layer source), `robot_addresses` (default `192.168.123.10`, `192.168.123.161`). Needs `sensor.capture`. Unknown keys are refused. |
| `host_threats` | Optional. `socket_path` (the socket `robodr-threat-forward` writes Pulsar threats to), `socket_mode` (`"0600"` default or `"0660"`), `allowed_uids` (peers besides uid 0), `max_connections` (default 2, max 8). See "Host threats" below. |
| `control_plane` | Optional, off when absent. The SOC API `robodr-control-plane/v2`: `listen_tcp` (with `tls` any address, mutual TLS; without, loopback only), `tls` (`cert_chain`, `key_file`, `client_ca`, optional `client_spki_sha256` pins), `unix_socket` (`socket_mode` `"0600"`/`"0660"`), `state_dir` (required, private 0700: request journal, replay store, exports), `soc_keys` (Ed25519 public key files), `max_clock_skew_s` 30, `rate_per_minute` 30, `burst` 10, `max_connections` 4, `max_requests` 1024, `answer_timeout_ms` 5000, `evidence` (optional; evidence API, see below). Needs `finding_signing` (answers are signed). Requests are judged and recorded, **never executed**. See "Control plane" below. |
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

## Unitree

Unitree SDK2 robots (Go2, Go2-W, B2, B2-W, A2, AS2, H1, H1-2, H2, G1, R1)
speak plain DDS on topics `rt/lowcmd`, `rt/arm_sdk`, `rt/api/<svc>/request`,
...; the pipeline learns their writers from SEDP (type names
`unitree_go::msg::dds_::LowCmd_`, `unitree_hg::...`, `unitree_api::...`),
de-mangles the topics like ROS topics (`/lowcmd`, `/api/sport/request`,
`/dex3/left/cmd`) and decodes them with `robodr-cdr`. On top of the generic
path:

- **Joint firewall.** With `firewall.joint_config`, every decoded low-level
  frame on one of the file's `joint_channels` goes to the agent with its
  command (`Agent::handle_with_joint`): `Firewall::check_joint` on every
  slot (CRC verdict, `mode_pr` / `mode_machine`, any non-zero mode octet is
  enabled), stamped with the **capture time** of its datagram so the rate
  and gap checks see the real inter-arrival times. The verdict is recorded
  as `robodr.firewall_joint_verdict` (`"enforcing": false`) and its events
  become findings like every firewall deviation. Recording-only: there is
  no in-path gateway yet (a later sprint). The file is compiled **as
  written** at `--check-config` (a humanoid with a damping / fail-open
  substitute is refused, so the same file is safe for the gateway), its
  `channels` must be empty (twist channels come from the profile and
  `max_angular` / `allow`), each joint channel must be a profiled motion
  channel, and its platform morphology must match the response policy.
  `status.json` carries `daemon.joint_frames` and the agent's
  `joint_firewall_checks`, `joint_frames_missing`, `joint_clock_clamped`.
- **Model awareness.** `robot.robot_model` (`Go2`, `G1`, `H1-2`, ...; case
  and `-` / `_` ignored) makes the pipeline interpret Unitree API requests
  with the model's tables (a model-specific id such as G1
  `SetStandHeight` is classified instead of `Unknown`, High) and is
  checked against the configuration: a humanoid model (G1, H1, H1-2, H2,
  R1) with a response policy or joint-firewall morphology other than
  `humanoid` is a configuration error (a de-energising response makes it
  fall); a legged quadruped with anything but `quadruped` (or the more
  conservative `humanoid`, warned) too; a joint channel `/lowcmd`,
  `/arm_sdk` or `/user_lowcmd` whose slot count differs from the model's
  IDL (go 20, hg 35) is an error; legacy UDP on a DDS model (or the
  reverse) is a warning. **Without** a model the morphology does not fail
  open: a 35-slot (`unitree_hg`) joint channel needs a `humanoid` firewall
  platform and a `humanoid` (or unspecified) policy, since every
  `unitree_hg` robot is a humanoid; and a profile with `/lowcmd`,
  `/arm_sdk`, `/user_lowcmd` or `/api/*` channels but no model is a
  warning (`--check-config` and the start log). Any joint channel whose
  profile-recorded type (`motion_types`, written by `robodr-commission
  learn`) is a Unitree `LowCmd_` must have that layout's slot count,
  whatever its name. A legacy channel (`/unitree_legacy/...`) is refused as
  a `joint_config` channel: legacy frames carry no writer identity the
  firewall could authorise, so every frame would be an unknown-source
  rejection before its joints were checked (the sensor checks the sender
  and the profile envelope checks the joints of every decodable frame).
  With a `firewall` section, a twist / joint-velocity channel whose kind
  neither the profile's recorded type nor its envelope tells (learned
  `max_linear_speed: 0` plus a `max_joint_speed`) is refused.
- **Legacy UDP (Go1).** With `sensor.unitree_legacy.enabled`, the capture
  (kernel BPF included) also accepts UDP on the legacy ports; the pipeline
  decodes `HighCmd` / `LowCmd` / `HighState` / `LowState` by length and maps
  them onto `/unitree_legacy/high_cmd`, `low_cmd`, `high_state`,
  `low_state` (commands to the agent, feedback when listed in
  `feedback_topics`). A command from an IP not in `command_senders` is
  `robot.unitree.legacy_unknown_sender` (Critical; Medium for state from an
  address not in `robot_addresses`) — also for a compressed v3.8.6
  `LowCmd`, which is additionally `robot.motion.undecodable_sample`. More
  than 16 unlisted senders of a class are aggregated
  (`robot.unitree.legacy_sender_flood`); a MAC-bound sender seen with
  another MAC is `robot.unitree.legacy_sender_mac_mismatch` (High); RTPS on
  a legacy port is inspected on both paths
  (`robot.unitree.legacy_port_rtps`, High). Legacy ports inside the DDS
  domain's RTPS port range are refused. A profile is learned from a legacy
  capture with `robodr-commission learn --pcap ... --unitree-legacy`.
- **Examples.** `config/profile.unitree-<model>.example.json` (one per
  model the decoders support; illustrative envelopes, the model label says
  `EXAMPLE-replace-with-OEM-data`; A1 / Aliengo / B1 have no decodable
  frame layout and no example), `config/agentd.unitree-sensor-box.example.json`
  (passive capture on a mirror / tap port, no control plane, legacy UDP
  for a Go1) and `config/agentd.unitree-edu.example.json` (on the EDU dev
  computer of a G1, with the joint firewall).

Not verified on a real Unitree robot: everything above has only seen
synthetic traffic built from the published IDL / `comm.h` layouts and the
independent reviewer vectors of `robodr-cdr`.

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
  it from its own pipeline. A response-policy `rule_overrides` entry is
  matched on the finding's rule id, so it can only target
  `robot.host.pulsar_threat` as a whole, never one Pulsar rule (the
  shipped policy examples therefore no longer carry the former
  `robot.host.unexpected_egress` override, which nothing emits).
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

## Control plane (SOC action requests and evidence)

With `control_plane` (contract `docs/contracts/robodr.control-plane.md`,
`robodr-control-plane/v2`) a SOC may *request* one of the seven actions of
the responder's catalog (`robodr_responder::actions`: `restrict_motion`,
`quarantine_node`, `isolate_network`, `record_evidence`, `safe_pause`,
`request_safe_state`, `rollback_config`) and export black-box evidence, over
a small, bounded, fuzzed HTTP/1.1 layer (`src/control/`). The answer is
truthful about what happens: **nothing is executed.** The only executor is
the recording one, so an accepted request is `recorded_not_executed`
(`"executed": false`), "accepted and recorded as a plan".

```json
"control_plane": {
  "listen_tcp": "10.0.7.7:8787",
  "tls": {
    "cert_chain": "/etc/robodr/control-plane/robot.pem",
    "key_file": "/run/credentials/robodr-agentd.service/cp-tls.key",
    "client_ca": "/etc/robodr/control-plane/soc-ca.pem",
    "client_spki_sha256": ["<64 hex>"]
  },
  "unix_socket": "/run/robodr-agentd/control.sock",
  "state_dir": "/var/lib/robodr/control-plane/agentd",
  "soc_keys": ["/etc/robodr/soc/soc.pub"],
  "evidence": {}
}
```

- **Transport (`src/control/tls.rs`).** A TCP listener with `tls` is mutual
  TLS (rustls + ring, the uplink's crates): the SOC's client certificate
  must chain to `client_ca`, be valid and permit `clientAuth`, and — with
  pins — have a pinned SPKI; no session resumption. Without `tls`,
  `listen_tcp` must be loopback (plain HTTP, tests / a local relay); the
  unix socket is plain too. `allow_remote` (v1) is gone and refused with a
  pointer to `tls`. A failed handshake is a failed authentication.
- **Authentication (`auth.rs`).** On every listener, each request is also
  signed with a configured SOC Ed25519 key over method, exact target, this
  robot's id, key id, timestamp, nonce and body hash (domain
  `robodr-control-plane/v2`); ±`max_clock_skew_s` and a **persisted** nonce
  store stop replays, also across restarts (full / unwritable: refused,
  never unchecked; untrusted at start: fenced); per-key token bucket. Every
  answer to an authenticated request is signed with the finding key, bound
  to the request signature (mandatory: `finding_signing` is required).
- **Allow-list.** The seven catalog actions, each with its own parameters (speed caps in
  (0, 10], a zone, a GUID or node name, a profile/program rollback); the
  time-limited classes need `ttl_seconds` 1..=86400, the others refuse one;
  no motion command, force or override field exists and `authority` must be
  `request`. Unknown or duplicate keys refuse the body.
- **Judgment.** Against the safety state *now* (live feed re-evaluated),
  the operational context and the response policy. `record_evidence`
  (capture only, nothing sent to the platform) is accepted in every state,
  observe mode included. Everything else is refused while the e-stop /
  safe state is active (also `request_safe_state`: the safety system has
  authority), in observe mode, when the context's morphology differs from
  the policy's (`morphology_mismatch`), for motion-affecting steps while a
  person commands motion or during take-off / landing; `fall_hazard` for
  `safe_pause` / `request_safe_state` on a humanoid and for
  `rollback_config` (a controller restart) on a humanoid or quadruped —
  also while `idle`, since a legged robot balances while idle — and for a
  `restrict_motion` cap below the policy's `min_motion_factor` of the
  envelope (or with no envelope to judge it) on a humanoid / quadruped;
  `rollback_config` unless `idle`; anything above the policy matrix's
  ceiling for the state; a speed cap above the profile envelope; and any
  plan that fails `check_invariants`. A refusal is final. The robot
  snapshot lists the robot's `morphology` and only the actions not refused
  for it.
- **Evidence.** Request (with its signature and exact body: it re-verifies
  offline), state, context and decision are one fsynced
  `robodr.control_plane_request` note; reverts, authenticated invalid
  requests, evidence exports and every start (`robodr.control_plane_start`)
  are notes too. No black box, no claim: the answer is then `failed` and
  nothing is stored.
- **Persistent state (`journal.rs`, `state.rs`).** `state_dir` (0700, the
  daemon's) holds a checksummed append-only request journal: `begin`
  (fsync) before the black-box note, `commit` (fsync) after it, `abort` if
  the black box refused; a decision a crash left dangling is settled at the
  next start from the black box (a note with its `decision_id` → commit,
  none → abort). Compaction writes a temp file, fsyncs, renames, fsyncs the
  directory; a torn last line is cut, damage in the middle is quarantined.
  A status query after a restart answers as before it.
- **Evidence API (`evidence.rs`, `control_plane.evidence`).** Inventory of
  the retained records; exports of a finding's evidence links (plus
  context), a seq range or a time range as an `RBBXBND1` bundle of the
  frames exactly as stored, with a manifest (selection, chain identity and
  signing key, record range, anchor, chunk hashes) signed with the finding
  key; signed, resumable chunks (16 KiB..4 MiB); limits on size, count,
  storage and age; one export at a time. The SOC verifies with the robot's
  public keys (`robodr-blackbox verify bundle.rbbx`).
- **Abuse.** Bounded parsing (8 KiB head, 16 KiB body, 5 s for the TLS
  handshake and 5 s for the request, 30 s for the answer), at most
  `max_connections`, a bounded queue to the main loop (full: 503). Failed
  authentications raise `robot.agent.control_plane_unauthenticated` (High),
  authenticated invalid requests `robot.agent.control_plane_invalid`
  (Medium); both observe-only self-health, rate-limited by
  `health_report_ms`. The API is not an input: a quiet SOC never makes the
  state `unknown`.
- **Sockets.** Every unix socket of the daemon (events, safety feed, host
  threats, control plane) is bound inside a fresh 0700 directory, given its
  final mode there and hard-linked into place: there is no window in which
  it is connectable with the umask's permissions.
- **Unit.** The shipped unit has `IPAddressDeny=any`; the drop-in example
  `30-control-plane.conf.example` allows the SOC network, makes `state_dir`
  writable and hands over the TLS key as a credential.
- **Status.** `status.json` and heartbeats carry `control_plane` (listeners,
  executor, counters incl. `tls_failures`, `last_auth_failure`, TLS
  identity, replay store, persistent state, evidence).

## Outputs

- **Black box** (`blackbox.dir`). It holds every deviation, plan note,
  firewall verdict and triggering event, as the agent records them. It also
  holds `robodr.agentd_start`, `robodr.agentd_heartbeat` (every
  `heartbeat_ms`: state, reasons, per-input counters, pipeline, agent and
  spool counters), `robodr.agentd_recovery` and a final `robodr.agentd_stop`
  note. A restart resumes the chain; the recorder signs a `Resume` record.
- **Spool** (`spool.dir`):
  - `ready/<seq:020>.json` holds one validated findings record
    (`robodr.findings` 2.x) per file: `{schema, seq, topic, key, partition,
    headers, value}` (`topic` = `findings.topic`). `value`
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
| `tests/control_plane.rs` | The control-plane API v2 on the real daemon with a test SOC key, over the unix socket, loopback TCP and mutual TLS (OpenSSL test PKI in `tests/data/control-tls/`, `gen.sh`): the robot snapshot; `restrict_motion` accepted and answered `recorded_not_executed` (`executed: false`, ladder step, evidence link), an idempotent resubmission, a GET with a percent-encoded id; a replay, a tampered body, an unknown key, a stale timestamp, a request signed for another robot, a v1-domain signature and one without credentials refused (401); an unknown action, a missing ttl and a motion field refused (400) and recorded; under e-stop (PLC socket feed) `request_safe_state` refused `safety_system_engaged`; revert `not_applied`, an irreversible revert refused; every answer signed with the finding key; mTLS: the SOC certificate + signature accepted, a valid certificate without or with a bad signature refused (401), no client certificate / another CA / an unpinned key / an expired certificate / plain HTTP get no channel (each with its reason in `last_auth_failure`), counted and reported; without pins any certificate of the CA (still not an expired one); restart: the same answer to a status query, the earlier request's replay refused, a resubmission a duplicate, a removed replay store fences; evidence: inventory, an export of a decision's evidence link, the manifest signature, a chunked download resumed after a "disconnect", the bundle verified with the black-box public key file only, tamper detected, no key material in it, idempotency / conflict / limit / out-of-range / invalid body, delete, the export surviving a restart and its black-box note; the observe-only findings; the black box verifies and the recorded SOC signature re-verifies offline. Off by default; strict config (TLS key permissions, wrong key for the certificate, pins, `allow_remote`, `finding_signing` required, state directory mode). |
| `tests/control_plane_vectors.rs` | The contract vectors `docs/contracts/fixtures/control-plane-v2/` are byte-identical to the generator (`examples/control_plane_vectors.rs`) and hold against the implementation: requests authenticate (or are refused 401) and route as stated, answer and manifest signatures verify, chunks reassemble to the bundle, the bundle verifies with the black-box public key and the tampered copy does not. |
| `tests/fuzz_smoke.rs` | The `control_plane_request` libFuzzer harness (`fuzz/harness/control_plane_request.rs`) driven by the std-only mutator over generated, signed seeds of every route (the seeds take the success path; the corpus equals the generator). |
| `tests/unitree_live.rs` | Unitree end to end on synthetic captures, the profile **learned** with `robodr-commission` from a clean capture and locked: Go2 (`unitree_go`, 12 of 20 slots), G1 (`unitree_hg`, 29 of 35, arm SDK), H1 (`unitree_go`, 20 slots, arm SDK) and Go1 (legacy UDP). Clean replay: no finding, every joint frame checked by the joint firewall. Rogue `rt/lowcmd` writer (unknown participant, unauthorized motion writer, `rejected_unknown_source`); torque / kp / step over the envelope (profile + joint firewall would-haves); `rt/arm_sdk` frames with mode 0 counted as motion; `2^32 + id` api aliasing (High); velocity over the envelope (Critical); a model-specific api id `Unknown` without `robot_model`, classified with it; humanoids never record a zero / damping substitute and a limp frame is a would-have rejection; the independent `robodr-cdr` vectors decode with `crc_ok` true; Go1: unknown sender (Critical / Medium), trick mode, joint torque, compressed frame, legacy off = nothing captured. |
| `tests/unitree_examples.rs` | Every Unitree example: a strict, valid profile per supported model with its topics and joint bounds; the firewall examples fit their profiles; the EDU and sensor-box daemon examples pass `--check-config`; morphology / slot-count / unknown-model / unsafe-substitute / `max_angular`-on-a-joint-channel refusals; every model's profile loads in the daemon with its `robot_model`. |
| `tests/agent_api.rs` | `Agent::handle_external`: sensor deviations get real plans when enforcing. Self-health and observe-mode deviations never get an action plan. |
| `tests/safety_feed.rs` | The live safety feed: Bool / UInt8 / String / Odometry mappings (with hysteresis, non-finite speed), staleness to `unknown`, conflicts to the most conservative state, unprofiled / IP-spoofed / wrong-type / non-allowlisted writers ignored with a High finding, undecodable and unmapped values read `unknown`. End to end through the daemon: an e-stop on the bus turns the plan for a Critical over-envelope command into Record (`request_safe_state` with the e-stop released); a rogue writer's "release" is reported and ignored; the PLC socket feed grades plans, goes stale to `unknown` (approval-gated plan) and every transition is in the black box. |
| unit tests | Config strictness and key file checks, spool atomicity and bounds, the line reader (CRLF, overlong lines, timeouts, a full queue), the unix socket, the peer-uid policy, the host-threat line parser and socket permission checks, and the health state machine. Control plane: the journal's crash points (killed during an append, between write and fsync, before the compaction's fsync / rename / directory fsync), damage quarantine, rollback of a survived failed append; the request state across restarts and the crash points around the black-box note (commit or abort from the black box, also for reverts), a journal that refuses fails closed, compaction bounds; the persisted replay store (replay after a restart, expiry, fence on damage or removal, a failing store refuses); evidence exports from a real recorder (multi-segment, rotation, time / finding selectors, gaps, limits, chunk reassembly, tamper, stored-export corruption and expiry); the HTTP head bound independent of read sizes and the answer write deadline. |

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
- **Control plane: tested locally only.** mTLS, signatures, the journal
  and the evidence API were exercised with an in-process client and an
  OpenSSL test PKI over loopback, not against a deployed SOC or across a
  real network. TLS material is read at start (rotation = restart); there
  is no CRL / OCSP for SOC certificates. The journal is checksummed, not
  signed (the black box is the signed record). The replay window needs NTP
  on robot and SOC. The `control_plane_request` fuzz target has run under
  the std-only smoke driver (about 90 000 inputs), not under libFuzzer.
- **Exporters live in `robodr-export`, not here.** The spool's only
  contract is the rename-to-`acked/` acknowledgement. `robodr-spool-export`
  (spool → diode batches) and `robodr-kafka-publish` (spool or diode output
  → Kafka) implement it and are tested against an in-process fake broker
  and real single-node Apache Kafka 3.9.1 / 4.1.0 (`scripts/kafka-it.sh`);
  not against a production cluster, and without TLS/SASL.
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
- **Pipeline findings share a subject.** The finding subject of a pipeline
  finding is its source IP (the pipeline's `Finding` carries no structured
  GUID), so the finding id groups by (rule, source IP). Occurrence counts
  restart with the process.
- **The `sensor` key list is duplicated.** The list in `config.rs`
  (`SENSOR_KEYS`) mirrors `robodr_ros2_pipeline::Config`'s fields and must
  be kept in sync with it. That config only ignores unknown keys, because it
  is shared with Pulsar.
