# robodr-commission

Observe-mode commissioning for RoboDR (Sprint 3). The robot does a **clean run**
while RoboDR only watches. This tool turns what it saw into a draft model profile
(`profile.json`, `locked: false`) and a commissioning report. The OEM reviews
the draft, locks it, and then proves that a clean re-run gives **zero deviations**.

The tool only reads recordings and writes files. It never talks to the robot or
changes how it behaves.

## Pipeline

```
events (JSONL) / capture (pcap, pcapng) ──► Learner ──► profile.json (locked:false) + report
                                              │ OEM review (report, diff)
                                              ▼
                                         lock ──► locked.json
                                              │
                    events of a re-run ──► check ──► deviations (exit 1) / none (exit 0)
```

## What is learned

Endpoint names are de-mangled with `Endpoint::ros_name()` and routed by kind,
exactly the way `Profile::evaluate` checks them. So learn → lock → check over
the same clean run gives zero deviations. `tests/roundtrip.rs` checks this on
400 random clean runs.

| Profile field       | Learned from                                                                                   |
|---------------------|------------------------------------------------------------------------------------------------|
| `participants`      | GUID prefixes from `ros2_participant_discovered` (SPDP) events                                  |
| `writer_topics`     | writers on ROS topics `rt/x` → `/x`, including `rt/rosout` and `rt/parameter_events`            |
| `services`          | writers on `rq/xRequest` (clients) and `rr/xReply` (servers) → `/x`, e.g. `/nav/get_parameters`  |
| `actions`           | writers on any of the five parts of an action (`rq/a/_action/send_goalRequest`, `rt/a/_action/status`, ...) → `/a` |
| `raw_dds_topics`    | writers on non-ROS DDS names, kept exactly (e.g. `ros_discovery_info`, vendor tools)            |
| `reader_topics`     | **opt-in** (`--learn-readers`): readers on ROS topics                                           |
| `motion_envelopes`  | for each `motion_command` channel and dimension: `min(max_observed × margin, OEM ceiling)`      |

* **Services, actions and raw topics come from writers.** Both sides of a
  service or action write something: clients write requests, and servers write
  replies, feedback and status. A complete capture therefore covers all of
  them. A service or action seen *only* on readers means the capture is
  incomplete. It is reported as `reader_only_name` and is not learned.
* **Parameter services.** Every ROS 2 node serves six parameter services
  (`/node/get_parameters`, `describe_parameters`, `get_parameter_types`,
  `list_parameters`, `set_parameters`, `set_parameters_atomically`). If they
  are missing from the profile, every node is flagged. The report warns
  `missing_parameter_services` when a participant writes `/rosout` (that is,
  it hosts a ROS node) but serves none of them. It warns
  `incomplete_parameter_services` when a node serves only some of the six.
* **ROS 2 internals.** `rt/rosout` and `rt/parameter_events` de-mangle to
  ordinary topics. `ros_discovery_info` has no ROS prefix, so it is a raw DDS
  topic. It is learned into `raw_dds_topics` and marked `(ROS 2 internal)` in
  the report. Every other raw name gets an info `raw_dds_topic` so that a
  human confirms it belongs.
* **Readers are opt-in (`--learn-readers`, off by default).** The sensor
  enforces `reader_topics` only when it is non-empty, so learning it turns on
  a new class of deviations. That is a policy decision for the OEM, and the
  tool should not make it as a side effect. Readers are also the noisiest part
  of a ROS 2 graph: rosbag, rqt and `ros2 topic echo` subscribe to anything,
  and subscribers that exist only at launch are easy for a capture to miss.
  Each missed subscriber would then deviate on every boot. The report always
  lists the reader topics and says how many were not learned
  (`reader_topics_not_learned`). With `--learn-readers`, reader topics go to
  `reader_topics`, and services, actions and raw names that appear only on
  the reader side are added to their sets too, because the reader check uses
  those sets as well.

* **Margin** defaults to `1.10` and must be in `[1.0, 10.0]`. A margin below 1
  would make the clean run deviate from its own profile.
* **Ceiling** (`--ceiling-linear`, `--ceiling-joint`) is the OEM's hard limit.
  An envelope is never above it. If the observed max is already above the
  ceiling, the report warns `observed_exceeds_ceiling`, because the clean run
  itself would then deviate.
* The bound is rounded **up** to 1e-6, so `0.5 × 1.1` is stored as `0.55`
  rather than `0.5500000000000001`. A bound is never below the observed max.
* GUIDs that appear only on endpoints or motion commands, and were never
  announced as participants, are **not** added to the profile. They are
  reported as `unannounced_participant` instead.
* If a motion channel has no valid sample in either dimension, it gets an empty
  envelope. `lock` refuses that, so a human has to set the bound.

### Anomalies (a clean run should have none)

These values are counted, listed in the report and never used to build an
envelope:

* non-finite (NaN/inf) speeds or negative speeds
* empty topic or channel names
* ROS names that `Profile::validate` would reject (whitespace or control
  characters): `invalid_ros_name`
* GUID prefixes that are not 24 lower-case hex chars (profile matching is exact)

### Report

`--report report.json` writes the full report. A human-readable version is
always printed to stdout. The report contains:

* runs, and event counts per kind
* for each participant: announcement count, first and last seen, source IPs, and the topics it writes and reads
* for each writer and reader topic: count, first and last seen, participants, and type names
* **services and actions**: clients, servers, the action parts seen, and whether each one is in the profile
* **raw DDS topics**: writers, readers, and whether ROS 2 created the topic itself
* for pcap runs, capture diagnostics: frames, RTPS datagrams, IP reassembly, and discovery DATA_FRAG reassembly (rebuilt, rejected, evicted, incomplete)
* for each motion channel: command count, sources, `min/p50/p99/max` per dimension (nearest-rank, so every value was actually observed), the resulting envelope, and whether a ceiling capped it
* anomalies: the first 1000 are stored, and all of them are counted
* warnings at level `warn` (resolve or accept these before locking) or `info`:
  `few_motion_samples` (< `--min-samples`, default 30: envelope not trustworthy),
  `participant_seen_once` (transient? tool?), `writer_without_reader`,
  `unannounced_participant`, `motion_channel_without_writer`,
  `motion_channel_without_envelope`, `observed_exceeds_ceiling`,
  `margin_capped_by_ceiling`, `zero_envelope`, `mangled_motion_channel`,
  `topic_type_conflict`, `anomalies_present`, `default_model_name`, `no_events`,
  `missing_parameter_services`, `incomplete_parameter_services`,
  `reader_only_name`, `raw_dds_topic`, `reader_topics_not_learned`, and, for
  captures, `fragmented_discovery_unreassembled` (DATA_FRAG seen but not all
  rebuilt, so endpoints are missing), `fragmented_discovery_reassembled`,
  `ip_reassembly_failed`, `truncated_frames` and `protected_discovery`.

`RobotEvent` has no timestamps. "First and last seen" are therefore positions,
written as `runN:POS`. POS is the line number for JSONL and the frame ordinal
for a capture.

### Determinism

All state is held in `BTreeMap` and `BTreeSet`. Floats are sorted with
`total_cmp`. No clocks, hashing or randomness are involved. Running `learn`
twice over the same input gives byte-identical `profile.json` and `report.json`,
and a test checks this. The profile depends only on sets and maxima, so event
order and merge order do not change it.

## CLI

```
robodr-commission learn (--events run.jsonl | --pcap run.pcapng) [...] [--model NAME]
                        [--margin 1.1] [--min-samples 30]
                        [--ceiling-linear M_PER_S] [--ceiling-joint RAD_PER_S]
                        [--learn-readers]
                        --out profile.json [--report report.json] [--quiet]
robodr-commission lock  --in profile.json --out locked.json
robodr-commission diff  old.json new.json [--json]
robodr-commission check --profile locked.json (--events run.jsonl | --pcap run.pcap) [...] [--json]
robodr-commission merge --out merged.json a.json b.json [...]
```

Exit codes:

* `0`: ok, clean, or identical
* `1`: a negative result (deviations found, profiles differ, or lock refused)
* `2`: a usage, input or I/O error

Profiles and reports are written to a temp file and then renamed, so a failed
run never leaves half a file.

* **Input**: JSON Lines of `RobotEvent` in the serde tagged format, for example
  `{"kind":"motion_command","channel":"/cmd_vel","source_guid":"…","linear_speed":0.4,"joint_speed":null}`.
  Blank lines and `#` comment lines are skipped, which is an extension to plain
  JSONL. Reading is strict: the first malformed line aborts with `file:line`.
  Lines are capped at 1 MiB.
* **`--pcap`**: a classic pcap or pcapng capture of the robot bus. The format
  is detected from the file, and links can be Ethernet (with VLAN), Linux
  SLL/SLL2, raw IP or BSD loopback. Frames go through `robodr-capture`
  (IPv4/IPv6, bounded IP fragment reassembly, RTPS port or magic filter), then
  through one `robodr_rtps::FragmentReassembler` per file. SEDP announcements
  that were split into DATA_FRAG submessages are therefore learned too. Large
  XTypes type information makes this common with Fast DDS and Connext. A
  capture contains **discovery only**: participants, writers and readers.
  Motion envelopes need the sensor's motion events, so mix `--pcap` and
  `--events` in one `learn` to get both. A capture that is not a pcap file,
  or that ends in the middle of a record, is an input error (exit 2). Capture
  with full snap length (`tcpdump -s 0 -w run.pcap udp`) and stop it with
  SIGINT so that the last record is flushed.
* **Multi-mission**: repeat `--events` in `learn`. The runs are unioned inside
  one `Learner`, so percentiles and warnings cover every sample and the margin
  is applied once. `merge` unions profiles that were already learned: per
  dimension the larger bound wins, and the result is unlocked again.
* **lock** collects every reason to refuse before failing:
  * the profile is already locked
  * there are no participants
  * there are no writer topics
  * a motion channel has no bound
  * any `Profile::validate` error, which the sensor would also refuse at load
    time: an empty model, a non-finite or negative bound, a GUID that is not
    24 lower-case hex characters, a ROS name that is mangled (`rt/x`) or
    relative, or an empty raw topic or channel
* **check** refuses (exit 2) a profile that fails `Profile::validate`.
* **diff** lists every change in participants, writer topics, services,
  actions, raw DDS topics, reader topics, motion channels and envelope bounds.
  Changes that permit more than before are marked `[LOOSENS]`. Reader topics
  need care. Adding the *first* reader topics switches enforcement on, which
  is `reader-topic enforcement: off -> on [tightens]`. Removing all of them
  switches it off, which is `[LOOSENS]`. Adding reader topics while
  enforcement is already on is `[LOOSENS]`.
* **merge** also unions services, actions, raw DDS topics and reader topics.
  It refuses to mix profiles that enforce reader topics with profiles that do
  not, because the union would start enforcing readers that the other
  missions never recorded.
* **check** runs `Profile::evaluate` on every event, plus one rule of this
  crate's own, `commission.motion.anomalous_speed` (see Limits).

## Demo (synthetic data)

`examples/clean-run.jsonl` and `examples/rogue-participant.jsonl` are
**synthetic** files. They were written by hand to model a 4-node ROS 2 UGV
(nav, base controller, lidar, sensor-mast pan/tilt) and were not captured from
a real robot. Like a real graph, each node has `/rosout`,
`/parameter_events`, its six parameter services and `ros_discovery_info`.
There is also one application service (`/base/set_mode`) and one action
(`/navigate_to_pose`). The rogue file is the clean run plus one unknown
participant that announces a writer on `rt/cmd_vel`.

```console
$ robodr-commission learn --events examples/clean-run.jsonl --model ugv-demo-synthetic \
      --ceiling-linear 1.5 --out profile.json --report report.json
...
Services (25):
  /base/set_mode  clients {"01103f5a8c2e000000000101"}  servers {"01103f5a8c2e000000000102"}
  /base_controller/describe_parameters  clients {}  servers {"01103f5a8c2e000000000102"}
  ...
Actions (1):
  /navigate_to_pose  clients {}  servers {"01103f5a8c2e000000000101"}  parts {"cancel_goal", "feedback", "get_result", "send_goal", "status"}

Raw DDS topics (1):
  "ros_discovery_info" (ROS 2 internal)  writers {...}  readers {...}

Motion channels (2):
  /cmd_vel  48 commands [run0:101 .. run0:168]
    linear: n=48 min=0.05 p50=0.601 p99=1.15 max=1.15 -> envelope 1.265 m/s
  /mast/pan_tilt_cmd  36 commands [run0:102 .. run0:188]
    joint: n=36 min=0.05 p50=0.5 p99=0.749 max=0.749 -> envelope 0.8239 rad/s

Anomalies: 0

Warnings: 1 (0 need attention)
  [info] reader_topics_not_learned: 6 reader topics observed but not learned: reader-topic enforcement stays off (use --learn-readers to opt in)
wrote draft profile profile.json (locked: false): 4 participants, 7 writer topics, 25 services, 1 actions, 1 raw DDS topics, 0 reader topics, 2 motion channels; 0 anomalies, 0 warnings need attention

$ robodr-commission lock --in profile.json --out locked.json
locked profile ugv-demo-synthetic -> locked.json

$ robodr-commission check --profile locked.json --events examples/clean-run.jsonl
0 deviation(s) over 186 event(s) against profile ugv-demo-synthetic
$ echo $?
0

$ robodr-commission check --profile locked.json --events examples/rogue-participant.jsonl
examples/rogue-participant.jsonl:117: [High] robot.ros2.unknown_participant: unknown DDS participant 0f0f0f0f0f0f0f0f0f0f0f0f from 10.42.0.99 joined the robot graph
examples/rogue-participant.jsonl:118: [Critical] robot.ros2.unauthorized_motion_writer: participant 0f0f0f0f0f0f0f0f0f0f0f0f not in profile is publishing motion topic /cmd_vel
  robot.ros2.unauthorized_motion_writer: 1
  robot.ros2.unknown_participant: 1
2 deviation(s) over 188 event(s) against profile ugv-demo-synthetic
$ echo $?
1
```

`tests/cli.rs` runs exactly this sequence against the built binary. It also
runs the sequence with `--learn-readers` (still zero deviations), and runs
learn → lock → check over a synthetic pcap. That pcap has a two-node
talker/listener graph, one SEDP announcement sent as DATA_FRAG and one that is
IP-fragmented. A second variant of the pcap is missing one DATA_FRAG, and the
test expects `fragmented_discovery_unreassembled` for it.

## Library API

* `Learner::new(LearnConfig)`, then:
  * `start_run`, `observe` or `observe_at`, and `ingest(&mut dyn EventSource)` to feed events
  * `merge(&Learner)` to union another learner's runs into this one
  * `profile()`, `report()` and `finish()` to get the results
* `envelope_bound(observed_max, margin, ceiling) -> (bound, capped)`
* `lock(&Profile) -> Result<Profile, Vec<LockRefusal>>`
* `diff(&old, &new) -> ProfileDiff`, with `is_empty()` and `loosens()`
* `merge_profiles(&[Profile]) -> Result<Profile, MergeError>`
* `Checker::new(&profile)`, then `observe` or `ingest`, then `finish() -> CheckReport`. `check_event` evaluates a single event.
* `input::{EventSource, JsonlSource, PcapSource, VecSource, InputSpec, open}`, plus
  `CaptureDiagnostics` (from `EventSource::capture_diagnostics`, which is copied into `RunSummary::capture`)
* `ProfileSlot::of(&RosName)`: the profile set that admits an endpoint, the same rule `Profile::evaluate` uses

## Limits

* The profile covers only what the clean run exercised. Rarely used topics and
  manoeuvres faster than anything in the run will deviate later. Merge more
  missions to widen coverage, and watch for `few_motion_samples`.
* Only synthetic inputs have been tested: hand-written JSONL, and pcaps built
  from the DDSI-RTPS layout with `robodr-capture`'s frame helpers. No Gazebo
  or real-robot capture from Fast DDS, Cyclone or Connext has been run through
  the tool yet. The names `ros_discovery_info` and `rq/…Request`/`rr/…Reply`
  follow the rmw naming as we know it, and have not been checked against a
  live stack.
* A capture cannot see shared-memory transports or DDS-Security protected
  discovery (the report counts protected submessages). See the limits in
  `robodr-capture`. Starting a capture after the nodes have started can miss
  SEDP, which is why the parameter-service warnings exist.
* The parameter-service check is a heuristic. It treats a participant that
  writes `/rosout` as hosting a ROS node, and it groups services by name
  prefix. A node started with `start_parameter_services:=false` or
  `enable_rosout:=false` gives a false or a missed warning.
* `check` adds `commission.motion.anomalous_speed` for negative speeds (the
  learner never feeds them into an envelope). Non-finite speeds are already a
  Critical deviation in `Profile::evaluate`.
* Every motion sample is kept in memory to compute percentiles. Each sample is
  8 bytes, about 1.4 MB per channel-hour at 50 Hz.
