# robodr-commission

Observe-mode commissioning for RoboDR (Sprint 3). The robot does a **clean run**
while RoboDR only watches. This tool turns what it saw into a draft model profile
(`profile.json`, `locked: false`) and a commissioning report. The OEM reviews
the draft, locks it, and then proves that a clean re-run gives **zero deviations**.

The tool only reads recordings and writes files. It never talks to the robot or
changes how it behaves.

## Pipeline

```
events (JSONL; pcap TODO) ──► Learner ──► profile.json (locked:false) + report
                                              │ OEM review (report, diff)
                                              ▼
                                         lock ──► locked.json
                                              │
                    events of a re-run ──► check ──► deviations (exit 1) / none (exit 0)
```

## What is learned

| Profile field       | Learned from                                                                                   |
|---------------------|------------------------------------------------------------------------------------------------|
| `participants`      | GUID prefixes from `ros2_participant_discovered` (SPDP) events                                  |
| `writer_topics`     | `Endpoint::ros_topic()` of every `ros2_writer_discovered`                                       |
| `motion_envelopes`  | for each `motion_command` channel and dimension: `min(max_observed × margin, OEM ceiling)`      |

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
* GUID prefixes that are not 24 lower-case hex chars (profile matching is exact)

### Report

`--report report.json` writes the full report. A human-readable version is
always printed to stdout. The report contains:

* runs, and event counts per kind
* for each participant: announcement count, first and last seen, source IPs, and the topics it writes and reads
* for each writer and reader topic: count, first and last seen, participants, and type names
* for each motion channel: command count, sources, `min/p50/p99/max` per dimension (nearest-rank, so every value was actually observed), the resulting envelope, and whether a ceiling capped it
* anomalies: the first 1000 are stored, and all of them are counted
* warnings at level `warn` (resolve or accept these before locking) or `info`:
  `few_motion_samples` (< `--min-samples`, default 30: envelope not trustworthy),
  `participant_seen_once` (transient? tool?), `writer_without_reader`,
  `unannounced_participant`, `motion_channel_without_writer`,
  `motion_channel_without_envelope`, `observed_exceeds_ceiling`,
  `margin_capped_by_ceiling`, `zero_envelope`, `mangled_motion_channel`,
  `topic_type_conflict`, `anomalies_present`, `default_model_name`, `no_events`.

`RobotEvent` has no timestamps. "First and last seen" are therefore positions,
written as `runN:LINE` (run index and line number in that run's JSONL file).

### Determinism

All state is held in `BTreeMap` and `BTreeSet`. Floats are sorted with
`total_cmp`. No clocks, hashing or randomness are involved. Running `learn`
twice over the same input gives byte-identical `profile.json` and `report.json`,
and a test checks this. The profile depends only on sets and maxima, so event
order and merge order do not change it.

## CLI

```
robodr-commission learn --events run.jsonl [--events run2.jsonl ...] [--model NAME]
                        [--margin 1.1] [--min-samples 30]
                        [--ceiling-linear M_PER_S] [--ceiling-joint RAD_PER_S]
                        --out profile.json [--report report.json] [--quiet]
robodr-commission lock  --in profile.json --out locked.json
robodr-commission diff  old.json new.json [--json]
robodr-commission check --profile locked.json --events run.jsonl [...] [--json]
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
* **Multi-mission**: repeat `--events` in `learn`. The runs are unioned inside
  one `Learner`, so percentiles and warnings cover every sample and the margin
  is applied once. `merge` unions profiles that were already learned: per
  dimension the larger bound wins, and the result is unlocked again.
* **lock** collects every reason to refuse before failing:
  * the profile is already locked
  * the model name is empty
  * there are no participants
  * there are no writer topics
  * a motion channel has no bound
  * a bound is non-finite or negative
* **diff** lists every change in participants, writer topics, motion channels
  and envelope bounds. Changes that permit more than before are marked
  `[LOOSENS]`.
* **check** runs `Profile::evaluate` on every event, plus one rule of this
  crate's own, `commission.motion.anomalous_speed` (see Limits).
* **`--pcap`** is accepted but not wired yet. See `TODO(pcap)` in
  `src/input.rs`. Wiring it means adding one `impl EventSource` and changing
  one match arm.

## Demo (synthetic data)

`examples/clean-run.jsonl` and `examples/rogue-participant.jsonl` are
**synthetic** files. They were written by hand to model a 4-node ROS 2 UGV
(nav, base controller, lidar, sensor-mast pan/tilt) and were not captured from
a real robot. The rogue file is the clean run plus one unknown participant that
announces a writer on `rt/cmd_vel`.

```console
$ robodr-commission learn --events examples/clean-run.jsonl --model ugv-demo-synthetic \
      --ceiling-linear 1.5 --out profile.json --report report.json
...
Motion channels (2):
  /cmd_vel  48 commands [run0:17 .. run0:84]
    linear: n=48 min=0.05 p50=0.601 p99=1.15 max=1.15 -> envelope 1.265 m/s
  /mast/pan_tilt_cmd  36 commands [run0:18 .. run0:104]
    joint: n=36 min=0.05 p50=0.5 p99=0.749 max=0.749 -> envelope 0.8239 rad/s

Anomalies: 0

Warnings: 0 (0 need attention)

$ robodr-commission lock --in profile.json --out locked.json
locked profile ugv-demo-synthetic -> locked.json

$ robodr-commission check --profile locked.json --events examples/clean-run.jsonl
0 deviation(s) over 106 event(s) against profile ugv-demo-synthetic
$ echo $?
0

$ robodr-commission check --profile locked.json --events examples/rogue-participant.jsonl
examples/rogue-participant.jsonl:33: [High] robot.ros2.unknown_participant: unknown DDS participant 0f0f0f0f0f0f0f0f0f0f0f0f from 10.42.0.99 joined the robot graph
examples/rogue-participant.jsonl:34: [Critical] robot.ros2.unauthorized_motion_writer: participant 0f0f0f0f0f0f0f0f0f0f0f0f not in profile is publishing motion topic /cmd_vel
  robot.ros2.unauthorized_motion_writer: 1
  robot.ros2.unknown_participant: 1
2 deviation(s) over 108 event(s) against profile ugv-demo-synthetic
$ echo $?
1
```

`tests/cli.rs` runs exactly this sequence against the built binary.

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
* `input::{EventSource, JsonlSource, VecSource, InputSpec, open}`

## Limits

* The profile covers only what the clean run exercised. Rarely used topics and
  manoeuvres faster than anything in the run will deviate later. Merge more
  missions to widen coverage, and watch for `few_motion_samples`.
* Only synthetic JSONL has been tested. No Gazebo or real-robot capture has
  been run through the tool yet, and pcap input is not wired.
* `Profile::evaluate` (in robodr-events) compares speeds with `>`. A NaN speed
  therefore passes the envelope check. `check` adds
  `commission.motion.anomalous_speed` so that a corrupted stream cannot report
  "zero deviations". The runtime path (sensor and firewall) needs the same
  guard.
* Every motion sample is kept in memory to compute percentiles. Each sample is
  8 bytes, about 1.4 MB per channel-hour at 50 Hz.
