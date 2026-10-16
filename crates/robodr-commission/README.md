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
* If a channel has samples in one dimension only, the other dimension is
  **not** left `null` (which means unlimited): it is set to the OEM ceiling
  for that dimension if one was given, else to `0` (deny any non-zero
  command), and becomes the sign-off item `envelope_dimension_unobserved`.
* If an envelope's observed maximum is more than `--outlier-ratio` (default
  3) times its 99th percentile, one stray (or injected) command is setting
  the bound: sign-off item `envelope_outlier` with max and p99.

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
  `motion_envelope_dropped_no_writer` (commands from accepted sources on a
  channel no accepted participant announced a writer on: no envelope is
  learned, because `Profile::validate` requires an enveloped channel to be a
  writer topic; commands on it are reported as an unprofiled channel),
  `motion_channel_without_envelope`, `observed_exceeds_ceiling`,
  `margin_capped_by_ceiling`, `zero_envelope`, `mangled_motion_channel`,
  `topic_type_conflict`, `anomalies_present`, `default_model_name`, `no_events`,
  `missing_parameter_services`, `incomplete_parameter_services`,
  `reader_only_name`, `raw_dds_topic`, `reader_topics_not_learned`, and, for
  captures, `fragmented_discovery_unreassembled` (DATA_FRAG seen but not all
  rebuilt, so endpoints are missing), `fragmented_discovery_reassembled`,
  `ip_reassembly_failed`, `truncated_frames` and `protected_discovery`;
  `endpoint_sender_mismatch`, `discovery_relay_attributed` (info),
  `discovery_relay_participants_ignored` (info), `envelope_outlier`,
  `envelope_dimension_unobserved` (info) and `presence_measured_by_position`
  (info: a run without timestamps, see below).

`RobotEvent` has no timestamps. "First and last seen" are therefore positions,
written as `runN:POS`. POS is the line number for JSONL and the frame ordinal
for a capture. The gate's late/brief fractions and minimum duration use the
capture timestamps when the input has them (pcap), so a flood of frames
cannot dilute them; JSONL runs fall back to line positions and the report
notes it (`presence_measured_by_position`).

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
                        [--hard-cap-linear 10] [--hard-cap-joint 10]
                        [--min-announcements 2] [--min-duration SECS]
                        [--outlier-ratio 3]
                        [--accept-participant GUID]... [--motion-topic /T]...
                        [--discovery-server PREFIX|PREFIX@IP|IP]...
                        [--trusted-discovery-server PREFIX|PREFIX@IP|IP]...
                        [--learn-readers]
                        --out profile.json [--signoff signoff.json]
                        [--report report.json] [--quiet] [--force]
robodr-commission lock    --in profile.json --signoff signoff.json --out locked.json
                          --operators operators.json [--motion-quorum N] [--no-manifest]
                          (--parent previous-locked.json | --platform P --profile-version N)
                          [--unit-id U] [--sign-key signing.key] [--trusted-keys trust.json]
                          [--locked-at UNIX_SECS]
                          [--hard-cap-linear 10] [--hard-cap-joint 10] [--force]
robodr-commission sign    --profile locked.json --sign-key signing.key [--force]
robodr-commission verify-profile --profile locked.json --trusted-keys trust.json
                          [--expect-platform P] [--expect-unit U]
                          [--state profile-state.json] [--allow-rollback sha256:HEX] [--json]
robodr-commission keygen  --out signing.key --trust-out trust.json [--key-id ID]
robodr-commission trust-keys --out trust.json --pub KEY.pub [--pub KEY2.pub]... [--force]
robodr-commission migrate-legacy --in legacy-locked.json --out locked.json
                          --platform P --profile-version N --operator NAME
                          --sign-key signing.key [--unit-id U] [--locked-at UNIX_SECS]
robodr-commission signoff --in profile.json --out signoff.json [--force]
robodr-commission signoff --signoff signoff.json --sign-key operator.key
                          [--in profile.json] [--operators operators.json] [--force]
robodr-commission operators --out operators.json --operator NAME=KEY.pub [...]
                          [--motion-quorum N] [--force]
robodr-commission diff    old.json new.json [--json]
robodr-commission check   --profile locked.json (--events run.jsonl | --pcap run.pcap) [...] [--json]
robodr-commission merge   --out merged.json a.json b.json [...]
                          [--hard-cap-linear 10] [--hard-cap-joint 10] [--force]
```

Exit codes:

* `0`: ok, clean, or identical
* `1`: a negative result (deviations found, profiles differ, lock refused,
  or `verify-profile` refused the profile)
* `2`: a usage, input or I/O error

Every output is written to a fresh temp file in the destination directory
(`O_EXCL`), fsynced, then published atomically (`link` when the file must not
exist yet, `rename` with `--force`). An existing file is never overwritten
without `--force`, a symlink at the output path is refused even with
`--force`, and outputs must differ from each other and from the inputs. A
failed `learn` writes nothing: every output path is checked before the
inputs are read, and the draft, sign-off list and report are published as a
unit (all temp files written first; if one publish fails, the ones already
published are removed or restored). A power loss in the middle of the
publish step can still leave a subset, so `learn` then writes an **output
manifest** `<out>.manifest.json` last (after removing a stale one, and only
once the other files are durable): the draft's and the report's SHA-256 and
the sign-off's `profile_sha256` / `items_sha256` (the operator edits
`confirmed` and `operator`, so the list's file hash cannot be recorded).
`lock` refuses a draft whose manifest is missing or does not match the
draft, the sign-off or the report (a new draft next to an old list, or a
stale report the operator would review); `check` refuses a draft whose
manifest does not match (a draft without one, e.g. from `merge`, is checked
with a note). `signoff --in/--out` writes the manifest for the conservative
list. `lock --no-manifest` skips the check for drafts made before manifests
existed. A manifest detects torn and mixed-up sets, not forgery. Profile inputs must be regular files
(no FIFOs or devices) of at most 64 MiB and are parsed strictly: every key
present, no unknown keys, and no duplicate keys at any depth, compared after
JSON unescaping (`"/cmd_vel"` and `"/cmd\u005fvel"` are the same key), and a
valid seal if locked.

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
* **lock** needs the draft *and* its sign-off list, and collects every reason
  to refuse before failing:
  * the sign-off is malformed, is for another model, does not match the
    SHA-256 of the draft bytes (the draft was edited after the list was
    made), has no `operator`, or has an item with `"confirmed": false`
  * items were deleted, added or reworded: `items_sha256` binds the item set
    (ids and reasons) to the draft; only `confirmed` and `operator` may change
  * independently of the list, every motion channel of the draft must be
    covered by a confirmed `motion_writer`, `motion_unattributed` or
    `motion_channel_unreviewed` item, and every motion dimension left `null`
    (unlimited) by a confirmed `envelope_dimension_unbounded` item (a floor
    recomputed from the draft)
  * the list is not **signed** (see "Signed operator sign-off" below): no
    valid signature from a key in `--operators`, any invalid or unknown
    signature, the named `operator` not among the signers, or fewer than
    `motion_quorum` distinct operators when the list has motion items
  * the output manifest is missing or does not match (unless `--no-manifest`)
  * a bound above `--hard-cap-linear` / `--hard-cap-joint` (default 10 m/s,
    10 rad/s; pass the values used for `learn` on a faster platform)
  * the profile is already locked
  * there are no participants
  * there are no writer topics
  * a motion channel has no bound
  * any `Profile::validate` error, which the sensor would also refuse at load
    time: an empty model, a non-finite or negative bound, a GUID that is not
    24 lower-case hex characters, a ROS name that is mangled (`rt/x`) or
    relative, or an empty raw topic or channel
* **Versioned, signed artifact** (`trust` module). `lock` stamps
  `metadata` (`schema_version`, monotonic `profile_version`, `platform`,
  optional `unit_id`, `locked_by` = the sign-off operator, `locked_at`,
  `parent_digest` = `sha256:` of the locked file it supersedes, via
  `--parent`) and, with `--sign-key`, writes `<out>.sig`: Ed25519 (the
  robodr-blackbox implementation, through its `Signer`/`Verifier` traits)
  over a domain tag and the exact sealed bytes. Every loader (sensor
  pipeline, agentd, `robodr-replay`, `robodr-ros2-watch`) enforces a locked
  profile only with metadata and a valid signature from a key in its trust
  file, and (with a state file) refuses a lower `profile_version` unless the
  operator names the exact file digest. A locked profile without metadata
  (locked before versioning) is refused; `migrate-legacy` re-issues it.
  Trust roots (`keygen --roots`, never profile keys) sign a revocation list
  (`revoke`, `verify-revocations`: revoked digests / key ids, monotonic
  serial, itself anti-rollback protected) and an optional trust-file
  `min_profile_version` floor (`trust-keys --min-profile-version --sign-key`).
  agentd records each accepted profile in the black box and flags a deleted
  or rewritten state file (Critical `robot.ros2.profile_state_tampered`).
  Limits: the Ed25519 code is not audited; root can delete both the state
  file and the black box (only the signed floor remains on the unit); an
  older root-signed trust file (lower floor) can be replayed; no expiry.

  The locked file is **sealed**: its first member is
  `"seal": "sha256:<hex>"` over the rest of the file. `check`, `diff` and
  `merge` refuse a locked profile whose seal is missing or wrong (edited,
  partially written, `locked` flipped by hand). The sensor's own loader
  ignores the extra member.
* **signoff** writes a conservative sign-off list for a draft that was edited
  by hand or produced by `merge` (every participant and motion channel must be
  confirmed individually, because the learner's provenance is gone), and the
  draft's output manifest (a stale one is replaced; one that still matches
  needs `--force`). With `--sign-key` it signs a confirmed list instead.
* **operators** builds the operators trust list from public key files.

### Signed operator sign-off (trust model)

`items_sha256` and `profile_sha256` are plain hashes: anyone with write
access could delete an item and recompute them. The confirmation becomes an
authenticated decision through the operator's **Ed25519 signature** over
the exact bytes of the confirmed list:

1. Each operator has a robodr-blackbox key file (`robodr-blackbox-key/v2`,
   Ed25519, secret file mode 0600; `robodr-commission keygen` or
   `robodr-blackbox keygen`). The security officer lists the public halves,
   each bound to an operator name, in an operators trust list:
   `robodr-commission operators --out operators.json --operator
   Alice=alice.key.pub --operator Bob=bob.key.pub --motion-quorum 2`
   (`robodr-operators/v1`). It is refused at load if it is a symlink or
   writable by group/others, lists a key id or a public key twice (one
   person counted twice), or asks for a quorum above its number of distinct
   operators.
2. After review: `robodr-commission signoff --signoff S --sign-key alice.key
   [--in draft.json] [--operators operators.json]` refuses a list that is
   not fully confirmed, names no operator, has a broken item digest or
   (with `--in`) belongs to another draft or misses a floor item, and
   otherwise adds the signature over `robodr-signoff-sig/v1\0 || <bytes>` to
   `S.sig` (`robodr-signoff-sigs/v1`). Further operators sign the same
   bytes. Editing the list afterwards voids all signatures (re-signing then
   needs `--force`, which discards them).
3. `lock --operators operators.json` verifies `S.sig`: every signature must
   verify under a listed key (fail closed), at least one must, the list's
   `operator` must be the name bound to one of the signers (so the locked
   profile's `locked_by` is an authenticated identity), and if the list has
   motion items (`motion_writer`, `motion_unattributed`,
   `motion_channel_unreviewed`) at least `motion_quorum` distinct operators
   (names, not keys) must have signed: the **two-person rule**.
   `--motion-quorum N` raises it for one lock, never lowers it.

What is trusted: the operators trust list (install it with the same care as
the profile trust file), the operators' secret keys, and the commissioning
workstation while `learn` runs. The learner is not a separate signing
identity (a learner key on the same workstation would add nothing over the
operator signature that follows); instead, what `lock` can recompute from
the digest-bound draft it does (the floor above), so a rewritten list can
drop learner findings only by getting an authorised operator to sign the
list they are shown. Limits: a careless or colluding operator (or quorum)
can still confirm anything, the signature makes it a named decision; no key
expiry or revocation list (remove the key from the trust list); the Ed25519
code is robodr-blackbox's, not audited. The library's `lock` /
`lock_draft_text` check content and confirmations only, for embedders that
authenticate the operator themselves; `lock_signed_draft` is what the CLI
runs.
* **check** refuses (exit 2) a profile that fails `Profile::validate`.
* **diff** lists every change in participants, writer topics, services,
  actions, raw DDS topics, reader topics, motion channels and envelope bounds.
  Changes that permit more than before are marked `[LOOSENS]`. Reader topics
  need care. Adding the *first* reader topics switches enforcement on, which
  is `reader-topic enforcement: off -> on [tightens]`. Removing all of them
  switches it off, which is `[LOOSENS]`. Adding reader topics while
  enforcement is already on is `[LOOSENS]`.
* **merge** refuses an input with a bound above the hard caps (same flags as
  `lock`), so "larger bound wins" cannot carry a hand-edited `1e300` into the
  result. It also unions services, actions, raw DDS topics and reader topics.
  It refuses to mix profiles that enforce reader topics with profiles that do
  not, because the union would start enforcing readers that the other
  missions never recorded.
* **check** runs `Profile::evaluate` on every event, plus one rule of this
  crate's own, `commission.motion.anomalous_speed` (see Limits).

## Learning-time poisoning and other hostile input

Commissioning trusts whatever is on the bus during the clean run, so an
intruder present then would be baked into the allowlist. Defences (details in
the `learner` module docs):

* **Quarantine** (not learned, nor its endpoints or motion samples): a
  participant announced fewer than `--min-announcements` (2) times, or, in
  captures, observed for less than `--min-duration` (5 s) in every run. The
  operator can override with `--accept-participant GUID`, which itself needs
  sign-off. Endpoints announced only by quarantined or unannounced GUIDs, and
  motion commands from them, are never learned.
* **Endpoint provenance** (captures): an endpoint is learned for the GUID it
  claims only if that GUID is the prefix the RTPS message was sent under
  (header / INFO_SRC) and the datagram came from one of that participant's
  commissioned IPs (IPs from which it passes the quarantine gate itself).
  Anything else is not learned and becomes `endpoint_sender_mismatch` (owner,
  sender, IP, names). An intruder can therefore not get a topic learned by
  writing a legitimate participant's GUID into `PID_ENDPOINT_GUID`. JSONL
  events carry no sender, so the check does not apply to them.
* **Discovery servers** (`--discovery-server`, `--trusted-discovery-server`;
  `PREFIX`, `PREFIX@IP` or `IP`, mirroring the sensor pipeline's
  `discovery_servers` binding option). A server re-sends other participants'
  announcements under its own prefix. A relay whose sender matches a
  configured server is attributed to the owner, never to the server, and
  never binds the server's IP to the owner. From a **known** server a
  relayed endpoint only confirms the owner's own announcement: no item if
  the owner is accepted and announced the same endpoint directly from a
  commissioned IP, otherwise it is not learned and becomes an
  `endpoint_sender_mismatch` item naming the server; participant
  announcements it relays are ignored by the gate (info
  `discovery_relay_participants_ignored`). From a **trusted** server,
  relayed participant announcements count for the owner's gate (under the
  pseudo-address `relay:<server>`, shown in the report, not counted as a
  second IP) and relayed endpoints of accepted owners are learned. Relays
  for owners that are not accepted are flagged either way; relays from
  unconfigured senders stay `endpoint_sender_mismatch`. Attributed relays
  are listed as info `discovery_relay_attributed`. Trusting a server means
  trusting whatever it relays; prefer the known mode with a capture point
  that also sees the participants' own traffic. (The RTPS layer also
  reports a relayed announcement as the relaying participant's own
  endpoint, as the sensor does; the server is gated and reviewed like any
  participant.)
* **Sign-off list** (`<out>.signoff.json`): every participant that writes a
  motion topic (learned channel, `--motion-topic`, or a name containing
  `cmd`/`command`/`twist`/`trajectory`) or sends motion commands; participants
  that joined late, were present briefly, came from several IPs or missed
  runs; unattributed motion commands; thin envelopes; samples above the cap;
  unobserved dimensions; outlier maxima; endpoint sender mismatches;
  capacity overflow; anomalies. `lock` refuses until a named operator has
  confirmed every item and signed the list with a key from the operators
  trust list (two distinct operators for motion items with
  `motion_quorum: 2`), and refuses a list with items removed.
* **Hard caps**: no envelope exceeds `--hard-cap-linear` / `--hard-cap-joint`
  (default 10 m/s, 10 rad/s) or the tighter OEM ceiling; NaN, infinite and
  negative speeds are never learned; `lock` and `merge` enforce the same
  caps on hand-edited drafts.
* **Bounded memory**: participants (4096), names per kind (16384), motion
  channels (256), inner sets (256) and retained samples per channel and
  dimension (16384, then decimated; count/min/max stay exact) are capped;
  overflow is counted, reported and becomes a sign-off item.
* **Hostile captures**: lengths are validated before allocation by
  `robodr-capture`; truncated captures abort `learn`; a capture in which no
  frame has a supported link type is refused instead of learning an empty
  profile; partial problems become warnings.

What this cannot catch: an intruder present from the very start for the whole
run, announcing normally from one IP and not touching motion topics. Only the
operator's review of the participant list catches that. The seal, the
sign-off digests and the output manifest are hashes, not signatures: they
detect edits, deletions, torn writes and corruption, not a forger who
recomputes them. What stops the forger is the operator signature on the
sign-off (and the OEM signature on the locked profile); the floor at `lock`
still applies to any list.

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

$ robodr-commission keygen --out alice.key --trust-out alice.trust.json --key-id alice
$ robodr-commission operators --out operators.json --operator Alice=alice.key.pub
$ robodr-commission lock --in profile.json --signoff profile.json.signoff.json --out locked.json \
    --operators operators.json --platform ugv-demo --profile-version 1
refusing to lock profile.json:
  - sign-off has no operator name (fill in "operator")
  - not confirmed by the operator: motion_writer:/cmd_vel 01103f5a8c2e000000000101 (...)
  ...
  - the sign-off carries no valid operator signature: ...
$ $EDITOR profile.json.signoff.json   # review each item, set "confirmed": true, "operator": "Alice"
$ robodr-commission signoff --signoff profile.json.signoff.json --sign-key alice.key \
    --in profile.json --operators operators.json
signed profile.json.signoff.json as key alice (operator "Alice") -> profile.json.signoff.json.sig ...
$ robodr-commission keygen --out oem.key --trust-out trust.json --key-id oem-demo
# oem.key (secret, 0600) + oem.key.pub (public, 0644): robodr-blackbox-key/v2,
# the same key file format as robodr-blackbox keygen (either can sign).
$ robodr-commission lock --in profile.json --signoff profile.json.signoff.json --out locked.json \
    --operators operators.json --platform ugv-demo --profile-version 1 --sign-key oem.key
locked profile ugv-demo-synthetic -> locked.json (sealed; profile_version 1, platform ugv-demo; ...)
signed by oem-demo -> locked.json.sig
$ robodr-commission verify-profile --profile locked.json --trusted-keys trust.json
TRUSTED locked.json: model "ugv-demo-synthetic", profile_version 1, ...

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
* `finish() -> Commissioning { profile, report, signoff }`
* `lock(&Profile, &Signoff)` and `lock_draft_text(&str, &Signoff)` `-> Result<Profile, Vec<LockRefusal>>`;
  `lockable(&Profile)` for the content checks alone
* `Signoff::for_profile`, `Signoff::confirm_all`; `profile_file::{parse_profile_text, sealed_text, write_file_atomic, read_regular_file}`
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
* Memory is capped (see above). Past `max_samples`, p50/p99 come from a
  deterministic decimated subset and are marked approximate; envelopes always
  use exact maxima. When a cap is hit, which entries got in depends on
  arrival order.
* "Late" and "brief" use input positions (frame ordinals, JSONL lines), not
  time; the duration gate needs capture timestamps (pcap) and is skipped,
  with a warning, for runs shorter than the minimum.
* The no-clobber publish uses `link(2)`; on a filesystem without hard links it
  falls back to check-then-rename, which has a narrow race.
