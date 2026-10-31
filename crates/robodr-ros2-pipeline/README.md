# robodr-ros2-pipeline

The Pulsar-independent half of the RoboDR ROS 2 / DDS sensor. Pure crate:
`std`, `robodr-events`, `robodr-rtps`, `robodr-cdr`, `robodr-capture`,
`robodr-commission`, serde. It builds and
is tested offline. The same code runs in three places:

- inside the Pulsar module `robodr-sensor-ros2`, which is only tokio/Pulsar glue;
- in the lab tool `robodr-ros2-watch`;
- in CI.

```text
 SPDP multicast socket ─┐            (socket.rs; async glue in the sensor)
 live AF_PACKET capture ┼─ Datagram ─► Pipeline ─► Finding ─► Pulsar threat / JSON line
 pcap / pcapng replay ──┘  (source.rs)  (pipeline.rs)
```

## Modules

| Module | What it does |
|---|---|
| `source` | `Datagram` and `DatagramSource`: a blocking, std-only seam. `CaptureDatagramSource` wraps `robodr_capture::rtps_datagrams` for live `AF_PACKET` (`open_live`, Linux, `CAP_NET_RAW`) and for pcap/pcapng files (`open_file`). It takes an optional stop flag. `VecDatagramSource` is the in-memory source. |
| `pipeline` | `Pipeline` runs `FragmentReassembler::parse_datagram_detailed`, using **one long-lived, bounded reassembler**. Then `Profile::evaluate` + removal, anomaly and fragmentation findings, then bounded dedup, then `Finding`s stamped `enforce` or `observe`. Also holds `load_profile`, `ProfileStatus` and `ThreatExtra`, the flat `extra` table and JSON line. |
| `motion` | The live motion decode path. Learns writer GUID → (topic, type) and reader GUID → topic from SEDP (bounded tables), walks user DATA / DATA_FRAG with `robodr-rtps`'s `UserDataWalker`, decodes samples on the profile's motion channels and on `motion.feedback_topics` with `robodr-cdr`, and returns `MotionCommand` / `MotionFeedback` samples (`Pipeline::process_with_motion_at`, `ProcessOutput::motion`). Commands go through `Profile::evaluate` (envelope). |
| `legacy` | Unitree legacy UDP (Go1 generation, `unitree_legged_sdk`), off by default (`unitree_legacy` sub-table). The capture filter (and its kernel BPF) also accepts UDP on the configured legacy ports; `Pipeline::process_datagram_with_motion` hands those datagrams (`Datagram::legacy`) to `Pipeline::process_legacy_from_at`: sender check on the class the length announces (a compressed 614-byte `LowCmd` is still a command), optional IP→MAC binding, decode by length (`robodr_cdr::unitree_legacy::LegacyFrame`), commands on `/unitree_legacy/high_cmd` / `low_cmd` as `MotionSample`s (a decoded `LowCmd` with its 20-slot joint frame; feedback when its channel is a feedback topic). A datagram on a legacy port is **always** a legacy datagram; one that is also RTPS (`LegacyUdp::also_rtps`) is inspected on both paths and reported. Unlisted senders have their own bounded finding budget (aggregated beyond 16 per class), outside the shared rate limiter. |
| `config` | `Config`, i.e. `[module.robodr-sensor-ros2]` plus the `[...capture]` sub-table, and its validation. Domain id gives the SPDP port. Capture domain ids give the `RtpsPortMap`. Default capture interfaces are `lo` plus the interface of the `/proc/net/route` default route. `CaptureSettings::open` opens the configured source. |
| `socket` | Receive-only SPDP multicast socket. It sets `SO_REUSEADDR` before `bind` and binds to the group address, so it coexists with the robot's DDS participants. |
| `sanitize`, `dedup` | Attacker-controlled text is control-escaped and capped at 512 chars. The dedup set is O(capacity) and stores keyed hashes. |
| `watch` | Argument parsing and run loop for `robodr-ros2-watch`. |
| `check` | `robodr-ros2-watch --check-config`: offline validation of `pulsar.toml`'s sensor section (TOML, unknown keys as Pulsar would ignore them, ranges, profile + trust without writing state, `/dev/shm` DDS segments, SROS 2 keystore). |
| `sros2` | SROS 2 policy input (`sros2_keystore`): `governance.xml` and `permissions.xml` parsed (bounded), SPDP DDS-Security identities judged against the grants, visibility statements. |

## Findings

| Rule | Severity | When |
|---|---|---|
| the profile's own rules (`robot.ros2.unknown_participant`, `robot.ros2.unauthorized_motion_writer`, `unknown_writer_topic`, `unknown_service`, `unknown_action`, `unknown_reader`, ...) | as `robodr-events` decides | every discovery event, through `Profile::evaluate` |
| `robot.capture.unsupported_transport` | Medium | once per host and transport set: SPDP advertises shared-memory (Fast DDS SHM, Cyclone iceoryx, Connext SHMEM), TCP or unknown locators; same-host traffic over them is not inspected ([`docs/DDS-TRANSPORTS.md`](../../docs/DDS-TRANSPORTS.md)) |
| `robot.ros2.untrusted_security_identity` | Medium / High | with `sros2_keystore`: no DDS-Security identity on a domain requiring authentication (Medium); a certificate subject no grant names (High) |
| `robot.ros2.participant_removed` | Medium | a **profiled** participant is announced disposed or unregistered (`relayed by …` when someone else sent it) |
| `robot.rtps.malformed_discovery` | Low | one per parse-anomaly kind and source IP (`report_anomalies`) |
| `robot.rtps.fragmented_discovery` | Low | one per source IP sending discovery `DATA_FRAG` (`report_fragmentation`) |
| `robot.rtps.discovery_fragment_rejected` | Medium; **Critical** (SEDP publications) / **High** (SEDP subscriptions) when refused for a reason a DDS stack does not share (size / memory cap, no capacity, geometry or key-flag mismatch with a pending copy) | the reassembler refused fragments (over a cap, bad geometry; that announcement was **not** inspected; an uninspected SEDP writer may be a rogue motion writer), or fragments overlapped with conflicting content (the first copy was inspected; a stack keeping the other copy sees a different announcement). Names the writer prefix. Always reported. |
| `robot.ros2.profile_refused` | High | once at start, when the profile fails `Profile::validate`, or a locked profile file fails the seal / strict file check |
| `robot.ros2.endpoint_source_mismatch` | Critical (writer on a motion topic, or any writer in an ambiguous announcement when the profile has motion topics) / High | an SEDP endpoint attributed to a participant was announced from an IP not bound to it (not its SPDP source, an advertised locator, or a `participant_ips` pin), or relayed / GUID-conflicting from a non-discovery-server IP. See `src/binding.rs`. |
| `robot.ros2.endpoint_unannounced_participant` | Medium (High for a motion-capable writer) | an SEDP endpoint whose participant sent no SPDP within `binding.hold_ms` (or before the end of a replay) |
| `robot.ros2.participant_source_mismatch` | High (profiled) / Medium | SPDP for a bound participant from outside its binding, or relayed by a non-discovery-server IP; not learned |
| `robot.ros2.identity_instances_exceeded` | High | an SPDP matches a profile identity (source IP, RTPS vendor, enclave) whose `max_instances` slots are all held by live participants; the newcomer stays an unknown participant. See `src/identity.rs`. |
| `robot.ros2.ambiguous_discovery` | High | a discovery sample repeats an identity parameter (topic, type, endpoint/participant GUID, key hash, status) with conflicting values. Stacks differ on first- vs last-wins, so what we inspected may not be what a stack acts on. Never rate limited. |
| `robot.rtps.discovery_not_inspected` | Medium | the parser dropped content (unsupported protocol version, truncated / malformed submessage or parameter list, undecodable value, announcement without topic, anomaly list overflow). Always reported. |
| `robot.rtps.discovery_fragment_evicted` | Medium; High when a victim's participant is profiled | partial discovery samples evicted by the reassembler to stay within its caps; not inspected. Names the victims (source prefix, writer, sequence number, reason) |
| `robot.rtps.discovery_removal` | Low / Medium | other disposes / unregisters (Medium when sent from an IP outside the owner's binding) |
| `robot.capture.*` | Low / Medium | the capture layer's counters (malformed frames, IP fragment conflicts / drops / evictions) grew |
| `robot.sensor.findings_capped` | the most severe suppressed, at least Medium | one input produced more than `max_findings_per_datagram` new findings |
| the profile's motion rules (`robot.motion.linear_over_envelope`, `angular_over_envelope`, `joint_over_envelope`, `non_finite_command`, `unprofiled_channel`, `robot.profile.invalid_envelope`) | as `robodr-events` decides (Critical for over-envelope / non-finite) | a `MotionCommand` decoded from user DATA on a profiled motion channel (`motion.evaluate_commands`, default on) |
| `robot.motion.undecodable_sample` | Medium, rate limited | a sample on a motion / feedback topic was not inspected: undecodable CDR, unknown type, wrong-role type, malformed DATA / inline QoS, fragments refused / evicted / conflicting, per-datagram sample cap |
| `robot.motion.unattributed_sample` | High | DATA to a reader announced on a motion / feedback topic from a writer never announced via SEDP; also a motion writer / reader evicted from (or refused by) the bounded endpoint tables |
| `robot.motion.sample_source_mismatch` | Critical (command topic) / High (feedback) | a decoded motion sample whose writer prefix is bound (SPDP / `participant_ips`) to other IPs than its source |
| `robot.motion.command_type_mismatch` | High | a writer announced on a profiled command channel with a type other than the profile's `motion_types` entry, a type no decoder knows, or a feedback type; at the announcement, never rate limited |
| `robot.unitree.legacy_unknown_sender` | Critical (command, decoded or compressed) / Medium (state, or no legacy length) | a Unitree legacy UDP frame from an IP not in `unitree_legacy.command_senders` (commands) / `robot_addresses` (state); the legacy protocol is unauthenticated. Not in the shared rate limiter: one finding per sender for the first 16 senders of a class |
| `robot.unitree.legacy_sender_flood` | Critical (commands) / Medium | frames from more unlisted senders than the 16 reported one by one (or a MAC-bound sender seen with many wrong MACs): one finding with the frame count at 1, 2, 4, 8, ... frames; bounded memory |
| `robot.unitree.legacy_sender_mac_mismatch` | High | a command from a listed sender whose `command_senders` entry binds a MAC, with another link-layer source (or reassembled from fragments, so unverifiable); the frame is not attributed |
| `robot.unitree.legacy_port_rtps` | High | a datagram on a legacy port that also parses as RTPS (inspected on both paths) |

Each distinct finding (rule + detail) is reported once. Dedup is bounded, so
eviction can only cause a re-report.

### Flood limits

- Every per-participant / per-endpoint finding names its GUID prefix as
  structured data (`Finding::participant`), never to be parsed back from
  the detail text: robodr-agentd aggregates a flooding source's findings
  by it (discovery-flood guard), and a participant that raised a High or
  Critical finding keeps its remembered quarantine locators longer, and
  keeps them (merged) when it comes back from a new address
  (`src/binding.rs`, "Quarantine locators"). Under global pressure the
  remembered locators of the fullest per-source bucket go first, so a
  spray from a few addresses evicts its own entries, never a SOC-named
  rogue's.
- **Per-datagram cap** (`max_findings_per_datagram`, default 64): new
  findings of one datagram (or tick / end of replay / capture-health update)
  are ordered most severe first and at most this many are reported; the rest
  are summarised in one `robot.sensor.findings_capped` finding and are **not**
  remembered, so they are reported when they recur. A 64 KiB datagram naming
  thousands of fake participants therefore cannot bury a Critical finding or
  flood the event bus.
- **Rate limit** (`rate_limit_burst`, `rate_limit_interval_ms`): per rule, on
  `robot.rtps.*`, `robot.capture.*`, `robot.sensor.*` and
  `robot.motion.undecodable_sample` only. The profile and
  binding rules (`robot.ros2.*`) are never rate limited.
- **Discovery reassembly caps** (`ReassemblyLimits::default()`, not
  configurable in the TOML): samples up to 512 KiB (was 64 KiB; DDS stacks
  accept far larger SEDP samples, so a padded announcement must not be
  refused here while the robot takes it), 8 MiB for all partial samples
  together, 256 partial samples, 64 per source.
- **Memory**: dedup set, reassembler, binding table (`binding.max_participants`,
  O(log n) eviction, profiled participants evicted last), held-announcement
  queue (1024), per-participant IP / locator lists and the rate limiter are
  all bounded; nothing grows with the number of distinct GUIDs or IPs seen.

### Observe vs enforce, and invalid profiles

| Profile | `profile_status` | Findings |
|---|---|---|
| valid, `locked: true` | `enforcing` | `mode = "enforce"` |
| valid, `locked: false` | `observing` | `mode = "observe"`, description prefixed `[observe-only] ` |
| fails `Profile::validate` (locked or not) | `refused` | errors reported, one `robot.ros2.profile_refused` finding; **observe-only** |
| `locked: true` but the file fails the commissioning check (`robodr_commission::parse_profile_text`: lock seal missing or not matching, i.e. edited after `robodr-commission lock`; unknown / missing keys) | `refused` | reason reported, one `robot.ros2.profile_refused` finding; **observe-only** |
| `locked: true` but not trusted (`load_profile_with_trust`: no metadata, no / bad `<profile>.sig`, key not in `profile_trust.trusted_keys`, platform/unit mismatch, anti-rollback refusal). The plain `load_profile` trusts no key, so it always lands here for a locked profile | `refused` | same, with the trust reason |

The file check lives in `robodr-commission`, which owns the profile file
format it writes (strict keys + seal). The pipeline depends on it rather than
duplicating the format and its SHA-256 in `robodr-events` (which cannot depend
on `robodr-blackbox`'s crypto without a cycle). An unlocked draft that fails
the strict check is still observed; the problem is shown in the status
message.

**Decision: a refused profile runs the sensor observe-only. It does not stop
the sensor.**

- A broken profile is a configuration fault. It must never become a
  safe-state request; otherwise whoever can corrupt the profile file could
  stop the robot.
- Refusing to start would blind the sensor.
- Observe-only keeps visibility, never acts on a profile we cannot trust, and
  is loud about it.

A profile file that cannot be read or parsed at all is a hard start-up error,
because there is nothing to observe against.

## Live motion decode (`motion`)

```text
datagram ─► discovery parse ─► SEDP: writer GUID → (topic, type), reader GUID → topic
        └─► UserDataWalker (INFO_SRC / INFO_DST / INFO_TS, LE + BE, DATA + DATA_FRAG,
            per-writer reassembly quota; only writers on motion / feedback topics)
              ─► robodr_cdr::Registry::decode(type announced by SEDP, payload)
              ─► to_event(EventContext { channel: "/cmd_vel", writer GUID, capture time })
              ─► MotionCommand ─► Profile::evaluate ─► findings
              └─► ProcessOutput::motion (for the agent chain: firewall, motion monitor)
```

Configuration (`[module.robodr-sensor-ros2.motion]` / agentd `sensor.motion`):
`enabled` (default true), `feedback_topics` (ROS names, e.g. `["/odom"]`),
`evaluate_commands` (default true), `max_writers` (4096),
`max_samples_per_datagram` (256). `MotionOptions::robot_model` has no key
here: `robodr-agentd` sets it from `robot.robot_model` (the Pulsar sensor
runs without it, so model-specific Unitree API ids are `Unknown` there).

Unitree legacy UDP (`[module.robodr-sensor-ros2.unitree_legacy]` / agentd
`sensor.unitree_legacy`): `enabled` (default false), `ports` (default
`[8007, 8080, 8082, 8090]`; refused when one lies inside the RTPS port
range of a configured DDS domain, e.g. domain 2 covers 7900-8149),
`command_senders` (IPs, or tables `{ip, mac?, label?}`: `mac` binds the
sender to its link-layer source, checked where the capture sees one —
`AF_PACKET`, Ethernet / Linux cooked pcap — and a raise of the bar only,
since a host on the same L2 segment can forge a MAC too), `robot_addresses`
(default `192.168.123.10`, `192.168.123.161`). Needs `capture`; `Datagram`
carries `legacy` (UDP ports, source MAC, reassembled, also-RTPS) and
`captured_at` (the capture timestamp, which `robodr-agentd` uses as the
joint firewall's clock).

- **Unitree.** Unitree SDK2 topics are plain DDS topics named `rt/...`
  and de-mangle like ROS topics (`rt/lowcmd` -> `/lowcmd`,
  `rt/api/sport/request` -> `/api/sport/request`, `rt/dex3/left/cmd` ->
  `/dex3/left/cmd`); their types decode by the SEDP type name
  (`unitree_go::msg::dds_::LowCmd_`, ...). A decoded low-level joint
  command also carries its per-slot frame in `MotionSample::joint`
  (`JointCommandSample`: every slot, the decoder's CRC verdict, the hg
  `mode_pr` / `mode_machine`) for a joint firewall, and
  `MotionOptions::robot_model` interprets Unitree API requests with the
  model's API tables (model-specific ids are otherwise `Unknown`). Every
  SDK2 topic of the decoder's model matrix is exercised by
  `tests/unitree_topics.rs`.
- The event time is the **capture** time the caller passes (the plain
  `process*` methods use nanoseconds since the pipeline was built). The
  INFO_TS source timestamp is exposed in `MotionSample::source_timestamp`
  as a sender claim and never used as time.
- The type that selects the decoder is the one SEDP announced for the
  writer. A writer announced before the sensor started is unknown until it
  is re-announced; its samples are not decoded meanwhile (and samples to a
  known motion reader raise `unattributed_sample`).
- A SEDP dispose does not forget a writer (a spoofed dispose must not blind
  the decoder); the tables are bounded and evict non-motion entries first,
  then motion entries of participants neither profiled nor bound (least
  recently announced first, O(log n)). A motion writer / reader of a
  profiled or bound participant is never evicted: a newcomer that would
  need it gone is refused (`MotionStats::writers_refused` /
  `readers_refused`), so a flood of fresh rogue `cmd_vel` writers cannot
  push out the robot's real writer. Every evicted or refused motion
  endpoint raises `robot.motion.unattributed_sample` (High) naming it.

## Go2 WebRTC sessions (`webrtc`)

`webrtc::WebRtcMonitor` (off by default) classifies the Go2's WebRTC
control sessions from what is readable without the session keys: HTTP
signalling on the robot's ports (the legacy `POST /offer` with a
plaintext SDP, of which only ICE user fragment, fingerprint hash
algorithm, candidates and media kinds are kept; the encrypted
`con_notify` / `con_ing_*` exchange by step only), ICE STUN messages
(username, ICE attributes, FINGERPRINT CRC), TURN methods and
ChannelData, DTLS record headers and SRTP demultiplexing (RFC 7983). One
bounded record per peer, attributed by IP and MAC; findings
`robot.unitree.webrtc_*` (unknown controller, new peer, controller MAC
mismatch, session in a denied window, concurrent sessions, relayed or
non-local session, media without signalling), each naming the flows. It
takes `FlowPacket`s (`decode_ipv4` builds them from an IPv4 packet); the
in-path gateway feeds it from its NFLOG copies. agentd's passive capture
does not feed it yet (its capture is UDP / RTPS-only). Limits are in the
module docs: nothing inside a session is visible, signalling formats come
from community clients, HTTP is read per segment.

## `robodr-ros2-watch`

```sh
# replay a capture
robodr-ros2-watch --profile /etc/robodr/profile.json --pcap lab.pcapng --stats
# live, read-only (Linux, CAP_NET_RAW)
sudo robodr-ros2-watch --profile profile.json --interface lo --interface eth0 --duration 60
# validate the daemon's configuration offline (read-only; exit 1 = invalid)
sudo robodr-ros2-watch --check-config /etc/robodr/pulsar.toml [--strict]
```

- **stdout:** one JSON object per finding, with the fields `rule`,
  `severity`, `detail`, `mode`, `observe_only`, `src_ip`, `profile_model`
  and `profile_status`.
- **stderr:** status messages. With `--stats`, final counters as JSON.
- **Exit codes:** 0 done, 1 runtime error (including a truncated or corrupt
  capture file, after its findings were printed), 2 usage.
- **Other options:**
  - `--domain N`, repeatable, selects the well-known ports to capture.
    RTPS on other ports is still caught by the `RTPS` magic.
  - `--dedup N`
  - `--no-anomalies`
  - `--no-fragmentation`

## Tests

`tests/unitree_topics.rs` (4): every Unitree SDK2 topic of the model matrix
(low-level, arm SDK, user control, hand SDK, Dex3, waist, IMU, sport state,
API) de-mangles, decodes by its SEDP type and maps to a command / feedback
(joint frames carry their slots, CRC verdict, `mode_pr` / `mode_machine`);
model-specific API ids with and without `robot_model`; the legacy UDP path
(off, unknown sender, over envelope, compressed frame, dedup).

`tests/review6_unitree_live_regressions.rs` (10): a compressed `LowCmd`
from an unknown host is Critical, and an `undecodable_sample` flood does not
suppress it; a 5000-address spoofed-source flood gives 16 per-sender and a
few aggregated findings; IP→MAC binding (match, mismatch, unknown,
fragmented); RTPS on a legacy port from a pcap is inspected on both paths;
unknown / feedback / changed types on a profiled command channel are High;
a decoded legacy `LowCmd` carries its joint frame. The config tests also
cover legacy ports inside the DDS port map and `command_senders` tables.

The counts below are from before the motion path; it added 23 tests:
16 in `tests/motion_decode.rs` (Twist on `rt/cmd_vel` from a profiled writer
within / over the envelope, NaN, an unprofiled writer (Critical discovery
rule, commands still decoded), DATA_FRAG-split Twist and Odometry, a
fragmented sample over the cap, big-endian submessage + `CDR_BE` payload,
INFO_TS exposed but not used as time, feedback topics, garbage payloads and
rate limiting, unknown / wrong-role types, never-announced writers to a
motion reader, a spoofed writer from an unbound IP, disabled decode, 3000
mutated datagrams and a GUID spray against bounded tables), 5 unit tests in
`src/motion.rs` and 2 config tests.

There were 73 tests before:

- **55 unit tests.**
- **8 end-to-end tests in `tests/e2e_pcap.rs`.** A generated pcap contains a
  legit participant with `rt/cmd_vel` and `rt/odom` writers, plus a rogue
  participant that beacons SPDP and announces `rt/cmd_vel` over unicast SEDP.
  The tests check:
  - exactly two findings: unknown participant (High) and unauthorized motion
    writer (Critical);
  - dedup across 5 and 200 beacons;
  - observe-only results with an unlocked profile;
  - a refused profile;
  - SEDP split over `DATA_FRAG` and IP fragments, reassembled;
  - an oversized fragmented sample, rejected and reported.
- **4 tests in `tests/rtps_fixtures.rs`.** They run the synthetic
  `robodr-rtps` fixtures, wrapped in a pcap, with expectations derived from
  the golden `.json` files.
- **4 tests in `tests/watch_cli.rs`.** They drive the binary through
  `std::process::Command`.
- **1 test in `tests/config_example.rs`.** It checks that
  `config/robodr.toml.example` keys are known and parse.
- **1 test in `tests/live_capture.rs`.** It catches a rogue SEDP on `lo`
  live. It needs `CAP_NET_RAW` and is otherwise SKIPPED.
- **`tests/real_captures.rs` and `tests/real_captures_lab.rs`.** They run
  real ROS 2 Jazzy captures (`fixtures/captures/ros2-jazzy/`, Fast DDS 2.14
  and Cyclone DDS 0.10, recorded in a container lab): learn a profile from
  one run with `robodr-commission`, replay another run in which every
  process has a new GUID prefix, and catch the rogue `/cmd_vel` publisher;
  a headless Gazebo Harmonic robot (rogue `/cmd_vel`, DATA before SEDP);
  fragmented discovery and a fragmented JointTrajectory (`DATA_FRAG`, both
  vendors); a `rmw_zenoh_cpp` robot reported as a blind spot.

## Limits

- Most tests use synthetic traffic built from the spec. Real traffic is
  limited to the container-lab captures above (Fast DDS and Cyclone DDS on
  ROS 2 Jazzy, a Gazebo simulation; Fast DDS 2.6 on ROS 2 Humble, incl.
  default shared-memory transports and SROS 2; no physical robot); RTI
  Connext has not been captured. On the motion decode path the XCDR1 `Twist` decode is
  confirmed on real Fast DDS and Cyclone DDS samples; XCDR2 / `D_CDR2` and
  the other message types only on hand-built vectors.
- Some traffic is invisible or opaque to it:
  - shared-memory transports (reported per host as
    `robot.capture.unsupported_transport`);
  - RTPS over TCP (reported the same way);
  - DDS-Security-protected discovery (participants and their claimed
    certificate subjects stay visible; `sros2_keystore` judges them, see
    `src/sros2.rs`).

  See `robodr-capture`, `robodr-rtps` and
  [`docs/DDS-TRANSPORTS.md`](../../docs/DDS-TRANSPORTS.md).
- There is no rate limit on *distinct* findings, so a GUID spray yields one
  finding per GUID. Memory stays bounded.
- Dedup is "until evicted": a participant that leaves and rejoins is not
  re-reported.
- Live capture sees what this host sends and receives. The socket does not
  enable promiscuous mode itself; on a sensor box whose capture NIC the OS
  puts in promiscuous mode (mirror / tap port) it sees the mirrored traffic
  of other hosts too. 802.1Q / 802.1ad tags (up to two) are followed.
