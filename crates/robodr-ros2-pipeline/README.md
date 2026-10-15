# robodr-ros2-pipeline

The Pulsar-independent half of the RoboDR ROS 2 / DDS sensor. Pure crate:
`std`, `robodr-events`, `robodr-rtps`, `robodr-capture`, serde. It builds and
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
| `config` | `Config`, i.e. `[module.robodr-sensor-ros2]` plus the `[...capture]` sub-table, and its validation. Domain id gives the SPDP port. Capture domain ids give the `RtpsPortMap`. Default capture interfaces are `lo` plus the interface of the `/proc/net/route` default route. `CaptureSettings::open` opens the configured source. |
| `socket` | Receive-only SPDP multicast socket. It sets `SO_REUSEADDR` before `bind` and binds to the group address, so it coexists with the robot's DDS participants. |
| `sanitize`, `dedup` | Attacker-controlled text is control-escaped and capped at 512 chars. The dedup set is O(capacity) and stores keyed hashes. |
| `watch` | Argument parsing and run loop for `robodr-ros2-watch`. |

## Findings

| Rule | Severity | When |
|---|---|---|
| the profile's own rules (`robot.ros2.unknown_participant`, `robot.ros2.unauthorized_motion_writer`, `unknown_writer_topic`, `unknown_service`, `unknown_action`, `unknown_reader`, ...) | as `robodr-events` decides | every discovery event, through `Profile::evaluate` |
| `robot.ros2.participant_removed` | Medium | a **profiled** participant is announced disposed or unregistered (`relayed by …` when someone else sent it) |
| `robot.rtps.malformed_discovery` | Low | one per parse-anomaly kind and source IP (`report_anomalies`) |
| `robot.rtps.fragmented_discovery` | Low | one per source IP sending discovery `DATA_FRAG` (`report_fragmentation`) |
| `robot.rtps.discovery_fragment_rejected` | Medium | the reassembler refused fragments: over a cap, bad geometry or conflicting overlap. That announcement was **not** inspected. Always reported. |
| `robot.ros2.profile_refused` | High | once at start, when the profile fails `Profile::validate` |

Each distinct finding (rule + detail) is reported once. Dedup is bounded, so
eviction can only cause a re-report.

### Observe vs enforce, and invalid profiles

| Profile | `profile_status` | Findings |
|---|---|---|
| valid, `locked: true` | `enforcing` | `mode = "enforce"` |
| valid, `locked: false` | `observing` | `mode = "observe"`, description prefixed `[observe-only] ` |
| fails `Profile::validate` (locked or not) | `refused` | errors reported, one `robot.ros2.profile_refused` finding; **observe-only** |

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

## `robodr-ros2-watch`

```sh
# replay a capture
robodr-ros2-watch --profile /etc/robodr/profile.json --pcap lab.pcapng --stats
# live, read-only (Linux, CAP_NET_RAW)
sudo robodr-ros2-watch --profile profile.json --interface lo --interface eth0 --duration 60
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

There are 73 tests:

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

## Limits

- The traffic is synthetic, built from the spec. The pipeline has **not**
  been run against captures from real Fast DDS, Cyclone DDS or Connext.
- Some traffic is invisible or opaque to it:
  - shared-memory transports;
  - RTPS over TCP;
  - DDS-Security-protected discovery.

  See `robodr-capture` and `robodr-rtps`.
- There is no rate limit on *distinct* findings, so a GUID spray yields one
  finding per GUID. Memory stays bounded.
- Dedup is "until evicted": a participant that leaves and rejoins is not
  re-reported.
- Live capture sees what this host sends and receives. It does not use
  promiscuous mode.
