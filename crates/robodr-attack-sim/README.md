# robodr-attack-sim

Attack scenarios for RoboDR proofs of concept and demos (gap T30). It
packages the network red-team scenarios of `tools/e2e/redteam_net.py` as a
std-only binary that needs no root, no network namespaces and no lab: it
produces a capture to replay, or (guarded) sends datagrams to one lab target,
and scores what RoboDR reported against what each scenario must produce.

## Scenarios

| Scenario | What it does | Must produce (verified, `tests/agentd_e2e.rs`) | Also seen in the lab profile |
|---|---|---|---|
| `rogue-participant` | an SPDP announcement cloned from the carrier with a new GUID prefix, from `--attacker-ip` | `robot.ros2.unknown_participant` | |
| `guid-spray` | `--count` SPDP announcements, each with a random GUID prefix, at `--rate` | `robot.ros2.unknown_participant`, `robot.ros2.discovery_flood` | |
| `malformed-rtps` | truncated headers, a first submessage length past the datagram, random bodies, mutated bytes, 60 KiB IP-fragmented datagrams and one never completed | `robot.rtps.malformed_discovery` | `robot.rtps.discovery_not_inspected`, `robot.ros2.participant_source_mismatch`, `robot.ros2.discovery_flood` |
| `cmd-vel-envelope` | the authorised operator's `geometry_msgs/Twist` commands rewritten to `--speed` (a spoofed, otherwise legitimate writer) | `robot.motion.linear_over_envelope` | `robot.firewall.rejected_over_hard_limit` |
| `lowcmd-torque` | Unitree legacy-UDP `LowCmd` (v3.8.6 compressed, valid CRC) from an unlisted host, `--torque` N·m on one joint | `robot.unitree.legacy_unknown_sender` | `robot.motion.unprofiled_channel`, `robot.firewall.rejected_unknown_channel` (profile without a LowCmd channel) |

"Must produce" is what `score` checks; it holds for any locked profile. The
last column depends on the profile and firewall configuration.
`robodr-attack-sim list --json` prints the table for scripts.

The end-to-end test learns a profile from the real Fast DDS capture
`fixtures/captures/ros2-jazzy/fastrtps_baseline.pcap`, merges each scenario
into the same capture, replays it through `robodr-agentd`, validates every
spooled finding and scores it; it also checks that the clean capture raises
none of the expected ids.

## Offline (default): a capture to replay

```sh
robodr-attack-sim pcap --scenario all \
    --carrier fixtures/captures/ros2-jazzy/fastrtps_baseline.pcap --out attack.pcap
# agentd.json: "sensor": {"capture": {"enabled": true, "pcap_replay": "/path/attack.pcap"}, ...}
robodr-attack-sim score --scenario all --findings /var/lib/robodr/spool/agentd
```

The carrier is the robot's normal traffic (pcap or pcapng, Ethernet): the
rogue and spray scenarios clone its SPDP announcements, `cmd-vel-envelope`
rewrites its Twist samples. Several scenarios run one after another,
`--stagger` seconds apart, from `--at` seconds after the carrier's first
frame (`cmd-vel-envelope` rewrites from `--at` on). Randomness is seeded
(`--seed`): the same arguments give the same bytes.

## Live: guarded

```sh
robodr-attack-sim send --scenario rogue-participant \
    --carrier baseline.pcap --target 239.255.0.1 --allow 239.255.0.1/32 --i-understand
```

A live send is refused unless **all** hold:

* `--i-understand` is given. The robot must be safe-stopped or on a test
  stand: `cmd-vel-envelope` and `lowcmd-torque` are motion commands a robot
  without RoboDR's gateway in the path would execute.
* the target is inside an `--allow` CIDR, each /16 or narrower;
* the target is private (RFC 1918), loopback, link-local or 239/8
  multicast. Public, broadcast and unspecified addresses are refused
  whatever `--allow` says.

The sender uses ordinary UDP sockets: no raw frames, no spoofed source
address (the scenario's `--attacker-ip` is what the robot sees only in the
offline mode), multicast TTL 1, and only the scenario's own datagrams (never
the carrier). Pre-fragmented frames of `malformed-rtps` are skipped.

`send` prints `first_send_unix_ms`. Pass it to `score --injected-at-ms` with
the spool directory to get the **time to detect** per rule (spool file time
minus injection time; T64). For the time to the SOC, see `demo/` (the demo
SOC records arrival times).

## Scoring

`score` reads an agentd spool directory or an NDJSON file of findings (as
the SOC or SIEM received them) and matches `entity_context.rule_id`. The JSON
report lists, per scenario, each expected rule's count, first spool time and
time to detect, plus every other rule id seen. Exit 0 when every expected
rule was seen, 1 otherwise.

## Not covered

* Live sends cannot spoof the source address or GUID-owner's address;
  scenarios that depend on it (`cmd-vel-envelope` from the operator's
  address) are exact only offline. Raw-frame sending (as `rtlib.py` does in
  a network namespace) stays in `tools/e2e`.
* Not packaged in the `.deb` / `.rpm` yet (`packaging/build-deb.sh` belongs
  to the packaging work package).
* Host-side scenarios (`tools/e2e/redteam2.sh`: shell, key reads, service
  tampering) need the Pulsar sensor on a real host and are not in this tool.
