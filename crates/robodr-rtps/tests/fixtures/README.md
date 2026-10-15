# RTPS fixtures — SYNTHETIC

**Every `.bin` file in this directory is synthetic.** None of them was captured
from a running DDS stack. They were built byte by byte by the generator in
[`../common/mod.rs`](../common/mod.rs) from the OMG DDSI-RTPS 2.3 specification
(§8.3, §9.4, §9.6) and from the field values Fast DDS 2.x / Cyclone DDS 0.10
use for ROS 2 Humble discovery. They are *protocol-faithful* (valid header,
submessage framing, encapsulation, parameter lists, CDR strings, locators) but
not *vendor-exact*: real stacks order parameters differently, add more
vendor-specific PIDs (0x8000+), fragment large announcements (DATA_FRAG), and
send SEDP unicast with INFO_DST/INFO_REPLY combinations not modelled here.

**Real captures must replace or augment them.** Sprint 1, E2 stands up Gazebo +
turtlebot3 on ROS 2 and captures SPDP/SEDP traffic (see `docs/SPRINTS.md`).
When those exist, extract each UDP payload into `<vendor>_<what>.bin` here,
bless its `.json` (below), review it by hand, and keep the synthetic files only
for the cases the captures do not cover (big-endian, inline QoS, ...).

Each file is one RTPS datagram (UDP payload, starting with `RTPS`). The parser
is fed `src_ip = "192.168.10.21"`.

| File | Bytes | Construction | Expected events (current parser) |
|---|---|---|---|
| `fastdds_spdp_participant.bin` | 224 | header (v2.3, vendor `01 0f`, prefix `010f3a7c2104000001000000`) · INFO_TS · DATA readerId `000100c7` writerId `000100c2`, `PL_CDR_LE`: PROTOCOL_VERSION, VENDORID, PARTICIPANT_GUID, metatraffic unicast 192.168.10.21:7410, metatraffic multicast 239.255.0.1:7400, default unicast :7411, LEASE_DURATION 20 s, BUILTIN_ENDPOINT_SET `0xc3f`, USER_DATA `"enclave=/;"` | participant |
| `cyclonedds_spdp_participant.bin` | 300 | header (vendor `01 10`, prefix `01105e2b9c41a7d38e6f1c22`) · INFO_TS · DATA readerId unknown, writerId `000100c2`: DOMAIN_ID 0, the SPDP set above (192.168.10.22), empty ENTITY_NAME, vendor PID `0x8007` (version info) | participant |
| `sedp_pub_cmd_vel.bin` | 236 | Fast DDS header · INFO_DST (Cyclone prefix) · INFO_TS · DATA `000003c7`/`000003c2` SN 3: ENDPOINT_GUID (`…00001203`), PARTICIPANT_GUID, TOPIC_NAME `rt/cmd_vel`, TYPE_NAME `geometry_msgs::msg::dds_::Twist_`, RELIABILITY reliable, DURABILITY volatile, UNICAST_LOCATOR | participant + writer `rt/cmd_vel` |
| `sedp_sub_odom.bin` | 252 | Cyclone header · INFO_DST · INFO_TS · DATA flags E\|Q\|D, `000004c7`/`000004c2`, inline QoS KEY_HASH, then `rt/odom` / `nav_msgs::msg::dds_::Odometry_` reader params | participant + reader `rt/odom` |
| `sedp_pub_service_request.bin` | 248 | second Fast DDS participant (prefix `010f3a7c5509…`) · INFO_TS · DATA: `rq/add_two_intsRequest` / `example_interfaces::srv::dds_::AddTwoInts_Request_` | participant + writer `rq/add_two_intsRequest` |
| `sedp_pub_action_feedback.bin` | 488 | Cyclone header · INFO_TS · two DATA: `rt/fibonacci/_action/feedback` (`action_tutorials_interfaces::action::dds_::Fibonacci_FeedbackMessage_`) and `rt/fibonacci/_action/status` (`action_msgs::msg::dds_::GoalStatusArray_`) | participant + 2 writers, in order |
| `sedp_pub_big_endian.bin` | 216 | header vendor `01 01`, prefix `0101c0a80a1700002a110001` · INFO_TS with E=0 · DATA with E=0 (BE lengths/ids) and `PL_CDR_BE` (`00 02`): `rt/scan` / `sensor_msgs::msg::dds_::LaserScan_` | participant + writer `rt/scan` |
| `heartbeat_acknack_only.bin` | 96 | Fast DDS header · INFO_DST · ACKNACK (flags E\|F, SEDP pub reader→writer, base 4, 0 bits, count 2) · HEARTBEAT (first 1, last 3, count 5) | participant only |

The `.json` next to each `.bin` is the golden snapshot used by
`tests/golden_corpus.rs`: the sorted set of `{kind, guid_prefix, topic}`.
Locators, src_ip and type names are deliberately not snapshotted.

## Tests that use these files

- `tests/fixtures.rs` — `.bin` files (and the fuzz seed corpus) are
  byte-identical to the generator; per-fixture assertions on kind, GUID,
  topic and type name; byte-offset spot checks of the documented layout.
- `tests/golden_corpus.rs` — scans this directory, compares each `.bin`
  against its `.json`.
- `tests/mutation_fuzz.rs` — uses the same datagrams as mutation seeds.

## Regenerating / blessing

After an intended change to the generator or the parser:

```sh
ROBODR_BLESS=1 cargo test -p robodr-rtps --test fixtures fixture_files_match_generator
ROBODR_BLESS=1 cargo test -p robodr-rtps --test golden_corpus
git diff crates/robodr-rtps/tests/fixtures fuzz/corpus   # review every change
```

The first command rewrites the `.bin` files and `fuzz/corpus/parse_datagram/seed-*.bin`;
the second rewrites the `.json` snapshots. In the offline sandbox
(`tools/offline-cargo.sh`) the build runs on a copy of the tree, so blessed
files land under `$OFFLINE_WORK/src/...` and must be copied back by hand.
