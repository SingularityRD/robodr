# RoboDR demo kit

One command from a checkout (or an unpacked release) to a robot being
attacked, RoboDR detecting it, and signed findings arriving at a SOC and in
Kafka (gap T28). No robot, no root on the host, no lab network.

```sh
demo/run.sh            # replay demo; prints the SOC viewer URL when the first finding arrives
demo/run.sh --live     # + a live-capturing robot and an attacker: time to detect / to SOC
demo/run.sh --compare  # after a run: RoboDR vs Pulsar-only table
demo/run.sh --clean    # stop everything and delete demo/state (all demo keys)
```

Needs Docker with Compose v2.24+, `curl`, and the release binaries: set
`ROBODR_BIN` to a directory holding them (an unpacked release), or let
`run.sh` build them with cargo from this checkout (`target/release`).
Images: `ubuntu:24.04` and `apache/kafka:3.9.1`, both pinned by digest.

## What happens

| Step | Container | What it shows |
|---|---|---|
| 1 | `robot` | `robodr-commission` learns the model profile of a **real** ROS 2 Jazzy robot from its capture (`fixtures/captures/ros2-jazzy/fastrtps_baseline.pcap`: Fast DDS, a base controller, a teleop at 0.3 m/s), two operators sign it off, an OEM key locks and signs it: the commissioning flow of `docs/OPERATIONS.md`, with fresh demo keys |
| 2 | `robot` | `robodr-attack-sim` merges every scenario into the same traffic: rogue DDS participant, GUID spray, malformed RTPS, the operator's commands rewritten to 3 m/s, Unitree `LowCmd` torque from an unlisted host |
| 3 | `robot` | `robodr-agentd` replays it: profile trust check, detection, signed black box, signed findings in the spool; `robodr-attack-sim score` checks each scenario raised what it must (`demo/state/score.json`) |
| 4 | `soc`, `uplink` | `robodr-uplink` sends the spool to `robodr-demo-soc` over the `robodr.ingest` API; the SOC verifies every batch and every finding signature and shows them at http://127.0.0.1:8080/ |
| 5 | `kafka`, `publisher` | `robodr-kafka-publish` sends a copy to topic `robodr.findings` with the `robodr-finding-sig` header (the SIEM path; `integrations/`) |
| live | `robot-live`, `attacker`, `uplink-live` | a second robot captures live on its interface; the attacker sends the rogue-participant and GUID-spray scenarios with `robodr-attack-sim send` (guarded: `--i-understand`, demo subnet only); time to detect and to SOC are measured on the wall clock |

Read the Kafka topic:

```sh
docker compose -f demo/docker-compose.yml exec kafka /opt/kafka/bin/kafka-console-consumer.sh \
  --bootstrap-server kafka:9092 --topic robodr.findings --from-beginning --property print.headers=true
```

## Measured on 2026-10-31 (lab)

4 vCPU shared cloud VM, release build, Docker 29.9, all containers on one host.

* **Time to first finding at the SOC**: 7-8 s from `demo/run.sh` (binaries
  already built; the first image pull adds its own time). Target: < 10 min.
* **Replay**: all five scenarios pass their expected rule ids
  (`demo/state/score.json`); 1 456 signed findings (most are the 600 LowCmd
  frames, each judged) reach the SOC, all signature-verified.
* **Live, time to detect** (attacker's first send → finding persisted in the
  robot's spool, `robodr-attack-sim score --injected-at-ms`):
  rogue participant 1-5 ms, GUID spray 0 ms (first unknown participant) and
  13-14 ms (discovery flood aggregate).
* **Live, time to SOC** (finding's detection time `ocsf.time` → arrival at
  the SOC, uplink polling every 200 ms): p50 34 ms, p90 43 ms, p99 161 ms
  over 17 findings. The replay robot's backlog of 1 456 findings arrived
  with p50 4.7 s (1 000-line batches every second): that is the uplink's
  batching under a burst, not detection.

These are single runs on one shared host with no network between robot and
SOC; a site's numbers depend on the uplink interval and the network. The
live time to detect is measured to the spool file's modification time (the
black-box record is written before it).

## RoboDR vs Pulsar-only

`demo/run.sh --compare` replays every scenario from two attacker placements
(a new host; the operator's own, compromised host) and prints the table in
`tools/e2e/COMPARISON-pulsar-only.md`: RoboDR detected 10/10; a Pulsar-only
deployment could at best flag 4/10, and then only as "a datagram from an
unknown address" or "a short datagram". Method and limits are in
`tools/e2e/compare_pulsar_only.py`.

## Not in the demo

* The in-path gateway (`robodr-firewall-gw`): it needs network namespaces and
  nftables on the host and is being reworked (docs/SALES-READINESS.md WP11).
* Host-side detections (Pulsar on a real kernel, T27) and the correlation of
  host and network signals.
* TLS between robot and SOC: the demo SOC speaks plain HTTP on loopback
  inside its container; a real SOC uses the TLS ingest endpoint.
* Everything runs as root in containers with demo keys in `demo/state`.
  Never reuse them.
