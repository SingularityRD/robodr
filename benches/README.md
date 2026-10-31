# robodr-benches

Throughput benchmarks for sizing a RoboDR sensor box and catching
performance regressions (gap T32). Std-only harness, no criterion.

```sh
cargo build --release -p robodr-benches
target/release/robodr-bench                     # full suite, JSON on stdout
target/release/robodr-bench --quick --gate benches/results/baseline-quick.json
cargo bench -p robodr-benches                   # same workloads, in-process
```

`robodr-bench` runs every workload in its own child process so that
`peak_rss_kib` (`VmHWM`) belongs to that workload alone. `--gate BASELINE`
exits 1 when a workload's rate falls below `(1 - tolerance)` of the
baseline's, its peak RSS rises above `(1 + tolerance)` of it, or it dropped
datagrams (`--tolerance`, default 0.3). A baseline is only comparable on the
same host class: record one per CI runner type (`--out`).

## Workloads

**agentd** (`robodr-agentd` end to end: pcap replay -> capture decode -> ROS 2
pipeline -> motion firewall and decision chain -> signed black box ->
findings spool, correlation on). Synthetic graph: `P` participants with `T`
writers each sending 10 Hz samples, the robot's `/cmd_vel` writer at
1 kHz, SPDP beacons every second. The profile is learned from the first 3 s
of the same traffic with `robodr-commission`'s learner, locked and signed, so
a clean run raises nothing. `rogueN` sends N % of the 1 kHz motion commands
from an unknown participant at 3 m/s, so each of those is a finding
(judged, written to the black box, spooled).

The replay is unpaced: the pipeline thread is saturated for the whole run,
so `datagrams_per_s` is its maximum on one core. The input queue is set to
its maximum and each capture is sized to fit (≤ 60 000 datagrams), so a run
drops nothing (`valid: true`); the peak RSS therefore includes a queue
holding most of the capture and is an upper bound for a live sensor. Wall
time includes the daemon's start-up and shutdown (profile check, black-box
open and seal), which weighs on the short runs.

**correlate** (`robodr-correlate` alone, default rules): a mix of nine signal
kinds the default rules join, spread over `groups` distinct sources
(participant, address, process).

## Lab results (2026-10-31)

Host: 4 vCPU Intel Xeon @ 2.10 GHz (shared cloud VM), x86_64, release
build, commit of this change. Raw: `results/full-2026-10-31.json`.
Values are **lab**, one run each, on a shared machine: use them for order of
magnitude, not as a specification.

| Workload | Datagrams in capture | Findings | Datagrams/s (1 core) | × real time | Peak RSS |
|---|---|---|---|---|---|
| 1 participant × 5 topics, 1 kHz motion | 31 568 | 0 | 252 782 | 240 | 29.0 MiB |
| 10 × 5 | 45 392 | 0 | 390 607 | 258 | 32.5 MiB |
| 50 × 5 | 57 118 | 0 | 500 590 | 140 | 35.2 MiB |
| 200 × 5 | 57 207 | 0 | 500 267 | 44 | 35.1 MiB |
| 50 × 20 | 56 307 | 0 | 488 975 | 43 | 37.2 MiB |
| 10 × 5, 1 % rogue motion (10 findings/s) | 45 394 | 297 | 72 298 | 48 | 34.5 MiB |
| 10 × 5, 10 % rogue motion (100 findings/s) | 45 394 | 2 952 | 8 674 | 5.7 | 34.7 MiB |

| Correlation workload | Signals/s | Correlated findings | Pending groups | Peak RSS |
|---|---|---|---|---|
| 1 M signals, 10 sources | 788 043 | 423 | 24 | 4.1 MiB |
| 1 M signals, 1 000 sources | 75 394 | 17 899 | 516 | 4.5 MiB |
| 1 M signals, 100 000 sources | 67 068 | 43 | 516 | 4.5 MiB |

What this says for sizing:

* Clean traffic is cheap: one core keeps up with 250 000-500 000 RTPS
  datagrams/s, 40-250 × the synthetic graphs' real rate. Participant count
  barely moves memory (29 → 37 MiB from 1 to 200 participants, queue
  included).
* **Findings are the cost.** Each finding is judged, signed into the black
  box and spooled: with 100 findings/s the daemon still runs 5.7 × real
  time, so its ceiling on this host is roughly 500-600 findings/s. A flood
  above that is shed by the input queue (counted, reported as
  `robot.agent.queue_overflow`) and by the per-rule rate limits; size the
  box for the attack, not for the clean graph.
* The correlation engine slows tenfold once its group table is full (516
  pending groups, `Limits`): the O(groups) sweep on a full table
  (`crates/robodr-correlate/README.md`). 67 000 signals/s is still far above
  the daemon's finding ceiling, so it is not the bottleneck.

Not measured here: live `AF_PACKET` capture cost (kernel ring, copies), arm64
boards, Unitree DDS `LowCmd` at 500 Hz with 20-35 motors, and the exporters
(`robodr-kafka-publish`, `robodr-uplink`). The lab measurements in
`tools/e2e/RESULTS.md` (live capture, 1.9 % CPU / ~12 MiB) cover part of the
first.
