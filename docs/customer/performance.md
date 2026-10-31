# Performance data sheet

> **Pre-release draft (2026-10-30). Every number on this page is a LAB
> value**, measured on a shared development VM without a real-time kernel,
> with lab captures and synthetic traffic. **None was measured on a robot,
> a sensor box, a Jetson or an RT kernel, and none is a budget or a
> guarantee.** The GA targets at the end are open until they are measured
> on target hardware. Sources: [`tools/e2e/RESULTS.md`](../../tools/e2e/RESULTS.md),
> [`crates/robodr-firewall-gw/README.md`](../../crates/robodr-firewall-gw/README.md)
> "Latency", [`crates/robodr-firewall/README.md`](../../crates/robodr-firewall/README.md)
> "Latency and jitter harness".

## Measurements and their environments

| Id | What | Date | Source revision | Environment |
|---|---|---|---|---|
| **S** | 2-hour soak of the full robot-side stack with a SOC client and Kafka export | 2026-10-30, 7201 s | `1356263` (wave-2 integration head), release build, rustc 1.98.1 | One VM, 4 vCPU, 16 GB RAM, kernel 6.18.44, no RT kernel, **shared with another CPU-heavy workload** (CPU pressure PSI "some" avg60: mean 9.3 %, max 61 %; hypervisor steal). ROS 2: the Gazebo lab capture replayed at 1x on veth pairs. Unitree / trajectory traffic: synthetic. |
| **G** | Inline gateway decision path and end-to-end latency through the kernel | 2026-10-26 | not recorded | 4-vCPU VM (Intel Xeon), release build, no RT kernel, no CPU pinning, load average 5–20 from other work |
| **F** | Motion Firewall decision core (library) | 2026-10-16 (twist), 2026-10-25 (joint frames) | not recorded | 2-vCPU VM, Intel Xeon @ 2.80 GHz (twist); 4-vCPU VM, Intel Xeon @ 2.10 GHz, shared (joint) |
| **D** | Secure delivery through the shipped agent binary (swtpm) | 2026-10-30 | `1356263` | same VM as S |
| **A** | AutoSecOps ingest benchmark (SOC side) | before 2026-10-26 | AutoSecOps `09133dc0` | loaded 4-vCPU VM |

## Resources per process (S, lab)

| Process | RSS first → last (max) | RSS slope, 2nd hour | CPU mean (max) | Open fds |
|---|---|---|---|---|
| `robodr-agentd` | 11.0 → 11.9 MiB (22.8 MiB) | +1.3 MiB/h, sawtooth (below) | **1.9 %** (2.6 %) | 15 → 15 |
| `robodr-firewall-gw` | 4.1 → 4.2 MiB (4.2) | +0.04 MiB/h | 4.7 % (6.3 %) | 7 → 7 |
| `robodr-executor` | 4.0 → 4.3 MiB (4.3) | +0.1 MiB/h | 0.3 % | 4 → 4 |
| `robodr-anchor-receiver` (off-robot) | 3.9 → 3.9 MiB | 0 | 0.4 % | 5 → 5 |
| `robodr-kafka-publish` | 5.8 → 6.0 MiB | +0.1 MiB/h | 0.04 % | 5 → 4 |
| `robodr-deliverd` (D) | 7.9 → 8.0 MB over 11 min | — | not recorded | — |

CPU is a percentage of one core. agentd's baseline stayed at 11.6–11.9 MiB;
its maximum follows the SOC's evidence inventory, which indexes the
retained black box and returns to baseline within minutes (bounded by the
default 8 × 8 MiB retention). No crash, restart, panic or leak in 2 hours.

Load in S: 377,993 ROS 2 datagrams inspected live (about 52 per second,
the rate of the replayed capture) and 249,503 motion events; through the
gateway 3,623,018 packets (LowCmd at 500 Hz, sport `Move`, a joint
trajectory every second). **This is not a throughput limit**: the
maximum datagram rate per core has not been measured.

## Latency (lab)

| Path | p50 | p99 | Tail | Id |
|---|---|---|---|---|
| Gateway: receive → verdict, in the soak | 53 µs | **129 µs** | max 133 ms | S |
| Gateway: LowCmd 500 Hz send → receive across the bridge | 166 µs | 1.7 ms | p99.9 135 ms, max 1.18 s; per-minute p99 median 1.07 ms, above 5 ms in 5 of 120 minutes | S |
| Gateway decision path, G1 35 motors at 1 kHz, paced | 10.2–13.8 µs | 35–36 µs | p99.9 57 µs–0.36 ms | G |
| Gateway decision path, Go2 20 motors at 1 kHz, paced | 9.3–11.4 µs | 30–35 µs | p99.9 37 µs–0.97 ms | G |
| Gateway added end-to-end latency through the kernel (1 kHz) | ≈ 20–70 µs added to the median | not measurable on this VM (the baseline itself reaches ms tails) | — | G |
| Motion Firewall joint check, 35 slots at 1 kHz, paced | 3.2–3.4 µs | 7.2–9.1 µs | p99.9 39–74 µs | F |
| Motion Firewall, mixed command stream (twists and 6-joint commands, 1 kHz) | 180–200 ns | 470–550 ns | p99.9 0.8–3.5 µs | F |
| Control-plane robot snapshot (SOC client, mutual TLS, loopback) | 32 ms | — | max 77 ms (119 of 120 OK) | S |
| SOC `restrict_motion` to the gateway showing it | within 5 s (the adapter's verification window) | — | — | S |
| AutoSecOps ingest, 1000-line batch | — | p95 ≈ 1.27 s | — | A |

The tails are the shared VM's. In S the gateway read 0.46 % of LowCmd
frames more than its 5 ms queue-delay bound after arrival and gave them the
fail-safe verdict (then reported as a Critical
`robot.firewall.internal_fault` per burst; the gateway now reports late
packets as `robot.gateway.overload`, at most once per interval):
the designed behaviour of an overloaded box, which must be re-measured on
a sensor box with an RT kernel.

## Detection and delivery (S, D)

| Measured | Result |
|---|---|
| Rogue ROS 2 participant injected every ~10 min (11 times) | detected 11 / 11 (`robot.correlate.motion_hijack`, with the unknown-source and envelope findings) |
| Gateway injections (torque over limit, overshooting trajectory, foreign LowCmd writer), 11 rounds | each limited or refused; no foreign LowCmd reached the robot |
| Findings spooled → delivered to Kafka over mutual TLS | 2,946 → 2,946; 0 write errors, 0 dropped, 0 dead-lettered |
| Black box after 2 hours | 8,408 records, 9.4 MB, verifies `INTACT, CLEAN`; remote anchor held the last record |
| Spool volume | 2,946 findings, 20.4 MB (about 7 KB per finding) |
| Secure delivery: time to installed (D) | 2.3 s for the first release, then 58–62 s (the agent polls once a minute) |
| Crypto-erase after the robot reached `idle` (D) | 0.35 s |
| **Time from attack to finding, and to the SOC** | **not measured yet** |

## What these numbers do not show

- **False-positive rate.** The clean-traffic finding rate in S (858 per
  hour) was almost entirely the gateway's late-packet verdicts caused by
  this overloaded host, plus one defect fixed during the run; agentd's own
  detectors raised nothing on clean traffic that the replay loop or a host
  stall does not explain. A false-positive rate needs a real robot on a
  real-time host.
- Anything on arm64, a Jetson, a robot, a sensor box or an RT kernel.
- More than 2 hours (the GA soak is 72 hours).
- Throughput limits, and memory as a function of the number of
  participants and topics.

## GA targets and status

| Target (GA-ROADMAP, Sprint 11 / Sprint 8) | Lab value | Status |
|---|---|---|
| agentd CPU < 5 % on the robot | 1.9 % mean (S) | **Open**: not measured on target hardware |
| agentd RSS < 150 MB on the robot | 11.9 MiB baseline, 22.8 MiB max (S) | **Open**: not measured on target hardware |
| Gateway added latency p99 < 1 ms | decision p99 35 µs (G), receive → verdict p99 129 µs (S); end-to-end p99 not measurable on the VM | **Open**: to be measured on the sensor box (RT kernel, pinned core) with `gw_latency --budget-p99-ns` and `tests/netns_e2e.rs` |
| False positives < 1 per robot per day | not measured | **Open** |
| 72-hour soak without data loss or leak | 2 hours, no loss, no leak (S) | **Open** |
| Time to detect and time to SOC | not measured | **Open** |

## Re-running the measurements

On your own sensor box or robot computer, before relying on any number
above:

```sh
# gateway decision path, with a p99 budget gate (exit 1 when exceeded)
cargo run --release -p robodr-firewall-gw --example gw_latency -- --budget-p99-ns 1000000
# Motion Firewall core
cargo run --release -p robodr-firewall --example latency
cargo run --release -p robodr-firewall --example joint_latency
# the soak: tools/e2e/RESULTS.md, "Re-running"
```

Report the hardware, kernel (and whether it is RT), CPU pinning, load and
source revision with every figure.
