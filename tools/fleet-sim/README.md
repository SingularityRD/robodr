# Fleet capacity simulator

Two harnesses measure how the fleet lifecycle (`robodr-enroll`, contract
[`robodr.fleet-api`](../../docs/contracts/robodr.fleet-api.md)) behaves with
many units at once, against the reference SOC of the contract
(`crates/robodr-fleet/tests/common/soc.rs`). Both use **test keys and a
throw-away PKI only**.

| Harness | What runs per unit | Network | Default size |
| --- | --- | --- | --- |
| `tools/fleet-sim/run.sh` | the real `robodr-enroll` binary, one process per step | TLS; loopback, or one network namespace per unit (`--netns`, root) | 50 |
| `cargo test -p robodr-fleet --test fleet_capacity` | the library, one thread per unit at a time | in process (no TLS) | 8 (`ROBODR_FLEET_SIM_UNITS`) |

## What each unit does

`run.sh`: enroll (bulk-issued single-use token) → rotate the uplink key
(overlap, swap) → `rotate --finish` (old key retired at the SOC) →
`check` (TLS, fleet API, key accepted) → `decommission` (every key retired,
receipt). The cargo test also sends a finding-key rotation and cancels it
at the SOC, and verifies every unit's fleet journal afterwards.

Afterwards both check the SOC's invariants: every unit enrolled and
decommissioned; every key registered exactly once (no key id or
fingerprint reused across units); no key left active; no rotation left
open. `run.sh` exits non-zero and keeps its work directory (logs per unit)
when any step or invariant fails.

## Running

```sh
tools/fleet-sim/run.sh                          # 50 units on loopback
sudo tools/fleet-sim/run.sh --units 500 --netns # 500 units, one netns each
ROBODR_FLEET_SIM_UNITS=50 cargo test -p robodr-fleet --test fleet_capacity -- --nocapture
```

`--parallel P` (default 16) bounds how many units run at once; the SOC
serialises its own processing (one lock, like a single database writer), so
the numbers measure the robot side and the protocol, not a production SOC.

## Results (2026-10-31, debug build, 4-core shared VM)

`run.sh --netns --parallel 8`, real binaries, one network namespace per
unit, TLS to the SOC stub:

| Units | enroll p50 / p95 | rotate p50 / p95 | retire p50 / p95 | check p50 / p95 | decommission p50 / p95 | Wall | Invariants |
| --- | --- | --- | --- | --- | --- | --- | --- |
| 50 | 1396 / 1972 ms | 2995 / 3764 ms | 1521 / 2216 ms | 203 / 422 ms | 4768 / 5919 ms | 71 s | pass |
| 500 | 914 / 1915 ms | 1932 / 4017 ms | 1056 / 2336 ms | 163 / 396 ms | 3227 / 6708 ms | 533 s | pass (2000 distinct keys, 0 active, 0 open rotations) |

(The 50-unit run shared the machine with a parallel test run; the 500-unit
run had it for most of the time.)

Per-step time is dominated by key generation, fsync'd state and journal
writes on the unit (each unit is a separate process with its own state
directory, as on a real fleet), and by the units sharing four cores; the
reference SOC keeps everything in memory. Release builds were not measured.

## Not covered here

* 5000 units: the harness takes `--units 5000` (5000 namespaces need
  `net.core` / `fs.file-max` headroom; each unit keeps about 100 KB of
  keys and state); it has not been run on the shared CI machine.
* The AutoSecOps SOC: its capacity (database, concurrency) is not measured
  here. Pointing this harness at it needs the SOC to issue the tokens
  (`fleet_sim_soc` issues them for its own keys) and its fleet public key
  and CA bundle in each unit's directory.
* The black-box anchor receiver at fleet scale: it serves up to 4096 units
  per instance and reloads its unit list while serving
  (`robodr-anchor-receiver(8)`, "Unit-list reload").
