# robodr-firewall — Motion Firewall core

The Motion Firewall is the only RoboDR component in the robot's control path.
Every motion command goes through `Firewall::check(&mut self, cmd, now) -> Verdict`
and comes out as one of three verdicts:

- **Passed**: the original command, unchanged down to the bit.
- **Limited**: the same command with its motion reduced.
- **Rejected**: the command is not forwarded. A safe substitute is emitted in its place, or nothing at all.

The command is checked against the locked model envelope and the set of sources
allowed on its channel.

This crate is only the **pure decision core**. It does no I/O, starts no threads and
has no clock of its own. The ROS 2 gateway that subscribes to commands, resolves
DDS writer GUIDs and republishes verdicts is a later step (see "Integration" below).

> **Not a safety-rated component.** This is a cyber-security control. It does not
> implement and does not replace any safety function under ISO 10218, ISO 13849 or
> IEC 61508. The platform's safety PLC and e-stop remain the final authority. The
> firewall can only pass, reduce, refuse, zero or briefly hold commands. It never
> originates motion and never overrides the safety system, which keeps it within
> RoboDR's protective scope.

## Design

```
 Profile (locked)  ─┐
 ChannelSpec map   ─┼─ Policy::compile ─► Policy ─► Firewall::new        (validates, interns, allocates — once)
 PlatformConfig    ─┘
 Command{SourceId, ChannelId, stamp_ns, Motion} ─► check(cmd, now) ─► Verdict   (no alloc, no panic, bounded)
                                                      └─► FirewallEvent → fixed buffer ─► drain_deviations()
```

- **Own command type.** A `Command` holds either a `Twist` (linear and angular
  `Vec3`) or `JointVelocities`, a fixed `[f64; 32]` plus a length. It contains no
  `Vec` and no `String`, and it is `Copy`.
- **Interned identity.** Endpoint GUIDs and channel names are turned into
  `SourceId(u16)` and `ChannelId(u16)` when the policy is compiled. The hot path
  only compares integers and tests a 256-bit allow-set per channel. Each allowed
  GUID must belong to a participant in the profile; otherwise compilation fails.
- **Policy compilation fails closed.** Compilation stops with an error in any of
  these cases:
  - a profiled motion channel has no spec, or a spec names a channel the profile doesn't have;
  - a limit is NaN or negative;
  - a hard factor is below 1 or not finite;
  - a channel has no allowed source;
  - a GUID is malformed or not in the profile;
  - a rate limit is zero.

  Limits in the per-channel spec can only **tighten** the envelope. The angular
  limit comes only from the spec, because `Envelope` has no angular field.
- **Events without allocation.** `Deviation` holds a `String`, so `check` never
  builds one. Instead it writes a `Copy` `FirewallEvent` into a fixed-capacity
  buffer. The caller drains the buffer outside the control loop.
  `drain_deviations()` calls `Deviation::new` there, and if any events were lost
  it adds a `robot.firewall.events_dropped` deviation whose severity is at least
  Medium and as high as the worst event lost.
- **Flood-resistant event retention.** A spoofer can cause one event per packet, so
  the buffer (rev3 finding 4):
  - **coalesces** identical events (same rule, channel, source, action) into one
    record with a `count`, first/last time and the worst value;
  - **reserves capacity by source class**: events whose source is not authorised
    on the channel (`authorised == false`) may fill at most half the buffer;
  - when full, **evicts by priority** (severity, then authorised over not), the
    oldest of the lowest first, and only for a strictly higher-priority event.
    A pending Critical from an authorised source is therefore never evicted, and
    never in favour of an unknown-source event.

  All of this is allocation-free and bounded: one scan of the buffer per event,
  so `event_capacity` should stay in the hundreds.

## Decision semantics

The stages run in order and the first rejection wins. All rules are prefixed `robot.firewall.`.

| # | Stage | Condition | Enforcing verdict | Rule (severity) |
|---|---|---|---|---|
| 0 | clock | `now` < previous `now` | Reject | `rejected_clock_regression` (High) |
| 1 | channel | unknown id | Reject, **no substitute** | `rejected_unknown_channel` (High) |
| 2 | source | unknown / `SourceId::UNKNOWN` | Reject | `rejected_unknown_source` (Critical) |
| 2 | source | known, not allowed on channel | Reject | `rejected_unauthorized_source` (Critical) |
| 3 | rate | token bucket per (channel, source) empty | Reject | `rejected_rate_limited` (High) |
| 4 | kind | twist↔joints or wrong joint count | Reject | `rejected_kind_mismatch` (High) |
| 5 | values | NaN / ±inf anywhere | Reject | `rejected_non_finite` (Critical) |
| 6 | time | `stamp > now + max_future` (10 ms) | Reject | `rejected_future_timestamp` (High) |
| 6 | time | `now − stamp > max_age` (200 ms) | Reject | `rejected_stale` (Medium) |
| 6 | time | `stamp ≤` last stamp of (channel, source) | Reject | `rejected_out_of_order` (High) |
| 7 | hard | speed `> hard_factor × limit` (2×) | Reject | `rejected_over_hard_limit` (Critical) |
| 8a | speed | speed `> limit` | Limit: uniform scale | `limited_speed` (High) |
| 8b | accel | `‖Δv‖ > a_max·dt` | Limit: rate-limit | `limited_acceleration` (Medium) |
| 8b | jerk | `‖Δv‖/dt > ‖a_prev‖ + j_max·dt` | Limit: rate-limit | `limited_jerk` (Medium) |
| 9 | post | output non-finite / over limit (a bug) | per `FaultPolicy` | `internal_fault` (Critical) |

How speed is measured:

- **Twist commands:** two groups, linear (Euclidean norm) and angular (Euclidean norm).
- **Joint commands:** one group, the maximum absolute joint speed.

The limiting rules:

- **Speed (8a).** The whole command is multiplied by one factor, `min(limit/‖g‖)`
  over the groups. This keeps the direction. For a twist it also keeps v/ω, so a
  turning UGV keeps its turning radius. All joints scale together, so joint-space
  direction is kept too. A margin of a few ulps makes `‖out‖ ≤ limit` hold exactly
  despite rounding.
- **Acceleration and jerk (8b).** The output is `prev + λ·(target − prev)`, with
  `λ ∈ [0,1]`. Here `prev` is what was last emitted on the channel and `target` is
  the speed-limited command. As a result, the output lies on a segment between two
  in-envelope points: it stays inside the envelope and is never motion nobody asked for.
- **Clock for `dt`.** `dt` is measured on the gateway's clock and capped at
  `dynamics_dt_cap` (100 ms). The source's stamp is never used for this, because an
  attacker controls it. After `state_reset_after` (500 ms) with no output, the
  firewall assumes the platform is at rest.
- **Jerk is simplified.** "Jerk" here limits how fast the acceleration
  *magnitude* may grow. It does not limit changes in the direction of acceleration.
- **Stops are never delayed.** A command that moves every component toward zero
  without crossing it skips 8b, unless `limit_deceleration` is set. A reversal is
  not counted as a deceleration.

Rejection substitutes, set per platform by `FailBehaviour`:

- **`ZeroVelocity`** (default): emit an all-zero command of the channel's kind.
- **`HoldLast { max_hold_ns }`**: re-emit the last **accepted** output while it is
  younger than `max_hold_ns`, then emit zero. The age is measured from when that
  output was accepted, so a run of rejections cannot stretch the hold. The hold is
  only granted if it is a component-wise deceleration of the rejected command
  (own source, readable content), and it is **never more than what was last
  emitted downstream** (rev3 finding 2): the accepted output is scaled down to a
  deceleration of the last emission, so after a zero substitute every further
  hold is zero and the output can only rise again through accepted, acceleration
  limited commands. No hold is granted if the last emission is older than the
  channel's `state_reset_after_ns`, nor under a gateway clock regression (rev3
  finding 3: the hold age cannot be measured then), so zero is emitted.
- **`PassThroughObserveOnly`**: no enforcement on this platform. It behaves exactly
  like observe mode. Limiting is switched off as well, so a 1.5× command is never
  treated more strictly than a 3× one.

A substitute always carries `source = SourceId::FIREWALL` and `stamp = now`.
**A rejected command's values are never forwarded.**

`ForeignSourceAction` controls what happens when the source is unknown or not authorised:

- **`Substitute`** (default) emits the substitute. This favours the safe state, but
  it means a spoofer can stop the robot (denial of service).
- **`Drop`** emits nothing. The legitimate stream keeps control and the attempt is still recorded.

**Observe mode.** Observe mode applies when the profile is not locked, or when the
platform is set to pass-through. Every verdict is then
`Passed { cmd: original, would_have }`, where `would_have` is the limit or reject
that enforcement would have produced. Events are recorded with `EventAction::ObservedOnly`.

**When the firewall itself fails (`FaultPolicy`).** The design document leaves this
as an open question: *"Hareket Güvenlik Duvarı arızasında varsayılan davranış ne
olmalı?"* ("What should the default behaviour be when the Motion Firewall fails?").
It assigns the decision to the OEM per robot model, so it is configuration here and
we do not decide it silently.

- **Default: `FailSafe`.** Reject and emit **zero**. The firewall never holds in
  this case, because its state may be bad.
- **`FailOpen`.** Forward the original command and record the fault. This is meant
  for platforms whose safety case says an unexpected stop is the greater hazard.

Inside the library, a fault means the post-condition check failed. The gateway
should call `Firewall::fault_verdict` when it cannot run `check` before its
deadline. If the gateway **crashes**, the decision is outside this crate and the
platform's own command timeout (for example a `cmd_vel` watchdog) applies. The
gateway must be deployed so that this timeout exists.

## Invariants (and where they are verified)

| Invariant | Verified by |
|---|---|
| Emitted output is always finite and within every speed limit (independent naive norm) | `tests/properties.rs` (24 random configs × 20 000 commands, NaN/inf/`f64::MAX`/subnormals/replays/stale/future/foreign sources) |
| `Passed` (enforcing) is bit-exact and has no `would_have` | properties, decision table |
| A rejection never forwards the rejected values: the substitute is zero or exactly the last accepted output | properties |
| A hold never exceeds the last emitted output, so the emitted stream never steps up past the acceleration limit; no hold under clock regression | properties, `tests/rev3_regressions.rs` |
| A foreign-source flood cannot evict an authorised source's Critical event; floods coalesce; drop reports carry the worst lost severity | `tests/rev3_regressions.rs`, `events::tests` |
| Unknown source, non-finite, stale or future commands never pass or get limited | properties, decision table |
| The output stays inside the hull of {previous output, 0, input}, so it is never motion nobody asked for | properties |
| The acceleration bound holds for every accepted step except pure decelerations | properties (a mutation that loosens λ fails the test) |
| Speed scaling is one common factor and keeps direction and curvature | `randomized_scaling_preserves_direction`, `joints_scaled_together` |
| Observe mode always forwards the input bit-exact (including NaN payloads) | `randomized_observe_mode_always_passes_input` |
| Every row of the decision table, the boundaries (`=` vs `+1`) and the stage order | `tests/decision_table.rs` (47 tests) |
| Exact token-bucket, acceleration-ramp and jerk-ramp maths | decision table |
| Fail-safe and fail-open fault handling (via injected faults) | `src/tests.rs` |
| **No heap allocation in `check`, `fault_verdict` or `drain_events`** after construction, across all paths, all fail behaviours, observe mode and a full event buffer | `tests/alloc_free.rs`: a counting `GlobalAlloc` with a thread-local counter, plus a check that the counter does see real allocations |
| No `unwrap`/`expect`/`panic!`/slice indexing/unchecked integer arithmetic in hot-path modules | `#![deny(clippy::{unwrap_used, expect_used, panic, indexing_slicing, arithmetic_side_effects})]` on `engine`, `command`, `events`, `verdict`; confirmed to fire on a deliberate probe |
| Policy compilation rejects every class of malformed config | `config::tests` |

Total: 99 tests. Every loop in `check` runs over at most `MAX_JOINTS` (32)
elements or a constant 4 rounds. There is no recursion and no search over sources.

## Latency and jitter harness

`examples/latency.rs` is a std-only harness (`Instant`, no external crates):

    cargo run --release -p robodr-firewall --example latency -- [N] \
        [--budget-p50-ns X] [--budget-p99-ns X] [--budget-max-ns X] [--budget-jitter-ns X]

Budgets can also come from `ROBODR_FW_BUDGET_{P50,P99,MAX,JITTER}_NS` (flags win).
It times N (default 10⁶) pre-generated commands one by one and prints p50, p99,
p99.9, max, mean, jitter (p99 − p50), the `Instant` overhead and a log2 histogram,
then one `BUDGET:` line per configured budget. **Exit code 1 if any configured
budget is exceeded**, 2 on a usage error, 0 otherwise.

**Gate status: report-only.** Until the harness runs on the target controller (RT
kernel, pinned core, frequency fixed) the numbers below are not a budget, and CI
must not fail on them: run it without budgets (pure report), or with budgets and
treat a non-zero exit as a warning. Once target hardware exists, set the budgets
from the design doc's control-path allowance and make the exit code blocking.

The command mix:

- a 1 kHz ±50 µs stream, two thirds of it twists on a channel with accel, jerk and rate limits;
- one third joint commands for a 6-joint arm;
- smooth random-walk targets with rare jumps, plus about 7 % rejections (unknown source, NaN, stale, over-hard);
- `HoldLast` fail behaviour, 1024-entry event buffer drained every 512 commands.

The resulting verdicts: about 3 % passed, 91 % limited and 7 % rejected (the
tight angular/jerk limits make most random-walk steps limited, which exercises
the slowest accept path).

Measured 2026-10-16 in the development sandbox: a 2-vCPU VM on an Intel Xeon @ 2.80 GHz, release profile:

| p50 | p99 | p99.9 | max | jitter (p99 − p50) | Timer overhead (`Instant` pair) |
|---|---|---|---|---|---|
| 180–200 ns | 470–550 ns | 0.8–3.5 µs | 12–20 ms (preemption) | 290–350 ns | 19 ns (p50) |

**Machine caveat.** These numbers come from a shared, non-isolated VM with no RT
kernel, no CPU pinning and no frequency control.

- **The tail is the environment, not the algorithm.** The µs–ms outliers
  (fewer than 0.1 % in typical runs) are preemption, page faults and timer interrupts. `check`
  itself has no data-dependent unbounded work.
- **The numbers are not a latency budget for the robot.** The budget (the design
  doc's target is < 1 ms added in the control path) must be measured on the target
  controller, with the gateway, under load, with the firewall on and off. That is
  the Sprint 7 jitter harness; this example is its library-level half (the
  gateway-in-the-loop measurement is still to do).

## Integration (not done here)

- **ROS 2 gateway.** It has to:
  - subscribe on a shadow topic and republish verdict outputs;
  - map RTPS writer GUIDs to `SourceId` once per discovered endpoint, using `SourceId::UNKNOWN` when there is no match;
  - convert header stamps into the same monotonic domain as `now`;
  - call `fault_verdict` on a deadline miss;
  - drain events off the control thread.
- **Platform watchdog.** Make sure a gateway crash leads to the platform's own
  command timeout. This is the fail-safe that sits outside the library.
- **OEM decisions per model.** Choose `FailBehaviour`, `FaultPolicy`,
  `ForeignSourceAction` and the limits per model, and validate them with the OEM.
- **Not verified here.** Behaviour on real hardware, behaviour with a real DDS
  stack, and worst-case latency on the target controller.
