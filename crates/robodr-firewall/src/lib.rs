//! # RoboDR Motion Firewall core
//!
//! The only RoboDR component that sits **in** the control path. Every motion
//! command passes through [`Firewall::check`], which returns a [`Verdict`]:
//! **Passed**, **Limited** (an adjusted command) or **Rejected** (with a safe
//! substitute). This crate is the pure decision core — no I/O, no threads, no
//! clock of its own. The ROS 2 gateway that feeds it comes later.
//!
//! **Not a safety-rated component.** This is a cyber-security control in front
//! of the platform's own safety functions (ISO 10218 / ISO 13849 / IEC 61508
//! scope). The safety PLC and e-stop remain the final authority; the firewall
//! can only reduce, refuse, zero or briefly hold commands — it never originates
//! motion and never overrides the safety system.
//!
//! ## Pipeline
//!
//! ```text
//!  Profile (locked) ─┐
//!  ChannelSpec map  ─┼─ Policy::compile ──► Policy ──► Firewall::new   (allocates, once)
//!  PlatformConfig   ─┘
//!
//!  Command{source:SourceId, channel:ChannelId, stamp, motion} ─► check(cmd, now) ─► Verdict
//!                                                                    │
//!                                       FirewallEvent ring (fixed) ◄─┘ ─► drain_deviations()
//! ```
//!
//! ## Decision table (stages run in order; the first rejection wins)
//!
//! | # | Stage | Condition | Enforcing verdict | Rule |
//! |---|-------|-----------|-------------------|------|
//! | 0 | clock | `now` < previous `now` | Reject `ClockRegression` | `rejected_clock_regression` |
//! | 1 | channel | id not in policy | Reject `UnknownChannel`, **no substitute** | `rejected_unknown_channel` |
//! | 2 | source | `UNKNOWN` / not interned | Reject `UnknownSource` | `rejected_unknown_source` |
//! | 2 | source | known but not allowed on channel | Reject `UnauthorizedSource` | `rejected_unauthorized_source` |
//! | 3 | rate | token bucket of (channel, source) empty | Reject `RateLimited` | `rejected_rate_limited` |
//! | 4 | kind | twist↔joints, or joint count ≠ configured | Reject `KindMismatch` | `rejected_kind_mismatch` |
//! | 5 | values | any NaN / ±inf | Reject `NonFinite` | `rejected_non_finite` |
//! | 6 | time | `stamp > now + max_future` | Reject `FutureTimestamp` | `rejected_future_timestamp` |
//! | 6 | time | `now − stamp > max_age` | Reject `Stale` | `rejected_stale` |
//! | 6 | time | `stamp ≤` last stamp of (channel, source) | Reject `OutOfOrder` | `rejected_out_of_order` |
//! | 7 | hard | any group speed `> hard_factor × limit` | Reject `OverHardLimit` | `rejected_over_hard_limit` |
//! | 8a | speed | any group speed `> limit` | Limit: uniform scale to the limit | `limited_speed` |
//! | 8b | accel | `‖Δv‖ > a_max·dt` | Limit: rate-limit toward target | `limited_acceleration` |
//! | 8b | jerk | `‖Δv‖/dt > ‖a_prev‖ + j_max·dt` | Limit: rate-limit toward target | `limited_jerk` |
//! | 9 | post | output non-finite or over limit (bug) | per [`FaultPolicy`] | `internal_fault` |
//! | — | — | none of the above | Pass (bit-exact) | — |
//!
//! All rule ids are prefixed `robot.firewall.` (see [`rules`]). Rate-limit
//! credit and the per-source last-stamp are consumed/updated at their stage
//! even if a later stage rejects (so a replay of an over-limit command is
//! still a replay).
//!
//! ### Groups and norms
//! A twist has two groups: linear (Euclidean norm, m/s) and angular
//! (Euclidean norm, rad/s). A joint command has one group: the max absolute
//! joint speed. Limits: linear = min(envelope `max_linear_speed`, spec), angular
//! = spec only (the profile envelope has no angular field), joint =
//! min(envelope `max_joint_speed`, spec). `None` = unconstrained.
//!
//! ### Speed limiting (8a)
//! The **whole** command is multiplied by one factor `s = min(limit/‖g‖)`
//! over groups. Direction is preserved, and for a twist the ratio v/ω (path
//! curvature) is preserved too — a turning UGV keeps its turning radius while
//! slowing down. For joints, all joints scale together (joint-space direction
//! preserved, so synchronised motions stay synchronised). A margin of a few
//! ulps guarantees `‖out‖ ≤ limit` exactly despite rounding.
//!
//! ### Acceleration / jerk limiting (8b)
//! With `prev` = the last motion emitted on the channel and `target` the
//! speed-limited command, the output is `prev + λ·(target − prev)` with
//! `λ ∈ [0, 1]` the largest value satisfying, per group,
//! `‖Δ‖ ≤ a_max·dt` and `‖Δ‖/dt ≤ ‖a_prev‖ + j_max·dt`. Consequences:
//! - the output always lies on the segment between two in-envelope points, so
//!   it is in-envelope and never a motion nobody asked for;
//! - "jerk" here bounds the **growth of acceleration magnitude** between
//!   consecutive outputs; it does not bound direction changes of the
//!   acceleration vector (documented simplification);
//! - `dt = min(now − last_emit, dynamics_dt_cap)`, using the gateway's clock,
//!   never the source's stamp (which an attacker controls);
//! - if nothing was emitted for `state_reset_after`, `prev` is taken as zero
//!   (platform assumed at rest; ramp-up is limited from rest);
//! - **stops are never delayed**: a command that moves every component toward
//!   zero without crossing it bypasses 8b unless `limit_deceleration` is set.
//!
//! ### Rejection substitutes ([`FailBehaviour`], per platform)
//! - `ZeroVelocity`: emit an all-zero command of the channel's kind.
//! - `HoldLast { max_hold_ns }`: re-emit the last **accepted** output while it
//!   is younger than `max_hold_ns` (measured from its acceptance, so repeated
//!   rejections cannot extend it), then zero.
//! - `PassThroughObserveOnly`: no enforcement on this platform; behaves like
//!   observe mode.
//!
//! Substitutes carry `source = SourceId::FIREWALL` and `stamp = now`. A
//! rejected command's values are **never** forwarded. With
//! [`ForeignSourceAction::Drop`], rejections caused by an unknown/unauthorised
//! source emit nothing, so a spoofer cannot use the firewall to stop the
//! robot (the default, `Substitute`, prefers the safe state).
//!
//! ### Observe mode
//! When the profile is not locked (or the platform is pass-through), every
//! verdict is `Passed { cmd: original, would_have }` where `would_have` is
//! the limit/reject that enforcement would have produced, and every event is
//! recorded with [`EventAction::ObservedOnly`].
//!
//! ### Firewall failure ([`FaultPolicy`], per platform)
//! Open question in the design doc, so it is configuration: `FailSafe`
//! (**default**) rejects with a zero substitute (never hold — state may be
//! bad); `FailOpen` forwards the original and records the fault. Inside the
//! library a fault is a failed post-condition check (finite, within limits);
//! the gateway should call [`Firewall::fault_verdict`] if it cannot run
//! `check` within its deadline. A gateway **crash** is outside this crate: the
//! platform's command timeout (e.g. a `cmd_vel` watchdog) then applies.
//!
//! ## Determinism
//! `check` performs no heap allocation (proved by `tests/alloc_free.rs` with
//! a counting global allocator), contains no `unwrap`/indexing/unchecked
//! integer arithmetic (enforced by clippy `deny` lints on the engine module)
//! and only bounded loops. See the crate README for measured latency.

mod command;
mod config;
mod engine;
mod events;
mod verdict;

pub use command::{ChannelId, Command, JointVelocities, Motion, SourceId, Twist, Vec3, MAX_JOINTS};
pub use config::{
    ChannelKind, ChannelSpec, ConfigError, FailBehaviour, FaultPolicy, ForeignSourceAction,
    PlatformConfig, Policy, RateLimit, MAX_CHANNELS, MAX_SOURCES,
};
pub use engine::{Firewall, Stats};
pub use events::{reject_rule, rules, EventAction, EventBuffer, FirewallEvent};
pub use verdict::{LimitReasons, RejectReason, Substitute, SubstituteKind, Verdict, WouldHave};

#[cfg(test)]
mod tests;
