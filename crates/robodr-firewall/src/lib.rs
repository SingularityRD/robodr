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
//! All rule ids are prefixed `robot.firewall.` (see [`rules`]).
//!
//! ### State, and who can change it
//! - **Per (channel, source)**: rate-limit credit and last stamp. Only an
//!   **accepted** command (passed or limited) of that source updates them; a
//!   rejected command — at any stage — changes nothing, so a source cannot
//!   burn its own (or anyone's) credit or advance its stamp with commands
//!   that were refused. Foreign sources have no pair state at all.
//! - **Per channel**: the last *emitted* output and its acceleration (the
//!   base of 8b) and the last accepted output (for `HoldLast`). This is
//!   deliberately per channel, not per source: it describes what the
//!   platform was told to do, and making it per source would let two
//!   authorised sources alternate and step the platform between their
//!   velocities with no acceleration bound. It changes only when something is
//!   actually emitted (an accepted output, or a substitute).
//! - Global: the gateway clock (stage 0).
//!
//! ### Groups and norms
//! A twist has two groups: linear (Euclidean norm, m/s) and angular
//! (Euclidean norm, rad/s). A joint command has one group: the max absolute
//! joint speed. Limits: linear = min(envelope `max_linear_speed`, spec), angular
//! = spec only (the profile envelope has no angular field; required for Twist
//! channels), joint = min(envelope `max_joint_speed`, spec). `None` =
//! unconstrained (except angular on a Twist channel: a compile error).
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
//! A rejected command must never cause more motion than a stop.
//! - `ZeroVelocity`: emit an all-zero command of the channel's kind.
//! - `HoldLast { max_hold_ns }`: re-emit the last **accepted** output while it
//!   is younger than `max_hold_ns` (measured from its acceptance, so repeated
//!   rejections cannot extend it), then zero — and **only** if the rejected
//!   command is readable intent (authorised source, right kind, finite) of
//!   which the held output is a component-wise deceleration (each component
//!   zero, or same sign and no larger). A rejected stop, slow-down or
//!   reversal, unreadable content (NaN, wrong kind) and foreign sources all
//!   get zero. The held value is also never more than what was **last
//!   emitted** downstream (it is the accepted output scaled down, if needed,
//!   to a component-wise deceleration of the last emission; zero if the last
//!   emission was zero or is older than the channel's reset gap), so a hold
//!   can never step the output up past the acceleration limit. Under a
//!   gateway clock regression the hold age cannot be measured, so no hold is
//!   granted.
//! - `PassThroughObserveOnly`: no enforcement on this platform; behaves like
//!   observe mode.
//!
//! Substitutes carry `source = SourceId::FIREWALL` and `stamp = now`. A
//! rejected command's values are **never** forwarded. With
//! [`ForeignSourceAction::Drop`] (**default**), rejections caused by an
//! unknown/unauthorised source emit nothing and touch no state, so a spoofer
//! cannot use the firewall to stop the robot or disturb the legitimate
//! stream; the attempt is still a Critical deviation for the responder. The
//! opt-in `Substitute` emits the substitute at most once per
//! [`PlatformConfig::foreign_substitute_min_interval_ns`] per channel.
//!
//! ### Limits must be finite
//! [`Policy::compile`] runs `Profile::validate` and rejects NaN, infinite or
//! negative limits; "unconstrained" is only expressed by omitting an optional
//! limit (`None`). A Twist channel **must** set `max_angular_speed` (the
//! profile has no angular field, so there is nothing to fall back on).
//!
//! ### Observe mode
//! When the profile is not locked (or the platform is pass-through), every
//! verdict is `Passed { cmd: original, would_have }` where `would_have` is
//! the limit/reject that enforcement would have produced, and every event is
//! recorded with [`EventAction::ObservedOnly`]; the rendered deviations carry
//! `Mode::Observe` (see [`policy_mode`]), so a responder never acts on them.
//!
//! ### Firewall failure ([`FaultPolicy`], per platform)
//! An OEM safety-case decision, so it is configuration: `FailSafe`
//! (**default**) rejects with a zero substitute (never hold — state may be
//! bad), refused for a humanoid joint channel, where `FailHold` applies;
//! `FailOpen` forwards the original and records the fault (also refused for
//! a humanoid joint channel: it would forward an unchecked frame). Inside the
//! library a fault is a failed post-condition check (finite, within limits);
//! the gateway should call [`Firewall::fault_verdict`] if it cannot run
//! `check` within its deadline. A gateway **crash** is outside this crate: the
//! platform's command timeout (e.g. a `cmd_vel` watchdog) then applies.
//!
//! ## Low-level joint frames (Unitree `LowCmd` style)
//!
//! A second entry point, [`Firewall::check_joint`], decides on
//! [`JointCommand`]s: a fixed-capacity [`JointFrame`] of up to
//! [`MAX_MOTORS`] (35) motor slots, each with a position target `q`, a
//! velocity target `dq`, a feed-forward torque `tau`, gains `kp` / `kd` and
//! an enable [`MotorMode`], plus the decoder's CRC verdict. Such channels
//! are configured with a [`JointChannelSpec`] (a per-slot envelope:
//! position range, `|dq|` / `|tau|` bounds, gain ranges, step bounds
//! relative to the previous accepted target, enabled flag; CRC requirement,
//! required rate window, staleness deadline, optional `mode_pr` /
//! `mode_machine` pins) and compiled with
//! [`Policy::compile_with_joints`] (or [`FirewallConfig`] from JSON). They
//! share the firewall's sources, clock, statistics and event buffer, and get
//! the channel ids after the twist / joint-velocity channels, so existing ids
//! never change. The verdict ([`JointVerdict`]) has the same three shapes:
//! pass (bit-exact), limit (each field clamped into its envelope — a
//! magnitude is only ever lowered, `q` projected onto its range, a gain
//! never raised), reject (with a substitute).
//!
//! **Humanoid rule.** For a [`Morphology::Humanoid`] platform a joint
//! channel never emits a zero-torque, damping or limp frame (the robot would
//! fall): a rejection or a fault holds the last accepted frame (velocity
//! targets zeroed), or emits nothing if there is none yet; a frame in which
//! every enabled slot is limp is rejected. Compilation refuses
//! [`FailBehaviour::ZeroVelocity`], [`FaultPolicy::FailSafe`] and
//! [`FaultPolicy::FailOpen`] for such a platform
//! ([`ConfigError::UnsafeSubstitute`]), an enabled slot that may go limp
//! without an explicit `allow_limp`, and one without `max_dq_step`; the
//! engine applies the substitute rule regardless of configuration. Past
//! `max_hold_ns` the hold continues (feed-forward torque zeroed) and a
//! Critical `joint_hold_exceeded` event is raised once per hold episode.
//! Other morphologies keep every option (the damping frame for
//! `ZeroVelocity`; see [`Morphology`] for the trade-off).
//!
//! See the crate README ("Low-level joint frames") for the decision table and
//! the rule ids.
//!
//! ## Determinism
//! `check` and `check_joint` perform no heap allocation (proved by `tests/alloc_free.rs` with
//! a counting global allocator), contains no `unwrap`/indexing/unchecked
//! integer arithmetic (enforced by clippy `deny` lints on the engine module)
//! and only bounded loops. See the crate README for measured latency.

// S10: this crate has no `unsafe` code and must stay that way.
#![forbid(unsafe_code)]

mod command;
mod config;
mod engine;
mod events;
mod joint;
mod joint_config;
mod joint_engine;
mod verdict;

pub use command::{ChannelId, Command, JointVelocities, Motion, SourceId, Twist, Vec3, MAX_JOINTS};
pub use config::{
    ChannelKind, ChannelSpec, ConfigError, FailBehaviour, FaultPolicy, ForeignSourceAction,
    Morphology, PlatformConfig, Policy, RateLimit, IDENTITY_SOURCE_PREFIX, MAX_CHANNELS,
    MAX_SOURCES,
};
pub use engine::{Firewall, Stats};
pub use events::{policy_mode, reject_rule, rules, EventAction, EventBuffer, FirewallEvent};
pub use joint::{JointCommand, JointFrame, MotorCmd, MotorMode, MAX_MOTORS};
pub use joint_config::{
    FirewallConfig, JointChannelSpec, JointRate, MotorLimits, MAX_TIME_WINDOW_NS,
};
pub use verdict::{
    JointLimitReasons, JointSubstitute, JointVerdict, JointWouldHave, LimitReasons, RejectReason,
    Substitute, SubstituteKind, Verdict, WouldHave,
};

#[cfg(test)]
mod tests;
