//! Motion/feedback consistency detection (pure): catches injected telemetry by
//! correlating commands with sensor-authored feedback.
//!
//! # Threat
//!
//! *"Seeing is Not Believing"* (Shen et al., 2026) loaded a hook into a Secure
//! ROS 2 process via one environment variable and injected **fabricated
//! telemetry and control**: SROS 2 authenticated the messages because they came
//! from a legitimate, key-holding process. Authentication cannot catch this;
//! physics can. A robot's motion is constrained by its dynamics, so commands,
//! feedback and independent sensors must agree. This crate checks that they
//! do. It covers both directions:
//!
//! * telemetry that does not match what was commanded (fake or frozen
//!   odometry, replayed streams), and
//! * motion that nobody visibly commanded (a command injected below or beside
//!   the channel we observe, or a mechanical fault).
//!
//! It also covers the roadmap's GNSS/navigation-spoofing case through the
//! cross-sensor check (GNSS speed vs. odometry vs. IMU).
//!
//! The crate is **pure**: no I/O, no clocks, no threads. The motion sensor
//! (`robodr-sensor-motion`, not in this crate) subscribes to command and
//! feedback topics, stamps each message with a monotonic observer clock, and
//! feeds [`ConsistencyMonitor`]. Findings become [`robodr_events::Deviation`]s
//! via [`Finding::to_deviation`]. RoboDR only detects and reports: the monitor
//! *reads* the platform's safety-stop state and never sets it.
//!
//! # Model
//!
//! Per tracked [`Axis`] (forward speed, yaw rate, max joint speed) the expected
//! motion follows the command through
//!
//! 1. a **dead time** somewhere in `[latency_min_ns, latency_max_ns]`
//!    (actuation latency *plus* feedback transport delay, as seen on the
//!    observer clock), then
//! 2. a **rate-limited first-order response**:
//!    `de/dt = clamp((u - e) / tau, -max_accel, +max_accel)`, solved exactly
//!    between command changes ([`first_order_step`]).
//!
//! The model runs twice, once at each end of the latency window; the
//! **expected band** is the hull `[lo, hi]` of the two, widened by
//! `abs_tol + rel_tol * max(|lo|, |hi|)`. A command older than
//! `command_timeout_ns` (mirror of the base controller's watchdog) counts as
//! rest; so does "no command seen yet". A command that leaves an axis
//! unspecified (`None`) removes the expectation for that axis until it is
//! specified again, after which checks resume only once the true state could
//! have settled (`5 tau + |u|/max_accel + latency spread`). The first
//! `warmup_ns` after the first event are never judged (initial state unknown).
//!
//! The model uses only the *observer* clock. Source stamps are untrusted and
//! feed only the integrity checks.
//!
//! # Detections
//!
//! Value checks use **episodes** ([`Persistence`]): an episode starts at
//! the first bad sample and ends only after `clear_samples` *consecutive*
//! good samples. It fires once, when it is at least `min_duration_ns` old,
//! holds `min_samples` bad samples, and bad samples are at least
//! `min_bad_fraction` (default 25 %) of its samples. Interleaved good samples
//! therefore only dilute an episode, they cannot reset it; samples with no
//! basis to judge (NaN, unspecified axis) are neither good nor bad.
//! For the command-model rules (divergence, uncommanded motion) and the
//! cross-sensor rule a good sample arriving within `episode_hold_ns` (default 200 ms) of the latest
//! bad one is also **neutral**: the episode is judged on the stream's worst
//! sample per hold window (an upper envelope), not on the per-sample
//! majority, so no mixing ratio of plausible values interleaved between
//! real samples can dilute it. Neutral samples never count as bad, so the
//! hold does not amplify sparse honest outliers.
//! Integrity checks (stamps, non-finite) fire immediately but are latched
//! per source and re-arm after `rearm_clean_samples` clean samples.
//!
//! | Rule id | Condition | Severity | Why |
//! |---|---|---|---|
//! | `robot.motion.feedback_divergence` | feedback outside the band while a non-rest command is in effect, over | High | The telemetry or the actuation is not what the command path says; either is an integrity failure on the control loop. |
//! | ″ | opposite (signed feedback on the other side of zero from a signed command) | Critical once `min_samples` of the episode's opposite-direction samples are `>= uncommanded_critical` (or the firing sample itself is), else High; a latched High/Medium divergence episode escalates to Critical once when that count is reached later (hold-protected, evidence reports the opposite-direction peak) | Driving / turning against the command is as hazardous as uncommanded motion; an injector cannot pre-open a mild episode to mask a later reversal. |
//! | ″ | ″ under-motion (moving less than commanded) | High if `safety_stop_signal_wired`, else Medium | An undeclared e-stop, obstacle or stall looks exactly like this. If the integrator wires the safety-stop state, an unexplained stall is suspicious; if not, it is too often legitimate to page at High. |
//! | `robot.motion.uncommanded_motion` | command at rest (both latency ends) and feedback beyond the decaying band and the noise floor | Critical once `min_samples` of the episode's bad samples are `>= uncommanded_critical` (a latched High episode escalates to Critical, once), else High; evidence reports the episode's peak | Motion nobody visibly commanded is either a command injected around the observed channel or a mechanical/safety fault; above walking-pace speeds it is a direct physical hazard. |
//! | `robot.motion.frozen_feedback` (`FrozenValues`) | ≥ `frozen_min_samples` bit-identical samples over ≥ `frozen_min_duration_ns` while the band says the robot is moving **and** the band midpoint moved by ≥ `frozen_change_factor * abs_tol` during the run | High | A live sensor shows a commanded speed change; a stream that stays bit-identical through one is frozen or replayed. A steady cruise is not judged (noise-free quantised odometry repeats values there legitimately). |
//! | ″ (`TimestampAnomaly` backwards / future) | stamp earlier than the previous from the same source, or ahead of the observer clock by > `max_future_skew_ns` | High | Replay loops and a second (injected) publisher interleaving with the real one produce backwards stamps; future stamps mean a forged or broken clock. |
//! | ″ (duplicate / late) | identical stamp; stamp older than `max_stamp_age_ns` on arrival | Medium | Also produced by benign driver bugs and stalled pipelines. Duplicates are dropped from value checks. |
//! | ″ (`StaleFeedback`) | a source that has reported silent for > `stale_after_ns` while moving (via [`ConsistencyMonitor::tick`]) | Medium | Silence is ambiguous (driver crash vs. suppression). |
//! | `robot.motion.cross_sensor_disagreement` | two sources' latest readings (received within `cross_max_skew_ns`) differ beyond `cross_abs_tol + cross_rel_tol * max` (hold-protected episode) | High | Fake odometry that mirrors the command passes the command check; it cannot also fool an independent IMU or GNSS. Evidence names the more trusted side. |
//! | `robot.motion.invalid_feedback` (`NonFiniteFeedback`) | NaN / ±inf in a feedback value | Medium | Usually a driver fault, but NaN is also a classic way to poison downstream estimators. The value is dropped. |
//! | ″ (`NonFiniteRate`) | ≥ `nan_rate_high` of a stream's last 64 samples on an axis non-finite (after `nan_rate_min_samples`), while motion is expected, observed or an episode is open, **or** the whole window is non-finite | High | A NaN stream blinds every motion check. An all-invalid stream means "motion state unknown", which is never reported as fine, even at rest. |
//! | `robot.motion.multiple_feedback_publishers` | a publisher resumes on a source type after another, still-active publisher sent samples (interleaving); or (`PublisherOverflow`) more than [`PUBLISHER_SLOTS`] concurrent publishers on a source type | High | Two writers on one telemetry topic is the injection signature. A clean hand-over (driver restart) does not fire. |
//! | `robot.motion.inconsistent_feedback_stream` | ≥ `jump_min_count` jumps within one (source, publisher) stream, each larger than the cross tolerance **and** `jump_accel_factor * max_accel * dt`, with gaps < `jump_window_ns` between jumps | High | Catches an injector the caller cannot attribute (same publisher id): every real <-> fake transition implies an acceleration the platform cannot produce, however many fakes it sends per real sample. |
//!
//! Each finding carries a `Copy` [`Evidence`] value with the numbers that
//! justified it (band, tolerance, measurement, since, sample count, trust).
//!
//! ## Direction (signed values)
//!
//! Linear and angular values are **signed body-frame velocities** by default
//! (`compare_magnitudes = false`), so a robot moving against its command is
//! an `Opposite` divergence, and two sensors reporting opposite turns
//! disagree. Inputs that only carry magnitudes are declared, not guessed:
//! [`CommandSample::direction_known`] `= false` (set by
//! [`CommandSample::from_motion_command`]) and `SourceConfig::signed = false`
//! (GNSS speed over ground by default). While such an input is involved the
//! comparison falls back to magnitudes and **a reversal is invisible**.
//!
//! ## Publishers
//!
//! Feedback state (stamps, frozen, NaN window, persistence, cross-check) is
//! kept per **(source type, publisher)** in a fixed table of
//! [`PUBLISHER_SLOTS`] slots per source type, keyed by a [`PublisherKey`]
//! stored inline and compared exactly. Prefer
//! [`ConsistencyMonitor::on_feedback_guid`] with the **full 16-byte DDS
//! writer GUID** ([`PublisherKey::from_guid_str`] parses the textual form):
//! an adversary choosing its own GUID cannot collide with the real writer.
//! [`ConsistencyMonitor::on_feedback_from`] (a caller `u32`: interned id or
//! the legacy [`publisher_id`] hash) is kept for compatibility; `Id` and
//! `Guid` keys never collide with each other. An injected second publisher
//! cannot dilute the real one's detectors, findings carry the publisher,
//! and the interleaving itself is a finding.
//! [`ConsistencyMonitor::on_feedback`] uses [`PublisherKey::UNKNOWN`]: all
//! samples share one slot, and only the episode hold plus the
//! inconsistent-stream check protect it. Slots expire after
//! `publisher_expiry_ns` of silence; beyond [`PUBLISHER_SLOTS`] concurrent
//! publishers the extra ones share a dedicated **overflow slot** per source
//! type (never a tracked publisher's slot, so a flood cannot dilute the real
//! writer), counted in [`MonitorStats::publisher_overflow`] and flagged once
//! (`PublisherOverflow`) until the overflow slot has been silent for
//! `publisher_expiry_ns`.
//!
//! ## Safety stop
//!
//! [`ConsistencyMonitor::set_safety_stop`] declares the platform's e-stop /
//! protective-stop state. While active the expected motion is zero,
//! under-motion is legitimate, and uncommanded-motion checks wait
//! `safety_stop_grace_ns` for coast-down (after which motion during an
//! e-stop *is* reported). After release, under-motion is not judged for
//! `safety_stop_grace_ns` (drive re-enable). Without the signal, an e-stop
//! while the planner keeps publishing shows up as a **Medium** under-motion
//! divergence: we cannot tell an e-stop from a stall, and we say so rather
//! than stay silent.
//!
//! ## Sensor-authored vs process-authored
//!
//! Telemetry we can trust is telemetry the attacker's process did not author.
//! Wheel odometry and joint states in ROS 2 are *computed by a controller
//! process* (e.g. `diff_drive_controller`) in the same software domain as the
//! command path: the "Seeing is Not Believing" hook can fabricate them.
//! An IMU is a separate device whose gyro measures rotation directly; a
//! GNSS receiver is a separate device but listens to an RF signal an outside
//! adversary can spoof. Default `trust_rank`: IMU 3 > GNSS 2 > wheel odometry
//! = joint state 1 > other 0. Trust never suppresses a finding; it only
//! states which side of a disagreement is more believable. Note that today
//! every source still reaches us through a driver *process*; trust becomes
//! real only when the IMU/GNSS path is read from the bus (Bus Tap) or
//! attested. Until then the cross-check raises the attacker's cost (they must
//! forge every sensor consistently) rather than making forgery impossible.
//!
//! # Determinism and allocation
//!
//! [`ConsistencyMonitor::new`] allocates the command ring once (`Vec` filled
//! to `command_capacity`, then written only by index). After that,
//! `on_command`, `on_feedback`, `tick` and `set_safety_stop` perform **no
//! heap allocation**: state is fixed-size arrays, findings go to a
//! caller-supplied `FnMut(Finding)` sink as `Copy` values, and the channel
//! filter is a borrowed string compare. Cost per event is
//! `O(command_capacity)` in the worst case (ring scans), constant otherwise.
//! No clocks, randomness or hash maps: the same input sequence always yields
//! the same findings. [`Finding::detail`] / [`Finding::to_deviation`] allocate
//! and belong off the control path. Tests verify all of this with a counting
//! global allocator.
//!
//! Hostile input never panics: non-finite command values count as 0 ("nothing
//! valid commanded"), non-finite feedback is dropped (it never resets an
//! episode or a frozen run) and reported, all time
//! arithmetic saturates, observer time regressions are clamped and counted,
//! and negative wire stamps are rejected at conversion ([`stamp_from_ros`],
//! [`stamp_from_secs_f64`]).
//!
//! # Tuning per platform
//!
//! Defaults ([`MonitorConfig::ugv`], [`MonitorConfig::manipulator`]) are
//! plausible starting points, **not** values fitted to real hardware.
//!
//! * **Latency window**: measure command-to-first-motion plus feedback
//!   transport on the real robot (step tests); set `min` at the 1st and `max`
//!   at the 99th percentile. Typical: small UGV 20–150 ms, tracked or
//!   hydraulic platforms 100–400 ms, torque-controlled arms 2–50 ms.
//! * **`tau_s` / `max_accel`**: fit to step responses on the load and terrain
//!   the platform actually sees. Set `max_accel` to the *largest* rate the
//!   platform can achieve in either direction (braking included), otherwise
//!   hard stops read as under-motion.
//! * **Tolerances**: `abs_tol` ≥ 3σ of feedback noise at rest; `rel_tol`
//!   covers model error at speed (20–30 % on rough terrain). GNSS speed is
//!   poor below ~0.5 m/s: raise linear `cross_abs_tol` if GNSS is
//!   cross-checked on slow platforms.
//! * **Persistence**: longer than the longest benign transient (wheel slip
//!   on the platform's worst surface, bump, docking contact). 0.5 s / 10
//!   samples is a guess for a 50 Hz UGV.
//! * **`command_capacity`**: ≥ command rate × `latency_max` × 2; watch
//!   [`MonitorStats::history_underruns`].
//! * **Frozen check**: drivers that output quantised velocities (encoder
//!   ticks at constant speed) repeat values legitimately at a steady
//!   cruise; the check only judges runs during which the expectation moved
//!   by `frozen_change_factor * abs_tol`, so this needs no tuning unless
//!   the quantum exceeds `abs_tol` (then raise the factor).
//! * Feed the *final* command (after `twist_mux` / safety filters) via
//!   `command_channels`, or the band follows a command the robot never got.
//!
//! # Known limits
//!
//! * **Untuned.** Nothing here has seen a real lab trace; all thresholds
//!   need fitting on the reference UGV (and the Franka arm used in the
//!   original attack) before the rules leave observe mode.
//! * One scalar model per axis: no slope/load dependence, no wheel slip
//!   model, no turning/linear coupling, no per-joint model (joint axis is
//!   max |speed| only).
//! * The latency hull is exact for monotone responses; for rapidly reversing
//!   commands intermediate latencies can fall slightly outside it (absorbed
//!   by the tolerance).
//! * An attacker who forges **every** feedback source consistently with a
//!   fabricated command defeats this check; attestation of the runtime and
//!   bus-level capture are the answer to that, not this crate.
//! * Long genuine slip (stuck in mud) or a long stall will raise
//!   cross-sensor/divergence findings: physically true, not an attack.
//! * A feedback injector that **replaces** the real publisher (real one
//!   silenced, fake one starts) looks like a driver restart: no
//!   multiple-publishers finding. Only the command check (if the fake is
//!   inconsistent with commands) and the cross-check against an independent
//!   sensor remain.
//! * Without publisher attribution, an injector interleaving "at rest"
//!   samples with the real ones (same publisher id, any ratio, any level,
//!   each jump below the jump tolerance) no longer dilutes the command-model
//!   episodes **as long as real samples keep arriving at least every
//!   `episode_hold_ns`**: set it above the slowest honest feedback period.
//!   An injector that also *suppresses* real samples for longer than the
//!   hold is a replacement, not an interleaving (see above). The jump check
//!   (`inconsistent_feedback_stream`) needs `max_accel` on the axis and is
//!   untuned: very noisy high-rate sensors (vibration, wheel slip spikes)
//!   may need a larger `jump_accel_factor`. Neither check looks for
//!   bimodality below the jump tolerance; the hold makes that unnecessary
//!   for the command-model and cross-sensor rules. For the cross-sensor
//!   rule the hold must exceed the slowest honest period of the
//!   cross-checked sources (a 1 Hz GNSS needs a hold above 1 s for its
//!   disagreements not to be diluted by interleaved agreeing samples).
//! * The hold also delays the end of a genuine episode by up to
//!   `episode_hold_ns`, and a sensor that produces an out-of-band sample at
//!   least every `episode_hold_ns` (e.g. > 5 sigma spikes several times a
//!   second) is reported even if those samples are a small fraction.
//! * [`publisher_id`] is a 32-bit FNV-1a hash; an adversary choosing its GUID
//!   can collide with the real writer. Use [`ConsistencyMonitor::on_feedback_guid`]
//!   (full GUID); `robodr-agent` does whenever `publisher_guid` parses as a
//!   GUID.
//! * A feedback stream frozen at a **steady cruise** is not reported until
//!   the expected motion next changes (indistinguishable from a noise-free
//!   quantised sensor by values alone); stamp checks (replays) and the
//!   cross-sensor check still apply meanwhile.
//! * More than [`PUBLISHER_SLOTS`] concurrent publishers of one source type
//!   share its overflow slot: they lose separation from *each other* (not
//!   from the tracked publishers), and the overflow is reported.
//! * Commands built from [`robodr_events::MotionCommand`] carry no sign: no
//!   direction-reversal detection on them.
//! * IMU linear velocity is only usable if the caller supplies a fused
//!   estimate; raw accelerometer integration drifts.
//! * Stamps must share the observer's time base; the sensor must map ROS
//!   time / sim time to it, or disable `stamp_check`.

// S10: this crate has no `unsafe` code and must stay that way.
#![forbid(unsafe_code)]

mod config;
mod model;
mod monitor;
mod sample;

pub use config::{AxisModel, ConfigError, MonitorConfig, Persistence, SourceConfig, SourceTable};
pub use model::first_order_step;
pub use monitor::{
    rules, ConsistencyMonitor, Direction, Evidence, Finding, MonitorStats, StampAnomaly,
    PUBLISHER_SLOTS,
};
pub use sample::{
    publisher_id, stamp_from_ros, stamp_from_secs_f64, Axis, CommandSample, FeedbackSample,
    FeedbackSource, PublisherKey, PUBLISHER_UNKNOWN,
};
